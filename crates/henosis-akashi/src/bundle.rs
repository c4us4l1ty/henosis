//! Portable, content-addressed, optionally Ed25519-signed Capability Bundles (`.hcap`).
//!
//! Packages a capability node, optional realization contract, verification log,
//! Failure Atlas records, optional perturbation suite report, optional proxy
//! blackout receipt, and a selectively disclosed list of verified capability IDs
//! (enabling peer compositional synergy checks without exposing a private Worldline).
//!
//! Epistemic rule on import: importing a peer's `.hcap` bundle rewrites capability
//! provenance to [`AssistanceProvenance::External`] so another person's signed work
//! never silently inflates the local user's unassisted human capability state `H`.

use crate::perturb::PerturbationSuiteReport;
use henosis_dag::{
    validate_id, AssistanceProvenance, EpistemicStatus, FailureRecord, Node, RealizationContract,
    VerificationEntry, WorldlineOp,
};
use henosis_proxy::BlackoutReceipt;
use henosis_vault::{
    hex, public_key_fingerprint, verify_domain_hex, Identity, DOMAIN_CAPABILITY_BUNDLE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::path::Path;

pub const BUNDLE_FORMAT_V1: &str = "henosis.hcap.v1";
const BUNDLE_HASH_PREFIX: &[u8] = b"henosis.akashi.bundle-id.v1\0";
pub const MAX_BUNDLE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityBundle {
    pub format: String,
    pub bundle_id: String,
    pub capability: Node,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<RealizationContract>,
    pub verifications: Vec<VerificationEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<FailureRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perturbation_report: Option<PerturbationSuiteReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blackout_receipt: Option<BlackoutReceipt>,
    /// Selectively disclosed verified capability IDs of the author for peer
    /// compositional synergy queries `Delta F_syn(H_A, H_B)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disclosed_capabilities: Vec<String>,
    /// Honest explicit statement of conditions not guaranteed by this bundle.
    pub scope_limits: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
}

/// Inputs for constructing a verified [`CapabilityBundle`].
pub struct BundleInput {
    pub capability: Node,
    pub contract: Option<RealizationContract>,
    pub verifications: Vec<VerificationEntry>,
    pub failures: Vec<FailureRecord>,
    pub perturbation_report: Option<PerturbationSuiteReport>,
    pub blackout_receipt: Option<BlackoutReceipt>,
    pub disclosed_capabilities: BTreeSet<String>,
    pub scope_limits: String,
}

#[derive(Serialize)]
struct CanonicalBundleBody<'a> {
    format: &'a str,
    capability: &'a Node,
    contract: &'a Option<RealizationContract>,
    verifications: &'a [VerificationEntry],
    failures: &'a [FailureRecord],
    perturbation_report: &'a Option<PerturbationSuiteReport>,
    blackout_receipt: &'a Option<BlackoutReceipt>,
    disclosed_capabilities: &'a [String],
    scope_limits: &'a str,
}

fn compute_bundle_id(body: &CanonicalBundleBody<'_>) -> Result<String, String> {
    let encoded = serde_json::to_vec(body).map_err(|err| err.to_string())?;
    let mut hasher = Sha256::new();
    hasher.update(BUNDLE_HASH_PREFIX);
    hasher.update(&encoded);
    Ok(hex::encode(&hasher.finalize()))
}

/// Construct, validate, content-address, and optionally sign a `.hcap` bundle.
pub fn build_bundle(input: BundleInput, signer: Option<&Identity>) -> Result<CapabilityBundle, String> {
    let contract = match input.contract {
        Some(c) => Some(c.normalized()?),
        None => None,
    };
    let disclosed_capabilities: Vec<String> = input.disclosed_capabilities.into_iter().collect();
    let scope_limits = if input.scope_limits.trim().is_empty() {
        "Bundle signature attests key possession over recorded evidence digests; independent replication required before trusting unverified assumptions.".into()
    } else {
        input.scope_limits
    };

    let bundle_id = compute_bundle_id(&CanonicalBundleBody {
        format: BUNDLE_FORMAT_V1,
        capability: &input.capability,
        contract: &contract,
        verifications: &input.verifications,
        failures: &input.failures,
        perturbation_report: &input.perturbation_report,
        blackout_receipt: &input.blackout_receipt,
        disclosed_capabilities: &disclosed_capabilities,
        scope_limits: &scope_limits,
    })?;

    let (author_pubkey_hex, author_fingerprint, signature_hex) = if let Some(id) = signer {
        let pk = id.public_key_hex();
        let fp = id.fingerprint();
        let sig = id
            .sign_domain_hex(DOMAIN_CAPABILITY_BUNDLE, bundle_id.as_bytes())
            .map_err(|err| err.to_string())?;
        (Some(pk), Some(fp), Some(sig))
    } else {
        (None, None, None)
    };

    let bundle = CapabilityBundle {
        format: BUNDLE_FORMAT_V1.into(),
        bundle_id,
        capability: input.capability,
        contract,
        verifications: input.verifications,
        failures: input.failures,
        perturbation_report: input.perturbation_report,
        blackout_receipt: input.blackout_receipt,
        disclosed_capabilities,
        scope_limits,
        author_pubkey_hex,
        author_fingerprint,
        signature_hex,
    };
    bundle.verify(signer.is_some())?;
    Ok(bundle)
}

impl CapabilityBundle {
    /// Validate bundle schema, internal references, content-addressed `bundle_id`,
    /// optional blackout receipt, and Ed25519 signature.
    pub fn verify(&self, require_signature: bool) -> Result<(), String> {
        if self.format != BUNDLE_FORMAT_V1 {
            return Err(format!("unsupported bundle format '{}'", self.format));
        }
        self.capability.validate()?;
        if !self.capability.status.is_verified() {
            return Err("capability bundle requires an observed or reproduced capability".into());
        }
        if self.verifications.is_empty() {
            return Err("capability bundle must contain at least one verification entry".into());
        }
        for v in &self.verifications {
            v.validate()?;
            if v.node_id != self.capability.id {
                return Err(format!(
                    "verification references '{}', expected '{}'",
                    v.node_id, self.capability.id
                ));
            }
        }
        if let Some(contract) = &self.contract {
            contract.validate()?;
        }
        for failure in &self.failures {
            failure.validate()?;
        }
        if let Some(receipt) = &self.blackout_receipt {
            receipt.verify(false)?;
        }
        for cap_id in &self.disclosed_capabilities {
            validate_id(cap_id)?;
        }
        if self.scope_limits.trim().is_empty() || self.scope_limits.len() > 2048 {
            return Err("bundle scope_limits must be 1..=2048 non-whitespace bytes".into());
        }

        let recomputed = compute_bundle_id(&CanonicalBundleBody {
            format: &self.format,
            capability: &self.capability,
            contract: &self.contract,
            verifications: &self.verifications,
            failures: &self.failures,
            perturbation_report: &self.perturbation_report,
            blackout_receipt: &self.blackout_receipt,
            disclosed_capabilities: &self.disclosed_capabilities,
            scope_limits: &self.scope_limits,
        })?;
        if recomputed != self.bundle_id {
            return Err(format!(
                "bundle content hash mismatch: expected '{}', computed '{recomputed}'",
                self.bundle_id
            ));
        }

        match (&self.author_pubkey_hex, &self.signature_hex) {
            (Some(pk_hex), Some(sig_hex)) => {
                let pk = hex::decode_array::<32>(pk_hex)
                    .map_err(|_| "invalid bundle author public key".to_owned())?;
                if let Some(fp) = &self.author_fingerprint {
                    if public_key_fingerprint(&pk) != *fp {
                        return Err("bundle author fingerprint mismatch".into());
                    }
                }
                verify_domain_hex(
                    pk_hex,
                    DOMAIN_CAPABILITY_BUNDLE,
                    self.bundle_id.as_bytes(),
                    sig_hex,
                )
                .map_err(|err| format!("bundle signature invalid: {err}"))
            }
            (None, None) if !require_signature => Ok(()),
            _ => Err("bundle lacks a required valid Ed25519 signature".into()),
        }
    }

    /// Disclosed capability set suitable for peer synergy comparison.
    pub fn disclosed_set(&self) -> BTreeSet<String> {
        let mut set: BTreeSet<String> = self.disclosed_capabilities.iter().cloned().collect();
        if self.capability.credits_unassisted_human_state() {
            set.insert(self.capability.id.clone());
        }
        set
    }

    /// Convert a verified peer bundle into `WorldlineOp`s for local import.
    /// The imported capability's provenance is strictly tagged `External` and
    /// status `Observed` so a peer's proof never enters the local user's
    /// unassisted capability set `H` without local cleanroom replication.
    pub fn to_peer_import_ops(&self) -> Result<Vec<WorldlineOp>, String> {
        self.verify(false)?;
        let mut ops = Vec::new();
        let mut imported_node = self.capability.clone();
        imported_node.provenance = AssistanceProvenance::External;
        imported_node.status = EpistemicStatus::Observed;
        ops.push(WorldlineOp::UpsertNode {
            node: Box::new(imported_node),
        });
        if let Some(contract) = &self.contract {
            let mut imported_contract = contract.clone();
            if imported_contract.status == EpistemicStatus::Reproduced {
                imported_contract.status = EpistemicStatus::Observed;
            }
            ops.push(WorldlineOp::UpsertContract {
                contract: Box::new(imported_contract),
            });
        }
        for failure in &self.failures {
            ops.push(WorldlineOp::RecordFailure {
                failure: Box::new(failure.clone()),
            });
        }
        Ok(ops)
    }
}

/// Write a validated `.hcap` bundle to `path` without overwriting an existing file.
pub fn save_bundle(path: &Path, bundle: &CapabilityBundle) -> io::Result<()> {
    bundle
        .verify(bundle.signature_hex.is_some())
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    let mut bytes = serde_json::to_vec_pretty(bundle).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle exceeds 4 MiB size limit",
        ));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    tmp.write_all(&bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path).map_err(|err| err.error)?;
    Ok(())
}

/// Read and verify a `.hcap` bundle from a regular file.
pub fn load_bundle(path: &Path, require_signature: bool) -> io::Result<CapabilityBundle> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "bundle path is not a regular file",
        ));
    }
    let mut buf = Vec::new();
    file.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_BUNDLE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bundle exceeds 4 MiB limit",
        ));
    }
    let bundle: CapabilityBundle = serde_json::from_slice(&buf)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    bundle
        .verify(require_signature)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidData, msg))?;
    Ok(bundle)
}
