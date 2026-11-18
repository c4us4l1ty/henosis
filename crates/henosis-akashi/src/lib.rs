#![deny(unsafe_code)]
//! Akashi verification and falsification primitives: seven proof operators,
//! assistance-provenance gating, controlled worktree perturbation runs with
//! Operator 07 (`PredictFailure`) scoring, and signed `.hcap` capability bundles.
//!
//! Honest epistemology: Akashi validates recorded command evidence, perturbation
//! outcomes, provenance declarations, and optional proxy blackout receipts. It
//! prevents accidental conflation of unverified exposure or AI-assisted output
//! with unassisted capability, but cannot detect out-of-band assistance or
//! guarantee correctness beyond the conditions actually tested.

pub mod bundle;
pub mod perturb;

pub use bundle::{
    build_bundle, load_bundle, save_bundle, BundleInput, CapabilityBundle, BUNDLE_FORMAT_V1,
};
pub use perturb::{
    run_suite, FileMutation, PerturbationCase, PerturbationOutcome, PerturbationSuiteReport,
    PredictedOutcome, PredictionVerdict,
};

use henosis_dag::{
    validate_id, validate_sha256_hex, AssistanceProvenance, ProofOperator, VerificationEntry,
};
use henosis_evidence::Evidence;
use henosis_proxy::BlackoutReceipt;
use henosis_vault::hex;
use sha2::{Digest, Sha256};

const EVIDENCE_HASH_PREFIX: &[u8] = b"henosis.akashi.evidence.v1\0";
const WRITTEN_PROOF_PREFIX: &[u8] = b"henosis.akashi.written-proof.v1\0";

/// Compute a canonical domain-separated SHA-256 digest of a recorded [`Evidence`].
pub fn evidence_digest(evidence: &Evidence) -> String {
    let bytes = serde_json::to_vec(evidence).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(EVIDENCE_HASH_PREFIX);
    hasher.update(&bytes);
    hex::encode(&hasher.finalize())
}

/// Compute a canonical domain-separated SHA-256 digest for a written derivation,
/// explanation, or critique artifact (used by `Explain`, `Reconstruct`, `Criticize`).
pub fn written_artifact_digest(operator: ProofOperator, content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(WRITTEN_PROOF_PREFIX);
    hasher.update(operator.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(content);
    hex::encode(&hasher.finalize())
}

/// Build a validated [`VerificationEntry`] from deterministic command [`Evidence`],
/// requiring a matching exit code, non-timeout execution, complete stream capture,
/// and a readable post-run artifact hash.
pub fn verify_from_evidence(
    node_id: &str,
    operator: ProofOperator,
    provenance: AssistanceProvenance,
    evidence: &Evidence,
    blackout: Option<&BlackoutReceipt>,
    summary: impl Into<String>,
) -> Result<VerificationEntry, String> {
    validate_id(node_id)?;
    if evidence.timed_out {
        return Err("cannot verify capability from a timed-out command run".into());
    }
    if evidence.exit_code != Some(evidence.expected_exit) {
        return Err(format!(
            "command exit {:?} did not match expected {}",
            evidence.exit_code, evidence.expected_exit
        ));
    }
    if evidence.output_incomplete {
        return Err("command output capture was incomplete; inspect background processes".into());
    }
    if evidence.artifact_sha256.is_none() {
        return Err("command run has no readable post-run artifact hash".into());
    }
    let proxy_blackout_verified = match blackout {
        Some(receipt) => {
            receipt.verify(false)?;
            true
        }
        None => false,
    };
    let entry = VerificationEntry {
        node_id: node_id.to_owned(),
        operator,
        provenance,
        evidence_sha256: evidence_digest(evidence),
        proxy_blackout_verified,
        summary: summary.into(),
    };
    entry.validate()?;
    Ok(entry)
}

/// Build a [`VerificationEntry`] for Operator 07 (`PredictFailure`) from a
/// completed [`PerturbationSuiteReport`], requiring 100% prediction accuracy and
/// at least one confirmed failure boundary.
pub fn verify_from_perturbation(
    node_id: &str,
    provenance: AssistanceProvenance,
    report: &PerturbationSuiteReport,
    blackout: Option<&BlackoutReceipt>,
    summary: impl Into<String>,
) -> Result<VerificationEntry, String> {
    validate_id(node_id)?;
    if report.outcomes.is_empty() {
        return Err("perturbation report contains no cases".into());
    }
    if report.accurate_predictions != report.outcomes.len() {
        return Err(format!(
            "failure prediction accuracy was {}/{}; revise model and retest",
            report.accurate_predictions,
            report.outcomes.len()
        ));
    }
    let confirmed_breaks = report
        .outcomes
        .iter()
        .filter(|o| o.verdict == PredictionVerdict::ConfirmedBreak)
        .count();
    if confirmed_breaks == 0 {
        return Err(
            "Operator 07 (PredictFailure) requires at least one confirmed failure boundary".into(),
        );
    }
    validate_sha256_hex(&report.report_sha256)?;
    let proxy_blackout_verified = match blackout {
        Some(receipt) => {
            receipt.verify(false)?;
            true
        }
        None => false,
    };
    let entry = VerificationEntry {
        node_id: node_id.to_owned(),
        operator: ProofOperator::PredictFailure,
        provenance,
        evidence_sha256: report.report_sha256.clone(),
        proxy_blackout_verified,
        summary: summary.into(),
    };
    entry.validate()?;
    Ok(entry)
}

/// Build a [`VerificationEntry`] from an explicit SHA-256 evidence digest (e.g.
/// a verified derivation file or reproduced dataset), enforcing non-empty summary
/// and valid blackout receipt if supplied.
pub fn verify_from_digest(
    node_id: &str,
    operator: ProofOperator,
    provenance: AssistanceProvenance,
    evidence_sha256: &str,
    blackout: Option<&BlackoutReceipt>,
    summary: impl Into<String>,
) -> Result<VerificationEntry, String> {
    validate_id(node_id)?;
    validate_sha256_hex(evidence_sha256)?;
    let proxy_blackout_verified = match blackout {
        Some(receipt) => {
            receipt.verify(false)?;
            true
        }
        None => false,
    };
    let entry = VerificationEntry {
        node_id: node_id.to_owned(),
        operator,
        provenance,
        evidence_sha256: evidence_sha256.to_owned(),
        proxy_blackout_verified,
        summary: summary.into(),
    };
    entry.validate()?;
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use henosis_dag::{EntityKind, EpistemicStatus, Node, RealizationContract, Worldline, WorldlineOp};
    #[cfg(unix)]
    use henosis_vault::Identity;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[cfg(unix)]
    #[test]
    fn perturbation_suite_verifies_predict_failure_and_exports_signed_hcap_bundle() {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("params.txt"), "dt=1\n").unwrap();
        let script = "grep -q 'dt=1' params.txt && printf ok > out.txt";
        let baseline = henosis_evidence::run(
            project.path().to_str().unwrap(),
            "out.txt",
            0,
            "/bin/sh",
            &["-c".into(), script.into()],
        )
        .unwrap();

        // Source project still has dt=1 after running unstable perturbation in cloned worktree.
        let cases = vec![
            PerturbationCase {
                id: "within-bound".into(),
                assumption_tested: "solver handles whitespace comment".into(),
                trigger_description: "append trailing comment".into(),
                mutations: vec![FileMutation::AppendText {
                    path: "params.txt".into(),
                    text: "# safe\n".into(),
                }],
                prediction: PredictedOutcome::Survive { expected_exit: 0 },
                artifact: "out.txt".into(),
                program: "/bin/sh".into(),
                arguments: vec!["-c".into(), script.into()],
            },
            PerturbationCase {
                id: "exceed-cfl".into(),
                assumption_tested: "dt <= 2/lambda stability criterion".into(),
                trigger_description: "set dt=9 exceeding CFL limit".into(),
                mutations: vec![FileMutation::ReplaceExact {
                    path: "params.txt".into(),
                    find: "dt=1".into(),
                    replace: "dt=9".into(),
                }],
                prediction: PredictedOutcome::Break {
                    baseline_exit: 0,
                    reason: "amplification factor exceeds unity".into(),
                },
                artifact: "out.txt".into(),
                program: "/bin/sh".into(),
                arguments: vec!["-c".into(), script.into()],
            },
        ];

        let report = run_suite(project.path(), "euler-cap", &cases).unwrap();
        assert_eq!(
            std::fs::read_to_string(project.path().join("params.txt")).unwrap(),
            "dt=1\n"
        );
        assert_eq!(report.accurate_predictions, 2);
        assert_eq!(report.outcomes[0].verdict, PredictionVerdict::ConfirmedResilience);
        assert_eq!(report.outcomes[1].verdict, PredictionVerdict::ConfirmedBreak);
        assert_eq!(report.exposed_failures.len(), 1);

        let v_impl = verify_from_evidence(
            "euler-cap",
            ProofOperator::Implement,
            AssistanceProvenance::UnassistedHuman,
            &baseline,
            None,
            "Baseline solver reproduced exact output",
        )
        .unwrap();
        let v_pred = verify_from_perturbation(
            "euler-cap",
            AssistanceProvenance::UnassistedHuman,
            &report,
            None,
            "Predicted CFL blow-up before execution",
        )
        .unwrap();

        let alice = Identity::recover(PHRASE, "alice").unwrap();
        let mut wl = Worldline::new();
        let mut ops = vec![
            WorldlineOp::UpsertNode {
                node: Box::new(Node {
                    id: "euler-cap".into(),
                    kind: EntityKind::Capability,
                    title: "Explicit Euler integration".into(),
                    domain: "numerical-analysis".into(),
                    summary: "Stable first-order scalar integration".into(),
                    status: EpistemicStatus::Hypothesized,
                    provenance: AssistanceProvenance::UnassistedHuman,
                    evidence_sha256: vec![],
                    proof_operators: vec![],
                }),
            },
            WorldlineOp::UpsertContract {
                contract: Box::new(
                    RealizationContract {
                        id: "c-euler".into(),
                        title: "Construct explicit Euler integrator".into(),
                        prerequisites: vec!["calculus".into()],
                        assumptions: vec!["dt <= 2/lambda".into()],
                        resources: vec!["rustc".into()],
                        output: "euler-cap".into(),
                        verification: "analytical error bound + CFL perturbation".into(),
                        failure_boundary: vec![],
                        status: EpistemicStatus::Observed,
                        cost_units: 2,
                    }
                    .normalized()
                    .unwrap(),
                ),
            },
            WorldlineOp::RecordVerification {
                entry: Box::new(v_impl.clone()),
            },
            WorldlineOp::RecordVerification {
                entry: Box::new(v_pred.clone()),
            },
        ];
        for f in &report.exposed_failures {
            ops.push(WorldlineOp::RecordFailure {
                failure: Box::new(f.clone()),
            });
        }
        wl.commit("Verify euler-cap with Implement + PredictFailure", ops, Some(&alice))
            .unwrap();

        let state = wl.materialize_head().unwrap();
        let bundle = build_bundle(
            BundleInput {
                capability: state.nodes["euler-cap"].clone(),
                contract: Some(state.contracts["c-euler"].clone()),
                verifications: state.verifications.clone(),
                failures: report.exposed_failures.clone(),
                perturbation_report: Some(report),
                blackout_receipt: None,
                disclosed_capabilities: ["calculus".to_owned(), "euler-cap".to_owned()]
                    .into_iter()
                    .collect(),
                scope_limits: "Tested on linear scalar decay only; stiff coupled systems excluded."
                    .into(),
            },
            Some(&alice),
        )
        .unwrap();

        let bundle_path = project.path().join("euler.hcap");
        save_bundle(&bundle_path, &bundle).unwrap();
        let loaded = load_bundle(&bundle_path, true).unwrap();
        assert_eq!(loaded, bundle);

        // Importing Alice's bundle into Bob's worldline preserves the contract and
        // failure atlas, but NEVER inflates Bob's unassisted capability set H!
        let mut bob_wl = Worldline::new();
        bob_wl
            .commit(
                "Import Alice euler.hcap for peer review",
                loaded.to_peer_import_ops().unwrap(),
                None,
            )
            .unwrap();
        let bob_state = bob_wl.materialize_head().unwrap();
        assert!(bob_state.unassisted_capabilities().is_empty());
        assert!(bob_state.assisted_verified_nodes().contains("euler-cap"));
        assert_eq!(bob_state.failures.len(), 1);

        // Tampering with the .hcap file breaks verification.
        let tampered = std::fs::read_to_string(&bundle_path)
            .unwrap()
            .replace("linear scalar", "nonlinear tensor");
        std::fs::write(&bundle_path, tampered).unwrap();
        assert!(load_bundle(&bundle_path, true).is_err());
    }

    #[test]
    fn written_proof_and_failed_bundle_guards_run_on_every_platform() {
        let d1 = written_artifact_digest(ProofOperator::Reconstruct, b"proof step 1");
        let d2 = written_artifact_digest(ProofOperator::Explain, b"proof step 1");
        assert_eq!(d1.len(), 64);
        assert_ne!(d1, d2);
        let entry = verify_from_digest(
            "cayley-hamilton",
            ProofOperator::Reconstruct,
            AssistanceProvenance::UnassistedHuman,
            &d1,
            None,
            "Derived characteristic polynomial annihilation from memory",
        )
        .unwrap();
        assert_eq!(entry.operator, ProofOperator::Reconstruct);
    }
}
