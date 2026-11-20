#![deny(unsafe_code)]
//! Content-addressed branching Worldline Merkle-DAG, materialized World Model,
//! Failure Atlas, Exposure Quarantine Queue, and CSR Capability Hypergraph.
//!
//! Every commit's identifier is the SHA-256 digest of a domain-separated
//! canonical representation covering its parent commit IDs, topological sequence
//! number, branch hint, commit message, and typed operations. Commits can be
//! signed with a [`henosis_vault::Identity`] Ed25519 key; loading re-validates
//! every commit digest, parent link, topological acyclicity, and attached
//! signature.
//!
//! Honest boundaries: content addressing and signatures detect modification of
//! commits and prove key possession when signed, but do not prevent local file
//! deletion/rollback of the entire DAG file or prove that an unassisted claim
//! was truly produced without external help.

pub mod hypergraph;
pub mod model;

pub use hypergraph::{BackwardLightCone, CsrHypergraph, ExpansionDelta, FeasibleClosure, SynergyReport};
pub use model::{
    validate_id, validate_sha256_hex, AssistanceProvenance, EntityKind, EpistemicStatus,
    FailureRecord, Node, ProofOperator, QuarantineItem, RealizationContract, VerificationEntry,
    WorldlineOp,
};

use henosis_vault::{
    hex, public_key_fingerprint, verify_domain_hex, Identity, DOMAIN_WORLDLINE_COMMIT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

const WORLDLINE_VERSION: u32 = 1;
const COMMIT_HASH_PREFIX: &[u8] = b"henosis.worldline.commit.v1\0";
pub const MAX_WORLDLINE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COMMITS: usize = 32_768;

#[derive(Debug)]
pub enum DagError {
    Io(io::Error),
    Validation(String),
    Integrity(String),
    NotFound(String),
}

impl fmt::Display for DagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "worldline I/O error: {err}"),
            Self::Validation(msg) => write!(f, "worldline validation error: {msg}"),
            Self::Integrity(msg) => write!(f, "worldline integrity failure: {msg}"),
            Self::NotFound(msg) => write!(f, "worldline entry not found: {msg}"),
        }
    }
}

impl std::error::Error for DagError {}

impl From<io::Error> for DagError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// One immutable node in the Worldline Merkle-DAG.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub id: String,
    pub seq: u64,
    pub parents: Vec<String>,
    pub branch_hint: String,
    pub message: String,
    pub ops: Vec<WorldlineOp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_pubkey_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_hex: Option<String>,
}

#[derive(Serialize)]
struct CanonicalCommitBody<'a> {
    seq: u64,
    parents: &'a [String],
    branch_hint: &'a str,
    message: &'a str,
    ops: &'a [WorldlineOp],
}

fn compute_commit_id(
    seq: u64,
    parents: &[String],
    branch_hint: &str,
    message: &str,
    ops: &[WorldlineOp],
) -> Result<String, DagError> {
    let body = serde_json::to_vec(&CanonicalCommitBody {
        seq,
        parents,
        branch_hint,
        message,
        ops,
    })
    .map_err(|err| DagError::Validation(err.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(COMMIT_HASH_PREFIX);
    hasher.update(&body);
    Ok(hex::encode(&hasher.finalize()))
}

/// Deterministic materialized state `W(t) = (K(t), C(t), A(t), E(t), H(t))` at
/// any commit in the Worldline DAG.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldState {
    pub nodes: BTreeMap<String, Node>,
    pub contracts: BTreeMap<String, RealizationContract>,
    pub failures: BTreeMap<String, FailureRecord>,
    pub quarantine: BTreeMap<String, QuarantineItem>,
    pub verifications: Vec<VerificationEntry>,
}

impl WorldState {
    pub fn apply(&mut self, op: &WorldlineOp) -> Result<(), DagError> {
        op.validate().map_err(DagError::Validation)?;
        match op {
            WorldlineOp::UpsertNode { node } => {
                self.nodes.insert(node.id.clone(), (**node).clone());
            }
            WorldlineOp::UpsertContract { contract } => {
                let normalized = contract.clone().normalized().map_err(DagError::Validation)?;
                self.contracts.insert(normalized.id.clone(), normalized);
            }
            WorldlineOp::RecordFailure { failure } => {
                // Recording a failure against a contract automatically appends
                // its trigger to known failure boundaries if not already noted.
                if let Some(contract) = self.contracts.get_mut(&failure.target_id) {
                    if !contract.failure_boundary.contains(&failure.trigger) {
                        contract.failure_boundary.push(failure.trigger.clone());
                    }
                }
                self.failures
                    .insert(failure.id.clone(), (**failure).clone());
            }
            WorldlineOp::EnqueueExposure { item } => {
                self.quarantine.insert(item.id.clone(), (**item).clone());
            }
            WorldlineOp::ResolveExposure {
                exposure_id,
                resolved_by_node,
            } => {
                let item = self.quarantine.get_mut(exposure_id).ok_or_else(|| {
                    DagError::NotFound(format!("quarantine item '{exposure_id}'"))
                })?;
                if !self.nodes.contains_key(resolved_by_node) {
                    return Err(DagError::NotFound(format!(
                        "resolution node '{resolved_by_node}'"
                    )));
                }
                item.resolved_by_node = Some(resolved_by_node.clone());
            }
            WorldlineOp::RecordVerification { entry } => {
                let node = self
                    .nodes
                    .get_mut(&entry.node_id)
                    .ok_or_else(|| DagError::NotFound(format!("node '{}'", entry.node_id)))?;
                if !node.evidence_sha256.contains(&entry.evidence_sha256) {
                    node.evidence_sha256.push(entry.evidence_sha256.clone());
                }
                if entry.provenance != AssistanceProvenance::AiGenerated
                    && !node.proof_operators.contains(&entry.operator)
                {
                    node.proof_operators.push(entry.operator);
                }
                // Assistance-provenance law: AI-generated verification never
                // promotes a capability to Observed/Reproduced; joint verification
                // records a joint realization without crediting unassisted state H;
                // only unassisted human verification promotes an unassisted human capability.
                match entry.provenance {
                    AssistanceProvenance::UnassistedHuman => {
                        node.provenance = AssistanceProvenance::UnassistedHuman;
                        node.status = if node.status == EpistemicStatus::Reproduced
                            || (node.proof_operators.len() >= 2
                                && node.status == EpistemicStatus::Observed)
                        {
                            EpistemicStatus::Reproduced
                        } else {
                            EpistemicStatus::Observed
                        };
                    }
                    AssistanceProvenance::JointHumanAi | AssistanceProvenance::External => {
                        // Do not downgrade an already-verified unassisted human capability.
                        if !node.credits_unassisted_human_state() {
                            node.provenance = entry.provenance;
                            node.status = EpistemicStatus::Observed;
                        }
                    }
                    AssistanceProvenance::AiGenerated => {
                        if !node.status.is_verified() {
                            node.provenance = AssistanceProvenance::AiGenerated;
                            node.status = EpistemicStatus::Hypothesized;
                        }
                    }
                }
                node.validate().map_err(DagError::Validation)?;
                self.verifications.push((**entry).clone());
            }
        }
        Ok(())
    }

    /// Sovereign unassisted human capability set `H`: strictly those `Capability`
    /// nodes verified under `UnassistedHuman` provenance with evidence and at
    /// least one Akashi proof operator.
    pub fn unassisted_capabilities(&self) -> BTreeSet<String> {
        self.nodes
            .values()
            .filter(|n| n.credits_unassisted_human_state())
            .map(|n| n.id.clone())
            .collect()
    }

    /// Joint or externally assisted verified capabilities/realizations (valuable
    /// operational output, tracked separately from `H`).
    pub fn assisted_verified_nodes(&self) -> BTreeSet<String> {
        self.nodes
            .values()
            .filter(|n| {
                n.status.is_verified() && n.provenance != AssistanceProvenance::UnassistedHuman
            })
            .map(|n| n.id.clone())
            .collect()
    }

    /// Unresolved exposure items still sitting in the Epistemic Quarantine Queue.
    pub fn unresolved_quarantine(&self) -> Vec<&QuarantineItem> {
        self.quarantine
            .values()
            .filter(|q| q.resolved_by_node.is_none())
            .collect()
    }

    /// Compile the active CSR capability hypergraph for fast topological queries.
    pub fn hypergraph(&self) -> CsrHypergraph {
        CsrHypergraph::from_state(self)
    }
}

/// Branching, content-addressed Worldline Merkle-DAG document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Worldline {
    pub version: u32,
    pub head_branch: String,
    pub branches: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub commits: BTreeMap<String, Commit>,
}

impl Default for Worldline {
    fn default() -> Self {
        Self::new()
    }
}

impl Worldline {
    pub fn new() -> Self {
        Self {
            version: WORLDLINE_VERSION,
            head_branch: "main".into(),
            branches: BTreeMap::new(),
            tags: BTreeMap::new(),
            commits: BTreeMap::new(),
        }
    }

    /// Current commit ID of `head_branch`, or `None` for an empty genesis worldline.
    pub fn head_commit_id(&self) -> Option<&str> {
        self.branches.get(&self.head_branch).map(String::as_str)
    }

    /// Append a new commit onto `head_branch`, validating that all operations
    /// apply cleanly on top of the current branch state before committing.
    pub fn commit(
        &mut self,
        message: impl Into<String>,
        ops: Vec<WorldlineOp>,
        signer: Option<&Identity>,
    ) -> Result<String, DagError> {
        let parents: Vec<String> = self
            .head_commit_id()
            .map(|id| vec![id.to_owned()])
            .unwrap_or_default();
        self.append_commit_with_parents(parents, message.into(), ops, signer)
    }

    /// Create a new branch pointing at `from_commit` (or current `head_branch` tip).
    pub fn create_branch(
        &mut self,
        branch_name: &str,
        from_commit: Option<&str>,
    ) -> Result<String, DagError> {
        validate_id(branch_name).map_err(DagError::Validation)?;
        if self.branches.contains_key(branch_name) {
            return Err(DagError::Validation(format!(
                "branch '{branch_name}' already exists"
            )));
        }
        let target = match from_commit {
            Some(id) => id.to_owned(),
            None => self
                .head_commit_id()
                .ok_or_else(|| {
                    DagError::Validation("cannot branch before the first commit".into())
                })?
                .to_owned(),
        };
        if !self.commits.contains_key(&target) {
            return Err(DagError::NotFound(format!("commit '{target}'")));
        }
        self.branches.insert(branch_name.to_owned(), target.clone());
        Ok(target)
    }

    /// Switch `head_branch` to an existing branch.
    pub fn checkout(&mut self, branch_name: &str) -> Result<(), DagError> {
        if !self.branches.contains_key(branch_name) {
            return Err(DagError::NotFound(format!("branch '{branch_name}'")));
        }
        self.head_branch = branch_name.to_owned();
        Ok(())
    }

    /// Create a lightweight tag pointing to `commit_id`. Tags are immutable
    /// named references to commits, useful for marking releases or baselines.
    pub fn tag(&mut self, tag_name: &str, commit_id: &str) -> Result<(), DagError> {
        validate_id(tag_name).map_err(DagError::Validation)?;
        if self.tags.contains_key(tag_name) {
            return Err(DagError::Validation(format!(
                "tag '{tag_name}' already exists"
            )));
        }
        if !self.commits.contains_key(commit_id) {
            return Err(DagError::NotFound(format!("commit '{commit_id}'")));
        }
        self.tags.insert(tag_name.to_owned(), commit_id.to_owned());
        Ok(())
    }

    /// Resolve a tag name to its target commit ID.
    pub fn resolve_tag(&self, tag_name: &str) -> Result<&str, DagError> {
        self.tags
            .get(tag_name)
            .map(String::as_str)
            .ok_or_else(|| DagError::NotFound(format!("tag '{tag_name}'")))
    }

    /// List all tag names in sorted order.
    pub fn list_tags(&self) -> Vec<&str> {
        self.tags.keys().map(String::as_str).collect()
    }

    /// Deterministically merge `source_branch` into `head_branch`. Performs a
    /// fast-forward if `head` is an ancestor of `source`; otherwise creates a
    /// multi-parent merge commit recording `rationale`.
    pub fn merge(
        &mut self,
        source_branch: &str,
        rationale: impl Into<String>,
        signer: Option<&Identity>,
    ) -> Result<String, DagError> {
        let source_tip = self
            .branches
            .get(source_branch)
            .ok_or_else(|| DagError::NotFound(format!("branch '{source_branch}'")))?
            .clone();
        let Some(head_tip) = self.head_commit_id().map(str::to_owned) else {
            self.branches
                .insert(self.head_branch.clone(), source_tip.clone());
            return Ok(source_tip);
        };
        if head_tip == source_tip || self.is_ancestor(&source_tip, &head_tip)? {
            return Ok(head_tip);
        }
        if self.is_ancestor(&head_tip, &source_tip)? {
            self.branches
                .insert(self.head_branch.clone(), source_tip.clone());
            return Ok(source_tip);
        }
        let mut parents = vec![head_tip, source_tip];
        parents.sort();
        parents.dedup();
        self.append_commit_with_parents(parents, rationale.into(), Vec::new(), signer)
    }

    fn append_commit_with_parents(
        &mut self,
        mut parents: Vec<String>,
        message: String,
        ops: Vec<WorldlineOp>,
        signer: Option<&Identity>,
    ) -> Result<String, DagError> {
        if self.commits.len() >= MAX_COMMITS {
            return Err(DagError::Validation("worldline commit limit reached".into()));
        }
        if message.trim().is_empty() || message.len() > 1024 {
            return Err(DagError::Validation(
                "commit message must be 1..=1024 non-whitespace bytes".into(),
            ));
        }
        if ops.is_empty() && parents.len() < 2 {
            return Err(DagError::Validation(
                "non-merge commit must contain at least one operation".into(),
            ));
        }
        parents.sort();
        parents.dedup();
        let mut max_parent_seq = 0u64;
        for parent in &parents {
            let commit = self
                .commits
                .get(parent)
                .ok_or_else(|| DagError::NotFound(format!("parent commit '{parent}'")))?;
            max_parent_seq = max_parent_seq.max(commit.seq);
        }
        let seq = max_parent_seq + 1;

        // Dry-run causal replay + new ops before inserting the commit.
        let mut state = self.materialize_ancestors(&parents)?;
        for op in &ops {
            state.apply(op)?;
        }

        let id = compute_commit_id(seq, &parents, &self.head_branch, &message, &ops)?;
        if self.commits.contains_key(&id) {
            return Err(DagError::Validation(format!(
                "commit '{id}' already exists"
            )));
        }

        let (author_pubkey_hex, author_fingerprint, signature_hex) = if let Some(identity) = signer
        {
            let pk = identity.public_key_hex();
            let fp = identity.fingerprint();
            let sig = identity
                .sign_domain_hex(DOMAIN_WORLDLINE_COMMIT, id.as_bytes())
                .map_err(|err| DagError::Validation(err.to_string()))?;
            (Some(pk), Some(fp), Some(sig))
        } else {
            (None, None, None)
        };

        let commit = Commit {
            id: id.clone(),
            seq,
            parents,
            branch_hint: self.head_branch.clone(),
            message,
            ops,
            author_pubkey_hex,
            author_fingerprint,
            signature_hex,
        };
        self.commits.insert(id.clone(), commit);
        self.branches.insert(self.head_branch.clone(), id.clone());
        Ok(id)
    }

    fn ancestor_order(&self, tips: &[String]) -> Result<Vec<&Commit>, DagError> {
        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        for tip in tips {
            if visited.insert(tip.clone()) {
                queue.push_back(tip.clone());
            }
        }
        let mut list = Vec::new();
        while let Some(id) = queue.pop_front() {
            let commit = self
                .commits
                .get(&id)
                .ok_or_else(|| DagError::NotFound(format!("commit '{id}'")))?;
            for parent in &commit.parents {
                if visited.insert(parent.clone()) {
                    queue.push_back(parent.clone());
                }
            }
            list.push(commit);
        }
        // Canonical total order respecting causality: strictly increasing seq,
        // breaking concurrent branch ties by content-addressed commit ID.
        list.sort_by(|a, b| a.seq.cmp(&b.seq).then_with(|| a.id.cmp(&b.id)));
        Ok(list)
    }

    fn is_ancestor(&self, candidate: &str, tip: &str) -> Result<bool, DagError> {
        let ancestors = self.ancestor_order(&[tip.to_owned()])?;
        Ok(ancestors.iter().any(|c| c.id == candidate))
    }

    fn materialize_ancestors(&self, tips: &[String]) -> Result<WorldState, DagError> {
        let ordered = self.ancestor_order(tips)?;
        let mut state = WorldState::default();
        for commit in ordered {
            for op in &commit.ops {
                state.apply(op)?;
            }
        }
        Ok(state)
    }

    /// Materialize the exact World Model state at `commit_id`.
    pub fn materialize_at(&self, commit_id: &str) -> Result<WorldState, DagError> {
        if !self.commits.contains_key(commit_id) {
            return Err(DagError::NotFound(format!("commit '{commit_id}'")));
        }
        self.materialize_ancestors(&[commit_id.to_owned()])
    }

    /// Materialize the exact World Model state at `head_branch` (empty if no commits yet).
    pub fn materialize_head(&self) -> Result<WorldState, DagError> {
        match self.head_commit_id() {
            Some(tip) => self.materialize_at(tip),
            None => Ok(WorldState::default()),
        }
    }

    /// Return commits in canonical causal order for `branch_name` (or `head_branch`).
    pub fn log(&self, branch_name: Option<&str>) -> Result<Vec<&Commit>, DagError> {
        let name = branch_name.unwrap_or(&self.head_branch);
        let Some(tip) = self.branches.get(name) else {
            if name == self.head_branch && self.commits.is_empty() {
                return Ok(Vec::new());
            }
            return Err(DagError::NotFound(format!("branch '{name}'")));
        };
        self.ancestor_order(std::slice::from_ref(tip))
    }

    /// Verify every commit hash, parent link, topological sequence invariant,
    /// signature, branch reference, and deterministic replay across all branches.
    pub fn verify_all(&self, require_signatures: bool) -> Result<usize, DagError> {
        if self.version != WORLDLINE_VERSION {
            return Err(DagError::Integrity(format!(
                "unsupported worldline version {}",
                self.version
            )));
        }
        validate_id(&self.head_branch).map_err(DagError::Integrity)?;
        if !self.commits.is_empty() && !self.branches.contains_key(&self.head_branch) {
            return Err(DagError::Integrity(format!(
                "head branch '{}' is missing from branches table",
                self.head_branch
            )));
        }

        let mut signed_count = 0usize;
        for (key, commit) in &self.commits {
            if key != &commit.id {
                return Err(DagError::Integrity(format!(
                    "commit map key '{key}' does not match commit.id '{}'",
                    commit.id
                )));
            }
            validate_id(&commit.branch_hint).map_err(DagError::Integrity)?;
            if commit.message.trim().is_empty() || commit.message.len() > 1024 {
                return Err(DagError::Integrity(format!(
                    "commit '{}' has invalid message",
                    commit.id
                )));
            }
            if commit.ops.is_empty() && commit.parents.len() < 2 {
                return Err(DagError::Integrity(format!(
                    "non-merge commit '{}' has empty ops",
                    commit.id
                )));
            }
            // Verify sorted, unique parents with strictly lower seq (guarantees acyclicity).
            let mut max_parent_seq = 0u64;
            for (idx, parent_id) in commit.parents.iter().enumerate() {
                if idx > 0 && commit.parents[idx - 1] >= *parent_id {
                    return Err(DagError::Integrity(format!(
                        "commit '{}' parents are not strictly sorted and unique",
                        commit.id
                    )));
                }
                let parent = self.commits.get(parent_id).ok_or_else(|| {
                    DagError::Integrity(format!(
                        "commit '{}' references missing parent '{parent_id}'",
                        commit.id
                    ))
                })?;
                if parent.seq >= commit.seq {
                    return Err(DagError::Integrity(format!(
                        "commit '{}' violates causal sequence order against parent '{parent_id}'",
                        commit.id
                    )));
                }
                max_parent_seq = max_parent_seq.max(parent.seq);
            }
            if commit.seq != max_parent_seq + 1 {
                return Err(DagError::Integrity(format!(
                    "commit '{}' has seq {}, expected {}",
                    commit.id,
                    commit.seq,
                    max_parent_seq + 1
                )));
            }

            for op in &commit.ops {
                op.validate().map_err(DagError::Integrity)?;
            }

            let recomputed = compute_commit_id(
                commit.seq,
                &commit.parents,
                &commit.branch_hint,
                &commit.message,
                &commit.ops,
            )?;
            if recomputed != commit.id {
                return Err(DagError::Integrity(format!(
                    "commit '{}' failed SHA-256 content-address check (got '{recomputed}')",
                    commit.id
                )));
            }

            match (&commit.author_pubkey_hex, &commit.signature_hex) {
                (Some(pk_hex), Some(sig_hex)) => {
                    let pk = hex::decode_array::<32>(pk_hex)
                        .map_err(|_| DagError::Integrity("invalid author public key hex".into()))?;
                    if let Some(fp) = &commit.author_fingerprint {
                        if public_key_fingerprint(&pk) != *fp {
                            return Err(DagError::Integrity(
                                "commit author fingerprint mismatch".into(),
                            ));
                        }
                    }
                    verify_domain_hex(
                        pk_hex,
                        DOMAIN_WORLDLINE_COMMIT,
                        commit.id.as_bytes(),
                        sig_hex,
                    )
                    .map_err(|err| {
                        DagError::Integrity(format!(
                            "commit '{}' signature invalid: {err}",
                            commit.id
                        ))
                    })?;
                    signed_count += 1;
                }
                (None, None) if !require_signatures => {}
                _ => {
                    return Err(DagError::Integrity(format!(
                        "commit '{}' lacks a required valid Ed25519 signature",
                        commit.id
                    )));
                }
            }
        }

        for (branch, tip) in &self.branches {
            validate_id(branch).map_err(DagError::Integrity)?;
            if !self.commits.contains_key(tip) {
                return Err(DagError::Integrity(format!(
                    "branch '{branch}' points to unknown commit '{tip}'"
                )));
            }
            let _ = self.materialize_at(tip)?;
        }

        for (tag, target) in &self.tags {
            validate_id(tag).map_err(DagError::Integrity)?;
            if !self.commits.contains_key(target) {
                return Err(DagError::Integrity(format!(
                    "tag '{tag}' points to unknown commit '{target}'"
                )));
            }
        }

        Ok(signed_count)
    }

    /// Persist a validated Worldline DAG atomically via a synced temporary file.
    pub fn save(&self, path: &Path) -> Result<(), DagError> {
        let _ = self.verify_all(false)?;
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|err| DagError::Validation(err.to_string()))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_WORLDLINE_BYTES {
            return Err(DagError::Validation(
                "serialized worldline exceeds 16 MiB limit".into(),
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
        tmp.persist(path).map_err(|err| DagError::Io(err.error))?;
        Ok(())
    }

    /// Create a brand-new empty Worldline file without overwriting an existing path.
    pub fn create(path: &Path) -> Result<Self, DagError> {
        let wl = Self::new();
        let mut bytes =
            serde_json::to_vec_pretty(&wl).map_err(|err| DagError::Validation(err.to_string()))?;
        bytes.push(b'\n');
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
        tmp.persist_noclobber(path)
            .map_err(|err| DagError::Io(err.error))?;
        Ok(wl)
    }

    /// Read and cryptographically verify a Worldline file under a shared lock.
    pub fn load(path: &Path) -> Result<Self, DagError> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file: File = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(DagError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worldline is not a regular file",
            )));
        }
        fs2::FileExt::lock_shared(&file)?;
        let mut buf = Vec::new();
        file.take(MAX_WORLDLINE_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_WORLDLINE_BYTES {
            return Err(DagError::Integrity("worldline exceeds 16 MiB limit".into()));
        }
        let wl: Self =
            serde_json::from_slice(&buf).map_err(|err| DagError::Integrity(err.to_string()))?;
        let _ = wl.verify_all(false)?;
        Ok(wl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn sample_digest(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    #[test]
    fn signed_branching_merkle_dag_enforces_provenance_quarantine_and_tamper_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worldline.json");
        let id = Identity::recover(PHRASE, "").unwrap();

        let mut wl = Worldline::create(&path).unwrap();
        assert!(Worldline::create(&path).is_err());

        // 1. Ingest quarantined AI exposure + hypothesized capability (not yet in H).
        wl.commit(
            "Quarantine NotebookLM exposure on explicit Euler",
            vec![
                WorldlineOp::EnqueueExposure {
                    item: Box::new(QuarantineItem {
                        id: "exp-euler-1".into(),
                        source: "henosis-proxy".into(),
                        topic: "Explicit Euler ODE stability".into(),
                        prompt_sha256: Some(sample_digest('a')),
                        notes: "Read summary; unverified exposure".into(),
                        resolved_by_node: None,
                    }),
                },
                WorldlineOp::UpsertNode {
                    node: Box::new(Node {
                        id: "euler-solver".into(),
                        kind: EntityKind::Capability,
                        title: "Implement explicit Euler solver".into(),
                        domain: "numerical-analysis".into(),
                        summary: "First-order time integration of scalar ODEs".into(),
                        status: EpistemicStatus::Hypothesized,
                        provenance: AssistanceProvenance::External,
                        evidence_sha256: vec![],
                        proof_operators: vec![],
                    }),
                },
            ],
            Some(&id),
        )
        .unwrap();

        let s1 = wl.materialize_head().unwrap();
        assert!(s1.unassisted_capabilities().is_empty());
        assert_eq!(s1.unresolved_quarantine().len(), 1);

        // 2. Joint AI-assisted realization does NOT promote unassisted human state H!
        wl.commit(
            "Log joint implementation with coding agent",
            vec![WorldlineOp::RecordVerification {
                entry: Box::new(VerificationEntry {
                    node_id: "euler-solver".into(),
                    operator: ProofOperator::Implement,
                    provenance: AssistanceProvenance::JointHumanAi,
                    evidence_sha256: sample_digest('b'),
                    proxy_blackout_verified: false,
                    summary: "Built prototype with AI assistance".into(),
                }),
            }],
            Some(&id),
        )
        .unwrap();
        let s2 = wl.materialize_head().unwrap();
        assert!(s2.unassisted_capabilities().is_empty());
        assert!(s2.assisted_verified_nodes().contains("euler-solver"));

        // 3. Branch to test stiff instability boundary and record Failure Atlas entry.
        wl.create_branch("stiff-regime", None).unwrap();
        wl.checkout("stiff-regime").unwrap();
        wl.commit(
            "Expose explicit Euler blow-up at dt=0.25",
            vec![WorldlineOp::RecordFailure {
                failure: Box::new(FailureRecord {
                    id: "fail-cfl-1".into(),
                    target_id: "euler-solver".into(),
                    broken_assumption: "|1 - lambda*dt| < 1".into(),
                    trigger: "lambda=10, dt=0.25 (|1 - 2.5| = 1.5 > 1)".into(),
                    predicted: "Oscillatory divergence".into(),
                    observed: "Exited non-zero with alternating amplitude growth".into(),
                    evidence_sha256: Some(sample_digest('c')),
                }),
            }],
            Some(&id),
        )
        .unwrap();

        // 4. On main, pass unassisted cleanroom Reconstruct proof and resolve quarantine.
        wl.checkout("main").unwrap();
        assert!(wl.materialize_head().unwrap().failures.is_empty());
        wl.commit(
            "Cleanroom derivation and failure prediction",
            vec![
                WorldlineOp::RecordVerification {
                    entry: Box::new(VerificationEntry {
                        node_id: "euler-solver".into(),
                        operator: ProofOperator::Reconstruct,
                        provenance: AssistanceProvenance::UnassistedHuman,
                        evidence_sha256: sample_digest('d'),
                        proxy_blackout_verified: true,
                        summary: "Derived amplification factor G = 1 - lambda*dt independently"
                            .into(),
                    }),
                },
                WorldlineOp::ResolveExposure {
                    exposure_id: "exp-euler-1".into(),
                    resolved_by_node: "euler-solver".into(),
                },
            ],
            Some(&id),
        )
        .unwrap();

        // 5. Merge rival branch into main; both verified capability AND Failure Atlas coexist!
        wl.merge(
            "stiff-regime",
            "Integrate stability failure boundary into main worldline",
            Some(&id),
        )
        .unwrap();
        let signed = wl.verify_all(true).unwrap();
        assert_eq!(signed, 5);
        wl.save(&path).unwrap();

        let reloaded = Worldline::load(&path).unwrap();
        assert_eq!(reloaded, wl);
        let final_state = reloaded.materialize_head().unwrap();
        assert!(final_state.unassisted_capabilities().contains("euler-solver"));
        assert_eq!(
            final_state.nodes["euler-solver"].status,
            EpistemicStatus::Reproduced
        );
        assert!(final_state.failures.contains_key("fail-cfl-1"));
        assert!(final_state.unresolved_quarantine().is_empty());

        // 6. Flipping one word in a saved commit is caught by content-address verification.
        let tampered = std::fs::read_to_string(&path)
            .unwrap()
            .replace("Oscillatory divergence", "Monotonic convergence");
        std::fs::write(&path, tampered).unwrap();
        assert!(matches!(Worldline::load(&path), Err(DagError::Integrity(_))));
    }

    #[test]
    fn forbids_unverified_or_ai_only_capability_claiming_verified_status() {
        let bad_no_ev = Node {
            id: "fake-cap".into(),
            kind: EntityKind::Capability,
            title: "Fake".into(),
            domain: "math".into(),
            summary: String::new(),
            status: EpistemicStatus::Observed,
            provenance: AssistanceProvenance::UnassistedHuman,
            evidence_sha256: vec![],
            proof_operators: vec![ProofOperator::Explain],
        };
        assert!(bad_no_ev.validate().is_err());

        let bad_ai = Node {
            evidence_sha256: vec![sample_digest('1')],
            provenance: AssistanceProvenance::AiGenerated,
            ..bad_no_ev
        };
        assert!(bad_ai.validate().is_err());
    }
}
