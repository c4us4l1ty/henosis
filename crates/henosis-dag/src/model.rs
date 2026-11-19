//! Foundational ontology, strict epistemic typing, assistance provenance,
//! realization contracts, failure atlas entries, and worldline operations.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The eleven load-bearing entity kinds of the Henosis World Model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Concept,
    Method,
    Capability,
    Problem,
    Constraint,
    Instrument,
    Realization,
    Evidence,
    Hypothesis,
    Opportunity,
    Failure,
}

impl EntityKind {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "concept" => Ok(Self::Concept),
            "method" => Ok(Self::Method),
            "capability" => Ok(Self::Capability),
            "problem" => Ok(Self::Problem),
            "constraint" => Ok(Self::Constraint),
            "instrument" => Ok(Self::Instrument),
            "realization" => Ok(Self::Realization),
            "evidence" => Ok(Self::Evidence),
            "hypothesis" => Ok(Self::Hypothesis),
            "opportunity" => Ok(Self::Opportunity),
            "failure" => Ok(Self::Failure),
            _ => Err(format!("unknown entity kind '{value}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Concept => "concept",
            Self::Method => "method",
            Self::Capability => "capability",
            Self::Problem => "problem",
            Self::Constraint => "constraint",
            Self::Instrument => "instrument",
            Self::Realization => "realization",
            Self::Evidence => "evidence",
            Self::Hypothesis => "hypothesis",
            Self::Opportunity => "opportunity",
            Self::Failure => "failure",
        }
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Strict epistemic status preventing speculation from masquerading as verified observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicStatus {
    Unknown,
    Hypothesized,
    Inferred,
    Observed,
    Reproduced,
    Contested,
    Refuted,
}

impl EpistemicStatus {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "hypothesized" => Ok(Self::Hypothesized),
            "inferred" => Ok(Self::Inferred),
            "observed" => Ok(Self::Observed),
            "reproduced" => Ok(Self::Reproduced),
            "contested" => Ok(Self::Contested),
            "refuted" => Ok(Self::Refuted),
            _ => Err(format!("unknown epistemic status '{value}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Hypothesized => "hypothesized",
            Self::Inferred => "inferred",
            Self::Observed => "observed",
            Self::Reproduced => "reproduced",
            Self::Contested => "contested",
            Self::Refuted => "refuted",
        }
    }

    pub fn is_verified(self) -> bool {
        matches!(self, Self::Observed | Self::Reproduced)
    }
}

impl fmt::Display for EpistemicStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Assistance-provenance decomposition `E = (E_human, E_ai, E_joint, E_external)`.
/// Only `UnassistedHuman` with verified status and evidence credits the sovereign
/// unassisted capability state `H`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistanceProvenance {
    UnassistedHuman,
    JointHumanAi,
    AiGenerated,
    External,
}

impl AssistanceProvenance {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "human" | "unassisted_human" => Ok(Self::UnassistedHuman),
            "joint" | "joint_human_ai" => Ok(Self::JointHumanAi),
            "ai" | "ai_generated" => Ok(Self::AiGenerated),
            "external" => Ok(Self::External),
            _ => Err(format!(
                "unknown provenance '{value}' (expected human, joint, ai, or external)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnassistedHuman => "unassisted_human",
            Self::JointHumanAi => "joint_human_ai",
            Self::AiGenerated => "ai_generated",
            Self::External => "external",
        }
    }
}

impl fmt::Display for AssistanceProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The seven composable verification operators of Akashi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofOperator {
    Explain,
    Reconstruct,
    Implement,
    Criticize,
    Modify,
    Transfer,
    PredictFailure,
}

impl ProofOperator {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "explain" => Ok(Self::Explain),
            "reconstruct" => Ok(Self::Reconstruct),
            "implement" => Ok(Self::Implement),
            "criticize" => Ok(Self::Criticize),
            "modify" => Ok(Self::Modify),
            "transfer" => Ok(Self::Transfer),
            "predict_failure" | "predict-failure" => Ok(Self::PredictFailure),
            _ => Err(format!("unknown proof operator '{value}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explain => "explain",
            Self::Reconstruct => "reconstruct",
            Self::Implement => "implement",
            Self::Criticize => "criticize",
            Self::Modify => "modify",
            Self::Transfer => "transfer",
            Self::PredictFailure => "predict_failure",
        }
    }
}

impl fmt::Display for ProofOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Validate a portable identifier slug (`[a-z0-9][a-z0-9._:-]{0,95}`).
pub fn validate_id(id: &str) -> Result<(), String> {
    let ok = !id.is_empty()
        && id.len() <= 96
        && id.bytes().enumerate().all(|(idx, b)| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || (idx > 0 && matches!(b, b'-' | b'_' | b'.' | b':'))
        });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid identifier '{id}': must be 1..=96 lowercase ASCII [a-z0-9._:-] starting with alphanumeric"
        ))
    }
}

pub fn validate_sha256_hex(digest: &str) -> Result<(), String> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err("expected 64-character lowercase hexadecimal SHA-256 digest".into())
    }
}

/// A typed entity in the World Model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub kind: EntityKind,
    pub title: String,
    pub domain: String,
    pub summary: String,
    pub status: EpistemicStatus,
    pub provenance: AssistanceProvenance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_sha256: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proof_operators: Vec<ProofOperator>,
}

impl Node {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        if self.title.trim().is_empty() || self.title.len() > 256 {
            return Err("node title must be 1..=256 non-whitespace bytes".into());
        }
        if self.domain.trim().is_empty() || self.domain.len() > 128 {
            return Err("node domain must be 1..=128 non-whitespace bytes".into());
        }
        if self.summary.len() > 4096 {
            return Err("node summary exceeds 4096 bytes".into());
        }
        for digest in &self.evidence_sha256 {
            validate_sha256_hex(digest)?;
        }
        // Core epistemic invariant: verified capabilities require concrete evidence
        // and cannot derive from raw AI output alone.
        if self.kind == EntityKind::Capability && self.status.is_verified() {
            if self.evidence_sha256.is_empty() {
                return Err(format!(
                    "capability '{}' cannot be marked {} without at least one evidence digest",
                    self.id, self.status
                ));
            }
            if self.provenance == AssistanceProvenance::AiGenerated {
                return Err(format!(
                    "capability '{}' with ai_generated provenance cannot be marked verified",
                    self.id
                ));
            }
            if self.provenance == AssistanceProvenance::UnassistedHuman
                && self.proof_operators.is_empty()
            {
                return Err(format!(
                    "unassisted human capability '{}' requires at least one Akashi proof operator",
                    self.id
                ));
            }
        }
        Ok(())
    }

    /// Returns `true` iff this node belongs to the user's verified unassisted
    /// human capability state `H`.
    pub fn credits_unassisted_human_state(&self) -> bool {
        self.kind == EntityKind::Capability
            && self.status.is_verified()
            && self.provenance == AssistanceProvenance::UnassistedHuman
            && !self.evidence_sha256.is_empty()
            && !self.proof_operators.is_empty()
    }
}

/// Directed hyperedge `e = (P, A, R, O, V, Sigma)` encoding a conditional
/// multi-capability realization contract. Existence of a contract never certifies
/// its claim; check `status` and linked failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealizationContract {
    pub id: String,
    pub title: String,
    /// `P`: required capabilities/methods that must co-occur simultaneously.
    pub prerequisites: Vec<String>,
    /// `A`: assumptions and operating-regime preconditions.
    pub assumptions: Vec<String>,
    /// `R`: required instruments, datasets, compute, or resources.
    pub resources: Vec<String>,
    /// `O`: resulting capability, operation, or problem node made realizable.
    pub output: String,
    /// `V`: domain-appropriate verification test procedure.
    pub verification: String,
    /// `Sigma`: known failure boundaries and breakdown regimes.
    pub failure_boundary: Vec<String>,
    pub status: EpistemicStatus,
    /// Estimated effort/resource units (>= 1). Ordinal estimate, not exact cost.
    pub cost_units: u32,
}

impl RealizationContract {
    /// Normalize prerequisite ordering/deduplication and check invariants.
    pub fn normalized(mut self) -> Result<Self, String> {
        self.prerequisites.sort();
        self.prerequisites.dedup();
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        validate_id(&self.output)?;
        if self.title.trim().is_empty() || self.title.len() > 256 {
            return Err("contract title must be 1..=256 non-whitespace bytes".into());
        }
        if self.verification.trim().is_empty() || self.verification.len() > 2048 {
            return Err("contract verification procedure must be 1..=2048 bytes".into());
        }
        if self.cost_units == 0 {
            return Err("contract cost_units must be at least 1".into());
        }
        if self.prerequisites.len() > 64 {
            return Err("contract cannot list more than 64 prerequisites".into());
        }
        for pre in &self.prerequisites {
            validate_id(pre)?;
            if pre == &self.output {
                return Err(format!(
                    "contract '{}' cannot list its own output '{}' as a prerequisite",
                    self.id, self.output
                ));
            }
        }
        Ok(())
    }
}

/// First-class entry in the Failure Atlas recording where a claim or solver broke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureRecord {
    pub id: String,
    pub target_id: String,
    pub broken_assumption: String,
    pub trigger: String,
    pub predicted: String,
    pub observed: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
}

impl FailureRecord {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        validate_id(&self.target_id)?;
        if self.broken_assumption.trim().is_empty() || self.trigger.trim().is_empty() {
            return Err("failure record requires non-empty broken_assumption and trigger".into());
        }
        if self.observed.trim().is_empty() {
            return Err("failure record requires non-empty observed outcome".into());
        }
        if let Some(digest) = &self.evidence_sha256 {
            validate_sha256_hex(digest)?;
        }
        Ok(())
    }
}

/// Quarantined exposure from reading, external tools, or AI proxy sessions.
/// Never contributes to verified capability until resolved through Akashi.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineItem {
    pub id: String,
    pub source: String,
    pub topic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_sha256: Option<String>,
    pub notes: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by_node: Option<String>,
}

impl QuarantineItem {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        if self.source.trim().is_empty() || self.topic.trim().is_empty() {
            return Err("quarantine item requires non-empty source and topic".into());
        }
        if let Some(digest) = &self.prompt_sha256 {
            validate_sha256_hex(digest)?;
        }
        if let Some(node) = &self.resolved_by_node {
            validate_id(node)?;
        }
        Ok(())
    }
}

/// Recorded verification event linking a node to an operator, provenance, and evidence digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEntry {
    pub node_id: String,
    pub operator: ProofOperator,
    pub provenance: AssistanceProvenance,
    pub evidence_sha256: String,
    pub proxy_blackout_verified: bool,
    pub summary: String,
}

impl VerificationEntry {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.node_id)?;
        validate_sha256_hex(&self.evidence_sha256)?;
        if self.summary.trim().is_empty() || self.summary.len() > 2048 {
            return Err("verification summary must be 1..=2048 non-whitespace bytes".into());
        }
        Ok(())
    }
}

/// Atomic state-transition operation stored in a Worldline Merkle-DAG commit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorldlineOp {
    UpsertNode { node: Box<Node> },
    UpsertContract { contract: Box<RealizationContract> },
    RecordFailure { failure: Box<FailureRecord> },
    EnqueueExposure { item: Box<QuarantineItem> },
    ResolveExposure { exposure_id: String, resolved_by_node: String },
    RecordVerification { entry: Box<VerificationEntry> },
}

impl WorldlineOp {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::UpsertNode { node } => node.validate(),
            Self::UpsertContract { contract } => contract.validate(),
            Self::RecordFailure { failure } => failure.validate(),
            Self::EnqueueExposure { item } => item.validate(),
            Self::ResolveExposure {
                exposure_id,
                resolved_by_node,
            } => {
                validate_id(exposure_id)?;
                validate_id(resolved_by_node)
            }
            Self::RecordVerification { entry } => entry.validate(),
        }
    }
}
