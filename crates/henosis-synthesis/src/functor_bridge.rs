//! Functorial Bridge: algebraic-property-preserving structure transfer between
//! two Henosis world models.
//!
//! A `StructuralSignature` captures the shape of a structure: its node kinds,
//! operation arities, and algebraic properties. A functor between two
//! signatures must map every source element to a target element of matching
//! arity and must preserve every property the source declares. The backtracking
//! solver searches assignments conservatively: it rejects on the first
//! property-preservation failure and never invents target structure that the
//! source does not warrant.
//!
//! The Three-Part Transfer Gate extracts signatures, solves for a functor, and
//! accepts or rejects the transfer. The spurious-novelty Rejection Filter
//! rejects transfers whose target introduces structure not accounted for by the
//! source — novelty must be established through Akashi, not smuggled across a
//! bridge.

use henosis_dag::validate_id;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_SIGNATURE_ELEMENTS: usize = 64;
const MAX_BACKTRACKING_NODES: u64 = 50_000;

/// Algebraic properties a structure may declare. Preservation is directional:
/// if the source has property `P`, the target must also have `P`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlgebraicProperty {
    Associative,
    Commutative,
    Idempotent,
    Invertible,
    Distributive,
    Cancellative,
    Unital,
    Absorptive,
    Identity,
    Inverse,
}

impl AlgebraicProperty {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "associative" => Ok(Self::Associative),
            "commutative" => Ok(Self::Commutative),
            "idempotent" => Ok(Self::Idempotent),
            "invertible" => Ok(Self::Invertible),
            "distributive" => Ok(Self::Distributive),
            "cancellative" => Ok(Self::Cancellative),
            "unital" => Ok(Self::Unital),
            "absorptive" => Ok(Self::Absorptive),
            "identity" => Ok(Self::Identity),
            "inverse" => Ok(Self::Inverse),
            _ => Err(format!("unknown algebraic property '{value}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Associative => "associative",
            Self::Commutative => "commutative",
            Self::Idempotent => "idempotent",
            Self::Invertible => "invertible",
            Self::Distributive => "distributive",
            Self::Cancellative => "cancellative",
            Self::Unital => "unital",
            Self::Absorptive => "absorptive",
            Self::Identity => "identity",
            Self::Inverse => "inverse",
        }
    }
}

/// Compressed shape of a structure suitable for exact functor comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralSignature {
    pub structure_id: String,
    /// Sorted node kind identifiers (e.g. `["concept", "method", "capability"]`).
    pub node_kinds: Vec<String>,
    /// Operation name -> arity, sorted by name.
    pub operations: Vec<(String, u32)>,
    /// Declared algebraic properties.
    pub properties: BTreeSet<AlgebraicProperty>,
}

impl StructuralSignature {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.structure_id)?;
        if self.node_kinds.len() > MAX_SIGNATURE_ELEMENTS
            || self.operations.len() > MAX_SIGNATURE_ELEMENTS
        {
            return Err("signature exceeds the element bound".into());
        }
        let mut seen_kinds = BTreeSet::new();
        for kind in &self.node_kinds {
            if kind.trim().is_empty() {
                return Err("signature node kinds must be non-empty".into());
            }
            if !seen_kinds.insert(kind.clone()) {
                return Err(format!("duplicate node kind '{kind}'"));
            }
        }
        let mut seen_ops = BTreeSet::new();
        for (name, arity) in &self.operations {
            if name.trim().is_empty() {
                return Err("signature operation names must be non-empty".into());
            }
            if *arity > 16 {
                return Err(format!("operation '{name}' arity exceeds 16"));
            }
            if !seen_ops.insert(name.clone()) {
                return Err(format!("duplicate operation '{name}'"));
            }
        }
        Ok(())
    }
}

/// A candidate functor: maps every source element identifier to a target
/// element identifier. Object mapping and operation mapping share one namespace
/// of element identifiers for this bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Functor {
    pub source_structure: String,
    pub target_structure: String,
    /// Source element id -> target element id.
    pub mapping: BTreeMap<String, String>,
}

impl Functor {
    pub fn is_empty(&self) -> bool {
        self.mapping.is_empty()
    }
}

/// Why a transfer was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    ArityMismatch,
    PropertyNotPreserved,
    SpuriousNovelty,
    NoFunctorExists,
    UnboundedSearch,
}

impl RejectionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ArityMismatch => "arity_mismatch",
            Self::PropertyNotPreserved => "property_not_preserved",
            Self::SpuriousNovelty => "spurious_novelty",
            Self::NoFunctorExists => "no_functor_exists",
            Self::UnboundedSearch => "unbounded_search",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    pub accepted: bool,
    pub functor: Option<Functor>,
    pub preserved_properties: Vec<AlgebraicProperty>,
    pub violations: Vec<RejectionReason>,
    pub rejected_target_elements: Vec<String>,
}

/// Backtracking state for the functor search.
struct Search<'a> {
    source: &'a StructuralSignature,
    target: &'a StructuralSignature,
    // Ordered source elements still to assign (operation names then node kinds).
    pending: Vec<usize>,
    // Target elements already consumed (injectivity: one target per source).
    used: BTreeSet<usize>,
    mapping: BTreeMap<String, String>,
    nodes: u64,
    limit: u64,
}

impl<'a> Search<'a> {
    fn new(source: &'a StructuralSignature, target: &'a StructuralSignature) -> Self {
        let mut pending: Vec<usize> = (0..source.operations.len() + source.node_kinds.len()).collect();
        // Most constrained first: operations with rare arities go early.
        pending.sort_by_cached_key(|&i| {
            if i < source.operations.len() {
                let arity = source.operations[i].1;
                let count = target
                    .operations
                    .iter()
                    .filter(|(_, a)| *a == arity)
                    .count();
                (count, i)
            } else {
                (target.node_kinds.len(), i)
            }
        });
        Self {
            source,
            target,
            pending,
            used: BTreeSet::new(),
            mapping: BTreeMap::new(),
            nodes: 0,
            limit: MAX_BACKTRACKING_NODES,
        }
    }

    fn element_name(&self, index: usize) -> &str {
        if index < self.source.operations.len() {
            &self.source.operations[index].0
        } else {
            &self.source.node_kinds[index - self.source.operations.len()]
        }
    }

    fn target_arity_matches(&self, source_op_index: usize, target_index: usize) -> bool {
        let source_arity = self.source.operations[source_op_index].1;
        self.target.operations[target_index].1 == source_arity
    }

    fn recurse(&mut self) -> Option<BTreeMap<String, String>> {
        self.nodes += 1;
        if self.nodes > self.limit {
            return None;
        }
        if self.pending.is_empty() {
            return Some(self.mapping.clone());
        }
        let source_index = self.pending.remove(0);
        let name = self.element_name(source_index).to_owned();

        // Candidate target indices: same arity for operations, any free kind slot otherwise.
        let candidates: Vec<usize> = if source_index < self.source.operations.len() {
            self.target
                .operations
                .iter()
                .enumerate()
                .filter(|(t, _)| !self.used.contains(t))
                .filter(|(t, _)| self.target_arity_matches(source_index, *t))
                .map(|(t, _)| t)
                .collect()
        } else {
            (0..self.target.node_kinds.len())
                .filter(|t| !self.used.contains(t))
                .collect()
        };

        for t in candidates {
            self.used.insert(t);
            let target_name = if source_index < self.source.operations.len() {
                self.target.operations[t].0.clone()
            } else {
                self.target.node_kinds[t].clone()
            };
            self.mapping.insert(name.clone(), target_name.clone());

            if self.properties_still_preservable() {
                if let Some(result) = self.recurse() {
                    return Some(result);
                }
            }

            self.mapping.remove(&name);
            self.used.remove(&t);
        }

        self.pending.insert(0, source_index);
        None
    }

    /// Prune early: every source property must have a plausible target
    /// counterpart. Since properties are global (not per-element), check once
    /// all assignments are done is cheaper; here we only check the quick
    /// necessary condition that target declares at least the source's cardinality
    /// of each property class — properties are sets, so this is a placeholder
    /// validated fully in `verify_functor`.
    fn properties_still_preservable(&self) -> bool {
        // Full property check is done at leaf nodes to keep backtracking cheap.
        true
    }
}

/// Verify a complete functor preserves all source properties in the target.
fn verify_functor(
    source: &StructuralSignature,
    target: &StructuralSignature,
) -> Vec<AlgebraicProperty> {
    let mut missing = Vec::new();
    for prop in &source.properties {
        if !target.properties.contains(prop) {
            missing.push(*prop);
        }
    }
    missing
}

/// Solve for a property-preserving functor from source to target, if one exists.
pub fn solve_functor(
    source: &StructuralSignature,
    target: &StructuralSignature,
) -> Result<Functor, RejectionReason> {
    source.validate().map_err(|_| RejectionReason::NoFunctorExists)?;
    target.validate().map_err(|_| RejectionReason::NoFunctorExists)?;

    if source.properties.is_empty() && source.operations.is_empty() && source.node_kinds.is_empty() {
        return Ok(Functor {
            source_structure: source.structure_id.clone(),
            target_structure: target.structure_id.clone(),
            mapping: BTreeMap::new(),
        });
    }

    // Necessary condition: target must declare every source property.
    for prop in &source.properties {
        if !target.properties.contains(prop) {
            return Err(RejectionReason::PropertyNotPreserved);
        }
    }

    // Necessary condition: every source operation arity must exist in target.
    for (_, arity) in &source.operations {
        if !target.operations.iter().any(|(_, a)| a == arity) {
            return Err(RejectionReason::ArityMismatch);
        }
    }

    let mut search = Search::new(source, target);
    let mapping = search.recurse().ok_or(RejectionReason::UnboundedSearch)?;
    let missing = verify_functor(source, target);
    if !missing.is_empty() {
        return Err(RejectionReason::PropertyNotPreserved);
    }

    Ok(Functor {
        source_structure: source.structure_id.clone(),
        target_structure: target.structure_id.clone(),
        mapping,
    })
}

/// Check whether `target` introduces elements or properties not covered by the
/// source functor's mapping — spurious novelty that the bridge must not ratify.
pub fn spurious_novelty(
    functor: &Functor,
    source: &StructuralSignature,
    target: &StructuralSignature,
) -> Vec<String> {
    let mut novel = Vec::new();
    let mapped_targets: BTreeSet<String> = functor.mapping.values().cloned().collect();
    for (name, _) in &target.operations {
        if !mapped_targets.contains(name) {
            novel.push(format!("operation '{name}'"));
        }
    }
    for kind in &target.node_kinds {
        if !mapped_targets.contains(kind) {
            novel.push(format!("node kind '{kind}'"));
        }
    }
    for prop in &target.properties {
        if !source.properties.contains(prop) {
            novel.push(format!("property '{}'", prop.as_str()));
        }
    }
    novel.sort();
    novel.dedup();
    novel
}

/// Three-Part Transfer Gate: (1) extract signatures, (2) solve functor,
/// (3) accept only if no spurious novelty and all properties preserved.
pub fn transfer_gate(
    source: &StructuralSignature,
    target: &StructuralSignature,
) -> Result<GateResult, RejectionReason> {
    let mut violations = Vec::new();

    // Part 1: signatures validated on entry.

    // Part 2: solve functor.
    let functor = match solve_functor(source, target) {
        Ok(f) => f,
        Err(reason) => {
            violations.push(reason);
            return Ok(GateResult {
                accepted: false,
                functor: None,
                preserved_properties: source.properties.iter().copied().collect(),
                violations,
                rejected_target_elements: spurious_novelty_dummy(source, target),
            });
        }
    };

    let preserved: Vec<AlgebraicProperty> = source
        .properties
        .iter()
        .filter(|p| target.properties.contains(*p))
        .copied()
        .collect();

    // Part 3: spurious-novelty rejection filter.
    let novel = spurious_novelty(&functor, source, target);
    if !novel.is_empty() {
        violations.push(RejectionReason::SpuriousNovelty);
        return Ok(GateResult {
            accepted: false,
            functor: Some(functor),
            preserved_properties: preserved,
            violations,
            rejected_target_elements: novel,
        });
    }

    if preserved.len() != source.properties.len() {
        violations.push(RejectionReason::PropertyNotPreserved);
        return Ok(GateResult {
            accepted: false,
            functor: Some(functor),
            preserved_properties: preserved,
            violations,
            rejected_target_elements: novel,
        });
    }

    Ok(GateResult {
        accepted: true,
        functor: Some(functor),
        preserved_properties: preserved,
        violations,
        rejected_target_elements: Vec::new(),
    })
}

/// Fallback listing of target elements when a gate rejects before a functor
/// exists (kept deterministic and side-effect free).
fn spurious_novelty_dummy(source: &StructuralSignature, target: &StructuralSignature) -> Vec<String> {
    let mut novel = Vec::new();
    for prop in &target.properties {
        if !source.properties.contains(prop) {
            novel.push(format!("property '{}'", prop.as_str()));
        }
    }
    novel.sort();
    novel.dedup();
    novel
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature(id: &str, ops: &[(&str, u32)], kinds: &[&str], props: &[&str]) -> StructuralSignature {
        StructuralSignature {
            structure_id: id.into(),
            node_kinds: kinds.iter().map(|s| (*s).to_owned()).collect(),
            operations: ops.iter().map(|(n, a)| ((*n).to_owned(), *a)).collect(),
            properties: props.iter().map(|s| AlgebraicProperty::parse(s).unwrap()).collect(),
        }
    }

    #[test]
    fn property_preserving_transfer_is_accepted() {
        let source = signature("s", &[("op", 2)], &["A"], &["associative", "commutative"]);
        let target = signature("t", &[("op", 2)], &["A", "B"], &["associative", "commutative", "unital"]);
        let result = transfer_gate(&source, &target).unwrap();
        assert!(result.accepted);
        assert!(result.functor.is_some());
        assert_eq!(result.rejected_target_elements, Vec::<String>::new());
    }

    #[test]
    fn missing_property_is_rejected() {
        let source = signature("s", &[("op", 2)], &["A"], &["associative"]);
        let target = signature("t", &[("op", 2)], &["A"], &[]);
        let result = transfer_gate(&source, &target).unwrap();
        assert!(!result.accepted);
        assert!(result.violations.contains(&RejectionReason::PropertyNotPreserved));
    }

    #[test]
    fn arity_mismatch_is_rejected() {
        let source = signature("s", &[("op", 3)], &["A"], &[]);
        let target = signature("t", &[("op", 2)], &["A"], &[]);
        assert!(matches!(
            transfer_gate(&source, &target),
            Err(RejectionReason::ArityMismatch)
        ));
    }

    #[test]
    fn spurious_novelty_is_flagged() {
        let source = signature("s", &[("op", 2)], &["A"], &["associative"]);
        let target = signature("t", &[("op", 2), ("extra", 0)], &["A"], &["associative", "idempotent"]);
        let functor = solve_functor(&source, &target).unwrap();
        let novel = spurious_novelty(&functor, &source, &target);
        assert!(novel.iter().any(|n| n.contains("extra")));
        assert!(novel.iter().any(|n| n.contains("idempotent")));
    }
}
