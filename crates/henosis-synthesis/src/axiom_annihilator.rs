//! Axiom Annihilator: epistemic leveling and the exact minimal hitting-set
//! Lobachevsky operator.
//!
//! Axioms are classified into three regimes:
//!   * Level 0 Iron — immutable laws (e.g. thermodynamics); never annihilatable.
//!   * Level 1 Empirical Regime — contingent best models; revisable with evidence.
//!   * Level 2 Convention — coordination choices; freely revisable.
//!
//! The Lobachevsky operator receives a set of axioms plus recorded conflicts
//! (sets of axioms that cannot hold simultaneously) and returns every exact
//! minimal hitting set: smallest subsets of axioms whose removal resolves all
//! conflicts. Iron axioms are guarded and can never be selected. This is an
//! exact, exponential search bounded to small axiom sets; it is a decision aid,
//! not a license to delete inconvenient truths.

use combination::Combination;
use henosis_crux::Event;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_AXIOM_COUNT: usize = 24;
const MAX_COMBINATION_CHECKS: u64 = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AxiomLevel {
    /// Level 0: iron law. Guarded; cannot be annihilated.
    Iron,
    /// Level 1: empirical regime. Revisable only with evidence.
    EmpiricalRegime,
    /// Level 2: convention. Freely revisable.
    Convention,
}

impl AxiomLevel {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "iron" | "level-0" | "level_0" => Ok(Self::Iron),
            "empirical_regime" | "empirical" | "level-1" | "level_1" => Ok(Self::EmpiricalRegime),
            "convention" | "level-2" | "level_2" => Ok(Self::Convention),
            _ => Err(format!("unknown axiom level '{value}' (expected iron, empirical_regime, convention)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Iron => "iron",
            Self::EmpiricalRegime => "empirical_regime",
            Self::Convention => "convention",
        }
    }

    pub fn annihilatable(self) -> bool {
        matches!(self, Self::EmpiricalRegime | Self::Convention)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Axiom {
    pub id: String,
    pub statement: String,
    pub level: AxiomLevel,
}

impl Axiom {
    pub fn validate(&self) -> Result<(), String> {
        iron_law_guard::validate_id(&self.id)?;
        if self.statement.trim().is_empty() || self.statement.len() > 4096 {
            return Err("axiom statement must be 1..=4096 non-whitespace bytes".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Conflict {
    pub id: String,
    pub involved_axioms: Vec<String>,
}

impl Conflict {
    pub fn validate(&self, axioms: &BTreeMap<String, &Axiom>) -> Result<(), String> {
        iron_law_guard::validate_id(&self.id)?;
        if self.involved_axioms.is_empty() {
            return Err(format!("conflict '{}' must involve at least one axiom", self.id));
        }
        if self.involved_axioms.len() != self.involved_axioms.iter().collect::<BTreeSet<_>>().len() {
            return Err(format!("conflict '{}' lists duplicate axioms", self.id));
        }
        for axiom_id in &self.involved_axioms {
            if !axioms.contains_key(axiom_id.as_str()) {
                return Err(format!(
                    "conflict '{}' references unknown axiom '{}'",
                    self.id, axiom_id
                ));
            }
        }
        Ok(())
    }
}

/// Exact minimal hitting set: a set of axiom ids whose removal breaks every
/// conflict, minimal by inclusion and of minimum cardinality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HittingSet {
    pub annihilated_axioms: BTreeSet<String>,
    pub level: AxiomLevel,
    /// Highest epistemic level touched (iron sets are rejected by the guard).
    pub touches_empirical: bool,
    pub touches_convention: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AxiomSystem {
    pub id: String,
    pub axioms: Vec<Axiom>,
    pub conflicts: Vec<Conflict>,
}

impl AxiomSystem {
    pub fn validate(&self) -> Result<(), String> {
        iron_law_guard::validate_id(&self.id)?;
        if self.axioms.len() > MAX_AXIOM_COUNT {
            return Err(format!(
                "axiom system exceeds the exact-search bound of {MAX_AXIOM_COUNT} axioms"
            ));
        }
        if self.conflicts.len() > 256 {
            return Err("axiom system cannot list more than 256 conflicts".into());
        }
        let mut axiom_ids = BTreeSet::new();
        for axiom in &self.axioms {
            axiom.validate()?;
            if !axiom_ids.insert(axiom.id.clone()) {
                return Err(format!("duplicate axiom id '{}'", axiom.id));
            }
        }
        let axioms_map: BTreeMap<String, &Axiom> = self.axioms.iter().map(|a| (a.id.clone(), a)).collect();
        for conflict in &self.conflicts {
            conflict.validate(&axioms_map)?;
        }
        Ok(())
    }

    fn axiom_index(&self, id: &str) -> Option<usize> {
        self.axioms.iter().position(|a| a.id == id)
    }

    /// Guard result: iron axioms are never selectable for annihilation.
    fn selectable_indices(&self) -> Vec<usize> {
        self.axioms
            .iter()
            .enumerate()
            .filter(|(_, a)| a.level.annihilatable())
            .map(|(i, _)| i)
            .collect()
    }

    /// Whether a candidate hitting set respects the iron-law guard.
    pub fn guard_respected(&self, chosen: &[usize]) -> bool {
        chosen.iter().all(|&i| self.axioms[i].level.annihilatable())
    }
}

/// Lobachevsky operator output: every exact minimal hitting set found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LobachevskyResult {
    pub system_id: String,
    pub minimal_hitting_sets: Vec<HittingSet>,
    pub search_exhaustive: bool,
    pub iron_guard_applied: bool,
}

/// Run the exact minimal hitting-set search.
///
/// Returns all hitting sets of the smallest cardinality that respect the
/// iron-law guard, or an error if no guard-respecting hitting set exists.
pub fn lobachevsky(system: &AxiomSystem) -> Result<LobachevskyResult, String> {
    system.validate()?;
    let selectable = system.selectable_indices();
    let n = u32::try_from(system.axioms.len()).expect("axiom system bound checked by validate");

    // Conflict bitmasks over axiom indices for fast subset checks.
    let conflict_masks: Vec<u32> = system
        .conflicts
        .iter()
        .map(|c| {
            let mut mask = 0u32;
            for id in &c.involved_axioms {
                if let Some(idx) = system.axiom_index(id) {
                    mask |= 1u32 << idx;
                }
            }
            mask
        })
        .collect();

    let selectable_mask: u32 = selectable.iter().fold(0u32, |acc, &i| acc | (1u32 << i));
    let mut results: Vec<HittingSet> = Vec::new();
    let mut checked = 0u64;

    // Exact search by increasing cardinality: the first cardinality that yields
    // any valid hitting set defines the minimum; all minimal sets at that
    // cardinality are returned.
    for size in 0u32..=n as u32 {
        if size > selectable_mask.count_ones() {
            break;
        }
        let mut comb = Combination::new(n as u32, size);
        while let Some(chosen) = comb.next() {
            checked += 1;
            if checked > MAX_COMBINATION_CHECKS {
                return Err("exact search exceeded the combination bound; reduce the axiom set".into());
            }
            // Guard: all chosen axioms must be annihilatable.
            if chosen.iter().any(|&i| !system.axioms[i as usize].level.annihilatable()) {
                continue;
            }
            let mut mask = 0u32;
            for &i in &chosen {
                mask |= 1u32 << i;
            }
            // Hitting set condition: every conflict mask intersects chosen mask.
            if conflict_masks.iter().all(|cm| cm & mask != 0) {
                let mut annihilated = BTreeSet::new();
                let mut touches_empirical = false;
                let mut touches_convention = false;
                for &i in &chosen {
                    let axiom = &system.axioms[i as usize];
                    annihilated.insert(axiom.id.clone());
                    match axiom.level {
                        AxiomLevel::EmpiricalRegime => touches_empirical = true,
                        AxiomLevel::Convention => touches_convention = true,
                        AxiomLevel::Iron => {}
                    }
                }
                results.push(HittingSet {
                    annihilated_axioms: annihilated,
                    level: if touches_convention {
                        AxiomLevel::Convention
                    } else if touches_empirical {
                        AxiomLevel::EmpiricalRegime
                    } else {
                        AxiomLevel::Convention // empty set defaults to convention
                    },
                    touches_empirical,
                    touches_convention,
                });
            }
        }
        if !results.is_empty() {
            break; // minimum cardinality found
        }
    }

    if results.is_empty() {
        return Err(
            "no guard-respecting hitting set exists: an iron axiom participates in every conflict resolution"
                .into(),
        );
    }

    results.sort_by(|a, b| {
        b.annihilated_axioms
            .len()
            .cmp(&a.annihilated_axioms.len())
            .then_with(|| a.annihilated_axioms.cmp(&b.annihilated_axioms))
            .then_with(|| a.touches_empirical.cmp(&b.touches_empirical))
    });

    Ok(LobachevskyResult {
        system_id: system.id.clone(),
        minimal_hitting_sets: results,
        search_exhaustive: true,
        iron_guard_applied: true,
    })
}

/// Compile an annihilated axiom system into a crux `Event::Proposed`, recording
/// the decision as a reviewable proposal rather than an irreversible mutation.
pub fn compile_proposal(
    system_id: &str,
    goal: &str,
    hypothesis: &str,
    test: &str,
) -> Result<Event, String> {
    if goal.trim().is_empty() || hypothesis.trim().is_empty() || test.trim().is_empty() {
        return Err("proposal goal, hypothesis, and test must be non-empty".into());
    }
    if goal.len() > 2048 || hypothesis.len() > 2048 || test.len() > 4096 {
        return Err("proposal fields exceed size limits".into());
    }
    henosis_dag::validate_id(system_id)?;
    Ok(Event::Proposed {
        goal: format!("[system {system_id}] {goal}"),
        hypothesis: hypothesis.to_owned(),
        test: test.to_owned(),
    })
}

mod combination {
    /// Lexicographic combinations of `size` elements from `0..n`.
    pub(super) struct Combination {
        n: u32,
        size: u32,
        vals: Vec<u32>,
        finished: bool,
    }

    impl Combination {
        pub(super) fn new(n: u32, size: u32) -> Self {
            let vals = if size == 0 || size > n {
                Vec::new()
            } else {
                (0..size).collect()
            };
            Self { n, size, vals, finished: size == 0 || size > n }
        }

        pub(super) fn next(&mut self) -> Option<Vec<u32>> {
            if self.finished {
                return None;
            }
            if self.size == 0 {
                self.finished = true;
                return Some(vec![]);
            }
            let result = self.vals.clone();
            // Advance to the next lexicographic combination.
            let mut i = self.size;
            loop {
                i -= 1; // self.size >= 1 here, so i >= 0
                if self.vals[i as usize] == self.n - (self.size - i) {
                    if i == 0 {
                        self.finished = true;
                        return Some(result);
                    }
                } else {
                    self.vals[i as usize] += 1;
                    let mut j = i + 1;
                    while j < self.size {
                        self.vals[j as usize] = self.vals[(j - 1) as usize] + 1;
                        j += 1;
                    }
                    break;
                }
            }
            Some(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn axiom(id: &str, level: &str) -> Axiom {
        Axiom {
            id: id.into(),
            statement: format!("statement of {id}"),
            level: AxiomLevel::parse(level).unwrap(),
        }
    }

    #[test]
    fn exact_minimal_hitting_set_prefers_smaller_sets() {
        let system = AxiomSystem {
            id: "sys-1".into(),
            axioms: vec![axiom("a1", "iron"), axiom("a2", "convention"), axiom("a3", "empirical_regime")],
            conflicts: vec![
                Conflict { id: "c1".into(), involved_axioms: vec!["a1".into(), "a2".into()] },
                Conflict { id: "c2".into(), involved_axioms: vec!["a2".into(), "a3".into()] },
            ],
        };
        let result = lobachevsky(&system).unwrap();
        assert_eq!(result.minimal_hitting_sets.len(), 1);
        assert_eq!(
            result.minimal_hitting_sets[0].annihilated_axioms,
            BTreeSet::from(["a2".into()])
        );
    }

    #[test]
    fn iron_axiom_cannot_be_annihilated() {
        let system = AxiomSystem {
            id: "sys-2".into(),
            axioms: vec![axiom("a1", "iron"), axiom("a2", "iron")],
            conflicts: vec![Conflict {
                id: "c1".into(),
                involved_axioms: vec!["a1".into(), "a2".into()],
            }],
        };
        assert!(lobachevsky(&system).is_err());
    }

    #[test]
    fn compile_proposal_wraps_system_id() {
        let event = compile_proposal("sys-1", "goal", "hypothesis", "test").unwrap();
        assert!(matches!(event, Event::Proposed { .. }));
        match event {
            Event::Proposed { goal, .. } => assert!(goal.contains("[system sys-1]")),
            _ => unreachable!(),
        }
    }
}

mod iron_law_guard {
    pub(super) fn validate_id(id: &str) -> Result<(), String> {
        henosis_dag::validate_id(id)
    }
}
