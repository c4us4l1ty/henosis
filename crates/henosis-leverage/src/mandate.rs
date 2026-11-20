//! Mandate-to-Subtract abandonment detector.
//!
//! A "mandate" is a capability the operator has committed to maintain or build.
//! Subtracting a mandate means dropping it from the active requirement set and
//! re-checking whether every active frontier goal remains feasible through the
//! CSR hypergraph. Mandates that sit on no active goal's backward light-cone
//! spine are abandonment candidates: keeping them consumes retention budget and
//! drill time for zero load-bearing value.
//!
//! This detector is purely structural: it reports which mandates are *not*
//! required by any active goal. It does not decide whether abandoning a mandate
//! is socially, legally, or strategically acceptable.

use crate::Interval;
use henosis_dag::{validate_id, CsrHypergraph};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub id: String,
    pub title: String,
    pub domain: String,
    /// Estimated weekly retention/maintenance cost units (>= 1).
    pub cost_units: u32,
    /// Goals this mandate claims to support (declared by the operator).
    pub claimed_supported_goals: Vec<String>,
}

impl Mandate {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        if self.title.trim().is_empty() || self.title.len() > 256 {
            return Err("mandate title must be 1..=256 non-whitespace bytes".into());
        }
        if self.domain.trim().is_empty() || self.domain.len() > 128 {
            return Err("mandate domain must be 1..=128 non-whitespace bytes".into());
        }
        if self.cost_units == 0 {
            return Err("mandate cost_units must be at least 1".into());
        }
        for goal in &self.claimed_supported_goals {
            validate_id(goal)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbandonmentVerdict {
    /// No active goal's backward light-cone requires this mandate.
    Abandon,
    /// At least one active goal requires this mandate; retain.
    Retain,
    /// The mandate itself is not in the hypergraph at all: untracked, cannot be
    /// verified load-bearing, default to abandon pending registration.
    Untracked,
}

impl AbandonmentVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Abandon => "abandon",
            Self::Retain => "retain",
            Self::Untracked => "untracked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MandateReport {
    pub mandate_id: String,
    pub title: String,
    pub domain: String,
    pub cost_units: u32,
    pub claimed_supported_goals: Vec<String>,
    pub actually_supported_goals: Vec<String>,
    pub weekly_cost_interval: Interval,
    pub verdict: AbandonmentVerdict,
    pub load_bearing: bool,
}

/// Detect which mandates are load-bearing for any active frontier goal and
/// which can be subtracted (abandoned).
pub fn detect_abandonment(
    hypergraph: &CsrHypergraph,
    mandates: &[Mandate],
    active_goals: &[String],
    _verified: &BTreeSet<String>,
) -> Result<Vec<MandateReport>, String> {
    // Trace the full structural backward light-cone (passing an empty verified set so
    // foundations beneath already-verified intermediate capabilities remain load-bearing).
    let empty = BTreeSet::new();
    let mut goal_needed_caps: BTreeMap<&String, BTreeSet<String>> = BTreeMap::new();
    let mut load_bearing_caps: BTreeSet<String> = BTreeSet::new();
    for goal in active_goals {
        let cone = hypergraph.backward_light_cone(goal, &empty)?;
        let needed: BTreeSet<String> = cone.missing_capabilities.into_iter().collect();
        load_bearing_caps.extend(needed.iter().cloned());
        goal_needed_caps.insert(goal, needed);
    }

    let mut reports = Vec::with_capacity(mandates.len());
    for mandate in mandates {
        mandate.validate()?;
        let mut actually_supported: Vec<String> = active_goals
            .iter()
            .filter(|goal| {
                goal_needed_caps
                    .get(goal)
                    .is_some_and(|caps| caps.contains(&mandate.id))
            })
            .cloned()
            .collect();
        actually_supported.sort();
        actually_supported.dedup();
        let load_bearing = load_bearing_caps.contains(&mandate.id);

        let weekly_cost = f64::from(mandate.cost_units);
        let weekly_cost_interval = Interval::new(weekly_cost * 0.5, weekly_cost * 2.0)?;

        let verdict = if !hypergraph.node_ids().contains(&mandate.id) {
            AbandonmentVerdict::Untracked
        } else if load_bearing {
            AbandonmentVerdict::Retain
        } else {
            AbandonmentVerdict::Abandon
        };

        reports.push(MandateReport {
            mandate_id: mandate.id.clone(),
            title: mandate.title.clone(),
            domain: mandate.domain.clone(),
            cost_units: mandate.cost_units,
            claimed_supported_goals: mandate.claimed_supported_goals.clone(),
            actually_supported_goals: actually_supported,
            weekly_cost_interval,
            verdict,
            load_bearing,
        });
    }

    reports.sort_by(|a, b| {
        b.weekly_cost_interval
            .midpoint()
            .total_cmp(&a.weekly_cost_interval.midpoint())
            .then_with(|| a.mandate_id.cmp(&b.mandate_id))
    });
    Ok(reports)
}

/// Shortlist of high-cost mandates that are not load-bearing anywhere: the
/// primary subtraction targets, ordered by cost.
pub fn subtraction_targets(reports: &[MandateReport], limit: usize) -> Vec<&MandateReport> {
    let mut targets: Vec<&MandateReport> = reports
        .iter()
        .filter(|r| matches!(r.verdict, AbandonmentVerdict::Abandon | AbandonmentVerdict::Untracked))
        .collect();
    targets.sort_by(|a, b| {
        b.cost_units
            .cmp(&a.cost_units)
            .then_with(|| a.mandate_id.cmp(&b.mandate_id))
    });
    targets.into_iter().take(limit).collect()
}

/// Weekly cost saved by abandoning all subtraction targets.
pub fn weekly_cost_saved(targets: &[&MandateReport]) -> Interval {
    let lo: f64 = targets
        .iter()
        .map(|r| r.weekly_cost_interval.lo)
        .sum();
    let hi: f64 = targets.iter().map(|r| r.weekly_cost_interval.hi).sum();
    Interval { lo, hi }
}

#[cfg(test)]
mod tests {
    use super::*;
    use henosis_dag::{EpistemicStatus, RealizationContract};

    fn contract(id: &str, prereqs: &[&str], output: &str, cost: u32) -> RealizationContract {
        RealizationContract {
            id: id.into(),
            title: id.into(),
            prerequisites: prereqs.iter().map(|s| (*s).to_owned()).collect(),
            assumptions: vec!["x".into()],
            resources: vec!["y".into()],
            output: output.into(),
            verification: "z".into(),
            failure_boundary: vec![],
            status: EpistemicStatus::Observed,
        cost_units: cost,
    }
        .normalized()
        .unwrap()
    }

    #[test]
    fn untracked_mandate_defaults_to_abandon() {
        // The tracked goal must exist in the hypergraph; an unknown target is a
        // caller error on `backward_light_cone`, not a load-bearing foundation.
        let hg = CsrHypergraph::from_contracts(&[contract("c-goal", &[], "g1", 1)]);
        let mandates = [Mandate {
            id: "ghost".into(),
            title: "Ghost".into(),
            domain: "d".into(),
            cost_units: 1,
            claimed_supported_goals: vec!["g1".into()],
        }];
        let reports = detect_abandonment(&hg, &mandates, &["g1".into()], &BTreeSet::new()).unwrap();
        assert_eq!(reports[0].verdict, AbandonmentVerdict::Untracked);
        assert!(!reports[0].load_bearing);
    }

    #[test]
    fn load_bearing_mandate_is_retained() {
        let hg = CsrHypergraph::from_contracts(&[
            contract("c1", &["foundation"], "goal", 3),
        ]);
        let mandates = [Mandate {
            id: "foundation".into(),
            title: "Foundation".into(),
            domain: "d".into(),
            cost_units: 5,
            claimed_supported_goals: vec!["goal".into()],
        }];
        let reports =
            detect_abandonment(&hg, &mandates, &["goal".into()], &BTreeSet::new()).unwrap();
        assert_eq!(reports[0].verdict, AbandonmentVerdict::Retain);
        assert!(reports[0].load_bearing);
    }

    #[test]
    fn non_load_bearing_mandate_is_abandoned() {
        // "irrelevant" is tracked in the hypergraph (an output of c-irr) but
        // sits on no goal's backward light-cone, so it abandons rather than
        // being reported untracked.
        let hg = CsrHypergraph::from_contracts(&[
            contract("c1", &["a"], "goal", 3),
            contract("c-irr", &[], "irrelevant", 1),
        ]);
        let mandates = [Mandate {
            id: "irrelevant".into(),
            title: "Irrelevant".into(),
            domain: "d".into(),
            cost_units: 9,
            claimed_supported_goals: vec!["goal".into()],
        }];
        let reports =
            detect_abandonment(&hg, &mandates, &["goal".into()], &BTreeSet::new()).unwrap();
        assert_eq!(reports[0].verdict, AbandonmentVerdict::Abandon);
        let targets = subtraction_targets(&reports, 1);
        assert_eq!(targets[0].mandate_id, "irrelevant");
    }

    #[test]
    fn already_verified_foundation_remains_load_bearing() {
        let hg = CsrHypergraph::from_contracts(&[
            contract("c1", &["foundation"], "mid", 2),
            contract("c2", &["mid"], "goal", 3),
        ]);
        let mandates = [Mandate {
            id: "foundation".into(),
            title: "Foundation".into(),
            domain: "d".into(),
            cost_units: 5,
            claimed_supported_goals: vec![],
        }];
        let verified = BTreeSet::from(["foundation".to_owned(), "mid".to_owned()]);
        let reports = detect_abandonment(&hg, &mandates, &["goal".into()], &verified).unwrap();
        assert_eq!(reports[0].verdict, AbandonmentVerdict::Retain);
        assert!(reports[0].load_bearing);
        assert_eq!(reports[0].actually_supported_goals, vec!["goal".to_owned()]);
    }
}
