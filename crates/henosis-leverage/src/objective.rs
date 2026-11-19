//! Interval-bounded objective `J(a)` dominance analysis.
//!
//! Every candidate action `a` carries an objective value `J(a)` expressed as an
//! interval `[lo, hi]` plus a cost. Action A strictly dominates B when A's
//! worst case is at least B's best case after costs, so B can be discarded
//! without knowing the true value of either. Overlapping intervals are
//! unresolved, not equal: the analyzer never fabricates precision.

use crate::Interval;
use henosis_dag::validate_id;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Objective {
    pub id: String,
    pub action: String,
    /// Bounded estimate of `J(action)` before costs.
    pub estimate: Interval,
    /// Cost units consumed by the action (>= 0).
    pub cost: f64,
}

impl Objective {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        if self.action.trim().is_empty() || self.action.len() > 256 {
            return Err("objective action must be 1..=256 non-whitespace bytes".into());
        }
        if !self.cost.is_finite() || self.cost < 0.0 {
            return Err("objective cost must be finite and non-negative".into());
        }
        // estimate is an Interval already validated at construction via Interval::new
        Ok(())
    }

    /// Cost-adjusted objective `J(a) - cost` as an interval.
    pub fn net(&self) -> Interval {
        Interval {
            lo: self.estimate.lo - self.cost,
            hi: self.estimate.hi - self.cost,
        }
    }
}

/// Strict dominance relationship between two cost-adjusted objectives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DominanceRelation {
    Dominates,
    DominatedBy,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DominanceReport {
    pub id: String,
    pub action: String,
    pub net_interval: Interval,
    pub dominated_by: Vec<String>,
    pub dominates: Vec<String>,
    pub is_pareto_optimal: bool,
}

impl DominanceReport {
    pub fn relation_to(&self, other: &DominanceReport) -> DominanceRelation {
        if self.net_interval.lo >= other.net_interval.hi {
            return DominanceRelation::Dominates;
        }
        if other.net_interval.lo >= self.net_interval.hi {
            return DominanceRelation::DominatedBy;
        }
        DominanceRelation::Unresolved
    }
}

/// Analyze strict dominance across objectives.
///
/// Returns one `DominanceReport` per input action, in the same order. An action
/// is Pareto-optimal when no other action strictly dominates it.
pub fn analyze(objectives: &[Objective]) -> Result<Vec<DominanceReport>, String> {
    let mut reports: Vec<DominanceReport> = Vec::with_capacity(objectives.len());
    for obj in objectives {
        obj.validate()?;
        reports.push(DominanceReport {
            id: obj.id.clone(),
            action: obj.action.clone(),
            net_interval: obj.net(),
            dominated_by: Vec::new(),
            dominates: Vec::new(),
            is_pareto_optimal: true, // provisional
        });
    }

    // Phase 1: classify all pairs under an immutable borrow of `reports`.
    let mut dominates_pairs: Vec<(usize, usize)> = Vec::new();
    let mut dominated_by_pairs: Vec<(usize, usize)> = Vec::new();
    let mut not_pareto: Vec<usize> = Vec::new();

    for i in 0..reports.len() {
        for j in 0..reports.len() {
            if i == j {
                continue;
            }
            let rel = reports[i].relation_to(&reports[j]);
            match rel {
                DominanceRelation::Dominates => {
                    dominates_pairs.push((i, j));
                    dominated_by_pairs.push((j, i));
                    not_pareto.push(j);
                }
                DominanceRelation::DominatedBy => {
                    dominated_by_pairs.push((i, j));
                    dominates_pairs.push((j, i));
                    not_pareto.push(i);
                }
                DominanceRelation::Unresolved => {}
            }
        }
    }

    // Snapshot all action strings while `reports` is still immutably borrowed,
    // then apply mutations in a separate pass to avoid borrow conflicts.
    let all_actions: Vec<String> = reports.iter().map(|r| r.action.clone()).collect();

    for (i, j) in dominates_pairs {
        reports[i].dominates.push(all_actions[j].clone());
    }
    for (i, j) in dominated_by_pairs {
        reports[i].dominated_by.push(all_actions[j].clone());
    }
    for i in not_pareto {
        reports[i].is_pareto_optimal = false;
    }

    for report in &mut reports {
        report.dominated_by.sort();
        report.dominated_by.dedup();
        report.dominates.sort();
        report.dominates.dedup();
    }

    Ok(reports)
}

/// The Pareto frontier: actions not strictly dominated by any other action.
pub fn pareto_frontier(reports: &[DominanceReport]) -> Vec<String> {
    let mut frontier: Vec<String> = reports
        .iter()
        .filter(|r| r.is_pareto_optimal)
        .map(|r| r.action.clone())
        .collect();
    frontier.sort();
    frontier.dedup();
    frontier
}

/// Check whether `candidate` is strictly dominated by at least one member of
/// `frontier` (used to prune new options without re-running the full analysis).
pub fn is_dominated_by_frontier(candidate: &Objective, frontier: &[DominanceReport]) -> bool {
    let candidate_net = candidate.net();
    frontier.iter().any(|report| {
        // `report.action` strictly dominates `candidate` iff report.lo >= candidate.hi.
        report.net_interval.lo >= candidate_net.hi
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(id: &str, action: &str, lo: f64, hi: f64, cost: f64) -> Objective {
        Objective {
            id: id.into(),
            action: action.into(),
            estimate: Interval::new(lo, hi).unwrap(),
            cost,
        }
    }

    #[test]
    fn strict_dominance_removes_dominated_action() {
        let objectives = [
            obj("a", "A", 10.0, 12.0, 1.0), // net [9, 11]
            obj("b", "B", 5.0, 8.0, 0.5),    // net [4.5, 7.5]
        ];
        let reports = analyze(&objectives).unwrap();
        assert_eq!(reports[0].relation_to(&reports[1]), DominanceRelation::Dominates);
        assert!(reports[0].is_pareto_optimal);
        assert!(!reports[1].is_pareto_optimal);
        assert_eq!(pareto_frontier(&reports), vec!["A".to_owned()]);
        assert!(is_dominated_by_frontier(&obj("c", "C", 6.0, 7.0, 0.0), &reports));
    }

    #[test]
    fn overlapping_intervals_are_unresolved() {
        let objectives = [
            obj("a", "A", 5.0, 10.0, 0.0),
            obj("b", "B", 8.0, 12.0, 0.0),
        ];
        let reports = analyze(&objectives).unwrap();
        assert_eq!(reports[0].relation_to(&reports[1]), DominanceRelation::Unresolved);
        assert_eq!(pareto_frontier(&reports), vec!["A".to_owned(), "B".to_owned()]);
    }
}
