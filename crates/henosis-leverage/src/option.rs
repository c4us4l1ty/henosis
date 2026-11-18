//! Multi-criteria option evaluator for leverage decisions.
//!
//! Combines constraint-wall signals, objective dominance, retention cost, and
//! mandate abandonment into a single recommendation per option. Every output is
//! a suggestion to the operator, not an automated command: the operator owns
//! the final decision.

use crate::interval::Interval;
use crate::mandate::{AbandonmentVerdict, MandateReport};
use crate::objective::{DominanceReport, Objective};
use crate::retention::DecayAlert;
use crate::walls::{RankedWall, WallSignal};
use henosis_dag::validate_id;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Recommendation {
    /// Strong signal to pursue: high-value bottleneck or dominance win.
    Pursue,
    /// Worth doing but not a top leverage point: do after frontier items.
    Delegate,
    /// Abandon: not load-bearing, dominated, or decayed without support.
    Abandon,
    /// Insufficient evidence: gather more data before committing.
    Defer,
}

impl Recommendation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pursue => "pursue",
            Self::Delegate => "delegate",
            Self::Abandon => "abandon",
            Self::Defer => "defer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeverageOption {
    pub id: String,
    pub title: String,
    /// Objective whose cost-adjusted value estimates this option's payoff.
    pub objective_id: String,
    /// Constraint wall this option addresses, if any.
    pub wall_id: Option<String>,
    /// Mandate this option would discharge or abandon, if any.
    pub mandate_id: Option<String>,
}

impl LeverageOption {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        if self.title.trim().is_empty() || self.title.len() > 256 {
            return Err("option title must be 1..=256 non-whitespace bytes".into());
        }
        validate_id(&self.objective_id)?;
        if let Some(wall) = &self.wall_id {
            validate_id(wall)?;
        }
        if let Some(mandate) = &self.mandate_id {
            validate_id(mandate)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptionContext<'a> {
    pub dominance_reports: &'a [DominanceReport],
    pub wall_reports: &'a [RankedWall],
    pub mandate_reports: &'a [MandateReport],
    pub decay_alerts: &'a [DecayAlert],
    pub verified_capabilities: &'a BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptionEvaluation {
    pub option_id: String,
    pub title: String,
    pub recommendation: Recommendation,
    pub rationale: String,
    pub net_objective_interval: Option<Interval>,
    pub wall_signal: Option<WallSignal>,
    pub mandate_verdict: Option<AbandonmentVerdict>,
    pub decay_risk: bool,
}

/// Evaluate one option against the full leverage context.
pub fn evaluate_option(
    option: &LeverageOption,
    context: &OptionContext<'_>,
) -> Result<OptionEvaluation, String> {
    option.validate()?;

    let objective_report = context
        .dominance_reports
        .iter()
        .find(|r| r.action == option.objective_id)
        .ok_or_else(|| format!("no dominance report for objective '{}'", option.objective_id))?;

    let wall_report = option
        .wall_id
        .as_ref()
        .and_then(|wall_id| context.wall_reports.iter().find(|r| r.wall_id == *wall_id));

    let mandate_report = option
        .mandate_id
        .as_ref()
        .and_then(|mandate_id| context.mandate_reports.iter().find(|r| r.mandate_id == *mandate_id));

    let decay_risk = context
        .decay_alerts
        .iter()
        .any(|alert| context.verified_capabilities.contains(&alert.capability_id));

    let mut rationale = String::new();
    let mut score: f64 = 0.0;

    if let Some(wall) = wall_report {
        rationale.push_str(&format!(
            "wall '{}' gap {:.1}x signal {}; ",
            wall.title, wall.asymptotic_gap, wall.signal.as_str()
        ));
        score += wall.log10_gap.max(0.0);
    }

    if let Some(mandate) = mandate_report {
        rationale.push_str(&format!(
            "mandate '{}' verdict {}; ",
            mandate.title, mandate.verdict.as_str()
        ));
        if matches!(mandate.verdict, AbandonmentVerdict::Abandon) {
            score += 1.0; // abandoning a costly mandate is itself leverage
        }
    }

    if decay_risk {
        rationale.push_str("decay risk on a verified load-bearing capability; ");
        score -= 1.0;
    }

    let recommendation = if decay_risk && !objective_report.is_pareto_optimal {
        Recommendation::Abandon
    } else if objective_report.is_pareto_optimal && score > 1.0 {
        Recommendation::Pursue
    } else if objective_report.is_pareto_optimal {
        Recommendation::Delegate
    } else {
        Recommendation::Defer
    };

    if rationale.is_empty() {
        rationale.push_str("no wall, mandate, or decay signals bound to this option");
    }

    Ok(OptionEvaluation {
        option_id: option.id.clone(),
        title: option.title.clone(),
        recommendation,
        rationale,
        net_objective_interval: Some(objective_report.net_interval),
        wall_signal: wall_report.map(|r| r.signal),
        mandate_verdict: mandate_report.map(|r| r.verdict),
        decay_risk,
    })
}

/// Evaluate every option and return evaluations sorted by recommendation
/// priority, then by option id.
pub fn evaluate_options(
    options: &[LeverageOption],
    context: &OptionContext<'_>,
) -> Result<Vec<OptionEvaluation>, String> {
    let mut evaluations: Vec<OptionEvaluation> = Vec::with_capacity(options.len());
    for option in options {
        evaluations.push(evaluate_option(option, context)?);
    }
    evaluations.sort_by(|a, b| {
        b.recommendation
            .priority()
            .cmp(&a.recommendation.priority())
            .then_with(|| a.option_id.cmp(&b.option_id))
    });
    Ok(evaluations)
}

impl Recommendation {
    fn priority(self) -> u8 {
        match self {
            Self::Pursue => 3,
            Self::Delegate => 2,
            Self::Defer => 1,
            Self::Abandon => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objective::analyze;

    fn option(id: &str, objective: &str) -> LeverageOption {
        LeverageOption {
            id: id.into(),
            title: id.into(),
            objective_id: objective.into(),
            wall_id: None,
            mandate_id: None,
        }
    }

    #[test]
    fn dominated_option_defers_while_pareto_option_pursues() {
        let objectives = [
            crate::objective::Objective {
                id: "obj-strong".into(),
                action: "strong".into(),
                estimate: Interval::new(10.0, 12.0).unwrap(),
                cost: 1.0,
            },
            crate::objective::Objective {
                id: "obj-weak".into(),
                action: "weak".into(),
                estimate: Interval::new(4.0, 6.0).unwrap(),
                cost: 0.0,
            },
        ];
        let reports = analyze(&objectives).unwrap();
        let walls: [RankedWall; 0] = [];
        let mandates: [MandateReport; 0] = [];
        let alerts: [DecayAlert; 0] = [];
        let verified = BTreeSet::new();
        let context = OptionContext {
            dominance_reports: &reports,
            wall_reports: &walls,
            mandate_reports: &mandates,
            decay_alerts: &alerts,
            verified_capabilities: &verified,
        };

        let strong = evaluate_option(&option("opt-strong", "obj-strong"), &context).unwrap();
        let weak = evaluate_option(&option("opt-weak", "obj-weak"), &context).unwrap();
        assert_eq!(strong.recommendation, Recommendation::Pursue);
        assert_eq!(weak.recommendation, Recommendation::Defer);
    }
}
