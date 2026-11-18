//! Five-axis topological skill retention (`R_c(t)`) and backward replenishment.
//!
//! Tracks capability decay across `Recall`, `Derive`, `ApplyFamiliar`,
//! `ApplyUnfamiliar`, and `Implement`. When a higher-order realization contract
//! succeeds, retention reinforcement cascades backward across prerequisite
//! hyperedges (attenuated by topological depth), suppressing unnecessary drills
//! on foundations that the user is actively composing in real work.

use henosis_dag::{validate_id, CsrHypergraph, ProofOperator};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionAxis {
    Recall,
    Derive,
    ApplyFamiliar,
    ApplyUnfamiliar,
    Implement,
}

impl RetentionAxis {
    pub const ALL: [Self; 5] = [
        Self::Recall,
        Self::Derive,
        Self::ApplyFamiliar,
        Self::ApplyUnfamiliar,
        Self::Implement,
    ];

    pub fn default_half_life_days(self) -> f64 {
        match self {
            Self::Recall => 14.0,
            Self::Derive => 28.0,
            Self::ApplyFamiliar => 35.0,
            Self::ApplyUnfamiliar => 21.0,
            Self::Implement => 30.0,
        }
    }

    /// Targeted Akashi proof operator recommended when this axis decays.
    pub fn repair_operator(self) -> ProofOperator {
        match self {
            Self::Recall => ProofOperator::Explain,
            Self::Derive => ProofOperator::Reconstruct,
            Self::ApplyFamiliar => ProofOperator::Implement,
            Self::ApplyUnfamiliar => ProofOperator::Transfer,
            Self::Implement => ProofOperator::Modify,
        }
    }

    pub fn from_operator(operator: ProofOperator) -> &'static [Self] {
        match operator {
            ProofOperator::Explain => &[Self::Recall],
            ProofOperator::Reconstruct => &[Self::Derive, Self::Recall],
            ProofOperator::Implement => &[Self::Implement, Self::ApplyFamiliar],
            ProofOperator::Criticize => &[Self::Derive, Self::ApplyUnfamiliar],
            ProofOperator::Modify => &[Self::Implement, Self::ApplyUnfamiliar],
            ProofOperator::Transfer => &[Self::ApplyUnfamiliar, Self::Derive],
            ProofOperator::PredictFailure => &[Self::Derive, Self::ApplyUnfamiliar, Self::Implement],
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recall => "recall",
            Self::Derive => "derive",
            Self::ApplyFamiliar => "apply_familiar",
            Self::ApplyUnfamiliar => "apply_unfamiliar",
            Self::Implement => "implement",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AxisCurve {
    pub half_life_days: f64,
    pub last_day: f64,
    pub initial_strength: f64,
}

impl AxisCurve {
    pub fn fresh(axis: RetentionAxis, day: f64) -> Self {
        Self {
            half_life_days: axis.default_half_life_days(),
            last_day: day,
            initial_strength: 1.0,
        }
    }

    pub fn retention_at(&self, current_day: f64) -> f64 {
        let elapsed = (current_day - self.last_day).max(0.0);
        let hl = self.half_life_days.max(0.5);
        (self.initial_strength * 2.0_f64.powf(-elapsed / hl)).clamp(0.0, 1.0)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RetentionLedger {
    pub capabilities: BTreeMap<String, BTreeMap<RetentionAxis, AxisCurve>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecayAlert {
    pub capability_id: String,
    pub weakest_axis: RetentionAxis,
    pub estimated_retention: f64,
    pub supported_goals: Vec<String>,
    pub recommended_operator: ProofOperator,
}

impl RetentionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Initialize all five retention axes for a newly verified capability at `day`.
    pub fn seed_capability(&mut self, capability_id: &str, day: f64) -> Result<(), String> {
        validate_id(capability_id)?;
        if !day.is_finite() || day < 0.0 {
            return Err("day must be finite and non-negative".into());
        }
        let entry = self
            .capabilities
            .entry(capability_id.to_owned())
            .or_default();
        for axis in RetentionAxis::ALL {
            entry.insert(axis, AxisCurve::fresh(axis, day));
        }
        Ok(())
    }

    /// Record a direct Akashi verification on `capability_id`, restoring tested
    /// axes to full strength and extending their half-lives by 1.5x.
    pub fn record_verification(
        &mut self,
        capability_id: &str,
        operator: ProofOperator,
        day: f64,
    ) -> Result<(), String> {
        validate_id(capability_id)?;
        if !day.is_finite() || day < 0.0 {
            return Err("day must be finite and non-negative".into());
        }
        let axes = self
            .capabilities
            .entry(capability_id.to_owned())
            .or_default();
        for axis in RetentionAxis::ALL {
            axes.entry(axis).or_insert_with(|| AxisCurve::fresh(axis, day));
        }
        for &axis in RetentionAxis::from_operator(operator) {
            if let Some(curve) = axes.get_mut(&axis) {
                curve.initial_strength = 1.0;
                curve.last_day = day.max(curve.last_day);
                curve.half_life_days = (curve.half_life_days * 1.5).min(365.0 * 3.0);
            }
        }
        Ok(())
    }

    /// Propagate implicit reinforcement backward along all prerequisite ancestors
    /// of `contract_id` after the contract is executed at `day`.
    /// Returns the number of prerequisite capabilities reinforced.
    pub fn propagate_contract_success(
        &mut self,
        hypergraph: &CsrHypergraph,
        contract_id: &str,
        day: f64,
    ) -> Result<usize, String> {
        if !day.is_finite() || day < 0.0 {
            return Err("day must be finite and non-negative".into());
        }
        let ancestors = hypergraph.prerequisite_ancestors(contract_id)?;
        let mut reinforced = 0usize;
        for (node_id, depth) in ancestors {
            let Some(axes) = self.capabilities.get_mut(&node_id) else {
                continue;
            };
            // Depth 1 receives strong implicit boost (0.85), attenuating smoothly deeper down.
            // Iterative multiply avoids an unsigned-to-signed cast.
            let mut gain = 1.0f64;
            let mut remaining = depth;
            while remaining > 0 {
                gain *= 0.85;
                remaining -= 1;
            }
            for (&axis, curve) in axes.iter_mut() {
                let current = curve.retention_at(day);
                let boosted = current + (1.0 - current) * gain;
                curve.initial_strength = boosted.clamp(0.0, 1.0);
                curve.last_day = day.max(curve.last_day);
                // Active composition reinforces operational and derivational durability.
                let factor = if axis == RetentionAxis::Recall {
                    1.10
                } else {
                    1.20
                };
                curve.half_life_days = (curve.half_life_days * factor).min(365.0 * 3.0);
            }
            reinforced += 1;
        }
        Ok(reinforced)
    }

    /// Inspect all five axis retention estimates for `capability_id` at `current_day`.
    pub fn snapshot(&self, capability_id: &str, current_day: f64) -> Option<BTreeMap<RetentionAxis, f64>> {
        let axes = self.capabilities.get(capability_id)?;
        Some(
            axes.iter()
                .map(|(&axis, curve)| (axis, curve.retention_at(current_day)))
                .collect(),
        )
    }

    /// Surface only decayed *load-bearing* capabilities required by active
    /// `frontier_goals`, ignoring unrelated skills to prevent review debt.
    pub fn orphaned_load_bearing_alerts(
        &self,
        hypergraph: &CsrHypergraph,
        verified: &BTreeSet<String>,
        frontier_goals: &[String],
        current_day: f64,
        min_retention: f64,
    ) -> Result<Vec<DecayAlert>, String> {
        let threshold = min_retention.clamp(0.0, 1.0);
        // Map each foundation capability -> active goals whose full ancestry uses it.
        let mut goal_support: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let empty = BTreeSet::new();
        for goal in frontier_goals {
            // Trace full structural cone (passing empty set so verified foundations below
            // intermediate verified capabilities are also tracked as load-bearing).
            let cone = hypergraph.backward_light_cone(goal, &empty)?;
            for cap in cone.missing_capabilities {
                if verified.contains(&cap) {
                    goal_support
                        .entry(cap)
                        .or_default()
                        .insert(goal.clone());
                }
            }
        }

        let mut alerts = Vec::new();
        for (cap_id, goals) in goal_support {
            let Some(axes) = self.capabilities.get(&cap_id) else {
                continue;
            };
            let weakest = axes
                .iter()
                .map(|(&axis, curve)| (axis, curve.retention_at(current_day)))
                .min_by(|a, b| a.1.total_cmp(&b.1));
            if let Some((weakest_axis, ret)) = weakest {
                if ret < threshold {
                    alerts.push(DecayAlert {
                        capability_id: cap_id,
                        weakest_axis,
                        estimated_retention: ret,
                        supported_goals: goals.into_iter().collect(),
                        recommended_operator: weakest_axis.repair_operator(),
                    });
                }
            }
        }

        alerts.sort_by(|a, b| {
            b.supported_goals
                .len()
                .cmp(&a.supported_goals.len())
                .then_with(|| a.estimated_retention.total_cmp(&b.estimated_retention))
                .then_with(|| a.capability_id.cmp(&b.capability_id))
        });
        Ok(alerts)
    }
}
