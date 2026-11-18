//! Constraint-Boundary Cartographer (`partial F`) and shadow-price estimation.
//!
//! Decomposes active impossibility or friction walls into typed binding facets,
//! measures their asymptotic cost gap (`current_cost / theoretical_minimum`),
//! and aggregates workaround pressure and recorded Failure Atlas hits.
//!
//! Epistemic restraint: a large asymptotic gap or shadow-price band identifies a
//! promising fault line to investigate; it does not prove that the gap can be
//! closed economically, safely, or at all.

use crate::Interval;
use henosis_dag::{validate_id, WorldState};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintFacet {
    PhysicalLimit,
    ThermodynamicBound,
    InformationBound,
    ComputationalComplexity,
    MaterialBound,
    EmpiricalRegime,
    OrganizationalChoke,
    HumanConvention,
}

impl ConstraintFacet {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "physical_limit" | "physical" => Ok(Self::PhysicalLimit),
            "thermodynamic_bound" | "thermodynamic" => Ok(Self::ThermodynamicBound),
            "information_bound" | "information" => Ok(Self::InformationBound),
            "computational_complexity" | "complexity" => Ok(Self::ComputationalComplexity),
            "material_bound" | "material" => Ok(Self::MaterialBound),
            "empirical_regime" | "empirical" => Ok(Self::EmpiricalRegime),
            "organizational_choke" | "organizational" => Ok(Self::OrganizationalChoke),
            "human_convention" | "convention" => Ok(Self::HumanConvention),
            _ => Err(format!("unknown constraint facet '{value}'")),
        }
    }

    pub fn is_iron_law(self) -> bool {
        matches!(
            self,
            Self::PhysicalLimit | Self::ThermodynamicBound | Self::InformationBound
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PhysicalLimit => "physical_limit",
            Self::ThermodynamicBound => "thermodynamic_bound",
            Self::InformationBound => "information_bound",
            Self::ComputationalComplexity => "computational_complexity",
            Self::MaterialBound => "material_bound",
            Self::EmpiricalRegime => "empirical_regime",
            Self::OrganizationalChoke => "organizational_choke",
            Self::HumanConvention => "human_convention",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintWall {
    pub id: String,
    pub title: String,
    pub domain: String,
    pub desired_operation: String,
    pub facets: Vec<ConstraintFacet>,
    pub current_cost: f64,
    pub theoretical_minimum: f64,
    pub cost_unit: String,
    pub workaround_count: u32,
    pub failed_trajectories: u32,
    pub notes: String,
}

impl ConstraintWall {
    pub fn validate(&self) -> Result<(), String> {
        validate_id(&self.id)?;
        if self.title.trim().is_empty()
            || self.domain.trim().is_empty()
            || self.desired_operation.trim().is_empty()
            || self.cost_unit.trim().is_empty()
        {
            return Err("constraint wall requires non-empty title, domain, desired_operation, and cost_unit".into());
        }
        if self.facets.is_empty() {
            return Err("constraint wall must name at least one binding facet".into());
        }
        if !self.current_cost.is_finite()
            || !self.theoretical_minimum.is_finite()
            || self.theoretical_minimum <= 0.0
            || self.current_cost < self.theoretical_minimum
        {
            return Err(
                "current_cost and theoretical_minimum must be finite, positive, and current_cost >= theoretical_minimum"
                    .into(),
            );
        }
        Ok(())
    }

    /// Ratio `current_cost / theoretical_minimum` (>= 1.0).
    pub fn asymptotic_gap(&self) -> f64 {
        self.current_cost / self.theoretical_minimum
    }

    pub fn has_mutable_facet(&self) -> bool {
        self.facets.iter().any(|f| !f.is_iron_law())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WallSignal {
    /// Gap >= 100x with at least one non-iron facet and observed workaround pressure.
    HiddenDelusionCandidate,
    /// Substantial gap or workaround pressure meriting targeted falsification.
    ActiveBottleneck,
    /// Current cost is within 3x of theoretical floor; diminishing returns likely.
    NearAsymptote,
    /// All listed facets are Level-0 iron bounds; reframe objective rather than fight the law.
    IronLawBound,
}

impl WallSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HiddenDelusionCandidate => "hidden_delusion_candidate",
            Self::ActiveBottleneck => "active_bottleneck",
            Self::NearAsymptote => "near_asymptote",
            Self::IronLawBound => "iron_law_bound",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RankedWall {
    pub wall_id: String,
    pub title: String,
    pub domain: String,
    pub asymptotic_gap: f64,
    pub log10_gap: f64,
    pub total_failures: u32,
    pub workaround_pressure: f64,
    /// Explicit uncertainty interval for heuristic shadow-price index (not a
    /// calibrated dollar value or proof of solvability).
    pub shadow_price_band: Interval,
    pub signal: WallSignal,
}

/// Evaluate and rank frontier constraint walls, incorporating linked Failure Atlas
/// entries from `state` when provided.
pub fn rank_walls(
    walls: &[ConstraintWall],
    state: Option<&WorldState>,
) -> Result<Vec<RankedWall>, String> {
    let mut ranked = Vec::with_capacity(walls.len());
    for wall in walls {
        wall.validate()?;
        let atlas_hits = state.map_or(0, |s| {
            let n = s
                .failures
                .values()
                .filter(|f| f.target_id == wall.id)
                .count();
            u32::try_from(n).unwrap_or(u32::MAX)
        });
        let total_failures = wall.failed_trajectories.saturating_add(atlas_hits);
        let gap = wall.asymptotic_gap();
        let log10_gap = gap.log10();
        let raw_pressure = f64::from(wall.workaround_count) + 2.0 * f64::from(total_failures);
        let workaround_pressure = (1.0 + raw_pressure).ln();
        let mutable = wall.has_mutable_facet();

        let signal = if !mutable {
            WallSignal::IronLawBound
        } else if gap >= 100.0 && raw_pressure > 0.0 {
            WallSignal::HiddenDelusionCandidate
        } else if gap < 3.0 {
            WallSignal::NearAsymptote
        } else {
            WallSignal::ActiveBottleneck
        };

        // Express shadow-price estimate as a wide uncertainty interval reflecting
        // whether observed gap is actually recoverable vs. blocked by unmodeled physics.
        let mutability_low = if mutable { 0.35 } else { 0.0 };
        let mutability_high = if mutable { 1.0 } else { 0.1 };
        let base = log10_gap * (1.0 + workaround_pressure);
        let shadow_price_band = Interval::new(base * mutability_low, base * mutability_high)?;

        ranked.push(RankedWall {
            wall_id: wall.id.clone(),
            title: wall.title.clone(),
            domain: wall.domain.clone(),
            asymptotic_gap: gap,
            log10_gap,
            total_failures,
            workaround_pressure,
            shadow_price_band,
            signal,
        });
    }

    ranked.sort_by(|a, b| {
        b.shadow_price_band
            .midpoint()
            .total_cmp(&a.shadow_price_band.midpoint())
            .then_with(|| a.wall_id.cmp(&b.wall_id))
    });
    Ok(ranked)
}
