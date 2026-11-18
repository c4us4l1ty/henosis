#![deny(unsafe_code)]

//! Leverage analysis for Henosis: constraint-boundary cartography, objective
//! dominance, mandate-to-subtract abandonment, topological skill retention,
//! and multi-criteria option evaluation.
//!
//! Everything here is decision support for the operator, not automation. An
//! interval, gap, or signal marks where to look; it never proves an outcome.
//! Prefer rejecting actions (dominance, abandonment) over accepting them.

pub mod interval;
pub mod mandate;
pub mod objective;
pub mod option;
pub mod retention;
pub mod walls;

pub use interval::Interval;
pub use mandate::{AbandonmentVerdict, Mandate, MandateReport, detect_abandonment, subtraction_targets, weekly_cost_saved};
pub use objective::{analyze, DominanceReport, DominanceRelation, is_dominated_by_frontier, pareto_frontier, Objective};
pub use option::{evaluate_option, evaluate_options, LeverageOption, OptionContext, OptionEvaluation, Recommendation};
pub use retention::{RetentionAxis, RetentionLedger, AxisCurve, DecayAlert};
pub use walls::{ConstraintFacet, ConstraintWall, RankedWall, WallSignal, rank_walls};
