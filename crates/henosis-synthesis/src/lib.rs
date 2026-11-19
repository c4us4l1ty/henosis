#![deny(unsafe_code)]

//! Synthesis layer for Henosis: the Axiom Annihilator and the Functorial Bridge.
//!
//! The Axiom Annihilator levels axioms (iron / empirical / convention) and runs
//! the exact minimal hitting-set Lobachevsky operator under an iron-law guard.
//! The Functorial Bridge extracts structural signatures, solves for
//! property-preserving functors by backtracking, and runs the Three-Part
//! Transfer Gate with a spurious-novelty Rejection Filter.
//!
//! All outputs compile to reviewable proposals (`henosis_crux::Event::Proposed`)
//! rather than irreversible state mutations.

pub mod axiom_annihilator;
pub mod functor_bridge;

pub use axiom_annihilator::{
    Axiom, AxiomLevel, AxiomSystem, Conflict, HittingSet, LobachevskyResult, compile_proposal,
    lobachevsky,
};
pub use functor_bridge::{
    AlgebraicProperty, Functor, GateResult, RejectionReason, StructuralSignature, solve_functor,
    spurious_novelty, transfer_gate,
};
