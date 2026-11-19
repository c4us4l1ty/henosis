//! Bounded real interval used for every quantitative estimate in this crate.
//!
//! Henosis treats all cost, retention, and objective figures as intervals with
//! explicit uncertainty, never as point estimates. An interval is only a model
//! of ignorance: wide intervals mean "we do not know," not "the value is free."

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interval {
    pub lo: f64,
    pub hi: f64,
}

impl Interval {
    pub fn new(lo: f64, hi: f64) -> Result<Self, String> {
        if !(lo.is_finite() && hi.is_finite()) {
            return Err("interval bounds must be finite".into());
        }
        if lo > hi {
            return Err(format!("interval lower bound {lo} exceeds upper bound {hi}"));
        }
        Ok(Self { lo, hi })
    }

    pub fn point(value: f64) -> Result<Self, String> {
        if !value.is_finite() {
            return Err("point interval must be finite".into());
        }
        Ok(Self { lo: value, hi: value })
    }

    pub fn is_empty(self) -> bool {
        self.lo > self.hi
    }

    pub fn width(self) -> f64 {
        (self.hi - self.lo).max(0.0)
    }

    pub fn midpoint(self) -> f64 {
        (self.lo + self.hi) / 2.0
    }

    pub fn contains(self, value: f64) -> bool {
        value.is_finite() && self.lo <= value && value <= self.hi
    }

    pub fn intersects(self, other: Self) -> bool {
        self.lo <= other.hi && other.lo <= self.hi
    }

    pub fn clamp(self, value: f64) -> f64 {
        value.clamp(self.lo, self.hi)
    }
}
