//! `shed` — priority load shedding (roadmap AB5-T7). Reports, exports and
//! AI calls each have a number of slots; when interactive requests pile up
//! past `interactive_high_water`, each of those classes runs one request
//! at a time so people clicking through records stay fast.

use serde::Deserialize;

/// Slots per request class.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ShedPermits {
    pub report: usize,
    pub export: usize,
    pub ai: usize,
    pub background: usize,
}

impl Default for ShedPermits {
    fn default() -> Self {
        Self {
            report: 8,
            export: 4,
            ai: 8,
            background: 4,
        }
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ShedSection {
    pub permits: ShedPermits,
    /// Interactive requests in flight above which the other classes shrink
    /// to one at a time.
    pub interactive_high_water: usize,
}

impl Default for ShedSection {
    fn default() -> Self {
        Self {
            permits: ShedPermits::default(),
            interactive_high_water: 200,
        }
    }
}
