//! `extensions` — the limits of extension calls (roadmap Y10-T1), read by
//! `attome-extension`'s runtime.

use serde::Deserialize;

/// Limits of one extension call.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ExtensionsSection {
    /// Fuel one call may spend, about one unit per instruction.
    pub fuel: u64,
    /// The most linear memory one call may hold, in MiB (1 to 4096).
    pub memory_mib: u32,
    /// The longest one call may run, in milliseconds (1 to 60000).
    pub timeout_ms: u32,
}

impl Default for ExtensionsSection {
    fn default() -> Self {
        Self {
            fuel: 100_000_000,
            memory_mib: 64,
            timeout_ms: 500,
        }
    }
}

impl ExtensionsSection {
    /// The memory and time limits are in range.
    pub fn check(&self) -> Result<(), (String, String)> {
        if !(1..=4096).contains(&self.memory_mib) {
            return Err(("extensions.memory_mib".into(), "1 to 4096".into()));
        }
        if !(1..=60_000).contains(&self.timeout_ms) {
            return Err((
                "extensions.timeout_ms".into(),
                "1 to 60000 milliseconds".into(),
            ));
        }
        if self.fuel == 0 {
            return Err(("extensions.fuel".into(), "more than 0".into()));
        }
        Ok(())
    }
}
