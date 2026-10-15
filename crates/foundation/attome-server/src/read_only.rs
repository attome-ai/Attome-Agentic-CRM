//! Read-only mode (roadmap AB5-T6): while it is on, every write answers 503
//! `read_only` and reads, sign-in and the switch itself keep working.
//!
//! The reason lives in [`crate::state::AppState::read_only`] as a byte;
//! `middleware::mutation_gate` reads it on every mutating request (one atomic
//! load), and `attome_api::spawn_read_only_refresh` sets it from the operator
//! switch (the `ops.read_only` setting, so every node follows it within the
//! refresh interval) and the database-size ceiling.

use std::sync::atomic::{AtomicU8, Ordering};

/// Why the deployment is read-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ReadOnlyReason {
    /// An administrator switched it on.
    Operator = 1,
    /// The database reached its size ceiling.
    Disk = 2,
    /// A restore or recovery is running.
    Recovery = 3,
}

impl ReadOnlyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Disk => "disk",
            Self::Recovery => "recovery",
        }
    }

    fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Operator),
            2 => Some(Self::Disk),
            3 => Some(Self::Recovery),
            _ => None,
        }
    }
}

/// The current reason, if the deployment is read-only.
pub fn current(flag: &AtomicU8) -> Option<ReadOnlyReason> {
    ReadOnlyReason::from_u8(flag.load(Ordering::Relaxed))
}

/// Sets the reason (or clears it) and returns the one it replaced.
pub fn set(flag: &AtomicU8, reason: Option<ReadOnlyReason>) -> Option<ReadOnlyReason> {
    ReadOnlyReason::from_u8(flag.swap(reason.map_or(0, |r| r as u8), Ordering::Relaxed))
}

/// The writes read-only mode still lets through: signing in and out, keeping
/// a session, and the switch that ends it.
pub const ALLOWED_WRITES: &[&str] = &[
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/auth/refresh",
    "/api/v1/admin/settings/ops.read_only",
];

/// Whether a write to `path` still goes through in read-only mode.
pub fn write_allowed(path: &str) -> bool {
    ALLOWED_WRITES.contains(&path.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reason_round_trips_through_the_flag() {
        let flag = AtomicU8::new(0);
        assert_eq!(current(&flag), None);
        assert_eq!(set(&flag, Some(ReadOnlyReason::Disk)), None);
        assert_eq!(current(&flag), Some(ReadOnlyReason::Disk));
        assert_eq!(set(&flag, None), Some(ReadOnlyReason::Disk));
        assert_eq!(current(&flag), None);
    }

    #[test]
    fn sign_in_and_the_switch_stay_writable() {
        assert!(write_allowed("/api/v1/auth/login"));
        assert!(write_allowed("/api/v1/admin/settings/ops.read_only"));
        assert!(!write_allowed("/api/v1/account"));
        assert!(!write_allowed("/api/v1/admin/settings/core.locale"));
    }
}
