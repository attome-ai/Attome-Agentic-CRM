//! A person's session limits (roadmap Q8-T2), compiled from the
//! `role_auth_policy` rows of their roles: the smallest set value wins, the
//! deployment defaults fill the rest, and administrators never get more than
//! one hour idle or twelve hours in all.

use serde::Serialize;

/// One role's stored session limits; `None` means the deployment default.
#[derive(Debug, Clone, Default, PartialEq, Eq, sqlx::FromRow)]
pub struct RoleSessionRow {
    pub idle_timeout_secs: Option<i32>,
    pub absolute_lifetime_secs: Option<i32>,
    pub max_sessions: Option<i32>,
    pub max_sessions_mode: Option<String>,
}

/// What happens when a sign-in would pass `max_sessions`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaxSessionsMode {
    EndOldest,
    RefuseNew,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionPolicy {
    pub idle_secs: i64,
    pub absolute_secs: i64,
    pub max_sessions: Option<i32>,
    pub mode: MaxSessionsMode,
}

/// The deployment's own limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionDefaults {
    pub idle_secs: i64,
    pub absolute_secs: i64,
}

impl SessionDefaults {
    /// Eight hours idle; `absolute_days` from `auth.refresh_absolute_lifetime_days`.
    pub fn from_absolute_days(absolute_days: i64) -> Self {
        Self {
            idle_secs: 8 * 3600,
            absolute_secs: absolute_days.max(1) * 86_400,
        }
    }
}

/// The most an administrator's session may stay idle, and last.
pub const ADMIN_MAX_IDLE_SECS: i64 = 3600;
pub const ADMIN_MAX_ABSOLUTE_SECS: i64 = 12 * 3600;

pub fn compile(
    rows: &[RoleSessionRow],
    is_admin: bool,
    defaults: SessionDefaults,
) -> SessionPolicy {
    let smallest = |pick: fn(&RoleSessionRow) -> Option<i32>| {
        rows.iter().filter_map(pick).filter(|v| *v > 0).min()
    };
    let mut idle_secs = smallest(|r| r.idle_timeout_secs).map_or(defaults.idle_secs, i64::from);
    let mut absolute_secs =
        smallest(|r| r.absolute_lifetime_secs).map_or(defaults.absolute_secs, i64::from);
    if is_admin {
        idle_secs = idle_secs.min(ADMIN_MAX_IDLE_SECS);
        absolute_secs = absolute_secs.min(ADMIN_MAX_ABSOLUTE_SECS);
    }
    // Refusing a new sign-in is the stricter answer, so one role asking for
    // it is enough.
    let mode = if rows
        .iter()
        .any(|r| r.max_sessions_mode.as_deref() == Some("refuse_new"))
    {
        MaxSessionsMode::RefuseNew
    } else {
        MaxSessionsMode::EndOldest
    };
    SessionPolicy {
        idle_secs,
        absolute_secs,
        max_sessions: smallest(|r| r.max_sessions),
        mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn defaults() -> SessionDefaults {
        SessionDefaults::from_absolute_days(30)
    }

    #[test]
    fn admin_gets_strict_defaults() {
        let p = compile(&[], true, defaults());
        assert_eq!(p.idle_secs, ADMIN_MAX_IDLE_SECS);
        assert_eq!(p.absolute_secs, ADMIN_MAX_ABSOLUTE_SECS);
        let plain = compile(&[], false, defaults());
        assert_eq!(plain.idle_secs, 8 * 3600);
        assert_eq!(plain.absolute_secs, 30 * 86_400);
    }

    #[test]
    fn strictest_role_wins() {
        let rows = vec![
            RoleSessionRow {
                idle_timeout_secs: Some(1800),
                max_sessions: Some(5),
                ..RoleSessionRow::default()
            },
            RoleSessionRow {
                idle_timeout_secs: Some(900),
                absolute_lifetime_secs: Some(86_400),
                max_sessions: Some(2),
                max_sessions_mode: Some("refuse_new".into()),
            },
        ];
        let p = compile(&rows, false, defaults());
        assert_eq!(p.idle_secs, 900);
        assert_eq!(p.absolute_secs, 86_400);
        assert_eq!(p.max_sessions, Some(2));
        assert_eq!(p.mode, MaxSessionsMode::RefuseNew);
    }
}
