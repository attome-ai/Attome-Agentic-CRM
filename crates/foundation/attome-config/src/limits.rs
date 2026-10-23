//! AA9-T1: every limit the platform enforces, in one list: what it protects,
//! whether it bounds resources or stops abuse, where it is set, its default
//! per deployment profile, and the range an operator may set it in.
//!
//! A limit is one of two kinds and nothing else ([`LimitKind`]). A
//! per-transaction count limit (how many queries a request may run, how many
//! rows a save may touch in one transaction) is forbidden (V2-D151): it fails
//! real work at an arbitrary size instead of bounding a resource, and
//! work that big belongs on the background path instead.
//!
//! The defaults are the shipped ones: the rate limits are
//! `config.example.json`'s, the statement timeouts are
//! `attome_db::tx::StatementClass::defaults`, the bulk cap is
//! `bulk::MAX_BULK_RECORDS`. Changing one there changes it here too.

/// What a limit is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitKind {
    /// Bounds the memory, time or connections one piece of work may use.
    Resource,
    /// Slows or stops a caller who is guessing, flooding or scraping.
    Abuse,
}

/// Where an operator sets a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitScope {
    /// In the configuration file, read at start.
    BootConfig,
    /// A runtime setting, changed without a restart.
    RuntimeSetting,
}

/// One limit.
#[derive(Debug, Clone, Copy)]
pub struct LimitSpec {
    pub key: &'static str,
    pub purpose: &'static str,
    pub kind: LimitKind,
    pub scope: LimitScope,
    /// The default on one server.
    pub default_solo: i64,
    /// The default for a small team's deployment.
    pub default_team: i64,
    /// The default for a scaled-out deployment.
    pub default_scale: i64,
    /// The smallest value accepted.
    pub floor: i64,
    /// The largest value accepted.
    pub ceiling: i64,
    pub unit: &'static str,
    /// The feature that owns it.
    pub owner: &'static str,
}

const fn rate(key: &'static str, purpose: &'static str, rpm: i64) -> LimitSpec {
    LimitSpec {
        key,
        purpose,
        kind: LimitKind::Abuse,
        scope: LimitScope::BootConfig,
        default_solo: rpm,
        default_team: rpm,
        default_scale: rpm,
        floor: 1,
        ceiling: 10_000_000,
        unit: "requests per minute",
        owner: "rate limiting",
    }
}

const fn timeout(key: &'static str, purpose: &'static str, ms: i64) -> LimitSpec {
    LimitSpec {
        key,
        purpose,
        kind: LimitKind::Resource,
        scope: LimitScope::RuntimeSetting,
        default_solo: ms,
        default_team: ms,
        default_scale: ms,
        floor: 100,
        ceiling: 3_600_000,
        unit: "milliseconds",
        owner: "database",
    }
}

const fn ai_budget(key: &'static str, purpose: &'static str) -> LimitSpec {
    LimitSpec {
        key,
        purpose,
        kind: LimitKind::Resource,
        scope: LimitScope::RuntimeSetting,
        // 0 is "no cap": a budget applies only once an operator sets one.
        default_solo: 0,
        default_team: 0,
        default_scale: 0,
        floor: 0,
        ceiling: 1_000_000_000,
        unit: "currency units per month",
        owner: "N24",
    }
}

/// M1-T4: a flow run's bounds, changed at run time.
const fn workflow_limit(
    key: &'static str,
    purpose: &'static str,
    default: i64,
    floor: i64,
    ceiling: i64,
    unit: &'static str,
) -> LimitSpec {
    LimitSpec {
        key,
        purpose,
        kind: LimitKind::Resource,
        scope: LimitScope::RuntimeSetting,
        default_solo: default,
        default_team: default,
        default_scale: default,
        floor,
        ceiling,
        unit,
        owner: "M1",
    }
}

/// Every limit.
pub static LIMITS: &[LimitSpec] = &[
    rate(
        "rate_limit.authenticated",
        "requests one signed-in caller may make outside a named category",
        600,
    ),
    rate(
        "rate_limit.anonymous",
        "requests one address may make before signing in",
        60,
    ),
    rate(
        "rate_limit.credential",
        "sign-in and credential attempts",
        30,
    ),
    rate("rate_limit.mfa", "second-factor attempts", 20),
    rate("rate_limit.password_reset", "password reset requests", 5),
    rate("rate_limit.api", "generic API calls", 600),
    rate("rate_limit.export", "exports started", 30),
    rate(
        "rate_limit.expensive_query",
        "costly queries and searches",
        600,
    ),
    rate("rate_limit.presign", "file download and upload links", 20),
    rate("rate_limit.consent_capture", "portal consent captures", 600),
    rate("rate_limit.portal_status", "portal status checks", 600),
    rate("rate_limit.webchat", "web chat messages", 600),
    LimitSpec {
        key: "http.max_body_bytes",
        purpose: "the largest request body read",
        kind: LimitKind::Resource,
        scope: LimitScope::BootConfig,
        default_solo: 10 * 1024 * 1024,
        default_team: 10 * 1024 * 1024,
        default_scale: 10 * 1024 * 1024,
        floor: 1,
        ceiling: 1024 * 1024 * 1024,
        unit: "bytes",
        owner: "HTTP",
    },
    LimitSpec {
        key: "bulk.max_records_per_request",
        purpose: "records one bulk request may carry; more go through a staged import",
        kind: LimitKind::Resource,
        scope: LimitScope::RuntimeSetting,
        default_solo: 500,
        default_team: 500,
        default_scale: 500,
        floor: 1,
        ceiling: 10_000,
        unit: "records",
        owner: "bulk",
    },
    timeout(
        "query.timeout_ms.interactive",
        "how long an ordinary request's statement may run",
        5_000,
    ),
    timeout(
        "query.timeout_ms.report",
        "how long a report's statement may run",
        60_000,
    ),
    timeout(
        "query.timeout_ms.export",
        "how long an export's statement may run",
        60_000,
    ),
    LimitSpec {
        key: "auth.mfa_challenge_max_attempts",
        purpose: "wrong codes one second-factor challenge accepts before it is spent",
        kind: LimitKind::Abuse,
        scope: LimitScope::BootConfig,
        default_solo: 5,
        default_team: 5,
        default_scale: 5,
        floor: 1,
        ceiling: 10,
        unit: "attempts",
        owner: "authentication",
    },
    workflow_limit(
        "workflow.max_steps_per_run",
        "node executions one flow run may make, retries included",
        1_000,
        10,
        100_000,
        "node runs",
    ),
    workflow_limit(
        "workflow.max_loop_items",
        "items one for-each step may go through",
        10_000,
        1,
        1_000_000,
        "items",
    ),
    workflow_limit(
        "workflow.max_nesting",
        "sub-flows and for-each runs one run may nest inside each other",
        20,
        1,
        50,
        "levels",
    ),
    workflow_limit(
        "workflow.max_run_minutes",
        "minutes a flow run may last, waits included",
        43_200,
        1,
        525_600,
        "minutes",
    ),
    ai_budget(
        "ai.spend.deployment_monthly",
        "what the whole deployment may spend on models in a month",
    ),
    ai_budget(
        "ai.spend.caller_monthly",
        "what one person may spend on models in a month",
    ),
    ai_budget(
        "ai.spend.agent_monthly",
        "what one agent may spend on models in a month",
    ),
];

/// The limit named `key`.
pub fn spec(key: &str) -> Option<&'static LimitSpec> {
    LIMITS.iter().find(|limit| limit.key == key)
}

/// AA9-T2: every boot-config limit this configuration sets, as
/// `(registry key, value)`. A rate category the configuration does not name
/// falls back to the top-level rates, which are checked themselves.
pub fn boot_values(config: &crate::AppConfig) -> Vec<(String, i64)> {
    let rate = &config.rate_limit;
    let mut values = vec![
        (
            "rate_limit.anonymous".to_owned(),
            i64::from(rate.anonymous_rpm),
        ),
        (
            "rate_limit.authenticated".to_owned(),
            i64::from(rate.authenticated_rpm),
        ),
        (
            "http.max_body_bytes".to_owned(),
            i64::try_from(config.app.max_body_size_bytes).unwrap_or(i64::MAX),
        ),
        (
            "auth.mfa_challenge_max_attempts".to_owned(),
            i64::from(config.auth.mfa_challenge_max_attempts),
        ),
    ];
    for (category, limits) in &rate.categories {
        let key = format!("rate_limit.{category}");
        // A category the registry does not list is ruled by the top-level
        // rate's range.
        let key = if spec(&key).is_some() {
            key
        } else {
            "rate_limit.authenticated".to_owned()
        };
        values.push((key.clone(), i64::from(limits.anonymous_rpm)));
        values.push((key, i64::from(limits.authenticated_rpm)));
    }
    values
}

/// AA9-T2: every boot-config limit outside its range, one line each.
pub fn boot_violations(config: &crate::AppConfig) -> Vec<String> {
    boot_values(config)
        .into_iter()
        .filter_map(|(key, value)| validate(&key, value).err())
        .collect()
}

/// Whether `value` is an acceptable setting for `key`.
pub fn validate(key: &str, value: i64) -> Result<(), String> {
    let limit = spec(key).ok_or_else(|| format!("{key} is not a known limit"))?;
    if value < limit.floor || value > limit.ceiling {
        return Err(format!(
            "{key} must be between {} and {} {}, got {value}",
            limit.floor, limit.ceiling, limit.unit
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn registry_keys_are_unique() {
        let keys: BTreeSet<&str> = LIMITS.iter().map(|l| l.key).collect();
        assert_eq!(keys.len(), LIMITS.len());
    }

    #[test]
    fn security_limits_have_floor_at_least_one() {
        for limit in LIMITS.iter().filter(|l| l.kind == LimitKind::Abuse) {
            assert!(limit.floor >= 1, "{} may be switched off", limit.key);
        }
    }

    #[test]
    fn defaults_sit_inside_their_range() {
        for limit in LIMITS {
            for default in [limit.default_solo, limit.default_team, limit.default_scale] {
                assert!(validate(limit.key, default).is_ok(), "{}", limit.key);
            }
        }
        assert!(validate("auth.mfa_challenge_max_attempts", 0).is_err());
        assert!(validate("bulk.max_records_per_request", 10_001).is_err());
        assert!(validate("no.such.limit", 1).is_err());
    }
}
