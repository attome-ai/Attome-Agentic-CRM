//! Feature-flag evaluation (M95, D-430).
//!
//! # The invariant
//!
//! `evaluation = license.allows(module) && module_enabled && flag_value(scope)`.
//!
//! In this codebase `ModuleSet` (`EngineState.license`) already fuses
//! "signed license grants this module" and "an admin hasn't turned it off in
//! Module Management" into one bitset: `load_license`
//! (`attome-server/src/system.rs`) builds `ModuleSet` from
//! `module_configuration` (`enabled` + `enabled_modules`) whenever
//! that self-hosted row is readable, falling back to the signed
//! `license` row only if it isn't — and `ModelRegistry::mounted_routes`
//! gates every engine's own routes on exactly `ModuleSet::has_module`.
//! So `license.allows(module) && module_enabled` in the invariant above is
//! `ModuleSet::has_module(flag.module)` — one check, not two — and it is
//! the *same* check that produces `AppError::FeatureHidden` for that
//! module's routes. [`is_on`] performs it first, unconditionally, before it
//! ever looks at the stored flag value: a flag can only narrow what the
//! license already allows, never widen it. `dependency_and_license_invariant`
//! below is the test that pins this.
//!
//! # Storage
//!
//! A flag's policy value is one `setting` row at `Deployment` scope,
//! key `"feature.{flag.key}"` (`setting_catalog.rs`'s `feature_flag_settings`).
//! The JSON value is a [`FeatureFlagPolicy`] carrying all three targeting
//! tiers the M95 plan calls for (deployment / role / user) plus an optional
//! progressive-rollout percentage — inside one blob rather than as separate
//! rows at other `SettingScope`s, since that enum has no `Role` variant and
//! this module rides entirely on the M02 store as-is (no new migration).
//!
//! # Cache
//!
//! `EngineState.feature_flags` is a moka `HotCache<bool>` keyed
//! `"{flag_key}:{user_id}"` — the computed evaluation, not the raw policy
//! (which is already cached via `EngineState.settings`, change-log + poll
//! invalidated, same as every other M02 setting). A feature-flag write
//! invalidates it wholesale on the writing node (`EngineState::invalidate_feature_flags`,
//! called right after `write_setting` refreshes `state.settings`); other
//! nodes bound their staleness by TTL, same posture as the D-012 authz L1 —
//! never a security control, since the license check inside `is_on` is
//! always evaluated fresh against the live `ModuleSet` arc-swap on every
//! call, cached or not.

use std::collections::HashMap;

use attome_server::security::SecurityContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::feature_flag_descriptor::{FeatureFlag, registry as flag_registry};
use crate::setting_store::SettingsSnapshot;
use crate::state::EngineState;

/// The moka cache key shape for a computed evaluation — two-part, matching
/// guidelines §5's convention (single-tenant deployment, D-002).
pub fn feature_flag_cache_key(flag_key: &str, user_id: Uuid) -> String {
    format!("{flag_key}:{user_id}")
}

/// The stored policy value for one flag (`setting.value` under the
/// `feature.*` namespace). All three targeting tiers the M95 plan calls for,
/// plus the optional progressive-rollout percentage, live in one blob — see
/// the module doc for why.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct FeatureFlagPolicy {
    /// The deployment-wide base value.
    #[serde(default)]
    pub deployment: bool,
    /// Stringified user UUID -> explicit override. Highest precedence.
    #[serde(default)]
    pub user_overrides: HashMap<String, bool>,
    /// Privilege key -> override. A caller holding any matching privilege is
    /// in scope; "most permissive role wins" if more than one matches (same
    /// posture the record-level access-level resolution uses elsewhere in
    /// this codebase). Checked after `user_overrides`, before the
    /// deployment/percentage tier.
    #[serde(default)]
    pub role_overrides: HashMap<String, bool>,
    /// `0..=100`. When present, `deployment: true` is additionally narrowed
    /// to a deterministic hash-of-user-id bucket of that size — the same
    /// user always lands on the same side of the line while the percentage
    /// stays fixed, and a wider rollout only ever adds users, never drops
    /// one already in.
    #[serde(default)]
    pub percentage: Option<u8>,
    /// T6-T1: team id -> override, checked after the user's own and before
    /// the privileges'. A person in several teams gets `true` if any says so.
    #[serde(default)]
    pub team_overrides: HashMap<String, bool>,
    /// T6-T1: organisation (unit) id -> override, matched against the units
    /// the person reaches (`SecurityContext::accessible_org_ids`), after
    /// teams. A person resolved without units is never matched.
    #[serde(default)]
    pub unit_overrides: HashMap<String, bool>,
    /// T6-T1: who answers for the flag (a name, an email or a user id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// T6-T1: when the flag should be gone; listed by the expiry report from
    /// the day after. It changes nothing by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_on: Option<chrono::NaiveDate>,
    /// T6-T1: changes to the deployment value and rollout that take effect at
    /// a time. The latest one whose time has come replaces `deployment` and
    /// `percentage`; overrides stay as stored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schedule: Vec<ScheduledChange>,
}

/// T6-T1: one scheduled change of a flag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct ScheduledChange {
    pub at: chrono::DateTime<chrono::Utc>,
    pub deployment: bool,
    #[serde(default)]
    pub percentage: Option<u8>,
}

/// The most scheduled changes one flag holds.
pub const MAX_SCHEDULED_CHANGES: usize = 20;

/// T6-T1: a flag past its expiry date, for the expiry report.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct ExpiredFlag {
    pub key: String,
    pub owner: Option<String>,
    pub expires_on: chrono::NaiveDate,
}

impl FeatureFlagPolicy {
    fn from_settings(snapshot: &SettingsSnapshot, setting_key: &str, code_default: bool) -> Self {
        snapshot
            .rows_for(setting_key)
            .iter()
            .find(|r| r.scope == "deployment" && r.scope_ref.is_none())
            .and_then(|r| serde_json::from_value::<FeatureFlagPolicy>(r.value.clone()).ok())
            .unwrap_or(FeatureFlagPolicy {
                deployment: code_default,
                ..Default::default()
            })
    }

    /// Validates the shape a write is allowed to store: `percentage` (if
    /// present) must be `<= 100`, and every `user_overrides` key must parse
    /// as a UUID. Called by `attome-server::features_admin` before the value
    /// ever reaches `write_setting` — the generic `validate_against_schema`
    /// minimal validator only checks the top-level JSON `type`, it has no
    /// nested-property support.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(pct) = self.percentage
            && pct > 100
        {
            return Err(format!("percentage must be <= 100, got {pct}"));
        }
        if self.schedule.len() > MAX_SCHEDULED_CHANGES {
            return Err(format!(
                "a flag holds at most {MAX_SCHEDULED_CHANGES} scheduled changes"
            ));
        }
        if let Some(change) = self
            .schedule
            .iter()
            .find(|c| c.percentage.is_some_and(|p| p > 100))
        {
            return Err(format!(
                "the change scheduled at {} has a percentage above 100",
                change.at
            ));
        }
        for key in self.team_overrides.keys().chain(self.unit_overrides.keys()) {
            if Uuid::parse_str(key).is_err() {
                return Err(format!(
                    "team or unit override key {key:?} is not a valid UUID"
                ));
            }
        }
        if self.owner.as_ref().is_some_and(|o| o.chars().count() > 200) {
            return Err("owner is at most 200 characters".to_owned());
        }
        for key in self.user_overrides.keys() {
            if Uuid::parse_str(key).is_err() {
                return Err(format!("user_overrides key {key:?} is not a valid UUID"));
            }
        }
        if self.role_overrides.keys().any(|k| k.trim().is_empty()) {
            return Err("role_overrides keys must not be empty".to_owned());
        }
        Ok(())
    }
}

impl FeatureFlagPolicy {
    /// T6-T1: the deployment value and rollout in force at `now`: the latest
    /// scheduled change whose time has come, else the stored ones. Pure.
    pub fn base_at(&self, now: chrono::DateTime<chrono::Utc>) -> (bool, Option<u8>) {
        self.schedule
            .iter()
            .filter(|c| c.at <= now)
            .max_by_key(|c| c.at)
            .map_or((self.deployment, self.percentage), |c| {
                (c.deployment, c.percentage)
            })
    }
}

/// T6-T1: the flags past their expiry date on `today`, by key. Pure over
/// the settings snapshot.
pub fn expired_flags(snapshot: &SettingsSnapshot, today: chrono::NaiveDate) -> Vec<ExpiredFlag> {
    let mut out: Vec<ExpiredFlag> = flag_registry()
        .iter()
        .filter_map(|flag| {
            let policy =
                FeatureFlagPolicy::from_settings(snapshot, &flag.setting_key(), flag.default);
            let expires_on = policy.expires_on.filter(|d| *d < today)?;
            Some(ExpiredFlag {
                key: flag.key.to_owned(),
                owner: policy.owner,
                expires_on,
            })
        })
        .collect();
    out.sort_by(|a, b| a.key.cmp(&b.key));
    out
}

/// Deterministic, stable-across-restarts-and-nodes bucket for `(flag_key,
/// user_id)`, `0..100`. Keying the hash by the flag too (not just the user)
/// means two different percentage-rollout flags pick independent, uncorrelated
/// subsets of users rather than always widening the same cohort first.
fn rollout_bucket(flag_key: &str, user_id: Uuid) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(flag_key.as_bytes());
    hasher.update(b":");
    hasher.update(user_id.as_bytes());
    let digest = hasher.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    (n % 100) as u8
}

/// Resolves the stored policy against one caller — pure function, no I/O,
/// easily unit-tested. Does **not** perform the license check; callers use
/// [`is_on`] (or replicate its license-first ordering) so the invariant can
/// never be bypassed by calling this directly with a licensed-looking
/// context. Production code reads the clock once per request and calls
/// [`evaluate_policy_at`]; tests use this.
#[cfg(test)]
fn evaluate_policy(flag_key: &str, policy: &FeatureFlagPolicy, ctx: &SecurityContext) -> bool {
    evaluate_policy_at(flag_key, policy, ctx, chrono::Utc::now())
}

/// [`evaluate_policy`] at `now` (T6-T1: scheduled changes), in order: the
/// person, their teams, their units, their privileges, then the deployment
/// value and rollout in force.
fn evaluate_policy_at(
    flag_key: &str,
    policy: &FeatureFlagPolicy,
    ctx: &SecurityContext,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if let Some(v) = policy.user_overrides.get(&ctx.user_id.to_string()) {
        return *v;
    }
    let any_of = |overrides: &HashMap<String, bool>, ids: &[Uuid]| {
        ids.iter()
            .filter_map(|id| overrides.get(&id.to_string()).copied())
            .fold(None, |acc: Option<bool>, v| Some(acc.unwrap_or(false) || v))
    };
    if let Some(v) = any_of(&policy.team_overrides, &ctx.team_ids) {
        return v;
    }
    if let Some(v) = any_of(&policy.unit_overrides, &ctx.accessible_org_ids) {
        return v;
    }

    let role_match = policy
        .role_overrides
        .iter()
        .filter(|(privilege, _)| ctx.privileges.contains(*privilege))
        .map(|(_, v)| *v)
        .fold(None, |acc: Option<bool>, v| Some(acc.unwrap_or(false) || v));
    if let Some(v) = role_match {
        return v;
    }

    let (deployment, percentage) = policy.base_at(now);
    if !deployment {
        return false;
    }
    match percentage {
        Some(pct) => rollout_bucket(flag_key, ctx.user_id) < pct.min(100),
        None => true,
    }
}

/// T6-T1: whether every flag `flag` requires is on for `ctx` (recursively;
/// the catalogue's `requires` graph is acyclic). A required flag whose
/// module is off counts as off. Pure over the snapshot and module set.
fn requirements_met(
    flag: &FeatureFlag,
    snapshot: &SettingsSnapshot,
    modules: &attome_modules::ModuleSet,
    ctx: &SecurityContext,
    now: chrono::DateTime<chrono::Utc>,
    depth: usize,
) -> bool {
    if depth > 16 {
        return false;
    }
    let registry = flag_registry();
    flag.requires.iter().all(|key| {
        let Some(required) = registry.get(key) else {
            return false;
        };
        let policy =
            FeatureFlagPolicy::from_settings(snapshot, &required.setting_key(), required.default);
        modules.has(required.module)
            && evaluate_policy_at(required.key, &policy, ctx, now)
            && requirements_met(required, snapshot, modules, ctx, now, depth + 1)
    })
}

/// Write-time dependency check (M95 checklist item 3): a flag's stored
/// `deployment` value may only become `true` while every flag it `requires`
/// is *also* currently `deployment: true`. Pure function over the current
/// settings snapshot — `attome-server::features_admin` calls this before
/// writing, and it is what the dependency test below exercises directly.
pub fn validate_flag_dependencies(
    flag: &FeatureFlag,
    new_deployment_value: bool,
    settings: &SettingsSnapshot,
) -> Result<(), String> {
    if !new_deployment_value {
        return Ok(());
    }
    let registry = flag_registry();
    for req_key in flag.requires {
        let Some(req_flag) = registry.get(req_key) else {
            // Unreachable in practice — FeatureFlagRegistry::new() already
            // asserts every `requires` entry names a real flag — but never
            // trust that invariant blindly from a write path.
            return Err(format!("{req_key} is not a registered feature flag"));
        };
        let req_policy =
            FeatureFlagPolicy::from_settings(settings, &req_flag.setting_key(), req_flag.default);
        if !req_policy.deployment {
            return Err(format!(
                "cannot enable {}: its prerequisite {req_key} is not enabled deployment-wide",
                flag.key
            ));
        }
    }
    Ok(())
}

/// E13-T1: a policy's value for the deployment as a whole: on only when
/// switched on for everyone, with no partial percentage rollout.
fn deployment_value(policy: &FeatureFlagPolicy) -> bool {
    let (deployment, percentage) = policy.base_at(chrono::Utc::now());
    deployment && percentage.is_none_or(|p| p >= 100)
}

/// Borrowed accessor returned by `EngineState::feature_flags()` — a thin
/// wrapper so the call reads `state.feature_flags().is_on(key, ctx)`, the
/// shape the M95 plan names (`FeatureFlags::is_on(key, &SecurityContext)`).
pub struct FeatureFlags<'a> {
    state: &'a EngineState,
}

impl std::fmt::Debug for FeatureFlags<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeatureFlags").finish_non_exhaustive()
    }
}

impl<'a> FeatureFlags<'a> {
    pub(crate) fn new(state: &'a EngineState) -> Self {
        Self { state }
    }

    /// `evaluation = license.allows(module) && module_enabled && flag_value(scope)`
    /// — see the module doc for how `ModuleSet::has_module` fuses the
    /// first two terms in this codebase, and why that composition can never
    /// be bypassed here. An unknown key (not in the closed catalogue) is
    /// always `false`, never an error — callers ask "is this on", they don't
    /// need to distinguish "off" from "doesn't exist".
    pub async fn is_on(&self, key: &str, ctx: &SecurityContext) -> bool {
        let Some(flag) = flag_registry().get(key) else {
            return false;
        };

        // THE license gate (D-430) — checked first, unconditionally, fresh
        // on every call (never itself cached), exactly mirroring
        // `ModelRegistry::mounted_routes`'s own `has_module` check.
        if !self.state.modules.load().has(flag.module) {
            return false;
        }

        let cache_key = feature_flag_cache_key(key, ctx.user_id);
        if let Some(cached) =
            attome_cache::get_recorded(&self.state.feature_flags, &cache_key, "feature_flags").await
        {
            return cached;
        }

        let snapshot = self.state.settings.load();
        let policy = FeatureFlagPolicy::from_settings(&snapshot, &flag.setting_key(), flag.default);
        let now = chrono::Utc::now();
        // T6-T1: the module (above), then the flags it depends on, then
        // targeting.
        let value = requirements_met(flag, &snapshot, &self.state.modules.load(), ctx, now, 0)
            && evaluate_policy_at(flag.key, &policy, ctx, now);

        self.state.feature_flags.insert(cache_key, value).await;
        value
    }

    /// E13-T1: whether `key` is on for the deployment as a whole, for work
    /// with no signed-in user (a background job). The module gate applies
    /// first, then the policy's deployment value. Per-user and per-role
    /// overrides do not apply (there is no user), and a partial percentage
    /// rollout counts as off, since there is no user to place in a bucket.
    /// Reads the settings snapshot; not cached.
    pub fn is_on_for_deployment(&self, key: &str) -> bool {
        let Some(flag) = flag_registry().get(key) else {
            return false;
        };
        if !self.state.modules.load().has(flag.module) {
            return false;
        }
        let snapshot = self.state.settings.load();
        deployment_value(&FeatureFlagPolicy::from_settings(
            &snapshot,
            &flag.setting_key(),
            flag.default,
        ))
    }

    /// Every registered flag, evaluated for `ctx` — the effective-flags map
    /// `GET /api/v1/features` returns.
    pub async fn effective(&self, ctx: &SecurityContext) -> HashMap<String, bool> {
        let mut out = HashMap::new();
        for flag in flag_registry().iter() {
            out.insert(flag.key.to_owned(), self.is_on(flag.key, ctx).await);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_modules::{MODULE_CORE, MODULE_PROJECT, ModuleSet};
    use std::collections::HashSet;

    fn ctx(user_id: Uuid, privileges: &[&str]) -> SecurityContext {
        SecurityContext {
            user_id,
            is_admin: false,
            privileges: privileges
                .iter()
                .map(|s| s.to_string())
                .collect::<HashSet<_>>(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            field_masks: Default::default(),
            service_principal: false,
        }
    }

    fn snapshot_with(setting_key: &str, policy: &FeatureFlagPolicy) -> SettingsSnapshot {
        use crate::setting_store::SettingRow;
        SettingsSnapshot::from_rows(vec![SettingRow {
            id: Uuid::now_v7(),
            key: setting_key.to_owned(),
            scope: "deployment".into(),
            scope_ref: None,
            value: serde_json::to_value(policy).unwrap(),
            schema: serde_json::json!({}),
            row_version: 0,
            updated_at: chrono::Utc::now(),
        }])
    }

    /// T6-T1: teams and units come after the person and before privileges.
    #[test]
    fn feature_flag_targets_teams_and_units() {
        let team = Uuid::now_v7();
        let unit = Uuid::now_v7();
        let policy = FeatureFlagPolicy {
            deployment: false,
            team_overrides: HashMap::from([(team.to_string(), true)]),
            unit_overrides: HashMap::from([(unit.to_string(), true)]),
            role_overrides: HashMap::from([("beta.tester".to_owned(), false)]),
            ..Default::default()
        };
        let mut in_team = ctx(Uuid::now_v7(), &["beta.tester"]);
        in_team.team_ids = vec![team];
        assert!(evaluate_policy("core.beta_ui", &policy, &in_team));
        let mut in_unit = ctx(Uuid::now_v7(), &[]);
        in_unit.accessible_org_ids = vec![unit];
        assert!(evaluate_policy("core.beta_ui", &policy, &in_unit));
        assert!(!evaluate_policy(
            "core.beta_ui",
            &policy,
            &ctx(Uuid::now_v7(), &["beta.tester"])
        ));
        let bad = FeatureFlagPolicy {
            team_overrides: HashMap::from([("not-a-uuid".to_owned(), true)]),
            ..Default::default()
        };
        assert!(bad.validate().is_err());
    }

    /// T6-T1: the latest scheduled change whose time has come wins.
    #[test]
    fn feature_flag_schedule_takes_effect_at_its_time() {
        let t = |h: i64| {
            chrono::DateTime::<chrono::Utc>::from_timestamp(1_800_000_000 + h * 3600, 0).unwrap()
        };
        let change = |h: i64, deployment: bool, percentage: Option<u8>| ScheduledChange {
            at: t(h),
            deployment,
            percentage,
        };
        let policy = FeatureFlagPolicy {
            deployment: false,
            schedule: vec![change(10, true, Some(20)), change(20, true, None)],
            ..Default::default()
        };
        assert_eq!(policy.base_at(t(5)), (false, None));
        assert_eq!(policy.base_at(t(15)), (true, Some(20)));
        assert_eq!(policy.base_at(t(25)), (true, None));
        let user = ctx(Uuid::now_v7(), &[]);
        assert!(!evaluate_policy_at("core.beta_ui", &policy, &user, t(5)));
        assert!(evaluate_policy_at("core.beta_ui", &policy, &user, t(25)));
        let too_many = FeatureFlagPolicy {
            schedule: (0..21).map(|h| change(h, true, None)).collect(),
            ..Default::default()
        };
        assert!(too_many.validate().is_err());
    }

    /// T6-T1: the expiry report lists flags from the day after their date.
    #[test]
    fn feature_flag_expiry_report() {
        let flag = flag_registry().get("core.beta_ui").unwrap();
        let day = |d: u32| chrono::NaiveDate::from_ymd_opt(2026, 11, d).unwrap();
        let policy = FeatureFlagPolicy {
            owner: Some("platform team".into()),
            expires_on: Some(day(10)),
            ..Default::default()
        };
        let snapshot = snapshot_with(&flag.setting_key(), &policy);
        assert!(expired_flags(&snapshot, day(10)).is_empty());
        let report = expired_flags(&snapshot, day(11));
        assert_eq!(report.len(), 1);
        assert_eq!(report[0].key, "core.beta_ui");
        assert_eq!(report[0].owner.as_deref(), Some("platform team"));
    }

    /// E13-T1: a job with no user sees only the deployment-wide value.
    #[test]
    fn deployment_value_ignores_user_targeting_and_partial_rollouts() {
        let on = FeatureFlagPolicy {
            deployment: true,
            ..Default::default()
        };
        assert!(deployment_value(&on));
        assert!(!deployment_value(&FeatureFlagPolicy::default()));
        let partial = FeatureFlagPolicy {
            deployment: true,
            percentage: Some(30),
            ..Default::default()
        };
        assert!(!deployment_value(&partial));
        let full = FeatureFlagPolicy {
            deployment: true,
            percentage: Some(100),
            ..Default::default()
        };
        assert!(deployment_value(&full));
        let user_only = FeatureFlagPolicy {
            deployment: false,
            user_overrides: HashMap::from([(Uuid::now_v7().to_string(), true)]),
            ..Default::default()
        };
        assert!(!deployment_value(&user_only));
    }

    #[test]
    fn deployment_true_turns_the_flag_on_for_everyone_absent_other_targeting() {
        let flag = flag_registry().get("core.beta_ui").unwrap();
        let policy = FeatureFlagPolicy {
            deployment: true,
            ..Default::default()
        };
        let snapshot = snapshot_with(&flag.setting_key(), &policy);
        let resolved =
            FeatureFlagPolicy::from_settings(&snapshot, &flag.setting_key(), flag.default);
        let c = ctx(Uuid::now_v7(), &[]);
        assert!(evaluate_policy(flag.key, &resolved, &c));
    }

    #[test]
    fn user_override_beats_deployment_off() {
        let flag = flag_registry().get("core.beta_ui").unwrap();
        let user_id = Uuid::now_v7();
        let policy = FeatureFlagPolicy {
            deployment: false,
            user_overrides: HashMap::from([(user_id.to_string(), true)]),
            ..Default::default()
        };
        let snapshot = snapshot_with(&flag.setting_key(), &policy);
        let resolved =
            FeatureFlagPolicy::from_settings(&snapshot, &flag.setting_key(), flag.default);
        assert!(evaluate_policy(flag.key, &resolved, &ctx(user_id, &[])));
        // A different user gets the deployment default (off).
        assert!(!evaluate_policy(
            flag.key,
            &resolved,
            &ctx(Uuid::now_v7(), &[])
        ));
    }

    #[test]
    fn role_override_beats_deployment_default() {
        let flag = flag_registry().get("core.beta_ui").unwrap();
        let policy = FeatureFlagPolicy {
            deployment: false,
            role_overrides: HashMap::from([("beta.tester".to_owned(), true)]),
            ..Default::default()
        };
        let snapshot = snapshot_with(&flag.setting_key(), &policy);
        let resolved =
            FeatureFlagPolicy::from_settings(&snapshot, &flag.setting_key(), flag.default);
        assert!(evaluate_policy(
            flag.key,
            &resolved,
            &ctx(Uuid::now_v7(), &["beta.tester"])
        ));
        assert!(!evaluate_policy(
            flag.key,
            &resolved,
            &ctx(Uuid::now_v7(), &["some.other.privilege"])
        ));
    }

    #[test]
    fn percentage_rollout_is_deterministic_and_bucket_stable() {
        let user_id = Uuid::now_v7();
        let b1 = rollout_bucket("core.beta_ui", user_id);
        let b2 = rollout_bucket("core.beta_ui", user_id);
        assert_eq!(
            b1, b2,
            "the same (flag, user) pair must always hash to the same bucket"
        );
    }

    #[test]
    fn percentage_rollout_zero_never_admits_and_hundred_always_admits() {
        let flag = flag_registry().get("core.beta_ui").unwrap();
        for pct in [0u8, 100u8] {
            let policy = FeatureFlagPolicy {
                deployment: true,
                percentage: Some(pct),
                ..Default::default()
            };
            let snapshot = snapshot_with(&flag.setting_key(), &policy);
            let resolved =
                FeatureFlagPolicy::from_settings(&snapshot, &flag.setting_key(), flag.default);
            let on = evaluate_policy(flag.key, &resolved, &ctx(Uuid::now_v7(), &[]));
            assert_eq!(
                on,
                pct == 100,
                "percentage {pct} should be always-off (0) or always-on (100)"
            );
        }
    }

    #[test]
    fn policy_validate_rejects_out_of_range_percentage_and_bad_uuid_keys() {
        let mut policy = FeatureFlagPolicy {
            percentage: Some(101),
            ..Default::default()
        };
        assert!(policy.validate().is_err());

        policy.percentage = Some(50);
        policy.user_overrides.insert("not-a-uuid".to_owned(), true);
        assert!(policy.validate().is_err());

        policy.user_overrides.clear();
        policy
            .user_overrides
            .insert(Uuid::now_v7().to_string(), true);
        assert!(policy.validate().is_ok());
    }

    // ── The invariant (M95's mandatory test) ────────────────────────────────

    #[test]
    fn a_flag_can_never_widen_an_unlicensed_module_open() {
        // `project.gantt_v2_preview` is gated on MODULE_PROJECT. An admin
        // turns the stored value fully on — deployment: true, no targeting
        // at all — the most permissive value the store can hold.
        let flag = flag_registry().get("project.gantt_v2_preview").unwrap();
        assert_eq!(flag.module, MODULE_PROJECT);
        let policy = FeatureFlagPolicy {
            deployment: true,
            ..Default::default()
        };
        let snapshot = snapshot_with(&flag.setting_key(), &policy);
        let resolved =
            FeatureFlagPolicy::from_settings(&snapshot, &flag.setting_key(), flag.default);
        let c = ctx(Uuid::now_v7(), &[]);

        // The bare policy resolution (no license check) says "on" — proving
        // this isn't a vacuous test where the value was already off.
        assert!(evaluate_policy(flag.key, &resolved, &c));

        // A license that does NOT hold MODULE_PROJECT (e.g. MODULE_CORE
        // only) must still make the flag evaluate false — this is the
        // license-first check `FeatureFlags::is_on` performs, replicated
        // directly here so the invariant is pinned without needing an
        // EngineState/DB fixture.
        let license = ModuleSet::core_only();
        assert!(!license.has(flag.module));
        let effective = license.has(flag.module) && evaluate_policy(flag.key, &resolved, &c);
        assert!(
            !effective,
            "a flag must never make a route reachable that the license gate hides"
        );

        // Conversely, a license that DOES hold MODULE_PROJECT lets the same
        // stored value take effect — proving the license check narrows,
        // never distorts, the stored value.
        let mut licensed_bits = [0u64; 4];
        licensed_bits[MODULE_PROJECT.word] |= MODULE_PROJECT.mask;
        let licensed = ModuleSet::from_bits(licensed_bits);
        assert!(licensed.has(flag.module) && evaluate_policy(flag.key, &resolved, &c));
    }

    #[test]
    fn the_core_only_module_set_turns_off_every_non_core_flag() {
        let degraded = ModuleSet::core_only();
        for flag in flag_registry()
            .iter()
            .filter(|flag| flag.module != MODULE_CORE)
        {
            assert!(
                !degraded.has(flag.module),
                "flag {:?} must be unreachable under a degraded license",
                flag.key
            );
        }
    }

    // ── Dependency enforcement (M95 checklist item 3) ───────────────────────

    #[test]
    fn enabling_a_dependent_flag_without_its_prerequisite_is_rejected() {
        let dependent = flag_registry().get("core.beta_ui_advanced_panels").unwrap();
        assert_eq!(dependent.requires, &["core.beta_ui"]);

        // Prerequisite (core.beta_ui) has no stored row at all -> resolves
        // to its code default, false.
        let empty_snapshot = SettingsSnapshot::default();
        let err = validate_flag_dependencies(dependent, true, &empty_snapshot)
            .expect_err("must reject enabling a dependent whose prerequisite is off");
        assert!(err.contains("core.beta_ui"));

        // Prerequisite explicitly stored as on -> now allowed.
        let prereq = flag_registry().get("core.beta_ui").unwrap();
        let on_policy = FeatureFlagPolicy {
            deployment: true,
            ..Default::default()
        };
        let snapshot = snapshot_with(&prereq.setting_key(), &on_policy);
        validate_flag_dependencies(dependent, true, &snapshot)
            .expect("prerequisite is enabled, so this must be allowed");

        // Disabling the dependent never needs its prerequisite.
        validate_flag_dependencies(dependent, false, &empty_snapshot)
            .expect("turning a flag off never needs its prerequisites checked");
    }
}
