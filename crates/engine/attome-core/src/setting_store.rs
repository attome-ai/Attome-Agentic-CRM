//! `setting` value store, resolution, and change-log-driven cache
//! invalidation (M02 §3, D-412).
//!
//! # Cache shape — a deliberate simplification vs. `EntityMetaRegistry`
//!
//! `EntityMetaRegistry` (`meta_registry.rs`) patches one entity's key at a
//! time because that table is large and per-entity patching avoids a full
//! rebuild on every metadata edit. `setting` is, by construction, a
//! small operational table (a few dozen to a few hundred rows across every
//! deployment) — an admin-configured settings store, not a per-record data
//! table. So this cache does the simpler thing on every change: reload the
//! *whole* table in one query and swap the snapshot. That is still
//! change-log-driven invalidation (the change log is what tells every node
//! *that* something changed and lets it track a watermark to avoid polling
//! blind), it just skips incremental per-key patching as unearned complexity
//! for a table this size. `module_configuration`'s own precedent
//! (hourly poll, no pub/sub at all — see `attome-server/src/system.rs`) already
//! establishes that a poll-driven, full-reread cache is an accepted shape for
//! a small admin-configured singleton in this codebase; this is the same
//! trade-off with a tighter interval, since settings are read on every
//! `/api/v1/settings/me` call rather than only consulted once an hour for
//! license gating.
//!
//! Invalidation is poll-only (no dedicated Redis pub/sub channel) for the
//! same reason: a second always-on subscriber connection per node is a real
//! cost, and a 20s worst-case propagation window is an acceptable trade for
//! a settings table (never a security control — see `attome-server::settings_admin`
//! for why `boot_time_only` settings never reach this table at all). The
//! writer's own node applies its write synchronously after commit (see
//! `settings_admin::put_setting`), so same-node reads are never stale.

use std::collections::HashMap;

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::setting_descriptor::{SettingDescriptor, SettingScope, SettingSource};

/// Fixed, platform-wide advisory-lock key for `setting` writes,
/// namespaced under this crate's `attome-core/` prefix (guidelines §2).
/// Scoped by the setting's own key (not scope/scope_ref) — concurrent writes
/// to *different* keys never contend, and this stays cheap since setting
/// writes are rare, admin/self-service-initiated operations, not a hot path.
pub fn setting_write_lock_key(key: &str) -> String {
    format!("attome-core/setting-write:{key}")
}

/// Acquires the per-key advisory lock inside `tx`. Non-blocking — matches
/// `pg_try_advisory_xact_lock`'s semantics used elsewhere (guidelines §2).
///
/// C-18 — delegates to the crate-wide [`crate::try_xact_lock`] shared body.
pub async fn acquire_setting_write_lock(tx: &mut Tx<'_>, key: &str) -> Result<(), AppError> {
    crate::try_xact_lock(
        tx,
        &setting_write_lock_key(key),
        "a write to this setting is already in progress",
    )
    .await
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct SettingRow {
    pub id: Uuid,
    pub key: String,
    pub scope: String,
    pub scope_ref: Option<Uuid>,
    pub value: serde_json::Value,
    /// A copy of the descriptor's JSON Schema fragment as of the write that
    /// produced this row — not a foreign key to the live descriptor, so a
    /// historical row stays self-describing even after a later release
    /// changes the descriptor's schema (see the migration's header comment).
    pub schema: serde_json::Value,
    pub row_version: i64,
    pub updated_at: DateTime<Utc>,
}

/// The runtime value cache — every live row in `setting`, grouped by
/// key. Held behind `EngineState.settings: MetadataCache<SettingsSnapshot>`
/// (arc-swap), same tier as `EntityMetaRegistry`.
#[derive(Default, Clone)]
pub struct SettingsSnapshot {
    by_key: HashMap<String, Vec<SettingRow>>,
}

impl std::fmt::Debug for SettingsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsSnapshot").finish_non_exhaustive()
    }
}

impl SettingsSnapshot {
    /// Builds a snapshot directly from rows, grouping by key — the shared
    /// tail of `load_all` below, also used by other modules' tests (e.g.
    /// `feature_flag_store`) that need a `SettingsSnapshot` fixture without a
    /// live database.
    pub fn from_rows(rows: Vec<SettingRow>) -> Self {
        let mut by_key: HashMap<String, Vec<SettingRow>> = HashMap::new();
        for row in rows {
            by_key.entry(row.key.clone()).or_default().push(row);
        }
        Self { by_key }
    }

    /// AA9-T3: the stored value of the runtime limit `key` (setting
    /// `limits.{key}`), or `None` when no value is stored, so the caller
    /// keeps its boot value or code default.
    pub fn runtime_limit(&self, key: &str) -> Option<i64> {
        let descriptor = crate::setting_registry().get(&format!("limits.{key}"))?;
        match self.resolve(descriptor, None, None) {
            (_, SettingSource::CodeDefault) => None,
            (value, _) => value.as_i64(),
        }
    }

    pub fn rows_for(&self, key: &str) -> &[SettingRow] {
        self.by_key.get(key).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Resolution order (M02 §3): user -> organization -> deployment -> code
    /// default. Only scopes the descriptor actually `allows_scope` are
    /// consulted — a key with no user-scope entry in `allowed_scopes` never
    /// looks at a user override even if one somehow existed.
    pub fn resolve(
        &self,
        descriptor: &SettingDescriptor,
        user_id: Option<Uuid>,
        organization_ref: Option<Uuid>,
    ) -> (serde_json::Value, SettingSource) {
        let rows = self.rows_for(descriptor.key);

        if descriptor.allows_scope(SettingScope::User)
            && let Some(uid) = user_id
            && let Some(row) = rows
                .iter()
                .find(|r| r.scope == SettingScope::User.as_str() && r.scope_ref == Some(uid))
        {
            return (row.value.clone(), SettingSource::User);
        }
        if descriptor.allows_scope(SettingScope::Organization)
            && let Some(org) = organization_ref
            && let Some(row) = rows.iter().find(|r| {
                r.scope == SettingScope::Organization.as_str() && r.scope_ref == Some(org)
            })
        {
            return (row.value.clone(), SettingSource::Organization);
        }
        if descriptor.allows_scope(SettingScope::Deployment)
            && let Some(row) = rows
                .iter()
                .find(|r| r.scope == SettingScope::Deployment.as_str() && r.scope_ref.is_none())
        {
            return (row.value.clone(), SettingSource::Deployment);
        }
        ((descriptor.default)(), SettingSource::CodeDefault)
    }
}

/// Full reload from `setting` — see the module doc for why this is
/// a whole-table reread rather than an incremental patch.
pub async fn load_all(db: &DbPool) -> Result<SettingsSnapshot, AppError> {
    let rows: Vec<SettingRow> = sqlx::query_as(
        "SELECT id, key, scope, scope_ref, value, schema, row_version, updated_at \
         FROM setting WHERE is_deleted = FALSE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(SettingsSnapshot::from_rows(rows))
}

/// Appends one row to the append-only `setting_change_log`. Call as
/// the last statement before `commit()`, same convention as
/// `change_log::append_change_log`.
pub async fn append_setting_change_log(
    tx: &mut Tx<'_>,
    setting_key: &str,
    scope: SettingScope,
    scope_ref: Option<Uuid>,
    is_delete: bool,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "INSERT INTO setting_change_log (setting_key, scope, scope_ref, change_kind) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(setting_key)
    .bind(scope.as_str())
    .bind(scope_ref)
    .bind(if is_delete { "delete" } else { "upsert" })
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Highest committed setting-change-log id — the watermark the poll loop
/// compares against (`attome-server/src/system.rs`).
///
/// C-18 — delegates to `change_log::change_log_watermark`, the shared
/// watermark-query body this shares with `log_watermark`/
/// `label_store::label_log_watermark`.
pub async fn setting_log_watermark(db: &DbPool) -> Result<i64, AppError> {
    crate::change_log::change_log_watermark(db, "setting_change_log").await
}

// ── Minimal JSON Schema subset validator ────────────────────────────────────
//
// Deliberately not a general JSON Schema implementation — no external
// `jsonschema`-style crate is a workspace dependency today, and pulling one
// in for the handful of keywords the seeded descriptors actually use would
// be exactly the "speculative abstraction" guidelines §0/§13 warn against.
// Supports: `type` (string/integer/number/boolean/array/object), `enum`,
// `minimum`/`maximum` (numeric), `minLength`/`maxLength` (string), `pattern`
// (string, via `regex`). An unrecognized keyword is ignored, not rejected —
// this is a validator for the schemas this module ships, not a conformance
// checker; extend it (or swap in a real crate) if a future descriptor needs
// more.

/// Validates `value` against `schema` (a JSON Schema fragment, as produced by
/// a [`SettingDescriptor::schema`] fn). Returns a human-readable reason on
/// failure — surfaced as `AppError::Validation` by the caller.
pub fn validate_against_schema(
    value: &serde_json::Value,
    schema: &serde_json::Value,
) -> Result<(), String> {
    let Some(obj) = schema.as_object() else {
        return Ok(());
    };

    if let Some(ty) = obj.get("type").and_then(|t| t.as_str()) {
        let ok = match ty {
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "array" => value.is_array(),
            "object" => value.is_object(),
            "null" => value.is_null(),
            _ => true,
        };
        if !ok {
            return Err(format!("expected type \"{ty}\", got {value}"));
        }
    }

    if let Some(allowed) = obj.get("enum").and_then(|e| e.as_array())
        && !allowed.contains(value)
    {
        return Err(format!("{value} is not one of the allowed values"));
    }

    if let Some(n) = value.as_f64() {
        if let Some(min) = obj.get("minimum").and_then(|m| m.as_f64())
            && n < min
        {
            return Err(format!("{n} is below the minimum of {min}"));
        }
        if let Some(max) = obj.get("maximum").and_then(|m| m.as_f64())
            && n > max
        {
            return Err(format!("{n} is above the maximum of {max}"));
        }
    }

    if let Some(s) = value.as_str() {
        if let Some(min_len) = obj.get("minLength").and_then(|m| m.as_u64())
            && (s.chars().count() as u64) < min_len
        {
            return Err(format!("must be at least {min_len} characters"));
        }
        if let Some(max_len) = obj.get("maxLength").and_then(|m| m.as_u64())
            && (s.chars().count() as u64) > max_len
        {
            return Err(format!("must be at most {max_len} characters"));
        }
        if let Some(pattern) = obj.get("pattern").and_then(|p| p.as_str()) {
            match regex::Regex::new(pattern) {
                Ok(re) => {
                    if !re.is_match(s) {
                        return Err(format!("must match pattern {pattern}"));
                    }
                }
                Err(e) => return Err(format!("descriptor schema has an invalid pattern: {e}")),
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_stored_limit_wins_and_none_stored_means_the_boot_value() {
        assert_eq!(
            SettingsSnapshot::from_rows(Vec::new()).runtime_limit("bulk.max_records_per_request"),
            None
        );
        let snapshot = SettingsSnapshot::from_rows(vec![SettingRow {
            id: Uuid::now_v7(),
            key: "limits.bulk.max_records_per_request".into(),
            scope: "deployment".into(),
            scope_ref: None,
            value: json!(3),
            schema: json!({}),
            row_version: 0,
            updated_at: Utc::now(),
        }]);
        assert_eq!(
            snapshot.runtime_limit("bulk.max_records_per_request"),
            Some(3)
        );
        assert_eq!(snapshot.runtime_limit("query.timeout_ms.report"), None);
        assert_eq!(snapshot.runtime_limit("no.such.limit"), None);
    }

    #[test]
    fn resolves_user_over_organization_over_deployment_over_default() {
        let descriptor = crate::setting_catalog::all()
            .into_iter()
            .find(|d| d.key == "core.locale")
            .unwrap();
        let user_id = Uuid::now_v7();
        let org_id = Uuid::now_v7();

        let mut by_key = HashMap::new();
        by_key.insert(
            "core.locale".to_string(),
            vec![
                SettingRow {
                    id: Uuid::now_v7(),
                    key: "core.locale".into(),
                    scope: "deployment".into(),
                    scope_ref: None,
                    value: json!("fr-FR"),
                    schema: json!({}),
                    row_version: 0,
                    updated_at: Utc::now(),
                },
                SettingRow {
                    id: Uuid::now_v7(),
                    key: "core.locale".into(),
                    scope: "organization".into(),
                    scope_ref: Some(org_id),
                    value: json!("de-DE"),
                    schema: json!({}),
                    row_version: 0,
                    updated_at: Utc::now(),
                },
            ],
        );
        let snapshot = SettingsSnapshot { by_key };

        // No user override yet: organization beats deployment.
        let (value, source) = snapshot.resolve(&descriptor, Some(user_id), Some(org_id));
        assert_eq!(value, json!("de-DE"));
        assert_eq!(source, SettingSource::Organization);

        // Add a user override: it now wins.
        let mut snapshot = snapshot;
        snapshot
            .by_key
            .get_mut("core.locale")
            .unwrap()
            .push(SettingRow {
                id: Uuid::now_v7(),
                key: "core.locale".into(),
                scope: "user".into(),
                scope_ref: Some(user_id),
                value: json!("ja-JP"),
                schema: json!({}),
                row_version: 0,
                updated_at: Utc::now(),
            });
        let (value, source) = snapshot.resolve(&descriptor, Some(user_id), Some(org_id));
        assert_eq!(value, json!("ja-JP"));
        assert_eq!(source, SettingSource::User);

        // No org/user context at all: falls back to the deployment row.
        let (value, source) = snapshot.resolve(&descriptor, None, None);
        assert_eq!(value, json!("fr-FR"));
        assert_eq!(source, SettingSource::Deployment);
    }

    #[test]
    fn falls_back_to_code_default_with_no_rows() {
        let descriptor = crate::setting_catalog::all()
            .into_iter()
            .find(|d| d.key == "core.locale")
            .unwrap();
        let snapshot = SettingsSnapshot::default();
        let (value, source) = snapshot.resolve(&descriptor, None, None);
        assert_eq!(value, json!("en-US"));
        assert_eq!(source, SettingSource::CodeDefault);
    }

    #[test]
    fn schema_validation_rejects_out_of_range_integer() {
        let schema = json!({"type": "integer", "minimum": 10, "maximum": 200});
        assert!(validate_against_schema(&json!(25), &schema).is_ok());
        assert!(validate_against_schema(&json!(5), &schema).is_err());
        assert!(validate_against_schema(&json!(500), &schema).is_err());
        assert!(validate_against_schema(&json!("25"), &schema).is_err());
    }

    #[test]
    fn schema_validation_checks_pattern() {
        let schema = json!({"type": "string", "pattern": "^[a-z]{2}(-[A-Z]{2})?$"});
        assert!(validate_against_schema(&json!("en-US"), &schema).is_ok());
        assert!(validate_against_schema(&json!("EN"), &schema).is_err());
    }
}
