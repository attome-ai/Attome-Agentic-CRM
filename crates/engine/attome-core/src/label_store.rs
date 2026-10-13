//! `metadata_label` per-locale resolution and change-log-driven
//! cache invalidation (M05 Phase 1, D-426).
//!
//! # Cache shape — same simplification `setting_store` makes
//!
//! `metadata_label` is, by construction, a small admin-configured
//! table (a handful of translated strings per object, not a per-record data
//! table), so this cache reloads the *whole* table on every change and swaps
//! the snapshot, exactly like `setting_store::SettingsSnapshot` — see that
//! module's doc comment for the full reasoning (`EntityMetaRegistry`'s
//! incremental per-entity patch is unearned complexity at this table's
//! size). Invalidation is poll-only for the same reason (a settings-table-size
//! cache is not worth a dedicated Redis pub/sub subscriber connection); the
//! writer's own node refreshes synchronously after commit
//! (`attome-server::metadata_label_admin::write_label`), so only *other* nodes
//! rely on the poll loop in `attome-server/src/system.rs`.
//!
//! # Resolution — the fallback chain (D-426)
//!
//! `resolve` implements the chain M05's plan §3.1 specifies: **requested
//! locale -> deployment default locale (`core.locale`, M02/D-412) -> the
//! base `display_name`/`name` column already on the object's own metadata
//! row.** That base column is never overwritten and stays the canonical,
//! locale-less key every internal reference (bundle export, `logicalname`
//! lookups, audit) continues to use — a label row is *only* ever a
//! presentation override, so `resolve` returns `None` rather than a value
//! when neither the requested nor the deployment-default locale has a row,
//! leaving the caller to fall back to that base column itself (this module
//! has no access to it, and reaching across for one string is not worth a
//! dependency).

use std::collections::HashMap;

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Fixed, platform-wide advisory-lock key prefix for `metadata_label`
/// writes (guidelines §2), scoped by the label's own key so concurrent writes
/// to *different* labels never contend — label writes are rare, admin-only
/// operations, same posture as `setting_write_lock_key`.
pub fn label_write_lock_key(object_kind: &str, object_ref: &str, locale: &str) -> String {
    format!("attome-core/label-write:{object_kind}:{object_ref}:{locale}")
}

/// Acquires the per-key advisory lock inside `tx`. Non-blocking, matching
/// `pg_try_advisory_xact_lock`'s semantics used elsewhere (guidelines §2).
///
/// C-18 — delegates to the crate-wide [`crate::try_xact_lock`] shared body.
pub async fn acquire_label_write_lock(
    tx: &mut Tx<'_>,
    object_kind: &str,
    object_ref: &str,
    locale: &str,
) -> Result<(), AppError> {
    crate::try_xact_lock(
        tx,
        &label_write_lock_key(object_kind, object_ref, locale),
        "a write to this metadata label is already in progress",
    )
    .await
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct LabelRow {
    pub id: Uuid,
    pub object_kind: String,
    pub object_ref: String,
    pub locale: String,
    pub display_name: String,
    pub description: Option<String>,
    pub row_version: i64,
    pub updated_at: DateTime<Utc>,
}

/// The runtime label cache — every live row in `metadata_label`,
/// grouped by `(object_kind, object_ref)`. Held behind
/// `EngineState.labels: MetadataCache<LabelSnapshot>` (arc-swap), same tier as
/// `settings`.
#[derive(Default, Clone)]
pub struct LabelSnapshot {
    by_object: HashMap<(String, String), Vec<LabelRow>>,
}

impl std::fmt::Debug for LabelSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabelSnapshot").finish_non_exhaustive()
    }
}

impl LabelSnapshot {
    pub fn rows_for(&self, object_kind: &str, object_ref: &str) -> &[LabelRow] {
        self.by_object
            .get(&(object_kind.to_owned(), object_ref.to_owned()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Resolves a display name + description for `(object_kind, object_ref)`
    /// through the fallback chain (D-426): `requested_locale` first (when
    /// given and a row exists for it), then `deployment_locale`. Returns
    /// `None` when neither has a row — the caller falls back to the object's
    /// own base `display_name`/`name` column, which this module never sees.
    pub fn resolve<'a>(
        &'a self,
        object_kind: &str,
        object_ref: &str,
        requested_locale: Option<&str>,
        deployment_locale: &str,
    ) -> Option<&'a LabelRow> {
        let rows = self.rows_for(object_kind, object_ref);
        if let Some(loc) = requested_locale
            && let Some(row) = rows.iter().find(|r| r.locale == loc)
        {
            return Some(row);
        }
        rows.iter().find(|r| r.locale == deployment_locale)
    }
}

/// Full reload from `metadata_label` — see the module doc for why
/// this is a whole-table reread rather than an incremental patch.
pub async fn load_all(db: &DbPool) -> Result<LabelSnapshot, AppError> {
    let rows: Vec<LabelRow> = sqlx::query_as(
        "SELECT id, object_kind, object_ref, locale, display_name, description, \
                row_version, updated_at \
         FROM metadata_label WHERE is_deleted = FALSE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut by_object: HashMap<(String, String), Vec<LabelRow>> = HashMap::new();
    for row in rows {
        by_object
            .entry((row.object_kind.clone(), row.object_ref.clone()))
            .or_default()
            .push(row);
    }
    Ok(LabelSnapshot { by_object })
}

/// Appends one row to the append-only `metadata_label_change_log`.
/// Call as the last statement before `commit()`, same convention as
/// `change_log::append_change_log`/`setting_store::append_setting_change_log`.
pub async fn append_label_change_log(
    tx: &mut Tx<'_>,
    object_kind: &str,
    object_ref: &str,
    locale: &str,
    is_delete: bool,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "INSERT INTO metadata_label_change_log (object_kind, object_ref, locale, change_kind) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(object_kind)
    .bind(object_ref)
    .bind(locale)
    .bind(if is_delete { "delete" } else { "upsert" })
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Highest committed label-change-log id — the watermark the poll loop
/// compares against (`attome-server/src/system.rs`).
///
/// C-18 — delegates to `change_log::change_log_watermark`, the shared
/// watermark-query body this shares with `change_log::log_watermark`/
/// `setting_store::setting_log_watermark`.
pub async fn label_log_watermark(db: &DbPool) -> Result<i64, AppError> {
    crate::change_log::change_log_watermark(db, "metadata_label_change_log").await
}

/// The closed vocabulary `metadata_label.object_kind` accepts (the
/// migration's CHECK constraint, restated here so callers can validate before
/// ever reaching the database — same convention `bundle::model::KNOWN_FIELD_TYPES`
/// uses for `ensure_attribute`'s field-type vocabulary).
pub const KNOWN_OBJECT_KINDS: &[&str] = &[
    "entity",
    "attribute",
    "choice_option",
    "view",
    "sidebar",
    "dashboard",
];

/// A bare BCP-47 language tag, matching `core.locale`'s own descriptor
/// pattern (`attome_core::setting_catalog`) — `^[a-z]{2}(-[A-Z]{2})?$`.
pub fn is_valid_locale_tag(locale: &str) -> bool {
    let bytes = locale.as_bytes();
    match bytes.len() {
        2 => bytes.iter().all(u8::is_ascii_lowercase),
        5 => {
            bytes[..2].iter().all(u8::is_ascii_lowercase)
                && bytes[2] == b'-'
                && bytes[3..].iter().all(u8::is_ascii_uppercase)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn row(object_kind: &str, object_ref: &str, locale: &str, display_name: &str) -> LabelRow {
        LabelRow {
            id: Uuid::now_v7(),
            object_kind: object_kind.to_owned(),
            object_ref: object_ref.to_owned(),
            locale: locale.to_owned(),
            display_name: display_name.to_owned(),
            description: None,
            row_version: 0,
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn resolves_requested_locale_over_deployment_default() {
        let mut by_object = HashMap::new();
        by_object.insert(
            ("entity".to_owned(), "account".to_owned()),
            vec![
                row("entity", "account", "en-US", "Account"),
                row("entity", "account", "ar-AE", "حساب"),
            ],
        );
        let snapshot = LabelSnapshot { by_object };

        let resolved = snapshot
            .resolve("entity", "account", Some("ar-AE"), "en-US")
            .unwrap();
        assert_eq!(resolved.display_name, "حساب");
    }

    #[test]
    fn falls_back_to_deployment_default_when_requested_locale_has_no_row() {
        let mut by_object = HashMap::new();
        by_object.insert(
            ("entity".to_owned(), "account".to_owned()),
            vec![row("entity", "account", "en-US", "Account")],
        );
        let snapshot = LabelSnapshot { by_object };

        let resolved = snapshot
            .resolve("entity", "account", Some("fr-FR"), "en-US")
            .unwrap();
        assert_eq!(resolved.display_name, "Account");
    }

    #[test]
    fn returns_none_when_neither_locale_has_a_row_so_caller_falls_back_to_base_display_name() {
        let snapshot = LabelSnapshot::default();
        assert!(
            snapshot
                .resolve("entity", "account", Some("ar-AE"), "en-US")
                .is_none()
        );
    }

    #[test]
    fn validates_bcp47_style_tags() {
        assert!(is_valid_locale_tag("en"));
        assert!(is_valid_locale_tag("en-US"));
        assert!(is_valid_locale_tag("ar-AE"));
        assert!(!is_valid_locale_tag("EN"));
        assert!(!is_valid_locale_tag("en_US"));
        assert!(!is_valid_locale_tag(""));
        assert!(!is_valid_locale_tag("english"));
    }
}
