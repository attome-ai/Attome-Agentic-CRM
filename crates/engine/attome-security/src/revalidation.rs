//! D-188 — reactive staleness detection for
//! `field_security_profile_field`'s `entity_logicalname`/
//! `field_logicalname` string references. Same "logged and skipped, never
//! enforced" shape as `attome_records::query_admin::revalidate_all`
//! (P-stored-query-containment addendum §11(c)), applied to the one other
//! logicalname-reference consumer that had no revalidation path: unlike
//! `sql_query`, nothing previously re-checked whether a field-security
//! profile's field still resolves to an active entity/attribute after that
//! field is deactivated via `attome_server::admin::delete_attribute` (or its
//! owning entity via `delete_entity`).
//!
//! Deliberately read-only: a stale row already grants/restricts access to a
//! field nobody can read or write through generic CRUD once it's inactive,
//! so staleness here is a housekeeping signal, not a live security hole.
//! Auto-deleting or auto-deactivating a security-grant row on a background
//! timer would be an unreviewed, silent security-relevant mutation
//! (guidelines §7) — cleanup stays a deliberate admin action.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// One `field_security_profile_field` row whose `entity_logicalname`/
/// `field_logicalname` no longer resolves to an active entity/attribute.
#[derive(Debug, Clone)]
pub struct StaleFieldSecurityRef {
    pub id: Uuid,
    pub profile_ref: Uuid,
    pub entity_logicalname: String,
    pub field_logicalname: String,
}

/// `(id, profile_ref, entity_logicalname, field_logicalname)`. Tuple type,
/// not a `FromRow` derive — matches the row-alias convention
/// `attome-security/src/admin.rs` already uses (`GrantRow` etc.) rather than
/// introducing a new pattern for one query.
type StaleFieldSecurityRefRow = (Uuid, Uuid, String, String);

/// Counts from one `revalidate_field_security_profiles` run — logged by the
/// job handler (`EngineJob::RevalidateFieldSecurityProfiles`), same shape
/// as `attome_records::query_admin::RevalidationSummary`.
#[derive(Debug, Clone, Copy, Default)]
pub struct FieldSecurityRevalidationSummary {
    /// Total active profile-field rows examined this run.
    pub checked: usize,
    /// Rows whose entity or field no longer resolves to an active
    /// `entity_info`/`attribute_info` row.
    pub stale: usize,
}

/// Counts non-deleted field-security profile rows currently referencing
/// `(entity_logicalname, field_logicalname)` — called synchronously from
/// `attome_server::admin::delete_attribute`/`delete_entity` right after a
/// deactivation, purely to log an operator-actionable signal immediately
/// instead of waiting for the next `revalidate_field_security_profiles` job
/// run. Never blocks or fails the deactivation itself — callers treat this as
/// best-effort observability, not a precondition.
pub async fn count_field_security_refs(
    db: &DbPool,
    entity_logicalname: &str,
    field_logicalname: &str,
) -> Result<i64, AppError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM field_security_profile_field f \
         JOIN field_security_profile p ON p.id = f.profile_ref AND p.is_deleted = false \
         WHERE f.entity_logicalname = $1 AND f.field_logicalname = $2",
    )
    .bind(entity_logicalname)
    .bind(field_logicalname)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    Ok(count)
}

/// Entity-scoped sibling of `count_field_security_refs` — called from
/// `attome_server::admin::delete_entity`/`hard_delete_entity`, where every
/// attribute on the entity is deactivated (or removed) at once, so the check
/// is by `entity_logicalname` alone rather than one field at a time.
pub async fn count_field_security_refs_for_entity(
    db: &DbPool,
    entity_logicalname: &str,
) -> Result<i64, AppError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM field_security_profile_field f \
         JOIN field_security_profile p ON p.id = f.profile_ref AND p.is_deleted = false \
         WHERE f.entity_logicalname = $1",
    )
    .bind(entity_logicalname)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    Ok(count)
}

/// Finds every non-deleted field-security profile's field row whose
/// `entity_logicalname` no longer resolves to an active `entity_info`
/// row, or whose `field_logicalname` no longer resolves to an active
/// `attribute_info` row scoped to that entity. Read-only.
pub async fn find_stale_field_security_refs(
    db: &DbPool,
) -> Result<Vec<StaleFieldSecurityRef>, AppError> {
    let rows: Vec<StaleFieldSecurityRefRow> = sqlx::query_as(
        r#"
        SELECT f.id, f.profile_ref, f.entity_logicalname, f.field_logicalname
        FROM field_security_profile_field f
        JOIN field_security_profile p ON p.id = f.profile_ref AND p.is_deleted = false
        LEFT JOIN entity_info e
            ON e.logicalname = f.entity_logicalname
           AND (e.is_active IS NULL OR e.is_active = true)
        LEFT JOIN attribute_info a
            ON a.entity_ref = e.id
           AND a.logicalname = f.field_logicalname
           AND (a.is_active IS NULL OR a.is_active = true)
        WHERE e.id IS NULL OR a.id IS NULL
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    Ok(rows
        .into_iter()
        .map(
            |(id, profile_ref, entity_logicalname, field_logicalname)| StaleFieldSecurityRef {
                id,
                profile_ref,
                entity_logicalname,
                field_logicalname,
            },
        )
        .collect())
}

/// Background job entry point (`EngineJob::RevalidateFieldSecurityProfiles`):
/// logs one `tracing::warn!` per stale row (names the profile/entity/field so
/// an operator can act on it) and returns a summary count. Never mutates
/// `field_security_profile_field` — see this module's doc comment for
/// why.
pub async fn revalidate_field_security_profiles(
    db: &DbPool,
) -> Result<FieldSecurityRevalidationSummary, AppError> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM field_security_profile_field f \
         JOIN field_security_profile p ON p.id = f.profile_ref AND p.is_deleted = false",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    let stale = find_stale_field_security_refs(db).await?;
    for row in &stale {
        tracing::warn!(
            profile_field_id = %row.id,
            profile_ref = %row.profile_ref,
            entity_logicalname = %row.entity_logicalname,
            field_logicalname = %row.field_logicalname,
            "field security profile: stale reference — entity or field no longer active"
        );
    }

    Ok(FieldSecurityRevalidationSummary {
        checked: total.max(0) as usize,
        stale: stale.len(),
    })
}
