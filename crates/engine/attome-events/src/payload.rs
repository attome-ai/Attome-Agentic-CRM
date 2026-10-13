//! Owner-scoped record payload projection (M62 plan §5 "Security" — "a
//! subscription must never be a permission bypass"). Re-reads the record
//! fresh from its physical table at delivery time, respecting the
//! subscription owner's `SecurityContext` at both the entity level (the
//! owner must hold `{entity}.read`) and the field level (an `is_sensitive`
//! column the owner lacks a field-security read grant for is never even
//! SELECTed) — the same two checks `attome_api::entity_crud`'s interactive
//! read path applies, reimplemented here against `attome_core::
//! fetch_entity_snapshot` (the same DB-direct metadata read `attome-api`'s
//! own background-job/bundle-plan paths use) rather than shared with
//! `attome-api` directly: `attome-events` is a peer `xrm-*` engine crate and may
//! not depend on `attome-api`, which sits above the engine layer
//! (guidelines §1).

use attome_core::{fetch_entity_snapshot, quote_ident};
use attome_db::DbPool;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::Value;
use uuid::Uuid;

/// Builds the `data` object a webhook payload carries for one changed
/// record, scoped to what `owner_ctx` may see. `Ok(None)` — not an error —
/// whenever there is nothing safe/possible to include:
///
/// * the owner lacks entity-level `{entity}.read` — no field-level detail
///   leaks through for an entity the owner cannot read at all;
/// * the entity no longer exists/is inactive (deleted since the event was
///   recorded);
/// * the record itself is not currently live (a delete/purge event's record
///   has `is_active = false` by definition — the delivery still carries
///   `entity`/`record_id`/`operation` regardless, just no `data`; see
///   `dispatch`/`delivery`'s payload assembly).
///
/// Field-level scoping within a readable entity is `select_columns_
/// filtered`'s job (same predicate `entity_crud::build_response` uses on the
/// interactive read path) — an `is_sensitive` column the owner lacks a
/// field-security read grant for is never even SELECTed, so it cannot appear
/// in the JSON regardless of what a caller does with the result afterward.
///
/// Deliberately does NOT re-apply record-level (business-unit/team/share)
/// scoping the way an interactive `GET /api/v1/{entity}/{id}` would — doing
/// so exactly would mean re-deriving the full `rls_predicate` WHERE clause
/// here, a materially larger scope than M62 Phase 1. Entity- and
/// field-level scoping are what the plan's §5 and the test suite's
/// "owner-scoped payload" case actually specify; full row-level scoping is
/// flagged as a Phase 2+ hardening item, not silently assumed equivalent.
pub async fn owner_scoped_record_data(
    db: &DbPool,
    owner_ctx: &SecurityContext,
    entity_logicalname: &str,
    record_id: Uuid,
) -> Result<Option<Value>, AppError> {
    if owner_ctx.require(entity_logicalname, "read").is_err() {
        return Ok(None);
    }

    let entity_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity_logicalname)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let Some(entity_id) = entity_id else {
        return Ok(None);
    };

    let Some(meta) = fetch_entity_snapshot(db, entity_id).await? else {
        return Ok(None);
    };

    let table = quote_ident(entity_logicalname);
    // D-589: webhook payloads are a bulk surface.
    let cols = attome_security::field_gate::bulk_columns(
        owner_ctx,
        entity_logicalname,
        &meta.attrs,
        meta.primary_name_attribute.as_deref(),
    );
    let sql = format!(
        "SELECT row_to_json(t) FROM (SELECT {cols} FROM {table} WHERE id = $1 AND is_active = true) t"
    );

    let row: Option<Value> = sqlx::query_scalar::<_, Value>(&sql)
        .bind(record_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;

    Ok(row)
}
