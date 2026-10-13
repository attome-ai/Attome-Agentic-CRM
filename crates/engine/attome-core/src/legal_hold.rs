//! P-data-protection-governance §4 — per-record/matter legal hold
//! (`legal_hold`, migration `0088_data_protection_governance.sql`),
//! extending — never replacing — D-177's deployment-wide
//! `retention.legal_hold` config flag: that flag stays the outer,
//! all-or-nothing gate (D-002: one dedicated deployment per customer, so a
//! litigation hold is realistically deployment-wide by default); this table
//! adds a narrower hold scoped to one record, or one whole entity
//! (`record_id IS NULL`), for the "freeze this one matter's records, not the
//! whole deployment" case D-177 explicitly deferred.
//!
//! Lives in attome-core, not `attome-metadata` or `attome-audit`, because both
//! `attome_metadata::purge::scrub_record` and `attome_audit::erasure::destroy_key`
//! need the identical check before acting and neither crate may depend on
//! the other (guidelines §1 layering) — exactly the "more than one engine
//! genuinely owns the concept" case that earns a spot here rather than being
//! duplicated in each.

use attome_types::AppError;
use sqlx::Postgres;
use uuid::Uuid;

/// One active hold matching a queried `(entity_logicalname, record_id)` pair.
#[derive(Debug, Clone)]
pub struct LegalHoldInfo {
    pub id: Uuid,
    pub matter_reference: String,
    /// `None` means this is a whole-entity hold (it did not name the queried
    /// record specifically), `Some(record_id)` means a hold naming that exact
    /// record.
    pub record_id: Option<Uuid>,
}

/// Returns the active hold blocking `record_id` in `entity_logicalname`, if
/// any — either a hold naming this exact record, or a whole-entity hold
/// (`legal_hold.record_id IS NULL`). `None` means this table has no
/// objection to acting on the record; the caller must still separately honor
/// the deployment-wide `retention.legal_hold` config flag, which this
/// function has no visibility into (attome-config is not a dependency of this
/// crate — guidelines §1).
///
/// Checked at the point of action (inside `scrub_record`/`destroy_key`
/// themselves), not only when a purge/erasure action is proposed or
/// requested — a hold can be placed after a request was made but before it
/// executes, mirroring D-177's own `dry_run`/`legal_hold` re-check-at-execute
/// precedent (`attome-server/src/retention.rs`).
pub async fn record_is_held<'e, E>(
    executor: E,
    entity_logicalname: &str,
    record_id: Uuid,
) -> Result<Option<LegalHoldInfo>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row: Option<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, matter_reference, record_id FROM legal_hold \
         WHERE entity_logicalname = $1 AND (record_id = $2 OR record_id IS NULL) \
           AND released_at IS NULL AND is_deleted = false \
         ORDER BY record_id NULLS LAST LIMIT 1",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)?;

    Ok(row.map(|(id, matter_reference, record_id)| LegalHoldInfo {
        id,
        matter_reference,
        record_id,
    }))
}
