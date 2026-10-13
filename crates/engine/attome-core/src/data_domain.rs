//! M15 (Data Governance, D-413) — the accountability-register read
//! primitive: resolving which `data_domain` (migration
//! `0171_data_domain.sql`) an entity belongs to, and who that domain's
//! steward is.
//!
//! Lives in attome-core, not one engine crate, for the same reason
//! `legal_hold.rs` does: the M15 plan's own §3 design names this as the
//! default reviewer for M03 access reviews, M13 duplicate queues, M14
//! quality issues, and M24 DSRs — four different call sites, several of
//! which (M03/M13/M14) are not yet built as engine crates and may not all
//! land in the same one. A shared foundation primitive means none of them
//! needs a dependency on whichever crate happened to build this table, and
//! none of them duplicates the join.
//!
//! Domain CRUD (create/list/update/assign-entities) and the accountability
//! report endpoint are the HTTP surface for this table family and live in
//! `attome-compliance::governance_admin`, alongside `legal_hold_admin`/
//! `dsr_admin`/`retention_admin` — this module only holds the read-only
//! resolution primitive those and future callers share.

use attome_types::AppError;
use sqlx::Postgres;
use uuid::Uuid;

/// Returns the accountable steward for `entity_logicalname`'s data domain,
/// if the entity is currently assigned to one
/// (`entity_info.domain_ref`) and that domain names an owner.
/// Falls back to the domain's `deputy_ref` when no `steward_ref` is set.
/// Returns `None` when the entity has no domain, the domain names neither a
/// steward nor a deputy, or the entity itself does not exist or is inactive.
///
/// This is a read-only lookup, not a "default reviewer" workflow assignment
/// — this platform has no generic reviewer/assignment concept yet (M03
/// doesn't exist as an engine). Today's caller
/// (`attome_compliance::legal_hold_admin::place_hold`) surfaces the resolved id
/// purely as information for the placing admin; it does not gate or route
/// anything on it. A future M03/M13/M14/M24 queue that wants to actually
/// *assign* a steward as an owner/reviewer should call this at its own
/// creation point and store the result on its own row — this function only
/// answers "who would that be right now".
pub async fn resolve_steward_for_domain<'e, E>(
    executor: E,
    entity_logicalname: &str,
) -> Result<Option<Uuid>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let row: Option<(Option<Uuid>, Option<Uuid>)> = sqlx::query_as(
        "SELECT d.steward_ref, d.deputy_ref \
           FROM entity_info e \
           JOIN data_domain d ON d.id = e.domain_ref \
          WHERE e.logicalname = $1 AND e.is_active = true AND d.is_deleted = false",
    )
    .bind(entity_logicalname)
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)?;

    Ok(row.and_then(|(steward_ref, deputy_ref)| steward_ref.or(deputy_ref)))
}

// Pure-logic coverage would just re-assert one SQL join with no branching
// worth a unit test in isolation; DB-backed coverage lives in
// `crates/xrm/attome-server/tests/governance_admin.rs`.
