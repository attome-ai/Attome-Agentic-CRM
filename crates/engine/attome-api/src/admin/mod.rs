// P-db-privilege-separation / D-117: every handler under this module reads/
// writes entity_info/attribute_info and/or calls
// attome-metadata::provision's DDL (ensure_entity, ensure_attribute,
// evolve_attribute_schema, drop_table, ...) — this is the entity/attribute
// schema-admin surface (system.admin gated on every route), not ordinary
// request-time record CRUD. Every query here deliberately runs on
// `state.base.db_migrator`, not `state.base.db`, so this module can keep
// working once `db`/`database.user` is locked down to DML-only (see
// AppState::db_migrator's doc comment).
//
// P-crate-pruning §4.3: split from a single 1,663-line admin.rs into sibling
// modules by use case (entity-level schema admin vs. attribute-level schema
// admin), mirroring the existing entity_crud/bulk.rs precedent. Pure move —
// no behavior change. `entity` and `attribute` share the cross-cutting
// metadata-invalidation helpers below.

mod attribute;
/// Y12-T2: the per-entity DDL ledger.
/// Y12-T3: how proposed structure changes will run.
mod change_plan;
/// Y12-T5: a data step run's progress, pause, resume and cancel.
mod data_step_runs;
mod ddl_log;
#[cfg(debug_assertions)]
mod dev_scaffold;
mod entity;
/// Y2-T4: lookup values that point at no record.
pub(crate) mod orphans;
/// Solution 7 Phase 2 (D-788 rule 9) — the 30-day recovery archive routes.
mod recovery_archive;
/// Solution 7 Phase 2 (D-788 Topic 14, D-791) — the release report routes.
mod release_report;

use attome_audit::AuditFieldChange;
use attome_cache::Store;
use attome_core::EngineState;
use axum::{
    Router,
    routing::{get, patch, post},
};

use uuid::Uuid;

use attribute::{
    abandon_field_run, add_attribute_choice, attribute_index_status,
    attribute_schema_change_status, change_attribute_type, choice_usage, create_attribute,
    delete_attribute, remove_attribute_choice, rename_attribute, update_attribute,
};
#[cfg(debug_assertions)]
use dev_scaffold::{dev_tools_available, scaffold_form_component};
use entity::{create_entity, delete_entity, get_entity, list_entities, update_entity};

/// D-195/P-four-eyes-approval §5 step 9 — `approval_admin::execute_approved`
/// (a sibling top-level module, not a descendant of `admin`) needs to name
/// these directly; `attribute`'s own submodule declaration above is private,
/// so without this re-export nothing outside `admin::attribute` itself could
/// reach them. Same cross-module wrinkle `attome_security::admin`'s
/// `ACTION_ROLE_GRANT`/`do_assign_user_role` re-export documents.
pub(crate) use attribute::{
    ACTION_SCHEMA_CHANGE, CreateAttributeBody, StructureAction, UpdateAttributeBody,
    do_create_attribute_recorded, do_update_attribute_recorded, run_structure_change,
};
pub(crate) use entity::{ACTION_ENTITY_DELETE, ACTION_ENTITY_HARD_DELETE, do_delete_entity};

/// P1.15 §4(d): best-effort (see doc comment below), but still bounded — an
/// unreachable Redis must add at most this much latency to a metadata write,
/// not hang the handler indefinitely on top of the Postgres commit it already
/// paid for. The shared `BACKGROUND` bound (500 ms), the value this doorbell
/// has always used: a missed doorbell is caught up by the subscriber's
/// reconnect re-check, so it keeps the longer bound rather than
/// `REQUEST_PATH`'s 300 ms.
const NOTIFY_TIMEOUT: std::time::Duration = attome_cache::timeouts::BACKGROUND;

/// Publishes the `meta_version` doorbell after a metadata write commits so
/// every node's subscriber task wakes up and catches up from
/// `metadata_change_log` (Plan 1.14 — the payload/counter value itself
/// is no longer meaningful, `catch_up` always re-derives truth from the log
/// table). Best-effort — a Redis hiccup here must never fail the request; a
/// missed doorbell is caught by the subscriber's reconnect re-check
/// (`attome-api/src/system.rs`).
pub(crate) async fn notify_metadata_change(redis: &Store) {
    match tokio::time::timeout(NOTIFY_TIMEOUT, redis.incr("meta_version")).await {
        Ok(Ok(n)) => {
            match tokio::time::timeout(
                NOTIFY_TIMEOUT,
                redis.publish("meta_version", &n.to_string()),
            )
            .await
            {
                Ok(Err(e)) => tracing::warn!(error = %e, "failed to publish meta_version doorbell"),
                Err(_) => tracing::warn!("publishing meta_version doorbell timed out"),
                Ok(Ok(_)) => {}
            }
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "failed to INCR meta_version"),
        Err(_) => tracing::warn!("INCR meta_version timed out"),
    }
}

/// P1.12, LSN-aware since P-read-your-writes-lsn — pins `user_id` to the
/// primary after an admin metadata mutation, so ordinary same-user reads
/// afterward aren't served stale by a lagging read replica. Schema reads use
/// the migrator pool because `attribute_info` is intentionally hidden
/// from the stored-query read-only role. Thin wrapper
/// around the shared helper (`rw_pin.rs`) also used by `entity_crud.rs`'s six
/// mutation sites — see that function's doc comment for the LSN-capture and
/// TTL-reconciliation details. Best-effort, same shape as
/// `notify_metadata_change` above — a Redis/LSN-query hiccup here must never
/// fail the request.
pub(crate) async fn pin_write_best_effort(state: &EngineState, user_id: Uuid, action: &str) {
    attome_records::rw_pin::pin_write_with_current_lsn(state, user_id, action).await;
}

/// Shared `AuditService` constructor for `entity.rs`/`attribute.rs`'s
/// schema-admin mutations. Every `create_entity`/`update_entity`/
/// `delete_entity`/`hard_delete_entity`/`do_create_attribute`/
/// `do_update_attribute`/`delete_attribute` write site uses this so the
/// schema-admin surface stops being the one place D-001's audit trail is
/// missing. Re-export of the canonical `attome_audit::audit_service` (M26 R-15
/// dedup) under this module's existing `pub(crate)` name so
/// `entity.rs`/`attribute.rs`'s `use super::audit_service` keeps working
/// unchanged.
pub(crate) use attome_audit::audit_service;

/// Minimal `AuditFieldChange` for a schema-admin scalar diff (entity/
/// attribute metadata such as `name`, `is_required`, `max_length` — not a
/// business-record field), so callers don't repeat this struct's 12 fields
/// at every call site. No lookup/display-value resolution: schema metadata
/// fields aren't lookups themselves.
pub(crate) fn simple_field_change(
    field_name: &str,
    old_value: Option<String>,
    new_value: Option<String>,
) -> AuditFieldChange {
    AuditFieldChange {
        field_name: field_name.to_owned(),
        display_name: None,
        data_type: None,
        old_value,
        new_value,
        old_display_value: None,
        new_display_value: None,
        old_lookup_entity: None,
        old_lookup_name: None,
        new_lookup_entity: None,
        new_lookup_name: None,
        is_sensitive: false,
    }
}

/// P-api-contract Phase 1 — this sub-tree's slice of the workspace OpenAPI
/// document; merged by `crate::openapi::openapi_document`.
pub(crate) fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = entity::openapi_fragment();
    doc.merge(attribute::openapi_fragment());
    doc.merge(recovery_archive::openapi_fragment());
    doc.merge(ddl_log::openapi_fragment());
    doc.merge(data_step_runs::openapi_fragment());
    doc.merge(change_plan::openapi_fragment());
    doc.merge(orphans::openapi_fragment());
    doc.merge(release_report::openapi_fragment());
    // Gated like every other reference to this module (lines 18/36/178): the
    // scaffold is physically absent from release binaries, so an unconditional
    // call here fails `cargo build --release` outright — which is exactly what
    // it did at HEAD, since a debug build (what clippy and the test jobs run)
    // compiles it fine. The routes it documents aren't mounted in release
    // either, so dropping the fragment keeps the document matching the router.
    #[cfg(debug_assertions)]
    doc.merge(dev_scaffold::openapi_fragment());
    doc
}

pub fn routes() -> Router<EngineState> {
    #[allow(unused_mut)]
    let mut router = Router::new()
        .route(
            "/api/v1/admin/entities",
            get(list_entities).post(create_entity),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}",
            get(get_entity).patch(update_entity).delete(delete_entity),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields",
            post(create_attribute),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}",
            patch(update_attribute).delete(delete_attribute),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/index-status",
            get(attribute_index_status),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/schema-change-status",
            get(attribute_schema_change_status),
        )
        // Solution 7 Phase 2 (D-788): structure changes.
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/rename",
            post(rename_attribute),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/change-type",
            post(change_attribute_type),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/choices",
            post(add_attribute_choice),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/choices/{value}",
            axum::routing::delete(remove_attribute_choice),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/choice-usage",
            get(choice_usage),
        )
        .route(
            "/api/v1/admin/entities/{entity_id}/fields/{field_id}/runs/{run_id}/abandon",
            post(abandon_field_run),
        )
        .merge(recovery_archive::routes())
        .merge(ddl_log::routes())
        .merge(data_step_runs::routes())
        .merge(change_plan::routes())
        .merge(orphans::routes())
        .merge(release_report::routes());

    // Physically absent from release binaries — see dev_scaffold.rs's module
    // doc comment for the full dev-only rationale (D-suggested scaffold tool).
    #[cfg(debug_assertions)]
    {
        router = router
            .route(
                "/api/v1/admin/dev-tools/available",
                get(dev_tools_available),
            )
            .route(
                "/api/v1/admin/entities/{entity_id}/scaffold-ui",
                post(scaffold_form_component),
            );
    }

    router
}
