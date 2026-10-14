use attome_core::EngineState;
/// Generic entity CRUD: GET / POST / PATCH / DELETE for any entity table
/// registered in entity_info. Entity logicalname is validated against the
/// DB before being used in dynamic SQL, preventing injection.
use axum::{Router, routing::get};

mod access;
pub mod clone;
pub mod favourites;
mod hierarchy;
/// U6 (basic-units plan B-R12, D-601): `/{entity}/{id}/history`, the
/// record-scoped, field-security-filtered change history.
pub mod history;
/// M01-core C-05: the shared, RLS-aware lookup/polymorphic-reference
/// display-name batch — see its module doc comment.
mod lookup_names;
mod merge;
mod mutations;
pub mod new_record;
pub mod recycle_bin;
/// M01 Core P3 gap (D-455): `/{entity}/{id}/related/{relationship}` — the
/// generic M:M link/unlink/list API.
mod related;
mod resolve;
mod response;
mod row_version;
mod survivorship;
pub mod tags;
/// U3 (basic-units plan B-R4, D-601): `/{entity}/{id}/timeline`, the
/// entity-generic record timeline. `pub` so `attome-service`'s ticket route is a
/// thin caller of it.
pub mod timeline;
mod upsert;

#[cfg(test)]
mod tests;

// Re-exports so every item that was reachable at `entity_crud::X` before this
// directory split still is (external callers: bulk.rs, admin/attribute.rs,
// admin/entity.rs, query_exec.rs, approval_admin.rs, files.rs, files_scan.rs,
// retention.rs, erasure_admin.rs, system.rs, entity_mutation.rs).
// D-477 (T3-2): pub, not pub(crate) — attome-server's approval_admin.rs,
// bulk_transform.rs, communication.rs, data_export.rs, data_profile_admin.rs,
// duplicates_admin.rs, duplicates_match.rs, files.rs, migration.rs, and
// relationship_admin.rs all call into these directly, and attome-server is now
// an external crate to this one.
/// M01 Core C-12: `resolve_cascade_dependent_access` resolves the per-dependent
/// access data `guard_cascade_dependent_access` needs, on the pool, before a
/// caller's own mutation transaction opens — `bulk.rs`'s `apply_one`/
/// `dry_run_one`/`apply_staged_one` all call it the same way
/// `mutations.rs::delete_record` (this directory) does. See
/// `access::resolve_cascade_dependent_access`'s doc comment.
pub use access::resolve_cascade_dependent_access;
pub use access::{
    LEDGER_ENTITIES, POLYMORPHIC_AUDIT_ENTITIES, POLYMORPHIC_CHILD_ENTITIES, fetch_audit_ctx,
    grant_creator_share, guard_cascade_dependent_access, referenced_record_visible,
    require_record_access, require_record_access_with, resolve_record_access_inputs,
};
// Used only inside this crate — kept crate-private. C-10: `mutation_ring`
// (a sibling top-level module, external to this directory) is now a fourth
// caller of the first two, and the ring's hard-delete path needs the third
// (`invalidate_privilege_grant_user`) directly — see
// `GrantInvalidation::ByUser`'s doc comment for why that one case can't go
// through `invalidate_privilege_grant_target`.
pub(crate) use access::{
    invalidate_audit_user_if_systemuser, invalidate_privilege_grant_target,
    invalidate_privilege_grant_user,
};
/// U1 (basic-units plan B-R1): the parent-record gate for polymorphic child
/// entities, shared by this directory's single-record CRUD and `bulk.rs`.
pub(crate) use access::{require_child_parent_access, require_child_parent_access_for_write};
/// M01-core C-05 — `pub`, not `pub(crate)`: `query_exec.rs` (this crate, a
/// sibling module of this directory) and `attome-server`'s `documents_tree.rs`
/// (an external crate, D-477) both batch a lookup/polymorphic-reference
/// field's display name through this same RLS-aware helper instead of each
/// running its own unpredicated `WHERE id = ANY($1)`.
pub use lookup_names::{ResolvedLookup, resolve_visible};
/// D-432 / M13 — the merge core, shared by the HTTP `/{entity}/{id}/merge`
/// endpoint and `duplicates_admin`'s manual/auto-merge paths. See
/// `merge::admin_security_context`'s doc comment for the authorization
/// posture the latter two rely on. `pub`, not `pub(crate)`, since
/// `duplicates_admin.rs`/`approval_admin.rs` (D-477: now external crates)
/// call all three directly.
pub use merge::{MergeResponse, admin_security_context, do_merge_core};
/// `pub`, not `pub(crate)` — `communication.rs` (D-477: now external) uses
/// this directly too.
pub use mutations::field_changes_from_obj;
/// C-10: `mutation_ring` calls this directly for the create/update paths'
/// file-field mirror step, rather than each mutation call site remembering
/// to call it itself. `pub(crate)`, not `pub` — no crate outside this one
/// needs it.
pub(crate) use mutations::sync_file_field_documents;
/// The record read with its full authorization, minus every transport
/// concern. `pub` (not `pub(crate)`) so `attome-ai`'s `record.get` reuses
/// THIS path rather than growing a second one — the same reasoning that makes
/// `entity_mutation` public for `attome-workflow`'s Create/Update nodes.
pub use mutations::{
    CreateCheck, CreateCheckWarning, UpdateOutcome, create_record_for, delete_record_for,
    read_record, read_record_bulk, restore_record_for, update_record_for,
    update_record_for_outcome, update_record_for_with_comment, validate_create,
};
/// M07 Phase A: `POST /{entity}/{id}/transition` takes an optional `If-Match`
/// (absent = the record's current version) with the same parsing rules as
/// the delete/restore paths.
pub use row_version::optional_expected_row_version;

/// `pub`, not `pub(crate)` — a dozen `attome-server` admin surfaces
/// (D-477: now an external crate) resolve a logicalname through this.
pub use resolve::resolve_entity;
/// The direct-Postgres resolver for callers holding only a `DbPool`
/// (`attome-server`'s bundle record sets).
pub use resolve::resolve_entity_from_db;

// Pulled in only to feed the pure-logic unit tests' `use super::*;` below —
// production code in this module never names these directly (each submodule
// that needs them imports them itself).
#[cfg(test)]
use crate::entity_mutation::{json_to_str, sql_cast, validate_body};
#[cfg(test)]
use attome_core::{AttrInfo, OnTargetDelete};
#[cfg(test)]
use attome_types::AppError;
#[cfg(test)]
use row_version::{
    expected_row_version, expected_upsert_row_version, if_none_match_row_version, row_version_etag,
};
#[cfg(test)]
use serde_json::Value;

// â”€â”€ Routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// P-api-contract Phase 1 — this sub-tree's slice of the workspace OpenAPI
/// document; merged by `crate::openapi::openapi_document`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = mutations::openapi_fragment();
    doc.merge(upsert::openapi_fragment());
    doc.merge(hierarchy::openapi_fragment());
    doc.merge(merge::openapi_fragment());
    doc.merge(related::openapi_fragment());
    doc.merge(timeline::openapi_fragment());
    doc.merge(history::openapi_fragment());
    doc.merge(favourites::openapi_fragment());
    doc.merge(clone::openapi_fragment());
    doc.merge(tags::openapi_fragment());
    doc.merge(recycle_bin::openapi_fragment());
    doc.merge(new_record::openapi_fragment());
    doc
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/me/recent",
            get(favourites::list_recent)
                .post(favourites::report_recent)
                .delete(favourites::delete_recent),
        )
        .route("/api/v1/me/favourites", get(favourites::list_favourites))
        .route(
            "/api/v1/{entity}/{id}/tags",
            get(tags::list_record_tags).post(tags::add_record_tag),
        )
        .route(
            "/api/v1/{entity}/{id}/tags/{tag_id}",
            axum::routing::delete(tags::remove_record_tag),
        )
        .route(
            "/api/v1/{entity}/tags/bulk",
            axum::routing::post(tags::bulk_tag_records),
        )
        .route("/api/v1/tags/suggest", get(tags::suggest_tags))
        .route(
            "/api/v1/tags/{tag_id}/records",
            get(tags::list_tagged_records),
        )
        .route(
            "/api/v1/admin/tag-groups",
            get(tags::list_tag_groups).post(tags::create_tag_group),
        )
        .route(
            "/api/v1/me/favourites/lists",
            axum::routing::post(favourites::create_my_list),
        )
        .route(
            "/api/v1/me/favourites/lists/{id}",
            axum::routing::put(favourites::replace_my_list).delete(favourites::delete_my_list),
        )
        .route(
            "/api/v1/teams/{team_id}/favourites/lists",
            axum::routing::post(favourites::create_team_list),
        )
        .route(
            "/api/v1/teams/{team_id}/favourites/lists/{id}",
            axum::routing::put(favourites::replace_team_list).delete(favourites::delete_team_list),
        )
        .route(
            "/api/v1/{entity}",
            axum::routing::post(mutations::create_record),
        )
        .route(
            "/api/v1/{entity}/upsert",
            axum::routing::post(upsert::upsert_record),
        )
        .route(
            "/api/v1/{entity}/validate",
            axum::routing::post(mutations::validate_record),
        )
        .route("/api/v1/{entity}/deleted", get(recycle_bin::list_deleted))
        .route(
            "/api/v1/{entity}/delete-impact",
            axum::routing::post(recycle_bin::preview_delete),
        )
        .route(
            "/api/v1/bin/restore",
            axum::routing::post(recycle_bin::restore_selection),
        )
        .route(
            "/api/v1/bin/operations/{operation_id}/restore",
            axum::routing::post(recycle_bin::restore_operation),
        )
        .route("/api/v1/{entity}/new", get(new_record::new_record_defaults))
        .route(
            "/api/v1/{entity}/{id}",
            get(mutations::get_record)
                .patch(mutations::update_record)
                .delete(mutations::delete_record),
        )
        .route(
            "/api/v1/{entity}/{id}/restore",
            axum::routing::post(mutations::restore_record),
        )
        .route(
            "/api/v1/{entity}/{id}/clone",
            axum::routing::post(clone::clone_record_route),
        )
        .route(
            "/api/v1/{entity}/{id}/hard-delete",
            axum::routing::delete(mutations::hard_delete_record),
        )
        .route(
            "/api/v1/{entity}/{id}/ancestors",
            get(hierarchy::list_ancestors),
        )
        .route(
            "/api/v1/{entity}/{id}/descendants",
            get(hierarchy::list_descendants),
        )
        .route(
            "/api/v1/{entity}/{id}/timeline",
            get(timeline::get_record_timeline),
        )
        .route(
            "/api/v1/{entity}/{id}/timeline/export",
            get(timeline::export_record_timeline),
        )
        .route(
            "/api/v1/{entity}/{id}/history",
            get(history::get_record_history),
        )
        .route(
            "/api/v1/{entity}/{id}/merge",
            axum::routing::post(merge::merge_records),
        )
        .route(
            "/api/v1/{entity}/{id}/related/{relationship}",
            get(related::list_related)
                .post(related::link_related)
                .delete(related::unlink_related),
        )
}
