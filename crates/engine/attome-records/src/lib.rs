//! T3-2 / D-477 — the platform's generic entity engine, extracted out of
//! `attome-server`: entity CRUD, mutation, bulk operations, and the stored-query
//! executor/admin surface. Sits above `attome-metadata` and `attome-security` (depends
//! on both; neither depends on it) — see D-477 for why this couldn't fold
//! into the existing `attome-metadata` crate instead.
//!
//! Every module here already carries its own `pub fn routes() -> Router<
//! EngineState>` and `pub(crate) fn openapi_fragment()`/`pub fn openapi()`, the
//! same shape every other sibling engine crate uses — `attome-server` mounts
//! these routes and merges this crate's [`openapi()`] exactly as it does for
//! `attome_security`, `attome_notification`, and the rest, rather than owning them
//! directly.
//!
//! # Module map
//! - [`entity_crud`] — generic entity CRUD (`/api/v1/{entity}[/…]`),
//!   read/write access resolution, hierarchy, merge, survivorship, related
//!   records.
//! - [`entity_mutation`] — the shared create/update/delete primitives
//!   `entity_crud`, `bulk`, and sibling engines (`attome-workflow`) call into.
//! - [`bulk`] — bulk entity operations and staged import, including the M12
//!   field-mapping application `data_mapping_admin.rs` (still in
//!   `attome-server`) provisions.
//! - [`query_exec`] — `/api/v1/query/execute`, the stored-query engine.
//! - [`query_admin`] — stored-query CRUD/publish/reconcile admin surface.
//! - [`business_rules`] — the D-789 business-rule write pipeline (locks,
//!   `set_value`, `error` policies) `entity_mutation` runs on every create
//!   and update, for staff, portal and system writers.
//! - [`rule_engine`] — M45 (`attome-rules`) integration: compiling, caching
//!   and evaluating expressions (formula fields, transition guards, legacy
//!   rule kinds, business-rule `set_value` expressions).
//! - [`rw_pin`] — read-your-writes LSN pinning for a just-completed write.

pub mod access_plan;
pub mod bulk;
/// B5-T1: `POST /api/v1/{entity}/bulk-edit`, per-attribute operations over
/// many records, applied by the bulk engine.
pub mod bulk_edit;
mod bulk_graph;
pub mod business_rules;
pub mod data_mapping;
pub mod duplicate_check;
pub mod entity_crud;
pub mod entity_mutation;
/// C-10 — the shared mutation-commit orchestration helper (creator share,
/// file mirror, audit write, commit, post-commit invalidation, rw-pin).
/// `pub`, not `pub(crate)`: `attome-server::communication` and
/// `attome-workflow::scheduler` (both external crates to this one) call
/// [`mutation_ring::MutationRing`] directly, the same reasoning
/// `entity_mutation` is already `pub` for.
pub mod mutation_ring;
pub mod query_admin;
pub mod query_exec;
pub mod rule_engine;
pub mod rw_pin;

/// Advisory-lock namespace for the `"xrm-files/…"` prefix — `entity_
/// mutation`'s file-version lock and `attome-server`'s `files.rs`'s per-
/// (record, field) upload-session lock and per-user/deployment storage-quota
/// locks. Deliberately its own namespace rather than sharing any other one:
/// the upload-session key is per record *and* field, by far the highest-
/// cardinality key space this subsystem takes, and keeping it apart is
/// precisely what stops it colliding with lower-cardinality keys (L-1 /
/// TODO-027).
///
/// Relocated from `attome-server`'s crate root by D-477 (T3-2) when
/// `entity_mutation.rs` moved — same value (`9`), same key string, same
/// registry row in `crates/server/tests/advisory_lock_namespaces.rs`, this
/// is a Rust-path move only. `pub` so `attome-server`'s `files.rs` (which stays
/// put) binds it as `attome_records::FILES_ADVISORY_LOCK_NAMESPACE`.
pub const FILES_ADVISORY_LOCK_NAMESPACE: i32 = 9;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome_server::openapi_document()` the same way every other sibling engine
/// crate's `openapi()` is.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = entity_crud::openapi();
    doc.merge(bulk::openapi_fragment());
    doc.merge(bulk_edit::openapi_fragment());
    doc.merge(query_exec::openapi_fragment());
    doc.merge(query_admin::openapi_fragment());
    doc
}
