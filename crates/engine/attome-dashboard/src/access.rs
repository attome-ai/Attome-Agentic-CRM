//! Record-level authorization helpers for this crate's bespoke routes (R-04).
//!
//! Every handler in `lifecycle.rs`, `layout.rs` (`from-layout`),
//! `widget_actions.rs`, `health.rs`, `context.rs`, `decision.rs`, and
//! `scenario.rs` authorizes with a global `Authorized<Privilege<X>>`
//! (`auth.rs`) and then reads `WHERE id = $1` — that checks the caller holds
//! `attome_dashboard.update` (or the equivalent for `dashboard_decision`/
//! `dashboard_scenario`) *somewhere*, never whether the caller may act on *this
//! particular record* under that entity's own RLS/share model. Generic
//! entity CRUD does not have this gap: it runs
//! `attome_records::entity_crud::require_record_access` (D-133) in front
//! of every plain field read/write. This module gives this crate's bespoke
//! routes the same check.
//!
//! `attome-records` sits above both `attome-metadata` and `attome-security` in
//! the dependency graph (depends on both; neither depends on it, D-477) and
//! does not depend on `attome-dashboard`, so this crate depending on it closes
//! no cycle — see `Cargo.toml`'s comment on the `attome-records`
//! dependency. Unlike `attome-project::access` (written before D-477/T3-2, when
//! the generic engine was still private to `attome-api`, forcing it to
//! reimplement `resolve_entity_access_level` + `rls_predicate*` by hand),
//! this module reuses `require_record_access` directly.
use attome_core::EngineState;
use attome_db::DbPool;
use attome_records::entity_crud::require_record_access;
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use uuid::Uuid;

/// Resolves `logicalname`'s entity id from the live metadata registry
/// without holding the `arc_swap` guard across an `.await` — "load, copy the
/// `Uuid`, drop the guard", same shape as `attome-project::access::
/// project_entity_id`.
pub(crate) fn entity_id(state: &EngineState, logicalname: &str) -> Result<Uuid, AppError> {
    let registry = state.entities.load();
    registry
        .get(logicalname)
        .map(|meta| meta.entity_id)
        .ok_or_else(|| {
            AppError::internal(format!(
                "{logicalname} entity metadata missing from registry"
            ))
        })
}

/// `require_record_access` for any entity this crate calls into by
/// logicalname, not only `attome_dashboard` — `decision.rs`'s `dashboard_decision`
/// and `scenario.rs`'s `dashboard_scenario` share this same helper rather than
/// each growing their own copy. `AppError::NotFound` on a miss is
/// `require_record_access`'s own documented behavior (a caller must not
/// learn a hidden record exists) — preserved here, not reinterpreted.
pub(crate) async fn require_entity_access(
    state: &EngineState,
    ctx: &SecurityContext,
    logicalname: &str,
    record_id: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    let entity_id = entity_id(state, logicalname)?;
    require_record_access(state, ctx, entity_id, logicalname, record_id, action).await
}

/// `attome_dashboard`'s own convenience wrapper — every `lifecycle.rs`/
/// `layout.rs`/`widget_actions.rs`/`health.rs`/`context.rs` route that
/// resolves a `dashboard_id` checks it through this one call.
pub(crate) async fn require_dashboard_access(
    state: &EngineState,
    ctx: &SecurityContext,
    dashboard_id: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    require_entity_access(state, ctx, "attome_dashboard", dashboard_id, action).await
}

#[derive(sqlx::FromRow)]
struct DashboardRefRow {
    dashboard_id: Uuid,
}

/// `widget_id -> section_id -> page_id -> dashboard_id`, one bound SELECT
/// with two JOINs — same join shape as `health.rs::do_health_check`'s own
/// widget/section/page query. `NotFound` on a miss anywhere in the chain
/// (deleted widget, deleted section, deleted page), same non-distinguishing
/// posture `require_record_access` uses for a hidden record.
pub(crate) async fn dashboard_of_widget(db: &DbPool, widget_id: Uuid) -> Result<Uuid, AppError> {
    let row: Option<DashboardRefRow> = sqlx::query_as(
        "SELECT p.dashboard_id AS dashboard_id \
         FROM dashboard_widget w \
         JOIN dashboard_section s ON s.id = w.section_id \
             AND (s.is_active IS NULL OR s.is_active = true) \
         JOIN dashboard_page p ON p.id = s.page_id \
             AND (p.is_active IS NULL OR p.is_active = true) \
         WHERE w.id = $1 AND (w.is_active IS NULL OR w.is_active = true)",
    )
    .bind(widget_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    row.map(|r| r.dashboard_id).ok_or(AppError::NotFound)
}

/// `section_id -> page_id -> dashboard_id`.
pub(crate) async fn dashboard_of_section(db: &DbPool, section_id: Uuid) -> Result<Uuid, AppError> {
    let row: Option<DashboardRefRow> = sqlx::query_as(
        "SELECT p.dashboard_id AS dashboard_id \
         FROM dashboard_section s \
         JOIN dashboard_page p ON p.id = s.page_id \
             AND (p.is_active IS NULL OR p.is_active = true) \
         WHERE s.id = $1 AND (s.is_active IS NULL OR s.is_active = true)",
    )
    .bind(section_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    row.map(|r| r.dashboard_id).ok_or(AppError::NotFound)
}
