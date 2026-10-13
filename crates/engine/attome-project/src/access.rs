//! Shared authorization helpers for this crate's bespoke routes.
//!
//! None of them can reuse `attome-api`'s private `entity_crud::resolve_entity`/
//! `require_record_access` (this crate does not depend on `attome-api` — see
//! `seed.rs`'s doc comment), so each reimplements the same
//! `resolve_entity_access_level` + `rls_predicate*` pattern
//! `entity_crud/hierarchy.rs` uses, on `attome_security`'s public API.
use attome_core::EngineState;
use attome_security::{RecordAction, resolve_entity_access_level, rls_predicate_by_column};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use uuid::Uuid;

/// Resolves `attome_project`'s entity id from the live metadata registry
/// without holding the `arc_swap` guard across an `.await` — "load, copy the
/// `Uuid`, drop the guard".
pub(crate) fn project_entity_id(state: &EngineState) -> Result<Uuid, AppError> {
    let registry = state.entities.load();
    registry
        .get("attome_project")
        .map(|meta| meta.entity_id)
        .ok_or_else(|| AppError::internal("attome_project entity metadata missing from registry"))
}

/// Same shape as `project_entity_id`, for `project_resource_rate` — used
/// by `summary.rs`'s `actual_cost` gate, which checks whether the caller can
/// read this entity at all before computing a value derived from its
/// `is_sensitive` rate fields.
pub(crate) fn resource_rate_entity_id(state: &EngineState) -> Result<Uuid, AppError> {
    let registry = state.entities.load();
    registry
        .get("project_resource_rate")
        .map(|meta| meta.entity_id)
        .ok_or_else(|| {
            AppError::internal("project_resource_rate entity metadata missing from registry")
        })
}

/// Same shape as `project_entity_id`, for `resource_allocation` — used by
/// `capacity.rs`'s team-scope gate.
pub(crate) fn resource_allocation_entity_id(state: &EngineState) -> Result<Uuid, AppError> {
    let registry = state.entities.load();
    registry
        .get("resource_allocation")
        .map(|meta| meta.entity_id)
        .ok_or_else(|| {
            AppError::internal("resource_allocation entity metadata missing from registry")
        })
}

pub(crate) fn program_entity_id(state: &EngineState) -> Result<Uuid, AppError> {
    let registry = state.entities.load();
    registry
        .get("project_program")
        .map(|meta| meta.entity_id)
        .ok_or_else(|| AppError::internal("project_program entity metadata missing from registry"))
}

pub(crate) fn portfolio_entity_id(state: &EngineState) -> Result<Uuid, AppError> {
    let registry = state.entities.load();
    registry
        .get("project_portfolio")
        .map(|meta| meta.entity_id)
        .ok_or_else(|| {
            AppError::internal("project_portfolio entity metadata missing from registry")
        })
}

/// Shared by `summary.rs`'s `actual_cost` and `portfolio_program.rs`'s own
/// aggregate cost fields — all three read `project_resource_rate`'s
/// `is_sensitive` rate columns, so all three gate on the same check: does
/// this caller hold *any* read access to that entity at all. `AccessLevel::
/// None` is exactly what `resolve_entity_access_level` returns when no held
/// role grants `project_resource_rate.read`, per that function's own
/// doc comment.
pub(crate) async fn resource_rate_access_level(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<AccessLevel, AppError> {
    let entity_id = resource_rate_entity_id(state)?;
    resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        "project_resource_rate",
        RecordAction::Read,
    )
    .await
}

/// Confirms `project_id` exists, is active, and is visible to `ctx` under
/// record-level RLS — without fetching any of its fields. `AppError::NotFound`
/// covers both "no such project" and "exists, but RLS excludes this caller",
/// same non-distinguishing behavior generic entity reads already give an
/// unauthorized caller. The entity-level `attome_project.read` privilege is
/// already checked by the route's `Authorized<Privilege<ProjectRead>>`
/// extractor before this runs.
pub(crate) async fn authorize_project_access(
    state: &EngineState,
    ctx: &SecurityContext,
    project_id: Uuid,
) -> Result<(), AppError> {
    let entity_id = project_entity_id(state)?;
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        "attome_project",
        RecordAction::Read,
    )
    .await?;
    let rls = rls_predicate_by_column(
        ctx,
        entity_id,
        "p",
        "id",
        access_level,
        RecordAction::Read.share_capability(),
        2,
    );

    let mut sql = "SELECT 1 FROM attome_project p \
         WHERE p.id = $1 AND (p.is_active IS NULL OR p.is_active = true)"
        .to_owned();
    if let Some(pred) = &rls {
        sql.push_str(&pred.sql);
    }

    let mut q = sqlx::query_scalar::<_, i32>(&sql).bind(project_id);
    if let Some(pred) = &rls {
        q = q
            .bind(pred.binds.entity_ref)
            .bind(pred.binds.caller_id)
            .bind(&pred.binds.team_ids)
            .bind(pred.binds.capability)
            .bind(&pred.binds.accessible_org_ids)
            .bind(&pred.binds.subordinate_user_ids);
    }

    let found = q
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    match found {
        Some(_) => Ok(()),
        None => Err(AppError::NotFound),
    }
}

/// Same shape and same reasoning as `authorize_project_access`, for
/// `project_program`. The entity/table name is a fixed `&'static str` literal
/// baked in below, never request input — the "quote dynamic identifiers
/// through the established helper" rule is about a name read from a
/// request or metadata row, not a compile-time constant.
pub(crate) async fn authorize_program_access(
    state: &EngineState,
    ctx: &SecurityContext,
    program_id: Uuid,
) -> Result<(), AppError> {
    let entity_id = program_entity_id(state)?;
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        "project_program",
        RecordAction::Read,
    )
    .await?;
    let rls = rls_predicate_by_column(
        ctx,
        entity_id,
        "p",
        "id",
        access_level,
        RecordAction::Read.share_capability(),
        2,
    );

    let mut sql = "SELECT 1 FROM project_program p \
         WHERE p.id = $1 AND (p.is_active IS NULL OR p.is_active = true)"
        .to_owned();
    if let Some(pred) = &rls {
        sql.push_str(&pred.sql);
    }

    let mut q = sqlx::query_scalar::<_, i32>(&sql).bind(program_id);
    if let Some(pred) = &rls {
        q = q
            .bind(pred.binds.entity_ref)
            .bind(pred.binds.caller_id)
            .bind(&pred.binds.team_ids)
            .bind(pred.binds.capability)
            .bind(&pred.binds.accessible_org_ids)
            .bind(&pred.binds.subordinate_user_ids);
    }

    let found = q
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    match found {
        Some(_) => Ok(()),
        None => Err(AppError::NotFound),
    }
}

/// Same shape and same reasoning as `authorize_project_access`, for
/// `project_portfolio`.
pub(crate) async fn authorize_portfolio_access(
    state: &EngineState,
    ctx: &SecurityContext,
    portfolio_id: Uuid,
) -> Result<(), AppError> {
    let entity_id = portfolio_entity_id(state)?;
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        "project_portfolio",
        RecordAction::Read,
    )
    .await?;
    let rls = rls_predicate_by_column(
        ctx,
        entity_id,
        "p",
        "id",
        access_level,
        RecordAction::Read.share_capability(),
        2,
    );

    let mut sql = "SELECT 1 FROM project_portfolio p \
         WHERE p.id = $1 AND (p.is_active IS NULL OR p.is_active = true)"
        .to_owned();
    if let Some(pred) = &rls {
        sql.push_str(&pred.sql);
    }

    let mut q = sqlx::query_scalar::<_, i32>(&sql).bind(portfolio_id);
    if let Some(pred) = &rls {
        q = q
            .bind(pred.binds.entity_ref)
            .bind(pred.binds.caller_id)
            .bind(&pred.binds.team_ids)
            .bind(pred.binds.capability)
            .bind(&pred.binds.accessible_org_ids)
            .bind(&pred.binds.subordinate_user_ids);
    }

    let found = q
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    match found {
        Some(_) => Ok(()),
        None => Err(AppError::NotFound),
    }
}

/// Same shape and reasoning as `authorize_project_access`/
/// `authorize_program_access`/`authorize_portfolio_access` above,
/// generalized over `(table, logicalname)` — added for
/// `change_request.rs`/`timesheet.rs` rather than hand-copied a fourth and
/// fifth time. `table`/`logicalname` are always a fixed `&'static str`
/// literal at the call site, never request input.
async fn authorize_record_access(
    state: &EngineState,
    ctx: &SecurityContext,
    table: &'static str,
    logicalname: &'static str,
    record_id: Uuid,
) -> Result<(), AppError> {
    let entity_id = {
        let registry = state.entities.load();
        registry
            .get(logicalname)
            .map(|meta| meta.entity_id)
            .ok_or_else(|| {
                AppError::internal(format!(
                    "{logicalname} entity metadata missing from registry"
                ))
            })?
    };
    let access_level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        logicalname,
        RecordAction::Read,
    )
    .await?;
    let rls = rls_predicate_by_column(
        ctx,
        entity_id,
        "r",
        "id",
        access_level,
        RecordAction::Read.share_capability(),
        2,
    );

    let mut sql = format!(
        "SELECT 1 FROM {table} r WHERE r.id = $1 AND (r.is_active IS NULL OR r.is_active = true)"
    );
    if let Some(pred) = &rls {
        sql.push_str(&pred.sql);
    }

    let mut q = sqlx::query_scalar::<_, i32>(&sql).bind(record_id);
    if let Some(pred) = &rls {
        q = q
            .bind(pred.binds.entity_ref)
            .bind(pred.binds.caller_id)
            .bind(&pred.binds.team_ids)
            .bind(pred.binds.capability)
            .bind(&pred.binds.accessible_org_ids)
            .bind(&pred.binds.subordinate_user_ids);
    }

    let found = q
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    match found {
        Some(_) => Ok(()),
        None => Err(AppError::NotFound),
    }
}

/// Confirms `change_request_id` exists, is active, and is visible to `ctx`
/// under record-level RLS. Used by `change_request.rs`'s approve/reject
/// routes before either reads or decides the record; the entity-level
/// `project_change_request.approve` privilege is checked by the route's
/// `Authorized<Privilege<ChangeRequestApprove>>` extractor and `.update` by
/// `decide` (P0 0.7).
pub(crate) async fn authorize_change_request_access(
    state: &EngineState,
    ctx: &SecurityContext,
    change_request_id: Uuid,
) -> Result<(), AppError> {
    authorize_record_access(
        state,
        ctx,
        "project_change_request",
        "project_change_request",
        change_request_id,
    )
    .await
}

/// Same shape, for `timesheet.rs`'s submit/approve/reject routes.
pub(crate) async fn authorize_timesheet_access(
    state: &EngineState,
    ctx: &SecurityContext,
    timesheet_id: Uuid,
) -> Result<(), AppError> {
    authorize_record_access(
        state,
        ctx,
        "project_timesheet",
        "project_timesheet",
        timesheet_id,
    )
    .await
}
