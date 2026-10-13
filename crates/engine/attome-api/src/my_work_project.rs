//! Dashboard 10/10 Phase 6 — the Project work `MyWorkProvider`. Lives in
//! `attome-api` for the same reason `my_work_approvals.rs` does: it needs
//! `attome_records::entity_crud::{resolve_entity, require_record_access}`,
//! and `attome-project` cannot depend on `attome-records` (layer direction,
//! guidelines §1).
//!
//! Three sources, one provider (the plan's Project-work row names all three):
//!
//! - `project_change_request` in `pending` — the caller must hold
//!   `project_change_request.update` and `.approve` (the pair
//!   `change_request.rs`'s approve/reject routes require) and be able to read
//!   the record. Actions point at those two routes, which own the impact
//!   application and any four-eyes gate.
//! - `project_timesheet` in `submitted` — the same shape with
//!   `project_timesheet.update` and `.approve`. The approver != owner
//!   guard is the state engine's (a self-decision answers 422 at the route);
//!   this provider mirrors only the privilege pair and adds no rule of its own.
//! - `project_work_item` owned by the caller and not `done` — actions
//!   come from the generic D-406 state-lifecycle registry
//!   (`available_transitions`, which itself filters to transitions the
//!   caller's privileges allow) through the shared generic
//!   `/api/v1/{entity}/{id}/transition` route, never a bespoke endpoint.
//!
//! `actions()` re-resolves fresh from all three tables by primary key — the
//! trait hands it only a record id, and a multi-source provider must not
//! assume which source an id came from.

use attome_core::{
    EngineState, MyWorkAction, MyWorkFuture, MyWorkItem, MyWorkPage, MyWorkProvider,
    available_transitions,
};
use attome_project::auth::{
    ChangeRequestApprove, ChangeRequestUpdate, TimesheetApprove, TimesheetUpdate,
};
use attome_records::entity_crud::{require_record_access, resolve_entity};
use attome_security::RecordAction;
use attome_server::authz::PrivilegeKey;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Same bounded-scan posture as `my_work_approvals::SCAN_LIMIT`.
const SCAN_LIMIT: i64 = 500;
const CR_ENTITY: &str = "project_change_request";
const TS_ENTITY: &str = "project_timesheet";
const WI_ENTITY: &str = "project_work_item";

#[derive(Debug)]
pub struct ProjectMyWorkProvider;

#[derive(Debug, sqlx::FromRow)]
struct ChangeRequestRow {
    id: Uuid,
    title: String,
    status: String,
    requested_date: Option<DateTime<Utc>>,
}

#[derive(Debug, sqlx::FromRow)]
struct TimesheetRow {
    id: Uuid,
    status: String,
    week_start_date: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct WorkItemRow {
    id: Uuid,
    name: String,
    status: String,
    due_date: Option<DateTime<Utc>>,
}

impl MyWorkProvider for ProjectMyWorkProvider {
    fn name(&self) -> &'static str {
        "project"
    }

    fn count<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
    ) -> MyWorkFuture<'a, usize> {
        Box::pin(async move { Ok(eligible_items(state, ctx).await?.len()) })
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        cursor: Option<&'a str>,
        limit: usize,
    ) -> MyWorkFuture<'a, MyWorkPage> {
        Box::pin(async move {
            let mut items = eligible_items(state, ctx).await?;
            sort_items(&mut items);
            let offset: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
            let page = items
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect::<Vec<_>>();
            let next_cursor =
                (offset + page.len() < items.len()).then(|| (offset + page.len()).to_string());
            Ok(MyWorkPage::new(page, next_cursor))
        })
    }

    fn actions<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        record_id: Uuid,
    ) -> MyWorkFuture<'a, Vec<MyWorkAction>> {
        Box::pin(async move {
            if let Some(row) = fetch_change_request(state, ctx, record_id).await? {
                return Ok(change_request_actions(row.id));
            }
            if let Some(row) = fetch_timesheet(state, ctx, record_id).await? {
                return Ok(timesheet_actions(row.id));
            }
            if let Some(row) = fetch_work_item(state, ctx, record_id).await? {
                return Ok(work_item_actions(state, ctx, &row));
            }
            Ok(Vec::new())
        })
    }
}

/// Every open item the caller may act on now, across the three sources.
async fn eligible_items(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Vec<MyWorkItem>, AppError> {
    let mut items = Vec::new();

    if holds(ctx, ChangeRequestUpdate::KEY) && holds(ctx, ChangeRequestApprove::KEY) {
        for row in list_change_requests(state).await? {
            if record_readable(state, ctx, CR_ENTITY, row.id).await {
                items.push(change_request_item(&row));
            }
        }
    }
    if holds(ctx, TimesheetUpdate::KEY) && holds(ctx, TimesheetApprove::KEY) {
        for row in list_timesheets(state).await? {
            if record_readable(state, ctx, TS_ENTITY, row.id).await {
                items.push(timesheet_item(&row));
            }
        }
    }
    for row in list_work_items(state, ctx.user_id).await? {
        if record_readable(state, ctx, WI_ENTITY, row.id).await {
            items.push(work_item_item(state, ctx, &row));
        }
    }
    Ok(items)
}

async fn list_change_requests(state: &EngineState) -> Result<Vec<ChangeRequestRow>, AppError> {
    sqlx::query_as(
        "SELECT id, title, status, requested_date \
         FROM project_change_request \
         WHERE is_active = true AND status = 'pending' \
         ORDER BY requested_date ASC NULLS LAST, id \
         LIMIT $1",
    )
    .bind(SCAN_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn list_timesheets(state: &EngineState) -> Result<Vec<TimesheetRow>, AppError> {
    sqlx::query_as(
        "SELECT id, status, week_start_date \
         FROM project_timesheet \
         WHERE is_active = true AND status = 'submitted' \
         ORDER BY week_start_date ASC, id \
         LIMIT $1",
    )
    .bind(SCAN_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn list_work_items(state: &EngineState, user_id: Uuid) -> Result<Vec<WorkItemRow>, AppError> {
    sqlx::query_as(
        "SELECT id, name, status, due_date \
         FROM project_work_item \
         WHERE is_active = true AND owner_id = $1 AND status <> 'done' \
         ORDER BY due_date ASC NULLS LAST, id \
         LIMIT $2",
    )
    .bind(user_id)
    .bind(SCAN_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// One change request, re-fetched fresh for `actions()` and re-checked for
/// the privilege, the open state and record access.
async fn fetch_change_request(
    state: &EngineState,
    ctx: &SecurityContext,
    record_id: Uuid,
) -> Result<Option<ChangeRequestRow>, AppError> {
    if !(holds(ctx, ChangeRequestUpdate::KEY) && holds(ctx, ChangeRequestApprove::KEY)) {
        return Ok(None);
    }
    let row: Option<ChangeRequestRow> = sqlx::query_as(
        "SELECT id, title, status, requested_date \
         FROM project_change_request \
         WHERE id = $1 AND is_active = true AND status = 'pending'",
    )
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    match row {
        Some(row) if record_readable(state, ctx, CR_ENTITY, row.id).await => Ok(Some(row)),
        _ => Ok(None),
    }
}

async fn fetch_timesheet(
    state: &EngineState,
    ctx: &SecurityContext,
    record_id: Uuid,
) -> Result<Option<TimesheetRow>, AppError> {
    if !(holds(ctx, TimesheetUpdate::KEY) && holds(ctx, TimesheetApprove::KEY)) {
        return Ok(None);
    }
    let row: Option<TimesheetRow> = sqlx::query_as(
        "SELECT id, status, week_start_date \
         FROM project_timesheet \
         WHERE id = $1 AND is_active = true AND status = 'submitted'",
    )
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    match row {
        Some(row) if record_readable(state, ctx, TS_ENTITY, row.id).await => Ok(Some(row)),
        _ => Ok(None),
    }
}

async fn fetch_work_item(
    state: &EngineState,
    ctx: &SecurityContext,
    record_id: Uuid,
) -> Result<Option<WorkItemRow>, AppError> {
    let row: Option<WorkItemRow> = sqlx::query_as(
        "SELECT id, name, status, due_date \
         FROM project_work_item \
         WHERE id = $1 AND is_active = true AND owner_id = $2 AND status <> 'done'",
    )
    .bind(record_id)
    .bind(ctx.user_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    match row {
        Some(row) if record_readable(state, ctx, WI_ENTITY, row.id).await => Ok(Some(row)),
        _ => Ok(None),
    }
}

/// The generic record-access half of the trait's visibility rule. A missing
/// entity registration is "not visible", never an error — same posture
/// `my_work_service` takes.
async fn record_readable(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
    record_id: Uuid,
) -> bool {
    let Ok((entity_id, ..)) = resolve_entity(state, entity).await else {
        return false;
    };
    require_record_access(state, ctx, entity_id, entity, record_id, RecordAction::Read)
        .await
        .is_ok()
}

fn holds(ctx: &SecurityContext, key: &str) -> bool {
    ctx.is_admin || ctx.privileges.contains(key)
}

fn action(key: &str, route: String) -> MyWorkAction {
    MyWorkAction {
        key: key.to_string(),
        method: "POST".to_string(),
        route,
    }
}

fn change_request_actions(id: Uuid) -> Vec<MyWorkAction> {
    vec![
        action(
            "approve",
            format!("/api/v1/project/change-request/{id}/approve"),
        ),
        action(
            "reject",
            format!("/api/v1/project/change-request/{id}/reject"),
        ),
    ]
}

fn timesheet_actions(id: Uuid) -> Vec<MyWorkAction> {
    vec![
        action("approve", format!("/api/v1/project/timesheet/{id}/approve")),
        action("reject", format!("/api/v1/project/timesheet/{id}/reject")),
    ]
}

fn work_item_actions(
    state: &EngineState,
    ctx: &SecurityContext,
    row: &WorkItemRow,
) -> Vec<MyWorkAction> {
    let registry = state.state_models.load();
    let Some(entry) = registry.get(WI_ENTITY) else {
        return Vec::new();
    };
    available_transitions(entry, ctx, Some(row.status.as_str()))
        .into_iter()
        .map(|t| {
            action(
                &t.name,
                format!("/api/v1/{WI_ENTITY}/{}/transition", row.id),
            )
        })
        .collect()
}

fn change_request_item(row: &ChangeRequestRow) -> MyWorkItem {
    MyWorkItem {
        provider: "project".to_string(),
        source_entity: CR_ENTITY.to_string(),
        record_id: row.id,
        title: row.title.clone(),
        due_date: row.requested_date,
        priority: None,
        state: row.status.clone(),
        actions: change_request_actions(row.id),
        row_version: None,
    }
}

fn timesheet_item(row: &TimesheetRow) -> MyWorkItem {
    MyWorkItem {
        provider: "project".to_string(),
        source_entity: TS_ENTITY.to_string(),
        record_id: row.id,
        title: format!("Timesheet: week of {}", row.week_start_date.date_naive()),
        due_date: Some(row.week_start_date),
        priority: None,
        state: row.status.clone(),
        actions: timesheet_actions(row.id),
        row_version: None,
    }
}

fn work_item_item(state: &EngineState, ctx: &SecurityContext, row: &WorkItemRow) -> MyWorkItem {
    MyWorkItem {
        provider: "project".to_string(),
        source_entity: WI_ENTITY.to_string(),
        record_id: row.id,
        title: row.name.clone(),
        due_date: row.due_date,
        priority: None,
        state: row.status.clone(),
        actions: work_item_actions(state, ctx, row),
        row_version: None,
    }
}

/// Due date first (undated last), then id — the ordering `list` pages over,
/// so the cursor stays a plain offset with no repeats or gaps.
fn sort_items(items: &mut [MyWorkItem]) {
    items.sort_by(|a, b| {
        a.due_date
            .is_none()
            .cmp(&b.due_date.is_none())
            .then_with(|| a.due_date.cmp(&b.due_date))
            .then_with(|| a.record_id.cmp(&b.record_id))
    });
}
