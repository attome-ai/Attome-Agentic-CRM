//! Dashboard 10/10 Phase 6 — the Decisions `MyWorkProvider`. Lives in
//! `attome-api` for the same reason `my_work_approvals.rs` does: it needs
//! `attome_records::entity_crud::{resolve_entity, require_record_access}`.
//!
//! Source: `dashboard_decision` rows still in `proposed` — the state a
//! human decides by choosing one option (`attome_dashboard::decision::do_approve`).
//! Eligibility mirrors that route exactly: the caller must hold
//! `dashboard_decision.update` (the compile-time policy the route
//! carries) and be able to read the record.
//!
//! The action's route is the approve route, which needs a `chosen_option_id`
//! body — the Action Center opens the decision to pick one, rather than this
//! read model inventing a default choice. That is why a decision item's
//! action is a link to the authoritative route and not a one-click mutation:
//! `MyWorkAction` carries no request body by design, and choosing an option
//! is the decision itself.

use attome_core::{
    EngineState, MyWorkAction, MyWorkFuture, MyWorkItem, MyWorkPage, MyWorkProvider,
};
use attome_dashboard::auth::DecisionUpdate;
use attome_records::entity_crud::{require_record_access, resolve_entity};
use attome_security::RecordAction;
use attome_server::authz::PrivilegeKey;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Same bounded-scan posture as `my_work_approvals::SCAN_LIMIT`.
const SCAN_LIMIT: i64 = 500;
const ENTITY: &str = "dashboard_decision";

#[derive(Debug)]
pub struct DecisionsMyWorkProvider;

#[derive(Debug, sqlx::FromRow)]
struct DecisionRow {
    id: Uuid,
    title: String,
    status: String,
    measure_at: Option<DateTime<Utc>>,
}

impl MyWorkProvider for DecisionsMyWorkProvider {
    fn name(&self) -> &'static str {
        "decisions"
    }

    fn count<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
    ) -> MyWorkFuture<'a, usize> {
        Box::pin(async move { Ok(eligible_decisions(state, ctx).await?.len()) })
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        cursor: Option<&'a str>,
        limit: usize,
    ) -> MyWorkFuture<'a, MyWorkPage> {
        Box::pin(async move {
            let decisions = eligible_decisions(state, ctx).await?;
            let offset: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
            let items = decisions
                .iter()
                .skip(offset)
                .take(limit)
                .map(to_my_work_item)
                .collect::<Vec<_>>();
            let next_cursor = (offset + items.len() < decisions.len())
                .then(|| (offset + items.len()).to_string());
            Ok(MyWorkPage::new(items, next_cursor))
        })
    }

    fn actions<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        record_id: Uuid,
    ) -> MyWorkFuture<'a, Vec<MyWorkAction>> {
        Box::pin(async move {
            let Some(row) = fetch_proposed_decision(state, ctx, record_id).await? else {
                return Ok(vec![]);
            };
            Ok(approve_action(row.id))
        })
    }
}

/// Every `proposed` decision the caller may decide now — `count`/`list`
/// share this so they can never disagree.
async fn eligible_decisions(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Vec<DecisionRow>, AppError> {
    if !holds(ctx, DecisionUpdate::KEY) {
        return Ok(Vec::new());
    }
    let rows: Vec<DecisionRow> = sqlx::query_as(
        "SELECT id, title, status, measure_at \
         FROM dashboard_decision \
         WHERE is_active = true AND status = 'proposed' \
         ORDER BY measure_at ASC NULLS LAST, id \
         LIMIT $1",
    )
    .bind(SCAN_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let Ok((entity_id, ..)) = resolve_entity(state, ENTITY).await else {
        return Ok(Vec::new());
    };
    let mut eligible = Vec::new();
    for row in rows {
        if require_record_access(state, ctx, entity_id, ENTITY, row.id, RecordAction::Read)
            .await
            .is_ok()
        {
            eligible.push(row);
        }
    }
    Ok(eligible)
}

/// One decision, re-fetched fresh and re-checked for `actions()`.
async fn fetch_proposed_decision(
    state: &EngineState,
    ctx: &SecurityContext,
    record_id: Uuid,
) -> Result<Option<DecisionRow>, AppError> {
    if !holds(ctx, DecisionUpdate::KEY) {
        return Ok(None);
    }
    let row: Option<DecisionRow> = sqlx::query_as(
        "SELECT id, title, status, measure_at \
         FROM dashboard_decision \
         WHERE id = $1 AND is_active = true AND status = 'proposed'",
    )
    .bind(record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let Ok((entity_id, ..)) = resolve_entity(state, ENTITY).await else {
        return Ok(None);
    };
    if require_record_access(state, ctx, entity_id, ENTITY, row.id, RecordAction::Read)
        .await
        .is_err()
    {
        return Ok(None);
    }
    Ok(Some(row))
}

fn holds(ctx: &SecurityContext, key: &str) -> bool {
    ctx.is_admin || ctx.privileges.contains(key)
}

fn approve_action(id: Uuid) -> Vec<MyWorkAction> {
    vec![MyWorkAction {
        key: "approve".to_string(),
        method: "POST".to_string(),
        route: format!("/api/v1/decisions/{id}/approve"),
    }]
}

fn to_my_work_item(row: &DecisionRow) -> MyWorkItem {
    MyWorkItem {
        provider: "decisions".to_string(),
        source_entity: ENTITY.to_string(),
        record_id: row.id,
        title: row.title.clone(),
        due_date: row.measure_at,
        priority: None,
        state: row.status.clone(),
        actions: approve_action(row.id),
        row_version: None,
    }
}
