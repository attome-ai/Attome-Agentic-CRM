//! Dashboard 10/10 Phase 6 — the Service work `MyWorkProvider`. Lives in
//! `attome-api`, same reasoning as `my_work_approvals.rs`: it needs
//! `attome_records::entity_crud::{resolve_entity, require_record_access}`,
//! and `attome-service` cannot depend on `attome-records` (layer direction,
//! guidelines §1).
//!
//! Eligibility is two business predicates over `service_ticket`, both
//! already established in `attome_service::queue` (`is_active_member`,
//! `open_item_count`, `next_open_ticket`): a ticket directly assigned to the
//! caller (`assignee_id`), or an unassigned ticket sitting in a work queue
//! (D-464) the caller is an active member of. "Still open" is that same
//! module's own predicate: `status NOT IN ('resolved', 'closed')` and
//! `is_active = true` (soft-delete, distinct from "open"). On top of that
//! business predicate this provider still applies the trait's own
//! readable-record check (`require_record_access`) — the two are
//! independent: an assignee/queue-member relationship is service-specific
//! eligibility, not a substitute for XRM's generic entity security.
//!
//! Actions come from the generic state-lifecycle registry (D-406), not a
//! bespoke ticket-transition endpoint — `service_ticket`'s lifecycle is
//! declared in `platform-bundles/attome-service.json`'s `state_models` block
//! and enforced identically whether a caller PATCHes `status` directly or
//! calls the generic `POST /api/v1/{entity}/{id}/transition`
//! (`attome-state::record_routes`). Each available transition becomes one
//! `MyWorkAction` pointing at that same generic route.

use attome_core::{
    EngineState, MyWorkAction, MyWorkFuture, MyWorkItem, MyWorkPage, MyWorkProvider,
    available_transitions,
};
use attome_records::entity_crud::{require_record_access, resolve_entity};
use attome_security::RecordAction;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Same posture as `my_work_approvals::SCAN_LIMIT`: a read model over
/// "what's open right now", not a paginated report.
const SCAN_LIMIT: i64 = 500;
const ENTITY: &str = "service_ticket";

#[derive(Debug)]
pub struct ServiceMyWorkProvider;

#[derive(Debug, sqlx::FromRow)]
struct TicketRow {
    id: Uuid,
    title: String,
    status: String,
    resolution_due_at: Option<DateTime<Utc>>,
    priority: Option<String>,
}

impl MyWorkProvider for ServiceMyWorkProvider {
    fn name(&self) -> &'static str {
        "service"
    }

    fn count<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
    ) -> MyWorkFuture<'a, usize> {
        Box::pin(async move { Ok(eligible_open_tickets(state, ctx).await?.len()) })
    }

    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        cursor: Option<&'a str>,
        limit: usize,
    ) -> MyWorkFuture<'a, MyWorkPage> {
        Box::pin(async move {
            let tickets = eligible_open_tickets(state, ctx).await?;
            let offset: usize = cursor.and_then(|c| c.parse().ok()).unwrap_or(0);
            let items = tickets
                .iter()
                .skip(offset)
                .take(limit)
                .map(|row| to_my_work_item(state, ctx, row))
                .collect::<Vec<_>>();
            let next_cursor =
                (offset + items.len() < tickets.len()).then(|| (offset + items.len()).to_string());
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
            let Some(row) = fetch_visible_ticket(state, ctx, record_id).await? else {
                return Ok(vec![]);
            };
            Ok(transition_actions(state, ctx, &row))
        })
    }
}

/// Every open ticket the caller is business-eligible for (assignee, or an
/// active member of the queue an unassigned ticket sits in) AND can read
/// under XRM's generic record access — `count`/`list` share this so they
/// can never disagree.
async fn eligible_open_tickets(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Vec<TicketRow>, AppError> {
    let rows: Vec<TicketRow> = sqlx::query_as(
        "SELECT id, title, status, resolution_due_at, priority \
         FROM service_ticket \
         WHERE is_active = true \
           AND status NOT IN ('resolved', 'closed') \
           AND ( \
             assignee_id = $1 \
             OR (assignee_id IS NULL AND work_queue_ref IN ( \
                   SELECT queue_ref FROM service_work_queue_member \
                   WHERE user_ref = $1 AND (is_active IS NULL OR is_active = true) \
                )) \
           ) \
         ORDER BY resolution_due_at ASC NULLS LAST, id \
         LIMIT $2",
    )
    .bind(ctx.user_id)
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

/// One ticket, re-fetched fresh and re-checked for `actions()` — never
/// trusts a `list()` snapshot. `None` when the ticket no longer matches the
/// business predicate, is closed, or fails the record-access check.
async fn fetch_visible_ticket(
    state: &EngineState,
    ctx: &SecurityContext,
    record_id: Uuid,
) -> Result<Option<TicketRow>, AppError> {
    let Some(row): Option<TicketRow> = sqlx::query_as(
        "SELECT id, title, status, resolution_due_at, priority \
         FROM service_ticket \
         WHERE id = $1 AND is_active = true AND status NOT IN ('resolved', 'closed') \
           AND ( \
             assignee_id = $2 \
             OR (assignee_id IS NULL AND work_queue_ref IN ( \
                   SELECT queue_ref FROM service_work_queue_member \
                   WHERE user_ref = $2 AND (is_active IS NULL OR is_active = true) \
                )) \
           )",
    )
    .bind(record_id)
    .bind(ctx.user_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    else {
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

/// The generic state-lifecycle registry's available transitions for this
/// ticket's current `status`, each mapped to the one generic transition
/// route every governed entity shares — no ticket-specific endpoint.
fn transition_actions(
    state: &EngineState,
    ctx: &SecurityContext,
    row: &TicketRow,
) -> Vec<MyWorkAction> {
    let registry = state.state_models.load();
    let Some(entry) = registry.get(ENTITY) else {
        return Vec::new();
    };
    available_transitions(entry, ctx, Some(row.status.as_str()))
        .into_iter()
        .map(|t| MyWorkAction {
            key: t.name.clone(),
            method: "POST".to_string(),
            route: format!("/api/v1/{ENTITY}/{}/transition", row.id),
        })
        .collect()
}

fn to_my_work_item(state: &EngineState, ctx: &SecurityContext, row: &TicketRow) -> MyWorkItem {
    MyWorkItem {
        provider: "service".to_string(),
        source_entity: ENTITY.to_string(),
        record_id: row.id,
        title: row.title.clone(),
        due_date: row.resolution_due_at,
        priority: row.priority.clone(),
        state: row.status.clone(),
        actions: transition_actions(state, ctx, row),
        row_version: None,
    }
}
