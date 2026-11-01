//! The steward inbox (roadmap L3-T3): one read view over the work waiting
//! on a data steward in the domains they look after: open duplicates, open
//! quality issues and active legal holds on those domains' entities, oldest
//! first. Nothing is edited here; each item carries the deep link of the
//! screen that owns it.
//!
//! A steward's domains are those naming them steward or deputy
//! (`data_domain`) and those where L3-T2 gives them the `owner` or
//! `steward` role (`governance_role`). Each source is an [`InboxProvider`]
//! contributing one `SELECT` over the same columns; the route runs them as
//! one `UNION ALL` ordered by date and cut to the page, so a page never
//! loads more than one page. Held contributions (L1), access reviews (Q11)
//! and DSR scopes (R1) have no entity-scoped rows yet and contribute
//! nothing until they do.
//!
//! **Cover (L3-T4).** A deputy sees a domain's items only while its
//! steward is out of office (an active `out_of_office` delegation, the
//! approvals' absence record) or the domain has no steward. Once a day
//! ([`escalate_overdue`]) items older than two days go to the domain's
//! owners, once each.
//!
//! Record-level access is applied per entity, before the query: an entity
//! is listed only when the steward may read every record of it (the `read`
//! privilege at the global level, or an administrator), so no item names a
//! record they cannot read and the total never counts one (the rule L2-T10
//! set for quality issues). A steward who reads only part of an entity sees
//! none of its items here; its owning screen lists the ones they may read.

use std::collections::BTreeMap;

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// One source of inbox items.
pub trait InboxProvider: Sync {
    /// The item kind it contributes (`duplicate`, `quality_issue`, ...).
    fn source(&self) -> &'static str;
    /// A `SELECT` of `source, id, entity, record_id, related_id, detail,
    /// due_at` over rows whose entity is in `$1` (a `text[]`), or `None`
    /// while the feature has no such rows.
    fn select(&self) -> Option<&'static str>;
    /// The screen that owns the item.
    fn link(&self) -> &'static str;
}

struct Duplicates;
struct QualityIssues;
struct LegalHolds;
/// L1, Q11 and R1: nothing entity-scoped to list yet.
struct Pending(&'static str, &'static str);

impl InboxProvider for Duplicates {
    fn source(&self) -> &'static str {
        "duplicate"
    }
    fn select(&self) -> Option<&'static str> {
        Some(
            "SELECT 'duplicate'::text AS source, id, entity_logicalname AS entity, \
                    record_a AS record_id, record_b AS related_id, \
                    round(score::numeric, 2)::text AS detail, detected_at AS due_at \
               FROM duplicate_candidate \
              WHERE status = 'open' AND entity_logicalname = ANY($1)",
        )
    }
    fn link(&self) -> &'static str {
        "/xrm/admin/duplicates"
    }
}

impl InboxProvider for QualityIssues {
    fn source(&self) -> &'static str {
        "quality_issue"
    }
    fn select(&self) -> Option<&'static str> {
        Some(
            "SELECT 'quality_issue'::text, id, entity_logicalname, record_id, \
                    related_record_id, dimension || ': ' || detail, detected_at \
               FROM quality_issue \
              WHERE status = 'open' AND entity_logicalname = ANY($1)",
        )
    }
    fn link(&self) -> &'static str {
        "/xrm/admin/data/quality"
    }
}

impl InboxProvider for LegalHolds {
    fn source(&self) -> &'static str {
        "legal_hold"
    }
    fn select(&self) -> Option<&'static str> {
        Some(
            "SELECT 'legal_hold'::text, id, entity_logicalname, record_id, NULL::uuid, \
                    matter_reference, placed_at \
               FROM legal_hold \
              WHERE is_deleted = false AND released_at IS NULL \
                AND entity_logicalname = ANY($1)",
        )
    }
    fn link(&self) -> &'static str {
        "/xrm/admin/data-protection/legal-holds"
    }
}

impl InboxProvider for Pending {
    fn source(&self) -> &'static str {
        self.0
    }
    fn select(&self) -> Option<&'static str> {
        None
    }
    fn link(&self) -> &'static str {
        self.1
    }
}

/// Every provider, in a fixed order.
pub fn providers() -> [&'static dyn InboxProvider; 6] {
    [
        &Duplicates,
        &QualityIssues,
        &LegalHolds,
        &Pending("held_contribution", ""),
        &Pending("access_review", ""),
        &Pending("dsr_scope", ""),
    ]
}

/// The one query over every provider with rows, ordered oldest first and
/// cut to `$2`/`$3`; `None` when no provider has any. Pure.
pub fn inbox_sql(providers: &[&dyn InboxProvider]) -> Option<String> {
    let selects: Vec<&str> = providers.iter().filter_map(|p| p.select()).collect();
    if selects.is_empty() {
        return None;
    }
    Some(format!(
        "SELECT source, id, entity, record_id, related_id, detail, due_at, count(*) OVER () AS total \
           FROM ({}) items ORDER BY due_at, id LIMIT $2 OFFSET $3",
        selects.join(" UNION ALL ")
    ))
}

/// One item in the inbox.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InboxItem {
    /// `duplicate`, `quality_issue` or `legal_hold`.
    pub source: String,
    /// The item's id in its own feature.
    pub id: Uuid,
    pub entity: String,
    /// The record it is about; none for a hold on a whole entity.
    pub record_id: Option<Uuid>,
    /// The other record of a duplicate pair or a quality issue, if any.
    pub related_id: Option<Uuid>,
    /// The duplicate's score, the issue's dimension and detail, or the
    /// hold's matter reference.
    pub detail: String,
    /// When it was detected or placed; the inbox is oldest first.
    pub due_at: DateTime<Utc>,
    /// The screen that owns it.
    pub link: String,
}

type Row = (
    String,
    Uuid,
    String,
    Option<Uuid>,
    Option<Uuid>,
    String,
    DateTime<Utc>,
    i64,
);

/// The entities of the domains `user` looks after: those they steward or
/// own or steward under L3-T2's roles, and (L3-T4) those they deputise
/// while the steward is out of office (an active `out_of_office`
/// delegation of the steward's) or the domain has no steward.
async fn steward_entities(db: &sqlx::PgPool, user: Uuid) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT e.logicalname FROM entity_info e \
          WHERE (e.is_active IS NULL OR e.is_active = true) \
            AND e.domain_ref IN ( \
                SELECT id FROM data_domain d \
                 WHERE d.is_deleted = false \
                   AND (d.steward_ref = $1 \
                        OR (d.deputy_ref = $1 AND (d.steward_ref IS NULL OR EXISTS ( \
                            SELECT 1 FROM approval_delegation a \
                             WHERE a.from_user = d.steward_ref AND a.source = 'out_of_office' \
                               AND a.is_deleted = false AND now() >= a.valid_from AND now() < a.valid_to)))) \
                UNION \
                SELECT domain_ref FROM governance_role \
                 WHERE user_id = $1 AND role IN ('owner', 'steward')) \
          ORDER BY e.logicalname",
    )
    .bind(user)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// The steward inbox
///
/// The work waiting on the caller as a data steward (L3-T3): open duplicates, open quality issues
/// and active legal holds on the entities of the domains they steward or deputise (or own or steward
/// under L3-T2's roles), oldest first. Read only; each item links to the screen that owns it. Only
/// entities whose every record the caller may read are listed, so no item names a record they cannot
/// read. A caller who stewards no domain sees none.
#[utoipa::path(
    get,
    path = "/api/v1/governance/inbox",
    operation_id = "get_steward_inbox",
    tag = "governance",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<InboxItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn inbox(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<InboxItem>>, AppError> {
    let window = q.window();
    let entities = readable_in_full(
        &state,
        &ctx,
        steward_entities(&state.base.db, ctx.user_id).await?,
    )
    .await?;
    let all = providers();
    let (Some(sql), false) = (inbox_sql(&all), entities.is_empty()) else {
        return Ok(Json(PaginatedResponse::new(
            Vec::new(),
            0,
            window.page,
            window.page_size,
        )));
    };
    let rows: Vec<Row> = sqlx::query_as(&sql)
        .bind(&entities)
        .bind(window.page_size)
        .bind(window.offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let total = rows.first().map_or(0, |r| r.7);
    let links: BTreeMap<&str, &str> = all.iter().map(|p| (p.source(), p.link())).collect();
    let items = rows
        .into_iter()
        .map(
            |(source, id, entity, record_id, related_id, detail, due_at, _)| InboxItem {
                link: links.get(source.as_str()).copied().unwrap_or("").to_owned(),
                source,
                id,
                entity,
                record_id,
                related_id,
                detail,
                due_at,
            },
        )
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// The `entities` whose every record `ctx` may read: the `read` privilege,
/// at the global level (or an administrator).
async fn readable_in_full(
    state: &EngineState,
    ctx: &SecurityContext,
    entities: Vec<String>,
) -> Result<Vec<String>, AppError> {
    let mut out = Vec::new();
    for entity in entities {
        if ctx.require(&entity, "read").is_err() {
            continue;
        }
        let Some(entity_id) = state.entities.load().get(&entity).map(|m| m.entity_id) else {
            continue;
        };
        let level = attome_security::resolve_entity_access_level(
            &state.base.db,
            ctx.user_id,
            entity_id,
            &entity,
            attome_security::RecordAction::Read,
        )
        .await?;
        if ctx.is_admin || level == AccessLevel::Global {
            out.push(entity);
        }
    }
    Ok(out)
}

/// L3-T4: how long an item may wait before its domain's owners hear of it.
pub const OVERDUE_DAYS: i32 = 2;

/// One notice an escalation run owes a domain owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverdueNotice {
    pub owner: Uuid,
    pub domain: String,
    /// The items newly overdue in the domain.
    pub items: usize,
}

/// L3-T4, the daily job: every inbox item older than [`OVERDUE_DAYS`] that
/// was not escalated before is recorded in `steward_escalation`, and each
/// domain with new ones owes each of its owners (L3-T2's `owner` role) one
/// notice naming how many; the job sends them. An item is escalated once.
pub async fn escalate_overdue(state: &EngineState) -> Result<Vec<OverdueNotice>, AppError> {
    let all = providers();
    let selects: Vec<&str> = all.iter().filter_map(|p| p.select()).collect();
    if selects.is_empty() {
        return Ok(Vec::new());
    }
    let domains: Vec<(Uuid, String, Vec<String>)> = sqlx::query_as(
        "SELECT d.id, d.name, array_agg(e.logicalname ORDER BY e.logicalname) \
           FROM data_domain d JOIN entity_info e ON e.domain_ref = d.id \
          WHERE d.is_deleted = false AND (e.is_active IS NULL OR e.is_active = true) \
          GROUP BY d.id, d.name",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut notices = Vec::new();
    for (domain, name, entities) in domains {
        let fresh: Vec<Uuid> = sqlx::query_scalar(&format!(
            "INSERT INTO steward_escalation (source, item_id, domain_ref) \
             SELECT source, id, $2 FROM ({}) items \
              WHERE due_at < now() - make_interval(days => $3::int) \
             ON CONFLICT (source, item_id) DO NOTHING RETURNING item_id",
            selects.join(" UNION ALL ")
        ))
        .bind(&entities)
        .bind(domain)
        .bind(OVERDUE_DAYS)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if fresh.is_empty() {
            continue;
        }
        let owners: Vec<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM governance_role WHERE domain_ref = $1 AND role = 'owner'",
        )
        .bind(domain)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        notices.extend(owners.into_iter().map(|owner| OverdueNotice {
            owner,
            domain: name.clone(),
            items: fresh.len(),
        }));
    }
    Ok(notices)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/governance/inbox", get(inbox))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(inbox))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_merge_into_one_query_and_stubs_add_nothing() {
        let all = providers();
        let sql = inbox_sql(&all).expect("three providers have rows");
        assert_eq!(sql.matches("UNION ALL").count(), 2);
        assert!(sql.ends_with("ORDER BY due_at, id LIMIT $2 OFFSET $3"));
        let none: [&dyn InboxProvider; 1] = [&Pending("dsr_scope", "")];
        assert!(inbox_sql(&none).is_none());
        assert_eq!(
            all.iter().map(|p| p.source()).collect::<Vec<_>>(),
            [
                "duplicate",
                "quality_issue",
                "legal_hold",
                "held_contribution",
                "access_review",
                "dsr_scope"
            ]
        );
    }
}
