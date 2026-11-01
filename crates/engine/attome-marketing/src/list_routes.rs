//! A marketing list's refresh, current members and usage over HTTP (roadmap
//! E7-T9). The other list routes sit with their engines: member changes and
//! imports in [`crate::static_list`]; count, sample, explain and past
//! members in [`crate::segment_insight`]. Lists themselves, and their
//! combinations, are created and edited through the generic entity API.
//!
//! - **Refresh** (`POST .../refresh`, `marketing_list.update`) queues the
//!   [`REFRESH_JOB`] job, one pending per list, and answers 202; the job
//!   runs [`crate::segment::refresh`], and the list's `last_refreshed_at`
//!   moves when it has.
//! - **Members** (`GET .../members`) pages the list's current members the
//!   caller may read, newest first; past members are `GET .../members-as-of`.
//! - **Usage** (`GET .../usage`) names what uses the list: email and SMS
//!   sends to it, nurture programmes whose audience it is, and journeys that
//!   take entries from it. Read from those records, so nothing registers.
//! - **In use** ([`InUseCheck`], the generic engine's save check): changing
//!   what a list holds (its kind, query, target or account expansion, or
//!   its combinations) while a live journey takes entries from it is
//!   refused with 409 `list.in_use`, unless the request confirms it with
//!   the header `Attome-Confirm: list.in_use`.

use attome_core::record_check::{RecordCheck, RecordCheckFuture, RecordSave};
use attome_core::{EngineState, quote_ident};
use attome_security::{
    RLS_BIND_COUNT, RecordAction, bind_rls_predicate, bind_rls_predicate_as,
    resolve_entity_access_level, rls_predicate,
};
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::segment_insight::ListRead;
use crate::sms_campaign::ListUpdate;

/// The refresh job's registered name (payload `{"list_id"}`).
pub const REFRESH_JOB: &str = "marketing_list_refresh";
/// Most uses of each kind one usage answer names, newest first.
pub const USAGE_PER_KIND: i64 = 100;

/// A list that exists and is not deleted, or 404.
async fn live_list(state: &EngineState, list: Uuid) -> Result<(), AppError> {
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM marketing_list WHERE id = $1 AND is_active IS NOT FALSE)",
    )
    .bind(list)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if found {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// A list `ctx` may read, or 404.
async fn readable_list(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
) -> Result<(), AppError> {
    live_list(state, list).await?;
    if attome_records::entity_crud::referenced_record_visible(state, ctx, "marketing_list", list)
        .await?
    {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

// ── Refresh ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingListRefresh {
    pub list_id: Uuid,
    /// `false` when a refresh of this list was already waiting to run.
    pub queued: bool,
}

/// Queues a refresh of `list`; one pending per list.
pub async fn queue_refresh(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
) -> Result<MarketingListRefresh, AppError> {
    readable_list(state, ctx, list).await?;
    let job = attome_core::jobs::JOB_TYPES
        .job(REFRESH_JOB, &json!({ "list_id": list }))
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let queued = attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        attome_core::jobs::EngineJob::Registered(job),
        &format!("list:{list}"),
    )
    .await
    .map_err(AppError::internal)?;
    if queued {
        attome_audit::write_business_event_in_tx(
            &mut tx,
            &attome_audit::audit_service(state),
            attome_audit::BusinessEvent::new(
                "marketing_list",
                list,
                attome_audit::AuditOperation::Update,
                "marketing.list.refresh_requested",
                ctx.user_id,
            ),
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(MarketingListRefresh {
        list_id: list,
        queued,
    })
}

/// The refresh job: the list's members brought in line with its definition.
pub async fn run_refresh(state: &EngineState, list: Uuid) -> Result<(), AppError> {
    match live_list(state, list).await {
        Ok(()) => {}
        Err(AppError::NotFound) => return Ok(()),
        Err(e) => return Err(e),
    }
    let done = crate::segment::refresh(state, list, "manual", Utc::now()).await?;
    tracing::info!(
        %list,
        added = done.added,
        removed = done.removed,
        members = done.members,
        "marketing list refreshed"
    );
    Ok(())
}

/// Refresh a marketing list
///
/// Queues a refresh of the list's members; the list's `last_refreshed_at` moves once it has run.
/// A refresh already waiting is not queued twice.
#[utoipa::path(
    post,
    path = "/api/v1/marketing/lists/{id}/refresh",
    operation_id = "refresh_marketing_list",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list")),
    responses(
        (status = 202, description = "The refresh is queued (or already was)", body = MarketingListRefresh),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.update", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
async fn post_refresh(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListUpdate>>,
    Path(list): Path<Uuid>,
) -> Result<(StatusCode, Json<MarketingListRefresh>), AppError> {
    let queued = queue_refresh(&state, &ctx, list).await?;
    Ok((StatusCode::ACCEPTED, Json(queued)))
}

// ── Members ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MembersPage {
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    pub page_size: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema, sqlx::FromRow)]
pub struct MarketingListMember {
    pub person_id: Uuid,
    /// The person's entity (`contact`, `lead`, ...).
    pub person_entity: String,
    /// `segment`, `manual`, `form`, `flow` or `import`.
    pub source: String,
    pub added_at: DateTime<Utc>,
}

/// The current members of `list` that `ctx` may read, one page.
pub async fn members(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    page: attome_types::OnePageQuery,
) -> Result<PaginatedResponse<MarketingListMember>, AppError> {
    readable_list(state, ctx, list).await?;
    let window = page.window();
    let entity: Option<String> = sqlx::query_scalar(
        "SELECT person_entity FROM marketing_list_member WHERE list_id = $1 LIMIT 1",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let entity_id = entity
        .as_deref()
        .and_then(|e| state.entities.load().get(e).map(|m| m.entity_id));
    let (Some(entity), Some(entity_id)) = (entity, entity_id) else {
        return Ok(PaginatedResponse::new(
            Vec::new(),
            0,
            window.page,
            window.page_size,
        ));
    };
    let level = resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity,
        RecordAction::Read,
    )
    .await?;
    // $1 the list; the predicate's binds from $2.
    let pred = rls_predicate(
        ctx,
        entity_id,
        "p",
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let from = format!(
        "FROM marketing_list_member m JOIN {} p ON p.id = m.person_id \
         WHERE m.list_id = $1 AND p.is_active IS NOT FALSE {}",
        quote_ident(&entity),
        pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let next = 2 + if pred.is_some() { RLS_BIND_COUNT } else { 0 };

    let count_sql = format!("SELECT COUNT(*) {from}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql).bind(list);
    if let Some(p) = &pred {
        count = bind_rls_predicate(count, &p.binds);
    }
    let total = count
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let page_sql = format!(
        "SELECT m.person_id, m.person_entity, m.source, m.added_at {from} \
         ORDER BY m.added_at DESC, m.person_id LIMIT ${next} OFFSET ${}",
        next + 1
    );
    let mut rows = sqlx::query_as::<_, MarketingListMember>(&page_sql).bind(list);
    if let Some(p) = &pred {
        rows = bind_rls_predicate_as(rows, &p.binds);
    }
    let items = rows
        .bind(window.page_size)
        .bind(window.offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    ))
}

/// Read a list's members
///
/// The list's current members the caller may read, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/lists/{id}/members",
    operation_id = "list_marketing_list_members",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list"), MembersPage),
    responses(
        (status = 200, description = "One page of the members the caller may read", body = PaginatedResponse<MarketingListMember>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_members(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListRead>>,
    Path(list): Path<Uuid>,
    Query(q): Query<MembersPage>,
) -> Result<Json<PaginatedResponse<MarketingListMember>>, AppError> {
    let page = attome_types::OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    };
    members(&state, &ctx, list, page).await.map(Json)
}

// ── Usage ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct MarketingListUsage {
    /// `email_send`, `sms_send`, `nurture_program` or `journey`.
    pub kind: String,
    pub id: Uuid,
    /// The email subject, programme or journey name; none for an SMS send.
    pub name: Option<String>,
    pub status: Option<String>,
}

fn usage_rows(
    kind: &str,
    rows: Vec<(Uuid, Option<String>, Option<String>)>,
) -> Vec<MarketingListUsage> {
    rows.into_iter()
        .map(|(id, name, status)| MarketingListUsage {
            kind: kind.to_owned(),
            id,
            name,
            status,
        })
        .collect()
}

/// What uses `list`, at most [`USAGE_PER_KIND`] of each kind.
pub async fn usage(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
) -> Result<Vec<MarketingListUsage>, AppError> {
    readable_list(state, ctx, list).await?;
    let db = &state.base.db;
    let fetch = |sql: &'static str| async move {
        sqlx::query_as::<_, (Uuid, Option<String>, Option<String>)>(sql)
            .bind(list)
            .bind(USAGE_PER_KIND)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)
    };
    let mut out = usage_rows(
        "email_send",
        fetch(
            "SELECT id, subject, status FROM email_campaign_send \
              WHERE list_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .await?,
    );
    out.extend(usage_rows(
        "sms_send",
        fetch(
            "SELECT id, NULL::text, status FROM sms_campaign_send \
              WHERE list_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .await?,
    ));
    let installed = |entity: &str| state.entities.load().get(entity).is_some();
    if installed("marketing_nurture_program") {
        out.extend(usage_rows(
            "nurture_program",
            fetch(
                "SELECT id, name, status FROM marketing_nurture_program \
                  WHERE audience_list_ref = $1 AND is_active IS NOT FALSE \
                  ORDER BY id DESC LIMIT $2",
            )
            .await?,
        ));
    }
    if installed("marketing_journey") {
        // A journey's entry sources are JSON text; a list id appears in it
        // only as that list's `list_id`.
        out.extend(usage_rows(
            "journey",
            fetch(
                "SELECT id, workflow_definition_logicalname, status FROM marketing_journey \
                  WHERE is_active IS NOT FALSE AND strpos(entry_sources, $1::text) > 0 \
                  ORDER BY id DESC LIMIT $2",
            )
            .await?,
        ));
    }
    Ok(out)
}

/// Read what uses a list
///
/// The email and SMS sends to the list, the nurture programmes whose audience it is, and the
/// journeys that take entries from it.
#[utoipa::path(
    get,
    path = "/api/v1/marketing/lists/{id}/usage",
    operation_id = "get_marketing_list_usage",
    tag = "marketing",
    params(("id" = Uuid, Path, description = "The marketing list")),
    responses(
        (status = 200, description = "Every use, at most 100 of each kind (one page)", body = PaginatedResponse<MarketingListUsage>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_list.read", body = ErrorResponse),
        (status = 404, description = "No such list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_usage(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ListRead>>,
    Path(list): Path<Uuid>,
) -> Result<Json<PaginatedResponse<MarketingListUsage>>, AppError> {
    let items = usage(&state, &ctx, list).await?;
    let total = items.len() as i64;
    let size = total.max(1);
    Ok(Json(PaginatedResponse::new(items, total, 1, size)))
}

// ── In use ───────────────────────────────────────────────────────────────────

/// The code a change to an in-use list is refused with, and confirmed by.
pub const IN_USE: &str = "list.in_use";
/// The list fields that decide who is in it.
const DEFINING: [&str; 4] = ["kind", "query_id", "target_entity", "account_expand"];

/// The list a save of `entity` changes the membership of, if any. Pure for
/// a list; a combination names its list, or keeps the stored one.
fn changed_list(save: &RecordSave<'_>) -> Option<Uuid> {
    match save.entity {
        "marketing_list" => {
            if DEFINING.iter().any(|f| save.body.contains_key(*f)) {
                save.record_id
            } else {
                None
            }
        }
        _ => save
            .body
            .get("list_ref")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok()),
    }
}

/// Refuses changing what a list used by a live journey holds, unless
/// confirmed (E7-T9).
#[derive(Debug)]
pub struct InUseCheck;

impl RecordCheck for InUseCheck {
    fn check<'a>(
        &'a self,
        conn: &'a mut sqlx::PgConnection,
        state: &'a EngineState,
        save: RecordSave<'a>,
    ) -> RecordCheckFuture<'a> {
        Box::pin(async move {
            if attome_core::record_check::confirmed(IN_USE)
                || state.entities.load().get("marketing_journey").is_none()
            {
                return Ok(None);
            }
            let list = match changed_list(&save) {
                Some(list) => Some(list),
                // A combination updated without naming its list.
                None if save.entity == "marketing_list_combination" => match save.record_id {
                    Some(id) => sqlx::query_scalar::<_, Option<Uuid>>(
                        "SELECT list_ref FROM marketing_list_combination WHERE id = $1",
                    )
                    .bind(id)
                    .fetch_optional(&mut *conn)
                    .await
                    .map_err(AppError::internal)?
                    .flatten(),
                    None => None,
                },
                None => None,
            };
            let Some(list) = list else {
                return Ok(None);
            };
            let in_use: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM marketing_journey \
                  WHERE status = 'live' AND is_active IS NOT FALSE \
                    AND strpos(entry_sources, $1::text) > 0)",
            )
            .bind(list)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            if in_use {
                Err(AppError::Conflict(IN_USE))
            } else {
                Ok(None)
            }
        })
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/marketing/lists/{id}/refresh", post(post_refresh))
        .route("/api/v1/marketing/lists/{id}/usage", get(get_usage))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_refresh, get_members, get_usage),
    components(schemas(MarketingListRefresh, MarketingListMember, MarketingListUsage))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_rows_carry_their_kind() {
        let id = Uuid::now_v7();
        let rows = usage_rows("sms_send", vec![(id, None, Some("done".into()))]);
        assert_eq!(
            rows,
            vec![MarketingListUsage {
                kind: "sms_send".into(),
                id,
                name: None,
                status: Some("done".into()),
            }]
        );
    }
}
