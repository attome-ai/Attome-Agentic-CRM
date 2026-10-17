//! Competitor routes (roadmap D25-T5): deciding a proposed mention, the
//! battle cards for a deal, and a competitor's head-to-head record. The
//! competitor, deal-competitor and review records themselves stay on the
//! generic entity API.
//!
//! - Confirming a mention puts the competitor on the deal (status
//!   `suspected`) unless it is already there, then marks the mention
//!   `confirmed`; rejecting marks it `rejected`. Both need the caller to be
//!   able to update the deal and the mention's current `row_version`
//!   (`If-Match`), so two people cannot decide one mention twice. The link
//!   is written first: a retry after a failed mark finds it and only marks.
//! - Battle cards list each competitor on a readable deal with its
//!   `battlecard_ref` (the knowledge article id).
//! - Head-to-head counts and sums only the deals the caller may read.

use attome_core::EngineState;
use attome_security::{
    RecordAction, bind_rls_predicate_as, resolve_entity_access_level, rls_predicate,
};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, header::IF_MATCH},
};
use serde::Serialize;
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::opportunity_lines::OpportunityRead;
use crate::split_store::OpportunityUpdate;

/// `competitor.read`: may read competitors.
#[derive(Debug)]
pub struct CompetitorRead;

impl PrivilegeKey for CompetitorRead {
    const KEY: &'static str = "competitor.read";
}

/// Mentions a head-to-head lists.
pub const RECENT_MENTIONS: i64 = 10;

/// Review reasons a head-to-head lists.
pub const TOP_REASONS: i64 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesMentionDecided {
    pub mention_id: Uuid,
    pub status: String,
    /// The deal's competitor link, on a confirm.
    pub opportunity_competitor_id: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesBattlecard {
    pub competitor_id: Uuid,
    pub name: Option<String>,
    pub status: Option<String>,
    pub threat_level: Option<String>,
    /// The knowledge article holding the battle card, when one is set.
    pub battlecard_ref: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesHeadToHeadReason {
    pub reason: String,
    pub count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesHeadToHeadMention {
    pub mention_id: Uuid,
    pub opportunity_id: Uuid,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesHeadToHead {
    pub competitor_id: Uuid,
    pub won: i64,
    pub lost: i64,
    pub open: i64,
    /// Decimal sums, as text.
    pub won_amount: String,
    pub lost_amount: String,
    pub open_amount: String,
    pub top_reasons: Vec<SalesHeadToHeadReason>,
    pub recent_mentions: Vec<SalesHeadToHeadMention>,
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to decide a mention".into())
    })?;
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

async fn installed(state: &EngineState) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT to_regclass('competitor_mention') IS NOT NULL \
            AND to_regclass('opportunity_competitor') IS NOT NULL",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)
}

async fn require_deal(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    deal: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    let entity = crate::team::opportunity_entity_id(state)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity,
        "opportunity",
        deal,
        action,
    )
    .await
}

/// A mention's deal, competitor, status and `row_version`.
type MentionRow = (Option<Uuid>, Option<Uuid>, Option<String>, i64);

/// Decides one proposed mention as `ctx`.
pub async fn decide_mention(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    mention: Uuid,
    expected: i64,
    confirm: bool,
) -> Result<SalesMentionDecided, AppError> {
    if !installed(state).await? {
        return Err(AppError::NotFound);
    }
    let db = &state.base.db;
    let row: Option<MentionRow> = sqlx::query_as(
        "SELECT opportunity_ref, competitor_ref, status, row_version FROM competitor_mention \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(mention)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(deal), Some(competitor), status, version)) = row else {
        return Err(AppError::NotFound);
    };
    require_deal(state, ctx, deal, RecordAction::Update).await?;
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    if status.as_deref() != Some("proposed") {
        return Err(AppError::Conflict("the mention is already decided"));
    }
    let mut link = None;
    if confirm {
        let existing: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM opportunity_competitor \
             WHERE opportunity_ref = $1 AND competitor_ref = $2 \
               AND (is_active IS NULL OR is_active = true) LIMIT 1",
        )
        .bind(deal)
        .bind(competitor)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        link = Some(match existing {
            Some(id) => id,
            None => {
                attome_records::entity_crud::create_record_for(
                    state,
                    ctx,
                    ctx.user_id,
                    "opportunity_competitor",
                    json!({
                        "opportunity_ref": deal.to_string(),
                        "competitor_ref": competitor.to_string(),
                        "status": "suspected",
                    }),
                )
                .await?
                .0
            }
        });
    }
    let decided = if confirm { "confirmed" } else { "rejected" };
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        ctx.user_id,
        "competitor_mention",
        mention,
        expected,
        json!({"status": decided, "decided_by": ctx.user_id.to_string()}),
    )
    .await?;
    Ok(SalesMentionDecided {
        mention_id: mention,
        status: decided.to_owned(),
        opportunity_competitor_id: link,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/competitor-mentions/{id}/confirm",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The proposed mention"),
        ("If-Match" = String, Header, description = "The mention's row_version, quoted"),
    ),
    responses(
        (status = 200, description = "The competitor is on the deal and the mention confirmed", body = SalesMentionDecided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update the deal", body = ErrorResponse),
        (status = 404, description = "No such mention", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or already decided", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_mention_confirm(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(mention): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SalesMentionDecided>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        decide_mention(&state, &ctx, mention, expected, true).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/competitor-mentions/{id}/reject",
    tag = "sales",
    params(
        ("id" = Uuid, Path, description = "The proposed mention"),
        ("If-Match" = String, Header, description = "The mention's row_version, quoted"),
    ),
    responses(
        (status = 200, description = "The mention is rejected", body = SalesMentionDecided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update the deal", body = ErrorResponse),
        (status = 404, description = "No such mention", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or already decided", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_mention_reject(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(mention): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SalesMentionDecided>, AppError> {
    let expected = if_match(&headers)?;
    Ok(Json(
        decide_mention(&state, &ctx, mention, expected, false).await?,
    ))
}

type CardRow = (
    Uuid,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The competitors on a deal the caller may read.
pub async fn battlecards(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    deal: Uuid,
) -> Result<Vec<SalesBattlecard>, AppError> {
    if !installed(state).await? {
        return Err(AppError::NotFound);
    }
    require_deal(state, ctx, deal, RecordAction::Read).await?;
    let rows: Vec<CardRow> = sqlx::query_as(
        "SELECT c.id, c.name, oc.status, oc.threat_level, c.battlecard_ref \
         FROM opportunity_competitor oc JOIN competitor c ON c.id = oc.competitor_ref \
         WHERE oc.opportunity_ref = $1 \
           AND (oc.is_active IS NULL OR oc.is_active = true) \
           AND (c.is_active IS NULL OR c.is_active = true) \
         ORDER BY (oc.status = 'primary') DESC, c.name, c.id",
    )
    .bind(deal)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(
            |(competitor_id, name, status, threat_level, battlecard_ref)| SalesBattlecard {
                competitor_id,
                name,
                status,
                threat_level,
                battlecard_ref,
            },
        )
        .collect())
}

#[utoipa::path(
    get,
    path = "/api/v1/sales/opportunities/{id}/battlecards",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    responses(
        (status = 200, description = "The deal's competitors with their battle cards", body = [SalesBattlecard]),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity, or competitors are not installed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_sales_battlecards(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityRead>>,
    Path(deal): Path<Uuid>,
) -> Result<Json<Vec<SalesBattlecard>>, AppError> {
    Ok(Json(battlecards(&state, &ctx, deal).await?))
}

/// A competitor's record against the deals `ctx` may read.
pub async fn head_to_head(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    competitor: Uuid,
) -> Result<SalesHeadToHead, AppError> {
    if !installed(state).await? {
        return Err(AppError::NotFound);
    }
    let db = &state.base.db;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM competitor WHERE id = $1 \
             AND (is_active IS NULL OR is_active = true))",
    )
    .bind(competitor)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let entity = crate::team::opportunity_entity_id(state)?;
    let level =
        resolve_entity_access_level(db, ctx.user_id, entity, "opportunity", RecordAction::Read)
            .await?;
    // $1 the competitor; record rules from $2.
    let predicate = rls_predicate(
        ctx,
        entity,
        "o",
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let rls = predicate.as_ref().map_or("", |p| p.sql.as_str());
    let deals = format!(
        "WITH deals AS (SELECT o.id, o.stage, o.amount FROM opportunity o \
             WHERE (o.is_active IS NULL OR o.is_active = true) \
               AND (o.lost_to_competitor_ref = $1 OR EXISTS ( \
                   SELECT 1 FROM opportunity_competitor oc \
                   WHERE oc.opportunity_ref = o.id AND oc.competitor_ref = $1 \
                     AND (oc.is_active IS NULL OR oc.is_active = true))) {rls}) "
    );
    let totals_sql = format!(
        "{deals}SELECT \
             COUNT(*) FILTER (WHERE stage = 'closed_won'), \
             COUNT(*) FILTER (WHERE stage = 'closed_lost'), \
             COUNT(*) FILTER (WHERE COALESCE(stage, '') NOT IN ('closed_won', 'closed_lost')), \
             COALESCE(SUM(amount) FILTER (WHERE stage = 'closed_won'), 0)::text, \
             COALESCE(SUM(amount) FILTER (WHERE stage = 'closed_lost'), 0)::text, \
             COALESCE(SUM(amount) FILTER (WHERE COALESCE(stage, '') \
                 NOT IN ('closed_won', 'closed_lost')), 0)::text \
         FROM deals"
    );
    let reasons_sql = format!(
        "{deals}SELECT r.main_reason, COUNT(*) FROM win_loss_review r \
         JOIN deals d ON d.id = r.opportunity_ref \
         WHERE r.main_reason IS NOT NULL AND (r.is_active IS NULL OR r.is_active = true) \
         GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT {TOP_REASONS}"
    );
    let mentions_sql = format!(
        "{deals}SELECT m.id, m.opportunity_ref, m.snippet FROM competitor_mention m \
         JOIN deals d ON d.id = m.opportunity_ref \
         WHERE m.competitor_ref = $1 AND m.status = 'confirmed' \
           AND (m.is_active IS NULL OR m.is_active = true) \
         ORDER BY m.modified_at DESC NULLS LAST, m.id LIMIT {RECENT_MENTIONS}"
    );
    let mut totals =
        sqlx::query_as::<_, (i64, i64, i64, String, String, String)>(&totals_sql).bind(competitor);
    let mut reasons = sqlx::query_as::<_, (String, i64)>(&reasons_sql).bind(competitor);
    let mut mentions =
        sqlx::query_as::<_, (Uuid, Uuid, Option<String>)>(&mentions_sql).bind(competitor);
    if let Some(p) = &predicate {
        totals = bind_rls_predicate_as(totals, &p.binds);
        reasons = bind_rls_predicate_as(reasons, &p.binds);
        mentions = bind_rls_predicate_as(mentions, &p.binds);
    }
    let (won, lost, open, won_amount, lost_amount, open_amount) =
        totals.fetch_one(db).await.map_err(AppError::internal)?;
    let top_reasons = reasons
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(reason, count)| SalesHeadToHeadReason { reason, count })
        .collect();
    let recent_mentions = mentions
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(
            |(mention_id, opportunity_id, snippet)| SalesHeadToHeadMention {
                mention_id,
                opportunity_id,
                snippet,
            },
        )
        .collect();
    Ok(SalesHeadToHead {
        competitor_id: competitor,
        won,
        lost,
        open,
        won_amount,
        lost_amount,
        open_amount,
        top_reasons,
        recent_mentions,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/sales/competitors/{id}/head-to-head",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The competitor")),
    responses(
        (status = 200, description = "Won, lost and open deals against the competitor, over the deals the caller may read", body = SalesHeadToHead),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks competitor.read", body = ErrorResponse),
        (status = 404, description = "No such competitor, or competitors are not installed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_sales_head_to_head(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CompetitorRead>>,
    Path(competitor): Path<Uuid>,
) -> Result<Json<SalesHeadToHead>, AppError> {
    Ok(Json(head_to_head(&state, &ctx, competitor).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        post_sales_mention_confirm,
        post_sales_mention_reject,
        get_sales_battlecards,
        get_sales_head_to_head
    ),
    components(schemas(
        SalesMentionDecided,
        SalesBattlecard,
        SalesHeadToHead,
        SalesHeadToHeadReason,
        SalesHeadToHeadMention
    ))
)]
pub(crate) struct ApiDocFragment;
