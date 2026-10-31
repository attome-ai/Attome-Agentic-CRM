//! F9-T5: partner tiers are re-evaluated each fiscal quarter, and a person
//! confirms any change.
//!
//! - **Evaluation** ([`evaluate_tick`], daily, acting on a quarter's first
//!   day): over the last 12 months, in batches of [`BATCH`] partners, each
//!   partner's revenue (won opportunities naming it), certified people
//!   (distinct contacts with an unexpired certification) and approved
//!   registrations are compared with its programme's tiers
//!   ([`target_tier`]). A partner whose target differs from its tier gets one
//!   `tier_change_proposal`, unless one is already open. Nothing changes a
//!   tier here.
//! - **Decision** (`POST /api/v1/partner/tier-proposals/{id}/confirm` and
//!   `/dismiss`): a person with update access on the proposal, with
//!   `If-Match`. Confirming sets `account.partner_tier_ref`. API keys, S2S
//!   clients and agents are refused.
//!
//! The deployment has no fiscal-year setting yet (metrics also cut quarters
//! from January), so quarters start in [`FISCAL_START_MONTH`].

use attome_audit::{AuditOperation, BusinessEvent, write_business_event_in_tx};
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, header::IF_MATCH},
    routing::post,
};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::support::{installed, lock, person_only, require};

/// The registered daily job.
pub const EVALUATION_JOB: &str = "partner_tier_evaluation";
/// The month a fiscal year starts in (1 is a calendar year).
pub const FISCAL_START_MONTH: u32 = 1;
/// Partners a pass reads at once.
pub const BATCH: i64 = 200;
const ENTITY: &str = "tier_change_proposal";

/// What a partner did over the last 12 months.
#[derive(Debug, Clone, PartialEq)]
pub struct Metrics {
    pub revenue_12m: f64,
    pub certified_people: i64,
    pub registered_deals: i64,
}

/// A tier's minimums; a minimum not set is met.
#[derive(Debug, Clone, PartialEq, sqlx::FromRow)]
pub struct Tier {
    pub id: Uuid,
    pub rank: Option<f64>,
    pub min_revenue_12m: Option<f64>,
    pub min_certified_people: Option<f64>,
    pub min_registered_deals: Option<f64>,
}

impl Tier {
    fn met_by(&self, metrics: &Metrics) -> bool {
        self.min_revenue_12m
            .is_none_or(|min| metrics.revenue_12m >= min)
            && self
                .min_certified_people
                .is_none_or(|min| metrics.certified_people as f64 >= min)
            && self
                .min_registered_deals
                .is_none_or(|min| metrics.registered_deals as f64 >= min)
    }
}

/// The highest-ranked tier whose minimums are all met, if any. Pure.
pub fn target_tier(tiers: &[Tier], metrics: &Metrics) -> Option<Uuid> {
    tiers
        .iter()
        .filter(|t| t.met_by(metrics))
        .max_by(|a, b| {
            a.rank
                .unwrap_or(f64::MIN)
                .total_cmp(&b.rank.unwrap_or(f64::MIN))
        })
        .map(|t| t.id)
}

/// Whether `day` starts a fiscal quarter. Pure.
pub fn starts_quarter(day: NaiveDate, fiscal_start_month: u32) -> bool {
    day.day() == 1 && (day.month() + 12 - fiscal_start_month).is_multiple_of(3)
}

/// Why a proposal names its tier, for the person deciding. Pure.
fn reasons(metrics: &Metrics) -> String {
    format!(
        "12 months: revenue {}, certified people {}, approved registrations {}",
        metrics.revenue_12m, metrics.certified_people, metrics.registered_deals
    )
}

/// One partner's numbers as of `as_of`.
pub async fn evaluate_partner(
    conn: &mut sqlx::PgConnection,
    partner: Uuid,
    as_of: DateTime<Utc>,
) -> Result<Metrics, AppError> {
    let (revenue_12m, certified_people, registered_deals): (f64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT COALESCE(sum(amount), 0)::float8 FROM opportunity \
             WHERE partner_account_ref = $1 AND stage = 'closed_won' \
               AND close_date > $2 - interval '12 months' AND close_date <= $2), \
           (SELECT count(DISTINCT partner_contact_ref) FROM partner_certification \
             WHERE partner_account_ref = $1 AND partner_contact_ref IS NOT NULL \
               AND (expires_on IS NULL OR expires_on > $2) \
               AND (is_active IS NULL OR is_active = true)), \
           (SELECT count(*) FROM deal_registration \
             WHERE partner_account_ref = $1 AND status IN ('approved', 'lapsed') \
               AND opportunity_ref IS NOT NULL \
               AND modified_at > $2 - interval '12 months')",
    )
    .bind(partner)
    .bind(as_of)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)?;
    Ok(Metrics {
        revenue_12m,
        certified_people,
        registered_deals,
    })
}

/// Evaluates every partner as of `as_of`. Answers how many proposals were
/// written; a second pass writes none, since a partner's open proposal stands.
pub async fn evaluate_all(state: &EngineState, as_of: DateTime<Utc>) -> Result<u64, AppError> {
    let db = &state.base.db;
    let mut after = Uuid::nil();
    let mut proposed = 0;
    loop {
        let partners: Vec<(Uuid, Option<Uuid>, Uuid)> = sqlx::query_as(
            "SELECT id, partner_tier_ref, partner_programme_ref FROM account \
              WHERE is_partner = true AND partner_programme_ref IS NOT NULL \
                AND (is_active IS NULL OR is_active = true) AND id > $1 \
              ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = partners.last() else { break };
        after = last.0;
        let done = (partners.len() as i64) < BATCH;
        for (partner, current, programme) in partners {
            match propose(state, partner, current, programme, as_of).await {
                Ok(true) => proposed += 1,
                Ok(false) => {}
                // One partner's failure leaves the others evaluated.
                Err(error) => tracing::warn!(%partner, %error, "partner tier not evaluated"),
            }
        }
        if done {
            break;
        }
    }
    Ok(proposed)
}

async fn propose(
    state: &EngineState,
    partner: Uuid,
    current: Option<Uuid>,
    programme: Uuid,
    as_of: DateTime<Utc>,
) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock(&mut tx, format!("attome-partner/tier:{partner}")).await?;
    let open: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM tier_change_proposal \
          WHERE partner_account_ref = $1 AND status = 'proposed')",
    )
    .bind(partner)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if open {
        return Ok(false);
    }
    let tiers: Vec<Tier> = sqlx::query_as(
        "SELECT id, rank::float8 AS rank, min_revenue_12m::float8 AS min_revenue_12m, \
                min_certified_people::float8 AS min_certified_people, \
                min_registered_deals::float8 AS min_registered_deals \
           FROM partner_tier \
          WHERE programme_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(programme)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let metrics = evaluate_partner(&mut tx, partner, as_of).await?;
    let target = target_tier(&tiers, &metrics);
    if target == current {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO tier_change_proposal \
                (partner_account_ref, from_tier_ref, to_tier_ref, reasons, status, is_active, \
                 row_version) \
         VALUES ($1, $2, $3, $4, 'proposed', true, 0)",
    )
    .bind(partner)
    .bind(current)
    .bind(target)
    .bind(reasons(&metrics))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(true)
}

/// The daily job: evaluates on a quarter's first day, otherwise does nothing.
pub async fn evaluate_tick(state: &EngineState) -> Result<u64, AppError> {
    let now = Utc::now();
    if !starts_quarter(now.date_naive(), FISCAL_START_MONTH)
        || !installed(&state.base.db, ENTITY, "to_tier_ref").await?
    {
        return Ok(0);
    }
    evaluate_all(state, now).await
}

/// The proposal after a decision.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TierProposalDecided {
    pub id: Uuid,
    /// `confirmed` or `dismissed`.
    pub status: String,
    pub row_version: i64,
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?;
    let value = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    value.parse::<i64>().map_err(|_| {
        AppError::Validation(format!(
            "If-Match must be a row_version integer, got: {value}"
        ))
    })
}

/// Confirms or dismisses an open proposal at `row_version`.
pub async fn decide(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    row_version: i64,
    confirm: bool,
) -> Result<TierProposalDecided, AppError> {
    person_only(ctx)?;
    require(state, ctx, ENTITY, id, RecordAction::Update).await?;
    let status = if confirm { "confirmed" } else { "dismissed" };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<(Uuid, Option<Uuid>, i64)> = sqlx::query_as(
        "UPDATE tier_change_proposal SET status = $3, modified_at = now(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND row_version = $2 AND status = 'proposed' \
          RETURNING partner_account_ref, to_tier_ref, row_version",
    )
    .bind(id)
    .bind(row_version)
    .bind(status)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((partner, target, row_version)) = row else {
        return Err(AppError::Conflict(
            "the proposal is decided or changed; reload it",
        ));
    };
    if confirm {
        sqlx::query(
            "UPDATE account SET partner_tier_ref = $2, modified_at = now(), \
                    row_version = row_version + 1 WHERE id = $1",
        )
        .bind(partner)
        .bind(target)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            ENTITY,
            id,
            AuditOperation::Update,
            format!("partner.tier_proposal_{status}"),
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(TierProposalDecided {
        id,
        status: status.to_owned(),
        row_version,
    })
}

/// Confirm a tier change
///
/// F9-T5: sets the partner's tier to the proposal's. A person with update access decides, with
/// the proposal's `If-Match` row version; API keys and S2S clients are refused. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/tier-proposals/{id}/confirm",
    operation_id = "partner_tier_proposal_confirm",
    tag = "partner",
    params(
        ("id" = Uuid, Path, description = "The tier change proposal"),
        ("If-Match" = String, Header, description = "The proposal's row_version, quoted"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Confirmed", body = TierProposalDecided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such proposal the caller may read", body = ErrorResponse),
        (status = 409, description = "Already decided, or changed since read", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(crate) async fn post_confirm(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<TierProposalDecided>, AppError> {
    decide(&state, &ctx, id, if_match(&headers)?, true)
        .await
        .map(Json)
}

/// Dismiss a tier change
///
/// F9-T5: closes the proposal and leaves the partner's tier alone. A person with update access
/// decides, with the proposal's `If-Match` row version. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/tier-proposals/{id}/dismiss",
    operation_id = "partner_tier_proposal_dismiss",
    tag = "partner",
    params(
        ("id" = Uuid, Path, description = "The tier change proposal"),
        ("If-Match" = String, Header, description = "The proposal's row_version, quoted"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Dismissed", body = TierProposalDecided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such proposal the caller may read", body = ErrorResponse),
        (status = 409, description = "Already decided, or changed since read", body = ErrorResponse),
        (status = 422, description = "If-Match missing or malformed", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(crate) async fn post_dismiss(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<TierProposalDecided>, AppError> {
    decide(&state, &ctx, id, if_match(&headers)?, false)
        .await
        .map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/partner/tier-proposals/{id}/confirm",
            post(post_confirm),
        )
        .route(
            "/api/v1/partner/tier-proposals/{id}/dismiss",
            post(post_dismiss),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_confirm, post_dismiss),
    components(schemas(TierProposalDecided))
)]
pub(crate) struct TiersApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    fn tier(rank: i32, revenue: i32) -> Tier {
        Tier {
            id: Uuid::now_v7(),
            rank: Some(f64::from(rank)),
            min_revenue_12m: Some(f64::from(revenue)),
            min_certified_people: None,
            min_registered_deals: None,
        }
    }

    fn metrics(revenue: i32) -> Metrics {
        Metrics {
            revenue_12m: f64::from(revenue),
            certified_people: 0,
            registered_deals: 0,
        }
    }

    #[test]
    fn picks_highest_met_tier() {
        let (silver, gold) = (tier(1, 100), tier(2, 1000));
        let tiers = [silver.clone(), gold.clone()];
        assert_eq!(target_tier(&tiers, &metrics(5000)), Some(gold.id));
        assert_eq!(target_tier(&tiers, &metrics(500)), Some(silver.id));
    }

    #[test]
    fn demotes_when_revenue_drops() {
        let (silver, gold) = (tier(1, 100), tier(2, 1000));
        let tiers = [gold, silver.clone()];
        assert_eq!(target_tier(&tiers, &metrics(100)), Some(silver.id));
        assert_eq!(target_tier(&tiers, &metrics(99)), None);
    }

    #[test]
    fn quarters_start_from_the_fiscal_month() {
        let day = |m, d| NaiveDate::from_ymd_opt(2026, m, d).expect("a date");
        assert!(starts_quarter(day(1, 1), 1));
        assert!(starts_quarter(day(10, 1), 1));
        assert!(!starts_quarter(day(2, 1), 1));
        assert!(!starts_quarter(day(4, 2), 1));
        assert!(starts_quarter(day(5, 1), 2));
        assert!(!starts_quarter(day(4, 1), 2));
    }
}
