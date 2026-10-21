//! W3-T4: sealed requests for quotation.
//!
//! An `rfq` (procurement pack 0003) is open until its `deadline_at`.
//! Vendors bid through the portal: an `rfq_bid` keeps its price, lead time
//! and notes in **sensitive** fields that no field profile grants, so staff
//! see that a vendor bid but not what it offered (a portal vendor sees only
//! its own bids, by the portal role's row scope).
//!
//! **Opening.** Every five minutes the `rfq_open` job takes each open RFQ
//! past its deadline and, in one transaction under the RFQ's row lock,
//! copies every bid's sealed values into its readable `opened_*` fields,
//! marks a bid made after the deadline `late`, and closes the RFQ. Run
//! twice, it opens nothing twice.
//!
//! **Award** (`POST /api/v1/procurement/rfqs/{id}/award`): only a closed
//! (opened) RFQ, only one of its own bids that was on time, and only with a
//! reason; the award, its reason and time are written with an audit event.
//!
//! An administrator bypasses field profiles and so can read a sealed bid;
//! the seal holds against every other staff member.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "rfq_open";
const BATCH: i64 = 100;

/// `rfq.update`: who awards.
#[derive(Debug)]
pub struct RfqUpdate;

impl PrivilegeKey for RfqUpdate {
    const KEY: &'static str = "rfq.update";
}

/// Whether bids are still sealed at `now`. Pure.
pub fn sealed(deadline: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    deadline.is_none_or(|d| now < d)
}

/// Whether a bid made at `made` is late for `deadline`. Pure.
pub fn late(made: DateTime<Utc>, deadline: DateTime<Utc>) -> bool {
    made > deadline
}

/// Why an award is refused, if it is. Pure.
pub fn award_refusal(
    rfq_status: Option<&str>,
    bid_belongs: bool,
    bid_late: bool,
    reason: &str,
) -> Option<&'static str> {
    if rfq_status != Some("closed") {
        return Some("an RFQ is awarded once its bids are opened at the deadline");
    }
    if !bid_belongs {
        return Some("bid_id: not a bid on this RFQ");
    }
    if bid_late {
        return Some("bid_id: a late bid is not awarded");
    }
    if reason.trim().is_empty() {
        return Some("reason: say why this bid wins");
    }
    None
}

async fn installed(db: &attome_db::DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT to_regclass('rfq') IS NOT NULL AND to_regclass('rfq_bid') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// One tick: opens the RFQs past their deadline. Answers how many.
pub async fn tick(state: &EngineState, now: DateTime<Utc>) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db).await? {
        return Ok(0);
    }
    let due: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM rfq WHERE status = 'open' AND deadline_at::timestamptz <= $1 \
            AND (is_active IS NULL OR is_active = true) ORDER BY deadline_at LIMIT $2",
    )
    .bind(now)
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut opened = 0;
    for id in due {
        let mut tx = attome_db::tx::begin(db).await?;
        let deadline: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT deadline_at::timestamptz FROM rfq WHERE id = $1 AND status = 'open' \
               FOR NO KEY UPDATE SKIP LOCKED",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .flatten();
        let Some(deadline) = deadline else {
            continue;
        };
        sqlx::query(
            "UPDATE rfq_bid SET opened_amount = amount, opened_lead_time_days = lead_time_days, \
                 opened_notes = notes, opened_at = $2, late = (created_at > $3), \
                 modified_at = now(), row_version = row_version + 1 \
              WHERE rfq_ref = $1 AND opened_at IS NULL AND (is_active IS NULL OR is_active = true)",
        )
        .bind(id)
        .bind(now)
        .bind(deadline)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "UPDATE rfq SET status = 'closed', modified_at = now(), row_version = row_version + 1 \
              WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        tracing::info!(rfq = %id, "rfq: bids opened at the deadline");
        opened += 1;
    }
    Ok(opened)
}

/// The award.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AwardBody {
    pub bid_id: Uuid,
    /// Why this bid wins; kept on the RFQ.
    pub reason: String,
}

/// The awarded RFQ.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Awarded {
    pub rfq_id: Uuid,
    pub bid_id: Uuid,
    pub vendor_id: Option<Uuid>,
    pub awarded_at: DateTime<Utc>,
}

/// Awards an opened RFQ to one of its on-time bids.
pub async fn award(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    id: Uuid,
    body: &AwardBody,
    now: DateTime<Utc>,
) -> Result<Awarded, AppError> {
    let db = &state.base.db;
    if !installed(db).await? {
        return Err(AppError::NotFound);
    }
    attome_records::entity_crud::read_record(state, ctx, "rfq", id).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    let status: Option<Option<String>> = sqlx::query_scalar(
        "SELECT status::text FROM rfq WHERE id = $1 AND (is_active IS NULL OR is_active = true) \
           FOR NO KEY UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(status) = status else {
        return Err(AppError::NotFound);
    };
    if status.as_deref() == Some("awarded") {
        return Err(AppError::Conflict("this RFQ is already awarded"));
    }
    let bid: Option<(Option<Uuid>, Option<bool>)> = sqlx::query_as(
        "SELECT vendor_ref, late FROM rfq_bid WHERE id = $1 AND rfq_ref = $2 \
            AND (is_active IS NULL OR is_active = true)",
    )
    .bind(body.bid_id)
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some(refusal) = award_refusal(
        status.as_deref(),
        bid.is_some(),
        bid.as_ref().and_then(|b| b.1).unwrap_or(false),
        &body.reason,
    ) {
        return Err(if status.as_deref() == Some("closed") {
            AppError::Validation(refusal.into())
        } else {
            AppError::Conflict(refusal)
        });
    }
    let vendor = bid.and_then(|b| b.0);
    sqlx::query(
        "UPDATE rfq SET status = 'awarded', awarded_bid_ref = $2, award_reason = $3, \
             awarded_at = $4, modified_at = now(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(id)
    .bind(body.bid_id)
    .bind(body.reason.trim())
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "rfq",
            id,
            attome_audit::AuditOperation::Update,
            "procurement.rfq_awarded",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Awarded {
        rfq_id: id,
        bid_id: body.bid_id,
        vendor_id: vendor,
        awarded_at: now,
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/procurement/rfqs/{id}/award",
    operation_id = "post_rfq_award",
    tag = "procurement",
    params(("id" = Uuid, Path, description = "The request for quotation")),
    request_body = AwardBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Awarded", body = Awarded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks rfq.update", body = ErrorResponse),
        (status = 404, description = "No such RFQ, or RFQs are not installed", body = ErrorResponse),
        (status = 409, description = "Bids are still sealed, or it is already awarded", body = ErrorResponse),
        (status = 422, description = "Not its bid, a late bid, or no reason", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Awards a request for quotation.
///
/// Only after its bids were opened at the deadline, only to one of its
/// on-time bids, and only with a reason, which is kept on the RFQ.
async fn post_award(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<RfqUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<AwardBody>,
) -> Result<Json<Awarded>, AppError> {
    Ok(Json(award(&state, &ctx, id, &body, Utc::now()).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/procurement/rfqs/{id}/award", post(post_award))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_award), components(schemas(AwardBody, Awarded)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod rfq_sealing {
    use super::*;

    fn at(h: u32) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(2027, 3, 1)
            .and_then(|d| d.and_hms_opt(h, 0, 0))
            .expect("a real time")
            .and_utc()
    }

    #[test]
    fn bids_stay_sealed_until_the_deadline() {
        assert!(sealed(Some(at(12)), at(11)));
        assert!(!sealed(Some(at(12)), at(12)), "opened at the deadline");
        assert!(sealed(None, at(23)), "no deadline: never opened");
    }

    #[test]
    fn a_bid_after_the_deadline_is_late() {
        assert!(!late(at(12), at(12)));
        assert!(late(at(13), at(12)));
    }

    #[test]
    fn award_needs_an_opened_rfq_its_own_on_time_bid_and_a_reason() {
        assert!(award_refusal(Some("open"), true, false, "best price").is_some());
        assert!(award_refusal(Some("closed"), false, false, "best price").is_some());
        assert!(award_refusal(Some("closed"), true, true, "best price").is_some());
        assert!(award_refusal(Some("closed"), true, false, "  ").is_some());
        assert_eq!(
            award_refusal(Some("closed"), true, false, "best price"),
            None
        );
    }
}
