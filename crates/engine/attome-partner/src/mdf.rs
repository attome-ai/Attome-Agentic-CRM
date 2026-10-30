//! F9-T7: market development funds — requests and claims.
//!
//! A partner asks for part of its fund as an `mdf_request` and, once that is
//! approved, claims its spend with proof as an `mdf_claim` (partner pack),
//! through the partner portal or any record write. Partner portal roles
//! scope `mdf_fund`, `mdf_request` and `mdf_claim` to the caller's account,
//! so no partner sees another's amounts.
//!
//! - **Check** ([`check_tick`], every minute): a `submitted` request asking
//!   for more than is left of its fund (its amount less the approved
//!   requests and the submitted ones made before it) is `rejected` with the
//!   reason; a claim whose
//!   request is not approved, or that has no proof file, likewise. Either
//!   way `checked_at` is set and the partner manager is told.
//! - **Decision** (`POST /api/v1/partner/mdf/requests/{id}/decision` and
//!   `.../claims/{id}/decision`): a person with update access approves or
//!   rejects (with a reason). A request is approved under the fund's lock
//!   (`attome-partner/mdf-fund:{fund}`) only while it still fits the fund. An
//!   approved claim writes the named event `partner.mdf_claim_approved` once,
//!   in the same transaction as its status, for payment (W5 or F4) to take
//!   up; nothing is posted to a ledger here.

use attome_audit::{AuditOperation, BusinessEvent, write_business_event_in_tx};
use attome_core::EngineState;
use attome_core::change_feed::{ChangeOperation, emit_named};
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::registration::Decision;
use crate::support::{installed, lock, notify, partner_manager, person_only, require};

/// The registered check job (every minute).
pub const CHECK_JOB: &str = "partner_mdf_check";
/// The named event an approved claim writes.
pub const CLAIM_APPROVED: &str = "partner.mdf_claim_approved";
const BATCH: i64 = 500;

/// Why a request or claim is refused before anyone looks at it. Pure.
pub fn refusal(
    kind: Kind,
    fits: bool,
    request_approved: bool,
    has_proof: bool,
) -> Option<&'static str> {
    match kind {
        Kind::Request if !fits => Some("the amount is more than is left of the fund"),
        Kind::Claim if !request_approved => Some("the request it claims against is not approved"),
        Kind::Claim if !has_proof => Some("a claim needs a proof file"),
        _ => None,
    }
}

/// A request or a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Request,
    Claim,
}

impl Kind {
    fn entity(self) -> &'static str {
        match self {
            Self::Request => "mdf_request",
            Self::Claim => "mdf_claim",
        }
    }
}

/// Whether the request fits what is left of its fund: the fund's amount
/// less the approved requests and the submitted ones made before it (ids
/// are time-ordered), so pending requests are served first come, first
/// served and two never refuse each other.
async fn fits_fund(conn: &mut sqlx::PgConnection, request: Uuid) -> Result<bool, AppError> {
    let fits: Option<bool> = sqlx::query_scalar(
        "SELECT COALESCE(r.amount, 0) <= f.amount - COALESCE(( \
                  SELECT SUM(o.amount) FROM mdf_request o \
                   WHERE o.fund_ref = f.id AND o.id <> r.id \
                     AND (o.status = 'approved' OR (o.status = 'submitted' AND o.id < r.id)) \
                     AND (o.is_active IS NULL OR o.is_active = true)), 0) \
           FROM mdf_request r JOIN mdf_fund f ON f.id = r.fund_ref \
          WHERE r.id = $1 AND (f.is_active IS NULL OR f.is_active = true)",
    )
    .bind(request)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .flatten();
    Ok(fits.unwrap_or(false))
}

/// A claim's request status and whether it carries proof.
async fn claim_facts(conn: &mut sqlx::PgConnection, claim: Uuid) -> Result<(bool, bool), AppError> {
    let facts: Option<(Option<String>, bool)> = sqlx::query_as(
        "SELECT r.status, (c.proof_file IS NOT NULL AND c.proof_file::text NOT IN ('', '[]', 'null')) \
           FROM mdf_claim c LEFT JOIN mdf_request r ON r.id = c.request_ref WHERE c.id = $1",
    )
    .bind(claim)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(facts.map_or((false, false), |(status, proof)| {
        (status.as_deref() == Some("approved"), proof)
    }))
}

/// The partner a request or claim belongs to, through its fund.
async fn partner_of(
    conn: &mut sqlx::PgConnection,
    kind: Kind,
    id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let sql = match kind {
        Kind::Request => {
            "SELECT f.partner_account_ref FROM mdf_request r \
               JOIN mdf_fund f ON f.id = r.fund_ref WHERE r.id = $1"
        }
        Kind::Claim => {
            "SELECT f.partner_account_ref FROM mdf_claim c \
               JOIN mdf_request r ON r.id = c.request_ref \
               JOIN mdf_fund f ON f.id = r.fund_ref WHERE c.id = $1"
        }
    };
    let partner: Option<Option<Uuid>> = sqlx::query_scalar(sql)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(partner.flatten())
}

/// The check job: refuses the requests and claims that cannot be approved
/// and tells the partner manager of the rest. Answers how many were checked.
pub async fn check_tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db, "mdf_claim", "checked_at").await? {
        return Ok(0);
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let mut checked = 0;
    for kind in [Kind::Request, Kind::Claim] {
        let sql = match kind {
            Kind::Request => {
                "SELECT id FROM mdf_request WHERE status = 'submitted' AND checked_at IS NULL \
                   AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $1"
            }
            Kind::Claim => {
                "SELECT id FROM mdf_claim WHERE (status IS NULL OR status = 'submitted') \
                   AND checked_at IS NULL AND (is_active IS NULL OR is_active = true) \
                 ORDER BY id LIMIT $1"
            }
        };
        let ids: Vec<Uuid> = sqlx::query_scalar(sql)
            .bind(BATCH)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?;
        for id in ids {
            let reason = match kind {
                Kind::Request => {
                    let fits = fits_fund(&mut conn, id).await?;
                    refusal(kind, fits, true, true)
                }
                Kind::Claim => {
                    let (approved, proof) = claim_facts(&mut conn, id).await?;
                    refusal(kind, true, approved, proof)
                }
            };
            let update = match kind {
                Kind::Request => {
                    "UPDATE mdf_request SET status = CASE WHEN $2::text IS NULL THEN status ELSE 'rejected' END, \
                            decision_reason = $2, checked_at = now(), modified_at = now(), \
                            row_version = row_version + 1 \
                      WHERE id = $1 AND status = 'submitted' AND checked_at IS NULL"
                }
                Kind::Claim => {
                    "UPDATE mdf_claim SET status = CASE WHEN $2::text IS NULL THEN 'submitted' ELSE 'rejected' END, \
                            decision_reason = $2, checked_at = now(), modified_at = now(), \
                            row_version = row_version + 1 \
                      WHERE id = $1 AND (status IS NULL OR status = 'submitted') AND checked_at IS NULL"
                }
            };
            let done = sqlx::query(update)
                .bind(id)
                .bind(reason)
                .execute(&mut *conn)
                .await
                .map_err(AppError::internal)?;
            if done.rows_affected() != 1 {
                continue;
            }
            checked += 1;
            let partner = partner_of(&mut conn, kind, id).await?;
            if let Some(manager) = partner_manager(state, partner).await {
                let what = match kind {
                    Kind::Request => "MDF request",
                    Kind::Claim => "MDF claim",
                };
                let subject = match reason {
                    Some(_) => format!("A partner's {what} was refused"),
                    None => format!("A partner's {what} waits for a decision"),
                };
                notify(
                    state,
                    manager,
                    subject,
                    reason.unwrap_or("Waiting for a decision.").to_owned(),
                    format!("/xrm/entity/{}/{id}", kind.entity()),
                )
                .await;
            }
        }
    }
    Ok(checked)
}

/// `POST .../decision` on a request or claim.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct MdfDecisionBody {
    pub decision: Decision,
    /// Required to reject; kept either way.
    #[serde(default)]
    pub reason: Option<String>,
}

/// A request or claim after a decision.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct MdfDecided {
    pub id: Uuid,
    /// `approved` or `rejected`.
    pub status: String,
}

/// Approves or rejects a request or claim as `ctx` (see the module doc).
pub async fn decide(
    state: &EngineState,
    ctx: &SecurityContext,
    kind: Kind,
    id: Uuid,
    body: MdfDecisionBody,
) -> Result<MdfDecided, AppError> {
    person_only(ctx)?;
    require(state, ctx, kind.entity(), id, RecordAction::Update).await?;
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(str::to_owned);
    if body.decision == Decision::Reject && reason.is_none() {
        return Err(AppError::Validation("a rejection needs a reason".into()));
    }
    let approve = body.decision == Decision::Approve;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if approve {
        match kind {
            Kind::Request => {
                let fund: Option<Uuid> =
                    sqlx::query_scalar("SELECT fund_ref FROM mdf_request WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(AppError::internal)?
                        .flatten();
                let fund = fund.ok_or(AppError::NotFound)?;
                lock(&mut tx, format!("attome-partner/mdf-fund:{fund}")).await?;
                if !fits_fund(&mut tx, id).await? {
                    return Err(AppError::Validation(
                        "the amount is more than is left of the fund".into(),
                    ));
                }
            }
            Kind::Claim => {
                let (approved, proof) = claim_facts(&mut tx, id).await?;
                if let Some(why) = refusal(kind, true, approved, proof) {
                    return Err(AppError::Validation(why.into()));
                }
            }
        }
    }
    let status = if approve { "approved" } else { "rejected" };
    let update = match kind {
        Kind::Request => {
            "UPDATE mdf_request SET status = $2, decision_reason = $3, decided_by = $4, \
                    modified_by = $4, modified_at = now(), row_version = row_version + 1 \
              WHERE id = $1 AND status = 'submitted'"
        }
        Kind::Claim => {
            "UPDATE mdf_claim SET status = $2, decision_reason = $3, decided_by = $4, \
                    modified_by = $4, modified_at = now(), row_version = row_version + 1 \
              WHERE id = $1 AND (status IS NULL OR status = 'submitted')"
        }
    };
    let done = sqlx::query(update)
        .bind(id)
        .bind(status)
        .bind(&reason)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if done.rows_affected() != 1 {
        return Err(AppError::Conflict("it is already decided"));
    }
    // Once: the status moved from submitted in this transaction.
    if approve && kind == Kind::Claim {
        emit_named(
            &mut tx,
            kind.entity(),
            id,
            ChangeOperation::Update,
            CLAIM_APPROVED,
        )
        .await?;
    }
    write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            kind.entity(),
            id,
            AuditOperation::Update,
            format!("partner.{}_{status}", kind.entity()),
            ctx.user_id,
        )
        .comment(reason.unwrap_or_default()),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(MdfDecided {
        id,
        status: status.to_owned(),
    })
}

/// Decide an MDF request
///
/// F9-T7: approve (only while it fits what is left of the fund) or reject (with a reason). A
/// person with update access decides; API keys and S2S clients are refused. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/mdf/requests/{id}/decision",
    operation_id = "partner_mdf_request_decide",
    tag = "partner",
    params(("id" = Uuid, Path, description = "The MDF request")),
    request_body = MdfDecisionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Decided", body = MdfDecided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such request the caller may read", body = ErrorResponse),
        (status = 409, description = "Already decided", body = ErrorResponse),
        (status = 422, description = "Over the fund, or a rejection without a reason", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(crate) async fn post_request_decision(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<MdfDecisionBody>,
) -> Result<Json<MdfDecided>, AppError> {
    decide(&state, &ctx, Kind::Request, id, body)
        .await
        .map(Json)
}

/// Decide an MDF claim
///
/// F9-T7: approve (only against an approved request, with a proof file; writes
/// `partner.mdf_claim_approved` once for payment) or reject (with a reason). A person with update
/// access decides; API keys and S2S clients are refused. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/mdf/claims/{id}/decision",
    operation_id = "partner_mdf_claim_decide",
    tag = "partner",
    params(("id" = Uuid, Path, description = "The MDF claim")),
    request_body = MdfDecisionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Decided", body = MdfDecided),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such claim the caller may read", body = ErrorResponse),
        (status = 409, description = "Already decided", body = ErrorResponse),
        (status = 422, description = "No approved request or no proof, or a rejection without a reason", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(crate) async fn post_claim_decision(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<MdfDecisionBody>,
) -> Result<Json<MdfDecided>, AppError> {
    decide(&state, &ctx, Kind::Claim, id, body).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/partner/mdf/requests/{id}/decision",
            post(post_request_decision),
        )
        .route(
            "/api/v1/partner/mdf/claims/{id}/decision",
            post(post_claim_decision),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_request_decision, post_claim_decision),
    components(schemas(MdfDecisionBody, MdfDecided))
)]
pub(crate) struct MdfApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_must_fit_and_claims_need_an_approved_request_and_proof() {
        assert_eq!(refusal(Kind::Request, true, false, false), None);
        assert!(refusal(Kind::Request, false, true, true).is_some());
        assert!(refusal(Kind::Claim, true, false, true).is_some());
        assert!(refusal(Kind::Claim, true, true, false).is_some());
        assert_eq!(refusal(Kind::Claim, false, true, true), None);
    }
}
