//! F9-T4: leads routed to partners, with a time limit to accept.
//!
//! A partner reaches a lead through `lead.partner_account_ref`, the field its
//! portal role scopes reads by, as it reaches deals (F9-T3): there is no
//! staff share to write or remove, and the lead's owner never changes, so
//! a lead that comes back is simply its owner's again.
//!
//! - **Offer** (`POST /api/v1/partner/leads/{id}/offer`): a person with update
//!   access names the partner and the hours it has to accept. D4's assignment
//!   rules pick staff, so an offer is its own step.
//! - **Accept or reject** ([`respond`], the portal's
//!   `/{keyword}/api/v1/partner/leads/{id}/accept|reject`): only the partner
//!   the lead is offered to, before the limit; any other caller finds nothing.
//!   A rejection clears the partner.
//! - **Return** ([`return_tick`], hourly): an offer past its limit, or an
//!   accepted lead untouched for [`STALE_DAYS_SETTING`] days, is `returned`
//!   and no longer names the partner. The lead is never deleted.

use attome_audit::{AuditOperation, BusinessEvent, write_business_event_in_tx};
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::support::{installed, person_only, require};

/// The registered hourly job.
pub const RETURN_JOB: &str = "partner_lead_return";
/// Days an accepted lead may sit untouched.
pub const STALE_DAYS_SETTING: &str = "partner.lead_stale_days";
/// [`STALE_DAYS_SETTING`] until someone sets it.
pub const DEFAULT_STALE_DAYS: i64 = 14;
/// Hours to accept when an offer names none.
pub const DEFAULT_ACCEPT_HOURS: i32 = 48;
const BATCH: i64 = 500;

/// `POST /api/v1/partner/leads/{id}/offer`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct OfferBody {
    pub partner_account_id: Uuid,
    /// Hours the partner has to accept; 48 when absent.
    #[serde(default)]
    pub accept_hours: Option<i32>,
}

/// The lead after an offer or an answer.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PartnerLead {
    pub id: Uuid,
    /// `offered`, `accepted` or `rejected`.
    pub partner_status: String,
    /// When an offer lapses.
    pub partner_accept_by: Option<DateTime<Utc>>,
}

/// Offers `lead` to `partner`, unless a partner already holds it.
pub async fn offer_lead_to_partner(
    tx: &mut attome_db::Tx<'_>,
    lead: Uuid,
    partner: Uuid,
    accept_hours: i32,
) -> Result<DateTime<Utc>, AppError> {
    sqlx::query_scalar(
        "UPDATE lead SET partner_account_ref = $2, partner_status = 'offered', \
                partner_accept_by = now() + make_interval(hours => $3), \
                modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND (partner_status IS NULL OR partner_status NOT IN ('offered', 'accepted')) \
            AND EXISTS (SELECT 1 FROM account WHERE id = $2 AND is_partner = true) \
          RETURNING partner_accept_by",
    )
    .bind(lead)
    .bind(partner)
    .bind(accept_hours)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::Conflict(
        "the lead is held by a partner, or the account is not a partner",
    ))
}

/// Offers a lead as the person calling.
pub async fn offer(
    state: &EngineState,
    ctx: &SecurityContext,
    id: Uuid,
    body: OfferBody,
) -> Result<PartnerLead, AppError> {
    person_only(ctx)?;
    require(state, ctx, "lead", id, RecordAction::Update).await?;
    let hours = body.accept_hours.unwrap_or(DEFAULT_ACCEPT_HOURS);
    if hours <= 0 {
        return Err(AppError::Validation(
            "accept_hours must be above zero".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let accept_by = offer_lead_to_partner(&mut tx, id, body.partner_account_id, hours).await?;
    write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            "lead",
            id,
            AuditOperation::Update,
            "partner.lead_offered",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(PartnerLead {
        id,
        partner_status: "offered".to_owned(),
        partner_accept_by: Some(accept_by),
    })
}

/// The partner account a portal person belongs to: their contact's account,
/// when it is a partner.
pub async fn partner_of_portal_user(
    state: &EngineState,
    user: Uuid,
) -> Result<Option<Uuid>, AppError> {
    if !installed(&state.base.db, "webportal_user", "contact_ref").await? {
        return Ok(None);
    }
    sqlx::query_scalar(
        "SELECT a.id FROM webportal_user u \
           JOIN contact c ON c.id = u.contact_ref \
           JOIN account a ON a.id = c.account_ref \
          WHERE u.id = $1 AND a.is_partner = true",
    )
    .bind(user)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Accepts or rejects a live offer made to `partner`. Anything else, another
/// partner's offer included, is not found.
pub async fn respond(
    state: &EngineState,
    partner: Uuid,
    actor: Uuid,
    id: Uuid,
    accept: bool,
) -> Result<PartnerLead, AppError> {
    let status = if accept { "accepted" } else { "rejected" };
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query(
        "UPDATE lead SET partner_status = $3, \
                partner_account_ref = CASE WHEN $3 = 'accepted' THEN partner_account_ref END, \
                modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND partner_account_ref = $2 AND partner_status = 'offered' \
            AND partner_accept_by > now()",
    )
    .bind(id)
    .bind(partner)
    .bind(status)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            "lead",
            id,
            AuditOperation::Update,
            format!("partner.lead_{status}"),
            actor,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(PartnerLead {
        id,
        partner_status: status.to_owned(),
        partner_accept_by: None,
    })
}

/// [`STALE_DAYS_SETTING`], or the default for a value that is not positive.
fn stale_days(state: &EngineState) -> i64 {
    attome_core::setting_registry()
        .get(STALE_DAYS_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_i64())
        .filter(|days| *days > 0)
        .unwrap_or(DEFAULT_STALE_DAYS)
}

/// The hourly job. Answers how many leads came back.
pub async fn return_tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    if !installed(db, "lead", "partner_status").await? {
        return Ok(0);
    }
    let days = i32::try_from(stale_days(state)).unwrap_or(i32::MAX);
    let mut returned = 0;
    loop {
        let mut tx = attome_db::tx::begin(db).await?;
        let rows: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE lead l SET partner_status = 'returned', partner_account_ref = NULL, \
                    modified_at = now(), row_version = row_version + 1 \
              WHERE l.id IN ( \
                    SELECT id FROM lead \
                     WHERE (partner_status = 'offered' AND partner_accept_by <= now()) \
                        OR (partner_status = 'accepted' \
                            AND modified_at < now() - make_interval(days => $1)) \
                     ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED) \
              RETURNING l.id",
        )
        .bind(days)
        .bind(BATCH)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let audit = attome_audit::audit_service(state);
        for id in &rows {
            write_business_event_in_tx(
                &mut tx,
                &audit,
                BusinessEvent::new(
                    "lead",
                    *id,
                    AuditOperation::Update,
                    "partner.lead_returned",
                    Uuid::nil(),
                ),
            )
            .await?;
        }
        attome_db::tx::commit(tx).await?;
        returned += rows.len() as u64;
        if (rows.len() as i64) < BATCH {
            break;
        }
    }
    Ok(returned)
}

/// Offer a lead to a partner
///
/// F9-T4: gives the partner until the limit to accept; a lead a partner already holds cannot be
/// offered. A person with update access on the lead offers; API keys and S2S clients are refused.
/// Audited.
#[utoipa::path(
    post,
    path = "/api/v1/partner/leads/{id}/offer",
    operation_id = "partner_lead_offer",
    tag = "partner",
    params(("id" = Uuid, Path, description = "The lead")),
    request_body = OfferBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Offered", body = PartnerLead),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a person, or no update access", body = ErrorResponse),
        (status = 404, description = "No such lead the caller may read", body = ErrorResponse),
        (status = 409, description = "A partner holds the lead, or the account is not a partner", body = ErrorResponse),
        (status = 422, description = "The hours are not above zero", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(crate) async fn post_offer(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<OfferBody>,
) -> Result<Json<PartnerLead>, AppError> {
    offer(&state, &ctx, id, body).await.map(Json)
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/partner/leads/{id}/offer", post(post_offer))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_offer), components(schemas(OfferBody, PartnerLead)))]
pub(crate) struct LeadsApiDoc;
