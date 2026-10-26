//! Buyer feedback after a close (roadmap D25-T7).
//!
//! `POST /api/v1/sales/win-loss-reviews/{id}/buyer-feedback` asks the
//! buyer's contacts how the deal went, in one of two ways:
//!
//! - `survey`: the published survey named [`BUYER_SURVEY`] (G14) goes to each
//!   contact the caller may read who has consented to surveys (purpose
//!   [`SURVEY_PURPOSE`]); everyone else is skipped with the reason, and no
//!   one is emailed without consent. The answers link back to the review
//!   (`win_loss_review.buyer_feedback_ref`) when the first one arrives.
//! - `interview`: one task (an `activity` of type `task`) regarding the
//!   review, for the caller, naming the contacts to interview.
//!
//! The caller needs update access on the review.

use std::collections::BTreeSet;

use attome_audit::{AuditOperation, BusinessEvent};
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::Json;
use axum::extract::{Path, State};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The G14 survey sent to buyers.
pub const BUYER_SURVEY: &str = "win_loss_buyer";
/// The consent purpose a survey needs.
pub const SURVEY_PURPOSE: &str = "surveys";
/// Most contacts one request names.
pub const MAX_CONTACTS: usize = 50;

const REVIEW: &str = "win_loss_review";

/// How to ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackMode {
    Survey,
    Interview,
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SalesBuyerFeedbackBody {
    pub mode: FeedbackMode,
    /// The buyer's contacts, 1 to 50.
    pub contact_ids: Vec<Uuid>,
}

/// A contact the request did not reach, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesFeedbackSkip {
    pub contact_id: Uuid,
    /// `not_readable`, `no_consent`, `no_address` or `already_sent`.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesBuyerFeedback {
    /// The contacts a survey went to.
    pub sent: Vec<Uuid>,
    pub skipped: Vec<SalesFeedbackSkip>,
    /// The interview task, in `interview` mode.
    pub task_id: Option<Uuid>,
}

fn skip(contact_id: Uuid, reason: &str) -> SalesFeedbackSkip {
    SalesFeedbackSkip {
        contact_id,
        reason: reason.to_owned(),
    }
}

/// The distinct contacts named, in order; refused when none or too many.
pub fn contacts_of(ids: &[Uuid]) -> Result<Vec<Uuid>, AppError> {
    let mut seen = BTreeSet::new();
    let out: Vec<Uuid> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
    if out.is_empty() || out.len() > MAX_CONTACTS {
        return Err(AppError::Validation(format!(
            "contact_ids names 1 to {MAX_CONTACTS} contacts"
        )));
    }
    Ok(out)
}

fn entity_id(state: &EngineState, entity: &str) -> Result<Uuid, AppError> {
    state
        .entities
        .load()
        .get(entity)
        .map(|e| e.entity_id)
        .ok_or(AppError::NotFound)
}

/// Asks the buyer for feedback on review `review`, as `ctx`.
pub async fn request_feedback(
    state: &EngineState,
    ctx: &SecurityContext,
    review: Uuid,
    body: SalesBuyerFeedbackBody,
) -> Result<SalesBuyerFeedback, AppError> {
    let contacts = contacts_of(&body.contact_ids)?;
    let review_entity = entity_id(state, REVIEW)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        review_entity,
        REVIEW,
        review,
        RecordAction::Update,
    )
    .await?;
    let contact_entity = entity_id(state, "contact")?;

    let mut skipped = Vec::new();
    let mut readable = Vec::new();
    for contact in contacts {
        match attome_records::entity_crud::require_record_access(
            state,
            ctx,
            contact_entity,
            "contact",
            contact,
            RecordAction::Read,
        )
        .await
        {
            Ok(()) => readable.push(contact),
            Err(AppError::NotFound | AppError::Forbidden) => {
                skipped.push(skip(contact, "not_readable"));
            }
            Err(e) => return Err(e),
        }
    }

    let mut sent = Vec::new();
    let mut task_id = None;
    match body.mode {
        FeedbackMode::Survey => {
            let mut consented = Vec::new();
            for contact in readable {
                if attome_notification::consent_gate::has_active_consent(
                    &state.base.db,
                    "contact",
                    &contact.to_string(),
                    SURVEY_PURPOSE,
                )
                .await?
                {
                    consented.push(contact);
                } else {
                    skipped.push(skip(contact, "no_consent"));
                }
            }
            if !consented.is_empty() {
                let survey = attome_service::survey_send::published_named(state, BUYER_SURVEY)
                    .await?
                    .ok_or_else(|| {
                        AppError::Validation(format!(
                            "no published survey named {BUYER_SURVEY}; publish one first"
                        ))
                    })?;
                for contact in consented {
                    match attome_service::survey_send::send_to_contact(
                        state, &survey, REVIEW, review, contact,
                    )
                    .await?
                    {
                        Ok(_) => sent.push(contact),
                        Err(attome_service::survey_send::NotSent::NoAddress) => {
                            skipped.push(skip(contact, "no_address"));
                        }
                        Err(attome_service::survey_send::NotSent::AlreadySent) => {
                            skipped.push(skip(contact, "already_sent"));
                        }
                    }
                }
            }
        }
        FeedbackMode::Interview => {
            if readable.is_empty() {
                return Err(AppError::Validation(
                    "none of the contacts can be read; nobody to interview".into(),
                ));
            }
            let names = readable
                .iter()
                .map(Uuid::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let (id, _) = attome_records::entity_crud::create_record_for(
                state,
                ctx,
                ctx.user_id,
                "activity",
                json!({
                    "subject": "Buyer interview for a win-loss review",
                    "activity_type": "task",
                    "regarding_entity": REVIEW,
                    "regarding_id": review.to_string(),
                    "notes": format!("Interview the buyer's contacts: {names}"),
                }),
            )
            .await?;
            task_id = Some(id);
        }
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        BusinessEvent::new(
            REVIEW,
            review,
            AuditOperation::Create,
            "win_loss.buyer_feedback_requested",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(SalesBuyerFeedback {
        sent,
        skipped,
        task_id,
    })
}

/// Ask a buyer for feedback
///
/// D25-T7: sends the buyer survey to the consented contacts the caller may
/// read (`survey`), or creates a task to interview them (`interview`), about
/// a win-loss review. Contacts not reached are listed with the reason.
#[utoipa::path(
    post,
    path = "/api/v1/sales/win-loss-reviews/{id}/buyer-feedback",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The win-loss review")),
    request_body = SalesBuyerFeedbackBody,
    responses(
        (status = 200, description = "Who was asked and who was skipped", body = SalesBuyerFeedback),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this review", body = ErrorResponse),
        (status = 404, description = "No such review", body = ErrorResponse),
        (status = 422, description = "No contacts or too many, no published buyer survey, or no readable contact to interview", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_sales_buyer_feedback(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(review): Path<Uuid>,
    Json(body): Json<SalesBuyerFeedbackBody>,
) -> Result<Json<SalesBuyerFeedback>, AppError> {
    Ok(Json(request_feedback(&state, &ctx, review, body).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sales_buyer_feedback),
    components(schemas(
        FeedbackMode,
        SalesBuyerFeedbackBody,
        SalesFeedbackSkip,
        SalesBuyerFeedback
    ))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contacts_are_distinct_and_bounded() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        assert_eq!(contacts_of(&[a, b, a]).unwrap(), vec![a, b]);
        assert!(contacts_of(&[]).is_err());
        let many: Vec<Uuid> = (0..=MAX_CONTACTS).map(|_| Uuid::now_v7()).collect();
        assert!(contacts_of(&many).is_err());
    }
}
