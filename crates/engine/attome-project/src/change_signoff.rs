//! V5-T1: a customer signs a change request through K4, and the signature
//! decides it.
//!
//! `POST /api/v1/project/change-request/{id}/send-for-signoff` puts the
//! change document (an `attome_document` the caller may read) in a K4
//! envelope for the customer's signer, as the caller, and sends it. The
//! change request must be pending and customer facing; it keeps the
//! envelope in `signoff_envelope_ref`, `signoff_status = pending` and who
//! sent it (platform changeset 0063). One envelope at a time: the claim is
//! a guarded update, and an envelope that lost the race is voided.
//!
//! The `change_signoff` job (every minute) follows each pending envelope:
//! **completed** approves the change request as the person who sent it,
//! through the same decision path as the approve route
//! ([`crate::change_request::do_decide_change_request`]: transition,
//! privilege and guard, budget and schedule impact, then the automatic
//! rebaseline); **declined** or **voided** rejects it the same way. The
//! sign-off status is written first, so a decision the state model refuses
//! (the sender requested the change, say) is logged and left for a person,
//! and the envelope is not followed again.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "change_signoff";
const ENTITY: &str = "project_change_request";
const BATCH: i64 = 200;

/// `project_change_request.update`: who sends for sign-off.
#[derive(Debug)]
pub struct ChangeRequestUpdate;

impl PrivilegeKey for ChangeRequestUpdate {
    const KEY: &'static str = "project_change_request.update";
}

/// What a finished envelope does: `(signoff status, decision)`. Pure.
pub fn decision_of(envelope_status: &str) -> Option<(&'static str, &'static str)> {
    match envelope_status {
        "completed" => Some(("signed", "approved")),
        "declined" | "voided" => Some(("declined", "rejected")),
        _ => None,
    }
}

/// Why a change request cannot go for sign-off, if it cannot. Pure.
pub fn sendable(
    status: Option<&str>,
    customer_facing: Option<bool>,
    signoff: Option<&str>,
) -> Option<&'static str> {
    if status != Some("pending") {
        return Some("only a pending change request goes for sign-off");
    }
    if customer_facing != Some(true) {
        return Some("only a customer-facing change request goes for sign-off");
    }
    if matches!(signoff, Some("pending" | "signed")) {
        return Some("this change request is already out for sign-off or signed");
    }
    None
}

/// The request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SignoffBody {
    /// The change document, an `attome_document` record.
    pub document_id: Uuid,
    pub signer_name: String,
    pub signer_email: String,
}

/// The envelope sent.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SignoffSent {
    pub change_request_id: Uuid,
    pub envelope_id: Uuid,
}

/// Sends a change request for the customer's signature.
pub async fn send(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    id: Uuid,
    body: &SignoffBody,
) -> Result<SignoffSent, AppError> {
    let db = &state.base.db;
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = $1 \
            AND column_name = 'signoff_status')",
    )
    .bind(ENTITY)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Err(AppError::NotFound);
    }
    let email = body.signer_email.trim();
    if !email.contains('@') || email.len() > 320 {
        return Err(AppError::Validation(
            "signer_email: an email address".into(),
        ));
    }
    let name = body.signer_name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("signer_name: required".into()));
    }
    let record = attome_records::entity_crud::read_record(state, ctx, ENTITY, id).await?;
    let data = record.data();
    let text = |k: &str| data.get(k).and_then(serde_json::Value::as_str);
    if let Some(reason) = sendable(
        text("status"),
        data.get("is_customer_facing")
            .and_then(serde_json::Value::as_bool),
        text("signoff_status"),
    ) {
        return Err(AppError::Conflict(reason));
    }
    let title: String = format!(
        "Change request: {}",
        text("title").unwrap_or("project change")
    )
    .chars()
    .take(200)
    .collect();
    let envelope = attome_document::esign::create_envelope(
        state,
        ctx,
        &attome_document::esign::NewEnvelope {
            title,
            document_ids: vec![body.document_id],
            signers: vec![attome_document::esign::NewSigner {
                name: name.to_owned(),
                email: email.to_owned(),
                role: None,
                order: None,
            }],
        },
    )
    .await?;
    let claimed = sqlx::query(
        "UPDATE project_change_request SET signoff_envelope_ref = $2, signoff_status = 'pending', \
             signoff_requested_by = $3, modified_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND status = 'pending' \
            AND (signoff_status IS NULL OR signoff_status = 'declined')",
    )
    .bind(id)
    .bind(envelope.to_string())
    .bind(ctx.user_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        attome_document::esign::void_envelope(state, ctx, envelope).await?;
        return Err(AppError::Conflict(
            "this change request was sent for sign-off meanwhile",
        ));
    }
    attome_document::esign::send_envelope(state, ctx, envelope).await?;
    let mut tx = attome_db::tx::begin(db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            ENTITY,
            id,
            attome_audit::AuditOperation::Update,
            "project.change_sent_for_signoff",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(SignoffSent {
        change_request_id: id,
        envelope_id: envelope,
    })
}

/// One tick: decides the change requests whose envelopes finished.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let ready: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = 'project_change_request' \
            AND column_name = 'signoff_status')",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !ready {
        return Ok(0);
    }
    let pending: Vec<(Uuid, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, signoff_envelope_ref, signoff_requested_by FROM project_change_request \
          WHERE signoff_status = 'pending' AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut decided = 0;
    for (id, envelope, sender) in pending {
        let Some(envelope) = envelope.as_deref().and_then(|e| Uuid::parse_str(e).ok()) else {
            continue;
        };
        let Some(status) = attome_document::esign::envelope_status(state, envelope).await? else {
            continue;
        };
        let Some((signoff, decision)) = decision_of(&status) else {
            continue;
        };
        // The sign-off result first: the envelope is not followed again.
        let marked = sqlx::query(
            "UPDATE project_change_request SET signoff_status = $2, modified_at = now(), \
                 row_version = row_version + 1 WHERE id = $1 AND signoff_status = 'pending'",
        )
        .bind(id)
        .bind(signoff)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        if marked.rows_affected() == 0 {
            continue;
        }
        decided += 1;
        let Some(sender) = sender else {
            tracing::warn!(change_request = %id, "change sign-off: no sender to decide as");
            continue;
        };
        if let Err(error) =
            crate::change_request::do_decide_change_request(state, id, decision, sender).await
        {
            tracing::warn!(
                change_request = %id,
                %error,
                "change sign-off: the customer {signoff}, but the decision was refused; decide it by hand"
            );
        }
    }
    Ok(decided)
}

#[utoipa::path(
    post,
    path = "/api/v1/project/change-request/{id}/send-for-signoff",
    operation_id = "post_change_request_signoff",
    tag = "projects",
    params(("id" = Uuid, Path, description = "The change request")),
    request_body = SignoffBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Sent for signature", body = SignoffSent),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks project_change_request.update", body = ErrorResponse),
        (status = 404, description = "No such change request or document, or sign-off is not installed", body = ErrorResponse),
        (status = 409, description = "Not pending, not customer facing, or already out for sign-off", body = ErrorResponse),
        (status = 422, description = "No signer name or email", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Sends a change request for the customer's signature.
///
/// The change document goes to the signer in a K4 envelope; when it is
/// signed the change request is approved and the project rebaselined, and a
/// declined envelope rejects it.
async fn post_signoff(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ChangeRequestUpdate>>,
    Path(id): Path<Uuid>,
    Json(body): Json<SignoffBody>,
) -> Result<Json<SignoffSent>, AppError> {
    Ok(Json(send(&state, &ctx, id, &body).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/project/change-request/{id}/send-for-signoff",
        post(post_signoff),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_signoff), components(schemas(SignoffBody, SignoffSent)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod change_signoff_tests {
    use super::*;

    #[test]
    fn a_signed_envelope_approves_and_a_declined_one_rejects() {
        assert_eq!(decision_of("completed"), Some(("signed", "approved")));
        assert_eq!(decision_of("declined"), Some(("declined", "rejected")));
        assert_eq!(decision_of("voided"), Some(("declined", "rejected")));
        assert_eq!(decision_of("sent"), None);
        assert_eq!(decision_of("draft"), None);
    }

    #[test]
    fn only_pending_customer_facing_changes_go_for_signoff_once() {
        assert_eq!(sendable(Some("pending"), Some(true), None), None);
        assert_eq!(
            sendable(Some("pending"), Some(true), Some("declined")),
            None,
            "again after a decline"
        );
        assert!(sendable(Some("approved"), Some(true), None).is_some());
        assert!(sendable(Some("pending"), Some(false), None).is_some());
        assert!(sendable(Some("pending"), Some(true), Some("pending")).is_some());
        assert!(sendable(Some("pending"), Some(true), Some("signed")).is_some());
    }
}
