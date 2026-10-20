//! Plan acceptance (roadmap F10-T10): a participant signs their plan
//! through K4 electronic signatures before they are paid.
//!
//! `POST /api/v1/commission/plans/{id}/send-for-acceptance` takes a K3
//! template for `plan_participant` and, for each participant of the plan's
//! latest published version who has not accepted it, adds an
//! `attome_document` and queues the template's render against the
//! participant into that document's file, then marks the participant
//! `pending`. Nothing renders or emails on the request thread.
//!
//! The `commission_acceptance` job ([`tick`]) carries each request on:
//! once the document has its file it puts it in a K4 envelope for the
//! participant's user, as the person who asked, and sends it; when the
//! envelope is completed the participant is `accepted` and their `held`
//! payouts are released (`calculated`, or `approved` in a period closed
//! while they waited); a declined or voided envelope
//! makes them `declined` (a new request can be sent). While a participant
//! is pending or declined, calculation runs hold their payout
//! ([`crate::run::held`]). There is no second signing mechanism here: the
//! ceremony, codes, evidence and certificate are K4's.

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::plan_admin::PlanUpdate;

/// The registered job.
pub const JOB: &str = "commission_acceptance";
/// Participants one request or one tick handles.
pub const LIMIT: i64 = 500;

/// What a participant's acceptance becomes from their envelope's status.
/// Pure.
pub fn outcome(envelope_status: &str) -> Option<&'static str> {
    match envelope_status {
        "completed" => Some("accepted"),
        "declined" | "voided" => Some("declined"),
        _ => None,
    }
}

/// The request.
#[derive(Debug, Deserialize, ToSchema)]
pub struct SendForAcceptanceBody {
    /// A K3 `docgen_template` whose entity is `plan_participant`.
    pub template_id: Uuid,
}

/// What was requested.
#[derive(Debug, Serialize, ToSchema)]
pub struct AcceptanceRequested {
    pub plan_version_id: Uuid,
    /// Participants asked to accept.
    pub participants: u64,
    /// The renders, at `GET /api/v1/docgen/renders/{id}`.
    pub render_ids: Vec<Uuid>,
}

#[utoipa::path(
    post,
    path = "/api/v1/commission/plans/{id}/send-for-acceptance",
    tag = "commission",
    params(("id" = Uuid, Path, description = "The compensation plan")),
    request_body = SendForAcceptanceBody,
    responses(
        (status = 202, description = "Plan documents are rendering; each goes out for signature when ready", body = AcceptanceRequested),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks comp_plan.update or may not create documents", body = ErrorResponse),
        (status = 404, description = "No such plan or template", body = ErrorResponse),
        (status = 409, description = "The plan has no published version", body = ErrorResponse),
        (status = 422, description = "The template is not for plan participants", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn commission_post_send_for_acceptance(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<PlanUpdate>>,
    Path(plan): Path<Uuid>,
    Json(body): Json<SendForAcceptanceBody>,
) -> Result<(StatusCode, Json<AcceptanceRequested>), AppError> {
    ctx.require("plan_participant", "update")?;
    ctx.require("attome_document", "create")?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM comp_plan WHERE id = $1 \
             AND (is_active IS NULL OR is_active = true))",
    )
    .bind(plan)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !exists {
        return Err(AppError::NotFound);
    }
    let template =
        attome_records::entity_crud::read_record(&state, &ctx, "docgen_template", body.template_id)
            .await?;
    if template.data().get("entity").and_then(Value::as_str) != Some("plan_participant") {
        return Err(AppError::Validation(
            "template_id: the template must be for plan_participant".into(),
        ));
    }
    let version: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM comp_plan_version \
         WHERE plan_ref = $1 AND published_at IS NOT NULL \
           AND (is_active IS NULL OR is_active = true) \
         ORDER BY version DESC NULLS LAST, published_at DESC LIMIT 1",
    )
    .bind(plan)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(version) = version else {
        return Err(AppError::Conflict("the plan has no published version"));
    };
    // Not accepted and not already out for signature.
    let participants: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM plan_participant \
         WHERE plan_version_ref = $1 AND user_ref IS NOT NULL \
           AND (is_active IS NULL OR is_active = true) \
           AND (acceptance_status IS NULL OR acceptance_status = 'declined' \
                OR (acceptance_status = 'pending' AND envelope_id IS NULL)) \
         ORDER BY id LIMIT $2",
    )
    .bind(version)
    .bind(LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut render_ids = Vec::with_capacity(participants.len());
    for participant in &participants {
        let (document, _) = attome_records::entity_crud::create_record_for(
            &state,
            &ctx,
            ctx.user_id,
            "attome_document",
            json!({
                "name": "Commission plan acceptance",
                "entity_name": "plan_participant",
                "record_id": participant.to_string(),
            }),
        )
        .await?;
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let render = attome_docgen::render::enqueue_in_tx(
            &state,
            &ctx,
            &mut tx,
            body.template_id,
            *participant,
            Some(attome_docgen::render::AttachTarget {
                entity: "attome_document",
                record_id: document,
                field: "file",
            }),
        )
        .await?;
        sqlx::query(
            "UPDATE plan_participant SET acceptance_status = 'pending', \
                 acceptance_document_id = $2, acceptance_requested_by = $3, envelope_id = NULL, \
                 modified_at = now(), row_version = row_version + 1 WHERE id = $1",
        )
        .bind(participant)
        .bind(document.to_string())
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_audit::write_business_event_in_tx(
            &mut tx,
            &attome_audit::audit_service(&state),
            attome_audit::BusinessEvent::new(
                "plan_participant",
                *participant,
                attome_audit::AuditOperation::Create,
                "commission.acceptance_requested",
                ctx.user_id,
            )
            .comment(format!("plan version {version}, render {render}")),
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        render_ids.push(render);
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(AcceptanceRequested {
            plan_version_id: version,
            participants: participants.len() as u64,
            render_ids,
        }),
    ))
}

type Waiting = (Uuid, Option<Uuid>, Option<String>, Option<Uuid>);

/// One tick of the job: sends the envelopes whose documents are ready and
/// records the envelopes that finished. Answers the participants changed.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let mut changed = 0;

    // Rendered documents go out for signature.
    let ready: Vec<Waiting> = sqlx::query_as(
        "SELECT id, user_ref, acceptance_document_id, acceptance_requested_by \
           FROM plan_participant \
          WHERE acceptance_status = 'pending' AND envelope_id IS NULL \
            AND acceptance_document_id IS NOT NULL AND acceptance_requested_by IS NOT NULL \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $1",
    )
    .bind(LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (participant, user, document, requester) in ready {
        let (Some(user), Some(document), Some(requester)) = (
            user,
            document.as_deref().and_then(|d| Uuid::parse_str(d).ok()),
            requester,
        ) else {
            continue;
        };
        match send_one(state, participant, user, document, requester).await {
            Ok(true) => changed += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%participant, %error, "commission acceptance: not sent");
            }
        }
    }

    // Envelopes out for signature: finished ones are recorded, drafts sent.
    let out: Vec<(Uuid, Option<String>, Option<Uuid>)> = sqlx::query_as(
        "SELECT id, envelope_id, acceptance_requested_by FROM plan_participant \
          WHERE acceptance_status = 'pending' AND envelope_id IS NOT NULL \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $1",
    )
    .bind(LIMIT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for (participant, envelope, requester) in out {
        let Some(envelope) = envelope.as_deref().and_then(|e| Uuid::parse_str(e).ok()) else {
            continue;
        };
        let Some(status) = attome_document::esign::envelope_status(state, envelope).await? else {
            continue;
        };
        if status == "draft" {
            // Created, but sending failed last time.
            if let Some(requester) = requester {
                match state.base.security.resolve_strict(requester).await {
                    Ok(ctx) => {
                        if let Err(error) =
                            attome_document::esign::send_envelope(state, &ctx, envelope).await
                        {
                            tracing::warn!(%participant, %error, "commission acceptance: not sent");
                        }
                    }
                    Err(error) => {
                        tracing::warn!(%participant, %error, "commission acceptance: the requester is gone");
                    }
                }
            }
            continue;
        }
        if let (Some(result), Some(requester)) = (outcome(&status), requester) {
            record(state, participant, result, requester).await?;
            changed += 1;
        }
    }
    Ok(changed)
}

/// Puts one participant's rendered document in an envelope, as the person
/// who asked, and sends it. `false` while the render has not finished.
async fn send_one(
    state: &EngineState,
    participant: Uuid,
    user: Uuid,
    document: Uuid,
    requester: Uuid,
) -> Result<bool, AppError> {
    let ctx = state.base.security.resolve_strict(requester).await?;
    let record =
        attome_records::entity_crud::read_record(state, &ctx, "attome_document", document).await?;
    if record.data().get("file").is_none_or(Value::is_null) {
        return Ok(false);
    }
    let signer: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT user_name, email FROM user_account WHERE id = $1")
            .bind(user)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some((name, Some(email))) = signer else {
        return Err(AppError::Validation(
            "the participant's user has no email".into(),
        ));
    };
    let envelope = attome_document::esign::create_envelope(
        state,
        &ctx,
        &attome_document::esign::NewEnvelope {
            title: "Commission plan acceptance".to_owned(),
            document_ids: vec![document],
            signers: vec![attome_document::esign::NewSigner {
                name: name.unwrap_or_else(|| email.clone()),
                email,
                role: None,
                order: None,
            }],
        },
    )
    .await?;
    let claimed = sqlx::query(
        "UPDATE plan_participant SET envelope_id = $2, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND envelope_id IS NULL AND acceptance_status = 'pending'",
    )
    .bind(participant)
    .bind(envelope.to_string())
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        // Another tick sent one first; this draft is never sent.
        attome_document::esign::void_envelope(state, &ctx, envelope).await?;
        return Ok(false);
    }
    attome_document::esign::send_envelope(state, &ctx, envelope).await?;
    Ok(true)
}

/// Records a finished envelope: accepted releases the held payouts. The
/// audit event names `requester`, who sent the plan for acceptance.
pub async fn record(
    state: &EngineState,
    participant: Uuid,
    result: &str,
    requester: Uuid,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE plan_participant SET acceptance_status = $2, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE id = $1 AND acceptance_status = 'pending'",
    )
    .bind(participant)
    .bind(result)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Ok(());
    }
    if result == "accepted" {
        // Released into the period's flow: approved straight away when the
        // period was already closed while they waited.
        sqlx::query(
            "UPDATE comp_payout po SET status = CASE WHEN p.status IN ('approved', 'locked')                      THEN 'approved' ELSE 'calculated' END,                  modified_at = now(), row_version = po.row_version + 1               FROM comp_run r JOIN comp_period p ON p.id = r.period_ref              WHERE po.run_ref = r.id AND po.participant_ref = $1 AND po.status = 'held'",
        )
        .bind(participant)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "plan_participant",
            participant,
            attome_audit::AuditOperation::Update,
            if result == "accepted" {
                "commission.plan_accepted"
            } else {
                "commission.plan_declined"
            },
            requester,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(commission_post_send_for_acceptance),
    components(schemas(SendForAcceptanceBody, AcceptanceRequested))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_decides_the_acceptance() {
        assert_eq!(outcome("completed"), Some("accepted"));
        assert_eq!(outcome("declined"), Some("declined"));
        assert_eq!(outcome("voided"), Some("declined"));
        assert_eq!(outcome("sent"), None);
        assert_eq!(outcome("draft"), None);
    }
}
