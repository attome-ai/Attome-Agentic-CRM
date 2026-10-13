//! Invitations (P-registration-gating Phase 2, D-128). Admin-minted bearer
//! tokens that gate self-registration when auth.registration_mode = "invite"
//! (attome_auth::invitation, invitation_token, migration 0045).
//! system.admin-gated like every other admin-surface mutation here (D-011) —
//! minting an invitation is equivalent to deciding who may create an account,
//! which is exactly the kind of decision this coarse gate exists for.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::jobs::EngineJob;
use attome_email::EmailMessage;
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Generous enough to not be a UX problem; never varied per-deployment, not
/// a config knob.
const INVITATION_TOKEN_EXPIRY_HOURS: u64 = 168;

#[derive(Serialize, ToSchema)]
pub struct InvitationItem {
    id: Uuid,
    email: String,
    invited_by_ref: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for InvitationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationItem").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateInvitationBody {
    email: String,
}

/// Only ever returned once, right after minting — same "the caller needs the
/// actual bearer at least once" reasoning as every other token-issuance
/// response in this codebase (e.g. MFA's one-time recovery-code batch). Never
/// re-derivable from `list_invitations`, which only ever returns
/// `InvitationItem` (no `bearer`/`register_link` field).
#[derive(Serialize, ToSchema)]
pub struct CreateInvitationResponse {
    #[serde(flatten)]
    item: InvitationItem,
    /// The fully-qualified register link — handed to an admin to relay to the
    /// invitee directly, since `config.email.enabled = false` (no SMTP
    /// configured) is a fully supported deployment shape (D-002 single-tenant
    /// air-gapped install). Also emailed when `email.enabled` is true, same
    /// dual-path pattern as `register`'s own verification-email step.
    register_link: String,
}

impl std::fmt::Debug for CreateInvitationResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateInvitationResponse")
            .finish_non_exhaustive()
    }
}

type InvitationRow = (
    Uuid,
    String,
    Uuid,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
);

fn invitation_row_to_item(row: InvitationRow) -> InvitationItem {
    let (id, email, invited_by_ref, created_at, expires_at, used_at) = row;
    InvitationItem {
        id,
        email,
        invited_by_ref,
        created_at,
        expires_at,
        used_at,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/security/invitations",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<InvitationItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_invitations(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<InvitationItem>>, AppError> {
    let window = query.window();

    let rows: Vec<InvitationRow> = sqlx::query_as(
        "SELECT id, email, invited_by_ref, created_at, expires_at, used_at
         FROM invitation_token
         ORDER BY created_at DESC
         LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invitation_token")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows.into_iter().map(invitation_row_to_item).collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Mints an invitation and, when this deployment has email configured,
/// enqueues it (`EngineJob::SendEmail`, never sent on the request path —
/// guidelines §10) in the same transaction as the token insert — same
/// commit-together discipline as `register`/`reset_request`, so an enqueue
/// failure rolls back the invitation instead of being logged and reported as
/// success (previously it was caught and only `tracing::warn!`-ed here).
/// Does not check whether `email` already has a live `user_account` row —
/// an admin re-inviting an existing user is treated as their call, not this
/// endpoint's to second-guess; `register` itself still rejects a
/// duplicate/disabled email at INSERT time regardless of whether the
/// invitation token validated.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/invitations",
    tag = "admin-security",
    request_body = CreateInvitationBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = CreateInvitationResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_invitation(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateInvitationBody>,
) -> Result<(StatusCode, Json<CreateInvitationResponse>), AppError> {
    let email = body.email.trim();
    if email.is_empty() {
        return Err(AppError::Validation("email is required".into()));
    }
    // D-786 follow-up L2: an invitation to a reserved service-principal
    // address would let its accepter squat the address.
    crate::accounts::refuse_reserved_service_email(email)?;

    // P-email-hardening: transactional so the invitation token, its
    // email_delivery tracking row, and the durable job enqueue all
    // commit atomically — a crash between any two of them can no longer
    // leave a token minted with no tracked/queued email, or a tracking row
    // referencing a token that was never actually created.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let issued = attome_auth::invitation::issue_in_tx(
        &mut tx,
        email,
        ctx.user_id,
        INVITATION_TOKEN_EXPIRY_HOURS,
        &state.base.pepper_ring(),
    )
    .await?;
    let register_link = format!(
        "{}/register?invitation_token={}",
        state.base.config.frontend_url(),
        issued.bearer
    );

    if state.base.config.email.enabled {
        let (subject, text_body, html_body) = attome_email::templates::invitation(&register_link);
        let delivery_id = Uuid::now_v7();
        attome_email::delivery::record_queued_in_tx(
            &mut tx,
            delivery_id,
            attome_email::delivery::EmailDeliveryKind::Invitation,
            &issued.email,
            &subject,
            None,
            Some(ctx.user_id),
            None,
        )
        .await
        .map_err(AppError::internal)?;
        let job = EngineJob::SendEmail(Box::new(EmailMessage {
            to: issued.email.clone(),
            subject,
            text_body,
            html_body: Some(html_body),
            delivery_id: Some(delivery_id),
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
        }));
        attome_jobs::enqueue_in_tx(&mut tx, job)
            .await
            .map_err(AppError::internal)?;
    }
    // Audit plan 3.4: the invitation is a registration credential; its
    // mandatory event commits with the token.
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "invitation_token",
            Some(issued.id),
        )
        .named("invitation_issued"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    tracing::info!(
        invitation_id = %issued.id,
        admin_id = %ctx.user_id,
        "admin minted a registration invitation"
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateInvitationResponse {
            item: InvitationItem {
                id: issued.id,
                email: issued.email,
                invited_by_ref: ctx.user_id,
                created_at: issued.created_at,
                expires_at: issued.expires_at,
                used_at: None,
            },
            register_link,
        }),
    ))
}

/// Revokes a pending (unconsumed, unexpired) invitation by stamping `used_at`
/// — the same single-use marker `validate_and_consume` checks, so a revoked
/// invitation fails exactly like an already-used one (no separate "revoked"
/// state to add to `register`'s undifferentiated-403 reasoning, D-128 §8).
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/invitations/{id}",
    tag = "admin-security",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn revoke_invitation(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(invitation_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_audit::security::SecurityTx::begin(
        &state,
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Credential,
            AuditOperation::Revoke,
            ctx.user_id,
            "invitation_token",
            Some(invitation_id),
        ),
    )
    .await?;
    let revoked = sqlx::query(
        "UPDATE invitation_token SET used_at = NOW() WHERE id = $1 AND used_at IS NULL",
    )
    .bind(invitation_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    if revoked == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;

    tracing::info!(
        invitation_id = %invitation_id,
        admin_id = %ctx.user_id,
        "admin revoked a pending registration invitation"
    );
    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/api/v1/admin/security/invitations/{id}",
            axum::routing::delete(revoke_invitation),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_invitations, create_invitation, revoke_invitation))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
