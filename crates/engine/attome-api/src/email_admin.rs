//! P-email-hardening — delivery-state visibility, manual resend, and
//! suppression-list management for the three account-lifecycle email
//! producers (registration verification, password reset, admin invitation).
//! A dedicated route (guidelines §9: this isn't CRUD on a registered
//! entity), gated on `system.admin` the same way
//! `s2s_admin`/`license_admin`/`rewrap_admin`/`jobs_admin` are.
//!
//! Never returns a delivery's rendered body — `notification_email_delivery` doesn't
//! store one at all (see migration `0062`'s header comment: verification/
//! reset/invitation mail carries a live, single-use token URL). "Resend"
//! therefore re-mints a fresh token per `kind` via that feature's own
//! `*_in_tx` function rather than replaying stored content.

use attome_audit::security::{
    MandatoryCategory, SecurityAuditor, SecurityEvent, write_security_event,
};
use attome_audit::{AuditOperation, AuditService};
use attome_core::EngineState;
use attome_email::delivery::EmailDeliveryKind;
use attome_server::authz::{Admin, Authorized};
use attome_server::capability::{Available, Email, FastJobs};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, OnePageQuery, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// Token TTLs — never varied per-deployment, not config knobs.
const EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS: u64 = 48;
const PASSWORD_RESET_TOKEN_EXPIRY_MINS: u64 = 30;
const INVITATION_TOKEN_EXPIRY_HOURS: u64 = 168;

// ── Deliveries ───────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
struct DeliveryQuery {
    status: Option<String>,
    kind: Option<String>,
    recipient: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Serialize, ToSchema)]
struct DeliverySummary {
    id: Uuid,
    kind: String,
    recipient: String,
    subject: String,
    status: String,
    attempts: i32,
    last_error: Option<String>,
    sent_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

impl From<attome_email::delivery::EmailDeliveryRow> for DeliverySummary {
    fn from(row: attome_email::delivery::EmailDeliveryRow) -> Self {
        Self {
            id: row.id,
            kind: row.kind,
            recipient: row.recipient,
            subject: row.subject,
            status: row.status,
            attempts: row.attempts,
            last_error: row.last_error,
            sent_at: row.sent_at,
            created_at: row.created_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/email/deliveries",
    tag = "admin",
    params(DeliveryQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DeliverySummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_deliveries(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<DeliveryQuery>,
) -> Result<Json<PaginatedResponse<DeliverySummary>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );

    let rows = attome_email::delivery::list_paginated(
        &state.base.db,
        query.status.as_deref(),
        query.kind.as_deref(),
        query.recipient.as_deref(),
        offset,
        page_size,
    )
    .await
    .map_err(AppError::internal)?;
    let total = attome_email::delivery::count(
        &state.base.db,
        query.status.as_deref(),
        query.kind.as_deref(),
        query.recipient.as_deref(),
    )
    .await
    .map_err(AppError::internal)?;

    let items = rows.into_iter().map(DeliverySummary::from).collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/email/deliveries/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = DeliverySummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_delivery(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<DeliverySummary>, AppError> {
    let row = attome_email::delivery::get_by_id(&state.base.db, id)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(DeliverySummary::from(row)))
}

#[derive(Serialize, ToSchema)]
struct ResendResult {
    new_delivery_id: Uuid,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/email/deliveries/{id}/resend",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = ResendResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The delivery is still queued, or its recipient is suppressed", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn resend_delivery(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    // D-344 — both halves, because a resend needs both and either one being
    // down produces the same silent nothing. `SendEmail` is a fast-queue job
    // (`EngineJob::is_batch` is false for it), so a reachable relay with a
    // dead default worker sends exactly as much mail as a dead relay does.
    //
    // This one route also mints fresh single-use credentials on the way
    // through (`attome_auth::verification`/`reset::request_in_tx` — the
    // resent link carries a live token), so an enqueue that never sends
    // invalidates the recipient's previous link and replaces it with one
    // they will never receive. That makes the failure actively harmful
    // rather than merely useless, which is why this is the one place a
    // capability gate is worth two extractors.
    _email: Available<Email>,
    _jobs: Available<FastJobs>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<ResendResult>), AppError> {
    let row = attome_email::delivery::get_by_id(&state.base.db, id)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;

    // BEM-4: a queued row may still be sent by its own job; resending it
    // would mint a second live credential for one request.
    let status: attome_email::delivery::DeliveryStatus = row
        .status
        .parse()
        .map_err(|_| AppError::internal("delivery row has an unrecognized status"))?;
    if !status.is_terminal() {
        return Err(AppError::Conflict(
            "delivery is still queued; resend only a delivery that has finished",
        ));
    }

    if attome_email::suppression::is_suppressed(&state.base.db, &row.recipient)
        .await
        .map_err(AppError::internal)?
    {
        return Err(AppError::Conflict(
            "recipient address is suppressed; remove the suppression first",
        ));
    }

    let kind: EmailDeliveryKind = row
        .kind
        .parse()
        .map_err(|_| AppError::internal("delivery row has an unrecognized kind"))?;

    // D-786 follow-up L2: a resend re-issues a verification, reset or
    // invitation token to `row.recipient`; none may be minted for an address
    // reserved for a platform service principal.
    if kind != EmailDeliveryKind::Generic {
        attome_security::accounts::refuse_reserved_service_email(&row.recipient)?;
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (subject, text_body, html_body, user_ref, created_by) = match kind {
        EmailDeliveryKind::EmailVerification => {
            let user_id = row.user_ref.ok_or(AppError::Conflict(
                "delivery row has no associated user to re-verify",
            ))?;
            let issued = attome_auth::verification::request_in_tx(
                &mut tx,
                user_id,
                EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS,
                &state.base.pepper_ring(),
            )
            .await?;
            let link = format!(
                "{}/verify-email?token={}",
                state.base.config.frontend_url(),
                issued.bearer
            );
            let (subject, text_body, html_body) =
                attome_email::templates::email_verification(&link);
            (subject, text_body, html_body, Some(user_id), None)
        }
        EmailDeliveryKind::PasswordReset => {
            let issued = attome_auth::reset::request_in_tx(
                &mut tx,
                &row.recipient,
                PASSWORD_RESET_TOKEN_EXPIRY_MINS,
                &state.base.pepper_ring(),
            )
            .await?
            .ok_or(AppError::Conflict(
                "recipient no longer has an eligible password account",
            ))?;
            let link = format!(
                "{}/reset-password?token={}",
                state.base.config.frontend_url(),
                issued.bearer
            );
            let (subject, text_body, html_body) = attome_email::templates::password_reset(&link);
            (subject, text_body, html_body, Some(issued.user_id), None)
        }
        EmailDeliveryKind::Invitation => {
            let issued = attome_auth::invitation::issue_in_tx(
                &mut tx,
                &row.recipient,
                row.created_by.unwrap_or(ctx.user_id),
                INVITATION_TOKEN_EXPIRY_HOURS,
                &state.base.pepper_ring(),
            )
            .await?;
            let link = format!(
                "{}/register?invitation_token={}",
                state.base.config.frontend_url(),
                issued.bearer
            );
            let (subject, text_body, html_body) = attome_email::templates::invitation(&link);
            (subject, text_body, html_body, None, row.created_by)
        }
        EmailDeliveryKind::Generic => {
            return Err(AppError::Validation(
                "generic email deliveries have no stored body and cannot be resent".into(),
            ));
        }
    };

    let new_delivery_id = Uuid::now_v7();
    attome_email::delivery::record_queued_in_tx(
        &mut tx,
        new_delivery_id,
        kind,
        &row.recipient,
        &subject,
        user_ref,
        created_by,
        None,
    )
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: row.recipient,
            subject,
            text_body,
            html_body: Some(html_body),
            delivery_id: Some(new_delivery_id),
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
        })),
    )
    .await
    .map_err(AppError::internal)?;

    let audit = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    write_security_event(
        &mut tx,
        &audit,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "notification_email_delivery",
            Some(new_delivery_id),
        )
        .named("email.resend"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok((StatusCode::CREATED, Json(ResendResult { new_delivery_id })))
}

// ── Suppressions ─────────────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
struct SuppressionSummary {
    id: Uuid,
    email: String,
    reason: String,
    detail: Option<String>,
    created_by: Option<Uuid>,
    created_at: DateTime<Utc>,
}

impl From<attome_email::suppression::SuppressionRow> for SuppressionSummary {
    fn from(row: attome_email::suppression::SuppressionRow) -> Self {
        Self {
            id: row.id,
            email: row.email,
            reason: row.reason,
            detail: row.detail,
            created_by: row.created_by,
            created_at: row.created_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/email/suppressions",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<SuppressionSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_suppressions(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SuppressionSummary>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let rows = attome_email::suppression::list_paginated(&state.base.db, offset, page_size)
        .await
        .map_err(AppError::internal)?;
    let total = attome_email::suppression::count(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let items = rows.into_iter().map(SuppressionSummary::from).collect();
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct AddSuppressionBody {
    email: String,
    detail: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/email/suppressions",
    tag = "admin",
    request_body = AddSuppressionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn add_suppression(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<AddSuppressionBody>,
) -> Result<StatusCode, AppError> {
    if body.email.trim().is_empty() {
        return Err(AppError::Validation("email is required".into()));
    }
    attome_email::suppression::suppress(
        &state.base.db,
        &body.email,
        attome_email::suppression::SuppressionReason::AdminManual,
        body.detail.as_deref(),
        Some(ctx.user_id),
    )
    .await
    .map_err(AppError::internal)?;
    // attome-email cannot depend on attome-audit (layering, coding-guidelines §1), so
    // this writes after the base-layer commit rather than inside its transaction
    // — the same documented D-062 deviation Phase 3 item 3.3 uses for attome-auth.
    SecurityAuditor::from_state(&state)
        .write(
            SecurityEvent::new(
                MandatoryCategory::Configuration,
                AuditOperation::Create,
                ctx.user_id,
                "notification_email_suppression",
                None,
            )
            .named("email.suppression.add"),
        )
        .await?;
    Ok(StatusCode::CREATED)
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/email/suppressions/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn remove_suppression(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let removed = attome_email::suppression::unsuppress(&state.base.db, id)
        .await
        .map_err(AppError::internal)?;
    if !removed {
        return Err(AppError::NotFound);
    }
    // Same D-062 deviation as add_suppression: attome-email cannot depend on attome-audit.
    SecurityAuditor::from_state(&state)
        .write(
            SecurityEvent::new(
                MandatoryCategory::Configuration,
                AuditOperation::SoftDelete,
                ctx.user_id,
                "notification_email_suppression",
                Some(id),
            )
            .named("email.suppression.remove"),
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/email/deliveries", get(list_deliveries))
        .route("/api/v1/admin/email/deliveries/{id}", get(get_delivery))
        .route(
            "/api/v1/admin/email/deliveries/{id}/resend",
            post(resend_delivery),
        )
        .route(
            "/api/v1/admin/email/suppressions",
            get(list_suppressions).post(add_suppression),
        )
        .route(
            "/api/v1/admin/email/suppressions/{id}",
            axum::routing::delete(remove_suppression),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_deliveries,
    get_delivery,
    resend_delivery,
    list_suppressions,
    add_suppression,
    remove_suppression
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
