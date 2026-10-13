//! Self-service TOTP MFA (P2.8 step 7, D-069): enroll/confirm/disable/
//! regenerate-recovery-codes for the caller's own account
//! (`SessionClaims.sub`), same shape as `api_keys.rs` — no `SecurityContext`/
//! admin gate, a user manages their own second factor. All business logic
//! lives in `attome_auth::mfa`; this module is route wiring + the
//! `mfa_encryption_key` config lookup.
//!
//! The login-time pending-token flow (verify/recovery/pending-enroll/
//! pending-confirm) is bypass-listed and lives in the website's `auth.rs`
//! instead — those callers have no session yet, so they can't be mounted
//! here.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_auth::session::SessionClaims;
use attome_config::KeyRing;
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::middleware::rate_limit::{
    MFA_ATTEMPTS_PER_ACCOUNT_RPM, enforce_account_budget, mfa_account_key,
};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json, Router,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Cloned out of the arc-swap guard (not held as a reference) — every caller
/// awaits at least once after this, and `KeyRing` isn't `Copy`.
fn mfa_key(state: &EngineState) -> Result<KeyRing, AppError> {
    let ring = state.base.secrets.load().mfa_encryption_key.clone();
    if ring.is_empty() {
        return Err(AppError::internal(
            "auth.mfa_encryption_key has no active key configured",
        ));
    }
    Ok(ring)
}

#[derive(Serialize, ToSchema)]
struct StatusResponseBody {
    enrolled: bool,
}

#[derive(Serialize, ToSchema)]
struct EnrollResponseBody {
    secret_base32: String,
    otpauth_uri: String,
}

#[derive(Deserialize, ToSchema)]
struct CodeBody {
    code: String,
}

#[derive(Serialize, ToSchema)]
struct RecoveryCodesBody {
    recovery_codes: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct Ack {
    ok: bool,
}

/// Whether the caller's own account has a confirmed TOTP enrollment — the
/// self-service UI's only way to know whether to render "Enable" or "Disable"
/// (the enroll/confirm/disable/regenerate endpoints are mutation-only).
#[utoipa::path(
    get,
    path = "/api/v1/auth/mfa/status",
    tag = "auth",
    responses(
        (status = 200, description = "Success", body = StatusResponseBody),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn status(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
) -> Result<Json<StatusResponseBody>, AppError> {
    let enrolled = attome_auth::mfa::is_enrolled(&state.base.db, claims.sub).await?;
    Ok(Json(StatusResponseBody { enrolled }))
}

/// Audit plan 3.4 (D-541 rule 7): the self-service MFA events, written by a
/// [`attome_db::BeforeCommit`] hook inside `attome_auth::mfa`'s own transaction,
/// so the change and its event commit together (D-062).
fn mfa_hook<'s>(
    state: &'s EngineState,
    operation: AuditOperation,
    event_name: &'static str,
) -> impl attome_db::BeforeCommit<uuid::Uuid> + 's {
    attome_audit::security::account_event_hook(
        attome_audit::audit_service(state),
        attome_audit::security::MandatoryCategory::Credential,
        operation,
        "user_mfa",
        event_name,
    )
}

/// A rejected second-factor code on a self-service route: `Security` +
/// `FailedLogin` with outcome `Failed` (audit plan 3.4). Nothing was changed,
/// so there is no transaction to join; the write is bounded by the
/// per-account MFA budget charged before the verifier ran. Only an
/// `Unauthorized` rejection is recorded, then returned unchanged.
async fn record_failed_code(
    state: &EngineState,
    user_id: uuid::Uuid,
    event_name: &'static str,
    err: AppError,
) -> AppError {
    if !matches!(err, AppError::Unauthorized) {
        return err;
    }
    let written = attome_audit::security::SecurityAuditor::from_state(state)
        .write(
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Security,
                AuditOperation::FailedLogin,
                uuid::Uuid::nil(),
                "user_account",
                Some(user_id),
            )
            .named(event_name)
            .outcome(attome_audit::AuditOutcome::Failed),
        )
        .await;
    match written {
        Ok(_) => err,
        Err(audit_err) => audit_err,
    }
}

/// Starts (or restarts) enrollment. Gated on `auth.mfa_policy != "off"` —
/// a deployment kill switch means no one can enroll, not just that login
/// stops requiring it (mirrors `reset_request`'s `email.enabled` gate).
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/enroll",
    tag = "auth",
    // D-542: not exemptable. Starting enrolment replaces any unconfirmed
    // factor secret with a new one (a persistent credential-state change), so
    // none of the closed exemption reasons applies.
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = EnrollResponseBody),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn enroll(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
) -> Result<(StatusCode, Json<EnrollResponseBody>), AppError> {
    if state.base.config.auth.mfa_policy == "off" {
        return Err(AppError::FeatureUnavailable);
    }
    let key = mfa_key(&state)?;
    let resp = attome_auth::mfa::enroll_with(
        &state.base.db,
        &key,
        claims.sub,
        &mfa_hook(&state, AuditOperation::Create, "mfa_enrollment_started"),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(EnrollResponseBody {
            secret_base32: resp.secret_base32,
            otpauth_uri: resp.otpauth_uri,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/confirm",
    tag = "auth",
    request_body = CodeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::MfaEnrolled)])))),
    responses(
        (status = 200, description = "Success", body = RecoveryCodesBody),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn confirm(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Json(body): Json<CodeBody>,
) -> Result<Json<RecoveryCodesBody>, AppError> {
    let key = mfa_key(&state)?;
    let recovery_codes = match attome_auth::mfa::confirm_enrollment_with(
        &state.base.db,
        &key,
        &state.base.pepper_ring(),
        claims.sub,
        &body.code,
        &mfa_hook(&state, AuditOperation::MfaEnrolled, "mfa_enrolled"),
    )
    .await
    {
        Ok(codes) => codes,
        Err(e) => {
            return Err(record_failed_code(&state, claims.sub, "mfa_confirm_failed", e).await);
        }
    };
    Ok(Json(RecoveryCodesBody { recovery_codes }))
}

/// Disables the caller's MFA. The TOTP or recovery code in the request is this
/// request's step-up (D-510 rule 8): it is verified once, satisfies freshness
/// for this request only, and writes no elevation. Only a cookie session with
/// a live refresh family may call it (rule 7).
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/disable",
    tag = "auth",
    request_body = CodeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::MfaDisabled)])))),
    responses(
        (status = 200, description = "Success", body = Ack),
        (status = 401, description = "Missing or invalid credentials, a session without a live refresh family, or a missing, wrong or replayed code", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller: only a cookie session may disable MFA", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
        (status = 429, description = "Too many second-factor attempts for this account", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn disable(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Json(body): Json<CodeBody>,
) -> Result<Response, AppError> {
    // Base-auth hardening 2.1d (D-510 rules 7 and 8): refuse API-key and S2S
    // callers and sessions without a live family before anything else. The
    // code verified below is the step-up, so no elevation is read.
    attome_auth::step_up::require_recent_auth(
        &state.base.db,
        caller,
        claims.sub,
        attome_auth::step_up::Operation::MfaDisable,
        state.base.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    // Base-auth hardening 1.5: the same per-account bucket as login-time
    // verification, checked before any verifier runs; a Redis failure rejects.
    if let Some(rejected) = enforce_account_budget(
        &state.base.redis_coordination,
        &mfa_account_key(claims.sub),
        MFA_ATTEMPTS_PER_ACCOUNT_RPM,
        "mfa_disable",
    )
    .await?
    {
        return Ok(rejected);
    }
    let key = mfa_key(&state)?;
    if let Err(e) = attome_auth::mfa::disable_with(
        &state.base.db,
        &key,
        &state.base.pepper_ring(),
        claims.sub,
        &body.code,
        &mfa_hook(&state, AuditOperation::MfaDisabled, "mfa_disabled"),
    )
    .await
    {
        return Err(record_failed_code(&state, claims.sub, "mfa_disable_failed", e).await);
    }
    Ok(Json(Ack { ok: true }).into_response())
}

/// Regenerates the caller's recovery codes. The TOTP code in the request is
/// this request's step-up (D-510 rule 8): it is verified once, satisfies
/// freshness for this request only, and writes no elevation. Only TOTP is
/// accepted here (I11). Only a cookie session with a live refresh family may
/// call it (rule 7).
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/recovery-codes/regenerate",
    tag = "auth",
    request_body = CodeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Rotate)])))),
    responses(
        (status = 200, description = "Success", body = RecoveryCodesBody),
        (status = 401, description = "Missing or invalid credentials, a session without a live refresh family, or a missing, wrong or replayed TOTP code", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller: only a cookie session may regenerate recovery codes", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
        (status = 429, description = "Too many second-factor attempts for this account", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn regenerate_recovery_codes(
    State(state): State<EngineState>,
    Extension(claims): Extension<SessionClaims>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    // Authenticated-only by design: acts solely on the caller's own
    // `claims.sub`. Declared so the route's posture is explicit, and so the
    // extractor still proves the request passed through `authz`.
    _ctx: Authorized<SelfService>,
    Json(body): Json<CodeBody>,
) -> Result<Response, AppError> {
    // Base-auth hardening 2.1d (D-510 rules 7 and 8), as for `disable`.
    attome_auth::step_up::require_recent_auth(
        &state.base.db,
        caller,
        claims.sub,
        attome_auth::step_up::Operation::RecoveryCodesRegenerate,
        state.base.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    // Base-auth hardening 1.5: shares `disable`'s per-account MFA bucket.
    if let Some(rejected) = enforce_account_budget(
        &state.base.redis_coordination,
        &mfa_account_key(claims.sub),
        MFA_ATTEMPTS_PER_ACCOUNT_RPM,
        "mfa_regenerate_recovery_codes",
    )
    .await?
    {
        return Ok(rejected);
    }
    let key = mfa_key(&state)?;
    let recovery_codes = match attome_auth::mfa::regenerate_recovery_codes_with(
        &state.base.db,
        &key,
        &state.base.pepper_ring(),
        claims.sub,
        &body.code,
        &mfa_hook(
            &state,
            AuditOperation::Rotate,
            "mfa_recovery_codes_regenerated",
        ),
    )
    .await
    {
        Ok(codes) => codes,
        Err(e) => {
            return Err(record_failed_code(&state, claims.sub, "mfa_regenerate_failed", e).await);
        }
    };
    Ok(Json(RecoveryCodesBody { recovery_codes }).into_response())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/auth/mfa/status", get(status))
        .route("/api/v1/auth/mfa/enroll", post(enroll))
        .route("/api/v1/auth/mfa/confirm", post(confirm))
        .route("/api/v1/auth/mfa/disable", post(disable))
        .route(
            "/api/v1/auth/mfa/recovery-codes/regenerate",
            post(regenerate_recovery_codes),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(status, enroll, confirm, disable, regenerate_recovery_codes))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
