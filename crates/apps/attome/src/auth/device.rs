//! C7-T1 / T4-T1 (V2-D1415): the OAuth 2.0 device authorization grant
//! (RFC 8628), so a person signs a device in from a browser where they are
//! already signed in: the `attome` CLI, the Outlook add-in and the Gmail
//! add-on.
//!
//! 1. The device asks `POST /api/v1/oauth/device_authorization` with its
//!    `client_id` and receives a device code (kept secret on the device), a
//!    short user code and the page to enter it on.
//! 2. The person opens that page signed in, sees which application asks
//!    (`GET /api/v1/oauth/device?user_code=`), and approves or denies it
//!    (`POST /api/v1/oauth/device/approve`). Only a browser session may: an
//!    API key or a device session cannot approve another device.
//! 3. The device polls `POST /api/v1/oauth/device/token` with
//!    `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Once the
//!    grant is approved it receives an ordinary session, bound to a refresh
//!    family like a browser sign-in (sign-in rules, session limits, the
//!    `Security` + `Login` event, revocable from the person's session list),
//!    as an access token for `Authorization: Bearer` and a refresh token it
//!    redeems at the same endpoint with `grant_type=refresh_token`.
//!
//! The device token endpoint is its own route, not `/api/v1/oauth/token`:
//! that one is the S2S engine's endpoint for machine clients, which act as a
//! service user and never as a person.
//!
//! A grant lives ten minutes and is used once. Only the SHA-256 of the
//! device code is stored; the user code is eight letters from RFC 8628's
//! unambiguous set, shown as `XXXX-XXXX`. The session's authentication time
//! is the approving session's (`AuthContext::device_grant`), and its `amr`
//! is `dev`, never a factor.

use attome_audit::security::{
    ExemptReason, MandatoryCategory, SecurityAuditor, SecurityEvent, write_security_event, x_audit,
    x_audit_exempt,
};
use attome_audit::{AuditCategory, AuditOperation};
use attome_auth::auth_context::AuthContext;
use attome_auth::{SessionClaims, SessionId, accounts, refresh};
use attome_server::AppState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::middleware::auth::CookieSession;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Form, Json,
    extract::{Extension, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::session::{issue_session_tokens, refresh_lifetimes};

/// The device code grant type (RFC 8628 §3.4).
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// The refresh token grant type (RFC 6749 §6).
pub const REFRESH_TOKEN_GRANT: &str = "refresh_token";

/// The applications that may ask for a device grant, and the name a person
/// is shown before approving one. Public clients: they hold no secret.
pub const DEVICE_CLIENTS: &[(&str, &str)] = &[
    ("attome-cli", "Attome CLI"),
    ("attome-outlook", "Attome for Outlook"),
    ("attome-gmail", "Attome for Gmail"),
];

/// How long a grant may wait for its approval.
const GRANT_TTL_SECS: i64 = 600;
/// The slowest a device is asked to poll, in seconds.
const POLL_INTERVAL_SECS: i32 = 5;
/// RFC 8628 §6.1's alphabet: no vowels, no look-alike letters.
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;

fn client_name(client_id: &str) -> Option<&'static str> {
    DEVICE_CLIENTS
        .iter()
        .find(|(id, _)| *id == client_id)
        .map(|(_, name)| *name)
}

fn hash_device_code(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

fn new_device_code() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn new_user_code() -> String {
    let mut bytes = [0u8; USER_CODE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        // 256 is not a multiple of 20; the bias is under 2% per letter and a
        // user code is a lookup key guarded by a signed-in approval, not a
        // secret.
        .map(|b| USER_CODE_ALPHABET[usize::from(*b) % USER_CODE_ALPHABET.len()] as char)
        .collect()
}

/// `user_code` as stored: upper case, without the dash or spaces a person
/// may type. Pure.
pub fn normalise_user_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// `XXXX-XXXX`. Pure.
fn display_user_code(code: &str) -> String {
    if code.len() == USER_CODE_LEN {
        format!("{}-{}", &code[..4], &code[4..])
    } else {
        code.to_owned()
    }
}

/// An RFC 6749 §5.2 error answer.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct DeviceErrorBody {
    /// `invalid_request`, `invalid_client`, `unsupported_grant_type`,
    /// `invalid_grant`, `authorization_pending`, `slow_down`,
    /// `access_denied` or `expired_token`.
    error: String,
}

fn oauth_error(status: StatusCode, code: &str) -> Response {
    no_store(
        (
            status,
            Json(DeviceErrorBody {
                error: code.to_owned(),
            }),
        )
            .into_response(),
    )
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

// ── 1. The device asks ───────────────────────────────────────────────────────

/// A device authorization request (RFC 8628 §3.1), form-encoded.
#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct DeviceAuthorizationForm {
    /// `attome-cli`, `attome-outlook` or `attome-gmail`.
    client_id: String,
    /// Accepted and ignored: the session has the person's own access.
    #[allow(dead_code)]
    scope: Option<String>,
}

/// A device authorization response (RFC 8628 §3.2).
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct DeviceAuthorization {
    /// Kept on the device and sent when polling; never shown.
    device_code: String,
    /// Shown to the person, `XXXX-XXXX`.
    user_code: String,
    /// The page the person enters the code on.
    verification_uri: String,
    /// The same page with the code filled in.
    verification_uri_complete: String,
    /// Seconds the grant waits for its approval.
    expires_in: i64,
    /// Seconds to wait between polls.
    interval: i32,
}

/// Ask for a device grant
///
/// RFC 8628 §3.1: a device asks to be signed in. Returns its device code,
/// the user code the person enters at `verification_uri` in a signed-in
/// browser, and how often to poll `POST /api/v1/oauth/device/token`. No
/// credential: the grant does nothing until a signed-in person approves it.
#[utoipa::path(
    post,
    path = "/api/v1/oauth/device_authorization",
    tag = "auth",
    request_body(content = DeviceAuthorizationForm, content_type = "application/x-www-form-urlencoded"),
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::Delegated,
        Some("POST /api/v1/oauth/device/approve"),
        "opens a pending grant that does nothing until a signed-in person approves it; the approval and the session it creates are audited",
    )))),
    responses(
        (status = 200, description = "The grant's codes", body = DeviceAuthorization),
        (status = 400, description = "An unknown client", body = DeviceErrorBody),
    ),
)]
pub(super) async fn device_authorization(
    State(state): State<AppState>,
    Form(form): Form<DeviceAuthorizationForm>,
) -> Result<Response, AppError> {
    if client_name(&form.client_id).is_none() {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_client"));
    }
    // Grants a day past their expiry are of no further use.
    sqlx::query("DELETE FROM oauth_device_grant WHERE expires_at < now() - interval '1 day'")
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;
    let device_code = new_device_code();
    let mut user_code = String::new();
    for attempt in 0..5 {
        user_code = new_user_code();
        let inserted = sqlx::query(
            "INSERT INTO oauth_device_grant \
                 (id, device_code_hash, user_code, client_id, interval_secs, expires_at) \
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6::float8)) \
             ON CONFLICT DO NOTHING",
        )
        .bind(Uuid::now_v7())
        .bind(hash_device_code(&device_code))
        .bind(&user_code)
        .bind(&form.client_id)
        .bind(POLL_INTERVAL_SECS)
        .bind(GRANT_TTL_SECS as f64)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;
        if inserted.rows_affected() == 1 {
            break;
        }
        if attempt == 4 {
            return Err(AppError::Conflict("no free user code; try again"));
        }
    }
    let page = format!(
        "{}/xrm/device",
        state
            .config
            .app
            .public_frontend_url
            .as_deref()
            .unwrap_or_default()
            .trim_end_matches('/')
    );
    let shown = display_user_code(&user_code);
    Ok(no_store(
        Json(DeviceAuthorization {
            device_code,
            verification_uri_complete: format!("{page}?user_code={shown}"),
            verification_uri: page,
            user_code: shown,
            expires_in: GRANT_TTL_SECS,
            interval: POLL_INTERVAL_SECS,
        })
        .into_response(),
    ))
}

// ── 2. The person approves ───────────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
pub(super) struct UserCodeQuery {
    /// The code the device shows, with or without its dash.
    user_code: String,
}

/// A pending grant, as the person approving it sees it.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct PendingDeviceGrant {
    client_id: String,
    /// The application's name.
    client_name: String,
    user_code: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// A pending device grant
///
/// The application a user code belongs to, so the person sees what they are
/// about to sign in before approving it. 404 for a code that is unknown,
/// decided or expired.
#[utoipa::path(
    get,
    path = "/api/v1/oauth/device",
    tag = "auth",
    params(UserCodeQuery),
    responses(
        (status = 200, description = "The pending grant", body = PendingDeviceGrant),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No pending grant has this code", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn pending_grant(
    State(state): State<AppState>,
    _ctx: Authorized<SelfService>,
    Query(query): Query<UserCodeQuery>,
) -> Result<Json<PendingDeviceGrant>, AppError> {
    let code = normalise_user_code(&query.user_code);
    let row: Option<(String, String, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT client_id, user_code, created_at, expires_at FROM oauth_device_grant \
         WHERE user_code = $1 AND status = 'pending' AND expires_at > now()",
    )
    .bind(&code)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;
    let (client_id, user_code, created_at, expires_at) = row.ok_or(AppError::NotFound)?;
    Ok(Json(PendingDeviceGrant {
        client_name: client_name(&client_id).unwrap_or("").to_owned(),
        client_id,
        user_code: display_user_code(&user_code),
        created_at,
        expires_at,
    }))
}

/// Approving or denying a grant.
#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct DeviceDecision {
    user_code: String,
    /// `true` signs the device in as the caller; `false` refuses it.
    approve: bool,
}

/// Approve or deny a device
///
/// RFC 8628 §3.3: the signed-in person approves the grant a user code names,
/// so the device that asked receives a session as them on its next poll, or
/// denies it. Needs a browser session: an API key or another device's
/// session is refused (403). Audited with the application's name.
#[utoipa::path(
    post,
    path = "/api/v1/oauth/device/approve",
    tag = "auth",
    request_body = DeviceDecision,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 204, description = "Decided"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not a browser session", body = ErrorResponse),
        (status = 404, description = "No pending grant has this code", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn approve(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Extension(claims): Extension<SessionClaims>,
    cookie: Option<Extension<CookieSession>>,
    session: Option<Extension<SessionId>>,
    _ctx: Authorized<SelfService>,
    Json(decision): Json<DeviceDecision>,
) -> Result<StatusCode, AppError> {
    let (Some(_), Some(Extension(session))) = (cookie, session) else {
        return Err(AppError::Forbidden);
    };
    let code = normalise_user_code(&decision.user_code);
    let status = if decision.approve {
        "approved"
    } else {
        "denied"
    };
    let mut tx = attome_db::tx::begin(&state.db).await?;
    let decided: Option<String> = sqlx::query_scalar(
        "UPDATE oauth_device_grant \
            SET status = $2, user_ref = $3, approver_family = $4, decided_at = now() \
          WHERE user_code = $1 AND status = 'pending' AND expires_at > now() \
          RETURNING client_id",
    )
    .bind(&code)
    .bind(status)
    .bind(claims.sub)
    .bind(session.0)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let client_id = decided.ok_or(AppError::NotFound)?;
    let name = client_name(&client_id).unwrap_or("an unknown application");
    write_security_event(
        &mut tx,
        &auditor.service(),
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            claims.sub,
            "user_account",
            Some(claims.sub),
        )
        .named(if decision.approve {
            format!("device sign-in approved: {name}")
        } else {
            format!("device sign-in denied: {name}")
        }),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── 3. The device polls ──────────────────────────────────────────────────────

/// A device token request (RFC 8628 §3.4, RFC 6749 §6), form-encoded.
#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct DeviceTokenForm {
    /// `urn:ietf:params:oauth:grant-type:device_code` or `refresh_token`.
    grant_type: String,
    client_id: String,
    /// With the device code grant.
    device_code: Option<String>,
    /// With the refresh token grant.
    refresh_token: Option<String>,
}

/// An issued session (RFC 6749 §5.1).
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct DeviceTokens {
    /// For `Authorization: Bearer`.
    access_token: String,
    /// Always `Bearer`.
    token_type: String,
    /// Seconds until the access token expires.
    expires_in: u64,
    /// Redeemed here with `grant_type=refresh_token` for the next pair; each
    /// one works once.
    refresh_token: String,
}

/// A grant as a poll reads it.
#[derive(sqlx::FromRow)]
struct GrantRow {
    id: Uuid,
    client_id: String,
    status: String,
    user_ref: Option<Uuid>,
    approver_family: Option<Uuid>,
    interval_secs: i32,
    last_polled_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

/// Exchange a device grant or refresh token
///
/// RFC 8628 §3.4: a device polls with its device code until the person has
/// decided: `authorization_pending` meanwhile, `slow_down` when it polls
/// faster than `interval`, `access_denied` or `expired_token` at the end. An
/// approved grant gives an ordinary session for the person, once. A refresh
/// token gives the next pair (RFC 6749 §6), in the same family. Audited as a
/// sign-in.
#[utoipa::path(
    post,
    path = "/api/v1/oauth/device/token",
    tag = "auth",
    request_body(content = DeviceTokenForm, content_type = "application/x-www-form-urlencoded"),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login)])))),
    responses(
        (status = 200, description = "A session", body = DeviceTokens),
        (status = 400, description = "Pending, too fast, denied, expired, or a bad request (the RFC 8628 error codes)", body = DeviceErrorBody),
        (status = 401, description = "The refresh token is not live", body = DeviceErrorBody),
        (status = 403, description = "A sign-in rule of the person's roles refuses it", body = ErrorResponse),
    ),
)]
pub(super) async fn token(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Form(form): Form<DeviceTokenForm>,
) -> Result<Response, AppError> {
    let Some(client) = client_name(&form.client_id) else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_client"));
    };
    match form.grant_type.as_str() {
        DEVICE_CODE_GRANT => {
            let Some(device_code) = form.device_code.as_deref() else {
                return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
            };
            redeem_device_code(&state, &auditor, &form.client_id, client, device_code).await
        }
        REFRESH_TOKEN_GRANT => {
            let Some(presented) = form.refresh_token.as_deref() else {
                return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_request"));
            };
            refresh_device_session(&state, presented).await
        }
        _ => Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
        )),
    }
}

async fn redeem_device_code(
    state: &AppState,
    auditor: &SecurityAuditor,
    client_id: &str,
    client: &str,
    device_code: &str,
) -> Result<Response, AppError> {
    let hash = hash_device_code(device_code);
    let row: Option<GrantRow> = sqlx::query_as(
        "SELECT id, client_id, status, user_ref, approver_family, interval_secs, \
                last_polled_at, expires_at \
           FROM oauth_device_grant WHERE device_code_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;
    let Some(grant) = row else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
    };
    if grant.client_id != client_id {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
    }
    let now = Utc::now();
    if grant.status == "consumed" {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
    }
    if grant.status == "denied" {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "access_denied"));
    }
    if grant.expires_at <= now {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "expired_token"));
    }
    if grant.status == "pending" {
        // A poll sooner than the interval is told to slow down, and its time
        // still counts, as RFC 8628 §3.5 asks.
        let too_soon = grant
            .last_polled_at
            .is_some_and(|last| (now - last).num_seconds() < i64::from(grant.interval_secs));
        sqlx::query(
            "UPDATE oauth_device_grant SET last_polled_at = now(), \
                    interval_secs = interval_secs + CASE WHEN $2 THEN 5 ELSE 0 END \
              WHERE id = $1",
        )
        .bind(grant.id)
        .bind(too_soon)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;
        let code = if too_soon {
            "slow_down"
        } else {
            "authorization_pending"
        };
        return Ok(oauth_error(StatusCode::BAD_REQUEST, code));
    }
    // Approved: used once, by whichever poll claims it first.
    let claimed: Option<Uuid> = sqlx::query_scalar(
        "UPDATE oauth_device_grant SET status = 'consumed' \
          WHERE id = $1 AND status = 'approved' RETURNING user_ref",
    )
    .bind(grant.id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let (Some(user_id), Some(family)) = (claimed, grant.approver_family) else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
    };
    if grant.user_ref != Some(user_id) {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
    }
    // The device is never fresher than the session that approved it; a
    // session that has since ended approves nothing.
    let approver = refresh::session_context(
        &state.db,
        user_id,
        SessionId(family),
        refresh_lifetimes(state).absolute_secs,
    )
    .await?;
    let Some(approver) = approver else {
        return Ok(oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"));
    };
    let context = AuthContext::device_grant(approver.auth_time);
    let method = format!("device:{client_id}");
    let issued =
        issue_session_tokens(state, user_id, &context, Some((auditor, method.as_str()))).await?;
    tracing::info!(%user_id, client = client, "auth: device signed in");
    Ok(tokens(state, issued.access_token, issued.bearer))
}

async fn refresh_device_session(state: &AppState, presented: &str) -> Result<Response, AppError> {
    let redeemed = match refresh::redeem_session(
        &state.db,
        &state.redis,
        presented,
        refresh_lifetimes(state),
        &state.pepper_ring(),
    )
    .await
    {
        Ok(redeemed) => redeemed,
        Err(AppError::Unauthorized) => {
            return Ok(oauth_error(StatusCode::UNAUTHORIZED, "invalid_grant"));
        }
        Err(error) => return Err(error),
    };
    let access_token = accounts::issue_access_token(
        &state.db,
        redeemed.user_id,
        redeemed.family_id,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        state.config.access_token_expiry_secs() as i64,
    )
    .await?;
    Ok(tokens(state, access_token, redeemed.bearer))
}

fn tokens(state: &AppState, access_token: String, refresh_token: String) -> Response {
    no_store(
        Json(DeviceTokens {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: state.config.access_token_expiry_secs(),
            refresh_token,
        })
        .into_response(),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(device_authorization, pending_grant, approve, token),
    components(schemas(
        DeviceAuthorizationForm,
        DeviceAuthorization,
        PendingDeviceGrant,
        DeviceDecision,
        DeviceTokenForm,
        DeviceTokens,
        DeviceErrorBody
    ))
)]
pub(super) struct DeviceApiDoc;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <DeviceApiDoc as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_are_eight_unambiguous_letters() {
        for _ in 0..50 {
            let code = new_user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(
                code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)),
                "{code}"
            );
        }
        assert_eq!(display_user_code("BCDFGHJK"), "BCDF-GHJK");
        assert_eq!(normalise_user_code(" bcdf-ghjk "), "BCDFGHJK");
    }

    #[test]
    fn device_codes_are_long_and_hashed() {
        let code = new_device_code();
        assert!(code.len() >= 43, "{code}");
        assert_ne!(new_device_code(), code);
        assert_eq!(hash_device_code(&code).len(), 64);
        assert_eq!(hash_device_code(&code), hash_device_code(&code));
    }

    #[test]
    fn only_known_clients_ask() {
        assert_eq!(client_name("attome-cli"), Some("Attome CLI"));
        assert_eq!(client_name("evil"), None);
    }
}
