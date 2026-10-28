//! `POST /api/v1/s2s/webportals/{keyword}/login` (D-779): the HTTP side of
//! [`crate::trusted`]. S2S-only: the caller must present a valid S2S
//! signature (so an `S2SClaims` extension is set) *and* hold
//! `webportal.trusted_login`; an admin's staff session passes the privilege
//! check but is still refused. The portal must have `trusted_server_login`
//! on. Mounted with the staff routes (`PortalModel::routes`), behind staff
//! authn/authz, never on the portal router.
//!
//! D-780 adds the account self-service routes under
//! `/api/v1/s2s/webportals/{keyword}/accounts/{user_id}` (same caller rules):
//! read the email and MFA state, add an email (proven by an emailed link,
//! confirmed on the portal's `auth/email/verify`), and turn MFA on or off,
//! each change behind the account's password; and the login's optional
//! `code` for accounts with MFA.
//!
//! Rate limits (Redis sliding windows, per portal, keyed by the client
//! address the caller reports, which is the address it saw on its own
//! connection, never one a player typed):
//! - failed logins: 20 per address and 10 per account per 10 minutes;
//! - account creations: 3 per address per hour and 10 per day.

use std::net::IpAddr;
use std::time::Duration;

use attome_audit::security::{MandatoryCategory, SecurityEvent, x_audit};
use attome_audit::{AuditCategory, AuditOperation, AuditOutcome};
use attome_cache::token_window;
use attome_core::EngineState;
use attome_s2s::S2SClaims;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::extract::{Json, Path, Query, State};
use axum::routing::{get, post};
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ENTITY, email_link, link, portal_for, write};
use crate::auth::{self, DisableMfa};
use crate::trusted::{self, SecondFactor, TrustedOutcome};
use crate::trusted_account::{self, EmailAdd, PasswordCheck, mask_email};

/// `webportal.trusted_login`: declared in the attome-portal platform bundle;
/// granted to the S2S client's service user.
#[derive(Debug)]
pub struct TrustedLogin;
impl PrivilegeKey for TrustedLogin {
    const KEY: &'static str = "webportal.trusted_login";
}

const FAIL_WINDOW: Duration = Duration::from_secs(10 * 60);
const FAILS_PER_ADDRESS: u64 = 20;
const FAILS_PER_ACCOUNT: u64 = 10;
const HOUR: Duration = Duration::from_secs(60 * 60);
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const CREATES_PER_HOUR: u64 = 3;
const CREATES_PER_DAY: u64 = 10;
/// D-780: email-add links per account per day (each one is an email sent).
const EMAIL_ADDS_PER_DAY: u64 = 5;

#[derive(Debug, Deserialize, ToSchema)]
pub struct TrustedLoginBody {
    /// A username, or an email (contains `@`).
    pub login: String,
    pub password: String,
    /// The player's address as the calling server saw it on its own
    /// connection. Used for rate limits and the audit trail.
    pub client_ip: String,
    /// Create the account when `login` is a free, valid username.
    #[serde(default)]
    pub create_if_missing: bool,
    /// D-780: for an account with MFA, the player's TOTP code or one of their
    /// recovery codes (without it such an account answers `mfa_required`).
    #[serde(default)]
    pub code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TrustedLoginResult {
    /// `ok`, `created`, `bad_credentials`, `name_rejected`,
    /// `password_rejected`, `disabled`, `rate_limited`, `mfa_required` or
    /// `mfa_failed` (D-780: the code was wrong, replayed or used up).
    pub outcome: &'static str,
    /// Set for `ok` and `created`.
    pub user_id: Option<Uuid>,
    /// The account's username (case as stored), for `ok` and `created`.
    pub username: Option<String>,
    /// The credential epoch: sessions the caller issued under an older
    /// epoch are revoked (password change, disable, log out everywhere).
    pub auth_epoch: Option<i32>,
    /// For `rate_limited`: seconds until trying again helps.
    pub retry_after_secs: Option<i64>,
    /// For `name_rejected` and `password_rejected`: why, for the player.
    pub reason: Option<String>,
    /// D-780: `ok` with a recovery code (one fewer left; the owner is told by
    /// email when the account has one).
    pub recovery_code_used: Option<bool>,
}

impl TrustedLoginResult {
    fn outcome(outcome: &'static str) -> Self {
        Self {
            outcome,
            user_id: None,
            username: None,
            auth_epoch: None,
            retry_after_secs: None,
            reason: None,
            recovery_code_used: None,
        }
    }

    fn rate_limited(secs: i64) -> Self {
        Self {
            retry_after_secs: Some(secs.max(1)),
            ..Self::outcome("rate_limited")
        }
    }
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/s2s/webportals/{keyword}/login",
            post(trusted_login),
        )
        .route(
            "/api/v1/s2s/webportals/{keyword}/accounts/changes",
            get(account_changes),
        )
        .route(
            "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}",
            get(account_info),
        )
        .route(
            "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/email",
            post(account_email),
        )
        .route(
            "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/enroll",
            post(account_mfa_enroll),
        )
        .route(
            "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/confirm",
            post(account_mfa_confirm),
        )
        .route(
            "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/disable",
            post(account_mfa_disable),
        )
}

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    #[derive(utoipa::OpenApi)]
    #[openapi(
        paths(
            trusted_login,
            account_changes,
            account_info,
            account_email,
            account_mfa_enroll,
            account_mfa_confirm,
            account_mfa_disable
        ),
        components(schemas(
            TrustedLoginBody,
            TrustedLoginResult,
            AccountChange,
            AccountChanges,
            TrustedAccountInfo,
            AccountEmailBody,
            AccountPasswordBody,
            AccountCodeBody,
            AccountPasswordCodeBody,
            AccountActionResult
        ))
    )]
    struct Doc;
    <Doc as utoipa::OpenApi>::openapi()
}

/// A short, stable hash of a value for a Redis key (no raw address or name
/// in the key space).
fn digest(value: &str) -> String {
    let d = Sha256::digest(value.as_bytes());
    d[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn retry_secs(window: Duration, state: &token_window::WindowState) -> i64 {
    window.saturating_sub(state.elapsed).as_secs().max(1) as i64
}

/// Check a portal login for a trusted server
///
/// For a portal's own trusted server, over S2S: checks a portal user's credentials and answers with
/// the decision; a refusal is an outcome, not an error.
#[utoipa::path(
    post,
    path = "/api/v1/s2s/webportals/{keyword}/login",
    operation_id = "portal_trusted_login",
    tag = "admin-security",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = TrustedLoginBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Login),
        (AuditCategory::Security, AuditOperation::FailedLogin),
        (AuditCategory::Security, AuditOperation::Create),
    ])))),
    responses(
        (status = 200, description = "The decision (see `outcome`); refusals are outcomes, not errors", body = TrustedLoginResult),
        (status = 401, description = "Not an S2S request", body = ErrorResponse),
        (status = 403, description = "The client lacks webportal.trusted_login, or the portal doesn't allow trusted login", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Malformed body (e.g. client_ip is not an address)", body = ErrorResponse),
    ),
)]
async fn trusted_login(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrustedLogin>>,
    s2s: Option<Extension<S2SClaims>>,
    Path(keyword): Path<String>,
    Json(body): Json<TrustedLoginBody>,
) -> Result<Json<TrustedLoginResult>, AppError> {
    // A staff admin passes the privilege check; only a signed S2S caller
    // may use this route.
    let Some(Extension(s2s)) = s2s else {
        return Err(AppError::Forbidden);
    };
    let client_ip: IpAddr = body
        .client_ip
        .trim()
        .parse()
        .map_err(|_| AppError::Validation("client_ip is not an IP address".into()))?;
    let portal = portal_for(&state, &keyword).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let policy = crate::policy::load(&mut tx, portal.id).await?;
    if !policy.trusted_server_login || !portal.portal_type.has_users() {
        return Err(AppError::Forbidden);
    }

    let redis = &state.base.redis_coordination;
    let ip_key = format!(
        "attome-portal:tl:fail-ip:{}:{}",
        portal.id,
        digest(&client_ip.to_string())
    );
    let acct_key = format!(
        "attome-portal:tl:fail-acct:{}:{}",
        portal.id,
        digest(&body.login.trim().to_lowercase())
    );
    for (key, limit) in [(&ip_key, FAILS_PER_ADDRESS), (&acct_key, FAILS_PER_ACCOUNT)] {
        let used = token_window::read(redis, key, FAIL_WINDOW).await?;
        if used.consumed >= limit {
            write_event(
                &state,
                &mut tx,
                &s2s,
                AuditOperation::FailedLogin,
                None,
                "rate limited",
                &client_ip,
            )
            .await?;
            tx.commit().await.map_err(AppError::internal)?;
            return Ok(Json(TrustedLoginResult::rate_limited(retry_secs(
                FAIL_WINDOW,
                &used,
            ))));
        }
    }
    let hour_key = format!(
        "attome-portal:tl:create-h:{}:{}",
        portal.id,
        digest(&client_ip.to_string())
    );
    let day_key = format!(
        "attome-portal:tl:create-d:{}:{}",
        portal.id,
        digest(&client_ip.to_string())
    );
    let creation_budget = if body.create_if_missing {
        let hour = token_window::read(redis, &hour_key, HOUR).await?;
        let day = token_window::read(redis, &day_key, DAY).await?;
        if hour.consumed >= CREATES_PER_HOUR {
            Err(retry_secs(HOUR, &hour))
        } else if day.consumed >= CREATES_PER_DAY {
            Err(retry_secs(DAY, &day))
        } else {
            Ok(())
        }
    } else {
        Ok(())
    };

    let pepper = state.base.pepper_ring();
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let outcome = trusted::trusted_login(
        &mut tx,
        portal.id,
        &policy,
        trusted::TrustedRequest {
            login: &body.login,
            password: &body.password,
            create_if_missing: body.create_if_missing,
            creation_budget,
            now: chrono::Utc::now(),
            second_factor: body
                .code
                .as_deref()
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(|code| SecondFactor {
                    code,
                    pepper: &pepper,
                    mfa_ring: &mfa_ring,
                }),
        },
    )
    .await?;

    let result = match outcome {
        TrustedOutcome::Ok {
            user_id,
            auth_epoch,
        }
        | TrustedOutcome::OkWithRecoveryCode {
            user_id,
            auth_epoch,
        }
        | TrustedOutcome::Created {
            user_id,
            auth_epoch,
        } => {
            let created = matches!(outcome, TrustedOutcome::Created { .. });
            let recovery = matches!(outcome, TrustedOutcome::OkWithRecoveryCode { .. });
            let username: Option<String> =
                sqlx::query_scalar("SELECT username FROM webportal_user WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            let (operation, name) = if created {
                (
                    AuditOperation::Create,
                    "portal account created by a trusted server",
                )
            } else {
                (AuditOperation::Login, "portal login by a trusted server")
            };
            write_event(
                &state,
                &mut tx,
                &s2s,
                operation,
                Some(user_id),
                if recovery {
                    "portal login by a trusted server with a recovery code"
                } else {
                    name
                },
                &client_ip,
            )
            .await?;
            if recovery {
                notify_account(
                    &state,
                    &mut tx,
                    &portal,
                    user_id,
                    "a recovery code was used",
                    "One of your recovery codes was just used to sign in to your account. If \
                     this wasn't you, change your password and turn two-step codes off and on \
                     again for new recovery codes.",
                )
                .await?;
            }
            TrustedLoginResult {
                user_id: Some(user_id),
                username,
                auth_epoch: Some(auth_epoch),
                recovery_code_used: recovery.then_some(true),
                ..TrustedLoginResult::outcome(if created { "created" } else { "ok" })
            }
        }
        TrustedOutcome::BadCredentials { user_id } => {
            write_event(
                &state,
                &mut tx,
                &s2s,
                AuditOperation::FailedLogin,
                user_id,
                "bad credentials",
                &client_ip,
            )
            .await?;
            TrustedLoginResult::outcome("bad_credentials")
        }
        TrustedOutcome::Disabled { user_id } => {
            write_event(
                &state,
                &mut tx,
                &s2s,
                AuditOperation::FailedLogin,
                Some(user_id),
                "account disabled",
                &client_ip,
            )
            .await?;
            TrustedLoginResult::outcome("disabled")
        }
        TrustedOutcome::RetryLater {
            user_id,
            retry_after_secs,
        } => {
            write_event(
                &state,
                &mut tx,
                &s2s,
                AuditOperation::FailedLogin,
                Some(user_id),
                "account delay",
                &client_ip,
            )
            .await?;
            TrustedLoginResult::rate_limited(retry_after_secs)
        }
        TrustedOutcome::MfaRequired { user_id } => {
            write_event(
                &state,
                &mut tx,
                &s2s,
                AuditOperation::FailedLogin,
                Some(user_id),
                "mfa required",
                &client_ip,
            )
            .await?;
            TrustedLoginResult::outcome("mfa_required")
        }
        TrustedOutcome::MfaFailed { user_id } => {
            write_event(
                &state,
                &mut tx,
                &s2s,
                AuditOperation::FailedLogin,
                Some(user_id),
                "wrong second factor",
                &client_ip,
            )
            .await?;
            TrustedLoginResult::outcome("mfa_failed")
        }
        TrustedOutcome::CreationLimited { retry_after_secs } => {
            TrustedLoginResult::rate_limited(retry_after_secs)
        }
        TrustedOutcome::NameRejected(why) => TrustedLoginResult {
            reason: Some(why.message()),
            ..TrustedLoginResult::outcome("name_rejected")
        },
        TrustedOutcome::PasswordRejected(why) => TrustedLoginResult {
            reason: Some(why),
            ..TrustedLoginResult::outcome("password_rejected")
        },
    };
    tx.commit().await.map_err(AppError::internal)?;

    // Count after the commit: a request that failed to commit counts nothing.
    // (`mfa_required` is not a failure: the password was right, D-780.)
    match result.outcome {
        "bad_credentials" | "disabled" | "mfa_failed" => {
            token_window::add(redis, &ip_key, 1, FAIL_WINDOW).await?;
            token_window::add(redis, &acct_key, 1, FAIL_WINDOW).await?;
        }
        "created" => {
            token_window::add(redis, &hour_key, 1, HOUR).await?;
            token_window::add(redis, &day_key, 1, DAY).await?;
        }
        _ => {}
    }
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
pub struct ChangesQuery {
    /// Unix seconds; 0 = every account of the portal.
    #[serde(default)]
    pub since: i64,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountChange {
    pub user_id: Uuid,
    pub username: Option<String>,
    /// `active`, `invited`, `disabled` or `erased`.
    pub status: String,
    /// Sessions issued under an older epoch are revoked.
    pub auth_epoch: i32,
    /// Unix seconds of the change.
    pub changed_at: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AccountChanges {
    /// Oldest first.
    pub accounts: Vec<AccountChange>,
    /// Pass as `since` next time (the newest `changed_at`, or `since`).
    pub next_since: i64,
}

type ChangeRow = (Uuid, Option<String>, String, i32, i64);

/// List portal account changes
///
/// What changed about the portal's accounts since a time (a password change, reset, disable or sign-out
/// everywhere moves the credential epoch; erasure removes the account), so a trusted server can end
/// its own sessions within one pull.
#[utoipa::path(
    get,
    path = "/api/v1/s2s/webportals/{keyword}/accounts/changes",
    operation_id = "portal_trusted_account_changes",
    tag = "admin-security",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("since" = Option<i64>, Query, description = "Unix seconds; 0 = every account"),
        ("limit" = Option<i64>, Query, description = "At most this many (1-5000, default 1000)"),
    ),
    responses(
        (status = 200, description = "Accounts changed since `since`, oldest first", body = AccountChanges),
        (status = 403, description = "Not a privileged S2S client, or trusted login is off", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn account_changes(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrustedLogin>>,
    s2s: Option<Extension<S2SClaims>>,
    Path(keyword): Path<String>,
    Query(q): Query<ChangesQuery>,
) -> Result<Json<AccountChanges>, AppError> {
    if s2s.is_none() {
        return Err(AppError::Forbidden);
    }
    let portal = portal_for(&state, &keyword).await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let policy = crate::policy::load(&mut conn, portal.id).await?;
    if !policy.trusted_server_login {
        return Err(AppError::Forbidden);
    }
    let limit = q.limit.unwrap_or(1000).clamp(1, 5000);
    let rows: Vec<ChangeRow> = sqlx::query_as(
        "SELECT u.id, u.username, \
                CASE WHEN u.is_active IS FALSE OR c.webportal_user_id IS NULL THEN 'erased' \
                     ELSE u.status END, \
                COALESCE(c.auth_epoch, 0), \
                floor(EXTRACT(EPOCH FROM GREATEST(COALESCE(c.updated_at, 'epoch'::timestamptz), \
                                                  COALESCE(u.modified_at, 'epoch'::timestamptz))))::bigint \
                  AS changed \
         FROM webportal_user u \
         LEFT JOIN webportal_credential c ON c.webportal_user_id = u.id \
         WHERE u.webportal_ref = $1 \
           AND floor(EXTRACT(EPOCH FROM GREATEST(COALESCE(c.updated_at, 'epoch'::timestamptz), \
                                                 COALESCE(u.modified_at, 'epoch'::timestamptz)))) > $2 \
         ORDER BY changed, u.id \
         LIMIT $3",
    )
    .bind(portal.id)
    // Whole seconds on both sides: `changed_at` is floored, so a change is
    // never reported again after its own `next_since`.
    .bind(q.since.max(0) as f64)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let next_since = rows.last().map(|r| r.4).unwrap_or(q.since.max(0));
    Ok(Json(AccountChanges {
        accounts: rows
            .into_iter()
            .map(|r| AccountChange {
                user_id: r.0,
                username: r.1,
                status: r.2,
                auth_epoch: r.3,
                changed_at: r.4,
            })
            .collect(),
        next_since,
    }))
}

// ── D-780: account self-service ─────────────────────────────────────────────

#[derive(Debug, Serialize, ToSchema)]
pub struct TrustedAccountInfo {
    pub username: Option<String>,
    /// Masked (`z***@example.com`): the owner recognises it; the caller
    /// never needs the address itself.
    pub email: Option<String>,
    /// Masked: the address a link sent but not yet opened would add.
    pub pending_email: Option<String>,
    pub mfa_enabled: bool,
    pub recovery_codes_left: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AccountEmailBody {
    pub password: String,
    pub email: String,
    pub client_ip: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AccountPasswordBody {
    pub password: String,
    pub client_ip: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AccountCodeBody {
    pub code: String,
    pub client_ip: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AccountPasswordCodeBody {
    pub password: String,
    pub code: String,
    pub client_ip: String,
}

#[derive(Debug, Serialize, ToSchema, Default)]
pub struct AccountActionResult {
    /// `sent` (email: a link went to the address, or, when another account
    /// has it, a notice did: the answer is the same), `unchanged`,
    /// `invalid_email`, `ok` (MFA), `already_enabled`, `wrong_code`,
    /// `required` (the portal requires MFA: it can't be turned off),
    /// `bad_credentials` (the password), `rate_limited` or `unavailable`
    /// (the account is disabled or gone, or email isn't set up).
    pub outcome: &'static str,
    pub retry_after_secs: Option<i64>,
    /// For `invalid_email` and `unavailable`: why.
    pub reason: Option<String>,
    /// MFA enroll: the new secret (base32) and its `otpauth://` URI, for
    /// the player's authenticator app. Not in force until confirmed.
    pub secret: Option<String>,
    pub otpauth_uri: Option<String>,
    /// MFA confirm: the recovery codes, shown once.
    pub recovery_codes: Option<Vec<String>>,
}

impl AccountActionResult {
    fn outcome(outcome: &'static str) -> Self {
        Self {
            outcome,
            ..Self::default()
        }
    }
}

/// The caller rules every account route shares: a signed S2S caller, a
/// portal with trusted login on, a parseable client address.
async fn account_caller(
    state: &EngineState,
    s2s: Option<Extension<S2SClaims>>,
    keyword: &str,
    client_ip: Option<&str>,
) -> Result<(S2SClaims, crate::provision::PortalDetail, IpAddr), AppError> {
    let Some(Extension(s2s)) = s2s else {
        return Err(AppError::Forbidden);
    };
    let client_ip: IpAddr = match client_ip {
        Some(ip) => ip
            .trim()
            .parse()
            .map_err(|_| AppError::Validation("client_ip is not an IP address".into()))?,
        None => IpAddr::from([0, 0, 0, 0]),
    };
    let portal = portal_for(state, keyword).await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let policy = crate::policy::load(&mut conn, portal.id).await?;
    if !policy.trusted_server_login || !portal.portal_type.has_users() {
        return Err(AppError::Forbidden);
    }
    Ok((s2s, portal, client_ip))
}

/// The refusal for a password check that didn't pass (`None` = it passed).
fn password_refusal(check: &PasswordCheck) -> Option<AccountActionResult> {
    match check {
        PasswordCheck::Ok => None,
        PasswordCheck::Wrong => Some(AccountActionResult::outcome("bad_credentials")),
        PasswordCheck::RetryLater(secs) => Some(AccountActionResult {
            retry_after_secs: Some((*secs).max(1)),
            ..AccountActionResult::outcome("rate_limited")
        }),
        PasswordCheck::Unavailable => Some(AccountActionResult::outcome("unavailable")),
    }
}

/// What the password is being asked again for (the audit trail).
struct Recheck<'a> {
    s2s: &'a S2SClaims,
    portal_id: Uuid,
    user_id: Uuid,
    client_ip: &'a IpAddr,
    what: &'a str,
}

/// Checks the password; a wrong one writes the failure event.
async fn recheck_password(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    r: Recheck<'_>,
    password: &str,
) -> Result<Option<AccountActionResult>, AppError> {
    let check =
        trusted_account::check_password(tx, r.portal_id, r.user_id, password, chrono::Utc::now())
            .await?;
    if check == PasswordCheck::Wrong {
        write_event(
            state,
            tx,
            r.s2s,
            AuditOperation::FailedLogin,
            Some(r.user_id),
            &format!("wrong password ({})", r.what),
            r.client_ip,
        )
        .await?;
    }
    Ok(password_refusal(&check))
}

/// A short notice to the account's own email, when it has one and email is
/// set up.
async fn notify_account(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    portal: &crate::provision::PortalDetail,
    user_id: Uuid,
    headline: &str,
    body: &str,
) -> Result<(), AppError> {
    if !state.base.config.email.enabled {
        return Ok(());
    }
    let email: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM webportal_user WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    if let Some(to) = email.flatten().filter(|e| !e.is_empty()) {
        email_link(
            tx,
            attome_email::delivery::EmailDeliveryKind::Generic,
            &to,
            crate::email::notice(&portal.name, headline, body),
        )
        .await?;
    }
    Ok(())
}

/// Read a portal account for a trusted server
///
/// The account's email (masked) and MFA state, for the user's own account screen.
#[utoipa::path(
    get,
    path = "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}",
    operation_id = "portal_trusted_account_info",
    tag = "admin-security",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("user_id" = Uuid, Path, description = "The portal user"),
    ),
    responses(
        (status = 200, description = "The account", body = TrustedAccountInfo),
        (status = 403, description = "Not a privileged S2S client, or trusted login is off", body = ErrorResponse),
        (status = 404, description = "No such portal or account", body = ErrorResponse),
    ),
)]
async fn account_info(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrustedLogin>>,
    s2s: Option<Extension<S2SClaims>>,
    Path((keyword, user_id)): Path<(String, Uuid)>,
) -> Result<Json<TrustedAccountInfo>, AppError> {
    let (_, portal, _) = account_caller(&state, s2s, &keyword, None).await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let info = trusted_account::account_info(&mut conn, portal.id, user_id)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(Json(TrustedAccountInfo {
        username: info.username,
        email: info.email.as_deref().map(mask_email),
        pending_email: info.pending_email.as_deref().map(mask_email),
        mfa_enabled: info.mfa_enabled,
        recovery_codes_left: info.recovery_codes_left,
    }))
}

/// Add an email to a portal account
///
/// After the password again, sends a link to the new address; it is added only when its owner opens
/// it. When another account of the portal has the address, its owner is told instead, with the same
/// answer.
#[utoipa::path(
    post,
    path = "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/email",
    operation_id = "portal_trusted_account_email",
    tag = "admin-security",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("user_id" = Uuid, Path, description = "The portal user"),
    ),
    request_body = AccountEmailBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Update),
        (AuditCategory::Security, AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "The decision (see `outcome`)", body = AccountActionResult),
        (status = 403, description = "Not a privileged S2S client, or trusted login is off", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Malformed body", body = ErrorResponse),
    ),
)]
async fn account_email(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrustedLogin>>,
    s2s: Option<Extension<S2SClaims>>,
    Path((keyword, user_id)): Path<(String, Uuid)>,
    Json(body): Json<AccountEmailBody>,
) -> Result<Json<AccountActionResult>, AppError> {
    let (s2s, portal, client_ip) =
        account_caller(&state, s2s, &keyword, Some(&body.client_ip)).await?;
    if !state.base.config.email.enabled {
        return Ok(Json(AccountActionResult {
            reason: Some("email is not set up on this server".into()),
            ..AccountActionResult::outcome("unavailable")
        }));
    }
    let redis = &state.base.redis_coordination;
    let key = format!("attome-portal:tl:email:{}:{user_id}", portal.id);
    let used = token_window::read(redis, &key, DAY).await?;
    if used.consumed >= EMAIL_ADDS_PER_DAY {
        return Ok(Json(AccountActionResult {
            retry_after_secs: Some(retry_secs(DAY, &used)),
            ..AccountActionResult::outcome("rate_limited")
        }));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let recheck = Recheck {
        s2s: &s2s,
        portal_id: portal.id,
        user_id,
        client_ip: &client_ip,
        what: "add email",
    };
    if let Some(refusal) = recheck_password(&state, &mut tx, recheck, &body.password).await? {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(Json(refusal));
    }
    let pepper = state.base.pepper_ring();
    let result =
        match trusted_account::request_email_add(&mut tx, &pepper, portal.id, user_id, &body.email)
            .await?
        {
            EmailAdd::Send { to, token } => {
                let url = link(&state, &portal, "verify-email", &token.bearer);
                email_link(
                    &mut tx,
                    attome_email::delivery::EmailDeliveryKind::EmailVerification,
                    &to,
                    crate::email::email_add_verification(&portal.name, &url),
                )
                .await?;
                write_event(
                    &state,
                    &mut tx,
                    &s2s,
                    AuditOperation::Update,
                    Some(user_id),
                    "email add link sent",
                    &client_ip,
                )
                .await?;
                AccountActionResult::outcome("sent")
            }
            EmailAdd::InUse { to } => {
                email_link(
                    &mut tx,
                    attome_email::delivery::EmailDeliveryKind::Generic,
                    &to,
                    crate::email::notice(
                        &portal.name,
                        "someone tried to add this email",
                        "Someone asked to add this email address to another account. It is \
                         already yours, so nothing changed. If you have forgotten your \
                         password, you can reset it with this address.",
                    ),
                )
                .await?;
                AccountActionResult::outcome("sent")
            }
            EmailAdd::Unchanged => AccountActionResult::outcome("unchanged"),
            EmailAdd::Invalid(why) => AccountActionResult {
                reason: Some(why),
                ..AccountActionResult::outcome("invalid_email")
            },
        };
    tx.commit().await.map_err(AppError::internal)?;
    if result.outcome == "sent" {
        token_window::add(redis, &key, 1, DAY).await?;
    }
    Ok(Json(result))
}

/// Start MFA for a portal account
///
/// After the password again, a new secret for the user's authenticator app, in force once a code from
/// it confirms it.
#[utoipa::path(
    post,
    path = "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/enroll",
    operation_id = "portal_trusted_account_mfa_enroll",
    tag = "admin-security",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("user_id" = Uuid, Path, description = "The portal user"),
    ),
    request_body = AccountPasswordBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Update),
        (AuditCategory::Security, AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "The decision (see `outcome`); `ok` carries the secret", body = AccountActionResult),
        (status = 403, description = "Not a privileged S2S client, or trusted login is off", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn account_mfa_enroll(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrustedLogin>>,
    s2s: Option<Extension<S2SClaims>>,
    Path((keyword, user_id)): Path<(String, Uuid)>,
    Json(body): Json<AccountPasswordBody>,
) -> Result<Json<AccountActionResult>, AppError> {
    let (s2s, portal, client_ip) =
        account_caller(&state, s2s, &keyword, Some(&body.client_ip)).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let recheck = Recheck {
        s2s: &s2s,
        portal_id: portal.id,
        user_id,
        client_ip: &client_ip,
        what: "mfa enroll",
    };
    if let Some(refusal) = recheck_password(&state, &mut tx, recheck, &body.password).await? {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(Json(refusal));
    }
    let Some(principal) = trusted_account::principal(&mut tx, portal.id, user_id).await? else {
        return Ok(Json(AccountActionResult::outcome("unavailable")));
    };
    if principal.mfa_enabled {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(Json(AccountActionResult::outcome("already_enabled")));
    }
    let label: String = sqlx::query_scalar(
        "SELECT COALESCE(NULLIF(email, ''), username, name) FROM webportal_user WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let enrollment = auth::enroll_mfa(&mut tx, &mfa_ring, &principal, &label, &portal.name).await?;
    write_event(
        &state,
        &mut tx,
        &s2s,
        AuditOperation::Update,
        Some(user_id),
        "mfa enrollment started",
        &client_ip,
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(AccountActionResult {
        secret: Some(enrollment.secret),
        otpauth_uri: Some(enrollment.otpauth_uri),
        ..AccountActionResult::outcome("ok")
    }))
}

/// Confirm MFA for a portal account
///
/// A code from the authenticator app turns MFA on; the recovery codes come back once.
#[utoipa::path(
    post,
    path = "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/confirm",
    operation_id = "portal_trusted_account_mfa_confirm",
    tag = "admin-security",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("user_id" = Uuid, Path, description = "The portal user"),
    ),
    request_body = AccountCodeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "`ok` with the recovery codes, or `wrong_code`", body = AccountActionResult),
        (status = 403, description = "Not a privileged S2S client, or trusted login is off", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn account_mfa_confirm(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrustedLogin>>,
    s2s: Option<Extension<S2SClaims>>,
    Path((keyword, user_id)): Path<(String, Uuid)>,
    Json(body): Json<AccountCodeBody>,
) -> Result<Json<AccountActionResult>, AppError> {
    let (s2s, portal, client_ip) =
        account_caller(&state, s2s, &keyword, Some(&body.client_ip)).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some(principal) = trusted_account::principal(&mut tx, portal.id, user_id).await? else {
        return Ok(Json(AccountActionResult::outcome("unavailable")));
    };
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let codes = auth::confirm_mfa(
        &mut tx,
        &mfa_ring,
        &state.base.pepper_ring(),
        &principal,
        body.code.trim(),
    )
    .await?;
    let Some(codes) = codes else {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(Json(AccountActionResult::outcome("wrong_code")));
    };
    write_event(
        &state,
        &mut tx,
        &s2s,
        AuditOperation::Update,
        Some(user_id),
        "mfa enabled",
        &client_ip,
    )
    .await?;
    notify_account(
        &state,
        &mut tx,
        &portal,
        user_id,
        "two-step sign-in is on",
        "Two-step sign-in was turned on for your account: signing in now also needs a code \
         from your authenticator app. If this wasn't you, contact support right away.",
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(AccountActionResult {
        recovery_codes: Some(codes),
        ..AccountActionResult::outcome("ok")
    }))
}

/// Turn MFA off for a portal account
///
/// After the password and a current code; refused while the portal requires MFA.
#[utoipa::path(
    post,
    path = "/api/v1/s2s/webportals/{keyword}/accounts/{user_id}/mfa/disable",
    operation_id = "portal_trusted_account_mfa_disable",
    tag = "admin-security",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("user_id" = Uuid, Path, description = "The portal user"),
    ),
    request_body = AccountPasswordCodeBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Update),
        (AuditCategory::Security, AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "The decision (see `outcome`)", body = AccountActionResult),
        (status = 403, description = "Not a privileged S2S client, or trusted login is off", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn account_mfa_disable(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<TrustedLogin>>,
    s2s: Option<Extension<S2SClaims>>,
    Path((keyword, user_id)): Path<(String, Uuid)>,
    Json(body): Json<AccountPasswordCodeBody>,
) -> Result<Json<AccountActionResult>, AppError> {
    let (s2s, portal, client_ip) =
        account_caller(&state, s2s, &keyword, Some(&body.client_ip)).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let recheck = Recheck {
        s2s: &s2s,
        portal_id: portal.id,
        user_id,
        client_ip: &client_ip,
        what: "mfa disable",
    };
    if let Some(refusal) = recheck_password(&state, &mut tx, recheck, &body.password).await? {
        tx.commit().await.map_err(AppError::internal)?;
        return Ok(Json(refusal));
    }
    let Some(principal) = trusted_account::principal(&mut tx, portal.id, user_id).await? else {
        return Ok(Json(AccountActionResult::outcome("unavailable")));
    };
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let outcome =
        auth::disable_mfa(&mut tx, &mfa_ring, &portal, &principal, body.code.trim()).await?;
    let result = match outcome {
        DisableMfa::Disabled => {
            write_event(
                &state,
                &mut tx,
                &s2s,
                AuditOperation::Update,
                Some(user_id),
                "mfa disabled",
                &client_ip,
            )
            .await?;
            notify_account(
                &state,
                &mut tx,
                &portal,
                user_id,
                "two-step sign-in is off",
                "Two-step sign-in was turned off for your account. If this wasn't you, change \
                 your password and contact support right away.",
            )
            .await?;
            AccountActionResult::outcome("ok")
        }
        DisableMfa::WrongCode => AccountActionResult::outcome("wrong_code"),
        DisableMfa::Required => AccountActionResult::outcome("required"),
    };
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(result))
}

/// A security event whose actor is the S2S client's service user (acting for
/// the player) and whose record is the portal user when known, with the
/// client and the player's address in the comment.
async fn write_event(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    s2s: &S2SClaims,
    operation: AuditOperation,
    user: Option<Uuid>,
    name: &str,
    client_ip: &IpAddr,
) -> Result<(), AppError> {
    let event = SecurityEvent::new(
        MandatoryCategory::Security,
        operation,
        s2s.service_user_id,
        ENTITY,
        user,
    )
    .named(format!("trusted server login: {name}"))
    .comment(format!("client {} ({client_ip})", s2s.client_id))
    .outcome(if matches!(operation, AuditOperation::FailedLogin) {
        AuditOutcome::Failed
    } else {
        AuditOutcome::Succeeded
    });
    write(state, tx, event).await
}
