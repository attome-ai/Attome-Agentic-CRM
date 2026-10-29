//! Local password auth — register/login, MFA, and the password-reset /
//! email-verification lifecycle. See `super::session::issue_session_cookies_for`
//! for the shared session-issuance helper these handlers call once a
//! password (or MFA) check succeeds.

use attome_audit::security::{
    AuditHook, HookEvent, MandatoryCategory, SecurityAuditor, SecurityEvent, account_event_hook,
    write_security_event, x_audit,
};
use attome_audit::{AuditCategory, AuditOperation, AuditOutcome};
use attome_auth::{accounts, mfa, reset, verification};
use attome_core::jobs::EngineJob;
use attome_email::EmailMessage;
use attome_server::AppState;
use attome_server::middleware::rate_limit::{
    MFA_ATTEMPTS_PER_ACCOUNT_RPM, enforce_account_budget, mfa_account_key,
};
use attome_types::AppError;
use axum::{
    Json,
    extract::{ConnectInfo, Extension, State},
    http::{HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse, Response},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use uuid::Uuid;

use super::failed_login;
use super::login_guard;

use super::dto::{
    Ack, AuthResponse, LoginRequest, MfaChallengeResponse, MfaCodeSendBody, MfaEnrollResponse,
    MfaPendingConfirmResponse, MfaPendingEnrollBody, MfaVerifyBody, RegisterRequest,
    ResetConfirmBody, ResetRequestBody, VerifyEmailConfirmBody,
};
use super::session::{issue_session_cookies_for, issue_session_for};
use attome_auth::auth_context::AuthContext;
use attome_types::ErrorResponse;

/// Never varied per-deployment, not config knobs.
const EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS: u64 = 48;
const PASSWORD_RESET_TOKEN_EXPIRY_MINS: u64 = 30;

// ── Per-account throttle (T1-10, closes B11) ─────────────────────────────────
//
// `attome_server::middleware::rate_limit` keys the `credential`/`mfa` category
// budgets on the caller's IP (there is no `SessionClaims` yet on these
// routes), so ten failures for ONE email from ten IPs never trip it. The
// two throttles below add the missing axis: a sliding-window budget per
// *account*, so the same ten failures lock that email — not the IPs — for
// the rest of the window. Both sit in the handler, not the middleware,
// because the account key only exists once the body has been parsed.
//
// **Attempts are counted, not failures — deliberately.** The one primitive
// this repo has (`attome_cache::rate_limit::check`, D-145) admits and records
// in a single atomic Lua round-trip; a failures-only design would need a
// separate non-atomic peek before the engine call plus a record after it
// (two round-trips, a race that admits a burst past the limit, and a second
// primitive in `attome-cache`). Counting attempts also means the check runs
// *before* any database or argon2 work, so a throttled unknown email and a
// throttled known one are indistinguishable by construction — identical
// status, body, headers and timing — rather than by care. The cost to a
// legitimate user is nil: ten logins per rolling minute for one account is
// well above any human rate, and a burst of *successful* logins that trips
// it is itself a signal worth a 60-second pause.
//
// Mirrors the middleware's posture exactly: same 60-second window and 61s
// key TTL (owned by `check`), same fail-closed semantics (a Redis error or
// 300ms timeout surfaces as `AppError::internal` — never a silent admit,
// D-027 §security-controls-fail-closed), same coordination pool, same
// `AppError::TooManyRequests { retry_after_secs: None }` body plus `Retry-After`/`X-RateLimit-Reset`
// computed from the same atomic read as the decision. `X-RateLimit-Limit`/
// `-Remaining` are left to the category middleware, which stamps its own
// (per-IP) numbers on every response on the way out.
//
// Redis keys (crate-prefixed per caching-and-state; add to that skill's
// key table):
//   `server:rl:account:{sha256(normalized email)}:login`
//   `server:rl:account:{user_id}:mfa`
//   `server:rl:account:{sha256(normalized email)}:reset` (attome-auth hardening 2.5)
// The email is hashed (never stored raw in Redis, never logged) so a
// coordination-Redis dump or a SIEM export is not a list of who tried to
// sign in. Normalization is `attome_types::text::normalize_email` — the same
// trim + lowercase `accounts::login` applies before its own lookup — so
// `" Alice@Example.com "` and `"alice@example.com"` share one bucket.
//
// Constants, not config: the per-IP category limits are already tunable per
// deployment (`rate_limit.categories`); a per-account budget that a
// deployment could raise is one a misconfiguration could silently disable.
// The MFA budget, its key and the check itself live in
// `attome_server::middleware::rate_limit` (attome-auth hardening 1.5), because
// attome-security's self-service disable and recovery-code routes spend the
// same per-account bucket as the two login-time routes below.
const LOGIN_ATTEMPTS_PER_ACCOUNT_RPM: i32 = 10;

/// Reset requests per account per rolling minute (attome-auth hardening 2.5).
/// Every admitted request can send an email, so this sits well below the login
/// budget: enough for a user who asks again, too few to mail-bomb an address
/// from many IPs.
const RESET_REQUESTS_PER_ACCOUNT_RPM: i32 = 3;

/// The per-account bucket for an email-addressed route. It uses the SHA-256
/// of the normalized email, so Redis never holds the address itself.
fn email_throttle_key(email: &str, purpose: &str) -> String {
    let normalized = attome_types::text::normalize_email(email);
    let digest = Sha256::digest(normalized.as_bytes());
    attome_cache::rate_limit::account_key(&hex::encode(digest), purpose)
}

fn login_throttle_key(email: &str) -> String {
    email_throttle_key(email, "login")
}

fn reset_throttle_key(email: &str) -> String {
    email_throttle_key(email, "reset")
}

/// The `sub` of a pending-MFA token, read from the payload segment WITHOUT
/// verifying the signature — and that is fine for what it is used for. This
/// value only selects a throttle bucket; it never authenticates anything
/// (`mfa::complete_pending_login` re-decodes and verifies the token itself
/// before a single TOTP comparison). A forged `sub` cannot evade the
/// throttle: every genuine guess must carry the genuine token, whose signed
/// `sub` is fixed, so it lands in the real account's bucket. A forged `sub`
/// can, at most, spend the named account's budget — the same exposure the
/// email-keyed login bucket accepts by design, and here it additionally
/// requires knowing the victim's user id. `None` for anything that is not a
/// three-segment JWT with a `sub` claim; such a token cannot be a real guess
/// (the engine rejects it before any second-factor work), so it is left to
/// the per-IP limiter rather than bucketed.
///
/// The verified alternative (`PendingClaims`/`decode_claims` are
/// `pub(crate)` in `attome-auth`) needs a public accessor there; until one
/// exists this is the honest shape.
fn pending_token_subject(token: &str) -> Option<Uuid> {
    #[derive(Deserialize)]
    struct PendingSubject {
        sub: Uuid,
    }
    let mut segments = token.split('.');
    let (_header, payload, _signature) = (segments.next()?, segments.next()?, segments.next()?);
    if segments.next().is_some() {
        return None;
    }
    let bytes = base64url_decode(payload)?;
    serde_json::from_slice::<PendingSubject>(&bytes)
        .ok()
        .map(|claims| claims.sub)
}

/// Minimal base64url (RFC 4648 §5, padding optional) decoder — JWT segments
/// are `URL_SAFE_NO_PAD`. Local because `crates/server` does not depend on
/// the `base64` crate and pulling it in for one twelve-line loop is not
/// worth a Cargo.toml change. Rejects any byte outside the alphabet.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// Register a local account
///
/// P-registration-gating (D-128): `auth.registration_mode` gates this before
/// any DB work — `"disabled"` (the default) rejects outright, `"invite"`
/// requires a valid `invitation_token` matching `body.email`
/// (`accounts::register` validates and consumes it), `"public"` is today's
/// unconditional behavior. The route itself stays mounted and bypass-listed
/// (guidelines §3: the bypass list is a compile-time constant, not a runtime
/// toggle) — gating lives entirely in this handler.
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 409, description = "Email already registered", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn register(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<RegisterRequest>,
) -> Result<Response, AppError> {
    let invitation_token = match state.config.auth.registration_mode.as_str() {
        "disabled" => return Err(AppError::Forbidden),
        "invite" => Some(
            body.invitation_token
                .as_deref()
                .filter(|t| !t.is_empty())
                .ok_or(AppError::Forbidden)?,
        ),
        // "public" — validate() only ever admits these three values.
        _ => None,
    };
    // D-786: service-principal addresses can never hold a credential.
    if attome_security::accounts::is_reserved_service_email(&body.email) {
        return Err(AppError::Forbidden);
    }

    // BAU-27: policy and KDF run before the transaction, so no connection or
    // advisory lock is held across the KDF wait.
    let password = accounts::RegistrationPassword::prepare(&body.password).await?;

    // Account creation, its verification token, and the durable email job
    // commit together.  Logging an enqueue failure after committing the token
    // leaves a user unable to verify their account and is not an acceptable
    // best-effort boundary.
    let mut tx = attome_db::tx::begin(&state.db).await?;

    // The per-email advisory lock is taken inside this transaction so two
    // registrations of the same email serialize. `register_in_tx` below
    // re-takes this same per-email lock on its own normalized value; advisory
    // transaction locks are re-entrant within one transaction, so that is the
    // same lock taken once, not a second one. (The deployment-wide seat lock
    // that used to follow is gone with seat enforcement, D-778.)
    let normalized_email = attome_auth::email_identity::normalize_email(&body.email);
    if !attome_auth::email_identity::try_lock_email(&mut tx, &normalized_email).await? {
        return Err(AppError::Conflict("email already registered"));
    }

    let user_id = accounts::register_in_tx(
        &mut tx,
        &body.email,
        password,
        invitation_token,
        &state.pepper_ring(),
    )
    .await?;

    if state.config.email.enabled {
        let issued = verification::request_in_tx(
            &mut tx,
            user_id,
            EMAIL_VERIFICATION_TOKEN_EXPIRY_HOURS,
            &state.pepper_ring(),
        )
        .await?;
        let link = format!(
            "{}/verify-email?token={}",
            state.config.frontend_url(),
            issued.bearer
        );
        let brand =
            attome_core::theme_store::email_brand(&state.db, &state.config.frontend_url()).await;
        let (subject, text_body, html_body) =
            attome_email::templates::email_verification(&link, &brand);
        let delivery_id = Uuid::now_v7();
        attome_email::delivery::record_queued_in_tx(
            &mut tx,
            delivery_id,
            attome_email::delivery::EmailDeliveryKind::EmailVerification,
            &issued.email,
            &subject,
            Some(user_id),
            None,
            None,
        )
        .await
        .map_err(AppError::internal)?;
        attome_jobs::enqueue_in_tx(
            &mut tx,
            EngineJob::SendEmail(Box::new(EmailMessage {
                to: issued.email,
                subject,
                text_body,
                html_body: Some(html_body),
                delivery_id: Some(delivery_id),
                from_override: None,
                message_id: None,
                in_reply_to: None,
                references: None,
                communication_id: None,
                attachments: Vec::new(),
                stream: Default::default(),
                list_unsubscribe: None,
            })),
        )
        .await
        .map_err(AppError::internal)?;
    }
    // Audit plan 3.4 (D-541 rule 1): a self-registered account is an identity
    // event, written in the registration's own transaction (D-062). The new
    // account is its own actor. The email stays out of the event.
    write_security_event(
        &mut tx,
        &auditor.service(),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Create,
            user_id,
            "user_account",
            Some(user_id),
        )
        .named(if invitation_token.is_some() {
            "account_registered invite"
        } else {
            "account_registered public"
        }),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    let cookies =
        issue_session_cookies_for(&state, user_id, &AuthContext::password(), None).await?;

    Ok((
        StatusCode::CREATED,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

/// Q20-T2: a login-guard trigger (a delay starting for an account, a spray
/// challenge for an address) as a security event. The caller is
/// unauthenticated, so the actor is nil; the name carries the hashed
/// address, never the raw one.
fn login_guard_event(name: String) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Security,
        AuditOperation::FailedLogin,
        Uuid::nil(),
        "user_account",
        None,
    )
    .named(name)
}

/// Sign in with email and password
///
/// P2.8 step 7 (D-069): a correct password no longer always mints a session —
/// see `accounts::LoginOutcome`. The `MfaRequired`/`MfaEnrollmentRequired`
/// branches respond 200 with a `pending_token` instead of `Set-Cookie`; the
/// client must complete the flow via `/mfa/verify`, `/mfa/recovery`, or
/// `/mfa/pending-enroll` + `/mfa/pending-confirm` before a session exists.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Security, AuditOperation::Login),
        (AuditCategory::Security, AuditOperation::FailedLogin),
    ])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn login(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Response, AppError> {
    // T1-10: per-account budget, checked before any DB/argon2 work (see the
    // throttle section above for why attempts, not failures, are counted).
    if let Some(rejected) = enforce_account_budget(
        &state.redis_coordination,
        &login_throttle_key(&body.email),
        LOGIN_ATTEMPTS_PER_ACCOUNT_RPM,
        "login",
    )
    .await?
    {
        return Ok(rejected);
    }

    // Z4-T10: the per-address budget, across accounts, also before any
    // password work; only failures spend it (see `address_throttle`).
    let client_ip = connect_info.map(|Extension(ConnectInfo(peer))| {
        attome_server::middleware::client_ip::client_ip_from_parts(
            peer.ip(),
            &headers,
            &state.config,
        )
    });
    let address_key = client_ip
        .map(|ip| super::address_throttle::key(ip, state.config.rate_limit.ipv6_bucket_prefix));
    if let Some(key) = &address_key
        && let Some(retry_after_secs) =
            super::address_throttle::blocked(&state.redis_coordination, key).await?
    {
        return Err(AppError::TooManyRequests {
            retry_after_secs: Some(retry_after_secs),
        });
    }

    // Q20-T2: an address challenged for a password spray signs in only with
    // a CAPTCHA the provider in force accepts; with no provider, not at all
    // until the challenge ends. Q20-T3: the 429 names the challenge kind in
    // `Attome-Challenge` so the sign-in page can solve it and retry.
    if let Some(key) = &address_key
        && let Some(left) = login_guard::challenge_active(&state.redis_coordination, key).await?
    {
        let captcha = &state.config.portal.captcha;
        let provider = captcha.effective_provider(state.config.deployment.sovereign);
        let remote_ip = client_ip.map(|ip| ip.to_string());
        let pow_secret = state.secrets.load().jwt_secret.active().map(str::to_owned);
        let solved = provider != attome_config::CaptchaProvider::None
            && attome_auth::captcha::verify_challenge(
                captcha,
                state.config.deployment.sovereign,
                &state.redis_coordination,
                pow_secret.as_deref(),
                body.captcha_token.as_deref(),
                remote_ip.as_deref(),
            )
            .await;
        if !solved {
            let mut refused = AppError::TooManyRequests {
                retry_after_secs: Some(left),
            }
            .into_response();
            let kind = match provider {
                attome_config::CaptchaProvider::Pow => "pow",
                attome_config::CaptchaProvider::Turnstile => "turnstile",
                attome_config::CaptchaProvider::Hcaptcha => "hcaptcha",
                attome_config::CaptchaProvider::None => "wait",
            };
            refused.headers_mut().insert(
                "attome-challenge",
                axum::http::HeaderValue::from_static(kind),
            );
            return Ok(refused);
        }
    }

    // Q20-T2: after three failures in a row the account's attempts wait,
    // before the password is checked so a right and a wrong one take the
    // same time.
    let account_key = login_throttle_key(&body.email);
    let streak = login_guard::streak(&state.redis_coordination, &account_key).await?;
    let delay = login_guard::delay_for(
        streak,
        state.config.request_timeout().as_secs().saturating_sub(5),
    );
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }

    // D-786: a service principal has no password; answer like any bad
    // credential, and record it as a failed login like one (follow-up L3).
    let attempt = if attome_security::accounts::is_reserved_service_email(&body.email) {
        Err(AppError::Unauthorized)
    } else {
        // Q5-T3: the person's roles decide the second factor;
        // `auth.mfa_policy` is what a role set to inherit means. Q5-T4: a
        // remembered browser skips it while the policy allows.
        let device =
            attome_auth::remembered_device::presented(&headers, state.config.auth.secure_cookies);
        // Q5-T6: a new device or country, or recent failures, ask for the
        // second factor even on a remembered browser. A failed check counts
        // as risky (fail closed).
        let device = match device {
            Some(bearer)
                if !risky_sign_in(&state, &body.email, streak)
                    .await
                    .unwrap_or(true) =>
            {
                Some(bearer)
            }
            _ => None,
        };
        let ring = state.pepper_ring();
        accounts::login_with_policy(
            &state.db,
            &state.redis_coordination,
            &body.email,
            &body.password,
            state.config.auth.require_verified_email,
            &attome_security::mfa_policy::RoleMfaPolicySource {
                db: &state.db,
                deployment_floor: &state.config.auth.mfa_policy,
            },
            &state.secrets.load().jwt_secret,
            &state.config.auth.jwt_issuer,
            state.config.jwt_audience(),
            device.as_deref().map(|bearer| accounts::RememberedDevice {
                bearer,
                ring: &ring,
            }),
        )
        .await
    };
    let outcome = match attempt {
        Ok(outcome) => outcome,
        // `accounts::login` answers `Unauthorized` for exactly the credential
        // failures (unknown email, wrong password, inactive account, no local
        // password) and something else for every other rejection (an
        // unverified email is `Forbidden`, infrastructure errors are 5xx), so
        // only this arm is a failed-login event (D-541 rule 6).
        Err(AppError::Unauthorized) => {
            if let Some(key) = &address_key {
                super::address_throttle::record_failure(&state.redis_coordination, key).await?;
            }
            let ip = client_ip.map_or_else(|| "unknown".to_owned(), |ip| ip.to_string());
            // Q20-T2: the account's streak and the address's spray count.
            let streak =
                login_guard::record_account_failure(&state.redis_coordination, &account_key)
                    .await?;
            if streak == login_guard::DELAY_AFTER + 1 {
                auditor
                    .write(login_guard_event(format!(
                        "login.backoff_started:{}",
                        failed_login::ip_key(&ip)
                    )))
                    .await?;
            }
            if let Some(key) = &address_key
                && login_guard::record_spray(
                    &state.redis_coordination,
                    key,
                    &account_key,
                    chrono::Utc::now().timestamp(),
                )
                .await?
            {
                auditor
                    .write(login_guard_event(format!(
                        "login.spray_detected:{}",
                        failed_login::ip_key(&ip)
                    )))
                    .await?;
            }
            let subject = failed_login_subject(&state, &body.email).await?;
            failed_login::record_failure(
                &auditor,
                &state.redis_coordination,
                subject,
                &ip,
                chrono::Utc::now().timestamp(),
            )
            .await?;
            return Err(AppError::Unauthorized);
        }
        Err(other) => return Err(other),
    };
    // Q20-T2: the password was right.
    login_guard::clear_streak(&state.redis_coordination, &account_key).await;

    // Q1-T7: an SSO-only domain or role signs in through its provider. The
    // refusal reads exactly like a wrong password, so it reveals nothing; a
    // break-glass account keeps its password and its use is recorded.
    if let failed_login::Subject::Known { user_id, .. } =
        failed_login_subject(&state, &body.email).await?
    {
        use attome_security::auth_policy::{self, PasswordLogin};
        match auth_policy::password_login(&state.db, user_id, &body.email).await? {
            PasswordLogin::Refused => {
                auditor
                    .write(
                        SecurityEvent::new(
                            MandatoryCategory::Security,
                            AuditOperation::FailedLogin,
                            user_id,
                            "user_account",
                            Some(user_id),
                        )
                        .named("password_login_refused_sso_only"),
                    )
                    .await?;
                return Err(AppError::Unauthorized);
            }
            PasswordLogin::BreakGlass => {
                auth_policy::record_break_glass_sign_in();
                auditor
                    .write(
                        SecurityEvent::new(
                            MandatoryCategory::Security,
                            AuditOperation::Login,
                            user_id,
                            "user_account",
                            Some(user_id),
                        )
                        .named("break_glass_sign_in"),
                    )
                    .await?;
            }
            PasswordLogin::Allowed => {}
        }
    }

    // Q5-T10: what the sign-in page offers with a challenge: "later" while
    // the grace period runs, and remembering the browser where allowed.
    let (grace_until, remember_device) = match &outcome {
        accounts::LoginOutcome::Session(_) => (None, false),
        _ => challenge_hints(&state, &body.email).await,
    };
    match outcome {
        accounts::LoginOutcome::Session(user_id) => {
            let cookies = issue_session_cookies_for(
                &state,
                user_id,
                &AuthContext::password(),
                Some((&auditor, "password")),
            )
            .await?;
            Ok((
                StatusCode::OK,
                AppendHeaders(cookies),
                Json(AuthResponse { user_id }),
            )
                .into_response())
        }
        accounts::LoginOutcome::MfaRequired { pending_token } => Ok((
            StatusCode::OK,
            Json(MfaChallengeResponse {
                mfa: "required".to_string(),
                pending_token,
                grace_until: None,
                remember_device,
            }),
        )
            .into_response()),
        accounts::LoginOutcome::MfaEnrollmentRequired { pending_token } => Ok((
            StatusCode::OK,
            Json(MfaChallengeResponse {
                mfa: "enrollment_required".to_string(),
                pending_token,
                grace_until,
                remember_device: false,
            }),
        )
            .into_response()),
    }
}

/// A rejected second-factor code at login (`/mfa/verify`, `/mfa/verify-recovery`,
/// `/mfa/pending-confirm`): `Security` + `FailedLogin`, outcome `Failed`, against
/// the account the pending token names, **only when that token verifies**
/// (an unverified `sub` is never trusted for attribution). Nothing was
/// changed, so there is no transaction to join; the per-account MFA budget
/// charged before the attempt bounds the volume. Only an `Unauthorized`
/// rejection is recorded; the original error is returned unless the audit
/// write itself fails.
async fn record_failed_second_factor(
    state: &AppState,
    auditor: &SecurityAuditor,
    pending_token: &str,
    token_type: attome_auth::session::TokenType,
    event_name: &'static str,
    err: AppError,
) -> AppError {
    if !matches!(err, AppError::Unauthorized) {
        return err;
    }
    // Q5-T11: every refused second factor counts, by factor (the event
    // name's last word: totp, recovery_code, email_code, forced_at_login).
    let factor = event_name.rsplit(' ').next().unwrap_or("unknown");
    metrics::counter!("auth_mfa_failures_total", "factor" => factor).increment(1);
    let Some(user_id) = mfa::verified_pending_subject(
        pending_token,
        token_type,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    ) else {
        return err;
    };
    match auditor
        .write(
            SecurityEvent::new(
                MandatoryCategory::Security,
                AuditOperation::FailedLogin,
                Uuid::nil(),
                "user_account",
                Some(user_id),
            )
            .named(event_name)
            .outcome(AuditOutcome::Failed),
        )
        .await
    {
        Ok(_) => err,
        Err(audit_err) => audit_err,
    }
}

/// Resolves who a failed login was against: one indexed lookup by the
/// normalized email, run on every credential failure whether or not the
/// account exists, so it adds no timing difference between the two. An
/// unknown identifier yields [`failed_login::Subject::Unknown`] and nothing
/// about the typed string is kept (D-541 G3-1 a).
/// Q5-T10: the grace period's end while it runs, and whether the browser may
/// be remembered, for `email`'s challenge. A failure shows neither: the
/// challenge itself is what matters.
async fn challenge_hints(
    state: &AppState,
    email: &str,
) -> (Option<chrono::DateTime<chrono::Utc>>, bool) {
    let Ok(failed_login::Subject::Known { user_id, .. }) = failed_login_subject(state, email).await
    else {
        return (None, false);
    };
    match attome_security::mfa_policy::requirement_for(
        &state.db,
        user_id,
        &state.config.auth.mfa_policy,
    )
    .await
    {
        Ok(requirement) => {
            let now = chrono::Utc::now();
            (
                requirement.grace_until.filter(|until| *until > now),
                requirement.remember_device_days > 0,
            )
        }
        Err(error) => {
            tracing::warn!(%user_id, %error, "auth: the challenge hints could not be read");
            (None, false)
        }
    }
}

/// Q5-T6: whether a password sign-in for `email` is risky (see
/// `attome_security::sign_in_rules::risk`); an unknown address is not.
async fn risky_sign_in(state: &AppState, email: &str, streak: i64) -> Result<bool, AppError> {
    let failed_login::Subject::Known { user_id, .. } = failed_login_subject(state, email).await?
    else {
        return Ok(false);
    };
    let (device, country) = super::session::sign_in_place();
    let risk = attome_security::sign_in_rules::risk::assess(
        &state.db,
        user_id,
        &device,
        country.as_deref(),
        u32::try_from(streak).unwrap_or(u32::MAX),
    )
    .await?;
    if risk.any() {
        tracing::info!(%user_id, reasons = ?risk.reasons(), "auth: a risky sign-in asks for the second factor");
    }
    Ok(risk.any())
}

async fn failed_login_subject(
    state: &AppState,
    email: &str,
) -> Result<failed_login::Subject, AppError> {
    let normalized = attome_auth::email_identity::normalize_email(email);
    let row: Option<(Uuid, Option<Uuid>)> =
        sqlx::query_as("SELECT id, organization_ref FROM user_account WHERE email = $1 LIMIT 1")
            .bind(&normalized)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::internal)?;
    Ok(match row {
        Some((user_id, organization_ref)) => failed_login::Subject::Known {
            user_id,
            organization_ref,
        },
        None => failed_login::Subject::Unknown,
    })
}

/// Finish sign-in with a TOTP code
///
/// Completes an `MfaRequired` login with a TOTP code. Bypass-listed — the
/// caller has no session cookie yet (that's the whole point); identity comes
/// from `pending_token`, a short-lived, purpose-scoped token distinct from
/// `SessionClaims` (`attome_auth::mfa`), not from `AuthnLayer`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/verify",
    tag = "auth",
    request_body = MfaVerifyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn mfa_verify(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    headers: HeaderMap,
    Json(body): Json<MfaVerifyBody>,
) -> Result<Response, AppError> {
    // T1-10: per-account budget across *every* pending token for this user —
    // the per-challenge attempt ceiling (`mfa_challenge_max_attempts`) is
    // per-`jti`, so re-logging in for a fresh token would otherwise reset it.
    if let Some(user_id) = pending_token_subject(&body.pending_token)
        && let Some(rejected) = enforce_account_budget(
            &state.redis_coordination,
            &mfa_account_key(user_id),
            MFA_ATTEMPTS_PER_ACCOUNT_RPM,
            "mfa_verify",
        )
        .await?
    {
        return Ok(rejected);
    }

    let user_id = match mfa::complete_pending_login(
        &state.db,
        &state.secrets.load().mfa_encryption_key,
        &state.redis_coordination,
        &body.pending_token,
        &body.code,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        state.config.auth.mfa_challenge_max_attempts,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(e) => {
            return Err(record_failed_second_factor(
                &state,
                &auditor,
                &body.pending_token,
                attome_auth::session::TokenType::MfaPendingLogin,
                "mfa_verify_failed totp",
                e,
            )
            .await);
        }
    };
    // A pending login token comes only from a verified password, and this
    // request verified the TOTP code.
    let issued = issue_session_for(
        &state,
        user_id,
        &AuthContext::password_and_totp(),
        Some((&auditor, "password+totp")),
    )
    .await?;
    let mut cookies = issued.cookies.to_vec();
    // Q5-T4: remember this browser when asked and the policy allows it.
    if body.remember {
        let requirement = attome_security::mfa_policy::requirement_for(
            &state.db,
            user_id,
            &state.config.auth.mfa_policy,
        )
        .await?;
        if requirement.may_remember() {
            let epoch = attome_auth::epoch::current_epoch(&state.db, user_id).await?;
            let label = headers
                .get(axum::http::header::USER_AGENT)
                .and_then(|v| v.to_str().ok());
            // Q8-T4: ending this session from the session list forgets it.
            let bearer = attome_auth::remembered_device::remember_in_family(
                &state.db,
                &state.pepper_ring(),
                user_id,
                epoch,
                requirement.remember_device_days,
                label,
                Some(issued.family_id),
            )
            .await?;
            // Q5-T11: a remembered browser is a credential; its creation is
            // audited (the bearer never is).
            let device_id = bearer
                .split_once('.')
                .and_then(|(id, _)| id.parse::<Uuid>().ok());
            auditor
                .write(
                    SecurityEvent::new(
                        MandatoryCategory::Credential,
                        AuditOperation::Create,
                        user_id,
                        "remembered_device",
                        device_id,
                    )
                    .named("mfa device remembered"),
                )
                .await?;
            cookies.push((
                axum::http::header::SET_COOKIE,
                attome_auth::remembered_device::cookie(
                    &bearer,
                    requirement.remember_device_days,
                    state.config.auth.secure_cookies,
                ),
            ));
        }
    }

    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

/// Send a sign-in code
///
/// Q5-T5: with the `MfaRequired` pending token, sends a one-time code by
/// `channel` as the second factor, when every role of the person allows that
/// weaker factor. Never for an administrator (403), and never to an email
/// address that is not verified (403). `email` is the channel today; `sms`
/// and `whatsapp` answer 503 until those channels exist. The code works
/// once, for a minute; sending again replaces it. The token stays usable for
/// `mfa/code/verify`. Bypass-listed like `mfa/verify`; rate limited in the
/// `mfa` class.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/code/send",
    tag = "auth",
    request_body = MfaCodeSendBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::SendEmail"),
        "issues a one-time code and queues its email; the sign-in it completes is audited by mfa/code/verify",
    )))),
    responses(
        (status = 202, description = "The code is on its way"),
        (status = 401, description = "The pending token is not a live sign-in token", body = ErrorResponse),
        (status = 403, description = "The person's roles do not allow this factor, the person is an administrator, or the email address is not verified", body = ErrorResponse),
        (status = 422, description = "An unknown channel", body = ErrorResponse),
        (status = 503, description = "The channel is not available on this deployment", body = ErrorResponse),
    ),
)]
pub(super) async fn mfa_code_send(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MfaCodeSendBody>,
) -> Result<StatusCode, AppError> {
    use attome_auth::otp::OtpChannel;
    let user_id = mfa::pending_login_subject(
        &state.redis_coordination,
        &body.pending_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .await?;
    let channel = match body.channel.as_str() {
        "email" => OtpChannel::Email,
        "sms" => OtpChannel::Sms,
        "whatsapp" => OtpChannel::WhatsApp,
        _ => {
            return Err(AppError::Validation(
                "channel must be email, sms or whatsapp".into(),
            ));
        }
    };
    if channel != OtpChannel::Email {
        // No role can allow a channel that does not exist yet; an
        // administrator is refused every weak one.
        if attome_security::delegation::holds_system_admin(&state.db, user_id).await? {
            return Err(AppError::Forbidden);
        }
        return Err(AppError::FeatureUnavailable);
    }
    let requirement = attome_security::mfa_policy::requirement_for(
        &state.db,
        user_id,
        &state.config.auth.mfa_policy,
    )
    .await?;
    if !requirement.email_code {
        return Err(AppError::Forbidden);
    }
    let lang = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("en");
    let frontend_url = state.config.frontend_url();
    let sender = attome_security::otp_sender::PlatformOtpSender {
        db: &state.db,
        frontend_url: &frontend_url,
        lang,
    };
    attome_auth::otp::issue(
        &state.db,
        &state.pepper_ring(),
        &sender,
        user_id,
        mfa::OTP_LOGIN_PURPOSE,
        channel,
    )
    .await?;
    Ok(StatusCode::ACCEPTED)
}

/// Finish sign-in with a sent code
///
/// Q5-T5: like `mfa/verify`, with the one-time code `mfa/code/send` sent
/// instead of a TOTP code. The session records the weaker factor
/// (`otp_weak`), which no step-up counts as phishing-resistant. Refused when
/// the person's roles no longer allow email codes.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/code/verify",
    tag = "auth",
    request_body = MfaVerifyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login)])))),
    responses(
        (status = 200, description = "Signed in"),
        (status = 401, description = "The pending token or the code was refused", body = ErrorResponse),
        (status = 403, description = "The person's roles do not allow email codes", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn mfa_code_verify(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<MfaVerifyBody>,
) -> Result<Response, AppError> {
    // Shares the second-factor account budget with mfa/verify.
    if let Some(user_id) = pending_token_subject(&body.pending_token)
        && let Some(rejected) = enforce_account_budget(
            &state.redis_coordination,
            &mfa_account_key(user_id),
            MFA_ATTEMPTS_PER_ACCOUNT_RPM,
            "mfa_code_verify",
        )
        .await?
    {
        return Ok(rejected);
    }
    let subject = mfa::pending_login_subject(
        &state.redis_coordination,
        &body.pending_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .await?;
    let requirement = attome_security::mfa_policy::requirement_for(
        &state.db,
        subject,
        &state.config.auth.mfa_policy,
    )
    .await?;
    if !requirement.email_code {
        return Err(AppError::Forbidden);
    }
    let user_id = match mfa::complete_pending_login_otp(
        &state.db,
        &state.pepper_ring(),
        &state.redis_coordination,
        &body.pending_token,
        &body.code,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        state.config.auth.mfa_challenge_max_attempts,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(e) => {
            return Err(record_failed_second_factor(
                &state,
                &auditor,
                &body.pending_token,
                attome_auth::session::TokenType::MfaPendingLogin,
                "mfa_verify_failed email_code",
                e,
            )
            .await);
        }
    };
    let cookies = issue_session_cookies_for(
        &state,
        user_id,
        &AuthContext::password_and_weak_otp(),
        Some((&auditor, "password+email_code")),
    )
    .await?;
    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

/// Finish sign-in with a recovery code
///
/// Same as `mfa_verify` but via a single-use recovery code instead of a live
/// TOTP code.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/verify-recovery",
    tag = "auth",
    request_body = MfaVerifyBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn mfa_recovery(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<MfaVerifyBody>,
) -> Result<Response, AppError> {
    // T1-10: shares `mfa_verify`'s bucket — same second-factor step for the
    // same account, so alternating routes must not double the budget.
    if let Some(user_id) = pending_token_subject(&body.pending_token)
        && let Some(rejected) = enforce_account_budget(
            &state.redis_coordination,
            &mfa_account_key(user_id),
            MFA_ATTEMPTS_PER_ACCOUNT_RPM,
            "mfa_verify_recovery",
        )
        .await?
    {
        return Ok(rejected);
    }

    let user_id = match mfa::complete_pending_login_recovery(
        &state.db,
        &state.pepper_ring(),
        &state.redis_coordination,
        &body.pending_token,
        &body.code,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        state.config.auth.mfa_challenge_max_attempts,
    )
    .await
    {
        Ok(user_id) => user_id,
        Err(e) => {
            return Err(record_failed_second_factor(
                &state,
                &auditor,
                &body.pending_token,
                attome_auth::session::TokenType::MfaPendingLogin,
                "mfa_verify_failed recovery_code",
                e,
            )
            .await);
        }
    };
    let cookies = issue_session_cookies_for(
        &state,
        user_id,
        &AuthContext::password_and_recovery_code(),
        Some((&auditor, "password+recovery_code")),
    )
    .await?;

    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

/// Start required MFA enrolment
///
/// Starts forced enrollment (`mfa_policy = "required"`, account not yet
/// enrolled) using the `MfaEnrollmentRequired` pending token in place of a
/// session. Bypass-listed for the same reason as `mfa_verify`.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/pending-enroll",
    tag = "auth",
    request_body = MfaPendingEnrollBody,
    // D-542: not exemptable, same as `/mfa/enroll`: it replaces any
    // unconfirmed factor secret with a new one.
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn mfa_pending_enroll(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<MfaPendingEnrollBody>,
) -> Result<Response, AppError> {
    let hook = account_event_hook(
        auditor.service(),
        MandatoryCategory::Credential,
        AuditOperation::Create,
        "user_mfa",
        "mfa_enrollment_started forced_at_login",
    );
    let resp = mfa::enroll_pending_with(
        &state.db,
        &state.secrets.load().mfa_encryption_key,
        &body.pending_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        &hook,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(MfaEnrollResponse {
            secret_base32: resp.secret_base32,
            otpauth_uri: resp.otpauth_uri,
        }),
    )
        .into_response())
}

/// Put off required MFA enrolment
///
/// Q5-T3: with the `MfaEnrollmentRequired` pending token, signs the person in
/// with their password alone and puts enrolment off for a day, never past
/// the grace period their roles' policy gives once a second factor becomes
/// required. After the grace period it is refused (403) and the person must
/// enrol. The token works once. Bypass-listed like `mfa/pending-enroll`;
/// rate limited in the `mfa` class.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/postpone",
    tag = "auth",
    request_body = MfaPendingEnrollBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login)])))),
    responses(
        (status = 200, description = "Signed in; enrolment is put off"),
        (status = 401, description = "The pending token is not a live enrolment token", body = ErrorResponse),
        (status = 403, description = "The grace period is over, or no second factor is required", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn mfa_postpone(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<MfaPendingEnrollBody>,
) -> Result<Response, AppError> {
    let user_id = mfa::redeem_pending_enroll(
        &state.redis_coordination,
        &body.pending_token,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
    )
    .await?;
    let Some(until) = attome_security::mfa_policy::postpone_enrolment(
        &state.db,
        user_id,
        &state.config.auth.mfa_policy,
        chrono::Utc::now(),
    )
    .await?
    else {
        return Err(AppError::Forbidden);
    };
    tracing::info!(%user_id, %until, "mfa: enrolment put off");
    // The pending enrolment token comes only from a verified password.
    let cookies = issue_session_cookies_for(
        &state,
        user_id,
        &AuthContext::password(),
        Some((&auditor, "password (mfa enrolment postponed)")),
    )
    .await?;
    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

/// Confirm required MFA enrolment
///
/// Confirms forced enrollment and, on success, issues a real session
/// immediately (the `mfa_policy = "required"` first-login path completes in
/// one round trip: enroll, confirm, done) — plus the one-time-viewable
/// recovery-code batch in the response body alongside the cookies.
#[utoipa::path(
    post,
    path = "/api/v1/auth/mfa/pending-confirm",
    tag = "auth",
    request_body = MfaVerifyBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Credential, AuditOperation::MfaEnrolled),
        (AuditCategory::Security, AuditOperation::Login),
    ])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn mfa_pending_confirm(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<MfaVerifyBody>,
) -> Result<Response, AppError> {
    // The enrolment and its `MfaEnrolled` event commit together, inside
    // attome-auth's confirmation transaction (D-062).
    let hook = account_event_hook(
        auditor.service(),
        MandatoryCategory::Credential,
        AuditOperation::MfaEnrolled,
        "user_account",
        "mfa_enrolled forced_at_login",
    );
    let (user_id, recovery_codes) = match mfa::confirm_pending_enrollment_with(
        &state.db,
        &state.secrets.load().mfa_encryption_key,
        &state.pepper_ring(),
        &state.redis_coordination,
        &body.pending_token,
        &body.code,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        state.config.auth.mfa_challenge_max_attempts,
        &hook,
    )
    .await
    {
        Ok(confirmed) => confirmed,
        Err(e) => {
            return Err(record_failed_second_factor(
                &state,
                &auditor,
                &body.pending_token,
                attome_auth::session::TokenType::MfaPendingEnroll,
                "mfa_confirm_failed forced_at_login",
                e,
            )
            .await);
        }
    };
    // Forced enrollment follows a verified password, and confirming it verified
    // the new TOTP code.
    let cookies = issue_session_cookies_for(
        &state,
        user_id,
        &AuthContext::password_and_totp(),
        Some((&auditor, "password+totp")),
    )
    .await?;

    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(MfaPendingConfirmResponse {
            user_id,
            recovery_codes,
        }),
    )
        .into_response())
}

/// Request a password reset
///
/// Always responds 200 regardless of whether `body.email` matched an account
/// (anti-enumeration, guidelines/P-account-lifecycle) — only a match actually
/// enqueues an email. Bypass-listed, IP-rate-limited (this route classifies
/// as the `password_reset` category, `attome_server::middleware::rate_limit::
/// RATE_LIMIT_CATEGORIES` — its own independent, tighter budget, see
/// config.example.json).
#[utoipa::path(
    post,
    path = "/api/v1/auth/reset-request",
    tag = "auth",
    request_body = ResetRequestBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::PasswordReset)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn reset_request(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<ResetRequestBody>,
) -> Result<Response, AppError> {
    if !state.config.email.enabled {
        return Err(AppError::FeatureUnavailable);
    }

    // Base-auth hardening 2.5: a per-account budget, so one address cannot be
    // mail-bombed from many IPs. It counts attempts before any lookup, and a
    // throttled request gets the same 200 and sends nothing, so the throttle
    // reveals nothing about whether the address has an account. A Redis
    // failure fails closed, like every other per-account budget.
    if enforce_account_budget(
        &state.redis_coordination,
        &reset_throttle_key(&body.email),
        RESET_REQUESTS_PER_ACCOUNT_RPM,
        "reset_request",
    )
    .await?
    .is_some()
    {
        return Ok((StatusCode::OK, Json(Ack { ok: true })).into_response());
    }

    // D-786: no reset token for a service principal; same silent 200.
    if attome_security::accounts::is_reserved_service_email(&body.email) {
        return Ok((StatusCode::OK, Json(Ack { ok: true })).into_response());
    }
    let mut tx = attome_db::tx::begin(&state.db).await?;
    if let Some(issued) = reset::request_in_tx(
        &mut tx,
        &body.email,
        PASSWORD_RESET_TOKEN_EXPIRY_MINS,
        &state.pepper_ring(),
    )
    .await?
    {
        let link = format!(
            "{}/reset-password?token={}",
            state.config.frontend_url(),
            issued.bearer
        );
        let brand =
            attome_core::theme_store::email_brand(&state.db, &state.config.frontend_url()).await;
        let (subject, text_body, html_body) =
            attome_email::templates::password_reset(&link, &brand);
        let delivery_id = Uuid::now_v7();
        attome_email::delivery::record_queued_in_tx(
            &mut tx,
            delivery_id,
            attome_email::delivery::EmailDeliveryKind::PasswordReset,
            &issued.email,
            &subject,
            Some(issued.user_id),
            None,
            None,
        )
        .await
        .map_err(AppError::internal)?;
        attome_jobs::enqueue_in_tx(
            &mut tx,
            EngineJob::SendEmail(Box::new(EmailMessage {
                to: issued.email,
                subject,
                text_body,
                html_body: Some(html_body),
                delivery_id: Some(delivery_id),
                from_override: None,
                message_id: None,
                in_reply_to: None,
                references: None,
                communication_id: None,
                attachments: Vec::new(),
                stream: Default::default(),
                list_unsubscribe: None,
            })),
        )
        .await
        .map_err(AppError::internal)?;
        // In the token's own transaction (D-062). Only a known account gets
        // an event: an unmatched address writes nothing, so the audit trail
        // holds no typed string and the response stays identical (G3-1 a).
        // The requester is unauthenticated, so the actor is nil.
        let organization_ref: Option<Uuid> =
            sqlx::query_scalar("SELECT organization_ref FROM user_account WHERE id = $1")
                .bind(issued.user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::internal)?
                .flatten();
        let mut event = SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::PasswordReset,
            Uuid::nil(),
            "user_account",
            Some(issued.user_id),
        )
        .named("password_reset requested")
        .outcome(AuditOutcome::Succeeded);
        if let Some(org) = organization_ref {
            event = event.organization(org);
        }
        write_security_event(&mut tx, &auditor.service(), event).await?;
    }
    tx.commit().await.map_err(AppError::internal)?;

    Ok((StatusCode::OK, Json(Ack { ok: true })).into_response())
}

/// Reset a password with a reset token
///
/// Confirms a presented reset token. `reset::confirm` applies the whole reset
/// in one transaction (D-509): it consumes the token, sets the new password,
/// expires the account's other reset links, revokes every refresh token the
/// account holds and bumps `auth_epoch`, so live access tokens stop working
/// too. API keys and MFA enrollment are not touched.
#[utoipa::path(
    post,
    path = "/api/v1/auth/reset-confirm",
    tag = "auth",
    request_body = ResetConfirmBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::PasswordReset)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn reset_confirm(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<ResetConfirmBody>,
) -> Result<Response, AppError> {
    // D-509: `reset::confirm` revokes every refresh token inside its own
    // transaction, together with the password, the consumed token and the
    // epoch bump. A separate revocation here could fail after that commit and
    // leave the new password alongside live refresh families.
    // A completed reset writes its event inside the reset's own transaction
    // (hook, D-062). A refused reset changed nothing, so its event is written
    // on its own afterwards, and only when the token identified an account
    // (its secret verified); an invalid token writes nothing. The requester
    // is unauthenticated: actor nil.
    let hook = AuditHook::new(auditor.service(), |user_id: &Uuid| {
        vec![HookEvent::Security(
            SecurityEvent::new(
                MandatoryCategory::Credential,
                AuditOperation::PasswordReset,
                Uuid::nil(),
                "user_account",
                Some(*user_id),
            )
            .named("password_reset confirmed")
            .outcome(AuditOutcome::Succeeded),
        )]
    });
    let (result, subject) = reset::confirm_with_subject_hook(
        &state.db,
        &state.redis,
        &body.token,
        &body.new_password,
        &state.pepper_ring(),
        &hook,
    )
    .await;
    if result.is_err()
        && let Some(user_id) = subject
    {
        let (outcome, name) = (AuditOutcome::Failed, "password_reset refused");
        auditor
            .write(
                SecurityEvent::new(
                    MandatoryCategory::Credential,
                    AuditOperation::PasswordReset,
                    Uuid::nil(),
                    "user_account",
                    Some(user_id),
                )
                .named(name)
                .outcome(outcome),
            )
            .await?;
    }
    result?;

    Ok((StatusCode::OK, Json(Ack { ok: true })).into_response())
}

/// Confirm an email address
///
/// Confirms a presented email-verification token, flipping
/// `user_account.email_verified`. Bypass-listed — the user isn't
/// necessarily logged in when clicking the emailed link.
#[utoipa::path(
    post,
    path = "/api/v1/auth/verify-email/confirm",
    tag = "auth",
    request_body = VerifyEmailConfirmBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn verify_email_confirm(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    Json(body): Json<VerifyEmailConfirmBody>,
) -> Result<Response, AppError> {
    // Account state (D-541 rule 1): the verified flag and its event commit
    // together inside attome-auth's transaction (D-062).
    let hook = account_event_hook(
        auditor.service(),
        MandatoryCategory::Security,
        AuditOperation::Update,
        "user_account",
        "email_verified",
    );
    verification::confirm_with(&state.db, &body.token, &state.pepper_ring(), &hook).await?;
    Ok((StatusCode::OK, Json(Ack { ok: true })).into_response())
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    register,
    login,
    mfa_verify,
    mfa_recovery,
    mfa_pending_enroll,
    mfa_pending_confirm,
    mfa_postpone,
    mfa_code_send,
    mfa_code_verify,
    reset_request,
    reset_confirm,
    verify_email_confirm
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod throttle_tests {
    use super::*;

    #[test]
    fn base64url_decodes_unpadded_padded_and_standard_alphabets() {
        assert_eq!(base64url_decode("aGVsbG8").as_deref(), Some(&b"hello"[..]));
        assert_eq!(base64url_decode("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(base64url_decode("").as_deref(), Some(&b""[..]));
        // `-`/`_` (url-safe) and `+`/`/` (standard) map to the same values.
        assert_eq!(base64url_decode("-_8"), base64url_decode("+/8"));
        assert_eq!(base64url_decode("-_8").as_deref(), Some(&[0xfb, 0xff][..]));
        assert_eq!(base64url_decode("a*b"), None);
        assert_eq!(base64url_decode("aGV sbG8"), None);
    }

    #[test]
    fn pending_token_subject_reads_sub_from_the_payload_segment() {
        let user_id = Uuid::now_v7();
        // Header and signature contents are irrelevant to bucket selection —
        // only the payload's `sub` is read.
        let payload = format!(r#"{{"sub":"{user_id}","typ":"mfa_pending_login"}}"#);
        let token = format!("eyJhbGciOiJIUzI1NiJ9.{}.sig", b64url(payload.as_bytes()));
        assert_eq!(pending_token_subject(&token), Some(user_id));
    }

    #[test]
    fn pending_token_subject_is_none_for_anything_that_is_not_a_jwt_with_a_sub() {
        assert_eq!(pending_token_subject(""), None);
        assert_eq!(pending_token_subject("not-a-jwt"), None);
        assert_eq!(pending_token_subject("a.b"), None);
        assert_eq!(pending_token_subject("a.b.c.d"), None);
        let no_sub = format!("h.{}.s", b64url(br#"{"typ":"mfa_pending_login"}"#));
        assert_eq!(pending_token_subject(&no_sub), None);
        let bad_sub = format!("h.{}.s", b64url(br#"{"sub":"not-a-uuid"}"#));
        assert_eq!(pending_token_subject(&bad_sub), None);
        assert_eq!(pending_token_subject("h.%%%.s"), None);
    }

    #[test]
    fn reset_throttle_key_normalizes_and_is_a_separate_bucket_from_login() {
        let canonical = reset_throttle_key("alice@example.com");
        assert_eq!(reset_throttle_key("  Alice@Example.COM  "), canonical);
        assert_ne!(login_throttle_key("alice@example.com"), canonical);
        assert!(canonical.starts_with("server:rl:account:"));
        assert!(canonical.ends_with(":reset"));
        assert!(
            !canonical.contains("alice"),
            "the address itself must never reach Redis"
        );
    }

    #[test]
    fn login_throttle_key_normalizes_and_hashes_the_email() {
        let canonical = login_throttle_key("alice@example.com");
        assert_eq!(login_throttle_key("  Alice@Example.COM  "), canonical);
        assert_ne!(login_throttle_key("bob@example.com"), canonical);
        assert!(canonical.starts_with("server:rl:account:"));
        assert!(canonical.ends_with(":login"));
        assert!(
            !canonical.contains("alice") && !canonical.contains('@'),
            "the raw email must never appear in the Redis key: {canonical}"
        );
    }

    /// Test-only encoder so the decoder above is exercised against inputs
    /// it did not produce itself.
    fn b64url(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut acc = 0u32;
            for (i, b) in chunk.iter().enumerate() {
                acc |= u32::from(*b) << (16 - 8 * i);
            }
            let chars = chunk.len() + 1;
            for i in 0..chars {
                let idx = ((acc >> (18 - 6 * i)) & 0x3f) as usize;
                out.push(ALPHABET[idx] as char);
            }
        }
        out
    }
}
