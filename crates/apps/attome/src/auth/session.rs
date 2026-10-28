//! Session lifecycle — issuing, refreshing, ending, and introspecting a
//! session. Shared by every login path (`super::local`, `super::google`,
//! `super::oidc`) via `issue_session_cookies_for`.

use attome_audit::security::{
    AuditHook, HookEvent, MandatoryCategory, SecurityAuditor, SecurityEvent, account_event_hook,
    x_audit,
};
use attome_audit::{AuditCategory, AuditOperation, AuditOutcome};
use attome_auth::auth_context::AuthContext;
use attome_auth::{SessionClaims, accounts, cookie, refresh, revocation};
use attome_core::jobs::EngineJob;
use attome_server::AppState;
use attome_types::AppError;
use axum::{
    Json,
    extract::{Extension, State},
    http::{HeaderMap, StatusCode, header},
    response::{AppendHeaders, IntoResponse, Response},
};
use chrono::Utc;
use uuid::Uuid;

use super::REFRESH_COOKIE_PATH;
use super::dto::{AuthResponse, IdentityLinkInfo, LogoutResponse, SessionInfo};
use attome_types::ErrorResponse;

// ── Session issuance (shared by register/login/google) ───────────────────────

/// Q5-T6: the browser family and, with `auth.geoip_database` set, the
/// country of the request being served.
pub(super) fn sign_in_place() -> (String, Option<String>) {
    let meta = attome_server::middleware::request_meta::current();
    let device = attome_security::sign_in_rules::risk::device_family(
        meta.user_agent.as_deref().unwrap_or_default(),
    );
    let country = meta
        .ip_address
        .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
        .and_then(attome_server::login_restrictions::geoip::country);
    (device, country)
}

/// Q9-T1: refuses the sign-in (`403`) when a role `user_id` holds restricts
/// where or when they may sign in and this attempt is outside it. The
/// caller's address is the trusted client IP the request-meta layer
/// captured; with none, a network or country rule refuses. A refusal during
/// a sign-in is audited as a failed login naming the rule kind.
async fn enforce_sign_in_rules(
    state: &AppState,
    user_id: Uuid,
    login: Option<(&SecurityAuditor, &str)>,
) -> Result<(), AppError> {
    use attome_server::login_restrictions::{Refusal, evaluate, geoip};

    let rules = attome_security::sign_in_rules::load(&state.db, user_id, Utc::now()).await?;
    if rules.is_empty() {
        return Ok(());
    }
    let caller_ip = attome_server::middleware::request_meta::current()
        .ip_address
        .and_then(|ip| ip.parse::<std::net::IpAddr>().ok());
    let Err(refusal) = evaluate(&rules, caller_ip, geoip::country) else {
        return Ok(());
    };
    if refusal == Refusal::Country && !geoip::is_loaded() {
        tracing::error!(
            %user_id,
            "auth: a role restricts sign-in countries but auth.geoip_database is not set"
        );
    }
    tracing::warn!(%user_id, rule = refusal.as_str(), "auth: sign-in refused by a held role's rule");
    if let Some((auditor, method)) = login {
        let event = SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Login,
            user_id,
            "user_account",
            Some(user_id),
        )
        .named(format!("login {method} refused: {}", refusal.as_str()))
        .outcome(AuditOutcome::Failed);
        if let Err(error) = auditor.write(event).await {
            tracing::error!(%user_id, %error, "auth: the refused sign-in's audit event failed");
        }
    }
    Err(AppError::Forbidden)
}

/// Mints a fresh session for `user_id` after a credential verification and
/// returns both `Set-Cookie` values. The refresh cookie is scoped to
/// `/api/v1/auth` — the only paths that ever need to read it (`/refresh`,
/// `/logout`).
///
/// D-510 rule 2: `context` is what the caller actually verified. It is recorded
/// on the new refresh family, and the access token's `sid` names that family.
/// The token is minted inside the family's transaction so it can carry its id
/// and both commit or neither does (BAU-13c).
///
/// `login` names the auditor and sign-in method when this issuance completes a
/// sign-in: the `Security` + `Login` event (D-541 rule 7, `event_name`
/// `login {method}`) is then written inside the refresh family's insert
/// transaction through a [`attome_db::BeforeCommit`] hook, so the session and its
/// event commit together (D-062). `None` (registration) writes no login event.
pub(super) async fn issue_session_cookies_for(
    state: &AppState,
    user_id: Uuid,
    context: &AuthContext,
    login: Option<(&SecurityAuditor, &str)>,
) -> Result<[(header::HeaderName, String); 2], AppError> {
    // Q9-T1: the held roles' network, hours and country rules, before any
    // session or catch-up work.
    enforce_sign_in_rules(state, user_id, login).await?;
    // Retry the idempotent catch-up on every successful session issuance so
    // a transient queue failure is recovered on the user's next login.
    enqueue_notification_backfill(state, user_id, "session").await;
    let secure = state.config.auth.secure_cookies;

    let refresh_ttl = state.config.refresh_token_expiry_secs();
    let login_hook = login.map(|(auditor, method)| {
        account_event_hook(
            auditor.service(),
            MandatoryCategory::Security,
            AuditOperation::Login,
            "user_account",
            format!("login {method}"),
        )
    });
    let hook: &dyn attome_db::BeforeCommit<Uuid> = match &login_hook {
        Some(hook) => hook,
        None => &attome_db::NoHook,
    };
    // Q8-T6: the person's roles may cap their concurrent sessions.
    let lifetimes = refresh_lifetimes(state);
    let policy = attome_security::session_policy::load(
        &state.db,
        user_id,
        attome_security::session_policy::SessionDefaults {
            idle_secs: lifetimes.idle_secs,
            absolute_secs: lifetimes.absolute_secs,
        },
    )
    .await
    .map_err(AppError::internal)?;
    // BAU-13c: the access token is minted inside the family's transaction,
    // so a failed mint leaves no orphan refresh row.
    let secrets = state.secrets.load();
    let issued = refresh::issue_session_with_limit(
        &state.db,
        user_id,
        context,
        lifetimes,
        &state.pepper_ring(),
        &refresh::AccessTokenSpec {
            jwt_ring: &secrets.jwt_secret,
            issuer: &state.config.auth.jwt_issuer,
            audience: state.config.jwt_audience(),
            expiry_secs: state.config.access_token_expiry_secs() as i64,
        },
        policy.limit(),
        hook,
    )
    .await;
    // A refused sign-in wrote nothing; it is audited on its own.
    if let (Err(AppError::Conflict(refresh::SESSION_LIMIT_REACHED)), Some((auditor, method))) =
        (&issued, login)
    {
        let event = SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Login,
            user_id,
            "user_account",
            Some(user_id),
        )
        .named(format!("login {method} refused: session limit"))
        .outcome(AuditOutcome::Failed);
        if let Err(error) = auditor.write(event).await {
            tracing::error!(%user_id, %error, "auth: the refused sign-in's audit event failed");
        }
    }
    let issued = issued?;
    // Q5-T6: a completed sign-in's device and country become known.
    if login.is_some() {
        let (device, country) = sign_in_place();
        if let Err(error) = attome_security::sign_in_rules::risk::remember(
            &state.db,
            user_id,
            &device,
            country.as_deref(),
        )
        .await
        {
            tracing::warn!(%user_id, %error, "auth: the sign-in's device and country were not recorded");
        }
    }
    let refresh_cookie = cookie::build(
        cookie::refresh_cookie_name(secure),
        &issued.bearer,
        refresh_ttl as u64,
        secure,
        REFRESH_COOKIE_PATH,
    );
    let access_token = issued.access_token;
    let session_cookie = cookie::build(
        cookie::session_cookie_name(secure),
        &access_token,
        state.config.access_token_expiry_secs(),
        secure,
        "/",
    );

    Ok([
        (header::SET_COOKIE, session_cookie),
        (header::SET_COOKIE, refresh_cookie),
    ])
}

/// Both refresh-family lifetimes from config (D-504): the idle window each
/// token gets and the absolute cap the whole family obeys.
fn refresh_lifetimes(state: &AppState) -> refresh::RefreshLifetimes {
    refresh::RefreshLifetimes {
        idle_secs: state.config.refresh_token_expiry_secs(),
        absolute_secs: state.config.refresh_absolute_lifetime_secs(),
    }
}

/// A user may have been created while an organization/global notification
/// fan-out was in progress. Queue the idempotent catch-up job; notification
/// eventual consistency is allowed, but the race must not be permanent.
async fn enqueue_notification_backfill(state: &AppState, user_id: Uuid, flow: &str) {
    if let Err(error) = attome_jobs::enqueue_on_pool(
        &state.db,
        EngineJob::BackfillRecipientForNewUser { user_id },
    )
    .await
    {
        tracing::warn!(flow, %error, "auth: failed to enqueue notification recipient backfill");
    }
}

/// Sign out
///
/// Invalidates the presented session server-side (Plan 1.6a): denylists the
/// access token's `jti` for its remaining lifetime and revokes the refresh
/// token row, then clears both cookies. Malformed/absent/already-expired
/// tokens are not an error — logout always succeeds. A session that came
/// from an OIDC provider with an end-session endpoint answers its URL as
/// `redirect` (Q1-T10), and the browser goes there next.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Logout)])))),
    responses(
        (status = 200, description = "Signed out; `redirect`, when present, is the provider's sign-out page", body = LogoutResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn logout(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let secure = state.config.auth.secure_cookies;
    // Whose session ended: the access token's subject, or else the owner of
    // the refresh token this call actually revoked. A logout that identifies
    // no one (no or invalid cookies, an already-revoked refresh token) ends no
    // session and writes no event.
    let mut access_subject: Option<Uuid> = None;
    if let Some(token) = cookie::extract_session(&headers, secure)
        && let Ok(claims) = attome_auth::validate_token(
            &token,
            &state.secrets.load().jwt_secret,
            &state.config.auth.jwt_issuer,
            state.config.jwt_audience(),
        )
    {
        let remaining = claims.exp - Utc::now().timestamp();
        // BAU-9 / OD-1 (D-625) — the denylist lives on the **coordination**
        // pool, not the cache pool. Its correctness rests on the *absence* of a
        // key meaning "not revoked", and the cache role is the one an operator
        // may put an eviction policy on or flush; D-161 placed it on the cache
        // role without weighing that. All three sites move together — this
        // write, the admin revoke in `attome-security`, and the authn read in
        // `attome-attome::middleware::auth` — because a write on one pool and a
        // read on the other is worse than either.
        revocation::revoke(
            revocation::RevocationStore::choose(&state.redis_coordination, &state.db),
            claims.jti,
            remaining,
        )
        .await?;
        access_subject = Some(claims.sub);
    }
    // A revoked refresh family and its `Logout` event commit together
    // (hook inside attome-auth's revocation transaction, D-062).
    let mut refresh_owner: Option<Uuid> = None;
    let mut oidc_provider: Option<String> = None;
    if let Some(token) = cookie::extract_refresh(&headers, secure) {
        let hook = account_event_hook(
            auditor.service(),
            MandatoryCategory::Security,
            AuditOperation::Logout,
            "user_account",
            "logout",
        );
        if let Some(revoked) =
            refresh::revoke_session_with(&state.db, &token, &state.pepper_ring(), &hook).await?
        {
            refresh_owner = Some(revoked.user_id);
            oidc_provider = revoked.oidc_provider;
        }
    }
    // Only the access token was revoked: a Redis denylist entry, no database
    // mutation to share a transaction with, so the event is written after it.
    if refresh_owner.is_none()
        && let Some(user_id) = access_subject
    {
        auditor
            .write(
                SecurityEvent::new(
                    MandatoryCategory::Security,
                    AuditOperation::Logout,
                    user_id,
                    "user_account",
                    Some(user_id),
                )
                .named("logout"),
            )
            .await?;
    }

    // Clear exactly the names this build issues. BAU-3: the extra
    // unprefixed-name clears under `secure` are gone. They existed for the
    // P-cookie-csrf-hardening dual-read window, but hardening 1.1 removed the
    // read fallback (`extract_session`/`extract_refresh` read only the
    // prefixed name when `secure`), so clearing the bare name no longer
    // revokes anything a browser could still present.
    let cookies = vec![
        (
            header::SET_COOKIE,
            cookie::clear(cookie::session_cookie_name(secure), secure, "/"),
        ),
        (
            header::SET_COOKIE,
            cookie::clear(
                cookie::refresh_cookie_name(secure),
                secure,
                REFRESH_COOKIE_PATH,
            ),
        ),
    ];

    let redirect = match oidc_provider {
        Some(provider) => provider_sign_out_url(&state, &provider).await,
        None => None,
    };
    Ok((
        StatusCode::OK,
        AppendHeaders(cookies),
        Json(LogoutResponse { redirect }),
    )
        .into_response())
}

/// Q1-T10: the provider's end-session URL for a family signed in through
/// `provider`, coming back to the app. Attome's own sign-out has already
/// happened, so a provider that is gone, or whose discovery cannot be read
/// now, only costs the provider-side sign-out: logged, never an error.
async fn provider_sign_out_url(state: &AppState, provider: &str) -> Option<String> {
    let entry = state.oidc_providers.get(provider)?;
    match attome_auth::oidc::end_session_url(
        &state.redis,
        &entry.config,
        provider,
        &state.config.frontend_url(),
    )
    .await
    {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(provider, %error, "logout: the provider's end-session endpoint could not be read");
            None
        }
    }
}

/// Mints a new access token AND rotates the refresh token from a live
/// refresh cookie — no re-login needed. Bypass-listed
/// (`attome_server::middleware::bypass`): the caller has no valid access token
/// by definition when calling this.
///
/// P-session-refresh-hardening (D-129): `refresh::redeem` (not the old
/// `validate`) marks the presented token used and returns a replacement in
/// the same rotation family — reusing an already-redeemed token now revokes
/// the whole family instead of being silently accepted. Both cookies are
/// reissued together, closing the prior gap where only the access-token
/// cookie was refreshed and the same refresh cookie stayed live indefinitely.
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn refresh_session(
    State(state): State<AppState>,
    Extension(auditor): Extension<SecurityAuditor>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let secure = state.config.auth.secure_cookies;
    let token = cookie::extract_refresh(&headers, secure).ok_or(AppError::Unauthorized)?;
    let refresh_ttl = state.config.refresh_token_expiry_secs();
    // D-510 rule 2: rotation copies the family's authentication context
    // unchanged, and the new session token's `sid` names the family the
    // replacement belongs to.
    // A normal rotation writes no event. A replayed token revokes its whole
    // family, and the `Credential` + `SessionRevoked` event is written inside
    // that revocation's transaction (D-062); the request is then rejected
    // exactly as before. The presenter is unauthenticated: actor nil.
    let reuse_hook = AuditHook::new(auditor.service(), |user_id: &Uuid| {
        vec![HookEvent::Security(
            SecurityEvent::new(
                MandatoryCategory::Credential,
                AuditOperation::SessionRevoked,
                Uuid::nil(),
                "user_account",
                Some(*user_id),
            )
            .named("refresh_token_reuse"),
        )]
    });
    let redeemed = match refresh::redeem_session_outcome_with(
        &state.db,
        &state.redis,
        &token,
        refresh_lifetimes(&state),
        &state.pepper_ring(),
        &reuse_hook,
    )
    .await?
    {
        refresh::RedeemOutcome::Rotated(redeemed) => redeemed,
        refresh::RedeemOutcome::ReuseRevoked { .. } => return Err(AppError::Unauthorized),
    };
    let user_id = redeemed.user_id;
    let new_refresh_token = redeemed.bearer;

    let access_token = accounts::issue_access_token(
        &state.db,
        user_id,
        redeemed.family_id,
        &state.secrets.load().jwt_secret,
        &state.config.auth.jwt_issuer,
        state.config.jwt_audience(),
        state.config.access_token_expiry_secs() as i64,
    )
    .await?;
    let session_cookie = cookie::build(
        cookie::session_cookie_name(secure),
        &access_token,
        state.config.access_token_expiry_secs(),
        secure,
        "/",
    );
    let refresh_cookie = cookie::build(
        cookie::refresh_cookie_name(secure),
        &new_refresh_token,
        refresh_ttl as u64,
        secure,
        REFRESH_COOKIE_PATH,
    );

    Ok((
        StatusCode::OK,
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, refresh_cookie),
        ]),
        Json(AuthResponse { user_id }),
    )
        .into_response())
}

/// The current session
///
/// The Angular client's sole source of "am I logged in" truth
/// (P-session-refresh-hardening, D-129) — bootstraps from this call at app
/// init instead of trusting a localStorage marker. Protected (NOT
/// bypass-listed): rides `AuthnLayer` like any other route, so a 401 here IS
/// the "not logged in" signal. Enumerated columns (guidelines §4) — never
/// `SELECT *` even for a single-row self-lookup.
#[utoipa::path(
    get,
    path = "/api/v1/auth/session",
    tag = "auth",
    responses(
        (status = 200, description = "Success", body = SessionInfo),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn session_info(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
) -> Result<Json<SessionInfo>, AppError> {
    // Same live predicate as every other `user_account` reader
    // (`is_active IS NULL` is legacy-active, D-005): a disabled account's
    // still-valid cookie must not resolve to a profile here either.
    let email: Option<String> = sqlx::query_scalar(
        "SELECT email FROM user_account
         WHERE id = $1 AND (is_active IS NULL OR is_active = TRUE)",
    )
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;
    let email = email.ok_or(AppError::Unauthorized)?;
    Ok(Json(SessionInfo {
        user_id: claims.sub,
        email,
    }))
}

/// My linked identities
///
/// P-federation-linking-policy §4.3(a) UI support — self-scoped read of the
/// caller's own linked federated identities, backing the `/settings/security`
/// page's "already linked" state so it doesn't have to blindly offer every
/// configured OIDC provider as unlinked. `claims.sub` is always the
/// caller's own id (never a path/query parameter), so no additional
/// authorization check is needed beyond the ordinary `AuthnLayer`/`AuthzLayer`
/// this protected route already rides.
#[utoipa::path(
    get,
    path = "/api/v1/auth/identity-links",
    tag = "auth",
    responses(
        (status = 200, description = "Success", body = Vec<IdentityLinkInfo>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn identity_links(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
) -> Result<Json<Vec<IdentityLinkInfo>>, AppError> {
    let mut out: Vec<IdentityLinkInfo> = Vec::new();

    // Google links via user_account.google_sub directly, not
    // user_identity (D-072's legacy shape) — reported as a synthetic
    // entry so this page doesn't have to special-case Google to know it's
    // linked. No linked_at: there's no per-link timestamp column for it.
    let google_email: Option<String> = sqlx::query_scalar(
        "SELECT email FROM user_account
         WHERE id = $1 AND google_sub IS NOT NULL
           AND (is_active IS NULL OR is_active = TRUE)",
    )
    .bind(claims.sub)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(email) = google_email {
        out.push(IdentityLinkInfo {
            provider_key: "google".to_string(),
            email,
            linked_at: None,
        });
    }

    let links = attome_security::accounts::list_identities_for_user(&state.db, claims.sub).await?;
    out.extend(
        links
            .into_iter()
            .map(|(provider_key, email, linked_at)| IdentityLinkInfo {
                provider_key,
                email,
                linked_at: Some(linked_at),
            }),
    );
    Ok(Json(out))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(logout, refresh_session, session_info, identity_links))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
