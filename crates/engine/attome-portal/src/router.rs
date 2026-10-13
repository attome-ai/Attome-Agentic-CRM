//! The portal's own HTTP surface (D-573 item 3): `/{keyword}/api/v1/…`.
//!
//! Mounted by `crates/server` through `ServerBuilder::add_audience_bundle`, so
//! staff authn, authz, CSRF, the per-user rate limit and idempotency never
//! see these routes, and this module authenticates them itself:
//!
//! - **Portal resolution.** The keyword must name a live, enabled portal with
//!   users, on a deployment licensed for `portal`. Anything else, including an
//!   anonymous portal, is the same 404, so the routes reveal nothing.
//! - **Session.** The per-portal session cookie must hold a `PortalSession`
//!   token for this portal's audience, and [`auth::resolve_principal`] must
//!   accept it (live `active` account, current epoch, live refresh family).
//! - **Cross-site requests.** Every request that carries a portal cookie must
//!   come from the same origin (`Sec-Fetch-Site`) or an allowed `Origin`.
//! - **MFA required.** Until an enrolled authenticator exists, a session on a
//!   portal whose `mfa_policy` is `required` reaches only the MFA and logout
//!   routes.
//!
//! - **Budgets (R10).** Login, reset and invitation routes are rate limited
//!   per portal and per account in Redis, failing closed, on top of the
//!   inherited IP-only pre-auth limit.
//! - **Records.** `/{keyword}/api/v1/records/{entity}` runs
//!   `PortalSession → PortalContext → AccessPlan → shared entity engine`
//!   ([`crate::context`], `attome_records::access_plan`). No staff
//!   `SecurityContext` exists anywhere on this path.
//!
//! Handlers stay thin: parse, open a transaction, call the engine, write the
//! D-542 security event in the same transaction, commit, respond. A known
//! portal user is the event's actor with `Initiator::PortalUser` (D-576
//! item 6, D-579), so the id can never be read as a staff id; an unknown
//! caller (a failed login for an unknown address) has a nil actor.

use std::collections::HashMap;
use std::sync::Arc;

use attome_audit::security::{
    MandatoryCategory, SecurityAuditor, SecurityEvent, write_security_event, x_audit,
};
use attome_audit::{AuditCategory, AuditOperation, AuditOutcome, AuditRequestContext};
use attome_core::EngineState;
use attome_records::access_plan::{self, AccessPlan, PortalListQuery, PortalRecord};
use attome_types::PaginatedResponse;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use tracing::Instrument;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{self, DisableMfa, LoginOutcome, PortalPrincipal};
use crate::cache::{self, PortalCache, PortalEntry};
use crate::provision::PortalDetail;
use crate::refresh::{self, Rotation};
use crate::session;
use crate::telemetry;

mod account;
mod metadata;
mod oidc;
pub(crate) mod trusted;
mod uploads;

const ENTITY: &str = "webportal_user";

// ── Plumbing ──────────────────────────────────────────────────────────────────

fn licensed(state: &EngineState) -> bool {
    let license = state.license.load();
    license.require(attome_modules::MODULE_PORTAL).is_ok()
}

/// The portal a request names and its auth policy, or the uniform 404.
/// Inside [`gate`] this is the entry the gate already resolved (G-9: from the
/// portal cache when the access version is known); outside it, PostgreSQL.
async fn portal_entry_for(
    state: &EngineState,
    keyword: &str,
) -> Result<Arc<PortalEntry>, AppError> {
    if !licensed(state) {
        return Err(AppError::NotFound);
    }
    let keyword = keyword.to_ascii_lowercase();
    let resolved = RESOLVED
        .try_with(|r| (r.keyword == keyword).then(|| r.entry.clone()))
        .ok()
        .flatten();
    let entry = match resolved {
        Some(entry) => entry,
        None => cache::load_portal_entry(&state.base.db, &keyword)
            .await?
            .map(Arc::new),
    }
    .ok_or(AppError::NotFound)?;
    tracing::Span::current().record("webportal_id", tracing::field::display(entry.detail.id));
    Ok(entry)
}

/// The portal a request names, or the uniform 404.
async fn portal_for(state: &EngineState, keyword: &str) -> Result<PortalDetail, AppError> {
    Ok(portal_entry_for(state, keyword).await?.detail.clone())
}

fn secure_cookies(state: &EngineState) -> bool {
    state.base.config.auth.secure_cookies
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    attome_auth::cookie::extract(headers, name)
}

/// Requests carrying a portal cookie must be same-origin (or from an allowed
/// origin). A request with neither header and no portal cookie (a first login
/// from a non-browser client) is allowed; one with a cookie is not.
fn check_same_origin(
    state: &EngineState,
    portal: &PortalDetail,
    headers: &HeaderMap,
) -> Result<(), AppError> {
    let names = session::cookie_names(&portal.keyword, secure_cookies(state));
    let carries_cookie =
        cookie(headers, &names.session).is_some() || cookie(headers, &names.refresh).is_some();
    if !carries_cookie {
        return Ok(());
    }
    let fetch_site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    if matches!(fetch_site, Some("same-origin" | "none")) {
        return Ok(());
    }
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    if portal_origin_allowed(origin, &state.base.config) {
        Ok(())
    } else {
        telemetry::rejected(telemetry::REJECT_ORIGIN);
        Err(AppError::Forbidden)
    }
}

/// G-10 / D-585: once portal hosts are configured, a portal cookie is
/// accepted only from a portal host origin, never from anything on the staff
/// CORS allow-list. Without host sets (development, and deployments that
/// haven't split yet) the shared allow-list still applies.
fn portal_origin_allowed(origin: Option<&str>, config: &attome_config::AppConfig) -> bool {
    let portal_hosts = &config.deployment.portal_hosts;
    if portal_hosts.is_empty() {
        return attome_server::middleware::csrf::origin_is_allowed(
            origin,
            &config.allowed_origins(),
        );
    }
    origin_on_hosts(origin, portal_hosts, config.auth.secure_cookies)
}

/// `scheme://host[:port]` whose host is one of `hosts`; `https` only when
/// cookies are secure (plain `http` is a development setting).
fn origin_on_hosts(origin: Option<&str>, hosts: &[String], secure: bool) -> bool {
    let Some((scheme, rest)) = origin.and_then(|o| o.split_once("://")) else {
        return false;
    };
    if scheme != "https" && (secure || scheme != "http") {
        return false;
    }
    let host = rest.split(':').next().unwrap_or_default();
    !rest.contains('/') && hosts.iter().any(|h| h == host)
}

/// Resolves the session. `allow_enrollment_only` admits a session that must
/// still enroll MFA (the MFA and logout routes); every other route refuses it.
async fn authenticate(
    state: &EngineState,
    portal: &PortalDetail,
    headers: &HeaderMap,
    allow_enrollment_only: bool,
) -> Result<PortalPrincipal, AppError> {
    check_same_origin(state, portal, headers)?;
    let names = session::cookie_names(&portal.keyword, secure_cookies(state));
    let token = cookie(headers, &names.session).ok_or(AppError::Unauthorized)?;
    let ring = state.base.secrets.load().jwt_secret.clone();
    let (claims, sid) =
        session::validate_access(&token, &ring, &state.base.config.auth.jwt_issuer, portal.id)?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let Some(principal) =
        auth::resolve_principal(&mut conn, portal, claims.sub, claims.epoch, sid.0).await?
    else {
        // A correctly signed token the account no longer admits: stale
        // epoch, ended refresh family, or a disabled account (R4).
        telemetry::rejected(telemetry::REJECT_EPOCH);
        return Err(AppError::Unauthorized);
    };
    tracing::Span::current().record("portal_user_id", tracing::field::display(principal.user_id));
    if principal.mfa_enrollment_required && !allow_enrollment_only {
        return Err(AppError::Forbidden);
    }
    Ok(principal)
}

fn set_cookie(response: &mut Response, value: String) -> Result<(), AppError> {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value).map_err(AppError::internal)?,
    );
    Ok(())
}

fn session_cookies(
    state: &EngineState,
    portal: &PortalDetail,
    access: &str,
    refresh_bearer: &str,
    response: &mut Response,
) -> Result<(), AppError> {
    let secure = secure_cookies(state);
    let names = session::cookie_names(&portal.keyword, secure);
    set_cookie(
        response,
        attome_auth::cookie::build(
            &names.session,
            access,
            session::ACCESS_TTL_SECS as u64,
            secure,
            &session::session_cookie_path(&portal.keyword),
        ),
    )?;
    set_cookie(
        response,
        attome_auth::cookie::build(
            &names.refresh,
            refresh_bearer,
            session::REFRESH_IDLE_SECS as u64,
            secure,
            &session::refresh_cookie_path(&portal.keyword),
        ),
    )
}

fn clear_cookies(
    state: &EngineState,
    portal: &PortalDetail,
    response: &mut Response,
) -> Result<(), AppError> {
    let secure = secure_cookies(state);
    let names = session::cookie_names(&portal.keyword, secure);
    set_cookie(
        response,
        attome_auth::cookie::clear(
            &names.session,
            secure,
            &session::session_cookie_path(&portal.keyword),
        ),
    )?;
    set_cookie(
        response,
        attome_auth::cookie::clear(
            &names.refresh,
            secure,
            &session::refresh_cookie_path(&portal.keyword),
        ),
    )
}

fn mint(
    state: &EngineState,
    portal: &PortalDetail,
    user_id: Uuid,
    epoch: i32,
    family: Uuid,
) -> Result<String, AppError> {
    session::mint_access(
        &state.base.secrets.load().jwt_secret,
        &state.base.config.auth.jwt_issuer,
        portal.id,
        user_id,
        epoch,
        family,
    )
}

fn event(
    category: MandatoryCategory,
    operation: AuditOperation,
    user: Option<Uuid>,
) -> SecurityEvent {
    let event = SecurityEvent::new(category, operation, Uuid::nil(), ENTITY, user)
        .with_request_context(request_context());
    match user {
        Some(user) => event.portal_actor(user),
        None => event,
    }
}

// ── The portal router's own layers ───────────────────────────────────────────

tokio::task_local! {
    /// The current portal request's client address and browser, set by
    /// [`gate`] for the whole request so every audit row it writes carries
    /// them (G-7) without threading them through each handler.
    static REQUEST_CONTEXT: AuditRequestContext;
    /// What [`gate`] resolved for this request (G-9): the portal cache, the
    /// access version read once for the whole request (`None`: bypass the
    /// cache), and the portal the keyword names (`None`: unknown, disabled
    /// or anonymous — the uniform 404).
    static RESOLVED: Resolved;
}

#[derive(Clone)]
struct Resolved {
    cache: Arc<PortalCache>,
    version: Option<Arc<str>>,
    /// Lowercased, as portals are stored and resolved.
    keyword: String,
    entry: Option<Arc<PortalEntry>>,
}

fn request_context() -> AuditRequestContext {
    REQUEST_CONTEXT.try_with(Clone::clone).unwrap_or_default()
}

/// The first path segment: the portal keyword.
fn keyword_of(req: &Request) -> String {
    req.uri()
        .path()
        .trim_start_matches('/')
        .split('/')
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// Whether a client-address allowlist admits `client` (G-13). No policy row
/// or an empty list admits every address; a list with no resolvable client
/// address admits nothing (fail closed).
fn cidrs_admit(cidrs: Option<&[String]>, client: Option<IpAddr>) -> bool {
    match cidrs {
        None | Some([]) => true,
        Some(list) => {
            client.is_some_and(|ip| attome_server::middleware::ip_allowlist::ip_in_any(ip, list))
        }
    }
}

/// The allowlist of a portal that isn't served (disabled or anonymous, or no
/// portal at all), read from PostgreSQL: such a request ends in the uniform
/// 404 either way, but a refused address is still counted as refused.
/// `keyword` is lowercased, as portals are stored.
async fn address_admitted_unserved(
    state: &EngineState,
    keyword: &str,
    client: Option<IpAddr>,
) -> Result<bool, AppError> {
    let cidrs: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT p.allowed_cidrs FROM webportal_auth_policy p \
         JOIN webportal w ON w.id = p.webportal_id \
         WHERE w.keyword = $1 AND w.is_active IS NOT FALSE",
    )
    .bind(keyword)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(cidrs_admit(cidrs.as_deref(), client))
}

/// Outermost portal layer: resolves the client address (trusting a
/// forwarding header only from a configured proxy), reads the G-9 access
/// version and resolves the portal once for the whole request, answers a
/// refused address with the same 404 as an unknown portal (G-13), and scopes
/// the request's audit context (G-7).
///
/// The keyword is lowercased before anything is looked up, exactly as
/// [`portal_for`] resolves it, so `/CUSTOMERS/…` is checked against the
/// `customers` portal's allowlist (before G-9 the allowlist lookup compared
/// the raw segment, and a differently-cased keyword skipped it).
async fn gate(
    State((state, cache)): State<(EngineState, Arc<PortalCache>)>,
    req: Request,
    next: Next,
) -> Response {
    let client = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| {
        attome_server::middleware::client_ip::client_ip_from_parts(
            c.0.ip(),
            req.headers(),
            &state.base.config,
        )
    });
    // Plan §5: every portal span carries `webportal_id`, `portal_user_id`
    // and `request_id`; the first two are recorded once they are known
    // (`portal_for`, `authenticate`), never from the unauthenticated request.
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let span = tracing::info_span!(
        "portal_request",
        request_id = %request_id,
        webportal_id = tracing::field::Empty,
        portal_user_id = tracing::field::Empty,
    );
    let keyword = keyword_of(&req).to_ascii_lowercase();
    let resolve = async {
        let version = cache::current_version(&state.base.redis).await;
        let entry = if licensed(&state) {
            cache
                .portal(&state.base.db, &keyword, version.as_deref())
                .await?
        } else {
            None
        };
        let admitted = match &entry {
            Some(entry) => cidrs_admit(Some(&entry.policy.allowed_cidrs), client),
            None => address_admitted_unserved(&state, &keyword, client).await?,
        };
        Ok::<_, AppError>((version, entry, admitted))
    };
    let resolved = match resolve.instrument(span.clone()).await {
        Ok((_, _, false)) => {
            telemetry::rejected(telemetry::REJECT_CIDR);
            return AppError::NotFound.into_response();
        }
        Ok((version, entry, true)) => Resolved {
            cache,
            version: version.map(Arc::from),
            keyword,
            entry,
        },
        Err(e) => return e.into_response(),
    };
    let browser = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|ua| ua.chars().take(256).collect());
    let context = AuditRequestContext {
        ip_address: client.map(|ip| ip.to_string()),
        browser,
        device_type: None,
    };
    REQUEST_CONTEXT
        .scope(context, RESOLVED.scope(resolved, next.run(req)))
        .instrument(span)
        .await
}

/// Puts a valid portal session's claims in the request extensions, so the
/// platform's idempotency gate can scope an `x-idempotency-key` to the
/// portal user (G-5). Authentication itself still happens in the handler;
/// an invalid or missing session just leaves the gate a no-op.
async fn session_claims(
    State(state): State<EngineState>,
    mut req: Request,
    next: Next,
) -> Response {
    let mutating = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if mutating && req.headers().contains_key("x-idempotency-key") {
        let keyword = keyword_of(&req);
        if let Ok(portal) = portal_for(&state, &keyword).await {
            let names = session::cookie_names(&portal.keyword, secure_cookies(&state));
            if let Some(token) = cookie(req.headers(), &names.session) {
                let ring = state.base.secrets.load().jwt_secret.clone();
                if let Ok((claims, _)) = session::validate_access(
                    &token,
                    &ring,
                    &state.base.config.auth.jwt_issuer,
                    portal.id,
                ) {
                    req.extensions_mut().insert(claims);
                }
            }
        }
    }
    next.run(req).await
}

// ── Budgets (R10) ─────────────────────────────────────────────────────────────

/// Per-account and per-portal budgets, in requests per minute.
const ACCOUNT_LOGIN_RPM: i32 = 10;
const ACCOUNT_RESET_RPM: i32 = 3;
const PORTAL_AUTH_RPM: i32 = 600;
/// Record routes, per account (G-4). The portal-wide ceiling is the portal's
/// `records_rpm` setting.
const ACCOUNT_RECORD_READS_RPM: i32 = 120;
const ACCOUNT_RECORD_WRITES_RPM: i32 = 30;

/// The account key never holds the address itself (no PII in Redis keys).
fn account_key(kind: &str, portal: &PortalDetail, email: &str) -> String {
    let digest = Sha256::digest(email.trim().to_lowercase().as_bytes());
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("attome-portal:rl:{kind}:{}:{hex}", portal.id)
}

/// Fails closed: a Redis error refuses the request, like staff budgets.
async fn budget(state: &EngineState, key: String, limit: i32) -> Result<(), AppError> {
    let outcome = attome_cache::rate_limit::check(&state.base.redis_coordination, &key, limit)
        .await
        .inspect_err(|_| telemetry::rejected(telemetry::REJECT_BUDGET))?;
    if outcome.allowed {
        Ok(())
    } else {
        telemetry::rejected(telemetry::REJECT_BUDGET);
        Err(AppError::TooManyRequests {
            retry_after_secs: None,
        })
    }
}

async fn portal_budget(state: &EngineState, portal: &PortalDetail) -> Result<(), AppError> {
    budget(
        state,
        format!("attome-portal:rl:auth:{}", portal.id),
        PORTAL_AUTH_RPM,
    )
    .await
}

async fn write(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    event: SecurityEvent,
) -> Result<(), AppError> {
    let auditor = SecurityAuditor::from_state(state);
    write_security_event(tx, &auditor.service(), event).await?;
    Ok(())
}

fn validate_password(password: &str) -> Result<attome_auth::NewPassword, AppError> {
    attome_auth::NewPassword::validate(password)
}

async fn email_link(
    tx: &mut attome_db::Tx<'_>,
    kind: attome_email::delivery::EmailDeliveryKind,
    to: &str,
    content: (String, String, String),
) -> Result<(), AppError> {
    let (subject, text_body, html_body) = content;
    let delivery_id = Uuid::now_v7();
    // `user_ref` is for staff users; a portal recipient is recorded by address.
    attome_email::delivery::record_queued_in_tx(
        tx,
        delivery_id,
        kind,
        to,
        &subject,
        None,
        None,
        None,
    )
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(
        tx,
        attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: to.to_owned(),
            subject,
            text_body,
            html_body: Some(html_body),
            delivery_id: Some(delivery_id),
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
        })),
    )
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The base URL portal pages and callbacks live under. With D-585 host sets
/// configured that is the first portal host, never the staff frontend (whose
/// host doesn't serve portals at all); otherwise the shared frontend URL.
/// Every emailed portal link is built on it, the admin invitation included
/// (T-34).
pub(crate) fn portal_base_url(state: &EngineState) -> String {
    let config = &state.base.config;
    match config.deployment.portal_hosts.first() {
        Some(host) => {
            let scheme = if config.auth.secure_cookies {
                "https"
            } else {
                "http"
            };
            format!("{scheme}://{host}")
        }
        None => config.frontend_url(),
    }
}

fn link(state: &EngineState, portal: &PortalDetail, page: &str, bearer: &str) -> String {
    format!(
        "{}/{}/{page}?token={bearer}",
        portal_base_url(state),
        portal.keyword
    )
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct LoginBody {
    /// D-777: the username or the email (an email contains `@`).
    #[serde(default)]
    pub login: Option<String>,
    /// The email; kept for clients from before `login` (D-777). Ignored when
    /// `login` is set.
    #[serde(default)]
    pub email: Option<String>,
    pub password: String,
    /// The current TOTP code, when the account has MFA enrolled.
    #[serde(default)]
    pub code: Option<String>,
}

impl std::fmt::Debug for LoginBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginBody").finish_non_exhaustive()
    }
}

impl LoginBody {
    /// `login`, else `email`: the identifier to sign in with.
    fn identifier(&self) -> Result<&str, AppError> {
        self.login
            .as_deref()
            .or(self.email.as_deref())
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                AppError::Validation("login (a username or an email) is required".into())
            })
    }
}

#[derive(Serialize, ToSchema)]
pub struct PortalSessionInfo {
    pub user_id: Uuid,
    /// The portal requires MFA and this user has no usable authenticator
    /// (never enrolled, or signed in with a recovery code since): only the
    /// MFA enrollment and logout routes are available until they enrol.
    pub mfa_enrollment_required: bool,
    /// This sign-in spent a recovery code (D-588 item 1).
    pub recovery_code_used: bool,
}

impl std::fmt::Debug for PortalSessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalSessionInfo").finish_non_exhaustive()
    }
}

/// Single-use MFA recovery codes, shown once (D-588 item 1).
#[derive(Serialize, ToSchema)]
pub struct RecoveryCodes {
    pub recovery_codes: Vec<String>,
}

impl std::fmt::Debug for RecoveryCodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCodes").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct TokenPasswordBody {
    pub token: String,
    pub password: String,
}

impl std::fmt::Debug for TokenPasswordBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenPasswordBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct EmailBody {
    pub email: String,
}

impl std::fmt::Debug for EmailBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct PortalCodeBody {
    pub code: String,
}

impl std::fmt::Debug for PortalCodeBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalCodeBody").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct MfaEnrollment {
    /// Base32 secret, for manual entry.
    pub secret: String,
    /// `otpauth://` URI, for a QR code.
    pub otpauth_uri: String,
}

impl std::fmt::Debug for MfaEnrollment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaEnrollment").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct PortalMe {
    pub id: Uuid,
    pub webportal_id: Uuid,
    pub name: String,
    /// D-777: optional when the account has a username.
    pub email: Option<String>,
    /// D-777: the login username, when the account has one.
    pub username: Option<String>,
    pub mfa_enabled: bool,
    /// The profile's version: send it as `If-Match` on `PATCH /me`.
    pub row_version: i64,
    /// The fields this portal lets its users edit, with their values (empty
    /// when none are editable).
    #[schema(value_type = HashMap<String, serde_json::Value>)]
    pub profile: serde_json::Map<String, Value>,
}

impl std::fmt::Debug for PortalMe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalMe").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct PortalAck {
    pub ok: bool,
}

impl std::fmt::Debug for PortalAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalAck").finish_non_exhaustive()
    }
}

fn mfa_required_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "mfa_required", "message": "a TOTP code is required"})),
    )
        .into_response()
}

// ── Routes ────────────────────────────────────────────────────────────────────

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/login",
    operation_id = "portal_login",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = LoginBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Login), (AuditCategory::Security, AuditOperation::FailedLogin)])))),
    responses(
        (status = 200, description = "Logged in; portal session cookies set", body = PortalSessionInfo),
        (status = 401, description = "Invalid credentials, or `mfa_required`", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn login(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<LoginBody>,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let login_id = body.identifier()?;
    budget(
        &state,
        account_key("login", &portal, login_id),
        ACCOUNT_LOGIN_RPM,
    )
    .await?;
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let outcome = auth::login(
        &mut tx,
        &state.base.pepper_ring(),
        &mfa_ring,
        &portal,
        login_id,
        &body.password,
        body.code.as_deref(),
    )
    .await?;
    match outcome {
        LoginOutcome::Success {
            user_id,
            epoch,
            family,
            mfa_enrollment_required,
            recovery_code_used,
        } => {
            write(
                &state,
                &mut tx,
                event(
                    MandatoryCategory::Security,
                    AuditOperation::Login,
                    Some(user_id),
                )
                .named(if recovery_code_used {
                    "portal login with an MFA recovery code"
                } else {
                    "portal login"
                })
                .outcome(AuditOutcome::Succeeded),
            )
            .await?;
            // Tell the account's owner, so a stolen code can't be used
            // quietly (D-588 item 1), at the account's own address (D-777:
            // never the typed identifier; an account may have no email).
            let owner_email: Option<String> = if recovery_code_used {
                sqlx::query_scalar("SELECT email FROM webportal_user WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(AppError::internal)?
            } else {
                None
            };
            if let Some(owner_email) = owner_email {
                email_link(
                    &mut tx,
                    attome_email::delivery::EmailDeliveryKind::Generic,
                    &owner_email.trim().to_lowercase(),
                    crate::email::notice(
                        &portal.name,
                        "a recovery code was used",
                        "Someone signed in to your account with one of your MFA recovery \
                         codes. If this wasn't you, reset your password now and contact \
                         the portal's support team.",
                    ),
                )
                .await?;
            }
            tx.commit().await.map_err(AppError::internal)?;
            telemetry::auth_outcome(telemetry::AUTH_SUCCESS);
            let access = mint(&state, &portal, user_id, epoch, family.family_id)?;
            let mut response = Json(PortalSessionInfo {
                user_id,
                mfa_enrollment_required,
                recovery_code_used,
            })
            .into_response();
            session_cookies(&state, &portal, &access, &family.bearer, &mut response)?;
            Ok(response)
        }
        LoginOutcome::MfaRequired { .. } => {
            tx.commit().await.map_err(AppError::internal)?;
            telemetry::auth_outcome(telemetry::AUTH_MFA_REQUIRED);
            Ok(mfa_required_response())
        }
        LoginOutcome::Failed { user_id } => {
            write(
                &state,
                &mut tx,
                event(
                    MandatoryCategory::Security,
                    AuditOperation::FailedLogin,
                    user_id,
                )
                .named("portal login failed")
                .outcome(AuditOutcome::Failed),
            )
            .await?;
            tx.commit().await.map_err(AppError::internal)?;
            telemetry::auth_outcome(telemetry::AUTH_BAD_CREDENTIALS);
            Err(AppError::Unauthorized)
        }
        LoginOutcome::LockedOut { user_id } => {
            write(
                &state,
                &mut tx,
                event(
                    MandatoryCategory::Security,
                    AuditOperation::FailedLogin,
                    Some(user_id),
                )
                .named("portal login refused: account locked")
                .outcome(AuditOutcome::Failed),
            )
            .await?;
            tx.commit().await.map_err(AppError::internal)?;
            telemetry::auth_outcome(telemetry::AUTH_LOCKED);
            // Same response as a wrong password: the lockout is not revealed.
            Err(AppError::Unauthorized)
        }
    }
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/refresh",
    operation_id = "portal_refresh_session",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::SessionRevoked)])))),
    responses(
        (status = 200, description = "Rotated; new portal session cookies set", body = PortalSessionInfo),
        (status = 401, description = "Missing, invalid, expired or reused refresh token", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn refresh_session(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    let names = session::cookie_names(&portal.keyword, secure_cookies(&state));
    let bearer = cookie(&headers, &names.refresh).ok_or(AppError::Unauthorized)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    match refresh::rotate(&mut tx, &state.base.pepper_ring(), portal.id, &bearer).await? {
        Rotation::Rotated { issued, user_id } => {
            // The account must still be allowed a session on this portal.
            let row: Option<(i32, bool, bool)> = sqlx::query_as(
                "SELECT c.auth_epoch, c.mfa_enabled, c.mfa_reenroll_required \
                 FROM webportal_user u \
                 JOIN webportal_credential c ON c.webportal_user_id = u.id \
                 WHERE u.id = $1 AND u.webportal_ref = $2 AND u.is_active IS NOT FALSE \
                   AND u.status = 'active'",
            )
            .bind(user_id)
            .bind(portal.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            let Some((epoch, mfa_enabled, reenroll)) = row else {
                refresh::revoke_family(&mut tx, issued.family_id).await?;
                tx.commit().await.map_err(AppError::internal)?;
                return Err(AppError::Unauthorized);
            };
            tx.commit().await.map_err(AppError::internal)?;
            let access = mint(&state, &portal, user_id, epoch, issued.family_id)?;
            let mut response = Json(PortalSessionInfo {
                user_id,
                mfa_enrollment_required: auth::enrollment_required(&portal, mfa_enabled, reenroll),
                recovery_code_used: false,
            })
            .into_response();
            session_cookies(&state, &portal, &access, &issued.bearer, &mut response)?;
            Ok(response)
        }
        Rotation::Reused { family_id, user_id } => {
            write(
                &state,
                &mut tx,
                event(
                    MandatoryCategory::Credential,
                    AuditOperation::SessionRevoked,
                    Some(user_id),
                )
                .named(format!(
                    "portal refresh token reused; family {family_id} revoked"
                ))
                .outcome(AuditOutcome::Succeeded),
            )
            .await?;
            tx.commit().await.map_err(AppError::internal)?;
            Err(AppError::Unauthorized)
        }
        Rotation::Invalid => Err(AppError::Unauthorized),
    }
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/logout",
    operation_id = "portal_logout",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Logout)])))),
    responses(
        (status = 204, description = "Session ended; cookies cleared"),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn logout(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    // A stale or missing session still gets its cookies cleared.
    if let Ok(principal) = authenticate(&state, &portal, &headers, true).await {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        refresh::revoke_family(&mut tx, principal.family_id).await?;
        write(
            &state,
            &mut tx,
            event(
                MandatoryCategory::Security,
                AuditOperation::Logout,
                Some(principal.user_id),
            )
            .named("portal logout")
            .outcome(AuditOutcome::Succeeded),
        )
        .await?;
        tx.commit().await.map_err(AppError::internal)?;
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    clear_cookies(&state, &portal, &mut response)?;
    Ok(response)
}

#[utoipa::path(
    post,
    operation_id = "portal_accept_invitation",
    path = "/{keyword}/api/v1/auth/invitation/accept",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = TokenPasswordBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Password set; the account is active and its email verified"),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Invalid or expired invitation, or the password fails policy", body = ErrorResponse),
    ),
)]
async fn accept_invitation(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<TokenPasswordBody>,
) -> Result<StatusCode, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let password = validate_password(&body.password)?;
    let hash = attome_auth::hash_password_async(password).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some(user_id) = auth::accept_invitation(
        &mut tx,
        &state.base.pepper_ring(),
        &portal,
        &body.token,
        &hash,
    )
    .await?
    else {
        return Err(AppError::Validation(
            "the invitation link is invalid or has expired".into(),
        ));
    };
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Update,
            Some(user_id),
        )
        .named("portal invitation accepted; password set")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/reset-request",
    operation_id = "portal_reset_request",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = EmailBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::PasswordReset)])))),
    responses(
        (status = 200, description = "Always the same answer, whether or not the address has an account", body = PortalAck),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 503, description = "Email is not configured on this deployment", body = ErrorResponse),
    ),
)]
async fn reset_request(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EmailBody>,
) -> Result<Json<PortalAck>, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    if !state.base.config.email.enabled {
        return Err(AppError::FeatureUnavailable);
    }
    portal_budget(&state, &portal).await?;
    // Over budget answers exactly like success: the throttle says nothing
    // about whether the address has an account.
    if budget(
        &state,
        account_key("reset", &portal, &body.email),
        ACCOUNT_RESET_RPM,
    )
    .await
    .is_err()
    {
        return Ok(Json(PortalAck { ok: true }));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if let Some(issued) =
        auth::request_reset(&mut tx, &state.base.pepper_ring(), &portal, &body.email).await?
    {
        let link = link(&state, &portal, "reset-password", &issued.token.bearer);
        email_link(
            &mut tx,
            attome_email::delivery::EmailDeliveryKind::PasswordReset,
            &issued.email,
            crate::email::password_reset(&portal.name, &link),
        )
        .await?;
        write(
            &state,
            &mut tx,
            event(
                MandatoryCategory::Credential,
                AuditOperation::PasswordReset,
                Some(issued.user_id),
            )
            .named("portal password reset requested")
            .outcome(AuditOutcome::Succeeded),
        )
        .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(PortalAck { ok: true }))
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/reset-confirm",
    operation_id = "portal_reset_confirm",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = TokenPasswordBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::PasswordReset)])))),
    responses(
        (status = 204, description = "Password reset; every existing session ended"),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Invalid or expired link, or the password fails policy", body = ErrorResponse),
    ),
)]
async fn reset_confirm(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<TokenPasswordBody>,
) -> Result<StatusCode, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    check_same_origin(&state, &portal, &headers)?;
    portal_budget(&state, &portal).await?;
    let password = validate_password(&body.password)?;
    let hash = attome_auth::hash_password_async(password).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some(user_id) = auth::confirm_reset(
        &mut tx,
        &state.base.pepper_ring(),
        &portal,
        &body.token,
        &hash,
    )
    .await?
    else {
        return Err(AppError::Validation(
            "the reset link is invalid or has expired".into(),
        ));
    };
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::PasswordReset,
            Some(user_id),
        )
        .named("portal password reset completed")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    operation_id = "portal_mfa_enroll",
    path = "/{keyword}/api/v1/auth/mfa/enroll",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "A pending TOTP secret; confirm it with a code", body = MfaEnrollment),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn mfa_enroll(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<MfaEnrollment>, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, true).await?;
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // The authenticator app's account label: the email, or the username of
    // an account without one (D-777).
    let label: String =
        sqlx::query_scalar("SELECT COALESCE(email, username) FROM webportal_user WHERE id = $1")
            .bind(principal.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let enrollment = auth::enroll_mfa(&mut tx, &mfa_ring, &principal, &label, &portal.name).await?;
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            Some(principal.user_id),
        )
        .named("portal mfa enrollment started")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(MfaEnrollment {
        secret: enrollment.secret,
        otpauth_uri: enrollment.otpauth_uri,
    }))
}

#[utoipa::path(
    post,
    operation_id = "portal_mfa_confirm",
    path = "/{keyword}/api/v1/auth/mfa/confirm",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = PortalCodeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::MfaEnrolled)])))),
    responses(
        (status = 200, description = "MFA enabled; the new recovery codes, shown once", body = RecoveryCodes),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Wrong code or no pending enrollment", body = ErrorResponse),
    ),
)]
async fn mfa_confirm(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PortalCodeBody>,
) -> Result<Json<RecoveryCodes>, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, true).await?;
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let Some(recovery_codes) = auth::confirm_mfa(
        &mut tx,
        &mfa_ring,
        &state.base.pepper_ring(),
        &principal,
        &body.code,
    )
    .await?
    else {
        return Err(AppError::Validation(
            "the code is wrong or no enrollment is pending".into(),
        ));
    };
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::MfaEnrolled,
            Some(principal.user_id),
        )
        .named("portal mfa enabled")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(RecoveryCodes { recovery_codes }))
}

#[utoipa::path(
    post,
    path = "/{keyword}/api/v1/auth/mfa/recovery-codes",
    operation_id = "portal_mfa_recovery_codes",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = PortalCodeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Rotate)])))),
    responses(
        (status = 200, description = "A new set of recovery codes, shown once; the old set is void", body = RecoveryCodes),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Wrong authenticator code, or MFA is not enabled", body = ErrorResponse),
    ),
)]
async fn mfa_recovery_codes(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PortalCodeBody>,
) -> Result<Json<RecoveryCodes>, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let recovery_codes = match auth::regenerate_recovery_codes(
        &mut tx,
        &mfa_ring,
        &state.base.pepper_ring(),
        &portal,
        &principal,
        &body.code,
    )
    .await?
    {
        auth::RegenerateRecoveryCodes::Codes(codes) => codes,
        auth::RegenerateRecoveryCodes::WrongCode => {
            return Err(AppError::Validation(
                "the authenticator code is wrong, or MFA is not enabled".into(),
            ));
        }
    };
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::Rotate,
            Some(principal.user_id),
        )
        .named("portal mfa recovery codes regenerated")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(RecoveryCodes { recovery_codes }))
}

#[utoipa::path(
    post,
    operation_id = "portal_mfa_disable",
    path = "/{keyword}/api/v1/auth/mfa/disable",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    request_body = PortalCodeBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::MfaDisabled)])))),
    responses(
        (status = 204, description = "MFA disabled"),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 422, description = "Wrong code, or the portal requires MFA", body = ErrorResponse),
    ),
)]
async fn mfa_disable(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PortalCodeBody>,
) -> Result<StatusCode, AppError> {
    let portal = portal_for(&state, &keyword).await?;
    let principal = authenticate(&state, &portal, &headers, false).await?;
    let mfa_ring = state.base.secrets.load().mfa_encryption_key.clone();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    match auth::disable_mfa(&mut tx, &mfa_ring, &portal, &principal, &body.code).await? {
        DisableMfa::Disabled => {}
        DisableMfa::WrongCode => {
            return Err(AppError::Validation("the code is wrong".into()));
        }
        DisableMfa::Required => {
            return Err(AppError::Validation(
                "this portal requires MFA; it cannot be disabled".into(),
            ));
        }
    }
    write(
        &state,
        &mut tx,
        event(
            MandatoryCategory::Credential,
            AuditOperation::MfaDisabled,
            Some(principal.user_id),
        )
        .named("portal mfa disabled")
        .outcome(AuditOutcome::Succeeded),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    operation_id = "portal_me",
    path = "/{keyword}/api/v1/me",
    tag = "auth",
    params(("keyword" = String, Path, description = "Web portal keyword")),
    responses(
        (status = 200, description = "The signed-in portal user", body = PortalMe),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "MFA enrollment required first, or cross-site request", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
    ),
)]
async fn me(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
) -> Result<Json<PortalMe>, AppError> {
    let entry = portal_entry_for(&state, &keyword).await?;
    let principal = authenticate(&state, &entry.detail, &headers, false).await?;
    Ok(Json(me_of(&state, &entry, &principal).await?))
}

/// The signed-in user's name and email (never self-editable: staff rename a
/// portal user) and their editable profile, read through the self plan.
async fn me_of(
    state: &EngineState,
    entry: &PortalEntry,
    principal: &PortalPrincipal,
) -> Result<PortalMe, AppError> {
    let (name, email, username): (String, Option<String>, Option<String>) =
        sqlx::query_as("SELECT name, email, username FROM webportal_user WHERE id = $1")
            .bind(principal.user_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    // A read writes no audit row, so the organisation is never used here.
    let plan = crate::context::self_plan(
        &state.entities.load(),
        principal,
        name.clone(),
        &entry.policy.editable_profile_fields,
        attome_core::ROOT_ORGANIZATION_ID,
    );
    let profile = access_plan::plan_get(state, &plan, principal.user_id).await?;
    Ok(PortalMe {
        id: principal.user_id,
        webportal_id: principal.webportal_id,
        name,
        email,
        username,
        mfa_enabled: principal.mfa_enabled,
        row_version: profile.row_version,
        profile: profile.data,
    })
}

#[utoipa::path(
    patch,
    operation_id = "portal_update_me",
    path = "/{keyword}/api/v1/me",
    tag = "auth",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("If-Match" = String, Header, description = "The profile's row_version from GET /me"),
    ),
    request_body = HashMap<String, serde_json::Value>,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Updated; the profile as GET /me returns it", body = PortalMe),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "A field this portal doesn't let users edit (email, status, lookups and files never are), or consent is missing", body = ErrorResponse),
        (status = 404, description = "No such portal", body = ErrorResponse),
        (status = 409, description = "Stale row_version", body = ErrorResponse),
        (status = 422, description = "Invalid value, or If-Match missing", body = ErrorResponse),
    ),
)]
async fn update_me(
    State(state): State<EngineState>,
    Path(keyword): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<PortalMe>, AppError> {
    let caller = data_caller(&state, &keyword, &headers, true).await?;
    let expected = if_match(&headers, true)?.unwrap_or_default();
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let name: String = sqlx::query_scalar("SELECT name FROM webportal_user WHERE id = $1")
        .bind(caller.principal.user_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    // The profile edit's audit row carries the owning team's organisation,
    // like a portal record write, so org-scoped staff audit views show it.
    let org = crate::context::owning_org(&mut conn, &caller.entry.detail).await?;
    drop(conn);
    let mut plan = crate::context::self_plan(
        &state.entities.load(),
        &caller.principal,
        name,
        &caller.entry.policy.editable_profile_fields,
        org,
    );
    if !plan.can_update {
        return Err(AppError::Forbidden);
    }
    plan.request_context = request_context();
    access_plan::plan_update(&state, &plan, caller.principal.user_id, expected, body).await?;
    Ok(Json(me_of(&state, &caller.entry, &caller.principal).await?))
}

// ── Records: PortalSession → PortalContext → AccessPlan → engine ─────────────

/// What a record route needs: the plan, and the portal's page-size cap.
struct RecordAccess {
    plan: AccessPlan,
    page_size_cap: i64,
}

/// A signed-in caller of a data route (records, metadata, profile), past the
/// budgets and the consent check: one path for all of them (I-18).
struct Caller {
    entry: Arc<PortalEntry>,
    principal: PortalPrincipal,
}

/// The session, the budgets and consent, for a data route.
async fn data_caller(
    state: &EngineState,
    keyword: &str,
    headers: &HeaderMap,
    write: bool,
) -> Result<Caller, AppError> {
    let entry = portal_entry_for(state, keyword).await?;
    let (portal, policy) = (&entry.detail, &entry.policy);
    let principal = authenticate(state, portal, headers, false).await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    // G-4: the portal-wide ceiling, then the account's own read or write
    // budget. Both fail closed.
    budget(
        state,
        format!("attome-portal:rl:records:{}", portal.id),
        policy.records_rpm,
    )
    .await?;
    let (kind, limit) = if write {
        ("rec-write", ACCOUNT_RECORD_WRITES_RPM)
    } else {
        ("rec-read", ACCOUNT_RECORD_READS_RPM)
    };
    budget(
        state,
        format!(
            "attome-portal:rl:{kind}:{}:{}",
            portal.id, principal.user_id
        ),
        limit,
    )
    .await?;
    // G-11: while the portal requires consent, a user who hasn't accepted
    // the current terms and privacy versions can't reach records.
    if !crate::signup::has_current_consent(&mut conn, policy, principal.user_id).await? {
        return Err(AppError::Forbidden);
    }
    drop(conn);
    Ok(Caller { entry, principal })
}

/// The caller's plan for `entity`, or `None` (no role, no grant, an unknown
/// or hidden entity). `write` resolves the owning team, which `can_create`
/// needs.
async fn plan_of(
    state: &EngineState,
    caller: &Caller,
    entity: &str,
    write: bool,
) -> Result<Option<AccessPlan>, AppError> {
    let registry = state.entities.load();
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    // G-9: the role's plan template from the portal cache under the version
    // the gate read for this request; no version (or no gate), no cache.
    let resolved = RESOLVED.try_with(Clone::clone).ok();
    let cache = resolved
        .as_ref()
        .map(|r| (r.cache.as_ref(), r.version.as_deref()));
    let plan = crate::context::access_plan(
        &mut conn,
        &registry,
        &caller.entry.detail,
        &caller.principal,
        entity,
        write,
        cache,
    )
    .await?;
    Ok(plan.map(|mut plan| {
        plan.request_context = request_context();
        plan
    }))
}

/// The session, the budgets, then the plan for `entity`. No role, no grant,
/// an unknown or hidden entity: all the same 404.
async fn plan_for(
    state: &EngineState,
    keyword: &str,
    entity: &str,
    headers: &HeaderMap,
    write: bool,
) -> Result<RecordAccess, AppError> {
    let caller = data_caller(state, keyword, headers, write).await?;
    let plan = plan_of(state, &caller, entity, write)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok(RecordAccess {
        plan,
        page_size_cap: i64::from(caller.entry.policy.page_size_cap),
    })
}

fn if_match(headers: &HeaderMap, required: bool) -> Result<Option<i64>, AppError> {
    let Some(raw) = headers.get(header::IF_MATCH) else {
        return if required {
            Err(AppError::Validation(
                "If-Match is required for every update and delete".into(),
            ))
        } else {
            Ok(None)
        };
    };
    raw.to_str()
        .ok()
        .map(|s| s.trim().trim_matches('"'))
        .and_then(|s| s.parse::<i64>().ok())
        .map(Some)
        .ok_or_else(|| AppError::Validation("If-Match must be a row_version integer".into()))
}

#[utoipa::path(
    get,
    operation_id = "portal_list_records",
    path = "/{keyword}/api/v1/records/{entity}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("page" = Option<i64>, Query, description = "One-based: page 1 is the first page."),
        ("page_size" = Option<i64>, Query, description = "At most the portal's page-size cap (100 or less)"),
        ("order_by" = Option<String>, Query, description = "A filterable field"),
        ("order" = Option<String>, Query, description = "`asc` (default) or `desc`"),
    ),
    responses(
        (status = 200, description = "Records in the caller's scope; any other query key is an equality filter on a filterable field", body = PaginatedResponse<PortalRecord>),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such portal, or no access to this entity", body = ErrorResponse),
        (status = 422, description = "Unknown or non-filterable field", body = ErrorResponse),
    ),
)]
async fn list_records(
    State(state): State<EngineState>,
    Path((keyword, entity)): Path<(String, String)>,
    Query(mut params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<PaginatedResponse<PortalRecord>>, AppError> {
    let access = plan_for(&state, &keyword, &entity, &headers, false).await?;
    let page = params
        .remove("page")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let page_size = params
        .remove("page_size")
        .and_then(|v| v.parse().ok())
        .unwrap_or(access_plan::PORTAL_DEFAULT_PAGE_SIZE)
        .min(access.page_size_cap);
    let desc = params
        .remove("order")
        .is_some_and(|o| o.eq_ignore_ascii_case("desc"));
    let order_by = params.remove("order_by").map(|f| (f, desc));
    let mut filters: Vec<(String, String)> = params.into_iter().collect();
    filters.sort();
    let query = PortalListQuery {
        page,
        page_size,
        filters,
        order_by,
    };
    Ok(Json(
        access_plan::plan_list(&state, &access.plan, query).await?,
    ))
}

#[utoipa::path(
    get,
    operation_id = "portal_get_record",
    path = "/{keyword}/api/v1/records/{entity}/{id}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
    ),
    responses(
        (status = 200, description = "The record", body = PortalRecord),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "Not found or not in scope (indistinguishable)", body = ErrorResponse),
    ),
)]
async fn get_record(
    State(state): State<EngineState>,
    Path((keyword, entity, id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<Json<PortalRecord>, AppError> {
    let access = plan_for(&state, &keyword, &entity, &headers, false).await?;
    Ok(Json(access_plan::plan_get(&state, &access.plan, id).await?))
}

#[derive(Deserialize, utoipa::IntoParams)]
struct FileQuery {
    /// Which file, for a multi-file field (one of the keys the record shows).
    key: Option<String>,
}

#[utoipa::path(
    get,
    operation_id = "portal_download_record_file",
    path = "/{keyword}/api/v1/records/{entity}/{id}/files/{field}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
        ("field" = String, Path, description = "A file field the caller's role can read"),
        FileQuery,
    ),
    responses(
        (status = 200, description = "A short-lived download URL (the file is served as an attachment)", body = attome_document::files::DownloadUrlResponse),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "No such record, not in scope, a field the caller can't read, or no file (indistinguishable)", body = ErrorResponse),
        (status = 422, description = "A multi-file field without ?key=, or a stored key outside this record's own prefix (only on an in-scope record)", body = ErrorResponse),
    ),
)]
async fn download_record_file(
    State(state): State<EngineState>,
    Path((keyword, entity, id, field)): Path<(String, String, Uuid, String)>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
) -> Result<Json<attome_document::files::DownloadUrlResponse>, AppError> {
    let access = plan_for(&state, &keyword, &entity, &headers, false).await?;
    let key =
        access_plan::plan_file_key(&state, &access.plan, id, &field, query.key.as_deref()).await?;
    Ok(Json(
        attome_document::files::record_file_download(&state, &access.plan.entity, id, &field, &key)
            .await?,
    ))
}

#[utoipa::path(
    post,
    operation_id = "portal_create_record",
    path = "/{keyword}/api/v1/records/{entity}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("x-idempotency-key" = Option<String>, Header, description = "Replays the first result for a repeated key instead of creating twice"),
    ),
    request_body = HashMap<String, serde_json::Value>,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Entity, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created; owned by the portal's team, recording the portal user", body = PortalRecord),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "Not allowed to create, or a field is not writable", body = ErrorResponse),
        (status = 404, description = "No such portal, or no access to this entity", body = ErrorResponse),
        (status = 422, description = "Invalid, or the record would be outside the caller's scope", body = ErrorResponse),
    ),
)]
async fn create_record(
    State(state): State<EngineState>,
    Path((keyword, entity)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<PortalRecord>), AppError> {
    let access = plan_for(&state, &keyword, &entity, &headers, true).await?;
    let record = access_plan::plan_create(&state, &access.plan, body).await?;
    Ok((StatusCode::CREATED, Json(record)))
}

#[utoipa::path(
    patch,
    operation_id = "portal_update_record",
    path = "/{keyword}/api/v1/records/{entity}/{id}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
        ("If-Match" = String, Header, description = "The record's row_version"),
    ),
    request_body = HashMap<String, serde_json::Value>,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Entity, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Updated", body = PortalRecord),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 403, description = "A field is not writable", body = ErrorResponse),
        (status = 404, description = "Not found or not in scope (indistinguishable)", body = ErrorResponse),
        (status = 409, description = "Stale row_version", body = ErrorResponse),
        (status = 422, description = "Invalid, or the change would move the record out of scope", body = ErrorResponse),
    ),
)]
async fn update_record(
    State(state): State<EngineState>,
    Path((keyword, entity, id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<PortalRecord>, AppError> {
    let expected = if_match(&headers, true)?.unwrap_or_default();
    let access = plan_for(&state, &keyword, &entity, &headers, true).await?;
    Ok(Json(
        access_plan::plan_update(&state, &access.plan, id, expected, body).await?,
    ))
}

#[utoipa::path(
    delete,
    operation_id = "portal_delete_record",
    path = "/{keyword}/api/v1/records/{entity}/{id}",
    tag = "entity",
    params(
        ("keyword" = String, Path, description = "Web portal keyword"),
        ("entity" = String, Path, description = "Entity logical name"),
        ("id" = Uuid, Path, description = "Record id"),
        ("If-Match" = String, Header, description = "The record's row_version (required)"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Entity, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "No valid portal session", body = ErrorResponse),
        (status = 404, description = "Not found or not in scope (indistinguishable)", body = ErrorResponse),
        (status = 409, description = "Stale row_version, or the entity has dependents", body = ErrorResponse),
    ),
)]
async fn delete_record(
    State(state): State<EngineState>,
    Path((keyword, entity, id)): Path<(String, String, Uuid)>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let expected = if_match(&headers, true)?;
    let access = plan_for(&state, &keyword, &entity, &headers, true).await?;
    access_plan::plan_delete(&state, &access.plan, id, expected).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The portal router as `crates/server` mounts it, with its own layers
/// (outermost first): [`gate`] (G-9 access version and portal resolution,
/// client-address allowlist, audit context), [`session_claims`], then the
/// platform idempotency gate. Mount it with
/// `ServerBuilder::add_audience_bundle`. Owns this node's portal cache
/// ([`crate::cache`]).
pub fn app(state: EngineState) -> Router {
    let cache = Arc::new(PortalCache::default());
    routes()
        .route_layer(middleware::from_fn_with_state(
            state.base.clone(),
            attome_server::middleware::idempotency::idempotency,
        ))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            session_claims,
        ))
        .route_layer(middleware::from_fn_with_state((state.clone(), cache), gate))
        .with_state(state)
}

/// The portal router, state not yet applied, **without** its layers: use
/// [`app`] to mount it. `crates/server` applies the
/// state and mounts it with `ServerBuilder::add_audience_bundle`, never as an
/// ordinary bundle and never through `EngineModel::routes` (which would put it
/// behind staff authn).
pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/{keyword}/api/v1/auth/login", post(login))
        .route("/{keyword}/api/v1/auth/refresh", post(refresh_session))
        .route("/{keyword}/api/v1/auth/logout", post(logout))
        .route(
            "/{keyword}/api/v1/auth/invitation/accept",
            post(accept_invitation),
        )
        .route("/{keyword}/api/v1/auth/reset-request", post(reset_request))
        .route("/{keyword}/api/v1/auth/reset-confirm", post(reset_confirm))
        .route("/{keyword}/api/v1/auth/mfa/enroll", post(mfa_enroll))
        .route("/{keyword}/api/v1/auth/mfa/confirm", post(mfa_confirm))
        .route("/{keyword}/api/v1/auth/mfa/disable", post(mfa_disable))
        .route(
            "/{keyword}/api/v1/auth/mfa/recovery-codes",
            post(mfa_recovery_codes),
        )
        .route("/{keyword}/api/v1/me", get(me).patch(update_me))
        .route(
            "/{keyword}/api/v1/records/{entity}",
            get(list_records).post(create_record),
        )
        .route(
            "/{keyword}/api/v1/records/{entity}/{id}",
            get(get_record).patch(update_record).delete(delete_record),
        )
        .route(
            "/{keyword}/api/v1/records/{entity}/{id}/files/{field}",
            get(download_record_file),
        )
        .merge(account::routes())
        .merge(metadata::routes())
        .merge(uploads::routes())
        .merge(oidc::routes())
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    login,
    refresh_session,
    logout,
    accept_invitation,
    reset_request,
    reset_confirm,
    mfa_enroll,
    mfa_confirm,
    mfa_disable,
    mfa_recovery_codes,
    me,
    update_me,
    list_records,
    get_record,
    download_record_file,
    create_record,
    update_record,
    delete_record
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    let mut doc = <ApiDocFragment as utoipa::OpenApi>::openapi();
    doc.merge(<account::AccountApiDoc as utoipa::OpenApi>::openapi());
    doc.merge(<metadata::MetadataApiDoc as utoipa::OpenApi>::openapi());
    doc.merge(<uploads::UploadsApiDoc as utoipa::OpenApi>::openapi());
    doc.merge(<oidc::OidcApiDoc as utoipa::OpenApi>::openapi());
    doc.merge(trusted::openapi_fragment());
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portal_origins_are_portal_hosts_only_g10() {
        let hosts = vec!["portal.example.com".to_string()];
        assert!(origin_on_hosts(
            Some("https://portal.example.com"),
            &hosts,
            true
        ));
        assert!(origin_on_hosts(
            Some("https://portal.example.com:8443"),
            &hosts,
            true
        ));
        // The staff host is never a portal origin, whatever the staff CORS
        // list says.
        assert!(!origin_on_hosts(
            Some("https://app.example.com"),
            &hosts,
            true
        ));
        assert!(!origin_on_hosts(
            Some("http://portal.example.com"),
            &hosts,
            true
        ));
        assert!(origin_on_hosts(
            Some("http://portal.example.com"),
            &hosts,
            false
        ));
        assert!(!origin_on_hosts(
            Some("https://portal.example.com.evil.test"),
            &hosts,
            true
        ));
        assert!(!origin_on_hosts(
            Some("https://portal.example.com/x"),
            &hosts,
            true
        ));
        assert!(!origin_on_hosts(None, &hosts, true));
    }
}
