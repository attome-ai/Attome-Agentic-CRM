//! D15-T1: a person's own OAuth connection to their Microsoft 365 (Graph) or
//! Google mailbox and calendar.
//!
//! **Apps.** Each provider's OAuth app is an `integration_system` row whose
//! `config` names `"oauth": "microsoft" | "google"`, its `client_id` and,
//! for Microsoft, its `tenant` (`common` by default), with the client secret
//! as the system's encrypted credential.
//!
//! **Connecting.** `POST /api/v1/me/mail-connections/{provider}/start` keeps
//! a PKCE verifier server-side for ten minutes and answers the provider's
//! sign-in URL; the provider sends the person back to
//! `GET /api/v1/me/mail-connections/{provider}/callback`, a signed-in route,
//! which checks the state is theirs, trades the code for tokens and keeps
//! them encrypted and bound to their row (Q18). Each person has at most one
//! connection per provider; connecting again replaces it.
//!
//! **Using it.** [`access_token`] gives a fresh access token, refreshing it
//! with the refresh token when it is about to expire.
//!
//! **Disconnecting** revokes the token at Google (Microsoft has no revoke
//! endpoint for a delegated token; deleting it ends Attome's use) and deletes
//! the row. Connecting and disconnecting are Credential security events.
//!
//! **Tenant-wide consent.** An administrator can ask Microsoft for the
//! tenant's consent once (`GET .../admin-consent-url`), so people are not
//! each asked to consent.

use std::sync::OnceLock;
use std::time::Duration;

use attome_audit::security::{
    ExemptReason, MandatoryCategory, SecurityEvent, SecurityTx, x_audit, x_audit_exempt,
};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::{delete, get, post},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

const PENDING_MINUTES: i64 = 10;
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
/// Refresh this long before the token expires.
const REFRESH_EARLY_SECS: i64 = 120;

/// The two providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Microsoft,
    Google,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "microsoft" => Some(Self::Microsoft),
            "google" => Some(Self::Google),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Microsoft => "microsoft",
            Self::Google => "google",
        }
    }

    /// Mail and calendar, read and send, offline (a refresh token).
    pub fn scopes(self) -> &'static str {
        match self {
            Self::Microsoft => {
                "offline_access openid email Mail.ReadWrite Mail.Send Calendars.ReadWrite"
            }
            Self::Google => {
                "openid email https://www.googleapis.com/auth/gmail.modify \
                 https://www.googleapis.com/auth/calendar"
            }
        }
    }

    fn authorize_endpoint(self, tenant: &str) -> String {
        match self {
            Self::Microsoft => {
                format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize")
            }
            Self::Google => "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
        }
    }

    fn token_endpoint(self, tenant: &str) -> String {
        match self {
            Self::Microsoft => {
                format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
            }
            Self::Google => "https://oauth2.googleapis.com/token".to_owned(),
        }
    }
}

/// A PKCE verifier: 64 random hex characters. Not pure (randomness).
pub fn new_verifier() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

/// The S256 challenge of a verifier. Pure.
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn encode(v: &str) -> String {
    url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

/// The provider's sign-in URL. Pure.
pub fn authorize_url(
    provider: Provider,
    tenant: &str,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    verifier: &str,
) -> String {
    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}\
         &code_challenge={}&code_challenge_method=S256",
        provider.authorize_endpoint(tenant),
        encode(client_id),
        encode(redirect_uri),
        encode(provider.scopes()),
        encode(state),
        challenge(verifier),
    );
    if provider == Provider::Google {
        // A refresh token every time, and the consent screen to grant it.
        url.push_str("&access_type=offline&prompt=consent");
    }
    url
}

/// Microsoft's tenant-wide admin consent URL. Pure.
pub fn admin_consent_url(tenant: &str, client_id: &str, redirect_uri: &str) -> String {
    format!(
        "https://login.microsoftonline.com/{tenant}/v2.0/adminconsent?client_id={}&scope={}&redirect_uri={}",
        encode(client_id),
        encode("https://graph.microsoft.com/.default"),
        encode(redirect_uri),
    )
}

/// A token answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub scope: String,
    /// The account's email, from the ID token when one came back.
    pub email: Option<String>,
}

/// Reads a token endpoint's answer; the provider's error code otherwise.
pub fn parse_tokens(status: u16, body: &str) -> Result<Tokens, String> {
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(json
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("token_request_failed")
            .to_owned());
    }
    let access_token = json
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "no_access_token".to_owned())?
        .to_owned();
    Ok(Tokens {
        access_token,
        refresh_token: json
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::to_owned),
        expires_in: json
            .get("expires_in")
            .and_then(Value::as_i64)
            .unwrap_or(3600),
        scope: json
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        email: json
            .get("id_token")
            .and_then(Value::as_str)
            .and_then(id_token_email),
    })
}

/// The `email` (or `preferred_username`) claim of an ID token. The token came
/// straight from the provider's token endpoint over TLS in answer to our own
/// request, so its claims are read, not re-verified. Pure.
pub fn id_token_email(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims
        .get("email")
        .or_else(|| claims.get("preferred_username"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("mail-sync"), |b| {
            b.timeout(SEND_TIMEOUT)
        })
    })
}

struct App {
    client_id: String,
    tenant: String,
    secret: String,
}

async fn app(state: &EngineState, provider: Provider) -> Result<App, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT config, credential_ref FROM integration_system \
          WHERE status = 'active' AND (is_active IS NULL OR is_active = true) \
            AND CASE WHEN config IS JSON OBJECT THEN config::jsonb ->> 'oauth' END = $1 \
          ORDER BY created_at, id LIMIT 1",
    )
    .bind(provider.as_str())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // Not configured reads as absent, like an unlicensed feature.
    let (config, credential_ref) = row.ok_or(AppError::NotFound)?;
    let config: Value = config
        .and_then(|c| serde_json::from_str(&c).ok())
        .unwrap_or(Value::Null);
    let client_id = config
        .get("client_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(AppError::NotFound)?
        .to_owned();
    let tenant = config
        .get("tenant")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("common")
        .to_owned();
    let secret = crate::credential::resolve(
        &state.base.db,
        &state.base.config.integration.credential_encryption_key,
        credential_ref.as_deref(),
    )
    .await?
    .ok_or(AppError::NotFound)?;
    Ok(App {
        client_id,
        tenant,
        secret,
    })
}

fn redirect_uri(state: &EngineState, provider: Provider) -> String {
    format!(
        "{}/api/v1/me/mail-connections/{}/callback",
        state.base.config.frontend_url().trim_end_matches('/'),
        provider.as_str()
    )
}

fn binding(id: Uuid, column: &'static str) -> attome_auth::envelope::RowBinding<'static> {
    attome_auth::envelope::RowBinding {
        table: "user_mail_connection",
        column,
        row_id: id,
    }
}

fn seal(
    state: &EngineState,
    id: Uuid,
    column: &'static str,
    plain: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::encrypt_bound(
        "integration.credential_encryption_key",
        &state.base.config.integration.credential_encryption_key,
        plain,
        binding(id, column),
    )
}

fn open(
    state: &EngineState,
    id: Uuid,
    column: &'static str,
    sealed: &str,
) -> Result<String, AppError> {
    attome_auth::envelope::decrypt_bound(
        "integration.credential_encryption_key",
        &state.base.config.integration.credential_encryption_key,
        sealed,
        binding(id, column),
    )
    .map(attome_types::secret::SecretString::into_exposed)
}

async fn token_request(
    provider: Provider,
    app: &App,
    form: &[(&str, &str)],
) -> Result<Tokens, AppError> {
    let res = client()
        .post(provider.token_endpoint(&app.tenant))
        .form(form)
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body = res.text().await.unwrap_or_default();
    parse_tokens(status, &body)
        .map_err(|code| AppError::Validation(format!("the provider refused the sign-in ({code})")))
}

/// A connection, as its owner sees it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct MailConnection {
    pub id: Uuid,
    pub provider: String,
    pub account_email: Option<String>,
    pub scopes: String,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignInUrl {
    pub url: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

fn provider_of(raw: &str) -> Result<Provider, AppError> {
    Provider::parse(raw).ok_or(AppError::NotFound)
}

/// The caller's mailbox connections: at most one per provider, so the whole
/// list is one page.
#[utoipa::path(
    get,
    path = "/api/v1/me/mail-connections",
    tag = "integration",
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<MailConnection>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_connections(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<PaginatedResponse<MailConnection>>, AppError> {
    let rows: Vec<MailConnection> = sqlx::query_as(
        "SELECT id, provider, account_email, scopes, connected_at FROM user_mail_connection \
          WHERE user_id = $1 ORDER BY provider",
    )
    .bind(ctx.user_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(rows.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(rows, total, 1, total.max(1))))
}

/// Starts connecting: answers the provider's sign-in URL.
#[utoipa::path(
    post,
    path = "/api/v1/me/mail-connections/{provider}/start",
    operation_id = "start_mail_connection",
    tag = "integration",
    params(("provider" = String, Path, description = "`microsoft` or `google`")),
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::Delegated,
        Some("GET /api/v1/me/mail-connections/{provider}/callback"),
        "keeps a ten-minute PKCE verifier; the connection and its Credential event are made at the callback"
    )))),
    responses(
        (status = 200, description = "Where to send the person", body = SignInUrl),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "The provider is not configured", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(provider): Path<String>,
) -> Result<Json<SignInUrl>, AppError> {
    let provider = provider_of(&provider)?;
    let app = app(&state, provider).await?;
    let verifier = new_verifier();
    sqlx::query(
        "DELETE FROM user_mail_connection_pending WHERE created_at < now() - make_interval(mins => $1)",
    )
    .bind(i32::try_from(PENDING_MINUTES).unwrap_or(10))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let pending: Uuid = sqlx::query_scalar(
        "INSERT INTO user_mail_connection_pending (user_id, provider, code_verifier) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(ctx.user_id)
    .bind(provider.as_str())
    .bind(&verifier)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(SignInUrl {
        url: authorize_url(
            provider,
            &app.tenant,
            &app.client_id,
            &redirect_uri(&state, provider),
            &pending.to_string(),
            &verifier,
        ),
    }))
}

/// Where the provider sends the person back; keeps the tokens and returns
/// them to their settings page.
#[utoipa::path(
    get,
    path = "/api/v1/me/mail-connections/{provider}/callback",
    tag = "integration",
    params(("provider" = String, Path), CallbackQuery),
    responses(
        (status = 303, description = "Back to the person's settings"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such sign-in of the caller's", body = ErrorResponse),
        (status = 422, description = "The provider refused the sign-in", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
async fn callback(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<Redirect, AppError> {
    let provider = provider_of(&provider)?;
    let settings = format!(
        "{}/xrm/settings/connections",
        state.base.config.frontend_url().trim_end_matches('/')
    );
    if q.error.is_some() {
        return Ok(Redirect::to(&format!("{settings}?connected=0")));
    }
    let pending = q
        .state
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or(AppError::NotFound)?;
    // The state must be the caller's own, recent sign-in; it is used once.
    let verifier: String = sqlx::query_scalar(
        "DELETE FROM user_mail_connection_pending \
          WHERE id = $1 AND user_id = $2 AND provider = $3 \
            AND created_at >= now() - make_interval(mins => $4) \
         RETURNING code_verifier",
    )
    .bind(pending)
    .bind(ctx.user_id)
    .bind(provider.as_str())
    .bind(i32::try_from(PENDING_MINUTES).unwrap_or(10))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let code = q
        .code
        .as_deref()
        .ok_or_else(|| AppError::Validation("the provider sent no code".into()))?;
    let app = app(&state, provider).await?;
    let redirect = redirect_uri(&state, provider);
    let tokens = token_request(
        provider,
        &app,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect.as_str()),
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.secret.as_str()),
            ("code_verifier", verifier.as_str()),
        ],
    )
    .await?;
    store(&state, ctx.user_id, provider, &tokens).await?;
    Ok(Redirect::to(&format!("{settings}?connected=1")))
}

/// Keeps a person's tokens (replacing any earlier connection) with its
/// Credential event in the same transaction.
async fn store(
    state: &EngineState,
    user: Uuid,
    provider: Provider,
    tokens: &Tokens,
) -> Result<(), AppError> {
    let id = Uuid::now_v7();
    let access = seal(state, id, "access_token_enc", &tokens.access_token)?;
    let refresh = tokens
        .refresh_token
        .as_deref()
        .map(|r| seal(state, id, "refresh_token_enc", r))
        .transpose()?;
    let expires = Utc::now() + chrono::Duration::seconds(tokens.expires_in.max(60));
    let mut tx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            user,
            "user_mail_connection",
            Some(id),
        )
        .named("mail_connection_connected")
        .comment(format!("{} mailbox connected", provider.as_str())),
    )
    .await?;
    sqlx::query("DELETE FROM user_mail_connection WHERE user_id = $1 AND provider = $2")
        .bind(user)
        .bind(provider.as_str())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO user_mail_connection \
             (id, user_id, provider, account_email, scopes, access_token_enc, refresh_token_enc, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(id)
    .bind(user)
    .bind(provider.as_str())
    .bind(&tokens.email)
    .bind(&tokens.scope)
    .bind(&access)
    .bind(&refresh)
    .bind(expires)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct StoredConnection {
    id: Uuid,
    access_token_enc: String,
    refresh_token_enc: Option<String>,
    expires_at: DateTime<Utc>,
}

/// A fresh access token for `user`'s connection to `provider`, refreshed
/// when it is about to expire; `None` when they have not connected.
pub async fn access_token(
    state: &EngineState,
    user: Uuid,
    provider: Provider,
) -> Result<Option<String>, AppError> {
    let row: Option<StoredConnection> = sqlx::query_as(
        "SELECT id, access_token_enc, refresh_token_enc, expires_at FROM user_mail_connection \
          WHERE user_id = $1 AND provider = $2",
    )
    .bind(user)
    .bind(provider.as_str())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.expires_at > Utc::now() + chrono::Duration::seconds(REFRESH_EARLY_SECS) {
        return open(state, row.id, "access_token_enc", &row.access_token_enc).map(Some);
    }
    let Some(sealed) = row.refresh_token_enc.as_deref() else {
        return Ok(None);
    };
    let refresh = open(state, row.id, "refresh_token_enc", sealed)?;
    let app = app(state, provider).await?;
    let tokens = token_request(
        provider,
        &app,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.as_str()),
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.secret.as_str()),
        ],
    )
    .await?;
    let access = seal(state, row.id, "access_token_enc", &tokens.access_token)?;
    // Providers may rotate the refresh token; keep the newest.
    let refresh = match tokens.refresh_token.as_deref() {
        Some(r) => Some(seal(state, row.id, "refresh_token_enc", r)?),
        None => row.refresh_token_enc.clone(),
    };
    sqlx::query(
        "UPDATE user_mail_connection \
            SET access_token_enc = $2, refresh_token_enc = $3, expires_at = $4, updated_at = now() \
          WHERE id = $1",
    )
    .bind(row.id)
    .bind(&access)
    .bind(&refresh)
    .bind(Utc::now() + chrono::Duration::seconds(tokens.expires_in.max(60)))
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Some(tokens.access_token))
}

/// Disconnects: revokes at the provider where it can, then forgets the tokens.
#[utoipa::path(
    delete,
    path = "/api/v1/me/mail-connections/{provider}",
    tag = "integration",
    params(("provider" = String, Path, description = "`microsoft` or `google`")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Credential, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Disconnected"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such connection of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn disconnect(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(provider): Path<String>,
) -> Result<StatusCode, AppError> {
    let provider = provider_of(&provider)?.as_str().to_owned();
    let row: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, access_token_enc, refresh_token_enc FROM user_mail_connection \
          WHERE user_id = $1 AND provider = $2",
    )
    .bind(ctx.user_id)
    .bind(&provider)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (id, access, refresh) = row.ok_or(AppError::NotFound)?;
    // Best effort, before forgetting it: a provider outage must not keep a
    // person connected against their wish.
    if provider == "google" {
        let token = refresh
            .as_deref()
            .map(|r| open(&state, id, "refresh_token_enc", r))
            .unwrap_or_else(|| open(&state, id, "access_token_enc", &access));
        if let Ok(token) = token {
            let revoked = client()
                .post("https://oauth2.googleapis.com/revoke")
                .form(&[("token", token.as_str())])
                .send()
                .await;
            if let Err(e) = revoked {
                tracing::warn!(error = %e, "mail connection: Google revoke failed; forgetting the token anyway");
            }
        }
    }
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Revoke,
            ctx.user_id,
            "user_mail_connection",
            Some(id),
        )
        .named("mail_connection_disconnected")
        .comment(format!("{provider} mailbox disconnected")),
    )
    .await?;
    sqlx::query("DELETE FROM user_mail_connection WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The URL that asks a Microsoft tenant's administrator to consent for every
/// person at once.
#[utoipa::path(
    get,
    path = "/api/v1/admin/mail-connections/microsoft/admin-consent-url",
    tag = "admin",
    responses(
        (status = 200, description = "Where the administrator consents", body = SignInUrl),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Microsoft is not configured", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn microsoft_admin_consent(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<SignInUrl>, AppError> {
    let app = app(&state, Provider::Microsoft).await?;
    let back = format!(
        "{}/xrm/settings/connections",
        state.base.config.frontend_url().trim_end_matches('/')
    );
    Ok(Json(SignInUrl {
        url: admin_consent_url(&app.tenant, &app.client_id, &back),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/me/mail-connections", get(list_connections))
        .route("/api/v1/me/mail-connections/{provider}/start", post(start))
        .route(
            "/api/v1/me/mail-connections/{provider}/callback",
            get(callback),
        )
        .route("/api/v1/me/mail-connections/{provider}", delete(disconnect))
        .route(
            "/api/v1/admin/mail-connections/microsoft/admin-consent-url",
            get(microsoft_admin_consent),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_connections, start, callback, disconnect, microsoft_admin_consent))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_mail_oauth_sign_in_url_carries_pkce() {
        let verifier = "a".repeat(64);
        let url = authorize_url(
            Provider::Google,
            "common",
            "client-1",
            "https://crm.example.com/api/v1/me/mail-connections/google/callback",
            "state-1",
            &verifier,
        );
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?response_type=code"));
        assert!(url.contains("client_id=client-1"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&format!("code_challenge={}", challenge(&verifier))));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fcrm.example.com%2Fapi%2Fv1%2Fme"));
        assert!(url.ends_with("&access_type=offline&prompt=consent"));
        let ms = authorize_url(
            Provider::Microsoft,
            "contoso",
            "c",
            "https://x/cb",
            "s",
            &verifier,
        );
        assert!(ms.starts_with("https://login.microsoftonline.com/contoso/oauth2/v2.0/authorize?"));
        assert!(ms.contains("offline_access"));
        assert_eq!(new_verifier().len(), 64);
    }

    #[test]
    fn user_mail_oauth_reads_recorded_token_answers() {
        // `{"email":"sara@example.com"}`, as an unsigned ID token's payload.
        let payload = URL_SAFE_NO_PAD.encode(br#"{"email":"sara@example.com"}"#);
        let body = format!(
            r#"{{"access_token":"ya29.a","refresh_token":"1//r","expires_in":3599,
                "scope":"openid email","id_token":"h.{payload}.s"}}"#
        );
        let tokens = parse_tokens(200, &body).unwrap();
        assert_eq!(tokens.access_token, "ya29.a");
        assert_eq!(tokens.refresh_token.as_deref(), Some("1//r"));
        assert_eq!(tokens.expires_in, 3599);
        assert_eq!(tokens.email.as_deref(), Some("sara@example.com"));
        assert_eq!(
            parse_tokens(
                400,
                r#"{"error":"invalid_grant","error_description":"Bad Request"}"#
            ),
            Err("invalid_grant".to_owned())
        );
        assert_eq!(parse_tokens(200, "{}"), Err("no_access_token".to_owned()));
    }

    #[test]
    fn user_mail_oauth_admin_consent_is_tenant_wide() {
        let url = admin_consent_url(
            "contoso",
            "app-1",
            "https://crm.example.com/xrm/settings/connections",
        );
        assert!(url.starts_with(
            "https://login.microsoftonline.com/contoso/v2.0/adminconsent?client_id=app-1"
        ));
        assert!(url.contains("scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"));
        assert_eq!(Provider::parse("yahoo"), None);
    }
}
