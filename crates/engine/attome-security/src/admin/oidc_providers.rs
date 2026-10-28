//! Q1-T4: sign-in providers over the admin API, under
//! `/api/v1/admin/security/oidc-providers`, and the presets that fill the
//! form. A provider an administrator adds is a row of `oidc_provider` (Q1-T2)
//! whose client secret is sealed under `oidc.client_secret_encryption_key`
//! (Q1-T3) and never returned: an item says only whether one is set, when,
//! and its fingerprint. Configured providers are listed read-only and refused
//! a change with 409 `provider_is_config_managed`.
//!
//! `system.admin` only, not the Security area: whoever controls a provider
//! can assert any verified email and so sign in as anyone, administrators
//! included. Each change is audited in its own transaction and announced on
//! `attome-auth:oidc-providers:changed`, so every node's sign-in list follows.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_auth::oidc_presets::{MfaClaim, OidcPreset, PRESETS, PresetKind};
use attome_auth::oidc_registry::{
    ProviderHealth, announce_change, health, seal_secret, secret_fingerprint,
};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

const ENTITY: &str = "oidc_provider";
const LINK_MODES: &[&str] = &["link_only", "create"];

/// One sign-in provider. The client secret is never part of it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcProviderItem {
    /// The row; absent for a configured provider.
    pub id: Option<Uuid>,
    pub key: String,
    pub display_name: String,
    pub display_name_ar: Option<String>,
    pub preset: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    #[schema(value_type = Object)]
    pub claim_map: Value,
    /// `link_only` or `create`.
    pub link_mode: String,
    pub default_role_ref: Option<Uuid>,
    pub trusted_for_mfa: bool,
    pub tenant_allowlist: Vec<String>,
    pub enabled: bool,
    /// Defined in configuration: shown, never changed here.
    pub read_only: bool,
    pub secret_set: bool,
    pub secret_updated_at: Option<DateTime<Utc>>,
    /// The first 8 hex characters of the secret's SHA-256.
    pub secret_fingerprint: Option<String>,
    /// Send back as `If-Match` on the next `PATCH`.
    pub row_version: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    key: String,
    display_name: String,
    display_name_ar: Option<String>,
    preset: Option<String>,
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    claim_map: Value,
    link_mode: String,
    default_role_ref: Option<Uuid>,
    trusted_for_mfa: bool,
    tenant_allowlist: Vec<String>,
    enabled: bool,
    client_secret_updated_at: Option<DateTime<Utc>>,
    client_secret_fingerprint: Option<String>,
    row_version: i64,
}

const COLUMNS: &str = "id, key, display_name, display_name_ar, preset, issuer, client_id, scopes, \
                       claim_map, link_mode, default_role_ref, trusted_for_mfa, tenant_allowlist, \
                       enabled, client_secret_updated_at, client_secret_fingerprint, row_version";

impl From<Row> for OidcProviderItem {
    fn from(r: Row) -> Self {
        Self {
            id: Some(r.id),
            key: r.key,
            display_name: r.display_name,
            display_name_ar: r.display_name_ar,
            preset: r.preset,
            issuer: r.issuer,
            client_id: r.client_id,
            scopes: r.scopes,
            claim_map: r.claim_map,
            link_mode: r.link_mode,
            default_role_ref: r.default_role_ref,
            trusted_for_mfa: r.trusted_for_mfa,
            tenant_allowlist: r.tenant_allowlist,
            enabled: r.enabled,
            read_only: false,
            secret_set: true,
            secret_updated_at: r.client_secret_updated_at,
            secret_fingerprint: r.client_secret_fingerprint,
            row_version: Some(r.row_version),
        }
    }
}

/// A new provider. `client_secret` is write-only.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOidcProviderBody {
    /// Lowercase letters, digits and `-`, 2 to 40: the `{provider}` in
    /// `/api/v1/auth/oidc/{provider}/login`.
    pub key: String,
    pub display_name: String,
    #[serde(default)]
    pub display_name_ar: Option<String>,
    /// The preset the form started from, recorded for the screen.
    #[serde(default)]
    pub preset: Option<String>,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// Default `openid email profile`; must include `openid`.
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    /// Claim names and provider settings (`email`, `groups`, `mfa_acr`, ...).
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub claim_map: Option<Value>,
    /// `link_only` (default) or `create`.
    #[serde(default)]
    pub link_mode: Option<String>,
    #[serde(default)]
    pub default_role_ref: Option<Uuid>,
    /// Default true.
    #[serde(default)]
    pub trusted_for_mfa: Option<bool>,
    #[serde(default)]
    pub tenant_allowlist: Option<Vec<String>>,
    /// Default true.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// A change to a provider; absent fields keep their value. A
/// `client_secret` replaces the secret.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct UpdateOidcProviderBody {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub display_name_ar: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub claim_map: Option<Value>,
    #[serde(default)]
    pub link_mode: Option<String>,
    #[serde(default)]
    pub default_role_ref: Option<Uuid>,
    #[serde(default)]
    pub trusted_for_mfa: Option<bool>,
    #[serde(default)]
    pub tenant_allowlist: Option<Vec<String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// One preset, as the form uses it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcPresetItem {
    pub key: &'static str,
    pub display_name: &'static str,
    /// `oidc` or `broker` (a SAML provider through an OpenID Connect broker).
    pub kind: &'static str,
    /// With `{placeholders}` to fill in.
    pub issuer_template: &'static str,
    pub scopes: Vec<&'static str>,
    /// Suggested claim map: `email`, `groups`, `name`, `title`, `department`,
    /// `phone`, `manager`, and `mfa_acr`; an absent claim the provider does
    /// not send by default.
    #[schema(value_type = Object)]
    pub claim_map: Value,
    /// `amr` or `acr`: where the provider reports MFA.
    pub mfa_claim: &'static str,
    pub supports_forced_reauth: bool,
}

impl From<&OidcPreset> for OidcPresetItem {
    fn from(p: &OidcPreset) -> Self {
        let mut claims = serde_json::Map::new();
        for (name, claim) in [
            ("email", p.email_claim),
            ("groups", p.groups_claim),
            ("name", p.profile_claims.name),
            ("title", p.profile_claims.title),
            ("department", p.profile_claims.department),
            ("phone", p.profile_claims.phone),
            ("manager", p.profile_claims.manager),
        ] {
            if !claim.is_empty() {
                claims.insert(name.to_owned(), json!(claim));
            }
        }
        if !p.mfa_acr_values.is_empty() {
            claims.insert("mfa_acr".to_owned(), json!(p.mfa_acr_values));
        }
        Self {
            key: p.key,
            display_name: p.display_name,
            kind: match p.kind {
                PresetKind::Oidc => "oidc",
                PresetKind::Broker => "broker",
            },
            issuer_template: p.issuer_template,
            scopes: p.scopes.to_vec(),
            claim_map: Value::Object(claims),
            mfa_claim: match p.mfa_claim {
                MfaClaim::Amr => "amr",
                MfaClaim::Acr => "acr",
            },
            supports_forced_reauth: p.supports_forced_reauth,
        }
    }
}

fn valid_key(key: &str) -> bool {
    (2..=40).contains(&key.len())
        && key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// An issuer is an https URL with no trailing slash; plain http only for
/// this machine (a local test provider).
fn check_issuer(issuer: &str) -> Result<(), AppError> {
    let local = issuer.starts_with("http://localhost") || issuer.starts_with("http://127.0.0.1");
    if !(issuer.starts_with("https://") || local) || issuer.ends_with('/') || issuer.len() > 500 {
        return Err(AppError::Validation(
            "issuer is an https URL without a trailing slash".into(),
        ));
    }
    Ok(())
}

fn check_text(field: &str, value: &str, max: usize) -> Result<(), AppError> {
    if value.trim().is_empty() || value.len() > max {
        return Err(AppError::Validation(format!(
            "{field} is required, at most {max} characters"
        )));
    }
    Ok(())
}

fn check_scopes(scopes: &[String]) -> Result<(), AppError> {
    if !scopes.iter().any(|s| s == "openid") || scopes.len() > 20 {
        return Err(AppError::Validation(
            "scopes include openid (at most 20)".into(),
        ));
    }
    Ok(())
}

fn check_secret(secret: &str) -> Result<(), AppError> {
    if secret.len() < 8 || secret.len() > 2000 {
        return Err(AppError::Validation(
            "client_secret is 8 to 2000 characters".into(),
        ));
    }
    Ok(())
}

fn check_link_mode(mode: &str) -> Result<(), AppError> {
    if !LINK_MODES.contains(&mode) {
        return Err(AppError::Validation(
            "link_mode is link_only or create".into(),
        ));
    }
    Ok(())
}

fn check_claim_map(map: &Value) -> Result<(), AppError> {
    if !map.is_object() || map.to_string().len() > 8_000 {
        return Err(AppError::Validation(
            "claim_map is an object (at most 8000 characters)".into(),
        ));
    }
    Ok(())
}

/// The default role a provider gives a person it creates: live, and never one
/// that carries `system.admin` (a provider must not mint administrators).
async fn check_default_role(db: &attome_db::DbPool, role: Option<Uuid>) -> Result<(), AppError> {
    let Some(role) = role else { return Ok(()) };
    let (live, admin): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM role WHERE id = $1 AND is_deleted = false), \
                EXISTS (SELECT 1 FROM role_mm_privilege rp \
                          JOIN privilege p ON p.id = rp.privilege_ref \
                         WHERE rp.role_ref = $1 AND NOT rp.is_deleted AND p.key = $2)",
    )
    .bind(role)
    .bind(attome_server::security::ADMIN_PRIVILEGE_KEY)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !live {
        return Err(AppError::Validation(format!("no live role {role}")));
    }
    if admin {
        return Err(AppError::Validation(
            "a provider's default role cannot carry system.admin".into(),
        ));
    }
    Ok(())
}

fn configured(state: &EngineState, key: &str) -> bool {
    state.base.config.oidc.providers.contains_key(key)
}

fn config_item(key: &str, cfg: &attome_config::OidcProviderConfig) -> OidcProviderItem {
    OidcProviderItem {
        id: None,
        key: key.to_owned(),
        display_name: cfg.display_name.clone(),
        display_name_ar: None,
        preset: None,
        issuer: cfg.issuer.clone(),
        client_id: cfg.client_id.clone(),
        scopes: cfg.scopes.clone(),
        claim_map: json!({ "email": cfg.email_claim, "mfa_acr": cfg.mfa_acr_values }),
        link_mode: "create".to_owned(),
        default_role_ref: None,
        trusted_for_mfa: cfg.trust_idp_mfa,
        tenant_allowlist: Vec::new(),
        enabled: true,
        read_only: true,
        secret_set: !cfg.client_secret.expose().is_empty(),
        secret_updated_at: None,
        secret_fingerprint: None,
        row_version: None,
    }
}

async fn config_tx(
    state: &EngineState,
    operation: AuditOperation,
    actor: Uuid,
    id: Uuid,
) -> Result<SecurityTx<'_>, AppError> {
    SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            operation,
            actor,
            ENTITY,
            Some(id),
        ),
    )
    .await
}

/// After a commit: this node's list now, every other node's on the doorbell.
async fn publish(state: &EngineState) {
    let base = &state.base;
    let secrets = base.secrets.load();
    if let Err(e) = base
        .oidc_providers
        .reload(
            &base.db,
            &base.config.oidc.providers,
            &secrets.oidc_client_secrets,
            &base.config.oidc.client_secret_encryption_key,
        )
        .await
    {
        tracing::warn!(error = %e, "sign-in providers could not be reloaded after a change");
    }
    if let Err(e) = announce_change(&base.redis).await {
        tracing::warn!(error = %e, "a sign-in provider change could not be announced; other nodes catch up within a minute");
    }
}

/// Sign-in providers
///
/// Every sign-in provider: the ones added here and the configured ones (read-only). A client secret is never returned, only whether it is set, when, and its fingerprint. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/oidc-providers",
    operation_id = "list_oidc_providers",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<OidcProviderItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_providers(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<OidcProviderItem>>, AppError> {
    let window = query.window();
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM oidc_provider WHERE NOT is_deleted ORDER BY key"
    ))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut all: Vec<OidcProviderItem> = state
        .base
        .config
        .oidc
        .providers
        .iter()
        .map(|(key, cfg)| config_item(key, cfg))
        .collect();
    all.extend(rows.into_iter().map(OidcProviderItem::from));
    all.sort_by(|a, b| a.key.cmp(&b.key));
    let total = i64::try_from(all.len()).unwrap_or(i64::MAX);
    let items = all
        .into_iter()
        .skip(usize::try_from(window.offset).unwrap_or(0))
        .take(usize::try_from(window.page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Sign-in provider presets
///
/// What the add-provider form starts from for each common provider: the issuer template, scopes and claim names. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/oidc-presets",
    operation_id = "list_oidc_presets",
    tag = "admin-security",
    responses(
        (status = 200, description = "Success", body = Vec<OidcPresetItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_presets(_ctx: Authorized<Admin>) -> Json<Vec<OidcPresetItem>> {
    Json(PRESETS.iter().map(OidcPresetItem::from).collect())
}

/// Add a sign-in provider
///
/// Adds an OpenID Connect provider people can sign in with. The client secret is sealed and never returned. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/oidc-providers",
    operation_id = "create_oidc_provider",
    tag = "admin-security",
    request_body = CreateOidcProviderBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = OidcProviderItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The key is a configured provider (`provider_is_config_managed`) or taken", body = ErrorResponse),
        (status = 422, description = "Request failed validation, or no key ring is configured for client secrets", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_provider(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateOidcProviderBody>,
) -> Result<(StatusCode, Json<OidcProviderItem>), AppError> {
    if !valid_key(&body.key) {
        return Err(AppError::Validation(
            "key is 2 to 40 lowercase letters, digits or -".into(),
        ));
    }
    if configured(&state, &body.key) {
        return Err(AppError::Conflict("provider_is_config_managed"));
    }
    check_text("display_name", &body.display_name, 200)?;
    check_issuer(&body.issuer)?;
    check_text("client_id", &body.client_id, 500)?;
    check_secret(&body.client_secret)?;
    let scopes = body
        .scopes
        .unwrap_or_else(|| ["openid", "email", "profile"].map(str::to_owned).to_vec());
    check_scopes(&scopes)?;
    let claim_map = body.claim_map.unwrap_or_else(|| json!({}));
    check_claim_map(&claim_map)?;
    let link_mode = body.link_mode.unwrap_or_else(|| "link_only".to_owned());
    check_link_mode(&link_mode)?;
    check_default_role(&state.base.db, body.default_role_ref).await?;

    let id = Uuid::now_v7();
    let sealed = seal_secret(
        &state.base.config.oidc.client_secret_encryption_key,
        id,
        &body.client_secret,
    )?;
    let mut tx = config_tx(&state, AuditOperation::Create, ctx.user_id, id).await?;
    let row: Row = sqlx::query_as(&format!(
        "INSERT INTO oidc_provider \
             (id, key, display_name, display_name_ar, preset, issuer, client_id, \
              client_secret_enc, scopes, claim_map, link_mode, default_role_ref, \
              trusted_for_mfa, tenant_allowlist, enabled, client_secret_updated_at, \
              client_secret_fingerprint) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, now(), $16) \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&body.key)
    .bind(body.display_name.trim())
    .bind(body.display_name_ar.as_deref().map(str::trim))
    .bind(&body.preset)
    .bind(&body.issuer)
    .bind(body.client_id.trim())
    .bind(sealed)
    .bind(&scopes)
    .bind(&claim_map)
    .bind(&link_mode)
    .bind(body.default_role_ref)
    .bind(body.trusted_for_mfa.unwrap_or(true))
    .bind(body.tenant_allowlist.unwrap_or_default())
    .bind(body.enabled.unwrap_or(true))
    .bind(secret_fingerprint(&body.client_secret))
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| match attome_db::classify(e) {
        AppError::Conflict(_) => AppError::Conflict("a provider with this key exists"),
        other => other,
    })?;
    tx.commit().await?;
    publish(&state).await;
    Ok((StatusCode::CREATED, Json(row.into())))
}

/// Change a sign-in provider
///
/// Changes the given fields; a `client_secret` replaces the secret. `If-Match: "<row_version>"` guards against a lost update. A configured provider is refused. Administrators only; audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/security/oidc-providers/{id}",
    operation_id = "update_oidc_provider",
    tag = "admin-security",
    params(("id" = String, Path, description = "The provider's id, or a configured provider's key")),
    request_body = UpdateOidcProviderBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Changed", body = OidcProviderItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such provider", body = ErrorResponse),
        (status = 409, description = "A configured provider (`provider_is_config_managed`), or it changed since `If-Match`", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn update_provider(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateOidcProviderBody>,
) -> Result<Json<OidcProviderItem>, AppError> {
    if configured(&state, &id) {
        return Err(AppError::Conflict("provider_is_config_managed"));
    }
    let id: Uuid = id.parse().map_err(|_| AppError::NotFound)?;
    let expected = match headers.get(IF_MATCH) {
        None => None,
        Some(raw) => Some(
            raw.to_str()
                .ok()
                .map(|s| s.trim().trim_matches('"'))
                .and_then(|s| s.parse::<i64>().ok())
                .ok_or_else(|| {
                    AppError::Validation("If-Match must be a row_version integer".into())
                })?,
        ),
    };
    if let Some(name) = &body.display_name {
        check_text("display_name", name, 200)?;
    }
    if let Some(issuer) = &body.issuer {
        check_issuer(issuer)?;
    }
    if let Some(client_id) = &body.client_id {
        check_text("client_id", client_id, 500)?;
    }
    if let Some(secret) = &body.client_secret {
        check_secret(secret)?;
    }
    if let Some(scopes) = &body.scopes {
        check_scopes(scopes)?;
    }
    if let Some(map) = &body.claim_map {
        check_claim_map(map)?;
    }
    if let Some(mode) = &body.link_mode {
        check_link_mode(mode)?;
    }
    check_default_role(&state.base.db, body.default_role_ref).await?;
    let sealed = body
        .client_secret
        .as_deref()
        .map(|secret| {
            seal_secret(
                &state.base.config.oidc.client_secret_encryption_key,
                id,
                secret,
            )
        })
        .transpose()?;
    let fingerprint = body.client_secret.as_deref().map(secret_fingerprint);

    let mut tx = config_tx(&state, AuditOperation::Update, ctx.user_id, id).await?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM oidc_provider WHERE id = $1 AND NOT is_deleted FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(current) = current else {
        return Err(AppError::NotFound);
    };
    if expected.is_some_and(|v| v != current) {
        return Err(AppError::Conflict(
            "version_conflict: the provider changed; reload it",
        ));
    }
    let row: Row = sqlx::query_as(&format!(
        "UPDATE oidc_provider SET \
             display_name = COALESCE($2, display_name), \
             display_name_ar = COALESCE($3, display_name_ar), \
             issuer = COALESCE($4, issuer), \
             client_id = COALESCE($5, client_id), \
             client_secret_enc = COALESCE($6, client_secret_enc), \
             client_secret_updated_at = CASE WHEN $6 IS NULL THEN client_secret_updated_at ELSE now() END, \
             client_secret_fingerprint = COALESCE($7, client_secret_fingerprint), \
             scopes = COALESCE($8, scopes), \
             claim_map = COALESCE($9, claim_map), \
             link_mode = COALESCE($10, link_mode), \
             default_role_ref = COALESCE($11, default_role_ref), \
             trusted_for_mfa = COALESCE($12, trusted_for_mfa), \
             tenant_allowlist = COALESCE($13, tenant_allowlist), \
             enabled = COALESCE($14, enabled), \
             row_version = row_version + 1, updated_at = now() \
         WHERE id = $1 \
         RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(body.display_name.as_deref().map(str::trim))
    .bind(body.display_name_ar.as_deref().map(str::trim))
    .bind(&body.issuer)
    .bind(body.client_id.as_deref().map(str::trim))
    .bind(sealed)
    .bind(fingerprint)
    .bind(&body.scopes)
    .bind(&body.claim_map)
    .bind(&body.link_mode)
    .bind(body.default_role_ref)
    .bind(body.trusted_for_mfa)
    .bind(&body.tenant_allowlist)
    .bind(body.enabled)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    publish(&state).await;
    Ok(Json(row.into()))
}

/// Remove a sign-in provider
///
/// Nobody signs in with it from now on; its links to people stay, so adding it back restores them. A configured provider is refused. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/oidc-providers/{id}",
    operation_id = "delete_oidc_provider",
    tag = "admin-security",
    params(("id" = String, Path, description = "The provider's id, or a configured provider's key")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such provider", body = ErrorResponse),
        (status = 409, description = "A configured provider (`provider_is_config_managed`)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_provider(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    if configured(&state, &id) {
        return Err(AppError::Conflict("provider_is_config_managed"));
    }
    let id: Uuid = id.parse().map_err(|_| AppError::NotFound)?;
    let mut tx = config_tx(&state, AuditOperation::SoftDelete, ctx.user_id, id).await?;
    let n = sqlx::query(
        "UPDATE oidc_provider SET is_deleted = true, enabled = false, \
             row_version = row_version + 1, updated_at = now() \
         WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    publish(&state).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Q1-T12: a provider's sign-in failures on the node that answers.
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcProviderHealthItem {
    pub key: String,
    /// `discovery`, `jwks`, `token_exchange`, `id_token_rejected` or
    /// `clock_skew`.
    pub last_failure_kind: Option<&'static str>,
    pub last_failure_at: Option<DateTime<Utc>>,
    /// Failures per kind since this node started.
    #[schema(value_type = Object)]
    pub failures: std::collections::BTreeMap<&'static str, u64>,
    /// The node these numbers are from; each node keeps its own, and
    /// `oidc_provider_failures_total` adds them up.
    pub node: String,
}

/// Sign-in provider health
///
/// The provider's last sign-in failure and its failures per kind since this node started (discovery, key set, token exchange, a refused ID token, clock skew). Per node; the `oidc_provider_failures_total` metric is the deployment-wide view. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/oidc-providers/{id}/health",
    operation_id = "oidc_provider_health",
    tag = "admin-security",
    params(("id" = String, Path, description = "The provider's id, or a configured provider's key")),
    responses(
        (status = 200, description = "Success", body = OidcProviderHealthItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such provider", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn provider_health(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<String>,
) -> Result<Json<OidcProviderHealthItem>, AppError> {
    let key = if configured(&state, &id) {
        id
    } else {
        let id: Uuid = id.parse().map_err(|_| AppError::NotFound)?;
        sqlx::query_scalar("SELECT key FROM oidc_provider WHERE id = $1 AND NOT is_deleted")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?
    };
    let ProviderHealth {
        last_failure_kind,
        last_failure_at,
        failures,
    } = health(&key);
    Ok(Json(OidcProviderHealthItem {
        key,
        last_failure_kind,
        last_failure_at,
        failures,
        node: attome_server::metrics_store::node_name(state.base.config.app.port),
    }))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_providers,
    list_presets,
    create_provider,
    update_provider,
    delete_provider,
    provider_health
))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/oidc-providers",
            get(list_providers).post(create_provider),
        )
        .route(
            "/api/v1/admin/security/oidc-providers/{id}",
            axum::routing::patch(update_provider).delete(delete_provider),
        )
        .route("/api/v1/admin/security/oidc-presets", get(list_presets))
        .route(
            "/api/v1/admin/security/oidc-providers/{id}/health",
            get(provider_health),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_issuers_and_presets_are_checked() {
        assert!(valid_key("entra-main") && !valid_key("Entra") && !valid_key("a"));
        assert!(check_issuer("https://login.example/v2.0").is_ok());
        assert!(check_issuer("https://login.example/").is_err());
        assert!(check_issuer("http://evil.example").is_err());
        assert!(check_issuer("http://localhost:8080/realms/test").is_ok());
        let entra = OidcPresetItem::from(attome_auth::oidc_presets::preset("entra").unwrap());
        assert_eq!(entra.claim_map["title"], "jobTitle");
        assert_eq!(entra.claim_map["mfa_acr"], json!(["mfa"]));
        let google = OidcPresetItem::from(attome_auth::oidc_presets::preset("google").unwrap());
        assert!(google.claim_map.get("groups").is_none());
    }
}
