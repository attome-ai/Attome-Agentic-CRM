//! Q1-T6: the email domains that route sign-in to a provider, under
//! `/api/v1/admin/security/oidc-domains`. A domain belongs to one provider
//! added on screen (`oidc_domain.provider_ref`) and is proven by a DNS TXT
//! record: `_attome-verify.<domain>` holding `attome-verify=<token>`. Only a
//! verified domain routes an email to its provider
//! (`auth_policy::provider_for_email`), and a provider added on screen signs
//! in only people whose email domain is verified for it
//! (`auth_policy::domain_verified_for`).
//!
//! `system.admin` only, like the providers themselves: a domain decides who
//! a provider may sign in. Each change is audited in its own transaction.
//! The DNS lookup runs before that transaction opens, never inside it.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

const ENTITY: &str = "oidc_domain";

/// The DNS name the proof lives under, for `domain`.
pub fn record_name(domain: &str) -> String {
    format!("_attome-verify.{domain}")
}

/// The TXT value that proves `token`.
pub fn record_value(token: &str) -> String {
    format!("attome-verify={token}")
}

/// One sign-in domain, with the DNS record that proves it.
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcDomainItem {
    pub id: Uuid,
    pub domain: String,
    pub provider_id: Uuid,
    pub provider_key: String,
    /// The TXT record to publish: its name and its value.
    pub verification_record_name: String,
    pub verification_record_value: String,
    /// When the record was found; `null` until then. A verified domain stays
    /// verified when a later check fails.
    pub verified_at: Option<DateTime<Utc>>,
    /// People with an email on this domain must sign in through the provider.
    pub sso_only: bool,
    pub last_checked_at: Option<DateTime<Utc>>,
    /// Why the last check did not verify it.
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub row_version: i64,
}

#[derive(sqlx::FromRow)]
struct Row {
    id: Uuid,
    domain: String,
    provider_ref: Uuid,
    provider_key: String,
    verification_token: String,
    verified_at: Option<DateTime<Utc>>,
    sso_only: bool,
    last_checked_at: Option<DateTime<Utc>>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    row_version: i64,
}

impl From<Row> for OidcDomainItem {
    fn from(r: Row) -> Self {
        Self {
            verification_record_name: record_name(&r.domain),
            verification_record_value: record_value(&r.verification_token),
            id: r.id,
            domain: r.domain,
            provider_id: r.provider_ref,
            provider_key: r.provider_key,
            verified_at: r.verified_at,
            sso_only: r.sso_only,
            last_checked_at: r.last_checked_at,
            last_error: r.last_error,
            created_at: r.created_at,
            row_version: r.row_version,
        }
    }
}

const SELECT: &str = "SELECT d.id, d.domain, d.provider_ref, p.key AS provider_key, \
        d.verification_token, d.verified_at, d.sso_only, d.last_checked_at, d.last_error, \
        d.created_at, d.row_version \
     FROM oidc_domain d JOIN oidc_provider p ON p.id = d.provider_ref";

/// What to add.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateOidcDomainBody {
    /// A provider added on screen (configured providers do not route by
    /// domain).
    pub provider_id: Uuid,
    /// The email domain, such as `example.sa`.
    pub domain: String,
    /// Whether people on the domain must sign in through the provider.
    #[serde(default)]
    pub sso_only: bool,
}

/// `domain` lowercased and checked as a DNS name: two or more labels of
/// letters, digits and `-` (not at either end), each at most 63 characters,
/// at most 253 in all; no wildcard, no trailing dot. Pure.
pub fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().to_ascii_lowercase();
    if domain.len() > 253 || !domain.contains('.') {
        return None;
    }
    let labels_ok = domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    labels_ok.then_some(domain)
}

/// Whether any of the TXT `values` found is the proof for `token`. A TXT
/// record split into several strings is joined first. Pure.
pub fn record_matches(values: &[String], token: &str) -> bool {
    let expected = record_value(token);
    values.iter().any(|value| value.trim() == expected)
}

/// The TXT values at `name`, each record's strings joined, through the
/// system's resolver with a 5 s limit. An error is the reason to show.
pub async fn txt_values(name: &str) -> Result<Vec<String>, String> {
    let lookup = async {
        let mut builder = hickory_resolver::TokioResolver::builder_tokio()
            .map_err(|e| format!("the DNS resolver could not be set up: {e}"))?;
        builder.options_mut().timeout = std::time::Duration::from_secs(5);
        builder.options_mut().attempts = 1;
        let resolver = builder
            .build()
            .map_err(|e| format!("the DNS resolver could not be set up: {e}"))?;
        let found = resolver
            .txt_lookup(name)
            .await
            .map_err(|e| format!("no TXT record found at {name}: {e}"))?;
        Ok(found
            .answers()
            .iter()
            .filter_map(|record| match record.data() {
                hickory_resolver::proto::rr::RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|part| String::from_utf8_lossy(part))
                        .collect::<String>(),
                ),
                _ => None,
            })
            .collect())
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), lookup)
        .await
        .unwrap_or_else(|_| Err(format!("the DNS lookup of {name} timed out")))
}

fn new_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

/// Sign-in domains
///
/// Every email domain that routes sign-in to a provider, with the DNS record that proves it and whether it is verified. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/oidc-domains",
    operation_id = "list_oidc_domains",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<OidcDomainItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_domains(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<OidcDomainItem>>, AppError> {
    let window = query.window();
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM oidc_domain")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let rows: Vec<Row> = sqlx::query_as(&format!(
        "{SELECT} ORDER BY d.domain, d.id LIMIT $1 OFFSET $2"
    ))
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows.into_iter().map(OidcDomainItem::from).collect(),
        total,
        window.page,
        window.page_size,
    )))
}

/// Add a sign-in domain
///
/// Adds an email domain for a provider added on screen and answers the DNS TXT record that proves it; the domain routes sign-in only once that record is checked. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/oidc-domains",
    operation_id = "create_oidc_domain",
    tag = "admin-security",
    request_body = CreateOidcDomainBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Added, not yet verified", body = OidcDomainItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such provider added on screen", body = ErrorResponse),
        (status = 409, description = "The domain already routes to a provider (`domain_taken`)", body = ErrorResponse),
        (status = 422, description = "Not a domain name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_domain(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateOidcDomainBody>,
) -> Result<(StatusCode, Json<OidcDomainItem>), AppError> {
    let domain = normalize_domain(&body.domain)
        .ok_or_else(|| AppError::Validation("domain is a DNS name such as example.sa".into()))?;
    let id = Uuid::now_v7();
    let mut tx = config_tx(&state, AuditOperation::Create, ctx.user_id, id).await?;
    let provider: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM oidc_provider WHERE id = $1 AND NOT is_deleted")
            .bind(body.provider_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if provider.is_none() {
        return Err(AppError::NotFound);
    }
    sqlx::query(
        "INSERT INTO oidc_domain (id, domain, provider_ref, verification_token, sso_only) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(&domain)
    .bind(body.provider_id)
    .bind(new_token())
    .bind(body.sso_only)
    .execute(&mut *tx)
    .await
    .map_err(|e| match attome_db::classify(e) {
        AppError::Conflict(_) => AppError::Conflict("domain_taken"),
        other => other,
    })?;
    let row: Row = sqlx::query_as(&format!("{SELECT} WHERE d.id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

/// Remove a sign-in domain
///
/// The domain no longer routes sign-in, and its SSO-only rule ends. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/oidc-domains/{id}",
    operation_id = "delete_oidc_domain",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The sign-in domain")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such sign-in domain", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_domain(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = config_tx(&state, AuditOperation::HardDelete, ctx.user_id, id).await?;
    let n = sqlx::query("DELETE FROM oidc_domain WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if n == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Check a sign-in domain's DNS record
///
/// Looks up the domain's `_attome-verify` TXT record now (at most 5 seconds) and marks the domain verified when it holds the expected value; otherwise answers why in `last_error`. A domain already verified stays verified. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/oidc-domains/{id}/verify",
    operation_id = "verify_oidc_domain",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The sign-in domain")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Checked; `verified_at` says whether it is verified", body = OidcDomainItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such sign-in domain", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn verify_domain(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<OidcDomainItem>, AppError> {
    let found: Option<(String, String)> =
        sqlx::query_as("SELECT domain, verification_token FROM oidc_domain WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (domain, token) = found.ok_or(AppError::NotFound)?;
    // The lookup runs before any transaction opens.
    let name = record_name(&domain);
    let error = match txt_values(&name).await {
        Ok(values) if record_matches(&values, &token) => None,
        Ok(_) => Some(format!(
            "the TXT record at {name} does not hold {}",
            record_value(&token)
        )),
        Err(reason) => Some(reason),
    };
    let mut tx = config_tx(&state, AuditOperation::Update, ctx.user_id, id).await?;
    let n = sqlx::query(
        "UPDATE oidc_domain SET \
             verified_at = CASE WHEN $2::text IS NULL THEN COALESCE(verified_at, now()) \
                                ELSE verified_at END, \
             last_checked_at = now(), last_error = $2, \
             row_version = row_version + 1, updated_at = now() \
         WHERE id = $1 AND verification_token = $3",
    )
    .bind(id)
    .bind(&error)
    .bind(&token)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    // Removed (or re-created) while the lookup ran.
    if n == 0 {
        return Err(AppError::NotFound);
    }
    let row: Row = sqlx::query_as(&format!("{SELECT} WHERE d.id = $1"))
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await?;
    if error.is_none() {
        tracing::info!(%id, domain = %row.domain, "sign-in domain verified");
    }
    Ok(Json(row.into()))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_domains, create_domain, delete_domain, verify_domain))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/oidc-domains",
            get(list_domains).post(create_domain),
        )
        .route(
            "/api/v1/admin/security/oidc-domains/{id}",
            axum::routing::delete(delete_domain),
        )
        .route(
            "/api/v1/admin/security/oidc-domains/{id}/verify",
            post(verify_domain),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_checked_and_lowercased() {
        assert_eq!(
            normalize_domain(" Example.SA ").as_deref(),
            Some("example.sa")
        );
        assert_eq!(
            normalize_domain("mail.gov.sa").as_deref(),
            Some("mail.gov.sa")
        );
        for bad in [
            "localhost",
            "*.example.sa",
            "example.sa.",
            "-bad.example",
            "bad-.example",
            "ex ample.sa",
            "a..b",
            "user@example.sa",
        ] {
            assert!(normalize_domain(bad).is_none(), "accepted {bad}");
        }
        assert!(normalize_domain(&format!("{}.sa", "a".repeat(64))).is_none());
    }

    #[test]
    fn only_the_exact_proof_verifies() {
        let token = "0123abcd";
        assert!(record_matches(
            &[
                "v=spf1 -all".to_owned(),
                " attome-verify=0123abcd ".to_owned()
            ],
            token
        ));
        assert!(!record_matches(
            &["attome-verify=0123abc".to_owned()],
            token
        ));
        assert!(!record_matches(
            &["attome-verify=0123abcde".to_owned()],
            token
        ));
        assert!(!record_matches(&[], token));
        assert_eq!(record_name("example.sa"), "_attome-verify.example.sa");
    }

    #[test]
    fn tokens_are_fresh_and_hex() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
    }
}
