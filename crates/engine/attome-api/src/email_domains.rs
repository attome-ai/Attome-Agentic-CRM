//! Z8-T4: `GET /api/v1/admin/email/domains/{domain}/check` — a sending
//! domain's SPF, DKIM and DMARC records, read from DNS and judged, each
//! with the record to publish (`attome_email::domain_check`). Admin only;
//! reads DNS, changes nothing. A domain listed in
//! `email.domain_check.domains` is checked against its provider's SPF
//! include and DKIM selector; any other domain gets the generic checks.
//!
//! The daily `email_domain_check` job ([`check_all`]) checks every listed
//! domain and raises the `SendingDomainBroken` alert while any record is
//! missing or wrong (it resolves on the next clean run).

use attome_core::EngineState;
use attome_email::domain_check::{self, DnsTxtResolver, DomainSettings};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;

/// The registered daily job.
pub const JOB: &str = "email_domain_check";

/// The alert the daily check raises.
pub const ALERT: &str = "SendingDomainBroken";

/// One record's verdict (`attome_email::domain_check::RecordCheck`).
#[derive(Debug, Serialize, ToSchema)]
pub struct DomainRecordCheck {
    /// `spf`, `dkim` or `dmarc`.
    pub kind: String,
    /// The DNS name the record lives at.
    pub name: String,
    /// `ok`, `missing`, `wrong`, `not_configured` or `unknown`.
    pub status: String,
    /// What DNS holds there now.
    pub found: Vec<String>,
    /// The TXT record to publish.
    pub expected: String,
    pub detail: Option<String>,
}

/// A domain's verdict.
#[derive(Debug, Serialize, ToSchema)]
pub struct SendingDomainCheck {
    pub domain: String,
    pub records: Vec<DomainRecordCheck>,
    /// Every record is `ok` (or DKIM is not configured).
    pub ok: bool,
}

impl From<domain_check::DomainCheck> for SendingDomainCheck {
    fn from(check: domain_check::DomainCheck) -> Self {
        Self {
            domain: check.domain,
            ok: check.ok,
            records: check
                .records
                .into_iter()
                .map(|r| DomainRecordCheck {
                    kind: r.kind.to_owned(),
                    name: r.name,
                    status: r.status.to_owned(),
                    found: r.found,
                    expected: r.expected,
                    detail: r.detail,
                })
                .collect(),
        }
    }
}

/// The settings `email.domain_check.domains` names for `domain`.
fn settings_for(state: &EngineState, domain: &str) -> DomainSettings {
    state
        .base
        .config
        .email
        .domain_check
        .domains
        .iter()
        .find(|d| d.domain.trim_end_matches('.').eq_ignore_ascii_case(domain))
        .map(|d| DomainSettings {
            spf_include: d.spf_include.clone(),
            dkim_selector: d.dkim_selector.clone(),
        })
        .unwrap_or_default()
}

fn resolver(state: &EngineState) -> Result<DnsTxtResolver, AppError> {
    DnsTxtResolver::new(&state.base.config.email.domain_check.resolver)
        .map_err(|e| AppError::Validation(format!("email.domain_check.resolver: {e}")))
}

/// Check a sending domain
///
/// Z8-T4: the domain's SPF, DKIM and DMARC records as DNS holds them now,
/// each `ok`, `missing`, `wrong`, `not_configured` or `unknown`, with the
/// record to publish. Admin only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/email/domains/{domain}/check",
    tag = "email",
    operation_id = "check_sending_domain",
    params(("domain" = String, Path, description = "The sending domain (`example.com`)")),
    responses(
        (status = 200, description = "Each record's verdict", body = SendingDomainCheck),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "Not a domain name, or no usable resolver configured", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn check(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(domain): Path<String>,
) -> Result<Json<SendingDomainCheck>, AppError> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if !domain_check::domain_ok(&domain) {
        return Err(AppError::Validation(format!(
            "{domain} is not a domain name"
        )));
    }
    let resolver = resolver(&state)?;
    let settings = settings_for(&state, &domain);
    Ok(Json(
        domain_check::check_domain(&resolver, &domain, &settings)
            .await
            .into(),
    ))
}

/// The daily check of every configured domain; answers how many are broken.
/// A domain DNS did not answer for is not counted as broken.
pub async fn check_all(state: &EngineState) -> Result<usize, AppError> {
    let domains = &state.base.config.email.domain_check.domains;
    if domains.is_empty() {
        return Ok(0);
    }
    let resolver = resolver(state)?;
    let mut broken = Vec::new();
    for configured in domains {
        let domain = configured.domain.trim_end_matches('.').to_ascii_lowercase();
        let settings = DomainSettings {
            spf_include: configured.spf_include.clone(),
            dkim_selector: configured.dkim_selector.clone(),
        };
        let check = domain_check::check_domain(&resolver, &domain, &settings).await;
        let bad: Vec<&str> = check
            .records
            .iter()
            .filter(|r| r.status == "missing" || r.status == "wrong")
            .map(|r| r.kind)
            .collect();
        if !bad.is_empty() {
            tracing::warn!(%domain, records = ?bad, "sending domain records broken");
            broken.push(format!("{domain} ({})", bad.join(", ")));
        }
    }
    let summary = if broken.is_empty() {
        "every sending domain's SPF, DKIM and DMARC records are in place".to_owned()
    } else {
        format!(
            "sending domain records missing or wrong: {}",
            broken.join("; ")
        )
    };
    attome_server::alerts::set_job_alert(
        &state.base.db,
        ALERT,
        "warning",
        &summary,
        Some(broken.len() as f64),
        !broken.is_empty(),
    )
    .await
    .map_err(AppError::internal)?;
    Ok(broken.len())
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/email/domains/{domain}/check", get(check))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(check),
    components(schemas(SendingDomainCheck, DomainRecordCheck))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
