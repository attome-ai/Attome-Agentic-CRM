//! The deliverability routes (roadmap E6-T11):
//!
//! - `GET /api/v1/marketing/deliverability/daily` — the rollup (E6-T4), a
//!   page at a time, filtered by sending domain, provider and date range;
//! - `GET /api/v1/marketing/deliverability/sends/{send_id}` — one campaign's
//!   totals per provider;
//! - `GET /api/v1/marketing/deliverability/dmarc` and
//!   `POST /api/v1/marketing/deliverability/dmarc/upload` — DMARC (E6-T7),
//!   administrators only; the upload is the report file as the body (XML,
//!   gzip or ZIP), at most 20 MB;
//! - `POST /api/v1/marketing/address-check` — the address checks (E6-T6),
//!   limited to 60 a minute per person;
//! - `POST /api/v1/marketing/precheck` — the pre-send check (E6-T10): a
//!   score and findings, nothing sent or stored;
//! - `GET /api/v1/marketing/deliverability/overview` — the dashboard's
//!   figures (E6-T13): rates per provider and day, per-send totals, recent
//!   alerts, blocklist status and the DMARC pass share.
//!
//! The policy itself changes through the generic entity API on
//! `marketing_deliverability_policy` (an audited entity).

use attome_audit::security::{ExemptReason, x_audit_exempt};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey, SelfService, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, Query, State},
    routing::{get, post},
};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// `marketing_deliverability_policy.read` — who may read deliverability.
#[derive(Debug)]
pub struct DeliverabilityRead;

impl PrivilegeKey for DeliverabilityRead {
    const KEY: &'static str = "marketing_deliverability_policy.read";
}

/// Address checks one person may run a minute.
pub const ADDRESS_CHECKS_PER_MINUTE: i32 = 60;

/// One rollup row.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DeliverabilityDay {
    pub day: NaiveDate,
    pub sending_domain: String,
    pub mailbox_provider: String,
    pub send_ref: String,
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub opened: i64,
    pub clicked: i64,
    pub complaints: i64,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DailyQuery {
    /// Only this sending domain.
    pub domain: Option<String>,
    /// Only this mailbox provider (`gmail`, `outlook`, `regional:stc`, ...).
    pub provider: Option<String>,
    /// First day, inclusive.
    pub from: Option<NaiveDate>,
    /// Last day, inclusive.
    pub to: Option<NaiveDate>,
    /// One-based page.
    #[param(minimum = 1)]
    pub page: Option<i64>,
    /// Rows per page.
    pub page_size: Option<i64>,
}

const DAY_COLUMNS: &str = "day, sending_domain, mailbox_provider, send_ref, sent, delivered, \
     bounced, opened, clicked, complaints";

/// The daily list's filters, all bound (`$1`..`$4`).
const DAILY_FILTER: &str = "($1::text IS NULL OR sending_domain = lower($1)) \
     AND ($2::text IS NULL OR mailbox_provider = $2) \
     AND ($3::date IS NULL OR day >= $3) AND ($4::date IS NULL OR day <= $4)";

#[utoipa::path(
    get,
    path = "/api/v1/marketing/deliverability/daily",
    operation_id = "list_deliverability_daily",
    tag = "marketing",
    params(DailyQuery),
    responses(
        (status = 200, description = "Rollup rows, newest day first", body = PaginatedResponse<DeliverabilityDay>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_deliverability_policy.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// List the daily deliverability rollup.
///
/// Sent, delivered, bounced, opened, clicked and complaints per day, sending
/// domain, mailbox provider and campaign, newest day first.
async fn get_daily(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<DeliverabilityRead>>,
    Query(q): Query<DailyQuery>,
) -> Result<Json<PaginatedResponse<DeliverabilityDay>>, AppError> {
    let window = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    let total: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM marketing_deliverability_daily WHERE {DAILY_FILTER}"
    ))
    .bind(&q.domain)
    .bind(&q.provider)
    .bind(q.from)
    .bind(q.to)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<DeliverabilityDay> = sqlx::query_as(&format!(
        "SELECT {DAY_COLUMNS} FROM marketing_deliverability_daily WHERE {DAILY_FILTER} \
         ORDER BY day DESC, sending_domain, mailbox_provider, send_ref LIMIT $5 OFFSET $6"
    ))
    .bind(&q.domain)
    .bind(&q.provider)
    .bind(q.from)
    .bind(q.to)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// One campaign's totals per provider.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct SendProvider {
    pub mailbox_provider: String,
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub opened: i64,
    pub clicked: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SendDeliverability {
    pub send_ref: String,
    pub providers: Vec<SendProvider>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/deliverability/sends/{send_id}",
    operation_id = "get_send_deliverability",
    tag = "marketing",
    params(("send_id" = String, Path, description = "The campaign the mail was sent for")),
    responses(
        (status = 200, description = "The campaign's totals per mailbox provider", body = SendDeliverability),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_deliverability_policy.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Read one campaign's deliverability.
///
/// Its sent, delivered, bounced, opened and clicked totals per mailbox
/// provider, over every day of the rollup.
async fn get_send(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<DeliverabilityRead>>,
    Path(send_id): Path<String>,
) -> Result<Json<SendDeliverability>, AppError> {
    let providers: Vec<SendProvider> = sqlx::query_as(
        "SELECT mailbox_provider, SUM(sent)::bigint AS sent, SUM(delivered)::bigint AS delivered, \
                SUM(bounced)::bigint AS bounced, SUM(opened)::bigint AS opened, \
                SUM(clicked)::bigint AS clicked \
           FROM marketing_deliverability_daily WHERE send_ref = $1 \
          GROUP BY mailbox_provider ORDER BY sent DESC, mailbox_provider",
    )
    .bind(&send_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(SendDeliverability {
        send_ref: send_id,
        providers,
    }))
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DmarcQuery {
    /// The sending domain.
    pub domain: String,
    /// Days back (default 30, at most 365).
    pub days: Option<i32>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DmarcSourceView {
    pub source_ip: String,
    pub messages: i64,
    pub spf_pass: i64,
    pub dkim_pass: i64,
    pub both_fail: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DmarcSummaryView {
    pub domain: String,
    pub days: i32,
    pub sources: Vec<DmarcSourceView>,
    /// Sources whose every message failed both SPF and DKIM.
    pub unauthorised: Vec<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/deliverability/dmarc",
    operation_id = "get_dmarc_summary",
    tag = "marketing",
    params(DmarcQuery),
    responses(
        (status = 200, description = "SPF and DKIM per sending source", body = DmarcSummaryView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Administrators only", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Summarise DMARC reports for a domain.
///
/// Per sending source over the window, the messages reported and how many
/// passed SPF and DKIM, and the sources that failed both.
async fn get_dmarc(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Communication>>,
    Query(q): Query<DmarcQuery>,
) -> Result<Json<DmarcSummaryView>, AppError> {
    let days = q.days.unwrap_or(30).clamp(1, 365);
    let (sources, unauthorised) =
        crate::dmarc::summarise(&state.base.db, q.domain.trim(), days).await?;
    Ok(Json(DmarcSummaryView {
        domain: q.domain.trim().to_ascii_lowercase(),
        days,
        sources: sources
            .into_iter()
            .map(|s| DmarcSourceView {
                source_ip: s.source_ip,
                messages: s.messages,
                spf_pass: s.spf_pass,
                dkim_pass: s.dkim_pass,
                both_fail: s.both_fail,
            })
            .collect(),
        unauthorised,
    }))
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DmarcUploaded {
    /// False when this reporter's report was already stored.
    pub stored: bool,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/deliverability/dmarc/upload",
    operation_id = "upload_dmarc_report",
    tag = "marketing",
    request_body(content = Vec<u8>, description = "The report file: XML, gzip or ZIP", content_type = "application/octet-stream"),
    responses(
        (status = 200, description = "The report was read", body = DmarcUploaded),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Administrators only", body = ErrorResponse),
        (status = 422, description = "Not a readable aggregate report", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(
        ("x-body-limit" = json!(20 * 1024 * 1024)),
        ("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)]))),
    ),
)]
/// Upload a DMARC aggregate report.
///
/// Reads one report (XML, gzip or ZIP) and stores it, once per reporter and
/// report id.
async fn post_dmarc_upload(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Communication>>,
    body: Bytes,
) -> Result<Json<DmarcUploaded>, AppError> {
    let report = crate::dmarc::parse_report(&body)?;
    let service = attome_audit::audit_service(&state);
    let stored =
        crate::dmarc::store_report(&state.base.db, &report, Some((&service, ctx.user_id))).await?;
    tracing::info!(
        user = %ctx.user_id,
        reporter = %report.reporter_org,
        report_id = %report.report_id,
        stored,
        "dmarc report uploaded"
    );
    Ok(Json(DmarcUploaded { stored }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddressCheckBody {
    pub address: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AddressCheckView {
    /// `valid`, `risky` or `invalid`.
    pub status: String,
    /// Stable issue codes (`role_address`, `disposable_domain`, ...).
    pub issues: Vec<String>,
    pub suggestion: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/address-check",
    operation_id = "check_email_address",
    tag = "marketing",
    request_body = AddressCheckBody,
    responses(
        (status = 200, description = "The address's findings", body = AddressCheckView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 429, description = "Too many checks this minute", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::ReadOnly,
        None,
        "read-only check",
    )))),
)]
/// Check an email address.
///
/// Syntax, role address, disposable domain and typo suggestion; a syntax
/// error is invalid, the rest are risky.
async fn post_address_check(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<AddressCheckBody>,
) -> Result<Json<AddressCheckView>, AppError> {
    let key = format!("marketing:address_check:{}", ctx.user_id);
    let outcome = attome_cache::rate_limit::check(
        &state.base.redis_coordination,
        &key,
        ADDRESS_CHECKS_PER_MINUTE,
    )
    .await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }
    let check = match address_cache() {
        Some(cache) => {
            crate::address_check::check_address(
                &body.address,
                &crate::address_check::NoMxResolver,
                cache,
            )
            .await
        }
        None => crate::address_check::check_address_offline(&body.address, None),
    };
    Ok(Json(AddressCheckView {
        status: match check.status {
            crate::address_check::AddressStatus::Valid => "valid",
            crate::address_check::AddressStatus::Risky => "risky",
            crate::address_check::AddressStatus::Invalid => "invalid",
        }
        .to_owned(),
        issues: check
            .issues
            .iter()
            .map(|i| crate::address_check::issue_code(i).to_owned())
            .collect(),
        suggestion: check.suggestion,
    }))
}

/// The process's MX cache (in process until a store is wired); `None`
/// when the cache cannot be built, and the checks run without MX.
fn address_cache() -> Option<&'static crate::address_check::MxCache> {
    static CACHE: std::sync::OnceLock<Option<crate::address_check::MxCache>> =
        std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| match crate::address_check::MxCache::new(None) {
            Ok(cache) => Some(cache),
            Err(error) => {
                tracing::error!(%error, "address check: MX cache refused");
                None
            }
        })
        .as_ref()
}

/// A message to check before sending.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PrecheckBody {
    /// The rendered HTML body.
    pub html: String,
    /// The plain-text part, if the message has one.
    #[serde(default)]
    pub text: Option<String>,
    /// The audience: how many, how many never mailed before, how many with
    /// an invalid address.
    #[serde(default)]
    pub recipients: i64,
    #[serde(default)]
    pub never_mailed: i64,
    #[serde(default)]
    pub invalid: i64,
}

#[utoipa::path(
    post,
    path = "/api/v1/marketing/precheck",
    operation_id = "post_marketing_precheck",
    tag = "marketing",
    request_body = PrecheckBody,
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::ReadOnly,
        None,
        "scores a message; sends and writes nothing",
    )))),
    responses(
        (status = 200, description = "The score and findings", body = crate::precheck::PrecheckReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_deliverability_policy.read", body = ErrorResponse),
        (status = 422, description = "The message is empty", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Check a message before sending.
///
/// A score from 0 to 100 (70 passes) and the findings behind it: spam
/// wording, image-heavy content, links to domains on a blocklist this
/// deployment checked in the last week, a missing unsubscribe link or text
/// part, size, and the audience's never-mailed and invalid shares. Each
/// finding names a guidance key; nothing is sent or stored.
async fn post_precheck(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<DeliverabilityRead>>,
    Json(body): Json<PrecheckBody>,
) -> Result<Json<crate::precheck::PrecheckReport>, AppError> {
    if body.html.trim().is_empty() {
        return Err(AppError::Validation("html is required".into()));
    }
    let blocked: std::collections::HashSet<String> = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT lower(target) FROM marketing_blocklist_check \
          WHERE target_kind = 'domain' AND listed AND checked_at >= now() - interval '7 days'",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    Ok(Json(crate::precheck::precheck(
        crate::precheck::PrecheckEmail {
            html: &body.html,
            text: body.text.as_deref(),
            size_bytes: body.html.len() + body.text.as_deref().map_or(0, str::len),
        },
        crate::precheck::AudienceStats {
            recipients: body.recipients.max(0),
            never_mailed: body.never_mailed.max(0),
            invalid: body.invalid.max(0),
        },
        &blocked,
    )))
}

/// The overview's window.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OverviewQuery {
    /// Days back from today, 1 to 90 (default 30).
    #[param(minimum = 1, maximum = 90)]
    pub days: Option<i32>,
}

/// One provider's totals on one day.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct ProviderDay {
    pub day: NaiveDate,
    pub mailbox_provider: String,
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub complaints: i64,
}

/// One send's totals over the window.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct SendTotals {
    pub send_ref: String,
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub complaints: i64,
    pub opened: i64,
    pub clicked: i64,
}

/// One alert raised by the daily evaluation (E6-T10).
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct AlertView {
    pub day: NaiveDate,
    pub subject: String,
    /// `bounce_rate`, `complaint_rate`, `blocklisted`, `dmarc_failures` or
    /// `reputation_drop`.
    pub kind: String,
    pub value: f64,
    pub threshold: f64,
    /// The screens' translation key for what to do (`deliverabilityAlert.<kind>`).
    pub guidance_key: String,
}

/// The latest check of one target on one blocklist.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct BlocklistStatus {
    pub target: String,
    pub target_kind: String,
    pub list_name: String,
    pub listed: bool,
    pub checked_at: chrono::DateTime<chrono::Utc>,
}

/// DMARC messages for one domain and how many passed (SPF or DKIM aligned).
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct DmarcShare {
    pub domain: String,
    pub messages: i64,
    pub passed: i64,
}

/// The deliverability dashboard's figures.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DeliverabilityOverview {
    pub days: i32,
    /// The bounce and complaint limits in force, in percent.
    pub bounce_limit: f64,
    pub complaint_limit: f64,
    pub providers: Vec<ProviderDay>,
    /// The 50 largest sends in the window.
    pub sends: Vec<SendTotals>,
    /// The 100 newest alerts in the window.
    pub alerts: Vec<AlertView>,
    pub blocklist: Vec<BlocklistStatus>,
    pub dmarc: Vec<DmarcShare>,
}

#[utoipa::path(
    get,
    path = "/api/v1/marketing/deliverability/overview",
    operation_id = "get_deliverability_overview",
    tag = "marketing",
    params(OverviewQuery),
    responses(
        (status = 200, description = "The dashboard's figures", body = DeliverabilityOverview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks marketing_deliverability_policy.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// The deliverability dashboard.
///
/// Over the last `days` days: sent, delivered, bounced and complaints per
/// mailbox provider and day, the largest sends, the alerts raised with their
/// guidance keys, the latest result per target and blocklist, and each
/// domain's DMARC pass share, with the bounce and complaint limits in force.
async fn get_overview(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<DeliverabilityRead>>,
    Query(q): Query<OverviewQuery>,
) -> Result<Json<DeliverabilityOverview>, AppError> {
    let days = q.days.unwrap_or(30).clamp(1, 90);
    let db = &state.base.db;
    let (bounce_limit, complaint_limit) = crate::alerts::rate_limits(&state).await?;
    let providers: Vec<ProviderDay> = sqlx::query_as(
        "SELECT day, mailbox_provider, sum(sent)::int8 AS sent, sum(delivered)::int8 AS delivered, \
                sum(bounced)::int8 AS bounced, sum(complaints)::int8 AS complaints \
           FROM marketing_deliverability_daily WHERE day >= current_date - $1 \
          GROUP BY day, mailbox_provider ORDER BY day, mailbox_provider",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let sends: Vec<SendTotals> = sqlx::query_as(
        "SELECT send_ref, sum(sent)::int8 AS sent, sum(delivered)::int8 AS delivered, \
                sum(bounced)::int8 AS bounced, sum(complaints)::int8 AS complaints, \
                sum(opened)::int8 AS opened, sum(clicked)::int8 AS clicked \
           FROM marketing_deliverability_daily WHERE day >= current_date - $1 AND send_ref <> '' \
          GROUP BY send_ref ORDER BY sum(sent) DESC, send_ref LIMIT 50",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let alerts: Vec<AlertView> = sqlx::query_as(
        "SELECT day, subject, kind, COALESCE((detail->>'value')::float8, 0) AS value, \
                COALESCE((detail->>'threshold')::float8, 0) AS threshold, \
                'deliverabilityAlert.' || kind AS guidance_key \
           FROM marketing_deliverability_alert WHERE day >= current_date - $1 \
          ORDER BY day DESC, kind, subject LIMIT 100",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let blocklist: Vec<BlocklistStatus> = sqlx::query_as(
        "SELECT DISTINCT ON (target, list_name) target, target_kind, list_name, listed, checked_at \
           FROM marketing_blocklist_check WHERE checked_at >= now() - make_interval(days => $1) \
          ORDER BY target, list_name, checked_at DESC LIMIT 200",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let dmarc: Vec<DmarcShare> = sqlx::query_as(
        "SELECT rep.domain, COALESCE(sum(rec.message_count), 0)::int8 AS messages, \
                COALESCE(sum(rec.message_count) FILTER (WHERE rec.dkim = 'pass' OR rec.spf = 'pass'), 0)::int8 \
                  AS passed \
           FROM marketing_dmarc_report rep JOIN marketing_dmarc_record rec ON rec.report_ref = rep.id \
          WHERE rep.date_end >= now() - make_interval(days => $1) \
          GROUP BY rep.domain ORDER BY rep.domain",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(DeliverabilityOverview {
        days,
        bounce_limit,
        complaint_limit,
        providers,
        sends,
        alerts,
        blocklist,
        dmarc,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/marketing/deliverability/overview",
            get(get_overview),
        )
        .route("/api/v1/marketing/precheck", post(post_precheck))
        .route("/api/v1/marketing/deliverability/daily", get(get_daily))
        .route(
            "/api/v1/marketing/deliverability/sends/{send_id}",
            get(get_send),
        )
        .route("/api/v1/marketing/deliverability/dmarc", get(get_dmarc))
        .route(
            "/api/v1/marketing/deliverability/dmarc/upload",
            post(post_dmarc_upload),
        )
        .route("/api/v1/marketing/address-check", post(post_address_check))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        get_daily,
        get_send,
        get_dmarc,
        post_dmarc_upload,
        post_address_check,
        post_precheck,
        get_overview
    ),
    components(schemas(
        ProviderDay,
        SendTotals,
        AlertView,
        BlocklistStatus,
        DmarcShare,
        DeliverabilityOverview,
        PrecheckBody,
        crate::precheck::PrecheckReport,
        crate::precheck::Finding,
        crate::precheck::Severity,
        DeliverabilityDay,
        SendProvider,
        SendDeliverability,
        DmarcSourceView,
        DmarcSummaryView,
        DmarcUploaded,
        AddressCheckBody,
        AddressCheckView
    ))
)]
pub(crate) struct ApiDocFragment;
