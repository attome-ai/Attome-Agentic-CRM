//! `/api/v1/admin/slo` (roadmap AA13-T8): each SLO class with its status,
//! 30-day error budget (from the built-in metrics store,
//! `attome_server::slo`), reference latency targets and any target this
//! deployment set for itself. An administrator sets a class's own p95/p99
//! targets within half to three times the reference
//! (`PUT /api/v1/admin/slo/targets/{class_id}`, row-version checked) or goes
//! back to the reference (`DELETE`); both are `Configuration` events written
//! in the change's own transaction.
//!
//! AA13-T9: `GET /api/v1/admin/slo/reports` lists the monthly reports the
//! `SloMonthlyReport` job writes (one per calendar month, UTC, from the
//! built-in store: error budgets only, since the store keeps no latency
//! histograms), and the `SloBurnCheck` job tells the administrators, at most
//! once per class per hour, when a class burns its budget fast.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_server::slo::{self, SloClass, Targets};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, put},
};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The smallest and largest share of the reference target a deployment may
/// set.
const MIN_FACTOR: f64 = 0.5;
const MAX_FACTOR: f64 = 3.0;

/// A deployment's own targets for a class.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct SloOverride {
    pub p95_ms: i32,
    pub p99_ms: i32,
    pub row_version: i64,
    pub updated_by: Uuid,
    pub updated_at: DateTime<Utc>,
}

/// Reference latency targets, in milliseconds.
#[derive(Debug, Clone, Copy, Serialize, ToSchema)]
pub struct SloTargets {
    pub p50_ms: Option<f64>,
    pub p95_ms: Option<f64>,
    pub p99_ms: Option<f64>,
}

impl From<Targets> for SloTargets {
    fn from(t: Targets) -> Self {
        Self {
            p50_ms: t.p50_ms,
            p95_ms: t.p95_ms,
            p99_ms: t.p99_ms,
        }
    }
}

/// One SLO class as an administrator sees it.
#[derive(Debug, Serialize, ToSchema)]
pub struct SloClassStatus {
    pub id: String,
    pub name_en: String,
    pub name_ar: String,
    /// `http`, `gauge` or `browser`.
    pub kind: String,
    /// `ok`, `at_risk` or `exhausted` from the error budget; `unmeasured`
    /// for a class without one here.
    pub status: String,
    /// The reference targets for this deployment's profile.
    pub target: Option<SloTargets>,
    /// This deployment's own targets, when set.
    #[serde(rename = "override")]
    pub override_: Option<SloOverride>,
    /// The share of the 30-day error budget left (1 = untouched).
    pub budget_remaining: Option<f64>,
    /// 5xx responses over all responses in the last 30 days.
    pub error_ratio_30d: Option<f64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SloOverview {
    /// `solo` or `team`, the profile whose reference targets apply.
    pub profile: String,
    pub classes: Vec<SloClassStatus>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SloTargetBody {
    pub p95_ms: i32,
    pub p99_ms: i32,
    /// Required to change an existing override (409 when stale).
    pub row_version: Option<i64>,
}

/// The profile whose targets apply: Solo when the deployment runs on the
/// in-process cache, else Team.
fn profile(state: &EngineState) -> &'static str {
    if state.base.config.cache.backend == attome_config::CacheBackend::Memory {
        "solo"
    } else {
        "team"
    }
}

fn find_class(class_id: &str) -> Result<&'static SloClass, AppError> {
    slo::catalogue()
        .classes
        .iter()
        .find(|c| c.id == class_id)
        .ok_or(AppError::NotFound)
}

/// Whether `value` is within the allowed share of `reference`.
fn within(value: i32, reference: Option<f64>) -> bool {
    match reference {
        Some(reference) if reference > 0.0 => {
            let v = f64::from(value);
            v >= reference * MIN_FACTOR && v <= reference * MAX_FACTOR
        }
        _ => false,
    }
}

/// The checks a new target must pass.
fn validate_targets(class: &SloClass, profile: &str, body: &SloTargetBody) -> Result<(), AppError> {
    let reference = class.targets_for(profile).ok_or_else(|| {
        AppError::Validation(format!(
            "class {} has no latency targets to change",
            class.id
        ))
    })?;
    if body.p95_ms <= 0 || body.p99_ms < body.p95_ms {
        return Err(AppError::Validation(
            "p95_ms must be positive and p99_ms at least p95_ms".into(),
        ));
    }
    if !within(body.p95_ms, reference.p95_ms)
        || (reference.p99_ms.is_some() && !within(body.p99_ms, reference.p99_ms))
    {
        return Err(AppError::Validation(format!(
            "targets must be between {MIN_FACTOR} and {MAX_FACTOR} times the reference \
             (p95 {:?} ms, p99 {:?} ms)",
            reference.p95_ms, reference.p99_ms
        )));
    }
    Ok(())
}

/// Service level objectives
///
/// Service level objectives. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/slo",
    tag = "admin",
    operation_id = "get_slo_overview",
    responses(
        (status = 200, description = "Every SLO class with its status, budget and targets", body = SloOverview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_overview(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<SloOverview>, AppError> {
    let profile = profile(&state);
    let overrides: Vec<(String, i32, i32, i64, Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT class_id, p95_ms, p99_ms, row_version, updated_by, updated_at \
           FROM ops_slo_target_override",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut classes = Vec::new();
    for class in &slo::catalogue().classes {
        let budget = slo::budget(&state.base.db, class)
            .await
            .map_err(AppError::internal)?;
        let override_ = overrides
            .iter()
            .find(|o| o.0 == class.id)
            .map(|o| SloOverride {
                p95_ms: o.1,
                p99_ms: o.2,
                row_version: o.3,
                updated_by: o.4,
                updated_at: o.5,
            });
        classes.push(SloClassStatus {
            id: class.id.clone(),
            name_en: class.name_en.clone(),
            name_ar: class.name_ar.clone(),
            kind: class.kind.clone(),
            status: budget.as_ref().map_or("unmeasured", slo::status).to_owned(),
            target: class.targets_for(profile).map(SloTargets::from),
            override_,
            budget_remaining: budget.map(|b| b.remaining_ratio),
            error_ratio_30d: budget.and_then(|b| {
                let total = b.good + b.bad;
                (total > 0.0).then(|| b.bad / total)
            }),
        });
    }
    Ok(Json(SloOverview {
        profile: profile.to_owned(),
        classes,
    }))
}

/// Set an SLO target
///
/// Set an SLO target. Administrators only. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/slo/targets/{class_id}",
    tag = "admin",
    operation_id = "set_slo_target",
    params(("class_id" = String, Path)),
    request_body = SloTargetBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The class's own targets", body = SloOverride),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such class", body = ErrorResponse),
        (status = 409, description = "The override changed since it was read", body = ErrorResponse),
        (status = 422, description = "Targets out of bounds", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_target(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(class_id): Path<String>,
    Json(body): Json<SloTargetBody>,
) -> Result<Json<SloOverride>, AppError> {
    let class = find_class(&class_id)?;
    validate_targets(class, profile(&state), &body)?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "ops_slo_target_override",
            None,
        )
        .named("slo.target_changed")
        .comment(format!(
            "class {class_id}: p95 {} ms, p99 {} ms",
            body.p95_ms, body.p99_ms
        )),
    )
    .await?;
    let existing: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM ops_slo_target_override WHERE class_id = $1 FOR UPDATE",
    )
    .bind(&class_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let saved: SloOverride = match existing {
        None => sqlx::query_as(
            "INSERT INTO ops_slo_target_override (class_id, p95_ms, p99_ms, updated_by) \
             VALUES ($1, $2, $3, $4) \
             RETURNING p95_ms, p99_ms, row_version, updated_by, updated_at",
        )
        .bind(&class_id)
        .bind(body.p95_ms)
        .bind(body.p99_ms)
        .bind(ctx.user_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?,
        Some(current) => {
            if body.row_version != Some(current) {
                return Err(AppError::VersionConflict);
            }
            sqlx::query_as(
                "UPDATE ops_slo_target_override \
                    SET p95_ms = $2, p99_ms = $3, updated_by = $4, updated_at = now(), \
                        row_version = row_version + 1 \
                  WHERE class_id = $1 \
                  RETURNING p95_ms, p99_ms, row_version, updated_by, updated_at",
            )
            .bind(&class_id)
            .bind(body.p95_ms)
            .bind(body.p99_ms)
            .bind(ctx.user_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?
        }
    };
    tx.commit().await?;
    Ok(Json(saved))
}

/// Remove an SLO target
///
/// Remove an SLO target. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/slo/targets/{class_id}",
    tag = "admin",
    operation_id = "clear_slo_target",
    params(("class_id" = String, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "The reference targets apply again"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such class, or it has no override", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn clear_target(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(class_id): Path<String>,
) -> Result<StatusCode, AppError> {
    find_class(&class_id)?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::HardDelete,
            ctx.user_id,
            "ops_slo_target_override",
            None,
        )
        .named("slo.target_cleared")
        .comment(format!("class {class_id}: back to the reference targets")),
    )
    .await?;
    let removed = sqlx::query("DELETE FROM ops_slo_target_override WHERE class_id = $1")
        .bind(&class_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if removed == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Monthly reports and the burn check (AA13-T9) ────────────────────────────

/// One month's report.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct SloReport {
    pub id: Uuid,
    /// The month's first day (UTC).
    pub period_start: NaiveDate,
    /// `{period_start, period_end, latency, classes: [{id, name_en, name_ar,
    /// kind, status, objective, good, bad, error_ratio, budget_remaining}]}`.
    #[schema(value_type = Object)]
    pub report: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// The first day of the month before the one `now` falls in, counted from
/// 02:00 UTC on the first: until then the month before that is still the
/// latest one to report.
pub fn report_period(now: DateTime<Utc>) -> NaiveDate {
    let anchor = (now - chrono::Duration::hours(2)).date_naive();
    let (year, month) = if anchor.month() == 1 {
        (anchor.year() - 1, 12)
    } else {
        (anchor.year(), anchor.month() - 1)
    };
    NaiveDate::from_ymd_opt(year, month, 1).unwrap_or(anchor)
}

fn next_month(start: NaiveDate) -> NaiveDate {
    let (year, month) = if start.month() == 12 {
        (start.year() + 1, 1)
    } else {
        (start.year(), start.month() + 1)
    };
    NaiveDate::from_ymd_opt(year, month, 1).unwrap_or(start)
}

fn midnight(day: NaiveDate) -> DateTime<Utc> {
    day.and_hms_opt(0, 0, 0)
        .map(|t| t.and_utc())
        .unwrap_or_else(Utc::now)
}

/// The report for the month starting `start`.
pub async fn build_report(
    state: &EngineState,
    start: NaiveDate,
) -> Result<serde_json::Value, AppError> {
    let end = next_month(start);
    let mut classes = Vec::new();
    for class in &slo::catalogue().classes {
        let mut row = serde_json::json!({
            "id": class.id, "name_en": class.name_en, "name_ar": class.name_ar,
            "kind": class.kind, "status": "unmeasured",
        });
        if let (Some((method, endpoint)), Some(objective)) =
            (class.http_route(), class.error_objective)
        {
            let (bad, total) = slo::counts_between(
                &state.base.db,
                method,
                endpoint,
                midnight(start),
                midnight(end),
            )
            .await
            .map_err(AppError::internal)?;
            let budget = slo::budget_of(total - bad, bad, objective);
            row["status"] = serde_json::json!(slo::status(&budget));
            row["objective"] = serde_json::json!(objective);
            row["good"] = serde_json::json!(budget.good);
            row["bad"] = serde_json::json!(budget.bad);
            row["error_ratio"] = serde_json::json!(if total > 0.0 { bad / total } else { 0.0 });
            row["budget_remaining"] = serde_json::json!(budget.remaining_ratio);
        }
        classes.push(row);
    }
    Ok(serde_json::json!({
        "period_start": start,
        "period_end": end,
        "latency": "not in this report: the built-in store keeps no latency histograms; the release gate's load tests and Prometheus judge latency",
        "classes": classes,
    }))
}

/// The `SloMonthlyReport` job: writes the latest finished month's report if
/// it is not there yet. True when this call wrote it; a repeat is a no-op.
pub async fn monthly_report(state: &EngineState, now: DateTime<Utc>) -> Result<bool, AppError> {
    let start = report_period(now);
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ops_slo_report WHERE period_start = $1)")
            .bind(start)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if exists {
        return Ok(false);
    }
    let report = build_report(state, start).await?;
    let written = sqlx::query(
        "INSERT INTO ops_slo_report (id, period_start, report) VALUES ($1, $2, $3) \
         ON CONFLICT (period_start) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(start)
    .bind(&report)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(written > 0)
}

/// The Redis key that lets a class's burn notify once per hour.
pub fn burn_key(class_id: &str, now: DateTime<Utc>) -> String {
    format!("slo:burn:{class_id}:{}", now.format("%Y%m%d%H"))
}

/// How long a burn key is kept: two hours, so the hour it names is covered
/// on every node's clock.
const BURN_KEY_TTL: std::time::Duration = std::time::Duration::from_secs(2 * 3600);

/// The `SloBurnCheck` job: every `http` class whose bad ratio over both the
/// last hour and the last five minutes is past [`slo::FAST_BURN_FACTOR`]
/// times its objective notifies the administrators, at most once per class
/// per hour. The classes it notified about. No transaction is open while it
/// notifies.
pub async fn burn_check(
    state: &EngineState,
    notification: &attome_config::NotificationSection,
    now: DateTime<Utc>,
) -> Result<Vec<String>, AppError> {
    let mut notified = Vec::new();
    for class in &slo::catalogue().classes {
        let (Some((method, endpoint)), Some(objective)) =
            (class.http_route(), class.error_objective)
        else {
            continue;
        };
        let db = &state.base.db;
        let hour = slo::counts_between(db, method, endpoint, now - chrono::Duration::hours(1), now)
            .await
            .map_err(AppError::internal)?;
        let five = slo::counts_between(
            db,
            method,
            endpoint,
            now - chrono::Duration::minutes(5),
            now,
        )
        .await
        .map_err(AppError::internal)?;
        if !slo::is_fast_burn(hour, five, objective) {
            continue;
        }
        let first = match state
            .base
            .redis_coordination
            .set_nx(burn_key(&class.id, now), "1", Some(BURN_KEY_TTL))
            .await
        {
            Ok(first) => first,
            // Without the key every node would notify every five minutes; the
            // built-in HighHttpErrorRate alert still fires.
            Err(e) => {
                tracing::warn!(class = %class.id, error = %e, "slo burn check: dedupe key unavailable, not notifying");
                continue;
            }
        };
        if !first {
            continue;
        }
        let ratio = if five.1 > 0.0 { five.0 / five.1 } else { 0.0 };
        tracing::warn!(class = %class.id, ratio, objective, "slo burn check: class burning its error budget fast");
        attome_ai::quality_monitor::alert_admins(
            db,
            notification,
            format!("{} is burning its error budget fast", class.name_en),
            format!(
                "Over the last hour and the last five minutes more than {:.1} times the allowed share \
                 of {} requests failed ({:.2}% in the last five minutes; the objective allows {:.2}%).",
                slo::FAST_BURN_FACTOR,
                class.name_en,
                ratio * 100.0,
                objective * 100.0
            ),
            "/xrm/admin/slo",
        )
        .await;
        notified.push(class.id.clone());
    }
    Ok(notified)
}

/// List SLO reports
///
/// List SLO reports. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/slo/reports",
    tag = "admin",
    operation_id = "list_slo_reports",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Monthly SLO reports, newest first", body = PaginatedResponse<SloReport>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_reports(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SloReport>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM ops_slo_report")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let items: Vec<SloReport> = sqlx::query_as(
        "SELECT id, period_start, report, created_at FROM ops_slo_report \
         ORDER BY period_start DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// `2026-09` or `2026-09-01` as the month's first day.
fn parse_period(period: &str) -> Result<NaiveDate, AppError> {
    let day = NaiveDate::parse_from_str(&format!("{period}-01"), "%Y-%m-%d")
        .or_else(|_| NaiveDate::parse_from_str(period, "%Y-%m-%d"))
        .map_err(|_| AppError::Validation(format!("{period} is not a month (YYYY-MM)")))?;
    NaiveDate::from_ymd_opt(day.year(), day.month(), 1)
        .ok_or_else(|| AppError::Validation(format!("{period} is not a month (YYYY-MM)")))
}

/// One SLO report
///
/// One SLO report. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/slo/reports/{period}",
    tag = "admin",
    operation_id = "get_slo_report",
    params(("period" = String, Path, description = "The month, `YYYY-MM`")),
    responses(
        (status = 200, description = "The month's report", body = SloReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No report for that month", body = ErrorResponse),
        (status = 422, description = "Not a month", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_report(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(period): Path<String>,
) -> Result<Json<SloReport>, AppError> {
    let start = parse_period(&period)?;
    sqlx::query_as(
        "SELECT id, period_start, report, created_at FROM ops_slo_report WHERE period_start = $1",
    )
    .bind(start)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .map(Json)
    .ok_or(AppError::NotFound)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/slo", get(get_overview))
        .route("/api/v1/admin/slo/reports", get(list_reports))
        .route("/api/v1/admin/slo/reports/{period}", get(get_report))
        .route(
            "/api/v1/admin/slo/targets/{class_id}",
            put(set_target).delete(clear_target),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_overview, set_target, clear_target, list_reports, get_report),
    components(schemas(
        SloOverview,
        SloClassStatus,
        SloTargets,
        SloOverride,
        SloTargetBody,
        SloReport
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_must_stay_within_half_to_three_times_the_reference() {
        let class = find_class("S1").expect("S1 ships");
        let ok = SloTargetBody {
            p95_ms: 40,
            p99_ms: 90,
            row_version: None,
        };
        assert!(validate_targets(class, "solo", &ok).is_ok());
        let too_low = SloTargetBody {
            p95_ms: 10,
            p99_ms: 60,
            row_version: None,
        };
        assert!(validate_targets(class, "solo", &too_low).is_err());
        let too_high = SloTargetBody {
            p95_ms: 30,
            p99_ms: 500,
            row_version: None,
        };
        assert!(validate_targets(class, "solo", &too_high).is_err());
        let inverted = SloTargetBody {
            p95_ms: 50,
            p99_ms: 40,
            row_version: None,
        };
        assert!(validate_targets(class, "solo", &inverted).is_err());
        assert!(find_class("nope").is_err());
    }

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn the_report_period_is_the_last_finished_month_from_two_in_the_morning() {
        let day = |y, m| NaiveDate::from_ymd_opt(y, m, 1).unwrap_or_default();
        assert_eq!(report_period(at("2026-10-01T02:00:00Z")), day(2026, 9));
        assert_eq!(report_period(at("2026-10-01T01:59:00Z")), day(2026, 8));
        assert_eq!(report_period(at("2026-10-18T12:00:00Z")), day(2026, 9));
        assert_eq!(report_period(at("2027-01-05T00:00:00Z")), day(2026, 12));
        assert_eq!(next_month(day(2026, 12)), day(2027, 1));
    }

    #[test]
    fn a_period_reads_as_a_month() {
        let sept = NaiveDate::from_ymd_opt(2026, 9, 1).unwrap_or_default();
        assert_eq!(parse_period("2026-09").ok(), Some(sept));
        assert_eq!(parse_period("2026-09-15").ok(), Some(sept));
        assert!(parse_period("September").is_err());
        assert_eq!(
            burn_key("S1", at("2026-10-18T07:59:00Z")),
            "slo:burn:S1:2026101807"
        );
    }
}
