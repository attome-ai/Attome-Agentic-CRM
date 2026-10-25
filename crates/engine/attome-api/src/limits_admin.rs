//! AA9-T6: what the limits are, and how close callers come to them.
//!
//! `GET /api/v1/admin/limits` lists every limit in the registry
//! (`attome_config::limits::LIMITS`) with the value in force (a stored
//! runtime setting, else the configuration, else the code default), its
//! range, and the last seven days of hits from `limit_usage_daily`. A
//! runtime limit is changed through `PUT /api/v1/admin/settings/{key}` (key
//! `limits.{key}`), which is audited and versioned; there is no second write
//! route here. `GET /api/v1/limits/me` tells any caller the limits that
//! apply to them and, for each rate class, how much of the current minute's
//! budget is left.
//!
//! AA9-T7: a limit warns when someone was refused by it in the last seven
//! days, or its seven-day peak reached `limits.warn_at_percent` (default
//! 80) of its value; the daily [`limit_warning_check`] tells every
//! administrator about each warning limit, once per limit per day.

use std::collections::HashMap;

use attome_config::limits::{LIMITS, LimitScope, LimitSpec};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use utoipa::ToSchema;

/// One limit, as an administrator sees it.
#[derive(Debug, Serialize, ToSchema)]
pub struct LimitView {
    pub key: String,
    pub purpose: String,
    /// `resource` or `abuse`.
    pub kind: String,
    /// `boot_config` or `runtime_setting`.
    pub scope: String,
    pub value: i64,
    pub default: i64,
    pub floor: i64,
    pub ceiling: i64,
    pub unit: String,
    pub hits_7d: i64,
    /// The highest use seen in seven days, in `unit`: the size asked for,
    /// or for a rate the requests counted in one window.
    pub peak_7d: i64,
    /// Someone was refused by this limit in the last seven days, or its
    /// peak reached `limits.warn_at_percent` of its value.
    pub warning: bool,
}

/// One limit that applies to the caller.
#[derive(Debug, Serialize, ToSchema)]
pub struct MyLimit {
    pub key: String,
    pub value: i64,
    pub unit: String,
    /// For a rate class: requests left in the current minute.
    pub remaining: Option<i64>,
}

/// The limits that apply to the caller.
#[derive(Debug, Serialize, ToSchema)]
pub struct MyLimits {
    pub limits: Vec<MyLimit>,
}

/// The value of `spec` in force: a stored runtime setting, else what the
/// configuration sets, else the code default.
fn value_of(state: &EngineState, spec: &LimitSpec) -> i64 {
    if let Some(stored) = state.runtime_limit(spec.key) {
        return stored;
    }
    let config = &state.base.config;
    let configured = match spec.key {
        "rate_limit.anonymous" => Some(i64::from(config.rate_limit.anonymous_rpm)),
        "rate_limit.authenticated" => Some(i64::from(config.rate_limit.authenticated_rpm)),
        "http.max_body_bytes" => i64::try_from(config.app.max_body_size_bytes).ok(),
        "auth.mfa_challenge_max_attempts" => {
            Some(i64::from(config.auth.mfa_challenge_max_attempts))
        }
        "query.timeout_ms.interactive" => Some(i64::from(config.query.timeouts_ms.interactive)),
        "query.timeout_ms.report" => Some(i64::from(config.query.timeouts_ms.report)),
        key => key
            .strip_prefix("rate_limit.")
            .map(|category| i64::from(config.rate_limit.limits_for(category).1)),
    };
    configured.unwrap_or(spec.default_solo)
}

/// `limits.warn_at_percent` when none is stored.
pub const DEFAULT_WARN_AT_PERCENT: i64 = 80;

/// The share of a limit, in percent, at which it warns.
fn warn_at_percent(state: &EngineState) -> i64 {
    state
        .runtime_limit("warn_at_percent")
        .unwrap_or(DEFAULT_WARN_AT_PERCENT)
        .clamp(50, 99)
}

/// Whether a limit of `value` warns: refused at least once, or its peak at
/// or above `percent` of the value.
pub fn is_warning(value: i64, hits: i64, peak: i64, percent: i64) -> bool {
    hits > 0 || (value > 0 && peak.saturating_mul(100) >= value.saturating_mul(percent))
}

/// Every limit with its use over the seven days up to `today`.
async fn limit_views(
    state: &EngineState,
    today: chrono::NaiveDate,
) -> Result<Vec<LimitView>, AppError> {
    let usage: HashMap<String, (i64, i64)> = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT limit_key, COALESCE(SUM(hits), 0)::bigint, COALESCE(MAX(peak), 0)::bigint
           FROM limit_usage_daily
          WHERE day >= $1::date - 7 AND day <= $1::date
          GROUP BY limit_key",
    )
    .bind(today)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|(key, hits, peak)| (key, (hits, peak)))
    .collect();
    let percent = warn_at_percent(state);
    Ok(LIMITS
        .iter()
        .map(|spec| {
            let (hits_7d, peak_7d) = usage.get(spec.key).copied().unwrap_or((0, 0));
            let value = value_of(state, spec);
            LimitView {
                key: spec.key.to_owned(),
                purpose: spec.purpose.to_owned(),
                kind: format!("{:?}", spec.kind).to_ascii_lowercase(),
                scope: match spec.scope {
                    LimitScope::BootConfig => "boot_config",
                    LimitScope::RuntimeSetting => "runtime_setting",
                }
                .to_owned(),
                value,
                default: spec.default_solo,
                floor: spec.floor,
                ceiling: spec.ceiling,
                unit: spec.unit.to_owned(),
                hits_7d,
                peak_7d,
                warning: is_warning(value, hits_7d, peak_7d, percent),
            }
        })
        .collect())
}

/// How long a day's warning key is kept: two days, so the day it names is
/// covered whichever node runs the check.
const WARN_KEY_TTL: std::time::Duration = std::time::Duration::from_secs(2 * 86_400);

/// The Redis key that lets a limit warn once per day.
pub fn warn_key(limit_key: &str, day: chrono::NaiveDate) -> String {
    format!("limits:warn:{limit_key}:{}", day.format("%Y%m%d"))
}

/// AA9-T7, the daily job's body: tells every administrator about each limit
/// that warns over the seven days up to `now`, at most once per limit per
/// day. Returns the limits notified. Without Redis nothing is sent: the
/// limits list still shows the warning.
pub async fn limit_warning_check(
    state: &EngineState,
    notification: &attome_config::NotificationSection,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<String>, AppError> {
    let today = now.date_naive();
    let percent = warn_at_percent(state);
    let mut notified = Vec::new();
    for view in limit_views(state, today).await? {
        if !view.warning {
            continue;
        }
        let first = match state
            .base
            .redis_coordination
            .set_nx(warn_key(&view.key, today), "1", Some(WARN_KEY_TTL))
            .await
        {
            Ok(first) => first,
            Err(e) => {
                tracing::warn!(limit = %view.key, error = %e, "limit warning: dedupe key unavailable, not notifying");
                continue;
            }
        };
        if !first {
            continue;
        }
        let body = if view.hits_7d > 0 {
            format!(
                "{} ({}) refused {} requests in the last seven days. Its value is {} {}; \
                 raise it within {} to {} if the use is expected.",
                view.key,
                view.purpose,
                view.hits_7d,
                view.value,
                view.unit,
                view.floor,
                view.ceiling
            )
        } else {
            format!(
                "{} ({}) reached {} of its {} {} in the last seven days, at or above the \
                 {percent}% warning level. Raise it within {} to {} if the use is expected.",
                view.key,
                view.purpose,
                view.peak_7d,
                view.value,
                view.unit,
                view.floor,
                view.ceiling
            )
        };
        tracing::warn!(limit = %view.key, peak = view.peak_7d, hits = view.hits_7d, value = view.value, "limit warning: a limit is close to binding");
        attome_ai::quality_monitor::alert_admins(
            &state.base.db,
            notification,
            format!("Limit {} is close to its value", view.key),
            body,
            "/xrm/admin/settings",
        )
        .await;
        notified.push(view.key);
    }
    Ok(notified)
}

/// Limits
///
/// Limits.
#[utoipa::path(
    get,
    path = "/api/v1/admin/limits",
    tag = "admin",
    operation_id = "admin_limits",
    responses(
        (status = 200, description = "Every limit with its value, range and recent use", body = PaginatedResponse<LimitView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Every limit and its use.
///
/// The value in force, the default, floor and ceiling, and the last seven
/// days' hits and peak for every limit in the registry. Change a runtime
/// limit with `PUT /api/v1/admin/settings/limits.{key}`.
async fn list_limits(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<LimitView>>, AppError> {
    let items = limit_views(&state, chrono::Utc::now().date_naive()).await?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

/// My limits
///
/// My limits. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/limits/me",
    tag = "auth",
    operation_id = "my_limits",
    responses(
        (status = 200, description = "The limits that apply to the caller", body = MyLimits),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// The limits that apply to the caller.
///
/// Each rate class with the requests left in the current minute, the bulk
/// size and the query time limits.
async fn my_limits(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<MyLimits>, AppError> {
    let mut limits = Vec::new();
    for spec in LIMITS {
        let Some(category) = spec.key.strip_prefix("rate_limit.") else {
            continue;
        };
        if matches!(category, "anonymous" | "authenticated") {
            continue;
        }
        let value = value_of(&state, spec);
        let key = format!("base:rl:user:{}:{category}", ctx.user_id);
        let used = attome_cache::rate_limit::peek(&state.base.redis_coordination, &key)
            .await
            .ok();
        limits.push(MyLimit {
            key: spec.key.to_owned(),
            value,
            unit: spec.unit.to_owned(),
            remaining: used.map(|used| (value - used).max(0)),
        });
    }
    for key in [
        "bulk.max_records_per_request",
        "query.timeout_ms.interactive",
        "query.timeout_ms.report",
    ] {
        if let Some(spec) = attome_config::limits::spec(key) {
            limits.push(MyLimit {
                key: spec.key.to_owned(),
                value: value_of(&state, spec),
                unit: spec.unit.to_owned(),
                remaining: None,
            });
        }
    }
    Ok(Json(MyLimits { limits }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_warns_when_refused_or_near_its_value() {
        assert!(is_warning(500, 0, 425, 80), "85% of the value");
        assert!(is_warning(500, 0, 400, 80), "exactly 80%");
        assert!(!is_warning(500, 0, 399, 80), "under 80%");
        assert!(is_warning(500, 1, 0, 80), "refused once");
        assert!(!is_warning(500, 0, 425, 90), "a higher warning level");
        assert!(!is_warning(0, 0, 10, 80), "a zero value never warns on use");
    }

    #[test]
    fn the_warning_key_names_the_limit_and_day() {
        let day = chrono::NaiveDate::from_ymd_opt(2026, 10, 18).unwrap();
        assert_eq!(
            warn_key("bulk.max_records_per_request", day),
            "limits:warn:bulk.max_records_per_request:20261018"
        );
    }
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/limits", get(list_limits))
        .route("/api/v1/limits/me", get(my_limits))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_limits, my_limits),
    components(schemas(LimitView, MyLimit, MyLimits))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
