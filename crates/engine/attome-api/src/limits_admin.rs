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
    pub peak_7d: i64,
    /// Someone reached this limit in the last seven days.
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
    let usage: HashMap<String, (i64, i64)> = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT limit_key, COALESCE(SUM(hits), 0)::bigint, COALESCE(MAX(peak), 0)::bigint
           FROM limit_usage_daily
          WHERE day >= current_date - 7
          GROUP BY limit_key",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|(key, hits, peak)| (key, (hits, peak)))
    .collect();
    let items: Vec<LimitView> = LIMITS
        .iter()
        .map(|spec| {
            let (hits_7d, peak_7d) = usage.get(spec.key).copied().unwrap_or((0, 0));
            LimitView {
                key: spec.key.to_owned(),
                purpose: spec.purpose.to_owned(),
                kind: format!("{:?}", spec.kind).to_ascii_lowercase(),
                scope: match spec.scope {
                    LimitScope::BootConfig => "boot_config",
                    LimitScope::RuntimeSetting => "runtime_setting",
                }
                .to_owned(),
                value: value_of(&state, spec),
                default: spec.default_solo,
                floor: spec.floor,
                ceiling: spec.ceiling,
                unit: spec.unit.to_owned(),
                hits_7d,
                peak_7d,
                warning: hits_7d > 0,
            }
        })
        .collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

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
