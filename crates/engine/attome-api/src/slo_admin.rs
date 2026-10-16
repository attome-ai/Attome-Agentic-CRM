//! `/api/v1/admin/slo` (roadmap AA13-T8): each SLO class with its status,
//! 30-day error budget (from the built-in metrics store,
//! `attome_server::slo`), reference latency targets and any target this
//! deployment set for itself. An administrator sets a class's own p95/p99
//! targets within half to three times the reference
//! (`PUT /api/v1/admin/slo/targets/{class_id}`, row-version checked) or goes
//! back to the reference (`DELETE`); both are `Configuration` events written
//! in the change's own transaction.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_server::slo::{self, SloClass, Targets};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
};
use chrono::{DateTime, Utc};
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

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/slo", get(get_overview))
        .route(
            "/api/v1/admin/slo/targets/{class_id}",
            put(set_target).delete(clear_target),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_overview, set_target, clear_target),
    components(schemas(SloOverview, SloClassStatus, SloTargets, SloOverride, SloTargetBody))
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
}
