//! AB3-T1: recovery targets (`ops_recovery_target`, migration 0268): the
//! recovery point and time each deployment profile promises per disaster
//! scenario, and whether a drill has proven it.
//!
//! A target is `proven` only when its evidence kind is `fresh` (AB4-T9)
//! and the newest passing drill of that kind measured a recovery point and
//! time within the target; `proven_on` is when that drill finished. Only
//! signed evidence exists (AB4-T6), so nothing is proven from an unsigned
//! file.
//!
//! - `GET /api/v1/ops/recovery-targets?profile=` (`ops.read`); the profile
//!   defaults to `ops.profile` (`solo` unless configured).
//! - `PATCH /api/v1/ops/recovery-targets/{id}` (`ops.drill.manage`,
//!   `If-Match`) changes the numbers; audited
//!   (`ops.recovery_target_changed`).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_db::DbPool;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, patch},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::drill_schedules::OpsDrillManage;
use crate::evidence::EvidenceKind;
use crate::upgrades::OpsRead;

/// The deployment profiles a target is set for.
pub const PROFILES: [&str; 4] = ["solo", "team", "ha", "scale"];

const COLUMNS: &str = "id, profile, scenario, rpo_seconds, rto_seconds, evidence_kind, row_version, updated_by, updated_at";

#[derive(Debug, sqlx::FromRow)]
struct TargetRow {
    id: Uuid,
    profile: String,
    scenario: String,
    rpo_seconds: i32,
    rto_seconds: i32,
    evidence_kind: String,
    row_version: i64,
    updated_by: Option<Uuid>,
    updated_at: Option<DateTime<Utc>>,
}

/// One recovery target and its proof.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecoveryTarget {
    pub id: Uuid,
    /// `solo`, `team`, `ha` or `scale`.
    pub profile: String,
    /// `node_loss`, `site_loss`, `corruption`, `ransomware` or `bad_change`.
    pub scenario: String,
    pub rpo_seconds: i32,
    pub rto_seconds: i32,
    /// The drill kind whose evidence proves it.
    pub evidence_kind: String,
    /// A fresh drill of that kind measured within the target.
    pub proven: bool,
    /// When that drill finished.
    pub proven_on: Option<DateTime<Utc>>,
    /// What the newest passing drill measured.
    pub measured_rpo_seconds: Option<f64>,
    pub measured_rto_seconds: Option<f64>,
    pub row_version: i64,
    pub updated_by: Option<Uuid>,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Whether a target is proven. Pure.
pub fn proven(
    fresh: bool,
    target_rpo: i32,
    target_rto: i32,
    measured_rpo: Option<f64>,
    measured_rto: Option<f64>,
) -> bool {
    fresh
        && measured_rpo.is_some_and(|m| m <= f64::from(target_rpo))
        && measured_rto.is_some_and(|m| m <= f64::from(target_rto))
}

/// The profile asked for, or the configured one. Pure.
pub fn profile_or(asked: Option<&str>, configured: &str) -> Result<String, AppError> {
    let profile = asked
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or(configured);
    if PROFILES.contains(&profile) {
        Ok(profile.to_owned())
    } else {
        Err(AppError::Validation(format!(
            "profile is one of {}",
            PROFILES.join(", ")
        )))
    }
}

/// Every target of `profile` with its proof.
pub async fn list_with_proof(db: &DbPool, profile: &str) -> Result<Vec<RecoveryTarget>, AppError> {
    let rows: Vec<TargetRow> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_recovery_target WHERE profile = $1 ORDER BY scenario"
    ))
    .bind(profile)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let kind: Option<EvidenceKind> =
            serde_json::from_value(serde_json::Value::from(row.evidence_kind.as_str())).ok();
        let fresh = match kind {
            Some(kind) => crate::freshness::freshness(db, kind).await?.status == "fresh",
            None => false,
        };
        let measured: Option<(Option<f64>, Option<f64>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT rpo_seconds, rto_seconds, finished_at FROM ops_drill_run \
              WHERE kind = $1 AND overall_ok ORDER BY finished_at DESC, id DESC LIMIT 1",
        )
        .bind(&row.evidence_kind)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let (rpo, rto, at) = match measured {
            Some((rpo, rto, at)) => (rpo, rto, Some(at)),
            None => (None, None, None),
        };
        let ok = proven(fresh, row.rpo_seconds, row.rto_seconds, rpo, rto);
        out.push(RecoveryTarget {
            id: row.id,
            profile: row.profile,
            scenario: row.scenario,
            rpo_seconds: row.rpo_seconds,
            rto_seconds: row.rto_seconds,
            evidence_kind: row.evidence_kind,
            proven: ok,
            proven_on: if ok { at } else { None },
            measured_rpo_seconds: rpo,
            measured_rto_seconds: rto,
            row_version: row.row_version,
            updated_by: row.updated_by,
            updated_at: row.updated_at,
        });
    }
    Ok(out)
}

/// The list's filter.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TargetFilter {
    /// `solo`, `team`, `ha` or `scale`; the configured `ops.profile` when
    /// absent.
    #[serde(default)]
    pub profile: Option<String>,
}

/// A target's new numbers; absent ones stay.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateRecoveryTarget {
    #[serde(default)]
    pub rpo_seconds: Option<i32>,
    #[serde(default)]
    pub rto_seconds: Option<i32>,
}

/// List recovery targets
///
/// AB3-T1: one profile's recovery point and time per scenario, each with
/// whether a fresh drill proved it. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/recovery-targets",
    tag = "ops",
    operation_id = "list_ops_recovery_targets",
    params(TargetFilter),
    responses(
        (status = 200, description = "The profile's targets", body = PaginatedResponse<RecoveryTarget>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
        (status = 422, description = "An unknown profile", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_targets(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Query(filter): Query<TargetFilter>,
) -> Result<Json<PaginatedResponse<RecoveryTarget>>, AppError> {
    let profile = profile_or(filter.profile.as_deref(), &state.base.config.ops.profile)?;
    let items = list_with_proof(&state.base.db, &profile).await?;
    let n = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, n, 1, n.max(1))))
}

/// Change a recovery target
///
/// AB3-T1: its recovery point or time, in seconds. `If-Match` names the
/// row version. Needs `ops.drill.manage`. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/ops/recovery-targets/{id}",
    tag = "ops",
    operation_id = "update_ops_recovery_target",
    params(
        ("id" = Uuid, Path, description = "The target"),
        ("If-Match" = String, Header, description = "The target's row_version, quoted"),
    ),
    request_body = UpdateRecoveryTarget,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The target, with its proof", body = RecoveryTarget),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.drill.manage", body = ErrorResponse),
        (status = 404, description = "No such target", body = ErrorResponse),
        (status = 409, description = "A stale row_version", body = ErrorResponse),
        (status = 422, description = "A missing If-Match, a negative number or nothing to change", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_target(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsDrillManage>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpdateRecoveryTarget>,
) -> Result<Json<RecoveryTarget>, AppError> {
    let expected = crate::upgrades::if_match(&headers)?;
    if body.rpo_seconds.is_none() && body.rto_seconds.is_none() {
        return Err(AppError::Validation("nothing to change".into()));
    }
    if body.rpo_seconds.is_some_and(|v| v < 0) || body.rto_seconds.is_some_and(|v| v < 0) {
        return Err(AppError::Validation("seconds are zero or more".into()));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated: Option<TargetRow> = sqlx::query_as(&format!(
        "UPDATE ops_recovery_target SET rpo_seconds = COALESCE($2, rpo_seconds), \
                rto_seconds = COALESCE($3, rto_seconds), row_version = row_version + 1, \
                updated_by = $5, updated_at = now() \
          WHERE id = $1 AND row_version = $4 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(body.rpo_seconds)
    .bind(body.rto_seconds)
    .bind(expected)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = updated else {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM ops_recovery_target WHERE id = $1)")
                .bind(id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    };
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "ops_recovery_target",
            Some(id),
        )
        .named("ops.recovery_target_changed")
        .comment(format!(
            "{} {}: RPO {} s, RTO {} s",
            row.profile, row.scenario, row.rpo_seconds, row.rto_seconds
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    let target = list_with_proof(&state.base.db, &row.profile)
        .await?
        .into_iter()
        .find(|t| t.id == id)
        .ok_or(AppError::NotFound)?;
    Ok(Json(target))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/ops/recovery-targets", get(list_targets))
        .route("/api/v1/ops/recovery-targets/{id}", patch(update_target))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_targets, update_target),
    components(schemas(RecoveryTarget, UpdateRecoveryTarget))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_evidence_within_target_is_proven() {
        assert!(proven(true, 300, 3600, Some(60.0), Some(120.0)));
        assert!(proven(true, 300, 3600, Some(300.0), Some(3600.0)));
    }

    #[test]
    fn evidence_over_target_or_stale_is_not_proven() {
        assert!(!proven(true, 30, 3600, Some(60.0), Some(120.0)));
        assert!(!proven(true, 300, 60, Some(60.0), Some(120.0)));
        assert!(!proven(false, 300, 3600, Some(60.0), Some(120.0)));
        assert!(!proven(true, 300, 3600, None, Some(120.0)));
    }

    #[test]
    fn the_profile_defaults_to_the_configured_one() {
        assert_eq!(profile_or(None, "solo").unwrap(), "solo");
        assert_eq!(profile_or(Some("ha"), "solo").unwrap(), "ha");
        assert_eq!(profile_or(Some(" "), "team").unwrap(), "team");
        assert!(profile_or(Some("huge"), "solo").is_err());
    }
}
