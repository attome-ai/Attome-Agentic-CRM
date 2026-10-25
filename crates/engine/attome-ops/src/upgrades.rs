//! AB8-T6: the upgrade record (`ops_upgrade`, migration 0263).
//!
//! - `POST /api/v1/ops/upgrades` records an upgrade's start: the versions,
//!   the safety point (the backup or snapshot to go back to) and the
//!   pre-upgrade check report. It needs `ops.upgrade.run` and a fresh
//!   step-up (`platform_upgrade`).
//! - `PATCH /api/v1/ops/upgrades/{id}` moves its status (`If-Match` names
//!   the row version): `started` to `verified`, `failed` or `rolled_back`,
//!   and `verified` or `failed` to `rolled_back`; with the verification's
//!   evidence id and when the contract step ran.
//! - `GET /api/v1/ops/upgrades` pages the history, newest first
//!   (`ops.read`).
//!
//! Each write commits with its Configuration event (`ops.upgrade_started`,
//! `ops.upgrade_status_changed`).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// `ops.upgrade.run`: who starts and records upgrades.
#[derive(Debug)]
pub struct OpsUpgradeRun;

impl PrivilegeKey for OpsUpgradeRun {
    const KEY: &'static str = "ops.upgrade.run";
}

/// `ops.read`: who reads operations history.
#[derive(Debug)]
pub struct OpsRead;

impl PrivilegeKey for OpsRead {
    const KEY: &'static str = "ops.read";
}

const COLUMNS: &str = "id, from_version, to_version, started_by, started_at, finished_at, status, \
     safety_point, check_report, verification_evidence_id, contract_applied_at, row_version";

/// One upgrade.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct Upgrade {
    pub id: Uuid,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub started_by: Option<Uuid>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    /// `started`, `verified`, `failed` or `rolled_back`.
    pub status: String,
    /// The backup or snapshot the upgrade can go back to.
    pub safety_point: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub check_report: Option<Value>,
    pub verification_evidence_id: Option<Uuid>,
    pub contract_applied_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// An upgrade starting.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StartUpgrade {
    pub from_version: String,
    pub to_version: String,
    #[serde(default)]
    pub safety_point: Option<String>,
    /// The pre-upgrade checks' report.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub check_report: Option<Value>,
}

/// An upgrade's status change.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct UpgradeStatus {
    /// `verified`, `failed` or `rolled_back`.
    pub status: String,
    /// The signed evidence of the verification (AB4-T2).
    #[serde(default)]
    pub verification_evidence_id: Option<Uuid>,
    /// When the contract step (the old schema's removal) ran.
    #[serde(default)]
    pub contract_applied_at: Option<DateTime<Utc>>,
}

/// Whether an upgrade may move from `from` to `to`. Pure.
pub fn transition_allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("started", "verified" | "failed" | "rolled_back") | ("verified" | "failed", "rolled_back")
    )
}

fn version_ok(v: &str) -> bool {
    let v = v.trim();
    !v.is_empty()
        && v.len() <= 64
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+_".contains(c))
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))?
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    raw.parse::<i64>().map_err(|_| {
        AppError::Validation(format!(
            "If-Match must be a row_version integer, got: {raw}"
        ))
    })
}

fn event(
    operation: AuditOperation,
    actor: Uuid,
    id: Uuid,
    name: &str,
    comment: String,
) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "ops_upgrade",
        Some(id),
    )
    .named(name.to_owned())
    .comment(comment)
}

/// Record an upgrade's start
///
/// AB8-T6: the versions, the safety point and the pre-upgrade check
/// report. Needs `ops.upgrade.run` and a fresh step-up
/// (`platform_upgrade`, 15 minutes). Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/upgrades",
    tag = "ops",
    operation_id = "start_ops_upgrade",
    request_body = StartUpgrade,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The upgrade, started", body = Upgrade),
        (status = 401, description = "Missing or invalid credentials, or `reauth_required` without a step-up in the last 15 minutes", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.upgrade.run", body = ErrorResponse),
        (status = 422, description = "A version that is empty or not a version string", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start_upgrade(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsUpgradeRun>>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    Json(body): Json<StartUpgrade>,
) -> Result<(StatusCode, Json<Upgrade>), AppError> {
    if !version_ok(&body.from_version) || !version_ok(&body.to_version) {
        return Err(AppError::Validation(
            "from_version and to_version are version strings".into(),
        ));
    }
    attome_auth::step_up::require_recent_auth(
        &state.base.db,
        caller,
        ctx.user_id,
        attome_auth::step_up::Operation::PlatformUpgrade,
        state.base.config.refresh_absolute_lifetime_secs(),
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let upgrade: Upgrade = sqlx::query_as(&format!(
        "INSERT INTO ops_upgrade (id, from_version, to_version, started_by, started_at, status, \
                                  safety_point, check_report) \
         VALUES (uuidv7(), $1, $2, $3, now(), 'started', $4, $5) RETURNING {COLUMNS}"
    ))
    .bind(body.from_version.trim())
    .bind(body.to_version.trim())
    .bind(ctx.user_id)
    .bind(body.safety_point.as_deref().map(str::trim))
    .bind(&body.check_report)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Create,
            ctx.user_id,
            upgrade.id,
            "ops.upgrade_started",
            format!(
                "upgrade {} to {} started",
                body.from_version.trim(),
                body.to_version.trim()
            ),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(upgrade)))
}

/// Record an upgrade's status
///
/// AB8-T6: verified, failed or rolled back, with the verification's
/// evidence id and when the contract step ran. `If-Match` names the row
/// version. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/ops/upgrades/{id}",
    tag = "ops",
    operation_id = "update_ops_upgrade",
    params(
        ("id" = Uuid, Path, description = "The upgrade"),
        ("If-Match" = String, Header, description = "The upgrade's row_version, quoted"),
    ),
    request_body = UpgradeStatus,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The upgrade", body = Upgrade),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.upgrade.run", body = ErrorResponse),
        (status = 404, description = "No such upgrade", body = ErrorResponse),
        (status = 409, description = "A stale row_version", body = ErrorResponse),
        (status = 422, description = "A missing If-Match, or a status the upgrade cannot move to", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_upgrade(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsUpgradeRun>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<UpgradeStatus>,
) -> Result<Json<Upgrade>, AppError> {
    let expected = if_match(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT status, row_version FROM ops_upgrade WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let (status, version) = current.ok_or(AppError::NotFound)?;
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    if !transition_allowed(&status, &body.status) {
        return Err(AppError::Validation(format!(
            "an upgrade that is {status} cannot become {}",
            body.status
        )));
    }
    let upgrade: Upgrade = sqlx::query_as(&format!(
        "UPDATE ops_upgrade SET status = $2, finished_at = now(), \
                verification_evidence_id = COALESCE($3, verification_evidence_id), \
                contract_applied_at = COALESCE($4, contract_applied_at), \
                row_version = row_version + 1 \
          WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&body.status)
    .bind(body.verification_evidence_id)
    .bind(body.contract_applied_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Update,
            ctx.user_id,
            id,
            "ops.upgrade_status_changed",
            format!("upgrade {status} -> {}", body.status),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(upgrade))
}

/// List upgrades
///
/// AB8-T6: the upgrade history, newest first. Needs `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/upgrades",
    tag = "ops",
    operation_id = "list_ops_upgrades",
    params(OnePageQuery),
    responses(
        (status = 200, description = "One page of upgrades", body = PaginatedResponse<Upgrade>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_upgrades(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OpsRead>>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<Upgrade>>, AppError> {
    let w = page.window();
    let items: Vec<Upgrade> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_upgrade ORDER BY started_at DESC NULLS LAST, id DESC \
          LIMIT $1 OFFSET $2"
    ))
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ops_upgrade")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ops/upgrades",
            get(list_upgrades).post(start_upgrade),
        )
        .route("/api/v1/ops/upgrades/{id}", patch(update_upgrade))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(start_upgrade, update_upgrade, list_upgrades),
    components(schemas(Upgrade, StartUpgrade, UpgradeStatus))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_change_follows_the_lifecycle() {
        assert!(transition_allowed("started", "verified"));
        assert!(transition_allowed("started", "rolled_back"));
        assert!(transition_allowed("verified", "rolled_back"));
        assert!(!transition_allowed("verified", "failed"));
        assert!(!transition_allowed("rolled_back", "started"));
        assert!(!transition_allowed("started", "started"));
    }

    #[test]
    fn status_change_requires_if_match() {
        assert!(if_match(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::IF_MATCH, "\"3\"".parse().unwrap());
        assert_eq!(if_match(&headers).unwrap(), 3);
        assert!(version_ok("2.4.0-rc.1"));
        assert!(!version_ok("2.4 ; drop"));
    }
}
