//! AB11-T5: planned maintenance windows.
//!
//! - `POST /api/v1/ops/maintenance` plans one (`ops.incident.publish`): both
//!   titles, a start in the future and an end after it.
//! - `PATCH /api/v1/ops/maintenance/{id}` (`If-Match`) changes a window that
//!   is not cancelled or over; `POST /api/v1/ops/maintenance/{id}/cancel`
//!   (`If-Match`) cancels it.
//! - `GET /api/v1/ops/maintenance?from=&to=`: the windows overlapping the
//!   range, for any signed-in user (internal ones for `ops.read` holders):
//!   what the banner announces and what SLA reports exclude
//!   ([`exclusions`]).
//!
//! Every write commits with its Configuration event and clears the cached
//! status snapshot. Reminders 24 hours and 1 hour before a window are sent
//! with subscriber delivery (AB11-T6).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey, SelfService};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::incidents::{AUDIENCES, OpsIncidentPublish};
use crate::upgrades::OpsRead;

const MAX_TITLE: usize = 200;
/// The widest range one list may ask for.
const MAX_RANGE_DAYS: i64 = 400;

const COLUMNS: &str = "id, title_en, title_ar, components, starts_at, ends_at, audience, \
     created_by, cancelled_at, row_version";

/// A maintenance window.
#[derive(Debug, Clone, Serialize, sqlx::FromRow, ToSchema)]
pub struct Maintenance {
    pub id: Uuid,
    pub title_en: String,
    pub title_ar: Option<String>,
    pub components: Vec<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    /// `internal` or `public`.
    pub audience: String,
    pub created_by: Option<Uuid>,
    pub cancelled_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

/// A window to plan.
#[derive(Debug, Deserialize, ToSchema)]
pub struct NewMaintenance {
    pub title_en: String,
    pub title_ar: String,
    #[serde(default)]
    pub components: Vec<String>,
    pub starts_at: DateTime<Utc>,
    pub ends_at: DateTime<Utc>,
    /// `public` (the default) or `internal`.
    #[serde(default)]
    pub audience: Option<String>,
}

/// A window's changes; an absent field is kept.
#[derive(Debug, Deserialize, ToSchema)]
pub struct MaintenanceChange {
    pub title_en: Option<String>,
    pub title_ar: Option<String>,
    pub components: Option<Vec<String>>,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub audience: Option<String>,
}

/// The range a list covers; the next 30 days when absent.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MaintenanceRange {
    /// Windows ending after this moment.
    pub from: Option<DateTime<Utc>>,
    /// Windows starting before this moment.
    pub to: Option<DateTime<Utc>>,
}

/// A window's shape: both titles, an end after its start, and (on create)
/// a start in the future. Pure.
pub fn check_window(
    title_en: &str,
    title_ar: &str,
    starts_at: DateTime<Utc>,
    ends_at: DateTime<Utc>,
    now: Option<DateTime<Utc>>,
) -> Result<(), AppError> {
    for (field, title) in [("title_en", title_en), ("title_ar", title_ar)] {
        let len = title.trim().chars().count();
        if len == 0 || len > MAX_TITLE {
            return Err(AppError::Validation(format!(
                "{field} must be 1 to {MAX_TITLE} characters"
            )));
        }
    }
    if ends_at <= starts_at {
        return Err(AppError::Validation(
            "ends_at must be after starts_at".into(),
        ));
    }
    if let Some(now) = now
        && starts_at <= now
    {
        return Err(AppError::Validation(
            "starts_at must be in the future".into(),
        ));
    }
    Ok(())
}

/// AB1: the `(start, end)` spans an SLA report leaves out, merged where
/// windows overlap, from windows not cancelled. Pure.
pub fn exclusions(windows: &[Maintenance]) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let mut spans: Vec<(DateTime<Utc>, DateTime<Utc>)> = windows
        .iter()
        .filter(|w| w.cancelled_at.is_none())
        .map(|w| (w.starts_at, w.ends_at))
        .collect();
    spans.sort();
    let mut merged: Vec<(DateTime<Utc>, DateTime<Utc>)> = Vec::new();
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
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
        "ops_maintenance",
        Some(id),
    )
    .named(name.to_owned())
    .comment(comment)
}

fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Validation("If-Match is required".into()))?;
    raw.trim().trim_matches('"').parse::<i64>().map_err(|_| {
        AppError::Validation(format!(
            "If-Match must be a row_version integer, got: {raw}"
        ))
    })
}

async fn check_components(
    tx: &mut sqlx::PgConnection,
    components: &[String],
) -> Result<(), AppError> {
    if components.is_empty() {
        return Ok(());
    }
    let known: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT key) FROM ops_status_component WHERE key = ANY($1)",
    )
    .bind(components)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let distinct = components
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if usize::try_from(known).unwrap_or(0) != distinct {
        return Err(AppError::Validation(
            "components must name status components".into(),
        ));
    }
    Ok(())
}

/// Plan maintenance
///
/// AB11-T5: both titles, a future start and a later end. Needs
/// `ops.incident.publish`. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/maintenance",
    tag = "ops",
    operation_id = "create_ops_maintenance",
    request_body = NewMaintenance,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The planned window", body = Maintenance),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.incident.publish", body = ErrorResponse),
        (status = 422, description = "A missing title, a past start, an end before the start, or an unknown component", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_maintenance(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsIncidentPublish>>,
    Json(body): Json<NewMaintenance>,
) -> Result<(StatusCode, Json<Maintenance>), AppError> {
    check_window(
        &body.title_en,
        &body.title_ar,
        body.starts_at,
        body.ends_at,
        Some(Utc::now()),
    )?;
    let audience = body.audience.as_deref().unwrap_or("public");
    if !AUDIENCES.contains(&audience) {
        return Err(AppError::Validation(
            "audience must be internal or public".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    check_components(&mut tx, &body.components).await?;
    let window: Maintenance = sqlx::query_as(&format!(
        "INSERT INTO ops_maintenance (id, title_en, title_ar, components, starts_at, ends_at, audience, created_by) \
         VALUES (uuidv7(), $1, $2, $3, $4, $5, $6, $7) RETURNING {COLUMNS}"
    ))
    .bind(body.title_en.trim())
    .bind(body.title_ar.trim())
    .bind(&body.components)
    .bind(body.starts_at)
    .bind(body.ends_at)
    .bind(audience)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Create,
            ctx.user_id,
            window.id,
            "ops.maintenance_planned",
            format!("maintenance planned: {}", window.title_en),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::public_status::invalidate();
    Ok((StatusCode::CREATED, Json(window)))
}

/// Change maintenance
///
/// AB11-T5: a window not cancelled and not over. `If-Match` names the row
/// version. Needs `ops.incident.publish`. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/ops/maintenance/{id}",
    tag = "ops",
    operation_id = "update_ops_maintenance",
    params(
        ("id" = Uuid, Path, description = "The window"),
        ("If-Match" = String, Header, description = "The window's row_version, quoted"),
    ),
    request_body = MaintenanceChange,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The changed window", body = Maintenance),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.incident.publish", body = ErrorResponse),
        (status = 404, description = "No such window", body = ErrorResponse),
        (status = 409, description = "Cancelled or over, or a stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match missing, or an invalid field", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_maintenance(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsIncidentPublish>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<MaintenanceChange>,
) -> Result<Json<Maintenance>, AppError> {
    let expected = if_match(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<Maintenance> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_maintenance WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let current = current.ok_or(AppError::NotFound)?;
    if current.cancelled_at.is_some() || current.ends_at <= Utc::now() {
        return Err(AppError::Conflict("this window is cancelled or over"));
    }
    if current.row_version != expected {
        return Err(AppError::VersionConflict);
    }
    let title_en = body
        .title_en
        .clone()
        .unwrap_or_else(|| current.title_en.clone());
    let title_ar = body
        .title_ar
        .clone()
        .or_else(|| current.title_ar.clone())
        .unwrap_or_default();
    let starts_at = body.starts_at.unwrap_or(current.starts_at);
    let ends_at = body.ends_at.unwrap_or(current.ends_at);
    // A start already passed may stay; a moved start must be in the future.
    let moved = body.starts_at.filter(|s| *s != current.starts_at);
    check_window(
        &title_en,
        &title_ar,
        starts_at,
        ends_at,
        moved.map(|_| Utc::now()),
    )?;
    let audience = body
        .audience
        .clone()
        .unwrap_or_else(|| current.audience.clone());
    if !AUDIENCES.contains(&audience.as_str()) {
        return Err(AppError::Validation(
            "audience must be internal or public".into(),
        ));
    }
    let components = body
        .components
        .clone()
        .unwrap_or_else(|| current.components.clone());
    check_components(&mut tx, &components).await?;
    let window: Maintenance = sqlx::query_as(&format!(
        "UPDATE ops_maintenance SET title_en = $2, title_ar = $3, components = $4, \
            starts_at = $5, ends_at = $6, audience = $7, row_version = row_version + 1 \
          WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(title_en.trim())
    .bind(title_ar.trim())
    .bind(&components)
    .bind(starts_at)
    .bind(ends_at)
    .bind(&audience)
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
            "ops.maintenance_changed",
            format!("maintenance changed: {}", window.title_en),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::public_status::invalidate();
    Ok(Json(window))
}

/// Cancel maintenance
///
/// AB11-T5: `If-Match` names the row version. Needs
/// `ops.incident.publish`. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/ops/maintenance/{id}/cancel",
    tag = "ops",
    operation_id = "cancel_ops_maintenance",
    params(
        ("id" = Uuid, Path, description = "The window"),
        ("If-Match" = String, Header, description = "The window's row_version, quoted"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Cancelled)])))),
    responses(
        (status = 200, description = "The cancelled window", body = Maintenance),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks ops.incident.publish", body = ErrorResponse),
        (status = 404, description = "No such window", body = ErrorResponse),
        (status = 409, description = "Already cancelled, or a stale row_version", body = ErrorResponse),
        (status = 422, description = "If-Match is missing or not a row_version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cancel_maintenance(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpsIncidentPublish>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<Maintenance>, AppError> {
    let expected = if_match(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<(Option<DateTime<Utc>>, i64)> = sqlx::query_as(
        "SELECT cancelled_at, row_version FROM ops_maintenance WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (cancelled_at, version) = current.ok_or(AppError::NotFound)?;
    if cancelled_at.is_some() {
        return Err(AppError::Conflict("this window is already cancelled"));
    }
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    let window: Maintenance = sqlx::query_as(&format!(
        "UPDATE ops_maintenance SET cancelled_at = now(), row_version = row_version + 1 \
          WHERE id = $1 RETURNING {COLUMNS}"
    ))
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        event(
            AuditOperation::Cancelled,
            ctx.user_id,
            id,
            "ops.maintenance_cancelled",
            format!("maintenance cancelled: {}", window.title_en),
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    crate::public_status::invalidate();
    Ok(Json(window))
}

/// List maintenance
///
/// AB11-T5: windows overlapping `from`..`to` (the next 30 days when
/// absent; at most 400 days), cancelled ones included and marked. Any
/// signed-in user; internal windows need `ops.read`.
#[utoipa::path(
    get,
    path = "/api/v1/ops/maintenance",
    tag = "ops",
    operation_id = "list_ops_maintenance",
    params(MaintenanceRange),
    responses(
        (status = 200, description = "The windows in the range, earliest first", body = PaginatedResponse<Maintenance>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "to before from, or a range over 400 days", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_maintenance(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(range): Query<MaintenanceRange>,
) -> Result<Json<PaginatedResponse<Maintenance>>, AppError> {
    let from = range.from.unwrap_or_else(Utc::now);
    let to = range.to.unwrap_or(from + chrono::Duration::days(30));
    if to <= from || to - from > chrono::Duration::days(MAX_RANGE_DAYS) {
        return Err(AppError::Validation(format!(
            "to must be after from, at most {MAX_RANGE_DAYS} days later"
        )));
    }
    let internal = ctx.is_admin || ctx.privileges.contains(OpsRead::KEY);
    let items: Vec<Maintenance> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM ops_maintenance \
          WHERE ends_at > $1 AND starts_at < $2 AND ($3 OR audience = 'public') \
          ORDER BY starts_at, id"
    ))
    .bind(from)
    .bind(to)
    .bind(internal)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/ops/maintenance",
            get(list_maintenance).post(create_maintenance),
        )
        .route("/api/v1/ops/maintenance/{id}", patch(update_maintenance))
        .route(
            "/api/v1/ops/maintenance/{id}/cancel",
            post(cancel_maintenance),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_maintenance,
        update_maintenance,
        cancel_maintenance,
        list_maintenance
    ),
    components(schemas(Maintenance, NewMaintenance, MaintenanceChange))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(hours: i64) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1_800_000_000 + hours * 3600, 0).unwrap()
    }

    #[test]
    fn window_end_before_start_is_422() {
        assert!(check_window("Upgrade", "ترقية", at(2), at(1), None).is_err());
        assert!(check_window("Upgrade", "ترقية", at(2), at(2), None).is_err());
        assert!(check_window("Upgrade", "", at(1), at(2), None).is_err());
        assert!(
            check_window("Upgrade", "ترقية", at(1), at(2), Some(at(3))).is_err(),
            "a past start"
        );
        assert!(check_window("Upgrade", "ترقية", at(4), at(5), Some(at(3))).is_ok());
    }

    #[test]
    fn exclusions_merge_overlaps_and_skip_cancelled() {
        let window = |start: i64, end: i64, cancelled: bool| Maintenance {
            id: Uuid::now_v7(),
            title_en: "w".into(),
            title_ar: None,
            components: Vec::new(),
            starts_at: at(start),
            ends_at: at(end),
            audience: "public".into(),
            created_by: None,
            cancelled_at: cancelled.then(|| at(0)),
            row_version: 1,
        };
        let spans = exclusions(&[
            window(5, 8, false),
            window(1, 3, false),
            window(2, 4, false),
            window(9, 10, true),
        ]);
        assert_eq!(spans, vec![(at(1), at(4)), (at(5), at(8))]);
    }
}
