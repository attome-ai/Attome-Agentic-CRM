//! The device registry routes (roadmap B17-T4) over `user_device` (B17-T3).
//!
//! A signed-in app registers itself and keeps the returned id in secure
//! storage; on every resume it asks `GET /api/v1/devices/me/{id}` whether to
//! wipe, and reports `POST .../wiped` once it has cleared its local data. An
//! administrator lists devices and requests a wipe, which also ends the
//! owner's sessions everywhere (refresh families revoked and the auth epoch
//! bumped) in the same transaction as the mandatory security event, so the
//! device cannot sign back in with what it holds.
//!
//! The owner always comes from the session, never the request body; a device
//! that is not the caller's reads as absent (404), so ids cannot be probed.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

const PLATFORMS: &[&str] = &["ios", "android", "web"];
const APP_KINDS: &[&str] = &["standard", "branded", "pwa"];
const MAX_VERSION_CHARS: usize = 50;
const MAX_LABEL_CHARS: usize = 200;

/// `POST /api/v1/devices`.
#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct RegisterDeviceBody {
    /// The id this device was given before, to refresh it; absent (or no
    /// longer the caller's live device) registers a new one.
    #[serde(default)]
    id: Option<Uuid>,
    /// `ios`, `android` or `web`.
    platform: String,
    /// `standard`, `branded` or `pwa`.
    app_kind: String,
    app_version: String,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub(super) struct RegisteredDevice {
    id: Uuid,
}

/// What an app asks on resume.
#[derive(Debug, Serialize, ToSchema)]
pub(super) struct DeviceStatus {
    /// True when an administrator asked for a wipe the app has not yet done.
    wipe: bool,
}

/// One device, as an administrator sees it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub(super) struct DeviceRow {
    id: Uuid,
    user_id: Uuid,
    user_name: Option<String>,
    platform: String,
    app_kind: String,
    app_version: String,
    label: Option<String>,
    wipe_requested_at: Option<DateTime<Utc>>,
    wiped_at: Option<DateTime<Utc>>,
    last_seen_at: DateTime<Utc>,
    created_at: DateTime<Utc>,
    /// B18-T12: offline sync, when the device has synced.
    last_pull_at: Option<DateTime<Utc>>,
    last_push_at: Option<DateTime<Utc>>,
    /// Changes waiting on the device, as it last reported.
    queue_size: Option<i32>,
    /// Bytes its offline store uses, as it last reported.
    bytes_used: Option<i64>,
    last_sync_error: Option<String>,
    /// A refresh is due at the device's next pull.
    force_refresh: Option<bool>,
}

/// A registration's fields, trimmed and checked against the table's limits.
/// Pure.
fn check_registration(body: &RegisterDeviceBody) -> Result<(String, Option<String>), AppError> {
    if !PLATFORMS.contains(&body.platform.as_str()) {
        return Err(AppError::Validation(
            "platform: must be ios, android or web".into(),
        ));
    }
    if !APP_KINDS.contains(&body.app_kind.as_str()) {
        return Err(AppError::Validation(
            "app_kind: must be standard, branded or pwa".into(),
        ));
    }
    let version = body.app_version.trim();
    if version.is_empty() || version.chars().count() > MAX_VERSION_CHARS {
        return Err(AppError::Validation(format!(
            "app_version: 1 to {MAX_VERSION_CHARS} characters"
        )));
    }
    let label = body
        .label
        .as_deref()
        .map(str::trim)
        .filter(|l| !l.is_empty());
    if label.is_some_and(|l| l.chars().count() > MAX_LABEL_CHARS) {
        return Err(AppError::Validation(format!(
            "label: at most {MAX_LABEL_CHARS} characters"
        )));
    }
    Ok((version.to_owned(), label.map(str::to_owned)))
}

/// Registers this device for the signed-in person, or refreshes it.
#[utoipa::path(
    post,
    path = "/api/v1/devices",
    tag = "auth",
    request_body = RegisterDeviceBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The device id to keep", body = RegisteredDevice),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn register_device(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<RegisterDeviceBody>,
) -> Result<Json<RegisteredDevice>, AppError> {
    let (version, label) = check_registration(&body)?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "user_device",
            None,
        )
        .named("device_register"),
    )
    .await?;
    // A refresh touches only the caller's own device that has not been
    // wiped; anything else registers afresh.
    let refreshed: Option<Uuid> = match body.id {
        Some(id) => sqlx::query_scalar(
            "UPDATE user_device \
                SET platform = $3, app_kind = $4, app_version = $5, label = $6, \
                    last_seen_at = now(), row_version = row_version + 1 \
              WHERE id = $1 AND user_id = $2 AND wiped_at IS NULL \
          RETURNING id",
        )
        .bind(id)
        .bind(ctx.user_id)
        .bind(&body.platform)
        .bind(&body.app_kind)
        .bind(&version)
        .bind(&label)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?,
        None => None,
    };
    let id = match refreshed {
        Some(id) => {
            tx.event_mut().set_comment("device refreshed");
            id
        }
        None => sqlx::query_scalar(
            "INSERT INTO user_device (user_id, platform, app_kind, app_version, label) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(ctx.user_id)
        .bind(&body.platform)
        .bind(&body.app_kind)
        .bind(&version)
        .bind(&label)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?,
    };
    tx.event_mut().set_record_id(id);
    tx.commit().await?;
    Ok(Json(RegisteredDevice { id }))
}

/// Whether this device must wipe itself. Only its owner may ask.
#[utoipa::path(
    get,
    path = "/api/v1/devices/me/{id}",
    tag = "auth",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = DeviceStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such device of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn my_device_status(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<Json<DeviceStatus>, AppError> {
    let wipe: bool = sqlx::query_scalar(
        "SELECT wipe_requested_at IS NOT NULL AND wiped_at IS NULL \
           FROM user_device WHERE id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(ctx.user_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    Ok(Json(DeviceStatus { wipe }))
}

/// The app reports that it cleared its local data after a wipe request.
#[utoipa::path(
    post,
    path = "/api/v1/devices/me/{id}/wiped",
    tag = "auth",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Recorded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No pending wipe on a device of the caller's", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn my_device_wiped(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Update,
            ctx.user_id,
            "user_device",
            Some(id),
        )
        .named("device_wiped"),
    )
    .await?;
    let done = sqlx::query(
        "UPDATE user_device SET wiped_at = now(), row_version = row_version + 1 \
          WHERE id = $1 AND user_id = $2 \
            AND wipe_requested_at IS NOT NULL AND wiped_at IS NULL",
    )
    .bind(id)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if done == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Every registered device, most recently seen first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/devices",
    tag = "admin-security",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DeviceRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_devices(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DeviceRow>>, AppError> {
    let window = query.window();
    let items: Vec<DeviceRow> = sqlx::query_as(
        "SELECT d.id, d.user_id, coalesce(u.user_name, u.email) AS user_name, d.platform, d.app_kind, \
                d.app_version, d.label, d.wipe_requested_at, d.wiped_at, \
                d.last_seen_at, d.created_at, \
                o.last_pull_at, o.last_push_at, o.queue_size, o.bytes_used, \
                o.last_error AS last_sync_error, o.force_refresh \
           FROM user_device d LEFT JOIN user_account u ON u.id = d.user_id \
           LEFT JOIN offline_device_state o ON o.device_id = d.id \
          ORDER BY d.last_seen_at DESC, d.id LIMIT $1 OFFSET $2",
    )
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM user_device")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Asks a device to wipe itself and ends its owner's sessions everywhere.
#[utoipa::path(
    post,
    path = "/api/v1/admin/devices/{id}/wipe",
    tag = "admin-security",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::Revoke)])))),
    responses(
        (status = 204, description = "Wipe requested and sessions ended"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such device", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn wipe_device(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Revoke,
            ctx.user_id,
            "user_device",
            Some(id),
        )
        .named("device_wipe"),
    )
    .await?;
    // A new request restarts the cycle even after an earlier wipe was done.
    let owner: Uuid = sqlx::query_scalar(
        "UPDATE user_device \
            SET wipe_requested_at = now(), wiped_at = NULL, row_version = row_version + 1 \
          WHERE id = $1 RETURNING user_id",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    tx.event_mut().set_comment(format!(
        "device wipe requested; sessions of user {owner} ended"
    ));
    attome_auth::refresh::revoke_all_for_user_in_tx(tx.tx(), owner).await?;
    attome_auth::epoch::bump_in_tx(tx.tx(), owner).await?;
    tx.commit().await?;

    state.base.security.invalidate_sync(owner).await?;
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, owner).await;
    Ok(StatusCode::NO_CONTENT)
}

/// B18-T12: the device starts its offline data again at its next pull: a
/// fresh manifest, every record re-sent.
#[utoipa::path(
    post,
    path = "/api/v1/admin/devices/{id}/offline-refresh",
    tag = "admin-security",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Refresh due at the next pull"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such device, or it has never synced", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn force_offline_refresh(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "user_device",
            Some(id),
        )
        .named("device_offline_refresh"),
    )
    .await?;
    let set =
        sqlx::query("UPDATE offline_device_state SET force_refresh = true WHERE device_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
    if set == 0 {
        return Err(AppError::NotFound);
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/devices", post(register_device))
        .route("/api/v1/devices/me/{id}", get(my_device_status))
        .route("/api/v1/devices/me/{id}/wiped", post(my_device_wiped))
        .route("/api/v1/admin/devices", get(list_devices))
        .route("/api/v1/admin/devices/{id}/wipe", post(wipe_device))
        .route(
            "/api/v1/admin/devices/{id}/offline-refresh",
            post(force_offline_refresh),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    register_device,
    my_device_status,
    my_device_wiped,
    list_devices,
    wipe_device,
    force_offline_refresh
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(platform: &str, kind: &str, version: &str, label: Option<&str>) -> RegisterDeviceBody {
        RegisterDeviceBody {
            id: None,
            platform: platform.into(),
            app_kind: kind.into(),
            app_version: version.into(),
            label: label.map(Into::into),
        }
    }

    #[test]
    fn device_registration_is_checked_against_the_table() {
        let (version, label) =
            check_registration(&body("ios", "standard", " 2.1.0 ", Some("  "))).unwrap();
        assert_eq!(version, "2.1.0");
        assert_eq!(label, None);
        assert!(check_registration(&body("windows", "standard", "1", None)).is_err());
        assert!(check_registration(&body("web", "kiosk", "1", None)).is_err());
        assert!(check_registration(&body("web", "pwa", "  ", None)).is_err());
        assert!(check_registration(&body("web", "pwa", &"9".repeat(51), None)).is_err());
        assert!(check_registration(&body("web", "pwa", "1", Some(&"x".repeat(201)))).is_err());
    }
}
