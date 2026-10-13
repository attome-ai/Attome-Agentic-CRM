//! Runtime settings API — `/api/v1/admin/settings` and `/api/v1/settings/me`
//! (M02, D-412).
//!
//! Thin handlers over `attome_core::{setting_descriptor, setting_store}` —
//! this file parses requests, checks the closed descriptor catalogue and the
//! boot-time-only guard, and calls the engine layer's resolve/write
//! primitives; it does not itself decide what a valid setting looks like.
//!
//! Every write is audited (`AuditCategory::Entity`, matching the schema-admin
//! convention `admin::attribute`'s writes use — this table is metadata-like,
//! not a business record) and goes through the same
//! `attome-core/setting-write:{key}` advisory lock regardless of which
//! route reached it, so an admin `PUT /admin/settings/{key}` and a user's own
//! `PUT /settings/me/{key}` for the same key can never race each other.

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource, fetch_audit_ctx,
};
use attome_core::{
    EngineState, SettingScope, SettingSource, acquire_setting_write_lock,
    append_setting_change_log, load_all_settings, setting_registry, validate_against_schema,
};
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::admin::{audit_service, pin_write_best_effort, simple_field_change};

#[derive(Serialize, ToSchema)]
pub(crate) struct SettingValueView {
    key: String,
    description: String,
    schema: serde_json::Value,
    allowed_scopes: Vec<String>,
    boot_time_only: bool,
    value: serde_json::Value,
    source: String,
    updated_at: Option<DateTime<Utc>>,
}

#[derive(Serialize, ToSchema)]
struct SettingListResponse {
    items: Vec<SettingValueView>,
}

#[derive(Deserialize, ToSchema)]
struct PutSettingRequest {
    scope: SettingScope,
    /// Required when `scope` is `organization` or `user`; must be omitted
    /// (or null) when `scope` is `deployment` — the same shape
    /// `setting`'s CHECK constraint enforces at the database.
    scope_ref: Option<Uuid>,
    value: serde_json::Value,
}

#[derive(Deserialize, ToSchema)]
struct PutSelfSettingRequest {
    value: serde_json::Value,
}

use utoipa::ToSchema;

/// Shared write path for both `PUT /admin/settings/{key}` and
/// `PUT /settings/me/{key}` — validates the descriptor/scope/schema, takes
/// the per-key advisory lock, upserts the row + change-log entry + audit
/// event in one transaction, then (after commit) synchronously refreshes
/// this node's own `state.settings` cache so the actor's own next read is
/// never stale — other nodes catch up via the poll loop in `system.rs`
/// (`setting_store`'s module doc explains why that's poll-only).
pub(crate) async fn write_setting(
    state: &EngineState,
    actor_user_id: Uuid,
    key: &str,
    scope: SettingScope,
    scope_ref: Option<Uuid>,
    value: serde_json::Value,
) -> Result<SettingValueView, AppError> {
    let registry = setting_registry();
    let descriptor = registry.get(key).ok_or(AppError::NotFound)?;

    if descriptor.boot_time_only {
        return Err(AppError::Validation(format!(
            "{key} is boot-time-only configuration (config.json/environment, D-038) and \
             can never be written through the runtime settings API"
        )));
    }
    if !descriptor.allows_scope(scope) {
        return Err(AppError::Validation(format!(
            "{key} does not allow the {scope:?} scope",
        )));
    }
    match scope {
        SettingScope::Deployment if scope_ref.is_some() => {
            return Err(AppError::Validation(
                "scope_ref must be omitted for deployment-scope settings".to_owned(),
            ));
        }
        SettingScope::Organization | SettingScope::User if scope_ref.is_none() => {
            return Err(AppError::Validation(
                "scope_ref is required for organization- and user-scope settings".to_owned(),
            ));
        }
        _ => {}
    }
    let schema = (descriptor.schema)();
    validate_against_schema(&value, &schema).map_err(AppError::Validation)?;

    let (user_ctx, org_ref) = fetch_audit_ctx(state, actor_user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    acquire_setting_write_lock(&mut tx, key).await?;

    let updated: Option<(Uuid, i64, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE setting \
         SET value = $1, schema = $2, updated_at = NOW(), row_version = row_version + 1 \
         WHERE key = $3 AND scope = $4 AND scope_ref IS NOT DISTINCT FROM $5 AND is_deleted = FALSE \
         RETURNING id, row_version, updated_at",
    )
    .bind(&value)
    .bind(&schema)
    .bind(key)
    .bind(scope.as_str())
    .bind(scope_ref)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let (row_id, updated_at) = match updated {
        Some((id, _row_version, updated_at)) => (id, updated_at),
        None => {
            let (id, updated_at): (Uuid, DateTime<Utc>) = sqlx::query_as(
                "INSERT INTO setting (key, scope, scope_ref, value, schema) \
                 VALUES ($1, $2, $3, $4, $5) RETURNING id, updated_at",
            )
            .bind(key)
            .bind(scope.as_str())
            .bind(scope_ref)
            .bind(&value)
            .bind(&schema)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (id, updated_at)
        }
    };

    append_setting_change_log(&mut tx, key, scope, scope_ref, false).await?;

    audit_service(state)
        .write_in_tx(
            &mut tx,
            AuditEvent {
                organization_ref: org_ref,
                category: AuditCategory::Entity,
                entity_name: Some("setting".to_owned()),
                record_id: Some(row_id),
                operation: AuditOperation::Update,
                version_before: None,
                version_after: None,
                user_context: user_ctx,
                changed_on: Utc::now(),
                source: AuditSource::Api,
                request_context: AuditRequestContext::default(),
                correlation_id: None,
                batch_id: None,
                event_name: Some("setting_changed".to_owned()),
                event_comment: Some(format!("{key} set at {} scope", scope.as_str())),
                changed_fields: vec![simple_field_change("value", None, Some(value.to_string()))],
                snapshot_json: None,
            },
        )
        .await?;

    attome_db::tx::commit(tx).await?;

    pin_write_best_effort(state, actor_user_id, "setting.write").await;

    // Synchronous local refresh — see the fn doc and setting_store's module
    // doc for why other nodes rely on the poll loop instead.
    match load_all_settings(&state.base.db).await {
        Ok(snapshot) => state.settings.swap(snapshot),
        Err(e) => tracing::warn!(
            error = %e,
            key,
            "failed to refresh local settings cache after write — will self-heal on next poll tick",
        ),
    }

    Ok(SettingValueView {
        key: descriptor.key.to_owned(),
        description: descriptor.description.to_owned(),
        schema,
        allowed_scopes: descriptor
            .allowed_scopes
            .iter()
            .map(|s| s.as_str().to_owned())
            .collect(),
        boot_time_only: descriptor.boot_time_only,
        value,
        source: match scope {
            SettingScope::User => "user",
            SettingScope::Organization => "organization",
            SettingScope::Deployment => "deployment",
        }
        .to_owned(),
        updated_at: Some(updated_at),
    })
}

fn source_label(source: SettingSource) -> &'static str {
    match source {
        SettingSource::User => "user",
        SettingSource::Organization => "organization",
        SettingSource::Deployment => "deployment",
        SettingSource::CodeDefault => "default",
    }
}

/// Lists every runtime-eligible setting with its deployment-perspective
/// effective value (deployment override if one exists, else the code
/// default) — an administrator's overview, not any one user's resolved
/// view. `boot_time_only` descriptors never appear here (M02 §6).
#[utoipa::path(
    get,
    path = "/api/v1/admin/settings",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = SettingListResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_admin_settings(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<SettingListResponse>, AppError> {
    let snapshot = state.settings.load();
    let items = setting_registry()
        .runtime_eligible()
        .map(|d| {
            let (value, source) = snapshot.resolve(d, None, None);
            let row = snapshot
                .rows_for(d.key)
                .iter()
                .find(|r| r.scope == "deployment" && r.scope_ref.is_none());
            SettingValueView {
                key: d.key.to_owned(),
                description: d.description.to_owned(),
                schema: (d.schema)(),
                allowed_scopes: d
                    .allowed_scopes
                    .iter()
                    .map(|s| s.as_str().to_owned())
                    .collect(),
                boot_time_only: d.boot_time_only,
                value,
                source: source_label(source).to_owned(),
                updated_at: row.map(|r| r.updated_at),
            }
        })
        .collect();
    Ok(Json(SettingListResponse { items }))
}

/// Sets a value at an explicit scope — the admin-only path, able to write
/// deployment defaults or seed an organization's/user's override on their
/// behalf. Rejects `boot_time_only` keys (M02 §6's required behavior) and
/// any key `SettingRegistry` doesn't recognize.
#[utoipa::path(
    put,
    path = "/api/v1/admin/settings/{key}",
    tag = "admin",
    params(("key" = String, Path, description = "Setting key, \"{module}.{name}\"")),
    request_body = PutSettingRequest,
    responses(
        (status = 200, description = "Success", body = SettingValueView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown setting key", body = ErrorResponse),
        (status = 422, description = "Validation failed, or the key is boot-time-only", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
async fn put_admin_setting(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(key): Path<String>,
    Json(request): Json<PutSettingRequest>,
) -> Result<Json<SettingValueView>, AppError> {
    let view = write_setting(
        &state,
        ctx.user_id,
        &key,
        request.scope,
        request.scope_ref,
        request.value,
    )
    .await?;
    Ok(Json(view))
}

/// Every runtime-eligible setting that allows the `user` scope, resolved for
/// the calling user (their own override, else their organization's, else
/// the deployment default, else the code default) — self-service, same
/// posture as the sidebar's own `SelfService`-gated GET.
#[utoipa::path(
    get,
    path = "/api/v1/settings/me",
    tag = "settings",
    responses(
        (status = 200, description = "Success", body = SettingListResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_my_settings(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<SettingListResponse>, AppError> {
    let (_user_ctx, org_ref) = fetch_audit_ctx(&state, ctx.user_id).await;
    let snapshot = state.settings.load();
    let items = setting_registry()
        .runtime_eligible()
        .filter(|d| d.allows_scope(SettingScope::User))
        .map(|d| {
            let (value, source) = snapshot.resolve(d, Some(ctx.user_id), Some(org_ref));
            SettingValueView {
                key: d.key.to_owned(),
                description: d.description.to_owned(),
                schema: (d.schema)(),
                allowed_scopes: d
                    .allowed_scopes
                    .iter()
                    .map(|s| s.as_str().to_owned())
                    .collect(),
                boot_time_only: d.boot_time_only,
                value,
                source: source_label(source).to_owned(),
                updated_at: None,
            }
        })
        .collect();
    Ok(Json(SettingListResponse { items }))
}

/// Sets the calling user's own override for one setting. Only settings whose
/// descriptor `allows_scope(User)` can be set here — everything else is a
/// 422, the same message shape `write_setting` already produces for an
/// admin request naming a disallowed scope.
#[utoipa::path(
    put,
    path = "/api/v1/settings/me/{key}",
    tag = "settings",
    params(("key" = String, Path, description = "Setting key, \"{module}.{name}\"")),
    request_body = PutSelfSettingRequest,
    responses(
        (status = 200, description = "Success", body = SettingValueView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Unknown setting key", body = ErrorResponse),
        (status = 422, description = "Validation failed, the key is boot-time-only, or it does not allow the user scope", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
async fn put_my_setting(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(key): Path<String>,
    Json(request): Json<PutSelfSettingRequest>,
) -> Result<Json<SettingValueView>, AppError> {
    let view = write_setting(
        &state,
        ctx.user_id,
        &key,
        SettingScope::User,
        Some(ctx.user_id),
        request.value,
    )
    .await?;
    Ok(Json(view))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/settings", get(list_admin_settings))
        .route("/api/v1/admin/settings/{key}", put(put_admin_setting))
        .route("/api/v1/settings/me", get(get_my_settings))
        .route("/api/v1/settings/me/{key}", put(put_my_setting))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_admin_settings,
    put_admin_setting,
    get_my_settings,
    put_my_setting
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
