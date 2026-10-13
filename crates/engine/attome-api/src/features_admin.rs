//! Feature-flag API — `/api/v1/admin/features` and `/api/v1/features` (M95,
//! D-430).
//!
//! Thin handlers over `attome_core::{feature_flag_descriptor,
//! feature_flag_store}` — this file resolves the closed-catalogue lookup,
//! runs the `requires`-dependency check, and delegates the actual storage
//! write to `settings_admin::write_setting` (the same tx/advisory-lock/
//! change-log/audit/local-cache-refresh path `PUT /api/v1/admin/settings/{key}`
//! already uses — a feature flag's stored value is, after all, just one more
//! `setting` row at the `feature.*` namespace). It does not itself
//! decide what a valid flag value looks like beyond that dependency check;
//! `FeatureFlagPolicy::validate` (attome-core) owns the value-shape rules.

use std::collections::HashMap;

use attome_core::{
    EngineState, FeatureFlagPolicy, SettingScope, feature_flag_registry, validate_flag_dependencies,
};
use attome_modules::MODULE_MAP;
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, put},
};
use serde::Serialize;
use utoipa::ToSchema;

fn module_name(module: attome_modules::ModuleId) -> &'static str {
    MODULE_MAP
        .iter()
        .find(|(_, id)| *id == module)
        .map(|(name, _)| *name)
        .unwrap_or("unknown")
}

#[derive(Serialize, ToSchema)]
struct FeatureFlagView {
    key: String,
    module: String,
    description: String,
    default: bool,
    requires: Vec<String>,
    policy: FeatureFlagPolicy,
}

#[derive(Serialize, ToSchema)]
struct FeatureFlagListResponse {
    items: Vec<FeatureFlagView>,
}

#[derive(Serialize, ToSchema)]
struct EffectiveFeaturesResponse {
    flags: HashMap<String, bool>,
}

fn view_for(state: &EngineState, key: &str) -> Option<FeatureFlagView> {
    let flag = feature_flag_registry().get(key)?;
    let snapshot = state.settings.load();
    let policy = snapshot
        .rows_for(&flag.setting_key())
        .iter()
        .find(|r| r.scope == "deployment" && r.scope_ref.is_none())
        .and_then(|r| serde_json::from_value::<FeatureFlagPolicy>(r.value.clone()).ok())
        .unwrap_or(FeatureFlagPolicy {
            deployment: flag.default,
            ..Default::default()
        });
    Some(FeatureFlagView {
        key: flag.key.to_owned(),
        module: module_name(flag.module).to_owned(),
        description: flag.description.to_owned(),
        default: flag.default,
        requires: flag.requires.iter().map(|s| s.to_string()).collect(),
        policy,
    })
}

/// Every registered flag with its current stored policy — the Module
/// Management "Feature Flags" admin listing.
#[utoipa::path(
    get,
    path = "/api/v1/admin/features",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = FeatureFlagListResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_features(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<FeatureFlagListResponse>, AppError> {
    let items = feature_flag_registry()
        .iter()
        .filter_map(|flag| view_for(&state, flag.key))
        .collect();
    Ok(Json(FeatureFlagListResponse { items }))
}

/// Sets a flag's stored policy value (deployment default, user/role
/// overrides, rollout percentage). Rejects an unknown key (404) and rejects
/// turning `deployment` on while a `requires` prerequisite is not itself
/// enabled deployment-wide (422, M95 checklist item 3).
#[utoipa::path(
    put,
    path = "/api/v1/admin/features/{key}",
    tag = "admin",
    params(("key" = String, Path, description = "Feature flag key, \"{module}.{name}\"")),
    request_body = FeatureFlagPolicy,
    responses(
        (status = 200, description = "Success", body = FeatureFlagView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown feature flag key", body = ErrorResponse),
        (status = 422, description = "Validation failed, or a required prerequisite flag is not enabled", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
async fn put_feature_flag(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(key): Path<String>,
    Json(policy): Json<FeatureFlagPolicy>,
) -> Result<Json<FeatureFlagView>, AppError> {
    let flag = feature_flag_registry()
        .get(&key)
        .ok_or(AppError::NotFound)?;

    policy.validate().map_err(AppError::Validation)?;

    {
        let snapshot = state.settings.load();
        validate_flag_dependencies(flag, policy.deployment, &snapshot)
            .map_err(AppError::Validation)?;
    }

    let value = serde_json::to_value(&policy).map_err(AppError::internal)?;
    // Reuses the M02 settings write path in full (advisory lock, change log,
    // audit event with actor + "deployment scope", local cache refresh) —
    // see this file's module doc.
    let _ = crate::settings_admin::write_setting(
        &state,
        ctx.user_id,
        &flag.setting_key(),
        SettingScope::Deployment,
        None,
        value,
    )
    .await?;

    // The moka evaluation cache is derived from `state.settings`, which
    // `write_setting` above already refreshed synchronously on this node —
    // drop every cached evaluation so the actor's own next read (and every
    // other request landing on this node) recomputes against the new value
    // rather than serving a stale cached bool for up to the TTL.
    state.invalidate_feature_flags().await;

    Ok(Json(view_for(&state, &key).ok_or(AppError::NotFound)?))
}

/// Every registered flag, evaluated for the calling user — what `/api/v1/features`
/// gives Angular's `FeatureService` so the UI and the API agree on what's on.
#[utoipa::path(
    get,
    path = "/api/v1/features",
    tag = "settings",
    responses(
        (status = 200, description = "Success", body = EffectiveFeaturesResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_effective_features(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<EffectiveFeaturesResponse>, AppError> {
    let flags = state.feature_flags().effective(&ctx).await;
    Ok(Json(EffectiveFeaturesResponse { flags }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/features", get(list_features))
        .route("/api/v1/admin/features/{key}", put(put_feature_flag))
        .route("/api/v1/features", get(get_effective_features))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_features, put_feature_flag, get_effective_features))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
