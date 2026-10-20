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
    /// U10-T3: the stored row this value comes from (its audit trail is
    /// `entity_name = "setting"`, `record_id = id`); `null` while the code
    /// default applies, or in a user's own view.
    id: Option<Uuid>,
    key: String,
    description: String,
    /// U10-T1: the admin console area (`general`, `security`, `features`,
    /// `ai`, `channels`).
    area: String,
    /// U10-T1: the description in Arabic.
    description_ar: Option<String>,
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
        id: Some(row_id),
        key: descriptor.key.to_owned(),
        area: attome_core::setting_descriptor::area(descriptor.key).to_owned(),
        description_ar: attome_core::setting_descriptor::description_ar(descriptor.key)
            .map(str::to_owned),
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
                id: row.map(|r| r.id),
                key: d.key.to_owned(),
                area: attome_core::setting_descriptor::area(d.key).to_owned(),
                description_ar: attome_core::setting_descriptor::description_ar(d.key)
                    .map(str::to_owned),
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
                area: attome_core::setting_descriptor::area(d.key).to_owned(),
                description_ar: attome_core::setting_descriptor::description_ar(d.key)
                    .map(str::to_owned),
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
                id: None,
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

// ── Brand themes (B13-T3/T4/T5) ──────────────────────────────────────────────

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::theme_store::{self, ThemeRow};
use attome_core::theme_tokens::{ContrastReport, ThemeTokens};

/// `POST /api/v1/admin/themes`.
#[derive(Deserialize, ToSchema)]
struct ThemeDraftBody {
    /// `deployment`, `app`, `unit`, `domain` or `portal`.
    scope_kind: String,
    /// The app, unit, domain (host name) or portal; empty for the deployment.
    #[serde(default)]
    scope_ref: String,
    tokens: ThemeTokens,
}

/// `PATCH /api/v1/admin/themes/{id}` and `POST .../preview-check`.
#[derive(Deserialize, ToSchema)]
struct ThemeTokensBody {
    tokens: ThemeTokens,
}

/// What the browser applies: the CSS variables the theme sets, and whether
/// to hide the vendor's name.
#[derive(Serialize, ToSchema)]
struct PublicBranding {
    variables: std::collections::BTreeMap<String, String>,
    hide_vendor_name: bool,
    /// The product name to show, when the theme sets one.
    app_name: Option<String>,
    /// `/api/v1/branding/asset?kind=logo&v=…` when a logo is published.
    logo_url: Option<String>,
    logo_dark_url: Option<String>,
    favicon_url: Option<String>,
    font_latin_url: Option<String>,
    font_arabic_url: Option<String>,
    font_latin: Option<String>,
    font_arabic: Option<String>,
}

fn required_row_version(headers: &axum::http::HeaderMap) -> Result<i64, AppError> {
    attome_records::entity_crud::optional_expected_row_version(headers)?
        .ok_or_else(|| AppError::Validation("If-Match: \"<row_version>\" is required".into()))
}

fn theme_event(operation: AuditOperation, actor: Uuid, id: Uuid, name: &str) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        "theme",
        Some(id),
    )
    .named(name)
}

/// B13-T4: every theme version, by scope, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/themes",
    tag = "settings",
    params(attome_types::OnePageQuery),
    responses(
        (status = 200, description = "A page of theme versions", body = attome_types::PaginatedResponse<ThemeRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_themes(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    axum::extract::Query(page): axum::extract::Query<attome_types::OnePageQuery>,
) -> Result<Json<attome_types::PaginatedResponse<ThemeRow>>, AppError> {
    let window = page.window();
    let (rows, total) = theme_store::list(&state.base.db, window.page_size, window.offset).await?;
    Ok(Json(attome_types::PaginatedResponse::new(
        rows,
        total,
        window.page,
        window.page_size,
    )))
}

/// B13-T4: saves a new draft version of a scope's theme.
#[utoipa::path(
    post,
    path = "/api/v1/admin/themes",
    tag = "settings",
    request_body = ThemeDraftBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The new draft", body = ThemeRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 409, description = "Another save of this scope's theme is in progress", body = ErrorResponse),
        (status = 422, description = "Invalid scope or token", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_theme(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<ThemeDraftBody>,
) -> Result<(axum::http::StatusCode, Json<ThemeRow>), AppError> {
    let event = theme_event(
        AuditOperation::Create,
        ctx.user_id,
        Uuid::nil(),
        "theme.draft_saved",
    );
    let mut stx = SecurityTx::begin(&state, event).await?;
    let row = theme_store::save_draft(
        &mut stx,
        &body.scope_kind,
        body.scope_ref.trim(),
        &body.tokens,
        ctx.user_id,
    )
    .await?;
    stx.event_mut().set_record_id(row.id);
    stx.commit().await?;
    Ok((axum::http::StatusCode::CREATED, Json(row)))
}

/// B13-T4: one theme version.
#[utoipa::path(
    get,
    path = "/api/v1/admin/themes/{id}",
    tag = "settings",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The version", body = ThemeRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such theme", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_theme(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<ThemeRow>, AppError> {
    Ok(Json(theme_store::get(&state.base.db, id).await?))
}

/// B13-T4: replaces a draft's tokens. `If-Match: "<row_version>"` is required.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/themes/{id}",
    tag = "settings",
    params(("id" = Uuid, Path)),
    request_body = ThemeTokensBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The draft", body = ThemeRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such theme", body = ErrorResponse),
        (status = 409, description = "Stale row_version", body = ErrorResponse),
        (status = 422, description = "Missing If-Match, an invalid token, or not a draft", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_theme(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ThemeTokensBody>,
) -> Result<Json<ThemeRow>, AppError> {
    let expected = required_row_version(&headers)?;
    let event = theme_event(
        AuditOperation::Update,
        ctx.user_id,
        id,
        "theme.draft_updated",
    );
    let mut stx = SecurityTx::begin(&state, event).await?;
    let row = theme_store::update_draft(&mut stx, id, expected, &body.tokens).await?;
    stx.commit().await?;
    Ok(Json(row))
}

/// B13-T3: publishes a version once its colours pass the contrast check; the
/// scope's previous version is retired. `If-Match: "<row_version>"` is
/// required. A failing theme is refused naming each pair and its ratio.
#[utoipa::path(
    post,
    path = "/api/v1/admin/themes/{id}/publish",
    tag = "settings",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Published", body = ThemeRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such theme", body = ErrorResponse),
        (status = 409, description = "Stale row_version", body = ErrorResponse),
        (status = 422, description = "Missing If-Match, or colours that fail the contrast check", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn publish_theme(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: axum::http::HeaderMap,
) -> Result<Json<ThemeRow>, AppError> {
    let expected = required_row_version(&headers)?;
    let event = theme_event(AuditOperation::Update, ctx.user_id, id, "theme.published");
    let mut stx = SecurityTx::begin(&state, event).await?;
    let (row, _) = theme_store::publish(&mut stx, id, expected).await?;
    stx.commit().await?;
    Ok(Json(row))
}

/// `POST /api/v1/admin/themes/rollback`.
#[derive(Deserialize, ToSchema)]
struct ThemeRollbackBody {
    scope_kind: String,
    #[serde(default)]
    scope_ref: String,
    /// The version to publish again.
    version: i32,
}

/// B13-T3: publishes an earlier version of a scope's theme again.
#[utoipa::path(
    post,
    path = "/api/v1/admin/themes/rollback",
    tag = "settings",
    request_body = ThemeRollbackBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The version now published", body = ThemeRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such version", body = ErrorResponse),
        (status = 422, description = "Invalid scope, or colours that fail the contrast check", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rollback_theme(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<ThemeRollbackBody>,
) -> Result<Json<ThemeRow>, AppError> {
    let event = theme_event(
        AuditOperation::Update,
        ctx.user_id,
        Uuid::nil(),
        "theme.rolled_back",
    );
    let mut stx = SecurityTx::begin(&state, event).await?;
    let row = theme_store::rollback(
        &mut stx,
        &body.scope_kind,
        body.scope_ref.trim(),
        body.version,
    )
    .await?;
    stx.event_mut().set_record_id(row.id);
    stx.commit().await?;
    Ok(Json(row))
}

/// B13-T3: what a version changes against its scope's published one.
#[utoipa::path(
    get,
    path = "/api/v1/admin/themes/{id}/diff",
    tag = "settings",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Each changed token, before and after", body = attome_types::PaginatedResponse<theme_store::TokenChange>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such theme", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn diff_theme(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<attome_types::PaginatedResponse<theme_store::TokenChange>>, AppError> {
    let changes = theme_store::diff(&state.base.db, id).await?;
    let total = i64::try_from(changes.len()).map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        changes,
        total,
        1,
        total.max(1),
    )))
}

/// B13-T4: checks colours without saving anything.
#[utoipa::path(
    post,
    path = "/api/v1/admin/themes/preview-check",
    tag = "settings",
    request_body = ThemeTokensBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "measures colours and writes nothing"
    )))),
    responses(
        (status = 200, description = "The contrast report", body = ContrastReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn preview_theme(
    _ctx: Authorized<Admin>,
    Json(body): Json<ThemeTokensBody>,
) -> Json<ContrastReport> {
    Json(attome_core::theme_tokens::check(&body.tokens))
}

/// B13-T5: the published brand for this host, for the sign-in page and the
/// app shell: CSS variables, fonts and whether to hide the vendor's name.
/// No session and no user data. Answers `304` to an `If-None-Match` naming
/// the current published versions.
#[utoipa::path(
    get,
    path = "/api/v1/branding/public",
    tag = "settings",
    responses(
        (status = 200, description = "The brand to apply", body = PublicBranding),
        (status = 304, description = "Unchanged since the ETag the caller holds"),
    ),
)]
async fn public_branding(
    State(state): State<EngineState>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, AppError> {
    let host = request_host(&headers);
    let scope = theme_store::BrandScope {
        host: host.as_deref(),
        ..theme_store::BrandScope::default()
    };
    let resolved = theme_store::resolve(&state.base.db, scope).await?;
    let assets = theme_store::published_assets(&state.base.db, scope).await?;
    branding_response(&headers, resolved, &assets, "public, max-age=300")
}

/// `GET /api/v1/branding/me`.
#[derive(Deserialize, utoipa::IntoParams)]
struct BrandingMeQuery {
    /// The app being shown, when it has its own theme.
    app: Option<String>,
}

/// B13-T5: the brand for the signed-in caller: the deployment's, then the
/// app's (`app`), the caller's business unit's, the domain's.
#[utoipa::path(
    get,
    path = "/api/v1/branding/me",
    tag = "settings",
    params(BrandingMeQuery),
    responses(
        (status = 200, description = "The brand to apply", body = PublicBranding),
        (status = 304, description = "Unchanged since the ETag the caller holds"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn my_branding(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<BrandingMeQuery>,
) -> Result<axum::response::Response, AppError> {
    let (_user_ctx, unit) = fetch_audit_ctx(&state, ctx.user_id).await;
    let unit = (!unit.is_nil()).then(|| unit.to_string());
    let host = request_host(&headers);
    let scope = theme_store::BrandScope {
        app: query
            .app
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty()),
        unit: unit.as_deref(),
        host: host.as_deref(),
        portal: None,
    };
    let resolved = theme_store::resolve(&state.base.db, scope).await?;
    let assets = theme_store::published_assets(&state.base.db, scope).await?;
    branding_response(&headers, resolved, &assets, "private, max-age=60")
}

/// `kind` of a brand asset.
#[derive(Deserialize, utoipa::IntoParams)]
struct AssetKindQuery {
    /// `logo`, `logo_dark`, `favicon`, `font_arabic`, `font_latin` or
    /// `guidelines_pdf`.
    kind: String,
}

/// B13-T4: uploads one asset of a draft theme as the raw request body, with
/// its `Content-Type`. At most 2 MB; PNG, SVG, ICO, WOFF2 or PDF as the kind
/// allows. An SVG with a script, event handler, external reference or
/// foreign object is refused. Replaces the draft's asset of that kind.
#[utoipa::path(
    post,
    path = "/api/v1/admin/themes/{id}/assets",
    tag = "settings",
    params(("id" = Uuid, Path), AssetKindQuery),
    request_body(content = Vec<u8>, content_type = "application/octet-stream", description = "The file"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The stored asset", body = theme_store::BrandAsset),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such theme", body = ErrorResponse),
        (status = 409, description = "The theme is not a draft", body = ErrorResponse),
        (status = 413, description = "Larger than 2 MB", body = ErrorResponse),
        (status = 422, description = "Unknown kind, wrong content type or unsafe SVG", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn upload_theme_asset(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    axum::extract::Query(query): axum::extract::Query<AssetKindQuery>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<theme_store::BrandAsset>, AppError> {
    use object_store::ObjectStoreExt;
    use sha2::{Digest, Sha256};
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or(v).trim().to_ascii_lowercase())
        // Browsers label .ico files with the registered name.
        .map(|v| {
            if v == "image/vnd.microsoft.icon" {
                "image/x-icon".to_owned()
            } else {
                v
            }
        })
        .unwrap_or_default();
    theme_store::check_asset(&query.kind, &content_type, &body)?;
    let sha256 = hex::encode(Sha256::digest(&body));
    let key = theme_store::asset_storage_key(id, &query.kind, &sha256);
    // The bytes go to the object store before the transaction opens; a
    // failed commit leaves an unreferenced object, never a row without one.
    let path = object_store::path::Path::parse(&key).map_err(AppError::internal)?;
    let size = i64::try_from(body.len()).map_err(AppError::internal)?;
    state
        .base
        .storage
        .store()
        .put(&path, body.into())
        .await
        .map_err(AppError::internal)?;
    let event = theme_event(
        AuditOperation::Update,
        ctx.user_id,
        id,
        "theme.asset_uploaded",
    );
    let mut stx = SecurityTx::begin(&state, event).await?;
    let asset = theme_store::put_asset(
        &mut stx,
        id,
        &query.kind,
        &key,
        &content_type,
        size,
        &sha256,
    )
    .await?;
    stx.commit().await?;
    Ok(Json(asset))
}

/// B13-T4: a theme version's assets.
#[utoipa::path(
    get,
    path = "/api/v1/admin/themes/{id}/assets",
    tag = "settings",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "The version's assets, one per kind", body = attome_types::PaginatedResponse<theme_store::BrandAsset>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_theme_assets(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<attome_types::PaginatedResponse<theme_store::BrandAsset>>, AppError> {
    let items = theme_store::list_assets(&state.base.db, id).await?;
    let total = i64::try_from(items.len()).map_err(AppError::internal)?;
    Ok(Json(attome_types::PaginatedResponse::new(
        items,
        total,
        1,
        i64::try_from(theme_store::ASSET_KINDS.len()).map_err(AppError::internal)?,
    )))
}

/// B13-T4: a published logo, favicon or font for this host, without a
/// session (the sign-in page shows them). Served inert: `nosniff` and a
/// `sandbox` content security policy, so an SVG opened directly runs
/// nothing.
#[utoipa::path(
    get,
    path = "/api/v1/branding/asset",
    tag = "settings",
    params(AssetKindQuery),
    responses(
        (status = 200, description = "The file", body = Vec<u8>, content_type = "application/octet-stream"),
        (status = 304, description = "Unchanged since the ETag the caller holds"),
        (status = 404, description = "No published asset of that kind", body = ErrorResponse),
    ),
)]
async fn public_brand_asset(
    State(state): State<EngineState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<AssetKindQuery>,
) -> Result<axum::response::Response, AppError> {
    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::IntoResponse;
    use object_store::ObjectStoreExt;
    if !theme_store::PUBLIC_ASSET_KINDS.contains(&query.kind.as_str()) {
        return Err(AppError::NotFound);
    }
    let host = request_host(&headers);
    let scope = theme_store::BrandScope {
        host: host.as_deref(),
        ..theme_store::BrandScope::default()
    };
    let assets = theme_store::published_assets(&state.base.db, scope).await?;
    let asset = assets
        .into_iter()
        .find(|a| a.kind == query.kind)
        .ok_or(AppError::NotFound)?;
    let etag =
        HeaderValue::from_str(&format!("\"{}\"", asset.sha256)).map_err(AppError::internal)?;
    let fixed = [
        (
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=300"),
        ),
        (
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ),
        (
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("sandbox; default-src 'none'; style-src 'unsafe-inline'"),
        ),
    ];
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|value| value.as_bytes() == etag.as_bytes());
    if unchanged {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)], fixed).into_response());
    }
    let path = object_store::path::Path::parse(&asset.storage_key).map_err(AppError::internal)?;
    let bytes = match state.base.storage.store().get(&path).await {
        Ok(result) => result.bytes().await.map_err(AppError::internal)?,
        Err(object_store::Error::NotFound { .. }) => return Err(AppError::NotFound),
        Err(e) => return Err(AppError::internal(e)),
    };
    let content_type = HeaderValue::from_str(&asset.content_type).map_err(AppError::internal)?;
    Ok((
        [(header::CONTENT_TYPE, content_type), (header::ETAG, etag)],
        fixed,
        bytes,
    )
        .into_response())
}

/// The newest local backup.
#[derive(Serialize, ToSchema)]
struct BackupArchive {
    name: String,
    /// When it was taken, from its name.
    taken_at: Option<chrono::DateTime<chrono::Utc>>,
    size_bytes: u64,
    /// Files listed beside it; `null` when it has no file list.
    files: Option<usize>,
}

/// `GET /api/v1/admin/backup`.
#[derive(Serialize, ToSchema)]
struct BackupStatus {
    /// `backup.enabled`.
    enabled: bool,
    /// Whether this deployment runs the built-in backup (Solo only).
    runs_here: bool,
    /// `backup.files`.
    files: bool,
    dir: String,
    keep: u32,
    /// The hour (UTC) it runs.
    hour: u32,
    /// True when `backup.dir` is not set, so backups share the database's
    /// machine and disk.
    same_disk: bool,
    archives: usize,
    latest: Option<BackupArchive>,
    /// The newest restore drill (U6-T3), as `attome backup drill` and the
    /// monthly run record it.
    last_drill: Option<serde_json::Value>,
}

/// U6-T1: what the daily local backup does and the newest one it wrote, so
/// the admin console can warn when backups stay on the same disk or have
/// stopped.
#[utoipa::path(
    get,
    path = "/api/v1/admin/backup",
    tag = "settings",
    responses(
        (status = 200, description = "The backup settings and the newest archive", body = BackupStatus),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn backup_status(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<BackupStatus>, AppError> {
    let config = &state.base.config;
    let section = &config.backup;
    let dir = section.resolved_dir();
    let mut names = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("attome-") && name.ends_with(".dump") {
                names.push(name);
            }
        }
    }
    names.sort();
    let latest = match names.last() {
        Some(name) => {
            let size_bytes = tokio::fs::metadata(dir.join(name))
                .await
                .map(|m| m.len())
                .unwrap_or(0);
            let stem = name.trim_start_matches("attome-").trim_end_matches(".dump");
            let taken_at = chrono::NaiveDateTime::parse_from_str(stem, "%Y%m%d-%H%M")
                .ok()
                .map(|t| t.and_utc());
            let manifest = dir.join(format!("{}.files.json", name.trim_end_matches(".dump")));
            let files = tokio::fs::read(&manifest)
                .await
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).ok())
                .map(|list| list.len());
            Some(BackupArchive {
                name: name.clone(),
                taken_at,
                size_bytes,
                files,
            })
        }
        None => None,
    };
    Ok(Json(BackupStatus {
        enabled: section.enabled,
        runs_here: config.cache.backend == attome_config::CacheBackend::Memory,
        files: section.files,
        dir: dir.display().to_string(),
        keep: section.keep,
        hour: section.hour,
        same_disk: section
            .dir
            .as_deref()
            .map(str::trim)
            .is_none_or(str::is_empty),
        archives: names.len(),
        latest,
        last_drill: tokio::fs::read_to_string(dir.join("drills.jsonl"))
            .await
            .ok()
            .and_then(|text| {
                text.lines()
                    .rev()
                    .find(|l| !l.trim().is_empty())
                    .and_then(|l| serde_json::from_str(l).ok())
            }),
    }))
}

/// The request's host name, lower case and without a port.
fn request_host(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase())
}

/// The brand as JSON with its ETag, or a bodyless `304` when the caller's
/// `If-None-Match` already names it.
fn branding_response(
    headers: &axum::http::HeaderMap,
    (tokens, tag): (ThemeTokens, String),
    assets: &[theme_store::PublishedAsset],
    cache_control: &'static str,
) -> Result<axum::response::Response, AppError> {
    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::IntoResponse;
    let etag = format!("\"{tag}\"");
    let unchanged = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.split(',').any(|t| t.trim() == etag));
    let etag = HeaderValue::from_str(&etag).map_err(AppError::internal)?;
    let cache = HeaderValue::from_static(cache_control);
    if unchanged {
        return Ok((
            StatusCode::NOT_MODIFIED,
            [(header::ETAG, etag), (header::CACHE_CONTROL, cache)],
        )
            .into_response());
    }
    let url = |kind: &str| {
        assets.iter().find(|a| a.kind == kind).map(|a| {
            let short = a.sha256.get(..12).unwrap_or(&a.sha256);
            format!("/api/v1/branding/asset?kind={kind}&v={short}")
        })
    };
    let body = PublicBranding {
        variables: attome_core::theme_tokens::to_css_variables(&tokens),
        hide_vendor_name: tokens.hide_vendor_name.unwrap_or(false),
        app_name: tokens.app_name.clone(),
        logo_url: url("logo"),
        logo_dark_url: url("logo_dark"),
        favicon_url: url("favicon"),
        font_latin_url: url("font_latin"),
        font_arabic_url: url("font_arabic"),
        font_latin: tokens.font_latin.clone(),
        font_arabic: tokens.font_arabic.clone(),
    };
    Ok((
        [(header::ETAG, etag), (header::CACHE_CONTROL, cache)],
        Json(body),
    )
        .into_response())
}

// ── X12-T3: the first-run region setup ─────────────────────────────────────

/// The pack whose `region_country` records the first-run wizard offers.
const REGIONS_PACK: &str = "regions";
/// The languages the wizard offers; the locale becomes `{language}-{country}`.
const SETUP_LANGUAGES: [&str; 2] = ["ar", "en"];
/// `core.calendar`'s values.
const SETUP_CALENDARS: [&str; 3] = ["gregorian", "hijri", "both"];

/// One country the regions pack presets, from its `region_country` record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) struct RegionPreset {
    /// ISO 3166 alpha-2 code, e.g. `SA`.
    code: String,
    name: String,
    name_ar: Option<String>,
    currency_code: Option<String>,
    /// IANA time zone, e.g. `Asia/Riyadh`.
    time_zone: String,
    /// `gregorian`, `hijri` or `both`.
    default_date_calendar: String,
    /// First day of the business week (`sun`, `mon`, `sat`).
    week_start: Option<String>,
}

/// `GET`/`POST /api/v1/admin/setup/region`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct RegionSetupView {
    /// The deployment's country (`core.country`), or null before the first
    /// run picked one.
    country: Option<String>,
    /// Whether the regions pack is next to the server (`app.packs_root`).
    pack_available: bool,
    /// The countries the pack presets, by code.
    countries: Vec<RegionPreset>,
}

/// `POST /api/v1/admin/setup/region`.
#[derive(Debug, Deserialize, ToSchema)]
struct RegionSetupRequest {
    /// A code from `countries`.
    country: String,
    /// `ar` or `en`.
    language: String,
    /// `gregorian`, `hijri` or `both`; omitted, the country's default.
    calendar: Option<String>,
}

/// The `region_country` records of the regions pack's documents, sorted by
/// code. An operation that is not a country record, or lacks a code, name or
/// time zone, is skipped.
pub(crate) fn region_presets(documents: &[serde_json::Value]) -> Vec<RegionPreset> {
    let text = |v: &serde_json::Value, key: &str| {
        v.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    let mut out: Vec<RegionPreset> = documents
        .iter()
        .filter_map(|doc| doc.get("operations").and_then(serde_json::Value::as_array))
        .flatten()
        .filter(|op| {
            op.get("op").and_then(serde_json::Value::as_str) == Some("upsert_record")
                && op["target"]["entity"].as_str() == Some("region_country")
        })
        .filter_map(|op| {
            let values = &op["args"]["values"];
            Some(RegionPreset {
                code: text(values, "code")?,
                name: text(values, "name")?,
                name_ar: text(values, "name_ar"),
                currency_code: text(values, "currency_code"),
                time_zone: text(values, "time_zone")?,
                default_date_calendar: text(values, "default_date_calendar")
                    .filter(|c| SETUP_CALENDARS.contains(&c.as_str()))
                    .unwrap_or_else(|| "gregorian".to_owned()),
                week_start: text(values, "week_start"),
            })
        })
        .collect();
    out.sort_by(|a, b| a.code.cmp(&b.code));
    out.dedup_by(|a, b| a.code == b.code);
    out
}

/// The regions pack's documents, read off the async runtime. `None` when the
/// pack is not next to the server.
async fn regions_documents(state: &EngineState) -> Option<Vec<serde_json::Value>> {
    let config = state.base.config.clone();
    match tokio::task::spawn_blocking(move || {
        crate::changeset::boot::read_pack_documents(&config, REGIONS_PACK)
    })
    .await
    {
        Ok(Ok(documents)) => Some(documents),
        Ok(Err(error)) => {
            tracing::info!(%error, "first-run setup: the regions pack is not available");
            None
        }
        Err(error) => {
            tracing::warn!(%error, "first-run setup: reading the regions pack failed");
            None
        }
    }
}

/// The deployment's `core.country`, or `None` while it is empty.
fn current_country(state: &EngineState) -> Option<String> {
    let descriptor = setting_registry().get("core.country")?;
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value.as_str().filter(|c| !c.is_empty()).map(str::to_owned)
}

async fn region_setup_view(state: &EngineState) -> RegionSetupView {
    let documents = regions_documents(state).await;
    RegionSetupView {
        country: current_country(state),
        pack_available: documents.is_some(),
        countries: documents.as_deref().map(region_presets).unwrap_or_default(),
    }
}

/// The first-run region setup's state (X12-T3).
///
/// The deployment's country, if one was picked, and the countries the
/// regions pack presets (currency, time zone, default calendar and business
/// week), so the first-run wizard can offer them. `pack_available` is false
/// when the regions pack is not next to the server.
#[utoipa::path(
    get,
    path = "/api/v1/admin/setup/region",
    tag = "admin",
    responses(
        (status = 200, description = "The deployment's country and the presets on offer", body = RegionSetupView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_region_setup(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<RegionSetupView>, AppError> {
    Ok(Json(region_setup_view(&state).await))
}

/// Sets the deployment up for a country (X12-T3).
///
/// Installs the regions pack (its changesets through the same idempotent
/// ledger path as `attome init --pack`; a second run changes nothing), then
/// stores the deployment defaults: `core.country`, `core.locale`
/// (`{language}-{country}`), `core.time_zone` and `core.calendar` (the given
/// one, else the country's). Each setting write is audited. A person's own
/// choices still win over these defaults.
#[utoipa::path(
    post,
    path = "/api/v1/admin/setup/region",
    tag = "admin",
    request_body = RegionSetupRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The deployment is set up for the country", body = RegionSetupView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 422, description = "Unknown country, language or calendar, or the regions pack is not next to the server", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn post_region_setup(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(request): Json<RegionSetupRequest>,
) -> Result<Json<RegionSetupView>, AppError> {
    if !SETUP_LANGUAGES.contains(&request.language.as_str()) {
        return Err(AppError::Validation("language must be ar or en".to_owned()));
    }
    if let Some(calendar) = &request.calendar
        && !SETUP_CALENDARS.contains(&calendar.as_str())
    {
        return Err(AppError::Validation(
            "calendar must be gregorian, hijri or both".to_owned(),
        ));
    }
    let documents = regions_documents(&state).await.ok_or_else(|| {
        AppError::Validation(
            "the regions pack is not next to the server: install the packs directory \
             beside the executable or set app.packs_root"
                .to_owned(),
        )
    })?;
    let preset = region_presets(&documents)
        .into_iter()
        .find(|p| p.code == request.country)
        .ok_or_else(|| AppError::Validation(format!("unknown country {:?}", request.country)))?;

    for document in &documents {
        crate::changeset::boot::apply_pack_document(&state, document).await?;
    }
    let calendar = request
        .calendar
        .unwrap_or_else(|| preset.default_date_calendar.clone());
    let locale = format!("{}-{}", request.language, preset.code);
    let values = [
        ("core.country", serde_json::json!(preset.code)),
        ("core.locale", serde_json::json!(locale)),
        ("core.time_zone", serde_json::json!(preset.time_zone)),
        ("core.calendar", serde_json::json!(calendar)),
    ];
    for (key, value) in values {
        write_setting(
            &state,
            ctx.user_id,
            key,
            SettingScope::Deployment,
            None,
            value,
        )
        .await?;
    }
    Ok(Json(region_setup_view(&state).await))
}

#[cfg(test)]
mod region_setup_tests {
    use super::*;

    #[test]
    fn presets_come_from_country_records_only() {
        let doc = serde_json::json!({ "operations": [
            { "op": "upsert_record", "target": { "entity": "region_country", "key": { "code": "SA" } },
              "args": { "values": { "code": "SA", "name": "Saudi Arabia", "name_ar": "السعودية",
                "currency_code": "SAR", "time_zone": "Asia/Riyadh", "default_date_calendar": "both",
                "week_start": "sun" } } },
            { "op": "upsert_record", "target": { "entity": "region_tax_rate", "key": { "code": "SA-VAT-S" } },
              "args": { "values": { "code": "SA-VAT-S", "name": "VAT", "time_zone": "x" } } },
            { "op": "upsert_record", "target": { "entity": "region_country", "key": { "code": "XX" } },
              "args": { "values": { "code": "XX", "name": "No zone" } } },
            { "op": "add_field", "args": {} }
        ] });
        let doc2 = serde_json::json!({ "operations": [
            { "op": "upsert_record", "target": { "entity": "region_country", "key": { "code": "AE" } },
              "args": { "values": { "code": "AE", "name": "UAE", "time_zone": "Asia/Dubai",
                "default_date_calendar": "lunar" } } }
        ] });
        let presets = region_presets(&[doc, doc2]);
        let codes: Vec<&str> = presets.iter().map(|p| p.code.as_str()).collect();
        assert_eq!(codes, ["AE", "SA"]);
        assert_eq!(presets[1].time_zone, "Asia/Riyadh");
        assert_eq!(presets[1].default_date_calendar, "both");
        // An unknown calendar falls back to gregorian.
        assert_eq!(presets[0].default_date_calendar, "gregorian");
    }

    #[test]
    fn the_shipped_regions_pack_presets_saudi_arabia_the_uae_and_egypt() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs/regions/changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .map(|entries| entries.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        files.sort();
        let documents: Vec<serde_json::Value> = files
            .iter()
            .filter_map(|f| std::fs::read_to_string(f).ok())
            .filter_map(|t| serde_json::from_str(&t).ok())
            .collect();
        let codes: Vec<String> = region_presets(&documents)
            .into_iter()
            .map(|p| p.code)
            .collect();
        assert_eq!(codes, ["AE", "EG", "SA"]);
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/settings", get(list_admin_settings))
        .route("/api/v1/admin/settings/{key}", put(put_admin_setting))
        .route("/api/v1/settings/me", get(get_my_settings))
        .route("/api/v1/settings/me/{key}", put(put_my_setting))
        .route("/api/v1/admin/themes", get(list_themes).post(create_theme))
        .route(
            "/api/v1/admin/themes/preview-check",
            axum::routing::post(preview_theme),
        )
        .route(
            "/api/v1/admin/themes/{id}",
            get(get_theme).patch(update_theme),
        )
        .route(
            "/api/v1/admin/themes/{id}/publish",
            axum::routing::post(publish_theme),
        )
        .route(
            "/api/v1/admin/themes/rollback",
            axum::routing::post(rollback_theme),
        )
        .route("/api/v1/admin/themes/{id}/diff", get(diff_theme))
        .route("/api/v1/branding/public", get(public_branding))
        .route("/api/v1/branding/me", get(my_branding))
        .route("/api/v1/branding/asset", get(public_brand_asset))
        .route("/api/v1/admin/backup", get(backup_status))
        .route(
            "/api/v1/admin/setup/region",
            get(get_region_setup).post(post_region_setup),
        )
        .route(
            "/api/v1/admin/themes/{id}/assets",
            get(list_theme_assets).post(upload_theme_asset),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_admin_settings,
    put_admin_setting,
    get_my_settings,
    put_my_setting,
    list_themes,
    create_theme,
    update_theme,
    get_theme,
    publish_theme,
    preview_theme,
    rollback_theme,
    diff_theme,
    public_branding,
    my_branding,
    public_brand_asset,
    backup_status,
    upload_theme_asset,
    list_theme_assets,
    get_region_setup,
    post_region_setup
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
