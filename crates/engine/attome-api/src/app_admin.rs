//! M65 Phase 1 — Application Builder: admin CRUD over `app`, plus
//! the self-service `GET /api/v1/apps` the Angular app switcher reads.
//!
//! **"Apps only filter navigation, they never authorize" (D-467).** Nothing
//! in this file grants access: `entities`/`roles` are read-only inputs to a
//! client-side sidebar filter and a switcher visibility check, never
//! consulted by `entity_crud`, `query_exec`, or any privilege check. Removing
//! an entity from every app's list does not revoke access to it, and an app
//! naming an entity does not grant access either — the existing
//! `security_role`/privilege model is the sole authorization source,
//! completely unchanged by this file.
//!
//! **No registry (unlike the removed `form_admin.rs`, D-790).** `app` is read once per
//! session by the shell to build the switcher (`ShellComponent`), never on
//! the interactive record-write hot path the way `state_models`/
//! `relationships` are — so a plain DB read here is the smaller,
//! sufficient mechanism (guidelines §5: do not add a cache without a clear
//! benefit). If the switcher read ever becomes hot enough to matter, it can
//! adopt the same `state_registry`-style full-reload registry then.
//!
//! **Concurrency (guidelines §2).** Same posture the removed `form_admin.rs` took: the only
//! race is "two callers create the same live `name`", already closed by
//! `core_app_name_idx` (a partial unique index) inside a short transaction —
//! `map_unique_violation` turns the loser's write into `Conflict`, not silent
//! duplication. No advisory lock, no `row_version`/If-Match contract (an
//! admin-authored nav-metadata row, not a customer entity record).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordedOp, Recording, RecordingCtx};
use attome_metadata::provision::{ReconcileOutcome, ReconcilePolicy};
use attome_server::authz::{Admin, Authorized, SelfService};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::admin_hooks as hooks;
use crate::bundle::model::AppDef;
use attome_records::query_admin::{
    ReconcileStep, customized_marker, map_unique_violation, reconcile_step,
};

#[derive(sqlx::FromRow, Serialize, ToSchema)]
pub(crate) struct AppDetail {
    id: Uuid,
    name: String,
    icon: String,
    sidebar_root_ref: Option<Uuid>,
    default_dashboard_ref: Option<Uuid>,
    entities: Value,
    roles: Value,
    display_order: i32,
    is_active: bool,
    row_version: i64,
    /// Solution 7 (D-785) — the layer that owns this app: `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer
    /// may update or retire it (409 `layer_mismatch` otherwise).
    owner_layer: String,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct AppBody {
    name: String,
    #[serde(default = "default_icon")]
    icon: String,
    #[serde(default)]
    sidebar_root_ref: Option<Uuid>,
    #[serde(default)]
    default_dashboard_ref: Option<Uuid>,
    #[serde(default)]
    entities: Value,
    #[serde(default)]
    roles: Value,
    #[serde(default)]
    display_order: i32,
}

fn default_icon() -> String {
    "las la-th-large".into()
}

fn validate_string_array(value: &Value, field: &str) -> Result<(), AppError> {
    match value {
        Value::Null => Ok(()),
        Value::Array(items) => {
            if items.iter().all(|v| v.is_string()) {
                Ok(())
            } else {
                Err(AppError::Validation(format!(
                    "{field} must be an array of strings"
                )))
            }
        }
        _ => Err(AppError::Validation(format!(
            "{field} must be a JSON array"
        ))),
    }
}

fn validate_body(body: &AppBody) -> Result<(), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::Validation("app name is required".into()));
    }
    validate_string_array(&body.entities, "entities")?;
    validate_string_array(&body.roles, "roles")?;
    Ok(())
}

const APP_SELECT: &str = "SELECT id, name, icon, sidebar_root_ref, default_dashboard_ref, \
     entities, roles, display_order, is_active, row_version, owner_layer FROM app";

/// List apps
///
/// List apps. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/apps",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<AppDetail>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_apps(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AppDetail>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();

    let sql = format!(
        "{APP_SELECT} WHERE is_deleted = false \
         ORDER BY display_order, name LIMIT $1 OFFSET $2"
    );
    let rows = sqlx::query_as(&sql)
        .bind(page_size)
        .bind(offset)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app WHERE is_deleted = false")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(rows, total, page, page_size)))
}

/// One app
///
/// One app. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/apps/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = AppDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such app", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_app(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<AppDetail>, AppError> {
    let sql = format!("{APP_SELECT} WHERE id = $1 AND is_deleted = false");
    let row = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;
    Ok(Json(row))
}

/// Create an app
///
/// Create an app. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/apps",
    tag = "admin",
    request_body = AppBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = AppDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "An app with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_app(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Json(body): Json<AppBody>,
) -> Result<(StatusCode, Json<AppDetail>), AppError> {
    validate_body(&body)?;
    // D-785: resolve the changeset (or refuse) before any write.
    recording.preflight(&state.base.db).await?;
    let id = Uuid::now_v7();
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "app",
            Some(id),
        )
        .named("app.create"),
    )
    .await?;
    let row = create_app_in_tx(tx.tx(), &recording, id, &body).await?;
    // Last before commit (the security event is written by `commit` itself,
    // a plain insert that takes no lock after the changeset row's).
    recording
        .record(tx.tx(), app_op(Op::UpsertApp, &row)?)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(row)))
}

async fn read_app_in_tx(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<AppDetail, AppError> {
    let sql = format!("{APP_SELECT} WHERE id = $1");
    sqlx::query_as(&sql)
        .bind(id)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)
}

/// Locks the app `id` (not deleted; active too when `only_active`) and
/// applies the owner-layer rule (D-785 §1): `NotFound` when no such row,
/// 409 `layer_mismatch` when another layer owns it.
async fn lock_app_owner(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    only_active: bool,
) -> Result<(), AppError> {
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT owner_layer FROM app \
         WHERE id = $1 AND is_deleted = false AND (NOT $2 OR is_active = true) FOR UPDATE",
    )
    .bind(id)
    .bind(only_active)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let owner = owner.ok_or(AppError::NotFound)?;
    hooks::check_row_owner(recording, &owner)
}

/// The admin create's write, transaction-scoped (D-785 §3: one
/// implementation per write, shared with the changeset applier).
pub(crate) async fn create_app_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    body: &AppBody,
) -> Result<AppDetail, AppError> {
    let layer = recording.stamp()?;
    sqlx::query(
        "INSERT INTO app \
             (id, name, icon, sidebar_root_ref, default_dashboard_ref, entities, roles, \
              display_order, is_customized, is_active, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, true, $9)",
    )
    .bind(id)
    .bind(body.name.trim())
    .bind(body.icon.trim())
    .bind(body.sidebar_root_ref)
    .bind(body.default_dashboard_ref)
    .bind(&body.entities)
    .bind(&body.roles)
    .bind(body.display_order)
    .bind(layer.as_str())
    .execute(&mut **tx)
    .await
    .map_err(map_unique_violation)?;
    read_app_in_tx(tx, id).await
}

/// The admin PATCH's write, transaction-scoped.
pub(crate) async fn update_app_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
    body: &AppBody,
) -> Result<AppDetail, AppError> {
    lock_app_owner(tx, recording, id, false).await?;
    let changed = sqlx::query(
        "UPDATE app SET name=$2, icon=$3, sidebar_root_ref=$4, default_dashboard_ref=$5, \
             entities=$6, roles=$7, display_order=$8, is_customized=true, \
             row_version = row_version + 1, updated_at = NOW() \
         WHERE id=$1 AND is_deleted=false",
    )
    .bind(id)
    .bind(body.name.trim())
    .bind(body.icon.trim())
    .bind(body.sidebar_root_ref)
    .bind(body.default_dashboard_ref)
    .bind(&body.entities)
    .bind(&body.roles)
    .bind(body.display_order)
    .execute(&mut **tx)
    .await
    .map_err(map_unique_violation)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    read_app_in_tx(tx, id).await
}

/// The admin DELETE's write (a soft retire), transaction-scoped.
pub(crate) async fn retire_app_in_tx(
    tx: &mut attome_db::Tx<'_>,
    recording: &Recording,
    id: Uuid,
) -> Result<AppDetail, AppError> {
    lock_app_owner(tx, recording, id, true).await?;
    let changed = sqlx::query(
        "UPDATE app SET is_active=false, is_customized=true, \
             row_version = row_version + 1, updated_at = NOW() \
         WHERE id=$1 AND is_deleted=false AND is_active=true",
    )
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if changed.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    read_app_in_tx(tx, id).await
}

/// The recorded op for an app row: target `{app: <name>}` (D-467: an app is
/// keyed by its name).
fn app_op(op: Op, row: &AppDetail) -> Result<RecordedOp, AppError> {
    hooks::recorded(
        op,
        "app",
        row.id,
        serde_json::json!({ "app": row.name }),
        row,
    )
}

/// Update an app
///
/// Update an app. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/apps/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    request_body = AppBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Success", body = AppDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such app", body = ErrorResponse),
        (status = 409, description = "An app with this name already exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_app(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
    Json(body): Json<AppBody>,
) -> Result<Json<AppDetail>, AppError> {
    validate_body(&body)?;
    recording.preflight(&state.base.db).await?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "app",
            Some(id),
        )
        .named("app.update"),
    )
    .await?;
    let row = update_app_in_tx(tx.tx(), &recording, id, &body).await?;
    recording
        .record(tx.tx(), app_op(Op::UpsertApp, &row)?)
        .await?;
    tx.commit().await?;
    Ok(Json(row))
}

/// Delete an app
///
/// Delete an app. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/apps/{id}",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such app", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_app(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    recording: RecordingCtx,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    recording.preflight(&state.base.db).await?;
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::SoftDelete,
            ctx.user_id,
            "app",
            Some(id),
        )
        .named("app.delete"),
    )
    .await?;
    let row = retire_app_in_tx(tx.tx(), &recording, id).await?;
    recording
        .record(tx.tx(), app_op(Op::RetireApp, &row)?)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Self-service: the app switcher's own read (D-467: filters only) ────────

#[derive(sqlx::FromRow)]
struct AvailableAppRow {
    id: Uuid,
    name: String,
    icon: String,
    sidebar_root_ref: Option<Uuid>,
    default_dashboard_ref: Option<Uuid>,
    entities: Value,
    roles: Value,
}

#[derive(Serialize, ToSchema)]
struct AvailableApp {
    id: Uuid,
    name: String,
    icon: String,
    sidebar_root_ref: Option<Uuid>,
    default_dashboard_ref: Option<Uuid>,
    /// Entity logicalnames the Angular shell filters the sidebar tree down
    /// to when this app is selected. A pure UX filter — see this file's own
    /// doc comment; never re-checked as a grant.
    entities: Value,
}

/// `roles` is empty (unrestricted, same convention `AvailableView.
/// required_privilege IS NULL` uses) or intersects the caller's own
/// privileges — this is visibility for the switcher list, still never an
/// authorization decision (D-467).
fn visible_to(
    ctx_is_admin: bool,
    ctx_privileges: &std::collections::HashSet<String>,
    roles: &Value,
) -> bool {
    let Some(roles) = roles.as_array() else {
        return true;
    };
    if roles.is_empty() {
        return true;
    }
    if ctx_is_admin {
        return true;
    }
    roles
        .iter()
        .filter_map(Value::as_str)
        .any(|r| ctx_privileges.contains(r))
}

/// My apps
///
/// My apps. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/apps",
    tag = "core",
    responses(
        (status = 200, description = "Success", body = Vec<AvailableApp>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_available_apps(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<Vec<AvailableApp>>, AppError> {
    let rows: Vec<AvailableAppRow> = sqlx::query_as(
        "SELECT id, name, icon, sidebar_root_ref, default_dashboard_ref, entities, roles \
         FROM app WHERE is_active = true AND is_deleted = false \
         ORDER BY display_order, name",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(
        rows.into_iter()
            .filter(|row| visible_to(ctx.is_admin, &ctx.privileges, &row.roles))
            .map(|row| AvailableApp {
                id: row.id,
                name: row.name,
                icon: row.icon,
                sidebar_root_ref: row.sidebar_root_ref,
                default_dashboard_ref: row.default_dashboard_ref,
                entities: row.entities,
            })
            .collect(),
    ))
}

// ── Bundle reconcile (P-environment-promotion §5 step 13) ──────────────────
//
// Called from `bundle::apply::run_step`'s `Step::App`/retire arms, not from
// any HTTP route — see `view_admin::reconcile_view`'s section header for why
// this is a parallel implementation rather than a call into
// `create_app`/`update_app`.

#[derive(sqlx::FromRow)]
struct AppProbeRow {
    id: Uuid,
    icon: String,
    entities: Value,
    roles: Value,
    display_order: i32,
    is_customized: bool,
    is_active: bool,
}

/// M65 Phase 1 (D-467) — compare-first reconcile of one `app` row,
/// keyed by `name`. `sidebar_root_ref`/`default_dashboard_ref` are
/// deliberately left out of both the compare and the `UPDATE` — see
/// `AppDef`'s own doc comment in `bundle/model.rs`: each is a
/// deployment-local fact a bundle does not carry, so a re-apply must never
/// wipe out what an admin wired up locally after import. A fresh `CREATE`
/// still inserts both `NULL`, same "an imported app always applies with
/// both null" contract that doc comment states.
pub async fn reconcile_app(
    state: &EngineState,
    desc: &AppDef,
    policy: ReconcilePolicy,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let name = desc.name.trim();
    if name.is_empty() {
        return Err(AppError::Validation("app name is required".into()));
    }
    validate_string_array(&desc.entities, "entities")?;
    validate_string_array(&desc.roles, "roles")?;
    let icon = desc.icon.trim();
    let icon = if icon.is_empty() {
        default_icon()
    } else {
        icon.to_owned()
    };
    let db = &state.base.db;

    let current: Option<AppProbeRow> = sqlx::query_as(
        "SELECT id, icon, entities, roles, display_order, is_customized, is_active \
         FROM app WHERE name = $1",
    )
    .bind(name)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let state_differs = current.as_ref().is_some_and(|row| {
        row.icon != icon
            || row.entities != desc.entities
            || row.roles != desc.roles
            || row.display_order != desc.display_order
            || row.is_active != desc.is_active
    });
    let status = current.as_ref().map(|r| (r.is_customized, r.is_active));
    let step = reconcile_step(policy, status, state_differs);

    let id = match step {
        ReconcileStep::Unchanged => current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?,
        ReconcileStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(app = %name, "app reconcile: seed skipped a customized app (is_customized = true)");
            id
        }
        ReconcileStep::Create | ReconcileStep::Update => match current.as_ref().map(|r| r.id) {
            Some(id) => {
                let n = sqlx::query(
                    "UPDATE app SET icon=$2, entities=$3, roles=$4, display_order=$5, \
                         is_active=$6, is_customized = COALESCE($7, is_customized), \
                         row_version = row_version + 1, updated_at = NOW() \
                     WHERE id=$1",
                )
                .bind(id)
                .bind(&icon)
                .bind(&desc.entities)
                .bind(&desc.roles)
                .bind(desc.display_order)
                .bind(desc.is_active)
                .bind(customized_marker(policy))
                .execute(db)
                .await
                .map_err(map_unique_violation)?
                .rows_affected();
                if n != 1 {
                    return Err(AppError::Conflict("app row vanished during reconcile"));
                }
                id
            }
            None => {
                let id = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO app \
                         (id, name, icon, sidebar_root_ref, default_dashboard_ref, entities, roles, \
                          display_order, is_customized, is_active, owner_layer) \
                     VALUES ($1, $2, $3, NULL, NULL, $4, $5, $6, $7, $8, $9)",
                )
                .bind(id)
                .bind(name)
                .bind(&icon)
                .bind(&desc.entities)
                .bind(&desc.roles)
                .bind(desc.display_order)
                .bind(customized_marker(policy).unwrap_or(false))
                .bind(desc.is_active)
                .bind(hooks::reconcile_layer(policy).as_str())
                .execute(db)
                .await
                .map_err(map_unique_violation)?;
                id
            }
        },
    };
    let outcome = step.outcome();
    tracing::info!(app = %name, ?outcome, ?policy, "app reconcile: reconciled app");
    Ok((id, outcome))
}

/// Soft-retire (`is_active = false`) the app named `name`. Idempotent.
/// Never drops.
pub async fn retire_app(state: &EngineState, name: &str) -> Result<ReconcileOutcome, AppError> {
    let n = sqlx::query(
        "UPDATE app SET is_active = false, row_version = row_version + 1, \
             updated_at = NOW() \
         WHERE name = $1 AND is_deleted = false AND is_active = true",
    )
    .bind(name.trim())
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    tracing::info!(app = %name, "app reconcile: retired");
    Ok(ReconcileOutcome::Updated)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/apps", get(list_available_apps))
        .route("/api/v1/admin/apps", get(list_apps).post(create_app))
        .route(
            "/api/v1/admin/apps/{id}",
            get(get_app).patch(update_app).delete(delete_app),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; see `view_admin.rs`'s identical closing comment.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_apps,
    get_app,
    create_app,
    update_app,
    delete_app,
    list_available_apps
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod changeset_hook_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_app_op_targets_the_app_by_name() {
        let row = AppDetail {
            id: Uuid::now_v7(),
            name: "sales".into(),
            icon: default_icon(),
            sidebar_root_ref: None,
            default_dashboard_ref: None,
            entities: json!(["account"]),
            roles: json!([]),
            display_order: 0,
            is_active: true,
            row_version: 0,
            owner_layer: "project".into(),
        };
        let op = app_op(Op::UpsertApp, &row).expect("op");
        assert_eq!(op.target, json!({ "app": "sales" }));
        assert_eq!(op.snapshot["entities"], json!(["account"]));
        assert!(op.check().is_ok());
        assert!(app_op(Op::RetireApp, &row).expect("op").check().is_ok());
    }
}
