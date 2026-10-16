//! `/api/v1/admin/env-variables` (roadmap A30-T1/T3): the values of the
//! environment variables this deployment's published metadata defines (the
//! `environment_variable` kind). Definitions are configuration and promote
//! between environments; values are this deployment's own
//! (`environment_variable_value`) and never travel.
//!
//! A secret's value is encrypted under `integration.credential_encryption_key`
//! and is write-only: reads say only whether it is set and when. Every set
//! and clear is kept in `environment_variable_history` (without secret
//! values) and written as a `Configuration` event in its own transaction.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_model::kinds::environment_variable::{ENVIRONMENT_VARIABLE, value_fits};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

/// The envelope field name (associated data) a secret value is sealed under.
const SECRET_FIELD: &str = "environment_variable";

/// One variable: its definition and this deployment's value.
#[derive(Debug, Serialize, ToSchema)]
pub struct EnvVariable {
    pub name: String,
    /// `text`, `number`, `boolean`, `url` or `secret`.
    #[serde(rename = "type")]
    pub value_type: String,
    pub required: bool,
    #[schema(value_type = Object)]
    pub default: Value,
    pub description_en: Option<String>,
    pub description_ar: Option<String>,
    /// This deployment's value; always absent for a secret.
    #[schema(value_type = Object)]
    pub value: Value,
    /// Whether this deployment set a value.
    pub is_set: bool,
    pub updated_at: Option<DateTime<Utc>>,
    pub updated_by: Option<Uuid>,
    pub row_version: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetEnvVariable {
    #[schema(value_type = Object)]
    pub value: Value,
    /// Required to change a value already set (409 when stale).
    pub row_version: Option<i64>,
}

/// One change to a variable's value.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct EnvVariableChange {
    pub id: Uuid,
    /// `set` or `cleared`.
    pub change: String,
    /// The value set; absent for a secret.
    #[schema(value_type = Object)]
    pub value: Option<Value>,
    pub is_secret: bool,
    pub changed_by: Uuid,
    pub changed_at: DateTime<Utc>,
}

/// The published definitions, by name.
fn definitions() -> Vec<(String, Value)> {
    let cooked = crate::model_admin::cooked();
    let snapshot = cooked.snapshot();
    let prefix = format!("{}:", ENVIRONMENT_VARIABLE.0);
    snapshot
        .manifest
        .artefacts
        .keys()
        .filter(|key| key.starts_with(&prefix))
        .filter_map(|key| cooked.get::<Value>(ENVIRONMENT_VARIABLE.0, key))
        .filter_map(|doc| {
            let name = doc["name"].as_str()?.to_owned();
            Some((name, (*doc).clone()))
        })
        .collect()
}

fn definition(name: &str) -> Result<Value, AppError> {
    definitions()
        .into_iter()
        .find(|(n, _)| n == name)
        .map(|(_, doc)| doc)
        .ok_or(AppError::NotFound)
}

#[derive(sqlx::FromRow)]
struct StoredValue {
    name: String,
    value: Option<Value>,
    row_version: i64,
    updated_by: Uuid,
    updated_at: DateTime<Utc>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/env-variables",
    tag = "admin",
    operation_id = "list_env_variables",
    responses(
        (status = 200, description = "Every defined variable with this deployment's value (page 1 holds them all)", body = PaginatedResponse<EnvVariable>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_variables(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<EnvVariable>>, AppError> {
    let stored: Vec<StoredValue> = sqlx::query_as(
        "SELECT name, value, row_version, updated_by, updated_at FROM environment_variable_value",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut items: Vec<EnvVariable> = definitions()
        .into_iter()
        .map(|(name, doc)| {
            let value_type = doc["type"].as_str().unwrap_or("text").to_owned();
            let row = stored.iter().find(|s| s.name == name);
            EnvVariable {
                value: if value_type == "secret" {
                    Value::Null
                } else {
                    row.and_then(|r| r.value.clone()).unwrap_or(Value::Null)
                },
                is_set: row.is_some(),
                updated_at: row.map(|r| r.updated_at),
                updated_by: row.map(|r| r.updated_by),
                row_version: row.map(|r| r.row_version),
                required: doc["required"].as_bool().unwrap_or(false),
                default: doc.get("default").cloned().unwrap_or(Value::Null),
                description_en: doc["description_en"].as_str().map(str::to_owned),
                description_ar: doc["description_ar"].as_str().map(str::to_owned),
                name,
                value_type,
            }
        })
        .collect();
    items.sort_by(|a, b| a.name.cmp(&b.name));
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse {
        page_size: total.max(1),
        items,
        total,
        page: 1,
    }))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/env-variables/{name}",
    tag = "admin",
    operation_id = "set_env_variable",
    params(("name" = String, Path)),
    request_body = SetEnvVariable,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Set"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such variable is defined", body = ErrorResponse),
        (status = 409, description = "The value changed since it was read", body = ErrorResponse),
        (status = 422, description = "The value does not fit the variable's type", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_variable(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(name): Path<String>,
    Json(body): Json<SetEnvVariable>,
) -> Result<StatusCode, AppError> {
    let doc = definition(&name)?;
    let value_type = doc["type"].as_str().unwrap_or("text");
    if !value_fits(value_type, &body.value) {
        return Err(AppError::Validation(format!(
            "{name} takes a {value_type} value"
        )));
    }
    let is_secret = value_type == "secret";
    let (plain, encrypted) = if is_secret {
        let ring = &state.base.config.integration.credential_encryption_key;
        if ring.is_empty() {
            return Err(AppError::Validation(
                "secret variables need integration.credential_encryption_key".into(),
            ));
        }
        let text = body.value.as_str().unwrap_or_default();
        (
            None,
            Some(attome_auth::envelope::encrypt(SECRET_FIELD, ring, text)?),
        )
    } else {
        (Some(body.value.clone()), None)
    };
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "environment_variable_value",
            None,
        )
        .named("env_variable.set")
        .comment(format!("{name} set")),
    )
    .await?;
    let current: Option<i64> = sqlx::query_scalar(
        "SELECT row_version FROM environment_variable_value WHERE name = $1 FOR UPDATE",
    )
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    match current {
        None => {
            sqlx::query(
                "INSERT INTO environment_variable_value (name, value, value_encrypted, updated_by) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&name)
            .bind(&plain)
            .bind(&encrypted)
            .bind(ctx.user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
        Some(version) => {
            if body.row_version != Some(version) {
                return Err(AppError::VersionConflict);
            }
            sqlx::query(
                "UPDATE environment_variable_value \
                    SET value = $2, value_encrypted = $3, updated_by = $4, updated_at = now(), \
                        row_version = row_version + 1 \
                  WHERE name = $1",
            )
            .bind(&name)
            .bind(&plain)
            .bind(&encrypted)
            .bind(ctx.user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }
    sqlx::query(
        "INSERT INTO environment_variable_history (name, change, value, is_secret, changed_by) \
         VALUES ($1, 'set', $2, $3, $4)",
    )
    .bind(&name)
    .bind(&plain)
    .bind(is_secret)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/env-variables/{name}",
    tag = "admin",
    operation_id = "clear_env_variable",
    params(("name" = String, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Cleared: the default applies again"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "The variable has no value here", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn clear_variable(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::HardDelete,
            ctx.user_id,
            "environment_variable_value",
            None,
        )
        .named("env_variable.cleared")
        .comment(format!("{name} cleared")),
    )
    .await?;
    let removed: Option<bool> = sqlx::query_scalar(
        "DELETE FROM environment_variable_value WHERE name = $1 \
         RETURNING value_encrypted IS NOT NULL",
    )
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let is_secret = removed.ok_or(AppError::NotFound)?;
    sqlx::query(
        "INSERT INTO environment_variable_history (name, change, is_secret, changed_by) \
         VALUES ($1, 'cleared', $2, $3)",
    )
    .bind(&name)
    .bind(is_secret)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/env-variables/{name}/history",
    tag = "admin",
    operation_id = "env_variable_history",
    params(("name" = String, Path)),
    responses(
        (status = 200, description = "The variable's changes, newest first (at most 200)", body = PaginatedResponse<EnvVariableChange>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn variable_history(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(name): Path<String>,
) -> Result<Json<PaginatedResponse<EnvVariableChange>>, AppError> {
    let items: Vec<EnvVariableChange> = sqlx::query_as(
        "SELECT id, change, value, is_secret, changed_by, changed_at \
           FROM environment_variable_history WHERE name = $1 \
          ORDER BY changed_at DESC, id DESC LIMIT 200",
    )
    .bind(&name)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: 200,
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/env-variables", get(list_variables))
        .route(
            "/api/v1/admin/env-variables/{name}",
            axum::routing::put(set_variable).delete(clear_variable),
        )
        .route(
            "/api/v1/admin/env-variables/{name}/history",
            get(variable_history),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_variables, set_variable, clear_variable, variable_history),
    components(schemas(EnvVariable, SetEnvVariable, EnvVariableChange))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
