//! `/api/v1/admin/customer-flags` (roadmap T6-T2): flags a builder defines
//! and rules and flows read as `flag("name")`. A deployment's own state,
//! like environment variable values: defined and switched here, never
//! promoted. Every change is a `Configuration` event in its own
//! transaction, and readers take the table as it is now
//! (`attome_core::customer_flags`), so an emergency off holds on every node
//! at once.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_core::customer_flags::valid_name;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most flags a deployment defines; the list returns them all.
const MAX_FLAGS: i64 = 500;

/// One customer flag.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct CustomerFlag {
    pub name: String,
    pub description: Option<String>,
    /// The value set; `on` below is what rules read.
    pub value: bool,
    /// Switched off in an emergency: off until it is set again.
    pub emergency_off: bool,
    /// Whether `flag(name)` reads true now.
    pub on: bool,
    pub row_version: i64,
    pub updated_by: Uuid,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetCustomerFlag {
    pub value: bool,
    pub description: Option<String>,
    /// Required to change a flag that exists (409 when stale).
    pub row_version: Option<i64>,
}

const COLUMNS: &str = "name, description, value, emergency_off, value AND NOT emergency_off AS on, \
                       row_version, updated_by, updated_at";

fn check_name(name: &str) -> Result<(), AppError> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(AppError::Validation(
            "a flag name is lower-case letters, digits and underscores, starting with a letter, \
             at most 63 characters"
                .into(),
        ))
    }
}

/// List customer flags
///
/// List customer flags. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/customer-flags",
    tag = "admin",
    operation_id = "list_customer_flags",
    responses(
        (status = 200, description = "Every flag (page 1 holds them all)", body = PaginatedResponse<CustomerFlag>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_flags(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
) -> Result<Json<PaginatedResponse<CustomerFlag>>, AppError> {
    let items: Vec<CustomerFlag> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM customer_flag ORDER BY name LIMIT $1"
    ))
    .bind(MAX_FLAGS)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse {
        items,
        total,
        page: 1,
        page_size: MAX_FLAGS,
        warnings: Vec::new(),
    }))
}

/// Set a customer flag
///
/// Defines a customer flag or sets its value. Setting a flag clears an
/// emergency off. Administrators only. Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/customer-flags/{name}",
    tag = "admin",
    operation_id = "set_customer_flag",
    params(("name" = String, Path, description = "The flag's name")),
    request_body = SetCustomerFlag,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The flag as stored", body = CustomerFlag),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The flag exists and `row_version` is missing or stale", body = ErrorResponse),
        (status = 422, description = "An invalid name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn set_flag(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Path(name): Path<String>,
    Json(body): Json<SetCustomerFlag>,
) -> Result<Json<CustomerFlag>, AppError> {
    write_flag(&state, ctx.user_id, &name, body).await.map(Json)
}

/// The route's write: name check, row version, one transaction with its
/// `Configuration` event. Also the flags agent tool's, through
/// [`ApiFlagsWriter`] (T6-T4).
async fn write_flag(
    state: &EngineState,
    actor: Uuid,
    name: &str,
    body: SetCustomerFlag,
) -> Result<CustomerFlag, AppError> {
    check_name(name)?;
    let mut tx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            actor,
            "customer_flag",
            None,
        )
        .named("customer_flag.set")
        .comment(format!("{name} set to {}", body.value)),
    )
    .await?;
    let current: Option<i64> =
        sqlx::query_scalar("SELECT row_version FROM customer_flag WHERE name = $1 FOR UPDATE")
            .bind(name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let flag: CustomerFlag = match current {
        None => sqlx::query_as(&format!(
            "INSERT INTO customer_flag (name, description, value, updated_by) \
             VALUES ($1, $2, $3, $4) RETURNING {COLUMNS}"
        ))
        .bind(name)
        .bind(&body.description)
        .bind(body.value)
        .bind(actor)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?,
        Some(version) => {
            if body.row_version != Some(version) {
                return Err(AppError::VersionConflict);
            }
            sqlx::query_as(&format!(
                "UPDATE customer_flag \
                    SET value = $2, description = COALESCE($3, description), \
                        emergency_off = false, updated_by = $4, updated_at = now(), \
                        row_version = row_version + 1 \
                  WHERE name = $1 RETURNING {COLUMNS}"
            ))
            .bind(name)
            .bind(body.value)
            .bind(&body.description)
            .bind(actor)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?
        }
    };
    tx.commit().await?;
    Ok(flag)
}

/// T6-T4: the flags agent tool's write, the route's own.
pub struct ApiFlagsWriter;

impl attome_core::customer_flags::FlagsWriter for ApiFlagsWriter {
    fn set<'a>(
        &'a self,
        state: &'a EngineState,
        actor: Uuid,
        name: &'a str,
        value: bool,
        description: Option<String>,
        row_version: Option<i64>,
    ) -> attome_core::customer_flags::FlagWriteFuture<'a> {
        Box::pin(async move {
            let flag = write_flag(
                state,
                actor,
                name,
                SetCustomerFlag {
                    value,
                    description,
                    row_version,
                },
            )
            .await?;
            serde_json::to_value(flag).map_err(AppError::internal)
        })
    }
}

/// Switch a customer flag off now
///
/// Emergency off: the flag reads off everywhere at once, whatever its value,
/// until someone sets it again. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/customer-flags/{name}/emergency-off",
    tag = "admin",
    operation_id = "emergency_off_customer_flag",
    params(("name" = String, Path, description = "The flag's name")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The flag, now off", body = CustomerFlag),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such flag", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn emergency_off(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Path(name): Path<String>,
) -> Result<Json<CustomerFlag>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "customer_flag",
            None,
        )
        .named("customer_flag.emergency_off")
        .comment(format!("{name} switched off in an emergency")),
    )
    .await?;
    let flag: Option<CustomerFlag> = sqlx::query_as(&format!(
        "UPDATE customer_flag \
            SET emergency_off = true, updated_by = $2, updated_at = now(), \
                row_version = row_version + 1 \
          WHERE name = $1 RETURNING {COLUMNS}"
    ))
    .bind(&name)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let flag = flag.ok_or(AppError::NotFound)?;
    tx.commit().await?;
    tracing::warn!(flag = %name, user_id = %ctx.user_id, "customer flag switched off in an emergency");
    Ok(Json(flag))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/customer-flags", get(list_flags))
        .route("/api/v1/admin/customer-flags/{name}", put(set_flag))
        .route(
            "/api/v1/admin/customer-flags/{name}/emergency-off",
            post(emergency_off),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_flags, set_flag, emergency_off),
    components(schemas(CustomerFlag, SetCustomerFlag))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
