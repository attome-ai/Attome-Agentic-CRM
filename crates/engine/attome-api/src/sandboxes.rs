//! T5-T1: the copy API. `POST /api/v1/admin/sandboxes` asks for a masked
//! sandbox copy of this deployment's database; the registered job
//! [`SANDBOX_COPY`] makes it with the same code as `attome scratch create`
//! (the server's `scratch` module) and records the outcome on the request,
//! which `GET /api/v1/admin/sandboxes` and `.../{id}` read. A copy takes
//! minutes to hours, so the request answers 202 at once. Asking needs the
//! Deployment administration area and is audited as a configuration change.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The job that makes a requested copy.
pub const SANDBOX_COPY: attome_jobs::JobType = attome_jobs::JobType {
    lane: attome_jobs::registry::Lane::Batch,
    max_attempts: 1,
    max_concurrency: Some(1),
    ..attome_jobs::JobType::new("sandbox_copy", 1)
};

/// [`SANDBOX_COPY`]'s payload: the request to carry out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxCopyPayload {
    pub request_id: Uuid,
}

/// What to copy.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SandboxBody {
    /// The new database: 3 to 63 lowercase letters, digits or underscores,
    /// starting with a letter.
    pub name: String,
    /// `full` (the default), `sample` or `metadata`.
    #[serde(default)]
    pub mode: Option<String>,
    /// `sample`: the share of each customer-data entity kept, 1 to 99
    /// (default 10).
    #[serde(default)]
    pub percent: Option<i16>,
}

/// A requested copy.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct SandboxRequest {
    pub id: Uuid,
    pub database_name: String,
    pub mode: String,
    pub sample_percent: Option<i16>,
    /// `queued`, `running`, `done` or `failed`.
    pub status: String,
    /// What the copy did, or why it failed.
    pub detail: Option<String>,
    pub requested_by: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// The checks a request passes before it is queued. Pure.
pub fn check_body(
    body: &SandboxBody,
    source: &str,
) -> Result<(String, String, Option<i16>), AppError> {
    let name = body.name.trim().to_owned();
    let shaped = (3..=63).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if !shaped || name == source {
        return Err(AppError::Validation(
            "name is 3 to 63 lowercase letters, digits or underscores, starting with a letter, \
             and not this deployment's database"
                .into(),
        ));
    }
    let mode = body.mode.as_deref().unwrap_or("full").to_owned();
    if !matches!(mode.as_str(), "full" | "sample" | "metadata") {
        return Err(AppError::Validation(
            "mode is full, sample or metadata".into(),
        ));
    }
    let percent = match (mode.as_str(), body.percent) {
        ("sample", None) => Some(10),
        ("sample", Some(p)) if (1..=99).contains(&p) => Some(p),
        ("sample", Some(_)) => {
            return Err(AppError::Validation("percent is 1 to 99".into()));
        }
        (_, Some(_)) => {
            return Err(AppError::Validation(
                "percent applies to a sample only".into(),
            ));
        }
        (_, None) => None,
    };
    Ok((name, mode, percent))
}

const COLUMNS: &str = "id, database_name, mode, sample_percent, status, detail, requested_by, \
                       created_at, finished_at";

/// Ask for a sandbox copy
///
/// Queues a masked copy of this deployment's database into a new database on the same server, as
/// `attome scratch create` makes it. Answers at once; read the request for its outcome.
#[utoipa::path(
    post,
    path = "/api/v1/admin/sandboxes",
    tag = "admin",
    request_body = SandboxBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 202, description = "The copy is queued", body = SandboxRequest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not administer the deployment", body = ErrorResponse),
        (status = 409, description = "A copy with this name is queued, running or made", body = ErrorResponse),
        (status = 422, description = "A name, mode or percent out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn request_sandbox(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Json(body): Json<SandboxBody>,
) -> Result<(StatusCode, Json<SandboxRequest>), AppError> {
    let (name, mode, percent) = check_body(&body, &state.base.config.database.dbname)?;
    let id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let request: SandboxRequest = sqlx::query_as(&format!(
        "INSERT INTO sandbox_request (id, database_name, mode, sample_percent, requested_by) \
         VALUES ($1, $2, $3, $4, $5) RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&name)
    .bind(&mode)
    .bind(percent)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        let taken =
            matches!(&e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23505"));
        if taken {
            AppError::Conflict("a copy with this name is queued, running or made")
        } else {
            AppError::internal(e)
        }
    })?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
            name: SANDBOX_COPY.name.to_owned(),
            version: SANDBOX_COPY.version,
            payload: json!(SandboxCopyPayload { request_id: id }),
            next: None,
        }),
    )
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "sandbox_request",
            Some(id),
        )
        .named("ops.sandbox_requested")
        .comment(format!("sandbox copy {name} ({mode}) requested")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::ACCEPTED, Json(request)))
}

/// Sandbox copies
///
/// The copies asked for, newest first, with their outcome.
#[utoipa::path(
    get,
    path = "/api/v1/admin/sandboxes",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "A page of requests", body = PaginatedResponse<SandboxRequest>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not administer the deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn list_sandboxes(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<SandboxRequest>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = query.window();
    let items: Vec<SandboxRequest> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM sandbox_request ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2"
    ))
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sandbox_request")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// A sandbox copy
///
/// One requested copy and its outcome.
#[utoipa::path(
    get,
    path = "/api/v1/admin/sandboxes/{id}",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The request")),
    responses(
        (status = 200, description = "The request", body = SandboxRequest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not administer the deployment", body = ErrorResponse),
        (status = 404, description = "No such request", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn get_sandbox(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SandboxRequest>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM sandbox_request WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .map(Json)
    .ok_or(AppError::NotFound)
}

/// The job's bookkeeping: marks the request running and returns it, or
/// `None` when it is gone or no longer queued.
pub async fn start(state: &EngineState, id: Uuid) -> Result<Option<SandboxRequest>, AppError> {
    sqlx::query_as(&format!(
        "UPDATE sandbox_request SET status = 'running' \
          WHERE id = $1 AND status = 'queued' RETURNING {COLUMNS}"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Records the outcome of a copy.
pub async fn finish(
    state: &EngineState,
    id: Uuid,
    done: bool,
    detail: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE sandbox_request SET status = $2, detail = $3, finished_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(if done { "done" } else { "failed" })
    .bind(detail)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/sandboxes",
            get(list_sandboxes).post(request_sandbox),
        )
        .route("/api/v1/admin/sandboxes/{id}", get(get_sandbox))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(request_sandbox, list_sandboxes, get_sandbox),
    components(schemas(SandboxBody, SandboxRequest))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(name: &str, mode: Option<&str>, percent: Option<i16>) -> SandboxBody {
        SandboxBody {
            name: name.into(),
            mode: mode.map(str::to_owned),
            percent,
        }
    }

    #[test]
    fn sandbox_request_checks() {
        assert_eq!(
            check_body(&body("copy_a", None, None), "attome").ok(),
            Some(("copy_a".into(), "full".into(), None))
        );
        assert_eq!(
            check_body(&body("copy_a", Some("sample"), None), "attome").ok(),
            Some(("copy_a".into(), "sample".into(), Some(10)))
        );
        assert!(check_body(&body("attome", None, None), "attome").is_err());
        assert!(check_body(&body("Bad", None, None), "attome").is_err());
        assert!(check_body(&body("copy_a", Some("other"), None), "attome").is_err());
        assert!(check_body(&body("copy_a", Some("sample"), Some(0)), "attome").is_err());
        assert!(check_body(&body("copy_a", Some("full"), Some(5)), "attome").is_err());
    }
}
