//! `/api/v1/acceptance-scripts` (roadmap T7-T4): acceptance scripts for
//! business users. A builder writes one as a customer test whose definition
//! is a checklist (`{"checklist": ["Open a lead", ...]}`, on the customer
//! tests screen); any signed-in user lists them and records a run, marking
//! each step passed or failed with a note. The run is a `customer_test_run`
//! row like any other, with who ran it, so a builder sees it beside the
//! automatic runs. No automatic runner picks a script up.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_records::customer_tests::{self as store, AcceptanceScript, StepMark};
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The acceptance scripts
///
/// The active acceptance scripts (customer tests with a checklist) by name, each with its steps and
/// its last run. Any signed-in user.
#[utoipa::path(
    get,
    path = "/api/v1/acceptance-scripts",
    operation_id = "list_acceptance_scripts",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<AcceptanceScript>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_scripts(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<AcceptanceScript>>, AppError> {
    let window = q.window();
    let (items, total) =
        store::list_acceptance_scripts(&state.base.db, window.page_size, window.offset).await?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// A person's marks for one run.
#[derive(Debug, Deserialize, ToSchema)]
pub(crate) struct ChecklistRunBody {
    /// One mark per step, in order.
    steps: Vec<StepMark>,
}

/// The recorded run.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct ChecklistRunResult {
    run_id: Uuid,
    passed: bool,
    /// One line per failed step: its number, text and note.
    failures: Vec<String>,
}

/// Record a run of an acceptance script
///
/// Records a person's run of an acceptance script, one mark per step in order: it passed when every
/// step did. Any signed-in user. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/acceptance-scripts/{id}/runs",
    operation_id = "record_acceptance_script_run",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The acceptance script")),
    request_body = ChecklistRunBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The run", body = ChecklistRunResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such active acceptance script", body = ErrorResponse),
        (status = 422, description = "The marks do not match the steps one for one", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn record_run(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<ChecklistRunBody>,
) -> Result<(axum::http::StatusCode, Json<ChecklistRunResult>), AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "customer_test_run",
            None,
        )
        .named("customer_test.acceptance_run"),
    )
    .await?;
    let (run_id, outcome) =
        store::record_checklist_run(&mut tx, id, ctx.user_id, &body.steps).await?;
    tx.event_mut().set_record_id(run_id);
    tx.commit().await?;
    Ok((
        axum::http::StatusCode::CREATED,
        Json(ChecklistRunResult {
            run_id,
            passed: outcome.passed,
            failures: outcome.failures,
        }),
    ))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/acceptance-scripts", get(list_scripts))
        .route("/api/v1/acceptance-scripts/{id}/runs", post(record_run))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_scripts, record_run))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
