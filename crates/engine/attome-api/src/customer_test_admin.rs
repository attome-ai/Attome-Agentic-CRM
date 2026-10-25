//! `/api/v1/admin/customer-tests` (roadmap Z15-T13): a builder's own tests
//! of their configuration — create, change, delete, run one, run all,
//! export and import. The tests and the runner live in
//! `attome_records::customer_tests`; these handlers parse, audit and call.
//!
//! A run executes inside a transaction that is always rolled back
//! (Z15-T12), so running a test writes only its `customer_test_run` row,
//! recorded with its `Configuration` event after the rollback.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_records::customer_tests::{
    self as store, CustomerTest, CustomerTestBody, CustomerTestExport, CustomerTestImportResult,
    CustomerTestPatch, CustomerTestRun,
};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header::IF_MATCH},
    routing::{get, post},
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// The runs `GET /{id}/runs` returns, newest first.
const RUN_HISTORY: i64 = 50;

/// `If-Match: "<row_version>"`; required on PATCH, optional on DELETE.
fn if_match(headers: &HeaderMap, required: bool) -> Result<Option<i64>, AppError> {
    let Some(raw) = headers.get(IF_MATCH) else {
        return if required {
            Err(AppError::Validation(
                "If-Match: \"<row_version>\" is required to change a customer test".into(),
            ))
        } else {
            Ok(None)
        };
    };
    let s = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    s.parse::<i64>().map(Some).map_err(|_| {
        AppError::Validation(format!("If-Match must be a row_version integer, got: {s}"))
    })
}

fn event(
    operation: AuditOperation,
    actor: Uuid,
    table: &str,
    id: Option<Uuid>,
    name: &'static str,
) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        actor,
        table,
        id,
    )
    .named(name)
}

/// One test's run.
#[derive(Debug, Serialize, ToSchema)]
pub struct CustomerTestRunResult {
    pub test_id: Uuid,
    pub name: String,
    pub run_id: Uuid,
    pub passed: bool,
    pub failures: Vec<String>,
}

/// Every active test's run.
#[derive(Debug, Serialize, ToSchema)]
pub struct CustomerTestRunAll {
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<CustomerTestRunResult>,
}

/// List customer tests
///
/// List customer tests. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/customer-tests",
    tag = "admin",
    operation_id = "list_customer_tests",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Customer tests by name, with each one's latest result", body = PaginatedResponse<CustomerTest>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_tests(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<CustomerTest>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let (items, total) = store::list_tests(&state.base.db, page_size, offset).await?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

/// Create a customer test
///
/// Create a customer test. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/customer-tests",
    tag = "admin",
    operation_id = "create_customer_test",
    request_body = CustomerTestBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = CustomerTest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "No name, or the definition does not read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_test(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CustomerTestBody>,
) -> Result<(StatusCode, Json<CustomerTest>), AppError> {
    store::validate(&body.name, &body.definition)?;
    let mut tx = SecurityTx::begin(
        &state,
        event(
            AuditOperation::Create,
            ctx.user_id,
            "customer_test",
            None,
            "customer_test.created",
        ),
    )
    .await?;
    let test = store::insert_test(&mut tx, &body, ctx.user_id).await?;
    tx.event_mut().set_record_id(test.id);
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(test)))
}

/// One customer test
///
/// One customer test. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/customer-tests/{id}",
    tag = "admin",
    operation_id = "get_customer_test",
    params(("id" = Uuid, Path, description = "The customer test")),
    responses(
        (status = 200, description = "The test", body = CustomerTest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such test", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_test(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<CustomerTest>, AppError> {
    Ok(Json(store::get_test(&state.base.db, id).await?))
}

/// Update a customer test
///
/// Update a customer test. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/customer-tests/{id}",
    tag = "admin",
    operation_id = "update_customer_test",
    params(("id" = Uuid, Path, description = "The customer test"), ("If-Match" = String, Header, description = "\"<row_version>\"")),
    request_body = CustomerTestPatch,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Changed", body = CustomerTest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such test", body = ErrorResponse),
        (status = 409, description = "The test changed since it was read", body = ErrorResponse),
        (status = 422, description = "No If-Match, or the definition does not read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_test(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(patch): Json<CustomerTestPatch>,
) -> Result<Json<CustomerTest>, AppError> {
    let row_version = if_match(&headers, true)?.unwrap_or_default();
    let mut tx = SecurityTx::begin(
        &state,
        event(
            AuditOperation::Update,
            ctx.user_id,
            "customer_test",
            Some(id),
            "customer_test.updated",
        ),
    )
    .await?;
    let test = store::update_test(&mut tx, id, row_version, &patch).await?;
    tx.commit().await?;
    Ok(Json(test))
}

/// Delete a customer test
///
/// Delete a customer test. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/customer-tests/{id}",
    tag = "admin",
    operation_id = "delete_customer_test",
    params(("id" = Uuid, Path, description = "The customer test"), ("If-Match" = Option<String>, Header, description = "\"<row_version>\", optional")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Deleted, with its runs"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such test", body = ErrorResponse),
        (status = 409, description = "The test changed since it was read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_test(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, AppError> {
    let row_version = if_match(&headers, false)?;
    let mut tx = SecurityTx::begin(
        &state,
        event(
            AuditOperation::HardDelete,
            ctx.user_id,
            "customer_test",
            Some(id),
            "customer_test.deleted",
        ),
    )
    .await?;
    store::delete_test(&mut tx, id, row_version).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A customer test's runs
///
/// A customer test's runs. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/customer-tests/{id}/runs",
    tag = "admin",
    operation_id = "list_customer_test_runs",
    params(("id" = Uuid, Path, description = "The customer test")),
    responses(
        (status = 200, description = "The test's latest runs, newest first (at most 50)", body = PaginatedResponse<CustomerTestRun>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_runs(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<CustomerTestRun>>, AppError> {
    let items = store::list_runs(&state.base.db, id, RUN_HISTORY).await?;
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, RUN_HISTORY)))
}

/// Runs one test and records the run with its event.
async fn run_one(
    state: &EngineState,
    ctx: &Authorized<Admin>,
    id: Uuid,
    name: String,
    definition: Result<store::TestDefinition, String>,
) -> Result<CustomerTestRunResult, AppError> {
    let started = chrono::Utc::now();
    let outcome = match definition {
        Ok(definition) => store::run_test(state, ctx, &definition).await,
        Err(e) => store::TestOutcome {
            passed: false,
            failures: vec![format!("the test does not read: {e}")],
        },
    };
    let mut tx = SecurityTx::begin(
        state,
        event(
            AuditOperation::Create,
            ctx.user_id,
            "customer_test_run",
            None,
            "customer_test.run",
        )
        .comment(format!(
            "{name}: {}",
            if outcome.passed { "passed" } else { "failed" }
        )),
    )
    .await?;
    let run_id = store::insert_run(&mut tx, id, started, &outcome).await?;
    tx.event_mut().set_record_id(run_id);
    tx.commit().await?;
    Ok(CustomerTestRunResult {
        test_id: id,
        name,
        run_id,
        passed: outcome.passed,
        failures: outcome.failures,
    })
}

/// Run a customer test
///
/// Run a customer test. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/customer-tests/{id}/run",
    tag = "admin",
    operation_id = "run_customer_test",
    params(("id" = Uuid, Path, description = "The customer test")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "The run: nothing the test did is kept", body = CustomerTestRunResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active test", body = ErrorResponse),
        (status = 422, description = "The stored definition does not read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn run_test(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<CustomerTestRunResult>, AppError> {
    let test = store::get_test(&state.base.db, id).await?;
    if !test.is_active {
        return Err(AppError::NotFound);
    }
    let definition = store::load_definition(&state.base.db, id).await?;
    Ok(Json(
        run_one(&state, &ctx, id, test.name, Ok(definition)).await?,
    ))
}

/// Run every customer test
///
/// Run every customer test. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/customer-tests/run-all",
    tag = "admin",
    operation_id = "run_all_customer_tests",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Every active test's run, by name", body = CustomerTestRunAll),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn run_all(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
) -> Result<Json<CustomerTestRunAll>, AppError> {
    let mut results = Vec::new();
    // One at a time: each run holds a transaction for its whole length.
    for (id, name, definition) in store::active_tests(&state.base.db, false).await? {
        results.push(run_one(&state, &ctx, id, name, definition).await?);
    }
    let passed = results.iter().filter(|r| r.passed).count();
    Ok(Json(CustomerTestRunAll {
        passed,
        failed: results.len() - passed,
        results,
    }))
}

/// Export customer tests
///
/// Export customer tests. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/customer-tests/export",
    tag = "admin",
    operation_id = "export_customer_tests",
    responses(
        (status = 200, description = "Every test, active or not, as an attome-customer-tests/v1 document", body = CustomerTestExport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn export_tests(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<CustomerTestExport>, AppError> {
    Ok(Json(store::export_tests(&state.base.db).await?))
}

/// Import customer tests
///
/// Import customer tests. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/customer-tests/import",
    tag = "admin",
    operation_id = "import_customer_tests",
    request_body = CustomerTestExport,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Import)])))),
    responses(
        (status = 200, description = "Imported: a test whose name is already here is replaced", body = CustomerTestImportResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Not an attome-customer-tests/v1 document, or an entry does not read (nothing is written)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn import_tests(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(document): Json<CustomerTestExport>,
) -> Result<Json<CustomerTestImportResult>, AppError> {
    let mut tx = SecurityTx::begin(
        &state,
        event(
            AuditOperation::Import,
            ctx.user_id,
            "customer_test",
            None,
            "customer_test.imported",
        )
        .comment(format!("{} tests", document.tests.len())),
    )
    .await?;
    let result = store::import_tests(&mut tx, &document, ctx.user_id).await?;
    tx.commit().await?;
    Ok(Json(result))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/customer-tests",
            get(list_tests).post(create_test),
        )
        .route("/api/v1/admin/customer-tests/run-all", post(run_all))
        .route("/api/v1/admin/customer-tests/export", get(export_tests))
        .route("/api/v1/admin/customer-tests/import", post(import_tests))
        .route(
            "/api/v1/admin/customer-tests/{id}",
            get(get_test).patch(update_test).delete(delete_test),
        )
        .route("/api/v1/admin/customer-tests/{id}/run", post(run_test))
        .route("/api/v1/admin/customer-tests/{id}/runs", get(list_runs))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_tests,
        create_test,
        get_test,
        update_test,
        delete_test,
        list_runs,
        run_test,
        run_all,
        export_tests,
        import_tests
    ),
    components(schemas(
        CustomerTest,
        CustomerTestBody,
        CustomerTestPatch,
        CustomerTestRun,
        CustomerTestExport,
        CustomerTestImportResult,
        CustomerTestRunResult,
        CustomerTestRunAll
    ))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn if_match_is_required_on_patch_and_optional_on_delete() {
        let mut headers = HeaderMap::new();
        assert!(if_match(&headers, true).is_err());
        assert_eq!(if_match(&headers, false).ok(), Some(None));
        headers.insert(IF_MATCH, HeaderValue::from_static("\"3\""));
        assert_eq!(if_match(&headers, true).ok(), Some(Some(3)));
        headers.insert(IF_MATCH, HeaderValue::from_static("abc"));
        assert!(if_match(&headers, false).is_err());
    }
}
