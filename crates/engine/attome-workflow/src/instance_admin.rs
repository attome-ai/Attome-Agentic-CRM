//! Instance admin API (P-workflow-engine.md §5 step 8): list/detail/cancel,
//! plus a manual-start endpoint that exercises the same entry mechanism an
//! automatic entity-event trigger uses (entity create/update auto-start runs
//! through the change-event outbox, `entity_trigger::dispatch_pending`).

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, DEFAULT_PAGE_SIZE, PageBase, PageWindow, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::Deserialize;
use uuid::Uuid;

use crate::graph::Graph;
use crate::model::{
    CancelInstanceBody, InstanceDetail, InstanceListItem, NodeRunSummary, StartInstanceBody,
};
use attome_types::ErrorResponse;
use utoipa::IntoParams;

/// What a masked value reads as.
const MASK: &str = "••••••";

/// A key's words, lower case: `X-Api-Key`, `apiKey` and `api_key` all give
/// `api`, `key`. A word's trailing digits go (`password1`).
fn key_words(key: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut last_lower = false;
    for c in key.chars() {
        if !c.is_alphanumeric() {
            words.push(std::mem::take(&mut word));
            last_lower = false;
            continue;
        }
        if c.is_uppercase() && last_lower {
            words.push(std::mem::take(&mut word));
        }
        last_lower = c.is_lowercase() || c.is_numeric();
        word.extend(c.to_lowercase());
    }
    words.push(word);
    words
        .into_iter()
        .map(|w| w.trim_end_matches(|c: char| c.is_ascii_digit()).to_owned())
        .filter(|w| !w.is_empty())
        .collect()
}

/// A key whose value is a credential, by its words: `password`, `client_secret`,
/// `Authorization`, `api_key`, `signing_key`, `access_token`. A `token` must end
/// the key, so `token_count` keeps its value; a bare `key` is not a credential.
fn is_secret_key(key: &str) -> bool {
    const ANY_WORD: [&str; 18] = [
        "password",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "secret",
        "secrets",
        "authorization",
        "auth",
        "bearer",
        "jwt",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "apikey",
        "pin",
        "otp",
    ];
    const KEY_OF: [&str; 8] = [
        "api",
        "private",
        "access",
        "signing",
        "encryption",
        "secret",
        "client",
        "shared",
    ];
    let words = key_words(key);
    words.iter().any(|w| ANY_WORD.contains(&w.as_str()))
        || words.last().is_some_and(|w| w == "token")
        || words
            .windows(2)
            .any(|p| p[1] == "key" && KEY_OF.contains(&p[0].as_str()))
}

/// `tokens` is a credential unless it counts something (`"tokens": 120`).
fn is_secret_field(key: &str, value: &serde_json::Value) -> bool {
    if value.is_null() {
        return false;
    }
    is_secret_key(key)
        || (key_words(key).last().is_some_and(|w| w == "tokens") && !value.is_number())
}

/// The credentials a text carries in itself: a URL's user and password, the
/// value after `Bearer` or `Basic`, and `password=…` or `"api_key": "…"`. If a
/// pattern could not be built, the whole text is withheld.
fn masked_text(text: &str) -> std::borrow::Cow<'_, str> {
    use regex::Regex;
    use std::sync::LazyLock;
    static URL: LazyLock<Option<Regex>> =
        LazyLock::new(|| Regex::new(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@").ok());
    static SCHEME: LazyLock<Option<Regex>> =
        LazyLock::new(|| Regex::new(r"\b(Bearer|bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}").ok());
    static PAIR: LazyLock<Option<Regex>> = LazyLock::new(|| {
        Regex::new(
            r#"(?i)\b([a-z0-9_-]*(?:password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s"'&,;}]+)"#,
        )
        .ok()
    });
    let (Some(url), Some(scheme), Some(pair)) = (&*URL, &*SCHEME, &*PAIR) else {
        return std::borrow::Cow::Borrowed(MASK);
    };
    let out = url.replace_all(text, format!("${{1}}{MASK}@").as_str());
    let out = scheme.replace_all(&out, format!("${{1}} {MASK}").as_str());
    let out = pair.replace_all(&out, format!("${{1}}{MASK}").as_str());
    if out == text {
        std::borrow::Cow::Borrowed(text)
    } else {
        std::borrow::Cow::Owned(out.into_owned())
    }
}

/// M2-T3: a run's values with every credential masked, however deep: a value
/// under a credential's key; the `value` beside a `name` that names one (a
/// header list); and what a text carries in itself. A step's input and output
/// hold what it was given (a webhook's headers, a connector's parameters), and a
/// run is read by whoever may inspect flows, not only by those who may see those
/// credentials. Personal values stay: they are the run's own data, under the
/// Automation privilege, and M3-T4 erases them.
fn masked(mut value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    fn named_secret(fields: &serde_json::Map<String, Value>) -> bool {
        ["name", "key", "header"].iter().any(|k| {
            fields
                .get(*k)
                .and_then(Value::as_str)
                .is_some_and(is_secret_key)
        })
    }
    fn walk(value: &mut Value) {
        match value {
            Value::Object(fields) => {
                let pair = named_secret(fields);
                for (key, field) in fields.iter_mut() {
                    if is_secret_field(key, field) || (pair && key == "value" && !field.is_null()) {
                        *field = Value::String(MASK.to_owned());
                    } else {
                        walk(field);
                    }
                }
            }
            Value::Array(items) => items.iter_mut().for_each(walk),
            Value::String(text) => {
                if let std::borrow::Cow::Owned(clean) = masked_text(text) {
                    *text = clean;
                }
            }
            _ => {}
        }
    }
    walk(&mut value);
    value
}

#[derive(sqlx::FromRow)]
struct InstanceListRow {
    id: Uuid,
    definition_version_id: Uuid,
    status: String,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    correlation_entity_id: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct InstanceDetailRow {
    id: Uuid,
    definition_id: Uuid,
    definition_version_id: Uuid,
    status: String,
    started_at: chrono::DateTime<chrono::Utc>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
    node_data: serde_json::Value,
    row_version: i64,
}

#[derive(sqlx::FromRow)]
struct NodeRunSummaryRow {
    node_id: String,
    round: i32,
    status: String,
    attempt_count: i32,
    last_error: Option<String>,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    input: Option<serde_json::Value>,
    output: Option<serde_json::Value>,
    payload_ref: Option<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct InstanceListQuery {
    /// Only this status.
    status: Option<String>,
    /// Only instances about this record.
    correlation_entity_id: Option<Uuid>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List workflow runs
///
/// Runs newest first, optionally only one status or only the runs about one record, one-based pages.
/// Automation administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/workflow/instances",
    tag = "workflow",
    params(InstanceListQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<InstanceListItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_instances(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    Query(q): Query<InstanceListQuery>,
) -> Result<Json<PaginatedResponse<InstanceListItem>>, AppError> {
    let window = PageWindow::resolve(q.page, q.page_size, PageBase::One, DEFAULT_PAGE_SIZE);

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_instance \
         WHERE ($1::text IS NULL OR status = $1) \
           AND ($2::uuid IS NULL OR correlation_entity_id = $2)",
    )
    .bind(&q.status)
    .bind(q.correlation_entity_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let rows: Vec<InstanceListRow> = sqlx::query_as(
        "SELECT id, definition_version_id, status, started_at, completed_at, correlation_entity_id \
         FROM workflow_instance \
         WHERE ($1::text IS NULL OR status = $1) \
           AND ($2::uuid IS NULL OR correlation_entity_id = $2) \
         ORDER BY started_at DESC LIMIT $3 OFFSET $4",
    )
    .bind(&q.status)
    .bind(q.correlation_entity_id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items = rows
        .into_iter()
        .map(|r| InstanceListItem {
            id: r.id,
            definition_version_id: r.definition_version_id,
            status: r.status,
            started_at: r.started_at,
            completed_at: r.completed_at,
            correlation_entity_id: r.correlation_entity_id,
        })
        .collect();
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Get a workflow run
///
/// One run: its version, status, context, node data and each step's runs (round, status, attempts,
/// last error). Automation administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/workflow/instances/{id}",
    tag = "workflow",
    params(("id" = Uuid, Path, description = "The run")),
    responses(
        (status = 200, description = "Success", body = InstanceDetail),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_instance(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Automation>>,
    Path(instance_id): Path<Uuid>,
) -> Result<Json<InstanceDetail>, AppError> {
    let row: InstanceDetailRow = sqlx::query_as(
        "SELECT i.id, v.definition_id, i.definition_version_id, i.status, i.started_at, \
                i.completed_at, i.started_by, i.correlation_entity_id, i.context, i.node_data, \
                i.row_version \
         FROM workflow_instance i \
         JOIN workflow_definition_version v ON v.id = i.definition_version_id \
         WHERE i.id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    let node_run_rows: Vec<NodeRunSummaryRow> = sqlx::query_as(
        "SELECT node_id, round, status, attempt_count, last_error, started_at, completed_at, \
                input, output, payload_ref \
         FROM workflow_node_run WHERE instance_id = $1 ORDER BY started_at NULLS LAST, round",
    )
    .bind(instance_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let node_runs = node_run_rows
        .into_iter()
        .map(|r| NodeRunSummary {
            node_id: r.node_id,
            round: r.round,
            status: r.status,
            attempt_count: r.attempt_count,
            last_error: r.last_error.map(|e| masked_text(&e).into_owned()),
            started_at: r.started_at,
            completed_at: r.completed_at,
            input: r.input.map(masked),
            output: r.output.map(masked),
            payload_ref: r.payload_ref,
        })
        .collect();

    Ok(Json(InstanceDetail {
        id: row.id,
        definition_id: row.definition_id,
        definition_version_id: row.definition_version_id,
        status: row.status,
        started_at: row.started_at,
        completed_at: row.completed_at,
        started_by: row.started_by,
        correlation_entity_id: row.correlation_entity_id,
        context: masked(row.context),
        node_data: masked(row.node_data),
        row_version: row.row_version,
        node_runs,
    }))
}

/// Cancel a workflow run
///
/// Cancels a queued, running, waiting or paused run when `row_version` is the stored one; a finished
/// or changed run is 409. Automation administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances/{id}/cancel",
    tag = "workflow",
    params(("id" = Uuid, Path, description = "The run")),
    request_body = CancelInstanceBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Cancelled)])))),
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn cancel_instance(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Path(instance_id): Path<Uuid>,
    Json(body): Json<CancelInstanceBody>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let rows = sqlx::query(
        "UPDATE workflow_instance SET status = 'cancelled', completed_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND row_version = $2 AND status IN ('queued', 'running', 'waiting', 'paused')",
    )
    .bind(instance_id)
    .bind(body.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if rows == 0 {
        return Err(AppError::VersionConflict);
    }
    sqlx::query("DELETE FROM workflow_trigger_index WHERE role = 'wait' AND instance_id = $1")
        .bind(instance_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;

    // Already fixed independently on main before this branch rebased onto
    // it (same gap, same shape) -- kept as-is, not re-implemented.
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "workflow_instance",
            instance_id,
            attome_audit::AuditOperation::Cancelled,
            "workflow_instance.cancel",
            ctx.user_id,
        ),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(
        serde_json::json!({ "id": instance_id, "status": "cancelled" }),
    ))
}

/// The test name, when the body names none.
#[derive(Debug, Default, Deserialize, utoipa::ToSchema)]
pub(crate) struct TestFromRunBody {
    /// The test's name; one from the run when left out.
    #[serde(default)]
    name: Option<String>,
}

/// A customer test from a failed workflow run
///
/// M4-T2: drafts and saves a test from a failed run that started on a record: it re-creates the
/// record as it stands now (as `POST /api/v1/admin/customer-tests/from-record` does) and expects
/// the run's workflow, simulated on it, to complete. It fails until the flow is fixed; edit it from
/// there. Deployment administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances/{id}/test",
    operation_id = "create_customer_test_from_workflow_run",
    tag = "workflow",
    params(("id" = Uuid, Path, description = "The failed run")),
    request_body = TestFromRunBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "The test", body = attome_records::customer_tests::CustomerTest),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such run, or its record is gone", body = ErrorResponse),
        (status = 409, description = "A test with that name exists", body = ErrorResponse),
        (status = 422, description = "The run did not fail, or did not start on a record", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn test_from_run(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Deployment>>,
    Path(instance_id): Path<Uuid>,
    body: Option<Json<TestFromRunBody>>,
) -> Result<
    (
        StatusCode,
        Json<attome_records::customer_tests::CustomerTest>,
    ),
    AppError,
> {
    use attome_records::customer_tests as store;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let (status, context, flow): (String, serde_json::Value, String) = sqlx::query_as(
        "SELECT i.status, i.context, d.logicalname FROM workflow_instance i \
           JOIN workflow_definition_version v ON v.id = i.definition_version_id \
           JOIN workflow_definition d ON d.id = v.definition_id \
          WHERE i.id = $1",
    )
    .bind(instance_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if status != "failed" {
        return Err(AppError::Validation(format!(
            "the run {status}; a test is made from a failed run"
        )));
    }
    let (entity, record_id) = run_record(&context)
        .ok_or_else(|| AppError::Validation("the run did not start on a record".into()))?;
    let (_, mut definition) = store::draft_from_record(&state, &ctx, &entity, record_id).await?;
    if let Some(expect) = definition
        .get_mut("expect")
        .and_then(serde_json::Value::as_array_mut)
    {
        expect.push(serde_json::json!({
            "flow": flow, "entity": entity, "ref": "record", "status": "completed"
        }));
    }
    let test = store::CustomerTestBody {
        name: body
            .name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("{flow} on {entity} {record_id}")),
        description: Some(format!("From the failed run {instance_id}")),
        definition,
        blocking: false,
        live_safe: false,
    };
    store::validate(&test.name, &test.definition)?;
    let mut tx = attome_audit::security::SecurityTx::begin(
        &state,
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "customer_test",
            None,
        )
        .named("customer_test.created"),
    )
    .await?;
    let created = store::insert_test(&mut tx, &test, ctx.user_id).await?;
    tx.event_mut().set_record_id(created.id);
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(created)))
}

/// The entity and record a run started on, from its context. Pure.
fn run_record(context: &serde_json::Value) -> Option<(String, Uuid)> {
    let entity = context
        .get("entity_logicalname")
        .or_else(|| context.get("entity"))
        .and_then(serde_json::Value::as_str)
        .filter(|e| !e.is_empty())?;
    let record = context
        .get("record_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|v| Uuid::parse_str(v).ok())?;
    Some((entity.to_owned(), record))
}

/// Start a workflow run
///
/// Starts the published, active version of the workflow named, with the context given and
/// optionally the record it is about. Automation administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/workflow/instances",
    tag = "workflow",
    request_body = StartInstanceBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = serde_json::Value),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn start_manual(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Automation>>,
    Json(body): Json<StartInstanceBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let instance_id = start_published_instance(
        &state,
        &body.definition_logicalname,
        Some(ctx.user_id),
        body.correlation_entity_id,
        body.context,
    )
    .await?;

    attome_audit::write_business_event(
        &state,
        "workflow_instance",
        instance_id,
        attome_audit::AuditOperation::Create,
        "workflow_instance.start",
        ctx.user_id,
        None,
        None,
        format!(
            "workflow instance started for {:?}",
            body.definition_logicalname
        ),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": instance_id })),
    ))
}

/// Starts the **published, active, not-deleted** version of the workflow
/// named `definition_logicalname` — the whole of a manual start once the
/// caller is authorized. Shared by the `POST /api/v1/workflow/instances`
/// handler above and by [`PublishedWorkflowStarter`], the seam `attome-ai`'s
/// `workflow.start` reaches it through (C5), so the two cannot drift.
/// Authorizes nothing: the handler's `Authorized<Admin>` and the licence gate
/// are the caller's to apply.
pub async fn start_published_instance(
    state: &EngineState,
    definition_logicalname: &str,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
) -> Result<Uuid, AppError> {
    let version_id: Uuid = sqlx::query_scalar(
        "SELECT v.id FROM workflow_definition_version v \
         JOIN workflow_definition d ON d.id = v.definition_id \
         WHERE d.logicalname = $1 AND v.status = 'published' AND d.is_active = TRUE AND d.is_deleted = FALSE",
    )
    .bind(definition_logicalname)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "workflow {definition_logicalname:?} has no published, active version"
        ))
    })?;

    start_instance_internal(
        state,
        version_id,
        None,
        started_by,
        correlation_entity_id,
        context,
    )
    .await
}

/// `attome-workflow`'s implementation of the `attome_core::WorkflowStarter`
/// seam, registered once by the composition root
/// (`EngineSystemBuilder::register_workflow_starter`). It is
/// [`start_published_instance`] and nothing else.
#[derive(Debug)]
pub struct PublishedWorkflowStarter;

impl attome_core::WorkflowStarter for PublishedWorkflowStarter {
    fn start<'a>(
        &'a self,
        state: &'a EngineState,
        request: attome_core::WorkflowStartRequest,
    ) -> attome_core::WorkflowStartFuture<'a> {
        Box::pin(async move {
            start_published_instance(
                state,
                &request.definition_logicalname,
                Some(request.started_by),
                request.correlation_entity_id,
                request.context,
            )
            .await
        })
    }

    fn start_batch_in_tx<'a, 'c: 'a>(
        &'a self,
        state: &'a EngineState,
        tx: &'a mut attome_db::Tx<'c>,
        request: attome_core::workflow_start::WorkflowBatchStartRequest,
    ) -> attome_core::workflow_start::WorkflowBatchStartFuture<'a> {
        Box::pin(async move {
            start_instances_in_tx(
                state,
                tx,
                &request.definition_logicalname,
                request.started_by,
                request.items,
            )
            .await
        })
    }
}

/// E8-T4: starts [`attome_core::workflow_start::MAX_BATCH_START`]-sized
/// chunks of `items` of the published `definition_logicalname`, each chunk
/// in its own transaction. Returns each started instance's correlated
/// record and id.
pub async fn start_instances_batch(
    state: &EngineState,
    definition_logicalname: &str,
    started_by: Option<Uuid>,
    items: Vec<(Uuid, serde_json::Value)>,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    let mut started = Vec::with_capacity(items.len());
    let mut rest = items;
    while !rest.is_empty() {
        let tail = rest.split_off(rest.len().min(attome_core::workflow_start::MAX_BATCH_START));
        let chunk = std::mem::replace(&mut rest, tail);
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        started.extend(
            start_instances_in_tx(state, &mut tx, definition_logicalname, started_by, chunk)
                .await?,
        );
        tx.commit().await.map_err(AppError::internal)?;
    }
    Ok(started)
}

/// E8-T4: one chunk of a batched start inside `tx`: the published version
/// resolved once, every instance in one insert and every entry node run in
/// another, a run job per running instance (a flow's `max_concurrent_runs`
/// leaves the rest `queued`, as a single start does), and one audit event
/// for the chunk. No external I/O.
pub async fn start_instances_in_tx(
    state: &EngineState,
    tx: &mut attome_db::Tx<'_>,
    definition_logicalname: &str,
    started_by: Option<Uuid>,
    items: Vec<(Uuid, serde_json::Value)>,
) -> Result<Vec<(Uuid, Uuid)>, AppError> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    if items.len() > attome_core::workflow_start::MAX_BATCH_START {
        return Err(AppError::Validation(format!(
            "a batched start takes at most {} instances",
            attome_core::workflow_start::MAX_BATCH_START
        )));
    }
    let (version_id, graph_json): (Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT v.id, v.graph FROM workflow_definition_version v \
         JOIN workflow_definition d ON d.id = v.definition_id \
         WHERE d.logicalname = $1 AND v.status = 'published' AND d.is_active = TRUE AND d.is_deleted = FALSE",
    )
    .bind(definition_logicalname)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "workflow {definition_logicalname:?} has no published, active version"
        ))
    })?;
    let graph = Graph::parse(&graph_json).map_err(AppError::internal)?;
    let entry_node_id = crate::node_types::entry_trigger(&graph, None)
        .ok_or_else(|| AppError::internal("published graph has no Trigger node"))?;

    // As a single start: the definition row lock serializes a capped flow's
    // starts; the first free slots run, the rest wait `queued`.
    let slots: i64 = match max_concurrent_runs(&graph_json) {
        Some(cap) => {
            sqlx::query(
                "SELECT d.id FROM workflow_definition d \
                   JOIN workflow_definition_version v ON v.definition_id = d.id \
                  WHERE v.id = $1 FOR UPDATE OF d",
            )
            .bind(version_id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            (cap - active_runs(tx, version_id).await?).max(0)
        }
        None => i64::MAX,
    };

    let correlations: Vec<Uuid> = items.iter().map(|(c, _)| *c).collect();
    let contexts: Vec<String> = items.iter().map(|(_, ctx)| ctx.to_string()).collect();
    let started: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "INSERT INTO workflow_instance \
            (definition_version_id, trigger_node_id, correlation_entity_id, status, started_by, \
             context, node_data, chain_depth) \
         SELECT $1, $2, i.correlation, CASE WHEN i.ord <= $6 THEN 'running' ELSE 'queued' END, $3, \
                i.context::jsonb, jsonb_build_object($2::text, i.context::jsonb), 0 \
           FROM UNNEST($4::uuid[], $5::text[]) WITH ORDINALITY AS i(correlation, context, ord) \
         RETURNING correlation_entity_id, id, status",
    )
    .bind(version_id)
    .bind(&entry_node_id)
    .bind(started_by)
    .bind(&correlations)
    .bind(&contexts)
    .bind(slots)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let ids: Vec<Uuid> = started.iter().map(|(_, id, _)| *id).collect();
    sqlx::query(
        "INSERT INTO workflow_node_run (id, instance_id, node_id, status, attempt_count, started_at, completed_at) \
         SELECT uuidv7(), i, $2, 'succeeded', 1, NOW(), NOW() FROM UNNEST($1::uuid[]) AS i",
    )
    .bind(&ids)
    .bind(&entry_node_id)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    for (_, instance_id, status) in &started {
        if status == "running" {
            attome_jobs::enqueue_in_tx(
                tx,
                attome_core::jobs::EngineJob::WorkflowExecute {
                    instance_id: *instance_id,
                },
            )
            .await
            .map_err(AppError::internal)?;
        }
    }

    // One event for the chunk, on the version it started (a per-instance
    // event a thousand times over would be the batch's whole cost).
    let audit = attome_audit::audit_service(state);
    let event = attome_audit::BusinessEvent::new(
        "workflow_definition_version",
        version_id,
        attome_audit::AuditOperation::Create,
        "workflow.instances.started",
        started_by.unwrap_or(Uuid::nil()),
    )
    .comment(format!("{} instances started in one batch", started.len()))
    .attributed(attome_audit::Attribution {
        acting_user_id: started_by.unwrap_or(Uuid::nil()),
        initiator: if started_by.is_some() {
            attome_audit::Initiator::User
        } else {
            attome_audit::Initiator::System
        },
        agent_session_id: None,
        agent_action_id: None,
    });
    attome_audit::write_business_event_in_tx(tx, &audit, event)
        .await
        .map_err(AppError::internal)?;

    Ok(started.into_iter().map(|(c, id, _)| (c, id)).collect())
}

/// Shared entry-start primitive — used by the manual-start HTTP handler
/// above and by `scheduler::execute_sub_workflow` for a `sub_workflow` node.
/// Picks the version's first `Trigger` node as the entry point (the graph
/// validator guarantees at least one exists); a specific `trigger_node_id`
/// can be supplied to disambiguate a multi-trigger graph.
pub async fn start_instance_internal(
    state: &EngineState,
    definition_version_id: Uuid,
    trigger_node_id: Option<&str>,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
) -> Result<Uuid, AppError> {
    start_instance_inner(
        state,
        definition_version_id,
        trigger_node_id,
        started_by,
        correlation_entity_id,
        context,
        None,
    )
    .await?
    .ok_or_else(|| AppError::internal("instance start without an event id cannot conflict"))
}

/// M06 W1 (plan §4.1, G1) — [`start_instance_internal`] for an entity-trigger
/// start. `trigger_event_id` is the `entity_change_event` row the
/// start came from; migration 0501's partial unique index on
/// `(definition_version_id, trigger_node_id, trigger_event_id)` plus
/// `ON CONFLICT DO NOTHING` make a re-read event a no-op. Returns `None` when
/// this event already started this trigger's instance — the at-least-once
/// dispatch loop re-reads an event after a crash between start and cursor
/// advance, and must not start it twice.
pub async fn start_instance_for_event(
    state: &EngineState,
    definition_version_id: Uuid,
    trigger_node_id: &str,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
    trigger_event_id: Uuid,
) -> Result<Option<Uuid>, AppError> {
    start_instance_inner(
        state,
        definition_version_id,
        Some(trigger_node_id),
        started_by,
        correlation_entity_id,
        context,
        Some(trigger_event_id),
    )
    .await
}

/// M1-T5: how deep a chain of flow-triggered flows may go. An event a
/// user's write produced has depth 0; a flow started by it writes events of
/// depth 1, and so on; an event at this depth starts nothing.
pub const MAX_CHAIN_DEPTH: i16 = 8;

/// The graph's `settings.max_concurrent_runs`, when set to a positive number.
pub fn max_concurrent_runs(graph: &serde_json::Value) -> Option<i64> {
    graph
        .pointer("/settings/max_concurrent_runs")
        .and_then(serde_json::Value::as_i64)
        .filter(|n| *n > 0)
}

/// Running or waiting instances of the flow `definition_version_id` belongs
/// to, over all its versions.
async fn active_runs(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    definition_version_id: Uuid,
) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_instance i \
           JOIN workflow_definition_version v ON v.id = i.definition_version_id \
          WHERE v.definition_id = (SELECT definition_id FROM workflow_definition_version WHERE id = $1) \
            AND i.status IN ('running', 'waiting')",
    )
    .bind(definition_version_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// M1-T5: starts queued instances of every capped flow that has a free slot,
/// oldest first. Run by the minute sweep (`EngineJob::WorkflowSlaSweep`).
/// The cap is the flow's published version's; a flow no longer capped
/// starts all its queued runs. Returns how many started.
pub async fn promote_queued(state: &EngineState) -> Result<u64, AppError> {
    let flows: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT v.definition_id FROM workflow_instance i \
           JOIN workflow_definition_version v ON v.id = i.definition_version_id \
          WHERE i.status = 'queued'",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let mut started = 0u64;
    for definition_id in flows {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let published: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT v.graph FROM workflow_definition d \
               LEFT JOIN workflow_definition_version v \
                 ON v.definition_id = d.id AND v.status = 'published' \
              WHERE d.id = $1 FOR UPDATE OF d",
        )
        .bind(definition_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .flatten();
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_instance i \
               JOIN workflow_definition_version v ON v.id = i.definition_version_id \
              WHERE v.definition_id = $1 AND i.status IN ('running', 'waiting')",
        )
        .bind(definition_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let free = match published.as_ref().and_then(max_concurrent_runs) {
            Some(cap) => (cap - active).max(0),
            None => i64::from(i32::MAX),
        };
        if free == 0 {
            continue;
        }
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE workflow_instance SET status = 'running', row_version = row_version + 1 \
              WHERE id IN (SELECT i.id FROM workflow_instance i \
                             JOIN workflow_definition_version v ON v.id = i.definition_version_id \
                            WHERE v.definition_id = $1 AND i.status = 'queued' \
                            ORDER BY i.started_at, i.id LIMIT $2 FOR UPDATE OF i SKIP LOCKED) \
              RETURNING id",
        )
        .bind(definition_id)
        .bind(free)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        for instance_id in &ids {
            attome_jobs::enqueue_in_tx(
                &mut tx,
                attome_core::jobs::EngineJob::WorkflowExecute {
                    instance_id: *instance_id,
                },
            )
            .await
            .map_err(AppError::internal)?;
        }
        tx.commit().await.map_err(AppError::internal)?;
        started += ids.len() as u64;
    }
    Ok(started)
}

async fn start_instance_inner(
    state: &EngineState,
    definition_version_id: Uuid,
    trigger_node_id: Option<&str>,
    started_by: Option<Uuid>,
    correlation_entity_id: Option<Uuid>,
    context: serde_json::Value,
    trigger_event_id: Option<Uuid>,
) -> Result<Option<Uuid>, AppError> {
    let graph_json: serde_json::Value =
        sqlx::query_scalar("SELECT graph FROM workflow_definition_version WHERE id = $1")
            .bind(definition_version_id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let graph = Graph::parse(&graph_json).map_err(AppError::internal)?;

    let entry_node_id = match trigger_node_id {
        Some(id) => id.to_string(),
        // B16-T13: a start that names its trigger kind (`context.trigger`,
        // e.g. `scan`) enters at a trigger of that kind when the flow has one.
        None => crate::node_types::entry_trigger(
            &graph,
            context.get("trigger").and_then(serde_json::Value::as_str),
        )
        .ok_or_else(|| AppError::internal("published graph has no Trigger node"))?,
    };

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // M1-T5: a start from an event a flow's own write produced carries that
    // event's chain depth; past `MAX_CHAIN_DEPTH` the chain stops here, so a
    // flow that triggers itself (or two that trigger each other) cannot loop.
    let chain_depth: i16 = match trigger_event_id {
        Some(event_id) => {
            sqlx::query_scalar("SELECT chain_depth FROM entity_change_event WHERE id = $1")
                .bind(event_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(AppError::internal)?
                .unwrap_or(0)
        }
        None => 0,
    };
    if chain_depth >= MAX_CHAIN_DEPTH {
        metrics::counter!("workflow_chain_depth_stops_total").increment(1);
        tracing::error!(
            %definition_version_id,
            trigger_node_id = %entry_node_id,
            chain_depth,
            "workflow start refused: the trigger chain reached its depth limit; \
             a flow's writes keep triggering flows"
        );
        return Ok(None);
    }

    // M1-T5: a flow may cap its parallel runs (`settings.max_concurrent_runs`
    // in the graph); a start past the cap is stored `queued` and the minute
    // sweep (`promote_queued`) starts it when a run finishes. The definition
    // row lock serializes this flow's capped starts so two cannot both see a
    // free slot; an uncapped flow takes no lock.
    let queued = match max_concurrent_runs(&graph_json) {
        Some(cap) => {
            sqlx::query(
                "SELECT d.id FROM workflow_definition d \
                   JOIN workflow_definition_version v ON v.definition_id = d.id \
                  WHERE v.id = $1 FOR UPDATE OF d",
            )
            .bind(definition_version_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            active_runs(&mut tx, definition_version_id).await? >= cap
        }
        None => false,
    };

    // The conflict target names 0501's partial unique index; a NULL
    // `trigger_event_id` (every non-entity start) never matches its predicate,
    // so those inserts behave exactly as before.
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO workflow_instance \
            (definition_version_id, trigger_node_id, correlation_entity_id, status, started_by, \
             context, node_data, trigger_event_id, chain_depth) \
         VALUES ($1, $2, $3, $8, $4, $5, $6, $7, $9) \
         ON CONFLICT (definition_version_id, trigger_node_id, trigger_event_id) \
             WHERE trigger_event_id IS NOT NULL DO NOTHING \
         RETURNING id",
    )
    .bind(definition_version_id)
    .bind(&entry_node_id)
    .bind(correlation_entity_id)
    .bind(started_by)
    .bind(&context)
    .bind(serde_json::json!({ &entry_node_id: context.clone() }))
    .bind(trigger_event_id)
    .bind(if queued { "queued" } else { "running" })
    .bind(chain_depth)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(instance_id) = inserted else {
        // Already started by an earlier delivery of the same event. Nothing
        // was written; dropping `tx` rolls back the empty transaction.
        return Ok(None);
    };

    sqlx::query(
        "INSERT INTO workflow_node_run (id, instance_id, node_id, status, attempt_count, started_at, completed_at) \
         VALUES ($1, $2, $3, 'succeeded', 1, NOW(), NOW())",
    )
    .bind(Uuid::now_v7())
    .bind(instance_id)
    .bind(&entry_node_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if !queued {
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::WorkflowExecute { instance_id },
        )
        .await
        .map_err(AppError::internal)?;
    }

    // Plan 4.3 (C19): this shared primitive (the manual-start HTTP handler
    // above and `scheduler::execute_sub_workflow` both call it) previously
    // wrote no audit event at all for instance start, despite `x-audit`
    // annotating both routes as covered (D-542) -- the annotation was
    // correct about the category/operation, but nothing actually wrote the
    // event. Fixed here, in this function's own transaction (D-062), so
    // both callers get it atomically with the insert above rather than each
    // needing its own after-the-fact, non-atomic write. `started_by` is
    // `None` for a scheduler-originated instance with no human starter
    // (a sub-workflow whose own parent chain traces back to one, or a
    // future automatic trigger) -- `Initiator::System` there, matching
    // `trd-engine::audit::attribution`'s and this crate's own
    // `scheduler.rs` node-run event's distinction, rather than falsely
    // claiming `Initiator::User` with a nil actor id.
    let audit = attome_audit::audit_service(state);
    let attribution = attome_audit::Attribution {
        acting_user_id: started_by.unwrap_or(Uuid::nil()),
        initiator: if started_by.is_some() {
            attome_audit::Initiator::User
        } else {
            attome_audit::Initiator::System
        },
        agent_session_id: None,
        agent_action_id: None,
    };
    let event = attome_audit::BusinessEvent::new(
        "workflow_instance",
        instance_id,
        attome_audit::AuditOperation::Create,
        "workflow.instance.started",
        started_by.unwrap_or(Uuid::nil()),
    )
    .attributed(attribution);
    attome_audit::write_business_event_in_tx(&mut tx, &audit, event)
        .await
        .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;
    Ok(Some(instance_id))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/workflow/instances",
            get(list_instances).post(start_manual),
        )
        .route("/api/v1/workflow/instances/{id}", get(get_instance))
        .route(
            "/api/v1/workflow/instances/{id}/cancel",
            post(cancel_instance),
        )
        .route("/api/v1/workflow/instances/{id}/test", post(test_from_run))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_instances,
    get_instance,
    cancel_instance,
    start_manual,
    test_from_run
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod run_record_tests {
    use super::{MASK, is_secret_key, masked, masked_text, run_record};
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn a_run_masks_credentials_at_any_depth_and_keeps_the_rest() {
        let run = masked(json!({
            "url": "https://hooks.example.test",
            "total_tokens": 120,
            "token_count": 7,
            "secret": "s",
            "headers": { "Authorization": "x", "X-Api-Key": "k", "Accept": "json" },
            "steps": [{ "apiKey": "k", "client_secret": "s", "access_token": "t", "name": "keep" }],
            "password": null,
            "user_password_hash": "h",
            "session-cookie": "c",
            "keys": ["a"],
            "tokens": { "access": "x" },
        }));
        assert_eq!(
            run,
            json!({
                "url": "https://hooks.example.test",
                "total_tokens": 120,
                "token_count": 7,
                "secret": MASK,
                "headers": { "Authorization": MASK, "X-Api-Key": MASK, "Accept": "json" },
                "steps": [{ "apiKey": MASK, "client_secret": MASK, "access_token": MASK, "name": "keep" }],
                "password": null,
                "user_password_hash": MASK,
                "session-cookie": MASK,
                "keys": ["a"],
                "tokens": MASK,
            })
        );
    }

    #[test]
    fn a_header_list_masks_the_value_beside_a_secret_name() {
        let run = masked(json!([
            { "name": "Authorization", "value": "abc" },
            { "name": "Accept", "value": "json" },
            { "key": "x-api-key", "value": "k" },
        ]));
        assert_eq!(
            run,
            json!([
                { "name": "Authorization", "value": MASK },
                { "name": "Accept", "value": "json" },
                { "key": "x-api-key", "value": MASK },
            ])
        );
    }

    #[test]
    fn a_text_loses_the_credentials_it_carries() {
        for (text, kept) in [
            ("https://me:pw@host.test/a", "https://••••••@host.test/a"),
            (
                "call failed: Bearer abc.defgh",
                "call failed: Bearer ••••••",
            ),
            ("Basic dXNlcjpwYXNz", "Basic ••••••"),
            (
                "https://h.test/a?api_key=k1&x=1",
                "https://h.test/a?api_key=••••••&x=1",
            ),
            (r#"{"password":"p 1"}"#, r#"{"password":••••••}"#),
            ("client_secret: s1 refused", "client_secret: •••••• refused"),
        ] {
            assert_eq!(masked_text(text), kept, "{text}");
        }
        for text in [
            "https://host.test/a:b",
            "a basic plan",
            "ten tokens used",
            "plain",
        ] {
            assert!(
                matches!(masked_text(text), std::borrow::Cow::Borrowed(_)),
                "{text}"
            );
        }
    }

    #[test]
    fn a_secret_key_is_known_by_its_words() {
        for key in [
            "password",
            "PASSWORD",
            "password1",
            "pass",
            "api_key",
            "apiKey",
            "X-API-Key",
            "apikey",
            "private_key",
            "signing_key",
            "encryption_key",
            "access_key",
            "refreshToken",
            "id_token",
            "credentials",
            "client_secret",
            "secrets",
            "cookie",
            "cookies",
            "auth",
            "bearer",
            "jwt",
        ] {
            assert!(is_secret_key(key), "{key}");
        }
        for key in [
            "tokens",
            "token_count",
            "key",
            "public_key",
            "monkey",
            "secretary",
            "name",
            "keyword",
            "author",
            "passes",
            "spinning",
        ] {
            assert!(!is_secret_key(key), "{key}");
        }
    }

    #[test]
    fn a_run_names_its_record_by_entity_and_id() {
        let id = Uuid::now_v7();
        assert_eq!(
            run_record(&json!({ "entity_logicalname": "lead", "record_id": id.to_string() })),
            Some(("lead".to_owned(), id))
        );
        assert_eq!(run_record(&json!({ "record_id": id.to_string() })), None);
        assert_eq!(
            run_record(&json!({ "entity_logicalname": "lead", "record_id": "x" })),
            None
        );
    }
}
