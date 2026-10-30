//! `POST /api/v1/composite` (roadmap S1-T7): up to 25 record operations in
//! one request, run in order, each on its own: one that fails is reported
//! and the rest still run. A later operation can use an earlier one's result
//! through `${<ref>.<field>}` (a string that is exactly that), so a client
//! can create an account and then a contact pointing at it in one call.
//!
//! Every operation goes through the same generic create/update/delete path
//! a single request does, after the same privilege check, so validation,
//! row versions, rules and audit apply to each.
//!
//! S1-T8: with `all_or_none`, every operation runs in one short transaction
//! (at most 5 seconds per statement) through the staged writes of
//! `entity_crud::staged`, and they commit together with one audit event
//! each; the first that fails rolls them all back, and every result is
//! marked `rolled_back`.

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most operations one request carries.
pub const MAX_OPERATIONS: usize = 25;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CompositeMethod {
    Create,
    Update,
    Delete,
    Upsert,
}

/// One operation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CompositeOp {
    /// This operation's name, for later references: lowercase letters,
    /// digits and `_`, starting with a letter, at most 32 characters.
    #[serde(rename = "ref")]
    pub reference: String,
    pub method: CompositeMethod,
    pub entity: String,
    /// The record, for update and delete; may be a `${ref.id}` reference.
    pub id: Option<String>,
    /// The record's `row_version`; required for update.
    pub if_match: Option<i64>,
    pub body: Option<Value>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CompositeRequest {
    /// Every operation commits or none does (S1-T8): they run in one
    /// transaction, and the first that fails rolls them all back.
    #[serde(default)]
    pub all_or_none: bool,
    pub operations: Vec<CompositeOp>,
}

/// One operation's outcome.
#[derive(Debug, Serialize, ToSchema)]
pub struct CompositeResult {
    #[serde(rename = "ref")]
    pub reference: String,
    /// The HTTP status the operation would have had on its own.
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    /// The error body, as a single request would have answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    /// S1-T8: true when an `all_or_none` request failed, so this operation
    /// was rolled back (or, after the failing one, never ran).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rolled_back: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CompositeResponse {
    pub results: Vec<CompositeResult>,
}

fn valid_ref(reference: &str) -> bool {
    let mut chars = reference.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase())
        && reference.len() <= 32
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The request's own shape: 1 to 25 operations with unique, well-formed refs.
fn validate(request: &CompositeRequest) -> Result<(), AppError> {
    if request.operations.is_empty() || request.operations.len() > MAX_OPERATIONS {
        return Err(AppError::Validation(format!(
            "a composite request carries 1 to {MAX_OPERATIONS} operations"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for op in &request.operations {
        if !valid_ref(&op.reference) {
            return Err(AppError::Validation(format!(
                "ref {:?} must be lowercase letters, digits and _, starting with a letter",
                op.reference
            )));
        }
        if !seen.insert(op.reference.as_str()) {
            return Err(AppError::Validation(format!(
                "ref {:?} is used twice",
                op.reference
            )));
        }
    }
    Ok(())
}

/// The value `${ref.field}` names: the result's own field, else the
/// record's data field.
fn lookup(results: &HashMap<String, Value>, expr: &str) -> Result<Value, AppError> {
    let (reference, field) = expr
        .split_once('.')
        .ok_or_else(|| AppError::Validation(format!("reference ${{{expr}}} needs a field")))?;
    let result = results.get(reference).ok_or_else(|| {
        AppError::Validation(format!(
            "reference ${{{expr}}} names no earlier operation that succeeded"
        ))
    })?;
    result
        .get(field)
        .or_else(|| result.get("data").and_then(|d| d.get(field)))
        .cloned()
        .ok_or_else(|| AppError::Validation(format!("reference ${{{expr}}} names no field")))
}

/// Replaces every string that is exactly `${ref.field}` with that earlier
/// result's value.
pub fn substitute_refs(
    value: &mut Value,
    results: &HashMap<String, Value>,
) -> Result<(), AppError> {
    match value {
        Value::String(s) => {
            if let Some(expr) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
                *value = lookup(results, expr)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                substitute_refs(item, results)?;
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                substitute_refs(item, results)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn record_id(op: &CompositeOp, results: &HashMap<String, Value>) -> Result<Uuid, AppError> {
    let mut id = Value::String(
        op.id
            .clone()
            .ok_or_else(|| AppError::Validation("this operation needs an id".into()))?,
    );
    substitute_refs(&mut id, results)?;
    id.as_str()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| AppError::Validation("id is not a record id".into()))
}

/// Runs one operation; `Ok((status, body))`.
async fn run_one(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    op: &CompositeOp,
    results: &HashMap<String, Value>,
) -> Result<(u16, Value), AppError> {
    let mut body = op.body.clone().unwrap_or_else(|| json!({}));
    substitute_refs(&mut body, results)?;
    match op.method {
        CompositeMethod::Create => {
            ctx.require(&op.entity, "create")?;
            let (_, response) =
                crate::entity_crud::create_record_for(state, ctx, ctx.user_id, &op.entity, body)
                    .await?;
            Ok((
                201,
                serde_json::to_value(response).map_err(AppError::internal)?,
            ))
        }
        CompositeMethod::Update => {
            ctx.require(&op.entity, "update")?;
            let id = record_id(op, results)?;
            let version = op.if_match.ok_or_else(|| {
                AppError::Validation("update needs if_match (the record's row_version)".into())
            })?;
            let response = crate::entity_crud::update_record_for(
                state,
                ctx,
                ctx.user_id,
                &op.entity,
                id,
                version,
                body,
            )
            .await?;
            Ok((
                200,
                serde_json::to_value(response).map_err(AppError::internal)?,
            ))
        }
        CompositeMethod::Delete => {
            ctx.require(&op.entity, "delete")?;
            let id = record_id(op, results)?;
            crate::entity_crud::delete_record_for(
                state,
                ctx,
                ctx.user_id,
                &op.entity,
                id,
                op.if_match,
                &crate::entity_mutation::DeleteOrigin::new(
                    crate::entity_mutation::DeleteKind::Request,
                ),
            )
            .await?;
            Ok((204, json!({ "id": id })))
        }
        CompositeMethod::Upsert => Err(AppError::Validation(
            "upsert is not available in a composite request yet".into(),
        )),
    }
}

/// The status and error body a single request would have answered with.
fn error_parts(error: AppError) -> (u16, Value) {
    use axum::response::IntoResponse;
    let response = error.into_response();
    let status = response.status().as_u16();
    (status, json!({ "status": status }))
}

/// [`error_parts`] with the message of a client error (never of a 5xx).
fn error_body(error: AppError) -> (u16, Value) {
    let message = error.to_string();
    let (status, mut detail) = error_parts(error);
    if status < 500 {
        detail["message"] = Value::String(message);
    }
    (status, detail)
}

/// The record action and privilege an operation needs.
fn action_of(
    method: CompositeMethod,
) -> Result<(attome_security::RecordAction, &'static str), AppError> {
    use attome_security::RecordAction;
    match method {
        CompositeMethod::Create => Ok((RecordAction::Create, "create")),
        CompositeMethod::Update => Ok((RecordAction::Update, "update")),
        CompositeMethod::Delete => Ok((RecordAction::Delete, "delete")),
        CompositeMethod::Upsert => Err(AppError::Validation(
            "upsert is not available in a composite request yet".into(),
        )),
    }
}

/// Every result of an `all_or_none` request that failed at operation
/// `failed`: the ones before it with the status they would have had, the
/// failing one with its error, the ones after it never run (424); all
/// marked `rolled_back`.
fn rolled_back(
    ops: &[CompositeOp],
    done: &[u16],
    failed: usize,
    error: AppError,
) -> Vec<CompositeResult> {
    let (status, detail) = error_body(error);
    let failed_ref = &ops[failed].reference;
    ops.iter()
        .enumerate()
        .map(|(i, op)| {
            let not_run = || {
                (
                    424,
                    Some(json!({
                        "status": 424,
                        "message": format!("not run: operation {failed_ref} failed"),
                    })),
                )
            };
            // An operation before the failing one ran (and was rolled back)
            // unless the request failed before the transaction opened.
            let (status, error) = match i.cmp(&failed) {
                std::cmp::Ordering::Less => match done.get(i) {
                    Some(&ran) => (ran, None),
                    None => not_run(),
                },
                std::cmp::Ordering::Equal => (status, Some(detail.clone())),
                std::cmp::Ordering::Greater => not_run(),
            };
            CompositeResult {
                reference: op.reference.clone(),
                status,
                body: None,
                error,
                rolled_back: true,
            }
        })
        .collect()
}

/// S1-T8: runs every operation in one transaction, committing them together
/// or none of them.
async fn run_all_or_none(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    ops: &[CompositeOp],
) -> Result<Vec<CompositeResult>, AppError> {
    use crate::entity_crud::staged;

    // Privileges and the per-entity access inputs, on the pool, before the
    // transaction opens (a held transaction never waits on a second
    // connection).
    let mut prepared = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        let step = async {
            let (action, privilege) = action_of(op.method)?;
            ctx.require(&op.entity, privilege)?;
            staged::prepare(state, ctx, &op.entity, action).await
        };
        match step.await {
            Ok(p) => prepared.push(p),
            Err(error) => return Ok(rolled_back(ops, &[], i, error)),
        }
    }
    let actor = crate::mutation_ring::MutationActor::fetch(state, ctx.user_id).await;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query("SET LOCAL statement_timeout = 5000")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let mut results: HashMap<String, Value> = HashMap::new();
    let mut in_request: HashSet<Uuid> = HashSet::new();
    let mut statuses: Vec<u16> = Vec::with_capacity(ops.len());
    let mut writes = Vec::with_capacity(ops.len());
    for (i, (op, prepared)) in ops.iter().zip(&prepared).enumerate() {
        let step = async {
            let mut body = op.body.clone().unwrap_or_else(|| json!({}));
            substitute_refs(&mut body, &results)?;
            match op.method {
                CompositeMethod::Create => Ok::<_, AppError>((
                    201,
                    staged::stage_create(&mut tx, state, ctx, &actor, prepared, body, &in_request)
                        .await?,
                )),
                CompositeMethod::Update => {
                    let id = record_id(op, &results)?;
                    let version = op.if_match.ok_or_else(|| {
                        AppError::Validation(
                            "update needs if_match (the record's row_version)".into(),
                        )
                    })?;
                    Ok((
                        200,
                        staged::stage_update(
                            &mut tx,
                            state,
                            ctx,
                            &actor,
                            prepared,
                            id,
                            version,
                            body,
                            &in_request,
                        )
                        .await?,
                    ))
                }
                CompositeMethod::Delete => {
                    let id = record_id(op, &results)?;
                    Ok((
                        204,
                        staged::stage_delete(
                            &mut tx,
                            state,
                            ctx,
                            &actor,
                            prepared,
                            id,
                            op.if_match,
                            &in_request,
                        )
                        .await?,
                    ))
                }
                CompositeMethod::Upsert => Err(AppError::Validation(
                    "upsert is not available in a composite request yet".into(),
                )),
            }
        };
        match step.await {
            Ok((status, write)) => {
                // A later operation reads this one's id and fields.
                results.insert(
                    op.reference.clone(),
                    json!({ "id": write.record_id, "data": write.row.clone().unwrap_or(Value::Null) }),
                );
                if op.method == CompositeMethod::Create {
                    in_request.insert(write.record_id);
                }
                statuses.push(status);
                writes.push(write);
            }
            Err(error) => {
                // Dropping the transaction rolls every staged write back.
                drop(tx);
                return Ok(rolled_back(ops, &statuses, i, error));
            }
        }
    }

    let mut answers = Vec::with_capacity(writes.len());
    let mut staged_writes = Vec::with_capacity(writes.len());
    for w in writes {
        answers.push((w.record_id, w.row, w.sent));
        staged_writes.push(w.staged);
    }
    crate::mutation_ring::MutationRing::new(state)
        .commit_many(tx, ctx, staged_writes, "composite all_or_none")
        .await?;

    let mut out = Vec::with_capacity(ops.len());
    for (((op, prepared), status), (id, row, sent)) in
        ops.iter().zip(&prepared).zip(statuses).zip(answers)
    {
        let body = match row {
            Some(row) => {
                staged::committed_response(state, ctx, prepared, id, row, sent.as_ref()).await?
            }
            None => json!({ "id": id }),
        };
        out.push(CompositeResult {
            reference: op.reference.clone(),
            status,
            body: Some(body),
            error: None,
            rolled_back: false,
        });
    }
    Ok(out)
}

/// Run several record operations
///
/// Up to 25 creates, updates and deletes in order, each on its own; a later one may use an earlier one's result through ${ref.field}. With all_or_none, they run in one transaction and the first failure rolls them all back. One result per operation.
#[utoipa::path(
    post,
    path = "/api/v1/composite",
    tag = "entity",
    operation_id = "composite",
    request_body = CompositeRequest,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("each operation's create/update/delete path"), "every operation is written through the generic entity path, which writes its own Entity audit event")))),
    responses(
        (status = 200, description = "One result per operation, in order", body = CompositeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "The request's own shape is wrong (count or refs)", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn composite(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(request): Json<CompositeRequest>,
) -> Result<Json<CompositeResponse>, AppError> {
    validate(&request)?;
    if request.all_or_none {
        let results = run_all_or_none(&state, &ctx, &request.operations).await?;
        return Ok(Json(CompositeResponse { results }));
    }
    let mut results: HashMap<String, Value> = HashMap::new();
    let mut out = Vec::with_capacity(request.operations.len());
    for op in &request.operations {
        match run_one(&state, &ctx, op, &results).await {
            Ok((status, body)) => {
                results.insert(op.reference.clone(), body.clone());
                out.push(CompositeResult {
                    reference: op.reference.clone(),
                    status,
                    body: Some(body),
                    error: None,
                    rolled_back: false,
                });
            }
            Err(error) => {
                let (status, detail) = error_body(error);
                out.push(CompositeResult {
                    reference: op.reference.clone(),
                    status,
                    body: None,
                    error: Some(detail),
                    rolled_back: false,
                });
            }
        }
    }
    Ok(Json(CompositeResponse { results: out }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/composite", post(composite))
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(composite),
    components(schemas(
        CompositeRequest,
        CompositeOp,
        CompositeMethod,
        CompositeResponse,
        CompositeResult
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(reference: &str) -> CompositeOp {
        CompositeOp {
            reference: reference.into(),
            method: CompositeMethod::Create,
            entity: "account".into(),
            id: None,
            if_match: None,
            body: None,
        }
    }

    #[test]
    fn substitute_refs_replaces_earlier_result() {
        let mut results = HashMap::new();
        results.insert(
            "acc".to_owned(),
            json!({"id": "0190-acc", "data": {"name": "Acme", "id": "0190-acc"}}),
        );
        let mut body = json!({
            "parentcustomerid": "${acc.id}",
            "note": "for ${acc.name}",
            "nested": ["${acc.name}"]
        });
        substitute_refs(&mut body, &results).expect("substitute");
        assert_eq!(body["parentcustomerid"], "0190-acc");
        assert_eq!(
            body["note"], "for ${acc.name}",
            "only a whole-string reference is replaced"
        );
        assert_eq!(body["nested"][0], "Acme", "data fields are reachable too");
    }

    #[test]
    fn substitute_refs_rejects_forward_reference() {
        let results = HashMap::new();
        let mut body = json!({"parentcustomerid": "${later.id}"});
        assert!(substitute_refs(&mut body, &results).is_err());
    }

    #[test]
    fn rolled_back_marks_every_result() {
        let ops = vec![op("a"), op("b"), op("c")];
        let results = rolled_back(&ops, &[201], 1, AppError::Conflict("version_conflict"));
        let before_tx = rolled_back(&ops, &[], 1, AppError::Forbidden);
        assert_eq!(
            before_tx[0].status, 424,
            "nothing ran before the transaction"
        );
        assert!(results.iter().all(|r| r.rolled_back));
        assert_eq!(results[0].status, 201);
        assert!(results[0].error.is_none());
        assert_eq!(results[1].status, 409);
        assert_eq!(results[2].status, 424);
        assert!(
            results[2].error.as_ref().unwrap()["message"]
                .as_str()
                .unwrap()
                .contains("operation b failed")
        );
    }

    #[test]
    fn rejects_more_than_25_operations() {
        let ops: Vec<CompositeOp> = (0..26).map(|i| op(&format!("op{i}"))).collect();
        let request = CompositeRequest {
            all_or_none: false,
            operations: ops,
        };
        assert!(validate(&request).is_err());
        let dup = CompositeRequest {
            all_or_none: false,
            operations: vec![op("a"), op("a")],
        };
        assert!(validate(&dup).is_err());
        let bad = CompositeRequest {
            all_or_none: false,
            operations: vec![op("Bad-Ref")],
        };
        assert!(validate(&bad).is_err());
        let ok = CompositeRequest {
            all_or_none: false,
            operations: vec![op("acc"), op("contact_1")],
        };
        assert!(validate(&ok).is_ok());
    }
}
