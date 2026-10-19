//! `POST /api/v1/offline/push` (roadmap B18-T7): a device's queued changes,
//! applied in order through the entity engine.
//!
//! **Same path as a person's edit.** Each operation checks the caller's
//! privilege on the entity (as the HTTP extractor does) and then calls the
//! engine's create, update or delete — record access, validation, rules,
//! duplicate rules, autonumbers, audit and the change feed all run as for an
//! edit made online. Nothing here writes a record itself.
//!
//! **Idempotent.** Every operation carries the device's own id for it. Its
//! result is kept in `offline_op`; a retried operation returns the kept
//! result and is not applied again. The engine commits its own transaction,
//! so the result is recorded just after; a crash between the two is
//! covered by the operation itself being retry-safe: a create whose id
//! already exists, an update whose fields already hold the new values, and a
//! delete of a record already gone each count as applied.
//!
//! **Per-attribute merge.** An update names the row version it was made
//! against and the values it started from. At that version it applies as is.
//! Otherwise, when every field it changes still holds the value it started
//! from, it applies at the current version (`merged`); when one does not, it
//! is a `conflict`, answered with the server's values for those fields.
//!
//! **Order.** A rejected or conflicting operation blocks the device's later
//! operations on the same record (`depends_on_failed`). One push per device
//! runs at a time.

use std::collections::HashSet;

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_records::entity_crud::{
    create_record_with_id_for, delete_record_for, read_record, update_record_for,
};
use attome_records::entity_mutation::{DeleteKind, DeleteOrigin};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// Most operations one push carries.
pub const MAX_OPS: usize = 100;

/// One queued change.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PushOp {
    /// The device's own id for this operation; a retry repeats it.
    pub client_op_id: Uuid,
    /// `create`, `update` or `delete`.
    pub kind: String,
    pub entity: String,
    /// The record. For a create, the UUIDv7 the device gave it.
    pub id: Uuid,
    /// The row version the change was made against (update, delete).
    #[serde(default)]
    pub base_row_version: Option<i64>,
    /// The fields changed and their new values (create, update).
    #[serde(default)]
    #[schema(value_type = Object)]
    pub changed: Map<String, Value>,
    /// The changed fields' values before the change (update).
    #[serde(default)]
    #[schema(value_type = Object)]
    pub base_values: Map<String, Value>,
}

/// `POST /api/v1/offline/push`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct PushBody {
    pub device_id: Uuid,
    pub ops: Vec<PushOp>,
    /// Changes still waiting on the device after this push.
    #[serde(default)]
    pub queue_size: Option<i32>,
    /// Bytes the device's offline store uses.
    #[serde(default)]
    pub bytes_used: Option<i64>,
}

/// What happened to one operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct OpResult {
    pub client_op_id: Uuid,
    /// `applied`, `merged`, `conflict` or `rejected`.
    pub status: String,
    pub id: Uuid,
    /// The record's row version after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_version: Option<i64>,
    /// A conflict's server values for the fields that clashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub server_values: Option<Value>,
    /// Why it was rejected: `forbidden`, `not_found`, `invalid`,
    /// `depends_on_failed`, …
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Where to open the record and see the problem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PushResult {
    pub results: Vec<OpResult>,
}

impl OpResult {
    fn new(op: &PushOp, status: &str) -> Self {
        Self {
            client_op_id: op.client_op_id,
            status: status.to_owned(),
            id: op.id,
            row_version: None,
            server_values: None,
            code: None,
            message: None,
            link: None,
        }
    }

    fn rejected(op: &PushOp, code: &str, message: impl Into<String>) -> Self {
        Self {
            code: Some(code.to_owned()),
            message: Some(message.into()),
            link: Some(record_link(&op.entity, op.id)),
            ..Self::new(op, "rejected")
        }
    }

    /// Whether later operations on this record must not run.
    pub fn blocks(&self) -> bool {
        matches!(self.status.as_str(), "rejected" | "conflict")
    }
}

/// Where a record opens in the app. Pure.
pub fn record_link(entity: &str, id: Uuid) -> String {
    format!("/xrm/entity/{entity}/form?id={id}")
}

/// The privilege an operation needs. Pure.
pub fn privilege(kind: &str) -> Option<&'static str> {
    match kind {
        "create" => Some("create"),
        "update" => Some("update"),
        "delete" => Some("delete"),
        _ => None,
    }
}

/// How an update made against an older version meets the current values:
/// `Ok(())` when every changed field still holds its starting value (merge),
/// or the fields that moved, with their current values. Pure.
pub fn merge_check(
    changed: &Map<String, Value>,
    base_values: &Map<String, Value>,
    current: &Map<String, Value>,
) -> Result<(), Map<String, Value>> {
    let mut clashes = Map::new();
    for field in changed.keys() {
        let now = current.get(field).cloned().unwrap_or(Value::Null);
        let base = base_values.get(field).cloned().unwrap_or(Value::Null);
        if now != base {
            clashes.insert(field.clone(), now);
        }
    }
    if clashes.is_empty() {
        Ok(())
    } else {
        Err(clashes)
    }
}

/// Whether the current values already are the change (a retried update
/// whose first attempt was applied). Pure.
pub fn already_applied(changed: &Map<String, Value>, current: &Map<String, Value>) -> bool {
    !changed.is_empty()
        && changed
            .iter()
            .all(|(k, v)| current.get(k).unwrap_or(&Value::Null) == v)
}

/// A refusal's code. Pure.
pub fn refusal_code(error: &AppError) -> &'static str {
    match error {
        AppError::Forbidden => "forbidden",
        AppError::NotFound => "not_found",
        AppError::VersionConflict => "version_conflict",
        AppError::Conflict(_) => "conflict",
        _ => "invalid",
    }
}

fn refuse(op: &PushOp, error: &AppError) -> OpResult {
    let message = match error {
        AppError::Validation(m) => m.clone(),
        AppError::Conflict(m) => (*m).to_owned(),
        _ => refusal_code(error).replace('_', " "),
    };
    OpResult::rejected(op, refusal_code(error), message)
}

async fn current_values(
    state: &EngineState,
    ctx: &SecurityContext,
    op: &PushOp,
) -> Result<(i64, Map<String, Value>), AppError> {
    let record = read_record(state, ctx, &op.entity, op.id).await?;
    let data = record.data().as_object().cloned().unwrap_or_default();
    Ok((record.row_version(), data))
}

/// Applies one operation; never fails the batch (a failure is its result).
async fn apply(state: &EngineState, ctx: &SecurityContext, op: &PushOp) -> OpResult {
    let Some(needed) = privilege(&op.kind) else {
        return OpResult::rejected(op, "invalid", "kind: create, update or delete");
    };
    if let Err(e) = ctx.require(&op.entity, needed) {
        return refuse(op, &e);
    }
    match op.kind.as_str() {
        "create" => {
            let body = Value::Object(op.changed.clone());
            match create_record_with_id_for(state, ctx, ctx.user_id, &op.entity, body, op.id).await
            {
                Ok((_, record)) => OpResult {
                    row_version: Some(record.row_version()),
                    ..OpResult::new(op, "applied")
                },
                // Already there: a retry whose first attempt was applied.
                Err(AppError::Conflict(_)) => match current_values(state, ctx, op).await {
                    Ok((version, _)) => OpResult {
                        row_version: Some(version),
                        ..OpResult::new(op, "applied")
                    },
                    Err(e) => refuse(op, &e),
                },
                Err(e) => refuse(op, &e),
            }
        }
        "update" => {
            let (version, current) = match current_values(state, ctx, op).await {
                Ok(found) => found,
                Err(e) => return refuse(op, &e),
            };
            if already_applied(&op.changed, &current) {
                return OpResult {
                    row_version: Some(version),
                    ..OpResult::new(op, "applied")
                };
            }
            let status = if op.base_row_version == Some(version) {
                "applied"
            } else {
                match merge_check(&op.changed, &op.base_values, &current) {
                    Ok(()) => "merged",
                    Err(clashes) => {
                        return OpResult {
                            server_values: Some(Value::Object(clashes)),
                            row_version: Some(version),
                            link: Some(record_link(&op.entity, op.id)),
                            ..OpResult::new(op, "conflict")
                        };
                    }
                }
            };
            let body = Value::Object(op.changed.clone());
            match update_record_for(state, ctx, ctx.user_id, &op.entity, op.id, version, body).await
            {
                Ok(record) => OpResult {
                    row_version: Some(record.row_version()),
                    ..OpResult::new(op, status)
                },
                Err(e) => refuse(op, &e),
            }
        }
        _ => {
            let origin = DeleteOrigin::with_id(DeleteKind::Request, op.client_op_id.to_string());
            match delete_record_for(
                state,
                ctx,
                ctx.user_id,
                &op.entity,
                op.id,
                op.base_row_version,
                &origin,
            )
            .await
            {
                // A record already gone: the delete it asked for holds.
                Ok(()) | Err(AppError::NotFound) => OpResult::new(op, "applied"),
                Err(e) => refuse(op, &e),
            }
        }
    }
}

/// One push for the caller's device.
pub async fn push(
    state: &EngineState,
    ctx: &SecurityContext,
    body: &PushBody,
) -> Result<PushResult, AppError> {
    if body.ops.len() > MAX_OPS {
        return Err(AppError::Validation(format!(
            "ops: at most {MAX_OPS} per push"
        )));
    }
    let db = &state.base.db;
    let mine: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_device \
                 WHERE id = $1 AND user_id = $2 AND wipe_requested_at IS NULL)",
    )
    .bind(body.device_id)
    .bind(ctx.user_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !mine {
        return Err(AppError::NotFound);
    }

    // One push per device at a time: the lock holds for the whole batch.
    let mut guard = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-offline/push:{}", body.device_id))
        .fetch_one(&mut *guard)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a push from this device is already running",
        ));
    }

    let mut results = Vec::with_capacity(body.ops.len());
    let mut blocked: HashSet<(String, Uuid)> = HashSet::new();
    for op in &body.ops {
        let kept: Option<Value> = sqlx::query_scalar(
            "SELECT result FROM offline_op WHERE device_id = $1 AND client_op_id = $2",
        )
        .bind(body.device_id)
        .bind(op.client_op_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        let result = match kept.and_then(|v| serde_json::from_value::<OpResult>(v).ok()) {
            Some(kept) => kept,
            None => {
                let result = if blocked.contains(&(op.entity.clone(), op.id)) {
                    OpResult::rejected(
                        op,
                        "depends_on_failed",
                        "an earlier change to this record was not applied",
                    )
                } else {
                    apply(state, ctx, op).await
                };
                sqlx::query(
                    "INSERT INTO offline_op (device_id, client_op_id, status, result) \
                     VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
                )
                .bind(body.device_id)
                .bind(op.client_op_id)
                .bind(&result.status)
                .bind(serde_json::to_value(&result).map_err(AppError::internal)?)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
                result
            }
        };
        if result.blocks() {
            blocked.insert((op.entity.clone(), op.id));
        }
        results.push(result);
    }

    sqlx::query(
        "UPDATE offline_device_state \
            SET last_push_at = now(), \
                queue_size = coalesce($2, queue_size), \
                bytes_used = coalesce($3, bytes_used) \
          WHERE device_id = $1",
    )
    .bind(body.device_id)
    .bind(body.queue_size)
    .bind(body.bytes_used)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(guard).await?;
    Ok(PushResult { results })
}

/// B18-T7: applies a device's queued changes in order, once each, through
/// the same path as an online edit.
#[utoipa::path(
    post,
    path = "/api/v1/offline/push",
    tag = "offline",
    request_body = PushBody,
    extensions(("x-audit" = json!(x_audit(&[
        (AuditCategory::Entity, AuditOperation::Create),
        (AuditCategory::Entity, AuditOperation::Update),
        (AuditCategory::Entity, AuditOperation::SoftDelete),
    ])))),
    responses(
        (status = 200, description = "Each operation's result, in order", body = PushResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Not the caller's device, or it was told to wipe", body = ErrorResponse),
        (status = 409, description = "A push from this device is already running", body = ErrorResponse),
        (status = 422, description = "More than 100 operations", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_push(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<PushBody>,
) -> Result<Json<PushResult>, AppError> {
    Ok(Json(push(&state, &ctx, &body).await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(v: Value) -> Map<String, Value> {
        v.as_object().cloned().unwrap()
    }

    #[test]
    fn disjoint_attributes_merge() {
        // The device changed `phone` from "1"; someone else changed `email`.
        let changed = map(json!({"phone": "2"}));
        let base = map(json!({"phone": "1"}));
        let current = map(json!({"phone": "1", "email": "new@x"}));
        assert_eq!(merge_check(&changed, &base, &current), Ok(()));
    }

    #[test]
    fn same_attribute_conflict_returns_server_value() {
        let changed = map(json!({"phone": "2", "city": "Riyadh"}));
        let base = map(json!({"phone": "1", "city": "Jeddah"}));
        let current = map(json!({"phone": "3", "city": "Jeddah"}));
        let clashes = merge_check(&changed, &base, &current).unwrap_err();
        assert_eq!(Value::Object(clashes), json!({"phone": "3"}));
    }

    #[test]
    fn push_retried_update_counts_as_applied() {
        let changed = map(json!({"phone": "2"}));
        assert!(already_applied(
            &changed,
            &map(json!({"phone": "2", "x": 1}))
        ));
        assert!(!already_applied(&changed, &map(json!({"phone": "1"}))));
        assert!(!already_applied(&Map::new(), &map(json!({}))));
    }

    #[test]
    fn rejected_op_blocks_dependents() {
        let op = PushOp {
            client_op_id: Uuid::nil(),
            kind: "update".into(),
            entity: "account".into(),
            id: Uuid::nil(),
            base_row_version: Some(1),
            changed: Map::new(),
            base_values: Map::new(),
        };
        let r = refuse(&op, &AppError::Validation("name: required".into()));
        assert!(r.blocks());
        assert_eq!(r.code.as_deref(), Some("invalid"));
        assert_eq!(
            r.link.as_deref(),
            Some("/xrm/entity/account/form?id=00000000-0000-0000-0000-000000000000")
        );
        assert!(!OpResult::new(&op, "merged").blocks());
        assert_eq!(refusal_code(&AppError::Forbidden), "forbidden");
        assert_eq!(privilege("archive"), None);
        // A stored result reads back the same.
        let back: OpResult = serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }
}
