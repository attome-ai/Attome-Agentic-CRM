//! D-369: bounded per-grant record conditions on a role<->privilege
//! assignment (`role_privilege_condition`, FK to
//! `role_mm_privilege`). Field eligibility, the cap-of-3, and the
//! request-time SQL rendering are `crate::conditions`' job; this module is
//! only the admin CRUD surface over it.
//!
//! Solution 7 Phase 1 (D-785): create and delete are recorded as
//! `add_role_grant_condition` / `remove_role_grant_condition`, target
//! `{ role, privilege, condition }` where `condition` is the row's content key
//! (`shared::condition_key`). A new condition is stamped with the changeset's
//! layer; removing one needs the condition row's own layer.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_core::changeset::{Op, RecordingCtx};
use attome_server::authz::{Authorized, Privilege, area};
use attome_server::security::ConditionOperator;
use attome_types::AppError;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::conditions::eligible_condition_field;
use crate::db::users_holding_role;

use super::shared::{
    access_tx, condition_key, invalidate_sync_all, mark_role_customized, parse_owner_layer,
    security_op, snapshot_row,
};

/// `role_privilege_condition`'s snapshot.
const CONDITION_SNAPSHOT: &str = "SELECT id, role_privilege_ref, field_logicalname, operator, \
     value, is_deleted, row_version, owner_layer \
     FROM role_privilege_condition WHERE id = $1";
use attome_types::ErrorResponse;
use utoipa::ToSchema;

/// Live-row cap per `role_privilege_ref` — enforced under a row lock in
/// [`create_condition`], not a DB constraint (D-369: "a product-level bound,
/// same category as other batch-size caps in this codebase").
const MAX_CONDITIONS_PER_GRANT: i64 = 3;

#[derive(Serialize, ToSchema)]
pub struct RoleGrantConditionItem {
    id: Uuid,
    role_privilege_ref: Uuid,
    field_logicalname: String,
    operator: i16,
    value: serde_json::Value,
    created_at: DateTime<Utc>,
    /// Solution 7 (D-785): the layer that owns this condition row.
    owner_layer: String,
}

impl std::fmt::Debug for RoleGrantConditionItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoleGrantConditionItem")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct CreateConditionBody {
    /// Empty for an expression condition.
    #[serde(default)]
    field_logicalname: String,
    /// 0=eq 1=ne 2=gt 3=lt 4=gte 5=lte 6=in 7=expression (Z11-T16: `value`
    /// is a rule expression over the entity's eligible fields, refused with
    /// 422 `untranslatable_condition` when it cannot run in the database).
    operator: i16,
    value: serde_json::Value,
}

/// The grant row's privilege key + owning role — resolved once per request
/// so both the field-eligibility check (needs the entity the key names) and
/// the post-write cache invalidation (needs the role) share one query. The
/// role's name is the recorded operation's `role` key.
struct GrantContext {
    role_id: Uuid,
    role_name: String,
    privilege_key: String,
}

async fn load_grant_context(
    db: &attome_db::DbPool,
    grant_id: Uuid,
) -> Result<GrantContext, AppError> {
    let row: Option<(Uuid, String, String)> = sqlx::query_as(
        r#"SELECT rp.role_ref, r.name, p.key
           FROM role_mm_privilege rp
           JOIN privilege p ON p.id = rp.privilege_ref
           JOIN role r ON r.id = rp.role_ref
           WHERE rp.id = $1 AND rp.is_deleted = false"#,
    )
    .bind(grant_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let (role_id, role_name, privilege_key) = row.ok_or(AppError::NotFound)?;
    Ok(GrantContext {
        role_id,
        role_name,
        privilege_key,
    })
}

/// A role grant's conditions
///
/// The conditions on a role grant. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/role-grants/{grant_id}/conditions",
    tag = "admin-security",
    params(("grant_id" = Uuid, Path, description = "The role grant")),
    responses(
        (status = 200, description = "Success", body = Vec<RoleGrantConditionItem>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such grant", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn list_conditions(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Roles>>,
    Path(grant_id): Path<Uuid>,
) -> Result<Json<Vec<RoleGrantConditionItem>>, AppError> {
    load_grant_context(&state.base.db, grant_id).await?;

    let rows: Vec<(Uuid, String, i16, serde_json::Value, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT id, field_logicalname, operator, value, created_at, owner_layer
         FROM role_privilege_condition
         WHERE role_privilege_ref = $1 AND is_deleted = false
         ORDER BY created_at",
    )
    .bind(grant_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(id, field_logicalname, operator, value, created_at, owner_layer)| {
                    RoleGrantConditionItem {
                        id,
                        role_privilege_ref: grant_id,
                        field_logicalname,
                        operator,
                        value,
                        created_at,
                        owner_layer,
                    }
                },
            )
            .collect(),
    ))
}

/// Add a condition to a role grant
///
/// Adds a field condition to a role grant. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/role-grants/{grant_id}/conditions",
    tag = "admin-security",
    params(("grant_id" = Uuid, Path, description = "The role grant")),
    request_body = CreateConditionBody,
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = RoleGrantConditionItem),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such grant", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn create_condition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    recording: RecordingCtx,
    Path(grant_id): Path<Uuid>,
    Json(body): Json<CreateConditionBody>,
) -> Result<(StatusCode, Json<RoleGrantConditionItem>), AppError> {
    let grant = load_grant_context(&state.base.db, grant_id).await?;

    let operator = ConditionOperator::from_i16(body.operator)
        .ok_or_else(|| AppError::Validation("unrecognized condition operator".into()))?;

    let entity_logicalname = grant
        .privilege_key
        .split('.')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::Validation("grant's privilege key has no entity segment".into())
        })?;
    let attrs = state
        .entities
        .load()
        .get(entity_logicalname)
        .map(|meta| meta.attrs.clone())
        .unwrap_or_default();
    if operator == ConditionOperator::Expression {
        // Z11-T16: a privilege condition must run in the database; an
        // expression the SQL translation cannot express is refused here.
        crate::conditions::check_expression(&body.value, &attrs).map_err(|reason| {
            AppError::Validation(format!("untranslatable_condition: {reason}"))
        })?;
        if !body.field_logicalname.is_empty() {
            return Err(AppError::Validation(
                "an expression condition names no field".into(),
            ));
        }
    } else {
        eligible_condition_field(&attrs, &body.field_logicalname).map_err(|reason| {
            AppError::Validation(format!(
                "field '{}' is not eligible for a condition: {reason}",
                body.field_logicalname
            ))
        })?;
    }

    if operator == ConditionOperator::In {
        if !body.value.is_array() {
            return Err(AppError::Validation(
                "an `in` condition's value must be a JSON array".into(),
            ));
        }
    } else if operator != ConditionOperator::Expression
        && (body.value.is_array() || body.value.is_object() || body.value.is_null())
    {
        return Err(AppError::Validation(
            "condition value must be a string, number, or boolean".into(),
        ));
    }

    recording.preflight(&state.base.db).await?;
    let layer = recording.stamp()?;

    let mut tx = access_tx(
        &state,
        AuditOperation::Create,
        ctx.user_id,
        "role_privilege_condition",
        None,
    )
    .await?;

    // Row-lock the parent grant before counting — closes the TOCTOU window
    // two concurrent creates would otherwise have against the cap (D-369).
    sqlx::query("SELECT id FROM role_mm_privilege WHERE id = $1 FOR UPDATE")
        .bind(grant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .ok_or(AppError::NotFound)?;

    let existing: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_privilege_condition
         WHERE role_privilege_ref = $1 AND is_deleted = false",
    )
    .bind(grant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if existing >= MAX_CONDITIONS_PER_GRANT {
        return Err(AppError::Validation(format!(
            "a grant may carry at most {MAX_CONDITIONS_PER_GRANT} conditions"
        )));
    }

    let row: (Uuid, DateTime<Utc>) = sqlx::query_as(
        "INSERT INTO role_privilege_condition
             (role_privilege_ref, field_logicalname, operator, value, owner_layer)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, created_at",
    )
    .bind(grant_id)
    .bind(&body.field_logicalname)
    .bind(body.operator)
    .bind(&body.value)
    .bind(layer.as_str())
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    mark_role_customized(&mut *tx, grant.role_id).await?;
    let snapshot = snapshot_row(&mut tx, CONDITION_SNAPSHOT, row.0).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::AddRoleGrantCondition,
                "role_grant_condition",
                row.0,
                serde_json::json!({
                    "role": grant.role_name,
                    "privilege": grant.privilege_key,
                    "condition": condition_key(&body.field_logicalname, body.operator, &body.value),
                }),
                snapshot,
            ),
        )
        .await?;
    tx.event_mut().set_record_id(row.0);
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, grant.role_id).await?,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(RoleGrantConditionItem {
            id: row.0,
            role_privilege_ref: grant_id,
            field_logicalname: body.field_logicalname,
            operator: body.operator,
            value: body.value,
            created_at: row.1,
            owner_layer: layer.as_str().to_owned(),
        }),
    ))
}

/// Remove a role grant condition
///
/// Removes one condition from a role grant. Administrators only; audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/security/role-grants/{grant_id}/conditions/{condition_id}",
    tag = "admin-security",
    params(
        ("grant_id" = Uuid, Path, description = "The role grant"),
        ("condition_id" = Uuid, Path, description = "The condition"),
    ),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Access, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such condition", body = ErrorResponse),
        (status = 409, description = "No open changeset to record into, or the condition is owned by another layer", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn delete_condition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    recording: RecordingCtx,
    Path((grant_id, condition_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    let grant = load_grant_context(&state.base.db, grant_id).await?;
    recording.preflight(&state.base.db).await?;

    let mut tx = access_tx(
        &state,
        AuditOperation::SoftDelete,
        ctx.user_id,
        "role_privilege_condition",
        Some(condition_id),
    )
    .await?;
    let live: Option<(String, String, i16, serde_json::Value)> = sqlx::query_as(
        "SELECT owner_layer, field_logicalname, operator, value \
         FROM role_privilege_condition \
         WHERE id = $1 AND role_privilege_ref = $2 AND is_deleted = false FOR UPDATE",
    )
    .bind(condition_id)
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let (owner, field, operator, value) = live.ok_or(AppError::NotFound)?;
    recording.check_owner(parse_owner_layer(&owner)?)?;
    let deleted: Option<Uuid> = sqlx::query_scalar(
        "UPDATE role_privilege_condition SET is_deleted = true, updated_at = NOW()
         WHERE id = $1 AND role_privilege_ref = $2 AND is_deleted = false
         RETURNING id",
    )
    .bind(condition_id)
    .bind(grant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    if deleted.is_none() {
        return Err(AppError::NotFound);
    }
    mark_role_customized(&mut *tx, grant.role_id).await?;
    let snapshot = snapshot_row(&mut tx, CONDITION_SNAPSHOT, condition_id).await?;
    recording
        .record(
            tx.tx(),
            security_op(
                Op::RemoveRoleGrantCondition,
                "role_grant_condition",
                condition_id,
                serde_json::json!({
                    "role": grant.role_name,
                    "privilege": grant.privilege_key,
                    "condition": condition_key(&field, operator, &value),
                }),
                snapshot,
            ),
        )
        .await?;
    tx.commit().await?;

    invalidate_sync_all(
        &state.base.security,
        users_holding_role(&state.base.db, grant.role_id).await?,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/role-grants/{grant_id}/conditions",
            get(list_conditions).post(create_condition),
        )
        .route(
            "/api/v1/admin/security/role-grants/{grant_id}/conditions/{condition_id}",
            axum::routing::delete(delete_condition),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_conditions, create_condition, delete_condition))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
