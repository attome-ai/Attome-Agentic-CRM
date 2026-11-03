//! Y2-T5: a lookup's database foreign key. A lookup whose `on_target_delete`
//! is `restrict` or `cascade-deactivate` is keyed when its column is created;
//! these routes show a field's key and add it to a lookup created before
//! (`NOT VALID`, then validated inline under the size gate or by the
//! `ValidateLookupForeignKey` job above it). Values that point at no record
//! refuse the validation: the orphan scan (`GET .../orphans`) finds them. An
//! `orphan` lookup keeps no key. Administrators with the data-model area.

use attome_audit::AuditOperation;
use attome_core::{EngineState, FieldType};
use attome_metadata::provision::lookup_fk::{self, FkRequest, FkState};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

/// A lookup field's key.
#[derive(Debug, Serialize, ToSchema)]
pub struct LookupKey {
    /// `none`, `not_valid` (new writes are held to it, existing rows not yet
    /// checked) or `valid`.
    #[schema(value_type = String)]
    pub state: FkState,
    /// The lookup's delete rule allows a key (`restrict` or `cascade-deactivate`).
    pub keyed: bool,
    pub target_entity: String,
    /// The validation is queued (a table over the size gate).
    pub queued: bool,
}

#[derive(sqlx::FromRow)]
struct FieldRow {
    entity: String,
    field: String,
    field_type: Option<i32>,
    on_target_delete: Option<String>,
    target: Option<String>,
}

async fn lookup_of(
    state: &EngineState,
    entity_id: Uuid,
    field_id: Uuid,
) -> Result<(String, String, String, bool), AppError> {
    let row: Option<FieldRow> = sqlx::query_as(
        "SELECT e.logicalname AS entity, a.logicalname AS field, a.type AS field_type, \
                a.on_target_delete, t.logicalname AS target \
           FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
           LEFT JOIN entity_info t ON t.id = a.lookup_entity_ref \
          WHERE a.id = $1 AND a.entity_ref = $2 AND a.is_active IS NOT FALSE",
    )
    .bind(field_id)
    .bind(entity_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    if row.field_type.and_then(FieldType::from_int) != Some(FieldType::Lookup) {
        return Err(AppError::Validation(format!(
            "{} is not a lookup",
            row.field
        )));
    }
    let target = row.target.ok_or_else(|| {
        AppError::Validation(format!("{} has no target entity to key to", row.field))
    })?;
    let keyed = lookup_fk::keyed(row.on_target_delete.as_deref().unwrap_or("orphan"));
    Ok((row.entity, row.field, target, keyed))
}

/// A lookup's foreign key
///
/// Y2-T5: whether lookup field `field_id` has its database foreign key, and whether that key has
/// been checked against the existing rows. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/foreign-key",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path, description = "The entity"),
        ("field_id" = Uuid, Path, description = "The lookup field"),
    ),
    responses(
        (status = 200, description = "The key's state", body = LookupKey),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the data-model area", body = ErrorResponse),
        (status = 404, description = "No such field", body = ErrorResponse),
        (status = 422, description = "Not a lookup, or no target entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_lookup_key(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Path((entity_id, field_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<LookupKey>, AppError> {
    let (entity, field, target, keyed) = lookup_of(&state, entity_id, field_id).await?;
    let state_now = lookup_fk::fk_state(&state.base.db, &entity, &field).await?;
    Ok(Json(LookupKey {
        state: state_now,
        keyed,
        target_entity: target,
        queued: false,
    }))
}

/// Key a lookup
///
/// Y2-T5: adds lookup field `field_id`'s database foreign key (`ON DELETE NO ACTION`, `NOT VALID`)
/// and validates it: inline when the table holds at most 10,000 rows (200), else by a queued job
/// (202). A value that points at no record refuses the validation (409) and the key stays
/// `NOT VALID`. Only for a lookup whose delete rule is `restrict` or `cascade-deactivate`.
/// Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/fields/{field_id}/foreign-key",
    tag = "admin",
    params(
        ("entity_id" = Uuid, Path, description = "The entity"),
        ("field_id" = Uuid, Path, description = "The lookup field"),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Keyed and valid", body = LookupKey),
        (status = 202, description = "Keyed NOT VALID; the validation is queued", body = LookupKey),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the data-model area", body = ErrorResponse),
        (status = 404, description = "No such field", body = ErrorResponse),
        (status = 409, description = "The lookup has orphan values", body = ErrorResponse),
        (status = 422, description = "Not a lookup, no target, or its delete rule keeps no key", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn key_lookup(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path((entity_id, field_id)): Path<(Uuid, Uuid)>,
) -> Result<(StatusCode, Json<LookupKey>), AppError> {
    let (entity, field, target, keyed) = lookup_of(&state, entity_id, field_id).await?;
    if !keyed {
        return Err(AppError::Validation(format!(
            "{field}: a key is kept only on a restrict or cascade-deactivate lookup; an orphan lookup's check is the orphan scan"
        )));
    }
    let outcome = lookup_fk::request_lookup_fk(
        &state.base.db_migrator,
        &entity,
        &field,
        &target,
        lookup_fk::FK_VALIDATE_INLINE_ROW_LIMIT,
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "attribute_info",
            field_id,
            AuditOperation::Update,
            "metadata.lookup_key",
            ctx.user_id,
        )
        .comment(format!("{entity}.{field} keyed to {target}")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    let queued = outcome == FkRequest::Queued;
    Ok((
        if queued {
            StatusCode::ACCEPTED
        } else {
            StatusCode::OK
        },
        Json(LookupKey {
            state: if queued {
                FkState::NotValid
            } else {
                FkState::Valid
            },
            keyed,
            target_entity: target,
            queued,
        }),
    ))
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/entities/{entity_id}/fields/{field_id}/foreign-key",
        get(get_lookup_key).post(key_lookup),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_lookup_key, key_lookup))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
