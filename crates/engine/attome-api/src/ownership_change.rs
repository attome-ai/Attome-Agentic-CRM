//! A31-T3: changing an entity's ownership model (A31-T1) safely.
//!
//! The model itself changes atomically: it is part of the entity's settings,
//! which take effect when a metadata version is published, and until then
//! every node filters with the old model. What needs care is the data the new
//! model reads:
//!
//! - **Preview.** `GET /api/v1/admin/security/ownership/{entity}/preview?target=`
//!   counts the entity's live records, their owners, and for `unit` the
//!   records with no unit (`organization_ref`; nobody below the global level
//!   would reach them), how many of those the owner's home unit can fill, and
//!   the records whose unit is not their owner's home unit (who reaches them
//!   changes). For `organisation` everyone whose role reaches the entity sees
//!   every record afterwards; the preview says how many records that is.
//! - **Prepare.** `POST .../prepare` queues [`PREPARE_JOB`], which fills each
//!   user-owned record's missing unit from its owner's home unit, 1,000
//!   records a statement, until none is left. Publish the new model after.
//!
//! Both need the Security administration area.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_audit::{AuditOperation, audit_service};
use attome_core::{EngineState, quote_ident};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// The registered job that fills missing record units.
pub const PREPARE_JOB: &str = "ownership_unit_backfill";
/// Records one backfill statement fills.
pub const BATCH: i64 = 1_000;

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparePayload {
    pub entity: String,
}

/// The model to preview.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PreviewQuery {
    /// `user_or_team`, `organisation` or `unit`.
    pub target: String,
}

/// What switching an entity's ownership model changes.
#[derive(Debug, Serialize, ToSchema)]
pub struct OwnershipPreview {
    pub entity: String,
    pub target: String,
    pub records: i64,
    pub owners: i64,
    /// `unit`: records with no unit.
    pub without_unit: i64,
    /// `unit`: of those, the ones their owner's home unit can fill.
    pub fillable: i64,
    /// `unit`: records whose unit is not their owner's home unit.
    pub unit_differs_from_owner: i64,
    /// What the switch means, in a sentence.
    pub summary: String,
}

/// A live entity table: in the registry, with a logical name. The name.
fn entity_table(state: &EngineState, entity: &str) -> Result<String, AppError> {
    let registry = state.entities.load();
    let meta = registry.get(entity).ok_or(AppError::NotFound)?;
    if !attome_db::ident::is_logical_name(&meta.logicalname) {
        return Err(AppError::NotFound);
    }
    Ok(meta.logicalname.clone())
}

/// The preview's sentence. Pure.
pub fn summary(target: &str, records: i64, without_unit: i64, fillable: i64) -> String {
    match target {
        "organisation" => format!(
            "Everyone whose role reaches this entity at any level will see all {records} records; \
             owners no longer narrow access."
        ),
        "unit" => format!(
            "Access will follow each record's unit. {without_unit} records have no unit; preparing \
             fills {fillable} of them from their owner's home unit, and the rest are reached only \
             at the global level or through shares."
        ),
        _ => format!("Access follows owners and teams again for all {records} records."),
    }
}

/// Preview an ownership model change
///
/// Counts what switching the entity to `target` changes. Changes nothing.
#[utoipa::path(
    get,
    path = "/api/v1/admin/security/ownership/{entity}/preview",
    tag = "admin",
    params(("entity" = String, Path, description = "The entity"), PreviewQuery),
    responses(
        (status = 200, description = "What the switch changes", body = OwnershipPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "An unknown model", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn preview(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Security>>,
    Path(entity): Path<String>,
    Query(q): Query<PreviewQuery>,
) -> Result<Json<OwnershipPreview>, AppError> {
    if !matches!(q.target.as_str(), "user_or_team" | "organisation" | "unit") {
        return Err(AppError::Validation(
            "target is user_or_team, organisation or unit".into(),
        ));
    }
    let table = quote_ident(&entity_table(&state, &entity)?);
    let live = "(t.is_active IS NULL OR t.is_active = true)";
    let (records, owners, without_unit, fillable, differs): (i64, i64, i64, i64, i64) =
        sqlx::query_as(&format!(
            "SELECT count(*), count(DISTINCT t.owner_ref), \
                    count(*) FILTER (WHERE t.organization_ref IS NULL), \
                    count(*) FILTER (WHERE t.organization_ref IS NULL AND t.owner_type = 0 \
                                       AND u.organization_ref IS NOT NULL), \
                    count(*) FILTER (WHERE t.organization_ref IS NOT NULL AND t.owner_type = 0 \
                                       AND u.organization_ref IS DISTINCT FROM t.organization_ref) \
               FROM {table} t LEFT JOIN user_account u ON u.id = t.owner_ref \
              WHERE {live}"
        ))
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(OwnershipPreview {
        summary: summary(&q.target, records, without_unit, fillable),
        entity,
        target: q.target,
        records,
        owners,
        without_unit,
        fillable,
        unit_differs_from_owner: differs,
    }))
}

/// Prepare an entity for unit ownership
///
/// Queues the job that fills each user-owned record's missing unit from its
/// owner's home unit. Publish the new model once it is done. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/ownership/{entity}/prepare",
    tag = "admin",
    params(("entity" = String, Path, description = "The entity")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, AuditOperation::Update)])))),
    responses(
        (status = 202, description = "Queued"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn prepare(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Security>>,
    Path(entity): Path<String>,
) -> Result<StatusCode, AppError> {
    let entity = entity_table(&state, &entity)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let job = attome_core::jobs::JOB_TYPES
        .job(
            PREPARE_JOB,
            &PreparePayload {
                entity: entity.clone(),
            },
        )
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "entity_info",
            None,
        )
        .named("security.ownership_prepare")
        .comment(format!("unit backfill queued for {entity}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::ACCEPTED)
}

/// The job: fills missing units, [`BATCH`] records a statement; how many.
pub async fn run_prepare(state: &EngineState, entity: &str) -> Result<u64, AppError> {
    let table = quote_ident(&entity_table(state, entity)?);
    let mut filled = 0;
    loop {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let done = sqlx::query(&format!(
            "UPDATE {table} t SET organization_ref = u.organization_ref \
               FROM user_account u \
              WHERE u.id = t.owner_ref AND u.organization_ref IS NOT NULL \
                AND t.id IN (SELECT r.id FROM {table} r \
                              JOIN user_account o ON o.id = r.owner_ref \
                             WHERE r.organization_ref IS NULL AND r.owner_type = 0 \
                               AND o.organization_ref IS NOT NULL \
                             ORDER BY r.id LIMIT $1)"
        ))
        .bind(BATCH)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        attome_db::tx::commit(tx).await?;
        filled += done;
        if done == 0 {
            break;
        }
    }
    tracing::info!(entity, filled, "record units filled for unit ownership");
    Ok(filled)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/ownership/{entity}/preview",
            get(preview),
        )
        .route(
            "/api/v1/admin/security/ownership/{entity}/prepare",
            post(prepare),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(preview, prepare))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn previews_say_what_changes() {
        assert!(summary("organisation", 40, 0, 0).contains("all 40 records"));
        let unit = summary("unit", 40, 5, 3);
        assert!(unit.contains("5 records have no unit") && unit.contains("fills 3"));
    }
}
