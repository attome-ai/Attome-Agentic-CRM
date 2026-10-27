//! A24-T4: running a migration project's waves.
//!
//! `POST /api/v1/admin/migration-projects/{id}/waves` queues the next wave
//! (`migration_wave`, migration 0308): the first is a full load, each later
//! one a catch-up of what changed at the source since the previous wave
//! began, and `cut_over: true` marks the last. The durable job
//! ([`WAVE_JOB`], [`run_wave`]) then, for the project's model mapping
//! (A24-T3):
//!
//! 1. opens the source the integration system names
//!    (`migration_connect::NamedSource`);
//! 2. applies the metadata steps (`migration_waves::metadata_steps`) through
//!    the same primitives the admin routes use (entity create, field create,
//!    choice add), each skipped when already in place, recording into an
//!    automatic changeset;
//! 3. reads every mapped entity, dependencies first, a page at a time, and
//!    queues each page as an A23 import (`create_rows_import`) that upserts
//!    by the source's key attribute, so a catch-up updates what the full
//!    load created and links resolve whichever record arrives first.
//!
//! The imports validate and apply on their own queue; the wave is `loaded`
//! once every page is queued. Not yet: keeping the source's created-by,
//! created-at and owner values (a migration write mode), and copying files.

use attome_core::EngineState;
use attome_core::changeset::{Recording, RecordingMode, RequestContext};
use attome_integration::connector::adapters::migration_connect::NamedSource;
use attome_integration::connector::adapters::migration_mapping::{MapAction, ModelMapping};
use attome_integration::connector::adapters::migration_waves::{
    MetadataStep, OWNER, SOURCE_ID, Wave, import_mapping, import_row, key_attribute, load_order,
    metadata_steps, next_wave, owner_of,
};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job that runs one wave.
pub const WAVE_JOB: &str = "migration_wave";
/// The most pages one entity is read to in one wave.
pub const MAX_PAGES: usize = 10_000;
/// The waves the list answers.
pub const MAX_WAVES_LISTED: i64 = 100;

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaveJob {
    pub wave_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
pub(crate) struct StartWaveBody {
    /// The integration system that is the source.
    system: String,
    /// The last wave, with the source frozen.
    #[serde(default)]
    cut_over: bool,
}

/// One wave.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub(crate) struct WaveRow {
    id: Uuid,
    project_id: Uuid,
    system: String,
    /// `full`, `catch_up` or `cut_over`.
    kind: String,
    /// What changed after this was read; `null` for a full load.
    since: Option<DateTime<Utc>>,
    /// `queued`, `running`, `loaded` or `failed`.
    status: String,
    #[schema(value_type = Object)]
    counts: Value,
    error: Option<String>,
    created_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
}

const WAVE_COLUMNS: &str = "id, project_id, system, kind, since, status, counts, error, \
                            created_at, started_at, finished_at";

fn kind_name(wave: Wave) -> &'static str {
    match wave {
        Wave::Full => "full",
        Wave::CatchUp { .. } => "catch_up",
        Wave::CutOver { .. } => "cut_over",
    }
}

/// The recording a wave's metadata writes go into: an automatic changeset
/// named for the wave, as an approved deferred change records.
fn wave_recording(state: &EngineState, actor: Uuid, wave_id: Uuid) -> Recording {
    let changesets = &state.base.config.metadata.changesets;
    Recording::for_request(RequestContext {
        header: None,
        actor: Some(actor),
        actor_label: format!("user:{actor}"),
        request_id: None,
        route: format!("MIGRATION WAVE {wave_id}"),
        mode: RecordingMode::Auto,
        auto_layer: changesets.auto_layer,
        break_glass: false,
    })
}

/// A source value as the text an import cell holds. Pure.
pub fn cell_text(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(cell_text).collect::<Vec<_>>().join(";"),
        other => other.to_string(),
    }
}

/// An import file name for a page: letters, digits, `-` and `_` only. Pure.
pub fn page_file_name(source: &str, wave: Uuid, page: usize) -> String {
    let safe: String = source
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(80)
        .collect();
    format!(
        "migration-{safe}-{}-{page}.csv",
        &wave.simple().to_string()[..12]
    )
}

async fn entity_id(state: &EngineState, logicalname: &str) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM entity_info WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)
}

/// The id and options of `entity`'s live attribute `name`.
async fn attribute(
    state: &EngineState,
    entity: Uuid,
    name: &str,
) -> Result<Option<(Uuid, Option<Value>)>, AppError> {
    sqlx::query_as(
        "SELECT id, options FROM attribute_info \
          WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity)
    .bind(name)
    .fetch_optional(&state.base.db_migrator)
    .await
    .map_err(AppError::internal)
}

/// Applies one metadata step, unless it is already in place. Answers
/// whether it changed anything.
async fn apply_step(
    state: &EngineState,
    actor: Uuid,
    recording: &Recording,
    step: &MetadataStep,
) -> Result<bool, AppError> {
    match step {
        MetadataStep::CreateEntity { logicalname, name } => {
            if entity_id(state, logicalname).await?.is_some() {
                return Ok(false);
            }
            let body: crate::admin::CreateEntityBody =
                serde_json::from_value(json!({ "logicalname": logicalname, "name": name }))
                    .map_err(AppError::internal)?;
            crate::admin::create_entity_core(state, actor, recording, body).await?;
            Ok(true)
        }
        MetadataStep::CreateAttribute {
            entity,
            logicalname,
            name,
            field_type,
            lookup_entity,
            options,
        } => {
            let entity_ref = entity_id(state, entity).await?.ok_or_else(|| {
                AppError::Validation(format!("no entity {entity} to add {logicalname} to"))
            })?;
            if attribute(state, entity_ref, logicalname).await?.is_some() {
                return Ok(false);
            }
            let lookup_ref = match lookup_entity {
                Some(target) => Some(entity_id(state, target).await?.ok_or_else(|| {
                    AppError::Validation(format!("no entity {target} for the lookup {logicalname}"))
                })?),
                None => None,
            };
            let body: crate::admin::CreateAttributeBody = serde_json::from_value(json!({
                "logicalname": logicalname,
                "name": name,
                "field_type": field_type,
                "lookup_entity_ref": lookup_ref,
                "options": options,
            }))
            .map_err(AppError::internal)?;
            crate::admin::do_create_attribute_recorded(
                state,
                entity_ref,
                actor,
                body,
                Some(recording),
            )
            .await?;
            Ok(true)
        }
        MetadataStep::AddChoice {
            entity,
            attribute: field,
            value,
        } => {
            let entity_ref = entity_id(state, entity)
                .await?
                .ok_or_else(|| AppError::Validation(format!("no entity {entity}")))?;
            let (attr_id, options) = attribute(state, entity_ref, field)
                .await?
                .ok_or_else(|| AppError::Validation(format!("no field {entity}.{field}")))?;
            let present = options
                .as_ref()
                .and_then(|o| o["choices"].as_array())
                .into_iter()
                .flatten()
                .any(|c| c.as_str().or_else(|| c["value"].as_str()) == Some(value.as_str()));
            if present {
                return Ok(false);
            }
            let result = crate::admin::run_structure_change(
                state,
                actor,
                entity_ref,
                attr_id,
                crate::admin::StructureAction::AddChoice,
                json!({ "value": value, "label": value }),
                recording,
            )
            .await?;
            if let Some(error) = result.error {
                return Err(AppError::Validation(format!(
                    "adding {value} to {entity}.{field} was refused: {error}"
                )));
            }
            Ok(true)
        }
    }
}

async fn set_status(
    state: &EngineState,
    wave_id: Uuid,
    status: &str,
    counts: &Value,
    error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE migration_wave SET status = $2, counts = $3, error = $4, \
                finished_at = CASE WHEN $2 IN ('loaded', 'failed') THEN now() ELSE finished_at END \
          WHERE id = $1",
    )
    .bind(wave_id)
    .bind(status)
    .bind(counts)
    .bind(error)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Runs wave `wave_id` (the job's body). A failure marks the wave `failed`
/// with the reason and is returned to the queue.
pub async fn run_wave(state: &EngineState, wave_id: Uuid) -> Result<(), AppError> {
    let claimed: Option<(Uuid, String, Option<DateTime<Utc>>, Uuid, String)> = sqlx::query_as(
        "UPDATE migration_wave SET status = 'running', started_at = now() \
          WHERE id = $1 AND status IN ('queued', 'running') \
          RETURNING project_id, system, since, created_by, kind",
    )
    .bind(wave_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((project_id, system, since, actor, _kind)) = claimed else {
        // Already loaded or failed: nothing to do.
        return Ok(());
    };
    let mut counts = json!({ "metadata_steps": 0, "entities": 0, "rows": 0, "imports": 0 });
    match load(
        state,
        wave_id,
        project_id,
        &system,
        since,
        actor,
        &mut counts,
    )
    .await
    {
        Ok(()) => set_status(state, wave_id, "loaded", &counts, None).await,
        Err(e) => {
            let reason = e.to_string();
            set_status(state, wave_id, "failed", &counts, Some(&reason)).await?;
            Err(e)
        }
    }
}

fn bump(counts: &mut Value, key: &str, by: u64) {
    let now = counts[key].as_u64().unwrap_or(0);
    counts[key] = json!(now + by);
}

async fn load(
    state: &EngineState,
    wave_id: Uuid,
    project_id: Uuid,
    system: &str,
    since: Option<DateTime<Utc>>,
    actor: Uuid,
    counts: &mut Value,
) -> Result<(), AppError> {
    let mapping: Value =
        sqlx::query_scalar("SELECT mapping FROM migration_model_mapping WHERE project_id = $1")
            .bind(project_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::Validation("the project has no model mapping".into()))?;
    let mapping: ModelMapping = serde_json::from_value(mapping).map_err(AppError::internal)?;
    let source = NamedSource::open(state, system).await?;
    let kind = source.kind.as_str();

    // 1. The metadata.
    let recording = wave_recording(state, actor, wave_id);
    recording.preflight(&state.base.db_migrator).await?;
    let targets = crate::migration_model::targets(state);
    for step in metadata_steps(&mapping, &targets, kind) {
        if apply_step(state, actor, &recording, &step).await? {
            bump(counts, "metadata_steps", 1);
        }
    }

    // 2. The records, dependencies first, a page at a time.
    let key = key_attribute(kind);
    let mut connector = source.connector();
    for name in load_order(&mapping) {
        let Some(entity) = mapping
            .entities
            .iter()
            .find(|e| e.source == name && e.action != MapAction::Skip)
        else {
            continue;
        };
        let import = serde_json::to_value(import_mapping(entity, &mapping, kind))
            .map_err(AppError::internal)?;
        let mut header = vec![SOURCE_ID.to_owned(), OWNER.to_owned()];
        header.extend(
            entity
                .attributes
                .iter()
                .filter(|a| a.action != MapAction::Skip)
                .map(|a| a.source.clone()),
        );
        bump(counts, "entities", 1);
        let mut cursor: Option<String> = None;
        for page_no in 0..MAX_PAGES {
            let page = connector
                .read_records(&entity.source, since, cursor.as_deref())
                .await?;
            if !page.records.is_empty() {
                let rows: Vec<Vec<String>> = page
                    .records
                    .iter()
                    .map(|r| {
                        let mut row = import_row(r, entity);
                        if let Some(owner) = owner_of(r, kind, &mapping.users) {
                            row.insert(OWNER.to_owned(), Value::String(owner));
                        }
                        header
                            .iter()
                            .map(|h| row.get(h).map(cell_text).unwrap_or_default())
                            .collect()
                    })
                    .collect();
                attome_document::import_routes::create_rows_import(
                    state,
                    &entity.target,
                    &page_file_name(&entity.source, wave_id, page_no),
                    &header,
                    &rows,
                    import.clone(),
                    "upsert",
                    vec![key.clone()],
                    actor,
                )
                .await?;
                bump(counts, "rows", rows.len() as u64);
                bump(counts, "imports", 1);
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
    }
    Ok(())
}

async fn project_exists(state: &EngineState, id: Uuid) -> Result<(), AppError> {
    let found: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM migration_project WHERE id = $1 AND is_deleted = false)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if found {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

/// Start a migration wave
///
/// Queues the project's next wave: a full load first, then catch-ups of
/// what changed at the source since the previous wave began; `cut_over`
/// marks the last. Refused while a wave is queued or running. Administrators
/// only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/migration-projects/{id}/waves",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    request_body = StartWaveBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 202, description = "The wave, queued", body = WaveRow),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project, or no model mapping yet", body = ErrorResponse),
        (status = 409, description = "A wave is already queued or running", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn start_wave(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<StartWaveBody>,
) -> Result<(StatusCode, Json<WaveRow>), AppError> {
    project_exists(&state, id).await?;
    let system = body.system.trim();
    if system.is_empty() {
        return Err(AppError::Validation("system must not be empty".into()));
    }
    let has_mapping: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM migration_model_mapping WHERE project_id = $1)",
    )
    .bind(id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !has_mapping {
        return Err(AppError::NotFound);
    }
    let wave_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    // One wave at a time per project.
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-api/migration-wave:{id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let busy: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM migration_wave WHERE project_id = $1 AND status IN ('queued', 'running'))",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !locked || busy {
        return Err(AppError::Conflict(
            "a wave of this project is already queued or running",
        ));
    }
    let previous: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT started_at FROM migration_wave \
          WHERE project_id = $1 AND status = 'loaded' ORDER BY started_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let wave = next_wave(previous, body.cut_over);
    let row: WaveRow = sqlx::query_as(&format!(
        "INSERT INTO migration_wave (id, project_id, system, kind, since, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING {WAVE_COLUMNS}"
    ))
    .bind(wave_id)
    .bind(id)
    .bind(system)
    .bind(kind_name(wave))
    .bind(wave.since())
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx_dedup(
        &mut tx,
        attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
            name: WAVE_JOB.to_owned(),
            version: 1,
            payload: serde_json::to_value(WaveJob { wave_id }).map_err(AppError::internal)?,
            next: None,
        }),
        &format!("attome-api/migration-wave:{wave_id}"),
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Create,
            ctx.user_id,
            "migration_wave",
            Some(wave_id),
        )
        .named("migration_wave.start"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok((StatusCode::ACCEPTED, Json(row)))
}

/// A project's waves
///
/// The project's waves, newest first (at most 100). Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/migration-projects/{id}/waves",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The migration project")),
    responses(
        (status = 200, description = "The waves", body = PaginatedResponse<WaveRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such project", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_waves(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<WaveRow>>, AppError> {
    project_exists(&state, id).await?;
    let rows: Vec<WaveRow> = sqlx::query_as(&format!(
        "SELECT {WAVE_COLUMNS} FROM migration_wave WHERE project_id = $1 \
          ORDER BY created_at DESC LIMIT {MAX_WAVES_LISTED}"
    ))
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = rows.len() as i64;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        1,
        MAX_WAVES_LISTED,
    )))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/migration-projects/{id}/waves",
        post(start_wave).get(list_waves),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(start_wave, list_waves))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waves_cells_and_file_names() {
        assert_eq!(cell_text(&json!(null)), "");
        assert_eq!(cell_text(&json!("a")), "a");
        assert_eq!(cell_text(&json!(3.5)), "3.5");
        assert_eq!(cell_text(&json!(true)), "true");
        assert_eq!(cell_text(&json!(["won", "lost"])), "won;lost");
        let name = page_file_name("res.partner", Uuid::nil(), 2);
        assert_eq!(name, "migration-res_partner-000000000000-2.csv");
    }
}
