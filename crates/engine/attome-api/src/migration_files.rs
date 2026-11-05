//! A24-T4 (V2-D1814): copying a migration wave's files onto the migrated
//! records' multi-file `attachments` field.
//!
//! A loaded wave queues [`FILES_JOB`] for itself. Each run ([`run_files`]):
//!
//! 1. waits while any import the wave queued is still applying (the wave
//!    only queues them), coming back a minute later;
//! 2. attaches what earlier runs copied: a copy whose upload session the
//!    scan found clean has its key added to the record's `attachments`
//!    through the generic record update (`update_record_for`: field rules,
//!    the file-reference check, change feed and audit), as the wave's
//!    runner, who owns the session; a refused or lapsed one is marked
//!    failed;
//! 3. copies the next [`RECORDS_PER_RUN`] records the wave's imports wrote
//!    and this wave has not looked at: their source files
//!    (`SourceConnector::read_files`) are downloaded with the source's
//!    credentials and ingested (`attome_document::files::ingest`: an upload
//!    session, quarantine, the scan) against the record's field;
//! 4. comes back a minute later while anything is left, at most
//!    [`MAX_ROUNDS`] times.
//!
//! `migration_file_copy` (migration 0399) makes every step idempotent: a
//! source file is copied once per project, whichever wave sees it first,
//! and a record a wave already looked at carries a `*<wave id>` marker.

use attome_core::EngineState;
use attome_integration::connector::adapters::migration_connect::NamedSource;
use attome_integration::connector::adapters::migration_mapping::{MapAction, ModelMapping};
use attome_integration::connector::adapters::migration_waves::{ATTACHMENTS, key_attribute};
use attome_security::SecurityContextExt;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// The registered job that copies one wave's files.
pub const FILES_JOB: &str = "migration_files";

/// How many records one run copies the files of.
pub const RECORDS_PER_RUN: i64 = 200;

/// How many times a wave's copy comes back (a minute apart: half a day).
pub const MAX_ROUNDS: u32 = 720;

/// The job's payload: the wave, and how many times it has come back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesJob {
    pub wave_id: Uuid,
    #[serde(default)]
    pub round: u32,
}

/// Queues the copy of `wave_id`'s files to run at `delay_secs` from now.
pub async fn queue(
    state: &EngineState,
    wave_id: Uuid,
    round: u32,
    delay_secs: i64,
) -> Result<(), AppError> {
    let job = attome_core::jobs::EngineJob::Registered(attome_jobs::RegisteredJob {
        name: FILES_JOB.to_owned(),
        version: 1,
        payload: serde_json::to_value(FilesJob { wave_id, round }).map_err(AppError::internal)?,
        next: None,
    });
    attome_jobs::enqueue_at_on_pool(
        &state.base.db,
        job,
        chrono::Utc::now() + chrono::Duration::seconds(delay_secs),
    )
    .await
    .map_err(AppError::internal)
}

/// Queues the next round a minute from now, unless the wave is out of
/// rounds.
async fn come_back(state: &EngineState, wave_id: Uuid, round: u32) -> Result<(), AppError> {
    if round + 1 >= MAX_ROUNDS {
        tracing::warn!(%wave_id, "migration files: stopped after {MAX_ROUNDS} rounds");
        return Ok(());
    }
    queue(state, wave_id, round + 1, 60).await
}

/// The wave's project, source system and runner, when it is loaded.
async fn loaded_wave(
    state: &EngineState,
    wave_id: Uuid,
) -> Result<Option<(Uuid, String, Uuid)>, AppError> {
    sqlx::query_as(
        "SELECT project_id, system, created_by FROM migration_wave \
          WHERE id = $1 AND status = 'loaded'",
    )
    .bind(wave_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// One run of a wave's copy (see the module documentation).
pub async fn run_files(state: &EngineState, job: FilesJob) -> Result<(), AppError> {
    let Some((project_id, system, actor)) = loaded_wave(state, job.wave_id).await? else {
        // Rolled back, failed or gone: nothing to copy.
        return Ok(());
    };

    // 1. The wave's imports first.
    let applying: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM migration_wave_import w \
           JOIN import_job j ON j.id = w.import_job_id \
          WHERE w.wave_id = $1 \
            AND j.status NOT IN ('applied', 'failed', 'undone', 'cancelled')",
    )
    .bind(job.wave_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if applying > 0 {
        return come_back(state, job.wave_id, job.round).await;
    }

    let ctx = attome_security::resolve_uncached(&state.base.db, actor).await?;

    // 2. Attach what the scan found clean.
    let scanning = attach_scanned(state, &ctx, actor, project_id).await?;

    // 3. Copy the next records' files.
    let mapping: Value =
        sqlx::query_scalar("SELECT mapping FROM migration_model_mapping WHERE project_id = $1")
            .bind(project_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| AppError::Validation("the project has no model mapping".into()))?;
    let mapping: ModelMapping = serde_json::from_value(mapping).map_err(AppError::internal)?;
    let source = NamedSource::open(state, &system).await?;
    let key = key_attribute(source.kind.as_str());
    let mut connector = source.connector();
    let marker = format!("*{}", job.wave_id);
    let mut left = false;
    for entity in mapping
        .entities
        .iter()
        .filter(|e| e.action != MapAction::Skip)
    {
        if ctx.require(&entity.target, "update").is_err() {
            tracing::warn!(entity = %entity.target, "migration files: the wave's runner may not update this entity");
            continue;
        }
        let records: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT r.record_id FROM import_row r \
               JOIN migration_wave_import w ON w.import_job_id = r.job_id \
              WHERE w.wave_id = $1 AND w.entity = $2 \
                AND NOT EXISTS (SELECT 1 FROM migration_file_copy c \
                                 WHERE c.project_id = $3 AND c.entity = $2 \
                                   AND c.record_id = r.record_id AND c.source_file_id = $4) \
              LIMIT $5",
        )
        .bind(job.wave_id)
        .bind(&entity.target)
        .bind(project_id)
        .bind(&marker)
        .bind(RECORDS_PER_RUN + 1)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if i64::try_from(records.len()).unwrap_or(i64::MAX) > RECORDS_PER_RUN {
            left = true;
        }
        let table = attome_core::quote_ident(&entity.target);
        let key_col = attome_core::quote_ident(&key);
        for record_id in records.into_iter().take(RECORDS_PER_RUN as usize) {
            let source_id: Option<String> = sqlx::query_scalar(&format!(
                "SELECT {key_col}::text FROM {table} WHERE id = $1"
            ))
            .bind(record_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
            if let Some(source_id) = source_id {
                copy_record(
                    state,
                    &mut *connector,
                    project_id,
                    actor,
                    &entity.source,
                    &entity.target,
                    record_id,
                    &source_id,
                )
                .await?;
            }
            mark(
                state,
                project_id,
                &entity.target,
                record_id,
                &marker,
                "checked",
                None,
            )
            .await?;
        }
    }

    if left || scanning {
        return come_back(state, job.wave_id, job.round).await;
    }
    Ok(())
}

/// Records one copy step. A file already recorded is left as it is.
async fn mark(
    state: &EngineState,
    project_id: Uuid,
    entity: &str,
    record_id: Uuid,
    source_file_id: &str,
    status: &str,
    error: Option<&str>,
) -> Result<bool, AppError> {
    let inserted = sqlx::query(
        "INSERT INTO migration_file_copy (id, project_id, entity, record_id, source_file_id, status, error) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (project_id, entity, record_id, source_file_id) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(project_id)
    .bind(entity)
    .bind(record_id)
    .bind(source_file_id)
    .bind(status)
    .bind(error)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(inserted == 1)
}

/// Copies one record's source files that the project has not copied yet.
#[allow(clippy::too_many_arguments)]
async fn copy_record(
    state: &EngineState,
    connector: &mut (
             dyn attome_integration::connector::adapters::migration_source::SourceConnector + '_
         ),
    project_id: Uuid,
    actor: Uuid,
    source_entity: &str,
    entity: &str,
    record_id: Uuid,
    source_id: &str,
) -> Result<(), AppError> {
    let files = match connector.read_files(source_entity, source_id).await {
        Ok(files) => files,
        Err(e) => {
            tracing::warn!(%entity, %record_id, error = %e, "migration files: the source did not list the record's files");
            return Ok(());
        }
    };
    for file in files {
        // Claim the file first, so a second run never copies it twice.
        if !mark(
            state, project_id, entity, record_id, &file.id, "scanning", None,
        )
        .await?
        {
            continue;
        }
        let copied = async {
            let bytes = connector.download(&file).await?;
            attome_document::files::ingest(
                state,
                attome_records::entity_mutation::FileOwner::Staff(actor),
                entity,
                record_id,
                ATTACHMENTS,
                &file.name,
                file.content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream"),
                bytes,
            )
            .await
        }
        .await;
        match copied {
            Ok(session_id) => {
                sqlx::query(
                    "UPDATE migration_file_copy SET session_id = $1 \
                      WHERE project_id = $2 AND entity = $3 AND record_id = $4 AND source_file_id = $5",
                )
                .bind(session_id)
                .bind(project_id)
                .bind(entity)
                .bind(record_id)
                .bind(&file.id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
            Err(e) => {
                let reason = e.to_string();
                sqlx::query(
                    "UPDATE migration_file_copy SET status = 'failed', error = $1 \
                      WHERE project_id = $2 AND entity = $3 AND record_id = $4 AND source_file_id = $5",
                )
                .bind(&reason)
                .bind(project_id)
                .bind(entity)
                .bind(record_id)
                .bind(&file.id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
        }
    }
    Ok(())
}

/// Adds every scanned-clean copy's key to its record's `attachments`, marks
/// the refused and lapsed ones, and answers whether any is still waiting
/// for its scan.
async fn attach_scanned(
    state: &EngineState,
    ctx: &attome_server::security::SecurityContext,
    actor: Uuid,
    project_id: Uuid,
) -> Result<bool, AppError> {
    // copy id, entity, record, session status, final key
    type Row = (Uuid, String, Uuid, Option<String>, Option<String>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT c.id, c.entity, c.record_id, s.status, s.final_key \
           FROM migration_file_copy c \
           LEFT JOIN upload_session s ON s.id = c.session_id \
          WHERE c.project_id = $1 AND c.status = 'scanning' AND c.session_id IS NOT NULL \
          ORDER BY c.entity, c.record_id",
    )
    .bind(project_id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut waiting = false;
    let mut by_record: std::collections::BTreeMap<(String, Uuid), Vec<(Uuid, String)>> =
        std::collections::BTreeMap::new();
    for (id, entity, record_id, status, final_key) in rows {
        match (status.as_deref(), final_key) {
            (Some("clean"), Some(key)) => by_record
                .entry((entity, record_id))
                .or_default()
                .push((id, key)),
            // The scan refused it, or the session lapsed or is gone.
            (Some("rejected" | "expired"), _) | (None, _) => {
                sqlx::query(
                    "UPDATE migration_file_copy SET status = 'failed', error = $2 WHERE id = $1",
                )
                .bind(id)
                .bind(format!(
                    "the upload was {}",
                    status.as_deref().unwrap_or("lost")
                ))
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
            _ => waiting = true,
        }
    }
    for ((entity, record_id), copies) in by_record {
        let table = attome_core::quote_ident(&entity);
        let column = attome_core::quote_ident(ATTACHMENTS);
        let current: Option<(i64, Option<Value>)> = sqlx::query_as(&format!(
            "SELECT row_version, to_jsonb({column}) FROM {table} \
              WHERE id = $1 AND is_active IS NOT FALSE"
        ))
        .bind(record_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let Some((row_version, current)) = current else {
            continue;
        };
        let mut keys: Vec<Value> = current
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();
        for (_, key) in &copies {
            if !keys.iter().any(|k| k.as_str() == Some(key.as_str())) {
                keys.push(Value::String(key.clone()));
            }
        }
        match attome_records::entity_crud::update_record_for(
            state,
            ctx,
            actor,
            &entity,
            record_id,
            row_version,
            {
                let mut body = serde_json::Map::new();
                body.insert(ATTACHMENTS.to_owned(), Value::Array(keys));
                Value::Object(body)
            },
        )
        .await
        {
            Ok(_) => {
                let ids: Vec<Uuid> = copies.iter().map(|(id, _)| *id).collect();
                sqlx::query(
                    "UPDATE migration_file_copy SET status = 'attached' WHERE id = ANY($1)",
                )
                .bind(&ids)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
            // Someone changed the record meanwhile: the next run tries again.
            Err(AppError::VersionConflict) => waiting = true,
            Err(e) => {
                let reason = e.to_string();
                let ids: Vec<Uuid> = copies.iter().map(|(id, _)| *id).collect();
                sqlx::query(
                    "UPDATE migration_file_copy SET status = 'failed', error = $2 WHERE id = ANY($1)",
                )
                .bind(&ids)
                .bind(&reason)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
        }
    }
    Ok(waiting)
}
