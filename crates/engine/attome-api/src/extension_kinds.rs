//! M17-T1: running job and webhook extensions (`attome_extension::kinds`).
//!
//! - **Job.** [`EXTENSION_JOB`], a Z7 registered job type, runs the
//!   published version's `on_job` export with the job's input, as the user
//!   who queued it (`POST /api/v1/admin/extensions/{name}/jobs`).
//! - **Webhook.** An inbound hook's handler `{"type": "extension", "name":
//!   ...}` runs the extension's `on_webhook` export with the event, after the
//!   hook's own signature and replay checks, as the hook's service user.
//!
//! - **Schedule.** A manifest's `schedule` (`{cron, timezone, input}`) runs
//!   the job by itself: [`sweep_schedules`] (a minute sweep) claims each
//!   published extension's slot once across every worker through the
//!   schedule ledger (`extension:<name>`) and queues the job as the
//!   administrator who uploaded the published version.
//!
//! Either way the module only answers the records it wants written;
//! [`run_kind`] holds them to the extension's grants and makes them one by
//! one through the generic write path, so each is checked, validated and
//! audited as any write of that user. Writes made before one fails stay, so
//! the job is not retried (a failed run is in the dead letters and the run
//! log).

use attome_core::EngineState;
use attome_extension::kinds::{check_writes, parse_answer};
use attome_extension::{CallCost, Grants, Limits, Runtime};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use attome_extension::kinds::{JOB_EXPORT, WEBHOOK_EXPORT};

/// The job type that runs a job extension.
pub const EXTENSION_JOB: attome_jobs::JobType = attome_jobs::JobType {
    max_attempts: 1,
    ..attome_jobs::JobType::new("extension_job", 1)
};

/// One queued run of a job extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionJobPayload {
    pub name: String,
    /// The user the run writes as: whoever queued it.
    pub run_as: Uuid,
    #[serde(default)]
    pub input: Value,
}

/// The minute sweep that queues scheduled job extensions.
pub const SCHEDULE_SWEEP: attome_jobs::JobType =
    attome_jobs::JobType::new("extension_schedule_sweep", 1);

/// Claims every published extension's due schedule slot once and queues its
/// job. Answers how many were queued. A schedule that no longer parses is
/// skipped with a warning (it was checked at upload).
pub async fn sweep_schedules(state: &EngineState) -> Result<usize, AppError> {
    let rows: Vec<(String, Option<Uuid>, Value)> = sqlx::query_as(
        "SELECT name, created_by, manifest FROM extension \
          WHERE status = 'published' AND jsonb_typeof(manifest->'schedule') = 'object'",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut queued = 0;
    for (name, created_by, manifest) in rows {
        let Ok(grants) = serde_json::from_value::<Grants>(manifest) else {
            continue;
        };
        let (Some(schedule), Some(run_as)) = (grants.schedule, created_by) else {
            continue;
        };
        let when = match attome_jobs::schedule::Schedule::cron(&schedule.cron, &schedule.timezone) {
            Ok(when) => when,
            Err(error) => {
                tracing::warn!(extension = %name, %error, "an extension's schedule does not parse; skipped");
                continue;
            }
        };
        let job = attome_jobs::RegisteredJob {
            name: EXTENSION_JOB.name.to_owned(),
            version: EXTENSION_JOB.version,
            payload: serde_json::to_value(ExtensionJobPayload {
                name: name.clone(),
                run_as,
                input: schedule.input,
            })
            .map_err(AppError::internal)?,
            next: None,
        };
        let claimed = attome_jobs::schedule::tick_at(
            &state.base.db,
            &format!("extension:{name}"),
            &when,
            attome_core::jobs::EngineJob::Registered(job),
        )
        .await
        .map_err(AppError::internal)?;
        if claimed {
            queued += 1;
        }
    }
    Ok(queued)
}

/// Queues a run of the job extension `name`.
pub async fn queue_job(state: &EngineState, payload: &ExtensionJobPayload) -> Result<(), AppError> {
    let job = attome_jobs::RegisteredJob {
        name: EXTENSION_JOB.name.to_owned(),
        version: EXTENSION_JOB.version,
        payload: serde_json::to_value(payload).map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_on_pool(
        &state.base.db,
        attome_core::jobs::EngineJob::Registered(job),
    )
    .await
    .map_err(AppError::internal)
}

/// Runs the published version of `name`'s `export` with `input`, logs the
/// run, and makes the writes it asks for as `run_as`. Answers the ids
/// written.
pub async fn run_kind(
    state: &EngineState,
    name: &str,
    export: &str,
    run_as: Uuid,
    input: &Value,
) -> Result<Vec<Uuid>, AppError> {
    let row: Option<(i32, String, String, Value)> = sqlx::query_as(
        "SELECT version, module_key, module_sha256, manifest FROM extension \
          WHERE name = $1 AND status = 'published'",
    )
    .bind(name)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((version, key, sha, manifest)) = row else {
        return Err(AppError::Validation(format!(
            "the extension {name} is not published"
        )));
    };
    let grants: Grants = serde_json::from_value(manifest)
        .map_err(|e| AppError::Validation(format!("the stored manifest: {e}")))?;
    let module = crate::extension_hooks::load(state, &key, &sha).await?;
    let limits = Limits::from(&state.base.config.extensions);
    let bytes = serde_json::to_vec(input).map_err(AppError::internal)?;
    let export_name = export.to_owned();
    let (out, cost) = tokio::task::spawn_blocking(move || match Runtime::shared() {
        Ok(rt) => rt.call_json_measured(&module, &export_name, &bytes, &limits),
        Err(e) => (Err(e), CallCost::default()),
    })
    .await
    .map_err(AppError::internal)?;
    let answer = out
        .map_err(|e| e.to_string())
        .and_then(|out| parse_answer(&out))
        .and_then(|answer| check_writes(&grants, &answer).map(|()| answer));
    let error = answer.as_ref().err().cloned();
    if let Err(log_error) = crate::extension_admin::record_run(
        &state.base.db,
        name,
        version,
        cost,
        error.as_deref(),
        &[],
        &[],
        false,
    )
    .await
    {
        tracing::warn!(extension = %name, error = %log_error, "an extension run was not logged");
    }
    let answer =
        answer.map_err(|e| AppError::Validation(format!("the extension {name} failed: {e}")))?;

    let ctx = state.base.security.resolve(run_as).await?;
    let mut written = Vec::with_capacity(answer.records.len());
    for write in answer.records {
        let values = Value::Object(write.values);
        match write.id {
            None => {
                let (id, _) = attome_records::entity_crud::create_record_for(
                    state,
                    &ctx,
                    run_as,
                    &write.entity,
                    values,
                )
                .await?;
                written.push(id);
            }
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|_| {
                    AppError::Validation(format!("the extension {name} named a bad record id"))
                })?;
                let current =
                    attome_records::entity_crud::read_record(state, &ctx, &write.entity, id)
                        .await?;
                attome_records::entity_crud::update_record_for(
                    state,
                    &ctx,
                    run_as,
                    &write.entity,
                    id,
                    current.row_version(),
                    values,
                )
                .await?;
                written.push(id);
            }
        }
    }
    Ok(written)
}
