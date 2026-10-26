//! A23-T7: an import's phases as durable jobs, and recurring imports.
//!
//! Each phase is a registered job whose payload names the import
//! ([`PhaseJob`]), queued with the dedup key
//! `attome-records/import:{job_id}:{phase}` so a phase is never queued twice
//! while one waits. A phase that succeeds queues the next one: stage, then
//! validate, then apply, unless the run is a dry run or the entity's import
//! policy wants approval first (more staged rows than
//! `import_policy.approval_over_rows`): then the job waits in
//! `awaiting_approval`. Undo runs on its own.
//!
//! **Quiet hours.** `import_policy.quiet_hours` lists windows in the
//! deployment's time, `[{"start": "22:00", "end": "06:00"}]` (the
//! `jobs.quiet_windows` form). An apply that comes due inside one queues
//! itself again for the window's end and writes nothing.
//!
//! **Failures.** A phase refused for the job's own data (a mapping that
//! names no field, invalid rows in an all-or-nothing import) fails the job
//! with the reason and is not retried; a phase that finds the job already
//! past it does nothing; anything else is the queue's to retry.
//!
//! **Recurring imports.** A job whose `counts.schedule` holds
//! `{cron, time_zone?, source: {kind: "storage" | "https", location}}` is a
//! template: the minute tick ([`run_schedules`]) finds each template that
//! is due, claims the slot by moving `counts.schedule.last_run`, fetches the
//! file (an object in storage, or an `https` URL through the SSRF-guarded
//! client, never inside a transaction), stores it, and creates a new
//! `uploaded` job with the template's entity, mapping and options, which it
//! then stages. A file identical to one already imported finds the earlier
//! job (the `import_job_file_uq` index) and starts nothing.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The registered job names, one per phase, and the minute tick.
pub const STAGE_JOB: &str = "import_stage";
pub const VALIDATE_JOB: &str = "import_validate";
pub const APPLY_JOB: &str = "import_apply";
pub const UNDO_JOB: &str = "import_undo";
pub const SCHEDULE_JOB: &str = "import_schedule_tick";

/// The most bytes a recurring import fetches from an `https` source.
pub const MAX_FETCH_BYTES: usize = 50 * 1024 * 1024;

/// How long an `https` fetch may take.
pub const FETCH_TIMEOUT_SECS: u64 = 60;

/// One phase of an import.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Stage,
    Validate,
    Apply,
    Undo,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stage => "stage",
            Self::Validate => "validate",
            Self::Apply => "apply",
            Self::Undo => "undo",
        }
    }

    pub fn job_name(self) -> &'static str {
        match self {
            Self::Stage => STAGE_JOB,
            Self::Validate => VALIDATE_JOB,
            Self::Apply => APPLY_JOB,
            Self::Undo => UNDO_JOB,
        }
    }
}

/// A phase job's payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhaseJob {
    pub job_id: Uuid,
    /// Stop after validation.
    #[serde(default)]
    pub dry_run: bool,
}

/// The dedup key of `phase` for import `job_id`.
pub fn dedup_key(job_id: Uuid, phase: Phase) -> String {
    format!("attome-records/import:{job_id}:{}", phase.as_str())
}

fn registered(phase: Phase, job: &PhaseJob) -> Result<attome_jobs::RegisteredJob, AppError> {
    Ok(attome_jobs::RegisteredJob {
        name: phase.job_name().to_owned(),
        version: 1,
        payload: serde_json::to_value(job).map_err(AppError::internal)?,
        next: None,
    })
}

/// Queues `phase` for the import, once while one waits. Answers whether it
/// was queued (false: one already waits).
pub async fn enqueue(db: &DbPool, phase: Phase, job: &PhaseJob) -> Result<bool, AppError> {
    attome_jobs::enqueue_dedup(
        db,
        attome_core::jobs::EngineJob::Registered(registered(phase, job)?),
        &dedup_key(job.job_id, phase),
    )
    .await
    .map_err(AppError::internal)
}

/// The minutes from `minute` (after midnight) to the end of the open window
/// it falls in, or `None` when none is open. Pure.
pub fn minutes_to_window_end(windows: &[(u16, u16)], minute: u16) -> Option<u16> {
    windows
        .iter()
        .filter(|&&(start, end)| attome_core::quiet_window::in_window(&[(start, end)], minute))
        .map(|&(_, end)| (end + 1440 - minute) % 1440)
        .max()
}

/// When an apply due now must wait for the entity's quiet hours to end.
async fn quiet_until(state: &EngineState, entity: &str) -> Result<Option<DateTime<Utc>>, AppError> {
    use chrono::Timelike;
    let hours: Option<Value> =
        sqlx::query_scalar("SELECT quiet_hours FROM import_policy WHERE entity_logicalname = $1")
            .bind(entity)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .flatten();
    let windows = hours
        .map(|h| attome_core::quiet_window::windows_of(&h))
        .unwrap_or_default();
    if windows.is_empty() {
        return Ok(None);
    }
    let now = attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref());
    let minute = u16::try_from(now.hour() * 60 + now.minute()).unwrap_or(0);
    Ok(minutes_to_window_end(&windows, minute)
        .map(|wait| Utc::now() + chrono::Duration::minutes(i64::from(wait.max(1)))))
}

/// Whether the entity's policy wants approval before this import applies.
async fn needs_approval(state: &EngineState, job_id: Uuid, entity: &str) -> Result<bool, AppError> {
    let over: Option<i32> = sqlx::query_scalar(
        "SELECT approval_over_rows FROM import_policy WHERE entity_logicalname = $1",
    )
    .bind(entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let Some(over) = over else {
        return Ok(false);
    };
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM import_stage WHERE job_id = $1")
        .bind(job_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(rows > i64::from(over))
}

async fn set_status(state: &EngineState, job_id: Uuid, status: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE import_job SET status = $2, row_version = row_version + 1 WHERE id = $1")
        .bind(job_id)
        .bind(status)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

async fn fail(state: &EngineState, job_id: Uuid, reason: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE import_job SET status = 'failed', finished_at = now(), \
                counts = counts || jsonb_build_object('error', $2::text), \
                row_version = row_version + 1 \
          WHERE id = $1 AND status NOT IN ('applied', 'undone', 'cancelled')",
    )
    .bind(job_id)
    .bind(reason)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn run_phase(state: &EngineState, phase: Phase, job: &PhaseJob) -> Result<(), AppError> {
    let id = job.job_id;
    match phase {
        Phase::Stage => {
            crate::import_stage::stage(state, id).await?;
            enqueue(&state.base.db, Phase::Validate, job).await?;
        }
        Phase::Validate => {
            attome_records::import_validate::validate(state, id).await?;
            if job.dry_run {
                return Ok(());
            }
            let entity: String =
                sqlx::query_scalar("SELECT entity_logicalname FROM import_job WHERE id = $1")
                    .bind(id)
                    .fetch_one(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
            if needs_approval(state, id, &entity).await? {
                set_status(state, id, "awaiting_approval").await?;
                return Ok(());
            }
            enqueue(&state.base.db, Phase::Apply, job).await?;
        }
        Phase::Apply => {
            let entity: String =
                sqlx::query_scalar("SELECT entity_logicalname FROM import_job WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&state.base.db)
                    .await
                    .map_err(AppError::internal)?
                    .ok_or(AppError::NotFound)?;
            if let Some(at) = quiet_until(state, &entity).await? {
                attome_jobs::enqueue_at_on_pool(
                    &state.base.db,
                    attome_core::jobs::EngineJob::Registered(registered(Phase::Apply, job)?),
                    at,
                )
                .await
                .map_err(AppError::internal)?;
                tracing::info!(job_id = %id, %at, "import apply waits for the quiet hours to end");
                return Ok(());
            }
            attome_records::import_apply::apply(state, id).await?;
        }
        Phase::Undo => {
            attome_records::import_undo::undo(state, id).await?;
        }
    }
    Ok(())
}

/// Runs one phase job (see the module doc for how failures end).
pub async fn run(state: &EngineState, phase: Phase, job: &PhaseJob) -> Result<(), AppError> {
    match run_phase(state, phase, job).await {
        Ok(()) => Ok(()),
        // The job already moved past this phase (a duplicate delivery).
        Err(AppError::Conflict(reason)) => {
            tracing::info!(job_id = %job.job_id, phase = phase.as_str(), reason, "import phase skipped");
            Ok(())
        }
        Err(AppError::NotFound) => Ok(()),
        Err(AppError::Validation(reason)) => {
            tracing::warn!(job_id = %job.job_id, phase = phase.as_str(), %reason, "import failed");
            fail(state, job.job_id, &reason).await
        }
        Err(other) => Err(other),
    }
}

// ── Recurring imports ─────────────────────────────────────────────────────────

/// Where a recurring import reads its file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Source {
    /// An object key in this deployment's storage.
    Storage { location: String },
    /// A public `https` URL.
    Https { location: String },
}

/// A template job's `counts.schedule`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecurringSchedule {
    pub cron: String,
    /// The schedule's time zone; the deployment's when absent.
    #[serde(default)]
    pub time_zone: Option<String>,
    pub source: Source,
    /// The slot last claimed.
    #[serde(default)]
    pub last_run: Option<DateTime<Utc>>,
}

/// The slot a schedule is due for at `now`, after `last` (the template's
/// creation when it never ran). Pure.
pub fn due_slot(
    schedule: &RecurringSchedule,
    deployment_tz: Option<&str>,
    created_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let tz = schedule
        .time_zone
        .as_deref()
        .or(deployment_tz)
        .unwrap_or("UTC");
    let parsed = attome_jobs::schedule::Schedule::cron(&schedule.cron, tz)
        .map_err(|e| AppError::Validation(format!("schedule: {}", e.0)))?;
    let after = schedule.last_run.unwrap_or(created_at);
    Ok(parsed.next_after(after).filter(|slot| *slot <= now))
}

/// The file name a source's location ends in. Pure.
fn file_name_of(location: &str) -> String {
    let path = location.split(['?', '#']).next().unwrap_or(location);
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("import.csv")
        .chars()
        .take(200)
        .collect()
}

async fn fetch_https(location: &str) -> Result<Vec<u8>, String> {
    let url =
        reqwest::Url::parse(location).map_err(|_| "the source URL does not parse".to_owned())?;
    if url.scheme() != "https" {
        return Err("a source URL is https".into());
    }
    let client = attome_server::ssrf_guard::GuardedClient::new(FETCH_TIMEOUT_SECS)
        .map_err(|_| "no HTTP client".to_owned())?;
    let mut res = client
        .get(url)
        .map_err(|_| "the URL reaches a private address".to_owned())?
        .send()
        .await
        .map_err(|_| "the source did not answer".to_owned())?;
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status().as_u16()));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|_| "the download broke off".to_owned())?
    {
        if bytes.len() + chunk.len() > MAX_FETCH_BYTES {
            return Err("the file is larger than 50 MiB".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[derive(sqlx::FromRow)]
struct TemplateRow {
    id: Uuid,
    schedule: Value,
    created_at: DateTime<Utc>,
}

/// Runs one due template: fetch, store, create the job, stage it. Answers
/// the new job's id, or `None` when the file was imported before.
async fn run_template(
    state: &EngineState,
    template: Uuid,
    schedule: &RecurringSchedule,
) -> Result<Option<Uuid>, AppError> {
    let bytes = match &schedule.source {
        Source::Storage { location } => {
            attome_storage::mirror::read_object(&state.base.storage, location)
                .await
                .map_err(AppError::internal)?
        }
        Source::Https { location } => fetch_https(location)
            .await
            .map_err(|reason| AppError::Validation(format!("source: {reason}")))?,
    };
    let location = match &schedule.source {
        Source::Storage { location } | Source::Https { location } => location,
    };
    let file_name = file_name_of(location);
    let sha = hex::encode(Sha256::digest(&bytes));
    let id = Uuid::now_v7();
    let key = format!("imports/{id}/{file_name}");
    attome_storage::mirror::write_object(&state.base.storage, &key, bytes)
        .await
        .map_err(AppError::internal)?;
    let created: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO import_job (id, entity_logicalname, storage_key, file_name, file_sha256, \
                                 encoding, sheet, mapping_ref, mapping, match_mode, match_columns, \
                                 all_or_nothing, triggers_on, status, counts, created_by) \
         SELECT $1, t.entity_logicalname, $2, $3, $4, t.encoding, t.sheet, t.mapping_ref, \
                t.mapping, t.match_mode, t.match_columns, t.all_or_nothing, t.triggers_on, \
                'uploaded', jsonb_build_object('scheduled_from', t.id), t.created_by \
           FROM import_job t WHERE t.id = $5 \
         ON CONFLICT (entity_logicalname, file_sha256) \
             WHERE status NOT IN ('failed', 'cancelled', 'undone') DO NOTHING \
         RETURNING id",
    )
    .bind(id)
    .bind(&key)
    .bind(&file_name)
    .bind(&sha)
    .bind(template)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(created) = created else {
        // The same file again: nothing new to import.
        if let Err(error) = attome_storage::mirror::delete_object(&state.base.storage, &key).await {
            tracing::warn!(%error, %key, "recurring import: the unused copy was not deleted");
        }
        return Ok(None);
    };
    enqueue(
        &state.base.db,
        Phase::Stage,
        &PhaseJob {
            job_id: created,
            dry_run: false,
        },
    )
    .await?;
    Ok(Some(created))
}

/// The minute tick: runs every recurring import that is due. Answers how
/// many new jobs it created.
pub async fn run_schedules(state: &EngineState) -> Result<usize, AppError> {
    let templates: Vec<TemplateRow> = sqlx::query_as(
        "SELECT id, counts->'schedule' AS schedule, created_at FROM import_job \
          WHERE counts ? 'schedule' AND status <> 'cancelled' \
          ORDER BY created_at LIMIT 500",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let now = Utc::now();
    let mut created = 0;
    for template in templates {
        let schedule: RecurringSchedule = match serde_json::from_value(template.schedule.clone()) {
            Ok(s) => s,
            Err(error) => {
                tracing::warn!(template = %template.id, %error, "recurring import: the schedule does not parse");
                continue;
            }
        };
        let slot = match due_slot(
            &schedule,
            state.base.config.app.time_zone.as_deref(),
            template.created_at,
            now,
        ) {
            Ok(Some(slot)) => slot,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(template = %template.id, %error, "recurring import: bad schedule");
                continue;
            }
        };
        // Claim the slot: only the node that moves last_run runs it.
        let claimed = sqlx::query(
            "UPDATE import_job \
                SET counts = jsonb_set(counts, '{schedule,last_run}', to_jsonb($2::timestamptz)) \
              WHERE id = $1 \
                AND (counts->'schedule'->'last_run') IS NOT DISTINCT FROM $3::jsonb",
        )
        .bind(template.id)
        .bind(slot)
        .bind(template.schedule.get("last_run").cloned())
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if claimed.rows_affected() != 1 {
            continue;
        }
        match run_template(state, template.id, &schedule).await {
            Ok(Some(job)) => {
                tracing::info!(template = %template.id, %job, "recurring import started");
                created += 1;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(template = %template.id, %error, "recurring import: this run failed");
            }
        }
    }
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_apply_inside_quiet_hours_waits_for_their_end() {
        let windows = [(22 * 60, 6 * 60)];
        assert_eq!(minutes_to_window_end(&windows, 23 * 60), Some(7 * 60));
        assert_eq!(minutes_to_window_end(&windows, 5 * 60 + 30), Some(30));
        assert_eq!(minutes_to_window_end(&windows, 12 * 60), None);
    }

    #[test]
    fn a_schedule_is_due_once_its_next_slot_has_passed() {
        let created = "2026-10-26T00:00:00Z".parse().unwrap();
        let schedule = RecurringSchedule {
            cron: "0 6 * * *".into(),
            time_zone: Some("UTC".into()),
            source: Source::Storage {
                location: "imports/daily.csv".into(),
            },
            last_run: None,
        };
        let before = "2026-10-26T05:59:00Z".parse().unwrap();
        assert_eq!(due_slot(&schedule, None, created, before).unwrap(), None);
        let after: DateTime<Utc> = "2026-10-26T06:01:00Z".parse().unwrap();
        let slot = due_slot(&schedule, None, created, after).unwrap().unwrap();
        assert_eq!(
            slot,
            "2026-10-26T06:00:00Z".parse::<DateTime<Utc>>().unwrap()
        );
        let ran = RecurringSchedule {
            last_run: Some(slot),
            ..schedule
        };
        assert_eq!(due_slot(&ran, None, created, after).unwrap(), None);
    }

    #[test]
    fn a_source_names_its_file() {
        assert_eq!(
            file_name_of("https://x.example/feeds/accounts.csv?t=1"),
            "accounts.csv"
        );
        assert_eq!(file_name_of("imports/daily.xlsx"), "daily.xlsx");
        let job: PhaseJob =
            serde_json::from_value(serde_json::json!({"job_id": Uuid::nil()})).unwrap();
        assert!(!job.dry_run);
        assert_eq!(
            dedup_key(Uuid::nil(), Phase::Apply),
            format!("attome-records/import:{}:apply", Uuid::nil())
        );
    }
}
