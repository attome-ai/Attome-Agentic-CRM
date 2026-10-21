//! AI6-T3: briefs made before meetings, unasked.
//!
//! [`scan`] (job `ai_meeting_brief_scan`, every 15 minutes) finds meetings
//! starting 60 to 75 minutes from now that are not cancelled and have no
//! `ai_meeting_brief` row, and queues one `ai_meeting_brief` job for each,
//! deduplicated on the meeting (`ai-meeting-brief:{meeting}`), so two scans
//! queue one job. A meeting whose owner turned briefs off
//! ([`BRIEFS_SETTING`], on by default) is skipped.
//!
//! [`run_brief`] runs `meeting.brief` **as the meeting owner**, through the
//! gate (as an agent with a `Reversible` ceiling), so the AI switch, the
//! licence, the owner's grants and their budget all apply, the way G1-T3
//! summarises a case as its assignee. A refusal is the owner's normal state
//! and is not retried. Once the brief is written the owner gets an in-app
//! notice linking to the meeting. The brief row itself is what keeps a later
//! scan from queueing the meeting again.

use std::sync::Arc;

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::RiskTier;
use crate::execute::{ActionOutcome, dispatch};

/// The scan's job name.
pub const SCAN_JOB: &str = "ai_meeting_brief_scan";
/// One meeting's brief job name.
pub const BRIEF_JOB: &str = "ai_meeting_brief";
/// AI6-T6: one transcript's notes job name.
pub const NOTES_JOB: &str = "ai_meeting_notes";
/// A user's (or the deployment's) switch for briefs made unasked.
pub const BRIEFS_SETTING: &str = "ai.meeting_briefs";
/// How far ahead a meeting is briefed, and the window one scan covers.
pub const LEAD_MINUTES: i64 = 60;
pub const WINDOW_MINUTES: i64 = 15;
/// Most meetings one scan queues.
pub const MAX_PER_SCAN: i64 = 200;

/// One meeting's brief job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BriefJob {
    pub meeting_id: Uuid,
}

/// AI6-T6: notes asked for from a transcript, made as the person who asked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotesJob {
    pub meeting_id: Uuid,
    pub transcript_ref: Uuid,
    pub user_id: Uuid,
}

/// The queue key that keeps one notes job per meeting, transcript and
/// person waiting. Pure.
pub fn notes_key(job: &NotesJob) -> String {
    format!(
        "ai-meeting-notes:{}:{}:{}",
        job.meeting_id, job.transcript_ref, job.user_id
    )
}

/// Queues a notes job; its key, and whether it was newly queued.
pub async fn queue_notes(state: &EngineState, job: &NotesJob) -> Result<(String, bool), AppError> {
    let key = notes_key(job);
    let registered = attome_core::jobs::JOB_TYPES
        .job(NOTES_JOB, job)
        .map_err(AppError::internal)?;
    let queued = attome_jobs::enqueue_dedup(
        &state.base.db,
        attome_core::jobs::EngineJob::Registered(registered),
        &key,
    )
    .await
    .map_err(AppError::internal)?;
    Ok((key, queued))
}

/// Runs `meeting.notes` for a queued job, as the person who asked, through
/// the gate. A refusal (no access, no AI, no budget, confirmed already) is
/// logged and not retried; `Ok(false)` says the notes were not made.
pub async fn run_notes(state: &EngineState, job: &NotesJob) -> Result<bool, AppError> {
    let security = state.base.security.resolve(job.user_id).await?;
    let ctx = ActionContext::user(security);
    let action = super::notes::MEETING_NOTES;
    let module = crate::engine::REGISTRY
        .resolve(action)
        .map(|d| d.module)
        .ok_or(AppError::NotFound)?;
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, module);
    let args = json!({ "meeting_id": job.meeting_id, "transcript_ref": job.transcript_ref });
    match dispatch(
        state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        action,
        &ctx,
        &inputs,
        &args,
    )
    .await
    {
        Ok(ActionOutcome::Completed { .. }) => Ok(true),
        Ok(_) => Ok(false),
        Err(
            error @ (AppError::NotFound
            | AppError::Forbidden
            | AppError::Validation(_)
            | AppError::Conflict(_)),
        ) => {
            tracing::info!(meeting = %job.meeting_id, %error, "meeting notes: not made");
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// The start times one scan at `now` briefs: `[now + 60m, now + 75m)`.
/// Pure.
pub fn window(now: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
    let from = now + Duration::minutes(LEAD_MINUTES);
    (from, from + Duration::minutes(WINDOW_MINUTES))
}

/// The queue key that keeps a meeting to one brief job. Pure.
pub fn dedup_key(meeting: Uuid) -> String {
    format!("ai-meeting-brief:{meeting}")
}

/// Whether `user` takes briefs made unasked: their own choice, else the
/// deployment's, else yes.
pub fn briefs_on(state: &EngineState, user: Uuid) -> bool {
    let Some(descriptor) = attome_core::setting_registry().get(BRIEFS_SETTING) else {
        return true;
    };
    let (value, _source) = state.settings.load().resolve(descriptor, Some(user), None);
    value.as_bool().unwrap_or(true)
}

/// One scan; how many brief jobs it queued.
pub async fn scan(state: &EngineState, now: DateTime<Utc>) -> Result<u64, AppError> {
    {
        let registry = state.entities.load();
        if registry.get("activity").is_none() || registry.get("ai_meeting_brief").is_none() {
            return Ok(0);
        }
    }
    let (from, to) = window(now);
    let due: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "SELECT a.id, COALESCE(a.owner_ref, a.created_by) FROM activity a \
          WHERE a.activity_type::text = 'meeting' \
            AND COALESCE(a.status::text, '') <> 'cancelled' \
            AND a.due_at >= $1 AND a.due_at < $2 \
            AND (a.is_active IS NULL OR a.is_active = true) \
            AND NOT EXISTS (SELECT 1 FROM ai_meeting_brief b \
                             WHERE b.meeting_entity = 'activity' AND b.meeting_id = a.id::text \
                               AND (b.is_active IS NULL OR b.is_active = true)) \
          ORDER BY a.due_at, a.id LIMIT $3",
    )
    .bind(from)
    .bind(to)
    .bind(MAX_PER_SCAN)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut queued = 0;
    for (meeting_id, owner) in due {
        let Some(owner) = owner else { continue };
        if !briefs_on(state, owner) {
            continue;
        }
        let job = attome_core::jobs::JOB_TYPES
            .job(BRIEF_JOB, &BriefJob { meeting_id })
            .map_err(AppError::internal)?;
        if attome_jobs::enqueue_dedup(
            &state.base.db,
            attome_core::jobs::EngineJob::Registered(job),
            &dedup_key(meeting_id),
        )
        .await
        .map_err(AppError::internal)?
        {
            queued += 1;
        }
    }
    Ok(queued)
}

/// Makes one meeting's brief as its owner and tells them. `Ok(false)` when
/// it was not made: the meeting is gone, its owner turned briefs off, or the
/// gate refused.
pub async fn run_brief(state: &EngineState, meeting_id: Uuid) -> Result<bool, AppError> {
    let row: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT COALESCE(owner_ref, created_by), subject FROM activity \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(meeting_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(owner), subject)) = row else {
        return Ok(false);
    };
    if !briefs_on(state, owner) {
        return Ok(false);
    }
    let security = state.base.security.resolve(owner).await?;
    let outcome = brief_as(state, security, meeting_id).await;
    match outcome {
        Ok(true) => {}
        Ok(false) => return Ok(false),
        // A refusal (no AI, no licence, no budget, no access) is the owner's
        // normal state, not a failure to retry.
        Err(error @ (AppError::NotFound | AppError::Forbidden | AppError::Validation(_))) => {
            tracing::debug!(%meeting_id, %error, "meeting brief: not made");
            return Ok(false);
        }
        Err(error) => return Err(error),
    }
    notify(state, owner, meeting_id, subject.as_deref()).await;
    Ok(true)
}

/// Dispatches `meeting.brief` through the gate as an agent of `security`.
async fn brief_as(
    state: &EngineState,
    security: Arc<attome_server::security::SecurityContext>,
    meeting_id: Uuid,
) -> Result<bool, AppError> {
    let ctx = ActionContext::agent(security, RiskTier::Reversible);
    let action = super::brief::MEETING_BRIEF;
    let module = crate::engine::REGISTRY
        .resolve(action)
        .map(|d| d.module)
        .ok_or(AppError::NotFound)?;
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = crate::engine::gate_inputs(state, module);
    let args: Value = json!({ "meeting_id": meeting_id });
    Ok(matches!(
        dispatch(
            state,
            &crate::engine::REGISTRY,
            &crate::engine::EXECUTORS,
            action,
            &ctx,
            &inputs,
            &args,
        )
        .await?,
        ActionOutcome::Completed { .. }
    ))
}

/// The owner's in-app notice. Best effort: the brief is already on the
/// meeting.
async fn notify(state: &EngineState, owner: Uuid, meeting_id: Uuid, subject: Option<&str>) {
    let locale = state.user_locale(owner);
    let subject = subject.filter(|s| !s.trim().is_empty());
    let (title, body) = if locale.starts_with("ar") {
        let subject = subject.unwrap_or("اجتماعك");
        (
            format!("الموجز جاهز: {subject}"),
            format!("موجز {subject} جاهز. افتح الاجتماع لقراءته."),
        )
    } else {
        let subject = subject.unwrap_or("your meeting");
        (
            format!("Brief ready: {subject}"),
            format!("Your brief for {subject} is ready. Open the meeting to read it."),
        )
    };
    let req = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale,
        recipient_user_ref: Some(owner),
        is_global: false,
        organization_ref: None,
        channels: Some(vec!["in_app".to_owned()]),
        subject: Some(title),
        body_html: None,
        body_text: Some(body),
        route: Some(format!("/activity/{meeting_id}")),
        variables: std::collections::HashMap::new(),
        priority: "normal".to_owned(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) = attome_notification::dispatch::create_dispatch(
        &state.base.db,
        &state.base.config.notification,
        req,
    )
    .await
    {
        tracing::warn!(%owner, %meeting_id, %error, "meeting brief: notice not sent");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scan_covers_the_fifteen_minutes_an_hour_ahead() {
        let now = DateTime::from_timestamp(1_800_000_000, 0).expect("a time");
        let (from, to) = window(now);
        assert_eq!(from - now, Duration::minutes(60));
        assert_eq!(to - now, Duration::minutes(75));
        // The next scan starts where this one ends: no meeting is missed.
        assert_eq!(window(now + Duration::minutes(15)).0, to);
    }

    #[test]
    fn one_job_key_per_meeting() {
        let m = Uuid::from_u128(5);
        assert_eq!(dedup_key(m), dedup_key(m));
        assert_ne!(dedup_key(m), dedup_key(Uuid::from_u128(6)));
        assert_eq!(
            serde_json::to_value(BriefJob { meeting_id: m }).expect("json"),
            json!({ "meeting_id": m })
        );
    }
}
