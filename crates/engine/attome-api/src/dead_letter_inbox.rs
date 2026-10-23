//! M5-T2: one inbox over every dead-letter source (M5-T1).
//!
//! * `GET  /api/v1/admin/dead-letters/groups` — items grouped by
//!   `cause_group` (source + step + error kind), largest first.
//! * `GET  /api/v1/admin/dead-letters` — items, optionally of one source or
//!   one group.
//! * `POST /api/v1/admin/dead-letters/{source}/{id}/replay` — one item.
//! * `POST /api/v1/admin/dead-letters/{source}/{id}/discard` — one item,
//!   with a required reason.
//! * `POST /api/v1/admin/dead-letters/groups/replay` — a whole group: the
//!   first item is replayed at once as the preview, and only when it went
//!   through are the rest queued as a Z7 batch job ([`GROUP_REPLAY_JOB`])
//!   that replays them at the asked rate, so a fixed endpoint is not hit by
//!   thousands of retries at once. Progress and cancel are the batch job's
//!   own `GET /api/v1/jobs/{id}` and `POST /api/v1/jobs/{id}/cancel`.
//!
//! Grouping reads at most [`SCAN_LIMIT`] items per source (newest first) and
//! says so in `warnings` when a source holds more. Each source audits its
//! own replay and discard (M5-T1); the group replay job replays as the
//! person who started it.

use std::time::Duration;

use attome_core::EngineState;
use attome_core::dead_letter::{DeadLetter, DeadLetterSource, ReplayOutcome};
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// The Z7 job type of a paced group replay
/// (payload [`GroupReplayPayload`]).
pub const GROUP_REPLAY_JOB: &str = "dead_letter_group_replay";

/// Items read per source when grouping or filtering by group.
pub const SCAN_LIMIT: i64 = 5_000;

/// The pace of a group replay, items per minute, when the caller names none.
pub const DEFAULT_RATE_PER_MINUTE: u32 = 60;
pub const MAX_RATE_PER_MINUTE: u32 = 600;

/// Items replayed between two pauses of a group replay.
const CHUNK: usize = 5;

/// Every dead-letter source this deployment has.
pub fn sources() -> Vec<Box<dyn DeadLetterSource>> {
    vec![
        Box::new(crate::jobs_admin::JobDeadLetters { batch: false }),
        Box::new(crate::jobs_admin::JobDeadLetters { batch: true }),
        Box::new(attome_workflow::dead_letter_source::FlowTriggerDeadLetters),
        Box::new(attome_workflow::dead_letter_source::FlowRunDeadLetters),
        Box::new(attome_events::dead_letter_source::WebhookDeadLetters),
    ]
}

fn source_named(name: &str) -> Result<Box<dyn DeadLetterSource>, AppError> {
    sources()
        .into_iter()
        .find(|s| s.source() == name)
        .ok_or(AppError::NotFound)
}

/// One group of items that failed the same way.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct DeadLetterGroup {
    pub cause_group: String,
    pub source: String,
    pub step: Option<String>,
    pub error_kind: String,
    pub count: i64,
    /// The oldest and newest first failure in the group.
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// The newest item's message, as a sample of the group's failure.
    pub sample_message: Option<String>,
}

/// Groups `items` by `cause_group`, largest group first (then newest).
pub fn group(items: &[DeadLetter]) -> Vec<DeadLetterGroup> {
    let mut groups: Vec<DeadLetterGroup> = Vec::new();
    for item in items {
        match groups
            .iter_mut()
            .find(|g| g.cause_group == item.cause_group)
        {
            Some(g) => {
                g.count += 1;
                if item.first_seen < g.first_seen {
                    g.first_seen = item.first_seen;
                }
                if item.first_seen > g.last_seen {
                    g.last_seen = item.first_seen;
                    g.sample_message = item.message.clone();
                }
            }
            None => groups.push(DeadLetterGroup {
                cause_group: item.cause_group.clone(),
                source: item.source.clone(),
                step: item.step.clone(),
                error_kind: item.error_kind.clone(),
                count: 1,
                first_seen: item.first_seen,
                last_seen: item.first_seen,
                sample_message: item.message.clone(),
            }),
        }
    }
    groups.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(b.last_seen.cmp(&a.last_seen))
            .then(a.cause_group.cmp(&b.cause_group))
    });
    groups
}

/// The source of a `cause_group` (`source:step:kind`).
fn group_source(cause_group: &str) -> Option<&str> {
    cause_group.split(':').next().filter(|s| !s.is_empty())
}

/// Up to [`SCAN_LIMIT`] items of each source in `wanted` (all when `None`),
/// with a warning per source that holds more.
async fn scan(
    state: &EngineState,
    wanted: Option<&str>,
) -> Result<(Vec<DeadLetter>, Vec<String>), AppError> {
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    for source in sources() {
        if wanted.is_some_and(|w| w != source.source()) {
            continue;
        }
        let found = source.list(state, 0, SCAN_LIMIT).await?;
        if found.len() as i64 == SCAN_LIMIT && source.count(state).await? > SCAN_LIMIT {
            warnings.push(format!(
                "{} holds more than {SCAN_LIMIT} dead letters; only the newest {SCAN_LIMIT} are grouped",
                source.source()
            ));
        }
        items.extend(found);
    }
    Ok((items, warnings))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct InboxQuery {
    /// Only this source (`jobs`, `batch_jobs`, `flow_trigger`, `flow_run`,
    /// `webhook`).
    pub source: Option<String>,
    /// Only this group (a `cause_group` from the groups list).
    pub group: Option<String>,
    /// One-based: page 1 is the first page.
    pub page: Option<i64>,
    pub page_size: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/dead-letters/groups",
    tag = "admin",
    operation_id = "dead_letter_groups",
    description = "Dead letters from every source grouped by cause (source, step and error kind), largest group first (M5-T2).",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The groups", body = PaginatedResponse<DeadLetterGroup>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_groups(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<DeadLetterGroup>>, AppError> {
    let w = page.window();
    let (items, warnings) = scan(&state, None).await?;
    let groups = group(&items);
    let total = groups.len() as i64;
    let page_items = groups
        .into_iter()
        .skip(usize::try_from(w.offset).unwrap_or(0))
        .take(usize::try_from(w.page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse {
        items: page_items,
        total,
        page: w.page,
        page_size: w.page_size,
        warnings,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/dead-letters",
    tag = "admin",
    operation_id = "dead_letter_items",
    description = "Dead letters, newest first, of one source or one group, or of every source (M5-T2).",
    params(InboxQuery),
    responses(
        (status = 200, description = "The dead letters", body = PaginatedResponse<DeadLetter>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such source", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_items(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(q): Query<InboxQuery>,
) -> Result<Json<PaginatedResponse<DeadLetter>>, AppError> {
    let w = OnePageQuery {
        page: q.page,
        page_size: q.page_size,
    }
    .window();
    // One source and no group: the source pages itself.
    if let (Some(name), None) = (q.source.as_deref(), q.group.as_deref()) {
        let source = source_named(name)?;
        let items = source.list(&state, w.offset, w.page_size).await?;
        let total = source.count(&state).await?;
        return Ok(Json(PaginatedResponse::new(
            items,
            total,
            w.page,
            w.page_size,
        )));
    }
    let wanted = q
        .source
        .as_deref()
        .or(q.group.as_deref().and_then(group_source));
    if let Some(name) = wanted {
        source_named(name)?;
    }
    let (mut items, warnings) = scan(&state, wanted).await?;
    if let Some(group) = q.group.as_deref() {
        items.retain(|i| i.cause_group == group);
    }
    items.sort_by(|a, b| b.first_seen.cmp(&a.first_seen));
    let total = items.len() as i64;
    let page_items = items
        .into_iter()
        .skip(usize::try_from(w.offset).unwrap_or(0))
        .take(usize::try_from(w.page_size).unwrap_or(0))
        .collect();
    Ok(Json(PaginatedResponse {
        items: page_items,
        total,
        page: w.page,
        page_size: w.page_size,
        warnings,
    }))
}

/// What replaying one item did.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReplayItemResult {
    /// `replayed`, `not_dead_lettered` or `refused`.
    pub outcome: String,
    /// Why the source refused, for `refused`.
    pub reason: Option<String>,
}

impl From<ReplayOutcome> for ReplayItemResult {
    fn from(outcome: ReplayOutcome) -> Self {
        match outcome {
            ReplayOutcome::Replayed => Self {
                outcome: "replayed".into(),
                reason: None,
            },
            ReplayOutcome::NotDeadLettered => Self {
                outcome: "not_dead_lettered".into(),
                reason: None,
            },
            ReplayOutcome::Refused(why) => Self {
                outcome: "refused".into(),
                reason: Some(why.into()),
            },
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/dead-letters/{source}/{id}/replay",
    tag = "admin",
    operation_id = "dead_letter_replay",
    description = "Runs one dead letter again (M5-T2).",
    params(("source" = String, Path), ("id" = String, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Execute)])))),
    responses(
        (status = 200, description = "Replayed", body = ReplayItemResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such source or dead letter", body = ErrorResponse),
        (status = 409, description = "The source refused the replay; the reason is in the body", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn replay_item(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((source, id)): Path<(String, String)>,
) -> Result<Json<ReplayItemResult>, AppError> {
    let source = source_named(&source)?;
    match source.replay(&state, &id, ctx.user_id).await? {
        ReplayOutcome::NotDeadLettered => Err(AppError::NotFound),
        ReplayOutcome::Refused(why) => Err(AppError::Conflict(why)),
        outcome => Ok(Json(outcome.into())),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DiscardBody {
    /// Why the dead letter is dropped; kept on the audit event.
    pub reason: String,
}

fn checked_reason(reason: &str) -> Result<&str, AppError> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(AppError::Validation("reason is required".into()));
    }
    if reason.chars().count() > 500 {
        return Err(AppError::Validation(
            "reason must be at most 500 characters".into(),
        ));
    }
    Ok(reason)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/dead-letters/{source}/{id}/discard",
    tag = "admin",
    operation_id = "dead_letter_discard",
    description = "Drops one dead letter, with the reason on its audit event (M5-T2). A flow run is cancelled; every other item is deleted.",
    params(("source" = String, Path), ("id" = String, Path)),
    request_body = DiscardBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::HardDelete)])))),
    responses(
        (status = 204, description = "Discarded"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such source or dead letter", body = ErrorResponse),
        (status = 422, description = "The reason is missing or too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn discard_item(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path((source, id)): Path<(String, String)>,
    Json(body): Json<DiscardBody>,
) -> Result<StatusCode, AppError> {
    let reason = checked_reason(&body.reason)?;
    let source = source_named(&source)?;
    if source.discard(&state, &id, ctx.user_id, reason).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GroupReplayBody {
    /// The group to replay, from the groups list.
    pub cause_group: String,
    /// Items per minute after the preview; default 60, at most 600.
    pub rate_per_minute: Option<u32>,
}

/// What a group replay started.
#[derive(Debug, Serialize, ToSchema)]
pub struct GroupReplayStarted {
    /// The first item, replayed at once.
    pub preview: ReplayItemResult,
    /// The batch job replaying the rest (`GET /api/v1/jobs/{id}`); `None`
    /// when the preview was the group's only item.
    pub job_id: Option<Uuid>,
    /// Items the job will replay.
    pub queued: i64,
    pub rate_per_minute: u32,
}

/// A group replay job's work: the item ids snapshotted at start, so an item
/// that fails again is not retried in a loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupReplayPayload {
    pub batch_id: Uuid,
    pub actor: Uuid,
    pub source: String,
    pub ids: Vec<String>,
    pub rate_per_minute: u32,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/dead-letters/groups/replay",
    tag = "admin",
    operation_id = "dead_letter_group_replay",
    description = "Replays a whole group (M5-T2): the first item at once as a preview; when it goes through, the rest as a batch job at the given rate.",
    request_body = GroupReplayBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Execute)])))),
    responses(
        (status = 202, description = "The preview went through and the rest is queued", body = GroupReplayStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such group", body = ErrorResponse),
        (status = 409, description = "The preview was refused; nothing was queued", body = ErrorResponse),
        (status = 422, description = "The rate is out of range", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn replay_group(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<GroupReplayBody>,
) -> Result<(StatusCode, Json<GroupReplayStarted>), AppError> {
    let rate = body.rate_per_minute.unwrap_or(DEFAULT_RATE_PER_MINUTE);
    if !(1..=MAX_RATE_PER_MINUTE).contains(&rate) {
        return Err(AppError::Validation(format!(
            "rate_per_minute must be between 1 and {MAX_RATE_PER_MINUTE}"
        )));
    }
    let name = group_source(&body.cause_group).ok_or(AppError::NotFound)?;
    let source = source_named(name)?;
    let mut ids: Vec<String> = source
        .list(&state, 0, SCAN_LIMIT)
        .await?
        .into_iter()
        .filter(|i| i.cause_group == body.cause_group)
        .map(|i| i.id)
        .collect();
    // Oldest first, so the replay follows the order things failed in.
    ids.reverse();
    if ids.is_empty() {
        return Err(AppError::NotFound);
    }
    let first = ids.remove(0);
    let preview = source.replay(&state, &first, ctx.user_id).await?;
    if let ReplayOutcome::Refused(why) = preview {
        return Err(AppError::Conflict(why));
    }
    let queued = ids.len() as i64;
    let job_id = if ids.is_empty() {
        None
    } else {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let batch_id =
            attome_jobs::batch::start(&mut tx, GROUP_REPLAY_JOB, Some(queued), Some(ctx.user_id))
                .await
                .map_err(AppError::internal)?;
        let payload = GroupReplayPayload {
            batch_id,
            actor: ctx.user_id,
            source: source.source().to_string(),
            ids,
            rate_per_minute: rate,
        };
        // Built here, not through the registry: a process that only serves
        // the API may not have registered the job type (the worker has).
        let job = attome_jobs::RegisteredJob {
            name: GROUP_REPLAY_JOB.to_string(),
            version: 1,
            payload: serde_json::to_value(&payload).map_err(AppError::internal)?,
            next: None,
        };
        attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
            .await
            .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        Some(batch_id)
    };
    Ok((
        StatusCode::ACCEPTED,
        Json(GroupReplayStarted {
            preview: preview.into(),
            job_id,
            queued,
            rate_per_minute: rate,
        }),
    ))
}

/// The pause before each chunk after the first, so `rate_per_minute` items
/// are replayed a minute.
pub fn pause_per_chunk(rate_per_minute: u32) -> Duration {
    let rate = u64::from(rate_per_minute.clamp(1, MAX_RATE_PER_MINUTE));
    Duration::from_millis(60_000 * CHUNK as u64 / rate)
}

struct GroupReplayBatch<'a> {
    state: &'a EngineState,
    source: Box<dyn DeadLetterSource>,
    payload: GroupReplayPayload,
}

impl attome_jobs::batch::BatchJob for GroupReplayBatch<'_> {
    type Chunk = Vec<String>;

    async fn next_chunk(
        &self,
        checkpoint: Option<&serde_json::Value>,
    ) -> Result<Option<(Self::Chunk, serde_json::Value)>, attome_jobs::registry::BoxError> {
        let at = checkpoint
            .and_then(|c| c["next"].as_u64())
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0);
        if at >= self.payload.ids.len() {
            return Ok(None);
        }
        if at > 0 {
            tokio::time::sleep(pause_per_chunk(self.payload.rate_per_minute)).await;
        }
        let end = (at + CHUNK).min(self.payload.ids.len());
        Ok(Some((
            self.payload.ids[at..end].to_vec(),
            serde_json::json!({ "next": end }),
        )))
    }

    /// Each replay commits in its source's own transaction with its audit
    /// event; the runner's `tx` only carries the checkpoint.
    async fn process(
        &self,
        _tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ids: Self::Chunk,
    ) -> Result<i64, attome_jobs::registry::BoxError> {
        let mut done = 0;
        for id in ids {
            match self
                .source
                .replay(self.state, &id, self.payload.actor)
                .await
            {
                Ok(ReplayOutcome::Replayed) => done += 1,
                Ok(other) => tracing::info!(
                    source = %self.payload.source,
                    %id,
                    ?other,
                    "dead-letter group replay: item not replayed"
                ),
                Err(error) => tracing::warn!(
                    source = %self.payload.source,
                    %id,
                    %error,
                    "dead-letter group replay: item failed, it stays in the dead letters"
                ),
            }
        }
        Ok(done)
    }
}

/// Runs a group replay job (registered by the binary under
/// [`GROUP_REPLAY_JOB`]).
pub async fn run_group_replay(
    state: &EngineState,
    payload: GroupReplayPayload,
) -> Result<(), attome_jobs::registry::BoxError> {
    let source = source_named(&payload.source)
        .map_err(|e| Box::new(e) as attome_jobs::registry::BoxError)?;
    let batch_id = payload.batch_id;
    let job = GroupReplayBatch {
        state,
        source,
        payload,
    };
    attome_jobs::batch::run(&state.base.db, batch_id, &job).await?;
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/dead-letters", get(list_items))
        .route("/api/v1/admin/dead-letters/groups", get(list_groups))
        .route(
            "/api/v1/admin/dead-letters/groups/replay",
            post(replay_group),
        )
        .route(
            "/api/v1/admin/dead-letters/{source}/{id}/replay",
            post(replay_item),
        )
        .route(
            "/api/v1/admin/dead-letters/{source}/{id}/discard",
            post(discard_item),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_groups, list_items, replay_item, discard_item, replay_group))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn item(group: &str, minute: u32, message: &str) -> DeadLetter {
        let mut parts = group.split(':');
        let source = parts.next().unwrap_or_default();
        let step = parts.next().filter(|s| *s != "-").map(str::to_string);
        DeadLetter {
            source: source.into(),
            id: format!("{group}-{minute}"),
            step,
            error_kind: parts.next().unwrap_or_default().into(),
            cause_group: group.into(),
            message: Some(message.into()),
            first_seen: Utc
                .with_ymd_and_hms(2026, 10, 23, 9, minute, 0)
                .single()
                .unwrap_or_default(),
            attempts: 1,
            payload_ref: None,
        }
    }

    #[test]
    fn dead_letter_inbox_groups_largest_first_with_the_newest_sample() {
        let items = vec![
            item("webhook:s1:timeout", 1, "old"),
            item("jobs:SendEmail:connect", 2, "only"),
            item("webhook:s1:timeout", 5, "new"),
        ];
        let groups = group(&items);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].cause_group, "webhook:s1:timeout");
        assert_eq!(groups[0].count, 2);
        assert_eq!(groups[0].sample_message.as_deref(), Some("new"));
        assert!(groups[0].first_seen < groups[0].last_seen);
        assert_eq!(groups[1].count, 1);
    }

    #[test]
    fn dead_letter_inbox_names_the_source_of_a_group() {
        assert_eq!(group_source("flow_run:v/n:timeout"), Some("flow_run"));
        assert_eq!(group_source(""), None);
    }

    #[test]
    fn dead_letter_inbox_paces_chunks_to_the_rate() {
        assert_eq!(pause_per_chunk(60), Duration::from_secs(5));
        assert_eq!(pause_per_chunk(600), Duration::from_millis(500));
        assert_eq!(
            pause_per_chunk(0),
            Duration::from_secs(300),
            "clamped to 1 a minute"
        );
    }

    #[test]
    fn dead_letter_inbox_requires_a_reason_to_discard() {
        assert!(checked_reason("   ").is_err());
        assert!(checked_reason(&"x".repeat(501)).is_err());
        assert_eq!(
            checked_reason("  endpoint retired ").ok(),
            Some("endpoint retired")
        );
    }

    #[test]
    fn dead_letter_inbox_knows_every_source() {
        let names: Vec<&str> = sources().iter().map(|s| s.source()).collect();
        assert_eq!(
            names,
            ["jobs", "batch_jobs", "flow_trigger", "flow_run", "webhook"]
        );
    }
}
