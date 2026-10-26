//! D17-T1: sales sequences — workflows of kind `sequence`.
//!
//! A sequence is an ordinary flow (its steps are ordinary nodes: send an
//! email, create a task, wait) that contacts are enrolled in, one run per
//! contact. [`enrol`] records one `workflow_sequence_enrolment` per contact
//! (one active enrolment per contact and sequence, held by a partial unique
//! index) and starts the contact's run in the same transaction.
//!
//! A contact leaves a sequence when they answer it. The exits that apply are
//! the published version's `settings.sequence.exit_on` (`reply`, `meeting`,
//! `stage_change`; all three when unset), copied onto the enrolment when it
//! is made. [`sweep`] reads the change feed (consumer [`CONSUMER`], run
//! every minute by [`SWEEP_JOB`]):
//!
//! - `reply`: an inbound `communication` filed on the contact (its own
//!   `entity_name`/`record_id`, or a `communication_link`);
//! - `meeting`: a `meeting` `activity` on the contact;
//! - `stage_change`: a change of an `opportunity`'s `stage`, for the
//!   contacts of the opportunity's account.
//!
//! An exit marks the enrolment `exited` with its reason; [`SequenceGuard`]
//! then ends the run before its next step, so a contact waiting between
//! steps is never sent the next one. The sweep also closes the enrolments
//! of runs that ended on their own: `completed`, or `stopped` with the run's
//! status for a failed or cancelled run.
//!
//! The `sequence.send_window` step waits until the contact's sending window
//! opens (by default 09:00 to 17:00, Sunday to Thursday) in the contact's
//! time zone: the contact's own `time_zone` field when the entity has one,
//! else their `country_code`'s zone from the regions pack
//! (`region_country.time_zone`), else the deployment's `app.time_zone`.

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_core::workflow_step::{
    GuardFuture, StepFuture, StepInvocation, StepOutcome, WorkflowKindGuard, WorkflowStepHandler,
};
use attome_modules::{MODULE_WORKFLOW, ModuleId};
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, NaiveTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The definition kind.
pub const KIND: &str = "sequence";
/// Every definition kind a workflow may have (the table's check).
pub const KINDS: [&str; 4] = ["flow", "journey", "nurture", KIND];
/// The change-feed consumer the exits read.
pub const CONSUMER: &str = "attome-workflow/sequence-exits";
/// The registered job that runs [`sweep`].
pub const SWEEP_JOB: &str = "workflow_sequence_exits";
/// The send-window step's node type.
pub const SEND_WINDOW_STEP: &str = "sequence.send_window";
/// Events read per sweep.
const BATCH: i64 = 500;

/// Why a contact leaves a sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExitOn {
    /// The contact answered: an inbound message filed on them.
    Reply,
    /// A meeting with the contact was booked.
    Meeting,
    /// A deal at the contact's account changed stage.
    StageChange,
}

impl ExitOn {
    pub const ALL: [ExitOn; 3] = [ExitOn::Reply, ExitOn::Meeting, ExitOn::StageChange];

    pub fn as_str(self) -> &'static str {
        match self {
            ExitOn::Reply => "reply",
            ExitOn::Meeting => "meeting",
            ExitOn::StageChange => "stage_change",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|e| e.as_str() == value.trim())
    }
}

/// The graph's `settings.sequence.exit_on`; every exit when unset. An
/// unknown name is a validation error, so a typo never silently drops an
/// exit.
pub fn exit_on(graph: &Value) -> Result<Vec<ExitOn>, String> {
    let Some(list) = graph.pointer("/settings/sequence/exit_on") else {
        return Ok(ExitOn::ALL.to_vec());
    };
    let items = list
        .as_array()
        .ok_or_else(|| "settings.sequence.exit_on is a list".to_owned())?;
    let mut out = Vec::new();
    for item in items {
        let name = item.as_str().unwrap_or_default();
        let exit = ExitOn::parse(name).ok_or_else(|| {
            format!("settings.sequence.exit_on: {name:?} is not reply, meeting or stage_change")
        })?;
        if !out.contains(&exit) {
            out.push(exit);
        }
    }
    Ok(out)
}

/// The exit a change event may signal, before its row is read. Pure.
pub fn signal_of(entity: &str, operation: ChangeOperation, changed: &[String]) -> Option<ExitOn> {
    let written = matches!(operation, ChangeOperation::Create | ChangeOperation::Update);
    match entity {
        "communication" if written => Some(ExitOn::Reply),
        "activity" if written => Some(ExitOn::Meeting),
        "opportunity"
            if operation == ChangeOperation::Update && changed.iter().any(|c| c == "stage") =>
        {
            Some(ExitOn::StageChange)
        }
        _ => None,
    }
}

/// A contact's sending window, in their time zone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendWindow {
    pub start: NaiveTime,
    pub end: NaiveTime,
    /// ISO weekdays (Monday 1 to Sunday 7).
    pub days: Vec<u32>,
}

impl Default for SendWindow {
    /// 09:00 to 17:00, Sunday to Thursday.
    fn default() -> Self {
        Self {
            start: NaiveTime::from_hms_opt(9, 0, 0).unwrap_or(NaiveTime::MIN),
            end: NaiveTime::from_hms_opt(17, 0, 0).unwrap_or(NaiveTime::MIN),
            days: vec![7, 1, 2, 3, 4],
        }
    }
}

impl SendWindow {
    /// The window a step's config names: `start` and `end` as `HH:MM`,
    /// `days` as ISO weekdays; each missing part keeps the default.
    pub fn from_config(config: &Value) -> Result<Self, String> {
        let mut window = Self::default();
        let time = |key: &str| -> Result<Option<NaiveTime>, String> {
            match config.get(key).and_then(Value::as_str) {
                None => Ok(None),
                Some(raw) => NaiveTime::parse_from_str(raw.trim(), "%H:%M")
                    .map(Some)
                    .map_err(|_| format!("{key} is a time as HH:MM")),
            }
        };
        if let Some(start) = time("start")? {
            window.start = start;
        }
        if let Some(end) = time("end")? {
            window.end = end;
        }
        if window.start >= window.end {
            return Err("start is before end".into());
        }
        if let Some(days) = config.get("days") {
            let days = days
                .as_array()
                .ok_or_else(|| "days is a list of weekdays (1 Monday to 7 Sunday)".to_owned())?;
            let mut parsed: Vec<u32> = Vec::new();
            for day in days {
                let day = day
                    .as_u64()
                    .and_then(|d| u32::try_from(d).ok())
                    .filter(|d| (1..=7).contains(d))
                    .ok_or_else(|| {
                        "days is a list of weekdays (1 Monday to 7 Sunday)".to_owned()
                    })?;
                if !parsed.contains(&day) {
                    parsed.push(day);
                }
            }
            if parsed.is_empty() {
                return Err("days names at least one weekday".into());
            }
            window.days = parsed;
        }
        Ok(window)
    }
}

/// `local` in `zone` as a UTC instant. A local time a clock change skips
/// moves to the first valid minute after it.
fn at_local<Z: TimeZone>(zone: &Z, local: NaiveDateTime) -> DateTime<Utc> {
    for minutes in [0, 30, 60, 90, 120] {
        if let Some(t) = zone
            .from_local_datetime(&(local + Duration::minutes(minutes)))
            .earliest()
        {
            return t.with_timezone(&Utc);
        }
    }
    local.and_utc()
}

/// When a message may go: `now` when it is inside the window in `zone`,
/// else the window's next opening. Pure.
pub fn next_send_time<Z: TimeZone>(
    now: DateTime<Utc>,
    zone: &Z,
    window: &SendWindow,
) -> DateTime<Utc> {
    let today = now.with_timezone(zone).date_naive();
    for offset in 0..8 {
        let date = today + Duration::days(offset);
        if !window.days.contains(&date.weekday().number_from_monday()) {
            continue;
        }
        let open = at_local(zone, date.and_time(window.start));
        if offset == 0 {
            if now < open {
                return open;
            }
            if now < at_local(zone, date.and_time(window.end)) {
                return now;
            }
            continue;
        }
        return open;
    }
    now
}

/// The deployment's zone: `app.time_zone`, else UTC.
fn deployment_zone(state: &EngineState) -> chrono_tz::Tz {
    state
        .base
        .config
        .app
        .time_zone
        .as_deref()
        .and_then(|z| z.trim().parse().ok())
        .unwrap_or(chrono_tz::UTC)
}

/// The contact's time zone; see the module doc.
pub async fn contact_zone(state: &EngineState, contact: Uuid) -> Result<chrono_tz::Tz, AppError> {
    let (own, country) = {
        let entities = state.entities.load();
        let has = |name: &str| {
            entities
                .get("contact")
                .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == name))
        };
        (
            has("time_zone"),
            has("country_code") && entities.get("region_country").is_some(),
        )
    };
    if own {
        let zone: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT time_zone::text FROM contact WHERE id = $1",
        )
        .bind(contact)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten();
        if let Some(tz) = zone.and_then(|z| z.trim().parse().ok()) {
            return Ok(tz);
        }
    }
    if country {
        let zone: Option<String> = sqlx::query_scalar::<_, Option<String>>(
            "SELECT r.time_zone::text FROM contact c \
               JOIN region_country r ON upper(r.code::text) = upper(c.country_code::text) \
              WHERE c.id = $1 LIMIT 1",
        )
        .bind(contact)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .flatten();
        if let Some(tz) = zone.and_then(|z| z.trim().parse().ok()) {
            return Ok(tz);
        }
    }
    Ok(deployment_zone(state))
}

/// `sequence.send_window`: waits until the contact's sending window opens.
/// Config `{start, end, days}`, each optional ([`SendWindow::from_config`]).
#[derive(Debug)]
pub struct SendWindowStep;

impl WorkflowStepHandler for SendWindowStep {
    fn key(&self) -> &'static str {
        SEND_WINDOW_STEP
    }
    fn module_id(&self) -> ModuleId {
        MODULE_WORKFLOW
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        SendWindow::from_config(config).map(|_| ())
    }
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            let window = SendWindow::from_config(&inv.config).map_err(AppError::Validation)?;
            let zone = match inv.correlation_entity_id {
                Some(contact) => contact_zone(state, contact).await?,
                None => deployment_zone(state),
            };
            let now = Utc::now();
            let at = next_send_time(now, &zone, &window);
            Ok(if at <= now + Duration::minutes(1) {
                StepOutcome::Done(json!({ "waited": false }))
            } else if inv.simulate {
                StepOutcome::Done(json!({ "would_wait_until": at, "time_zone": zone.name() }))
            } else {
                StepOutcome::Waiting {
                    resume_at: Some(at),
                    wait_event: None,
                }
            })
        })
    }
}

/// Registered for definition kind `sequence`: a run whose enrolment is no
/// longer active ends before its next step.
#[derive(Debug)]
pub struct SequenceGuard;

impl WorkflowKindGuard for SequenceGuard {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn before_node<'a>(
        &'a self,
        state: &'a EngineState,
        instance_id: Uuid,
        _correlation_entity_id: Option<Uuid>,
        _node_id: &'a str,
    ) -> GuardFuture<'a> {
        Box::pin(async move {
            let row: Option<(String, Option<String>)> = sqlx::query_as(
                "SELECT status, exit_reason FROM workflow_sequence_enrolment \
                  WHERE instance_id = $1 ORDER BY enrolled_at DESC LIMIT 1",
            )
            .bind(instance_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(match row {
                Some((status, reason)) if status != "active" => Some(format!(
                    "the contact left the sequence ({})",
                    reason.unwrap_or(status)
                )),
                _ => None,
            })
        })
    }
}

/// Enrolling contacts: `contact.update`, since the sequence writes to them.
#[derive(Debug)]
pub struct Enrol;

impl PrivilegeKey for Enrol {
    const KEY: &'static str = "contact.update";
}

/// The contacts to enrol.
#[derive(Debug, Deserialize, ToSchema)]
pub struct EnrolBody {
    /// At most 1,000 contacts.
    pub contact_ids: Vec<Uuid>,
}

/// What an enrolment did.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct EnrolOutcome {
    pub enrolled: u64,
    /// Already active in this sequence.
    pub skipped_active: u64,
    /// No such live contact.
    pub skipped_missing: u64,
}

/// Enrols `contacts` in the published sequence `logicalname` and starts
/// each one's run, as `enrolled_by`; see the module doc.
pub async fn enrol(
    state: &EngineState,
    logicalname: &str,
    contacts: &[Uuid],
    enrolled_by: Uuid,
) -> Result<EnrolOutcome, AppError> {
    let mut ids: Vec<Uuid> = contacts.to_vec();
    ids.sort();
    ids.dedup();
    if ids.is_empty() {
        return Err(AppError::Validation(
            "contact_ids names at least one contact".into(),
        ));
    }
    if ids.len() > attome_core::workflow_start::MAX_BATCH_START {
        return Err(AppError::Validation(format!(
            "at most {} contacts at a time",
            attome_core::workflow_start::MAX_BATCH_START
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (definition, version, graph): (Uuid, Uuid, Value) = sqlx::query_as(
        "SELECT d.id, v.id, v.graph FROM workflow_definition d \
           JOIN workflow_definition_version v ON v.definition_id = d.id AND v.status = 'published' \
          WHERE d.logicalname = $1 AND d.kind = 'sequence' \
            AND d.is_active = TRUE AND d.is_deleted = FALSE \
            FOR UPDATE OF d",
    )
    .bind(logicalname)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let exits: Vec<&str> = exit_on(&graph)
        .map_err(AppError::Validation)?
        .into_iter()
        .map(ExitOn::as_str)
        .collect();
    let live: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM contact WHERE id = ANY($1) AND is_active IS NOT FALSE")
            .bind(&ids)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let mut outcome = EnrolOutcome {
        skipped_missing: (ids.len() - live.len()) as u64,
        ..EnrolOutcome::default()
    };
    if live.is_empty() {
        return Ok(outcome);
    }
    // The partial unique index is the final word on one active enrolment.
    let inserted: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "INSERT INTO workflow_sequence_enrolment \
            (definition_id, definition_version_id, contact_id, status, exit_on, enrolled_by) \
         SELECT $1, $2, c, 'active', $4, $5 FROM UNNEST($3::uuid[]) AS c \
         ON CONFLICT (definition_id, contact_id) WHERE status = 'active' DO NOTHING \
         RETURNING id, contact_id",
    )
    .bind(definition)
    .bind(version)
    .bind(&live)
    .bind(&exits)
    .bind(enrolled_by)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    outcome.skipped_active = (live.len() - inserted.len()) as u64;
    if inserted.is_empty() {
        return Ok(outcome);
    }
    let items = inserted
        .iter()
        .map(|(enrolment, contact)| {
            (
                *contact,
                json!({ "sequence_enrolment_id": enrolment, "contact_id": contact }),
            )
        })
        .collect();
    let started = crate::instance_admin::start_instances_in_tx(
        state,
        &mut tx,
        logicalname,
        Some(enrolled_by),
        items,
    )
    .await?;
    let (people, instances): (Vec<Uuid>, Vec<Uuid>) = started.into_iter().unzip();
    sqlx::query(
        "UPDATE workflow_sequence_enrolment e SET instance_id = u.instance \
           FROM UNNEST($1::uuid[], $2::uuid[]) AS u(contact, instance) \
          WHERE e.definition_id = $3 AND e.contact_id = u.contact AND e.status = 'active'",
    )
    .bind(&people)
    .bind(&instances)
    .bind(definition)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    outcome.enrolled = inserted.len() as u64;
    Ok(outcome)
}

/// Marks the active enrolments of `contacts` that exit on `exit` as exited;
/// how many.
async fn exit(state: &EngineState, contacts: &[Uuid], reason: ExitOn) -> Result<u64, AppError> {
    if contacts.is_empty() {
        return Ok(0);
    }
    sqlx::query(
        "UPDATE workflow_sequence_enrolment \
            SET status = 'exited', exit_reason = $2, ended_at = now() \
          WHERE contact_id = ANY($1) AND status = 'active' AND $2 = ANY(exit_on)",
    )
    .bind(contacts)
    .bind(reason.as_str())
    .execute(&state.base.db)
    .await
    .map(|r| r.rows_affected())
    .map_err(AppError::internal)
}

fn has_entity(state: &EngineState, entity: &str) -> bool {
    state.entities.load().get(entity).is_some()
}

/// The contacts a change event answers for, by its exit.
async fn contacts_of(
    state: &EngineState,
    exit: ExitOn,
    record: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    let parse = |id: Option<String>| id.and_then(|s| Uuid::parse_str(s.trim()).ok());
    match exit {
        ExitOn::Reply => {
            let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT direction::text, entity_name::text, record_id::text \
                   FROM communication WHERE id = $1",
            )
            .bind(record)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let Some((direction, entity, record_id)) = row else {
                return Ok(Vec::new());
            };
            if direction.as_deref() != Some("inbound") {
                return Ok(Vec::new());
            }
            let mut contacts: Vec<Uuid> = sqlx::query_scalar(
                "SELECT record_id FROM communication_link \
                  WHERE communication_id = $1 AND entity_name = 'contact'",
            )
            .bind(record)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            if entity.as_deref() == Some("contact")
                && let Some(id) = parse(record_id)
            {
                contacts.push(id);
            }
            contacts.sort();
            contacts.dedup();
            Ok(contacts)
        }
        ExitOn::Meeting => {
            let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT activity_type::text, entity_name::text, record_id::text \
                   FROM activity WHERE id = $1",
            )
            .bind(record)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(match row {
                Some((Some(kind), Some(entity), record_id))
                    if kind == "meeting" && entity == "contact" =>
                {
                    parse(record_id).into_iter().collect()
                }
                _ => Vec::new(),
            })
        }
        ExitOn::StageChange => {
            if !state
                .entities
                .load()
                .get("contact")
                .is_some_and(|m| m.attrs.iter().any(|a| a.logicalname == "account_ref"))
            {
                return Ok(Vec::new());
            }
            sqlx::query_scalar(
                "SELECT e.contact_id FROM workflow_sequence_enrolment e \
                   JOIN contact c ON c.id = e.contact_id \
                   JOIN opportunity o ON o.account_ref = c.account_ref \
                  WHERE o.id = $1 AND e.status = 'active'",
            )
            .bind(record)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)
        }
    }
}

/// Closes the enrolments of runs that ended on their own; how many.
async fn close_finished(state: &EngineState) -> Result<u64, AppError> {
    sqlx::query(
        "UPDATE workflow_sequence_enrolment e \
            SET status = CASE WHEN i.status = 'completed' THEN 'completed' ELSE 'stopped' END, \
                exit_reason = CASE WHEN i.status = 'completed' THEN NULL ELSE i.status END, \
                ended_at = now() \
           FROM workflow_instance i \
          WHERE i.id = e.instance_id AND e.status = 'active' \
            AND i.status IN ('completed', 'failed', 'cancelled')",
    )
    .execute(&state.base.db)
    .await
    .map(|r| r.rows_affected())
    .map_err(AppError::internal)
}

/// What a sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepOutcome {
    pub exited: u64,
    pub closed: u64,
}

/// Exits the contacts the change feed shows answering since the last
/// sweep, then closes finished runs' enrolments; see the module doc.
pub async fn sweep(state: &EngineState) -> Result<SweepOutcome, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let mut outcome = SweepOutcome::default();
    if let Some(last) = events.last().cloned() {
        for event in &events {
            let Some(operation) = event.operation() else {
                continue;
            };
            let Some(signal) = signal_of(
                &event.entity_logicalname,
                operation,
                &event.changed_attributes,
            ) else {
                continue;
            };
            if !has_entity(state, &event.entity_logicalname) {
                continue;
            }
            let contacts = contacts_of(state, signal, event.record_id).await?;
            outcome.exited += exit(state, &contacts, signal).await?;
        }
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::advance(&mut conn, CONSUMER, &last).await?;
    }
    outcome.closed = close_finished(state).await?;
    Ok(outcome)
}

#[utoipa::path(
    post,
    path = "/api/v1/workflow/sequences/{logicalname}/enrolments",
    operation_id = "enrol_in_sequence",
    tag = "workflow",
    params(("logicalname" = String, Path, description = "The sequence's workflow")),
    request_body = EnrolBody,
    responses(
        (status = 200, description = "The contacts are enrolled and their runs started", body = EnrolOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks contact.update", body = ErrorResponse),
        (status = 404, description = "No published, active sequence with this name", body = ErrorResponse),
        (status = 422, description = "No contacts, more than 1,000, or the sequence's exits are invalid", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
/// Enrol contacts in a sequence.
///
/// Each contact gets one run of the sequence; a contact already active in it
/// is skipped. The contact leaves the sequence when they reply, a meeting
/// with them is booked, or a deal at their account changes stage (as the
/// sequence's `settings.sequence.exit_on` says).
async fn post_enrol(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<Enrol>>,
    Path(logicalname): Path<String>,
    Json(body): Json<EnrolBody>,
) -> Result<(StatusCode, Json<EnrolOutcome>), AppError> {
    let outcome = enrol(&state, logicalname.trim(), &body.contact_ids, ctx.user_id).await?;
    Ok((StatusCode::OK, Json(outcome)))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/workflow/sequences/{logicalname}/enrolments",
        post(post_enrol),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_enrol), components(schemas(EnrolBody, EnrolOutcome)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utc(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn sequence_exits_default_to_all() {
        assert_eq!(exit_on(&json!({})).unwrap(), ExitOn::ALL.to_vec());
        assert_eq!(
            exit_on(&json!({"settings": {"sequence": {"exit_on": ["reply", "reply"]}}})).unwrap(),
            vec![ExitOn::Reply]
        );
        assert!(exit_on(&json!({"settings": {"sequence": {"exit_on": ["replied"]}}})).is_err());
        assert!(exit_on(&json!({"settings": {"sequence": {"exit_on": "reply"}}})).is_err());
    }

    #[test]
    fn sequence_signals_by_entity() {
        let stage = vec!["stage".to_owned()];
        let amount = vec!["amount".to_owned()];
        assert_eq!(
            signal_of("communication", ChangeOperation::Create, &[]),
            Some(ExitOn::Reply)
        );
        assert_eq!(
            signal_of("activity", ChangeOperation::Update, &[]),
            Some(ExitOn::Meeting)
        );
        assert_eq!(
            signal_of("opportunity", ChangeOperation::Update, &stage),
            Some(ExitOn::StageChange)
        );
        assert_eq!(
            signal_of("opportunity", ChangeOperation::Update, &amount),
            None
        );
        assert_eq!(
            signal_of("opportunity", ChangeOperation::Create, &stage),
            None
        );
        assert_eq!(
            signal_of("communication", ChangeOperation::Delete, &[]),
            None
        );
        assert_eq!(signal_of("contact", ChangeOperation::Update, &stage), None);
    }

    #[test]
    fn sequence_window_config() {
        let w = SendWindow::from_config(&json!({})).unwrap();
        assert_eq!(w, SendWindow::default());
        let w = SendWindow::from_config(&json!({"start": "08:30", "days": [1, 1, 2]})).unwrap();
        assert_eq!(w.start, NaiveTime::from_hms_opt(8, 30, 0).unwrap());
        assert_eq!(w.days, vec![1, 2]);
        assert!(SendWindow::from_config(&json!({"start": "18:00"})).is_err());
        assert!(SendWindow::from_config(&json!({"days": []})).is_err());
        assert!(SendWindow::from_config(&json!({"days": [8]})).is_err());
        assert!(SendWindow::from_config(&json!({"end": "5pm"})).is_err());
    }

    #[test]
    fn sequence_window_in_contact_zone() {
        let riyadh = chrono_tz::Asia::Riyadh;
        let w = SendWindow::default();
        // Sunday 2026-10-25 10:00 Riyadh (07:00 UTC): inside, send now.
        let now = utc("2026-10-25T07:00:00Z");
        assert_eq!(next_send_time(now, &riyadh, &w), now);
        // Sunday 05:00 Riyadh: wait for 09:00 Riyadh (06:00 UTC).
        assert_eq!(
            next_send_time(utc("2026-10-25T02:00:00Z"), &riyadh, &w),
            utc("2026-10-25T06:00:00Z")
        );
        // Thursday 18:00 Riyadh: Friday and Saturday are off, so Sunday 09:00.
        assert_eq!(
            next_send_time(utc("2026-10-29T15:00:00Z"), &riyadh, &w),
            utc("2026-11-01T06:00:00Z")
        );
        // The same instant is inside the window in another zone.
        let london = chrono_tz::Europe::London;
        let weekdays = SendWindow::from_config(&json!({"days": [1, 2, 3, 4, 5]})).unwrap();
        // Thursday 15:00 UTC is 15:00 in London (GMT from 25 October).
        let thursday = utc("2026-10-29T15:00:00Z");
        assert_eq!(next_send_time(thursday, &london, &weekdays), thursday);
    }

    #[test]
    fn sequence_kind_is_known() {
        assert!(KINDS.contains(&KIND));
        assert_eq!(ExitOn::parse(" stage_change "), Some(ExitOn::StageChange));
        assert_eq!(ExitOn::parse("closed"), None);
    }
}
