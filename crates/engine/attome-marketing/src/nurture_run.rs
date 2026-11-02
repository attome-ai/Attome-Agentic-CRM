//! E9-T3: the nurture drip.
//!
//! A nurture programme's journey runs one `marketing.nurture_run` step
//! (config `purpose`, the consent purpose, and optionally `program_id`;
//! without it, the programme whose `journey_ref` is the run's definition).
//! The step puts the person in the programme (`marketing_nurture_state`, on
//! the track that fits them, due now) and waits for the named event
//! [`done_event`]. The drip itself is not a loop of graph nodes: every
//! minute [`tick`] claims the states that are due (moving `next_due_at` ten
//! minutes on, in one short statement, so no transaction is held while
//! sending) and, for each, sends the first email of the person's track they
//! have neither seen ([`record_seen`]: an open or click of an email from the
//! same saved design) nor been sent by this programme, then makes the next
//! one due after the programme's cadence. Each send goes through the
//! journey rules (consent, suppression, sunset, quiet hours, weekly cap) and
//! claims `(program, person:design)` in `marketing_message_log` in the same
//! transaction that queues it, so a retried tick never sends twice. With
//! nothing left to send the state stays, due again after the cadence, for
//! content added later.
//!
//! When a state leaves `active` (a hand-off, a customer leaving an
//! acquisition programme, a retired programme), [`finished`] lists it until
//! the workflow engine has delivered the done event to its run
//! ([`mark_signalled`]); the app's tick job does that delivery, since this
//! crate sits below the workflow engine.
//!
//! Only email content is sent: an `article` or `event` item has no sender
//! and is passed over.

use attome_core::EngineState;
use attome_core::workflow_step::{StepFuture, StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_modules::{MODULE_MARKETING, ModuleId};
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::journey::rules::{RuleVerdict, check};

/// The step's node key.
pub const KEY: &str = "marketing.nurture_run";

/// The registered job that runs [`tick`] (every minute, one pending).
pub const TICK_JOB: &str = "marketing_nurture_tick";

/// States claimed per tick.
const BATCH: i64 = 1_000;

/// How long a claim holds a state before another tick may take it.
const CLAIM_MINUTES: i32 = 10;

/// The cadence when the programme sets none.
const DEFAULT_CADENCE_DAYS: f64 = 7.0;

/// The `message_log` source kind of a nurture send.
const SOURCE_KIND: &str = "nurture";

/// The event a run's step waits for: its state has left `active`.
pub fn done_event(instance: Uuid) -> String {
    format!("nurture.done:{instance}")
}

/// The time between two sends, from the programme's `cadence_days`
/// (an hour to a year). Pure.
pub fn cadence(days: Option<f64>) -> Duration {
    let days = days
        .filter(|d| d.is_finite() && *d > 0.0)
        .unwrap_or(DEFAULT_CADENCE_DAYS)
        .clamp(1.0 / 24.0, 365.0);
    Duration::seconds((days * 86_400.0).round() as i64)
}

/// A step's configuration, checked. Pure.
pub fn config_problem(config: &Value) -> Option<&'static str> {
    if config
        .get("purpose")
        .and_then(Value::as_str)
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        return Some("purpose names the consent purpose");
    }
    match config.get("program_id") {
        None | Some(Value::Null) => None,
        Some(v) => v
            .as_str()
            .and_then(|s| Uuid::parse_str(s.trim()).ok())
            .map_or(Some("program_id names a nurture programme"), |_| None),
    }
}

fn uuid_in(value: &Value, key: &str) -> Option<Uuid> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

/// The programme the step names, or the one whose journey is the run's
/// definition.
async fn program_of(
    state: &EngineState,
    config: &Value,
    instance: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let named = uuid_in(config, "program_id");
    sqlx::query_scalar(
        "SELECT p.id FROM marketing_nurture_program p \
          WHERE p.is_active IS NOT FALSE \
            AND (p.id = $1 OR ($1 IS NULL AND p.journey_ref = ( \
                 SELECT v.definition_id FROM workflow_instance i \
                   JOIN workflow_definition_version v ON v.id = i.definition_version_id \
                  WHERE i.id = $2))) \
          ORDER BY p.id LIMIT 1",
    )
    .bind(named)
    .bind(instance)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The track that fits the person in the programme, if one does.
async fn track_for(
    db: &attome_db::DbPool,
    program: Uuid,
    entity: &str,
    person: Uuid,
) -> Result<Option<Uuid>, AppError> {
    let tracks = crate::nurture_tracks::tracks_of(db, program).await?;
    let facts = crate::nurture_tracks::person_facts(db, entity, person)
        .await?
        .unwrap_or_default();
    Ok(crate::nurture_tracks::best_track(&tracks, &facts))
}

/// What became of a person's entry into a programme.
enum Entry {
    /// The person is in, under this run.
    Entered,
    /// The person is already being nurtured by another run.
    AlreadyIn,
}

/// Puts the person in the programme under this run: a new state, a state
/// that had left `active` started again (what they have seen still
/// counts), or this run's own state found again on a replay.
#[allow(clippy::too_many_arguments)]
async fn enter(
    db: &attome_db::DbPool,
    program: Uuid,
    person: Uuid,
    entity: &str,
    purpose: &str,
    track: Option<Uuid>,
    instance: Uuid,
    enrolment: Option<Uuid>,
) -> Result<Entry, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let inserted = sqlx::query(
        "INSERT INTO marketing_nurture_state \
            (program_id, person_id, enrolment_id, track_id, position, next_due_at, status, \
             instance_id, person_entity, purpose) \
         VALUES ($1, $2, $3, $4, 0, now(), 'active', $5, $6, $7) \
         ON CONFLICT (program_id, person_id) DO NOTHING",
    )
    .bind(program)
    .bind(person)
    .bind(enrolment)
    .bind(track)
    .bind(instance)
    .bind(entity)
    .bind(purpose)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if inserted == 1 {
        attome_db::tx::commit(tx).await?;
        return Ok(Entry::Entered);
    }
    let current: Option<(String, Option<Uuid>)> = sqlx::query_as(
        "SELECT status, instance_id FROM marketing_nurture_state \
          WHERE program_id = $1 AND person_id = $2 FOR UPDATE",
    )
    .bind(program)
    .bind(person)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let entry = match current {
        Some((_, Some(run))) if run == instance => Entry::Entered,
        Some((status, Some(_))) if status == "active" => Entry::AlreadyIn,
        _ => {
            sqlx::query(
                "UPDATE marketing_nurture_state \
                    SET status = 'active', enrolment_id = $3, track_id = $4, position = 0, \
                        next_due_at = now(), paused_reason = NULL, instance_id = $5, \
                        person_entity = $6, purpose = $7, done_signalled_at = NULL \
                  WHERE program_id = $1 AND person_id = $2",
            )
            .bind(program)
            .bind(person)
            .bind(enrolment)
            .bind(track)
            .bind(instance)
            .bind(entity)
            .bind(purpose)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            Entry::Entered
        }
    };
    attome_db::tx::commit(tx).await?;
    Ok(entry)
}

/// The nurture step.
#[derive(Debug)]
pub struct NurtureRun;

impl WorkflowStepHandler for NurtureRun {
    fn key(&self) -> &'static str {
        KEY
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn config_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "purpose": { "type": "string", "title": "Consent purpose" },
                "program_id": { "type": "string", "format": "uuid", "title": "Nurture programme" }
            },
            "required": ["purpose"]
        })
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        config_problem(config).map_or(Ok(()), |p| Err(p.to_owned()))
    }
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            if let Some(problem) = config_problem(&inv.config) {
                return Err(AppError::Validation(problem.into()));
            }
            let purpose = inv.config["purpose"].as_str().unwrap_or_default().trim();
            let Some(person) = inv.correlation_entity_id else {
                return Ok(StepOutcome::Blocked {
                    reason: "the run has no person".into(),
                    continue_after: true,
                });
            };
            let entity = inv.input["person_entity"].as_str().unwrap_or("contact");
            let Some(program) = program_of(state, &inv.config, inv.instance_id).await? else {
                return Ok(StepOutcome::Blocked {
                    reason: "no nurture programme names this journey".into(),
                    continue_after: true,
                });
            };
            if inv.simulate || inv.input["is_test"].as_bool() == Some(true) {
                return Ok(StepOutcome::Done(json!({
                    "would": "start nurture",
                    "program_id": program,
                })));
            }
            let db = &state.base.db;
            let track = track_for(db, program, entity, person).await?;
            let enrolment = uuid_in(&inv.input, "enrolment_id");
            match enter(
                db,
                program,
                person,
                entity,
                purpose,
                track,
                inv.instance_id,
                enrolment,
            )
            .await?
            {
                Entry::AlreadyIn => Ok(StepOutcome::Done(json!({
                    "program_id": program,
                    "already_nurtured": true,
                }))),
                Entry::Entered => Ok(StepOutcome::Waiting {
                    resume_at: None,
                    wait_event: Some(done_event(inv.instance_id)),
                }),
            }
        })
    }
}

/// A claimed state: programme, person, track, person entity, purpose.
type Claimed = (
    Uuid,
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// One pass: claims the due states and sends each person's next email.
/// The number of emails queued.
pub async fn tick(state: &EngineState) -> Result<u64, AppError> {
    let db = &state.base.db;
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('marketing_nurture_content') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let claimed: Vec<Claimed> = sqlx::query_as(
        "WITH due AS ( \
            SELECT program_id, person_id FROM marketing_nurture_state \
             WHERE status = 'active' AND next_due_at <= now() \
             ORDER BY next_due_at LIMIT $1 FOR UPDATE SKIP LOCKED) \
         UPDATE marketing_nurture_state s \
            SET next_due_at = now() + make_interval(mins => $2) \
           FROM due WHERE s.program_id = due.program_id AND s.person_id = due.person_id \
         RETURNING s.program_id, s.person_id, s.track_id, s.person_entity, s.purpose, \
                   s.paused_reason",
    )
    .bind(BATCH)
    .bind(CLAIM_MINUTES)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut sent = 0;
    for claim in claimed {
        let (program, person) = (claim.0, claim.1);
        match drip_one(state, claim).await {
            Ok(true) => sent += 1,
            Ok(false) => {}
            // The claim lapses and a later tick tries again.
            Err(error) => {
                tracing::warn!(%error, %program, %person, "nurture: the next send failed");
            }
        }
    }
    Ok(sent)
}

/// Makes the state due again at `at`.
async fn due_at(
    db: &attome_db::DbPool,
    program: Uuid,
    person: Uuid,
    at: DateTime<Utc>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE marketing_nurture_state SET next_due_at = $3 \
          WHERE program_id = $1 AND person_id = $2 AND status = 'active'",
    )
    .bind(program)
    .bind(person)
    .bind(at)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Ends the state for `reason`; its run is told by [`finished`].
async fn exit(
    db: &attome_db::DbPool,
    program: Uuid,
    person: Uuid,
    reason: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE marketing_nurture_state SET status = 'exited', paused_reason = $3 \
          WHERE program_id = $1 AND person_id = $2 AND status = 'active'",
    )
    .bind(program)
    .bind(person)
    .bind(reason)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Sends the person's next email, if one is left and the rules allow it.
/// Whether an email was queued.
async fn drip_one(state: &EngineState, claim: Claimed) -> Result<bool, AppError> {
    let db = &state.base.db;
    let (program, person, track, entity, purpose, paused_reason) = claim;
    let now = Utc::now();
    let row: Option<(Option<String>, Option<f64>, bool)> = sqlx::query_as(
        "SELECT status, cadence_days::float8, COALESCE(pause_enabled, false) \
           FROM marketing_nurture_program WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(program)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((status, cadence_days, pause_enabled)) = row else {
        exit(db, program, person, "programme removed").await?;
        return Ok(false);
    };
    match status.as_deref() {
        Some("retired") => {
            exit(db, program, person, "programme retired").await?;
            return Ok(false);
        }
        Some("draft" | "paused") => {
            due_at(db, program, person, now + Duration::days(1)).await?;
            return Ok(false);
        }
        _ => {}
    }
    let every = cadence(cadence_days);
    let entity = entity.unwrap_or_else(|| "contact".to_owned());
    // E9-T6: while sales works the person, the drip holds and tries again
    // a day later; the pause and the resume are audited.
    let working = pause_enabled && sales_is_working(db, person).await?;
    if working != paused_reason.is_some() {
        set_paused(state, program, person, &entity, working).await?;
    }
    if working {
        due_at(db, program, person, now + Duration::days(1)).await?;
        return Ok(false);
    }
    let Some(purpose) = purpose.filter(|p| !p.trim().is_empty()) else {
        exit(db, program, person, "no consent purpose").await?;
        return Ok(false);
    };
    let track = match track {
        Some(track) => Some(track),
        None => track_for(db, program, &entity, person).await?,
    };
    let Some(track) = track else {
        // No track fits the person yet; a later change may make one fit.
        due_at(db, program, person, now + every).await?;
        return Ok(false);
    };

    let next: Option<(String, Option<f64>)> = sqlx::query_as(
        "SELECT lower(c.content_ref), c.position::float8 FROM marketing_nurture_content c \
          WHERE c.track_ref = $1 AND (c.is_active IS NULL OR c.is_active = true) \
            AND c.content_kind = 'email' \
            AND c.content_ref ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' \
            AND NOT EXISTS (SELECT 1 FROM marketing_content_seen s \
                             WHERE s.person_id = $2 AND s.content_kind = 'email' \
                               AND s.content_id = lower(c.content_ref)) \
            AND NOT EXISTS (SELECT 1 FROM marketing_message_log l \
                             WHERE l.source_kind = $4 AND l.source_id = $3 \
                               AND l.source_node = $2::text || ':' || lower(c.content_ref)) \
          ORDER BY c.position NULLS LAST, c.id LIMIT 1",
    )
    .bind(track)
    .bind(person)
    .bind(program)
    .bind(SOURCE_KIND)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((design, position)) = next else {
        // Everything sent or seen: the state stays for content added later.
        due_at(db, program, person, now + every).await?;
        return Ok(false);
    };
    let design_id = Uuid::parse_str(&design).map_err(AppError::internal)?;
    let (subject, locale, html, text) =
        match crate::journey::message_step::rendered(state, design_id).await {
            Ok(mail) => mail,
            Err(AppError::Validation(problem)) => {
                tracing::warn!(%program, %design_id, %problem, "nurture: content does not render");
                due_at(db, program, person, now + every).await?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
    let address: Option<String> = sqlx::query_scalar(&format!(
        "SELECT trim(email) FROM {} WHERE id = $1",
        attome_core::quote_ident(&entity)
    ))
    .bind(person)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let Some(address) = address.filter(|a| a.contains('@')) else {
        due_at(db, program, person, now + Duration::days(1)).await?;
        return Ok(false);
    };
    match check(state, &entity, person, &address, "email", &purpose, now).await? {
        RuleVerdict::Deferred(at) => {
            due_at(db, program, person, at).await?;
            return Ok(false);
        }
        RuleVerdict::Blocked(_) => {
            due_at(db, program, person, now + Duration::days(1)).await?;
            return Ok(false);
        }
        RuleVerdict::Allowed => {}
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let claimed = sqlx::query(
        "INSERT INTO marketing_message_log \
           (person_id, channel, purpose, source_kind, source_id, source_node) \
         VALUES ($1, 'email', $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(person)
    .bind(&purpose)
    .bind(SOURCE_KIND)
    .bind(program)
    .bind(format!("{person}:{design}"))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if claimed == 1 {
        let send_id: Uuid = sqlx::query_scalar(
            "INSERT INTO email_campaign_send \
               (list_id, subject, html_body, text_body, purpose_key, locale, design_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(program)
        .bind(&subject)
        .bind(&html)
        .bind(&text)
        .bind(&purpose)
        .bind(&locale)
        .bind(design_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query(
            "INSERT INTO email_campaign_recipient \
               (send_id, subject_entity, subject_id, email, unsubscribe_token) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(send_id)
        .bind(&entity)
        .bind(person)
        .bind(&address)
        .bind(format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "UPDATE marketing_nurture_state \
            SET track_id = $3, position = $4, next_due_at = $5 \
          WHERE program_id = $1 AND person_id = $2 AND status = 'active'",
    )
    .bind(program)
    .bind(person)
    .bind(track)
    .bind(position.map_or(0, |p| p.round().clamp(0.0, f64::from(i32::MAX)) as i32))
    .bind(now + every)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(claimed == 1)
}

/// E9-T6: whether sales is working the person: an active sales sequence
/// enrolment, a meeting about them in the last 14 days, or a hand-off of
/// theirs still pending or accepted. One indexed read each; a table this
/// deployment lacks counts as no.
pub async fn sales_is_working(db: &attome_db::DbPool, person: Uuid) -> Result<bool, AppError> {
    let (busy, has_activity): (bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM workflow_sequence_enrolment \
                         WHERE contact_id = $1 AND status = 'active') \
             OR EXISTS (SELECT 1 FROM marketing_handoff \
                         WHERE person_id = $1 AND status IN ('pending', 'accepted')), \
                to_regclass('activity') IS NOT NULL",
    )
    .bind(person)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if busy || !has_activity {
        return Ok(busy);
    }
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM activity a WHERE a.regarding_id = $1::text \
                          AND a.activity_type = 'meeting' AND a.is_active IS NOT FALSE \
                          AND a.activity_date > now() - interval '14 days')",
    )
    .bind(person)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)
}

/// Pauses (`true`) or resumes the person's drip, with its audit event.
async fn set_paused(
    state: &EngineState,
    program: Uuid,
    person: Uuid,
    entity: &str,
    paused: bool,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE marketing_nurture_state \
            SET paused_reason = CASE WHEN $3 THEN 'sales_working' ELSE NULL END \
          WHERE program_id = $1 AND person_id = $2",
    )
    .bind(program)
    .bind(person)
    .bind(paused)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            entity,
            person,
            attome_audit::AuditOperation::Update,
            if paused {
                "marketing.nurture_paused"
            } else {
                "marketing.nurture_resumed"
            },
            Uuid::nil(),
        )
        .comment(format!("nurture programme {program}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(())
}

/// A state that left `active` and whose run has not been told: programme,
/// person, run, status.
pub type Finished = (Uuid, Uuid, Uuid, String);

/// Up to `limit` states whose run still waits for [`done_event`].
pub async fn finished(db: &attome_db::DbPool, limit: i64) -> Result<Vec<Finished>, AppError> {
    sqlx::query_as(
        "SELECT program_id, person_id, instance_id, status FROM marketing_nurture_state \
          WHERE status <> 'active' AND instance_id IS NOT NULL AND done_signalled_at IS NULL \
          LIMIT $1",
    )
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Records that `instance` was told its state finished.
pub async fn mark_signalled(
    db: &attome_db::DbPool,
    program: Uuid,
    person: Uuid,
    instance: Uuid,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE marketing_nurture_state SET done_signalled_at = now() \
          WHERE program_id = $1 AND person_id = $2 AND instance_id = $3 \
            AND status <> 'active'",
    )
    .bind(program)
    .bind(person)
    .bind(instance)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Records that the person has seen a piece of content (once per item).
pub async fn record_seen(
    db: &attome_db::DbPool,
    person: Uuid,
    kind: &str,
    id: &str,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO marketing_content_seen (person_id, content_kind, content_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(person)
    .bind(kind)
    .bind(id.trim().to_lowercase())
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Records the email behind a recipient's tracking token as seen, when the
/// send came from a saved design.
pub async fn seen_from_token(db: &attome_db::DbPool, token: &str) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO marketing_content_seen (person_id, content_kind, content_id) \
         SELECT r.subject_id, 'email', s.design_id::text \
           FROM email_campaign_recipient r JOIN email_campaign_send s ON s.id = r.send_id \
          WHERE r.unsubscribe_token = $1 AND s.design_id IS NOT NULL \
         ON CONFLICT DO NOTHING",
    )
    .bind(token)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_step_names_its_purpose_and_maybe_its_programme() {
        assert_eq!(config_problem(&json!({ "purpose": "nurture" })), None);
        assert_eq!(
            config_problem(
                &json!({ "purpose": "nurture", "program_id": Uuid::now_v7().to_string() })
            ),
            None
        );
        assert!(config_problem(&json!({})).is_some());
        assert!(config_problem(&json!({ "purpose": " " })).is_some());
        assert!(config_problem(&json!({ "purpose": "n", "program_id": "x" })).is_some());
    }

    #[test]
    fn cadence_defaults_to_a_week_and_stays_in_bounds() {
        assert_eq!(cadence(None), Duration::days(7));
        assert_eq!(cadence(Some(3.0)), Duration::days(3));
        assert_eq!(cadence(Some(0.0)), Duration::days(7));
        assert_eq!(cadence(Some(0.001)), Duration::hours(1));
        assert_eq!(cadence(Some(10_000.0)), Duration::days(365));
    }

    #[test]
    fn the_done_event_names_the_run() {
        let run = Uuid::now_v7();
        assert_eq!(done_event(run), format!("nurture.done:{run}"));
    }

    /// E8-T13: every runnable marketing step describes its settings, each
    /// required key among its properties; a declared step with no run path
    /// says it is unavailable.
    #[test]
    fn every_marketing_step_describes_its_settings() {
        use crate::journey::{action_step, control_step, message_step};
        let runnable: Vec<Box<dyn WorkflowStepHandler>> = vec![
            Box::new(NurtureRun),
            Box::new(message_step::SendEmail),
            Box::new(control_step::WaitCalendar),
            Box::new(control_step::Engagement),
            Box::new(control_step::Split),
            Box::new(action_step::ListMembership { add: true }),
            Box::new(action_step::ListMembership { add: false }),
            Box::new(action_step::CampaignMembership),
        ];
        for step in runnable {
            let schema = step.config_schema();
            assert!(step.available(), "{}", step.key());
            assert_eq!(schema["type"], json!("object"), "{}", step.key());
            let properties = schema["properties"].as_object().expect("properties");
            for key in schema["required"].as_array().into_iter().flatten() {
                let key = key.as_str().unwrap_or_default();
                assert!(properties.contains_key(key), "{}: {key}", step.key());
            }
        }
        let declared = message_step::ChannelUnavailable {
            key: message_step::UNAVAILABLE_CHANNELS[0],
        };
        assert!(!declared.available());
        assert!(declared.config_schema().is_null());
    }
}
