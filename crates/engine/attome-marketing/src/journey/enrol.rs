//! Journey enrolment (roadmap E8-T4). [`enrol`] admits people into a live
//! journey and starts one workflow run each, in chunks of 1,000, each chunk
//! one transaction: the journey's definition row is locked (so two
//! enrolments of one journey cannot both read the same daily count), the
//! enrolments are inserted, the runs are started through the
//! `attome_core::workflow_start` seam in the same transaction, and each
//! enrolment records its run. Nothing is half-done: a chunk commits whole
//! or not at all, so a retried job never starts a person twice.
//!
//! Who is admitted ([`admit`], pure): never someone with an active run
//! (the partial unique index on `marketing_journey_enrolment` enforces it
//! too, so the check is not application-only); then the journey's
//! re-entry rule: `never` skips anyone enrolled before, `after_exit` only
//! the active, `after_cool_off` anyone whose last run ended within
//! `cool_off_days`; then the daily entry cap, counted from today's
//! enrolments. Test enrolments are kept apart: they never count toward the
//! cap and never block a real one.
//!
//! Large entries go through the `marketing_journey_enrol` job, queued in
//! chunks of 1,000 people by [`queue_enrol`].

use std::collections::{HashMap, HashSet};

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

/// The registered job's name.
pub const JOB: &str = "marketing_journey_enrol";
/// People per chunk (and per queued job).
pub const CHUNK: usize = attome_core::workflow_start::MAX_BATCH_START;

/// A person to enrol: a contact or a lead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonRef {
    pub id: Uuid,
    /// `contact` or `lead`.
    pub entity: String,
}

/// The journey's re-entry rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReEntry {
    Never,
    AfterExit,
    AfterCoolOff,
}

impl ReEntry {
    /// The stored choice; an unknown or empty value is the safest, `never`.
    pub fn parse(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            Some("after_exit") => Self::AfterExit,
            Some("after_cool_off") => Self::AfterCoolOff,
            _ => Self::Never,
        }
    }
}

/// A person's earlier run of the journey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prior {
    pub person: Uuid,
    pub active: bool,
    pub ended_at: Option<DateTime<Utc>>,
}

/// What one enrolment did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolOutcome {
    pub enrolled: u64,
    pub skipped_active: u64,
    pub skipped_re_entry: u64,
    pub skipped_cap: u64,
    pub skipped_invalid: u64,
}

impl EnrolOutcome {
    fn add(&mut self, other: Self) {
        self.enrolled += other.enrolled;
        self.skipped_active += other.skipped_active;
        self.skipped_re_entry += other.skipped_re_entry;
        self.skipped_cap += other.skipped_cap;
        self.skipped_invalid += other.skipped_invalid;
    }
}

/// Who of `people` may enter, in order, given their earlier runs, the
/// re-entry rule and the entries left today (`None`: no cap). Duplicates
/// and people who are not contacts or leads are left out. Pure.
pub fn admit(
    people: &[PersonRef],
    prior: &[Prior],
    rule: ReEntry,
    cool_off_days: i64,
    cap_left: Option<i64>,
    now: DateTime<Utc>,
) -> (Vec<PersonRef>, EnrolOutcome) {
    let mut outcome = EnrolOutcome::default();
    let mut runs: HashMap<Uuid, Vec<&Prior>> = HashMap::new();
    for p in prior {
        runs.entry(p.person).or_default().push(p);
    }
    let cool_off = Duration::days(cool_off_days.max(0));
    let mut seen = HashSet::new();
    let mut admitted = Vec::new();
    for person in people {
        if !matches!(person.entity.as_str(), "contact" | "lead") || !seen.insert(person.id) {
            outcome.skipped_invalid += 1;
            continue;
        }
        let earlier = runs.get(&person.id).map(Vec::as_slice).unwrap_or_default();
        if earlier.iter().any(|r| r.active) {
            outcome.skipped_active += 1;
            continue;
        }
        let blocked = match rule {
            ReEntry::Never => !earlier.is_empty(),
            ReEntry::AfterExit => false,
            ReEntry::AfterCoolOff => earlier
                .iter()
                .any(|r| r.ended_at.is_none_or(|ended| ended > now - cool_off)),
        };
        if blocked {
            outcome.skipped_re_entry += 1;
            continue;
        }
        if cap_left.is_some_and(|left| admitted.len() as i64 >= left) {
            outcome.skipped_cap += 1;
            continue;
        }
        admitted.push(person.clone());
    }
    (admitted, outcome)
}

/// A journey's settings, as enrolment needs them.
#[derive(Debug, Clone)]
struct Journey {
    logicalname: String,
    definition_id: Uuid,
    version_id: Uuid,
    re_entry: ReEntry,
    cool_off_days: i64,
    daily_cap: Option<i64>,
}

/// A journey row as read: workflow, re-entry, cool-off days, daily cap, status.
type JourneyRow = (
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

async fn load(state: &EngineState, journey: Uuid, is_test: bool) -> Result<Journey, AppError> {
    let row: Option<JourneyRow> = sqlx::query_as(
        "SELECT workflow_definition_logicalname, re_entry, cool_off_days::int8, \
                    daily_entry_cap::int8, status \
               FROM marketing_journey WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(journey)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (logicalname, re_entry, cool_off_days, daily_cap, status) =
        row.ok_or(AppError::NotFound)?;
    if !is_test && status.as_deref() != Some("live") {
        return Err(AppError::Validation(
            "the journey is not live; only test enrolments are taken".into(),
        ));
    }
    let (definition_id, version_id): (Uuid, Uuid) = sqlx::query_as(
        "SELECT d.id, v.id FROM workflow_definition d \
           JOIN workflow_definition_version v ON v.definition_id = d.id AND v.status = 'published' \
          WHERE d.logicalname = $1 AND d.kind = 'journey' AND d.is_active = TRUE AND d.is_deleted = FALSE",
    )
    .bind(&logicalname)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| {
        AppError::Validation(format!(
            "journey workflow {logicalname:?} has no published version"
        ))
    })?;
    Ok(Journey {
        logicalname,
        definition_id,
        version_id,
        re_entry: ReEntry::parse(re_entry.as_deref()),
        cool_off_days: cool_off_days.unwrap_or(0),
        daily_cap: daily_cap.filter(|c| *c > 0),
    })
}

/// Enrols `people` in the journey; see the module doc.
pub async fn enrol(
    state: &EngineState,
    journey: Uuid,
    people: Vec<PersonRef>,
    source: &str,
    is_test: bool,
) -> Result<EnrolOutcome, AppError> {
    let starter = state
        .workflow_starter
        .clone()
        .ok_or(AppError::CapabilityUnavailable("workflow start"))?;
    let settings = load(state, journey, is_test).await?;
    let mut total = EnrolOutcome::default();
    for chunk in people.chunks(CHUNK) {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        sqlx::query("SELECT id FROM workflow_definition WHERE id = $1 FOR UPDATE")
            .bind(settings.definition_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        let ids: Vec<Uuid> = chunk.iter().map(|p| p.id).collect();
        let prior: Vec<Prior> = sqlx::query_as::<_, (Uuid, String, Option<DateTime<Utc>>)>(
            "SELECT person_id, status, ended_at FROM marketing_journey_enrolment \
              WHERE definition_id = $1 AND person_id = ANY($2) AND is_test = $3",
        )
        .bind(settings.definition_id)
        .bind(&ids)
        .bind(is_test)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(person, status, ended_at)| Prior {
            person,
            active: status == "active",
            ended_at,
        })
        .collect();
        let cap_left = match (settings.daily_cap, is_test) {
            (Some(cap), false) => {
                let today: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM marketing_journey_enrolment \
                      WHERE definition_id = $1 AND is_test = FALSE \
                        AND entered_at >= date_trunc('day', now())",
                )
                .bind(settings.definition_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                Some((cap - today).max(0))
            }
            _ => None,
        };
        let (admitted, mut outcome) = admit(
            chunk,
            &prior,
            settings.re_entry,
            settings.cool_off_days,
            cap_left,
            Utc::now(),
        );
        if admitted.is_empty() {
            total.add(outcome);
            continue;
        }

        let people_ids: Vec<Uuid> = admitted.iter().map(|p| p.id).collect();
        let entities: Vec<&str> = admitted.iter().map(|p| p.entity.as_str()).collect();
        // The partial unique index is the final word on one active run.
        let inserted: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            "INSERT INTO marketing_journey_enrolment \
                (definition_id, definition_version_id, person_id, person_entity, status, \
                 entry_source, is_test) \
             SELECT $1, $2, p.id, p.entity, 'active', $5, $6 \
               FROM UNNEST($3::uuid[], $4::text[]) AS p(id, entity) \
             ON CONFLICT (definition_id, person_id) WHERE status = 'active' DO NOTHING \
             RETURNING id, person_id, person_entity",
        )
        .bind(settings.definition_id)
        .bind(settings.version_id)
        .bind(&people_ids)
        .bind(&entities)
        .bind(source)
        .bind(is_test)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        outcome.skipped_active += (admitted.len() - inserted.len()) as u64;

        let items = inserted
            .iter()
            .map(|(enrolment, person, entity)| {
                (
                    *person,
                    json!({
                        "journey_id": journey,
                        "enrolment_id": enrolment,
                        "person_entity": entity,
                        "source": source,
                        "is_test": is_test,
                    }),
                )
            })
            .collect();
        let started = starter
            .start_batch_in_tx(
                state,
                &mut tx,
                attome_core::workflow_start::WorkflowBatchStartRequest {
                    definition_logicalname: settings.logicalname.clone(),
                    started_by: None,
                    items,
                },
            )
            .await?;
        let (persons, instances): (Vec<Uuid>, Vec<Uuid>) = started.into_iter().unzip();
        sqlx::query(
            "UPDATE marketing_journey_enrolment e SET instance_id = u.instance \
               FROM UNNEST($1::uuid[], $2::uuid[]) AS u(person, instance) \
              WHERE e.definition_id = $3 AND e.person_id = u.person AND e.status = 'active'",
        )
        .bind(&persons)
        .bind(&instances)
        .bind(settings.definition_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        outcome.enrolled += inserted.len() as u64;
        total.add(outcome);
    }
    Ok(total)
}

/// The job's payload: one chunk of an entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolJob {
    pub journey_id: Uuid,
    pub people: Vec<PersonRef>,
    pub source: String,
    #[serde(default)]
    pub is_test: bool,
}

/// Queues an entry as `marketing_journey_enrol` jobs of at most [`CHUNK`]
/// people each, in the caller's transaction.
pub async fn queue_enrol(
    tx: &mut attome_db::Tx<'_>,
    journey: Uuid,
    people: &[PersonRef],
    source: &str,
    is_test: bool,
) -> Result<usize, AppError> {
    let mut queued = 0;
    for chunk in people.chunks(CHUNK) {
        let job = attome_core::jobs::JOB_TYPES
            .job(
                JOB,
                &EnrolJob {
                    journey_id: journey,
                    people: chunk.to_vec(),
                    source: source.to_owned(),
                    is_test,
                },
            )
            .map_err(AppError::internal)?;
        attome_jobs::enqueue_in_tx(tx, attome_core::jobs::EngineJob::Registered(job))
            .await
            .map_err(AppError::internal)?;
        queued += 1;
    }
    Ok(queued)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(n: u128) -> PersonRef {
        PersonRef {
            id: Uuid::from_u128(n),
            entity: "contact".into(),
        }
    }

    fn now() -> DateTime<Utc> {
        "2026-10-20T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn an_active_run_always_blocks() {
        let prior = [Prior {
            person: Uuid::from_u128(1),
            active: true,
            ended_at: None,
        }];
        let (admitted, outcome) = admit(
            &[person(1), person(2)],
            &prior,
            ReEntry::AfterExit,
            0,
            None,
            now(),
        );
        assert_eq!(admitted, vec![person(2)]);
        assert_eq!(outcome.skipped_active, 1);
    }

    #[test]
    fn re_entry_rules() {
        let ended = |days: i64| Prior {
            person: Uuid::from_u128(1),
            active: false,
            ended_at: Some(now() - Duration::days(days)),
        };
        let one = [person(1)];
        assert!(
            admit(&one, &[ended(40)], ReEntry::Never, 0, None, now())
                .0
                .is_empty()
        );
        assert_eq!(
            admit(&one, &[ended(1)], ReEntry::AfterExit, 0, None, now())
                .0
                .len(),
            1
        );
        assert!(
            admit(&one, &[ended(5)], ReEntry::AfterCoolOff, 30, None, now())
                .0
                .is_empty()
        );
        assert_eq!(
            admit(&one, &[ended(40)], ReEntry::AfterCoolOff, 30, None, now())
                .0
                .len(),
            1
        );
    }

    #[test]
    fn the_daily_cap_and_duplicates() {
        let people = [person(1), person(1), person(2), person(3)];
        let (admitted, outcome) = admit(&people, &[], ReEntry::Never, 0, Some(2), now());
        assert_eq!(admitted, vec![person(1), person(2)]);
        assert_eq!(outcome.skipped_invalid, 1, "the duplicate");
        assert_eq!(outcome.skipped_cap, 1);
        let account = PersonRef {
            id: Uuid::from_u128(9),
            entity: "account".into(),
        };
        assert_eq!(
            admit(&[account], &[], ReEntry::Never, 0, None, now())
                .1
                .skipped_invalid,
            1
        );
    }
}
