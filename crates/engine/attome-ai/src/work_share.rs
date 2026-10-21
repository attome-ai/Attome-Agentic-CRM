//! AK3-T4/T5: how much of each process's work agents do.
//!
//! A *measure* (`ai_work_measure`, AK3-T2) names what completing one task of
//! a process looks like: an entity, an attribute and the values that mean
//! done (a ticket's `status` set to `resolved` or `closed`). The consumer
//! [`consume_batch`] reads the change feed with its own cursor
//! ([`CONSUMER`]) and counts every create or update that sets a measure's
//! attribute to one of its values, by who made it: the event's `initiator`
//! (AK3-T1) is 1 for an agent acting for a person, 0 for the person. The
//! counts go into `ai_work_share_daily` per process and UTC day, with the
//! day's ticket hand-offs (`service_handoff`, AI7) for measures on
//! `service_ticket`.
//!
//! **Exactly once.** The counts and the cursor move in one transaction, which
//! also holds the cursor row locked (`FOR UPDATE`), so a batch is counted
//! once or not at all and two workers never count the same events.
//! [`rebuild`] takes the same lock, clears a date range and recounts it from
//! the events still retained that the consumer has already passed; the
//! consumer counts the rest as it reaches them. The table is derived and can
//! always be rebuilt.
//!
//! Events written before AK3-T1 carry the default initiator, so they count as
//! a person's.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeEvent};
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

/// The consumer's change-feed cursor.
pub const CONSUMER: &str = "attome-ai/work_share";
/// Events one batch reads.
pub const BATCH: i64 = 500;
/// Batches one scheduled run reads at most.
pub const MAX_BATCHES: usize = 10;
/// The registered job that runs the consumer.
pub const CONSUME_JOB: &str = "ai_work_share_consume";
/// The registered job that rebuilds a date range.
pub const REBUILD_JOB: &str = "ai_work_share_rebuild";
/// The longest range one rebuild recounts, in days.
pub const MAX_REBUILD_DAYS: i64 = 366;
/// Events one rebuild page reads.
const REBUILD_PAGE: i64 = 1_000;
/// The entity whose measures count hand-offs.
const TICKET_ENTITY: &str = "service_ticket";

/// One active measure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measure {
    pub process_key: String,
    pub entity: String,
    pub attribute: String,
    pub values: Vec<String>,
}

/// The rebuild job's payload: the UTC days to recount, both included.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct RebuildRange {
    pub from: NaiveDate,
    pub to: NaiveDate,
}

/// A measure's completion values from its comma-separated text: each
/// trimmed, empty ones dropped. Pure.
pub fn parse_values(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether `value` is one of the completion values: the value is trimmed,
/// then compared exactly, case included (`Resolved` is not `resolved`). Pure.
pub fn completes(values: &[String], value: &str) -> bool {
    let value = value.trim();
    values.iter().any(|v| v == value)
}

/// An event value as text: a string, number or boolean. A sensitive value
/// (`{"ref": true}`), a list or an empty value has none. Pure.
fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// The measures one event completes: a create or update of the measure's
/// entity that changed its attribute to a completion value. Pure.
pub fn completed_by<'a>(
    measures: &'a [Measure],
    entity: &str,
    operation: &str,
    changed: &[String],
    after: Option<&Value>,
) -> Vec<&'a Measure> {
    if operation != "create" && operation != "update" {
        return Vec::new();
    }
    measures
        .iter()
        .filter(|m| m.entity == entity && changed.iter().any(|c| c == &m.attribute))
        .filter(|m| {
            after
                .and_then(|a| a.get(&m.attribute))
                .and_then(value_text)
                .is_some_and(|v| completes(&m.values, &v))
        })
        .collect()
}

/// Completions counted for one process and day.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Tally {
    pub by_agent: i32,
    pub by_person: i32,
}

/// Counts by `(process_key, day)`.
pub type Tallies = BTreeMap<(String, NaiveDate), Tally>;

/// Adds one completion: initiator 1 is an agent, anything else a person. Pure.
pub fn count(tallies: &mut Tallies, measure: &Measure, day: NaiveDate, initiator: i16) {
    let entry = tallies
        .entry((measure.process_key.clone(), day))
        .or_default();
    if initiator == 1 {
        entry.by_agent += 1;
    } else {
        entry.by_person += 1;
    }
}

/// The active measures.
pub async fn active_measures(db: &attome_db::DbPool) -> Result<Vec<Measure>, AppError> {
    let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT process_key, entity_logical_name, completion_attribute, completion_values \
           FROM ai_work_measure WHERE is_active IS NOT FALSE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(process_key, entity, attribute, values)| Measure {
            process_key,
            entity,
            attribute,
            values: parse_values(values.as_deref().unwrap_or("")),
        })
        .filter(|m| !m.values.is_empty())
        .collect())
}

/// Creates the cursor if needed and locks its row for this transaction.
async fn lock_cursor(conn: &mut PgConnection) -> Result<change_feed::CursorPosition, AppError> {
    let position = change_feed::cursor(&mut *conn, CONSUMER).await?;
    sqlx::query("SELECT 1 FROM change_consumer_cursor WHERE consumer = $1 FOR UPDATE")
        .bind(CONSUMER)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(position)
}

/// The completions in `events`, reading the new values of the events that
/// could complete a measure.
async fn tally_events(
    conn: &mut PgConnection,
    measures: &[Measure],
    events: &[ChangeEvent],
) -> Result<Tallies, AppError> {
    let ids: Vec<Uuid> = events
        .iter()
        .filter(|e| {
            measures.iter().any(|m| {
                m.entity == e.entity_logicalname && e.changed_attributes.contains(&m.attribute)
            })
        })
        .map(|e| e.id)
        .collect();
    let mut tallies = Tallies::new();
    if ids.is_empty() {
        return Ok(tallies);
    }
    let rows: Vec<(Uuid, Option<Value>, i16)> = sqlx::query_as(
        "SELECT id, after, initiator FROM entity_change_event           WHERE id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let payloads: HashMap<Uuid, (Option<Value>, i16)> = rows
        .into_iter()
        .map(|(id, after, initiator)| (id, (after, initiator)))
        .collect();
    for event in events {
        let Some((after, initiator)) = payloads.get(&event.id) else {
            continue;
        };
        let done = completed_by(
            measures,
            &event.entity_logicalname,
            &event.operation,
            &event.changed_attributes,
            after.as_ref(),
        );
        let day = event.created_at.date_naive();
        for measure in done {
            count(&mut tallies, measure, day, *initiator);
        }
    }
    Ok(tallies)
}

/// Adds the tallies to the daily rows.
async fn add(conn: &mut PgConnection, tallies: &Tallies) -> Result<(), AppError> {
    for ((process, day), tally) in tallies {
        sqlx::query(
            "INSERT INTO ai_work_share_daily (process_key, day, done_by_agent, done_by_person) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (process_key, day) DO UPDATE \
                SET done_by_agent = ai_work_share_daily.done_by_agent + EXCLUDED.done_by_agent, \
                    done_by_person = ai_work_share_daily.done_by_person + EXCLUDED.done_by_person, \
                    computed_at = now()",
        )
        .bind(process)
        .bind(day)
        .bind(tally.by_agent)
        .bind(tally.by_person)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Sets the hand-off count of `days` for every measure on tickets.
async fn refresh_handoffs(
    conn: &mut PgConnection,
    measures: &[Measure],
    days: &BTreeSet<NaiveDate>,
) -> Result<(), AppError> {
    if days.is_empty() {
        return Ok(());
    }
    let days: Vec<NaiveDate> = days.iter().copied().collect();
    for measure in measures.iter().filter(|m| m.entity == TICKET_ENTITY) {
        sqlx::query(
            "INSERT INTO ai_work_share_daily (process_key, day, handed_between) \
             SELECT $1, (h.created_at AT TIME ZONE 'UTC')::date, count(*)::int \
               FROM service_handoff h \
              WHERE (h.created_at AT TIME ZONE 'UTC')::date = ANY($2::date[]) \
              GROUP BY 2 \
             ON CONFLICT (process_key, day) DO UPDATE \
                SET handed_between = EXCLUDED.handed_between, computed_at = now()",
        )
        .bind(&measure.process_key)
        .bind(&days)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// Counts up to [`BATCH`] events after the cursor and moves it past them, in
/// one transaction. Returns how many events were read; nothing is read while
/// no measure is active.
pub async fn consume_batch(state: &EngineState) -> Result<usize, AppError> {
    let measures = active_measures(&state.base.db).await?;
    if measures.is_empty() {
        return Ok(0);
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    lock_cursor(&mut tx).await?;
    let events = change_feed::read_batch(&mut tx, CONSUMER, BATCH).await?;
    let Some(last) = events.last().cloned() else {
        attome_db::tx::commit(tx).await?;
        return Ok(0);
    };
    let tallies = tally_events(&mut tx, &measures, &events).await?;
    add(&mut tx, &tallies).await?;
    let mut days: BTreeSet<NaiveDate> = tallies.keys().map(|(_, day)| *day).collect();
    days.insert(Utc::now().date_naive());
    refresh_handoffs(&mut tx, &measures, &days).await?;
    change_feed::advance(&mut tx, CONSUMER, &last).await?;
    attome_db::tx::commit(tx).await?;
    Ok(events.len())
}

/// AK3-T5: one scheduled run: batches until the feed is read or
/// [`MAX_BATCHES`] ran. Returns the events read.
pub async fn consume(state: &EngineState) -> Result<usize, AppError> {
    let mut read = 0;
    for _ in 0..MAX_BATCHES {
        let n = consume_batch(state).await?;
        read += n;
        if n < usize::try_from(BATCH).unwrap_or(usize::MAX) {
            break;
        }
    }
    Ok(read)
}

/// The range checked: `from` not after `to`, at most [`MAX_REBUILD_DAYS`]. Pure.
pub fn check_range(range: RebuildRange) -> Result<(), AppError> {
    let days = (range.to - range.from).num_days();
    if days < 0 {
        return Err(AppError::Validation("from must not be after to".into()));
    }
    if days >= MAX_REBUILD_DAYS {
        return Err(AppError::Validation(format!(
            "at most {MAX_REBUILD_DAYS} days in one rebuild"
        )));
    }
    Ok(())
}

/// One event row a rebuild reads.
type RebuildRow = (
    i64,
    String,
    String,
    Vec<String>,
    Option<Value>,
    i16,
    DateTime<Utc>,
);

/// AK3-T5: clears `range` and recounts it from the retained events the
/// consumer has already passed, holding the consumer's lock throughout.
/// Returns the completions counted.
pub async fn rebuild(state: &EngineState, range: RebuildRange) -> Result<i64, AppError> {
    check_range(range)?;
    let measures = active_measures(&state.base.db).await?;
    let start = range.from.and_time(chrono::NaiveTime::MIN).and_utc();
    let end = (range.to + chrono::Days::new(1))
        .and_time(chrono::NaiveTime::MIN)
        .and_utc();
    let entities: Vec<String> = measures
        .iter()
        .map(|m| m.entity.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let position = lock_cursor(&mut tx).await?;
    sqlx::query("DELETE FROM ai_work_share_daily WHERE day BETWEEN $1 AND $2")
        .bind(range.from)
        .bind(range.to)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    let mut counted = 0i64;
    let mut after_seq = 0i64;
    while !entities.is_empty() {
        let rows: Vec<RebuildRow> = sqlx::query_as(
            "SELECT seq, entity_logicalname, operation, changed_attributes, after, initiator, \
                    created_at \
               FROM entity_change_event \
              WHERE entity_logicalname = ANY($1) AND created_at >= $2 AND created_at < $3 \
                AND commit_xid <= $4::text::xid8 AND seq > $5 \
              ORDER BY seq LIMIT $6",
        )
        .bind(&entities)
        .bind(start)
        .bind(end)
        .bind(position.last_commit_xid.to_string())
        .bind(after_seq)
        .bind(REBUILD_PAGE)
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = rows.last() else {
            break;
        };
        after_seq = last.0;
        let page = i64::try_from(rows.len()).unwrap_or(i64::MAX);
        let mut tallies = Tallies::new();
        for (_, entity, operation, changed, after, initiator, at) in &rows {
            for measure in completed_by(&measures, entity, operation, changed, after.as_ref()) {
                count(&mut tallies, measure, at.date_naive(), *initiator);
                counted += 1;
            }
        }
        add(&mut tx, &tallies).await?;
        if page < REBUILD_PAGE {
            break;
        }
    }
    let span = range.from.iter_days().take_while(|d| *d <= range.to);
    let days: BTreeSet<NaiveDate> = span.collect();
    refresh_handoffs(&mut tx, &measures, &days).await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(%range.from, %range.to, counted, "work share rebuilt");
    Ok(counted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn measure() -> Measure {
        Measure {
            process_key: "service.ticket_resolved".into(),
            entity: "service_ticket".into(),
            attribute: "status".into(),
            values: parse_values(" resolved, closed ,,"),
        }
    }

    #[test]
    fn completion_value_matching_is_exact() {
        let m = measure();
        assert_eq!(m.values, vec!["resolved".to_owned(), "closed".to_owned()]);
        assert!(completes(&m.values, "resolved"));
        assert!(completes(&m.values, " closed "), "the value is trimmed");
        assert!(!completes(&m.values, "Resolved"), "case is kept");
        assert!(!completes(&m.values, "resolved later"));
        assert!(!completes(&m.values, ""));
    }

    #[test]
    fn work_share_counts_only_a_change_to_a_completion_value() {
        let measures = vec![measure()];
        let changed = vec!["status".to_owned()];
        let done = json!({ "status": "resolved" });
        let open = json!({ "status": "open" });
        let hidden = json!({ "status": { "ref": true } });
        let n = |entity: &str, op: &str, changed: &[String], after: &Value| {
            completed_by(&measures, entity, op, changed, Some(after)).len()
        };
        assert_eq!(n("service_ticket", "update", &changed, &done), 1);
        assert_eq!(n("service_ticket", "create", &changed, &done), 1);
        assert_eq!(n("service_ticket", "update", &changed, &open), 0);
        assert_eq!(n("service_ticket", "delete", &changed, &done), 0);
        assert_eq!(n("deal", "update", &changed, &done), 0);
        assert_eq!(n("service_ticket", "update", &[], &done), 0);
        assert_eq!(n("service_ticket", "update", &changed, &hidden), 0);
    }

    #[test]
    fn work_share_splits_agent_from_person() {
        let m = measure();
        let day = NaiveDate::from_ymd_opt(2026, 10, 21).unwrap();
        let mut tallies = Tallies::new();
        count(&mut tallies, &m, day, 1);
        count(&mut tallies, &m, day, 0);
        count(&mut tallies, &m, day, 0);
        let expected = Tally {
            by_agent: 1,
            by_person: 2,
        };
        assert_eq!(tallies[&(m.process_key.clone(), day)], expected);
    }

    #[test]
    fn work_share_rebuild_range_is_bounded() {
        let d = |day| NaiveDate::from_ymd_opt(2026, 1, day).unwrap();
        let r = |from, to| RebuildRange { from, to };
        assert!(check_range(r(d(1), d(1))).is_ok());
        assert!(check_range(r(d(2), d(1))).is_err());
        assert!(check_range(r(d(1), d(1) + chrono::Days::new(400))).is_err());
    }
}
