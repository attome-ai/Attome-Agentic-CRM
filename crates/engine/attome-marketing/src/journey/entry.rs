//! Journey entry sources (roadmap E8-T5): what puts people into a live
//! journey besides the enrol route.
//!
//! A journey's `entry_sources` is a JSON list of:
//!
//! - `{"type": "segment_entered", "list_id"}` — someone joins the list;
//! - `{"type": "event", "event_name", "entity"?, "filter"?}` — a named
//!   change-feed event (`form.submitted`, `email.clicked`, ...) or
//!   `record.created` / `record.changed`, optionally on one entity, whose
//!   record passes the attome-rules `filter`;
//! - `{"type": "date", "entity", "attribute", "offset_days", "calendar":
//!   "gregorian" | "hijri", "time"?}` — contacts or leads whose date plus
//!   the offset is today (Gregorian), or falls on today's Hijri month and
//!   day (Hijri);
//! - `{"type": "list_at", "list_id", "at"}` — the list's members, once, at
//!   that time;
//! - `{"type": "api"}` — the enrol route (E8-T10), source `api`.
//!
//! Only `live` journeys take entries; draft and paused ones are never read.
//!
//! **The entry tick** ([`entry_tick`], the `marketing_journey_entry` job,
//! every 10 seconds, one pending at most) reads a batch of the change feed
//! as consumer [`CONSUMER`]. A list that changed (`marketing.list.*`) has
//! its `entered` membership events read after the journey's mark for that
//! list (kept in `marketing_journey_entry_state`); other events are matched
//! against event sources. People are queued as `marketing_journey_enrol`
//! jobs in the same transaction that moves the mark; the cursor moves after
//! every journey's queueing has committed, so a crash re-reads the batch and
//! enrolment's own rules (one active run, re-entry) keep a person from
//! starting twice. Due `list_at` sources fire from the same tick, once each.
//!
//! **The date entry** ([`date_entry`], the `marketing_journey_date_entry`
//! job, hourly) runs each date source once a deployment day, from 00:10
//! deployment time, in batches of 1,000 people.

use std::collections::{BTreeMap, HashSet};

use attome_calendar::hijri::{HijriCalendar, HijriDate};
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, NaiveTime, Timelike, Utc};
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

use super::enrol::{PersonRef, queue_enrol};

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-marketing/journey_entry";
/// The entry tick's job.
pub const TICK_JOB: &str = "marketing_journey_entry";
/// The date entry's job.
pub const DATE_JOB: &str = "marketing_journey_date_entry";
/// Events read per tick.
pub const BATCH: i64 = 500;
/// People per date-entry batch.
pub const DATE_BATCH: i64 = 1_000;
/// The list events that mean members may have joined.
const LIST_EVENTS: &[&str] = &["marketing.list.refreshed", "marketing.list.members_changed"];
/// A journey with no mark for a list takes entries this far back.
const FIRST_LOOK_BACK_MINUTES: i64 = 10;

/// One entry source.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntrySource {
    SegmentEntered {
        list_id: Uuid,
    },
    Event {
        event_name: String,
        #[serde(default)]
        entity: Option<String>,
        #[serde(default)]
        filter: Option<String>,
    },
    Date {
        entity: String,
        attribute: String,
        #[serde(default)]
        offset_days: i64,
        #[serde(default)]
        calendar: DateCalendar,
        #[serde(default)]
        time: Option<String>,
    },
    ListAt {
        list_id: Uuid,
        at: DateTime<Utc>,
    },
    Api,
}

/// Which calendar a date source counts in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DateCalendar {
    #[default]
    Gregorian,
    Hijri,
}

/// The sources a journey's `entry_sources` text names; an entry that does
/// not parse is skipped (and logged), the rest still apply. Pure apart from
/// the log line.
pub fn parse_sources(journey: Uuid, raw: Option<&str>) -> Vec<EntrySource> {
    let Some(raw) = raw.map(str::trim).filter(|r| !r.is_empty()) else {
        return Vec::new();
    };
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) else {
        tracing::warn!(%journey, "journey entry_sources is not a JSON list; no entries taken");
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(
            |item| match serde_json::from_value::<EntrySource>(item.clone()) {
                Ok(source) => Some(source),
                Err(error) => {
                    tracing::warn!(%journey, %error, "journey entry source skipped");
                    None
                }
            },
        )
        .collect()
}

/// Whether a change-feed event is the one an event source names. Pure.
pub fn event_matches(
    source_name: &str,
    source_entity: Option<&str>,
    event_name: Option<&str>,
    operation: &str,
    entity: &str,
) -> bool {
    if source_entity.is_some_and(|e| e != entity) {
        return false;
    }
    match source_name {
        "record.created" => event_name.is_none() && operation == "create",
        "record.changed" => event_name.is_none() && operation == "update",
        name => event_name == Some(name),
    }
}

/// The person a record is about: itself for a contact or lead, else the
/// first person reference it carries (`person_id` with `person_entity`,
/// `contact_id`/`contact_ref`, `lead_id`/`lead_ref`). Pure.
pub fn person_of(entity: &str, id: Uuid, record: &Map<String, Value>) -> Option<PersonRef> {
    if matches!(entity, "contact" | "lead") {
        return Some(PersonRef {
            id,
            entity: entity.to_owned(),
        });
    }
    let uuid = |key: &str| {
        record
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
    };
    if let Some(person) = uuid("person_id") {
        let entity = match record.get("person_entity").and_then(Value::as_str) {
            Some("lead") => "lead",
            _ => "contact",
        };
        return Some(PersonRef {
            id: person,
            entity: entity.to_owned(),
        });
    }
    for (key, entity) in [
        ("contact_id", "contact"),
        ("contact_ref", "contact"),
        ("lead_id", "lead"),
        ("lead_ref", "lead"),
    ] {
        if let Some(id) = uuid(key) {
            return Some(PersonRef {
                id,
                entity: entity.to_owned(),
            });
        }
    }
    None
}

/// Every Gregorian date in the calendar's range that falls on `today`'s
/// Hijri month and day. On the last day of a 29-day month, day 30 of that
/// month in other years counts too, so nobody born on a 30th is skipped.
/// Pure.
pub fn hijri_anniversaries(calendar: &HijriCalendar, today: NaiveDate) -> Vec<NaiveDate> {
    let Ok(now) = calendar.to_hijri(today) else {
        return Vec::new();
    };
    let last_of_short = calendar
        .month_length(now.year, now.month)
        .is_ok_and(|len| len == 29 && now.day == 29);
    let mut out = Vec::new();
    for year in attome_calendar::hijri::FIRST_YEAR..=attome_calendar::hijri::LAST_YEAR {
        let days: &[u8] = if last_of_short {
            &[29, 30]
        } else {
            std::slice::from_ref(&now.day)
        };
        for &day in days {
            if let Ok(date) = calendar.to_gregorian(HijriDate::new(year, now.month, day)) {
                out.push(date);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether a date source's day has started: from 00:10, or its `time`
/// (`HH:MM`) when that is later. Pure.
pub fn date_due(now: NaiveTime, time: Option<&str>) -> bool {
    let floor = NaiveTime::from_hms_opt(0, 10, 0).unwrap_or(NaiveTime::MIN);
    let at = time
        .and_then(|t| NaiveTime::parse_from_str(t.trim(), "%H:%M").ok())
        .filter(|t| *t > floor)
        .unwrap_or(floor);
    now >= at
}

/// The live journeys and their sources.
async fn live_journeys(state: &EngineState) -> Result<Vec<(Uuid, Vec<EntrySource>)>, AppError> {
    let rows: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "SELECT id, entry_sources FROM marketing_journey \
          WHERE status = 'live' AND is_active IS NOT FALSE \
            AND entry_sources IS NOT NULL AND btrim(entry_sources) <> ''",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, raw)| (id, parse_sources(id, raw.as_deref())))
        .filter(|(_, sources)| !sources.is_empty())
        .collect())
}

/// Takes the journey's state row for `key` under a row lock, creating it.
async fn lock_state(
    tx: &mut attome_db::Tx<'_>,
    journey: Uuid,
    key: &str,
) -> Result<(Option<Uuid>, Option<NaiveDate>, Option<DateTime<Utc>>), AppError> {
    sqlx::query(
        "INSERT INTO marketing_journey_entry_state (journey_id, source_key) VALUES ($1, $2) \
         ON CONFLICT (journey_id, source_key) DO NOTHING",
    )
    .bind(journey)
    .bind(key)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query_as(
        "SELECT mark, fired_on, fired_at FROM marketing_journey_entry_state \
          WHERE journey_id = $1 AND source_key = $2 FOR UPDATE",
    )
    .bind(journey)
    .bind(key)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

async fn list_entity(state: &EngineState, list: Uuid) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT COALESCE(target_entity, 'contact') FROM marketing_list \
          WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Queues the people who entered `list` since the journey's mark.
async fn segment_entries(
    state: &EngineState,
    journey: Uuid,
    list: Uuid,
) -> Result<usize, AppError> {
    let Some(entity) = list_entity(state, list).await? else {
        return Ok(0);
    };
    let key = format!("list:{list}");
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (mark, _, _) = lock_state(&mut tx, journey, &key).await?;
    let entered: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT id, person_id FROM marketing_list_membership_event \
          WHERE list_id = $1 AND change = 'entered' \
            AND CASE WHEN $2::uuid IS NULL THEN at >= now() - make_interval(mins => $3) \
                     ELSE id > $2 END \
          ORDER BY id LIMIT 10000",
    )
    .bind(list)
    .bind(mark)
    .bind(FIRST_LOOK_BACK_MINUTES as i32)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(&(last, _)) = entered.last() else {
        attome_db::tx::commit(tx).await?;
        return Ok(0);
    };
    let mut seen = HashSet::new();
    let people: Vec<PersonRef> = entered
        .iter()
        .filter(|(_, p)| seen.insert(*p))
        .map(|(_, p)| PersonRef {
            id: *p,
            entity: entity.clone(),
        })
        .collect();
    queue_enrol(&mut tx, journey, &people, "segment_entered", false).await?;
    sqlx::query(
        "UPDATE marketing_journey_entry_state SET mark = $3, updated_at = now() \
          WHERE journey_id = $1 AND source_key = $2",
    )
    .bind(journey)
    .bind(&key)
    .bind(last)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(people.len())
}

/// Fires each due `list_at` source once.
async fn fire_list_at(
    state: &EngineState,
    journeys: &[(Uuid, Vec<EntrySource>)],
    now: DateTime<Utc>,
) -> Result<usize, AppError> {
    let mut queued = 0;
    for (journey, sources) in journeys {
        for source in sources {
            let EntrySource::ListAt { list_id, at } = source else {
                continue;
            };
            if *at > now {
                continue;
            }
            let Some(entity) = list_entity(state, *list_id).await? else {
                continue;
            };
            let key = format!("at:{list_id}:{}", at.timestamp());
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let (_, _, fired_at) = lock_state(&mut tx, *journey, &key).await?;
            if fired_at.is_some() {
                attome_db::tx::commit(tx).await?;
                continue;
            }
            let members: Vec<Uuid> = sqlx::query_scalar(
                "SELECT person_id FROM marketing_list_member WHERE list_id = $1 ORDER BY person_id",
            )
            .bind(list_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            let people: Vec<PersonRef> = members
                .into_iter()
                .map(|id| PersonRef {
                    id,
                    entity: entity.clone(),
                })
                .collect();
            queue_enrol(&mut tx, *journey, &people, "list_at", false).await?;
            sqlx::query(
                "UPDATE marketing_journey_entry_state SET fired_at = now(), updated_at = now() \
                  WHERE journey_id = $1 AND source_key = $2",
            )
            .bind(journey)
            .bind(&key)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            attome_db::tx::commit(tx).await?;
            queued += people.len();
        }
    }
    Ok(queued)
}

/// A record's current row as JSON, when its entity is a live one.
async fn record_json(
    state: &EngineState,
    entity: &str,
    id: Uuid,
) -> Result<Option<Map<String, Value>>, AppError> {
    if state.entities.load().get(entity).is_none() {
        return Ok(None);
    }
    let row: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t) FROM {} t WHERE id = $1",
        attome_core::quote_ident(entity)
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|v| match v {
        Value::Object(map) => Some(map),
        _ => None,
    }))
}

/// One tick; see the module doc. Returns the people queued.
pub async fn entry_tick(state: &EngineState) -> Result<usize, AppError> {
    let journeys = live_journeys(state).await?;
    let mut queued = fire_list_at(state, &journeys, Utc::now()).await?;
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
    let Some(last) = events.last().cloned() else {
        return Ok(queued);
    };

    let changed_lists: HashSet<Uuid> = events
        .iter()
        .filter(|e| {
            e.entity_logicalname == "marketing_list"
                && e.event_name
                    .as_deref()
                    .is_some_and(|n| LIST_EVENTS.contains(&n))
        })
        .map(|e| e.record_id)
        .collect();
    for (journey, sources) in &journeys {
        for source in sources {
            if let EntrySource::SegmentEntered { list_id } = source
                && changed_lists.contains(list_id)
            {
                queued += segment_entries(state, *journey, *list_id).await?;
            }
        }
    }

    let has_event_sources = journeys
        .iter()
        .any(|(_, s)| s.iter().any(|s| matches!(s, EntrySource::Event { .. })));
    if has_event_sources {
        let mut by_journey: BTreeMap<Uuid, Vec<PersonRef>> = BTreeMap::new();
        for event in events
            .iter()
            .filter(|e| e.entity_logicalname != "marketing_list")
        {
            let mut record: Option<Option<Map<String, Value>>> = None;
            for (journey, sources) in &journeys {
                for source in sources {
                    let EntrySource::Event {
                        event_name,
                        entity,
                        filter,
                    } = source
                    else {
                        continue;
                    };
                    if !event_matches(
                        event_name,
                        entity.as_deref(),
                        event.event_name.as_deref(),
                        &event.operation,
                        &event.entity_logicalname,
                    ) {
                        continue;
                    }
                    if record.is_none() {
                        record = Some(
                            record_json(state, &event.entity_logicalname, event.record_id).await?,
                        );
                    }
                    let Some(Some(row)) = &record else { continue };
                    if let Some(filter) = filter.as_deref().filter(|f| !f.trim().is_empty()) {
                        let attrs = state
                            .entities
                            .load()
                            .get(event.entity_logicalname.as_str())
                            .map(|m| m.attrs.clone())
                            .unwrap_or_default();
                        if !super::guard::holds(filter, &attrs, row, *journey) {
                            continue;
                        }
                    }
                    if let Some(person) = person_of(&event.entity_logicalname, event.record_id, row)
                    {
                        let people = by_journey.entry(*journey).or_default();
                        if !people.contains(&person) {
                            people.push(person);
                        }
                    }
                }
            }
        }
        for (journey, people) in by_journey {
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            queue_enrol(&mut tx, journey, &people, "event", false).await?;
            attome_db::tx::commit(tx).await?;
            queued += people.len();
        }
    }

    attome_core::change_feed::advance(&mut conn, CONSUMER, &last).await?;
    Ok(queued)
}

/// The people whose `attribute` plus `offset_days` lands on one of `days`,
/// a batch at a time after `after`.
async fn date_batch(
    state: &EngineState,
    entity: &str,
    attribute: &str,
    offset_days: i64,
    days: &[NaiveDate],
    after: Uuid,
) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT id FROM {} \
          WHERE ({})::date + $1::int = ANY($2) AND id > $3 \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY id LIMIT $4",
        attome_core::quote_ident(entity),
        attome_core::quote_ident(attribute),
    ))
    .bind(offset_days as i32)
    .bind(days)
    .bind(after)
    .bind(DATE_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Whether `attribute` is a date field of `entity` (a contact or lead).
fn date_attribute(state: &EngineState, entity: &str, attribute: &str) -> bool {
    matches!(entity, "contact" | "lead")
        && state.entities.load().get(entity).is_some_and(|m| {
            m.attrs
                .iter()
                .any(|a| a.logicalname == attribute && a.storage_type().is_temporal())
        })
}

/// Runs each due date source once for the deployment's day; see the module
/// doc. Returns the people queued.
pub async fn date_entry(state: &EngineState) -> Result<usize, AppError> {
    let local = attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref());
    let now_time =
        NaiveTime::from_hms_opt(local.hour(), local.minute(), 0).unwrap_or(NaiveTime::MIN);
    date_entry_on(state, local.date_naive(), now_time).await
}

/// [`date_entry`] for a given deployment day and time of day.
pub async fn date_entry_on(
    state: &EngineState,
    today: NaiveDate,
    now_time: NaiveTime,
) -> Result<usize, AppError> {
    let journeys = live_journeys(state).await?;
    let mut queued = 0;
    for (journey, sources) in &journeys {
        for (index, source) in sources.iter().enumerate() {
            let EntrySource::Date {
                entity,
                attribute,
                offset_days,
                calendar,
                time,
            } = source
            else {
                continue;
            };
            if !date_due(now_time, time.as_deref()) {
                continue;
            }
            if !date_attribute(state, entity, attribute) {
                tracing::warn!(%journey, %entity, %attribute, "journey date source names no date field of a contact or lead; skipped");
                continue;
            }
            let key = format!("date:{index}:{entity}.{attribute}");
            let days = match calendar {
                DateCalendar::Gregorian => vec![today],
                DateCalendar::Hijri => hijri_anniversaries(&state.hijri.load(), today),
            };
            // Claim the day first: a second run the same day finds it taken.
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let (_, fired_on, _) = lock_state(&mut tx, *journey, &key).await?;
            if fired_on == Some(today) {
                attome_db::tx::commit(tx).await?;
                continue;
            }
            let mut after = Uuid::nil();
            loop {
                let ids = date_batch(state, entity, attribute, *offset_days, &days, after).await?;
                let Some(&next) = ids.last() else { break };
                let people: Vec<PersonRef> = ids
                    .iter()
                    .map(|id| PersonRef {
                        id: *id,
                        entity: entity.clone(),
                    })
                    .collect();
                queue_enrol(&mut tx, *journey, &people, "date", false).await?;
                queued += people.len();
                after = next;
                if (ids.len() as i64) < DATE_BATCH {
                    break;
                }
            }
            sqlx::query(
                "UPDATE marketing_journey_entry_state SET fired_on = $3, fired_at = now(), \
                        updated_at = now() WHERE journey_id = $1 AND source_key = $2",
            )
            .bind(journey)
            .bind(&key)
            .bind(today)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            attome_db::tx::commit(tx).await?;
        }
    }
    Ok(queued)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sources_parse_and_bad_ones_are_skipped() {
        let id = Uuid::nil();
        let raw = json!([
            {"type": "segment_entered", "list_id": "00000000-0000-0000-0000-000000000001"},
            {"type": "event", "event_name": "form.submitted", "filter": "true"},
            {"type": "date", "entity": "contact", "attribute": "birthdate", "offset_days": -1, "calendar": "hijri"},
            {"type": "list_at", "list_id": "00000000-0000-0000-0000-000000000002", "at": "2026-11-01T09:00:00Z"},
            {"type": "api"},
            {"type": "carrier_pigeon"}
        ])
        .to_string();
        let sources = parse_sources(id, Some(&raw));
        assert_eq!(sources.len(), 5);
        assert!(matches!(
            sources[2],
            EntrySource::Date {
                calendar: DateCalendar::Hijri,
                offset_days: -1,
                ..
            }
        ));
        assert!(parse_sources(id, Some("not json")).is_empty());
        assert!(parse_sources(id, None).is_empty());
    }

    #[test]
    fn events_match_by_name_operation_and_entity() {
        assert!(event_matches(
            "form.submitted",
            None,
            Some("form.submitted"),
            "update",
            "x"
        ));
        assert!(!event_matches(
            "form.submitted",
            None,
            Some("email.clicked"),
            "update",
            "x"
        ));
        assert!(event_matches(
            "record.created",
            Some("lead"),
            None,
            "create",
            "lead"
        ));
        assert!(!event_matches(
            "record.created",
            Some("lead"),
            None,
            "create",
            "contact"
        ));
        assert!(!event_matches(
            "record.changed",
            None,
            Some("record.merged"),
            "update",
            "lead"
        ));
    }

    #[test]
    fn the_person_is_found_on_the_record() {
        let id = Uuid::from_u128(7);
        let person = Uuid::from_u128(9);
        assert_eq!(person_of("lead", id, &Map::new()).map(|p| p.id), Some(id));
        let row = json!({"contact_ref": person.to_string()});
        let found = person_of("event_registration", id, row.as_object().unwrap()).unwrap();
        assert_eq!((found.id, found.entity.as_str()), (person, "contact"));
        let row = json!({"person_id": person.to_string(), "person_entity": "lead"});
        assert_eq!(
            person_of("form_submission", id, row.as_object().unwrap())
                .unwrap()
                .entity,
            "lead"
        );
        assert!(person_of("web_visit", id, &Map::new()).is_none());
    }

    #[test]
    fn hijri_dates_fall_on_the_same_month_and_day() {
        let calendar = HijriCalendar::umm_al_qura();
        let today = NaiveDate::from_ymd_opt(2026, 10, 20).unwrap();
        let now = calendar.to_hijri(today).unwrap();
        let days = hijri_anniversaries(calendar, today);
        assert!(days.contains(&today));
        assert!(days.len() > 100);
        for d in &days {
            let h = calendar.to_hijri(*d).unwrap();
            assert_eq!(h.month, now.month);
        }
        // A year earlier in the Hijri calendar is about 354 days back.
        let year_before = calendar
            .to_gregorian(HijriDate::new(now.year - 1, now.month, now.day))
            .unwrap();
        assert!(days.contains(&year_before));
    }

    #[test]
    fn date_sources_start_at_ten_past_midnight_or_their_time() {
        let t = |h, m| NaiveTime::from_hms_opt(h, m, 0).unwrap();
        assert!(!date_due(t(0, 5), None));
        assert!(date_due(t(0, 10), None));
        assert!(!date_due(t(8, 59), Some("09:00")));
        assert!(date_due(t(9, 0), Some("09:00")));
        assert!(date_due(t(0, 10), Some("garbage")));
    }
}
