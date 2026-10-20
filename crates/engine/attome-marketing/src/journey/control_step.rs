//! Journey control steps (roadmap E8-T7), registered as workflow module
//! steps: wait for working time or a Hijri month, check engagement with an
//! earlier send, and split the audience. A wait for a duration, until a
//! date or for an event is the workflow's own `wait` and `wait_for_event`
//! node; none is re-implemented here.

use attome_core::EngineState;
use attome_core::workflow_step::{StepFuture, StepInvocation, StepOutcome, WorkflowStepHandler};
use attome_modules::{MODULE_MARKETING, ModuleId};
use attome_types::AppError;
use chrono::{DateTime, Duration, NaiveTime, TimeZone, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

fn uuid_at(config: &Value, key: &str) -> Option<Uuid> {
    config
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s.trim()).ok())
}

/// `marketing.wait_calendar`: `{mode: "next_working_time", calendar_id}`
/// waits until the business calendar's next working moment (holidays and
/// the calendar's own weekend included); `{mode: "hijri_time",
/// hijri_month, after_iftar?, iftar_time?, calendar_id?}` waits until the
/// next first day of that Hijri month (this deployment's Umm al-Qura
/// table with its sighting corrections), at midnight or, with
/// `after_iftar`, at `iftar_time` (default 18:30), in the calendar's time
/// zone (UTC without one).
#[derive(Debug)]
pub struct WaitCalendar;

/// The time of day an `after_iftar` wait resumes at, `HH:MM`. Pure.
fn iftar_time(config: &Value) -> Option<NaiveTime> {
    match config.get("iftar_time").and_then(Value::as_str) {
        None => NaiveTime::from_hms_opt(18, 30, 0),
        Some(t) => NaiveTime::parse_from_str(t.trim(), "%H:%M").ok(),
    }
}

impl WorkflowStepHandler for WaitCalendar {
    fn key(&self) -> &'static str {
        "marketing.wait_calendar"
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        match config.get("mode").and_then(Value::as_str) {
            Some("next_working_time") => uuid_at(config, "calendar_id")
                .map(|_| ())
                .ok_or_else(|| "next_working_time needs a calendar_id".into()),
            Some("hijri_time") => {
                let month = config.get("hijri_month").and_then(Value::as_u64);
                if !month.is_some_and(|m| (1..=12).contains(&m)) {
                    return Err("hijri_month is 1 to 12".into());
                }
                if config.get("calendar_id").is_some() && uuid_at(config, "calendar_id").is_none() {
                    return Err("calendar_id is not an id".into());
                }
                iftar_time(config)
                    .map(|_| ())
                    .ok_or_else(|| "iftar_time is HH:MM".into())
            }
            _ => Err("mode is next_working_time or hijri_time".into()),
        }
    }
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            let now = Utc::now();
            let tz = match uuid_at(&inv.config, "calendar_id") {
                Some(id) => Some(load(state, id).await?),
                None => None,
            };
            let resume = match inv.config.get("mode").and_then(Value::as_str) {
                Some("next_working_time") => {
                    let calendar = tz.ok_or_else(|| {
                        AppError::Validation("next_working_time needs a calendar_id".into())
                    })?;
                    calendar
                        .next_working_moment(now)
                        .map_err(|e| AppError::Validation(e.to_string()))?
                }
                _ => {
                    let month = inv
                        .config
                        .get("hijri_month")
                        .and_then(Value::as_u64)
                        .and_then(|m| u8::try_from(m).ok())
                        .unwrap_or(1);
                    let at = if inv.config.get("after_iftar").and_then(Value::as_bool) == Some(true)
                    {
                        iftar_time(&inv.config).unwrap_or(NaiveTime::MIN)
                    } else {
                        NaiveTime::MIN
                    };
                    let zone = tz.as_ref().map_or(chrono_tz::UTC, |c| c.tz());
                    next_hijri_month_start(&state.hijri.load(), now, month, at, zone)?
                }
            };
            Ok(if resume <= now + Duration::minutes(1) {
                StepOutcome::Done(json!({ "waited": false }))
            } else if inv.simulate {
                StepOutcome::Done(json!({ "would_wait_until": resume }))
            } else {
                StepOutcome::Waiting {
                    resume_at: Some(resume),
                    wait_event: None,
                }
            })
        })
    }
}

async fn load(
    state: &EngineState,
    calendar: Uuid,
) -> Result<attome_calendar::BusinessCalendar, AppError> {
    match attome_core::calendar::load_calendar(&state.base.db, calendar).await? {
        Ok(loaded) => Ok(loaded.calendar),
        Err(unresolved) => Err(AppError::Validation(format!(
            "the journey's calendar cannot be used: {unresolved:?}"
        ))),
    }
}

/// The next start of Hijri `month` at `at` in `zone`: now when `now` is
/// already inside that month (on or after `at` on its first day, or any
/// later day of it), else the month's first day this Hijri year or next.
/// Pure.
pub fn next_hijri_month_start(
    hijri: &attome_calendar::hijri::HijriCalendar,
    now: DateTime<Utc>,
    month: u8,
    at: NaiveTime,
    zone: chrono_tz::Tz,
) -> Result<DateTime<Utc>, AppError> {
    let bad = |e: attome_calendar::CalendarError| AppError::Validation(e.to_string());
    let today = now.with_timezone(&zone).date_naive();
    let current = hijri.to_hijri(today).map_err(bad)?;
    let start_of = |year: u16| -> Result<DateTime<Utc>, AppError> {
        let (first, _) = hijri.month_bounds(year, month).map_err(bad)?;
        zone.from_local_datetime(&first.and_time(at))
            .earliest()
            .map(|t| t.with_timezone(&Utc))
            .ok_or_else(|| AppError::Validation("no such local time".into()))
    };
    if current.month == month {
        let start = start_of(current.year)?;
        return Ok(if now >= start { now } else { start });
    }
    let year = if month > current.month {
        current.year
    } else {
        current.year + 1
    };
    start_of(year)
}

/// `marketing.engagement`: `{node_id, event: opened|clicked|replied}`.
/// Done with `{engaged}`: whether the person had that event on an email
/// sent to them since the named earlier step of this run finished; a
/// condition node downstream routes on `engaged`.
#[derive(Debug)]
pub struct Engagement;

impl WorkflowStepHandler for Engagement {
    fn key(&self) -> &'static str {
        "marketing.engagement"
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        if !config
            .get("node_id")
            .and_then(Value::as_str)
            .is_some_and(|n| !n.trim().is_empty())
        {
            return Err("node_id names the earlier send step".into());
        }
        match config.get("event").and_then(Value::as_str) {
            Some("opened" | "clicked" | "replied") => Ok(()),
            _ => Err("event is opened, clicked or replied".into()),
        }
    }
    fn run<'a>(&'a self, state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            let node = inv
                .config
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let event = inv
                .config
                .get("event")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let since: Option<DateTime<Utc>> = sqlx::query_scalar(
                "SELECT max(completed_at) FROM workflow_node_run \
                  WHERE instance_id = $1 AND node_id = $2 AND status = 'succeeded'",
            )
            .bind(inv.instance_id)
            .bind(node)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let engaged = match (since, inv.correlation_entity_id) {
                (Some(since), Some(person)) => sqlx::query_scalar(
                    "SELECT EXISTS ( \
                        SELECT 1 FROM communication c \
                          JOIN communication_event e ON e.communication_id = c.id \
                         WHERE c.record_id = $1::text AND e.event_type = $2 AND e.occurred_at >= $3)",
                )
                .bind(person)
                .bind(event)
                .bind(since)
                .fetch_one(&state.base.db)
                .await
                .map_err(AppError::internal)?,
                _ => false,
            };
            Ok(StepOutcome::Done(json!({ "engaged": engaged })))
        })
    }
}

/// One branch of a split.
#[derive(Debug, Clone, PartialEq)]
pub struct Variant {
    pub name: String,
    pub weight: u64,
}

fn variants(config: &Value) -> Result<Vec<Variant>, String> {
    let list = config
        .get("variants")
        .and_then(Value::as_array)
        .ok_or("variants is a list of {name, weight}")?;
    if !(2..=10).contains(&list.len()) {
        return Err("a split has 2 to 10 variants".into());
    }
    list.iter()
        .map(|v| {
            let name = v
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .ok_or("each variant has a name")?;
            let weight = v
                .get("weight")
                .and_then(Value::as_u64)
                .filter(|w| (1..=1_000).contains(w))
                .ok_or("each variant's weight is 1 to 1000")?;
            Ok(Variant {
                name: name.to_owned(),
                weight,
            })
        })
        .collect()
}

/// FNV-1a over the run and the node: the same run reaching the same split
/// always lands in the same place, with no random state. Pure.
fn stable_hash(instance: Uuid, node: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in instance.as_bytes().iter().chain(node.as_bytes()) {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Finish (splitmix64) so nearby inputs spread over the whole range.
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

/// The branch a run takes. Pure.
pub fn pick(instance: Uuid, node: &str, variants: &[Variant]) -> Option<String> {
    let total: u64 = variants.iter().map(|v| v.weight).sum();
    if total == 0 {
        return None;
    }
    let mut point = stable_hash(instance, node) % total;
    for v in variants {
        if point < v.weight {
            return Some(v.name.clone());
        }
        point -= v.weight;
    }
    None
}

/// `marketing.split`: `{variants: [{name, weight}]}`. Done with `{branch}`;
/// a condition node downstream routes on it. An A/B test's assignment is
/// reported by the E4 testing feature when it is built.
#[derive(Debug)]
pub struct Split;

impl WorkflowStepHandler for Split {
    fn key(&self) -> &'static str {
        "marketing.split"
    }
    fn module_id(&self) -> ModuleId {
        MODULE_MARKETING
    }
    fn validate_config(&self, config: &Value) -> Result<(), String> {
        variants(config).map(|_| ())
    }
    fn run<'a>(&'a self, _state: &'a EngineState, inv: StepInvocation) -> StepFuture<'a> {
        Box::pin(async move {
            let variants = variants(&inv.config).map_err(AppError::Validation)?;
            let branch = pick(inv.instance_id, &inv.node_id, &variants)
                .ok_or_else(|| AppError::Validation("the split has no weight".into()))?;
            Ok(StepOutcome::Done(json!({ "branch": branch })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Weekday};
    use std::collections::{HashMap, HashSet};

    fn halves() -> Vec<Variant> {
        vec![
            Variant {
                name: "a".into(),
                weight: 50,
            },
            Variant {
                name: "b".into(),
                weight: 50,
            },
        ]
    }

    #[test]
    fn split_is_stable_across_replays() {
        let instance = Uuid::now_v7();
        let first = pick(instance, "split1", &halves());
        for _ in 0..10 {
            assert_eq!(pick(instance, "split1", &halves()), first);
        }
        assert!(
            Split
                .validate_config(&json!({ "variants": [{"name": "a", "weight": 1}] }))
                .is_err()
        );
    }

    #[test]
    fn split_respects_weights_within_2_percent_over_10000() {
        let variants = vec![
            Variant {
                name: "a".into(),
                weight: 70,
            },
            Variant {
                name: "b".into(),
                weight: 30,
            },
        ];
        let mut counts: HashMap<String, u32> = HashMap::new();
        for _ in 0..10_000 {
            let branch = pick(Uuid::now_v7(), "split", &variants).unwrap();
            *counts.entry(branch).or_default() += 1;
        }
        let a = f64::from(counts["a"]) / 10_000.0;
        assert!((a - 0.70).abs() < 0.02, "a got {a}");
    }

    #[test]
    fn calendar_wait_skips_friday_saturday() {
        let working: HashSet<Weekday> = [
            Weekday::Sun,
            Weekday::Mon,
            Weekday::Tue,
            Weekday::Wed,
            Weekday::Thu,
        ]
        .into_iter()
        .collect();
        let calendar = attome_calendar::BusinessCalendar::simple(
            chrono_tz::Asia::Riyadh,
            working,
            attome_calendar::TimeRange::try_new(9 * 60, 17 * 60).unwrap(),
        )
        .unwrap();
        // Friday 2026-10-23, noon in Riyadh.
        let friday: DateTime<Utc> = "2026-10-23T09:00:00Z".parse().unwrap();
        let next = calendar.next_working_moment(friday).unwrap();
        let local = next.with_timezone(&chrono_tz::Asia::Riyadh);
        assert_eq!(local.weekday(), Weekday::Sun);
        assert_eq!(local.format("%H:%M").to_string(), "09:00");
    }

    #[test]
    fn hijri_wait_lands_on_the_month_start() {
        let hijri = attome_calendar::hijri::HijriCalendar::umm_al_qura();
        let now: DateTime<Utc> = "2026-10-20T12:00:00Z".parse().unwrap();
        let at = NaiveTime::from_hms_opt(18, 30, 0).unwrap();
        let start = next_hijri_month_start(hijri, now, 9, at, chrono_tz::Asia::Riyadh).unwrap();
        assert!(start > now);
        let local = start.with_timezone(&chrono_tz::Asia::Riyadh);
        assert_eq!(hijri.to_hijri(local.date_naive()).unwrap().month, 9);
        assert_eq!(hijri.to_hijri(local.date_naive()).unwrap().day, 1);
        assert_eq!(local.format("%H:%M").to_string(), "18:30");
    }
}
