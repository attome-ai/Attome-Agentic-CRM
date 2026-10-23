//! Schedule triggers (roadmap M1-T2): a published flow whose trigger node has
//! `trigger_type: "schedule"` starts once per slot of its schedule.
//!
//! The trigger node's config carries the schedule under `schedule`, one of:
//! - `{"every_minutes": 15}`: every N minutes, aligned to the hour;
//! - `{"daily_at": "09:00", "weekdays": [1, 2, 3, 4, 5]}`: once a day at a
//!   local time, optionally only on ISO weekdays (1 = Monday … 7 = Sunday);
//! - `{"cron": "0 9 * * 1-5"}`: a five-field cron expression (minute, hour,
//!   day of month, month, day of week with 0 and 7 both Sunday; `*`, `a`,
//!   `a-b`, `*/n`, `a-b/n` and comma lists).
//!
//! Times are in the deployment's time zone (`app.time_zone`). Registration is
//! the flow's published `entry` row in `workflow_trigger_index`: publishing
//! registers it and unpublishing (or deactivating the flow) removes it, so
//! the sweep never needs a separate register/unregister step.
//!
//! The sweep runs inside the durable `EngineJob::WorkflowSlaSweep` (every
//! minute). Each run takes the latest slot at or before now that is newer
//! than the version's publish time and at most [`LOOKBACK_MINUTES`] old, and
//! claims it in `workflow_schedule_slot` (primary key = version, node, slot).
//! Only the run whose insert lands starts the flow, so a slot starts at most
//! once however many workers sweep; a start that fails releases its claim so
//! the next sweep retries it. Missed slots older than the newest one are not
//! replayed: a server that was down all night runs a nightly flow once.
//!
//! **M12-T1: once per record of a view.** A trigger whose config names
//! `for_each_record_of: "<view id>"` does not start one run per slot: the
//! slot starts a Z7 batch job ([`RECORD_SCHEDULE_JOB`]) that pages the view
//! (keyset, [`RECORD_PAGE`] ids at a time, read as the flow's publisher) and
//! starts one run per record, the record as the run's correlated record and
//! `{trigger, slot_at, record_id}` as its context. Each run's start is keyed
//! by (version, node, slot, record), so a chunk replayed after a crash
//! starts nothing twice. `overlap: "skip"` (the default) skips a slot while
//! the previous slot's batch still runs; `"queue"` starts it anyway.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Timelike, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::graph::Graph;

/// How far back a missed slot is still started.
pub const LOOKBACK_MINUTES: i64 = 24 * 60;

/// M12-T1: the Z7 job type of a slot's run over a view's records.
pub const RECORD_SCHEDULE_JOB: &str = "workflow_record_schedule";

/// M12-T1: record ids read per chunk.
pub const RECORD_PAGE: i64 = 100;

/// M12-T1: the view a trigger runs over, from `config.for_each_record_of`.
pub fn record_view(config: &Value) -> Option<Uuid> {
    config
        .get("for_each_record_of")
        .and_then(Value::as_str)
        .and_then(|raw| Uuid::parse_str(raw).ok())
}

/// M12-T1: whether a slot is skipped while the previous one's batch runs.
pub fn skips_overlap(config: &Value) -> bool {
    config.get("overlap").and_then(Value::as_str) != Some("queue")
}

/// M12-T1: a record run's start key, the same for a replayed chunk.
pub fn record_run_key(version: Uuid, node_id: &str, slot_at: DateTime<Utc>, record: Uuid) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!(
            "attome-workflow/record-schedule:{version}:{node_id}:{}:{record}",
            slot_at.to_rfc3339()
        )
        .as_bytes(),
    )
}

/// M12-T1: a record batch's work.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecordSchedulePayload {
    pub batch_id: Uuid,
    pub definition_version_id: Uuid,
    pub node_id: String,
    pub view_id: Uuid,
    pub slot_at: DateTime<Utc>,
    pub started_by: Option<Uuid>,
}

fn batch_name(version: Uuid, node_id: &str) -> String {
    format!("{RECORD_SCHEDULE_JOB}:{version}:{node_id}")
}

/// Starts a slot's batch over `view_id`; `None` when it was skipped because
/// the previous slot's batch still runs.
async fn start_record_batch(
    state: &EngineState,
    entry: &ScheduleEntry,
    view_id: Uuid,
    slot_at: DateTime<Utc>,
    skip_overlap: bool,
) -> Result<Option<Uuid>, AppError> {
    let name = batch_name(entry.definition_version_id, &entry.node_id);
    if skip_overlap {
        let running: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM job_batch WHERE name = $1 AND status = 'running')",
        )
        .bind(&name)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if running {
            return Ok(None);
        }
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let batch_id = attome_jobs::batch::start(&mut tx, &name, None, entry.started_by)
        .await
        .map_err(AppError::internal)?;
    let payload = RecordSchedulePayload {
        batch_id,
        definition_version_id: entry.definition_version_id,
        node_id: entry.node_id.clone(),
        view_id,
        slot_at,
        started_by: entry.started_by,
    };
    // Built here, not through the registry: a node that only schedules may
    // not have registered the job type (the worker has).
    let job = attome_jobs::RegisteredJob {
        name: RECORD_SCHEDULE_JOB.to_string(),
        version: 1,
        payload: serde_json::to_value(&payload).map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(batch_id))
}

struct RecordBatch<'a> {
    state: &'a EngineState,
    ctx: std::sync::Arc<attome_server::security::SecurityContext>,
    payload: RecordSchedulePayload,
}

impl attome_jobs::batch::BatchJob for RecordBatch<'_> {
    type Chunk = Vec<Uuid>;

    async fn next_chunk(
        &self,
        checkpoint: Option<&Value>,
    ) -> Result<Option<(Self::Chunk, Value)>, attome_jobs::registry::BoxError> {
        let after = checkpoint
            .and_then(|c| c["after"].as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
        let ids = attome_records::query_exec::execute_view_ids_page(
            self.state,
            &self.ctx,
            self.payload.view_id,
            after,
            RECORD_PAGE,
        )
        .await?;
        Ok(ids
            .last()
            .copied()
            .map(|last| (ids, serde_json::json!({ "after": last }))))
    }

    /// Each start commits on its own; the runner's `tx` carries only the
    /// checkpoint.
    async fn process(
        &self,
        _tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ids: Self::Chunk,
    ) -> Result<i64, attome_jobs::registry::BoxError> {
        let p = &self.payload;
        let mut started = 0;
        for record_id in ids {
            let context = serde_json::json!({
                "trigger": "schedule",
                "slot_at": p.slot_at.to_rfc3339(),
                "record_id": record_id,
            });
            let key = record_run_key(p.definition_version_id, &p.node_id, p.slot_at, record_id);
            if crate::instance_admin::start_instance_for_event(
                self.state,
                p.definition_version_id,
                &p.node_id,
                p.started_by,
                Some(record_id),
                context,
                key,
            )
            .await?
            .is_some()
            {
                started += 1;
            }
        }
        Ok(started)
    }
}

/// M12-T1: runs a slot's batch over its view (the binary registers this
/// under [`RECORD_SCHEDULE_JOB`]). The view is read as the person who
/// published the flow.
pub async fn run_record_batch(
    state: &EngineState,
    payload: RecordSchedulePayload,
) -> Result<(), attome_jobs::registry::BoxError> {
    let Some(user) = payload.started_by else {
        return Err("a record schedule needs the flow's publisher to read the view as".into());
    };
    let ctx = state.base.security.resolve(user).await?;
    let batch_id = payload.batch_id;
    let job = RecordBatch {
        state,
        ctx,
        payload,
    };
    attome_jobs::batch::run(&state.base.db, batch_id, &job).await?;
    Ok(())
}

/// One trigger's schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleSpec {
    EveryMinutes(u32),
    Cron(CronExpr),
}

/// A parsed five-field cron expression: the allowed values per field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    minutes: Vec<bool>,
    hours: Vec<bool>,
    days_of_month: Vec<bool>,
    months: Vec<bool>,
    /// 0 = Sunday … 6 = Saturday.
    days_of_week: Vec<bool>,
    dom_restricted: bool,
    dow_restricted: bool,
}

fn parse_field(field: &str, min: u32, max: u32, name: &str) -> Result<(Vec<bool>, bool), String> {
    let mut allowed = vec![false; max as usize + 1];
    let restricted = field != "*";
    for part in field.split(',') {
        let (range, step) = match part.split_once('/') {
            Some((range, step)) => {
                let step: u32 = step
                    .parse()
                    .map_err(|_| format!("cron {name}: step {step:?} is not a number"))?;
                if step == 0 {
                    return Err(format!("cron {name}: step must be at least 1"));
                }
                (range, step)
            }
            None => (part, 1),
        };
        let (lo, hi) = if range == "*" {
            (min, max)
        } else if let Some((a, b)) = range.split_once('-') {
            let a: u32 = a
                .parse()
                .map_err(|_| format!("cron {name}: {a:?} is not a number"))?;
            let b: u32 = b
                .parse()
                .map_err(|_| format!("cron {name}: {b:?} is not a number"))?;
            (a, b)
        } else {
            let a: u32 = range
                .parse()
                .map_err(|_| format!("cron {name}: {range:?} is not a number"))?;
            // `5/15` means from 5 to the end, every 15.
            (a, if part.contains('/') { max } else { a })
        };
        if lo < min || hi > max || lo > hi {
            return Err(format!(
                "cron {name}: {range:?} is outside {min}-{max} or reversed"
            ));
        }
        let mut v = lo;
        while v <= hi {
            allowed[v as usize] = true;
            v += step;
        }
    }
    Ok((allowed, restricted))
}

impl CronExpr {
    pub fn parse(expr: &str) -> Result<Self, String> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        let [minute, hour, dom, month, dow] = fields.as_slice() else {
            return Err(format!(
                "cron {expr:?} needs five fields: minute hour day-of-month month day-of-week"
            ));
        };
        let (minutes, _) = parse_field(minute, 0, 59, "minute")?;
        let (hours, _) = parse_field(hour, 0, 23, "hour")?;
        let (days_of_month, dom_restricted) = parse_field(dom, 1, 31, "day of month")?;
        let (months, _) = parse_field(month, 1, 12, "month")?;
        let (mut days_of_week, dow_restricted) = parse_field(dow, 0, 7, "day of week")?;
        // 7 is Sunday too.
        if days_of_week[7] {
            days_of_week[0] = true;
        }
        days_of_week.truncate(7);
        Ok(Self {
            minutes,
            hours,
            days_of_month,
            months,
            days_of_week,
            dom_restricted,
            dow_restricted,
        })
    }

    /// Whether `at` (local, to the minute) is a slot.
    pub fn matches(&self, at: NaiveDateTime) -> bool {
        let dom = self.days_of_month[at.day() as usize];
        let dow = self.days_of_week[at.weekday().num_days_from_sunday() as usize];
        // Standard cron: with both day fields restricted, either may match.
        let day = match (self.dom_restricted, self.dow_restricted) {
            (true, true) => dom || dow,
            _ => dom && dow,
        };
        self.minutes[at.minute() as usize]
            && self.hours[at.hour() as usize]
            && self.months[at.month() as usize]
            && day
    }
}

/// The trigger node's `schedule` config, parsed.
pub fn parse_schedule(config: &Value) -> Result<ScheduleSpec, String> {
    let schedule = config
        .get("schedule")
        .ok_or("a schedule trigger needs a `schedule` object")?;
    if let Some(n) = schedule.get("every_minutes") {
        let n = n
            .as_u64()
            .filter(|n| (1..=24 * 60).contains(n))
            .ok_or("`every_minutes` must be a whole number from 1 to 1440")?;
        return Ok(ScheduleSpec::EveryMinutes(n as u32));
    }
    if let Some(expr) = schedule.get("cron").and_then(Value::as_str) {
        return CronExpr::parse(expr).map(ScheduleSpec::Cron);
    }
    if let Some(at) = schedule.get("daily_at").and_then(Value::as_str) {
        let (h, m) = at
            .split_once(':')
            .and_then(|(h, m)| Some((h.parse::<u32>().ok()?, m.parse::<u32>().ok()?)))
            .filter(|(h, m)| *h < 24 && *m < 60)
            .ok_or("`daily_at` must be HH:MM")?;
        let weekdays = match schedule.get("weekdays") {
            None | Some(Value::Null) => "*".to_owned(),
            Some(Value::Array(days)) => {
                let mut out = Vec::new();
                for d in days {
                    let d = d
                        .as_u64()
                        .filter(|d| (1..=7).contains(d))
                        .ok_or("`weekdays` holds ISO weekdays 1 (Monday) to 7 (Sunday)")?;
                    out.push((d % 7).to_string());
                }
                if out.is_empty() {
                    return Err("`weekdays` must name at least one day".to_owned());
                }
                out.join(",")
            }
            Some(_) => return Err("`weekdays` must be an array".to_owned()),
        };
        return CronExpr::parse(&format!("{m} {h} * * {weekdays}")).map(ScheduleSpec::Cron);
    }
    Err("`schedule` needs `every_minutes`, `daily_at` or `cron`".to_owned())
}

/// The newest slot at or before `now` and after `floor` (both local, the
/// deployment's wall clock), to the minute.
pub fn latest_slot(
    spec: &ScheduleSpec,
    now: NaiveDateTime,
    floor: NaiveDateTime,
) -> Option<NaiveDateTime> {
    let now = now.with_second(0)?.with_nanosecond(0)?;
    let earliest = floor.max(now - Duration::minutes(LOOKBACK_MINUTES));
    let slot = match spec {
        ScheduleSpec::EveryMinutes(n) => {
            let n = i64::from(*n);
            let minutes = now.and_utc().timestamp() / 60;
            let aligned = minutes - minutes.rem_euclid(n);
            DateTime::from_timestamp(aligned * 60, 0)?.naive_utc()
        }
        ScheduleSpec::Cron(expr) => {
            let mut at = now;
            loop {
                if at < earliest {
                    return None;
                }
                if expr.matches(at) {
                    break at;
                }
                at -= Duration::minutes(1);
            }
        }
    };
    (slot >= earliest).then_some(slot)
}

/// M12-T3: the first slot after `now` (local, to the minute), looking at
/// most eight days ahead.
pub fn next_slot(spec: &ScheduleSpec, now: NaiveDateTime) -> Option<NaiveDateTime> {
    let now = now.with_second(0)?.with_nanosecond(0)?;
    match spec {
        ScheduleSpec::EveryMinutes(n) => {
            let n = i64::from(*n);
            let minutes = now.and_utc().timestamp() / 60;
            let next = minutes - minutes.rem_euclid(n) + n;
            Some(DateTime::from_timestamp(next * 60, 0)?.naive_utc())
        }
        ScheduleSpec::Cron(expr) => {
            let mut at = now + Duration::minutes(1);
            let last = now + Duration::days(8);
            while at <= last {
                if expr.matches(at) {
                    return Some(at);
                }
                at += Duration::minutes(1);
            }
            None
        }
    }
}

#[derive(sqlx::FromRow)]
struct ScheduleEntry {
    definition_version_id: Uuid,
    node_id: String,
    graph: Value,
    published_at: Option<DateTime<Utc>>,
    started_by: Option<Uuid>,
}

/// Starts every schedule-triggered flow whose slot is due. Returns how many
/// started.
pub async fn run_due(state: &EngineState) -> Result<u64, AppError> {
    let now = attome_core::calendar::deployment_now(state.base.config.app.time_zone.as_deref());
    run_due_at(state, now).await
}

/// [`run_due`] at a given wall clock (tests pass a fake one).
pub async fn run_due_at(
    state: &EngineState,
    now: DateTime<chrono::FixedOffset>,
) -> Result<u64, AppError> {
    let entries: Vec<ScheduleEntry> = sqlx::query_as(
        "SELECT t.definition_version_id, t.node_id, v.graph, v.published_at, \
                COALESCE(v.published_by, d.created_by) AS started_by \
           FROM workflow_trigger_index t \
           JOIN workflow_definition_version v ON v.id = t.definition_version_id \
           JOIN workflow_definition d ON d.id = v.definition_id \
          WHERE t.role = 'entry' AND t.match_type = 'schedule' \
            AND v.status = 'published' AND d.is_active AND NOT d.is_deleted \
            AND NOT EXISTS (SELECT 1 FROM schedule_pause p WHERE p.kind = 'flow' \
                             AND p.target = d.id::text || ':' || t.node_id)",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    // M12-T3: a slot over a view's records is heavy work; it waits out a
    // quiet window unclaimed and starts once the window closes.
    let quiet = attome_core::quiet_window::quiet_now(state);

    let offset = *now.offset();
    let local_now = now.naive_local();
    let mut started = 0u64;
    for entry in entries {
        let Ok(graph) = serde_json::from_value::<Graph>(entry.graph.clone()) else {
            continue;
        };
        let Some(node) = graph.nodes.iter().find(|n| n.id == entry.node_id) else {
            continue;
        };
        let spec = match parse_schedule(&node.config) {
            Ok(spec) => spec,
            Err(reason) => {
                tracing::warn!(
                    definition_version_id = %entry.definition_version_id,
                    node_id = %entry.node_id,
                    reason,
                    "workflow schedule trigger: invalid schedule, skipped"
                );
                continue;
            }
        };
        let floor = entry
            .published_at
            .map(|at| at.with_timezone(&offset).naive_local())
            .unwrap_or(local_now - Duration::minutes(LOOKBACK_MINUTES));
        if quiet && record_view(&node.config).is_some() {
            continue;
        }
        let Some(slot_local) = latest_slot(&spec, local_now, floor) else {
            continue;
        };
        let Some(slot_at) = slot_local
            .and_local_timezone(offset)
            .single()
            .map(|at| at.with_timezone(&Utc))
        else {
            continue;
        };

        let claimed = sqlx::query(
            "INSERT INTO workflow_schedule_slot (definition_version_id, node_id, slot_at) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(entry.definition_version_id)
        .bind(&entry.node_id)
        .bind(slot_at)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
            == 1;
        if !claimed {
            continue;
        }

        // M12-T1: a slot over a view's records starts a batch, not a run.
        if let Some(view_id) = record_view(&node.config) {
            match start_record_batch(state, &entry, view_id, slot_at, skips_overlap(&node.config))
                .await
            {
                Ok(Some(_)) => started += 1,
                Ok(None) => tracing::info!(
                    definition_version_id = %entry.definition_version_id,
                    node_id = %entry.node_id,
                    %slot_at,
                    "workflow schedule trigger: the previous slot's records still run; slot skipped"
                ),
                Err(e) => {
                    tracing::error!(
                        definition_version_id = %entry.definition_version_id,
                        node_id = %entry.node_id,
                        %slot_at,
                        error = %e,
                        "workflow schedule trigger: record batch start failed; the slot is released for retry"
                    );
                    sqlx::query(
                        "DELETE FROM workflow_schedule_slot \
                          WHERE definition_version_id = $1 AND node_id = $2 AND slot_at = $3 \
                            AND instance_id IS NULL",
                    )
                    .bind(entry.definition_version_id)
                    .bind(&entry.node_id)
                    .bind(slot_at)
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                }
            }
            continue;
        }

        let context = serde_json::json!({
            "trigger": "schedule",
            "slot_at": slot_at.to_rfc3339(),
        });
        match crate::instance_admin::start_instance_internal(
            state,
            entry.definition_version_id,
            Some(&entry.node_id),
            entry.started_by,
            None,
            context,
        )
        .await
        {
            Ok(instance_id) => {
                sqlx::query(
                    "UPDATE workflow_schedule_slot SET instance_id = $4 \
                      WHERE definition_version_id = $1 AND node_id = $2 AND slot_at = $3",
                )
                .bind(entry.definition_version_id)
                .bind(&entry.node_id)
                .bind(slot_at)
                .bind(instance_id)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                started += 1;
            }
            Err(e) => {
                tracing::error!(
                    definition_version_id = %entry.definition_version_id,
                    node_id = %entry.node_id,
                    %slot_at,
                    error = %e,
                    "workflow schedule trigger: start failed; the slot is released for retry"
                );
                sqlx::query(
                    "DELETE FROM workflow_schedule_slot \
                      WHERE definition_version_id = $1 AND node_id = $2 AND slot_at = $3 \
                        AND instance_id IS NULL",
                )
                .bind(entry.definition_version_id)
                .bind(&entry.node_id)
                .bind(slot_at)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
        }
    }
    Ok(started)
}

#[cfg(test)]
mod schedule_trigger_tests {
    use super::*;
    use chrono::NaiveDate;
    use serde_json::json;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, mo, d)
            .and_then(|date| date.and_hms_opt(h, mi, 0))
            .expect("valid date")
    }

    #[test]
    fn schedule_trigger_daily_at_runs_once_per_slot_on_working_days() {
        let spec = parse_schedule(
            &json!({"schedule": {"daily_at": "09:00", "weekdays": [1, 2, 3, 4, 5]}}),
        )
        .expect("parses");
        let published = at(2026, 10, 12, 8, 0); // Monday
        // Before 09:00 on the publish day: nothing yet.
        assert_eq!(latest_slot(&spec, at(2026, 10, 12, 8, 59), published), None);
        // At and after 09:00: the same slot, so the ledger starts it once.
        let slot = at(2026, 10, 12, 9, 0);
        assert_eq!(latest_slot(&spec, slot, published), Some(slot));
        assert_eq!(
            latest_slot(&spec, at(2026, 10, 12, 17, 30), published),
            Some(slot)
        );
        // Saturday 08:00 (2026-10-17): the newest slot is still Friday's.
        assert_eq!(
            latest_slot(&spec, at(2026, 10, 17, 8, 0), published),
            Some(at(2026, 10, 16, 9, 0))
        );
        // Sunday 10:00: Friday's slot is past the look-back, so none.
        assert_eq!(latest_slot(&spec, at(2026, 10, 18, 10, 0), published), None);
    }

    #[test]
    fn schedule_trigger_never_runs_a_slot_before_publish() {
        let spec = parse_schedule(&json!({"schedule": {"daily_at": "09:00"}})).expect("parses");
        assert_eq!(
            latest_slot(&spec, at(2026, 10, 12, 10, 0), at(2026, 10, 12, 9, 30)),
            None
        );
    }

    #[test]
    fn schedule_trigger_every_minutes_aligns_to_the_hour() {
        let spec = parse_schedule(&json!({"schedule": {"every_minutes": 15}})).expect("parses");
        let floor = at(2026, 10, 12, 0, 0);
        assert_eq!(
            latest_slot(&spec, at(2026, 10, 12, 9, 44), floor),
            Some(at(2026, 10, 12, 9, 30))
        );
        assert_eq!(
            latest_slot(&spec, at(2026, 10, 12, 9, 45), floor),
            Some(at(2026, 10, 12, 9, 45))
        );
    }

    #[test]
    fn schedule_trigger_cron_fields() {
        let expr = CronExpr::parse("*/20 8-10 * * 0,7").expect("parses");
        assert!(expr.matches(at(2026, 10, 18, 8, 40))); // Sunday
        assert!(!expr.matches(at(2026, 10, 18, 11, 0)));
        assert!(!expr.matches(at(2026, 10, 19, 8, 40))); // Monday
        // Both day fields restricted: either matches.
        let either = CronExpr::parse("0 0 1 * 1").expect("parses");
        assert!(either.matches(at(2026, 10, 1, 0, 0))); // Thursday the 1st
        assert!(either.matches(at(2026, 10, 12, 0, 0))); // a Monday
        assert!(!either.matches(at(2026, 10, 13, 0, 0)));
    }

    #[test]
    fn schedule_trigger_rejects_bad_schedules() {
        for bad in [
            json!({}),
            json!({"schedule": {"every_minutes": 0}}),
            json!({"schedule": {"daily_at": "25:00"}}),
            json!({"schedule": {"daily_at": "09:00", "weekdays": [8]}}),
            json!({"schedule": {"cron": "* * *"}}),
            json!({"schedule": {"cron": "61 * * * *"}}),
            json!({"schedule": {"cron": "*/0 * * * *"}}),
        ] {
            assert!(parse_schedule(&bad).is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn schedule_trigger_record_runs_name_their_view_and_overlap() {
        let view = Uuid::now_v7();
        let config = serde_json::json!({ "for_each_record_of": view.to_string() });
        assert_eq!(record_view(&config), Some(view));
        assert!(skips_overlap(&config), "skip is the default");
        assert!(!skips_overlap(&serde_json::json!({ "overlap": "queue" })));
        assert_eq!(
            record_view(&serde_json::json!({ "for_each_record_of": "x" })),
            None
        );
    }

    #[test]
    fn schedule_trigger_record_run_key_is_stable_per_slot_and_record() {
        let (version, record) = (Uuid::now_v7(), Uuid::now_v7());
        let slot = DateTime::parse_from_rfc3339("2026-10-23T06:00:00Z")
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_default();
        let key = record_run_key(version, "t", slot, record);
        assert_eq!(key, record_run_key(version, "t", slot, record));
        assert_ne!(
            key,
            record_run_key(version, "t", slot + Duration::days(1), record)
        );
        assert_ne!(key, record_run_key(version, "t", slot, Uuid::now_v7()));
    }

    #[test]
    fn schedules_next_slot_follows_the_schedule() {
        let at = |s: &str| NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").unwrap();
        let every = ScheduleSpec::EveryMinutes(15);
        assert_eq!(
            next_slot(&every, at("2026-10-23 10:07")),
            Some(at("2026-10-23 10:15"))
        );
        assert_eq!(
            next_slot(&every, at("2026-10-23 10:15")),
            Some(at("2026-10-23 10:30"))
        );
        let weekday_nine =
            parse_schedule(&serde_json::json!({ "schedule": { "cron": "0 9 * * 1-5" } })).unwrap();
        // 2026-10-23 is a Friday: the next weekday 09:00 is Monday the 26th.
        assert_eq!(
            next_slot(&weekday_nine, at("2026-10-23 10:00")),
            Some(at("2026-10-26 09:00"))
        );
    }
}
