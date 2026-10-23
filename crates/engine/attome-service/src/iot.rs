//! I7-T1: device readings, their latest values and hourly summaries, and the
//! device rules that open work from them.
//!
//! **Intake.** A reading is an `asset_meter_reading` record (asset-management
//! pack `0002`). A device that knows its asset's id posts it through an M14
//! inbound hook whose record handler maps the payload to that entity. A
//! device that knows only its own id posts to
//! `POST /api/v1/service/device-readings`: each reading names `device_id`,
//! the asset holding that `device_id` (field-service pack `0010`) is looked
//! up, and the reading is created through the generic write path as the
//! caller. Either way the record engine validates, audits and emits it.
//!
//! **Latest and hourly.** The `device_readings` job reads new readings off
//! the change feed. Each reading is counted once (`device_reading_counted`)
//! into its hour's summary (`device_hourly_summary`: count, minimum, maximum,
//! sum and the last value) and becomes the asset's latest value of its meter
//! (`device_latest_reading`) unless a later reading already is; a feed
//! replay after a crash counts nothing twice. An edited or deleted reading
//! does not change a summary already made.
//!
//! **Rules.** A `device_rule` (pack `0010`) names a meter, optionally one
//! asset, and a condition in the business-rules language over `reading`,
//! `previous` (the asset's latest value before this reading, or null),
//! `meter` and `unit`, such as `reading > 90`. When it holds, the rule opens
//! a work order or a case for the asset, as the rule's owner, through the
//! generic write path. A rule fires at most once per asset within its quiet
//! period (`debounce_minutes`, default an hour) either side of the reading's
//! time, and once per reading: the fire is claimed under an advisory lock
//! before the record is made, and released again when the create fails, so
//! the next matching reading tries again. A condition that does not compile
//! or does not give true or false is logged and the rule skipped.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_rules::{Context, Schema, Type, Value as RulesValue, compile};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::post};
use chrono::{DateTime, Duration, DurationRound, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job.
pub const JOB: &str = "device_readings";
/// This consumer's change-feed cursor.
const CONSUMER: &str = "attome-service/device-readings";
/// Events read per tick.
const BATCH: i64 = 500;
/// The most enabled rules one tick evaluates.
const MAX_RULES: i64 = 1_000;
/// The quiet period of a rule that names none, in minutes.
const DEFAULT_DEBOUNCE_MINUTES: i64 = 60;
/// The longest quiet period honoured: a week.
const MAX_DEBOUNCE_MINUTES: i64 = 10_080;
/// The most readings one intake call takes.
pub const MAX_INTAKE: usize = 500;
/// How long a counted reading's id is kept against replays, in days.
const COUNTED_KEEP_DAYS: i32 = 3;

const READING: &str = "asset_meter_reading";
const RULE: &str = "device_rule";

/// What a rule opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    WorkOrder,
    Case,
}

impl Action {
    pub fn parse(value: Option<&str>) -> Option<Self> {
        match value? {
            "work_order" => Some(Self::WorkOrder),
            "case" => Some(Self::Case),
            _ => None,
        }
    }

    pub fn entity(self) -> &'static str {
        match self {
            Self::WorkOrder => "work_order",
            Self::Case => "service_ticket",
        }
    }
}

/// The start of the hour `at` falls in. Pure.
pub fn hour_of(at: DateTime<Utc>) -> DateTime<Utc> {
    at.duration_trunc(Duration::hours(1)).unwrap_or(at)
}

/// A rule's quiet period in minutes: its own, clamped, or the default. Pure.
pub fn debounce_minutes(value: Option<f64>) -> i64 {
    value
        .filter(|m| m.is_finite() && *m >= 0.0)
        .map(|m| m.round() as i64)
        .unwrap_or(DEFAULT_DEBOUNCE_MINUTES)
        .min(MAX_DEBOUNCE_MINUTES)
}

/// The readings times a fire at `at` keeps quiet: `minutes` either side,
/// end exclusive. Pure.
pub fn quiet_window(at: DateTime<Utc>, minutes: i64) -> (DateTime<Utc>, DateTime<Utc>) {
    let span = Duration::minutes(minutes);
    (at - span, at + span)
}

/// A work order's priority for a rule's priority (the work order's own
/// choices). Pure.
pub fn work_order_priority(value: Option<&str>) -> &'static str {
    match value {
        Some("low") => "low",
        Some("high") => "high",
        Some("urgent") => "urgent",
        _ => "normal",
    }
}

/// A case's priority for a rule's priority (the case's choices are low,
/// medium, high and critical). Pure.
pub fn case_priority(value: Option<&str>) -> &'static str {
    match value {
        Some("low") => "low",
        Some("high") => "high",
        Some("urgent") => "critical",
        _ => "medium",
    }
}

/// One reading, as the rules see it.
#[derive(Debug, Clone, PartialEq)]
pub struct Reading {
    pub id: Uuid,
    pub asset: Uuid,
    pub meter: String,
    pub value: f64,
    pub unit: Option<String>,
    pub read_at: DateTime<Utc>,
}

/// One enabled device rule.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceRule {
    pub id: Uuid,
    pub name: Option<String>,
    pub meter: Option<String>,
    pub condition: Option<String>,
    pub action: Option<String>,
    pub asset_ref: Option<Uuid>,
    pub priority: Option<String>,
    pub debounce_minutes: Option<f64>,
    pub owner: Option<Uuid>,
}

/// Whether `rule` is about `reading`'s meter and asset. Pure.
pub fn applies(rule: &DeviceRule, reading: &Reading) -> bool {
    rule.meter.as_deref().map(str::trim) == Some(reading.meter.as_str())
        && rule.asset_ref.is_none_or(|a| a == reading.asset)
}

fn rules_schema() -> Schema {
    Schema::new()
        .with_field("reading", Type::Number)
        .with_field("previous", Type::Number)
        .with_field("meter", Type::Text)
        .with_field("unit", Type::Text)
}

fn rules_context(reading: &Reading, previous: Option<f64>) -> Context {
    Context::new(Utc::now())
        .with_field("reading", RulesValue::Number(reading.value))
        .with_field(
            "previous",
            previous
                .filter(|p| p.is_finite())
                .map_or(RulesValue::Null, RulesValue::Number),
        )
        .with_field("meter", RulesValue::Text(reading.meter.clone()))
        .with_field(
            "unit",
            reading
                .unit
                .clone()
                .map_or(RulesValue::Null, RulesValue::Text),
        )
}

/// Whether `condition` holds for `reading`: `Ok(None)` when it gives neither
/// true nor false (a null comparison). Pure.
pub fn holds(
    condition: &str,
    reading: &Reading,
    previous: Option<f64>,
) -> Result<Option<bool>, String> {
    let compiled = compile(condition, &rules_schema()).map_err(|e| e.to_string())?;
    match compiled.eval(&rules_context(reading, previous)) {
        Ok(RulesValue::Bool(b)) => Ok(Some(b)),
        Ok(RulesValue::Null) => Ok(None),
        Ok(other) => Err(format!("the condition gives {other:?}, not true or false")),
        Err(e) => Err(e.to_string()),
    }
}

/// The record a fire opens. Pure.
pub fn target_body(
    rule: &DeviceRule,
    action: Action,
    reading: &Reading,
    owner: Uuid,
) -> serde_json::Value {
    let name = rule
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .unwrap_or("Device rule");
    let unit = reading.unit.as_deref().unwrap_or("");
    let title: String = format!("{name}: {} {}{unit}", reading.meter, reading.value)
        .trim()
        .chars()
        .take(200)
        .collect();
    let description = format!(
        "Reading {} {}{unit} at {} from asset {} met the condition of device rule {}.",
        reading.meter,
        reading.value,
        reading.read_at.to_rfc3339(),
        reading.asset,
        rule.id
    );
    match action {
        Action::WorkOrder => json!({
            "title": title,
            "asset_ref": reading.asset,
            "summary": description,
            "priority": work_order_priority(rule.priority.as_deref()),
            "status": "new",
        }),
        Action::Case => json!({
            "ticket_number": crate::intake::placeholder_number("TKT"),
            "title": title,
            "description": description,
            "requester_id": owner.to_string(),
            "priority": case_priority(rule.priority.as_deref()),
            "status": "new",
        }),
    }
}

// ── The sweep ──────────────────────────────────────────────────────────────

/// What one tick did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceRun {
    pub readings: usize,
    pub counted: usize,
    pub fired: usize,
    pub failed: usize,
}

/// Rules compiled once per tick, with their owners' contexts.
struct Rules {
    rules: Vec<DeviceRule>,
    owners: HashMap<Uuid, Arc<SecurityContext>>,
}

async fn load_rules(state: &EngineState) -> Result<Vec<DeviceRule>, AppError> {
    if state.entities.load().get(RULE).is_none() {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT id, name, meter, condition, action, asset_ref, priority, \
                debounce_minutes::float8 AS debounce_minutes, \
                COALESCE(owner_ref, created_by) AS owner \
           FROM device_rule \
          WHERE is_active AND (enabled IS NULL OR enabled) \
          ORDER BY id LIMIT $1",
    )
    .bind(MAX_RULES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// One pass over new readings on the change feed.
pub async fn tick(state: &EngineState) -> Result<DeviceRun, AppError> {
    let mut run = DeviceRun::default();
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(run);
    };
    let ids: BTreeSet<Uuid> = events
        .iter()
        .filter(|e| {
            e.entity_logicalname == READING
                && e.event_name.is_none()
                && e.operation() == Some(ChangeOperation::Create)
        })
        .map(|e| e.record_id)
        .collect();
    if !ids.is_empty() && state.entities.load().get(READING).is_some() {
        let mut rules = Rules {
            rules: load_rules(state).await?,
            owners: HashMap::new(),
        };
        for id in ids {
            run.readings += 1;
            match process(state, &mut rules, id).await {
                Ok((counted, fired, failed)) => {
                    run.counted += usize::from(counted);
                    run.fired += fired;
                    run.failed += failed;
                }
                Err(e) => {
                    run.failed += 1;
                    tracing::warn!(reading = %id, error = %e, "device readings: reading not processed");
                }
            }
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    change_feed::advance(&mut conn, CONSUMER, &last).await?;
    sqlx::query(
        "DELETE FROM device_reading_counted WHERE counted_at < now() - make_interval(days => $1)",
    )
    .bind(COUNTED_KEEP_DAYS)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(run)
}

/// Counts one reading and fires the rules it meets, loading the enabled
/// rules itself. Whether it was counted now, and the fires made and failed.
pub async fn process_reading(
    state: &EngineState,
    reading_id: Uuid,
) -> Result<(bool, usize, usize), AppError> {
    let mut rules = Rules {
        rules: load_rules(state).await?,
        owners: HashMap::new(),
    };
    process(state, &mut rules, reading_id).await
}

#[derive(sqlx::FromRow)]
struct ReadingRow {
    asset_ref: Option<Uuid>,
    meter: Option<String>,
    reading: Option<f64>,
    unit: Option<String>,
    read_at: Option<DateTime<Utc>>,
}

async fn load_reading(state: &EngineState, id: Uuid) -> Result<Option<Reading>, AppError> {
    let row: Option<ReadingRow> = sqlx::query_as(
        "SELECT asset_ref, meter, reading::float8 AS reading, unit, \
                read_at::timestamptz AS read_at \
           FROM asset_meter_reading WHERE id = $1 AND is_active",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(row.and_then(|r| {
        Some(Reading {
            id,
            asset: r.asset_ref?,
            meter: r
                .meter
                .map(|m| m.trim().to_owned())
                .filter(|m| !m.is_empty())?,
            value: r.reading.filter(|v| v.is_finite())?,
            unit: r.unit,
            read_at: r.read_at?,
        })
    }))
}

/// Counts `reading` into its hour and the latest values, once. The asset's
/// latest value of the meter before it, and whether it was counted now.
async fn count(state: &EngineState, reading: &Reading) -> Result<(Option<f64>, bool), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let previous: Option<f64> = sqlx::query_scalar(
        "SELECT reading FROM device_latest_reading WHERE asset_id = $1 AND meter = $2",
    )
    .bind(reading.asset)
    .bind(&reading.meter)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let fresh = sqlx::query(
        "INSERT INTO device_reading_counted (reading_id) VALUES ($1) ON CONFLICT DO NOTHING",
    )
    .bind(reading.id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected()
        == 1;
    if !fresh {
        attome_db::tx::commit(tx).await?;
        return Ok((previous, false));
    }
    sqlx::query(
        "INSERT INTO device_hourly_summary \
             (asset_id, meter, hour, readings, min_reading, max_reading, sum_reading, \
              last_reading, last_read_at) \
         VALUES ($1, $2, $3, 1, $4, $4, $4, $4, $5) \
         ON CONFLICT (asset_id, meter, hour) DO UPDATE SET \
             readings = device_hourly_summary.readings + 1, \
             min_reading = LEAST(device_hourly_summary.min_reading, EXCLUDED.min_reading), \
             max_reading = GREATEST(device_hourly_summary.max_reading, EXCLUDED.max_reading), \
             sum_reading = device_hourly_summary.sum_reading + EXCLUDED.sum_reading, \
             last_reading = CASE WHEN EXCLUDED.last_read_at >= device_hourly_summary.last_read_at \
                                 THEN EXCLUDED.last_reading ELSE device_hourly_summary.last_reading END, \
             last_read_at = GREATEST(device_hourly_summary.last_read_at, EXCLUDED.last_read_at)",
    )
    .bind(reading.asset)
    .bind(&reading.meter)
    .bind(hour_of(reading.read_at))
    .bind(reading.value)
    .bind(reading.read_at)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO device_latest_reading (asset_id, meter, reading, unit, read_at, reading_id) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (asset_id, meter) DO UPDATE SET \
             reading = EXCLUDED.reading, unit = EXCLUDED.unit, read_at = EXCLUDED.read_at, \
             reading_id = EXCLUDED.reading_id \
         WHERE device_latest_reading.read_at <= EXCLUDED.read_at",
    )
    .bind(reading.asset)
    .bind(&reading.meter)
    .bind(reading.value)
    .bind(&reading.unit)
    .bind(reading.read_at)
    .bind(reading.id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok((previous, true))
}

async fn process(
    state: &EngineState,
    rules: &mut Rules,
    reading_id: Uuid,
) -> Result<(bool, usize, usize), AppError> {
    let Some(reading) = load_reading(state, reading_id).await? else {
        return Ok((false, 0, 0));
    };
    let (previous, counted) = count(state, &reading).await?;
    let (mut fired, mut failed) = (0, 0);
    let matching: Vec<DeviceRule> = rules
        .rules
        .iter()
        .filter(|r| applies(r, &reading))
        .cloned()
        .collect();
    for rule in matching {
        let Some(action) = Action::parse(rule.action.as_deref()) else {
            continue;
        };
        let condition = rule.condition.as_deref().map(str::trim).unwrap_or("");
        match holds(condition, &reading, previous) {
            Ok(Some(true)) => {}
            Ok(_) => continue,
            Err(e) => {
                tracing::warn!(rule = %rule.id, error = %e, "device rule condition skipped");
                continue;
            }
        }
        match fire(state, rules, &rule, action, &reading).await {
            Ok(true) => fired += 1,
            Ok(false) => {}
            Err(e) => {
                failed += 1;
                tracing::warn!(rule = %rule.id, reading = %reading.id, error = %e, "device rule did not fire");
            }
        }
    }
    Ok((counted, fired, failed))
}

async fn owner_ctx(
    state: &EngineState,
    rules: &mut Rules,
    rule: &DeviceRule,
    action: Action,
) -> Result<Arc<SecurityContext>, AppError> {
    let owner = rule
        .owner
        .ok_or_else(|| AppError::Validation("the device rule has no owner".into()))?;
    let ctx = match rules.owners.get(&owner) {
        Some(ctx) => ctx.clone(),
        None => {
            let ctx = state.base.security.resolve_strict(owner).await?;
            rules.owners.insert(owner, ctx.clone());
            ctx
        }
    };
    ctx.require(action.entity(), "create")?;
    Ok(ctx)
}

/// Claims and makes one fire; false when the quiet period, an earlier fire
/// for the same reading, or a concurrent runner holds it back.
async fn fire(
    state: &EngineState,
    rules: &mut Rules,
    rule: &DeviceRule,
    action: Action,
    reading: &Reading,
) -> Result<bool, AppError> {
    let ctx = owner_ctx(state, rules, rule, action).await?;
    let (from, until) = quiet_window(reading.read_at, debounce_minutes(rule.debounce_minutes));
    let db = &state.base.db;
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-service/device-rule:{}:{}",
            rule.id, reading.asset
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(false);
    }
    let quiet: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM device_rule_fire \
                         WHERE rule_id = $1 AND asset_id = $2 \
                           AND (reading_id = $3 OR (read_at > $4 AND read_at < $5)))",
    )
    .bind(rule.id)
    .bind(reading.asset)
    .bind(reading.id)
    .bind(from)
    .bind(until)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if quiet {
        return Ok(false);
    }
    sqlx::query(
        "INSERT INTO device_rule_fire (rule_id, asset_id, reading_id, read_at, target_entity) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(rule.id)
    .bind(reading.asset)
    .bind(reading.id)
    .bind(reading.read_at)
    .bind(action.entity())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;

    let body = target_body(rule, action, reading, ctx.user_id);
    match attome_records::entity_crud::create_record_for(
        state,
        &ctx,
        ctx.user_id,
        action.entity(),
        body,
    )
    .await
    {
        Ok((target, _)) => {
            sqlx::query(
                "UPDATE device_rule_fire SET target_id = $3 WHERE rule_id = $1 AND reading_id = $2",
            )
            .bind(rule.id)
            .bind(reading.id)
            .bind(target)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            Ok(true)
        }
        Err(e) => {
            sqlx::query("DELETE FROM device_rule_fire WHERE rule_id = $1 AND reading_id = $2")
                .bind(rule.id)
                .bind(reading.id)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            Err(e)
        }
    }
}

// ── Intake by device id ────────────────────────────────────────────────────

/// `asset_meter_reading.create`: who may post device readings.
#[derive(Debug)]
pub struct ReadingCreate;

impl PrivilegeKey for ReadingCreate {
    const KEY: &'static str = "asset_meter_reading.create";
}

/// One reading a device posts.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[schema(as = DeviceReadingIn)]
pub struct ReadingIn {
    /// The device's id, as the asset's `device_id` holds it.
    pub device_id: String,
    pub meter: String,
    pub reading: f64,
    pub unit: Option<String>,
    /// When the device read it; now when absent.
    pub read_at: Option<DateTime<Utc>>,
}

/// Readings a device posts, up to 500.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[schema(as = DeviceReadingsIn)]
pub struct ReadingsIn {
    pub readings: Vec<ReadingIn>,
}

/// One posted reading's result.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(as = DeviceReadingResult)]
pub struct ReadingResult {
    pub device_id: String,
    /// The reading record made, when one was.
    pub reading_id: Option<Uuid>,
    /// Why none was: `unknown_device`, `invalid` or the write's error.
    pub error: Option<String>,
}

/// Each posted reading's result, in order.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[schema(as = DeviceReadingsResult)]
pub struct ReadingsResult {
    pub results: Vec<ReadingResult>,
}

/// Checks one posted reading. Pure.
pub fn check_reading(input: &ReadingIn) -> Result<(), &'static str> {
    if input.device_id.trim().is_empty() || input.device_id.len() > 200 {
        return Err("invalid");
    }
    if input.meter.trim().is_empty() || input.meter.len() > 100 || !input.reading.is_finite() {
        return Err("invalid");
    }
    Ok(())
}

/// What a posted reading's result says of a failed write: the client's own
/// mistake in full, anything else masked.
fn public_error(e: &AppError) -> String {
    match e {
        AppError::Validation(_)
        | AppError::FieldValidation(_)
        | AppError::Forbidden
        | AppError::AttributeNotWritable(_) => e.to_string(),
        _ => "the reading could not be recorded".into(),
    }
}

/// Creates a reading for each posted one whose device is an asset's, as
/// `ctx`. A reading that fails does not stop the others.
pub async fn intake(
    state: &EngineState,
    ctx: &SecurityContext,
    input: ReadingsIn,
) -> Result<ReadingsResult, AppError> {
    if input.readings.is_empty() || input.readings.len() > MAX_INTAKE {
        return Err(AppError::Validation(format!(
            "post between 1 and {MAX_INTAKE} readings"
        )));
    }
    // The device id is field-service pack `0010`'s, as are the rules.
    if state.entities.load().get(READING).is_none() || state.entities.load().get(RULE).is_none() {
        return Err(AppError::NotFound);
    }
    ctx.require(READING, "create")?;
    let devices: Vec<String> = input
        .readings
        .iter()
        .map(|r| r.device_id.trim().to_owned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let assets: HashMap<String, Uuid> = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT DISTINCT ON (device_id) device_id, id FROM asset \
          WHERE is_active AND device_id = ANY($1) ORDER BY device_id, id",
    )
    .bind(&devices)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .collect();
    let now = Utc::now();
    let mut results = Vec::with_capacity(input.readings.len());
    for r in input.readings {
        let device_id = r.device_id.trim().to_owned();
        if let Err(e) = check_reading(&r) {
            results.push(ReadingResult {
                device_id,
                reading_id: None,
                error: Some(e.into()),
            });
            continue;
        }
        let Some(asset) = assets.get(&device_id).copied() else {
            results.push(ReadingResult {
                device_id,
                reading_id: None,
                error: Some("unknown_device".into()),
            });
            continue;
        };
        let mut body = json!({
            "asset_ref": asset,
            "device_id": &device_id,
            "meter": r.meter.trim(),
            "reading": r.reading,
            "read_at": r.read_at.unwrap_or(now).to_rfc3339(),
        });
        if let Some(unit) = r.unit.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            body["unit"] = json!(unit);
        }
        match attome_records::entity_crud::create_record_for(state, ctx, ctx.user_id, READING, body)
            .await
        {
            Ok((id, _)) => results.push(ReadingResult {
                device_id,
                reading_id: Some(id),
                error: None,
            }),
            Err(e) => results.push(ReadingResult {
                device_id,
                reading_id: None,
                error: Some(public_error(&e)),
            }),
        }
    }
    Ok(ReadingsResult { results })
}

#[utoipa::path(
    post,
    path = "/api/v1/service/device-readings",
    operation_id = "post_device_readings",
    tag = "service",
    request_body = ReadingsIn,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Each reading's result, in order", body = ReadingsResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks asset_meter_reading.create", body = ErrorResponse),
        (status = 404, description = "Device readings are not installed", body = ErrorResponse),
        (status = 422, description = "No readings, or more than 500", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Records readings posted by devices that know only their own id.
///
/// Each reading names `device_id`; the asset holding that device id is
/// looked up and the reading is created on it through the generic write
/// path. A reading of an unknown device, or one that fails validation, is
/// answered with its error and does not stop the others. Device rules see
/// the readings on the next device readings run.
async fn post_readings(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<ReadingCreate>>,
    Json(input): Json<ReadingsIn>,
) -> Result<Json<ReadingsResult>, AppError> {
    Ok(Json(intake(&state, &ctx, input).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/service/device-readings", post(post_readings))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_readings),
    components(schemas(ReadingIn, ReadingsIn, ReadingResult, ReadingsResult))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod iot_rules {
    use super::*;
    use chrono::TimeZone;

    fn reading(value: f64) -> Reading {
        Reading {
            id: Uuid::nil(),
            asset: Uuid::from_u128(7),
            meter: "temperature".into(),
            value,
            unit: Some("C".into()),
            read_at: Utc.with_ymd_and_hms(2026, 10, 23, 14, 37, 12).unwrap(),
        }
    }

    fn rule(asset: Option<Uuid>) -> DeviceRule {
        DeviceRule {
            id: Uuid::from_u128(1),
            name: Some("Overheat".into()),
            meter: Some("temperature".into()),
            condition: Some("reading > 90".into()),
            action: Some("work_order".into()),
            asset_ref: asset,
            priority: Some("urgent".into()),
            debounce_minutes: None,
            owner: Some(Uuid::from_u128(9)),
        }
    }

    #[test]
    fn iot_rules_hour_truncates_to_the_hour() {
        let at = reading(1.0).read_at;
        assert_eq!(
            hour_of(at),
            Utc.with_ymd_and_hms(2026, 10, 23, 14, 0, 0).unwrap()
        );
    }

    #[test]
    fn iot_rules_threshold_holds_only_above_it() {
        assert_eq!(holds("reading > 90", &reading(95.0), None), Ok(Some(true)));
        assert_eq!(holds("reading > 90", &reading(90.0), None), Ok(Some(false)));
    }

    #[test]
    fn iot_rules_previous_reading_is_available() {
        let r = reading(95.0);
        assert_eq!(
            holds("reading - previous > 10", &r, Some(80.0)),
            Ok(Some(true))
        );
        assert_eq!(
            holds("reading - previous > 10", &r, Some(90.0)),
            Ok(Some(false))
        );
    }

    #[test]
    fn iot_rules_bad_condition_is_an_error() {
        assert!(holds("pressure > 1", &reading(1.0), None).is_err());
        assert!(holds("reading + 1", &reading(1.0), None).is_err());
    }

    #[test]
    fn iot_rules_apply_by_meter_and_asset() {
        let r = reading(95.0);
        assert!(applies(&rule(None), &r));
        assert!(applies(&rule(Some(r.asset)), &r));
        assert!(!applies(&rule(Some(Uuid::from_u128(8))), &r));
        let mut other = rule(None);
        other.meter = Some("vibration".into());
        assert!(!applies(&other, &r));
    }

    #[test]
    fn iot_rules_quiet_period_defaults_and_clamps() {
        assert_eq!(debounce_minutes(None), 60);
        assert_eq!(debounce_minutes(Some(15.4)), 15);
        assert_eq!(debounce_minutes(Some(-1.0)), 60);
        assert_eq!(debounce_minutes(Some(1e9)), MAX_DEBOUNCE_MINUTES);
        let at = reading(1.0).read_at;
        let (from, until) = quiet_window(at, 30);
        assert_eq!(until - from, Duration::minutes(60));
    }

    #[test]
    fn iot_rules_work_order_body_names_the_asset() {
        let r = reading(95.0);
        let body = target_body(&rule(None), Action::WorkOrder, &r, Uuid::from_u128(9));
        assert_eq!(body["asset_ref"], json!(r.asset));
        assert_eq!(body["priority"], "urgent");
        assert_eq!(body["status"], "new");
        assert!(
            body["title"]
                .as_str()
                .unwrap()
                .starts_with("Overheat: temperature 95")
        );
    }

    #[test]
    fn iot_rules_case_body_uses_case_priorities() {
        let body = target_body(
            &rule(None),
            Action::Case,
            &reading(95.0),
            Uuid::from_u128(9),
        );
        assert_eq!(body["priority"], "critical");
        assert_eq!(body["requester_id"], Uuid::from_u128(9).to_string());
        assert!(body["ticket_number"].as_str().unwrap().starts_with("TKT-"));
        assert_eq!(case_priority(None), "medium");
        assert_eq!(work_order_priority(Some("other")), "normal");
    }

    #[test]
    fn iot_rules_posted_reading_checks() {
        let ok = ReadingIn {
            device_id: "dev-1".into(),
            meter: "temperature".into(),
            reading: 1.0,
            unit: None,
            read_at: None,
        };
        assert!(check_reading(&ok).is_ok());
        let mut bad = ok.clone();
        bad.device_id = " ".into();
        assert!(check_reading(&bad).is_err());
        let mut bad = ok.clone();
        bad.reading = f64::NAN;
        assert!(check_reading(&bad).is_err());
        assert_eq!(
            Action::parse(Some("case")).map(Action::entity),
            Some("service_ticket")
        );
        assert_eq!(Action::parse(Some("call")), None);
    }
}
