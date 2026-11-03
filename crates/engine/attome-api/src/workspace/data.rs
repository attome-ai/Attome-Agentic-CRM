//! T5-T5: a workspace's records.
//!
//! A workspace is made with one of three kinds of data (`data.mode`):
//!
//! - `sample` (the default): up to `per_entity` records (20 unless set, at
//!   most 200) generated for every entity from its columns: text from the
//!   field's name (a keyed fake for an email, phone, national id or name
//!   field, else the field's name and a number), numbers, dates and flags
//!   from the row's number, and a lookup pointing at a generated record of
//!   its target. An entity whose columns cannot all be filled is skipped and
//!   reported. Reference data is copied whole from live.
//! - `masked`: `percent` (10 unless set) of every entity's live records,
//!   chosen by a hash of the id, then every record a kept record points at
//!   through a lookup, repeated until nothing is added (referential
//!   closure). Reference data is copied whole.
//! - `none`: every entity table stays empty.
//!
//! Either way every labelled field ([`crate::masking`], L10-T1) of the
//! workspace's records is then masked with a key made for this workspace and
//! never stored, so no live personal value reaches it: a fake for personal
//! text, a shuffle for financial values, cleared for health and secret ones
//! (a required column that cannot take a fake is shuffled). Credential
//! tables ([`crate::masking::CREDENTIAL_TABLES`]) are never filled.
//!
//! The storage the data needs is estimated from live's table sizes before
//! anything is copied and refused past `metadata.workspace_data_max_mb`
//! (1,024 MB unset). Copies run on the migrator pool, one entity a
//! statement or transaction.

use std::collections::BTreeSet;

use attome_core::{EngineState, quote_ident};
use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use super::schema;
use crate::masking::{self, CREDENTIAL_TABLES, MaskRule, effective_rule};

/// Records generated per entity unless `per_entity` says otherwise.
pub const DEFAULT_PER_ENTITY: u32 = 20;
/// Most records generated per entity.
pub const MAX_PER_ENTITY: u32 = 200;
/// The share of live records a masked workspace keeps unless `percent` says.
pub const DEFAULT_PERCENT: u8 = 10;
/// The storage limit when `metadata.workspace_data_max_mb` is unset.
pub const DEFAULT_MAX_MB: i64 = 1_024;
/// Bytes in a megabyte.
const MB: i64 = 1024 * 1024;
/// The most closure passes a masked copy makes.
const MAX_CLOSURE_PASSES: usize = 25;
/// Rounds of sample generation: an entity whose required lookup's target
/// was still empty is tried again once the others are filled.
const SAMPLE_ROUNDS: usize = 3;
/// Rows faked per statement.
const FAKE_BATCH: i64 = 1_000;
/// Bytes a generated row is taken to need when live has no rows to measure.
const UNMEASURED_ROW_BYTES: f64 = 512.0;

/// Which records a workspace starts with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DataMode {
    /// Every entity table empty.
    None,
    /// Generated records.
    #[default]
    Sample,
    /// A masked share of live's records.
    Masked,
}

/// `data` on a new workspace.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DataRequest {
    /// `sample` (the default), `masked` or `none`.
    #[serde(default)]
    pub mode: DataMode,
    /// `sample`: records per entity, 1 to 200 (20 unset).
    #[serde(default)]
    pub per_entity: Option<u32>,
    /// `masked`: the share of live records kept, 1 to 100 (10 unset).
    #[serde(default)]
    pub percent: Option<u8>,
}

/// A checked [`DataRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataPlan {
    pub mode: DataMode,
    pub per_entity: u32,
    pub percent: u8,
}

/// One entity's records in the workspace.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EntityRecords {
    pub entity: String,
    pub records: i64,
}

/// An entity sample data could not fill.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SkippedEntity {
    pub entity: String,
    pub reason: String,
}

/// What a workspace's data came to.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DataReport {
    pub mode: DataMode,
    /// The storage estimated before copying.
    pub estimated_bytes: i64,
    /// Records in the workspace, every entity together.
    pub records: i64,
    /// Entities holding records.
    pub entities: Vec<EntityRecords>,
    /// Entities sample data could not fill.
    pub skipped: Vec<SkippedEntity>,
    /// Labelled fields masked, as `entity.field`.
    pub masked_fields: Vec<String>,
}

/// Checks a request: `per_entity` only for sample data, `percent` only for
/// a masked copy, both in bounds. Pure.
pub fn checked(request: &DataRequest) -> Result<DataPlan, AppError> {
    let mut problems = Vec::new();
    if request.per_entity.is_some() && request.mode != DataMode::Sample {
        problems.push("data.per_entity: only for sample data".to_owned());
    }
    if request.percent.is_some() && request.mode != DataMode::Masked {
        problems.push("data.percent: only for a masked copy".to_owned());
    }
    let per_entity = request.per_entity.unwrap_or(DEFAULT_PER_ENTITY);
    if !(1..=MAX_PER_ENTITY).contains(&per_entity) {
        problems.push(format!("data.per_entity: 1 to {MAX_PER_ENTITY}"));
    }
    let percent = request.percent.unwrap_or(DEFAULT_PERCENT);
    if !(1..=100).contains(&percent) {
        problems.push("data.percent: 1 to 100".to_owned());
    }
    if problems.is_empty() {
        Ok(DataPlan {
            mode: request.mode,
            per_entity,
            percent,
        })
    } else {
        Err(AppError::Validation(problems.join("; ")))
    }
}

/// The storage limit in bytes.
fn limit_bytes(state: &EngineState) -> i64 {
    state
        .base
        .config
        .metadata
        .workspace_data_max_mb
        .unwrap_or(DEFAULT_MAX_MB)
        .saturating_mul(MB)
}

/// One entity a workspace's data may fill.
#[derive(Debug, Clone)]
struct Fillable {
    entity: String,
    reference: bool,
}

/// The entities live has a table for that a workspace copies (not metadata,
/// shared or credential tables), by name.
async fn fillable(db: &DbPool, live: &str) -> Result<Vec<Fillable>, AppError> {
    let rows: Vec<(String, bool)> = sqlx::query_as(
        "SELECT logicalname::text, COALESCE(is_reference_data, false) FROM entity_info \
          WHERE (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL \
          ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let metadata = schema::metadata_tables();
    let mut out = Vec::new();
    for (entity, reference) in rows {
        if metadata.contains(&entity.as_str())
            || schema::is_shared(&entity)
            || CREDENTIAL_TABLES.contains(&entity.as_str())
        {
            continue;
        }
        if schema::exists(db, live, &entity).await? {
            out.push(Fillable { entity, reference });
        }
    }
    Ok(out)
}

/// The bytes the data is estimated to need: a reference table whole, else
/// the share of each live table a masked copy keeps, or `per_entity` rows
/// of each table's measured row size.
async fn estimate(
    db: &DbPool,
    live: &str,
    plan: DataPlan,
    entities: &[Fillable],
) -> Result<i64, AppError> {
    let mut total = 0f64;
    for e in entities {
        let (bytes, rows): (i64, f64) = sqlx::query_as(
            "SELECT COALESCE(pg_total_relation_size(to_regclass($1)), 0)::bigint, \
                    COALESCE((SELECT GREATEST(reltuples, 0)::float8 FROM pg_class \
                               WHERE oid = to_regclass($1)), 0)",
        )
        .bind(format!("{}.{}", quote_ident(live), quote_ident(&e.entity)))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        #[allow(
            clippy::cast_precision_loss,
            reason = "an estimate: a table's size in bytes as a float is close enough"
        )]
        let bytes = bytes as f64;
        total += if e.reference {
            bytes
        } else {
            match plan.mode {
                DataMode::None => 0.0,
                DataMode::Masked => bytes * f64::from(plan.percent) / 100.0,
                DataMode::Sample => {
                    let per_row = if rows >= 1.0 {
                        bytes / rows
                    } else {
                        UNMEASURED_ROW_BYTES
                    };
                    per_row * f64::from(plan.per_entity)
                }
            }
        };
    }
    #[allow(
        clippy::cast_possible_truncation,
        reason = "an estimate in bytes, far below i64::MAX"
    )]
    Ok(total.ceil() as i64)
}

/// Estimates the data `plan` needs and refuses it past the configured
/// limit. Runs before the workspace schema is made.
pub async fn check_storage(state: &EngineState, plan: DataPlan) -> Result<i64, AppError> {
    if plan.mode == DataMode::None {
        return Ok(0);
    }
    let db = &state.base.db_migrator;
    let live = schema::live_schema(db).await?;
    let entities = fillable(db, &live).await?;
    let estimated = estimate(db, &live, plan, &entities).await?;
    let limit = limit_bytes(state);
    if estimated > limit {
        return Err(AppError::Validation(format!(
            "the workspace's data would take about {} MB, over the limit of {} MB \
             (metadata.workspace_data_max_mb); keep fewer records, or choose no data",
            (estimated + MB - 1) / MB,
            limit / MB
        )));
    }
    Ok(estimated)
}

/// Fills workspace `ws` with the data `plan` names, then masks its labelled
/// fields. `user` owns generated records whose owner column needs a value.
pub async fn fill(
    state: &EngineState,
    ws: &str,
    plan: DataPlan,
    user: Uuid,
    estimated_bytes: i64,
) -> Result<DataReport, AppError> {
    let mut report = DataReport {
        mode: plan.mode,
        estimated_bytes,
        records: 0,
        entities: Vec::new(),
        skipped: Vec::new(),
        masked_fields: Vec::new(),
    };
    if plan.mode == DataMode::None {
        return Ok(report);
    }
    let db = &state.base.db_migrator;
    let live = schema::live_schema(db).await?;
    // An entity made after the workspace's tables were copied has no table
    // there.
    let mut entities = Vec::new();
    for e in fillable(db, &live).await? {
        if schema::exists(db, ws, &e.entity).await? {
            entities.push(e);
        }
    }
    for e in entities.iter().filter(|e| e.reference) {
        copy_rows(db, &live, ws, &e.entity, None).await?;
    }
    let others: Vec<&Fillable> = entities.iter().filter(|e| !e.reference).collect();
    match plan.mode {
        DataMode::Sample => {
            report.skipped = sample(db, ws, &others, plan.per_entity, user).await?;
        }
        DataMode::Masked => masked_copy(db, &live, ws, &others, plan.percent).await?,
        DataMode::None => {}
    }
    report.masked_fields = mask(db, ws).await?;
    for e in &entities {
        let records: i64 = sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {}.{}",
            quote_ident(ws),
            quote_ident(&e.entity)
        ))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
        if records > 0 {
            report.records += records;
            report.entities.push(EntityRecords {
                entity: e.entity.clone(),
                records,
            });
        }
    }
    Ok(report)
}

/// Copies live's rows of `table` into the workspace: all of them, or those
/// whose id the temporary keep table lists for it.
async fn copy_rows(
    db: &DbPool,
    live: &str,
    ws: &str,
    table: &str,
    keep: Option<&mut PgConnection>,
) -> Result<(), AppError> {
    // The workspace's columns: the copy's structure, which live's has.
    let columns = schema::writable_columns(db, ws, table)
        .await?
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    if columns.is_empty() {
        return Ok(());
    }
    let source = format!("{}.{}", quote_ident(live), quote_ident(table));
    let target = format!("{}.{}", quote_ident(ws), quote_ident(table));
    match keep {
        None => {
            sqlx::query(&format!(
                "INSERT INTO {target} ({columns}) OVERRIDING SYSTEM VALUE \
                 SELECT {columns} FROM {source}"
            ))
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        }
        Some(conn) => {
            sqlx::query(&format!(
                "INSERT INTO {target} ({columns}) OVERRIDING SYSTEM VALUE \
                 SELECT {columns} FROM {source} x WHERE EXISTS \
                   (SELECT 1 FROM workspace_keep k WHERE k.entity = $1 AND k.id = x.id)"
            ))
            .bind(table)
            .execute(conn)
            .await
            .map_err(AppError::internal)?;
        }
    }
    Ok(())
}

/// Lookups among `entities`: (source entity, field, target entity).
async fn lookups(
    db: &DbPool,
    entities: &[&Fillable],
) -> Result<Vec<(String, String, String)>, AppError> {
    let names: Vec<&str> = entities.iter().map(|e| e.entity.as_str()).collect();
    sqlx::query_as(
        "SELECT s.logicalname::text, a.logicalname::text, t.logicalname::text \
           FROM attribute_info a \
           JOIN entity_info s ON s.id = a.entity_ref \
           JOIN entity_info t ON t.id = a.lookup_entity_ref \
          WHERE (a.is_active IS NULL OR a.is_active = true) \
            AND s.logicalname = ANY($1) AND t.logicalname = ANY($1)",
    )
    .bind(&names)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// The masked share: keep `percent` of each entity's ids by a hash of the
/// id, follow lookups from kept records until nothing is added, copy what is
/// kept. One connection: the keep table is temporary.
async fn masked_copy(
    db: &DbPool,
    live: &str,
    ws: &str,
    entities: &[&Fillable],
    percent: u8,
) -> Result<(), AppError> {
    let follow = lookups(db, entities).await?;
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    sqlx::query(
        "CREATE TEMP TABLE workspace_keep (entity text NOT NULL, id uuid NOT NULL, \
          PRIMARY KEY (entity, id))",
    )
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let result = async {
        for e in entities {
            sqlx::query(&format!(
                "INSERT INTO workspace_keep SELECT $1, id FROM {}.{} \
                  WHERE ((hashtext(id::text)::bigint % 100) + 100) % 100 < $2",
                quote_ident(live),
                quote_ident(&e.entity)
            ))
            .bind(&e.entity)
            .bind(i32::from(percent))
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
        }
        for _ in 0..MAX_CLOSURE_PASSES {
            let mut added = 0;
            for (source, field, target) in &follow {
                added += sqlx::query(&format!(
                    "INSERT INTO workspace_keep \
                     SELECT $1, s.{c} FROM {l}.{t} s \
                      WHERE s.{c} IS NOT NULL AND EXISTS \
                        (SELECT 1 FROM workspace_keep k WHERE k.entity = $2 AND k.id = s.id) \
                     ON CONFLICT DO NOTHING",
                    l = quote_ident(live),
                    t = quote_ident(source),
                    c = quote_ident(field)
                ))
                .bind(target)
                .bind(source)
                .execute(&mut *conn)
                .await
                .map_err(AppError::internal)?
                .rows_affected();
            }
            if added == 0 {
                break;
            }
        }
        for e in entities {
            copy_rows(db, live, ws, &e.entity, Some(&mut *conn)).await?;
        }
        Ok::<(), AppError>(())
    }
    .await;
    if let Err(error) = sqlx::query("DROP TABLE IF EXISTS workspace_keep")
        .execute(&mut *conn)
        .await
    {
        tracing::warn!(%error, "workspace: the keep table was not dropped; the connection is closed");
        conn.close_on_drop();
    }
    result
}

/// How a column is filled in sample data.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Gen {
    /// Generated text, cut to the column's length.
    Text(Option<i32>),
    Int,
    Number,
    Flag,
    Date,
    Timestamp,
    Time,
    /// A generated record of this entity.
    Lookup(String),
    /// The creating user (a required id with no lookup: an owner).
    User,
    EmptyJson,
    EmptyArray,
    Null,
    /// A required column of a type sample data does not make.
    Unsupported(String),
}

/// The generator for a column without a default. Pure.
fn generator(data_type: &str, nullable: bool, max_len: Option<i32>, lookup: Option<&str>) -> Gen {
    match (data_type, lookup) {
        ("uuid", Some(target)) => Gen::Lookup(target.to_owned()),
        ("uuid", None) if nullable => Gen::Null,
        ("uuid", None) => Gen::User,
        ("text" | "character varying" | "character" | "citext", _) => Gen::Text(max_len),
        ("smallint" | "integer" | "bigint", _) => Gen::Int,
        ("numeric" | "real" | "double precision", _) => Gen::Number,
        ("boolean", _) => Gen::Flag,
        ("date", _) => Gen::Date,
        ("timestamp with time zone" | "timestamp without time zone", _) => Gen::Timestamp,
        ("time without time zone" | "time with time zone", _) => Gen::Time,
        (_, _) if nullable => Gen::Null,
        ("json" | "jsonb", _) => Gen::EmptyJson,
        ("ARRAY", _) => Gen::EmptyArray,
        (other, _) => Gen::Unsupported(other.to_owned()),
    }
}

/// Sample text for row `n` of `entity.field`: a keyed fake for a field the
/// masking engine recognises, else the field's name and the number. Pure.
fn sample_text(key: &[u8], entity: &str, field: &str, n: u32) -> String {
    match masking::kind_of(field) {
        masking::FieldKind::Other => format!("{} {n}", field.replace('_', " ")),
        _ => masking::fake(key, field, &format!("{entity}:{n}")),
    }
}

/// The SQL expression filling one column for row `g.n`; text columns read
/// bound array `$param`. Pure.
fn expression(fill_with: &Gen, ws: &str, param: usize) -> Option<String> {
    Some(match fill_with {
        Gen::Text(Some(len)) => format!("left((${param}::text[])[g.n], {len})"),
        Gen::Text(None) => format!("(${param}::text[])[g.n]"),
        Gen::Int => "g.n".to_owned(),
        Gen::Number => "(g.n * 10.5)".to_owned(),
        Gen::Flag => "(g.n % 2 = 0)".to_owned(),
        Gen::Date => "(current_date - g.n)".to_owned(),
        Gen::Timestamp => "(now() - make_interval(hours => g.n))".to_owned(),
        Gen::Time => "(time '09:00' + make_interval(mins => g.n))".to_owned(),
        Gen::Lookup(target) => format!(
            "(SELECT x.id FROM {}.{} x ORDER BY md5(x.id::text || g.n::text) LIMIT 1)",
            quote_ident(ws),
            quote_ident(target)
        ),
        Gen::User => "$2".to_owned(),
        Gen::EmptyJson => "'{}'".to_owned(),
        Gen::EmptyArray => "'{}'".to_owned(),
        Gen::Null => "NULL".to_owned(),
        Gen::Unsupported(_) => return None,
    })
}

/// Fills every entity in `entities` with `per_entity` generated records;
/// the entities it could not fill, with why.
async fn sample(
    db: &DbPool,
    ws: &str,
    entities: &[&Fillable],
    per_entity: u32,
    user: Uuid,
) -> Result<Vec<SkippedEntity>, AppError> {
    let key = workspace_key();
    let follow = lookups(db, entities).await?;
    let mut pending: Vec<&Fillable> = entities.to_vec();
    let mut failed: Vec<SkippedEntity> = Vec::new();
    for round in 0..SAMPLE_ROUNDS {
        let last = round + 1 == SAMPLE_ROUNDS;
        let mut retry = Vec::new();
        failed.clear();
        for e in pending {
            match sample_one(db, ws, &e.entity, &follow, per_entity, user, &key).await? {
                Ok(()) => {}
                Err(reason) => {
                    if !last {
                        retry.push(e);
                    }
                    failed.push(SkippedEntity {
                        entity: e.entity.clone(),
                        reason,
                    });
                }
            }
        }
        if retry.is_empty() {
            break;
        }
        pending = retry;
    }
    Ok(failed)
}

/// One entity's generated records, in one transaction. `Ok(Err(reason))`
/// when this entity cannot be filled (its transaction rolled back).
async fn sample_one(
    db: &DbPool,
    ws: &str,
    entity: &str,
    follow: &[(String, String, String)],
    per_entity: u32,
    user: Uuid,
    key: &[u8],
) -> Result<Result<(), String>, AppError> {
    let columns: Vec<(String, String, bool, bool, Option<i32>)> = sqlx::query_as(
        "SELECT column_name::text, data_type::text, is_nullable = 'YES', \
                column_default IS NOT NULL OR is_identity = 'YES' OR is_generated <> 'NEVER', \
                character_maximum_length::int \
           FROM information_schema.columns \
          WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position",
    )
    .bind(ws)
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut names = Vec::new();
    let mut exprs = Vec::new();
    let mut texts: Vec<Vec<String>> = Vec::new();
    for (column, data_type, nullable, has_default, max_len) in columns {
        if has_default {
            continue;
        }
        let lookup = follow
            .iter()
            .find(|(s, f, _)| s == entity && *f == column)
            .map(|(_, _, t)| t.as_str());
        let fill_with = generator(&data_type, nullable, max_len, lookup);
        if let Gen::Unsupported(kind) = &fill_with {
            return Ok(Err(format!(
                "the required column {column} is of type {kind}, which sample data does not make"
            )));
        }
        let Some(expr) = expression(&fill_with, ws, texts.len() + 3) else {
            continue;
        };
        if matches!(fill_with, Gen::Text(_)) {
            texts.push(
                (1..=per_entity)
                    .map(|n| sample_text(key, entity, &column, n))
                    .collect(),
            );
        }
        names.push(quote_ident(&column));
        exprs.push(expr);
    }
    let sql = if names.is_empty() {
        format!(
            "INSERT INTO {}.{} SELECT FROM generate_series(1, $1) AS g(n)",
            quote_ident(ws),
            quote_ident(entity)
        )
    } else {
        format!(
            "INSERT INTO {}.{} ({}) SELECT {} FROM generate_series(1, $1) AS g(n)",
            quote_ident(ws),
            quote_ident(entity),
            names.join(", "),
            exprs.join(", ")
        )
    };
    let count = i32::try_from(per_entity).map_err(AppError::internal)?;
    let mut query = sqlx::query(&sql).bind(count).bind(user);
    for values in &texts {
        query = query.bind(values);
    }
    let mut tx = attome_db::tx::begin(db).await?;
    match query.execute(&mut *tx).await {
        Ok(_) => {
            attome_db::tx::commit(tx).await?;
            Ok(Ok(()))
        }
        Err(error) => {
            // Rolled back on drop. The database's words stay in the log.
            tracing::info!(entity, %error, "workspace: sample data skipped an entity");
            Ok(Err(
                "a column's rule refused the generated values (the server log has the detail)"
                    .to_owned(),
            ))
        }
    }
}

/// A key for this workspace's fakes, never stored.
fn workspace_key() -> Vec<u8> {
    let mut key = Uuid::new_v4().into_bytes().to_vec();
    key.extend_from_slice(&Uuid::new_v4().into_bytes());
    key
}

/// The workspace's labelled fields: entity, field, label (`sensitive` when
/// only `is_sensitive` marks it), the masking override, whether the column
/// is nullable and whether it is text.
type LabelledField = (String, String, String, Option<String>, bool, bool);

/// Masks every labelled field of the workspace's records; the fields
/// masked, as `entity.field`.
async fn mask(db: &DbPool, ws: &str) -> Result<Vec<String>, AppError> {
    let labelled: Vec<LabelledField> = sqlx::query_as(
        "SELECT e.logicalname::text, a.logicalname::text, \
                CASE WHEN a.sensitivity_confirmed THEN a.sensitivity::text ELSE 'sensitive' END, \
                a.options->>'masking', \
                COALESCE(c.is_nullable = 'YES', false), \
                COALESCE(c.data_type IN ('text', 'character varying', 'character'), false) \
           FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
           JOIN information_schema.columns c \
             ON c.table_schema = $1 AND c.table_name = e.logicalname \
            AND c.column_name = a.logicalname \
          WHERE a.is_sensitive OR (a.sensitivity_confirmed \
                AND a.sensitivity IN ('personal', 'financial', 'health', 'secret')) \
          ORDER BY 1, 2",
    )
    .bind(ws)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let key = workspace_key();
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let mut masked = BTreeSet::new();
    for (entity, field, label, override_rule, nullable, is_text) in labelled {
        let table = format!("{}.{}", quote_ident(ws), quote_ident(&entity));
        let column = quote_ident(&field);
        let rule = match effective_rule(&label, override_rule.as_deref(), nullable, is_text) {
            // Only an explicit `keep` leaves live values; a required column
            // that cannot take a fake has its values moved between records.
            MaskRule::Keep if override_rule.as_deref() != Some("keep") => MaskRule::Shuffle,
            rule => rule,
        };
        match rule {
            MaskRule::Keep => continue,
            MaskRule::Null => {
                sqlx::query(&format!(
                    "UPDATE {table} SET {column} = NULL WHERE {column} IS NOT NULL"
                ))
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            }
            MaskRule::Shuffle => {
                sqlx::query(&format!(
                    "WITH src AS (SELECT {column} AS v, row_number() OVER (ORDER BY id) AS n \
                                   FROM {table} WHERE {column} IS NOT NULL), \
                          dst AS (SELECT id, row_number() OVER (ORDER BY md5(id::text || $1)) AS n \
                                   FROM {table} WHERE {column} IS NOT NULL) \
                     UPDATE {table} SET {column} = src.v FROM src JOIN dst USING (n) \
                      WHERE {table}.id = dst.id"
                ))
                .bind(&hex_key)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            }
            MaskRule::Fake => fake_column(db, &table, &column, &field, &key).await?,
        }
        masked.insert(format!("{entity}.{field}"));
    }
    Ok(masked.into_iter().collect())
}

/// Replaces every value of a text column with its keyed fake, a batch of
/// rows at a time in id order.
async fn fake_column(
    db: &DbPool,
    table: &str,
    column: &str,
    field: &str,
    key: &[u8],
) -> Result<(), AppError> {
    let read = format!(
        "SELECT id, {column}::text FROM {table} \
          WHERE {column} IS NOT NULL AND id > $1 ORDER BY id LIMIT $2"
    );
    let write = format!(
        "UPDATE {table} SET {column} = u.v FROM unnest($1::uuid[], $2::text[]) AS u(id, v) \
          WHERE {table}.id = u.id"
    );
    let mut after = Uuid::nil();
    loop {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(&read)
            .bind(after)
            .bind(FAKE_BATCH)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
        let Some(last) = rows.last().map(|r| r.0) else {
            return Ok(());
        };
        let ids: Vec<Uuid> = rows.iter().map(|r| r.0).collect();
        let fakes: Vec<String> = rows
            .iter()
            .map(|(_, value)| masking::fake(key, field, value))
            .collect();
        sqlx::query(&write)
            .bind(&ids)
            .bind(&fakes)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
        after = last;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_bounded_and_fit_their_mode() {
        assert_eq!(
            checked(&DataRequest::default()).unwrap(),
            DataPlan {
                mode: DataMode::Sample,
                per_entity: DEFAULT_PER_ENTITY,
                percent: DEFAULT_PERCENT,
            }
        );
        let masked = DataRequest {
            mode: DataMode::Masked,
            per_entity: None,
            percent: Some(100),
        };
        assert_eq!(checked(&masked).unwrap().percent, 100);
        for bad in [
            DataRequest {
                mode: DataMode::Sample,
                per_entity: Some(0),
                percent: None,
            },
            DataRequest {
                mode: DataMode::Sample,
                per_entity: Some(MAX_PER_ENTITY + 1),
                percent: None,
            },
            DataRequest {
                mode: DataMode::Masked,
                per_entity: None,
                percent: Some(0),
            },
            DataRequest {
                mode: DataMode::Sample,
                per_entity: None,
                percent: Some(10),
            },
            DataRequest {
                mode: DataMode::None,
                per_entity: Some(5),
                percent: None,
            },
        ] {
            assert!(checked(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn each_column_type_has_a_generator() {
        assert_eq!(
            generator("uuid", false, None, Some("account")),
            Gen::Lookup("account".into())
        );
        assert_eq!(generator("uuid", true, None, None), Gen::Null);
        assert_eq!(generator("uuid", false, None, None), Gen::User);
        assert_eq!(
            generator("character varying", false, Some(40), None),
            Gen::Text(Some(40))
        );
        assert_eq!(generator("jsonb", true, None, None), Gen::Null);
        assert_eq!(generator("jsonb", false, None, None), Gen::EmptyJson);
        assert_eq!(generator("bytea", true, None, None), Gen::Null);
        assert_eq!(
            generator("bytea", false, None, None),
            Gen::Unsupported("bytea".into())
        );
    }

    #[test]
    fn sample_text_fakes_what_masking_recognises() {
        let key = [7u8; 32];
        assert_eq!(sample_text(&key, "deal", "next_step", 3), "next step 3");
        assert!(sample_text(&key, "contact", "email", 1).ends_with("@example.invalid"));
        assert_ne!(
            sample_text(&key, "contact", "email", 1),
            sample_text(&key, "contact", "email", 2)
        );
    }

    #[test]
    fn text_reads_its_own_bound_array() {
        assert_eq!(
            expression(&Gen::Text(Some(10)), "ws_x", 4).unwrap(),
            "left(($4::text[])[g.n], 10)"
        );
        assert_eq!(expression(&Gen::User, "ws_x", 3).unwrap(), "$2");
        assert!(expression(&Gen::Unsupported("bytea".into()), "ws_x", 3).is_none());
    }
}
