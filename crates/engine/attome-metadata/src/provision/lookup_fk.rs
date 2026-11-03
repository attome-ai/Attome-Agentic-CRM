//! Y2-T4: the orphan scan. For each lookup field of an entity, how many rows
//! hold a value that points at no record of the lookup's target (a row of
//! any state, live or soft-deleted, counts as present). The scan only reads:
//! it never clears or deletes a value; a builder decides what to do through
//! the record API.
//!
//! One pass reads every lookup column at once, in id order. A small table is
//! scanned whole ([`scan_batch`] with no limit); a table over the size gate
//! is scanned by a durable `data_step_run` of kind `orphan_scan`
//! ([`create_scan_run_in_tx`]), a batch per transaction with its cursor and
//! running counts in the run row, so a restarted worker resumes where it
//! stopped.
//!
//! Y2-T5 (V2-D1367's recommendation): a lookup whose `on_target_delete` is
//! `restrict` or `cascade-deactivate` also gets a database foreign key,
//! `fk_<entity>_<field>`, `ON DELETE NO ACTION` (never cascade or set null:
//! the engine owns those rules and refuses or handles the delete first). It
//! is added `NOT VALID` (no scan; every later write is held to it) and then
//! validated: inline on a table at or under the size gate, by the durable
//! `ValidateLookupForeignKey` job above it. An `orphan` lookup keeps no key
//! (a hard-deleted target leaves its value), and the orphan scan is its
//! check. A table with orphan values refuses validation and keeps the key
//! `NOT VALID`.

use attome_core::{EntityMeta, EntityMetaRegistry, FieldType, quote_ident};
use attome_db::{DbPool, ident::is_identifier};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

/// The rows one scan batch reads.
pub const ORPHAN_SCAN_BATCH: i64 = 5_000;

/// The run kind (migration 0110 admits it).
pub const ORPHAN_SCAN_KIND: &str = "orphan_scan";

/// One lookup field and the entity it points at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupColumn {
    pub attribute: String,
    pub target_entity: String,
}

/// A lookup field's orphan count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrphanTally {
    pub attribute: String,
    pub target_entity: String,
    pub orphans: i64,
}

/// The entity's lookup fields whose target is known, in field order. A
/// lookup with no recorded target (D-057) or a target that is not in the
/// registry is left out: there is no table to check it against.
pub fn lookup_columns(meta: &EntityMeta, registry: &EntityMetaRegistry) -> Vec<LookupColumn> {
    meta.attrs
        .iter()
        .filter(|a| a.field_type() == FieldType::Lookup && is_identifier(&a.logicalname))
        .filter_map(|a| {
            let target = registry.get_by_id(a.lookup_entity_ref?)?;
            is_identifier(&target.logicalname).then(|| LookupColumn {
                attribute: a.logicalname.clone(),
                target_entity: target.logicalname.clone(),
            })
        })
        .collect()
}

/// What one batch saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanBatch {
    pub scanned: i64,
    /// Per column, in the order given.
    pub orphans: Vec<i64>,
    /// The last id read; `None` when the batch read nothing.
    pub last: Option<Uuid>,
}

/// Reads up to `limit` rows after `after` (every row when `limit` is
/// `None`) and counts, per column, the values with no target row.
pub async fn scan_batch(
    conn: &mut PgConnection,
    entity: &str,
    columns: &[LookupColumn],
    after: Option<Uuid>,
    limit: Option<i64>,
) -> Result<ScanBatch, AppError> {
    if !is_identifier(entity) {
        return Err(AppError::Validation(
            "invalid entity for an orphan scan".into(),
        ));
    }
    if columns.is_empty() {
        return Ok(ScanBatch {
            scanned: 0,
            orphans: Vec::new(),
            last: None,
        });
    }
    let mut picked = String::from("id");
    let mut counts = String::new();
    for (n, col) in columns.iter().enumerate() {
        let c = quote_ident(&col.attribute);
        let t = quote_ident(&col.target_entity);
        picked.push_str(&format!(", {c} AS c{n}"));
        counts.push_str(&format!(
            ", count(*) FILTER (WHERE b.c{n} IS NOT NULL \
               AND NOT EXISTS (SELECT 1 FROM {t} t WHERE t.id = b.c{n}))"
        ));
    }
    let limit_sql = if limit.is_some() { " LIMIT $2" } else { "" };
    let sql = format!(
        "WITH b AS (SELECT {picked} FROM {table} \
                     WHERE ($1::uuid IS NULL OR id > $1) ORDER BY id{limit_sql}) \
         SELECT count(*), (SELECT id FROM b ORDER BY id DESC LIMIT 1){counts} FROM b",
        table = quote_ident(entity),
    );
    let mut query = sqlx::query(&sql).bind(after);
    if let Some(limit) = limit {
        query = query.bind(limit);
    }
    let row = query
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let scanned: i64 = row.try_get(0).map_err(AppError::internal)?;
    let last: Option<Uuid> = row.try_get(1).map_err(AppError::internal)?;
    let orphans = (0..columns.len())
        .map(|n| row.try_get::<i64, _>(n + 2).map_err(AppError::internal))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ScanBatch {
        scanned,
        orphans,
        last,
    })
}

/// The whole table in one pass, for a table under the size gate.
pub async fn count_orphans(
    db: &DbPool,
    entity: &str,
    columns: &[LookupColumn],
) -> Result<Vec<OrphanTally>, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let batch = scan_batch(&mut conn, entity, columns, None, None).await?;
    Ok(tallies(columns, &batch.orphans))
}

fn tallies(columns: &[LookupColumn], orphans: &[i64]) -> Vec<OrphanTally> {
    columns
        .iter()
        .zip(orphans)
        .map(|(col, n)| OrphanTally {
            attribute: col.attribute.clone(),
            target_entity: col.target_entity.clone(),
            orphans: *n,
        })
        .collect()
}

/// The run's spec: the columns and the counts so far. It names no `field` or
/// `attribute_id`, so a scan never makes a field busy.
pub fn scan_spec(entity_id: Uuid, columns: &[LookupColumn]) -> Value {
    json!({
        "entity_id": entity_id,
        "columns": columns,
        "orphans": vec![0_i64; columns.len()],
    })
}

/// The columns and counts a run's spec holds.
pub fn spec_tallies(spec: &Value) -> Result<(Vec<LookupColumn>, Vec<i64>), AppError> {
    let columns: Vec<LookupColumn> = spec
        .get("columns")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(AppError::internal)?
        .unwrap_or_default();
    let orphans: Vec<i64> = spec
        .get("orphans")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(AppError::internal)?
        .unwrap_or_default();
    if orphans.len() != columns.len() {
        return Err(AppError::internal(
            "orphan scan spec: counts and columns differ",
        ));
    }
    Ok((columns, orphans))
}

/// The counts a finished run reached.
pub fn run_tallies(spec: &Value) -> Result<Vec<OrphanTally>, AppError> {
    let (columns, orphans) = spec_tallies(spec)?;
    Ok(tallies(&columns, &orphans))
}

/// Queues a scan run for `entity`, or returns the live one (one queued or
/// running scan per entity: the partial unique index of migration 0110).
/// `true` when this call created it (the caller enqueues the job).
pub async fn create_scan_run_in_tx(
    conn: &mut PgConnection,
    entity: &str,
    spec: &Value,
    rows_estimate: Option<i64>,
    created_by: Uuid,
) -> Result<(Uuid, bool), AppError> {
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO data_step_run \
             (source, entity_logicalname, kind, spec, rows_estimate, created_by) \
         VALUES ('admin', $1, $2, $3, $4, $5) \
         ON CONFLICT (entity_logicalname) \
             WHERE kind = 'orphan_scan' AND status IN ('queued', 'claimed', 'running') \
         DO NOTHING \
         RETURNING id",
    )
    .bind(entity)
    .bind(ORPHAN_SCAN_KIND)
    .bind(spec)
    .bind(rows_estimate)
    .bind(created_by)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = inserted {
        return Ok((id, true));
    }
    let live: Uuid = sqlx::query_scalar(
        "SELECT id FROM data_step_run \
          WHERE entity_logicalname = $1 AND kind = 'orphan_scan' \
            AND status IN ('queued', 'claimed', 'running')",
    )
    .bind(entity)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok((live, false))
}

/// Writes a batch's counts into the run's spec (in the batch's transaction,
/// beside `advance_run`).
pub async fn add_batch_in_tx(
    conn: &mut PgConnection,
    run_id: Uuid,
    spec: &Value,
    batch: &ScanBatch,
) -> Result<Value, AppError> {
    let (columns, mut orphans) = spec_tallies(spec)?;
    for (total, n) in orphans.iter_mut().zip(&batch.orphans) {
        *total = total.saturating_add(*n);
    }
    let mut next = spec.clone();
    next["orphans"] = json!(orphans);
    next["columns"] = json!(columns);
    sqlx::query("UPDATE data_step_run SET spec = $2, updated_at = NOW() WHERE id = $1")
        .bind(run_id)
        .bind(&next)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(next)
}

/// The newest succeeded scan of `entity`: its run id, finish time and spec.
pub async fn latest_scan(
    db: &DbPool,
    entity: &str,
) -> Result<Option<(Uuid, chrono::DateTime<chrono::Utc>, Value)>, AppError> {
    sqlx::query_as(
        "SELECT id, finished_at, spec FROM data_step_run \
          WHERE entity_logicalname = $1 AND kind = 'orphan_scan' AND status = 'succeeded' \
            AND finished_at IS NOT NULL \
          ORDER BY finished_at DESC LIMIT 1",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Whether a scan of `entity` is queued or running.
pub async fn scan_running(db: &DbPool, entity: &str) -> Result<Option<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT id FROM data_step_run \
          WHERE entity_logicalname = $1 AND kind = 'orphan_scan' \
            AND status IN ('queued', 'claimed', 'running') LIMIT 1",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// The rows a table may hold for its lookup key to be validated inline; a
/// bigger table validates through the `ValidateLookupForeignKey` job.
pub const FK_VALIDATE_INLINE_ROW_LIMIT: i64 = 10_000;

/// Whether a lookup with this delete rule keeps a database foreign key. Pure.
pub fn keyed(on_target_delete: &str) -> bool {
    matches!(on_target_delete, "restrict" | "cascade-deactivate")
}

/// The constraint name for `entity.field`, at most 63 bytes (PostgreSQL's
/// identifier limit): `fk_<entity>_<field>`, or a cut of it with a stable
/// hash when longer. Pure.
pub fn fk_name(entity: &str, field: &str) -> String {
    let full = format!("fk_{entity}_{field}");
    if full.len() <= 63 {
        return full;
    }
    // FNV-1a: stable across builds, unlike the standard library's hasher.
    let mut hash: u32 = 0x811c_9dc5;
    for b in full.bytes() {
        hash ^= u32::from(b);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    let cut: String = full.chars().take(54).collect();
    format!("{cut}_{hash:08x}")
}

/// A lookup's foreign key, as the database has it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FkState {
    None,
    NotValid,
    Valid,
}

/// The state of `entity.field`'s foreign key.
pub async fn fk_state(db: &DbPool, entity: &str, field: &str) -> Result<FkState, AppError> {
    let validated: Option<bool> = sqlx::query_scalar(
        "SELECT c.convalidated FROM pg_catalog.pg_constraint c \
           JOIN pg_catalog.pg_class t ON t.oid = c.conrelid \
           JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace AND n.nspname = current_schema() \
          WHERE t.relname = $1 AND c.conname = $2 AND c.contype = 'f'",
    )
    .bind(entity)
    .bind(fk_name(entity, field))
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(match validated {
        None => FkState::None,
        Some(false) => FkState::NotValid,
        Some(true) => FkState::Valid,
    })
}

fn checked(entity: &str, field: &str, target: &str) -> Result<(), AppError> {
    if [entity, field, target].iter().all(|s| is_identifier(s)) {
        Ok(())
    } else {
        Err(AppError::internal(format!(
            "invalid identifier for a lookup key: {entity}.{field} -> {target}"
        )))
    }
}

/// Adds `entity.field`'s foreign key to `target`, `NOT VALID`, when it has
/// none. No scan.
pub async fn add_lookup_fk(
    db: &DbPool,
    entity: &str,
    field: &str,
    target: &str,
) -> Result<(), AppError> {
    checked(entity, field, target)?;
    if fk_state(db, entity, field).await? != FkState::None {
        return Ok(());
    }
    super::ddl::exec_ddl_locked(
        db,
        &[],
        &format!(
            "ALTER TABLE {} ADD CONSTRAINT {} FOREIGN KEY ({}) REFERENCES {} (id) \
             ON DELETE NO ACTION NOT VALID",
            quote_ident(entity),
            quote_ident(&fk_name(entity, field)),
            quote_ident(field),
            quote_ident(target)
        ),
    )
    .await
    .map_err(AppError::internal)
}

/// Validates `entity.field`'s foreign key now: a scan of the table. A value
/// that points at no record refuses it (`Conflict`), and the key stays
/// `NOT VALID`.
pub async fn validate_lookup_fk(db: &DbPool, entity: &str, field: &str) -> Result<(), AppError> {
    if !is_identifier(entity) || !is_identifier(field) {
        return Err(AppError::internal("invalid identifier for a lookup key"));
    }
    let sql = format!(
        "ALTER TABLE {} VALIDATE CONSTRAINT {}",
        quote_ident(entity),
        quote_ident(&fk_name(entity, field))
    );
    match super::ddl::exec_ddl_locked(db, &[], &sql).await {
        Ok(()) => Ok(()),
        Err(e)
            if e.as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|c| c == "23503") =>
        {
            Err(AppError::Conflict("lookup has orphan values"))
        }
        Err(e) => Err(AppError::internal(e)),
    }
}

/// What asking for a lookup's key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FkRequest {
    /// Added (if missing) and validated inline.
    Valid,
    /// Added `NOT VALID`; validation is queued (a table over the size gate).
    Queued,
}

/// Adds `entity.field`'s key to `target` `NOT VALID` and validates it:
/// inline when the table holds at most `inline_row_limit` rows, else by
/// queueing `ValidateLookupForeignKey` (dedup-keyed on the field).
pub async fn request_lookup_fk(
    db: &DbPool,
    entity: &str,
    field: &str,
    target: &str,
    inline_row_limit: i64,
) -> Result<FkRequest, AppError> {
    add_lookup_fk(db, entity, field, target).await?;
    if fk_state(db, entity, field).await? == FkState::Valid {
        return Ok(FkRequest::Valid);
    }
    if super::table_row_count_exceeds(db, entity, inline_row_limit).await? {
        attome_jobs::enqueue_dedup(
            db,
            attome_core::jobs::EngineJob::ValidateLookupForeignKey {
                entity_logicalname: entity.to_owned(),
                field_logicalname: field.to_owned(),
            },
            &format!("lookup-fk:{entity}.{field}"),
        )
        .await
        .map_err(AppError::internal)?;
        return Ok(FkRequest::Queued);
    }
    validate_lookup_fk(db, entity, field).await?;
    Ok(FkRequest::Valid)
}

/// The `ValidateLookupForeignKey` job: validates the key if it is still
/// there and not valid. Orphan values fail the job with the reason; the key
/// stays `NOT VALID`.
pub async fn run_validate_lookup_fk(
    db: &DbPool,
    entity: &str,
    field: &str,
) -> Result<(), AppError> {
    if fk_state(db, entity, field).await? != FkState::NotValid {
        return Ok(());
    }
    validate_lookup_fk(db, entity, field).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_keys_name_and_rule() {
        assert!(keyed("restrict") && keyed("cascade-deactivate"));
        assert!(!keyed("orphan"));
        assert_eq!(fk_name("deal", "account_ref"), "fk_deal_account_ref");
        let long = fk_name(&"e".repeat(40), &"f".repeat(40));
        assert_eq!(long.len(), 63);
        assert_eq!(long, fk_name(&"e".repeat(40), &"f".repeat(40)), "stable");
        assert_ne!(long, fk_name(&"e".repeat(40), &"g".repeat(40)));
    }

    #[test]
    fn spec_round_trips_and_adds() {
        let cols = vec![
            LookupColumn {
                attribute: "account".into(),
                target_entity: "account".into(),
            },
            LookupColumn {
                attribute: "owner".into(),
                target_entity: "user".into(),
            },
        ];
        let spec = scan_spec(Uuid::nil(), &cols);
        assert!(spec.get("field").is_none() && spec.get("attribute_id").is_none());
        let (back, counts) = spec_tallies(&spec).unwrap();
        assert_eq!(back, cols);
        assert_eq!(counts, vec![0, 0]);
        let mut broken = spec.clone();
        broken["orphans"] = json!([1]);
        assert!(spec_tallies(&broken).is_err());
        assert_eq!(run_tallies(&spec).unwrap()[1].target_entity, "user");
    }
}
