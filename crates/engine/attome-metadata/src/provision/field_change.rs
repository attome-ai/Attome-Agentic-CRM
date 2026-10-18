//! Solution 7 Phase 2 (D-788; `SOLUTION-7-PHASE-2-DESIGN.md` §3.1–§3.5,
//! §6.4) — the physical halves of the structure changes: rename a column in
//! place, drop a column after archiving its values, convert a column's type
//! in place, add or remove a choice value, and the batched run ledger
//! (`data_step_run`, migration 0526) for the large-table paths.
//!
//! Every `*_in_tx` function works inside the caller's transaction: the
//! orchestrator (`attome-server/src/field_changes.rs`) takes the metadata write
//! lock, runs the reference hooks, appends the change log, records the
//! changeset operation and commits, so the column, the attribute row, every
//! rewritten reference and the recorded op land at one commit (PostgreSQL
//! DDL is transactional). Identifiers come from validated metadata and are
//! quoted with `quote_ident`; every value is bound, and the only literals in
//! generated SQL (the conversion's true/false lists and choice map, needed
//! inside a trigger body where nothing can be bound) are quoted by the
//! server (`quote_literal`) — never by string formatting here.
//!
//! Values are archived before they are nulled or dropped, in the same
//! transaction ([`attome_core::recovery_archive::insert_batch`]).

use std::collections::BTreeMap;

use attome_config::KeyRing;
use attome_core::recovery_archive::{self, ArchiveEvent, ArchiveReason};
use attome_core::{FieldType, quote_ident};
use attome_db::{DbPool, Tx};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use super::identifiers::{attribute_index_name, is_multi_valued, valid_identifier};

/// Rows per keyset batch (archive copy, shadow-column backfill).
pub const FIELD_CHANGE_BATCH: i64 = 2_000;
/// How long a claimed run may sit without progress before takeover.
const RUN_CLAIM_TIMEOUT: &str = "30 minutes";
/// `lock_timeout` for the in-transaction DDL of these changes.
const FIELD_DDL_LOCK_TIMEOUT: &str = "5s";

/// Columns every entity table carries (`table.rs`), never metadata fields:
/// the one list, [`attome_core::ALL_SYSTEM_COLS`] (security review L3 —
/// this used to be a second list with a stray `ownerid` and no
/// `owner_type`). RLS and the engine name `owner_ref`/`organization_ref`
/// directly, so none of these is ever renamed, retyped or dropped.
pub const SYSTEM_COLUMNS: &[&str] = attome_core::ALL_SYSTEM_COLS;

/// Whether `name` is an entity table's system column ([`SYSTEM_COLUMNS`]).
pub fn is_system_column(name: &str) -> bool {
    SYSTEM_COLUMNS.contains(&name)
}

/// Refuses a structure change of a system column (rename, change type,
/// delete). Security review L3.
pub fn refuse_system_column(row: &FieldRow) -> Result<(), AppError> {
    if is_system_column(&row.field) {
        return Err(AppError::Validation(format!(
            "field_in_use: {} is a system column; it cannot be renamed, retyped or deleted",
            row.field
        )));
    }
    Ok(())
}

/// The live attribute a change works on, locked `FOR UPDATE`.
#[derive(Debug, Clone)]
pub struct FieldRow {
    pub attribute_id: Uuid,
    pub entity_id: Uuid,
    pub entity: String,
    pub field: String,
    /// The metadata type name (`FieldType::as_str`).
    pub field_type: String,
    pub options: Option<Value>,
    pub required: bool,
    pub max_length: Option<i32>,
    pub is_sortable: bool,
    pub is_filterable: bool,
    /// `is_sensitive` (D-111): archived values carry it (security review M1).
    pub is_sensitive: bool,
    pub owner_layer: String,
    pub primary_name_attribute: Option<String>,
}

impl FieldRow {
    pub fn is_multi(&self) -> bool {
        is_multi_valued(&self.field_type, self.options.as_ref())
    }

    fn table(&self) -> String {
        quote_ident(&self.entity)
    }

    fn column(&self) -> String {
        quote_ident(&self.field)
    }
}

/// Locks and reads the live attribute `attribute_id` of `entity_id`.
/// `NotFound` when it is not live.
pub async fn lock_field_in_tx(
    tx: &mut Tx<'_>,
    entity_id: Uuid,
    attribute_id: Uuid,
) -> Result<FieldRow, AppError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        entity_ref: Uuid,
        entity: String,
        field: String,
        type_int: i32,
        options: Option<Value>,
        required: bool,
        max_length: Option<i32>,
        is_sortable: bool,
        is_filterable: bool,
        is_sensitive: bool,
        owner_layer: String,
        primary_name_attribute: Option<String>,
    }
    let row: Option<Row> = sqlx::query_as(
        r#"SELECT a.id, a.entity_ref, e.logicalname AS entity, a.logicalname AS field,
                  COALESCE(a."type", 3) AS type_int, a.options,
                  COALESCE(a.required, false) AS required, a.max_length,
                  COALESCE(a.is_sortable, false) AS is_sortable,
                  COALESCE(a.is_filterable, false) AS is_filterable,
                  COALESCE(a.is_sensitive, false) AS is_sensitive,
                  a.owner_layer, e.primary_name_attribute
           FROM attribute_info a
           JOIN entity_info e ON e.id = a.entity_ref
           WHERE a.id = $1 AND a.entity_ref = $2
             AND (a.is_active IS NULL OR a.is_active = true)
             AND a.logicalname IS NOT NULL AND e.logicalname IS NOT NULL
           FOR UPDATE OF a"#,
    )
    .bind(attribute_id)
    .bind(entity_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    if !valid_identifier(&row.entity) || !valid_identifier(&row.field) {
        return Err(AppError::Validation("invalid schema identifier".into()));
    }
    Ok(FieldRow {
        attribute_id: row.id,
        entity_id: row.entity_ref,
        entity: row.entity,
        field: row.field,
        field_type: FieldType::from_int(row.type_int)
            .unwrap_or(FieldType::Text)
            .as_str()
            .to_owned(),
        options: row.options,
        required: row.required,
        max_length: row.max_length,
        is_sortable: row.is_sortable,
        is_filterable: row.is_filterable,
        is_sensitive: row.is_sensitive,
        owner_layer: row.owner_layer,
        primary_name_attribute: row.primary_name_attribute,
    })
}

/// Resolves `(entity, field)` logical names to `(entity_id, attribute_id)` of
/// the live attribute; `None` when either is not live.
pub async fn resolve_field(
    conn: &mut PgConnection,
    entity: &str,
    field: &str,
) -> Result<Option<(Uuid, Uuid)>, AppError> {
    sqlx::query_as(
        "SELECT e.id, a.id FROM attribute_info a \
         JOIN entity_info e ON e.id = a.entity_ref \
         WHERE e.logicalname = $1 AND a.logicalname = $2 \
           AND (e.is_active IS NULL OR e.is_active = true) \
           AND (a.is_active IS NULL OR a.is_active = true) \
         LIMIT 1",
    )
    .bind(entity)
    .bind(field)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Takes the per-attribute provisioning lock the reconcile primitives use,
/// so a concurrent reconcile of the same field conflicts instead of racing.
pub async fn lock_provisioning_in_tx(tx: &mut Tx<'_>, row: &FieldRow) -> Result<(), AppError> {
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-metadata/provision-attribute:{}:{}",
            row.entity_id, row.field
        ))
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if locked {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "attribute provisioning already in progress",
        ))
    }
}

/// `SET LOCAL` bounds for DDL inside the change's transaction: a lock that is
/// not granted within five seconds fails the change (409) instead of queuing
/// every reader of the table behind it; the statement itself is unbounded
/// (a small table's rewrite).
pub async fn set_ddl_bounds_in_tx(conn: &mut PgConnection) -> Result<(), AppError> {
    sqlx::query("SET LOCAL statement_timeout = 0")
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(&format!(
        "SET LOCAL lock_timeout = '{FIELD_DDL_LOCK_TIMEOUT}'"
    ))
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Maps a DDL error: a lock not granted in time is a retryable 409, anything
/// else masked.
pub fn map_ddl_error(error: sqlx::Error) -> AppError {
    let code = error
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.to_string());
    match code.as_deref() {
        Some("55P03") | Some("40P01") => AppError::Conflict(
            "field_busy: the table is in use; the change was not applied, retry shortly",
        ),
        _ => AppError::internal(error),
    }
}

/// `true` while a schema-change plan or a data-step/field run that names the
/// field is not terminal (design §3.1 step 2, `field_busy`). A `failed` run
/// counts as busy (security review L7): it is resumable (`claim_run` takes a
/// failed run) and still holds its partial state — a retype's shadow column
/// and sync trigger, a delete's archive rows — so no other change may start
/// on the field until the run is retried to completion.
pub async fn field_busy(conn: &mut PgConnection, row: &FieldRow) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM schema_change_operation \
             WHERE attribute_ref = $1 AND is_deleted = false \
               AND status IN ('queued', 'claimed', 'backfilling', 'altering')) \
         OR EXISTS (SELECT 1 FROM data_step_run \
             WHERE entity_logicalname = $2 \
               AND status IN ('queued', 'claimed', 'running', 'paused', 'failed') \
               AND (spec->>'field' = $3 OR spec->>'attribute_id' = $1::text \
                    OR spec->>'from' = $3 OR spec->>'to' = $3))",
    )
    .bind(row.attribute_id)
    .bind(&row.entity)
    .bind(&row.field)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Whether `table` has a column `column` (dropped columns excluded).
pub async fn column_exists(
    conn: &mut PgConnection,
    table: &str,
    column: &str,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2)",
    )
    .bind(table)
    .bind(column)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// The live row count of the entity table, exact (callers use it under the
/// size gate, where an exact count is cheap).
pub async fn count_rows(conn: &mut PgConnection, entity: &str) -> Result<i64, AppError> {
    sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {}", quote_ident(entity)))
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// Non-null values in the column. A full scan: callers use it only at or
/// under the size gate (security review M5).
pub async fn count_non_null(conn: &mut PgConnection, row: &FieldRow) -> Result<i64, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {} WHERE {} IS NOT NULL",
        row.table(),
        row.column()
    ))
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Whether the column holds any value (stops at the first; the batched job
/// asks once, not per batch — security review M5).
pub async fn has_non_null(conn: &mut PgConnection, row: &FieldRow) -> Result<bool, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {} WHERE {} IS NOT NULL)",
        row.table(),
        row.column()
    ))
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// The size gate inside the caller's transaction: whether the entity table
/// has more than `threshold` rows. Bounded (reads at most `threshold + 1`
/// rows), so it is the first thing a structure change asks, before any
/// count (security review M5).
pub async fn row_count_exceeds_in_tx(
    conn: &mut PgConnection,
    row: &FieldRow,
    threshold: i64,
) -> Result<bool, AppError> {
    sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {} OFFSET $1)",
        row.table()
    ))
    .bind(threshold.max(0))
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// The planner's estimate of the column's non-null values (`reltuples` ×
/// `1 - null_frac`), read from the catalog without touching the table —
/// what a large table's plan and dry run report instead of an exact count.
/// `None` when the table was never analyzed.
pub async fn estimate_non_null(
    conn: &mut PgConnection,
    row: &FieldRow,
) -> Result<Option<i64>, AppError> {
    sqlx::query_scalar::<_, Option<i64>>(
        "SELECT CASE WHEN c.reltuples < 0 THEN NULL \
                     ELSE GREATEST(0, ROUND(c.reltuples * (1 - COALESCE(s.null_frac, 0))))::bigint END \
         FROM pg_class c \
         LEFT JOIN pg_stats s ON s.schemaname = current_schema() AND s.tablename = $1 \
                             AND s.attname = $2 \
         WHERE c.oid = to_regclass(quote_ident($1))",
    )
    .bind(&row.entity)
    .bind(&row.field)
    .fetch_optional(&mut *conn)
    .await
    .map(Option::flatten)
    .map_err(AppError::internal)
}

// ── Rename (design §3.1 steps 3–5) ──────────────────────────────────────────

/// Checks `new_name` for a rename of `row`: a valid identifier, different,
/// not a system column, not an existing column (a retired attribute's column
/// still exists) and not a live attribute of the entity. A name a deleted
/// field once had may be reused (D-788: no name history).
pub async fn check_rename_target(
    conn: &mut PgConnection,
    row: &FieldRow,
    new_name: &str,
) -> Result<(), AppError> {
    if !valid_identifier(new_name) || !new_name.starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err(AppError::Validation(format!(
            "new_name must match ^[a-z][a-z0-9_]*$ and be at most {} chars",
            super::identifiers::MAX_IDENTIFIER_LEN
        )));
    }
    if new_name == row.field {
        return Err(AppError::Validation(
            "new_name must differ from the field's current name".into(),
        ));
    }
    refuse_system_column(row)?;
    if is_system_column(new_name) {
        return Err(AppError::Validation(format!(
            "new_name {new_name} is a system column"
        )));
    }
    if row.is_sortable || row.is_filterable {
        attribute_index_name(&row.entity, new_name)?;
    }
    let attribute_taken: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM attribute_info \
         WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true))",
    )
    .bind(row.entity_id)
    .bind(new_name)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if attribute_taken || column_exists(conn, &row.entity, new_name).await? {
        return Err(AppError::Conflict(
            "rename_target_exists: the entity already has a field or column with that name",
        ));
    }
    Ok(())
}

/// Renames the column in place, the objects whose names embed the field
/// (the sortable/filterable index, the length CHECK), the attribute row and
/// the entity's `primary_name_attribute`. Catalog-only DDL; the caller holds
/// the locks and set the DDL bounds.
pub async fn rename_column_in_tx(
    tx: &mut Tx<'_>,
    row: &FieldRow,
    new_name: &str,
) -> Result<(), AppError> {
    let table = row.table();
    sqlx::query(&format!(
        "ALTER TABLE {table} RENAME COLUMN {} TO {}",
        row.column(),
        quote_ident(new_name)
    ))
    .execute(&mut **tx)
    .await
    .map_err(map_ddl_error)?;

    let old_index = attribute_index_name(&row.entity, &row.field)?;
    let new_index = attribute_index_name(&row.entity, new_name)?;
    let index_exists: bool = sqlx::query_scalar("SELECT to_regclass(quote_ident($1)) IS NOT NULL")
        .bind(&old_index)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    if index_exists && new_index.len() <= attome_db::ident::PG_MAX_IDENTIFIER_LEN {
        sqlx::query(&format!(
            "ALTER INDEX {} RENAME TO {}",
            quote_ident(&old_index),
            quote_ident(&new_index)
        ))
        .execute(&mut **tx)
        .await
        .map_err(map_ddl_error)?;
    }
    for suffix in ["length", "notnull"] {
        let old_ck = format!("ck_{}_{}_{suffix}", row.entity, row.field);
        let new_ck = format!("ck_{}_{}_{suffix}", row.entity, new_name);
        if old_ck.len() > 63 || new_ck.len() > 63 {
            continue;
        }
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM pg_constraint c \
             JOIN pg_class t ON t.oid = c.conrelid \
             JOIN pg_namespace n ON n.oid = t.relnamespace \
             WHERE n.nspname = current_schema() AND t.relname = $1 AND c.conname = $2)",
        )
        .bind(&row.entity)
        .bind(&old_ck)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if exists {
            sqlx::query(&format!(
                "ALTER TABLE {table} RENAME CONSTRAINT {} TO {}",
                quote_ident(&old_ck),
                quote_ident(&new_ck)
            ))
            .execute(&mut **tx)
            .await
            .map_err(map_ddl_error)?;
        }
    }

    let n = sqlx::query(
        "UPDATE attribute_info SET logicalname = $2, modified_at = NOW() \
         WHERE id = $1",
    )
    .bind(row.attribute_id)
    .bind(new_name)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n != 1 {
        return Err(AppError::Conflict(
            "the field changed concurrently; reload and retry",
        ));
    }
    sqlx::query(
        "UPDATE entity_info SET primary_name_attribute = $3 \
         WHERE id = $1 AND primary_name_attribute = $2",
    )
    .bind(row.entity_id)
    .bind(&row.field)
    .bind(new_name)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    // Formula fields of the same entity name their inputs in
    // `options.expression`; an identifier-token rewrite keeps them compiling.
    rewrite_formula_inputs_in_tx(tx, row, new_name).await?;
    Ok(())
}

/// Formula fields of `row`'s entity whose expression names the field, by id
/// and name (the delete blocker, design §3.2 `field_in_use`).
pub async fn formula_dependents(
    conn: &mut PgConnection,
    row: &FieldRow,
) -> Result<Vec<(Uuid, String)>, AppError> {
    let candidates: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT id, logicalname, options->>'expression' FROM attribute_info \
         WHERE entity_ref = $1 AND id <> $2 AND \"type\" = $3 \
           AND (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL",
    )
    .bind(row.entity_id)
    .bind(row.attribute_id)
    .bind(FieldType::Formula.to_int())
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(candidates
        .into_iter()
        .filter(|(_, _, expr)| {
            expr.as_deref()
                .is_some_and(|e| expression_names(e, &row.field))
        })
        .map(|(id, name, _)| (id, name))
        .collect())
}

async fn rewrite_formula_inputs_in_tx(
    tx: &mut Tx<'_>,
    row: &FieldRow,
    new_name: &str,
) -> Result<(), AppError> {
    let rows: Vec<(Uuid, Value)> = sqlx::query_as(
        "SELECT id, options FROM attribute_info \
         WHERE entity_ref = $1 AND id <> $2 AND \"type\" = $3 AND options IS NOT NULL \
           AND (is_active IS NULL OR is_active = true)",
    )
    .bind(row.entity_id)
    .bind(row.attribute_id)
    .bind(FieldType::Formula.to_int())
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    for (id, mut options) in rows {
        let Some(expr) = options.get("expression").and_then(Value::as_str) else {
            continue;
        };
        let rewritten = rewrite_expression(expr, &row.field, new_name);
        if rewritten == expr {
            continue;
        }
        if let Some(map) = options.as_object_mut() {
            map.insert("expression".into(), Value::String(rewritten));
        }
        sqlx::query("UPDATE attribute_info SET options = $2, modified_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(&options)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(())
}

// ── Expression identifiers (attome-rules / formula grammar) ───────────────────

/// Splits an expression into tokens, keeping string literals whole, so an
/// identifier can be matched without touching text inside quotes. Returns
/// `(text, is_identifier)` pieces that concatenate back to the input.
fn expression_tokens(expr: &str) -> Vec<(String, bool)> {
    let chars: Vec<char> = expr.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == c {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let end = i.min(chars.len());
            out.push((chars[start..end].iter().collect(), false));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push((chars[start..i].iter().collect(), true));
        } else {
            out.push((c.to_string(), false));
            i += 1;
        }
    }
    out
}

/// Whether `expr` names `field` as a bare identifier of its own entity (not
/// the target half of a `lookup.field` hop, not inside a string).
pub fn expression_names(expr: &str, field: &str) -> bool {
    let tokens = expression_tokens(expr);
    tokens
        .iter()
        .enumerate()
        .any(|(i, (t, ident))| *ident && t == field && !(i > 0 && tokens[i - 1].0 == "."))
}

/// `expr` with every own-entity identifier `old` replaced by `new`.
pub fn rewrite_expression(expr: &str, old: &str, new: &str) -> String {
    let tokens = expression_tokens(expr);
    let mut out = String::with_capacity(expr.len());
    for (i, (t, ident)) in tokens.iter().enumerate() {
        if *ident && t == old && !(i > 0 && tokens[i - 1].0 == ".") {
            out.push_str(new);
        } else {
            out.push_str(t);
        }
    }
    out
}

// ── Archive and drop (design §3.2, §8.3) ────────────────────────────────────

/// Copies every non-null value of the column with `id > cursor` (at most
/// `limit` rows; all when `None`) into the recovery archive, in the caller's
/// transaction. Returns `(rows archived, last id)`.
pub async fn archive_values(
    conn: &mut PgConnection,
    ring: &KeyRing,
    event: &ArchiveEvent<'_>,
    row: &FieldRow,
    cursor: Option<Uuid>,
    limit: Option<i64>,
) -> Result<(u64, Option<Uuid>), AppError> {
    let mut cursor = cursor;
    let mut total: u64 = 0;
    loop {
        let take = match limit {
            Some(l) => (l - i64::try_from(total).unwrap_or(i64::MAX)).min(FIELD_CHANGE_BATCH),
            None => FIELD_CHANGE_BATCH,
        };
        if take <= 0 {
            break;
        }
        let batch: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
            "SELECT id, to_jsonb({col}) FROM {table} \
             WHERE {col} IS NOT NULL AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
            col = row.column(),
            table = row.table()
        ))
        .bind(cursor)
        .bind(take)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let n = batch.len();
        if n == 0 {
            break;
        }
        cursor = batch.last().map(|(id, _)| *id);
        recovery_archive::insert_batch(conn, ring, event, &batch).await?;
        total += n as u64;
        if i64::try_from(n).unwrap_or(0) < take {
            break;
        }
    }
    Ok((total, cursor))
}

/// Takes `SHARE` on the entity table: writers wait, readers do not. A large
/// run's final catch-up scans under it, so the table is only ever held
/// `ACCESS EXCLUSIVE` for the catalog-only DDL that follows (security review
/// M5). Bounded by the caller's `lock_timeout`.
pub async fn lock_table_share_in_tx(
    conn: &mut PgConnection,
    row: &FieldRow,
) -> Result<(), AppError> {
    sqlx::query(&format!("LOCK TABLE {} IN SHARE MODE", row.table()))
        .execute(&mut *conn)
        .await
        .map_err(map_ddl_error)?;
    Ok(())
}

/// `ACCESS EXCLUSIVE` on the entity table, for catalog-only DDL.
pub async fn lock_table_exclusive_in_tx(
    conn: &mut PgConnection,
    row: &FieldRow,
) -> Result<(), AppError> {
    sqlx::query(&format!(
        "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
        row.table()
    ))
    .execute(&mut *conn)
    .await
    .map_err(map_ddl_error)?;
    Ok(())
}

/// Archives the values of rows written since `since` (a large delete's final
/// catch-up; the run's archive rows for those records are replaced). Walks
/// the table in id-ordered batches of [`FIELD_CHANGE_BATCH`] rows, each a
/// bounded statement, never one unbounded fetch (security review M5). The
/// caller holds `SHARE` ([`lock_table_share_in_tx`]), so no row changes
/// under the walk.
pub async fn archive_changed_since(
    conn: &mut PgConnection,
    ring: &KeyRing,
    event: &ArchiveEvent<'_>,
    row: &FieldRow,
    since: DateTime<Utc>,
) -> Result<u64, AppError> {
    let mut cursor: Option<Uuid> = None;
    let mut total = 0;
    loop {
        let batch: Vec<(Uuid, Option<Value>)> = sqlx::query_as(&format!(
            "WITH b AS (SELECT id FROM {table} WHERE ($1::uuid IS NULL OR id > $1) \
                        ORDER BY id LIMIT $2) \
             SELECT t.id, CASE WHEN t.{col} IS NOT NULL \
                                AND (t.modified_at >= $3 OR t.created_at >= $3) \
                           THEN to_jsonb(t.{col}) END \
             FROM {table} t JOIN b ON b.id = t.id ORDER BY t.id",
            col = row.column(),
            table = row.table()
        ))
        .bind(cursor)
        .bind(FIELD_CHANGE_BATCH)
        .bind(since)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let Some((last, _)) = batch.last() else {
            break;
        };
        cursor = Some(*last);
        let scanned = batch.len();
        let changed: Vec<(Uuid, Value)> = batch
            .into_iter()
            .filter_map(|(id, v)| v.map(|v| (id, v)))
            .collect();
        for chunk in changed.chunks(500) {
            total += recovery_archive::insert_batch(conn, ring, event, chunk).await?;
        }
        if i64::try_from(scanned).unwrap_or(0) < FIELD_CHANGE_BATCH {
            break;
        }
    }
    Ok(total)
}

/// Security review L6: removes a batched run's archive rows whose value is
/// no longer the record's value at the end of the run — the record was
/// deleted, or its value was cleared or scrubbed after its batch archived it
/// (for a retype, also: it now holds a value that converts). What the
/// archive keeps is exactly what the drop or the conversion destroys, so a
/// value erased while the run was going never survives it. Bounded by the
/// run's own archive rows (`(run_ref, record_id)` index, a primary-key probe
/// each). The caller holds `SHARE` on the table. `still_lost` is the SQL
/// predicate (over alias `t`) of a record whose archived value is still the
/// one that is lost; built from quoted identifiers only.
pub async fn prune_run_archive(
    conn: &mut PgConnection,
    run_id: Uuid,
    row: &FieldRow,
    still_lost: &str,
) -> Result<u64, AppError> {
    let done = sqlx::query(&format!(
        "DELETE FROM recovery_archive a WHERE a.run_ref = $1 \
         AND NOT EXISTS (SELECT 1 FROM {table} t WHERE t.id = a.record_id AND {still_lost})",
        table = row.table()
    ))
    .bind(run_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected())
}

/// The [`prune_run_archive`] predicate of a delete: the value still exists.
pub fn delete_still_lost(row: &FieldRow) -> String {
    format!("t.{} IS NOT NULL", row.column())
}

/// Drops the column (catalog-only; the field's index and CHECKs go with it)
/// and deletes the attribute row. The caller archived the values first, in
/// this transaction.
pub async fn drop_column_in_tx(tx: &mut Tx<'_>, row: &FieldRow) -> Result<(), AppError> {
    sqlx::query(&format!(
        "ALTER TABLE {} DROP COLUMN IF EXISTS {}",
        row.table(),
        row.column()
    ))
    .execute(&mut **tx)
    .await
    .map_err(map_ddl_error)?;
    let n = sqlx::query("DELETE FROM attribute_info WHERE id = $1")
        .bind(row.attribute_id)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    if n != 1 {
        return Err(AppError::Conflict(
            "the field changed concurrently; reload and retry",
        ));
    }
    Ok(())
}

// ── Type conversion (design §3.4, §6.3, §6.4) ──────────────────────────────

/// `CONVERSIONS` in `scripts/changesets/lib.mjs`.
pub fn conversion_defined(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        (
            "text",
            "number" | "currency" | "date" | "bool" | "choice" | "rich_text"
        ) | ("number", "text" | "currency")
            | ("currency", "text" | "number")
            | ("date", "text")
            | ("bool", "text")
            | ("choice", "text")
    )
}

/// `DATE_FORMATS` in `lib.mjs` -> the `to_char`/`to_timestamp` pattern.
fn date_pattern(format: Option<&str>) -> Result<Option<&'static str>, AppError> {
    match format {
        None | Some("iso8601") => Ok(None),
        Some("dd/mm/yyyy") => Ok(Some("DD/MM/YYYY")),
        Some("mm/dd/yyyy") => Ok(Some("MM/DD/YYYY")),
        Some("dd.mm.yyyy") => Ok(Some("DD.MM.YYYY")),
        Some(other) => Err(AppError::Validation(format!(
            "conversion.format {other:?} is not one of iso8601, dd/mm/yyyy, mm/dd/yyyy, dd.mm.yyyy"
        ))),
    }
}

/// A requested in-place conversion (the op's `args.conversion` plus the
/// target type).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Conversion {
    pub from_type: String,
    #[serde(default)]
    pub to_type: String,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub true_values: Option<Vec<String>>,
    #[serde(default)]
    pub false_values: Option<Vec<String>>,
    #[serde(default)]
    pub map: Option<BTreeMap<String, String>>,
}

impl Conversion {
    /// Refuses conversions `lib.mjs` does not define and members that do not
    /// apply to the pair (mirrors `conversionErrors`).
    pub fn check(&self) -> Result<(), AppError> {
        let (from, to) = (self.from_type.as_str(), self.to_type.as_str());
        if from == to {
            return Err(AppError::Validation(
                "field_type must differ from the field's current type".into(),
            ));
        }
        if !conversion_defined(from, to) {
            return Err(AppError::Validation(format!(
                "conversion_not_defined: no conversion from {from} to {to}"
            )));
        }
        let text_date = matches!((from, to), ("text", "date") | ("date", "text"));
        if self.format.is_some() && !text_date {
            return Err(AppError::Validation(
                "conversion.format applies only to text<->date".into(),
            ));
        }
        date_pattern(self.format.as_deref())?;
        if (self.true_values.is_some() || self.false_values.is_some())
            && (from, to) != ("text", "bool")
        {
            return Err(AppError::Validation(
                "conversion.true_values/false_values apply only to text->bool".into(),
            ));
        }
        if self.map.is_some() && (from, to) != ("text", "choice") {
            return Err(AppError::Validation(
                "conversion.map applies only to text->choice".into(),
            ));
        }
        if (from, to) == ("text", "choice") && self.map.as_ref().is_none_or(BTreeMap::is_empty) {
            return Err(AppError::Validation(
                "a text->choice conversion needs conversion.map (source text -> choice value); \
                 the mapped values become the field's choices"
                    .into(),
            ));
        }
        for list in [&self.true_values, &self.false_values]
            .into_iter()
            .flatten()
        {
            if list.is_empty() || list.iter().any(|v| v.is_empty() || v.len() > 40) {
                return Err(AppError::Validation(
                    "true_values/false_values entries must be 1..40 chars".into(),
                ));
            }
        }
        if let Some(map) = &self.map
            && map
                .iter()
                .any(|(k, v)| k.is_empty() || v.is_empty() || v.len() > 100)
        {
            return Err(AppError::Validation(
                "conversion.map keys and values must be non-empty; values at most 100 chars".into(),
            ));
        }
        Ok(())
    }

    fn pg_type(ft: &str) -> &'static str {
        FieldType::try_from(ft)
            .unwrap_or(FieldType::Text)
            .pg_type(false)
    }

    /// Whether a stored value can become null (and so be archived). Every
    /// defined conversion *to text* keeps every value; the metadata-only
    /// pairs change none.
    pub fn can_null(&self) -> bool {
        self.changes_values() && self.to_type != "text"
    }

    /// Whether the physical column type changes.
    pub fn changes_column(&self) -> bool {
        Self::pg_type(&self.from_type) != Self::pg_type(&self.to_type)
    }

    /// Whether any stored value can change or become null. `false` for the
    /// metadata-only pairs (number<->currency, text->rich_text,
    /// choice->text).
    pub fn changes_values(&self) -> bool {
        !matches!(
            (self.from_type.as_str(), self.to_type.as_str()),
            ("number", "currency")
                | ("currency", "number")
                | ("text", "rich_text")
                | ("choice", "text")
        )
    }

    /// The target type's `options` (a choice target's `choices` are the
    /// map's distinct values, in first-seen order of the sorted map).
    pub fn target_options(&self) -> Option<Value> {
        if self.to_type != "choice" {
            return None;
        }
        let mut choices: Vec<&String> = Vec::new();
        for v in self.map.iter().flat_map(|m| m.values()) {
            if !choices.contains(&v) {
                choices.push(v);
            }
        }
        Some(json!({ "choices": choices }))
    }

    /// The SQL expression converting `col` (a quoted column reference,
    /// `"f"` or `NEW."f"`), NULL where the value does not convert. Literals
    /// are quoted by the server (`quote_literal`), never here.
    pub async fn expression(&self, conn: &mut PgConnection, col: &str) -> Result<String, AppError> {
        let (from, to) = (self.from_type.as_str(), self.to_type.as_str());
        Ok(match (from, to) {
            ("text", "number" | "currency") => format!("try_numeric({col})"),
            ("text", "date") => {
                let fmt = self.format.as_deref().unwrap_or("iso8601");
                // A closed list, checked by `check`; quoted by the server all
                // the same.
                format!("try_timestamptz({col}, {})", literal(conn, fmt).await?)
            }
            ("text", "bool") => {
                let t = text_array_literal(conn, self.true_values.as_deref()).await?;
                let f = text_array_literal(conn, self.false_values.as_deref()).await?;
                format!("try_bool({col}, {t}, {f})")
            }
            ("text", "choice") => {
                let map = serde_json::to_string(&self.map).map_err(AppError::internal)?;
                let choices: Vec<String> = self
                    .target_options()
                    .and_then(|o| o.get("choices").cloned())
                    .and_then(|c| serde_json::from_value(c).ok())
                    .unwrap_or_default();
                let map_lit = literal(conn, &map).await?;
                let choices_lit = text_array_literal(conn, Some(&choices)).await?;
                format!(
                    "(CASE WHEN COALESCE(({map_lit})::jsonb ->> btrim({col}), btrim({col})) \
                          = ANY({choices_lit}) \
                     THEN COALESCE(({map_lit})::jsonb ->> btrim({col}), btrim({col})) END)"
                )
            }
            ("text", "rich_text") | ("choice", "text") => col.to_owned(),
            ("number" | "currency", "text") | ("bool", "text") => format!("({col})::text"),
            ("number", "currency") | ("currency", "number") => col.to_owned(),
            ("date", "text") => match date_pattern(self.format.as_deref())? {
                None => {
                    format!("to_char(({col}) AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')")
                }
                Some(pattern) => format!(
                    "to_char(({col}) AT TIME ZONE 'UTC', {})",
                    literal(conn, pattern).await?
                ),
            },
            _ => {
                return Err(AppError::Validation(format!(
                    "conversion_not_defined: no conversion from {from} to {to}"
                )));
            }
        })
    }
}

/// `quote_literal($1)` — the server quotes, so no request text is ever
/// spliced into SQL by this process.
async fn literal(conn: &mut PgConnection, value: &str) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT quote_literal($1::text)")
        .bind(value)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// `ARRAY[...]::text[]` of server-quoted literals, or `NULL::text[]`.
async fn text_array_literal(
    conn: &mut PgConnection,
    values: Option<&[String]>,
) -> Result<String, AppError> {
    let Some(values) = values else {
        return Ok("NULL::text[]".into());
    };
    let mut parts = Vec::with_capacity(values.len());
    for v in values {
        parts.push(literal(conn, v).await?);
    }
    Ok(format!("ARRAY[{}]::text[]", parts.join(", ")))
}

/// How many non-null values would not convert, and up to `sample` of their
/// record ids (the dry run's `not_convertible` check; ids only, never
/// values).
pub async fn count_not_convertible(
    conn: &mut PgConnection,
    row: &FieldRow,
    conv: &Conversion,
    sample: i64,
) -> Result<(i64, Vec<Uuid>), AppError> {
    if !conv.can_null() {
        return Ok((0, Vec::new()));
    }
    let expr = conv.expression(conn, &row.column()).await?;
    let predicate = format!("{col} IS NOT NULL AND ({expr}) IS NULL", col = row.column());
    let count: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {} WHERE {predicate}",
        row.table()
    ))
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {} WHERE {predicate} ORDER BY id LIMIT $1",
        row.table()
    ))
    .bind(sample)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok((count, ids))
}

/// Archives the values that will not convert (every one, in batches), in
/// the caller's transaction. Returns the count archived.
pub async fn archive_not_convertible(
    conn: &mut PgConnection,
    ring: Option<&KeyRing>,
    event: &ArchiveEvent<'_>,
    row: &FieldRow,
    expr: &str,
) -> Result<u64, AppError> {
    let mut cursor: Option<Uuid> = None;
    let mut total = 0;
    loop {
        let batch: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
            "SELECT id, to_jsonb({col}) FROM {table} \
             WHERE {col} IS NOT NULL AND ({expr}) IS NULL AND ($1::uuid IS NULL OR id > $1) \
             ORDER BY id LIMIT $2",
            col = row.column(),
            table = row.table()
        ))
        .bind(cursor)
        .bind(FIELD_CHANGE_BATCH)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if batch.is_empty() {
            break;
        }
        let ring = ring.ok_or(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING))?;
        cursor = batch.last().map(|(id, _)| *id);
        for chunk in batch.chunks(500) {
            total += recovery_archive::insert_batch(conn, ring, event, chunk).await?;
        }
        if i64::try_from(batch.len()).unwrap_or(0) < FIELD_CHANGE_BATCH {
            break;
        }
    }
    Ok(total)
}

/// Updates the attribute row to the target type (and a choice target's
/// options; `max_length` cleared when the target is not text).
pub async fn set_attribute_type_in_tx(
    conn: &mut PgConnection,
    row: &FieldRow,
    conv: &Conversion,
) -> Result<(), AppError> {
    let to = FieldType::try_from(conv.to_type.as_str())
        .map_err(|e| AppError::Validation(format!("invalid field_type: {e}")))?;
    let options = conv.target_options().or_else(|| row.options.clone());
    let keep_length = matches!(conv.to_type.as_str(), "text" | "rich_text");
    let n = sqlx::query(
        "UPDATE attribute_info \
         SET \"type\" = $2, options = $3, \
             max_length = CASE WHEN $4 THEN max_length ELSE NULL END, modified_at = NOW() \
         WHERE id = $1",
    )
    .bind(row.attribute_id)
    .bind(to.to_int())
    .bind(options)
    .bind(keep_length)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 1 {
        Ok(())
    } else {
        Err(AppError::Conflict(
            "the field changed concurrently; reload and retry",
        ))
    }
}

/// The at-or-under-the-gate in-place conversion (design §6.4, small table),
/// in the caller's transaction: lock the table, drop a stale `NOT NULL`
/// (required is application-level, §3.6), archive the values that will not
/// convert, convert, update the attribute row. Returns the values nulled.
pub async fn retype_inline_in_tx(
    tx: &mut Tx<'_>,
    ring: Option<&KeyRing>,
    event: &ArchiveEvent<'_>,
    row: &FieldRow,
    conv: &Conversion,
) -> Result<u64, AppError> {
    let table = row.table();
    let col = row.column();
    sqlx::query(&format!("LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))
        .execute(&mut **tx)
        .await
        .map_err(map_ddl_error)?;
    sqlx::query(&format!(
        "ALTER TABLE {table} ALTER COLUMN {col} DROP NOT NULL"
    ))
    .execute(&mut **tx)
    .await
    .map_err(map_ddl_error)?;
    let mut nulled = 0;
    if conv.changes_values() {
        let expr = conv.expression(tx, &col).await?;
        if conv.can_null() {
            nulled = archive_not_convertible(tx, ring, event, row, &expr).await?;
        }
        if conv.changes_column() {
            let length_ck = format!("ck_{}_{}_length", row.entity, row.field);
            if length_ck.len() <= 63 {
                sqlx::query(&format!(
                    "ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {}",
                    quote_ident(&length_ck)
                ))
                .execute(&mut **tx)
                .await
                .map_err(map_ddl_error)?;
            }
            sqlx::query(&format!(
                "ALTER TABLE {table} ALTER COLUMN {col} TYPE {} USING {expr}",
                Conversion::pg_type(&conv.to_type)
            ))
            .execute(&mut **tx)
            .await
            .map_err(map_ddl_error)?;
        } else {
            sqlx::query(&format!(
                "UPDATE {table} SET {col} = {expr} WHERE {col} IS DISTINCT FROM {expr}"
            ))
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        }
    }
    set_attribute_type_in_tx(tx, row, conv).await?;
    Ok(nulled)
}

/// Deterministic 8-hex suffix of a large retype's shadow column and trigger:
/// the random tail of the run id (one run per field change, so unique per
/// table, and stable across a resume).
pub fn shadow_suffix(run_id: Uuid) -> String {
    let hex = run_id.simple().to_string();
    hex[hex.len() - 8..].to_owned()
}

fn shadow_names(suffix: &str) -> (String, String) {
    (format!("__rt_{suffix}"), format!("rt_{suffix}"))
}

/// Large retype, prepare (design §6.4 step 1): the nullable shadow column
/// and the sync trigger that keeps it converted for rows written from now
/// on. Idempotent (a resumed run re-runs it harmlessly).
pub async fn retype_prepare_in_tx(
    tx: &mut Tx<'_>,
    row: &FieldRow,
    conv: &Conversion,
    suffix: &str,
) -> Result<(), AppError> {
    let (shadow, trigger) = shadow_names(suffix);
    let table = row.table();
    sqlx::query(&format!(
        "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {} {}",
        quote_ident(&shadow),
        Conversion::pg_type(&conv.to_type)
    ))
    .execute(&mut **tx)
    .await
    .map_err(map_ddl_error)?;
    let expr = conv
        .expression(tx, &format!("NEW.{}", row.column()))
        .await?;
    sqlx::query(&format!(
        "CREATE OR REPLACE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $fn$ \
         BEGIN NEW.{shadow} := {expr}; RETURN NEW; END; $fn$",
        func = quote_ident(&trigger),
        shadow = quote_ident(&shadow)
    ))
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(&format!(
        "DROP TRIGGER IF EXISTS {trig} ON {table}",
        trig = quote_ident(&trigger)
    ))
    .execute(&mut **tx)
    .await
    .map_err(map_ddl_error)?;
    sqlx::query(&format!(
        "CREATE TRIGGER {trig} BEFORE INSERT OR UPDATE OF {col} ON {table} \
         FOR EACH ROW EXECUTE FUNCTION {trig}()",
        trig = quote_ident(&trigger),
        col = row.column()
    ))
    .execute(&mut **tx)
    .await
    .map_err(map_ddl_error)?;
    Ok(())
}

/// Large retype, one backfill batch (design §6.4 step 2): converts the next
/// `FIELD_CHANGE_BATCH` rows after `cursor` into the shadow column and
/// archives the batch's non-convertible values. Returns `(rows, nulled,
/// last id)`; zero rows means the backfill is done.
pub async fn retype_batch_in_tx(
    tx: &mut Tx<'_>,
    ring: Option<&KeyRing>,
    event: &ArchiveEvent<'_>,
    row: &FieldRow,
    conv: &Conversion,
    suffix: &str,
    cursor: Option<Uuid>,
) -> Result<(u64, u64, Option<Uuid>), AppError> {
    let (shadow, _) = shadow_names(suffix);
    let table = row.table();
    let col = row.column();
    let expr = conv.expression(tx, &format!("t.{col}")).await?;
    let updated: Vec<(Uuid, bool, Value)> = sqlx::query_as(&format!(
        "WITH b AS (SELECT id FROM {table} WHERE ($1::uuid IS NULL OR id > $1) \
                    ORDER BY id LIMIT $2 FOR UPDATE) \
         UPDATE {table} t SET {shadow} = {expr} FROM b WHERE t.id = b.id \
         RETURNING t.id, (t.{col} IS NOT NULL AND t.{shadow} IS NULL), to_jsonb(t.{col})",
        shadow = quote_ident(&shadow)
    ))
    .bind(cursor)
    .bind(FIELD_CHANGE_BATCH)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let rows = updated.len() as u64;
    let last = updated.iter().map(|(id, _, _)| *id).max().or(cursor);
    let nulled: Vec<(Uuid, Value)> = updated
        .into_iter()
        .filter(|(_, n, _)| *n)
        .map(|(id, _, v)| (id, v))
        .collect();
    if !nulled.is_empty() {
        let ring = ring.ok_or(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING))?;
        for chunk in nulled.chunks(500) {
            recovery_archive::insert_batch(tx, ring, event, chunk).await?;
        }
    }
    Ok((rows, nulled.len() as u64, last))
}

/// Large retype, catch-up (design §6.4 step 3, first half), in the swap's
/// transaction: `SHARE` on the table (writers wait, readers do not) while
/// the non-convertible values of rows the trigger converted after their
/// batch passed are archived in id-ordered batches, then the run's archive
/// rows whose record no longer loses a value are pruned (security review
/// L6). Returns the values archived. No scan runs under `ACCESS EXCLUSIVE`
/// (security review M5); [`retype_swap_in_tx`] follows in the same
/// transaction.
pub async fn retype_catch_up_in_tx(
    tx: &mut Tx<'_>,
    ring: Option<&KeyRing>,
    event: &ArchiveEvent<'_>,
    row: &FieldRow,
    suffix: &str,
) -> Result<u64, AppError> {
    let (shadow, _) = shadow_names(suffix);
    let table = row.table();
    let col = row.column();
    let shadow_q = quote_ident(&shadow);
    lock_table_share_in_tx(tx, row).await?;
    let mut archived = 0;
    let mut cursor: Option<Uuid> = None;
    loop {
        let batch: Vec<(Uuid, Option<Value>)> = sqlx::query_as(&format!(
            "WITH b AS (SELECT id FROM {table} WHERE ($1::uuid IS NULL OR id > $1) \
                        ORDER BY id LIMIT $2) \
             SELECT t.id, CASE WHEN t.{col} IS NOT NULL AND t.{shadow_q} IS NULL \
                           THEN to_jsonb(t.{col}) END \
             FROM {table} t JOIN b ON b.id = t.id ORDER BY t.id"
        ))
        .bind(cursor)
        .bind(FIELD_CHANGE_BATCH)
        .fetch_all(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        let Some((last, _)) = batch.last() else {
            break;
        };
        cursor = Some(*last);
        let scanned = batch.len();
        let pending: Vec<(Uuid, Value)> = batch
            .into_iter()
            .filter_map(|(id, v)| v.map(|v| (id, v)))
            .collect();
        if !pending.is_empty() {
            let ring = ring.ok_or(AppError::Conflict(recovery_archive::ARCHIVE_KEY_MISSING))?;
            for chunk in pending.chunks(500) {
                archived += recovery_archive::insert_batch(tx, ring, event, chunk).await?;
            }
        }
        if i64::try_from(scanned).unwrap_or(0) < FIELD_CHANGE_BATCH {
            break;
        }
    }
    if let Some(run_id) = event.run_ref {
        let still_lost = format!("t.{col} IS NOT NULL AND t.{shadow_q} IS NULL");
        prune_run_archive(tx, run_id, row, &still_lost).await?;
    }
    Ok(archived)
}

/// Large retype, swap (design §6.4 step 3, second half), after
/// [`retype_catch_up_in_tx`] in the same transaction: `ACCESS EXCLUSIVE`
/// only for the catalog DDL — drop the trigger and the old column, rename
/// the shadow column into place — and the attribute row. The field's index
/// (dropped with the old column) is recreated by the caller after commit.
pub async fn retype_swap_in_tx(
    tx: &mut Tx<'_>,
    row: &FieldRow,
    conv: &Conversion,
    suffix: &str,
) -> Result<(), AppError> {
    let (shadow, trigger) = shadow_names(suffix);
    let table = row.table();
    let col = row.column();
    lock_table_exclusive_in_tx(tx, row).await?;
    for sql in [
        format!(
            "DROP TRIGGER IF EXISTS {} ON {table}",
            quote_ident(&trigger)
        ),
        format!("DROP FUNCTION IF EXISTS {}()", quote_ident(&trigger)),
        format!("ALTER TABLE {table} DROP COLUMN {col}"),
        format!(
            "ALTER TABLE {table} RENAME COLUMN {} TO {col}",
            quote_ident(&shadow)
        ),
    ] {
        sqlx::query(&sql)
            .execute(&mut **tx)
            .await
            .map_err(map_ddl_error)?;
    }
    set_attribute_type_in_tx(tx, row, conv).await?;
    Ok(())
}

/// The shadow column of a large retype (`__rt_<suffix>`); present from the
/// run's creation until the swap renames it into place.
pub fn retype_shadow_column(suffix: &str) -> String {
    shadow_names(suffix).0
}

/// Drops a large retype's shadow column, sync trigger and trigger function
/// (an abandoned run), in the caller's transaction. The caller set the DDL
/// bounds ([`set_ddl_bounds_in_tx`]): each statement takes the table lock it
/// needs, bounded by `lock_timeout` (a busy table is a retryable 409).
/// Idempotent (`IF EXISTS` throughout).
pub async fn retype_cleanup_in_tx(
    conn: &mut PgConnection,
    row: &FieldRow,
    suffix: &str,
) -> Result<(), AppError> {
    let (shadow, trigger) = shadow_names(suffix);
    for sql in [
        format!(
            "DROP TRIGGER IF EXISTS {} ON {}",
            quote_ident(&trigger),
            row.table()
        ),
        format!("DROP FUNCTION IF EXISTS {}()", quote_ident(&trigger)),
        format!(
            "ALTER TABLE {} DROP COLUMN IF EXISTS {}",
            row.table(),
            quote_ident(&shadow)
        ),
    ] {
        sqlx::query(&sql)
            .execute(&mut *conn)
            .await
            .map_err(map_ddl_error)?;
    }
    Ok(())
}

// ── Choice values (design §3.5) ─────────────────────────────────────────────

/// `options.choices` of a choice field.
pub fn choices_of(options: Option<&Value>) -> Vec<String> {
    options
        .and_then(|o| o.get("choices"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Adds `value` to the field's choices (after `after`, or at the end), with
/// an optional style. `false` when the value is already a choice and the
/// style is unchanged (noop).
pub async fn add_choice_in_tx(
    conn: &mut PgConnection,
    row: &FieldRow,
    value: &str,
    after: Option<&str>,
    style: Option<&Value>,
) -> Result<bool, AppError> {
    if row.field_type != "choice" {
        return Err(AppError::Validation(format!(
            "{}.{} is a {} field, not a choice field",
            row.entity, row.field, row.field_type
        )));
    }
    if value.is_empty() || value.chars().count() > 100 {
        return Err(AppError::Validation(
            "a choice value must be 1..100 characters".into(),
        ));
    }
    let mut options = row.options.clone().unwrap_or_else(|| json!({}));
    let mut choices = choices_of(Some(&options));
    let mut changed = false;
    if !choices.iter().any(|c| c == value) {
        let at = match after {
            Some(a) => choices
                .iter()
                .position(|c| c == a)
                .map(|p| p + 1)
                .ok_or_else(|| {
                    AppError::Validation(format!("after: {a:?} is not a choice of this field"))
                })?,
            None => choices.len(),
        };
        choices.insert(at, value.to_owned());
        changed = true;
    }
    let Some(map) = options.as_object_mut() else {
        return Err(AppError::Validation(
            "the field's options are not an object".into(),
        ));
    };
    map.insert("choices".into(), json!(choices));
    if let Some(style) = style {
        let styles = map.entry("choice_styles").or_insert_with(|| json!({}));
        if let Some(styles) = styles.as_object_mut()
            && styles.get(value) != Some(style)
        {
            styles.insert(value.to_owned(), style.clone());
            changed = true;
        }
    }
    if changed {
        write_options(conn, row, &options).await?;
    }
    Ok(changed)
}

/// Removes `value` from the field's choices (and its style). Stored values
/// stay in place (design §3.5: no data step). Returns whether it was a
/// choice. Scans nothing: the caller counts the records that keep the value
/// only under the size gate (security review M5).
pub async fn remove_choice_in_tx(
    conn: &mut PgConnection,
    row: &FieldRow,
    value: &str,
) -> Result<bool, AppError> {
    if row.field_type != "choice" {
        return Err(AppError::Validation(format!(
            "{}.{} is a {} field, not a choice field",
            row.entity, row.field, row.field_type
        )));
    }
    let mut options = row.options.clone().unwrap_or_else(|| json!({}));
    let mut choices = choices_of(Some(&options));
    let before = choices.len();
    choices.retain(|c| c != value);
    if choices.len() == before {
        return Ok(false);
    }
    if let Some(map) = options.as_object_mut() {
        map.insert("choices".into(), json!(choices));
        if let Some(styles) = map.get_mut("choice_styles").and_then(Value::as_object_mut) {
            styles.remove(value);
        }
    }
    write_options(conn, row, &options).await?;
    Ok(true)
}

/// Rows holding `value` (the `choice_value_in_use` pre-check).
pub async fn count_choice_in_use(
    conn: &mut PgConnection,
    row: &FieldRow,
    value: &str,
) -> Result<i64, AppError> {
    let predicate = if row.is_multi() {
        format!("$1 = ANY({})", row.column())
    } else {
        format!("{} = $1", row.column())
    };
    sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {} WHERE {predicate}",
        row.table()
    ))
    .bind(value)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// A5-T3: how many records hold each stored value of a choice field, most
/// used first. One grouped scan; the caller applies the size gate.
pub async fn choice_usage(
    conn: &mut PgConnection,
    row: &FieldRow,
) -> Result<Vec<(String, i64)>, AppError> {
    let sql = if row.is_multi() {
        format!(
            "SELECT v, COUNT(*) FROM {}, unnest({}) AS v GROUP BY v ORDER BY 2 DESC, 1",
            row.table(),
            row.column()
        )
    } else {
        format!(
            "SELECT {col}::text, COUNT(*) FROM {} WHERE {col} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC, 1",
            row.table(),
            col = row.column()
        )
    };
    sqlx::query_as(&sql)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)
}

async fn write_options(
    conn: &mut PgConnection,
    row: &FieldRow,
    options: &Value,
) -> Result<(), AppError> {
    // The shape is the caller-validated `ChoiceOptions` (`attome_field::
    // validate_options` runs in the admin handler before this executor).
    sqlx::query(
        "UPDATE attribute_info SET options = $2, is_customized = true, \
         modified_at = NOW() WHERE id = $1",
    )
    .bind(row.attribute_id)
    .bind(options)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Required is application-level (design §3.6) ────────────────────────────

/// One-time sweep (D-788, amends D-180): drops the physical `NOT NULL` the
/// old required path left on a **required** attribute's column of a
/// **runtime-provisioned** entity table. Deliberately narrow (security review
/// H1): a table a migration creates or alters (audit chain, S2S, roles, …) is
/// often registered as an entity too, but its NOT NULLs are integrity
/// constraints, not "required" flags, so every table named in
/// `migration_tables` (see [`migration_owned_tables`]) is skipped, and so is
/// every `platform`-layer entity: platform tables are written by engine code
/// that relies on their NOT NULLs, and only project/customer entities go
/// through the application-level required check. System
/// columns (`ALL_SYSTEM_COLS`) and non-required attributes are never touched.
/// Catalog-only, one bounded statement per column; each dropped column is
/// logged. Returns the columns changed. Boot runs it once, behind a seed gate.
pub async fn drop_required_not_null(
    db: &DbPool,
    migration_tables: &std::collections::BTreeSet<String>,
) -> Result<u64, AppError> {
    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT e.logicalname, a.logicalname \
         FROM attribute_info a \
         JOIN entity_info e ON e.id = a.entity_ref \
         JOIN information_schema.columns c \
           ON c.table_schema = current_schema() AND c.table_name = e.logicalname \
          AND c.column_name = a.logicalname \
         WHERE c.is_nullable = 'NO' AND a.logicalname IS NOT NULL AND e.logicalname IS NOT NULL \
           AND COALESCE(a.required, false) AND e.owner_layer <> 'platform'",
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "D-788: required NOT NULL sweep: candidate query failed");
        AppError::internal(e)
    })?;
    let mut changed = 0;
    for (entity, field) in columns {
        if migration_tables.contains(&entity)
            || is_system_column(&field)
            || !valid_identifier(&entity)
            || !valid_identifier(&field)
        {
            continue;
        }
        super::ddl::exec_ddl_locked(
            db,
            &[],
            &format!(
                "ALTER TABLE {} ALTER COLUMN {} DROP NOT NULL",
                quote_ident(&entity),
                quote_ident(&field)
            ),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, entity = %entity, field = %field,
                "D-788: required NOT NULL sweep: DROP NOT NULL failed");
            AppError::internal(e)
        })?;
        tracing::info!(
            entity = %entity,
            field = %field,
            "D-788: dropped a physical NOT NULL; required is application-level"
        );
        changed += 1;
    }
    Ok(changed)
}

/// The tables a migration creates or alters, parsed from the migration SQL
/// texts (`CREATE TABLE` / `ALTER TABLE`, optional `IF [NOT] EXISTS`/`ONLY`,
/// plus every `RENAME TO` target; schema prefix and quotes stripped,
/// lower-cased). Their constraints belong
/// to the migration, so [`drop_required_not_null`] never touches them.
pub fn migration_owned_tables<'a>(
    sqls: impl IntoIterator<Item = &'a str>,
) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    for sql in sqls {
        let lower = sql.to_ascii_lowercase();
        let words: Vec<&str> = lower.split_whitespace().collect();
        for (i, pair) in words.windows(2).enumerate() {
            let table_stmt = matches!(pair[0], "create" | "alter") && pair[1] == "table";
            let rename_to = pair[0] == "rename" && pair[1] == "to";
            if !table_stmt && !rename_to {
                continue;
            }
            let mut k = i + 2;
            while let Some(w) = words.get(k) {
                if matches!(*w, "if" | "not" | "exists" | "only") {
                    k += 1;
                } else {
                    break;
                }
            }
            let Some(raw) = words.get(k) else { continue };
            let name = raw
                .split(['(', ';', ','])
                .next()
                .unwrap_or_default()
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .trim_matches('"');
            if valid_identifier(name) {
                out.insert(name.to_owned());
            }
        }
    }
    out
}

// ── The run ledger (migration 0526) ─────────────────────────────────────────

/// A new `data_step_run` row.
pub struct NewRun<'a> {
    pub changeset_op: Option<(Uuid, i32)>,
    pub apply_ref: Option<Uuid>,
    /// `admin | apply | replay`.
    pub source: &'a str,
    pub entity: &'a str,
    /// `retype | archive | ...`.
    pub kind: &'a str,
    pub spec: Value,
    pub rows_estimate: Option<i64>,
    pub created_by: Option<Uuid>,
}

impl std::fmt::Debug for NewRun<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewRun").finish_non_exhaustive()
    }
}

/// Inserts the run in the caller's transaction; one run per (changeset, op)
/// per deployment (an existing one is returned).
pub async fn create_run_in_tx(conn: &mut PgConnection, run: NewRun<'_>) -> Result<Uuid, AppError> {
    let (changeset_id, op_seq) = match run.changeset_op {
        Some((id, seq)) => (Some(id), Some(seq)),
        None => (None, None),
    };
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO data_step_run \
             (changeset_id, op_seq, apply_ref, source, entity_logicalname, kind, spec, \
              rows_estimate, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (changeset_id, op_seq) WHERE changeset_id IS NOT NULL DO NOTHING \
         RETURNING id",
    )
    .bind(changeset_id)
    .bind(op_seq)
    .bind(run.apply_ref)
    .bind(run.source)
    .bind(run.entity)
    .bind(run.kind)
    .bind(&run.spec)
    .bind(run.rows_estimate)
    .bind(run.created_by)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    if let Some(id) = inserted {
        return Ok(id);
    }
    sqlx::query_scalar("SELECT id FROM data_step_run WHERE changeset_id = $1 AND op_seq = $2")
        .bind(changeset_id)
        .bind(op_seq)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// One run row.
#[derive(Debug, Clone, sqlx::FromRow, Serialize)]
pub struct RunRow {
    pub id: Uuid,
    pub changeset_id: Option<Uuid>,
    pub op_seq: Option<i32>,
    pub source: String,
    pub entity_logicalname: String,
    pub kind: String,
    pub spec: Value,
    pub status: String,
    pub rows_estimate: Option<i64>,
    pub rows_scanned: i64,
    pub rows_written: i64,
    pub rows_nulled: i64,
    pub cursor: Option<Uuid>,
    pub error_message: Option<String>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

const RUN_COLUMNS: &str = "id, changeset_id, op_seq, source, entity_logicalname, kind, spec, \
     status, rows_estimate, rows_scanned, rows_written, rows_nulled, cursor, error_message, \
     created_by, created_at, finished_at";

pub async fn get_run(conn: &mut PgConnection, id: Uuid) -> Result<Option<RunRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {RUN_COLUMNS} FROM data_step_run WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Reads the run and locks it `FOR UPDATE` in the caller's transaction (a
/// concurrent [`claim_run`] waits, then sees the outcome). `None`: no such run.
pub async fn lock_run_in_tx(conn: &mut PgConnection, id: Uuid) -> Result<Option<RunRow>, AppError> {
    sqlx::query_as(&format!(
        "SELECT {RUN_COLUMNS} FROM data_step_run WHERE id = $1 FOR UPDATE"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)
}

/// Marks a **failed** run `abandoned` (migration 0538): terminal, so
/// [`field_busy`] no longer counts it and [`claim_run`] never takes it
/// again. The cursor and claim are cleared; the counters stay as the record
/// of what the run did. `false` when the run is not `failed` (nothing
/// changed).
pub async fn abandon_run_in_tx(conn: &mut PgConnection, id: Uuid) -> Result<bool, AppError> {
    let done = sqlx::query(
        "UPDATE data_step_run SET status = 'abandoned', cursor = NULL, claimed_by = NULL, claimed_at = NULL, finished_at = NOW(), updated_at = NOW(), row_version = row_version + 1 WHERE id = $1 AND status = 'failed'",
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected() == 1)
}

/// Removes every recovery-archive row a run wrote. Only for an abandoned run
/// whose destructive step never committed: the archived values are then
/// still the record's live values, so the copies protect nothing.
pub async fn delete_run_archive_in_tx(
    conn: &mut PgConnection,
    run_id: Uuid,
) -> Result<u64, AppError> {
    let done = sqlx::query("DELETE FROM recovery_archive WHERE run_ref = $1")
        .bind(run_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(done.rows_affected())
}

/// Row-CAS claim with a stale-claim takeover (the schema-change plan's
/// scheme). `None`: not claimable (terminal, or held by a live claim).
pub async fn claim_run(db: &DbPool, id: Uuid, worker: &str) -> Result<Option<RunRow>, AppError> {
    sqlx::query_as(&format!(
        "UPDATE data_step_run \
         SET status = 'running', claimed_by = $2, claimed_at = NOW(), updated_at = NOW(), \
             started_at = COALESCE(started_at, NOW()), row_version = row_version + 1 \
         WHERE id = $1 AND (status IN ('queued', 'failed') \
               OR (status IN ('claimed', 'running') \
                   AND claimed_at < NOW() - INTERVAL '{RUN_CLAIM_TIMEOUT}')) \
         RETURNING {RUN_COLUMNS}"
    ))
    .bind(id)
    .bind(worker)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Y12-T5: moves the run from one of `from` to `to`; `false` when it was in
/// none of them (nothing changed). A run leaving for `queued` or `paused`
/// gives up its claim.
pub async fn set_run_status(
    conn: &mut PgConnection,
    id: Uuid,
    from: &[&str],
    to: &str,
    error: Option<&str>,
) -> Result<bool, AppError> {
    let from: Vec<String> = from.iter().map(|s| (*s).to_owned()).collect();
    let done = sqlx::query(
        "UPDATE data_step_run \
         SET status = $3, error_message = COALESCE($4, error_message), \
             claimed_by = CASE WHEN $3 IN ('queued', 'paused') THEN NULL ELSE claimed_by END, \
             finished_at = CASE WHEN $3 IN ('abandoned') THEN NOW() ELSE finished_at END, \
             updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1 AND status = ANY($2)",
    )
    .bind(id)
    .bind(&from)
    .bind(to)
    .bind(error)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected() == 1)
}

/// Y12-T5: whether a run its worker holds was paused or cancelled since it
/// was claimed. The batch loops ask before each batch, so a run stops
/// between batches (each batch commits with its cursor; none is half done).
pub async fn run_stopped(db: &DbPool, id: Uuid) -> Result<bool, AppError> {
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM data_step_run WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(status.as_deref() != Some("running"))
}

/// Advances the cursor and counters in the batch's own transaction (and
/// refreshes the claim).
pub async fn advance_run(
    conn: &mut PgConnection,
    id: Uuid,
    cursor: Option<Uuid>,
    scanned: u64,
    written: u64,
    nulled: u64,
) -> Result<(), AppError> {
    let as_i64 = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    sqlx::query(
        "UPDATE data_step_run \
         SET cursor = $2, rows_scanned = rows_scanned + $3, rows_written = rows_written + $4, \
             rows_nulled = rows_nulled + $5, claimed_at = NOW(), updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(cursor)
    .bind(as_i64(scanned))
    .bind(as_i64(written))
    .bind(as_i64(nulled))
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Marks a run terminal. `error` is a masked, operator-readable message.
pub async fn finish_run(
    conn: &mut PgConnection,
    id: Uuid,
    error: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE data_step_run \
         SET status = CASE WHEN $2::text IS NULL THEN 'succeeded' ELSE 'failed' END, \
             error_message = $2, finished_at = CASE WHEN $2::text IS NULL THEN NOW() END, \
             updated_at = NOW(), row_version = row_version + 1 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(error)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Builds the archive event of a field for an op.
pub fn archive_event<'a>(
    reason: ArchiveReason,
    row: &'a FieldRow,
    op: Option<(Uuid, i32)>,
    run_ref: Option<Uuid>,
) -> ArchiveEvent<'a> {
    ArchiveEvent {
        reason,
        entity: &row.entity,
        field: &row.field,
        attribute_id: row.attribute_id,
        field_type: &row.field_type,
        sensitive: row.is_sensitive,
        op,
        run_ref,
        // Y12-T10: an entity-level retention setting (A18) is not defined
        // yet, so the archive keeps its default.
        retention_days: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field_row(field: &str) -> FieldRow {
        FieldRow {
            attribute_id: Uuid::now_v7(),
            entity_id: Uuid::now_v7(),
            entity: "invoice".into(),
            field: field.into(),
            field_type: "text".into(),
            options: None,
            required: false,
            max_length: None,
            is_sortable: false,
            is_filterable: false,
            is_sensitive: true,
            owner_layer: "project".into(),
            primary_name_attribute: None,
        }
    }

    #[test]
    fn system_columns_are_the_one_foundation_list_and_are_refused() {
        // Security review L3: one list, with `owner_type`, no stray `ownerid`.
        assert_eq!(SYSTEM_COLUMNS, attome_core::ALL_SYSTEM_COLS);
        for col in [
            "id",
            "owner_ref",
            "owner_type",
            "organization_ref",
            "row_version",
        ] {
            assert!(is_system_column(col), "{col}");
            assert!(refuse_system_column(&field_row(col)).is_err(), "{col}");
        }
        assert!(!is_system_column("ownerid"));
        assert!(refuse_system_column(&field_row("amount")).is_ok());
    }

    #[test]
    fn archive_events_carry_the_fields_sensitivity() {
        // Security review M1: the sensitivity is sealed with each value.
        let row = field_row("salary");
        let event = archive_event(ArchiveReason::FieldDeleted, &row, None, None);
        assert!(event.sensitive);
        assert_eq!(event.attribute_id, row.attribute_id);
    }

    #[test]
    fn only_conversions_that_can_null_need_the_archive() {
        let conv = |from: &str, to: &str| Conversion {
            from_type: from.into(),
            to_type: to.into(),
            ..Conversion::default()
        };
        assert!(conv("text", "number").can_null());
        assert!(conv("text", "date").can_null());
        for (from, to) in [
            ("number", "text"),
            ("date", "text"),
            ("bool", "text"),
            ("number", "currency"),
            ("text", "rich_text"),
        ] {
            assert!(!conv(from, to).can_null(), "{from}->{to}");
        }
    }

    #[test]
    fn the_delete_prune_keeps_only_values_still_present() {
        assert_eq!(
            delete_still_lost(&field_row("amount")),
            "t.\"amount\" IS NOT NULL"
        );
    }

    #[test]
    fn migration_owned_tables_parses_create_and_alter() {
        let t = migration_owned_tables([
            "CREATE TABLE IF NOT EXISTS audit_header (id uuid);",
            "alter table only public.\"s2s_client\" add column x int;",
            "ALTER TABLE role
  ALTER COLUMN owner_layer DROP DEFAULT;",
            "CREATE TABLE	foo_bar(id int); -- create table",
            "ALTER TABLE IF EXISTS a RENAME TO a;",
        ]);
        let got: Vec<&str> = t.iter().map(String::as_str).collect();
        // A set: each table once, in name order.
        assert_eq!(got, ["a", "audit_header", "foo_bar", "role", "s2s_client"]);
    }

    #[test]
    fn expression_rewrite_touches_only_own_entity_identifiers() {
        let e = "amount * 2 + parent_ref.amount + \"amount\" + amount_total";
        assert!(expression_names(e, "amount"));
        assert_eq!(
            rewrite_expression(e, "amount", "value"),
            "value * 2 + parent_ref.amount + \"amount\" + amount_total"
        );
        assert!(!expression_names("parent_ref.amount", "amount"));
        assert!(!expression_names("'amount' == x", "amount"));
    }

    #[test]
    fn conversions_mirror_the_catalogue() {
        for (from, tos) in [
            (
                "text",
                &["number", "currency", "date", "bool", "choice", "rich_text"][..],
            ),
            ("number", &["text", "currency"][..]),
            ("currency", &["text", "number"][..]),
            ("date", &["text"][..]),
            ("bool", &["text"][..]),
            ("choice", &["text"][..]),
        ] {
            for to in tos {
                assert!(conversion_defined(from, to), "{from}->{to}");
            }
        }
        assert!(!conversion_defined("bool", "date"));
        assert!(!conversion_defined("lookup", "text"));
        assert!(!conversion_defined("text", "lookup"));
    }

    #[test]
    fn conversion_members_apply_only_to_their_pair() {
        let base = |from: &str, to: &str| Conversion {
            from_type: from.into(),
            to_type: to.into(),
            ..Conversion::default()
        };
        assert!(base("text", "number").check().is_ok());
        assert!(base("text", "text").check().is_err());
        assert!(base("bool", "date").check().is_err());
        let mut c = base("text", "number");
        c.format = Some("iso8601".into());
        assert!(c.check().is_err());
        let mut c = base("text", "choice");
        assert!(c.check().is_err(), "text->choice needs a map");
        c.map = Some(BTreeMap::from([("Gold".to_owned(), "gold".to_owned())]));
        assert!(c.check().is_ok());
        assert_eq!(c.target_options(), Some(json!({ "choices": ["gold"] })));
        assert!(!base("number", "currency").changes_values());
        assert!(base("text", "number").changes_column());
        assert!(!base("text", "choice").changes_column());
    }
}
