//! Y2-T12: partitioning a large standard entity table online.
//!
//! A builder starts it for one entity (never automatic). The table must hold
//! more rows than the threshold (`records.partition_row_threshold`,
//! 50,000,000 unless set). Then:
//!
//! 1. [`plan_partition`] checks the table can move: still `standard`, no
//!    earlier run's tables left, and nothing PostgreSQL could not carry over
//!    to a table whose unique keys must include `created_at`: no unique index
//!    besides the primary key (a business key), no foreign key from another
//!    table pointing at it (a keyed lookup, Y2-T5), no trigger of its own and
//!    no view over it.
//! 2. [`prepare`] creates `<entity>__p` in the high-volume shape (A1-T6): the
//!    same columns, defaults and checks, `created_at` required, the primary
//!    key `(id, created_at)`, partitioned by month on `created_at` with one
//!    `<entity>__p_history` partition for everything before this month and
//!    monthly partitions ahead, the table's other indexes, its foreign keys
//!    and its grants. A trigger on the table copies every insert, update and
//!    delete into `<entity>__p` from then on.
//! 3. [`copy_batch`] copies the existing rows in batches of
//!    [`PARTITION_BATCH`] by id (a durable data step run of kind
//!    `partition`), each batch's rows locked `FOR SHARE` while they are
//!    copied so a concurrent delete waits for the copy and then removes the
//!    copied row through the trigger. A row the trigger already copied is
//!    left as the trigger wrote it. A row with no `created_at` gets the time
//!    of the copy, since the partition key cannot be empty.
//! 4. [`swap`] renames, in one short transaction under a 5-second lock
//!    timeout: `<entity>` to `<entity>__old` and `<entity>__p` to `<entity>`,
//!    drops the trigger, and marks the entity `high_volume`. `<entity>__old`
//!    stays until a builder drops it.
//!
//! [`discard`] undoes steps 2 and 3 (a cancelled run).

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Datelike, Utc};
use uuid::Uuid;

use super::storage::{
    PARTITION_COLUMN, PARTITION_MONTHS_AHEAD, PARTITION_STORAGE_PARAMS, StorageMode,
    storage_mode_of,
};

/// The data step run kind.
pub const PARTITION_KIND: &str = "partition";
/// Rows one copy batch takes.
pub const PARTITION_BATCH: i64 = 10_000;
/// The setting holding the row count a table must exceed.
pub const ROW_THRESHOLD_SETTING: &str = "records.partition_row_threshold";
/// The threshold when the setting is not set.
pub const DEFAULT_ROW_THRESHOLD: i64 = 50_000_000;
/// The longest a table name may be in PostgreSQL.
const MAX_IDENTIFIER: usize = 63;

/// The partitioned copy's name.
pub fn shadow_name(entity: &str) -> String {
    format!("{entity}__p")
}

/// The name the original table keeps after the swap.
pub fn old_name(entity: &str) -> String {
    format!("{entity}__old")
}

fn sync_name(entity: &str) -> String {
    format!("{entity}__p_sync")
}

fn history_name(entity: &str) -> String {
    format!("{entity}__p_history")
}

/// What [`plan_partition`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionPlan {
    pub entity: String,
    /// The table's row count: the planner's estimate, counted exactly when
    /// the estimate is at or under the threshold.
    pub rows: i64,
}

/// Why a table cannot be partitioned, as one message. Pure.
pub fn blockers_message(entity: &str, blockers: &[String]) -> String {
    format!(
        "{entity} cannot be partitioned while {}; a partitioned table's unique keys and the \
         keys pointing at it must include created_at",
        blockers.join("; ")
    )
}

/// Checks `entity` can be partitioned with `threshold` rows as the floor.
pub async fn plan_partition(
    db: &DbPool,
    entity: &str,
    threshold: i64,
) -> Result<PartitionPlan, AppError> {
    if !super::valid_identifier(entity)
        || old_name(entity).len() > MAX_IDENTIFIER
        || history_name(entity).len() > MAX_IDENTIFIER
    {
        return Err(AppError::Validation(format!(
            "{entity}: the name is too long for the partitioned tables' names"
        )));
    }
    if storage_mode_of(db, entity).await? == StorageMode::HighVolume {
        return Err(AppError::Conflict("the entity is already partitioned"));
    }
    for name in [shadow_name(entity), old_name(entity)] {
        if table_exists(db, &name).await? {
            return Err(AppError::Conflict(
                "a partition run is under way, or the table from before an earlier swap is \
                 still kept",
            ));
        }
    }
    let mut blockers = Vec::new();
    let unique: Vec<String> = sqlx::query_scalar(
        "SELECT c.relname::text FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid \
          WHERE i.indrelid = to_regclass($1) AND i.indisunique AND NOT i.indisprimary \
          ORDER BY 1",
    )
    .bind(quote_ident(entity))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if !unique.is_empty() {
        blockers.push(format!("it has unique indexes ({})", unique.join(", ")));
    }
    let inbound: Vec<String> = sqlx::query_scalar(
        "SELECT conrelid::regclass::text || '.' || conname::text FROM pg_constraint \
          WHERE contype = 'f' AND confrelid = to_regclass($1) AND conrelid <> confrelid \
          ORDER BY 1",
    )
    .bind(quote_ident(entity))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if !inbound.is_empty() {
        blockers.push(format!(
            "keyed lookups point at it ({})",
            inbound.join(", ")
        ));
    }
    let triggers: Vec<String> = sqlx::query_scalar(
        "SELECT tgname::text FROM pg_trigger \
          WHERE tgrelid = to_regclass($1) AND NOT tgisinternal ORDER BY 1",
    )
    .bind(quote_ident(entity))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if !triggers.is_empty() {
        blockers.push(format!("it has triggers ({})", triggers.join(", ")));
    }
    let views: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT v.relname::text FROM pg_depend d \
           JOIN pg_rewrite r ON r.oid = d.objid \
           JOIN pg_class v ON v.oid = r.ev_class \
          WHERE d.refobjid = to_regclass($1) AND v.oid <> d.refobjid ORDER BY 1",
    )
    .bind(quote_ident(entity))
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if !views.is_empty() {
        blockers.push(format!("views read it ({})", views.join(", ")));
    }
    if !blockers.is_empty() {
        return Err(AppError::Validation(blockers_message(entity, &blockers)));
    }
    let mut rows: i64 = sqlx::query_scalar(
        "SELECT COALESCE(reltuples, -1)::bigint FROM pg_class WHERE oid = to_regclass($1)",
    )
    .bind(quote_ident(entity))
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if rows <= threshold {
        rows = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {}", quote_ident(entity)))
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    }
    if rows <= threshold {
        return Err(AppError::Validation(format!(
            "{entity} holds {rows} rows; partitioning is for tables over {threshold} \
             ({ROW_THRESHOLD_SETTING})"
        )));
    }
    Ok(PartitionPlan {
        entity: entity.to_owned(),
        rows,
    })
}

async fn table_exists(db: &DbPool, name: &str) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(quote_ident(name))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// The table's insertable columns, in order.
pub async fn columns(db: &DbPool, table: &str) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = $1 \
            AND is_generated = 'NEVER' ORDER BY ordinal_position",
    )
    .bind(table)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// An index definition (`pg_get_indexdef`) rewritten to `name` on `table`:
/// everything from ` USING ` on is kept. `None` for a definition without
/// one. Pure.
pub fn index_on(definition: &str, name: &str, table: &str) -> Option<String> {
    let at = definition.find(" USING ")?;
    Some(format!(
        "CREATE INDEX IF NOT EXISTS {} ON {}{}",
        quote_ident(name),
        quote_ident(table),
        &definition[at..]
    ))
}

/// The copy statement for one batch: the rows of `entity` whose ids are
/// `$1`, `created_at` filled when empty, into the partitioned copy, a row
/// already there left alone. Pure.
pub fn batch_sql(entity: &str, columns: &[String]) -> String {
    let list = columns
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let select = columns
        .iter()
        .map(|c| {
            if c == PARTITION_COLUMN {
                format!("COALESCE({0}, now()) AS {0}", quote_ident(c))
            } else {
                quote_ident(c)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "INSERT INTO {shadow} ({list}) SELECT {select} FROM {table} WHERE \"id\" = ANY($1) \
         ON CONFLICT DO NOTHING",
        shadow = quote_ident(&shadow_name(entity)),
        table = quote_ident(entity),
    )
}

/// The sync trigger's function: every change to `entity`'s `columns`
/// repeated on its partitioned copy. Pure.
pub fn sync_function_sql(entity: &str, columns: &[String]) -> String {
    let list = columns
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let values = columns
        .iter()
        .map(|c| format!("r.{}", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "CREATE OR REPLACE FUNCTION {func}() RETURNS trigger LANGUAGE plpgsql AS $fn$ \
         DECLARE r {table}%ROWTYPE; \
         BEGIN \
           IF TG_OP IN ('UPDATE', 'DELETE') THEN \
             DELETE FROM {shadow} WHERE \"id\" = OLD.\"id\"; \
           END IF; \
           IF TG_OP IN ('INSERT', 'UPDATE') THEN \
             r := NEW; \
             r.{col} := COALESCE(r.{col}, now()); \
             INSERT INTO {shadow} ({list}) VALUES ({values}); \
           END IF; \
           RETURN NULL; \
         END; $fn$",
        func = quote_ident(&sync_name(entity)),
        table = quote_ident(entity),
        shadow = quote_ident(&shadow_name(entity)),
        col = quote_ident(PARTITION_COLUMN),
    )
}

async fn exec(tx: &mut attome_db::Tx<'_>, sql: &str) -> Result<(), AppError> {
    sqlx::query(sql)
        .execute(&mut **tx)
        .await
        .map(|_| ())
        .map_err(AppError::internal)
}

/// Step 2: the partitioned copy, its partitions, indexes, keys and grants,
/// and the sync trigger, in one transaction (the table is locked only for
/// the trigger's creation).
#[expect(
    clippy::expect_used,
    reason = "the first day of a month at midnight is always a valid timestamp"
)]
pub async fn prepare(db: &DbPool, entity: &str) -> Result<(), AppError> {
    let table = quote_ident(entity);
    let shadow = shadow_name(entity);
    let shadow_q = quote_ident(&shadow);
    let indexes: Vec<(String, String)> = sqlx::query_as(
        "SELECT c.relname::text, pg_get_indexdef(i.indexrelid) FROM pg_index i \
           JOIN pg_class c ON c.oid = i.indexrelid \
          WHERE i.indrelid = to_regclass($1) AND NOT i.indisprimary AND NOT i.indisunique \
          ORDER BY 1",
    )
    .bind(&table)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let keys: Vec<(String, String)> = sqlx::query_as(
        "SELECT conname::text, pg_get_constraintdef(oid) FROM pg_constraint \
          WHERE conrelid = to_regclass($1) AND contype = 'f' ORDER BY 1",
    )
    .bind(&table)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let grants: Vec<(String, String)> = sqlx::query_as(
        "SELECT grantee::text, string_agg(DISTINCT privilege_type::text, ', ') \
           FROM information_schema.role_table_grants \
          WHERE table_schema = current_schema() AND table_name = $1 AND grantee <> current_user \
          GROUP BY grantee ORDER BY 1",
    )
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let insertable = columns(db, entity).await?;
    let month = Utc::now()
        .date_naive()
        .with_day(1)
        .expect("day 1 is always valid")
        .and_hms_opt(0, 0, 0)
        .expect("midnight is always valid")
        .and_utc();

    let mut tx = attome_db::tx::begin(db).await?;
    exec(&mut tx, "SET LOCAL lock_timeout = '5s'").await?;
    exec(
        &mut tx,
        &format!(
            "CREATE TABLE {shadow_q} (LIKE {table} INCLUDING DEFAULTS INCLUDING CONSTRAINTS \
             INCLUDING GENERATED) PARTITION BY RANGE ({col})",
            col = quote_ident(PARTITION_COLUMN)
        ),
    )
    .await?;
    exec(
        &mut tx,
        &format!(
            "ALTER TABLE {shadow_q} ALTER COLUMN {col} SET NOT NULL, \
             ADD PRIMARY KEY (\"id\", {col})",
            col = quote_ident(PARTITION_COLUMN)
        ),
    )
    .await?;
    exec(
        &mut tx,
        &format!(
            "CREATE TABLE {} PARTITION OF {shadow_q} FOR VALUES FROM (MINVALUE) TO ('{}') \
             WITH ({PARTITION_STORAGE_PARAMS})",
            quote_ident(&history_name(entity)),
            month.to_rfc3339()
        ),
    )
    .await?;
    for (name, definition) in &indexes {
        if let Some(sql) = index_on(definition, &format!("{name}__p"), &shadow) {
            exec(&mut tx, &sql).await?;
        }
    }
    exec(
        &mut tx,
        &format!(
            "CREATE INDEX IF NOT EXISTS {} ON {shadow_q} USING brin ({})",
            quote_ident(&format!("{entity}_created_brin")),
            quote_ident(PARTITION_COLUMN)
        ),
    )
    .await?;
    for (name, definition) in &keys {
        exec(
            &mut tx,
            &format!(
                "ALTER TABLE {shadow_q} ADD CONSTRAINT {} {definition}",
                quote_ident(name)
            ),
        )
        .await?;
    }
    for (grantee, privileges) in &grants {
        let to = if grantee == "PUBLIC" {
            "PUBLIC".to_owned()
        } else {
            quote_ident(grantee)
        };
        exec(
            &mut tx,
            &format!("GRANT {privileges} ON {shadow_q} TO {to}"),
        )
        .await?;
    }
    exec(&mut tx, &sync_function_sql(entity, &insertable)).await?;
    exec(
        &mut tx,
        &format!(
            "CREATE TRIGGER {sync} AFTER INSERT OR UPDATE OR DELETE ON {table} \
             FOR EACH ROW EXECUTE FUNCTION {sync}()",
            sync = quote_ident(&sync_name(entity))
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    attome_core::partition_maintenance::ensure_ahead_partitions(
        db,
        &shadow,
        PARTITION_COLUMN,
        PARTITION_STORAGE_PARAMS,
        PARTITION_MONTHS_AHEAD,
    )
    .await?;
    Ok(())
}

/// Step 3, one batch: the next [`PARTITION_BATCH`] rows after `cursor`,
/// locked for share while copied. Returns the rows read, the rows written
/// and the last id; no rows read means the copy is done.
pub async fn copy_batch(
    tx: &mut attome_db::Tx<'_>,
    entity: &str,
    insert: &str,
    cursor: Option<Uuid>,
) -> Result<(u64, u64, Option<Uuid>), AppError> {
    let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT \"id\" FROM {} WHERE \"id\" > $1 ORDER BY \"id\" LIMIT $2 FOR SHARE",
        quote_ident(entity)
    ))
    .bind(cursor.unwrap_or(Uuid::nil()))
    .bind(PARTITION_BATCH)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if ids.is_empty() {
        return Ok((0, 0, cursor));
    }
    let written = sqlx::query(insert)
        .bind(&ids)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    Ok((ids.len() as u64, written, ids.last().copied()))
}

/// Step 4: the swap, in one transaction under a 5-second lock timeout.
/// Refused when the table's columns changed since the copy began (a field
/// added or removed meanwhile): the copy would miss it.
pub async fn swap(db: &DbPool, entity: &str) -> Result<(), AppError> {
    let shadow = shadow_name(entity);
    let mut tx = attome_db::tx::begin(db).await?;
    exec(&mut tx, "SET LOCAL lock_timeout = '5s'").await?;
    exec(
        &mut tx,
        &format!(
            "LOCK TABLE {} IN ACCESS EXCLUSIVE MODE",
            quote_ident(entity)
        ),
    )
    .await?;
    let same: bool = sqlx::query_scalar(
        "SELECT COALESCE(array_agg(column_name::text ORDER BY ordinal_position) \
                FILTER (WHERE table_name = $1) \
              = array_agg(column_name::text ORDER BY ordinal_position) \
                FILTER (WHERE table_name = $2), false) \
           FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name IN ($1, $2)",
    )
    .bind(entity)
    .bind(&shadow)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if !same {
        return Err(AppError::Conflict(
            "the entity's fields changed while it was being copied; cancel the run and start again",
        ));
    }
    exec(
        &mut tx,
        &format!(
            "DROP TRIGGER IF EXISTS {} ON {}",
            quote_ident(&sync_name(entity)),
            quote_ident(entity)
        ),
    )
    .await?;
    exec(
        &mut tx,
        &format!(
            "DROP FUNCTION IF EXISTS {}()",
            quote_ident(&sync_name(entity))
        ),
    )
    .await?;
    exec(
        &mut tx,
        &format!(
            "ALTER TABLE {} RENAME TO {}",
            quote_ident(entity),
            quote_ident(&old_name(entity))
        ),
    )
    .await?;
    exec(
        &mut tx,
        &format!(
            "ALTER TABLE {} RENAME TO {}",
            quote_ident(&shadow),
            quote_ident(entity)
        ),
    )
    .await?;
    sqlx::query(
        "UPDATE entity_info SET storage_mode = 'high_volume' \
          WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await
}

/// Undoes [`prepare`]: the trigger, its function and the partitioned copy.
/// The original table is untouched.
pub async fn discard(db: &DbPool, entity: &str) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    exec(&mut tx, "SET LOCAL lock_timeout = '5s'").await?;
    exec(
        &mut tx,
        &format!(
            "DROP TRIGGER IF EXISTS {} ON {}",
            quote_ident(&sync_name(entity)),
            quote_ident(entity)
        ),
    )
    .await?;
    exec(
        &mut tx,
        &format!(
            "DROP FUNCTION IF EXISTS {}()",
            quote_ident(&sync_name(entity))
        ),
    )
    .await?;
    exec(
        &mut tx,
        &format!("DROP TABLE IF EXISTS {}", quote_ident(&shadow_name(entity))),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_moves_to_the_partitioned_copy() {
        assert_eq!(
            index_on(
                "CREATE INDEX account_name_trgm ON public.account USING gin (name gin_trgm_ops)",
                "account_name_trgm__p",
                "account__p"
            )
            .as_deref(),
            Some(
                "CREATE INDEX IF NOT EXISTS \"account_name_trgm__p\" ON \"account__p\" USING gin (name gin_trgm_ops)"
            )
        );
        assert_eq!(index_on("CREATE INDEX x ON t (a)", "y", "u"), None);
    }

    #[test]
    fn a_batch_fills_an_empty_created_at() {
        let sql = batch_sql(
            "deal",
            &["id".to_owned(), "created_at".to_owned(), "name".to_owned()],
        );
        assert!(sql.starts_with("INSERT INTO \"deal__p\" (\"id\", \"created_at\", \"name\")"));
        assert!(sql.contains("COALESCE(\"created_at\", now()) AS \"created_at\""));
        assert!(sql.ends_with("ON CONFLICT DO NOTHING"));
    }

    #[test]
    fn the_sync_trigger_repeats_every_change() {
        let sql = sync_function_sql("deal", &["id".to_owned(), "name".to_owned()]);
        assert!(sql.contains("DELETE FROM \"deal__p\" WHERE \"id\" = OLD.\"id\""));
        assert!(
            sql.contains(
                "INSERT INTO \"deal__p\" (\"id\", \"name\") VALUES (r.\"id\", r.\"name\")"
            )
        );
        assert!(sql.contains("DECLARE r \"deal\"%ROWTYPE"));
    }

    #[test]
    fn blockers_name_what_stops_the_move() {
        let message = blockers_message("deal", &["it has triggers (t1)".to_owned()]);
        assert!(message.contains("deal cannot be partitioned while it has triggers (t1)"));
    }
}
