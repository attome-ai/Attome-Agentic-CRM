//! T5-T2: a workspace's own schema. It holds a copy of every metadata table a
//! changeset can change (the recorder's owner-layer tables and the metadata
//! object store), with their rows, and an empty copy of every live entity
//! table and many-to-many join table. Identity and access tables (people,
//! teams, organisations, units, positions, API keys) are not copied: a
//! workspace shares them with live, as it shares sessions, audit and jobs.
//!
//! Every statement runs on the migrator pool (schema-adjacent work, D-117),
//! one table a transaction, so a large model never holds hundreds of table
//! locks at once. Identifiers are checked, then quoted (guidelines §4).

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// Tables a workspace copies with their rows besides the recorder's
/// owner-layer tables: the metadata object store (Y1).
const MODEL_TABLES: &[&str] = &["metadata_object", "metadata_object_version"];

/// Entity tables a workspace shares with live: who people are and what they
/// may reach. A table named after one of these, or starting with it and `_`,
/// is never copied.
pub const SHARED_TABLES: &[&str] = &[
    "user_account",
    "team",
    "organization",
    "business_unit",
    "position",
    "api_key",
];

/// The runtime role a workspace's tables are granted to, as migrations grant
/// live tables to it.
const RUNTIME_ROLE: &str = "attome_runtime";

/// What one copy made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopySummary {
    pub metadata_tables: i32,
    pub entity_tables: i32,
}

/// The schema of workspace `id`: `ws_` and the id's 32 hex digits. Pure.
pub fn schema_name(id: Uuid) -> String {
    format!("ws_{}", id.simple())
}

/// Whether `name` is a workspace schema name this module made. Pure.
pub fn is_workspace_schema(name: &str) -> bool {
    name.strip_prefix("ws_")
        .is_some_and(|hex| hex.len() == 32 && hex.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The metadata tables a workspace copies with their rows. Pure.
pub fn metadata_tables() -> Vec<&'static str> {
    attome_core::changeset::OWNER_LAYER_TABLES
        .iter()
        .chain(MODEL_TABLES)
        .copied()
        .collect()
}

/// Whether the entity table `table` is shared with live rather than copied.
/// Pure.
pub fn is_shared(table: &str) -> bool {
    SHARED_TABLES.iter().any(|shared| {
        table == *shared
            || table
                .strip_prefix(shared)
                .is_some_and(|rest| rest.starts_with('_'))
    })
}

fn checked(schema: &str) -> Result<&str, AppError> {
    if is_workspace_schema(schema) {
        Ok(schema)
    } else {
        Err(AppError::internal(format!(
            "{schema} is not a workspace schema"
        )))
    }
}

/// The live schema: the first on the search path.
pub(crate) async fn live_schema(db: &DbPool) -> Result<String, AppError> {
    sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Whether `table` exists in `schema`.
pub(crate) async fn exists(db: &DbPool, schema: &str, table: &str) -> Result<bool, AppError> {
    let found: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(format!("{}.{}", quote_ident(schema), quote_ident(table)))
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    Ok(found.is_some())
}

/// The columns of `schema.table` a copy may write: every column but the
/// generated ones, in order.
pub(crate) async fn writable_columns(
    db: &DbPool,
    schema: &str,
    table: &str,
) -> Result<Vec<String>, AppError> {
    sqlx::query_scalar(
        "SELECT column_name::text FROM information_schema.columns \
          WHERE table_schema = $1 AND table_name = $2 AND is_generated = 'NEVER' \
          ORDER BY ordinal_position",
    )
    .bind(schema)
    .bind(table)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Copies one table's structure into the workspace and, with `rows`, its
/// rows; in its own transaction.
async fn copy_table(
    db: &DbPool,
    live: &str,
    schema: &str,
    table: &str,
    rows: bool,
) -> Result<(), AppError> {
    let source = format!("{}.{}", quote_ident(live), quote_ident(table));
    let target = format!("{}.{}", quote_ident(schema), quote_ident(table));
    let columns = if rows {
        writable_columns(db, live, table)
            .await?
            .iter()
            .map(|c| quote_ident(c))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        String::new()
    };
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    sqlx::query(&format!(
        "CREATE TABLE {target} (LIKE {source} INCLUDING ALL)"
    ))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if rows && !columns.is_empty() {
        sqlx::query(&format!(
            "INSERT INTO {target} ({columns}) OVERRIDING SYSTEM VALUE \
             SELECT {columns} FROM {source}"
        ))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await
}

/// Creates workspace schema `schema` with the metadata tables (and their
/// rows) and the entity and join tables (empty) of live. A failure part way
/// drops what was made.
pub async fn create(db: &DbPool, schema: &str) -> Result<CopySummary, AppError> {
    let schema = checked(schema)?;
    let live = live_schema(db).await?;
    sqlx::query(&format!("CREATE SCHEMA {}", quote_ident(schema)))
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    match fill(db, &live, schema).await {
        Ok(summary) => Ok(summary),
        Err(error) => {
            if let Err(cleanup) = drop_schema(db, schema).await {
                tracing::warn!(schema, error = %cleanup, "workspace: a half-made schema was not dropped");
            }
            Err(error)
        }
    }
}

async fn fill(db: &DbPool, live: &str, schema: &str) -> Result<CopySummary, AppError> {
    let mut summary = CopySummary::default();
    let metadata = metadata_tables();
    for table in &metadata {
        if exists(db, live, table).await? {
            copy_table(db, live, schema, table, true).await?;
            summary.metadata_tables += 1;
        }
    }
    let mut entity_tables: Vec<String> = sqlx::query_scalar(
        "SELECT logicalname::text FROM entity_info \
          WHERE (is_active IS NULL OR is_active = true) AND logicalname IS NOT NULL \
         UNION \
         SELECT join_table::text FROM relationship_info \
          WHERE is_active AND NOT is_deleted",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    entity_tables.sort();
    entity_tables.dedup();
    for table in entity_tables {
        if metadata.contains(&table.as_str()) || is_shared(&table) {
            continue;
        }
        if exists(db, live, &table).await? {
            copy_table(db, live, schema, &table, false).await?;
            summary.entity_tables += 1;
        }
    }
    // One statement a query: a prepared statement holds one command.
    for grant in [
        format!(
            "GRANT USAGE ON SCHEMA {} TO {}",
            quote_ident(schema),
            quote_ident(RUNTIME_ROLE)
        ),
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {} TO {}",
            quote_ident(schema),
            quote_ident(RUNTIME_ROLE)
        ),
    ] {
        sqlx::query(&grant)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
    }
    Ok(summary)
}

/// Drops workspace schema `schema` with everything in it; a schema already
/// gone is fine.
pub async fn drop_schema(db: &DbPool, schema: &str) -> Result<(), AppError> {
    let schema = checked(schema)?;
    sqlx::query(&format!(
        "DROP SCHEMA IF EXISTS {} CASCADE",
        quote_ident(schema)
    ))
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_names_are_recognised_and_nothing_else_is() {
        let name = schema_name(Uuid::now_v7());
        assert!(is_workspace_schema(&name), "{name}");
        for other in ["public", "attome_dev", "ws_", "ws_xyz", "ws_0123"] {
            assert!(!is_workspace_schema(other), "{other}");
        }
    }

    #[test]
    fn identity_tables_are_shared_and_records_are_copied() {
        for shared in ["user_account", "user_account_mm_team", "team", "api_key"] {
            assert!(is_shared(shared), "{shared}");
        }
        for copied in ["account", "teamwork_item", "contact", "positioning_note"] {
            assert!(!is_shared(copied), "{copied}");
        }
    }

    #[test]
    fn the_metadata_tables_include_the_model_store_and_the_owner_layer_tables() {
        let tables = metadata_tables();
        for table in ["entity_info", "attribute_info", "view", "metadata_object"] {
            assert!(tables.contains(&table), "{table}");
        }
    }
}
