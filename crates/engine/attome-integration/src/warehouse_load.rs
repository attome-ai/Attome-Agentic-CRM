//! Loading the warehouse export into Snowflake and BigQuery (roadmap
//! P13-T2).
//!
//! The export (P13-T1) writes Parquet files under `warehouse/{entity}/` in the
//! deployment's object storage. Attome holds no warehouse credentials: for
//! each entity it writes one load script the customer schedules on the
//! warehouse side (a Snowflake task, a BigQuery scheduled query). Each run of
//! the script stages the files not loaded yet, keeps each record's newest
//! change (`_event_id` is a UUIDv7, so its text sorts by time), and merges by
//! `id`: an upsert inserts or updates, a tombstone deletes, and a change
//! older than the row already loaded is ignored, so a rerun or a file read
//! twice changes nothing.
//!
//! - **Snowflake**: an external stage the customer created over the same
//!   bucket; `COPY INTO` with a pattern loads each file once (Snowflake's
//!   own load history skips loaded files), into a stage table the run
//!   empties afterwards.
//! - **BigQuery**: an external table over `gs://…/warehouse/{entity}/*`; a
//!   `__loaded` table keeps the newest event merged, and each run merges the
//!   changes after it up to the newest event it saw when it started.
//!
//! Every column is text, as in the files. The script adds columns the entity
//! gained (`ADD COLUMN IF NOT EXISTS`); regenerate it when the export's
//! schema version changes.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

/// Columns the target table keeps beside the attributes (`_op` stays in the
/// stage).
const TARGET_CONTROL: [&str; 3] = ["id", "_event_id", "_changed_at"];

/// A logical name the scripts may quote: lowercase letters, digits and `_`,
/// not starting with a digit. Pure.
pub fn is_safe_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_')
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && name.len() <= 128
}

/// A Snowflake stage name, optionally qualified (`DB.SCHEMA.STAGE`). Pure.
pub fn is_safe_stage(stage: &str) -> bool {
    let parts: Vec<&str> = stage.split('.').collect();
    (1..=3).contains(&parts.len())
        && parts.iter().all(|p| {
            let mut chars = p.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        })
}

/// A BigQuery dataset, optionally with its project (`project.dataset`). Pure.
pub fn is_safe_dataset(dataset: &str) -> bool {
    let parts: Vec<&str> = dataset.split('.').collect();
    (1..=2).contains(&parts.len())
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
}

/// A `gs://bucket[/prefix]` URI. Pure.
pub fn is_safe_bucket(uri: &str) -> bool {
    uri.strip_prefix("gs://").is_some_and(|rest| {
        let rest = rest.trim_end_matches('/');
        !rest.is_empty()
            && rest
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
            && !rest.contains("//")
    })
}

fn check_columns(entity: &str, columns: &[String]) -> Result<(), AppError> {
    if !is_safe_name(entity) || columns.iter().any(|c| !is_safe_name(c)) {
        return Err(AppError::Validation(
            "an entity or column name cannot be used in a load script".into(),
        ));
    }
    if !columns.iter().any(|c| c == "id") || !columns.iter().any(|c| c == "_op") {
        return Err(AppError::Validation(
            "the export's columns lack id or _op".into(),
        ));
    }
    Ok(())
}

/// The target table's columns: the control columns, then every exported
/// column but `_op`. Pure.
fn target_columns(columns: &[String]) -> Vec<&str> {
    let mut out: Vec<&str> = TARGET_CONTROL.to_vec();
    for c in columns {
        if c != "_op" && !out.contains(&c.as_str()) {
            out.push(c.as_str());
        }
    }
    out
}

/// A Snowflake quoted identifier (the name is already checked). Pure.
fn q(c: &str) -> String {
    format!("\"{c}\"")
}

/// The Snowflake load script for `entity` with the export's `columns`,
/// loading from external stage `stage` into table `"{entity}"`. Pure.
pub fn snowflake_script(entity: &str, columns: &[String], stage: &str) -> Result<String, AppError> {
    check_columns(entity, columns)?;
    if !is_safe_stage(stage) {
        return Err(AppError::Validation(
            "stage is not a Snowflake stage name".into(),
        ));
    }
    let table = q(entity);
    let staging = q(&format!("{entity}__stage"));
    let target = target_columns(columns);
    let mut s = String::new();
    s.push_str(&format!(
        "CREATE TABLE IF NOT EXISTS {table} ({});\n",
        target
            .iter()
            .map(|c| format!("{} VARCHAR", q(c)))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    for c in &target {
        s.push_str(&format!(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {} VARCHAR;\n",
            q(c)
        ));
    }
    s.push_str(&format!(
        "CREATE TABLE IF NOT EXISTS {staging} ({});\n",
        columns
            .iter()
            .map(|c| format!("{} VARCHAR", q(c)))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    for c in columns {
        s.push_str(&format!(
            "ALTER TABLE {staging} ADD COLUMN IF NOT EXISTS {} VARCHAR;\n",
            q(c)
        ));
    }
    s.push_str(&format!(
        "COPY INTO {staging} FROM @{stage}/warehouse/{entity}/ PATTERN = '.*[.]parquet' \
         FILE_FORMAT = (TYPE = PARQUET) MATCH_BY_COLUMN_NAME = CASE_SENSITIVE;\n"
    ));
    let updates = target
        .iter()
        .filter(|c| **c != "id")
        .map(|c| format!("t.{0} = s.{0}", q(c)))
        .collect::<Vec<_>>()
        .join(", ");
    let insert_cols = target.iter().map(|c| q(c)).collect::<Vec<_>>().join(", ");
    let insert_vals = target
        .iter()
        .map(|c| format!("s.{}", q(c)))
        .collect::<Vec<_>>()
        .join(", ");
    s.push_str(&format!(
        "MERGE INTO {table} AS t USING (SELECT * FROM {staging} \
         QUALIFY ROW_NUMBER() OVER (PARTITION BY \"id\" ORDER BY \"_event_id\" DESC) = 1) AS s \
         ON t.\"id\" = s.\"id\" \
         WHEN MATCHED AND s.\"_op\" = 'delete' AND s.\"_event_id\" >= t.\"_event_id\" THEN DELETE \
         WHEN MATCHED AND s.\"_op\" = 'upsert' AND s.\"_event_id\" > t.\"_event_id\" THEN UPDATE SET {updates} \
         WHEN NOT MATCHED AND s.\"_op\" = 'upsert' THEN INSERT ({insert_cols}) VALUES ({insert_vals});\n"
    ));
    s.push_str(&format!("TRUNCATE TABLE {staging};\n"));
    Ok(s)
}

/// The BigQuery load script for `entity` with the export's `columns`,
/// reading `{bucket}/warehouse/{entity}/*` into `` `{dataset}.{entity}` ``.
/// Pure.
pub fn bigquery_script(
    entity: &str,
    columns: &[String],
    dataset: &str,
    bucket: &str,
) -> Result<String, AppError> {
    check_columns(entity, columns)?;
    if !is_safe_dataset(dataset) {
        return Err(AppError::Validation(
            "dataset is not a BigQuery dataset name".into(),
        ));
    }
    if !is_safe_bucket(bucket) {
        return Err(AppError::Validation("bucket is not a gs:// URI".into()));
    }
    let bucket = bucket.trim_end_matches('/');
    let t = |suffix: &str| format!("`{dataset}.{entity}{suffix}`");
    let (table, files, loaded) = (t(""), t("__files"), t("__loaded"));
    let target = target_columns(columns);
    let mut s = String::new();
    s.push_str(&format!(
        "DECLARE upto STRING DEFAULT NULL;\nDECLARE since STRING DEFAULT NULL;\n\
         CREATE TABLE IF NOT EXISTS {table} ({});\n",
        target
            .iter()
            .map(|c| if *c == "id" {
                "id STRING NOT NULL".to_owned()
            } else {
                format!("{c} STRING")
            })
            .collect::<Vec<_>>()
            .join(", ")
    ));
    for c in target.iter().filter(|c| **c != "id") {
        s.push_str(&format!(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {c} STRING;\n"
        ));
    }
    s.push_str(&format!(
        "CREATE TABLE IF NOT EXISTS {loaded} (last_event_id STRING);\n\
         CREATE OR REPLACE EXTERNAL TABLE {files} OPTIONS (format = 'PARQUET', \
         uris = ['{bucket}/warehouse/{entity}/*']);\n\
         SET since = (SELECT IFNULL(MAX(last_event_id), '') FROM {loaded});\n\
         SET upto = (SELECT MAX(_event_id) FROM {files} WHERE _event_id > since);\n"
    ));
    let updates = target
        .iter()
        .filter(|c| **c != "id")
        .map(|c| format!("{c} = s.{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let insert_cols = target.join(", ");
    let insert_vals = target
        .iter()
        .map(|c| format!("s.{c}"))
        .collect::<Vec<_>>()
        .join(", ");
    let selected = columns.join(", ");
    s.push_str(&format!(
        "IF upto IS NOT NULL THEN\n\
         MERGE {table} t USING (SELECT * EXCEPT (rn) FROM (SELECT {selected}, \
         ROW_NUMBER() OVER (PARTITION BY id ORDER BY _event_id DESC) AS rn FROM {files} \
         WHERE _event_id > since AND _event_id <= upto) WHERE rn = 1) s \
         ON t.id = s.id \
         WHEN MATCHED AND s._op = 'delete' AND s._event_id >= t._event_id THEN DELETE \
         WHEN MATCHED AND s._op = 'upsert' AND s._event_id > t._event_id THEN UPDATE SET {updates} \
         WHEN NOT MATCHED AND s._op = 'upsert' THEN INSERT ({insert_cols}) VALUES ({insert_vals});\n\
         INSERT INTO {loaded} (last_event_id) VALUES (upto);\n\
         END IF;\n"
    ));
    Ok(s)
}

/// The warehouse a script is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Warehouse {
    Snowflake,
    Bigquery,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LoadScriptQuery {
    /// `snowflake` or `bigquery`.
    pub warehouse: Warehouse,
    /// Snowflake: the external stage over the export's bucket.
    #[serde(default)]
    pub stage: Option<String>,
    /// BigQuery: the dataset (`project.dataset` or `dataset`).
    #[serde(default)]
    pub dataset: Option<String>,
    /// BigQuery: the bucket the export writes to, `gs://bucket[/prefix]`.
    #[serde(default)]
    pub bucket: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WarehouseLoadScript {
    pub entity: String,
    /// The export's schema version the script was written for.
    pub schema_version: String,
    pub columns: Vec<String>,
    pub script: String,
}

/// The entity's export columns: the newest file's, else what the export
/// would write now.
async fn columns_for(state: &EngineState, entity: &str) -> Result<Vec<String>, AppError> {
    let stored: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT columns FROM warehouse_export_file WHERE entity_logicalname = $1 \
          ORDER BY hour DESC, created_at DESC LIMIT 1",
    )
    .bind(entity)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if let Some(columns) = stored.and_then(|v| serde_json::from_value::<Vec<String>>(v).ok()) {
        return Ok(columns);
    }
    let registry = state.entities.load();
    let meta = registry.get(entity).ok_or(AppError::NotFound)?;
    Ok(crate::warehouse_export::columns_of(&meta.attrs))
}

/// Warehouse load script
///
/// P13-T2: the script that loads one entity's warehouse export into
/// Snowflake or BigQuery, to schedule on the warehouse side (a Snowflake
/// task, a BigQuery scheduled query). It stages the new files, keeps each
/// record's newest change and merges by `id`, deleting tombstones.
/// Administrators only; Attome holds no warehouse credentials.
#[utoipa::path(
    get,
    path = "/api/v1/admin/integrations/warehouse/{entity}/load-script",
    tag = "admin",
    params(
        ("entity" = String, Path, description = "The exported entity"),
        LoadScriptQuery,
    ),
    responses(
        (status = 200, description = "The load script", body = WarehouseLoadScript),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "A missing or unusable stage, dataset or bucket", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_load_script(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Integrations>>,
    Path(entity): Path<String>,
    Query(query): Query<LoadScriptQuery>,
) -> Result<Json<WarehouseLoadScript>, AppError> {
    if !is_safe_name(&entity) {
        return Err(AppError::NotFound);
    }
    let columns = columns_for(&state, &entity).await?;
    let need = |v: &Option<String>, what: &str| {
        v.clone()
            .ok_or_else(|| AppError::Validation(format!("{what} is required for this warehouse")))
    };
    let script = match query.warehouse {
        Warehouse::Snowflake => snowflake_script(&entity, &columns, &need(&query.stage, "stage")?)?,
        Warehouse::Bigquery => bigquery_script(
            &entity,
            &columns,
            &need(&query.dataset, "dataset")?,
            &need(&query.bucket, "bucket")?,
        )?,
    };
    Ok(Json(WarehouseLoadScript {
        schema_version: crate::warehouse_export::schema_version(&columns),
        entity,
        columns,
        script,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/integrations/warehouse/{entity}/load-script",
        get(get_load_script),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_load_script),
    components(schemas(Warehouse, WarehouseLoadScript))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cols() -> Vec<String> {
        [
            "_op",
            "_event_id",
            "_changed_at",
            "id",
            "row_version",
            "title",
            "amount",
        ]
        .iter()
        .map(|c| (*c).to_owned())
        .collect()
    }

    #[test]
    fn warehouse_load_snowflake_stages_and_merges_by_id() {
        let s = snowflake_script("account", &cols(), "ANALYTICS.RAW.ATTOME_STAGE").unwrap();
        assert!(s.contains("COPY INTO \"account__stage\" FROM @ANALYTICS.RAW.ATTOME_STAGE/warehouse/account/ PATTERN = '.*[.]parquet'"), "{s}");
        assert!(s.contains("MERGE INTO \"account\" AS t"));
        assert!(s.contains("WHEN MATCHED AND s.\"_op\" = 'delete' AND s.\"_event_id\" >= t.\"_event_id\" THEN DELETE"));
        assert!(s.contains("ADD COLUMN IF NOT EXISTS \"amount\" VARCHAR"));
        assert!(s.contains("TRUNCATE TABLE \"account__stage\""));
        // `_op` stays in the stage table.
        assert!(!s.contains("CREATE TABLE IF NOT EXISTS \"account\" (\"_op\""));
        let created = s.lines().next().unwrap();
        assert!(!created.contains("\"_op\""), "{created}");
    }

    #[test]
    fn warehouse_load_bigquery_merges_changes_after_the_last_load() {
        let s = bigquery_script("account", &cols(), "proj.attome", "gs://acme-attome/").unwrap();
        assert!(s.starts_with("DECLARE upto STRING DEFAULT NULL;"), "{s}");
        assert!(s.contains("uris = ['gs://acme-attome/warehouse/account/*']"));
        assert!(s.contains("MERGE `proj.attome.account` t"));
        assert!(s.contains("WHERE _event_id > since AND _event_id <= upto"));
        assert!(
            s.contains("INSERT INTO `proj.attome.account__loaded` (last_event_id) VALUES (upto);")
        );
        assert!(s.contains("id STRING NOT NULL"));
    }

    #[test]
    fn warehouse_load_refuses_unsafe_names() {
        let mut bad = cols();
        bad.push("x\"; DROP TABLE y; --".to_owned());
        assert!(snowflake_script("account", &bad, "STAGE").is_err());
        assert!(snowflake_script("account", &cols(), "STAGE; DROP").is_err());
        assert!(bigquery_script("account", &cols(), "a.b.c", "gs://b").is_err());
        assert!(bigquery_script("account", &cols(), "ds", "s3://b").is_err());
        assert!(bigquery_script("account", &cols(), "ds", "gs://b'x").is_err());
        assert!(!is_safe_name("Account"));
        assert!(is_safe_name("_op"));
        let no_id: Vec<String> = vec!["_op".into(), "title".into()];
        assert!(snowflake_script("account", &no_id, "STAGE").is_err());
    }
}
