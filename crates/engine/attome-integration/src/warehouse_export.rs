//! P13-T1: an incremental export of record changes to Parquet files, for a
//! data warehouse to load.
//!
//! The deployment names the entities to export in the setting
//! `integration.warehouse_entities` (none by default: the export is off).
//! Every few minutes the job [`run`] reads the change feed after its own
//! cursor ([`CONSUMER`]), keeps the events of those entities, and writes one
//! Parquet file per entity and hour of change:
//! `warehouse/{entity}/{yyyy}/{mm}/{dd}/{HH}/{first}-{last}.parquet`, named
//! by the first and last event it holds, so a run repeated after a crash
//! writes the same object again rather than a second copy.
//!
//! Each file has the columns `_op` (`upsert` or `delete`), `_event_id`,
//! `_changed_at`, `id`, `row_version` and the entity's attributes, every
//! value as text. A record changed several times in one file appears once,
//! as it is now; a record deleted (or no longer live) is a tombstone with
//! only `_op`, `_event_id`, `_changed_at` and `id`. Sensitive attributes are
//! never exported. Each file carries a `schema_version` (a hash of its
//! column list), so a loader sees when the entity's columns changed.
//!
//! The manifest is the table `warehouse_export_file` (one row per file:
//! entity, hour, schema version, columns, row and tombstone counts, event
//! range, checksum) and its copy `warehouse/{entity}/manifest.json`,
//! rewritten after every run that wrote a file for the entity. The cursor
//! moves in the same transaction as the manifest rows, after the files are
//! stored: a crash between the two re-exports the same events to the same
//! object keys.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_types::AppError;
use chrono::{DateTime, Timelike, Utc};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The change-feed consumer.
pub const CONSUMER: &str = "attome-integration/warehouse-export";

/// The registered job that runs one export.
pub const JOB: &str = "warehouse_export";

/// The setting naming the exported entities.
pub const SETTING: &str = "integration.warehouse_entities";

/// Events read per run.
pub const BATCH: i64 = 5_000;

/// One kept change: the latest event of a record within one file.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub record_id: Uuid,
    pub event_id: Uuid,
    pub changed_at: DateTime<Utc>,
    pub deleted: bool,
}

/// The hour a change belongs to. Pure.
pub fn hour_of(at: DateTime<Utc>) -> DateTime<Utc> {
    at.with_minute(0)
        .and_then(|t| t.with_second(0))
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(at)
}

/// The events of one entity grouped by hour, one change per record (its
/// last event). Pure.
pub fn group_by_hour(events: &[Change]) -> BTreeMap<DateTime<Utc>, Vec<Change>> {
    let mut out: BTreeMap<DateTime<Utc>, Vec<Change>> = BTreeMap::new();
    for event in events {
        let group = out.entry(hour_of(event.changed_at)).or_default();
        match group.iter_mut().find(|c| c.record_id == event.record_id) {
            Some(existing) => *existing = event.clone(),
            None => group.push(event.clone()),
        }
    }
    out
}

/// A file's object key. Pure.
pub fn object_key(entity: &str, hour: DateTime<Utc>, first: Uuid, last: Uuid) -> String {
    format!(
        "warehouse/{entity}/{}/{first}-{last}.parquet",
        hour.format("%Y/%m/%d/%H")
    )
}

/// The columns of an entity's files: the control columns, then the
/// attributes it exports. Pure.
pub fn columns_of(attrs: &[AttrInfo]) -> Vec<String> {
    let mut columns: Vec<String> = ["_op", "_event_id", "_changed_at", "id", "row_version"]
        .iter()
        .map(|c| (*c).to_owned())
        .collect();
    for attr in attrs {
        let name = attr.logicalname.as_str();
        if !attr.is_sensitive && !columns.iter().any(|c| c == name) {
            columns.push(name.to_owned());
        }
    }
    columns
}

/// A column list's schema version: 12 hex digits of its hash. Pure.
pub fn schema_version(columns: &[String]) -> String {
    let digest = Sha256::digest(columns.join("\u{1f}").as_bytes());
    hex::encode(&digest[..6])
}

/// One file's rows as Arrow text columns. Pure.
fn record_batch(
    columns: &[String],
    rows: &[Map<String, Value>],
) -> Result<arrow_array::RecordBatch, AppError> {
    let schema = Arc::new(arrow_schema::Schema::new(
        columns
            .iter()
            .map(|c| arrow_schema::Field::new(c.as_str(), arrow_schema::DataType::Utf8, true))
            .collect::<Vec<_>>(),
    ));
    let arrays: Vec<arrow_array::ArrayRef> = columns
        .iter()
        .map(|column| {
            let mut builder =
                arrow_array::builder::StringBuilder::with_capacity(rows.len(), rows.len() * 16);
            for row in rows {
                match row.get(column) {
                    None | Some(Value::Null) => builder.append_null(),
                    Some(Value::String(text)) => builder.append_value(text),
                    Some(other) => builder.append_value(other.to_string()),
                }
            }
            Arc::new(builder.finish()) as arrow_array::ArrayRef
        })
        .collect();
    arrow_array::RecordBatch::try_new(schema, arrays).map_err(AppError::internal)
}

/// One file's bytes. Pure.
pub fn parquet_bytes(
    columns: &[String],
    rows: &[Map<String, Value>],
    schema_version: &str,
) -> Result<Vec<u8>, AppError> {
    let batch = record_batch(columns, rows)?;
    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::SNAPPY)
        .set_key_value_metadata(Some(vec![parquet::file::metadata::KeyValue::new(
            "attome.schema_version".to_owned(),
            schema_version.to_owned(),
        )]))
        .build();
    let mut writer = parquet::arrow::ArrowWriter::try_new(Vec::new(), batch.schema(), Some(props))
        .map_err(AppError::internal)?;
    writer.write(&batch).map_err(AppError::internal)?;
    writer.into_inner().map_err(AppError::internal)
}

/// One change as a file row: the record's current values (its exported
/// columns), or a tombstone. Pure.
pub fn file_row(
    change: &Change,
    current: Option<&Map<String, Value>>,
    columns: &[String],
) -> Map<String, Value> {
    let mut row = Map::new();
    row.insert(
        "_event_id".into(),
        Value::String(change.event_id.to_string()),
    );
    row.insert(
        "_changed_at".into(),
        Value::String(change.changed_at.to_rfc3339()),
    );
    row.insert("id".into(), Value::String(change.record_id.to_string()));
    let live =
        current.filter(|r| !change.deleted && r.get("is_active") != Some(&Value::Bool(false)));
    match live {
        Some(record) => {
            row.insert("_op".into(), Value::String("upsert".into()));
            for column in columns.iter().filter(|c| !c.starts_with('_') && *c != "id") {
                if let Some(value) = record.get(column) {
                    row.insert(column.clone(), value.clone());
                }
            }
        }
        None => {
            row.insert("_op".into(), Value::String("delete".into()));
        }
    }
    row
}

/// The exported entities the setting names.
fn exported_entities(state: &EngineState) -> Vec<String> {
    attome_core::setting_registry()
        .get(SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect()
}

/// One manifest entry.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ManifestEntry {
    pub object_key: String,
    pub hour: DateTime<Utc>,
    pub schema_version: String,
    pub rows: i32,
    pub tombstones: i32,
    pub first_event_id: Uuid,
    pub last_event_id: Uuid,
    pub checksum: String,
}

/// A file written this run, for its manifest row.
struct Written {
    entity: String,
    entry: ManifestEntry,
    columns: Vec<String>,
}

/// Rewrites `warehouse/{entity}/manifest.json` from the manifest table.
async fn write_manifest_copy(state: &EngineState, entity: &str) -> Result<(), AppError> {
    let entries: Vec<ManifestEntry> = sqlx::query_as(
        "SELECT object_key, hour, schema_version, rows, tombstones, first_event_id, \
                last_event_id, checksum \
           FROM warehouse_export_file WHERE entity_logicalname = $1 \
          ORDER BY hour, created_at LIMIT 100000",
    )
    .bind(entity)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "entity": entity,
        "files": entries,
    }))
    .map_err(AppError::internal)?;
    attome_storage::mirror::write_object(
        &state.base.storage,
        &format!("warehouse/{entity}/manifest.json"),
        body,
    )
    .await
    .map_err(AppError::internal)
}

/// One run (see the module doc). Answers how many files it wrote.
pub async fn run(state: &EngineState) -> Result<usize, AppError> {
    let entities = exported_entities(state);
    if entities.is_empty() {
        return Ok(0);
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
    drop(conn);
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };

    let mut by_entity: HashMap<String, Vec<Change>> = HashMap::new();
    for event in &events {
        if !entities.contains(&event.entity_logicalname) || event.event_name.is_some() {
            continue;
        }
        let deleted = matches!(
            event.operation(),
            Some(attome_core::ChangeOperation::Delete | attome_core::ChangeOperation::Purge)
        );
        by_entity
            .entry(event.entity_logicalname.clone())
            .or_default()
            .push(Change {
                record_id: event.record_id,
                event_id: event.id,
                changed_at: event.created_at,
                deleted,
            });
    }

    let mut written: Vec<Written> = Vec::new();
    for (entity, changes) in by_entity {
        let Some(meta) = state.entities.load().get(&entity).cloned() else {
            tracing::warn!(%entity, "warehouse export: the entity is gone; its changes are skipped");
            continue;
        };
        let columns = columns_of(&meta.attrs);
        let version = schema_version(&columns);
        let ids: Vec<Uuid> = changes.iter().map(|c| c.record_id).collect();
        let current: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT row_to_json(t)::text FROM {} t WHERE t.id = ANY($1)",
            quote_ident(&meta.logicalname)
        ))
        .bind(&ids)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let mut rows_by_id: HashMap<Uuid, Map<String, Value>> = HashMap::new();
        for text in current {
            let value: Value = serde_json::from_str(&text).map_err(AppError::internal)?;
            if let Some(map) = value.as_object()
                && let Some(id) = map
                    .get("id")
                    .and_then(Value::as_str)
                    .and_then(|s| Uuid::parse_str(s).ok())
            {
                rows_by_id.insert(id, map.clone());
            }
        }
        for (hour, group) in group_by_hour(&changes) {
            let rows: Vec<Map<String, Value>> = group
                .iter()
                .map(|c| file_row(c, rows_by_id.get(&c.record_id), &columns))
                .collect();
            let tombstones = rows
                .iter()
                .filter(|r| r.get("_op") == Some(&Value::String("delete".into())))
                .count();
            let (Some(first), Some(last_change)) = (group.first(), group.last()) else {
                continue;
            };
            let key = object_key(&entity, hour, first.event_id, last_change.event_id);
            let bytes = parquet_bytes(&columns, &rows, &version)?;
            let checksum = hex::encode(Sha256::digest(&bytes));
            attome_storage::mirror::write_object(&state.base.storage, &key, bytes)
                .await
                .map_err(AppError::internal)?;
            written.push(Written {
                entity: entity.clone(),
                columns: columns.clone(),
                entry: ManifestEntry {
                    object_key: key,
                    hour,
                    schema_version: version.clone(),
                    rows: i32::try_from(rows.len()).unwrap_or(i32::MAX),
                    tombstones: i32::try_from(tombstones).unwrap_or(i32::MAX),
                    first_event_id: first.event_id,
                    last_event_id: last_change.event_id,
                    checksum,
                },
            });
        }
    }

    // The manifest rows and the cursor move together, after the files exist.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    for file in &written {
        sqlx::query(
            "INSERT INTO warehouse_export_file (object_key, entity_logicalname, hour, \
                 schema_version, columns, rows, tombstones, first_event_id, last_event_id, checksum) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (object_key) DO NOTHING",
        )
        .bind(&file.entry.object_key)
        .bind(&file.entity)
        .bind(file.entry.hour)
        .bind(&file.entry.schema_version)
        .bind(serde_json::to_value(&file.columns).map_err(AppError::internal)?)
        .bind(file.entry.rows)
        .bind(file.entry.tombstones)
        .bind(file.entry.first_event_id)
        .bind(file.entry.last_event_id)
        .bind(&file.entry.checksum)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    attome_core::change_feed::advance(&mut tx, CONSUMER, &last).await?;
    attome_db::tx::commit(tx).await?;

    let mut touched: Vec<&str> = written.iter().map(|w| w.entity.as_str()).collect();
    touched.sort_unstable();
    touched.dedup();
    for entity in touched {
        if let Err(error) = write_manifest_copy(state, entity).await {
            tracing::warn!(%entity, %error, "warehouse export: the manifest copy was not rewritten");
        }
    }
    Ok(written.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        text.parse().unwrap()
    }

    fn change(record: Uuid, time: &str, deleted: bool) -> Change {
        Change {
            record_id: record,
            event_id: Uuid::now_v7(),
            changed_at: at(time),
            deleted,
        }
    }

    #[test]
    fn warehouse_export_groups_by_hour_and_keeps_each_records_last_change() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let events = vec![
            change(a, "2026-10-26T08:05:00Z", false),
            change(b, "2026-10-26T08:10:00Z", false),
            change(a, "2026-10-26T08:50:00Z", true),
            change(a, "2026-10-26T09:01:00Z", false),
        ];
        let groups = group_by_hour(&events);
        assert_eq!(groups.len(), 2);
        let eight = &groups[&at("2026-10-26T08:00:00Z")];
        assert_eq!(eight.len(), 2, "one change per record");
        assert!(
            eight.iter().any(|c| c.record_id == a && c.deleted),
            "a's last change in 08:00 wins"
        );
        assert_eq!(groups[&at("2026-10-26T09:00:00Z")].len(), 1);
    }

    #[test]
    fn warehouse_export_rows_carry_values_or_a_tombstone() {
        let id = Uuid::now_v7();
        let columns = vec![
            "_op".into(),
            "_event_id".into(),
            "_changed_at".into(),
            "id".into(),
            "row_version".into(),
            "title".into(),
        ];
        let record: Map<String, Value> = serde_json::from_value(serde_json::json!({
            "id": id.to_string(), "row_version": 3, "title": "Acme", "secret": "x", "is_active": true
        }))
        .unwrap();
        let upsert = file_row(
            &change(id, "2026-10-26T08:00:00Z", false),
            Some(&record),
            &columns,
        );
        assert_eq!(upsert["_op"], "upsert");
        assert_eq!(upsert["title"], "Acme");
        assert!(upsert.get("secret").is_none(), "only exported columns");
        let gone = file_row(
            &change(id, "2026-10-26T08:00:00Z", true),
            Some(&record),
            &columns,
        );
        assert_eq!(gone["_op"], "delete");
        assert!(gone.get("title").is_none());
        let missing = file_row(&change(id, "2026-10-26T08:00:00Z", false), None, &columns);
        assert_eq!(
            missing["_op"], "delete",
            "a record no longer there is a tombstone"
        );
    }

    #[test]
    fn warehouse_export_files_read_back_with_their_schema_version() {
        let columns = vec!["_op".to_owned(), "id".to_owned(), "title".to_owned()];
        let version = schema_version(&columns);
        assert_eq!(version.len(), 12);
        assert_eq!(version, schema_version(&columns), "stable");
        let rows: Vec<Map<String, Value>> = vec![
            serde_json::from_value(
                serde_json::json!({"_op": "upsert", "id": "1", "title": "شركة"}),
            )
            .unwrap(),
            serde_json::from_value(serde_json::json!({"_op": "delete", "id": "2"})).unwrap(),
        ];
        let bytes = parquet_bytes(&columns, &rows, &version).unwrap();
        let builder = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(
            bytes::Bytes::from(bytes),
        )
        .unwrap();
        let kv = builder
            .metadata()
            .file_metadata()
            .key_value_metadata()
            .cloned()
            .unwrap_or_default();
        assert!(
            kv.iter().any(|k| k.key == "attome.schema_version"
                && k.value.as_deref() == Some(version.as_str()))
        );
        let batches: Vec<_> = builder.build().unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(batches.iter().map(|b| b.num_rows()).sum::<usize>(), 2);
        assert_eq!(
            object_key(
                "account",
                at("2026-10-26T08:00:00Z"),
                Uuid::nil(),
                Uuid::nil()
            ),
            format!(
                "warehouse/account/2026/10/26/08/{}-{}.parquet",
                Uuid::nil(),
                Uuid::nil()
            )
        );
    }
}
