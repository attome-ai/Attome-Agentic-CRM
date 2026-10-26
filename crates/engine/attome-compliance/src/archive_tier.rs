//! The Parquet archive tier (roadmap L11-T1): many archived records of one
//! entity and month in one Parquet file, with an index of which file holds
//! each record, and restore of any one of them.
//!
//! [`archive_period`] takes soft-deleted records of one entity (the same
//! eligibility as the per-record archive in [`crate::archive`]: inactive,
//! not under a legal hold), writes their full rows to
//! `archive-tier/{entity}/{yyyy}/{mm}/{file}.parquet` (two columns, `id` and
//! `record`, the row's exact JSON, so a restore puts back exactly what was
//! there), copies their attachments under `archive/`, then in one
//! transaction records the file (`archive_tier_file`), scrubs each live row
//! the way the per-record archive does and indexes it (`archive_tier_record`)
//! with its audit event. A record that could not be scrubbed (a hold placed
//! in between, another archive running) is left live and unindexed; its copy
//! in the file is never restored.
//!
//! [`restore`] reads the record's file back, checks its checksum, copies its
//! attachments back and restores the row through
//! `attome_metadata::purge::restore_record`, the platform's restore path for
//! a scrubbed row.

use std::sync::Arc;

use arrow_array::Array;
use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::{EngineState, quote_ident};
use attome_types::AppError;
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::archive::{archived_key, copy_attachments};

/// Most records in one file.
pub const MAX_RECORDS_PER_FILE: usize = 10_000;
/// The file format version in the Parquet metadata.
pub const FORMAT_VERSION: &str = "1";

/// The first day of `at`'s month. Pure.
pub fn month_of(at: DateTime<Utc>) -> NaiveDate {
    at.date_naive()
        .with_day(1)
        .unwrap_or_else(|| at.date_naive())
}

/// The object key of a file. Pure.
pub fn object_key(entity: &str, period: NaiveDate, file: Uuid) -> String {
    format!(
        "archive-tier/{entity}/{:04}/{:02}/{file}.parquet",
        period.year(),
        period.month()
    )
}

/// One file's bytes: an `id` column and a `record` column holding each
/// row's exact JSON. Pure.
pub fn write_parquet(rows: &[(Uuid, Value)]) -> Result<Vec<u8>, AppError> {
    let schema = Arc::new(arrow_schema::Schema::new(vec![
        arrow_schema::Field::new("id", arrow_schema::DataType::Utf8, false),
        arrow_schema::Field::new("record", arrow_schema::DataType::Utf8, false),
    ]));
    let mut ids = arrow_array::builder::StringBuilder::with_capacity(rows.len(), rows.len() * 36);
    let mut records =
        arrow_array::builder::StringBuilder::with_capacity(rows.len(), rows.len() * 256);
    for (id, record) in rows {
        ids.append_value(id.to_string());
        records.append_value(record.to_string());
    }
    let batch = arrow_array::RecordBatch::try_new(
        schema,
        vec![
            Arc::new(ids.finish()) as arrow_array::ArrayRef,
            Arc::new(records.finish()) as arrow_array::ArrayRef,
        ],
    )
    .map_err(AppError::internal)?;
    let props = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::SNAPPY)
        .set_key_value_metadata(Some(vec![parquet::file::metadata::KeyValue::new(
            "attome.archive_tier.version".to_owned(),
            FORMAT_VERSION.to_owned(),
        )]))
        .build();
    let mut writer = parquet::arrow::ArrowWriter::try_new(Vec::new(), batch.schema(), Some(props))
        .map_err(AppError::internal)?;
    writer.write(&batch).map_err(AppError::internal)?;
    writer.into_inner().map_err(AppError::internal)
}

/// The rows of a file [`write_parquet`] wrote. Pure.
pub fn read_parquet(bytes: bytes::Bytes) -> Result<Vec<(Uuid, Value)>, AppError> {
    let reader = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(bytes)
        .map_err(AppError::internal)?
        .build()
        .map_err(AppError::internal)?;
    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.map_err(AppError::internal)?;
        let column = |name: &str| {
            batch
                .column_by_name(name)
                .and_then(|c| c.as_any().downcast_ref::<arrow_array::StringArray>())
                .ok_or_else(|| AppError::internal(format!("archive file has no {name} column")))
        };
        let (ids, records) = (column("id")?, column("record")?);
        for i in 0..batch.num_rows() {
            if ids.is_null(i) || records.is_null(i) {
                return Err(AppError::internal("archive file has an empty cell"));
            }
            let id = Uuid::parse_str(ids.value(i)).map_err(AppError::internal)?;
            let record: Value =
                serde_json::from_str(records.value(i)).map_err(AppError::internal)?;
            out.push((id, record));
        }
    }
    Ok(out)
}

/// What [`archive_period`] did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TierOutcome {
    /// The file, when anything was archived.
    pub file_id: Option<Uuid>,
    pub archived: Vec<Uuid>,
    /// Not archived: not soft-deleted, held, already archived or busy.
    pub skipped: Vec<Uuid>,
}

fn audit_service(state: &EngineState) -> AuditService<'_> {
    AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone())
}

fn audit_event(
    entity: &str,
    record_id: Uuid,
    operation: AuditOperation,
    name: &str,
    comment: String,
    user_context: attome_audit::AuditUserContext,
    organization_ref: Uuid,
) -> AuditEvent {
    AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some(entity.to_owned()),
        record_id: Some(record_id),
        operation,
        version_before: None,
        version_after: None,
        user_context,
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(name.to_owned()),
        event_comment: Some(comment),
        changed_fields: vec![],
        snapshot_json: None,
    }
}

/// Archives the soft-deleted records `ids` of `entity` into one file for
/// `period` (a month), as `actor`.
pub async fn archive_period(
    state: &EngineState,
    entity: &str,
    period: NaiveDate,
    ids: &[Uuid],
    actor: Uuid,
) -> Result<TierOutcome, AppError> {
    if ids.len() > MAX_RECORDS_PER_FILE {
        return Err(AppError::Validation(format!(
            "at most {MAX_RECORDS_PER_FILE} records go in one archive file"
        )));
    }
    if state.engine_owned_entities.contains(entity) {
        return Err(AppError::Validation(format!(
            "{entity} records are managed by their owning engine"
        )));
    }
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .ok_or(AppError::NotFound)?;
    let db = &state.base.db;
    let period = period.with_day(1).unwrap_or(period);

    let table = quote_ident(entity);
    let rows: Vec<(Uuid, Value)> = sqlx::query_as(&format!(
        "SELECT t.id, to_jsonb(t) FROM {table} t \
          WHERE t.id = ANY($1) AND t.is_active = false \
            AND NOT EXISTS (SELECT 1 FROM archive_tier_record r \
                             WHERE r.entity_logicalname = $2 AND r.record_id = t.id \
                               AND r.restored_at IS NULL)"
    ))
    .bind(ids)
    .bind(entity)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut held = 0usize;
    let mut eligible = Vec::with_capacity(rows.len());
    for (id, row) in rows {
        if attome_core::legal_hold::record_is_held(db, entity, id)
            .await?
            .is_some()
        {
            held += 1;
        } else {
            eligible.push((id, row));
        }
    }
    let mut skipped: Vec<Uuid> = ids
        .iter()
        .copied()
        .filter(|id| !eligible.iter().any(|(e, _)| e == id))
        .collect();
    if eligible.is_empty() {
        return Ok(TierOutcome {
            file_id: None,
            archived: Vec::new(),
            skipped,
        });
    }

    // Object-store work first, outside the transaction (guidelines §4).
    let bytes = write_parquet(&eligible)?;
    let checksum = hex::encode(Sha256::digest(&bytes));
    let file_id = Uuid::now_v7();
    let key = object_key(entity, period, file_id);
    let path = ObjectPath::parse(&key).map_err(AppError::internal)?;
    let store = state.base.storage.store();
    store
        .put(&path, bytes.into())
        .await
        .map_err(AppError::internal)?;
    for (id, row) in &eligible {
        copy_attachments(
            store,
            &attrs,
            row,
            entity,
            *id,
            |k| k.to_owned(),
            archived_key,
        )
        .await?;
    }

    let (user_context, organization_ref) = attome_audit::fetch_audit_ctx(state, actor).await;
    let audit = audit_service(state);
    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(
        "INSERT INTO archive_tier_file \
            (id, entity_logicalname, period, object_key, checksum, record_count, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(file_id)
    .bind(entity)
    .bind(period)
    .bind(&key)
    .bind(&checksum)
    .bind(i32::try_from(eligible.len()).map_err(AppError::internal)?)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut archived = Vec::with_capacity(eligible.len());
    for (id, _) in &eligible {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-compliance/archive-restore:{id}"))
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !locked
            || !attome_metadata::purge::scrub_record(&mut tx, entity, &attrs, *id, actor).await?
        {
            skipped.push(*id);
            continue;
        }
        sqlx::query(
            "INSERT INTO archive_tier_record (entity_logicalname, record_id, file_ref, archived_by) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (entity_logicalname, record_id) DO UPDATE \
               SET file_ref = EXCLUDED.file_ref, archived_at = now(), \
                   archived_by = EXCLUDED.archived_by, restored_at = NULL, restored_by = NULL",
        )
        .bind(entity)
        .bind(id)
        .bind(file_id)
        .bind(actor)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        audit
            .write_in_tx(
                &mut tx,
                audit_event(
                    entity,
                    *id,
                    AuditOperation::Export,
                    "archive_tier",
                    format!("L11-T1: archived {entity}/{id} to {key} (sha256={checksum}), then scrubbed the live row"),
                    user_context.clone(),
                    organization_ref,
                ),
            )
            .await?;
        archived.push(*id);
    }
    attome_db::tx::commit(tx).await?;
    skipped.sort();
    tracing::info!(entity, %file_id, archived = archived.len(), held, "archive tier: file written");
    Ok(TierOutcome {
        file_id: Some(file_id),
        archived,
        skipped,
    })
}

/// Restores record `record_id` of `entity` from its archive file, as
/// `actor`.
pub async fn restore(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    actor: Uuid,
) -> Result<(), AppError> {
    let db = &state.base.db;
    let found: Option<(String, String)> = sqlx::query_as(
        "SELECT f.object_key, f.checksum FROM archive_tier_record r \
           JOIN archive_tier_file f ON f.id = r.file_ref \
          WHERE r.entity_logicalname = $1 AND r.record_id = $2 AND r.restored_at IS NULL",
    )
    .bind(entity)
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (key, checksum) = found.ok_or(AppError::NotFound)?;
    let attrs = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.clone())
        .ok_or(AppError::NotFound)?;

    let store = state.base.storage.store();
    let path = ObjectPath::parse(&key).map_err(AppError::internal)?;
    let bytes = store
        .get(&path)
        .await
        .map_err(AppError::internal)?
        .bytes()
        .await
        .map_err(AppError::internal)?;
    if hex::encode(Sha256::digest(&bytes)) != checksum {
        return Err(AppError::internal(format!(
            "archive file checksum mismatch for {key}; refusing to restore possibly corrupted data"
        )));
    }
    let original = read_parquet(bytes)?
        .into_iter()
        .find(|(id, _)| *id == record_id)
        .map(|(_, row)| row)
        .ok_or_else(|| AppError::internal(format!("{key} does not hold {record_id}")))?;
    copy_attachments(
        store,
        &attrs,
        &original,
        entity,
        record_id,
        archived_key,
        |k| k.to_owned(),
    )
    .await?;

    let (user_context, organization_ref) = attome_audit::fetch_audit_ctx(state, actor).await;
    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-compliance/archive-restore:{record_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another archive/restore operation for this record is already in progress",
        ));
    }
    if !attome_metadata::purge::restore_record(&mut tx, entity, &attrs, record_id, actor, &original)
        .await?
    {
        return Err(AppError::Conflict(
            "record could not be restored: it is no longer in the archived state",
        ));
    }
    sqlx::query(
        "UPDATE archive_tier_record SET restored_at = now(), restored_by = $3 \
          WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(record_id)
    .bind(actor)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    audit_service(state)
        .write_in_tx(
            &mut tx,
            audit_event(
                entity,
                record_id,
                AuditOperation::Update,
                "archive_tier_restored",
                format!("L11-T1: restored {entity}/{record_id} from {key}"),
                user_context,
                organization_ref,
            ),
        )
        .await?;
    attome_db::tx::commit(tx).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn archive_parquet_round_trips_rows_exactly() {
        let rows = vec![
            (
                Uuid::now_v7(),
                json!({"id": "a", "name": "شركة الأمل", "amount": 1234.5, "count": 7,
                       "flag": true, "missing": null, "tags": ["x", "y"],
                       "nested": {"k": [1, 2]}}),
            ),
            (
                Uuid::now_v7(),
                json!({"id": "b", "note": "quote \" and \\ slash"}),
            ),
        ];
        let bytes = write_parquet(&rows).unwrap();
        let back = read_parquet(bytes::Bytes::from(bytes)).unwrap();
        assert_eq!(back, rows);
    }

    #[test]
    fn archive_parquet_files_are_named_by_entity_and_month() {
        let at = DateTime::parse_from_rfc3339("2026-10-26T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let period = month_of(at);
        assert_eq!(period, NaiveDate::from_ymd_opt(2026, 10, 1).unwrap());
        assert_eq!(
            object_key("account", period, Uuid::nil()),
            "archive-tier/account/2026/10/00000000-0000-0000-0000-000000000000.parquet"
        );
    }
}
