//! M23 Records Management (D-456) — the `archive` disposition outcome:
//! export a soft-deleted, past-grace-period entity record (plus any
//! file-field attachments) to `attome-storage` under an `archive/` prefix,
//! keep evidence in `archive_record`, then scrub the live row the
//! same way `entity_purge` does. Dispatched from
//! `retention::execute_action`'s `"archive"` arm — same approval-gated path
//! (`retention_admin::do_approve_retention_action`, D-195 four-eyes) every
//! other disposition already goes through; this module adds no new gate of
//! its own, it reuses that one.
//!
//! Reuses two things verbatim rather than rebuilding them:
//! - `retention::stream_masked_export_to_store` — the exact streamed,
//!   checksummed upload primitive the M12 record-export writer
//!   (`attome_api::data_export`) also reuses for its own `json` (NDJSON)
//!   format. This module's export is a one-line NDJSON stream through the
//!   identical function, unmasked (the four hardcoded partition tables'
//!   `masked_select_expr` doesn't apply to arbitrary business-entity
//!   columns — full fidelity is required for a faithful restore).
//! - `attome_metadata::purge::scrub_record`/`restore_record` — the same
//!   crypto-shred-adjacent field-scrub `entity_purge` uses, and its new
//!   restore counterpart. Both already check the legal-hold table
//!   themselves; this module also checks it up front (before spending the
//!   effort of an export+upload) so a held record fails fast rather than
//!   after a wasted upload.
//!
//! Attachments: a `file`-typed attribute's value is an object-store key
//! (single) or a JSON array of keys (multi, D-362) under
//! `{entity}/{record_id}/{field}/…` (`attome_document::files::final_key`'s
//! shape); a key outside that prefix is skipped, checked with
//! `attome_document::files::is_owned_file_key`, the same check the download
//! path applies (CLEANUP-REVIEW 2.10 retired this module's private copy,
//! which also accepted an empty suffix). Each referenced object is copied (not moved) to `archive/{original key}`, so restore can
//! copy it straight back; a missing object (already cleaned up by the
//! orphan sweep, `attome_document::files_scan.rs`) is logged and skipped, never a
//! hard failure — the record's own data is the thing this disposition must
//! not lose, not a best-effort attachment cache.

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_document::files::is_owned_file_key;
use attome_types::AppError;
use chrono::Utc;
use object_store::{ObjectStore, ObjectStoreExt, path::Path as ObjectPath};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::retention::{parse_entity_target, stream_masked_export_to_store};

/// `attome-metadata/src/provision/identifiers.rs::type_to_int`'s `"file" => 12`.
const FILE_FIELD_TYPE_INT: i32 = 12;

fn is_multi_valued(attr: &AttrInfo) -> bool {
    attr.options
        .as_ref()
        .and_then(|o| o.get("multi"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Every file-field object key `record` (a `row_to_json` value) currently
/// references, paired with the attribute that referenced it.
fn file_keys(attrs: &[AttrInfo], record: &Value) -> Vec<(String, String)> {
    attrs
        .iter()
        // `file` and `image` (U9) both store object keys.
        .filter(|a| a.field_type_int == FILE_FIELD_TYPE_INT || a.is_file_backed())
        .flat_map(|a| {
            let value = record.get(&a.logicalname);
            if is_multi_valued(a) {
                value
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(|k| (a.logicalname.clone(), k.to_string()))
                    .collect::<Vec<_>>()
            } else {
                value
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(|k| vec![(a.logicalname.clone(), k.to_string())])
                    .unwrap_or_default()
            }
        })
        .collect()
}

/// `archive/{key}` — where an attachment `key` (a live-prefix object key,
/// `{entity}/{record_id}/{field}/…`) lands once archived.
pub(crate) fn archived_key(key: &str) -> String {
    format!("archive/{key}")
}

/// Copies every attachment `record` references, from `src_of(key)` to
/// `dest_of(key)` — archive direction is `(key, archived_key(key))`, restore
/// direction is `(archived_key(key), key)`; both pass the *original*
/// (live-prefix) key through [`is_owned_file_key`], since that's the form
/// `file_keys` always returns regardless of direction (the archived JSON
/// record's file-field values are the original live keys, not the archived
/// ones — only the object-store copy's location differs). Best-effort per
/// object — a missing source object is logged and skipped (see this
/// module's top doc comment), any other storage error aborts the whole
/// operation. Returns how many objects were actually copied.
pub(crate) async fn copy_attachments(
    store: &dyn ObjectStore,
    attrs: &[AttrInfo],
    record: &Value,
    entity_logicalname: &str,
    record_id: Uuid,
    src_of: impl Fn(&str) -> String,
    dest_of: impl Fn(&str) -> String,
) -> Result<i64, AppError> {
    let mut copied = 0i64;
    for (field, key) in file_keys(attrs, record) {
        if !is_owned_file_key(entity_logicalname, record_id, &field, &key) {
            tracing::warn!(
                entity = %entity_logicalname, record_id = %record_id, field = %field, key = %key,
                "archive: file key does not match this record's owned prefix, skipping"
            );
            continue;
        }
        let src_key = src_of(&key);
        let dest_key = dest_of(&key);
        let src = ObjectPath::parse(&src_key)
            .map_err(|e| AppError::internal(format!("invalid file key {src_key:?}: {e}")))?;
        let dest = ObjectPath::parse(&dest_key)
            .map_err(|e| AppError::internal(format!("invalid file key {dest_key:?}: {e}")))?;
        match store.copy(&src, &dest).await {
            Ok(()) => copied += 1,
            Err(object_store::Error::NotFound { .. }) => {
                tracing::warn!(
                    key = %src_key,
                    "archive: referenced file object not found in storage, skipping"
                );
            }
            Err(e) => return Err(AppError::internal(e)),
        }
    }
    Ok(copied)
}

#[derive(Serialize)]
struct ArchiveManifest<'a> {
    entity_logicalname: &'a str,
    record_id: Uuid,
    record_ref: &'a str,
    checksum: &'a str,
    attachment_count: i64,
    archived_at: chrono::DateTime<Utc>,
}

/// `retention::execute_action`'s `"archive"` dispatch target — the
/// counterpart to that file's `execute_partition_archive`/
/// `execute_entity_purge`. `target` is `"{logicalname}:{record_id}"`, the
/// same shape `attome_metadata::purge::propose_purge_actions` writes regardless
/// of which disposition was configured. `retention_action_id` is recorded on
/// the evidence row so an operator can trace an archive back to the
/// approved action that triggered it; `approved_by` (falling back to
/// `Uuid::nil()` for the same defensive reason `execute_entity_purge` does)
/// is who the export/scrub/audit event are attributed to.
pub async fn execute_entity_archive(
    state: &EngineState,
    target: &str,
    retention_action_id: Uuid,
    approved_by: Option<Uuid>,
) -> Result<Option<String>, AppError> {
    let db = &state.base.db;
    let (entity_logicalname, record_id) = parse_entity_target(target)?;
    let archived_by = approved_by.unwrap_or(Uuid::nil());

    // Fail fast: scrub_record re-checks this itself (defense in depth), but
    // this avoids a wasted export+upload when a hold already blocks it.
    if attome_core::legal_hold::record_is_held(db, entity_logicalname, record_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "record is under an active legal hold — archive refused (P-data-protection-governance)",
        ));
    }

    let registry = state.entities.load();
    let meta = registry.get(entity_logicalname).ok_or_else(|| {
        AppError::internal(format!(
            "retention execute: entity {entity_logicalname} is no longer registered"
        ))
    })?;
    let attrs = meta.attrs.clone();

    let table = quote_ident(entity_logicalname);
    let sql =
        format!("SELECT row_to_json(t)::text FROM {table} t WHERE id = $1 AND is_active = false");
    let row_line: Option<String> = sqlx::query_scalar(&sql)
        .bind(record_id)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
    let Some(row_line) = row_line else {
        return Err(AppError::internal(format!(
            "retention execute: {target} is no longer a soft-deleted record — nothing to archive"
        )));
    };
    let record_value: Value = serde_json::from_str(&row_line).map_err(AppError::internal)?;

    let record_key = format!("archive/{entity_logicalname}/{record_id}/record.ndjson");
    let record_path = ObjectPath::parse(&record_key)
        .map_err(|e| AppError::internal(format!("invalid archive object key: {e}")))?;
    let rows = futures_util::stream::iter(vec![Ok::<_, sqlx::Error>(row_line)]);
    let (_lines, checksum) =
        stream_masked_export_to_store(rows, state.base.storage.store_arc(), record_path).await?;

    let store = state.base.storage.store();
    let attachment_count = copy_attachments(
        store,
        &attrs,
        &record_value,
        entity_logicalname,
        record_id,
        |key| key.to_string(),
        archived_key,
    )
    .await?;

    let manifest = ArchiveManifest {
        entity_logicalname,
        record_id,
        record_ref: &record_key,
        checksum: &checksum,
        attachment_count,
        archived_at: Utc::now(),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(AppError::internal)?;
    let manifest_key = format!("archive/{entity_logicalname}/{record_id}/manifest.json");
    let manifest_path = ObjectPath::parse(&manifest_key)
        .map_err(|e| AppError::internal(format!("invalid manifest key: {e}")))?;
    store
        .put(&manifest_path, manifest_bytes.into())
        .await
        .map_err(AppError::internal)?;

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

    // Re-checks legal_hold itself (the row could have been held between the
    // upfront check above and here) and refuses if the row is no longer
    // `is_active = false` (independently restored in the meantime).
    let scrubbed = attome_metadata::purge::scrub_record(
        &mut tx,
        entity_logicalname,
        &attrs,
        record_id,
        archived_by,
    )
    .await?;
    if !scrubbed {
        return Err(AppError::Conflict(
            "record could not be scrubbed after export (a legal hold was placed, or the record \
             is no longer eligible) — the archive export was already written to object storage \
             but no archive_record row was created; safe to retry",
        ));
    }

    sqlx::query(
        "INSERT INTO archive_record \
            (entity_logicalname, record_id, archive_ref, manifest_ref, checksum, \
             attachment_count, retention_action_ref, archived_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .bind(&record_key)
    .bind(&manifest_key)
    .bind(&checksum)
    .bind(attachment_count)
    .bind(retention_action_id)
    .bind(archived_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // D-062 / audit plan 3.6: the scrub, the evidence row, and the audit
    // event commit together — a failed audit write rolls the scrub back, so
    // the record stays soft-deleted (still eligible) and a retry re-runs the
    // whole disposition instead of leaving a scrubbed row with no evidence.
    let (user_ctx, organization_ref) = attome_audit::fetch_audit_ctx(state, archived_by).await;
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some(entity_logicalname.to_string()),
        record_id: Some(record_id),
        operation: AuditOperation::Export,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("retention_archive".to_string()),
        event_comment: Some(format!(
            "M23: archived {entity_logicalname}/{record_id} to {record_key} \
             (sha256={checksum}, attachments={attachment_count}), then scrubbed the live row"
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };
    audit_service.write_in_tx(&mut tx, event).await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(Some(format!(
        "{record_key} (sha256={checksum}, attachments={attachment_count})"
    )))
}

/// `archive_admin::restore`'s engine call — re-reads `archive_record`
/// (never trusting anything the caller supplied beyond its id), re-fetches
/// and re-verifies the archived NDJSON's checksum before touching the
/// database (never restore possibly-corrupted bytes), copies attachments
/// back, then [`attome_metadata::purge::restore_record`]s the row and writes the
/// audit event in one transaction. Does not itself check legal hold — see `restore_record`'s own doc
/// comment for why a hold only ever blocks *removing* evidence, never
/// restoring it.
pub async fn restore_archived_record(
    state: &EngineState,
    archive_record_id: Uuid,
    restored_by: Uuid,
) -> Result<(), AppError> {
    let db = &state.base.db;

    #[derive(sqlx::FromRow)]
    struct ArchiveRow {
        entity_logicalname: String,
        record_id: Uuid,
        archive_ref: String,
        checksum: String,
        restored_at: Option<chrono::DateTime<Utc>>,
    }
    let row: Option<ArchiveRow> = sqlx::query_as(
        "SELECT entity_logicalname, record_id, archive_ref, checksum, restored_at \
           FROM archive_record WHERE id = $1 AND is_deleted = false",
    )
    .bind(archive_record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;
    if row.restored_at.is_some() {
        return Err(AppError::Conflict(
            "this archived record has already been restored",
        ));
    }

    let store = state.base.storage.store();
    let path = ObjectPath::parse(&row.archive_ref)
        .map_err(|e| AppError::internal(format!("invalid archive_ref: {e}")))?;
    let get_result = store.get(&path).await.map_err(AppError::internal)?;
    let bytes = get_result.bytes().await.map_err(AppError::internal)?;
    let actual_checksum = hex::encode(Sha256::digest(bytes.as_ref()));
    if actual_checksum != row.checksum {
        return Err(AppError::internal(format!(
            "archive checksum mismatch for {} — refusing to restore possibly-corrupted data",
            row.archive_ref
        )));
    }
    let line = std::str::from_utf8(&bytes)
        .map_err(AppError::internal)?
        .trim_end_matches('\n');
    let record_value: Value = serde_json::from_str(line).map_err(AppError::internal)?;

    // D-535: an engine-owned entity's rows (an API key) are never brought back
    // to life generically; the holder creates a new one through its own route.
    if state
        .engine_owned_entities
        .contains(row.entity_logicalname.as_str())
    {
        return Err(AppError::Validation(format!(
            "{} records are managed by their owning engine; use its routes",
            row.entity_logicalname
        )));
    }

    let registry = state.entities.load();
    let meta = registry.get(&row.entity_logicalname).ok_or_else(|| {
        AppError::internal(format!(
            "restore: entity {} is no longer registered",
            row.entity_logicalname
        ))
    })?;
    let attrs = meta.attrs.clone();

    // Object-store I/O runs before the transaction opens (guidelines §4: no
    // external I/O inside a transaction). Copying `archive/{key}` back to
    // `{key}` is idempotent, so a restore that then fails below (lock miss,
    // row no longer scrubbed, audit write failure) at worst leaves live-prefix
    // copies no row references, which the orphan sweep
    // (`attome_document::files_scan`) removes — the same residue a failed commit
    // could already leave when this copy ran inside the transaction.
    copy_attachments(
        store,
        &attrs,
        &record_value,
        &row.entity_logicalname,
        row.record_id,
        archived_key,
        |key| key.to_string(),
    )
    .await
    .map_err(AppError::internal)?;

    let (user_ctx, organization_ref) = attome_audit::fetch_audit_ctx(state, restored_by).await;

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!(
            "attome-compliance/archive-restore:{}",
            row.record_id
        ))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "another archive/restore operation for this record is already in progress",
        ));
    }

    let restored = attome_metadata::purge::restore_record(
        &mut tx,
        &row.entity_logicalname,
        &attrs,
        row.record_id,
        restored_by,
        &record_value,
    )
    .await?;
    if !restored {
        return Err(AppError::Conflict(
            "record could not be restored — it is no longer in the scrubbed/inactive state this \
             archive expects (already restored or independently modified)",
        ));
    }

    sqlx::query(
        "UPDATE archive_record \
            SET restored_at = NOW(), restored_by = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(archive_record_id)
    .bind(restored_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // D-062 / audit plan 3.6: restore, `restored_at`, and the audit event
    // commit together; a failed audit write leaves the record scrubbed and
    // `restored_at` NULL, so the same restore call can simply be retried.
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some(row.entity_logicalname.clone()),
        record_id: Some(row.record_id),
        operation: AuditOperation::Restore,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some("retention_archive_restore".to_string()),
        event_comment: Some(format!(
            "M23: restored {}/{} from {}",
            row.entity_logicalname, row.record_id, row.archive_ref
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };
    audit_service.write_in_tx(&mut tx, event).await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(logicalname: &str, field_type_int: i32, options: Option<Value>) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_string(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity: Default::default(),
            options,
        }
    }

    #[test]
    fn is_owned_file_key_requires_the_exact_entity_record_field_prefix() {
        assert!(is_owned_file_key(
            "core_contact",
            Uuid::nil(),
            "avatar",
            &format!("core_contact/{}/avatar/abc.png", Uuid::nil())
        ));
        assert!(!is_owned_file_key(
            "core_contact",
            Uuid::nil(),
            "avatar",
            "some/other/key.png"
        ));
    }

    #[test]
    fn file_keys_reads_a_single_valued_file_field() {
        let id = Uuid::nil();
        let attrs = vec![attr("avatar", FILE_FIELD_TYPE_INT, None)];
        let record = serde_json::json!({ "avatar": format!("core_contact/{id}/avatar/x.png") });
        let keys = file_keys(&attrs, &record);
        assert_eq!(
            keys,
            vec![(
                "avatar".to_string(),
                format!("core_contact/{id}/avatar/x.png")
            )]
        );
    }

    #[test]
    fn file_keys_reads_a_multi_valued_file_field_array() {
        let id = Uuid::nil();
        let attrs = vec![attr(
            "attachments",
            FILE_FIELD_TYPE_INT,
            Some(serde_json::json!({ "multi": true })),
        )];
        let record = serde_json::json!({
            "attachments": [
                format!("core_contact/{id}/attachments/a.pdf"),
                format!("core_contact/{id}/attachments/b.pdf"),
            ]
        });
        let keys = file_keys(&attrs, &record);
        assert_eq!(keys.len(), 2);
        assert!(keys.iter().all(|(field, _)| field == "attachments"));
    }

    #[test]
    fn file_keys_ignores_non_file_attributes() {
        let attrs = vec![attr("name", 3, None)];
        let record = serde_json::json!({ "name": "not a file key" });
        assert!(file_keys(&attrs, &record).is_empty());
    }

    #[test]
    fn file_keys_ignores_an_empty_single_valued_file_field() {
        let attrs = vec![attr("avatar", FILE_FIELD_TYPE_INT, None)];
        let record = serde_json::json!({ "avatar": "" });
        assert!(file_keys(&attrs, &record).is_empty());
    }
}
