//! Q15-T5: who saw a Financial or Health value in full.
//!
//! A read that shows a confirmed Financial or Health attribute unmasked (to
//! an administrator or a holder of its field-security read grant) adds one
//! entry per (person, entity, record, attribute) to a bounded buffer
//! ([`CAPACITY`] entries). Each node flushes the buffer every ten seconds
//! into `field_view_log` (migration 0298). A masked value is not a full read
//! and is not logged.
//!
//! - **Source of truth:** `field_view_log`; the buffer is a write buffer, so
//!   it is allowed as process state (guidelines §5).
//! - **Full buffer:** the read that fills it writes the whole buffer itself,
//!   on its own request, rather than drop entries; if that write fails the
//!   read fails too (fail closed for audit) and the entries stay buffered.
//! - **Crash:** a node that stops between flushes loses at most ten seconds
//!   of entries.

use std::sync::Mutex;

use attome_core::{AttrInfo, Sensitivity};
use attome_db::DbPool;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::context::SecurityContextExt;

/// Most entries held between flushes.
pub const CAPACITY: usize = 10_000;

/// One full read of one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewEntry {
    pub user_id: Uuid,
    pub entity: String,
    pub record_id: Uuid,
    pub attribute: String,
    pub viewed_at: DateTime<Utc>,
}

static BUFFER: Mutex<Vec<ViewEntry>> = Mutex::new(Vec::new());

/// Whether reads of `attr` are logged: a confirmed Financial or Health label.
pub fn is_logged(attr: &AttrInfo) -> bool {
    attr.sensitivity_confirmed
        && matches!(
            attr.sensitivity,
            Sensitivity::Financial | Sensitivity::Health
        )
}

/// The full reads `records` (rows of `entity`, each with an `id`) show `ctx`:
/// every logged attribute present with a value, when the caller sees it
/// unmasked. Pure.
pub fn full_reads(
    ctx: &SecurityContext,
    entity: &str,
    attrs: &[AttrInfo],
    records: &[Value],
    now: DateTime<Utc>,
) -> Vec<ViewEntry> {
    let logged: Vec<&str> = attrs
        .iter()
        .filter(|a| is_logged(a))
        .filter(|a| ctx.is_admin || ctx.has_field_read_grant(entity, &a.logicalname))
        .map(|a| a.logicalname.as_str())
        .collect();
    if logged.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for record in records {
        let Some(record_id) = record
            .get("id")
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        for attribute in &logged {
            if record.get(*attribute).is_some_and(|v| !v.is_null()) {
                out.push(ViewEntry {
                    user_id: ctx.user_id,
                    entity: entity.to_owned(),
                    record_id,
                    attribute: (*attribute).to_owned(),
                    viewed_at: now,
                });
            }
        }
    }
    out
}

/// Buffers `entries`. When the buffer reaches [`CAPACITY`], writes it all
/// before returning; an error then fails the caller's read, and the entries
/// stay buffered for the next flush.
pub async fn record(db: &DbPool, entries: Vec<ViewEntry>) -> Result<(), AppError> {
    if entries.is_empty() {
        return Ok(());
    }
    let full = {
        // A poisoned lock still holds whole entries; recovering it is safe.
        let mut buffer = BUFFER.lock().unwrap_or_else(|e| e.into_inner());
        buffer.extend(entries);
        (buffer.len() >= CAPACITY).then(|| std::mem::take(&mut *buffer))
    };
    match full {
        Some(batch) => write_back_on_error(db, batch).await.map(|_| ()),
        None => Ok(()),
    }
}

/// Writes every buffered entry. The number written; on a database error the
/// entries are put back.
pub async fn flush(db: &DbPool) -> Result<usize, AppError> {
    let batch = std::mem::take(&mut *BUFFER.lock().unwrap_or_else(|e| e.into_inner()));
    if batch.is_empty() {
        return Ok(0);
    }
    write_back_on_error(db, batch).await
}

async fn write_back_on_error(db: &DbPool, batch: Vec<ViewEntry>) -> Result<usize, AppError> {
    match write(db, &batch).await {
        Ok(()) => Ok(batch.len()),
        Err(error) => {
            let mut buffer = BUFFER.lock().unwrap_or_else(|e| e.into_inner());
            let newer = std::mem::replace(&mut *buffer, batch);
            buffer.extend(newer);
            Err(error)
        }
    }
}

async fn write(db: &DbPool, batch: &[ViewEntry]) -> Result<(), AppError> {
    let mut users = Vec::with_capacity(batch.len());
    let mut entities = Vec::with_capacity(batch.len());
    let mut records = Vec::with_capacity(batch.len());
    let mut attributes = Vec::with_capacity(batch.len());
    let mut times = Vec::with_capacity(batch.len());
    for entry in batch {
        users.push(entry.user_id);
        entities.push(entry.entity.clone());
        records.push(entry.record_id);
        attributes.push(entry.attribute.clone());
        times.push(entry.viewed_at);
    }
    sqlx::query(
        "INSERT INTO field_view_log \
             (user_ref, entity_logicalname, record_id, attribute_logicalname, viewed_at) \
         SELECT * FROM UNNEST($1::uuid[], $2::text[], $3::uuid[], $4::text[], $5::timestamptz[])",
    )
    .bind(&users)
    .bind(&entities)
    .bind(&records)
    .bind(&attributes)
    .bind(&times)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Takes the buffered entries (tests only).
#[cfg(test)]
fn take() -> Vec<ViewEntry> {
    std::mem::take(&mut *BUFFER.lock().unwrap_or_else(|e| e.into_inner()))
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;

    fn attr(name: &str, sensitivity: Sensitivity, confirmed: bool) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int: 3,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            sensitivity,
            sensitivity_confirmed: confirmed,
            options: None,
        }
    }

    fn ctx(grants: &[&str]) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: grants.iter().map(|s| s.to_string()).collect(),
            field_write_grants: HashSet::new(),
            field_masks: Default::default(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            unit_scope: Default::default(),
            service_principal: false,
        }
    }

    /// A full read of a confirmed Financial or Health value is logged, once
    /// per record and attribute; a null, an unconfirmed label, a Personal
    /// label or a value seen only masked is not.
    #[test]
    fn view_log_records_full_reads_of_financial_and_health_values() {
        let attrs = [
            attr("salary", Sensitivity::Financial, true),
            attr("diagnosis", Sensitivity::Health, true),
            attr("bonus", Sensitivity::Financial, false),
            attr("email", Sensitivity::Personal, true),
        ];
        let id = Uuid::now_v7();
        let records = [serde_json::json!({
            "id": id.to_string(), "salary": 100, "diagnosis": null, "bonus": 5, "email": "a@b.c"
        })];
        let now = Utc::now();

        let reader = ctx(&["employee.salary", "employee.diagnosis", "employee.bonus"]);
        let reads = full_reads(&reader, "employee", &attrs, &records, now);
        assert_eq!(
            reads,
            vec![ViewEntry {
                user_id: reader.user_id,
                entity: "employee".into(),
                record_id: id,
                attribute: "salary".into(),
                viewed_at: now,
            }]
        );
        // Seen masked (no read grant): not a full read.
        assert!(full_reads(&ctx(&[]), "employee", &attrs, &records, now).is_empty());
        let admin = SecurityContext {
            is_admin: true,
            ..ctx(&[])
        };
        assert_eq!(
            full_reads(&admin, "employee", &attrs, &records, now).len(),
            1
        );
    }

    /// A read is logged: buffered entries come back out of the buffer for
    /// the flush, in order.
    #[test]
    fn view_log_buffers_until_flushed() {
        let entry = ViewEntry {
            user_id: Uuid::now_v7(),
            entity: "view_log_test".into(),
            record_id: Uuid::now_v7(),
            attribute: "salary".into(),
            viewed_at: Utc::now(),
        };
        BUFFER
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(entry.clone());
        assert!(take().contains(&entry));
    }
}
