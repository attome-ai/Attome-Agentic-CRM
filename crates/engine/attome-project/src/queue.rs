//! V7-T1: the generic queue. A `queue_item` puts a record of any entity in a
//! `queue`: the record is a polymorphic pair (`record_entity`, `record_id`,
//! `options.polymorphic.any`, A8-T1), so the generic entity API checks on
//! every write that the record exists, is live and is readable by the writer.
//! Both entities are platform changeset 0075 (`attome-project-queue`); items
//! are written through the generic entity API, never here.
//!
//! [`migrate_service_queues`] moves the service work queues onto it: every
//! live `service_work_queue` becomes a `queue` with the same id, and every
//! live ticket in one (`service_ticket.work_queue_ref`) becomes a
//! `queue_item` holding that ticket. Idempotent; runs at boot after the
//! platform definitions apply. The service engine's claim and assign
//! (`attome_service::queue`) still route by `work_queue_ref`; a ticket queued
//! after a boot gets its item on the next one.

use attome_db::DbPool;
use attome_types::AppError;

/// Ticket statuses whose item is `done`.
pub const DONE_TICKET_STATUSES: &[&str] = &["resolved", "closed"];

/// Rows moved per transaction.
const BATCH: i64 = 1000;

const LOCK_KEY: &str = "attome-project/queue-migrate:service";

/// The item status of a ticket: `done` once resolved or closed, `picked`
/// while someone holds it, else `waiting`. Pure; the migration's SQL applies
/// the same rule.
pub fn item_status(ticket_status: &str, assigned: bool) -> &'static str {
    if DONE_TICKET_STATUSES.contains(&ticket_status) {
        "done"
    } else if assigned {
        "picked"
    } else {
        "waiting"
    }
}

/// Moves the service work queues and their tickets into `queue` and
/// `queue_item`. Returns how many items it created. Does nothing when the
/// service tables are not provisioned (the service module is not licensed)
/// or another node holds the migration lock.
pub async fn migrate_service_queues(db: &DbPool) -> Result<u64, AppError> {
    let tables: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT to_regclass('service_work_queue') IS NOT NULL, \
                to_regclass('service_ticket') IS NOT NULL, \
                to_regclass('queue') IS NOT NULL, \
                to_regclass('queue_item') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if tables != (true, true, true, true) {
        return Ok(0);
    }
    let done: Vec<String> = DONE_TICKET_STATUSES
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let mut moved = 0u64;
    loop {
        let mut tx = attome_db::tx::begin(db).await?;
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(crate::ADVISORY_LOCK_NAMESPACE)
            .bind(LOCK_KEY)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            tx.rollback().await.map_err(AppError::internal)?;
            return Ok(moved);
        }
        sqlx::query(
            "INSERT INTO queue \
               (id, name, lead_ref, created_by, owner_ref, owner_type, organization_ref, \
                created_at, modified_at) \
             SELECT q.id, COALESCE(NULLIF(btrim(q.name), ''), q.id::text), q.lead_ref, \
                    q.created_by, q.owner_ref, q.owner_type, q.organization_ref, \
                    q.created_at, now() \
               FROM service_work_queue q \
              WHERE q.is_active IS NOT FALSE \
                AND NOT EXISTS (SELECT 1 FROM queue x WHERE x.id = q.id) \
              ORDER BY q.id LIMIT $1",
        )
        .bind(BATCH)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        // An item that exists, even soft-deleted, is never made again.
        let items = sqlx::query(
            "INSERT INTO queue_item \
               (id, queue_ref, record_entity, record_id, priority, status, assigned_ref, \
                entered_at, created_by, owner_ref, owner_type, organization_ref, \
                created_at, modified_at) \
             SELECT uuidv7(), t.work_queue_ref, 'service_ticket', t.id::text, \
                    COALESCE(t.priority::text, 'medium'), \
                    CASE WHEN t.status::text = ANY($2::text[]) THEN 'done' \
                         WHEN t.assignee_id IS NOT NULL THEN 'picked' \
                         ELSE 'waiting' END, \
                    t.assignee_id, t.created_at, t.created_by, t.owner_ref, t.owner_type, \
                    t.organization_ref, now(), now() \
               FROM service_ticket t \
               JOIN queue q ON q.id = t.work_queue_ref \
              WHERE t.is_active IS NOT FALSE \
                AND NOT EXISTS (SELECT 1 FROM queue_item i \
                                 WHERE i.record_entity = 'service_ticket' \
                                   AND i.record_id = t.id::text \
                                   AND i.queue_ref = t.work_queue_ref) \
              ORDER BY t.id LIMIT $1",
        )
        .bind(BATCH)
        .bind(&done)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        tx.commit().await.map_err(AppError::internal)?;
        moved += items;
        if items < BATCH as u64 {
            break;
        }
    }
    if moved > 0 {
        tracing::info!(moved, "service tickets moved into queue items");
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_queue_item_status_follows_the_ticket() {
        assert_eq!(item_status("new", false), "waiting");
        assert_eq!(item_status("open", true), "picked");
        assert_eq!(item_status("in_progress", true), "picked");
        assert_eq!(item_status("resolved", true), "done");
        assert_eq!(item_status("closed", false), "done");
    }

    /// The record pair admits any entity, so a queue holds records of
    /// every kind (A8-T1's check still runs on each write).
    #[test]
    fn generic_queue_record_is_polymorphic_over_any_entity() {
        let cs: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../changesets/platform/0075-attome-project-queue.json"
        ))
        .unwrap();
        let record = cs["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["target"]["entity"] == "queue_item" && o["target"]["field"] == "record_id")
            .unwrap();
        let poly = &record["args"]["definition"]["options"]["polymorphic"];
        assert_eq!(poly["pair"], "record_entity");
        assert_eq!(poly["any"], true);
    }
}
