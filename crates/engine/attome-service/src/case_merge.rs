//! G7-T1: the case-specific steps of merging two service tickets.
//!
//! The generic merge (A15, `attome_records::entity_crud::merge`) fills the
//! survivor's empty fields, moves records that point at the merged ticket
//! through a lookup, and retires or redirects the merged ticket. A case also
//! has things that hang off it by `entity_name`/`record_id` rather than a
//! lookup — its messages (`communication`), notes, activities, documents,
//! tags and followers — and a number people quote. After each ticket merge
//! ([`sweep_case_merges`], from the ticket SLA sweep):
//!
//! - every message, note, activity, document, tag and follow of the merged
//!   ticket moves to the survivor (messages keep their own times, so the
//!   survivor's thread reads in time order with both cases' messages);
//! - the merged ticket's number is kept on the survivor as an alias
//!   (`merged_numbers`, searchable), and its id redirects to the survivor
//!   (`record_redirect`, which undo removes with the merge);
//! - the merged ticket is closed with the resolution `merged`.
//!
//! Each merge is applied once (`service_case_merge`, with what moved). An
//! undone merge is not applied; the case steps of one undone after they ran
//! stay (the moved items are listed in `service_case_merge.moved`).

use attome_core::quote_ident;
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// The entity whose merges this applies to.
pub const CASE_ENTITY: &str = "service_ticket";
/// What hangs off a case by `entity_name`/`record_id`.
pub const CASE_CHILDREN: &[&str] = &[
    "communication",
    "note",
    "activity",
    "attome_document",
    "tag_item",
    "follow",
    "reminder",
];
/// The resolution code a merged case closes with.
pub const MERGED_RESOLUTION: &str = "merged";
/// Most merges applied per pass.
const MERGE_BATCH: i64 = 100;
/// Longest alias list kept.
const MAX_ALIASES_CHARS: usize = 2_000;

/// The survivor's alias list after adding `number`: comma-separated, each
/// once, never the survivor's own number. Pure.
pub fn merged_numbers(
    existing: Option<&str>,
    survivor_number: Option<&str>,
    number: Option<&str>,
) -> Option<String> {
    let mut list: Vec<String> = existing
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
        .collect();
    if let Some(number) = number.map(str::trim).filter(|n| !n.is_empty())
        && Some(number) != survivor_number.map(str::trim)
        && !list.iter().any(|n| n == number)
    {
        list.push(number.to_owned());
    }
    let joined = list.join(", ");
    if joined.is_empty() {
        return None;
    }
    // Keep the newest aliases when the list grows past its ceiling.
    let mut cut = joined.as_str();
    while cut.chars().count() > MAX_ALIASES_CHARS {
        match cut.split_once(", ") {
            Some((_, rest)) => cut = rest,
            None => break,
        }
    }
    Some(cut.to_owned())
}

/// Applies the case steps of every ticket merge not yet applied (and not
/// undone). Returns how many merges it applied.
pub async fn sweep_case_merges(db: &DbPool) -> Result<u64, AppError> {
    let pending: Vec<(Uuid, Uuid, Vec<Uuid>)> = sqlx::query_as(
        "SELECT m.id, m.survivor_id, m.merged_ids FROM merge_log m \
          WHERE m.entity_logicalname = $1 AND m.undone_at IS NULL \
            AND NOT EXISTS (SELECT 1 FROM service_case_merge c WHERE c.merge_log_id = m.id) \
          ORDER BY m.merged_at LIMIT $2",
    )
    .bind(CASE_ENTITY)
    .bind(MERGE_BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut applied = 0u64;
    for (log_id, survivor, merged) in pending {
        for merged_id in merged {
            apply_case_merge(db, log_id, survivor, merged_id).await?;
        }
        applied += 1;
    }
    Ok(applied)
}

/// The case steps of one merge, in one transaction.
async fn apply_case_merge(
    db: &DbPool,
    log_id: Uuid,
    survivor: Uuid,
    merged: Uuid,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    // A second worker applying the same merge stops here.
    let claimed = sqlx::query(
        "INSERT INTO service_case_merge (merge_log_id, survivor_id, merged_id) \
         VALUES ($1, $2, $3) ON CONFLICT (merge_log_id) DO NOTHING",
    )
    .bind(log_id)
    .bind(survivor)
    .bind(merged)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if claimed.rows_affected() == 0 {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(());
    }

    let mut moved = serde_json::Map::new();
    for child in CASE_CHILDREN {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(*child)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        if !exists {
            continue;
        }
        let mut sql = String::from("UPDATE ");
        sql.push_str(&quote_ident(child));
        sql.push_str(" SET record_id = $1 WHERE entity_name = $2 AND record_id = $3");
        if *child == "attome_document" {
            // A document mirrored from one of the merged ticket's file
            // fields stays with that field: the survivor's next save would
            // retire a mirror its own field does not name.
            sql.push_str(" AND source_field IS NULL");
        }
        sql.push_str(" RETURNING id");
        let ids: Vec<Uuid> = sqlx::query_scalar(&sql)
            .bind(survivor.to_string())
            .bind(CASE_ENTITY)
            .bind(merged.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        for id in &ids {
            attome_core::change_feed::emit_tx(
                &mut tx,
                child,
                *id,
                attome_core::ChangeOperation::Update,
            )
            .await?;
        }
        if !ids.is_empty() {
            moved.insert((*child).to_owned(), serde_json::json!(ids));
        }
    }

    let numbers: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT s.ticket_number, s.merged_numbers, m.ticket_number \
           FROM service_ticket s, service_ticket m WHERE s.id = $1 AND m.id = $2",
    )
    .bind(survivor)
    .bind(merged)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some((survivor_number, existing, merged_number)) = numbers {
        let aliases = merged_numbers(
            existing.as_deref(),
            survivor_number.as_deref(),
            merged_number.as_deref(),
        );
        if aliases != existing {
            sqlx::query("UPDATE service_ticket SET merged_numbers = $2 WHERE id = $1")
                .bind(survivor)
                .bind(&aliases)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            attome_core::change_feed::emit_tx(
                &mut tx,
                CASE_ENTITY,
                survivor,
                attome_core::ChangeOperation::Update,
            )
            .await?;
        }
    }

    sqlx::query(
        "UPDATE service_ticket SET status = 'closed', resolution_code = $2 \
          WHERE id = $1 AND status <> 'closed'",
    )
    .bind(merged)
    .bind(MERGED_RESOLUTION)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO record_redirect (entity_logicalname, from_id, to_id, merge_log_id) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (entity_logicalname, from_id) DO NOTHING",
    )
    .bind(CASE_ENTITY)
    .bind(merged)
    .bind(survivor)
    .bind(log_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("UPDATE service_case_merge SET moved = $2 WHERE merge_log_id = $1")
        .bind(log_id)
        .bind(serde_json::Value::Object(moved))
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(%survivor, %merged, "service: case merge steps applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_merge_keeps_the_merged_number_as_an_alias_once() {
        assert_eq!(
            merged_numbers(None, Some("TKT-1"), Some("TKT-7")).as_deref(),
            Some("TKT-7")
        );
        assert_eq!(
            merged_numbers(Some("TKT-7"), Some("TKT-1"), Some("TKT-9")).as_deref(),
            Some("TKT-7, TKT-9")
        );
        assert_eq!(
            merged_numbers(Some("TKT-7, TKT-9"), Some("TKT-1"), Some("TKT-7")).as_deref(),
            Some("TKT-7, TKT-9")
        );
    }

    #[test]
    fn case_merge_never_aliases_the_survivors_own_number_or_nothing() {
        assert_eq!(merged_numbers(None, Some("TKT-1"), Some("TKT-1")), None);
        assert_eq!(merged_numbers(None, None, None), None);
        assert_eq!(merged_numbers(Some(" , "), None, Some(" ")), None);
    }

    #[test]
    fn case_merge_moves_messages_and_the_rest_of_the_case() {
        for child in ["communication", "note", "attome_document", "activity"] {
            assert!(CASE_CHILDREN.contains(&child), "{child}");
        }
    }
}
