//! L2-T4: who looks after a data quality issue, and by when.
//!
//! A new open issue goes to the steward of its entity's data domain (L3
//! governance roles; the first by user id when there are several), else to
//! the owner of the record it is about, and is due its target's
//! `issue_sla_days` (migration 0236; [`DEFAULT_SLA_DAYS`] when unset) after
//! it was detected. An issue already assigned keeps its owner and due date.

use attome_core::{EntityMeta, quote_ident};
use attome_db::DbPool;
use attome_types::AppError;

/// Days an issue is due in when the entity's target sets none.
pub const DEFAULT_SLA_DAYS: i32 = 7;

/// Assigns `meta`'s unassigned open issues; how many were assigned.
pub async fn assign_open(db: &DbPool, meta: &EntityMeta) -> Result<u64, AppError> {
    let entity = &meta.logicalname;
    let has_owner: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
                         WHERE table_schema = current_schema() AND table_name = $1 \
                           AND column_name = 'owner_ref')",
    )
    .bind(entity)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    // The steward first, then the record's owner when the entity has one.
    let sql = if has_owner {
        format!(
            "UPDATE quality_issue i \
                SET owner_id = COALESCE( \
                        (SELECT g.user_id FROM entity_info e \
                           JOIN governance_role g ON g.domain_ref = e.domain_ref \
                          WHERE e.logicalname = i.entity_logicalname AND g.role = 'steward' \
                          ORDER BY g.user_id LIMIT 1), \
                        (SELECT r.owner_ref FROM {table} r WHERE r.id = i.record_id)), \
                    due_at = COALESCE(i.due_at, i.detected_at + make_interval(days => COALESCE( \
                        (SELECT t.issue_sla_days FROM quality_target t \
                          WHERE t.entity = i.entity_logicalname), $2))) \
              WHERE i.entity_logicalname = $1 AND i.status = 'open' AND i.owner_id IS NULL",
            table = quote_ident(entity)
        )
    } else {
        "UPDATE quality_issue i \
            SET owner_id = (SELECT g.user_id FROM entity_info e \
                              JOIN governance_role g ON g.domain_ref = e.domain_ref \
                             WHERE e.logicalname = i.entity_logicalname AND g.role = 'steward' \
                             ORDER BY g.user_id LIMIT 1), \
                due_at = COALESCE(i.due_at, i.detected_at + make_interval(days => COALESCE( \
                    (SELECT t.issue_sla_days FROM quality_target t \
                      WHERE t.entity = i.entity_logicalname), $2))) \
          WHERE i.entity_logicalname = $1 AND i.status = 'open' AND i.owner_id IS NULL"
            .to_owned()
    };
    let assigned = sqlx::query(&sql)
        .bind(entity)
        .bind(DEFAULT_SLA_DAYS)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
    Ok(assigned)
}

/// The statuses an issue moves through.
pub const STATUSES: &[&str] = &["open", "in_progress", "fixed", "accepted", "resolved"];

/// Checks a status change: a known status, and a reason when accepted.
/// Pure.
pub fn check_change(status: &str, accepted_reason: Option<&str>) -> Result<(), String> {
    if !STATUSES.contains(&status) {
        return Err(format!("status must be one of: {}", STATUSES.join(", ")));
    }
    let reason = accepted_reason.map(str::trim).filter(|r| !r.is_empty());
    match (status, reason) {
        ("accepted", None) => Err("accepting an issue needs a reason".into()),
        ("accepted", Some(r)) if r.len() > 2000 => {
            Err("the reason is at most 2,000 characters".into())
        }
        (s, Some(_)) if s != "accepted" => {
            Err("a reason is given only when accepting an issue".into())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_issue_change_needs_a_reason_to_accept() {
        assert!(check_change("in_progress", None).is_ok());
        assert!(check_change("accepted", Some("known legacy rows")).is_ok());
        assert!(check_change("accepted", None).is_err());
        assert!(check_change("accepted", Some("  ")).is_err());
        assert!(check_change("fixed", Some("why")).is_err());
        assert!(check_change("closed", None).is_err());
    }
}
