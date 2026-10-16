//! The follow-up stall detector (roadmap AI4-T3): for one follow-up rule,
//! the records that have gone quiet, written once per record and week to
//! the follow-up ledger (`ai_followup_item`).
//!
//! - `stalled_deal`: open records of the rule's entity (a `stage` that is
//!   not closed, else an `is_closed` that is false) untouched for
//!   `idle_days` (the entity's `last_activity_at` when it has one, else the
//!   row's last change).
//! - `overdue_task`: records with a due date (`due_at` or `due_date`) before
//!   today that are still open (`status` `open`, else `is_completed` false).
//! - `unanswered_customer`: conversations (`communication`, by the record
//!   they are about) whose newest message is inbound and older than
//!   `idle_days` days, with no outbound reply after it.
//!
//! Every name in the SQL comes from the metadata registry and is quoted;
//! a rule naming an unknown entity, or one without the needed attributes,
//! is refused before any SQL runs. Each run of a rule scans at most
//! [`SCAN_LIMIT`] records, oldest first, and the ledger's unique key
//! `(rule_ref, record_id, window_start)` with the week's Monday as the
//! window makes a rerun write nothing twice.

use attome_core::{EngineState, quote_ident};
use attome_types::AppError;
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use uuid::Uuid;

/// Records one rule's scan looks at per run.
pub const SCAN_LIMIT: i64 = 500;

/// A follow-up rule (`ai_followup_rule`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowupRule {
    pub id: Uuid,
    pub reason: String,
    pub target_entity: String,
    pub idle_days: i64,
}

/// Why a rule cannot be scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetectError {
    UnknownEntity(String),
    MissingAttribute { entity: String, needs: &'static str },
    UnknownReason(String),
}

impl From<DetectError> for AppError {
    fn from(e: DetectError) -> Self {
        AppError::Validation(match e {
            DetectError::UnknownEntity(entity) => format!("followup.unknown_entity: {entity}"),
            DetectError::MissingAttribute { entity, needs } => {
                format!("followup.missing_attribute: {entity} has no {needs}")
            }
            DetectError::UnknownReason(reason) => format!("followup.unknown_reason: {reason}"),
        })
    }
}

/// The Monday of `day`'s ISO week.
pub fn window_start(day: NaiveDate) -> NaiveDate {
    day - Duration::days(i64::from(day.weekday().num_days_from_monday()))
}

/// The SQL that finds a rule's candidates: `(record id, owner)` rows, with
/// `$1` the idle cutoff and `$2` the limit. Names come from `attrs` (the
/// entity's validated attributes) only.
pub fn candidate_sql(reason: &str, entity: &str, attrs: &[String]) -> Result<String, DetectError> {
    let has = |a: &str| attrs.iter().any(|x| x == a);
    let table = quote_ident(entity);
    match reason {
        "stalled_deal" => {
            let open = if has("stage") {
                "COALESCE(stage, '') NOT IN ('closed_won', 'closed_lost')".to_owned()
            } else if has("is_closed") {
                "COALESCE(is_closed, false) = false".to_owned()
            } else {
                return Err(DetectError::MissingAttribute {
                    entity: entity.to_owned(),
                    needs: "stage or is_closed",
                });
            };
            let last = if has("last_activity_at") {
                "COALESCE(last_activity_at, modified_at, created_at)"
            } else {
                "COALESCE(modified_at, created_at)"
            };
            Ok(format!(
                "SELECT id, owner_ref FROM {table} \
                 WHERE (is_active IS NULL OR is_active = true) AND owner_ref IS NOT NULL \
                   AND {open} AND {last} < $1 \
                 ORDER BY {last} LIMIT $2"
            ))
        }
        "overdue_task" => {
            let due = if has("due_at") {
                quote_ident("due_at")
            } else if has("due_date") {
                quote_ident("due_date")
            } else {
                return Err(DetectError::MissingAttribute {
                    entity: entity.to_owned(),
                    needs: "due_at or due_date",
                });
            };
            let open = if has("status") {
                "COALESCE(status, 'open') = 'open'"
            } else if has("is_completed") {
                "COALESCE(is_completed, false) = false"
            } else {
                return Err(DetectError::MissingAttribute {
                    entity: entity.to_owned(),
                    needs: "status or is_completed",
                });
            };
            Ok(format!(
                "SELECT id, owner_ref FROM {table} \
                 WHERE (is_active IS NULL OR is_active = true) AND owner_ref IS NOT NULL \
                   AND {open} AND {due}::date < now()::date AND $1::timestamptz IS NOT NULL \
                 ORDER BY {due} LIMIT $2"
            ))
        }
        "unanswered_customer" => {
            for needed in ["direction", "entity_name", "record_id"] {
                if !has(needed) {
                    return Err(DetectError::MissingAttribute {
                        entity: entity.to_owned(),
                        needs: "direction, entity_name and record_id",
                    });
                }
            }
            // The newest message per conversation; kept when it is inbound
            // and older than the cutoff (so nothing outbound came after it).
            Ok(format!(
                "SELECT id, owner_ref FROM ( \
                     SELECT DISTINCT ON (entity_name, record_id) id, owner_ref, direction, \
                            created_at \
                     FROM {table} \
                     WHERE (is_active IS NULL OR is_active = true) AND record_id IS NOT NULL \
                     ORDER BY entity_name, record_id, created_at DESC) newest \
                 WHERE direction = 'inbound' AND created_at < $1 AND owner_ref IS NOT NULL \
                 ORDER BY created_at LIMIT $2"
            ))
        }
        other => Err(DetectError::UnknownReason(other.to_owned())),
    }
}

/// Finds a rule's stalls and records the new ones; how many were new.
pub async fn detect(
    state: &EngineState,
    rule: &FollowupRule,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let attrs: Vec<String> = {
        let registry = state.entities.load();
        let meta = registry
            .get(&rule.target_entity)
            .ok_or_else(|| DetectError::UnknownEntity(rule.target_entity.clone()))?;
        meta.attrs.iter().map(|a| a.logicalname.clone()).collect()
    };
    let sql = candidate_sql(&rule.reason, &rule.target_entity, &attrs)?;
    let cutoff = now - Duration::days(rule.idle_days.max(0));
    let found: Vec<(Uuid, Uuid)> = sqlx::query_as(&sql)
        .bind(cutoff)
        .bind(SCAN_LIMIT)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    if found.is_empty() {
        return Ok(0);
    }
    let (ids, owners): (Vec<Uuid>, Vec<Uuid>) = found.into_iter().unzip();
    let inserted = sqlx::query(
        "INSERT INTO ai_followup_item \
           (rule_ref, entity_logical_name, record_id, owner_user_id, reason, window_start) \
         SELECT $1, $2, r.id, r.owner, $3, $4 \
         FROM unnest($5::uuid[], $6::uuid[]) AS r(id, owner) \
         ON CONFLICT (rule_ref, record_id, window_start) DO NOTHING",
    )
    .bind(rule.id)
    .bind(&rule.target_entity)
    .bind(&rule.reason)
    .bind(window_start(now.date_naive()))
    .bind(&ids)
    .bind(&owners)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(inserted)
}

/// The active follow-up rules.
pub async fn active_rules(db: &attome_db::DbPool) -> Result<Vec<FollowupRule>, AppError> {
    let rows: Vec<(Uuid, Option<String>, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT id, reason, target_entity, idle_days::bigint FROM ai_followup_rule \
         WHERE COALESCE(is_active, true) ORDER BY id",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, reason, target, idle)| {
            Some(FollowupRule {
                id,
                reason: reason?,
                target_entity: target?,
                idle_days: idle.unwrap_or(7),
            })
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, m, day).unwrap_or_default()
    }

    #[test]
    fn window_start_is_iso_monday() {
        // Mon 12 Oct 2026; Wed 14 and Sun 18 fall in the same week.
        assert_eq!(window_start(d(10, 14)), d(10, 12));
        assert_eq!(window_start(d(10, 18)), d(10, 12));
        assert_eq!(window_start(d(10, 12)), d(10, 12));
    }

    #[test]
    fn rules_without_the_needed_attributes_are_refused_before_sql() {
        let none: Vec<String> = vec!["name".into()];
        assert!(matches!(
            candidate_sql("stalled_deal", "opportunity", &none),
            Err(DetectError::MissingAttribute { .. })
        ));
        assert!(matches!(
            candidate_sql("overdue_task", "activity", &none),
            Err(DetectError::MissingAttribute { .. })
        ));
        assert!(matches!(
            candidate_sql("mystery", "activity", &none),
            Err(DetectError::UnknownReason(_))
        ));
        let deal: Vec<String> = vec!["stage".into(), "last_activity_at".into()];
        let sql = candidate_sql("stalled_deal", "opportunity", &deal).unwrap_or_default();
        assert!(sql.contains("\"opportunity\""));
        assert!(sql.contains("last_activity_at"));
    }
}
