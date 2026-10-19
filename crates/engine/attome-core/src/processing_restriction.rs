//! R1-T1: restriction of processing.
//!
//! A data subject may ask that their data be kept but not processed
//! (PDPL, GDPR art. 18). A fulfilled restriction request places one
//! `processing_restriction` row per matching record; while it is not lifted,
//! the record stays readable by people who may read it, but the processing
//! paths leave it out:
//!
//! - **AI**: `record.get` and `record.summarize` refuse it, and
//!   `query.execute` drops it from results (`attome-ai`);
//! - **exports**: the bulk data export excludes it with
//!   [`exclusion_sql`] in its `WHERE` (`attome-api` `data_export`);
//! - **marketing**: an email whose template is consent-gated (a marketing
//!   purpose) is not sent to a restricted user (`attome-notification`).
//!
//! The subject's own access and portability exports are not processing paths
//! and are unaffected.
//!
//! Lives in attome-core for the same reason `legal_hold` does: several
//! engines that may not depend on one another need the identical check.

use std::collections::HashSet;

use attome_types::AppError;
use sqlx::Postgres;
use uuid::Uuid;

/// Whether `record_id` in `entity_logicalname` is restricted now.
pub async fn record_is_restricted<'e, E>(
    executor: E,
    entity_logicalname: &str,
    record_id: Uuid,
) -> Result<bool, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM processing_restriction \
          WHERE entity_logicalname = $1 AND record_id = $2 AND lifted_at IS NULL)",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .fetch_one(executor)
    .await
    .map_err(AppError::internal)
}

/// Which of `record_ids` are restricted now, in any entity. For a result
/// set whose rows carry their ids but not their entity (record ids are
/// UUIDv7, unique across tables in practice).
pub async fn restricted_among<'e, E>(
    executor: E,
    record_ids: &[Uuid],
) -> Result<HashSet<Uuid>, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    if record_ids.is_empty() {
        return Ok(HashSet::new());
    }
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT record_id FROM processing_restriction \
          WHERE record_id = ANY($1) AND lifted_at IS NULL",
    )
    .bind(record_ids)
    .fetch_all(executor)
    .await
    .map_err(AppError::internal)?;
    Ok(ids.into_iter().collect())
}

/// The filter condition that leaves restricted records out of a query:
/// `entity_param` is the placeholder (e.g. `$3`) bound to the entity's
/// logical name, `id_expr` the row's id (e.g. `t.id`). Both are written by
/// the caller, never request data. Pure.
pub fn exclusion_sql(entity_param: &str, id_expr: &str) -> String {
    let mut sql = String::from(
        "NOT EXISTS (SELECT 1 FROM processing_restriction pr WHERE pr.entity_logicalname = ",
    );
    sql.push_str(entity_param);
    sql.push_str(" AND pr.record_id = ");
    sql.push_str(id_expr);
    sql.push_str(" AND pr.lifted_at IS NULL)");
    sql
}

/// A data-subject request's response deadline: `override_days` when the
/// deployment sets one (`compliance.dsr_response_days`), else the law of the
/// deployment's country (`core.country`) where the platform knows it, else
/// 30 days. Returns the law it applied, if any, and the days. Pure.
pub fn response_deadline(
    country: Option<&str>,
    override_days: Option<i64>,
) -> (Option<&'static str>, i64) {
    if let Some(days) = override_days.filter(|d| (1..=365).contains(d)) {
        return (None, days);
    }
    match country
        .map(str::trim)
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        // The Personal Data Protection Law's 30 days (roadmap R1-T1).
        Some("SA") => (Some("PDPL (Saudi Arabia)"), 30),
        _ => (None, 30),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsr_restriction_filter_names_the_entity_and_row() {
        let sql = exclusion_sql("$4", "t.id");
        assert!(sql.starts_with("NOT EXISTS"));
        assert!(sql.contains("pr.entity_logicalname = $4"));
        assert!(sql.contains("pr.record_id = t.id"));
        assert!(sql.contains("lifted_at IS NULL"));
    }

    #[test]
    fn dsr_restriction_deadline_follows_the_law_unless_overridden() {
        assert_eq!(
            response_deadline(Some("sa"), None),
            (Some("PDPL (Saudi Arabia)"), 30)
        );
        assert_eq!(response_deadline(Some("AE"), None), (None, 30));
        assert_eq!(response_deadline(None, None), (None, 30));
        assert_eq!(response_deadline(Some("SA"), Some(15)), (None, 15));
        assert_eq!(
            response_deadline(Some("SA"), Some(0)),
            (Some("PDPL (Saudi Arabia)"), 30)
        );
    }
}
