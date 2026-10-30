//! AI5-T2: the collections detector. For each active `ai_collection_rule`
//! it finds, and writes to the follow-up ledger (`ai_followup_item`, the
//! same ledger AI4's stall scan writes), the records a collector should
//! chase today:
//!
//! - `invoice_due`: unpaid invoices (`issued`, `sent` or `overdue` with
//!   something still open) due `offset_days` from today;
//! - `invoice_overdue`: unpaid invoices due `offset_days` ago;
//! - `renewal_due`: active or trial subscriptions ending within
//!   `offset_days`.
//!
//! An invoice with an open payment promise (`ai_payment_promise`, `open`,
//! promised for today or later, not rejected on review) is skipped, and so is any record that
//! already has `max_reminders` ledger rows under the rule. The ledger's
//! unique key with today as the window writes at most one row per record a
//! day. Entity and attribute names come from the metadata registry; a rule
//! whose entities are not installed finds nothing.
//!
//! AI5-T5: the hourly follow-up scan runs the collection rules once the
//! deployment's day has reached [`RUN_HOUR`] (08:00 in `core.time_zone`),
//! with that local date as "today" ([`collections_day`]); the ledger key
//! keeps later scans that day from adding a second row.

use attome_core::EngineState;
use attome_types::AppError;
use chrono::{Duration, NaiveDate};
use uuid::Uuid;

/// Records one rule's run looks at, at most.
pub const SCAN_LIMIT: i64 = 500;
/// The local hour from which a day's collection reminders are found.
pub const RUN_HOUR: u32 = 8;

/// The deployment's time zone (`core.time_zone` with no user), else UTC.
pub fn deployment_zone(state: &EngineState) -> chrono_tz::Tz {
    attome_core::setting_registry()
        .get("core.time_zone")
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_str().and_then(|s| s.parse::<chrono_tz::Tz>().ok()))
        .unwrap_or(chrono_tz::UTC)
}

/// The local date whose collections are due at `now` in `zone`, once that
/// day has reached [`RUN_HOUR`]; `None` before then. Pure.
pub fn collections_day(
    now: chrono::DateTime<chrono::Utc>,
    zone: chrono_tz::Tz,
) -> Option<NaiveDate> {
    use chrono::Timelike;
    let local = now.with_timezone(&zone);
    (local.hour() >= RUN_HOUR).then(|| local.date_naive())
}

/// An active collection rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRule {
    pub id: Uuid,
    /// `invoice_due`, `invoice_overdue` or `renewal_due`.
    pub kind: String,
    pub offset_days: i64,
    pub max_reminders: Option<i64>,
}

/// One candidate before the skips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub record: Uuid,
    pub owner: Uuid,
}

/// The date window a rule looks at, inclusive. Pure.
pub fn window(kind: &str, today: NaiveDate, offset_days: i64) -> Option<(NaiveDate, NaiveDate)> {
    let offset = Duration::days(offset_days.max(0));
    match kind {
        "invoice_due" => Some((today + offset, today + offset)),
        "invoice_overdue" => Some((today - offset, today - offset)),
        "renewal_due" => Some((today, today + offset)),
        _ => None,
    }
}

/// The candidates left after the skips: no open promise, and fewer than
/// `max_reminders` earlier reminders. Pure.
pub fn select(
    candidates: Vec<Candidate>,
    promised: &[Uuid],
    reminders: &std::collections::HashMap<Uuid, i64>,
    max_reminders: Option<i64>,
) -> Vec<Candidate> {
    candidates
        .into_iter()
        .filter(|c| !promised.contains(&c.record))
        .filter(|c| {
            max_reminders.is_none_or(|max| reminders.get(&c.record).copied().unwrap_or(0) < max)
        })
        .collect()
}

/// The entity a rule's kind reads, and the attributes it needs.
fn target(kind: &str) -> (&'static str, &'static [&'static str]) {
    match kind {
        "renewal_due" => ("subscription", &["end_date", "status"]),
        _ => ("invoice", &["due_date", "status"]),
    }
}

/// `(id, kind, offset days, max reminders)`.
type RuleRow = (Uuid, Option<String>, Option<f64>, Option<f64>);

/// The active rules.
pub async fn active_rules(db: &attome_db::DbPool) -> Result<Vec<CollectionRule>, AppError> {
    let present: bool = sqlx::query_scalar("SELECT to_regclass('ai_collection_rule') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !present {
        return Ok(Vec::new());
    }
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, kind::text, offset_days::float8, max_reminders::float8 FROM ai_collection_rule \
          WHERE COALESCE(is_active, true) ORDER BY id",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, kind, offset, max)| {
            Some(CollectionRule {
                id,
                kind: kind?,
                offset_days: offset.unwrap_or(0.0) as i64,
                max_reminders: max.filter(|m| *m > 0.0).map(|m| m as i64),
            })
        })
        .collect())
}

/// Finds a rule's records for `today` and records the new ones; how many.
pub async fn detect_collections(
    state: &EngineState,
    rule: &CollectionRule,
    today: NaiveDate,
) -> Result<u64, AppError> {
    let Some((from, to)) = window(&rule.kind, today, rule.offset_days) else {
        return Ok(0);
    };
    let (entity, needs) = target(&rule.kind);
    {
        let registry = state.entities.load();
        let Some(meta) = registry.get(entity) else {
            return Ok(0);
        };
        if needs
            .iter()
            .any(|n| !meta.attrs.iter().any(|a| a.logicalname == *n))
        {
            return Ok(0);
        }
    }
    let db = &state.base.db;
    let sql = if rule.kind == "renewal_due" {
        format!(
            "SELECT id, COALESCE(owner_ref, created_by) FROM {} \
              WHERE status::text IN ('active', 'trial') \
                AND end_date::date BETWEEN $1 AND $2 \
                AND COALESCE(owner_ref, created_by) IS NOT NULL \
                AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $3",
            attome_core::quote_ident(entity)
        )
    } else {
        format!(
            "SELECT id, COALESCE(owner_ref, created_by) FROM {} t \
              WHERE status::text IN ('issued', 'sent', 'overdue') \
                AND COALESCE((to_jsonb(t)->>'open_total')::numeric, 1) > 0 \
                AND due_date::date BETWEEN $1 AND $2 \
                AND COALESCE(owner_ref, created_by) IS NOT NULL \
                AND (is_active IS NULL OR is_active = true) ORDER BY id LIMIT $3",
            attome_core::quote_ident(entity)
        )
    };
    let found: Vec<(Uuid, Uuid)> = sqlx::query_as(&sql)
        .bind(from)
        .bind(to)
        .bind(SCAN_LIMIT)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
    if found.is_empty() {
        return Ok(0);
    }
    let ids: Vec<Uuid> = found.iter().map(|f| f.0).collect();
    let promised: Vec<Uuid> = if rule.kind == "renewal_due" {
        Vec::new()
    } else {
        let texts: Vec<String> = ids.iter().map(Uuid::to_string).collect();
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT p.invoice_id FROM ai_payment_promise p \
              WHERE p.invoice_id = ANY($1) AND p.status::text = 'open' \
                AND COALESCE(to_jsonb(p)->>'review_status', 'confirmed') <> 'rejected' \
                AND p.promised_date::date >= $2 AND (p.is_active IS NULL OR p.is_active = true)",
        )
        .bind(&texts)
        .bind(today)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        rows.iter()
            .filter_map(|r| Uuid::parse_str(r).ok())
            .collect()
    };
    let counts: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT record_id, COUNT(*) FROM ai_followup_item \
          WHERE rule_ref = $1 AND record_id = ANY($2) GROUP BY record_id",
    )
    .bind(rule.id)
    .bind(&ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let candidates = found
        .into_iter()
        .map(|(record, owner)| Candidate { record, owner })
        .collect();
    let chosen = select(
        candidates,
        &promised,
        &counts.into_iter().collect(),
        rule.max_reminders,
    );
    if chosen.is_empty() {
        return Ok(0);
    }
    let (records, owners): (Vec<Uuid>, Vec<Uuid>) =
        chosen.into_iter().map(|c| (c.record, c.owner)).unzip();
    let inserted = sqlx::query(
        "INSERT INTO ai_followup_item \
           (rule_ref, entity_logical_name, record_id, owner_user_id, reason, window_start) \
         SELECT $1, $2, r.id, r.owner, $3, $4 \
         FROM unnest($5::uuid[], $6::uuid[]) AS r(id, owner) \
         ON CONFLICT (rule_ref, record_id, window_start) DO NOTHING",
    )
    .bind(rule.id)
    .bind(entity)
    .bind(&rule.kind)
    .bind(today)
    .bind(&records)
    .bind(&owners)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(inserted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn c(n: u128) -> Candidate {
        Candidate {
            record: Uuid::from_u128(n),
            owner: Uuid::from_u128(100),
        }
    }

    fn day(m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2027, m, d).expect("a date")
    }

    #[test]
    fn collections_skips_open_promise() {
        let out = select(
            vec![c(1), c(2)],
            &[Uuid::from_u128(2)],
            &HashMap::new(),
            None,
        );
        assert_eq!(out, vec![c(1)]);
    }

    #[test]
    fn collections_respects_max_reminders() {
        let counts: HashMap<Uuid, i64> = [(Uuid::from_u128(1), 3), (Uuid::from_u128(2), 1)]
            .into_iter()
            .collect();
        let out = select(vec![c(1), c(2), c(3)], &[], &counts, Some(3));
        assert_eq!(out, vec![c(2), c(3)]);
        assert_eq!(select(vec![c(1)], &[], &counts, None).len(), 1, "no cap");
    }

    #[test]
    fn collections_wait_for_eight_in_the_morning_local_time() {
        use chrono::TimeZone;
        let riyadh: chrono_tz::Tz = "Asia/Riyadh".parse().expect("a zone");
        // 04:30 UTC is 07:30 in Riyadh: not yet.
        let early = chrono::Utc.with_ymd_and_hms(2027, 3, 10, 4, 30, 0).unwrap();
        assert_eq!(collections_day(early, riyadh), None);
        // 05:00 UTC is 08:00 in Riyadh: that day.
        let eight = chrono::Utc.with_ymd_and_hms(2027, 3, 10, 5, 0, 0).unwrap();
        assert_eq!(collections_day(eight, riyadh), Some(day(3, 10)));
        // 22:00 UTC is 01:00 the next day in Riyadh: that day has not
        // reached eight yet.
        let late = chrono::Utc.with_ymd_and_hms(2027, 3, 10, 22, 0, 0).unwrap();
        assert_eq!(collections_day(late, riyadh), None);
        // 20:00 UTC is 09:00 the next day in Auckland (UTC+13): that day.
        let auckland: chrono_tz::Tz = "Pacific/Auckland".parse().expect("a zone");
        let ahead = chrono::Utc.with_ymd_and_hms(2027, 3, 10, 20, 0, 0).unwrap();
        assert_eq!(collections_day(ahead, auckland), Some(day(3, 11)));
        assert_eq!(collections_day(early, chrono_tz::UTC), None);
    }

    #[test]
    fn each_kind_looks_at_its_own_dates() {
        assert_eq!(
            window("invoice_due", day(3, 10), 3),
            Some((day(3, 13), day(3, 13)))
        );
        assert_eq!(
            window("invoice_overdue", day(3, 10), 7),
            Some((day(3, 3), day(3, 3)))
        );
        assert_eq!(
            window("renewal_due", day(3, 10), 30),
            Some((day(3, 10), day(4, 9)))
        );
        assert_eq!(window("other", day(3, 10), 1), None);
    }
}
