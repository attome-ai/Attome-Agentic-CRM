//! Account-based marketing (roadmap E20-T1): target account lists
//! (`marketing_target_account`, migration 0097) with a stage per account,
//! an engagement score from the account's contacts' activity of the last
//! [`WINDOW_DAYS`] days, and the buying roles covered among its contacts.
//!
//! Engagement weighs each activity by kind (a meeting more than an email)
//! and fades it with a half-life; the score is 0 to 100 on a saturating
//! curve. The stage only moves forward on its own: `identified` becomes
//! `aware` when anyone engaged and `engaged` past [`ENGAGED_SCORE`]; an open
//! opportunity or a customer status is set by the sales side.

use std::collections::{HashMap, HashSet};

use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

/// How far back activity counts.
pub const WINDOW_DAYS: i64 = 90;
/// Days for an activity's weight to halve.
pub const HALF_LIFE_DAYS: f64 = 21.0;
/// The score at which an account is engaged.
pub const ENGAGED_SCORE: f64 = 40.0;
/// The buying roles a target account should have covered.
pub const WANTED_ROLES: &[&str] = &[
    "decision_maker",
    "economic_buyer",
    "technical_buyer",
    "champion",
];

/// An activity's weight by kind.
pub fn weight(kind: &str) -> f64 {
    match kind {
        "meeting" | "visit" => 5.0,
        "phone_call" => 3.0,
        "form_submit" | "webinar" => 3.0,
        "email_click" => 1.5,
        _ => 1.0,
    }
}

/// The engagement score of a set of `(when, kind)` activities at `now`.
pub fn engagement(events: &[(DateTime<Utc>, String)], now: DateTime<Utc>) -> f64 {
    let total: f64 = events
        .iter()
        .map(|(at, kind)| {
            let days = (now - *at).num_seconds().max(0) as f64 / 86_400.0;
            weight(kind) * 0.5f64.powf(days / HALF_LIFE_DAYS)
        })
        .sum();
    ((1.0 - (-total / 20.0).exp()) * 1000.0).round() / 10.0
}

/// The wanted roles present and missing among `roles`.
pub fn coverage(roles: &HashSet<String>) -> (Vec<String>, Vec<String>) {
    let (covered, missing): (Vec<&str>, Vec<&str>) = WANTED_ROLES
        .iter()
        .copied()
        .partition(|r| roles.contains(*r));
    (
        covered.into_iter().map(str::to_owned).collect(),
        missing.into_iter().map(str::to_owned).collect(),
    )
}

/// The stage after scoring: never backwards, and never past `engaged` on
/// its own.
pub fn next_stage(current: &str, score: f64, engaged_contacts: usize) -> &str {
    let rank = |s: &str| match s {
        "identified" => 0,
        "aware" => 1,
        "engaged" => 2,
        "opportunity" => 3,
        "customer" => 4,
        _ => 0,
    };
    let earned = if score >= ENGAGED_SCORE {
        "engaged"
    } else if engaged_contacts > 0 {
        "aware"
    } else {
        "identified"
    };
    if rank(earned) > rank(current) {
        earned
    } else {
        current
    }
}

type TargetRow = (Uuid, Uuid, String);

/// Rescores every target account; the number scored.
pub async fn rescore(db: &attome_db::DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('contact') IS NOT NULL AND to_regclass('activity') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let has_roles: bool =
        sqlx::query_scalar("SELECT to_regclass('opportunity_contact_role') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    let targets: Vec<TargetRow> =
        sqlx::query_as("SELECT list_id, account_id, stage FROM marketing_target_account")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
    let since = now - Duration::days(WINDOW_DAYS);
    let mut scored = 0;
    for chunk in targets.chunks(200) {
        let accounts: Vec<Uuid> = chunk.iter().map(|t| t.1).collect();
        let events: Vec<(Uuid, Uuid, DateTime<Utc>, String)> = sqlx::query_as(
            "SELECT c.account_ref, c.id, COALESCE(a.completed_at, a.created_at), a.activity_type \
             FROM activity a JOIN contact c ON a.entity_name = 'contact' AND a.record_id = c.id::text \
             WHERE c.account_ref = ANY($1) AND COALESCE(a.completed_at, a.created_at) >= $2 \
               AND (a.is_active IS NULL OR a.is_active = true)",
        )
        .bind(&accounts)
        .bind(since)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let mut by_account: HashMap<Uuid, (Vec<(DateTime<Utc>, String)>, HashSet<Uuid>)> =
            HashMap::new();
        for (account, contact, at, kind) in events {
            let entry = by_account.entry(account).or_default();
            entry.0.push((at, kind));
            entry.1.insert(contact);
        }
        let mut roles: HashMap<Uuid, HashSet<String>> = HashMap::new();
        if has_roles {
            let rows: Vec<(Uuid, String)> = sqlx::query_as(
                "SELECT DISTINCT c.account_ref, r.role FROM opportunity_contact_role r \
                 JOIN contact c ON c.id = r.contact_ref \
                 WHERE c.account_ref = ANY($1) AND r.role IS NOT NULL \
                   AND (r.is_active IS NULL OR r.is_active = true)",
            )
            .bind(&accounts)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            for (account, role) in rows {
                roles.entry(account).or_default().insert(role);
            }
        }
        for (list, account, stage) in chunk {
            let (events, contacts) = by_account.remove(account).unwrap_or_default();
            let score = engagement(&events, now);
            let (covered, missing) = coverage(&roles.remove(account).unwrap_or_default());
            let stage = next_stage(stage, score, contacts.len());
            sqlx::query(
                "UPDATE marketing_target_account SET score = $3::float8::numeric, stage = $4, \
                     engaged_contacts = $5, roles_covered = $6, roles_missing = $7, scored_at = $8 \
                 WHERE list_id = $1 AND account_id = $2",
            )
            .bind(list)
            .bind(account)
            .bind(score)
            .bind(stage)
            .bind(i32::try_from(contacts.len()).unwrap_or(i32::MAX))
            .bind(&covered)
            .bind(&missing)
            .bind(now)
            .execute(db)
            .await
            .map_err(AppError::internal)?;
            scored += 1;
        }
    }
    Ok(scored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0)
            .single()
            .unwrap_or_default()
    }

    #[test]
    fn recent_meetings_weigh_most() {
        let recent = (0..6)
            .map(|_| (now() - Duration::days(2), "meeting".to_owned()))
            .collect::<Vec<_>>();
        let old = (0..6)
            .map(|_| (now() - Duration::days(85), "meeting".to_owned()))
            .collect::<Vec<_>>();
        let emails = (0..6)
            .map(|_| (now() - Duration::days(2), "email".to_owned()))
            .collect::<Vec<_>>();
        let (r, o, e) = (
            engagement(&recent, now()),
            engagement(&old, now()),
            engagement(&emails, now()),
        );
        assert!(r > ENGAGED_SCORE, "{r}");
        assert!(o < 10.0 && e < r, "{o} {e} {r}");
        assert_eq!(engagement(&[], now()), 0.0);
    }

    #[test]
    fn coverage_lists_present_and_missing_roles() {
        let roles: HashSet<String> = ["champion".to_owned(), "user".to_owned()].into();
        let (covered, missing) = coverage(&roles);
        assert_eq!(covered, vec!["champion"]);
        assert_eq!(
            missing,
            vec!["decision_maker", "economic_buyer", "technical_buyer"]
        );
    }

    #[test]
    fn stages_only_move_forward() {
        assert_eq!(next_stage("identified", 10.0, 1), "aware");
        assert_eq!(next_stage("identified", 55.0, 3), "engaged");
        assert_eq!(next_stage("opportunity", 0.0, 0), "opportunity");
        assert_eq!(next_stage("engaged", 5.0, 1), "engaged");
    }
}
