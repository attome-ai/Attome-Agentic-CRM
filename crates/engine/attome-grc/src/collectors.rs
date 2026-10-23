//! R11-T1: evidence collectors: checks the platform runs on itself, each
//! writing a `grc_evidence` record and, when it fails, a `grc_finding`.
//!
//! The daily `grc_evidence_collect` job runs every [`Collector`]:
//!
//! - `mfa_policy`: every active administrator has a confirmed second factor;
//! - `admin_count`: between one and `grc.max_admins` (default 5) active
//!   administrators (`system.admin`, granted directly or through a role);
//! - `access_review_completion`: no completed access review campaign has an
//!   access left undecided;
//! - `backup_drill`: the newest restore drill passed and is at most 35 days
//!   old (the drill log is read by the server and passed in, [`Inputs`]);
//! - `audit_verification`: every organization's newest audit chain
//!   verification passed and is at most 8 days old;
//! - `release_version`: records the running version (always passes).
//!
//! Evidence is `reference_kind = audit_query`, `reference_value =
//! collector:<key>`, with the result as JSON in `notes`. A failing collector
//! opens one high-severity finding titled after it; while that finding is
//! still open or in progress no second one is opened. The writes are the
//! engine's own (no person acts); their rows carry no creator.

use attome_core::EngineState;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

/// The registered daily job.
pub const JOB: &str = "grc_evidence_collect";
/// The setting holding the most administrators allowed.
pub const MAX_ADMINS_SETTING: &str = "grc.max_admins";
/// The default most administrators.
pub const DEFAULT_MAX_ADMINS: i64 = 5;
/// How old a restore drill may be.
pub const DRILL_MAX_AGE_DAYS: i64 = 35;
/// How old an audit chain verification may be.
pub const VERIFICATION_MAX_AGE_DAYS: i64 = 8;

/// One evidence collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collector {
    MfaPolicy,
    AdminCount,
    AccessReviewCompletion,
    BackupDrill,
    AuditVerification,
    ReleaseVersion,
}

impl Collector {
    pub const ALL: [Collector; 6] = [
        Self::MfaPolicy,
        Self::AdminCount,
        Self::AccessReviewCompletion,
        Self::BackupDrill,
        Self::AuditVerification,
        Self::ReleaseVersion,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::MfaPolicy => "mfa_policy",
            Self::AdminCount => "admin_count",
            Self::AccessReviewCompletion => "access_review_completion",
            Self::BackupDrill => "backup_drill",
            Self::AuditVerification => "audit_verification",
            Self::ReleaseVersion => "release_version",
        }
    }
}

/// What the server passes the collectors that the engine cannot read.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// The newest restore drill: when, whether it passed, and its detail.
    pub last_drill: Option<(DateTime<Utc>, bool, String)>,
    /// The running release.
    pub release_version: String,
}

/// One collector's result.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub collector: Collector,
    pub passed: bool,
    pub summary: String,
    pub details: Value,
}

/// `admin_count`'s verdict. Pure.
pub fn admins_ok(admins: i64, max: i64) -> bool {
    admins >= 1 && admins <= max
}

/// `backup_drill`'s verdict. Pure.
pub fn drill_ok(last: Option<&(DateTime<Utc>, bool, String)>, now: DateTime<Utc>) -> bool {
    last.is_some_and(|(at, passed, _)| *passed && now - *at <= Duration::days(DRILL_MAX_AGE_DAYS))
}

/// `audit_verification`'s verdict over each organization's newest
/// verification. Pure.
pub fn verifications_ok(newest: &[(DateTime<Utc>, bool)], now: DateTime<Utc>) -> bool {
    !newest.is_empty()
        && newest
            .iter()
            .all(|(at, ok)| *ok && now - *at <= Duration::days(VERIFICATION_MAX_AGE_DAYS))
}

const ADMINS: &str = "SELECT u.id FROM user_account u \
    WHERE u.is_active AND ( \
      EXISTS (SELECT 1 FROM user_account_mm_privilege up \
                JOIN privilege p ON p.id = up.privilege_ref \
               WHERE up.user_ref = u.id AND up.is_active AND p.key = 'system.admin') \
      OR EXISTS (SELECT 1 FROM user_account_mm_role ur \
                   JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref AND NOT rp.is_deleted \
                   JOIN privilege p ON p.id = rp.privilege_ref \
                  WHERE ur.user_ref = u.id AND NOT ur.is_deleted AND p.key = 'system.admin'))";

fn max_admins(state: &EngineState) -> i64 {
    attome_core::setting_registry()
        .get(MAX_ADMINS_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_MAX_ADMINS)
}

async fn run_one(
    state: &EngineState,
    collector: Collector,
    inputs: &Inputs,
    now: DateTime<Utc>,
) -> Result<Outcome, AppError> {
    let db = &state.base.db;
    let (passed, summary, details) = match collector {
        Collector::MfaPolicy => {
            let without: i64 = sqlx::query_scalar(&format!(
                "SELECT count(*) FROM ({ADMINS}) a \
                  WHERE NOT EXISTS (SELECT 1 FROM user_mfa m \
                                     WHERE m.user_ref = a.id AND NOT m.is_deleted \
                                       AND m.confirmed_at IS NOT NULL)"
            ))
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            (
                without == 0,
                format!("{without} administrator(s) without a confirmed second factor"),
                json!({ "administrators_without_mfa": without }),
            )
        }
        Collector::AdminCount => {
            let admins: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM ({ADMINS}) a"))
                .fetch_one(db)
                .await
                .map_err(AppError::internal)?;
            let max = max_admins(state);
            (
                admins_ok(admins, max),
                format!("{admins} active administrator(s), at most {max} allowed"),
                json!({ "administrators": admins, "max": max }),
            )
        }
        Collector::AccessReviewCompletion => {
            let undecided: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM access_review_item i \
                   JOIN access_review r ON r.id = i.review_ref \
                  WHERE r.status = 'completed' AND NOT r.is_deleted AND i.decision IS NULL",
            )
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            (
                undecided == 0,
                format!("{undecided} access(es) left undecided in completed campaigns"),
                json!({ "undecided": undecided }),
            )
        }
        Collector::BackupDrill => {
            let ok = drill_ok(inputs.last_drill.as_ref(), now);
            let details = match &inputs.last_drill {
                Some((at, passed, detail)) => {
                    json!({ "at": at, "passed": passed, "detail": detail })
                }
                None => json!({ "at": null }),
            };
            let summary = match &inputs.last_drill {
                Some((at, passed, _)) => format!(
                    "newest restore drill {} on {}",
                    if *passed { "passed" } else { "failed" },
                    at.date_naive()
                ),
                None => "no restore drill recorded".to_owned(),
            };
            (ok, summary, details)
        }
        Collector::AuditVerification => {
            let newest: Vec<(DateTime<Utc>, bool)> = sqlx::query_as(
                "SELECT DISTINCT ON (organization_ref) verified_at, ok \
                   FROM audit_chain_verification \
                  ORDER BY organization_ref, verified_at DESC",
            )
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            let failing = newest.iter().filter(|(_, ok)| !ok).count();
            (
                verifications_ok(&newest, now),
                format!(
                    "{} organization(s) verified, {failing} with errors",
                    newest.len()
                ),
                json!({ "organizations": newest.len(), "failing": failing }),
            )
        }
        Collector::ReleaseVersion => (
            true,
            format!("running release {}", inputs.release_version),
            json!({ "version": inputs.release_version }),
        ),
    };
    Ok(Outcome {
        collector,
        passed,
        summary,
        details,
    })
}

async fn record(db: &DbPool, outcome: &Outcome) -> Result<bool, AppError> {
    let key = outcome.collector.key();
    let notes = json!({
        "collector": key,
        "passed": outcome.passed,
        "summary": outcome.summary,
        "details": outcome.details,
    });
    sqlx::query(
        "INSERT INTO grc_evidence (id, reference_kind, reference_value, collected_at, notes, \
                                   is_active) \
         VALUES (uuidv7(), 'audit_query', $1, now(), $2, true)",
    )
    .bind(format!("collector:{key}"))
    .bind(notes.to_string())
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    if outcome.passed {
        return Ok(false);
    }
    let title = format!("Evidence check failed: {key}");
    let opened = sqlx::query(
        "INSERT INTO grc_finding (id, title, severity, remediation, status, is_active) \
         SELECT uuidv7(), $1, 'high', $2, 'open', true \
          WHERE NOT EXISTS (SELECT 1 FROM grc_finding \
                             WHERE title = $1 AND status::text IN ('open', 'in_progress') \
                               AND (is_active IS NULL OR is_active = true))",
    )
    .bind(&title)
    .bind(&outcome.summary)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    Ok(opened == 1)
}

/// What one collection run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CollectionRun {
    pub collected: usize,
    pub failed: usize,
    pub findings_opened: usize,
}

/// Runs every collector, writing its evidence and, on failure, its finding.
/// A deployment without the GRC entities does nothing.
pub async fn collect(state: &EngineState, inputs: &Inputs) -> Result<CollectionRun, AppError> {
    let db = &state.base.db;
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('grc_evidence') IS NOT NULL AND to_regclass('grc_finding') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(CollectionRun::default());
    }
    let now = Utc::now();
    let mut run = CollectionRun::default();
    for collector in Collector::ALL {
        match run_one(state, collector, inputs, now).await {
            Ok(outcome) => {
                run.collected += 1;
                if !outcome.passed {
                    run.failed += 1;
                }
                if record(db, &outcome).await? {
                    run.findings_opened += 1;
                }
            }
            Err(e) => {
                tracing::warn!(collector = collector.key(), error = %e, "evidence collector failed to run");
            }
        }
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collector_admin_count_needs_one_to_max() {
        assert!(!admins_ok(0, 5));
        assert!(admins_ok(1, 5));
        assert!(admins_ok(5, 5));
        assert!(!admins_ok(6, 5));
    }

    #[test]
    fn collector_backup_drill_must_be_recent_and_passed() {
        let now = Utc::now();
        assert!(!drill_ok(None, now));
        assert!(drill_ok(
            Some(&(now - Duration::days(3), true, String::new())),
            now
        ));
        assert!(!drill_ok(
            Some(&(now - Duration::days(3), false, String::new())),
            now
        ));
        assert!(!drill_ok(
            Some(&(now - Duration::days(40), true, String::new())),
            now
        ));
    }

    #[test]
    fn collector_audit_verification_covers_every_organization() {
        let now = Utc::now();
        assert!(!verifications_ok(&[], now), "never verified");
        assert!(verifications_ok(&[(now - Duration::days(1), true)], now));
        assert!(!verifications_ok(
            &[(now - Duration::days(1), true), (now, false)],
            now
        ));
        assert!(!verifications_ok(&[(now - Duration::days(9), true)], now));
    }

    #[test]
    fn collector_keys_are_distinct() {
        let keys: std::collections::BTreeSet<&str> =
            Collector::ALL.iter().map(|c| c.key()).collect();
        assert_eq!(keys.len(), Collector::ALL.len());
    }
}
