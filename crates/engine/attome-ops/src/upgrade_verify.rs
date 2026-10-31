//! AB8-T7: what `attome upgrade apply` proves after a restart, and the signed
//! `attome-evidence/v1` report of it. The command gathers the answers; each
//! one becomes a [`Check`] here, so a pass means the same to every caller.

use attome_db::DbPool;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::evidence::{Check, CheckResult, Evidence, EvidenceKind, SCHEMA};

fn check(name: &str, passed: bool, detail: String) -> Check {
    Check {
        name: name.to_owned(),
        result: if passed {
            CheckResult::Pass
        } else {
            CheckResult::Fail
        },
        detail: Some(detail),
    }
}

/// The ledger holds what the manifest promises, and nothing failed partway.
/// Pure.
pub fn migration_check(applied: i64, unfinished: i64, expected: u32) -> Check {
    check(
        "migrations",
        applied == i64::from(expected) && unfinished == 0,
        format!("{applied} applied, {unfinished} unfinished, {expected} expected"),
    )
}

/// The audit chain's verifier ran and found it intact. Pure.
pub fn audit_chain_check(outcome: Result<(), String>) -> Check {
    match outcome {
        Ok(()) => check("audit_chain", true, "intact".to_owned()),
        Err(detail) => check("audit_chain", false, detail),
    }
}

/// A read of each entity's first page: a server error fails it, and a hidden
/// entity (401, 403 or 404) is the licence or the key, not the upgrade. Pure.
pub fn sample_read_check(reads: &[(String, u16)]) -> Check {
    let broken: Vec<&str> = reads
        .iter()
        .filter(|(_, status)| *status >= 500)
        .map(|(entity, _)| entity.as_str())
        .collect();
    let detail = if broken.is_empty() {
        format!("{} entities read", reads.len())
    } else {
        format!(
            "{} of {} failed: {}",
            broken.len(),
            reads.len(),
            broken.join(", ")
        )
    };
    check(
        "sample_reads",
        !reads.is_empty() && broken.is_empty(),
        detail,
    )
}

/// A key with no roles is still refused an admin route. Pure.
pub fn permission_check(status: u16) -> Check {
    check(
        "permission",
        status == 403,
        format!("GET /api/v1/admin/api-usage/summary answered {status}, 403 expected"),
    )
}

/// The live metadata matches the applied bundle; a deployment that never
/// applied one has nothing to differ from. Pure.
pub fn metadata_check(status: u16, report: &Value) -> Check {
    let clean = status == 200
        && (report["drift"].is_null() || report["drift"]["clean"].as_bool() == Some(true));
    check("metadata", clean, format!("drift report answered {status}"))
}

/// Sampled sealed values open under the configured key. Pure.
pub fn decrypt_check(opened: usize, failed: usize) -> Check {
    check(
        "decrypt",
        failed == 0,
        format!("{opened} sealed values opened, {failed} did not"),
    )
}

/// The ledger's applied count and its unfinished rows. `sqlx` records a
/// migration before it runs, so `success = false` is one that stopped.
pub async fn migration_ledger(db: &DbPool) -> Result<(i64, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE success), count(*) FILTER (WHERE NOT success) \
           FROM _sqlx_migrations",
    )
    .fetch_one(db)
    .await
}

/// The report of a verification, named after the upgrade it proves. Pure.
pub fn evidence(
    upgrade: Uuid,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    version: &str,
    checks: Vec<Check>,
) -> Evidence {
    let mut report = Evidence {
        schema: SCHEMA.to_owned(),
        kind: EvidenceKind::Upgrade,
        drill_id: upgrade,
        started_at,
        finished_at,
        platform_version: version.to_owned(),
        image_digest: None,
        deployment_id: None,
        checks,
        rpo_seconds: None,
        rto_seconds: None,
        data_size_bytes: None,
        restore_ok: false,
        provenance_ok: false,
        overall_ok: false,
        extra: Map::new(),
    };
    report.compute_overall();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn failed(check: &Check) -> bool {
        check.result == CheckResult::Fail
    }

    #[test]
    fn migrations_must_match_and_none_may_be_unfinished() {
        assert!(!failed(&migration_check(412, 0, 412)));
        assert!(failed(&migration_check(411, 0, 412)));
        assert!(failed(&migration_check(413, 0, 412)));
        assert!(failed(&migration_check(412, 1, 412)));
    }

    #[test]
    fn a_server_error_fails_sample_reads_and_a_hidden_entity_does_not() {
        let reads = [("account".to_owned(), 200), ("grc".to_owned(), 403)];
        assert!(!failed(&sample_read_check(&reads)));
        let broken = [("account".to_owned(), 500)];
        let result = sample_read_check(&broken);
        assert!(failed(&result));
        assert!(result.detail.expect("detail").contains("account"));
        assert!(
            failed(&sample_read_check(&[])),
            "nothing read proves nothing"
        );
    }

    #[test]
    fn only_a_403_passes_the_permission_check() {
        assert!(!failed(&permission_check(403)));
        assert!(failed(&permission_check(200)));
        assert!(failed(&permission_check(401)));
        assert!(failed(&permission_check(500)));
    }

    #[test]
    fn drifted_metadata_fails() {
        assert!(!failed(&metadata_check(200, &json!({ "drift": null }))));
        assert!(!failed(&metadata_check(
            200,
            &json!({ "drift": { "clean": true } })
        )));
        assert!(failed(&metadata_check(
            200,
            &json!({ "drift": { "clean": false } })
        )));
        assert!(failed(&metadata_check(500, &json!({ "drift": null }))));
    }

    #[test]
    fn one_failed_check_fails_the_evidence() {
        let now = Utc::now();
        let good = vec![permission_check(403), decrypt_check(3, 0)];
        assert!(evidence(Uuid::nil(), now, now, "2.3.0", good).overall_ok);
        let bad = vec![permission_check(403), decrypt_check(3, 1)];
        let report = evidence(Uuid::nil(), now, now, "2.3.0", bad);
        assert!(!report.overall_ok);
        assert_eq!(report.kind, EvidenceKind::Upgrade);
    }
}
