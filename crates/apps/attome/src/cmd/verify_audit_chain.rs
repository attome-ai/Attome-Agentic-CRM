//! P-backup-immutability (D-115) — standalone CLI wrapper around
//! `attome_audit::verify::verify_chain`, built specifically so
//! `scripts/backup/restore-drill.sh` has something to run against a
//! restored-but-otherwise-unbooted database: the drill boots the `server`
//! image itself to prove `/health/ready` (migrations + registry pre-warm),
//! and separately boots *this* bin to prove the audit hash chain the
//! restored database carries is actually intact — a restore that "boots
//! fine" but silently carries a broken/tampered chain is exactly the kind
//! of gap a shallow row-count drill (the pre-P-backup-immutability version
//! of restore-drill.sh) would never catch.
//!
//! Deliberately a separate bin from `audit_chainer` (which is a long-running
//! daemon) and from `server` itself (which never runs ad hoc CLI checks) —
//! same "one process, one job" reasoning as every other bin in this crate.
//! Connects directly with `attome_db::create_pool`, same as `audit_chainer`;
//! never touches `EngineState` (no metadata registry, no license, no HTTP).
//!
//! ```powershell
//! $env:APP_ENV = "debug"
//! cargo run --manifest-path crates/server/Cargo.toml --bin verify_audit_chain
//! # or, scoped to specific orgs:
//! cargo run --manifest-path crates/server/Cargo.toml --bin verify_audit_chain -- <org-uuid> [<org-uuid> ...]
//! ```
//!
//! P-audit-chain-hardening item (c), D-280: the same `storage` client also
//! lets `verify_chain_with_anchors` bridge a chain whose oldest remaining
//! batch isn't this org's true genesis (e.g. an old partition was dropped
//! once its calendar-month epoch was sealed) — it checks the sealed epoch's
//! externally anchored root instead of requiring the dropped rows to still
//! exist. Falls back to `external_anchoring_enabled`'s ordinary "no store,
//! no bridging" behavior when that's off, same as every other anchoring
//! path in this bin.
//!
//! P-audit-chain-hardening item (b): when `audit.external_anchoring_enabled`
//! is true, each organization's report also carries an `"anchor_check"`
//! object (`attome_audit::verify::verify_anchors`) cross-checking every
//! batch's `audit_chain_batch.merkle_root` against its externally
//! anchored copy — independent of trusting anything else read from this
//! deployment's own Postgres. A real mismatch fails the run; a batch with
//! no anchor on record (`"unanchored"`) does not, since that's expected for
//! any batch written before anchoring was enabled.
//!
//! **`--reanchor` (external feedback item 18, "document recovery from a
//! failed anchoring attempt"):** pass this flag to also back-fill every
//! batch `anchor_check.unanchored` names, via `attome_audit::anchor::
//! reanchor_batch` (idempotent — safe even if some of those batches'
//! original attempt actually succeeded and this is a redundant retry). Only
//! runs when a storage client was actually built (`external_anchoring_enabled`
//! true and reachable); each org's report gains a `"reanchored"` count and a
//! `"reanchor_failures"` array. This is the operator recovery path for a
//! batch whose one automatic anchoring attempt (best-effort, never retried
//! by the chainer itself — see `attome_audit::anchor`'s module doc) failed:
//!
//! ```powershell
//! cargo run --manifest-path crates/server/Cargo.toml --bin verify_audit_chain -- --reanchor
//! # or, scoped to specific orgs:
//! cargo run --manifest-path crates/server/Cargo.toml --bin verify_audit_chain -- --reanchor <org-uuid>
//! ```
//!
//! Output: one JSON object on stdout (`{"organizations_checked", "reports",
//! "ok"}`) — machine-parseable for the drill's evidence-file emission.
//! Exit code 0 when every checked organization's chain verifies clean AND at
//! least one organization was actually checked; exit code 1 on any chain
//! error, any DB/connection failure, or zero organizations found (a restored
//! database with literally nothing to verify is not proof the mechanism
//! works — the drill should treat that as a setup problem, not a pass). A
//! `--reanchor` failure on some batches does NOT by itself fail the run —
//! `reanchor_failures` is reported for visibility so an operator can retry,
//! consistent with anchoring being a best-effort, degrade-not-fail concern
//! (D-027) even when triggered manually.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use attome_config::AppConfig;
use attome_core::AuditSigner;
use futures_util::StreamExt;
use serde_json::json;
use uuid::Uuid;

#[tokio::main]
pub async fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    std::process::exit(verify().await);
}

async fn verify() -> i32 {
    let config = match AppConfig::from_file() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("verify_audit_chain: config load failed: {e}");
            return 1;
        }
    };
    if let Err(e) = config.validate() {
        eprintln!("verify_audit_chain: config validation failed: {e}");
        return 1;
    }
    // BCF-10 — one WARN per unknown config key, never a boot failure (BCF-D4).
    if let Err(e) = attome::boot::report_ignored_config_keys(&config, false) {
        eprintln!("verify_audit_chain: {e}");
        return 1;
    }

    let db = match attome_db::create_pool(&config).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("verify_audit_chain: could not connect to Postgres: {e}");
            return 1;
        }
    };
    // BDB-F10 / OD-6: this bin exists to certify a restored database's chain,
    // so it must refuse to certify one it is not actually connected to. The
    // drill treats a wrong identity as a failed restore, not a pass.
    let (expected_user, expected_dbname) = attome::boot::expected_runtime_identity(&config);
    if let Err(e) = attome_db::verify_pool_identity(&db, expected_user, expected_dbname).await {
        eprintln!("verify_audit_chain: pool identity check failed: {e}");
        return 1;
    }

    let signer = if config.audit.signing_enabled {
        match AuditSigner::from_config(
            &config.audit.signing_key_id,
            &config.audit.signing_private_key,
        ) {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!("verify_audit_chain: could not construct audit signer: {e}");
                return 1;
            }
        }
    } else {
        None
    };

    let args: Vec<String> = std::env::args().skip(2).collect();
    let reanchor = args.iter().any(|a| a == "--reanchor");
    let requested: Vec<Uuid> = args
        .iter()
        .filter_map(|a| Uuid::parse_str(a).ok())
        .collect();

    let orgs = if !requested.is_empty() {
        requested
    } else {
        match discover_organizations(&db).await {
            Ok(orgs) => orgs,
            Err(e) => {
                eprintln!("verify_audit_chain: could not enumerate organizations: {e}");
                return 1;
            }
        }
    };

    if orgs.is_empty() {
        eprintln!(
            "verify_audit_chain: no organizations found (checked organization and \
             audit_header) — nothing to verify. Treated as FAIL: a restore drill that \
             checks nothing proves nothing."
        );
        println!(
            "{}",
            json!({"organizations_checked": 0, "reports": [], "ok": false})
        );
        return 1;
    }

    // P-audit-chain-hardening item (b) — construction only when the
    // deployment actually anchors (`create_storage_client` never dials the
    // endpoint either way, but there is no point building a client this
    // bin will never use). A store that IS configured but unreachable
    // surfaces per-organization below as an anchor-check error, not a
    // whole-bin failure — an anchoring outage degrades the external
    // guarantee, not the in-database one this bin already checks via
    // `verify_chain` (same D-027 posture as `chainer::anchor_root`).
    // D-352: resolves to the dedicated append-only `audit.anchor_store` when
    // one is configured (required in production), the general storage bucket
    // otherwise — the same resolution `audit_chainer` writes through, so this
    // bin can never cross-check a different bucket than the one anchors
    // actually landed in.
    let storage = if config.audit.external_anchoring_enabled {
        match attome_audit::anchor::create_anchor_store(&config).await {
            Ok(s) => Some(s),
            Err(e) => {
                eprintln!(
                    "verify_audit_chain: audit.external_anchoring_enabled is true but the \
                     anchor storage client could not be built: {e} — skipping anchor \
                     cross-checks, in-database chain verification below is unaffected"
                );
                None
            }
        }
    } else {
        None
    };

    // Bounded-concurrency fan-out (buffer_unordered), not a sequential loop —
    // real bug found live 2026-08-06 running a production-sized restore
    // drill against 1,000,001 organizations: one org at a time took ~23
    // minutes end to end for what's individually a cheap per-org check.
    // Bound is the same connection_number this bin's own pool was built
    // with (attome_db::create_pool above), so this can never out-run the
    // connections actually available to serve it.
    let concurrency = (config.database.connection_number as usize).max(1);
    let signer_ref = signer.as_ref();
    let storage_ref = storage.as_ref();
    let results: Vec<(serde_json::Value, bool)> = fan_out(orgs, concurrency, |org| {
        let db = &db;
        async move {
            match attome_audit::verify::verify_chain_with_anchors(db, signer_ref, storage_ref, org)
                .await
            {
                Ok(report) => {
                    let mut ok = report.is_ok();
                    let mut report_json = json!({
                        "organization_ref": report.organization_ref,
                        "headers_checked": report.headers_checked,
                        "batches_checked": report.batches_checked,
                        "pending_ingest": report.pending_ingest,
                        "lag_seconds": report.lag_seconds,
                        // D-539 / audit plan Phase 2: which hash formula and
                        // clock each row carries, whether pre-v2 content is
                        // frozen by the v1 cutover checkpoint, which v2
                        // batches' anchor time bound could not be read
                        // (unknown, never passed), and how far ingest was
                        // pruned (item 2.8).
                        "v1_headers": report.v1_headers,
                        "v2_headers": report.v2_headers,
                        "anchor_time_checked_batches": report.anchor_time_checked_batches,
                        "anchor_time_unknown_batches": report.anchor_time_unknown_batches,
                        "v1_content_protection": report.v1_content_protection.as_str(),
                        "v1_checkpoint_partitions_dropped": report.v1_checkpoint_partitions_dropped,
                        "ingest_pruned_through": report.ingest_pruned_through,
                        "ingest_pruned_batches": report.ingest_pruned_batches,
                        "errors": report.errors,
                        "ok": report.is_ok(),
                    });

                    if let Some(store) = storage_ref {
                        match attome_audit::verify::verify_anchors(db, store, org).await {
                            Ok(anchor_report) => {
                                if !anchor_report.is_ok() {
                                    ok = false;
                                }

                                // External feedback item 18 — back-fill exactly
                                // the batches this check just flagged as never
                                // anchored, one reanchor_batch call each. Never
                                // touches `mismatches` (a real tamper signal, not
                                // a "missing" one) — reanchoring would silently
                                // overwrite the one piece of evidence a mismatch
                                // needs preserved.
                                let mut reanchored = 0u32;
                                let mut reanchor_failures = Vec::new();
                                if reanchor {
                                    for batch_id in &anchor_report.unanchored {
                                        match attome_audit::anchor::reanchor_batch(
                                            db, store, org, *batch_id,
                                        )
                                        .await
                                        {
                                            Ok(()) => reanchored += 1,
                                            Err(e) => reanchor_failures.push(json!({
                                                "batch_id": batch_id,
                                                "error": e.to_string(),
                                            })),
                                        }
                                    }
                                }

                                report_json["anchor_check"] = json!({
                                    "batches_checked": anchor_report.batches_checked,
                                    "unanchored": anchor_report.unanchored,
                                    "mismatches": anchor_report.mismatches,
                                    "ok": anchor_report.is_ok(),
                                    "reanchored": reanchored,
                                    "reanchor_failures": reanchor_failures,
                                });
                            }
                            Err(e) => {
                                // A failed *check* (e.g. the store went
                                // unreachable mid-run) is not the same as a
                                // *mismatch* — do not fail the drill over an
                                // infrastructure hiccup in the external check,
                                // only over actual disagreeing roots.
                                report_json["anchor_check"] = json!({
                                    "ok": false,
                                    "error": format!("verify_anchors call failed: {e}"),
                                });
                            }
                        }
                    }

                    (report_json, ok)
                }
                Err(e) => (
                    json!({
                        "organization_ref": org,
                        "ok": false,
                        "errors": [format!("verify_chain call failed: {e}")],
                    }),
                    false,
                ),
            }
        }
    })
    .await;

    let mut all_ok = true;
    let mut reports = Vec::with_capacity(results.len());
    for (report_json, ok) in results {
        if !ok {
            all_ok = false;
        }
        reports.push(report_json);
    }

    println!(
        "{}",
        json!({"organizations_checked": reports.len(), "reports": reports, "ok": all_ok})
    );

    if all_ok { 0 } else { 1 }
}

/// The bounded-concurrency fan-out itself (bc1f034's fix for the O(n)
/// sequential-loop bug), pulled out of `run()` so it's generic over
/// `verify_one` and testable without a database — see `mod tests` below.
async fn fan_out<F, Fut>(
    orgs: Vec<Uuid>,
    concurrency: usize,
    verify_one: F,
) -> Vec<(serde_json::Value, bool)>
where
    F: Fn(Uuid) -> Fut,
    Fut: std::future::Future<Output = (serde_json::Value, bool)>,
{
    futures_util::stream::iter(orgs)
        .map(verify_one)
        .buffer_unordered(concurrency)
        .collect()
        .await
}

/// `organization` is the authoritative source when populated; a scratch
/// restore-drill database that never seeded it (or one restored from a point
/// before any org row existed) still has audit rows to check, so this falls
/// back to the distinct `organization_ref` values `audit_header` itself
/// carries — a real, if unlabeled, organization.
async fn discover_organizations(db: &attome_db::DbPool) -> Result<Vec<Uuid>, sqlx::Error> {
    let from_orgs: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM organization")
        .fetch_all(db)
        .await?;
    if !from_orgs.is_empty() {
        return Ok(from_orgs);
    }

    sqlx::query_scalar(
        "SELECT DISTINCT organization_ref FROM audit_header WHERE organization_ref IS NOT NULL",
    )
    .fetch_all(db)
    .await
}

// Run 2026-08-12 (TODO-029): `cargo test -p server --bin verify_audit_chain
// fan_out_` — 3 passed, 0 failed. The note that used to sit here said these
// tests had never been compiled or run because the environment had no Rust
// toolchain; that stopped being true, and an unrun test is worth less than no
// test because it reads like coverage.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Regression test for bc1f034: the sequential per-org loop that took
    /// ~23 minutes against 1,000,001 orgs was replaced with this
    /// `buffer_unordered` fan-out. Guards against a future "simplification"
    /// silently dropping or duplicating orgs under concurrent completion.
    #[tokio::test]
    async fn fan_out_loses_no_orgs_and_duplicates_none() {
        let orgs: Vec<Uuid> = (0..200).map(|_| Uuid::new_v4()).collect();
        let expected = {
            let mut v = orgs.clone();
            v.sort();
            v
        };

        let results = fan_out(orgs, 16, |org| async move {
            (json!({"organization_ref": org}), true)
        })
        .await;

        assert_eq!(results.len(), expected.len());
        let mut seen: Vec<Uuid> = results
            .iter()
            .map(|(v, _)| serde_json::from_value::<Uuid>(v["organization_ref"].clone()).unwrap())
            .collect();
        seen.sort();
        assert_eq!(seen, expected);
    }

    /// The fix's whole point was bounding concurrency to the pool's
    /// `connection_number` instead of running every org at once — assert the
    /// bound is actually respected, not just that results eventually arrive.
    #[tokio::test]
    async fn fan_out_never_exceeds_the_configured_concurrency() {
        let orgs: Vec<Uuid> = (0..60).map(|_| Uuid::new_v4()).collect();
        let concurrency = 5usize;
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));

        let in_flight_for_closure = in_flight.clone();
        let max_in_flight_for_closure = max_in_flight.clone();
        let results = fan_out(orgs, concurrency, move |org| {
            let in_flight = in_flight_for_closure.clone();
            let max_in_flight = max_in_flight_for_closure.clone();
            async move {
                let current = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_flight.fetch_max(current, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                (json!({"organization_ref": org}), true)
            }
        })
        .await;

        assert_eq!(results.len(), 60);
        assert!(
            max_in_flight.load(Ordering::SeqCst) <= concurrency,
            "fan-out ran {} concurrently, exceeding the configured bound of {}",
            max_in_flight.load(Ordering::SeqCst),
            concurrency
        );
    }

    /// A single failing org's `ok: false` must survive interleaving with many
    /// succeeding orgs under `buffer_unordered` — the aggregation in `run()`
    /// trusts this per-item result, not just the count.
    #[tokio::test]
    async fn fan_out_preserves_a_single_failure_among_many_successes() {
        let failing_org = Uuid::new_v4();
        let mut orgs: Vec<Uuid> = (0..30).map(|_| Uuid::new_v4()).collect();
        orgs.push(failing_org);

        let results = fan_out(orgs, 8, move |org| async move {
            let ok = org != failing_org;
            (json!({"organization_ref": org, "ok": ok}), ok)
        })
        .await;

        assert_eq!(results.len(), 31);
        let failure_count = results.iter().filter(|(_, ok)| !*ok).count();
        assert_eq!(
            failure_count, 1,
            "expected exactly one failing org to survive the fan-out"
        );

        let failing_result_ok = results
            .iter()
            .find(|(v, _)| v["organization_ref"] == json!(failing_org))
            .map(|(_, ok)| *ok);
        assert_eq!(failing_result_ok, Some(false));
    }
}
