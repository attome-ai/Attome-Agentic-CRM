//! Confirms `attome_dashboard::seed::seed` satisfies the same fresh-boot
//! invariants `crates/server/tests/fresh_bootstrap.rs`'s generic loops check
//! for every registered entity: a default list view (or the admin list
//! 404s, D-036) and all five `{logicalname}.{action}` privilege rows (or a
//! late-registered entity picks up privileges only on a second boot). Same
//! shape as `attome-project/tests/seed.rs`/`attome-service`'s own seed test.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

mod common;

const DASHBOARD_ENTITIES: &[&str] = &[
    "attome_dashboard",
    "dashboard_version",
    "dashboard_page",
    "dashboard_section",
    "dashboard_section_breakpoint",
    "dashboard_widget",
    "dashboard_variable",
    "dashboard_parameter",
];

#[tokio::test]
async fn every_entity_gets_a_default_view_and_full_privilege_set() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state);
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    // The 8 `attome_dashboard*` entities/views moved to `platform-bundles/
    // attome-dashboard.json` (D-478), applied at boot by `bundle::
    // apply_platform_bundle` before `attome_dashboard::seed::seed` runs
    // (system.rs) — this bare-`DbPool` fixture has no equivalent, so
    // `seed_for_tests` walks the bundle directly first.
    attome_metric::metric::seed_for_tests(db)
        .await
        .expect("attome_metric::metric::seed_for_tests");
    attome_dashboard::seed::seed_for_tests(db)
        .await
        .expect("attome_dashboard::seed::seed_for_tests");
    // `seed_body` (not `seed`) — calling `seed()` twice would only prove the
    // seed-gate watermark short-circuits the second call, not that the body
    // itself is idempotent (M26 R-08).
    attome_dashboard::seed::seed_body(db)
        .await
        .expect("attome_dashboard::seed::seed_body");
    // Idempotency — a second call must be a pure no-op, same invariant every
    // other engine's seed carries.
    attome_dashboard::seed::seed_body(db)
        .await
        .expect("attome_dashboard::seed::seed_body (second call, must be idempotent)");
    // The real entry point, once — this is what actually writes the
    // seed-gate watermark row the assertion below reads. `seed_body`'s two
    // direct calls above never touch `seed_watermark`.
    attome_dashboard::seed::seed(db)
        .await
        .expect("attome_dashboard::seed::seed");
    attome_security::entity_privileges::seed_all(db)
        .await
        .expect("attome_security::entity_privileges::seed_all");

    // M26 R-08 — the watermark is `SEED_VERSION` plus a hash of the widget
    // registry's `type_id`s, not the bare human version, so registering a
    // new widget type re-runs the residual seed without a manual bump.
    let watermark_version: String =
        sqlx::query_scalar("SELECT version FROM seed_watermark WHERE module = $1")
            .bind("attome-dashboard-residual")
            .fetch_one(db)
            .await
            .expect("read seed_watermark for attome-dashboard-residual");
    assert!(
        watermark_version.starts_with(attome_dashboard::seed::SEED_VERSION),
        "watermark {watermark_version:?} should start with SEED_VERSION {:?}",
        attome_dashboard::seed::SEED_VERSION
    );
    assert!(
        watermark_version.len() > attome_dashboard::seed::SEED_VERSION.len(),
        "watermark {watermark_version:?} should be longer than the bare \
         SEED_VERSION {:?} — the hash suffix is missing",
        attome_dashboard::seed::SEED_VERSION
    );

    for logicalname in DASHBOARD_ENTITIES {
        let registered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM entity_info \
             WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true))",
        )
        .bind(logicalname)
        .fetch_one(db)
        .await
        .expect("read entity_info");
        assert!(registered, "{logicalname} must be registered after seed()");

        let has_view: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sql_query q \
               JOIN entity_info e ON e.id = q.entity_logical_name \
              WHERE e.logicalname = $1 AND q.required_privilege IS NOT NULL \
                AND (q.is_active IS NULL OR q.is_active = true))",
        )
        .bind(logicalname)
        .fetch_one(db)
        .await
        .expect("read default views");
        assert!(
            has_view,
            "{logicalname} has no default view — its admin list would 404 (D-036)"
        );

        for action in ["read", "create", "update", "delete", "bulk"] {
            let key = format!("{logicalname}.{action}");
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM privilege WHERE key = $1)")
                    .bind(&key)
                    .fetch_one(db)
                    .await
                    .expect("read privileges");
            assert!(exists, "privilege {key} missing");
        }
    }
}
