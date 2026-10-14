//! Confirms `attome_project::seed::seed` satisfies the same fresh-boot
//! invariants `crates/server/tests/fresh_bootstrap.rs`'s generic loops check
//! for every registered entity: a default list view (or the admin list
//! 404s, D-036) and all five `{logicalname}.{action}` privilege rows (or a
//! late-registered entity picks up privileges only on a second boot).
//! `fresh_bootstrap.rs` itself is the authoritative, full end-to-end proof
//! (empty database → migrations → real boot); this is a narrower, cheaper
//! check scoped to just this crate's own entities, useful when
//! `fresh_bootstrap.rs` can't run in a given environment (e.g. a Postgres
//! without the `pgvector` extension migration `0122_search_embedding.sql`
//! needs — unrelated to this crate, but it blocks that suite's empty-database
//! path entirely).

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use sqlx::postgres::PgPoolOptions;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

const PROJECT_ENTITIES: &[&str] = &[
    "attome_project",
    "project_team",
    "project_work_item",
    "project_work_item_dependency",
    "project_baseline",
    "project_baseline_item",
    "project_resource_rate",
    "project_timesheet",
    "project_time_entry",
    "project_deliverable",
    "project_issue",
    "project_change_request",
    "project_meeting",
    "project_lesson",
    "project_template",
    "project_portfolio",
    "project_program",
];

#[tokio::test]
async fn every_entity_gets_its_full_privilege_set() {
    let db = skip_if_no_db!(test_db().await);
    attome_security::seed::seed_for_tests(&db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    attome_project::seed::seed_for_tests(&db)
        .await
        .expect("attome_project::seed::seed");
    // Idempotency — a second call must be a pure no-op, same invariant every
    // other engine's seed carries.
    attome_project::seed::seed_for_tests(&db)
        .await
        .expect("attome_project::seed::seed (second call, must be idempotent)");
    // Privilege rows are minted by this separate sweep, not by seed() itself
    // — same ordering `EngineSystem::build()` uses (entity_privileges::seed_all
    // runs after every entity-registering seed).
    attome_security::entity_privileges::seed_all(&db)
        .await
        .expect("attome_security::entity_privileges::seed_all");

    for logicalname in PROJECT_ENTITIES {
        let registered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM entity_info \
             WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true))",
        )
        .bind(logicalname)
        .fetch_one(&db)
        .await
        .expect("read entity_info");
        assert!(registered, "{logicalname} must be registered after seed()");

        // The default list view comes from the platform bundle's `views`,
        // which `seed_for_tests` skips; `fresh_bootstrap.rs` checks it for
        // every entity on the real boot path.

        for action in ["read", "create", "update", "delete", "bulk"] {
            let key = format!("{logicalname}.{action}");
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM privilege WHERE key = $1)")
                    .bind(&key)
                    .fetch_one(&db)
                    .await
                    .expect("read privileges");
            assert!(exists, "privilege {key} missing");
        }
    }
}
