//! Confirms `attome_service::seed::seed` satisfies the same fresh-boot
//! invariants `crates/server/tests/fresh_bootstrap.rs`'s generic loops check
//! for every registered entity: a default list view (or the admin list
//! 404s, D-036) and all five `{logicalname}.{action}` privilege rows. Same
//! shape as `attome-project/tests/seed.rs` — see that file's doc comment for
//! why this narrower, cheaper check exists alongside `fresh_bootstrap.rs`.

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

const SERVICE_ENTITIES: &[&str] = &[
    "service_work_request",
    "service_ticket",
    "service_sla_policy",
    "service_offering",
];

#[tokio::test]
async fn every_entity_gets_its_full_privilege_set() {
    let db = skip_if_no_db!(test_db().await);
    attome_security::seed::seed_for_tests(&db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    // attome_service::seed::seed's linked_project_id lookup needs attome_project
    // registered first — same ordering system.rs uses in production.
    attome_project::seed::seed_for_tests(&db)
        .await
        .expect("attome_project::seed::seed");
    attome_service::seed::seed_for_tests(&db)
        .await
        .expect("attome_service::seed::seed");
    // Idempotency — a second call must be a pure no-op, same invariant every
    // other engine's seed carries.
    attome_service::seed::seed_for_tests(&db)
        .await
        .expect("attome_service::seed::seed (second call, must be idempotent)");
    attome_security::entity_privileges::seed_all(&db)
        .await
        .expect("attome_security::entity_privileges::seed_all");

    for logicalname in SERVICE_ENTITIES {
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
