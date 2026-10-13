//! Confirms `attome_grc::seed::seed` satisfies the same fresh-boot invariants
//! `crates/server/tests/fresh_bootstrap.rs`'s generic loops check for every
//! registered entity (default list view, full privilege set), is idempotent
//! on a second call, and adds the additive `risk_ref` lookup onto the
//! already-registered `project_issue` entity (M20-grc.md §5's risk
//! generalization, D-427). Same narrower/cheaper-than-`fresh_bootstrap.rs`
//! shape `attome-project/tests/seed.rs` documents for itself.

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

const GRC_ENTITIES: &[&str] = &[
    "grc_regulation",
    "grc_requirement",
    "grc_control",
    "grc_control_requirement",
    "grc_assessment",
    "grc_assessment_item",
    "grc_finding",
    "grc_evidence",
    "grc_risk",
    "grc_risk_dependency",
    "grc_policy",
    "grc_policy_ack",
];

async fn seed_prerequisites(db: &DbPool) {
    attome_security::seed::seed_for_tests(db)
        .await
        .expect("attome_security::seed::seed_for_tests");
    // attome_grc::seed adds risk_ref onto project_issue — must run after
    // attome-project's own seed, same ordering attome-api/src/system.rs uses in
    // production.
    attome_project::seed::seed_for_tests(db)
        .await
        .expect("attome_project::seed::seed");
}

#[tokio::test]
async fn every_entity_gets_a_default_view_and_full_privilege_set() {
    let db = skip_if_no_db!(test_db().await);
    seed_prerequisites(&db).await;

    attome_grc::seed::seed(&db)
        .await
        .expect("attome_grc::seed::seed");
    // Idempotency — a second call must be a pure no-op, same invariant every
    // other engine's seed carries.
    attome_grc::seed::seed(&db)
        .await
        .expect("attome_grc::seed::seed (second call, must be idempotent)");

    attome_security::entity_privileges::seed_all(&db)
        .await
        .expect("attome_security::entity_privileges::seed_all");

    for logicalname in GRC_ENTITIES {
        let registered: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM entity_info \
             WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true))",
        )
        .bind(logicalname)
        .fetch_one(&db)
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
        .fetch_one(&db)
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
                    .fetch_one(&db)
                    .await
                    .expect("read privileges");
            assert!(exists, "privilege {key} missing");
        }
    }
}

/// M20-grc.md §5 / D-427: the risk generalization is additive, not a
/// duplicate — `project_issue` gains a `risk_ref` lookup attribute
/// pointing at `grc_risk`, and `project_issue` itself stays owned by
/// attome-project (this crate's seed does not re-register it).
#[tokio::test]
async fn risk_ref_is_added_onto_the_existing_project_issue_entity() {
    let db = skip_if_no_db!(test_db().await);
    seed_prerequisites(&db).await;
    attome_grc::seed::seed(&db)
        .await
        .expect("attome_grc::seed::seed");

    // `"type"` is the stored integer field-type code (11 == lookup) — see
    // `attome-metadata/src/provision/reconcile.rs`'s `type_to_int`/`int_to_type`.
    let row: Option<(i32, Option<String>)> = sqlx::query_as(
        "SELECT a.\"type\", e2.logicalname \
         FROM attribute_info a \
         JOIN entity_info e ON e.id = a.entity_ref \
         LEFT JOIN entity_info e2 ON e2.id = a.lookup_entity_ref \
         WHERE e.logicalname = 'project_issue' AND a.logicalname = 'risk_ref'",
    )
    .fetch_optional(&db)
    .await
    .expect("read project_issue.risk_ref");

    let (field_type_int, lookup_target) =
        row.expect("project_issue.risk_ref must exist after attome_grc::seed::seed");
    assert_eq!(field_type_int, 11, "risk_ref must be a lookup field");
    assert_eq!(lookup_target.as_deref(), Some("grc_risk"));
}
