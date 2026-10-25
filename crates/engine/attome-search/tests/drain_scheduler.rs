//! The projector and the drain lock, against a real database.
//!
//! These close the gap that made every other search test pass over an empty
//! product: `drain_once` and the legs were both correct, and **nothing ever
//! called them**, so a real deployment's index stayed empty while search
//! returned well-formed empty pages and every test that seeded the index
//! directly stayed green.
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-search --test drain_scheduler
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use attome_db::DbPool;
use attome_search::corpus::project_record;
use attome_testkit::skip_if_no_db;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

/// Creates a physical entity table shaped like a provisioned one.
async fn create_entity_table(db: &DbPool, name: &str) {
    sqlx::query(&format!(
        r#"CREATE TABLE "{name}" (
               id               UUID PRIMARY KEY,
               organization_ref UUID,
               owner_ref        UUID,
               is_active        BOOLEAN NOT NULL DEFAULT TRUE,
               company_name     TEXT,
               notes            TEXT,
               salary_band      TEXT
           )"#
    ))
    .execute(db)
    .await
    .expect("create entity table");
}

/// Builds a registry snapshot for one entity, the way `pre_warm_registry`
/// would. `salary_band` is secured.
fn registry_for(entity: &str) -> attome_core::EntityMetaRegistry {
    use attome_core::{AttrInfo, DataClassification, EntityMeta, OnTargetDelete};
    let attr = |name: &str, sensitive: bool| AttrInfo {
        logicalname: name.into(),
        field_type_int: 3,
        is_required: false,
        max_length: None,
        is_sensitive: sensitive,
        is_write_restricted: false,
        is_sortable: false,
        is_filterable: false,
        lookup_entity_ref: None,
        on_target_delete: OnTargetDelete::default(),
        data_classification: DataClassification::default(),
        sensitivity: Default::default(),
        options: None,
    };
    attome_core::EntityMetaRegistry::from_entities(vec![EntityMeta {
        entity_id: Uuid::now_v7(),
        logicalname: entity.to_owned(),
        attrs: vec![
            attr("company_name", false),
            attr("notes", false),
            attr("salary_band", true),
        ],
        is_append_only: false,
        primary_name_attribute: Some("company_name".into()),
    }])
}

/// **The end-to-end shape of the gap.** A record in a real entity table
/// projects into indexable text, with the declared primary name as the title.
#[tokio::test]
async fn a_record_projects_into_indexable_text() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_corpus_{}", Uuid::now_v7().simple());
    create_entity_table(&db, &entity).await;

    let record_id = Uuid::now_v7();
    let org = Uuid::now_v7();
    sqlx::query(&format!(
        r#"INSERT INTO "{entity}" (id, organization_ref, company_name, notes, salary_band)
           VALUES ($1, $2, 'ACME Trading LLC', 'Wholesale electronics', 'BAND-SEVEN-CONFIDENTIAL')"#
    ))
    .bind(record_id)
    .bind(org)
    .execute(&db)
    .await
    .expect("insert record");

    let registry = registry_for(&entity);
    let (row, organization_ref, _owner) = project_record(&db, &registry, &entity, record_id)
        .await
        .expect("project")
        .expect("the record exists and is indexable");

    assert_eq!(row.title, "ACME Trading LLC", "the declared primary name");
    assert!(row.body_display.contains("Wholesale electronics"));
    assert_eq!(organization_ref, Some(org), "the RLS fast tier needs this");
    assert!(
        row.exact_keys.contains(&record_id.to_string()),
        "the record id is the one identifier the platform guarantees"
    );

    // **The S3 assertion, on real data.** A secured attribute's value must not
    // appear in ANY projected field — title, displayed body, or the indexed
    // text that becomes the tsvector. Matchability is the disclosure.
    for (what, text) in [
        ("title", &row.title),
        ("body_display", &row.body_display),
        ("body_indexed", &row.body_indexed),
    ] {
        assert!(
            !text.to_lowercase().contains("band-seven"),
            "the secured field's value leaked into {what}: {text}"
        );
    }

    let _ = sqlx::query(&format!(r#"DROP TABLE "{entity}""#))
        .execute(&db)
        .await;
}

/// A soft-deleted record projects to `None`, which the drain treats as a
/// delete. Leaving the row indexed would keep a deleted record findable —
/// the disclosure D-358's delete events exist to close (G2).
#[tokio::test]
async fn a_soft_deleted_record_projects_to_nothing() {
    let db = skip_if_no_db!(test_db().await);
    let entity = format!("test_corpus_{}", Uuid::now_v7().simple());
    create_entity_table(&db, &entity).await;

    let record_id = Uuid::now_v7();
    sqlx::query(&format!(
        r#"INSERT INTO "{entity}" (id, company_name, is_active) VALUES ($1, 'Gone Ltd', false)"#
    ))
    .bind(record_id)
    .execute(&db)
    .await
    .expect("insert record");

    let registry = registry_for(&entity);
    assert!(
        project_record(&db, &registry, &entity, record_id)
            .await
            .expect("project")
            .is_none(),
        "a soft-deleted record must not be indexable"
    );

    let _ = sqlx::query(&format!(r#"DROP TABLE "{entity}""#))
        .execute(&db)
        .await;
}

/// An entity the registry does not know projects to `None` rather than
/// erroring.
///
/// An error would stall the drain on one bad event **forever**: the cursor
/// cannot advance past an event whose processing fails, so a single dropped
/// entity would freeze indexing for every other entity in the deployment.
#[tokio::test]
async fn an_unknown_entity_does_not_stall_the_drain() {
    let db = skip_if_no_db!(test_db().await);
    let registry = registry_for("something_else");
    let result = project_record(&db, &registry, "no_such_entity", Uuid::now_v7()).await;
    assert!(
        matches!(result, Ok(None)),
        "an unknown entity must be a skip, not an error that freezes the cursor: {result:?}"
    );
}

/// Only one node drains at a time.
///
/// Two concurrent transactions take the same key; the second must be refused
/// rather than blocked. `pg_try_advisory_xact_lock` is the *try* form for
/// exactly this reason — a node that waits for the lock waits for work that is
/// already being done, and at N nodes that is N−1 connections held for nothing.
#[tokio::test]
async fn the_drain_lock_refuses_a_second_holder_rather_than_blocking() {
    let db = skip_if_no_db!(test_db().await);
    const KEY: &str = "attome-search/drain:record-corpus";

    let mut first = db.begin().await.expect("begin");
    let got_first: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_search::ADVISORY_LOCK_NAMESPACE)
        .bind(KEY)
        .fetch_one(&mut *first)
        .await
        .expect("first lock");
    assert!(got_first);

    let mut second = db.begin().await.expect("begin");
    let got_second: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_search::ADVISORY_LOCK_NAMESPACE)
        .bind(KEY)
        .fetch_one(&mut *second)
        .await
        .expect("second lock attempt returns immediately");
    assert!(
        !got_second,
        "the second node must be refused, not queued behind work it would duplicate"
    );

    // Released by the transaction, with no explicit unlock anywhere — the
    // property the session-scoped form cannot offer.
    first.commit().await.expect("commit");
    let got_third: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_search::ADVISORY_LOCK_NAMESPACE)
        .bind(KEY)
        .fetch_one(&mut *second)
        .await
        .expect("third lock attempt");
    assert!(got_third, "the lock must be released by the commit");
    second.rollback().await.expect("rollback");
}
