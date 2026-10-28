//! Integration coverage for `attome_metadata::provision::reconcile_*`
//! (P-environment-promotion §5 steps 13/18/19, §6 "Ownership") — the
//! declarative create-or-update half the `ensure_*` seeds are now thin
//! wrappers over.
//!
//! What is pinned here, against a live Postgres:
//! * create → unchanged (the steady-state reseed reports `Unchanged`; no
//!   duplicate rows, same id);
//! * an `Admin` update applies and sets `is_customized`;
//! * a `Seed` against a customized row keeps every property an admin set
//!   (Y11-T4: they are customer-layer rows) and still applies the platform's
//!   other properties; a retired customized row returns `SkippedCustomized`
//!   and writes nothing (§6 "Ownership (c)");
//! * a field-type change is refused with `Validation` (D-055);
//! * retire is `is_active = false` only, idempotent, and a later reconcile
//!   reactivates the *same* row rather than inserting a second one;
//! * `lookup_entity` is resolved from a logicalname, and an unknown target is
//!   a `Validation` error;
//! * `Admin`/`Bundle` install the physical `max_length` contract inline on a
//!   small table (D-788: required is application-level, never `NOT NULL`);
//!   `Seed` stays metadata-only;
//! * every write appends a change-log row; an unchanged call appends none.
//!
//! Requires a live Postgres with migrations applied (through `0132`, which
//! adds `is_customized`) — the same setup `scripts/run-integration-tests.ps1`
//! performs. Skips (loudly) when `DATABASE_URL` is unset, except under `CI`
//! (see `attome_testkit`):
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:postgres@localhost:5556/attomedb_test?options=-c%20search_path%3Dattome_dev%2Cpublic"
//! cargo test -p attome-metadata --test reconcile -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_db::DbPool;
use attome_metadata::provision::{
    AttributeDesc, EntityDesc, ReconcileOutcome, ReconcilePolicy, ensure_attribute, ensure_entity,
    reactivate_attribute, reactivate_entity, reconcile_attribute, reconcile_entity,
    retire_attribute, retire_entity,
};
use attome_testkit::{skip_if_no_db, unique_logicalname};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

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

fn entity_desc(logicalname: &str, display_name: &str) -> EntityDesc {
    EntityDesc {
        logicalname: logicalname.to_owned(),
        display_name: display_name.to_owned(),
        primary_name_attribute: Some("title".to_owned()),
        is_append_only: false,
        is_audited: false,
        category: None,
    }
}

fn text_attr(logicalname: &str, display_name: &str) -> AttributeDesc {
    AttributeDesc {
        logicalname: logicalname.to_owned(),
        display_name: display_name.to_owned(),
        field_type: "text".to_owned(),
        is_required: false,
        is_sensitive: false,
        is_write_restricted: None,
        is_sortable: false,
        is_filterable: false,
        lookup_entity: None,
        options: None,
        max_length: None,
        on_target_delete: None,
        data_classification: None,
        purpose: None,
    }
}

#[derive(sqlx::FromRow)]
struct AttrProbe {
    name: Option<String>,
    is_customized: bool,
    is_active: Option<bool>,
    lookup_entity_ref: Option<Uuid>,
    max_length: Option<i32>,
    data_classification: String,
}

async fn attr_probe(db: &DbPool, entity_id: Uuid, logicalname: &str) -> AttrProbe {
    sqlx::query_as(
        "SELECT name, is_customized, is_active, lookup_entity_ref, max_length, data_classification \
         FROM attribute_info WHERE entity_ref = $1 AND logicalname = $2 \
         ORDER BY (is_active IS NULL OR is_active = true) DESC LIMIT 1",
    )
    .bind(entity_id)
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("attribute row must exist")
}

async fn attr_row_count(db: &DbPool, entity_id: Uuid, logicalname: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM attribute_info WHERE entity_ref = $1 AND logicalname = $2",
    )
    .bind(entity_id)
    .bind(logicalname)
    .fetch_one(db)
    .await
    .expect("count attribute rows")
}

async fn entity_row_count(db: &DbPool, logicalname: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM entity_info WHERE logicalname = $1")
        .bind(logicalname)
        .fetch_one(db)
        .await
        .expect("count entity rows")
}

async fn change_log_count(db: &DbPool, entity_id: Uuid, kind: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM metadata_change_log WHERE entity_ref = $1 AND change_kind = $2",
    )
    .bind(entity_id)
    .bind(kind)
    .fetch_one(db)
    .await
    .expect("count change-log rows")
}

async fn column_is_nullable(db: &DbPool, table: &str, column: &str) -> bool {
    let is_nullable: String = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns WHERE table_name = $1 AND column_name = $2",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .expect("column must exist");
    is_nullable == "YES"
}

#[tokio::test]
async fn create_then_reseed_is_created_then_unchanged_with_one_row_each() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");

    let (entity_id, outcome) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    assert_eq!(outcome, ReconcileOutcome::Created);
    let upserts_after_create = change_log_count(&db, entity_id, "upsert").await;
    assert_eq!(
        upserts_after_create, 1,
        "a new registration logs one upsert"
    );

    let (again, outcome) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("reseed entity");
    assert_eq!(again, entity_id, "reseed must resolve to the same row");
    assert_eq!(outcome, ReconcileOutcome::Unchanged);
    assert_eq!(entity_row_count(&db, &entity_ln).await, 1);
    assert_eq!(
        change_log_count(&db, entity_id, "upsert").await,
        upserts_after_create,
        "an unchanged reseed must not append a change-log row (no lock, no write)"
    );

    let (attr_id, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "Title"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create attribute");
    assert_eq!(outcome, ReconcileOutcome::Created);
    let (attr_again, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "Title"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("reseed attribute");
    assert_eq!(attr_again, attr_id);
    assert_eq!(outcome, ReconcileOutcome::Unchanged);
    assert_eq!(attr_row_count(&db, entity_id, "title").await, 1);
    let probe = attr_probe(&db, entity_id, "title").await;
    assert!(!probe.is_customized, "a seed never sets is_customized");
}

#[tokio::test]
async fn seed_updates_a_drifted_pristine_row_and_ensure_wrappers_reconcile() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");

    let entity_id = ensure_entity(&db, &entity_ln, "Old Name", Some("title"), false)
        .await
        .expect("ensure_entity");
    ensure_attribute(
        &db,
        entity_id,
        "title",
        "Old Title",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("ensure_attribute");

    // The seed's literal changed in a new release: the pristine row follows.
    let same_id = ensure_entity(&db, &entity_ln, "New Name", Some("title"), false)
        .await
        .expect("ensure_entity again");
    assert_eq!(same_id, entity_id);
    let name: Option<String> = sqlx::query_scalar("SELECT name FROM entity_info WHERE id = $1")
        .bind(entity_id)
        .fetch_one(&db)
        .await
        .expect("entity name");
    assert_eq!(name.as_deref(), Some("New Name"));

    ensure_attribute(
        &db,
        entity_id,
        "title",
        "New Title",
        "text",
        true,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("ensure_attribute again");
    let probe = attr_probe(&db, entity_id, "title").await;
    assert_eq!(probe.name.as_deref(), Some("New Title"));
    assert!(!probe.is_customized);
    assert!(
        column_is_nullable(&db, &entity_ln, "title").await,
        "Seed is metadata-only: is_required=true must not install NOT NULL"
    );
}

#[tokio::test]
async fn admin_update_sets_is_customized_and_seed_then_skips_it() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    let (attr_id, _) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "Seeded Title"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");

    let mut admin_desc = text_attr("title", "Customer Title");
    admin_desc.data_classification = Some("personal".to_owned());
    let (id, outcome) = reconcile_attribute(&db, entity_id, &admin_desc, ReconcilePolicy::Admin)
        .await
        .expect("admin update");
    assert_eq!(id, attr_id);
    assert_eq!(outcome, ReconcileOutcome::Updated);
    let probe = attr_probe(&db, entity_id, "title").await;
    assert_eq!(probe.name.as_deref(), Some("Customer Title"));
    assert_eq!(probe.data_classification, "personal");
    assert!(
        probe.is_customized,
        "an admin write marks the row customized"
    );

    // §6 "Ownership (c)": the next boot's seed must NOT "fix" what the admin
    // set (Y11-T4: the admin's properties are customer-layer rows), and here
    // it sets nothing else.
    let (id, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "Seeded Title"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed against customized row");
    assert_eq!(id, attr_id);
    assert_eq!(outcome, ReconcileOutcome::Unchanged);
    let probe = attr_probe(&db, entity_id, "title").await;
    assert_eq!(probe.name.as_deref(), Some("Customer Title"));
    assert_eq!(
        probe.data_classification, "personal",
        "Seed + None leaves data_classification as the admin set it"
    );

    // The same wrapper path every engine seed uses must skip too.
    let id = ensure_attribute(
        &db,
        entity_id,
        "title",
        "Seeded Title",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("ensure_attribute against customized row");
    assert_eq!(id, attr_id);
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.name.as_deref(),
        Some("Customer Title")
    );

    // A bundle carrying is_customized=false is the exact desired state and
    // clears the marker.
    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "Seeded Title"),
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
    )
    .await
    .expect("bundle apply");
    assert_eq!(outcome, ReconcileOutcome::Updated);
    let probe = attr_probe(&db, entity_id, "title").await;
    assert!(!probe.is_customized);
    assert_eq!(probe.name.as_deref(), Some("Seeded Title"));
    assert_eq!(
        probe.data_classification, "general",
        "Bundle + None is the exact desired state: the NOT NULL default"
    );
}

#[tokio::test]
async fn admin_on_an_identical_pristine_row_only_marks_it_customized() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "T"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");

    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "T"),
        ReconcilePolicy::Admin,
    )
    .await
    .expect("admin touch");
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert!(attr_probe(&db, entity_id, "title").await.is_customized);
    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "T"),
        ReconcilePolicy::Admin,
    )
    .await
    .expect("admin touch again");
    assert_eq!(outcome, ReconcileOutcome::Unchanged);
}

#[tokio::test]
async fn field_type_change_is_refused_with_validation_naming_the_field() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "T"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");

    let mut retyped = text_attr("title", "T");
    retyped.field_type = "number".to_owned();
    for policy in [
        ReconcilePolicy::Admin,
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
    ] {
        let err = reconcile_attribute(&db, entity_id, &retyped, policy)
            .await
            .expect_err("a type change must be refused");
        match err {
            attome_types::AppError::Validation(msg) => {
                assert!(
                    msg.contains(&format!("{entity_ln}.title")),
                    "message must name entity.field: {msg}"
                );
                assert!(
                    msg.contains("text") && msg.contains("number"),
                    "message must name both types: {msg}"
                );
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }
    // A boot seed with drifted type must not fail the boot: warn, leave the
    // row alone, report Unchanged (the old create-only seed ignored it too).
    let (_, outcome) = reconcile_attribute(&db, entity_id, &retyped, ReconcilePolicy::Seed)
        .await
        .expect("a seed never fails a boot over a type drift");
    assert_eq!(outcome, ReconcileOutcome::Unchanged);
    // Nothing was written by any of the three.
    let probe = attr_probe(&db, entity_id, "title").await;
    assert!(!probe.is_customized);
    assert_eq!(probe.name.as_deref(), Some("T"));
    let ty: i32 = sqlx::query_scalar(
        r#"SELECT "type" FROM attribute_info WHERE entity_ref = $1 AND logicalname = 'title'"#,
    )
    .bind(entity_id)
    .fetch_one(&db)
    .await
    .expect("type");
    assert_eq!(ty, 3, "text");
}

#[tokio::test]
async fn retire_is_soft_and_idempotent_and_reconcile_reactivates_the_same_row() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    let (attr_id, _) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "T"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");

    // ── attribute ──
    assert_eq!(
        retire_attribute(&db, entity_id, "title")
            .await
            .expect("retire"),
        ReconcileOutcome::Updated
    );
    assert_eq!(
        retire_attribute(&db, entity_id, "title")
            .await
            .expect("retire again"),
        ReconcileOutcome::Unchanged,
        "retire is idempotent"
    );
    assert_eq!(
        retire_attribute(&db, entity_id, "never_existed")
            .await
            .expect("retire missing"),
        ReconcileOutcome::Unchanged,
        "retiring an absent key is the desired state already"
    );
    let probe = attr_probe(&db, entity_id, "title").await;
    assert_eq!(probe.is_active, Some(false));
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns WHERE table_name = $1",
    )
    .bind(&entity_ln)
    .fetch_all(&db)
    .await
    .expect("columns");
    assert!(
        cols.iter().any(|c| c == "title"),
        "retire never drops the physical column"
    );

    let (id, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "T"),
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
    )
    .await
    .expect("re-apply older bundle");
    assert_eq!(
        id, attr_id,
        "reactivate-over-insert: the same row comes back"
    );
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.is_active,
        Some(true)
    );
    assert_eq!(
        attr_row_count(&db, entity_id, "title").await,
        1,
        "no second metadata row for the same key"
    );
    assert_eq!(
        reactivate_attribute(&db, entity_id, "title")
            .await
            .expect("reactivate"),
        ReconcileOutcome::Unchanged,
        "already live"
    );

    // ── entity ──
    assert_eq!(
        retire_entity(&db, &entity_ln).await.expect("retire entity"),
        ReconcileOutcome::Updated
    );
    assert_eq!(change_log_count(&db, entity_id, "delete").await, 1);
    assert_eq!(
        retire_entity(&db, &entity_ln)
            .await
            .expect("retire entity again"),
        ReconcileOutcome::Unchanged
    );
    let live: Option<bool> = sqlx::query_scalar("SELECT is_active FROM entity_info WHERE id = $1")
        .bind(entity_id)
        .fetch_one(&db)
        .await
        .expect("entity active");
    assert_eq!(live, Some(false));
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.is_active,
        Some(true),
        "retire_entity flips only the entity row (lossless reactivate)"
    );
    let table_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM information_schema.tables WHERE table_name = $1")
            .bind(&entity_ln)
            .fetch_one(&db)
            .await
            .expect("tables");
    assert_eq!(table_count, 1, "retire never drops the physical table");

    let (id, outcome) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("reseed reactivates");
    assert_eq!(id, entity_id);
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert_eq!(entity_row_count(&db, &entity_ln).await, 1);
    assert_eq!(
        reactivate_entity(&db, &entity_ln)
            .await
            .expect("reactivate"),
        ReconcileOutcome::Unchanged
    );

    // And a customized, retired row stays retired under a seed.
    retire_entity(&db, &entity_ln).await.expect("retire");
    sqlx::query("UPDATE entity_info SET is_customized = true WHERE id = $1")
        .bind(entity_id)
        .execute(&db)
        .await
        .expect("mark customized");
    let (id, outcome) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed against customized retired row");
    assert_eq!(id, entity_id);
    assert_eq!(outcome, ReconcileOutcome::SkippedCustomized);
    let live: Option<bool> = sqlx::query_scalar("SELECT is_active FROM entity_info WHERE id = $1")
        .bind(entity_id)
        .fetch_one(&db)
        .await
        .expect("entity active");
    assert_eq!(live, Some(false));
    assert_eq!(entity_row_count(&db, &entity_ln).await, 1);
}

#[tokio::test]
async fn lookup_entity_is_resolved_from_logicalname_and_unknown_target_is_validation() {
    let db = skip_if_no_db!(test_db().await);
    let target_ln = unique_logicalname("test_rec_target");
    let entity_ln = unique_logicalname("test_rec");
    let (target_id, _) = reconcile_entity(
        &db,
        &entity_desc(&target_ln, "Target"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create target");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Source"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create source");

    let mut lookup = text_attr("owner_target", "Owner");
    lookup.field_type = "lookup".to_owned();
    lookup.lookup_entity = Some(target_ln.clone());
    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &lookup,
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
    )
    .await
    .expect("create lookup");
    assert_eq!(outcome, ReconcileOutcome::Created);
    assert_eq!(
        attr_probe(&db, entity_id, "owner_target")
            .await
            .lookup_entity_ref,
        Some(target_id)
    );

    let mut missing = lookup.clone();
    missing.logicalname = "owner_missing".to_owned();
    missing.lookup_entity = Some(unique_logicalname("test_rec_nope"));
    match reconcile_attribute(&db, entity_id, &missing, ReconcilePolicy::Admin).await {
        Err(attome_types::AppError::Validation(msg)) => {
            assert!(msg.contains("lookup target"), "{msg}");
            assert!(msg.contains("not found"), "{msg}");
        }
        other => panic!("expected Validation, got {other:?}"),
    }
    assert_eq!(attr_row_count(&db, entity_id, "owner_missing").await, 0);

    // Under Admin a lookup without a target is a validation error.
    let mut no_target = lookup.clone();
    no_target.logicalname = "owner_none".to_owned();
    no_target.lookup_entity = None;
    assert!(matches!(
        reconcile_attribute(&db, entity_id, &no_target, ReconcilePolicy::Admin).await,
        Err(attome_types::AppError::Validation(_))
    ));
}

#[tokio::test]
async fn bundle_accepts_a_target_less_lookup() {
    // Seeded target-less lookups are a legal shape (a plain UUID column, no
    // FK) — `plan.rs`'s `diff_entities` already treats them as such at plan
    // time, so `Bundle` apply must accept them too, the same as `Seed`.
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Source"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create source");

    let mut no_target = text_attr("owner_none", "Owner");
    no_target.field_type = "lookup".to_owned();
    no_target.lookup_entity = None;
    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &no_target,
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
    )
    .await
    .expect("bundle accepts a target-less lookup");
    assert_eq!(outcome, ReconcileOutcome::Created);
    assert_eq!(
        attr_probe(&db, entity_id, "owner_none")
            .await
            .lookup_entity_ref,
        None
    );
}

#[tokio::test]
async fn admin_contract_change_is_application_level_for_required() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "T"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");
    assert!(column_is_nullable(&db, &entity_ln, "title").await);

    let mut required = text_attr("title", "T");
    required.is_required = true;
    required.max_length = Some(40);
    let (_, outcome) = reconcile_attribute(&db, entity_id, &required, ReconcilePolicy::Admin)
        .await
        .expect("admin required");
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert!(
        column_is_nullable(&db, &entity_ln, "title").await,
        "D-788: required is application-level, no physical NOT NULL"
    );
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.max_length,
        Some(40)
    );

    // A brand-new required field on an empty table gets its contract too.
    let mut created_required = text_attr("code", "Code");
    created_required.is_required = true;
    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &created_required,
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
    )
    .await
    .expect("bundle create required");
    assert_eq!(outcome, ReconcileOutcome::Created);
    assert!(
        column_is_nullable(&db, &entity_ln, "code").await,
        "D-788: a new required field installs no NOT NULL either"
    );
}

async fn write_restricted(db: &DbPool, attr_id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_write_restricted FROM attribute_info WHERE id = $1")
        .bind(attr_id)
        .fetch_one(db)
        .await
        .expect("is_write_restricted")
}

/// D-507: `is_write_restricted` is a `managed_value` column. A `Seed` with no
/// opinion (`None` — every `ensure_attribute` caller) must leave a value set
/// by a bundle or an admin alone even while it rewrites other columns of the
/// same row; an `Admin` description owns the column, so its `None` is `false`.
#[tokio::test]
async fn seed_without_an_opinion_leaves_is_write_restricted_alone() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_rec");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Reconcile"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");

    let mut restricted = text_attr("title", "Title");
    restricted.is_write_restricted = Some(true);
    let (attr_id, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &restricted,
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
    )
    .await
    .expect("bundle create");
    assert_eq!(outcome, ReconcileOutcome::Created);
    assert!(write_restricted(&db, attr_id).await);
    assert!(
        !attr_probe(&db, entity_id, "title").await.is_customized,
        "precondition: a pristine row, so the seeds below really write it"
    );

    let (id, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "Renamed By Seed"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed update");
    assert_eq!(id, attr_id);
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.name.as_deref(),
        Some("Renamed By Seed")
    );
    assert!(
        write_restricted(&db, attr_id).await,
        "Seed + None must not clear is_write_restricted"
    );

    ensure_attribute(
        &db,
        entity_id,
        "title",
        "Renamed By Wrapper",
        "text",
        false,
        false,
        false,
        false,
        None,
        None,
    )
    .await
    .expect("ensure_attribute");
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.name.as_deref(),
        Some("Renamed By Wrapper")
    );
    assert!(
        write_restricted(&db, attr_id).await,
        "the ensure_attribute wrapper must not clear is_write_restricted"
    );

    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &text_attr("title", "Renamed By Wrapper"),
        ReconcilePolicy::Admin,
    )
    .await
    .expect("admin update");
    assert_eq!(outcome, ReconcileOutcome::Updated);
    assert!(
        !write_restricted(&db, attr_id).await,
        "an Admin description owns the column: None means false"
    );
}

/// A text attribute whose label is `label` and `max_length` is `max_length`.
fn sized_attr(label: &str, max_length: i32) -> AttributeDesc {
    let mut desc = text_attr("title", label);
    desc.max_length = Some(max_length);
    desc
}

async fn layer_of(db: &DbPool, key: &str, property: &str) -> Vec<(String, serde_json::Value)> {
    sqlx::query_as(
        "SELECT layer, value FROM metadata_property_layer           WHERE object_kind = 'attribute' AND object_key = $1 AND property = $2           ORDER BY layer",
    )
    .bind(key)
    .bind(property)
    .fetch_all(db)
    .await
    .expect("read property layers")
}

/// Y11-T4: a platform fix to `max_length` reaches a field whose label the
/// customer changed, and the label stays the customer's.
#[tokio::test]
async fn seed_updates_unchanged_property_of_customised_row() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_layer");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Layers"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 20),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");
    let key = format!("{entity_ln}.title");
    assert_eq!(
        layer_of(&db, &key, "max_length").await,
        vec![("platform".to_owned(), serde_json::json!(20))],
        "a seed records the properties it sets as the platform's"
    );

    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Mobile", 20),
        ReconcilePolicy::Admin,
    )
    .await
    .expect("admin relabels");
    assert_eq!(
        layer_of(&db, &key, "name").await,
        vec![
            ("customer".to_owned(), serde_json::json!("Mobile")),
            ("platform".to_owned(), serde_json::json!("Phone")),
        ]
    );
    assert!(
        layer_of(&db, &key, "max_length")
            .await
            .iter()
            .all(|(layer, _)| layer == "platform"),
        "the admin did not change max_length, so it records no customer row for it"
    );

    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 32),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("the platform fixes max_length");
    assert_eq!(outcome, ReconcileOutcome::Updated);
    let probe = attr_probe(&db, entity_id, "title").await;
    assert_eq!(probe.name.as_deref(), Some("Mobile"));
    assert_eq!(probe.max_length, Some(32));
    assert!(probe.is_customized, "a seed never clears the marker");
}

/// Y11-T4: a row customised before property layers existed has none; the
/// first seed pass records what differs from the platform as the customer's
/// (the backfill), so the label survives. It cannot tell a customer edit from
/// an older platform value, so a differing `max_length` is kept too.
#[tokio::test]
async fn seed_keeps_customer_label() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_layer");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Layers"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    let (attr_id, _) = reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 20),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");
    let key = format!("{entity_ln}.title");
    // As a deployment from before Y11-T4 has it: customised, no layer rows.
    sqlx::query("UPDATE attribute_info SET name = 'Mobile', is_customized = true WHERE id = $1")
        .bind(attr_id)
        .execute(&db)
        .await
        .expect("customise the old way");
    sqlx::query(
        "DELETE FROM metadata_property_layer WHERE object_kind = 'attribute' AND object_key = $1",
    )
    .bind(&key)
    .execute(&db)
    .await
    .expect("no layer rows yet");

    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 32),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed after upgrade");
    assert_eq!(outcome, ReconcileOutcome::Unchanged);
    let probe = attr_probe(&db, entity_id, "title").await;
    assert_eq!(probe.name.as_deref(), Some("Mobile"));
    assert_eq!(probe.max_length, Some(20));
    assert_eq!(
        layer_of(&db, &key, "name").await,
        vec![("customer".to_owned(), serde_json::json!("Mobile"))]
    );

    // Recorded once: the next seed reads the rows and keeps the label again.
    let (_, outcome) = reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 32),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("second seed");
    assert_eq!(outcome, ReconcileOutcome::Unchanged);
}

/// Y11-T6: a platform change to a property the customer also changed is a
/// conflict: the seed writes one open conflict and leaves the value alone,
/// and running again does not add a second one.
#[tokio::test]
async fn seed_records_a_conflict_instead_of_overwriting_the_customer() {
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_layer");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Layers"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 20),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 50),
        ReconcilePolicy::Admin,
    )
    .await
    .expect("the customer widens it");
    let key = format!("{entity_ln}.title");

    for _ in 0..2 {
        reconcile_attribute(
            &db,
            entity_id,
            &sized_attr("Phone", 32),
            ReconcilePolicy::Seed,
        )
        .await
        .expect("the platform changes it too");
    }
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.max_length,
        Some(50)
    );
    let conflicts: Vec<(
        String,
        Option<serde_json::Value>,
        serde_json::Value,
        serde_json::Value,
    )> = sqlx::query_as(
        "SELECT property, old_platform, new_platform, customer FROM metadata_layer_conflict \
              WHERE object_kind = 'attribute' AND object_key = $1 AND status = 'open'",
    )
    .bind(&key)
    .fetch_all(&db)
    .await
    .expect("read conflicts");
    assert_eq!(
        conflicts,
        vec![(
            "max_length".to_owned(),
            Some(serde_json::json!(20)),
            serde_json::json!(32),
            serde_json::json!(50),
        )]
    );
}

/// Y11-T7: taking the platform's side removes the customer's layer value,
/// applies the platform's value to the field and closes the conflict; a
/// second resolve is refused.
#[tokio::test]
async fn take_platform_removes_customer_row() {
    use attome_metadata::provision::layer_conflicts::{self, ALREADY_RESOLVED, Resolution};
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_layer");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Layers"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 20),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 50),
        ReconcilePolicy::Admin,
    )
    .await
    .expect("the customer widens it");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 32),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("the platform changes it too");
    let key = format!("{entity_ln}.title");
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM metadata_layer_conflict \
          WHERE object_kind = 'attribute' AND object_key = $1 AND status = 'open'",
    )
    .bind(&key)
    .fetch_one(&db)
    .await
    .expect("the open conflict");

    let actor = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&db).await.unwrap();
    let resolved = layer_conflicts::resolve_in_tx(&mut tx, id, Resolution::TakePlatform, actor)
        .await
        .expect("resolve");
    tx.commit().await.unwrap();
    assert_eq!(resolved.status, "resolved");
    assert_eq!(resolved.resolution.as_deref(), Some("take_platform"));

    assert_eq!(
        attr_probe(&db, entity_id, "title").await.max_length,
        Some(32)
    );
    let customer: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM metadata_property_layer \
          WHERE object_kind = 'attribute' AND object_key = $1 AND property = 'max_length' \
            AND layer = 'customer'",
    )
    .bind(&key)
    .fetch_all(&db)
    .await
    .unwrap();
    assert!(
        customer.is_empty(),
        "the customer's value is gone: {customer:?}"
    );

    let mut tx = attome_db::tx::begin(&db).await.unwrap();
    let again = layer_conflicts::resolve_in_tx(&mut tx, id, Resolution::KeepCustomer, actor).await;
    assert!(
        matches!(again, Err(attome_types::AppError::Conflict(m)) if m == ALREADY_RESOLVED),
        "{again:?}"
    );
}

/// Y11-T9: resetting a customised label puts the platform's back, and
/// undoing the reset restores the customer's.
#[tokio::test]
async fn reset_then_undo_restores_label() {
    use attome_metadata::provision::layer_reset;
    let db = skip_if_no_db!(test_db().await);
    let entity_ln = unique_logicalname("test_layer");
    let (entity_id, _) = reconcile_entity(
        &db,
        &entity_desc(&entity_ln, "Layers"),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("create entity");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Phone", 20),
        ReconcilePolicy::Seed,
    )
    .await
    .expect("seed attribute");
    reconcile_attribute(
        &db,
        entity_id,
        &sized_attr("Mobile", 20),
        ReconcilePolicy::Admin,
    )
    .await
    .expect("the customer relabels it");
    let key = format!("{entity_ln}.title");

    let preview = layer_reset::preview(&db, "attribute", &key, None)
        .await
        .unwrap();
    assert_eq!(preview.len(), 1, "{preview:?}");
    assert_eq!(preview[0].property, "name");
    assert_eq!(preview[0].current, serde_json::json!("Mobile"));
    assert_eq!(preview[0].after, Some(serde_json::json!("Phone")));
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.name.as_deref(),
        Some("Mobile"),
        "a preview changes nothing"
    );

    let actor = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&db).await.unwrap();
    let (reset_id, changes) = layer_reset::reset_in_tx(&mut tx, "attribute", &key, None, actor)
        .await
        .expect("reset");
    tx.commit().await.unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.name.as_deref(),
        Some("Phone")
    );

    let mut tx = attome_db::tx::begin(&db).await.unwrap();
    layer_reset::undo_in_tx(&mut tx, reset_id, actor)
        .await
        .expect("undo");
    tx.commit().await.unwrap();
    assert_eq!(
        attr_probe(&db, entity_id, "title").await.name.as_deref(),
        Some("Mobile")
    );

    let mut tx = attome_db::tx::begin(&db).await.unwrap();
    let again = layer_reset::undo_in_tx(&mut tx, reset_id, actor).await;
    assert!(
        matches!(again, Err(attome_types::AppError::Conflict(m)) if m == layer_reset::ALREADY_UNDONE),
        "{again:?}"
    );
}
