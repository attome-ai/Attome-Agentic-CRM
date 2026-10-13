//! Phase 1 money path: the `attome_dashboard` lifecycle state machine —
//! `Draft -> Review -> Approved -> Published -> Archived` — exercised
//! directly against the real transaction/lock/status logic in
//! `lifecycle.rs`'s `pub` `do_*` functions, same test shape as
//! `attome-service/tests` exercising `convert::convert_work_request_to_ticket`
//! directly rather than standing up a full authenticated HTTP request.
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI`, per the P1.8 testing-baseline convention. Both tests
//! in this file call the idempotent `attome_security::seed::seed`/
//! `attome_dashboard::seed::seed` against the same database; run with
//! `--test-threads=1` to avoid two threads racing the same provisioning DDL
//! (same convention `attome-project`'s entity-provisioning suites use):
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-dashboard --test dashboard_crud -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;

/// Inserts a bare `attome_dashboard` row bypassing the generic entity engine
/// (same reason `attome-service`'s conversion tests insert `service_work_request`
/// rows directly) — this suite is testing `lifecycle.rs`'s transitions, not
/// entity CRUD, which is already covered by the generic engine's own tests.
/// `lifecycle_status_literal: None` leaves the column `NULL`, exercising the
/// "no field-level default — NULL reads as draft" behavior documented in
/// `seed.rs`.
async fn insert_dashboard(db: &DbPool, name: &str, lifecycle_status_literal: Option<&str>) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO attome_dashboard (id, name, dashboard_type, lifecycle_status) \
         VALUES ($1, $2, 'team', $3)",
    )
    .bind(id)
    .bind(name)
    .bind(lifecycle_status_literal)
    .execute(db)
    .await
    .expect("insert test attome_dashboard row");
    id
}

async fn status_and_version(db: &DbPool, id: Uuid) -> (Option<String>, i64, bool) {
    sqlx::query_as(
        "SELECT lifecycle_status, row_version, is_active FROM attome_dashboard WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .expect("read attome_dashboard row")
}

/// Phase 2 fixtures — same "bypass the generic entity engine, this suite
/// tests our own code" reasoning as `insert_dashboard` above.
async fn insert_page(db: &DbPool, dashboard_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO dashboard_page (id, dashboard_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(dashboard_id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test dashboard_page row");
    id
}

async fn insert_section(
    db: &DbPool,
    page_id: Uuid,
    parent_section_id: Option<Uuid>,
    section_type: &str,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_section \
         (id, page_id, parent_section_id, section_type, layout_mode) \
         VALUES ($1, $2, $3, $4, 'grid')",
    )
    .bind(id)
    .bind(page_id)
    .bind(parent_section_id)
    .bind(section_type)
    .execute(db)
    .await
    .expect("insert test dashboard_section row");
    id
}

async fn insert_widget(db: &DbPool, section_id: Uuid, query_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_widget (id, section_id, widget_type, name, query_id, query_params) \
         VALUES ($1, $2, 'line_chart', 'Revenue', $3, $4)",
    )
    .bind(id)
    .bind(section_id)
    .bind(query_id.to_string())
    .bind(r#"{"filters":[]}"#)
    .execute(db)
    .await
    .expect("insert test dashboard_widget row");
    id
}

async fn insert_breakpoint(db: &DbPool, section_id: Uuid, breakpoint: &str) {
    sqlx::query(
        "INSERT INTO dashboard_section_breakpoint (id, section_id, breakpoint, is_visible) \
         VALUES ($1, $2, $3, false)",
    )
    .bind(Uuid::now_v7())
    .bind(section_id)
    .bind(breakpoint)
    .execute(db)
    .await
    .expect("insert test dashboard_section_breakpoint row");
}

/// D-521 — a stored query with one published version, so publish can pin a
/// widget bound to it. Returns `(query_id, version_id)`.
async fn insert_published_query(db: &DbPool) -> (Uuid, Uuid) {
    let query_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, sql_query, table_definition, is_active, created_at, owner_layer) \
         VALUES ($1, 'SELECT 1 AS one', '[]', true, NOW(), 'project')",
    )
    .bind(query_id)
    .execute(db)
    .await
    .expect("insert test sql_query row");
    let version_id = add_query_version(db, query_id).await;
    (query_id, version_id)
}

async fn add_query_version(db: &DbPool, query_id: Uuid) -> Uuid {
    let version_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query_version (id, query_id, sql_query, cost_estimate) \
         VALUES ($1, $2, 'SELECT 1 AS one', 1.0)",
    )
    .bind(version_id)
    .bind(query_id)
    .execute(db)
    .await
    .expect("insert test sql_query_version row");
    version_id
}

/// A view over `query_id`, so a view-bound widget can be pinned.
async fn insert_view(db: &DbPool, query_id: Uuid) -> Uuid {
    let entity_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = 'attome_dashboard' AND (is_active IS NULL OR is_active = true)",
    )
    .fetch_one(db)
    .await
    .expect("attome_dashboard entity metadata");
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO view (id, name, entity_logical_name, sql_query_ref, is_default, is_active, owner_layer) \
         VALUES ($1, $2, $3, $4, false, true, 'project')",
    )
    .bind(id)
    .bind(format!("pin test view {id}"))
    .bind(entity_id)
    .bind(query_id)
    .execute(db)
    .await
    .expect("insert test view row");
    id
}

/// Business events for `record_id` named `event_name`, on either audit path
/// (the chainer's ingest rows or synchronous headers).
async fn business_events(db: &DbPool, record_id: Uuid, event_name: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM audit_header WHERE record_id = $1 AND event_name = $2) \
              + (SELECT COUNT(*) FROM audit_ingest \
                 WHERE payload->>'record_id' = $1::text AND payload->>'event_name' = $2)",
    )
    .bind(record_id)
    .bind(event_name)
    .fetch_one(db)
    .await
    .expect("count business events")
}

async fn live_version(db: &DbPool, dashboard_id: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT published_version_id FROM attome_dashboard WHERE id = $1")
        .bind(dashboard_id)
        .fetch_one(db)
        .await
        .expect("read published_version_id")
}

/// Draft -> review -> approved -> published; returns `(row_version, version_id)`.
async fn publish_through_lifecycle(
    state: &attome_core::EngineState,
    dashboard_id: Uuid,
    row_version: i64,
) -> (i64, Uuid) {
    let actor = Uuid::now_v7();
    let row_version =
        attome_dashboard::lifecycle::do_submit_for_review(state, dashboard_id, row_version, actor)
            .await
            .expect("draft -> review");
    let row_version =
        attome_dashboard::lifecycle::do_approve(state, dashboard_id, row_version, actor)
            .await
            .expect("review -> approved");
    let (row_version, version_id, _) = attome_dashboard::lifecycle::do_publish_dashboard(
        state,
        dashboard_id,
        row_version,
        Uuid::now_v7(),
    )
    .await
    .expect("approved -> published");
    (row_version, version_id)
}

#[tokio::test]
async fn publish_snapshot_includes_pages_and_nested_sections() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Layout Test Dashboard", None).await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let parent_section_id = insert_section(&db, page_id, None, "row").await;
    let child_section_id = insert_section(&db, page_id, Some(parent_section_id), "card").await;
    insert_breakpoint(&db, child_section_id, "mobile").await;
    let (query_id, query_version_id) = insert_published_query(&db).await;
    let widget_id = insert_widget(&db, child_section_id, query_id).await;

    let row_version =
        attome_dashboard::lifecycle::do_submit_for_review(&state, dashboard_id, 0, Uuid::now_v7())
            .await
            .expect("draft -> review");
    let row_version =
        attome_dashboard::lifecycle::do_approve(&state, dashboard_id, row_version, Uuid::now_v7())
            .await
            .expect("review -> approved");
    let (_, version_id, _) = attome_dashboard::lifecycle::do_publish_dashboard(
        &state,
        dashboard_id,
        row_version,
        Uuid::now_v7(),
    )
    .await
    .expect("approved -> published");

    let snapshot_json: String =
        sqlx::query_scalar("SELECT snapshot_json FROM dashboard_version WHERE id = $1")
            .bind(version_id)
            .fetch_one(&db)
            .await
            .expect("read snapshot_json");
    let snapshot: serde_json::Value =
        serde_json::from_str(&snapshot_json).expect("snapshot_json must be valid JSON");

    let pages = snapshot["pages"].as_array().expect("pages array");
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0]["id"], page_id.to_string());
    assert_eq!(pages[0]["name"], "Overview");

    let top_sections = pages[0]["sections"].as_array().expect("sections array");
    assert_eq!(
        top_sections.len(),
        1,
        "only the parent section has no parent_section_id — the child must nest under it, not sit alongside it"
    );
    assert_eq!(top_sections[0]["id"], parent_section_id.to_string());
    assert_eq!(top_sections[0]["section_type"], "row");

    let children = top_sections[0]["children"]
        .as_array()
        .expect("children array");
    assert_eq!(children.len(), 1);
    assert_eq!(children[0]["id"], child_section_id.to_string());
    assert_eq!(children[0]["section_type"], "card");

    let breakpoints = children[0]["breakpoints"]
        .as_array()
        .expect("breakpoints array");
    assert_eq!(breakpoints.len(), 1);
    assert_eq!(breakpoints[0]["breakpoint"], "mobile");
    assert_eq!(breakpoints[0]["is_visible"], false);

    let widgets = children[0]["widgets"].as_array().expect("widgets array");
    assert_eq!(widgets.len(), 1);
    assert_eq!(widgets[0]["id"], widget_id.to_string());
    assert_eq!(widgets[0]["widget_type"], "line_chart");
    assert_eq!(
        widgets[0]["query_id"],
        query_id.to_string(),
        "the widget's stored-query reference must survive into the published snapshot"
    );
    assert_eq!(widgets[0]["query_params"], r#"{"filters":[]}"#);

    // D-543: format 3 captures the whole executable definition — the pinned
    // query version, the column metadata execution would otherwise read live,
    // and a fingerprint over the resolved whole.
    assert_eq!(snapshot["snapshot_format"], 4);
    assert!(
        snapshot["publication_fingerprint"]
            .as_str()
            .is_some_and(|f| f.len() == 64),
        "the snapshot carries a sha256 publication fingerprint"
    );
    assert!(snapshot["parameters"].is_array() && snapshot["variables"].is_array());
    let dependencies = snapshot["dependencies"]
        .as_array()
        .expect("dependencies array");
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0]["widget_id"], widget_id.to_string());
    assert_eq!(dependencies[0]["query_id"], query_id.to_string());
    assert_eq!(
        dependencies[0]["query_version_id"],
        query_version_id.to_string()
    );
    assert!(
        !dependencies[0]["column_definition"].is_null(),
        "the executable column metadata is captured, not left live: {:?}",
        dependencies[0]
    );
    assert_eq!(live_version(&db, dashboard_id).await, Some(version_id));
}

#[tokio::test]
async fn full_lifecycle_draft_to_archived() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let id = insert_dashboard(&db, "Lifecycle Test Dashboard", None).await;
    let (status, row_version, is_active) = status_and_version(&db, id).await;
    assert_eq!(status, None, "freshly inserted row has no lifecycle_status");
    assert_eq!(row_version, 0);
    assert!(is_active);

    // NULL reads as draft: submit-review succeeds against expected_row_version 0.
    let row_version =
        attome_dashboard::lifecycle::do_submit_for_review(&state, id, row_version, Uuid::now_v7())
            .await
            .expect("draft -> review");
    assert_eq!(row_version, 1);
    let (status, _, _) = status_and_version(&db, id).await;
    assert_eq!(status.as_deref(), Some("review"));

    // Wrong-state rejection: a dashboard in review cannot be submitted again.
    let err =
        attome_dashboard::lifecycle::do_submit_for_review(&state, id, row_version, Uuid::now_v7())
            .await
            .expect_err("review -> review must be rejected");
    assert!(matches!(err, attome_types::AppError::Conflict(_)));

    // Stale row_version rejection.
    let err = attome_dashboard::lifecycle::do_approve(&state, id, 999, Uuid::now_v7())
        .await
        .expect_err("stale row_version must be rejected");
    assert!(matches!(err, attome_types::AppError::Conflict(_)));

    let row_version =
        attome_dashboard::lifecycle::do_approve(&state, id, row_version, Uuid::now_v7())
            .await
            .expect("review -> approved");
    assert_eq!(row_version, 2);

    let published_by = Uuid::now_v7();
    let (row_version, version_id, version_number) =
        attome_dashboard::lifecycle::do_publish_dashboard(&state, id, row_version, published_by)
            .await
            .expect("approved -> published");
    assert_eq!(row_version, 3);
    assert_eq!(version_number, 1);
    let (status, _, _) = status_and_version(&db, id).await;
    assert_eq!(status.as_deref(), Some("published"));

    let snapshot_dashboard_id: Uuid =
        sqlx::query_scalar("SELECT dashboard_id FROM dashboard_version WHERE id = $1")
            .bind(version_id)
            .fetch_one(&db)
            .await
            .expect("read the version row do_publish_dashboard just wrote");
    assert_eq!(snapshot_dashboard_id, id);

    assert_eq!(live_version(&db, id).await, Some(version_id));
    let (row_version, status_after) =
        attome_dashboard::lifecycle::do_unpublish(&state, id, row_version, Uuid::now_v7())
            .await
            .expect("published -> draft");
    assert_eq!(row_version, 4);
    assert_eq!(status_after, "draft");
    assert_eq!(
        live_version(&db, id).await,
        None,
        "D-521: unpublish clears the live version"
    );

    let row_version =
        attome_dashboard::lifecycle::do_archive(&state, id, row_version, Uuid::now_v7())
            .await
            .expect("draft -> archived");
    assert_eq!(row_version, 5);
    let (status, _, is_active) = status_and_version(&db, id).await;
    assert_eq!(status.as_deref(), Some("archived"));
    assert!(
        !is_active,
        "archive must also deactivate the row (see lifecycle.rs's doc comment)"
    );
}

#[tokio::test]
async fn clone_copies_fields_and_resets_to_draft() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let source_id = insert_dashboard(&db, "Source Dashboard", Some("published")).await;
    let cloned_by = Uuid::now_v7();
    let new_id = attome_dashboard::lifecycle::do_clone(&state, source_id, cloned_by)
        .await
        .expect("clone");
    assert_ne!(new_id, source_id);

    let (name, dashboard_type, owner_id, lifecycle_status): (
        String,
        String,
        Option<Uuid>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT name, dashboard_type, owner_id, lifecycle_status FROM attome_dashboard WHERE id = $1",
    )
    .bind(new_id)
    .fetch_one(&db)
    .await
    .expect("read cloned row");
    assert_eq!(name, "Source Dashboard (Copy)");
    assert_eq!(dashboard_type, "team");
    assert_eq!(owner_id, Some(cloned_by));
    assert_eq!(
        lifecycle_status.as_deref(),
        Some("draft"),
        "a clone always starts in draft, regardless of the source's own state"
    );
}

/// Regression test for a real bug found 2026-08-29: `do_clone` used to copy
/// only `attome_dashboard`'s own scalar fields and leave the clone with zero
/// pages, despite being documented elsewhere as a full deep copy. Fixed
/// alongside `do_restore_version` — both share `layout::apply_pages_snapshot`.
#[tokio::test]
async fn clone_deep_copies_the_page_section_widget_tree() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let source_id = insert_dashboard(&db, "Tree Source", None).await;
    let page_id = insert_page(&db, source_id, "Overview").await;
    let section_id = insert_section(&db, page_id, None, "row").await;
    insert_breakpoint(&db, section_id, "mobile").await;
    let query_id = Uuid::now_v7();
    let widget_id = insert_widget(&db, section_id, query_id).await;
    sqlx::query("UPDATE dashboard_widget SET view_id = $1 WHERE id = $2")
        .bind("clone-source-view")
        .bind(widget_id)
        .execute(&db)
        .await
        .expect("set view_id on the source widget before cloning");

    let new_id = attome_dashboard::lifecycle::do_clone(&state, source_id, Uuid::now_v7())
        .await
        .expect("clone");

    let (new_page_id, new_page_name): (Uuid, String) =
        sqlx::query_as("SELECT id, name FROM dashboard_page WHERE dashboard_id = $1")
            .bind(new_id)
            .fetch_one(&db)
            .await
            .expect("clone must have exactly one page");
    assert_ne!(
        new_page_id, page_id,
        "a clone into a different dashboard must generate fresh ids, not reuse the source's"
    );
    assert_eq!(new_page_name, "Overview");

    let (new_section_id, section_type): (Uuid, String) =
        sqlx::query_as("SELECT id, section_type FROM dashboard_section WHERE page_id = $1")
            .bind(new_page_id)
            .fetch_one(&db)
            .await
            .expect("clone must have exactly one section");
    assert_ne!(new_section_id, section_id);
    assert_eq!(section_type, "row");

    let breakpoint_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dashboard_section_breakpoint WHERE section_id = $1",
    )
    .bind(new_section_id)
    .fetch_one(&db)
    .await
    .expect("count cloned breakpoints");
    assert_eq!(breakpoint_count, 1);

    let (new_widget_id, cloned_query_id, cloned_view_id): (Uuid, Option<String>, Option<String>) =
        sqlx::query_as("SELECT id, query_id, view_id FROM dashboard_widget WHERE section_id = $1")
            .bind(new_section_id)
            .fetch_one(&db)
            .await
            .expect("clone must have exactly one widget");
    assert_ne!(new_widget_id, widget_id);
    assert_eq!(
        cloned_query_id.as_deref(),
        Some(query_id.to_string()).as_deref(),
        "the widget's stored-query reference must survive the clone"
    );
    assert_eq!(
        cloned_view_id.as_deref(),
        Some("clone-source-view"),
        "the widget's view_id data-source reference must survive the clone"
    );

    // The source's own rows must be untouched — a clone is not a move.
    let source_page_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dashboard_page WHERE id = $1")
            .bind(page_id)
            .fetch_one(&db)
            .await
            .expect("count source page");
    assert_eq!(source_page_count, 1);
}

#[tokio::test]
async fn restore_version_reverts_scalar_fields_and_the_tree() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Restore Test v1", None).await;
    let page_id = insert_page(&db, dashboard_id, "Original Page").await;
    let section_id = insert_section(&db, page_id, None, "row").await;
    // R-07 step 5/6 regression fixture: one breakpoint (to prove restore no
    // longer duplicates it) and `emits`/`listens` on the widget (to prove
    // the snapshot no longer drops them).
    insert_breakpoint(&db, section_id, "mobile").await;
    let (query_id, _) = insert_published_query(&db).await;
    let widget_id = insert_widget(&db, section_id, query_id).await;
    let view_id = insert_view(&db, query_id).await;
    sqlx::query("UPDATE dashboard_widget SET view_id = $1, emits = $2, listens = $3 WHERE id = $4")
        .bind(view_id.to_string())
        .bind(r#"["revenue.selected"]"#)
        .bind(r#"["date_range.changed"]"#)
        .bind(widget_id)
        .execute(&db)
        .await
        .expect("set view_id/emits/listens on the test widget before publish");

    let row_version =
        attome_dashboard::lifecycle::do_submit_for_review(&state, dashboard_id, 0, Uuid::now_v7())
            .await
            .expect("draft -> review");
    let row_version =
        attome_dashboard::lifecycle::do_approve(&state, dashboard_id, row_version, Uuid::now_v7())
            .await
            .expect("review -> approved");
    let (_, version_id, _) = attome_dashboard::lifecycle::do_publish_dashboard(
        &state,
        dashboard_id,
        row_version,
        Uuid::now_v7(),
    )
    .await
    .expect("approved -> published; snapshots the tree above");

    // Mutate everything the restore is supposed to revert: rename the
    // dashboard, delete the page (cascading soft-deletes nothing on its
    // own — this simulates an operator editing the live tree after publish).
    sqlx::query("UPDATE attome_dashboard SET name = 'Edited After Publish' WHERE id = $1")
        .bind(dashboard_id)
        .execute(&db)
        .await
        .expect("mutate name post-publish");
    sqlx::query("UPDATE dashboard_page SET is_active = false WHERE id = $1")
        .bind(page_id)
        .execute(&db)
        .await
        .expect("deactivate the page post-publish");
    sqlx::query("UPDATE dashboard_widget SET view_id = 'edited-after-publish' WHERE id = $1")
        .bind(widget_id)
        .execute(&db)
        .await
        .expect("mutate view_id post-publish");

    let restored_by = Uuid::now_v7();
    attome_dashboard::lifecycle::do_restore_version(&state, dashboard_id, version_id, restored_by)
        .await
        .expect("restore");

    let name: String = sqlx::query_scalar("SELECT name FROM attome_dashboard WHERE id = $1")
        .bind(dashboard_id)
        .fetch_one(&db)
        .await
        .expect("read restored name");
    assert_eq!(
        name, "Restore Test v1",
        "restore must revert scalar fields too"
    );

    let (restored_page_name, page_active): (String, Option<bool>) =
        sqlx::query_as("SELECT name, is_active FROM dashboard_page WHERE id = $1")
            .bind(page_id)
            .fetch_one(&db)
            .await
            .expect("the ORIGINAL page id must come back, not a new one");
    assert_eq!(restored_page_name, "Original Page");
    let (status_after_restore, _, _) = status_and_version(&db, dashboard_id).await;
    assert_eq!(
        status_after_restore.as_deref(),
        Some("draft"),
        "D-521: restore writes the working copy, which has not been reviewed as such"
    );
    assert_eq!(
        live_version(&db, dashboard_id).await,
        Some(version_id),
        "D-521: restore never changes what viewers see"
    );
    assert_ne!(page_active, Some(false), "restore must reactivate it");

    let (restored_widget_id, widget_active, restored_view_id, restored_emits, restored_listens): (
        Uuid,
        Option<bool>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT id, is_active, view_id, emits, listens FROM dashboard_widget \
         WHERE section_id = $1",
    )
    .bind(section_id)
    .fetch_one(&db)
    .await
    .expect("the ORIGINAL widget id must come back");
    assert_eq!(restored_widget_id, widget_id);
    assert_ne!(widget_active, Some(false));
    assert_eq!(
        restored_view_id.as_deref(),
        Some(view_id.to_string().as_str()),
        "view_id must survive the publish -> restore round-trip"
    );
    assert_eq!(
        restored_emits.as_deref(),
        Some(r#"["revenue.selected"]"#),
        "R-07 step 6: emits must survive the publish -> restore round-trip"
    );
    assert_eq!(
        restored_listens.as_deref(),
        Some(r#"["date_range.changed"]"#),
        "R-07 step 6: listens must survive the publish -> restore round-trip"
    );

    let breakpoint_count_after_first_restore: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dashboard_section_breakpoint WHERE section_id = $1",
    )
    .bind(section_id)
    .fetch_one(&db)
    .await
    .expect("count breakpoints after the first restore");
    assert_eq!(
        breakpoint_count_after_first_restore, 1,
        "restore must reproduce the snapshot's own breakpoint count, not add to whatever \
         is already live"
    );

    // Idempotent: restoring the same version a second time must not create
    // duplicate rows (IdPolicy::ReuseIds + ON CONFLICT (id) DO UPDATE for
    // pages/sections/widgets; R-07 step 5's DELETE-then-reinsert for
    // breakpoints, which carry no id to upsert against).
    attome_dashboard::lifecycle::do_restore_version(&state, dashboard_id, version_id, restored_by)
        .await
        .expect("restore again");
    let page_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dashboard_page WHERE dashboard_id = $1 AND is_active = true",
    )
    .bind(dashboard_id)
    .fetch_one(&db)
    .await
    .expect("count pages after a second restore");
    assert_eq!(page_count, 1, "restoring twice must not duplicate rows");

    let breakpoint_count_after_second_restore: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dashboard_section_breakpoint WHERE section_id = $1",
    )
    .bind(section_id)
    .fetch_one(&db)
    .await
    .expect("count breakpoints after the second restore");
    assert_eq!(
        breakpoint_count_after_second_restore, 1,
        "R-07 step 5: restoring twice must equal the snapshot's own breakpoint count (1), \
         not double it — before the DELETE-then-reinsert fix this was 2"
    );
}

#[tokio::test]
async fn restore_version_rejects_a_version_from_another_dashboard() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_a = insert_dashboard(&db, "Dashboard A", None).await;
    let row_version =
        attome_dashboard::lifecycle::do_submit_for_review(&state, dashboard_a, 0, Uuid::now_v7())
            .await
            .expect("draft -> review");
    let row_version =
        attome_dashboard::lifecycle::do_approve(&state, dashboard_a, row_version, Uuid::now_v7())
            .await
            .expect("review -> approved");
    let (_, version_id, _) = attome_dashboard::lifecycle::do_publish_dashboard(
        &state,
        dashboard_a,
        row_version,
        Uuid::now_v7(),
    )
    .await
    .expect("approved -> published");

    let dashboard_b = insert_dashboard(&db, "Dashboard B", None).await;
    let err = attome_dashboard::lifecycle::do_restore_version(
        &state,
        dashboard_b,
        version_id,
        Uuid::now_v7(),
    )
    .await
    .expect_err("a version belonging to a different dashboard must be refused");
    assert!(matches!(err, attome_types::AppError::NotFound));
}

/// D-543 — the adversarial publication-immutability test. After publishing,
/// every definition-bearing input is mutated in turn and the published
/// definition must not move: not the tree, not the view's semantics, not the
/// column metadata, not a new query version, not a parameter or variable
/// default. Republishing then adopts all of it at once.
#[tokio::test]
async fn editing_any_definition_input_leaves_the_published_definition_unchanged() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Definition Immutability", None).await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let section_id = insert_section(&db, page_id, None, "row").await;
    let (query_id, _) = insert_published_query(&db).await;
    let widget_id = insert_widget(&db, section_id, query_id).await;
    let view_id = insert_view(&db, query_id).await;
    sqlx::query("UPDATE dashboard_widget SET view_id = $1 WHERE id = $2")
        .bind(view_id.to_string())
        .bind(widget_id)
        .execute(&db)
        .await
        .expect("bind the widget to the view");
    let parameter_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_parameter \
             (id, dashboard_id, page_id, name, parameter_type, default_value) \
         VALUES ($1, $2, $3, 'period', 'text', 'this_month')",
    )
    .bind(parameter_id)
    .bind(dashboard_id)
    .bind(page_id)
    .execute(&db)
    .await
    .expect("insert parameter");
    let variable_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_variable \
             (id, dashboard_id, page_id, name, variable_type, default_value) \
         VALUES ($1, $2, $3, 'region', 'user_var', 'north')",
    )
    .bind(variable_id)
    .bind(dashboard_id)
    .bind(page_id)
    .execute(&db)
    .await
    .expect("insert variable");

    let (row_version, _) = publish_through_lifecycle(&state, dashboard_id, 0).await;
    let published = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published");
    let before = published.snapshot.expect("a published snapshot");
    let fingerprint = before["publication_fingerprint"]
        .as_str()
        .expect("fingerprint")
        .to_string();
    assert_eq!(
        before["parameters"].as_array().expect("parameters").len(),
        1
    );
    assert_eq!(before["variables"].as_array().expect("variables").len(), 1);

    // Every definition-bearing mutation, one at a time.
    let mutations: Vec<(&str, String)> = vec![
        (
            "the draft tree",
            format!("UPDATE dashboard_widget SET name = 'Edited' WHERE id = '{widget_id}'"),
        ),
        (
            "the view's chart settings",
            format!(
                "UPDATE view SET view_metadata = '{{\"chart_type\":\"bar\"}}'::jsonb \
                 WHERE id = '{view_id}'"
            ),
        ),
        (
            "the view's columns",
            format!(
                "UPDATE view SET table_definition = '[{{\"logicalName\":\"late\"}}]'::jsonb \
                 WHERE id = '{view_id}'"
            ),
        ),
        (
            "the query's columns",
            format!(
                "UPDATE sql_query SET table_definition = '[{{\"logicalName\":\"late\"}}]' \
                 WHERE id = '{query_id}'"
            ),
        ),
        (
            "the query's SQL",
            format!("UPDATE sql_query SET sql_query = 'SELECT 2 AS one' WHERE id = '{query_id}'"),
        ),
        (
            "a parameter default",
            format!(
                "UPDATE dashboard_parameter SET default_value = 'last_year' WHERE id = '{parameter_id}'"
            ),
        ),
        (
            "a variable default",
            format!(
                "UPDATE dashboard_variable SET default_value = 'south' WHERE id = '{variable_id}'"
            ),
        ),
    ];
    for (what, sql) in mutations {
        sqlx::query(&sql).execute(&db).await.expect("mutate");
        let after = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
            .await
            .expect("load published")
            .snapshot
            .expect("a published snapshot");
        assert_eq!(
            after, before,
            "editing {what} must not change the published definition"
        );
        assert_eq!(after["publication_fingerprint"], fingerprint.as_str());
    }

    // A new query version is not adopted either.
    add_query_version(&db, query_id).await;
    let after = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published")
        .snapshot
        .expect("a published snapshot");
    assert_eq!(
        after, before,
        "a new query version must not change the live definition"
    );

    // Republishing adopts every one of them, and the fingerprint moves.
    let row_version = attome_dashboard::lifecycle::do_start_revision(
        &state,
        dashboard_id,
        row_version,
        Uuid::now_v7(),
    )
    .await
    .expect("published -> draft");
    publish_through_lifecycle(&state, dashboard_id, row_version).await;
    let republished = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published")
        .snapshot
        .expect("a published snapshot");
    assert_ne!(republished["publication_fingerprint"], fingerprint.as_str());
    assert_eq!(republished["parameters"][0]["default_value"], "last_year");
    assert_eq!(republished["variables"][0]["default_value"], "south");
    assert_eq!(
        republished["dependencies"][0]["view"]["view_metadata"]["chart_type"],
        "bar"
    );
}

/// D-521 — a widget bound to a query that was never published cannot be pinned,
/// so publish refuses, naming the widget, and nothing becomes live.
#[tokio::test]
async fn publish_refuses_a_widget_whose_query_cannot_be_pinned() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Unpinnable", None).await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let section_id = insert_section(&db, page_id, None, "row").await;
    let widget_id = insert_widget(&db, section_id, Uuid::now_v7()).await;

    let row_version =
        attome_dashboard::lifecycle::do_submit_for_review(&state, dashboard_id, 0, Uuid::now_v7())
            .await
            .expect("draft -> review");
    let row_version =
        attome_dashboard::lifecycle::do_approve(&state, dashboard_id, row_version, Uuid::now_v7())
            .await
            .expect("review -> approved");
    let err = attome_dashboard::lifecycle::do_publish_dashboard(
        &state,
        dashboard_id,
        row_version,
        Uuid::now_v7(),
    )
    .await
    .expect_err("an unpinnable widget must refuse publish");
    match err {
        attome_types::AppError::Validation(message) => assert!(
            message.contains(&widget_id.to_string()),
            "the error must name the widget: {message}"
        ),
        other => panic!("expected a validation error, got {other:?}"),
    }
    assert_eq!(live_version(&db, dashboard_id).await, None);
    let versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dashboard_version WHERE dashboard_id = $1")
            .bind(dashboard_id)
            .fetch_one(&db)
            .await
            .expect("count versions");
    assert_eq!(versions, 0, "a refused publish writes no version");
}

/// D-521 — viewers keep the published snapshot while the working copy is
/// edited, a new revision goes live only when it is published, and restore
/// and activate change the working copy and the live pointer respectively.
#[tokio::test]
async fn viewers_keep_the_published_version_while_the_working_copy_changes() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Immutable Publishing", None).await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let section_id = insert_section(&db, page_id, None, "row").await;
    let (query_id, _) = insert_published_query(&db).await;
    let widget_id = insert_widget(&db, section_id, query_id).await;

    let (row_version, v1) = publish_through_lifecycle(&state, dashboard_id, 0).await;
    let first = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published v1");
    assert_eq!(first.state, "published");
    assert_eq!(first.version_id, Some(v1));

    // Start a revision and edit the working copy: viewers must not see it.
    let row_version = attome_dashboard::lifecycle::do_start_revision(
        &state,
        dashboard_id,
        row_version,
        Uuid::now_v7(),
    )
    .await
    .expect("published -> draft revision");
    assert_eq!(
        live_version(&db, dashboard_id).await,
        Some(v1),
        "start-revision keeps the live version"
    );
    sqlx::query("UPDATE dashboard_widget SET name = 'Edited in revision' WHERE id = $1")
        .bind(widget_id)
        .execute(&db)
        .await
        .expect("edit the working copy");
    let during_revision = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published during revision");
    assert_eq!(
        during_revision.snapshot, first.snapshot,
        "editing the working copy must not change what viewers see"
    );

    // Publish the revision: the pointer moves to v2.
    let (row_version, v2) = publish_through_lifecycle(&state, dashboard_id, row_version).await;
    assert_ne!(v1, v2);
    // An activate prepared before that publish carries a stale row_version and
    // loses the race with a 409 instead of silently replacing v2.
    let err = attome_dashboard::lifecycle::do_activate_version(
        &state,
        dashboard_id,
        v1,
        row_version - 1,
        Uuid::now_v7(),
    )
    .await
    .expect_err("a stale activate must refuse");
    assert!(matches!(err, attome_types::AppError::Conflict(_)));
    assert_eq!(live_version(&db, dashboard_id).await, Some(v2));
    assert_eq!(live_version(&db, dashboard_id).await, Some(v2));
    let second = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published v2");
    assert_eq!(second.version_number, Some(2));
    assert_ne!(second.snapshot, first.snapshot);

    // Restore v1 into the working copy: viewers still see v2.
    attome_dashboard::lifecycle::do_restore_version(&state, dashboard_id, v1, Uuid::now_v7())
        .await
        .expect("restore v1 into the draft");
    assert_eq!(
        live_version(&db, dashboard_id).await,
        Some(v2),
        "restore never moves the live version"
    );
    let (status, row_version_after_restore, _) = status_and_version(&db, dashboard_id).await;
    assert_eq!(status.as_deref(), Some("draft"));
    assert!(row_version_after_restore > row_version);

    // Activate v1: the rollback moves the live pointer back.
    let (_, version_number) = attome_dashboard::lifecycle::do_activate_version(
        &state,
        dashboard_id,
        v1,
        row_version_after_restore,
        Uuid::now_v7(),
    )
    .await
    .expect("activate v1");
    assert_eq!(version_number, 1);
    assert_eq!(live_version(&db, dashboard_id).await, Some(v1));
    // D-062 / audit plan 3.6: start-revision and activate wrote their events
    // in the mutation's transaction; the refused (stale) activate wrote none.
    assert_eq!(
        business_events(&db, dashboard_id, "dashboard.start_revision").await,
        1
    );
    assert_eq!(
        business_events(&db, dashboard_id, "dashboard.activate_version").await,
        1,
        "one successful activation, and no event for the refused stale one"
    );
    let rolled_back = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published after rollback");
    assert_eq!(rolled_back.snapshot, first.snapshot);

    // A version from another dashboard cannot be activated.
    let other = insert_dashboard(&db, "Other", None).await;
    let err =
        attome_dashboard::lifecycle::do_activate_version(&state, other, v1, 0, Uuid::now_v7())
            .await
            .expect_err("a foreign version must be refused");
    assert!(matches!(err, attome_types::AppError::NotFound));
}

/// D-521 — a dashboard marked `published` with no live version shows nothing
/// to viewers, cannot be published in place, and has nothing to unpublish.
#[tokio::test]
async fn a_published_dashboard_without_a_version_shows_nothing() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Unversioned Published", Some("published")).await;
    insert_page(&db, dashboard_id, "Unversioned Page").await;

    let published = attome_dashboard::lifecycle::do_load_published(&db, dashboard_id)
        .await
        .expect("load published");
    assert_eq!(published.state, "none");
    assert_eq!(published.version_id, None);
    assert!(published.snapshot.is_none());

    let err =
        attome_dashboard::lifecycle::do_publish_dashboard(&state, dashboard_id, 0, Uuid::now_v7())
            .await
            .expect_err("a row without review cannot be published");
    assert!(matches!(err, attome_types::AppError::Conflict(_)));

    let err = attome_dashboard::lifecycle::do_unpublish(&state, dashboard_id, 0, Uuid::now_v7())
        .await
        .expect_err("there is no live version to unpublish");
    assert!(matches!(err, attome_types::AppError::Conflict(_)));
}

/// D-520/D-527 — a page is created with exactly one root grid section, the
/// draft tree carries `row_version`s, a page without a section is reported
/// rather than repaired on read, and the explicit repair refuses to add a
/// second section.
#[tokio::test]
async fn pages_are_created_with_a_root_section_and_the_draft_tree_loads_in_one_call() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Pages Route", None).await;
    let actor = Uuid::now_v7();
    let created = attome_dashboard::pages::do_create_page(
        &state,
        dashboard_id,
        attome_dashboard::pages::NewPageBody {
            name: "Created Page".to_string(),
            sequence: Some(10.0),
            ..Default::default()
        },
        actor,
    )
    .await
    .expect("create page");
    let (page_dashboard, section_count): (Option<Uuid>, i64) = sqlx::query_as(
        "SELECT p.dashboard_id, (SELECT COUNT(*) FROM dashboard_section s \
                                 WHERE s.page_id = p.id AND s.is_active = true) \
         FROM dashboard_page p WHERE p.id = $1",
    )
    .bind(created.id)
    .fetch_one(&db)
    .await
    .expect("read created page");
    assert_eq!(
        page_dashboard,
        Some(dashboard_id),
        "the page is owned through dashboard_id"
    );
    assert_eq!(section_count, 1, "exactly one root section");

    // A page inserted without a section is reported, not repaired on read.
    let bare_page = insert_page(&db, dashboard_id, "Bare Page").await;
    let ctx = common::admin_ctx(actor);
    let tree = attome_dashboard::pages::do_load_draft_tree(&state, &ctx, dashboard_id)
        .await
        .expect("load draft tree");
    assert_eq!(tree.dashboard.id, dashboard_id);
    assert_eq!(tree.pages.len(), 2);
    assert_eq!(tree.sections.len(), 1);
    assert!(
        tree.pages
            .iter()
            .all(|p| p.data.contains_key("row_version"))
    );
    assert_eq!(tree.pages_needing_root_section, vec![bare_page]);
    let sections_after_read: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM dashboard_section WHERE page_id = $1")
            .bind(bare_page)
            .fetch_one(&db)
            .await
            .expect("count sections");
    assert_eq!(sections_after_read, 0, "loading the tree must not write");

    let repaired =
        attome_dashboard::pages::do_repair_root_section(&state, dashboard_id, bare_page, actor)
            .await
            .expect("repair the bare page");
    assert_ne!(repaired, created.root_section_id);
    let err =
        attome_dashboard::pages::do_repair_root_section(&state, dashboard_id, bare_page, actor)
            .await
            .expect_err("a second repair must refuse");
    assert!(matches!(err, attome_types::AppError::Conflict(_)));
    // D-062 / audit plan 3.6: each successful mutation wrote its event in its
    // own transaction; the refused second repair wrote none.
    assert_eq!(
        business_events(&db, dashboard_id, "dashboard.page_create").await,
        1
    );
    assert_eq!(
        business_events(&db, dashboard_id, "dashboard.page_root_section_repair").await,
        1
    );

    // A page on another dashboard is not found through this dashboard.
    let other = insert_dashboard(&db, "Other Dashboard", None).await;
    let err = attome_dashboard::pages::do_repair_root_section(&state, other, bare_page, actor)
        .await
        .expect_err("a foreign page must be refused");
    assert!(matches!(err, attome_types::AppError::NotFound));
}

/// D-520 — a draft tree over the page ceiling is refused, never truncated.
#[tokio::test]
async fn a_draft_tree_over_the_page_ceiling_is_refused() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Too Many Pages", None).await;
    for i in 0..51 {
        insert_page(&db, dashboard_id, &format!("Page {i}")).await;
    }
    let ctx = common::admin_ctx(Uuid::now_v7());
    let err = attome_dashboard::pages::do_load_draft_tree(&state, &ctx, dashboard_id)
        .await
        .expect_err("51 pages must be refused");
    assert!(matches!(err, attome_types::AppError::Validation(_)));
}

/// `create_from_layout` — the single-call, AI-authoring-friendly counterpart
/// to `insert_dashboard`/`insert_page`/`insert_section`/`insert_widget`
/// above: one JSON-shaped document in, a whole draft dashboard tree out.
mod create_from_layout {
    use attome_dashboard::layout::{NewDashboardFields, SnapshotSection, SnapshotWidget};

    use super::*;

    fn fields(name: &str) -> NewDashboardFields {
        NewDashboardFields {
            name: name.to_string(),
            name_ar: None,
            description: None,
            description_ar: None,
            dashboard_type: "team".to_string(),
            visibility: Some("private".to_string()),
        }
    }

    #[tokio::test]
    async fn materializes_a_full_page_section_widget_tree_in_one_call() {
        let state = skip_if_no_db!(common::test_state().await);
        let db = common::pool(&state).clone();
        common::seed_once(&state).await;

        let query_id = Uuid::now_v7();
        let child = SnapshotSection {
            section_type: "card".to_string(),
            layout_mode: "grid".to_string(),
            widgets: vec![SnapshotWidget {
                widget_type: "line_chart".to_string(),
                name: Some("Revenue".to_string()),
                query_id: Some(query_id.to_string()),
                ..Default::default()
            }],
            breakpoints: vec![attome_dashboard::layout::SnapshotBreakpoint {
                breakpoint: "mobile".to_string(),
                is_visible: Some(false),
                ..Default::default()
            }],
            ..Default::default()
        };
        let parent = SnapshotSection {
            section_type: "row".to_string(),
            layout_mode: "grid".to_string(),
            children: vec![child],
            ..Default::default()
        };
        let page = attome_dashboard::layout::SnapshotPage {
            name: "Overview".to_string(),
            sections: vec![parent],
            ..Default::default()
        };

        let new_id = attome_dashboard::layout::do_create_from_layout(
            &state,
            fields("AI-authored Dashboard"),
            vec![page],
            Uuid::now_v7(),
        )
        .await
        .expect("create_from_layout");

        let (name, lifecycle_status): (String, Option<String>) =
            sqlx::query_as("SELECT name, lifecycle_status FROM attome_dashboard WHERE id = $1")
                .bind(new_id)
                .fetch_one(&db)
                .await
                .expect("read created attome_dashboard row");
        assert_eq!(name, "AI-authored Dashboard");
        assert_eq!(
            lifecycle_status.as_deref(),
            Some("draft"),
            "a layout-created dashboard always starts in draft"
        );

        let page_id: Uuid =
            sqlx::query_scalar("SELECT id FROM dashboard_page WHERE dashboard_id = $1")
                .bind(new_id)
                .fetch_one(&db)
                .await
                .expect("exactly one page must have been created");

        let (parent_section_id, section_type): (Uuid, String) = sqlx::query_as(
            "SELECT id, section_type FROM dashboard_section \
             WHERE page_id = $1 AND parent_section_id IS NULL",
        )
        .bind(page_id)
        .fetch_one(&db)
        .await
        .expect("exactly one top-level section must have been created");
        assert_eq!(section_type, "row");

        let child_section_id: Uuid =
            sqlx::query_scalar("SELECT id FROM dashboard_section WHERE parent_section_id = $1")
                .bind(parent_section_id)
                .fetch_one(&db)
                .await
                .expect("the child section must nest under the parent");

        let (widget_name, cloned_query_id): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT name, query_id FROM dashboard_widget WHERE section_id = $1")
                .bind(child_section_id)
                .fetch_one(&db)
                .await
                .expect("the widget must have been created under the child section");
        assert_eq!(widget_name.as_deref(), Some("Revenue"));
        assert_eq!(
            cloned_query_id.as_deref(),
            Some(query_id.to_string()).as_deref()
        );

        let breakpoint_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dashboard_section_breakpoint WHERE section_id = $1",
        )
        .bind(child_section_id)
        .fetch_one(&db)
        .await
        .expect("count breakpoints");
        assert_eq!(breakpoint_count, 1);
    }

    #[tokio::test]
    async fn rejects_an_unknown_widget_type() {
        let state = skip_if_no_db!(common::test_state().await);
        let db = common::pool(&state).clone();
        common::seed_once(&state).await;

        let section = SnapshotSection {
            section_type: "row".to_string(),
            layout_mode: "grid".to_string(),
            widgets: vec![SnapshotWidget {
                widget_type: "not_a_real_widget_type".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let page = attome_dashboard::layout::SnapshotPage {
            name: "Overview".to_string(),
            sections: vec![section],
            ..Default::default()
        };

        let err = attome_dashboard::layout::do_create_from_layout(
            &state,
            fields("Bad Widget Type"),
            vec![page],
            Uuid::now_v7(),
        )
        .await
        .expect_err("an unregistered widget_type must be rejected");
        assert!(matches!(err, attome_types::AppError::Validation(_)));

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM attome_dashboard WHERE name = 'Bad Widget Type'",
        )
        .fetch_one(&db)
        .await
        .expect("count");
        assert_eq!(
            count, 0,
            "a rejected layout must not leave a partial dashboard row behind"
        );
    }

    #[tokio::test]
    async fn rejects_an_invalid_section_type() {
        let state = skip_if_no_db!(common::test_state().await);
        common::seed_once(&state).await;

        let section = SnapshotSection {
            section_type: "not_a_real_section_type".to_string(),
            layout_mode: "grid".to_string(),
            ..Default::default()
        };
        let page = attome_dashboard::layout::SnapshotPage {
            name: "Overview".to_string(),
            sections: vec![section],
            ..Default::default()
        };

        let err = attome_dashboard::layout::do_create_from_layout(
            &state,
            fields("Bad Section Type"),
            vec![page],
            Uuid::now_v7(),
        )
        .await
        .expect_err("an out-of-band section_type must be rejected");
        assert!(matches!(err, attome_types::AppError::Validation(_)));
    }

    #[tokio::test]
    async fn rejects_an_invalid_dashboard_type() {
        let state = skip_if_no_db!(common::test_state().await);
        common::seed_once(&state).await;

        let mut bad_fields = fields("Bad Dashboard Type");
        bad_fields.dashboard_type = "not_a_real_dashboard_type".to_string();

        let err = attome_dashboard::layout::do_create_from_layout(
            &state,
            bad_fields,
            vec![],
            Uuid::now_v7(),
        )
        .await
        .expect_err("an out-of-band dashboard_type must be rejected");
        assert!(matches!(err, attome_types::AppError::Validation(_)));
    }
}

/// R-16 item 5: proves R-07 step 4's locking work — `do_clone` takes
/// `lock_dashboard(source)` immediately after `begin()` (see
/// `lifecycle.rs::do_clone`'s own doc comment), so a concurrent
/// `restore_version` (or any other lifecycle transition) already holding
/// that same advisory lock must make a racing `do_clone` fail with
/// `Conflict`, not silently interleave with it and clone a torn snapshot.
///
/// A dedicated connection outside the pool simulates "restore's transaction
/// is open elsewhere" — same fixture `attome-dashboard/tests/scenario.rs::
/// dedicated_connection`/`attome-api/tests/content_hierarchy_lock.rs::
/// dedicated_connection` use, and for the same reason:
/// `pg_try_advisory_xact_lock` is scoped to the session/transaction, so a
/// pooled connection could otherwise hand the same session to both
/// "requests".
async fn dedicated_connection() -> Option<PgConnection> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgConnection::connect(&url)
            .await
            .expect("connect a dedicated test connection"),
    )
}

#[tokio::test]
async fn clone_conflicts_while_another_transaction_holds_the_dashboards_lifecycle_lock() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Lock Contention Test", None).await;

    // Simulates `do_restore_version` (or any other lifecycle transition)
    // already mid-flight: take the exact same advisory lock key
    // `lock_dashboard` uses in `lifecycle.rs`, on a connection/transaction of
    // its own, and hold it open.
    let mut holder = skip_if_no_db!(dedicated_connection().await);
    sqlx::query("BEGIN")
        .execute(&mut holder)
        .await
        .expect("BEGIN on the holder connection");
    let locked: bool =
        sqlx::query_scalar::<_, bool>("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_dashboard::ADVISORY_LOCK_NAMESPACE)
            .bind(format!("attome-dashboard/lifecycle:{dashboard_id}"))
            .fetch_one(&mut holder)
            .await
            .expect("take the dashboard lifecycle lock on the holder connection");
    assert!(locked, "the holder must be the first to take this lock");

    let err = attome_dashboard::lifecycle::do_clone(&state, dashboard_id, Uuid::now_v7())
        .await
        .expect_err("clone must be refused while another transaction holds this dashboard's lock");
    assert!(
        matches!(err, attome_types::AppError::Conflict(_)),
        "expected Conflict, got {err:?}"
    );

    // No clone must have been created — a refused clone is not a partial one.
    let clone_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM attome_dashboard WHERE name = 'Lock Contention Test (Copy)'",
    )
    .fetch_one(&db)
    .await
    .expect("count would-be clones");
    assert_eq!(clone_count, 0);

    sqlx::query("ROLLBACK")
        .execute(&mut holder)
        .await
        .expect("ROLLBACK the holder connection");

    // Releasing the lock lets a subsequent clone proceed normally.
    let new_id = attome_dashboard::lifecycle::do_clone(&state, dashboard_id, Uuid::now_v7())
        .await
        .expect("clone must succeed once the lock is released");
    assert_ne!(new_id, dashboard_id);
}
