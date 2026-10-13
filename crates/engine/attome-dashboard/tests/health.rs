//! R-16 item 4 (`document/xrm/module/M26-dashboard/remediation.md`)
//! — `health.rs::do_health_check` exercised directly against a live
//! database, same "call the `pub` `do_*` function, skip the HTTP layer"
//! convention every suite in this crate already uses (see
//! `tests/dashboard_crud.rs`'s module doc comment).
//!
//! `do_health_check` originally checked only `query_id` (against
//! `sql_query`) — R-16 extended it to also check `view_id` (against
//! `view`), since a `declarative_widget`/`entity_data_grid` widget
//! can bind either independently and either can go stale on its own.
//!
//! Requires a live Postgres (`DATABASE_URL`) — skips (loudly) when unset,
//! except under `CI`. Run with `--test-threads=1` (idempotent provisioning
//! DDL shared with the other suites in this crate):
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-dashboard --test health -- --test-threads=1
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

mod common;

use attome_testkit::skip_if_no_db;

use attome_db::DbPool;
use serde_json::Value;
use uuid::Uuid;

async fn insert_dashboard(db: &DbPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query("INSERT INTO attome_dashboard (id, name, dashboard_type) VALUES ($1, $2, 'team')")
        .bind(id)
        .bind(name)
        .execute(db)
        .await
        .expect("insert test attome_dashboard row");
    id
}

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

async fn insert_section(db: &DbPool, page_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_section (id, page_id, section_type, layout_mode) \
         VALUES ($1, $2, 'row', 'grid')",
    )
    .bind(id)
    .bind(page_id)
    .execute(db)
    .await
    .expect("insert test dashboard_section row");
    id
}

async fn insert_widget(
    db: &DbPool,
    section_id: Uuid,
    name: &str,
    query_id: Option<&str>,
    view_id: Option<&str>,
) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO dashboard_widget (id, section_id, widget_type, name, query_id, view_id) \
         VALUES ($1, $2, 'line_chart', $3, $4, $5)",
    )
    .bind(id)
    .bind(section_id)
    .bind(name)
    .bind(query_id)
    .bind(view_id)
    .execute(db)
    .await
    .expect("insert test dashboard_widget row");
    id
}

/// `sql_query` is a legacy infrastructure table (0000_core_bootstrap):
/// its "name" column is actually `record_no` (varchar), and
/// `entity_logical_name` is a `uuid` (an entity id, not a logicalname string,
/// despite the name) — same shape `query_admin.rs::do_create_query`'s own
/// `INSERT` uses. Left NULL here: this suite never reads it back.
async fn insert_sql_query(db: &DbPool, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO sql_query (id, record_no, sql_query, is_active, owner_layer) \
         VALUES ($1, $2, 'SELECT 1', true, 'project')",
    )
    .bind(id)
    .bind(name)
    .execute(db)
    .await
    .expect("insert test sql_query row");
    id
}

/// `view.entity_logical_name`/`.sql_query_ref` are both required FKs
/// (0078_separate_views_from_sql_queries.sql) — a real entity id and a real
/// `sql_query` row are needed, not placeholders.
async fn insert_view(db: &DbPool, name: &str, entity_id: Uuid, query_id: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO view (id, name, entity_logical_name, sql_query_ref, owner_layer) \
         VALUES ($1, $2, $3, $4, 'project')",
    )
    .bind(id)
    .bind(name)
    .bind(entity_id)
    .bind(query_id)
    .execute(db)
    .await
    .expect("insert test view row");
    id
}

async fn dashboard_entity_id(db: &DbPool) -> Uuid {
    sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = 'attome_dashboard' AND (is_active IS NULL OR is_active = true)",
    )
    .fetch_one(db)
    .await
    .expect("attome_dashboard entity must already be provisioned by attome_dashboard::seed")
}

fn broken_reasons_for(broken: &[Value], field: &str) -> Vec<String> {
    broken
        .iter()
        .filter(|b| b["field"] == field)
        .map(|b| b["reason"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn a_healthy_dashboard_reports_nothing_broken() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let entity_id = dashboard_entity_id(&db).await;
    let query_id = insert_sql_query(&db, "Healthy Query").await;
    let view_query_id = insert_sql_query(&db, "Healthy View's Backing Query").await;
    let view_id = insert_view(&db, "Healthy View", entity_id, view_query_id).await;

    let dashboard_id = insert_dashboard(&db, "Healthy Dashboard").await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let section_id = insert_section(&db, page_id).await;
    insert_widget(
        &db,
        section_id,
        "Query Widget",
        Some(&query_id.to_string()),
        None,
    )
    .await;
    insert_widget(
        &db,
        section_id,
        "View Widget",
        None,
        Some(&view_id.to_string()),
    )
    .await;

    let result = attome_dashboard::health::do_health_check(&db, dashboard_id)
        .await
        .expect("health check must succeed");
    assert_eq!(result.checked, 2);
    assert!(
        result.broken.is_empty(),
        "expected nothing broken, got {:?}",
        serde_json::to_value(&result.broken).unwrap()
    );
}

/// R-16 item 4's exact case: a dashboard with one broken `query_id`
/// reference and one broken `view_id` reference — both must be reported.
#[tokio::test]
async fn a_broken_query_id_and_a_broken_view_id_are_both_reported() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Broken Refs Dashboard").await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let section_id = insert_section(&db, page_id).await;

    let dangling_query_id = Uuid::now_v7(); // well-formed, but no such row
    let dangling_view_id = Uuid::now_v7(); // well-formed, but no such row
    insert_widget(
        &db,
        section_id,
        "Broken Query Widget",
        Some(&dangling_query_id.to_string()),
        None,
    )
    .await;
    insert_widget(
        &db,
        section_id,
        "Broken View Widget",
        None,
        Some(&dangling_view_id.to_string()),
    )
    .await;

    let result = attome_dashboard::health::do_health_check(&db, dashboard_id)
        .await
        .expect("health check must succeed");
    assert_eq!(result.checked, 2);
    assert_eq!(
        result.broken.len(),
        2,
        "both broken references must be reported"
    );

    let broken_json = serde_json::to_value(&result.broken).unwrap();
    let broken = broken_json.as_array().unwrap();
    assert_eq!(
        broken_reasons_for(broken, "query_id"),
        vec!["not_found".to_string()]
    );
    assert_eq!(
        broken_reasons_for(broken, "view_id"),
        vec!["not_found".to_string()]
    );
    assert!(
        broken
            .iter()
            .any(|b| b["value"] == dangling_query_id.to_string()),
        "the broken query_id entry must carry the dangling value: {broken:?}"
    );
    assert!(
        broken
            .iter()
            .any(|b| b["value"] == dangling_view_id.to_string()),
        "the broken view_id entry must carry the dangling value: {broken:?}"
    );
}

/// Not-a-UUID-at-all is reported distinctly from a well-formed-but-missing
/// id, for both `query_id` and `view_id`.
#[tokio::test]
async fn a_malformed_query_id_and_view_id_are_reported_as_invalid_format() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "Malformed Refs Dashboard").await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let section_id = insert_section(&db, page_id).await;
    insert_widget(
        &db,
        section_id,
        "Malformed Widget",
        Some("not-a-uuid"),
        Some("also-not-a-uuid"),
    )
    .await;

    let result = attome_dashboard::health::do_health_check(&db, dashboard_id)
        .await
        .expect("health check must succeed");
    assert_eq!(result.checked, 2);
    let broken_json = serde_json::to_value(&result.broken).unwrap();
    let broken = broken_json.as_array().unwrap();
    assert_eq!(
        broken_reasons_for(broken, "query_id"),
        vec!["invalid_format".to_string()]
    );
    assert_eq!(
        broken_reasons_for(broken, "view_id"),
        vec!["invalid_format".to_string()]
    );
}

/// A widget with no `query_id`/`view_id` at all (rich text, dividers, …) is
/// not counted.
#[tokio::test]
async fn widgets_with_no_data_source_are_not_counted() {
    let state = skip_if_no_db!(common::test_state().await);
    let db = common::pool(&state).clone();
    common::seed_once(&state).await;

    let dashboard_id = insert_dashboard(&db, "No Data Source Dashboard").await;
    let page_id = insert_page(&db, dashboard_id, "Overview").await;
    let section_id = insert_section(&db, page_id).await;
    insert_widget(&db, section_id, "Rich Text Widget", None, None).await;

    let result = attome_dashboard::health::do_health_check(&db, dashboard_id)
        .await
        .expect("health check must succeed");
    assert_eq!(result.checked, 0);
    assert!(result.broken.is_empty());
}
