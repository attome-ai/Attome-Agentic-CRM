//! Z2-T10: query budgets for the hot record paths (an N+1 guard). Each
//! request runs through the whole router, authentication included, and
//! `attome_testkit::query_counter` counts the SQL statements its task ran.
//!
//! A budget is the count measured on the code when it was set, plus nothing:
//! a change that adds a query to a hot path raises it here, on purpose, with
//! the reason. The list's count must not grow with the page size.
//!
//! This binary installs its own global tracing subscriber (the counter);
//! nothing else in it may install one.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use attome_testkit::query_counter::count_queries;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// GET one record: the session and the caller's privileges (when not cached),
/// the entity's read grants and row-level predicate, the row, and its lookup
/// names.
const RECORD_GET_BUDGET: usize = 6;

/// One page of a list with three lookups: the stored query, the count, the
/// page, and one lookup-name read per lookup target (never per row).
const RECORD_LIST_BUDGET: usize = 8;

async fn create_entity(app: &TestApp, name: &str) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().parse().unwrap()
}

async fn add_field(app: &TestApp, entity_id: Uuid, field: Value) {
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            Some(field),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn create_record(app: &TestApp, entity: &str, body: Value) -> Uuid {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(body))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

/// An entity with three lookups to a second one, and 50 records.
async fn fixture(app: &TestApp) -> (String, Vec<Uuid>) {
    let token = Uuid::now_v7().simple().to_string();
    let target = format!("qb_target_{}", &token[..12]);
    let child = format!("qb_child_{}", &token[..12]);
    let target_id = create_entity(app, &target).await;
    add_field(
        app,
        target_id,
        json!({ "logicalname": "name", "name": "name", "field_type": "text" }),
    )
    .await;
    let child_id = create_entity(app, &child).await;
    add_field(
        app,
        child_id,
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
    )
    .await;
    for lookup in ["first_ref", "second_ref", "third_ref"] {
        add_field(
            app,
            child_id,
            json!({ "logicalname": lookup, "name": lookup,
                    "field_type": "lookup", "lookup_entity_ref": target_id }),
        )
        .await;
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    let mut targets = Vec::new();
    for n in 0..3 {
        targets.push(create_record(app, &target, json!({ "name": format!("T{n}") })).await);
    }
    let mut ids = Vec::new();
    for n in 0..50 {
        ids.push(
            create_record(
                app,
                &child,
                json!({
                    "title": format!("row {n}"),
                    "first_ref": targets[0],
                    "second_ref": targets[1],
                    "third_ref": targets[2],
                }),
            )
            .await,
        );
    }
    (child, ids)
}

async fn list(app: &TestApp, entity: &str, page_size: i64) -> (usize, usize) {
    let ((status, body), queries) = count_queries(app.request(
        Method::POST,
        "/api/v1/query/execute",
        Some(json!({ "entity": entity, "page_size": page_size })),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["data"]["records"].as_array().map_or(0, Vec::len);
    (queries, rows)
}

// feature: Z2
#[test]
fn record_get_and_list_within_budget() {
    attome_testkit::query_counter::install();
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (child, ids) = fixture(&app).await;
        let path = format!("/api/v1/{child}/{}", ids[0]);
        // Warm the caches a first request fills (session, privileges).
        let (status, body) = app.request(Method::GET, &path, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let ((status, body), queries) = count_queries(app.request(Method::GET, &path, None)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            queries <= RECORD_GET_BUDGET,
            "GET one record ran {queries} statements, over its budget of {RECORD_GET_BUDGET}"
        );

        list(&app, &child, 50).await;
        let (queries, rows) = list(&app, &child, 50).await;
        assert_eq!(rows, 50);
        assert!(
            queries <= RECORD_LIST_BUDGET,
            "a 50-row list ran {queries} statements, over its budget of {RECORD_LIST_BUDGET}"
        );
    });
}

// feature: Z2
#[test]
fn list_query_count_independent_of_page_size() {
    attome_testkit::query_counter::install();
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (child, _) = fixture(&app).await;
        list(&app, &child, 10).await;
        let (ten, rows_ten) = list(&app, &child, 10).await;
        let (fifty, rows_fifty) = list(&app, &child, 50).await;
        assert_eq!((rows_ten, rows_fifty), (10, 50));
        assert_eq!(
            ten, fifty,
            "a list's statement count grows with its page size (N+1): 10 rows ran {ten}, 50 ran {fifty}"
        );
    });
}

/// AA4-T6: an entity with one lookup per target in `targets`, and 50 rows
/// each pointing at a different record of every target. Returns its name.
async fn spread_fixture(app: &TestApp, targets: usize) -> String {
    let token = Uuid::now_v7().simple().to_string();
    let child = format!("ln_child_{}", &token[..12]);
    let mut target_names = Vec::new();
    let mut target_ids = Vec::new();
    for t in 0..targets {
        let name = format!("ln_t{t}_{}", &token[..10]);
        let id = create_entity(app, &name).await;
        add_field(
            app,
            id,
            json!({ "logicalname": "name", "name": "name", "field_type": "text" }),
        )
        .await;
        target_names.push(name);
        target_ids.push(id);
    }
    let child_id = create_entity(app, &child).await;
    add_field(
        app,
        child_id,
        json!({ "logicalname": "title", "name": "title", "field_type": "text" }),
    )
    .await;
    for (t, target_id) in target_ids.iter().enumerate() {
        add_field(
            app,
            child_id,
            json!({ "logicalname": format!("ref_{t}"), "name": format!("ref_{t}"),
                    "field_type": "lookup", "lookup_entity_ref": target_id }),
        )
        .await;
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    for n in 0..50 {
        let mut body = json!({ "title": format!("row {n}") });
        for (t, target) in target_names.iter().enumerate() {
            let id = create_record(app, target, json!({ "name": format!("{target} {n}") })).await;
            body[format!("ref_{t}")] = json!(id);
        }
        create_record(app, &child, body).await;
    }
    child
}

/// The statements of one 50-row list that resolved lookup names. Only the
/// first call is measured: a repeat within five seconds is served from the
/// repeat-query cache (AA4-T9) and reads nothing.
async fn lookup_name_statements(app: &TestApp, entity: &str) -> usize {
    let ((status, body), statements) = attome_testkit::query_counter::record_queries(app.request(
        Method::POST,
        "/api/v1/query/execute",
        Some(json!({ "entity": entity, "page_size": 50 })),
    ))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["records"].as_array().map(Vec::len), Some(50));
    statements
        .iter()
        .filter(|s| s.contains("entity.lookup_names"))
        .count()
}

// feature: AA4
#[test]
fn lookup_names_one_query_per_target() {
    attome_testkit::query_counter::install();
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let child = spread_fixture(&app, 1).await;
        assert_eq!(
            lookup_name_statements(&app, &child).await,
            1,
            "50 rows pointing at 50 different records resolve their names in one statement"
        );
    });
}

// feature: AA4
#[test]
fn lookup_names_two_lookups_two_queries() {
    attome_testkit::query_counter::install();
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let child = spread_fixture(&app, 2).await;
        assert_eq!(
            lookup_name_statements(&app, &child).await,
            2,
            "two lookup targets: one name statement each, never one per row"
        );
    });
}
