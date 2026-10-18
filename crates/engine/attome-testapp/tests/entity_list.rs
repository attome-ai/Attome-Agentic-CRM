//! S1-T2: `GET /api/v1/{entity}` lists records through the query engine:
//! `select`, `filter[<field>][<op>]`, `sort` and keyset pages.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use uuid::Uuid;

/// An entity with `title` and `amount`, and records 1 to 7.
async fn fixture(app: &TestApp) -> String {
    let entity = format!("elist_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": entity, "name": entity })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    for (name, ty) in [("title", "text"), ("amount", "number")] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{id}/fields"),
                Some(json!({ "logicalname": name, "name": name, "field_type": ty,
                             "is_sortable": true, "is_filterable": true })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    for n in 1..=7 {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": format!("row {n}"), "amount": n * 10 })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    entity
}

async fn get(app: &TestApp, path: &str) -> (StatusCode, Value) {
    app.request(Method::GET, path, None).await
}

fn items(page: &Value) -> &Vec<Value> {
    page["items"].as_array().unwrap()
}

// feature: S1
#[test]
fn get_list_returns_selected_attributes() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let (status, page) = get(&app, &format!("/api/v1/{entity}?select=title")).await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(items(&page).len(), 7);
        let first = &items(&page)[0];
        assert!(first.get("title").is_some(), "{first}");
        assert!(
            first.get("amount").is_none(),
            "select keeps only title: {first}"
        );
        let (status, _) = get(&app, &format!("/api/v1/{entity}?select=nope")).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: S1
#[test]
fn get_list_filters_and_sorts() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let (status, page) = get(
            &app,
            &format!("/api/v1/{entity}?filter%5Bamount%5D%5Bgt%5D=30&sort=-amount"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        let amounts: Vec<f64> = items(&page)
            .iter()
            .map(|r| r["amount"].as_f64().unwrap())
            .collect();
        assert_eq!(amounts, vec![70.0, 60.0, 50.0, 40.0], "{page}");
        let (status, page) = get(
            &app,
            &format!("/api/v1/{entity}?filter%5Btitle%5D%5Bin%5D=row%201,row%202"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{page}");
        assert_eq!(items(&page).len(), 2, "{page}");
        let (status, _) = get(
            &app,
            &format!("/api/v1/{entity}?filter%5Bamount%5D%5Bapprox%5D=1"),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}

// feature: S1
#[test]
fn get_list_cursor_pages_without_overlap() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = fixture(&app).await;
        let mut seen = std::collections::BTreeSet::new();
        let mut path = format!("/api/v1/{entity}?page_size=3&sort=amount");
        let mut pages = 0;
        loop {
            let (status, page) = get(&app, &path).await;
            assert_eq!(status, StatusCode::OK, "{page}");
            for record in items(&page) {
                let id = record["id"].as_str().unwrap().to_owned();
                assert!(seen.insert(id), "a record on two pages: {page}");
            }
            pages += 1;
            match page["next_cursor"].as_str() {
                Some(cursor) => {
                    path = format!("/api/v1/{entity}?page_size=3&sort=amount&cursor={cursor}");
                }
                None => break,
            }
            assert!(pages < 10, "paging does not end");
        }
        assert_eq!(seen.len(), 7);
        assert!(pages >= 3);
    });
}
