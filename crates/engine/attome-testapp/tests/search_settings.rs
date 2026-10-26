//! A25-T3: an administrator's synonyms widen a search, and a pinned record
//! is placed only for a caller who may read it.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_search::{Audience, execute_search};
use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// A fresh entity with a `title`, and one record per title, each indexed.
async fn indexed(app: &TestApp, titles: &[&str]) -> (String, Vec<Uuid>) {
    let name = format!("ss_{}", &Uuid::now_v7().simple().to_string()[..12]);
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{id}/fields"),
            Some(json!({ "logicalname": "title", "name": "title", "field_type": "text" })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    let mut ids = Vec::new();
    for title in titles {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{name}"),
                Some(json!({ "title": title })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let record: Uuid = body["id"].as_str().unwrap().parse().unwrap();
        let row = attome_search::project(title, None, title, Vec::new());
        attome_search::upsert_row(app.db(), &name, record, &row, None, None, None)
            .await
            .unwrap();
        ids.push(record);
    }
    (name, ids)
}

// feature: A25
#[test]
fn synonym_cr_finds_commercial_registration() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..8];
        let title = format!("Commercial registration filed {tag}");
        let (_entity, ids) = indexed(&app, &[&title]).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let short = format!("cr{tag}");
        let long = format!("commercial registration filed {tag}");

        let before = execute_search(&app.state, &admin, &short, 1, 20, Audience::Human)
            .await
            .unwrap();
        assert!(
            before.items.iter().all(|h| h.record_id != ids[0]),
            "no synonym yet: {:?}",
            before.items
        );

        sqlx::query("INSERT INTO search_synonym (terms) VALUES ($1)")
            .bind(vec![short.clone(), long])
            .execute(app.db())
            .await
            .unwrap();
        attome_search::controls::invalidate();
        let after = execute_search(&app.state, &admin, &short, 1, 20, Audience::Human)
            .await
            .unwrap();
        assert!(
            after.items.iter().any(|h| h.record_id == ids[0]),
            "the synonym finds it: {:?} (route {})",
            after.items,
            after.route
        );
    });
}

// feature: A25
#[test]
fn pin_hidden_from_unauthorized() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..8];
        let query = format!("pinned{tag}");
        let (entity, ids) = indexed(
            &app,
            &[&format!("Pinned brochure {tag}"), &format!("Other {tag}")],
        )
        .await;
        sqlx::query(
            "INSERT INTO search_pin (query_norm, entity_logicalname, record_id, position) \
             VALUES ($1, $2, $3, 1)",
        )
        .bind(attome_search::normalize_ar(&query))
        .bind(&entity)
        .bind(ids[1])
        .execute(app.db())
        .await
        .unwrap();
        attome_search::controls::invalidate();

        // An administrator sees the pinned record first.
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let seen = execute_search(&app.state, &admin, &query, 1, 20, Audience::Human)
            .await
            .unwrap();
        assert_eq!(
            seen.items.first().map(|h| h.record_id),
            Some(ids[1]),
            "{:?}",
            seen.items
        );

        // Someone who may not read the entity never sees it, pinned or not.
        let outsider = seed_user(app.db(), "search-pin-outsider").await;
        let outsider = app.state.base.security.resolve(outsider.id).await.unwrap();
        let hidden = execute_search(&app.state, &outsider, &query, 1, 20, Audience::Human)
            .await
            .unwrap();
        assert!(
            hidden.items.iter().all(|h| h.entity_logicalname != entity),
            "{:?}",
            hidden.items
        );
    });
}
