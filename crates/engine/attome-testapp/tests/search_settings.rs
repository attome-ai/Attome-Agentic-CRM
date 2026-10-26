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

async fn alerts_for(app: &TestApp, owner: Uuid, name: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM notification_dispatch WHERE recipient_user_ref = $1 AND subject = $2",
    )
    .bind(owner)
    .bind(format!("New results: \"{name}\""))
    .fetch_one(app.db())
    .await
    .unwrap()
}

/// A25-T8: a saved search with an alert tells its owner once per new match,
/// not on every run.
// feature: A25
#[test]
fn alert_sends_once_for_new_match() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..8];
        let word = format!("alertword{tag}");
        let (entity, _) = indexed(&app, &[&format!("{word} first")]).await;
        let name = format!("Alert {tag}");
        sqlx::query(
            "INSERT INTO saved_search (name, query_text, alert_enabled, owner_ref) \
             VALUES ($1, $2, true, $3)",
        )
        .bind(&name)
        .bind(&word)
        .bind(app.admin.id)
        .execute(app.db())
        .await
        .unwrap();

        attome_search::saved_search::sweep_alerts(&app.state)
            .await
            .unwrap();
        assert_eq!(alerts_for(&app, app.admin.id, &name).await, 1);
        attome_search::saved_search::sweep_alerts(&app.state)
            .await
            .unwrap();
        assert_eq!(
            alerts_for(&app, app.admin.id, &name).await,
            1,
            "nothing new"
        );

        // A second match is new.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": format!("{word} second") })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let record: Uuid = body["id"].as_str().unwrap().parse().unwrap();
        let title = format!("{word} second");
        let row = attome_search::project(&title, None, &title, Vec::new());
        attome_search::upsert_row(app.db(), &entity, record, &row, None, None, None)
            .await
            .unwrap();
        attome_search::saved_search::sweep_alerts(&app.state)
            .await
            .unwrap();
        assert_eq!(alerts_for(&app, app.admin.id, &name).await, 2);
    });
}

/// A25-T9: the search administration routes answer administrators only.
// feature: A25
// negative: list_synonyms
#[test]
fn admin_search_routes_forbid_non_admin() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let outsider = seed_user(app.db(), "search-admin-outsider").await;
        for (method, path) in [
            (Method::GET, "/api/v1/admin/search/synonyms"),
            (Method::GET, "/api/v1/admin/search/stopwords"),
            (Method::GET, "/api/v1/admin/search/pins"),
            (Method::GET, "/api/v1/admin/search/size"),
            (Method::GET, "/api/v1/admin/search/quality"),
        ] {
            let (status, _) = app
                .request_as(&outsider.cookie, method.clone(), path, None)
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            let (status, body) = app.request(method, path, None).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
        }
        let (status, _) = app
            .request_as(
                &outsider.cookie,
                Method::POST,
                "/api/v1/admin/search/synonyms",
                Some(json!({ "terms": ["a1", "b1"] })),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

/// A25-T9: facets count only what the caller may see: a reader of one
/// entity never learns how many results another entity holds.
// feature: A25
#[test]
fn facet_counts_exclude_hidden_records() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let tag = &Uuid::now_v7().simple().to_string()[..8];
        let word = format!("facetword{tag}");
        let (seen, _) = indexed(&app, &[&format!("{word} one"), &format!("{word} two")]).await;
        let (hidden, _) = indexed(&app, &[&format!("{word} three")]).await;

        // A reader of `seen` only.
        let (status, role) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/roles",
                Some(json!({ "name": format!("facets-{tag}") })),
            )
            .await;
        assert!(status.is_success(), "{status} {role}");
        let role_id = role["id"].as_str().unwrap().to_owned();
        let key = format!("{seen}.read");
        attome_security::db::ensure_privilege(
            app.db(),
            &key,
            &key,
            "test",
            attome_core::changeset::Layer::Project,
        )
        .await
        .unwrap();
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/role-grants",
                Some(json!({ "role_id": role_id, "privilege_key": key })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/security/role-entity-access",
                Some(json!({ "role_id": role_id, "entity": seen, "read_access_level": 3 })),
            )
            .await;
        assert!(status.is_success(), "{status} {body}");
        let reader = seed_user(app.db(), "facet-reader").await;
        sqlx::query("INSERT INTO user_account_mm_role (user_ref, role_ref) VALUES ($1, $2::uuid)")
            .bind(reader.id)
            .bind(&role_id)
            .execute(app.db())
            .await
            .unwrap();
        let reader = app.state.base.security.resolve(reader.id).await.unwrap();

        let options = attome_search::routes::SearchOptions {
            explain: false,
            facets: true,
        };
        let answer = attome_search::routes::execute_search_with(
            &app.state,
            &reader,
            &word,
            1,
            20,
            Audience::Human,
            options,
        )
        .await
        .unwrap();
        let facets = answer.facets.expect("facets were asked for");
        let entities: Vec<(&str, i64)> = facets
            .entity
            .iter()
            .map(|f| (f.value.as_str(), f.count))
            .collect();
        assert_eq!(entities, vec![(seen.as_str(), 2)], "{facets:?}");
        assert!(!format!("{facets:?}").contains(&hidden));

        // An administrator sees both.
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let all = attome_search::routes::execute_search_with(
            &app.state,
            &admin,
            &word,
            1,
            20,
            Audience::Human,
            options,
        )
        .await
        .unwrap();
        assert_eq!(all.facets.unwrap().entity.len(), 2);
    });
}
