//! AA10-T2: the size check counts the rows the caller may change, bounded
//! by the inline threshold, and says inline or background.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_records::heavy_op::{Path, size_check, size_check_with};
use attome_records::query_spec::Condition;
use attome_security::RecordAction;
use attome_testapp::{TestApp, seed_user};
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// An entity with a `title` and ten records, `big` titled for the first
/// four.
async fn ten_records(app: &TestApp) -> String {
    let name = format!("ho_{}", &Uuid::now_v7().simple().to_string()[..12]);
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
    for i in 0..10 {
        let title = if i < 4 { "big" } else { "small" };
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{name}"),
                Some(json!({ "title": title })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    name
}

// feature: AA10
#[test]
fn size_check_small_is_inline() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = ten_records(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let all = size_check_with(&app.state, &admin, &entity, None, RecordAction::Update, 500)
            .await
            .unwrap();
        assert_eq!(all.path, Path::Inline);
        assert!(!all.exceeds);
        assert_eq!((all.exact_upto, all.estimated_rows), (10, 10));

        // The filter narrows the count.
        let big: Condition = serde_json::from_value(
            json!({"kind": "compare", "field": "title", "op": "eq", "value": "big"}),
        )
        .unwrap();
        let some = size_check_with(
            &app.state,
            &admin,
            &entity,
            Some(&big),
            RecordAction::Delete,
            500,
        )
        .await
        .unwrap();
        assert_eq!(some.estimated_rows, 4);

        // The default threshold (500) from the setting.
        let default = size_check(&app.state, &admin, &entity, None, RecordAction::Update)
            .await
            .unwrap();
        assert_eq!(default.path, Path::Inline);
    });
}

// feature: AA10
#[test]
fn size_check_large_is_background() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = ten_records(&app).await;
        let admin = app.state.base.security.resolve(app.admin.id).await.unwrap();
        let large = size_check_with(&app.state, &admin, &entity, None, RecordAction::Update, 5)
            .await
            .unwrap();
        assert_eq!(large.path, Path::Background);
        assert!(large.exceeds);
        assert_eq!(
            large.exact_upto, 6,
            "the count stops one past the threshold"
        );
        assert!(large.estimated_rows >= 6);

        // Someone who may not change the entity gets no count at all.
        let outsider = seed_user(app.db(), "heavy-op-outsider").await;
        let outsider = app.state.base.security.resolve(outsider.id).await.unwrap();
        assert!(
            size_check_with(
                &app.state,
                &outsider,
                &entity,
                None,
                RecordAction::Update,
                5
            )
            .await
            .is_err()
        );
    });
}
