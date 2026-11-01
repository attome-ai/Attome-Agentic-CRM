//! G1-T1's prerequisite: a live entity is made to extend a base. A field of
//! the same name becomes the base field's copy, the base's other fields are
//! copied in, a different type is refused, and an entity extends one base
//! at most.

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

async fn entity(app: &TestApp, prefix: &str) -> (Uuid, String) {
    let logicalname = format!("{prefix}_{}", Uuid::now_v7().simple());
    let (code, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": logicalname, "name": "Rebase test" })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    (body["id"].as_str().unwrap().parse().unwrap(), logicalname)
}

async fn field(app: &TestApp, entity: Uuid, name: &str, field_type: &str) -> Value {
    let (code, body) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity}/fields"),
            Some(json!({ "logicalname": name, "name": name, "field_type": field_type })),
        )
        .await;
    assert_eq!(code, StatusCode::CREATED, "{body}");
    body
}

async fn rebase(app: &TestApp, entity: Uuid, base: Uuid) -> (StatusCode, Value) {
    app.request(
        Method::PATCH,
        &format!("/api/v1/admin/entities/{entity}"),
        Some(json!({ "extends_entity_id": base })),
    )
    .await
}

async fn inherited_from(app: &TestApp, entity: Uuid, name: &str) -> Option<Uuid> {
    sqlx::query_scalar(
        "SELECT inherited_from_attribute_id FROM attribute_info \
          WHERE entity_ref = $1 AND logicalname = $2 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity)
    .bind(name)
    .fetch_optional(app.db())
    .await
    .unwrap()
    .flatten()
}

// feature: G1
#[test]
fn a_live_entity_adopts_a_base() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (base, _) = entity(&app, "rb_base").await;
        let subject = field(&app, base, "subject", "text").await;
        let due = field(&app, base, "due_at", "date_time").await;
        let (ticket, _) = entity(&app, "rb_ticket").await;
        field(&app, ticket, "subject", "text").await;

        let (code, body) = rebase(&app, ticket, base).await;
        assert!(code.is_success(), "{code} {body}");
        let extends: Option<Uuid> =
            sqlx::query_scalar("SELECT extends_entity_id FROM entity_info WHERE id = $1")
                .bind(ticket)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(extends, Some(base));
        let subject_id: Uuid = subject["id"].as_str().unwrap().parse().unwrap();
        let due_id: Uuid = due["id"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            inherited_from(&app, ticket, "subject").await,
            Some(subject_id),
            "adopted"
        );
        assert_eq!(
            inherited_from(&app, ticket, "due_at").await,
            Some(due_id),
            "copied in"
        );

        // Again: nothing more.
        let (code, body) = rebase(&app, ticket, base).await;
        assert!(code.is_success(), "{code} {body}");

        // A second base is refused.
        let (other, _) = entity(&app, "rb_other").await;
        let (code, _) = rebase(&app, ticket, other).await;
        assert_eq!(code, StatusCode::CONFLICT);

        // A field of the base's name but another type is refused.
        let (task, _) = entity(&app, "rb_task").await;
        field(&app, task, "subject", "number").await;
        let (code, body) = rebase(&app, task, base).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        // An entity cannot extend what extends it.
        let (code, _) = rebase(&app, base, ticket).await;
        assert_eq!(code, StatusCode::UNPROCESSABLE_ENTITY);
    });
}
