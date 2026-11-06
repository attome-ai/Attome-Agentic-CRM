//! Y2-T6: a single-value choice field's values are held by a database CHECK
//! (`ck_<entity>_<field>_chc`). The raw writes below run on the throwaway
//! test database only, to show the database itself refuses a value the
//! record API would also refuse.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

/// An entity with a `stage` choice field of `choices`; answers the entity's
/// name and id and the field's id.
async fn choice_entity(app: &TestApp, choices: &[&str]) -> (String, Uuid, String) {
    let token = Uuid::now_v7().simple().to_string();
    let name = format!("chc_{}", &token[..12]);
    let (status, entity) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{entity}");
    let entity_id: Uuid = entity["id"].as_str().unwrap().parse().unwrap();
    let (status, field) = app
        .request(
            Method::POST,
            &format!("/api/v1/admin/entities/{entity_id}/fields"),
            Some(json!({
                "logicalname": "stage", "name": "Stage", "field_type": "choice",
                "options": { "choices": choices, "multi": false },
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{field}");
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    (name, entity_id, field["id"].as_str().unwrap().to_owned())
}

/// A record made through the API with no stage, then `stage = value`
/// written raw (the API would refuse a value outside the choices itself).
async fn insert_raw(app: &TestApp, entity: &str, value: &str) -> Result<(), sqlx::Error> {
    let (status, created) = app
        .request(Method::POST, &format!("/api/v1/{entity}"), Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let id: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    sqlx::query(&format!("UPDATE \"{entity}\" SET stage = $2 WHERE id = $1"))
        .bind(id)
        .bind(value)
        .execute(app.db())
        .await
        .map(|_| ())
}

async fn check_valid(app: &TestApp, entity: &str) -> Option<bool> {
    let name =
        attome_metadata::provision::choice_check::choice_check_name(entity, "stage").unwrap();
    sqlx::query_scalar(
        "SELECT c.convalidated FROM pg_catalog.pg_constraint c \
           JOIN pg_catalog.pg_class t ON t.oid = c.conrelid \
          WHERE t.relname = $1 AND c.conname = $2 AND c.contype = 'c'",
    )
    .bind(entity)
    .bind(name)
    .fetch_optional(app.db())
    .await
    .unwrap()
}

fn is_check_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|c| c == "23514")
}

// feature: Y2
#[test]
fn choice_check_rejects_unknown_value() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (entity, _, _) = choice_entity(&app, &["open", "won", "it's"]).await;
        assert_eq!(check_valid(&app, &entity).await, Some(true));
        insert_raw(&app, &entity, "open").await.unwrap();
        // A quote in a choice is a literal, not SQL.
        insert_raw(&app, &entity, "it's").await.unwrap();
        let refused = insert_raw(&app, &entity, "lost").await.unwrap_err();
        assert!(is_check_violation(&refused), "{refused}");
    });
}

// feature: Y2
#[test]
fn removing_choice_value_rebuilds_check() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (entity, entity_id, field_id) = choice_entity(&app, &["open", "won", "lost"]).await;
        let record = {
            let (status, created) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{entity}"),
                    Some(json!({ "stage": "lost" })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{created}");
            created["id"].as_str().unwrap().parse::<Uuid>().unwrap()
        };
        // `lost` leaves the choices; `pending` joins them.
        let (status, body) = app
            .request(
                Method::PATCH,
                &format!("/api/v1/admin/entities/{entity_id}/fields/{field_id}"),
                Some(
                    json!({ "options": { "choices": ["open", "won", "pending"], "multi": false } }),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(check_valid(&app, &entity).await, Some(true));
        // The new value is admitted at once.
        insert_raw(&app, &entity, "pending").await.unwrap();
        // The record that still holds the removed value can still be written.
        sqlx::query(&format!(
            "UPDATE \"{entity}\" SET stage = stage WHERE id = $1"
        ))
        .bind(record)
        .execute(app.db())
        .await
        .unwrap();
        // A value that was never a choice is refused.
        let refused = insert_raw(&app, &entity, "never").await.unwrap_err();
        assert!(is_check_violation(&refused), "{refused}");

        // Once no record holds the removed value, the next rebuild drops it.
        sqlx::query(&format!(
            "UPDATE \"{entity}\" SET stage = 'won' WHERE id = $1"
        ))
        .bind(record)
        .execute(app.db())
        .await
        .unwrap();
        let rebuilt =
            attome_metadata::provision::choice_check::sync_choice_check(app.db(), &entity, "stage")
                .await
                .unwrap();
        assert_eq!(
            rebuilt,
            attome_metadata::provision::choice_check::ChoiceCheck::Valid
        );
        let refused = insert_raw(&app, &entity, "lost").await.unwrap_err();
        assert!(is_check_violation(&refused), "{refused}");
    });
}
