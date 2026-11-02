//! A1-T8: splitting a text attribute into others converts the existing
//! rows, as a data step run, and reports the rows it could not split.

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

/// First, father, grandfather and family name, as split.
type NameParts = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// An entity with a full name and four name parts, and three rows.
async fn people(app: &TestApp) -> (String, Uuid) {
    let token = Uuid::now_v7().simple().to_string();
    let name = format!("split_people_{}", &token[..12]);
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let entity: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    for field in ["full_name", "first", "father", "grandfather", "family"] {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/fields"),
                Some(json!({ "logicalname": field, "name": field, "field_type": "text" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
    // Throwaway database: the rows, made directly.
    sqlx::query(&format!(
        "INSERT INTO \"{name}\" (full_name) VALUES \
           ('محمد عبدالله سالم الأحمد'), ('Sara Ali'), (NULL)"
    ))
    .execute(app.db())
    .await
    .unwrap();
    (name, entity)
}

fn split(bad: bool) -> serde_json::Value {
    json!({
        "source": "full_name",
        "targets": [
            { "field": "first", "expression": "word(full_name, 1)" },
            { "field": "father",
              "expression": "if(word_count(full_name) >= 3, word(full_name, 2), \"\")" },
            { "field": "grandfather",
              "expression": if bad { "word_count(full_name) > 1" }
                            else { "if(word_count(full_name) >= 4, word(full_name, 3), \"\")" } },
            { "field": "family",
              "expression": "if(word_count(full_name) >= 2, word(full_name, -1), \"\")" },
        ]
    })
}

// feature: A1
#[test]
fn split_full_name_into_four_parts() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (table, entity) = people(&app).await;

        let (status, preview) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/refactor/preview"),
                Some(split(false)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["rows_read"], 2, "an empty source is not read");
        assert_eq!(preview["rows_changed"], 2);
        assert_eq!(preview["rows_unconvertible"], 0);

        let (status, queued) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/refactor"),
                Some(split(false)),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        let run: Uuid = queued["run_id"].as_str().unwrap().parse().unwrap();
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();

        let rows: Vec<NameParts> = sqlx::query_as(&format!(
            "SELECT first, father, grandfather, family FROM \"{table}\" \
                  WHERE full_name IS NOT NULL ORDER BY full_name"
        ))
        .fetch_all(app.db())
        .await
        .unwrap();
        let some = |s: &str| Some(s.to_owned());
        assert_eq!(
            rows,
            vec![
                (some("Sara"), None, None, some("Ali")),
                (some("محمد"), some("عبدالله"), some("سالم"), some("الأحمد")),
            ]
        );
        let (status, written, failed): (String, i64, i64) = sqlx::query_as(
            "SELECT status, rows_written, rows_nulled FROM data_step_run WHERE id = $1",
        )
        .bind(run)
        .fetch_one(app.db())
        .await
        .unwrap();
        assert_eq!(status, "succeeded");
        assert_eq!((written, failed), (2, 0));
    });
}

// feature: A1
#[test]
fn rows_an_expression_fails_on_are_reported_and_left() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (_, entity) = people(&app).await;
        // A target expression that is not text: every row fails it.
        let (status, preview) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/refactor/preview"),
                Some(split(true)),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{preview}");
        assert_eq!(preview["rows_unconvertible"], 2);
        assert_eq!(preview["rows_changed"], 0);

        // A source that is not a text attribute is refused.
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/refactor/preview"),
                Some(json!({ "source": "nope", "targets": [] })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}
