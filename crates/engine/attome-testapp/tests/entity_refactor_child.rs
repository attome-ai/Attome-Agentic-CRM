//! A1-T9: repeating attributes extracted into a child entity: three phone
//! fields of a contact-like entity become rows of a child entity, one per
//! non-empty value, each pointing at its parent, as a data step run.

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

// feature: A1
// op: extract_child_entity
#[test]
fn extract_phones_into_child() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let parent = format!("people_{}", &token[20..]);
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": parent, "name": parent })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let entity: Uuid = body["id"].as_str().unwrap().parse().unwrap();
        for field in ["full_name", "phone_1", "phone_2", "phone_3"] {
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
        let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "INSERT INTO \"{parent}\" (full_name, phone_1, phone_2, phone_3) VALUES \
               ('Sara', '0501', '0502', NULL), ('Omar', '', NULL, '0553'), ('Nobody', NULL, NULL, NULL) \
             RETURNING id"
        ))
        .fetch_all(app.db())
        .await
        .unwrap();

        // Mixed types are refused before anything is created.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/refactor/extract-child"),
                Some(json!({
                    "sources": ["phone_1", "missing"],
                    "child_logicalname": format!("{parent}_phone"),
                    "child_name": "Phone",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let child = format!("{parent}_phone");
        let (status, queued) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/refactor/extract-child"),
                Some(json!({
                    "sources": ["phone_1", "phone_2", "phone_3"],
                    "child_logicalname": child,
                    "child_name": "Phone",
                })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        let run: Uuid = queued["run_id"].as_str().unwrap().parse().unwrap();
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();
        // Run again: a finished run is not claimed, so nothing doubles.
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();

        let rows: Vec<(Uuid, String, String)> = sqlx::query_as(&format!(
            "SELECT \"{parent}_ref\", value, source_field FROM \"{child}\" ORDER BY value"
        ))
        .fetch_all(app.db())
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![
                (ids[0], "0501".to_owned(), "phone_1".to_owned()),
                (ids[0], "0502".to_owned(), "phone_2".to_owned()),
                (ids[1], "0553".to_owned(), "phone_3".to_owned()),
            ],
            "one row per non-empty phone; an empty string and NULL are skipped"
        );
        let status: String = sqlx::query_scalar("SELECT status FROM data_step_run WHERE id = $1")
            .bind(run)
            .fetch_one(app.db())
            .await
            .unwrap();
        assert_eq!(status, "succeeded");
        // The sources are kept.
        let kept: Option<String> =
            sqlx::query_scalar(&format!("SELECT phone_1 FROM \"{parent}\" WHERE id = $1"))
                .bind(ids[0])
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(kept.as_deref(), Some("0501"));
    });
}
