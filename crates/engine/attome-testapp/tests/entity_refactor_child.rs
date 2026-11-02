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

/// Creates an entity named `name` with the given `(field, type, target)`
/// fields; its id.
async fn entity_with(app: &TestApp, name: &str, fields: &[(&str, &str, Option<Uuid>)]) -> Uuid {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/entities",
            Some(json!({ "logicalname": name, "name": name })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let entity: Uuid = body["id"].as_str().unwrap().parse().unwrap();
    for (field, kind, target) in fields {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity}/fields"),
                Some(json!({
                    "logicalname": field, "name": field, "field_type": kind,
                    "lookup_entity_ref": target,
                })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }
    entity
}

// feature: A1
// op: lookup_to_many_to_many
#[test]
fn lookup_to_many_to_many_copies_links() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let token = Uuid::now_v7().simple().to_string();
        let org = format!("orgs_{}", &token[20..]);
        let person = format!("staff_{}", &token[20..]);
        let org_id = entity_with(&app, &org, &[("title", "text", None)]).await;
        let person_id = entity_with(
            &app,
            &person,
            &[("title", "text", None), ("org_ref", "lookup", Some(org_id))],
        )
        .await;
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let orgs: Vec<Uuid> = sqlx::query_scalar(&format!(
            "INSERT INTO \"{org}\" (title) VALUES ('A'), ('B') RETURNING id"
        ))
        .fetch_all(app.db())
        .await
        .unwrap();
        let people: Vec<Uuid> = sqlx::query_scalar(&format!(
            "INSERT INTO \"{person}\" (title, org_ref) VALUES ('x', $1), ('y', $2), ('z', NULL) \
             RETURNING id"
        ))
        .bind(orgs[0])
        .bind(orgs[1])
        .fetch_all(app.db())
        .await
        .unwrap();

        // A text field is not a lookup.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{person_id}/refactor/to-many-to-many"),
                Some(json!({"lookup": "title", "name": format!("{person}_orgs"),
                            "role_a": "Member", "role_b": "Organisation"})),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, queued) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{person_id}/refactor/to-many-to-many"),
                Some(
                    json!({"lookup": "org_ref", "name": format!("{person}_orgs"),
                            "role_a": "Member", "role_b": "Organisation"}),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{queued}");
        let run: Uuid = queued["run_id"].as_str().unwrap().parse().unwrap();
        let join = queued["join_table"].as_str().unwrap().to_owned();
        attome_api::field_changes::run_field_run(&app.state, run)
            .await
            .unwrap();
        let mut links: Vec<(Uuid, Uuid)> =
            sqlx::query_as(&format!("SELECT a_id, b_id FROM \"{join}\""))
                .fetch_all(app.db())
                .await
                .unwrap();
        links.sort();
        let mut expected = vec![(people[0], orgs[0]), (people[1], orgs[1])];
        expected.sort();
        assert_eq!(
            links, expected,
            "one link per set lookup; an empty one makes none"
        );
    });
}
