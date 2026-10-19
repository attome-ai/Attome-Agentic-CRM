//! M12-T4 and M10-T4: the reads behind "My background work" and the pending
//! timers. `GET /api/v1/jobs` lists only the caller's own batch jobs;
//! `GET /api/v1/{entity}/{id}/timers` lists a readable record's pending
//! timers, and `GET /api/v1/admin/timers` every pending timer for an
//! administrator only.

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

// feature: M12
#[test]
fn my_batches_lists_only_the_callers_own() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let other = attome_testapp::seed_user(app.db(), "m12-other").await;
        let mut conn = app.db().acquire().await.unwrap();
        let mine =
            attome_jobs::batch::start(&mut conn, "test.import", Some(10), Some(app.admin.id))
                .await
                .unwrap();
        attome_jobs::batch::start(&mut conn, "test.theirs", None, Some(other.id))
            .await
            .unwrap();
        drop(conn);

        let (status, body) = app
            .request(Method::GET, "/api/v1/jobs?page_size=200", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let ids: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|b| b["id"].as_str())
            .collect();
        assert!(ids.contains(&mine.to_string().as_str()));
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .all(|b| b["name"] != "test.theirs"),
            "never someone else's: {body}"
        );
    });
}

// feature: M10
#[test]
fn record_timers_and_the_admin_list() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let entity = format!("m10_case_{}", &Uuid::now_v7().simple().to_string()[..12]);
        let (status, body) = app
            .request(
                Method::POST,
                "/api/v1/admin/entities",
                Some(json!({ "logicalname": entity, "name": entity })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let entity_id = body["id"].as_str().unwrap().to_owned();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/entities/{entity_id}/fields"),
                Some(json!({ "logicalname": "title", "name": "title", "field_type": "text" })),
            )
            .await;
        assert!(status.is_success(), "{body}");
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "title": "a case" })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let record: Uuid = body["id"].as_str().unwrap().parse().unwrap();

        let mut conn = app.db().acquire().await.unwrap();
        let timer = attome_core::timer::schedule(
            &mut conn,
            &attome_core::timer::NewTimer {
                kind: "service.escalation".into(),
                target_entity: Some(entity.clone()),
                target_id: Some(record),
                run_id: None,
                due_at: chrono::Utc::now() + chrono::Duration::hours(4),
                payload: json!({ "secret": "never shown" }),
            },
        )
        .await
        .unwrap();
        drop(conn);

        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/{entity}/{record}/timers"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 1, "{body}");
        assert_eq!(body["items"][0]["id"], timer.to_string());
        assert_eq!(body["items"][0]["kind"], "service.escalation");
        assert!(!body.to_string().contains("never shown"), "no payload");

        let (status, body) = app
            .request(Method::GET, "/api/v1/admin/timers?page_size=200", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            body["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|t| t["id"] == timer.to_string())
        );

        let user = attome_testapp::seed_user(app.db(), "m10-plain").await;
        let (status, _) = app
            .request_as(&user.cookie, Method::GET, "/api/v1/admin/timers", None)
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}
