//! E7-T9: a marketing list's refresh, members and usage routes. A refresh
//! is queued once and answers 202, members page the list as the caller
//! reads it, usage names the sends and journeys that use the list, and an
//! unknown list is a 404; a live journey's list changes only when confirmed.

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

async fn install(app: &TestApp) {
    for pack in ["crm", "marketing"] {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../packs")
            .join(pack)
            .join("changesets");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .collect();
        files.sort();
        for file in &files {
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            attome_api::changeset::boot::apply_pack_document(&app.state, &value)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        }
    }
    let registry = attome_core::build_registry(app.db()).await.unwrap();
    app.state.entities.swap(registry);
}

async fn static_list(app: &TestApp) -> Uuid {
    let (status, created) = app
        .request(
            Method::POST,
            "/api/v1/marketing_list",
            Some(json!({
                "name": format!("e7-t9 {}", Uuid::now_v7()),
                "kind": "static",
                "target_entity": "contact",
                "owner_ref": app.admin.id,
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    created["id"].as_str().unwrap().parse().unwrap()
}

async fn contacts(app: &TestApp, n: usize) -> Vec<Uuid> {
    let mut out = Vec::new();
    for i in 0..n {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO contact (full_name, email) VALUES ($1, $2) RETURNING id",
        )
        .bind(format!("Person {i}"))
        .bind(format!("e7t9-{}@example.invalid", Uuid::now_v7().simple()))
        .fetch_one(app.db())
        .await
        .unwrap();
        out.push(id);
    }
    out
}

// feature: E7
#[test]
fn members_paginated() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let list = static_list(&app).await;
        let people = contacts(&app, 3).await;
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/marketing/lists/{list}/members"),
                Some(json!({ "person_ids": people })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["changed"], 3, "{body}");

        let page = |n: u32| {
            let app = &app;
            async move {
                app.request(
                    Method::GET,
                    &format!("/api/v1/marketing/lists/{list}/members?page={n}&page_size=2"),
                    None,
                )
                .await
            }
        };
        let (status, first) = page(1).await;
        assert_eq!(status, StatusCode::OK, "{first}");
        assert_eq!(first["total"], 3, "{first}");
        assert_eq!(first["items"].as_array().unwrap().len(), 2, "{first}");
        assert_eq!(first["items"][0]["source"], "manual", "{first}");
        let (_, second) = page(2).await;
        assert_eq!(second["items"].as_array().unwrap().len(), 1, "{second}");
        let mut seen: Vec<String> = [&first, &second]
            .iter()
            .flat_map(|p| p["items"].as_array().unwrap().clone())
            .map(|m| m["person_id"].as_str().unwrap().to_owned())
            .collect();
        seen.sort();
        let mut want: Vec<String> = people.iter().map(Uuid::to_string).collect();
        want.sort();
        assert_eq!(seen, want);
    });
}

// feature: E7
#[test]
fn refresh_returns_202() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        // The app registers the job at boot; this binary runs no worker.
        let _ = attome_core::jobs::JOB_TYPES.register(
            attome_jobs::JobType::new(attome_marketing::list_routes::REFRESH_JOB, 1),
            |_state: attome_core::EngineState, _job| async { Ok(()) },
        );
        let list = static_list(&app).await;
        let path = format!("/api/v1/marketing/lists/{list}/refresh");

        let (status, body) = app.request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["queued"], true, "{body}");
        // One waiting refresh per list.
        let (status, body) = app.request(Method::POST, &path, None).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["queued"], false, "{body}");

        attome_marketing::list_routes::run_refresh(&app.state, list)
            .await
            .unwrap();
        let refreshed: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT last_refreshed_at FROM marketing_list WHERE id = $1")
                .bind(list)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert!(refreshed.is_some());
    });
}

// feature: E7
#[test]
fn usage_names_sends_and_journeys() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let list = static_list(&app).await;
        let send: Uuid = sqlx::query_scalar(
            "INSERT INTO email_campaign_send (list_id, subject, html_body, text_body, purpose_key) \
             VALUES ($1, 'Spring offer', '<p>x</p>', 'x', 'promotions') RETURNING id",
        )
        .bind(list)
        .fetch_one(app.db())
        .await
        .unwrap();
        let journey: Uuid = sqlx::query_scalar(
            "INSERT INTO marketing_journey \
               (workflow_definition_logicalname, entry_sources, status, is_active, row_version) \
             VALUES ($1, $2, 'live', true, 0) RETURNING id",
        )
        .bind(format!("welcome_{}", Uuid::now_v7().simple()))
        .bind(json!([{ "type": "segment_entered", "list_id": list }]).to_string())
        .fetch_one(app.db())
        .await
        .unwrap();

        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/marketing/lists/{list}/usage"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let uses: Vec<(String, String)> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| {
                (
                    u["kind"].as_str().unwrap().to_owned(),
                    u["id"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert!(
            uses.contains(&("email_send".into(), send.to_string())),
            "{body}"
        );
        assert!(
            uses.contains(&("journey".into(), journey.to_string())),
            "{body}"
        );

        // Another list is used by neither.
        let other = static_list(&app).await;
        let (_, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/marketing/lists/{other}/usage"),
                None,
            )
            .await;
        assert_eq!(body["total"], 0, "{body}");
    });
}

// feature: E7
// negative: POST /api/v1/marketing/lists/{id}/refresh
#[test]
fn unknown_list_is_404() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let missing = Uuid::now_v7();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/marketing/lists/{missing}/refresh"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        for route in ["members", "usage"] {
            let (status, body) = app
                .request(
                    Method::GET,
                    &format!("/api/v1/marketing/lists/{missing}/{route}"),
                    None,
                )
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{route}: {body}");
        }
    });
}

// feature: E7
// negative: PATCH /api/v1/{entity}/{id}
#[test]
fn in_use_list_change_conflicts() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        let list = static_list(&app).await;
        sqlx::query(
            "INSERT INTO marketing_journey \
               (workflow_definition_logicalname, entry_sources, status, is_active, row_version) \
             VALUES ($1, $2, 'live', true, 0)",
        )
        .bind(format!("in_use_{}", Uuid::now_v7().simple()))
        .bind(json!([{ "type": "segment_entered", "list_id": list }]).to_string())
        .execute(app.db())
        .await
        .unwrap();
        let path = format!("/api/v1/marketing_list/{list}");
        let if_match =
            |body: &Value| format!("\"{}\"", body["row_version"].to_string().trim_matches('"'));

        let (_, current) = app.request(Method::GET, &path, None).await;
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &path,
                &[("if-match", if_match(&current).as_str())],
                Some(json!({ "target_entity": "lead" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert!(body.to_string().contains("list.in_use"), "{body}");

        // Confirmed, the change goes through.
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &path,
                &[
                    ("if-match", if_match(&current).as_str()),
                    ("attome-confirm", "list.in_use"),
                ],
                Some(json!({ "target_entity": "lead" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        // A change that leaves the members alone needs no confirmation.
        let (_, current) = app.request(Method::GET, &path, None).await;
        let (status, body) = app
            .request_with(
                Method::PATCH,
                &path,
                &[("if-match", if_match(&current).as_str())],
                Some(json!({ "description": "renamed while live" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    });
}

// feature: E7
#[test]
fn starter_segments_name_their_queries() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        install(&app).await;
        // The pack ships the four starter queries (0015); a marketer makes
        // the lists over them (marketing_list has no business key to write
        // list rows by).
        for name in [
            "Engaged in the last 90 days",
            "New this month",
            "Unengaged for 6 months",
            "Customers",
        ] {
            let query = format!("contact/{name}");
            let resolved = attome_marketing::segment::resolve_query(app.db(), &query)
                .await
                .unwrap();
            assert!(resolved.is_some(), "{query} names no stored query");
        }
        // An unused list stops refreshing.
        let list = static_list(&app).await;
        sqlx::query(
            "UPDATE marketing_list SET refresh_mode = 'scheduled', \
                 last_used_at = now() - INTERVAL '91 days' WHERE id = $1",
        )
        .bind(list)
        .execute(app.db())
        .await
        .unwrap();
        attome_marketing::segment_housekeeping::pause_unused(&app.state, chrono::Utc::now())
            .await
            .unwrap();
        let paused: Option<bool> =
            sqlx::query_scalar("SELECT is_paused FROM marketing_list WHERE id = $1")
                .bind(list)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(paused, Some(true));
        // Reading it resumes it.
        let (status, body) = app
            .request(
                Method::GET,
                &format!("/api/v1/marketing/lists/{list}/usage"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let paused: Option<bool> =
            sqlx::query_scalar("SELECT is_paused FROM marketing_list WHERE id = $1")
                .bind(list)
                .fetch_one(app.db())
                .await
                .unwrap();
        assert_eq!(paused, Some(false));
    });
}
