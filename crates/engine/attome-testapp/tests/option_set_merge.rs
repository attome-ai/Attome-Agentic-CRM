//! A5-T2: merging one option set value into another. The merge retires the
//! old value and publishes the set; the job then moves every record holding
//! it to the new value through the generic update path; afterwards the old
//! value is refused on a new write.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_api::model_admin::option_merge::{MERGE_JOB, MergePayload, apply};
use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::json;
use uuid::Uuid;

// feature: A5
// negative: POST /api/v1/{entity}, POST /api/v1/admin/model/option_set/{id}/merge
#[test]
fn option_set_merge_moves_every_record_and_retires_the_value() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // The binary registers the job; this test runs it itself.
        let _ = attome_core::jobs::JOB_TYPES.register(
            attome_jobs::JobType::new(MERGE_JOB, 1),
            |_state: attome_core::EngineState, _job| async { Ok(()) },
        );
        let token = Uuid::now_v7().simple().to_string();
        let set_name = format!("city_{}", &token[..12]);
        let entity = format!("a5_branch_{}", &token[..12]);

        let set_id = Uuid::now_v7();
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/model/option_set/{set_id}/commands"),
                Some(json!({
                    "base_hash": "",
                    "name": set_name,
                    "commands": [{ "op": "set", "path": "/values", "value": [
                        { "code": "riyadh", "label_en": "Riyadh", "order": 1 },
                        { "code": "jedda", "label_en": "Jedda", "order": 2 },
                        { "code": "jeddah", "label_en": "Jeddah", "order": 3 }
                    ] }]
                })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/model/option_set/{set_id}/publish"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let entity_id = attome_metadata::provision::ensure_entity(
            app.db(),
            &entity,
            "Option set merge test",
            None,
            false,
        )
        .await
        .unwrap();
        attome_metadata::provision::ensure_attribute(
            app.db(),
            entity_id,
            "city",
            "City",
            "choice",
            false,
            false,
            false,
            false,
            None,
            Some(json!({ "option_set": set_name, "multi": false })),
        )
        .await
        .unwrap();
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);

        let mut ids = Vec::new();
        for city in ["jedda", "jedda", "riyadh"] {
            let (status, body) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{entity}"),
                    Some(json!({ "city": city })),
                )
                .await;
            assert_eq!(status, StatusCode::CREATED, "{body}");
            ids.push(body["id"].as_str().unwrap().to_owned());
        }

        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/model/option_set/{set_id}/merge"),
                Some(json!({ "from": "jedda", "into": "jeddah" })),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["queued"], true);

        // The published set retired the old value, so the field refuses it.
        let registry = attome_core::build_registry(app.db()).await.unwrap();
        app.state.entities.swap(registry);
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/{entity}"),
                Some(json!({ "city": "jedda" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let changed = apply(
            &app.state,
            &MergePayload {
                user_id: app.admin.id,
                set: set_name.clone(),
                from: "jedda".into(),
                into: "jeddah".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(changed, 2);
        for (id, want) in ids.iter().zip(["jeddah", "jeddah", "riyadh"]) {
            let (status, record) = app
                .request(Method::GET, &format!("/api/v1/{entity}/{id}"), None)
                .await;
            assert_eq!(status, StatusCode::OK, "{record}");
            assert_eq!(record["data"]["city"], want, "{record}");
        }

        // Merging into a retired value is refused.
        let (status, _) = app
            .request(
                Method::POST,
                &format!("/api/v1/admin/model/option_set/{set_id}/merge"),
                Some(json!({ "from": "riyadh", "into": "jedda" })),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    });
}
