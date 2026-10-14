//! The test app starts and answers as an administrator (roadmap Z15-T3).

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};

#[test]
fn test_app_starts_and_lists_entities() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (status, body) = app
            .request(Method::GET, "/api/v1/admin/entities", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["items"].is_array(), "a paginated list: {body}");
    });
}

/// A seeded record for a real entity passes the API's own validation.
#[test]
fn record_for_passes_validation() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let registry = app.state.entities.load();
        let mut created = 0;
        for meta in registry.iter() {
            if created == 3 || meta.is_append_only {
                continue;
            }
            // Skip entities with a required lookup or file: those need a
            // target the caller creates first.
            if meta
                .attrs
                .iter()
                .any(|a| a.is_required && matches!(a.field_type_int, 11 | 12 | 13 | 16 | 18))
            {
                continue;
            }
            let seed = 42;
            let token = attome_testkit::unique("fx");
            let body = attome_testapp::fixtures::record_for(meta, seed, &token);
            let (status, response) = app
                .request(
                    Method::POST,
                    &format!("/api/v1/{}", meta.logicalname),
                    Some(serde_json::Value::Object(body)),
                )
                .await;
            if status == StatusCode::CREATED {
                created += 1;
            } else if status != StatusCode::FORBIDDEN && status != StatusCode::NOT_FOUND {
                panic!(
                    "seed={seed} entity={}: {status} {response}",
                    meta.logicalname
                );
            }
        }
    });
}
