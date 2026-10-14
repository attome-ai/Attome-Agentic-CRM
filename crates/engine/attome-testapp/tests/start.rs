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
