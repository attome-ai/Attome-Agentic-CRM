//! Z15-T7: a route whose object store fails answers a masked error, never a
//! panic or a hang: a theme asset upload against a fake S3 that works, then
//! refuses every call.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use attome_testapp::faults::{FakeS3, FaultPlan};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

/// A 1x1 PNG.
const PNG: &[u8] = &[
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
    0x89, 0x00, 0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
    0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
    0x42, 0x60, 0x82,
];

async fn upload(app: &TestApp, theme: &str) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/v1/admin/themes/{theme}/assets?kind=logo"))
        .header("cookie", app.admin.cookie.as_str())
        .header("origin", "http://localhost:4200")
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "image/png")
        .body(Body::from(PNG.to_vec()))
        .unwrap();
    let response = app.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// feature: Z15
#[test]
fn upload_fails_cleanly_when_storage_fails() {
    attome_testkit::run_shared(async {
        let fake = FakeS3::start(FaultPlan::default()).await;
        let url = fake.url().to_owned();
        let Some(app) = TestApp::start_with(|config| config.storage.s3_endpoint = url).await else {
            return;
        };
        let (status, theme) = app
            .request(
                Method::POST,
                "/api/v1/admin/themes",
                Some(json!({
                    "scope_kind": "portal",
                    "scope_ref": format!("faults-{}", Uuid::now_v7().simple()),
                    "tokens": {}
                })),
            )
            .await;
        assert!(status.is_success(), "{status}: {theme}");
        let theme = theme["id"].as_str().unwrap().to_owned();

        // The store works: the upload lands in it.
        let (status, body) = upload(&app, &theme).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(fake.objects(), 1);

        // The store refuses every call from now on: a masked error, at once.
        fake.set_plan(FaultPlan {
            fail_on_call: Some(fake.calls() + 1),
            latency: None,
        });
        let started = std::time::Instant::now();
        let (status, body) = upload(&app, &theme).await;
        assert!(
            status.is_server_error(),
            "a failed store is a 5xx, not {status}: {body}"
        );
        assert!(
            matches!(
                body["error"].as_str(),
                Some("internal_error" | "capability_unavailable")
            ),
            "{body}"
        );
        assert!(
            !body.to_string().contains("AccessDenied"),
            "the store's answer is not shown: {body}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "it fails at once"
        );
    });
}
