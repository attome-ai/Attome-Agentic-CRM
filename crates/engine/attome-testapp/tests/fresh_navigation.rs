//! AK6-T1: a fresh deployment's navigation. A capability not set up yet
//! (the AI assistant without a model endpoint) keeps its working screens out
//! of the sidebar and shows an administrator a "Set up" entry instead; once
//! configured, the entry goes and nothing of it is hidden.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;
use axum::http::{Method, StatusCode};
use serde_json::Value;

/// Every route in the sidebar answer, children included.
fn routes(items: &Value, out: &mut Vec<String>) {
    for item in items.as_array().into_iter().flatten() {
        if let Some(route) = item["route"].as_str().filter(|r| !r.is_empty()) {
            out.push(route.to_owned());
        }
        routes(&item["child"], out);
    }
}

async fn sidebar(app: &TestApp) -> (Value, Vec<String>) {
    let (status, body) = app.request(Method::GET, "/api/v1/sidebar/get", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let mut all = Vec::new();
    routes(&body, &mut all);
    (body, all)
}

// feature: AK6
#[test]
fn a_capability_not_set_up_shows_only_in_set_up() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let (items, all) = sidebar(&app).await;
        for hidden in attome_api::setup::CAPABILITIES[0].routes {
            assert!(!all.iter().any(|r| r == hidden), "{hidden} shows: {items}");
        }
        let setup = items
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["id"] == "setup")
            .unwrap_or_else(|| panic!("no Set up entry: {items}"));
        assert_eq!(setup["child"][0]["route"], "/xrm/ai/status");

        let Some(configured) = TestApp::start_with(|config| {
            config.inference.generation.base_url = "http://127.0.0.1:9/v1".to_owned();
        })
        .await
        else {
            return;
        };
        let (items, _) = sidebar(&configured).await;
        assert!(
            !items.as_array().unwrap().iter().any(|i| i["id"] == "setup"),
            "{items}"
        );
    });
}
