//! T5-T3: a request naming a workspace is handed to that workspace's process,
//! and only an open workspace the caller may enter is reached. The forwarder
//! here echoes instead of starting a process.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use attome_api::workspace::proxy::{self, WORKSPACE_HEADER, WorkspaceForwarder};
use attome_testapp::{TestApp, seed_user};
use attome_types::AppError;
use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use uuid::Uuid;

/// Answers with the workspace and path it was given, and whether the
/// workspace header was removed on the way.
struct Echo;

impl WorkspaceForwarder for Echo {
    fn forward(
        &self,
        workspace: Uuid,
        request: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send>> {
        let body = json!({
            "workspace": workspace,
            "path": request.uri().path(),
            "header_kept": request.headers().contains_key(WORKSPACE_HEADER),
        });
        Box::pin(async move { Ok(Json(body).into_response()) })
    }
}

async fn start() -> Option<TestApp> {
    let app = TestApp::start().await?;
    // Once per test binary; a second test finds it installed.
    let _ = proxy::install(Arc::new(Echo));
    Some(app)
}

async fn open_workspace(app: &TestApp) -> String {
    let (status, body) = app
        .request(
            Method::POST,
            "/api/v1/admin/workspaces",
            Some(json!({ "name": "Proxy probe", "data": { "mode": "none" } })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body["id"].as_str().unwrap().to_owned()
}

async fn discard(app: &TestApp, id: &str) {
    let (status, _) = app
        .request(
            Method::DELETE,
            &format!("/api/v1/admin/workspaces/{id}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

// feature: T5
#[test]
fn a_request_naming_a_workspace_goes_to_its_process() {
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let id = open_workspace(&app).await;
        let (status, body): (StatusCode, Value) = app
            .request_with(
                Method::GET,
                "/api/v1/admin/entities",
                &[(WORKSPACE_HEADER, &id)],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["workspace"], id.as_str(), "{body}");
        assert_eq!(body["path"], "/api/v1/admin/entities", "{body}");
        assert_eq!(body["header_kept"], false, "{body}");

        // Without the header the request stays on live.
        let (status, body) = app
            .request(Method::GET, "/api/v1/admin/entities", None)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("workspace").is_none(), "{body}");
        discard(&app, &id).await;
    });
}

// feature: T5
#[test]
fn an_unknown_or_discarded_workspace_is_not_found() {
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let unknown = Uuid::now_v7().to_string();
        let (status, body) = app
            .request_with(
                Method::GET,
                "/api/v1/admin/entities",
                &[(WORKSPACE_HEADER, &unknown)],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let id = open_workspace(&app).await;
        discard(&app, &id).await;
        let (status, body) = app
            .request_with(
                Method::GET,
                "/api/v1/admin/entities",
                &[(WORKSPACE_HEADER, &id)],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let (status, body) = app
            .request_with(
                Method::GET,
                "/api/v1/admin/entities",
                &[(WORKSPACE_HEADER, "live")],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    });
}

// feature: T5
#[test]
fn an_outsider_cannot_enter_a_workspace() {
    attome_testkit::run_shared(async {
        let Some(app) = start().await else {
            return;
        };
        let id = open_workspace(&app).await;
        let outsider = seed_user(app.db(), "ws-outsider").await;
        let (status, body) = app
            .request_as_with(
                &outsider.cookie,
                Method::GET,
                "/api/v1/admin/entities",
                &[(WORKSPACE_HEADER, &id)],
                None,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body.get("workspace").is_none(), "{body}");
        discard(&app, &id).await;
    });
}
