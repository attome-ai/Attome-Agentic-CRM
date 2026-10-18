//! Fault injection for tests (roadmap Z15-T7): an object store and a Redis
//! that fail on demand, so a test proves a route fails cleanly (a masked 5xx
//! or a 503) instead of panicking or hanging.
//!
//! - [`FakeS3`] is a minimal S3 endpoint on a loopback port (PUT, GET, HEAD
//!   and DELETE of objects) that applies a [`FaultPlan`]. Point
//!   `storage.s3_endpoint` at [`FakeS3::url`] (see `TestApp::start_with`).
//!   A failing call answers 403 `AccessDenied`: the S3 client does not retry
//!   a 403, so the failure reaches the route at once rather than after the
//!   client's retry budget.
//! - [`dead_redis_url`] names a port nothing listens on, the approach the
//!   cache's fail-closed tests use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};

/// When the store fails, and how slow it is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FaultPlan {
    /// Every call from this one on (1-based) fails; `None` never fails.
    pub fail_on_call: Option<u32>,
    /// Added before every answer.
    pub latency: Option<Duration>,
}

#[derive(Debug, Default)]
struct Store {
    objects: HashMap<String, Vec<u8>>,
    calls: u32,
    plan: FaultPlan,
}

/// A fake S3 endpoint on a loopback port.
#[derive(Debug, Clone)]
pub struct FakeS3 {
    url: String,
    store: Arc<Mutex<Store>>,
}

impl FakeS3 {
    /// Starts the endpoint with `plan`.
    pub async fn start(plan: FaultPlan) -> Self {
        let store = Arc::new(Mutex::new(Store {
            plan,
            ..Store::default()
        }));
        let app = Router::new()
            .route("/{*key}", axum::routing::any(object))
            .with_state(store.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port for the fake S3");
        let url = format!(
            "http://{}",
            listener.local_addr().expect("the bound address")
        );
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, store }
    }

    /// The endpoint, for `storage.s3_endpoint`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Calls answered so far.
    pub fn calls(&self) -> u32 {
        self.store.lock().map(|s| s.calls).unwrap_or(0)
    }

    /// Objects stored so far.
    pub fn objects(&self) -> usize {
        self.store.lock().map(|s| s.objects.len()).unwrap_or(0)
    }

    /// Changes the plan for the calls to come.
    pub fn set_plan(&self, plan: FaultPlan) {
        if let Ok(mut store) = self.store.lock() {
            store.plan = plan;
        }
    }
}

fn s3_error(status: StatusCode, code: &str) -> Response {
    (
        status,
        [("content-type", "application/xml")],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{code}</Message></Error>"),
    )
        .into_response()
}

async fn object(
    State(store): State<Arc<Mutex<Store>>>,
    method: Method,
    Path(key): Path<String>,
    body: Bytes,
) -> Response {
    let (failing, latency) = {
        let Ok(mut store) = store.lock() else {
            return s3_error(StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
        };
        store.calls += 1;
        let failing = store.plan.fail_on_call.is_some_and(|n| store.calls >= n);
        (failing, store.plan.latency)
    };
    if let Some(latency) = latency {
        tokio::time::sleep(latency).await;
    }
    if failing {
        return s3_error(StatusCode::FORBIDDEN, "AccessDenied");
    }
    let Ok(mut store) = store.lock() else {
        return s3_error(StatusCode::INTERNAL_SERVER_ERROR, "InternalError");
    };
    match method {
        Method::PUT => {
            store.objects.insert(key, body.to_vec());
            (StatusCode::OK, [("etag", "\"fake\"")]).into_response()
        }
        Method::GET => match store.objects.get(&key) {
            Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
            None => s3_error(StatusCode::NOT_FOUND, "NoSuchKey"),
        },
        Method::HEAD => match store.objects.get(&key) {
            Some(bytes) => (
                StatusCode::OK,
                [
                    ("content-length", bytes.len().to_string()),
                    ("etag", "\"fake\"".into()),
                ],
            )
                .into_response(),
            None => StatusCode::NOT_FOUND.into_response(),
        },
        Method::DELETE => {
            store.objects.remove(&key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => s3_error(StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
    }
}

/// A Redis URL nothing listens on.
pub fn dead_redis_url() -> String {
    "redis://127.0.0.1:1".to_owned()
}
