//! AB6-T3: model calls go through `attome_outbound`. A model server that
//! keeps answering 500 opens its endpoint's breaker, and the next call is
//! refused at once, without dialling the server.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};

use attome_config::{InferenceEndpoint, InferenceSection};
use attome_inference::generate::{GenerationClient, GenerationRequest};
use attome_inference::testing::{FakeModelServer, http};
use attome_inference::{ChatMessage, InferenceError};

fn section(server: &FakeModelServer) -> InferenceSection {
    InferenceSection {
        generation: InferenceEndpoint {
            base_url: format!("http://{}/v1", server.addr()),
            model: "test-model".into(),
            request_timeout_secs: 5,
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    }
}

#[tokio::test]
async fn model_call_fails_fast_when_breaker_open() {
    let server =
        FakeModelServer::start(vec![http(500, "Internal Server Error", &[], "boom"); 40]).await;
    let client = GenerationClient::new(&section(&server)).expect("a loopback client");
    let request = || GenerationRequest::new(vec![ChatMessage::user("hello")]);

    // Enough failures for the breaker's window (20 calls, half failing).
    for _ in 0..20 {
        let error = client.generate(request()).await.unwrap_err();
        assert!(
            matches!(error, InferenceError::Upstream { .. }),
            "{error:?}"
        );
    }
    assert_eq!(server.request_count(), 20, "a 500 is not replayed");

    let started = Instant::now();
    let error = client.generate(request()).await.unwrap_err();
    assert!(
        matches!(error, InferenceError::Unavailable { retry_after_secs, .. } if retry_after_secs > 0),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 20, "an open breaker never dials");
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "refused at once"
    );
}
