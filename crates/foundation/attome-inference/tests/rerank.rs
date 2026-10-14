//! The rerank call (N15-T1) against the scripted model server.

#![allow(clippy::expect_used, reason = "test code")]

use attome_config::{InferenceEndpoint, InferenceSection};
use attome_inference::testing::{FakeModelServer, json};
use attome_inference::{InferenceError, RerankClient};

fn section(server: &FakeModelServer) -> InferenceSection {
    InferenceSection {
        rerank: InferenceEndpoint {
            base_url: server.base_url(),
            model: "bge-reranker-v2-m3".into(),
            request_timeout_secs: 5,
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    }
}

#[tokio::test]
async fn passages_are_scored_in_input_order() {
    let server = FakeModelServer::start(vec![json(
        r#"[{"index":2,"score":0.91},{"index":0,"score":0.12},{"index":1,"score":0.55}]"#,
    )])
    .await;
    let client = RerankClient::new(&section(&server)).expect("a loopback rerank client");
    let scores = client
        .rerank(
            "refund policy",
            &["shipping", "returns", "refund policy for goods"],
        )
        .await
        .expect("scores");
    assert_eq!(scores, vec![0.12, 0.55, 0.91]);
    let request = server.last_request();
    assert!(request.contains("POST /v1/rerank"), "{request}");
    assert!(request.contains("\"query\":\"refund policy\""));
}

#[tokio::test]
async fn a_short_answer_is_a_bad_response_and_nothing_is_sent_for_no_passages() {
    let server = FakeModelServer::start(vec![json(r#"[{"index":0,"score":0.5}]"#)]).await;
    let client = RerankClient::new(&section(&server)).expect("a loopback rerank client");
    assert_eq!(
        client.rerank("q", &[]).await.expect("empty"),
        Vec::<f32>::new()
    );
    assert_eq!(server.request_count(), 0);
    let short = client.rerank("q", &["a", "b"]).await;
    assert!(
        matches!(short, Err(InferenceError::BadResponse { .. })),
        "{short:?}"
    );
}
