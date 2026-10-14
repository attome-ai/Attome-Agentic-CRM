//! The OCR call (N21-T1) against the scripted model server.

#![allow(clippy::expect_used, reason = "test code")]

use attome_config::{InferenceEndpoint, InferenceSection};
use attome_inference::testing::{FakeModelServer, json};
use attome_inference::{InferenceError, OcrClient};

fn section(server: &FakeModelServer) -> InferenceSection {
    InferenceSection {
        ocr: InferenceEndpoint {
            base_url: server.base_url(),
            model: "qwen2.5-vl".into(),
            request_timeout_secs: 5,
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    }
}

#[tokio::test]
async fn an_image_is_read_through_the_chat_endpoint() {
    let body = r#"{"choices":[{"message":{"content":"  فاتورة ضريبية\nTax invoice 1042  "},"finish_reason":"stop"}]}"#;
    let server = FakeModelServer::start(vec![json(body)]).await;
    let client = OcrClient::new(&section(&server)).expect("a loopback OCR client");
    let read = client
        .read_text(b"\x89PNG\r\n", "image/png", Some("ar"))
        .await
        .expect("text");
    assert_eq!(read.text, "فاتورة ضريبية\nTax invoice 1042");
    assert_eq!(read.model_id, "qwen2.5-vl");
    let request = server.last_request();
    assert!(request.contains("POST /v1/chat/completions"), "{request}");
    assert!(
        request.contains("data:image/png;base64,iVBORw0K"),
        "{request}"
    );
    assert!(request.contains("language `ar`"));
}

#[tokio::test]
async fn wrong_images_are_refused_before_any_request() {
    let server = FakeModelServer::start(vec![]).await;
    let client = OcrClient::new(&section(&server)).expect("a loopback OCR client");
    for (image, media_type) in [(&b""[..], "image/png"), (&b"GIF89a"[..], "image/gif")] {
        let refused = client.read_text(image, media_type, None).await;
        assert!(
            matches!(refused, Err(InferenceError::Misconfigured { .. })),
            "{refused:?}"
        );
    }
    assert_eq!(server.request_count(), 0);
}

#[tokio::test]
async fn an_answer_without_text_is_a_bad_response() {
    let server = FakeModelServer::start(vec![json(r#"{"choices":[]}"#)]).await;
    let client = OcrClient::new(&section(&server)).expect("a loopback OCR client");
    let empty = client.read_text(b"x", "image/jpeg", None).await;
    assert!(
        matches!(empty, Err(InferenceError::BadResponse { .. })),
        "{empty:?}"
    );
}

#[test]
fn ocr_must_stay_inside_the_deployment() {
    let section = InferenceSection {
        allow_external_provider: true,
        ocr: InferenceEndpoint {
            base_url: "https://ocr.example.com/v1".into(),
            model: "vl".into(),
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    };
    assert!(matches!(
        OcrClient::new(&section),
        Err(InferenceError::ExternalProviderForbidden("ocr"))
    ));
}
