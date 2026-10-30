//! The image embedding call (A25-T6, SigLIP 2) against the scripted model
//! server: an image goes as a `data:` URL with `modality: image`, a text with
//! `modality: text`, and the vectors come back in the caller's order.

#![allow(clippy::expect_used, reason = "test code")]

use attome_config::{InferenceEndpoint, InferenceSection};
use attome_inference::image_embed::image_input;
use attome_inference::testing::{FakeModelServer, json};
use attome_inference::{ImageEmbeddingClient, Modality};

fn section(server: &FakeModelServer) -> InferenceSection {
    InferenceSection {
        image_embedding: InferenceEndpoint {
            base_url: server.base_url(),
            model: "google/siglip2-base-patch16-224".into(),
            request_timeout_secs: 5,
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    }
}

#[tokio::test]
async fn images_and_texts_are_embedded_with_their_modality() {
    let server = FakeModelServer::start(vec![
        json(r#"{"data":[{"index":1,"embedding":[0.0,1.0]},{"index":0,"embedding":[1.0,0.0]}]}"#),
        json(r#"{"data":[{"index":0,"embedding":[0.5,0.5]}]}"#),
    ])
    .await;
    let client = ImageEmbeddingClient::new(&section(&server)).expect("a loopback client");
    let gif = image_input(b"GIF89a").expect("a GIF");
    let png = image_input(b"\x89PNG\r\n\x1a\n").expect("a PNG");
    let vectors = client
        .embed(&[gif, png], Modality::Image)
        .await
        .expect("vectors");
    assert_eq!(vectors, vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
    let request = server.last_request();
    assert!(request.contains("POST /v1/embeddings"), "{request}");
    assert!(request.contains("\"modality\":\"image\""), "{request}");
    assert!(request.contains("data:image/gif;base64,"), "{request}");

    let text = client
        .embed(&["a damaged pump".to_owned()], Modality::Text)
        .await
        .expect("a text vector");
    assert_eq!(text, vec![vec![0.5, 0.5]]);
    assert!(server.last_request().contains("\"modality\":\"text\""));
}

#[tokio::test]
async fn nothing_is_sent_for_no_inputs_and_an_external_endpoint_is_refused() {
    let server = FakeModelServer::start(vec![]).await;
    let client = ImageEmbeddingClient::new(&section(&server)).expect("a loopback client");
    assert!(
        client
            .embed(&[], Modality::Image)
            .await
            .expect("empty")
            .is_empty()
    );
    assert_eq!(server.request_count(), 0);
    let external = InferenceSection {
        allow_external_provider: true,
        image_embedding: InferenceEndpoint {
            base_url: "https://api.example.com/v1".into(),
            model: "siglip2".into(),
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    };
    assert!(
        ImageEmbeddingClient::new(&external).is_err(),
        "images stay inside the deployment"
    );
}
