//! The transcription call (N22-T1) against the scripted model server.

#![allow(clippy::expect_used, reason = "test code")]

use attome_config::{InferenceEndpoint, InferenceSection};
use attome_inference::testing::{FakeModelServer, http, json};
use attome_inference::{InferenceError, SpeechClient};

fn section(server: &FakeModelServer) -> InferenceSection {
    InferenceSection {
        speech: InferenceEndpoint {
            base_url: server.base_url(),
            model: "whisper-large-v3".into(),
            request_timeout_secs: 5,
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    }
}

#[tokio::test]
async fn a_recording_is_transcribed_with_segments() {
    let body = r#"{"text":"مرحبا، كيف أساعدك؟","language":"ar","duration":2.5,
        "segments":[{"id":0,"start":0.0,"end":1.2,"text":"مرحبا،"},{"id":1,"start":1.2,"end":2.5,"text":"كيف أساعدك؟"}]}"#;
    let server = FakeModelServer::start(vec![json(body)]).await;
    let client = SpeechClient::new(&section(&server)).expect("a loopback speech client");
    let transcript = client
        .transcribe(b"RIFF....WAVE", "call.wav", Some("ar"))
        .await
        .expect("a transcript");
    assert_eq!(transcript.language.as_deref(), Some("ar"));
    assert_eq!(transcript.segments.len(), 2);
    assert!((transcript.segments[1].end - 2.5).abs() < f64::EPSILON);
    let request = server.last_request();
    assert!(
        request.contains("POST /v1/audio/transcriptions"),
        "{request}"
    );
    assert!(
        request
            .to_ascii_lowercase()
            .contains("content-type: multipart/form-data; boundary=attome-")
    );
    assert!(request.contains("name=\"model\"\r\n\r\nwhisper-large-v3"));
}

#[tokio::test]
async fn an_empty_or_oversized_recording_is_refused_before_any_request() {
    let server = FakeModelServer::start(vec![]).await;
    let client = SpeechClient::new(&section(&server)).expect("a loopback speech client");
    let empty = client.transcribe(b"", "a.wav", None).await;
    assert!(
        matches!(empty, Err(InferenceError::Misconfigured { .. })),
        "{empty:?}"
    );
    let huge = vec![0u8; attome_inference::speech::MAX_AUDIO_BYTES + 1];
    let oversized = client.transcribe(&huge, "a.wav", None).await;
    assert!(matches!(
        oversized,
        Err(InferenceError::Misconfigured { .. })
    ));
    assert_eq!(server.request_count(), 0);
}

#[tokio::test]
async fn a_server_error_is_classified_and_a_bad_body_refused() {
    let server = FakeModelServer::start(vec![
        http(
            500,
            "Internal Server Error",
            &[],
            "{\"error\":\"the recording said: secret\"}",
        ),
        json("{\"segments\":\"not a list\"}"),
    ])
    .await;
    let client = SpeechClient::new(&section(&server)).expect("a loopback speech client");
    let failed = client.transcribe(b"x", "a.wav", None).await;
    assert!(
        matches!(failed, Err(InferenceError::Upstream { .. })),
        "{failed:?}"
    );
    assert!(!format!("{failed:?}").contains("secret"));
    let bad = client.transcribe(b"x", "a.wav", None).await;
    assert!(
        matches!(bad, Err(InferenceError::BadResponse { .. })),
        "{bad:?}"
    );
}

#[test]
fn speech_must_stay_inside_the_deployment() {
    let section = InferenceSection {
        allow_external_provider: true,
        speech: InferenceEndpoint {
            base_url: "https://speech.example.com/v1".into(),
            model: "whisper".into(),
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    };
    assert!(matches!(
        SpeechClient::new(&section),
        Err(InferenceError::ExternalProviderForbidden("speech"))
    ));
}
