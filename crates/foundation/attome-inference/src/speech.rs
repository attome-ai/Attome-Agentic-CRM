//! Speech to text (roadmap N22-T1): batch transcription of a recording with
//! segment timestamps, against an OpenAI-compatible
//! `POST {base_url}/audio/transcriptions` (faster-whisper / speaches, the
//! `speech` profile in `deploy/model-servers/docker-compose.yml`).
//!
//! Recordings are customer data, so the endpoint must be inside the
//! deployment whatever `allow_external_provider` says, like embeddings. The
//! upload is bounded ([`MAX_AUDIO_BYTES`]), the request carries the endpoint's
//! timeout, and the answer is read under the crate's body cap and parsed into
//! a fixed shape; the provider's text never reaches an error or a log.
//!
//! The request is `multipart/form-data`, written here rather than through
//! reqwest's `multipart` feature: four text fields and one file part are a
//! few lines, and the feature would add dependencies to every build. The
//! boundary is checked against the audio, so it can never occur inside it.

use attome_config::InferenceSection;
use serde::{Deserialize, Serialize};

use crate::{InferenceError, Transport};

/// The transcription path, relative to the endpoint's `base_url`.
pub const TRANSCRIPTIONS_PATH: &str = "/audio/transcriptions";
/// The largest recording one call uploads (25 MiB, the common server limit).
pub const MAX_AUDIO_BYTES: usize = 25 * 1024 * 1024;

/// A transcript: the whole text and its timed segments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transcript {
    pub text: String,
    /// The language the server detected or was told, when it says.
    #[serde(default)]
    pub language: Option<String>,
    /// Seconds of audio, when the server says.
    #[serde(default)]
    pub duration: Option<f64>,
    #[serde(default)]
    pub segments: Vec<Segment>,
}

/// One timed stretch of speech, in seconds from the start.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Segment {
    pub start: f64,
    pub end: f64,
    pub text: String,
}

/// A transcription client over `inference.speech`.
#[derive(Clone)]
pub struct SpeechClient {
    transport: Transport,
}

impl std::fmt::Debug for SpeechClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpeechClient").finish_non_exhaustive()
    }
}

impl SpeechClient {
    pub fn new(section: &InferenceSection) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::new(section.speech.clone(), "speech", false)?,
        })
    }

    pub fn model_id(&self) -> &str {
        self.transport.model()
    }

    /// Transcribes one recording. `file_name` names the upload (its extension
    /// tells the server the container); `language` is an ISO 639-1 hint such
    /// as `ar`, or `None` to let the server detect it.
    pub async fn transcribe(
        &self,
        audio: &[u8],
        file_name: &str,
        language: Option<&str>,
    ) -> Result<Transcript, InferenceError> {
        if audio.is_empty() || audio.len() > MAX_AUDIO_BYTES {
            return Err(InferenceError::Misconfigured {
                endpoint: "speech",
                reason: "the recording is empty or larger than the upload limit",
            });
        }
        let started = std::time::Instant::now();
        let boundary = boundary_for(audio);
        let body = multipart_body(
            &boundary,
            self.transport.model(),
            file_name,
            language,
            audio,
        );
        let result = self
            .transport
            .post_bytes::<Transcript>(
                TRANSCRIPTIONS_PATH,
                &format!("multipart/form-data; boundary={boundary}"),
                body,
            )
            .await;
        crate::telemetry::record("speech", started, &result);
        result
    }
}

/// A boundary that does not occur in `audio`: seeded from the clock, and
/// moved on until the audio does not contain it.
pub fn boundary_for(audio: &[u8]) -> String {
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    loop {
        let boundary = format!("attome-{seed:032x}");
        let needle = boundary.as_bytes();
        if !audio.windows(needle.len()).any(|w| w == needle) {
            return boundary;
        }
        seed = seed.wrapping_add(1);
    }
}

/// The `multipart/form-data` body: model, response format, segment
/// timestamps, an optional language, and the file.
pub fn multipart_body(
    boundary: &str,
    model: &str,
    file_name: &str,
    language: Option<&str>,
    audio: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(audio.len() + 1024);
    let mut field = |name: &str, value: &str| {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    };
    field("model", model);
    field("response_format", "verbose_json");
    field("timestamp_granularities[]", "segment");
    if let Some(language) = language.filter(|l| !l.trim().is_empty()) {
        field("language", language.trim());
    }
    // The name is ours to quote: keep it to safe characters.
    let safe_name: String = file_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(100)
        .collect();
    let safe_name = if safe_name.is_empty() {
        "audio".to_owned()
    } else {
        safe_name
    };
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe_name}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(audio);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_body_carries_every_field_and_the_file() {
        let body = multipart_body("b", "whisper", "call 1/../x.wav", Some("ar"), b"RIFF");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("name=\"model\"\r\n\r\nwhisper\r\n"));
        assert!(text.contains("name=\"response_format\"\r\n\r\nverbose_json\r\n"));
        assert!(text.contains("name=\"language\"\r\n\r\nar\r\n"));
        assert!(text.contains("filename=\"call1..x.wav\""), "{text}");
        assert!(text.contains("\r\n\r\nRIFF\r\n--b--\r\n"));
        let boundary = boundary_for(b"plain audio");
        assert!(boundary.starts_with("attome-"));
        let no_language = multipart_body("b", "whisper", "", None, b"x");
        let text = String::from_utf8_lossy(&no_language);
        assert!(!text.contains("name=\"language\""));
        assert!(text.contains("filename=\"audio\""));
    }
}
