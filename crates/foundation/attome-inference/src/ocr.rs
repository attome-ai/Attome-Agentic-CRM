//! Reading the text of an image (roadmap N21-T1): a scanned page, a photo of
//! a receipt or an invoice, in Arabic and English.
//!
//! The model is a vision-language model served behind an OpenAI-compatible
//! `POST {base_url}/chat/completions` (Qwen2.5-VL through vLLM, the `ocr`
//! profile in `deploy/model-servers/docker-compose.yml`), sent the image as a
//! `data:` URL and a fixed instruction to transcribe it. No new wire format:
//! the same transport, timeout, body cap and status handling as generation.
//!
//! Documents are customer data, so the endpoint must be inside the deployment
//! whatever `allow_external_provider` says, like embeddings and speech. Only
//! PNG, JPEG and WebP up to [`MAX_IMAGE_BYTES`] are sent; the model's answer
//! is returned as text and never logged.

use attome_config::InferenceSection;
use serde::{Deserialize, Serialize};

use crate::generate::CHAT_COMPLETIONS_PATH;
use crate::{InferenceError, Transport};

/// The largest image one call sends (10 MiB before encoding).
pub const MAX_IMAGE_BYTES: usize = 10 * 1024 * 1024;

/// The image types a vision model reliably takes.
pub const IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/webp"];

const INSTRUCTION: &str = "Transcribe every piece of text in this image exactly as written, in its \
own language and script (Arabic stays Arabic). Keep the line breaks and the reading order. Output \
only the text: no commentary, no translation, no formatting.";

/// What the model read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcrText {
    pub text: String,
    /// The model that read it, for provenance.
    pub model_id: String,
}

#[derive(Serialize)]
struct OcrRequest<'a> {
    model: &'a str,
    temperature: f32,
    max_tokens: u32,
    messages: [OcrMessage; 1],
}

#[derive(Serialize)]
struct OcrMessage {
    role: &'static str,
    content: [Part; 2],
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Part {
    Text { text: String },
    ImageUrl { image_url: ImageUrl },
}

#[derive(Serialize)]
struct ImageUrl {
    url: String,
}

#[derive(Deserialize)]
struct OcrResponse {
    #[serde(default)]
    choices: Vec<OcrChoice>,
}

#[derive(Deserialize)]
struct OcrChoice {
    message: OcrAnswer,
}

#[derive(Deserialize)]
struct OcrAnswer {
    #[serde(default)]
    content: Option<String>,
}

/// An OCR client over `inference.ocr`.
#[derive(Clone)]
pub struct OcrClient {
    transport: Transport,
    max_output_tokens: u32,
}

impl std::fmt::Debug for OcrClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OcrClient").finish_non_exhaustive()
    }
}

impl OcrClient {
    pub fn new(section: &InferenceSection) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::new(section.ocr.clone(), "ocr", false)?,
            max_output_tokens: section.max_output_tokens.max(1024),
        })
    }

    pub fn model_id(&self) -> &str {
        self.transport.model()
    }

    /// Reads the text of one image of `media_type` (one of [`IMAGE_TYPES`]).
    /// `language` is a hint added to the instruction, such as `ar`.
    pub async fn read_text(
        &self,
        image: &[u8],
        media_type: &str,
        language: Option<&str>,
    ) -> Result<OcrText, InferenceError> {
        if image.is_empty() || image.len() > MAX_IMAGE_BYTES {
            return Err(InferenceError::Misconfigured {
                endpoint: "ocr",
                reason: "the image is empty or larger than the upload limit",
            });
        }
        if !IMAGE_TYPES.contains(&media_type) {
            return Err(InferenceError::Misconfigured {
                endpoint: "ocr",
                reason: "the image is not PNG, JPEG or WebP",
            });
        }
        let started = std::time::Instant::now();
        let result = self.read_once(image, media_type, language).await;
        crate::telemetry::record("ocr", started, &result);
        result
    }

    async fn read_once(
        &self,
        image: &[u8],
        media_type: &str,
        language: Option<&str>,
    ) -> Result<OcrText, InferenceError> {
        let mut instruction = INSTRUCTION.to_owned();
        if let Some(language) = language.map(str::trim).filter(|l| {
            !l.is_empty() && l.len() <= 8 && l.chars().all(|c| c.is_ascii_alphabetic() || c == '-')
        }) {
            instruction.push_str(&format!(" The text is mostly in language `{language}`."));
        }
        let request = OcrRequest {
            model: self.transport.model(),
            temperature: 0.0,
            max_tokens: self.max_output_tokens,
            messages: [OcrMessage {
                role: "user",
                content: [
                    Part::Text { text: instruction },
                    Part::ImageUrl {
                        image_url: ImageUrl {
                            url: format!("data:{media_type};base64,{}", base64(image)),
                        },
                    },
                ],
            }],
        };
        let response: OcrResponse = self.transport.post(CHAT_COMPLETIONS_PATH, &request).await?;
        let text = response
            .choices
            .into_iter()
            .next()
            .and_then(|choice| choice.message.content)
            .ok_or(InferenceError::BadResponse {
                endpoint: "ocr",
                reason: "the answer carried no text",
            })?;
        Ok(OcrText {
            text: text.trim().to_owned(),
            model_id: self.transport.model().to_owned(),
        })
    }
}

/// Standard base64 with padding (RFC 4648), for the `data:` URL.
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let index = |shift: u32| char::from(ALPHABET[((n >> shift) & 63) as usize]);
        out.push(index(18));
        out.push(index(12));
        out.push(if chunk.len() > 1 { index(6) } else { '=' });
        out.push(if chunk.len() > 2 { index(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc_4648() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), expected, "{input}");
        }
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }
}
