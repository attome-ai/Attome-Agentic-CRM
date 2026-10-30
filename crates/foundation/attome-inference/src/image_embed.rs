//! Image search embeddings (A25-T6, V2-D1429): an image-text model, SigLIP 2,
//! puts images and short texts in one vector space, so an image finds images
//! like it and a description finds the images it describes.
//!
//! The server is an OpenAI-compatible `POST {base_url}/embeddings` that
//! takes a `modality` (`image` or `text`), as Infinity does: an image goes in
//! as a `data:` URL with its base64 bytes. Results come back with an `index`
//! per item and are returned in the caller's order. Like every embedding
//! endpoint it must be inside the deployment: images are customer data.

use attome_config::InferenceSection;
use serde::{Deserialize, Serialize};

use crate::embed::EMBEDDINGS_PATH;
use crate::{InferenceError, Transport};

/// The most items embedded in one call.
pub const MAX_BATCH: usize = 16;
/// The largest image sent, in bytes before base64.
pub const MAX_IMAGE_BYTES: usize = 5 * 1024 * 1024;

/// What the inputs of one call are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modality {
    Image,
    Text,
}

impl Modality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Text => "text",
        }
    }
}

#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    input: &'a [String],
    modality: &'static str,
}

#[derive(Deserialize)]
struct Response {
    data: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    embedding: Vec<f32>,
    #[serde(default)]
    index: usize,
}

/// The image content type `bytes` starts like: PNG, JPEG, WebP or GIF. Pure.
pub fn image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.len() >= 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else {
        None
    }
}

/// `bytes` as the `data:` URL the server takes, or `None` when they are not
/// a supported image or are larger than [`MAX_IMAGE_BYTES`]. Pure.
pub fn image_input(bytes: &[u8]) -> Option<String> {
    use base64::Engine as _;
    if bytes.len() > MAX_IMAGE_BYTES {
        return None;
    }
    let content_type = image_type(bytes)?;
    Some(format!(
        "data:{content_type};base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    ))
}

/// A client over `inference.image_embedding`. Cheap to clone.
#[derive(Clone)]
pub struct ImageEmbeddingClient {
    transport: Transport,
}

impl std::fmt::Debug for ImageEmbeddingClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageEmbeddingClient")
            .finish_non_exhaustive()
    }
}

impl ImageEmbeddingClient {
    pub fn new(section: &InferenceSection) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::new(section.image_embedding.clone(), "image_embedding", false)?,
        })
    }

    pub fn model_id(&self) -> &str {
        self.transport.model()
    }

    /// One vector per input, in the caller's order. `inputs` are `data:`
    /// URLs ([`image_input`]) for [`Modality::Image`], plain text for
    /// [`Modality::Text`]; at most [`MAX_BATCH`] of them.
    pub async fn embed(
        &self,
        inputs: &[String],
        modality: Modality,
    ) -> Result<Vec<Vec<f32>>, InferenceError> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        if inputs.len() > MAX_BATCH {
            return Err(InferenceError::Misconfigured {
                endpoint: "image_embedding",
                reason: "too many inputs for one image embedding call",
            });
        }
        let started = std::time::Instant::now();
        let request = Request {
            model: self.transport.model(),
            input: inputs,
            modality: modality.as_str(),
        };
        // An embedding is a pure function of its input, so a transient
        // failure is replayed (D-645), as for text embeddings.
        let result = self
            .transport
            .post_idempotent::<_, Response>(EMBEDDINGS_PATH, &request)
            .await
            .and_then(|response| ordered(response, inputs.len()));
        crate::telemetry::record("image_embedding", started, &result);
        result
    }
}

/// The vectors in input order, or a bad response when one is missing,
/// repeated, out of range or empty.
fn ordered(response: Response, len: usize) -> Result<Vec<Vec<f32>>, InferenceError> {
    let bad = |reason| InferenceError::BadResponse {
        endpoint: "image_embedding",
        reason,
    };
    if response.data.len() != len {
        return Err(bad("embedding count did not match the input count"));
    }
    let mut out: Vec<Option<Vec<f32>>> = vec![None; len];
    for item in response.data {
        let slot = out
            .get_mut(item.index)
            .ok_or(bad("embedding index out of range"))?;
        if slot.is_some() {
            return Err(bad("embedding index repeated"));
        }
        if item.embedding.is_empty() || item.embedding.iter().any(|v| !v.is_finite()) {
            return Err(bad("embedding is empty or not a number"));
        }
        *slot = Some(item.embedding);
    }
    out.into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or(bad("embedding missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_types_are_read_from_the_bytes() {
        assert_eq!(image_type(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(image_type(&[0xFF, 0xD8, 0xFF, 0xE0]), Some("image/jpeg"));
        assert_eq!(image_type(b"RIFF\0\0\0\0WEBPVP8 "), Some("image/webp"));
        assert_eq!(image_type(b"GIF89a"), Some("image/gif"));
        assert_eq!(image_type(b"%PDF-1.7"), None);
        let url = image_input(b"GIF89a").unwrap_or_default();
        assert!(url.starts_with("data:image/gif;base64,"), "{url}");
        assert!(image_input(&vec![0u8; MAX_IMAGE_BYTES + 1]).is_none());
    }

    #[test]
    fn vectors_come_back_in_input_order() {
        let response = Response {
            data: vec![
                Item {
                    embedding: vec![2.0],
                    index: 1,
                },
                Item {
                    embedding: vec![1.0],
                    index: 0,
                },
            ],
        };
        assert_eq!(ordered(response, 2).ok(), Some(vec![vec![1.0], vec![2.0]]));
        let repeated = Response {
            data: vec![
                Item {
                    embedding: vec![1.0],
                    index: 0,
                },
                Item {
                    embedding: vec![1.0],
                    index: 0,
                },
            ],
        };
        assert!(ordered(repeated, 2).is_err());
    }
}
