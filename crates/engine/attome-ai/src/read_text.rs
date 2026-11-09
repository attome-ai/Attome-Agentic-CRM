//! N21 / B16-T14: reading the text of an image the person just captured (a
//! label, a document, a receipt) through the deployment's own vision model
//! (`attome_inference::OcrClient`, N21-T1).
//!
//! - `GET /api/v1/ai/read-text` says whether reading text is available here:
//!   the scan dialog shows its "Read text" button only when it is.
//! - `POST /api/v1/ai/read-text` takes one PNG, JPEG or WebP image (base64,
//!   at most 10 MiB decoded) and answers its text and the model that read it.
//!   It stores nothing and logs neither the image nor the text: the person
//!   decides what to do with the text. At most [`PER_MINUTE`] reads a minute
//!   per person (each one is a model run), refused with 429 past that and
//!   fail-closed when the rate store is down.
//!
//! The endpoint is inside the deployment whatever `allow_external_provider`
//! says (documents are customer data); without one configured the read is a
//! 503 `feature_unavailable` and the probe says `available: false`. Behind
//! the MODULE_AI licence gate with the other AI routes.

use attome_core::EngineState;
use attome_inference::{InferenceError, OcrClient};
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
// Named only inside the `#[utoipa::path]` attribute, which the compiler does not count as a use.
#[allow(unused_imports)]
use serde_json::json;
use utoipa::ToSchema;

/// The most reads a person may make in one minute.
pub const PER_MINUTE: i32 = 10;

/// Whether reading text is available.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReadTextAvailability {
    pub available: bool,
}

/// An image to read.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReadTextBody {
    /// The image, base64.
    pub image: String,
    /// `image/png`, `image/jpeg` or `image/webp`.
    pub media_type: String,
    /// A hint, `ar` or `en`, when the person knows the language.
    pub language: Option<String>,
}

/// What the model read.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ReadTextResponse {
    pub text: String,
    /// The model that read it, for provenance.
    pub model: String,
}

/// The image decoded, or why it is refused. Pure.
pub fn decode_image(body: &ReadTextBody) -> Result<Vec<u8>, AppError> {
    let media_type = body.media_type.trim().to_ascii_lowercase();
    if !attome_inference::ocr::IMAGE_TYPES.contains(&media_type.as_str()) {
        return Err(AppError::Validation(
            "media_type: image/png, image/jpeg or image/webp".into(),
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(body.image.trim())
        .map_err(|_| AppError::Validation("image: not base64".into()))?;
    if bytes.is_empty() || bytes.len() > attome_inference::ocr::MAX_IMAGE_BYTES {
        return Err(AppError::Validation(format!(
            "image: 1 to {} bytes",
            attome_inference::ocr::MAX_IMAGE_BYTES
        )));
    }
    Ok(bytes)
}

/// The language hint, when it is one the model is told about. Pure.
pub fn language_hint(language: Option<&str>) -> Option<&'static str> {
    match language.map(str::trim) {
        Some("ar") => Some("ar"),
        Some("en") => Some("en"),
        _ => None,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/ai/read-text",
    operation_id = "get_ai_read_text_availability",
    tag = "ai",
    responses(
        (status = 200, description = "Whether reading text from an image is available here", body = ReadTextAvailability),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Whether text can be read from images
///
/// B16-T14: `available` is false when the deployment has no vision model
/// for reading text; the scan dialog then hides its "Read text" button.
async fn availability(
    State(state): State<EngineState>,
    _ctx: Authorized<SelfService>,
) -> Json<ReadTextAvailability> {
    Json(ReadTextAvailability {
        available: OcrClient::new(&state.base.config.inference).is_ok(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/ai/read-text",
    operation_id = "post_ai_read_text",
    tag = "ai",
    request_body = ReadTextBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::ReadOnly,
        None,
        "reads the text of the image the caller sent and answers it; stores nothing"
    )))),
    responses(
        (status = 200, description = "The image's text", body = ReadTextResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Not a PNG, JPEG or WebP image, not base64, or too large", body = ErrorResponse),
        (status = 429, description = "More than 10 reads in a minute", body = ErrorResponse),
        (status = 503, description = "No vision model for reading text here, or it is down", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Read the text of an image
///
/// N21 / B16-T14: the deployment's own vision model transcribes the image's
/// text in its own language and script. Nothing is stored or logged.
async fn read_text(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<ReadTextBody>,
) -> Result<Json<ReadTextResponse>, AppError> {
    let image = decode_image(&body)?;
    let client = match OcrClient::new(&state.base.config.inference) {
        Ok(client) => client,
        Err(InferenceError::NotConfigured(_)) => return Err(AppError::FeatureUnavailable),
        Err(error) => return Err(AppError::internal(error)),
    };
    let key = format!("ai:rl:user:{}:read_text", ctx.user_id);
    let outcome =
        attome_cache::rate_limit::check(&state.base.redis_coordination, &key, PER_MINUTE).await?;
    if !outcome.allowed {
        return Err(AppError::TooManyRequests {
            retry_after_secs: Some(outcome.retry_after_secs),
        });
    }
    let started = std::time::Instant::now();
    let read = client
        .read_text(
            &image,
            body.media_type.trim(),
            language_hint(body.language.as_deref()),
        )
        .await;
    tracing::info!(
        user_id = %ctx.user_id,
        bytes = image.len(),
        ok = read.is_ok(),
        elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        "image text read"
    );
    match read {
        Ok(text) => Ok(Json(ReadTextResponse {
            text: text.text,
            model: text.model_id,
        })),
        Err(InferenceError::NotConfigured(_)) => Err(AppError::FeatureUnavailable),
        Err(InferenceError::Timeout(_) | InferenceError::Transport { .. }) => {
            Err(AppError::CapabilityUnavailable("ai_model"))
        }
        Err(error) => Err(AppError::internal(error)),
    }
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/ai/read-text", get(availability).post(read_text))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(availability, read_text),
    components(schemas(ReadTextAvailability, ReadTextBody, ReadTextResponse))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test fixtures")]

    use super::*;

    fn body(image: &str, media_type: &str) -> ReadTextBody {
        ReadTextBody {
            image: image.to_owned(),
            media_type: media_type.to_owned(),
            language: None,
        }
    }

    #[test]
    fn only_a_base64_png_jpeg_or_webp_is_read() {
        let png = base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n");
        assert_eq!(
            decode_image(&body(&png, "image/png")).unwrap(),
            b"\x89PNG\r\n"
        );
        assert!(decode_image(&body(&png, "IMAGE/JPEG ")).is_ok());
        assert!(matches!(
            decode_image(&body(&png, "application/pdf")),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            decode_image(&body("%%%", "image/png")),
            Err(AppError::Validation(_))
        ));
        assert!(matches!(
            decode_image(&body("", "image/png")),
            Err(AppError::Validation(_))
        ));
    }

    #[test]
    fn only_arabic_and_english_hints_reach_the_model() {
        assert_eq!(language_hint(Some("ar")), Some("ar"));
        assert_eq!(language_hint(Some(" en ")), Some("en"));
        assert_eq!(language_hint(Some("fr")), None);
        assert_eq!(language_hint(None), None);
    }
}
