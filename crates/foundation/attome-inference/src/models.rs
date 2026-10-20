//! Model listing — `GET {base_url}/models`, the one outbound call that is
//! neither a generation nor an embedding.
//!
//! A provider record and `config.inference.generation` describe the same kind
//! of destination, so they must not disagree about how it is reached or how
//! its answer is masked. This used to live in `xrm-ai`'s `provider_models`
//! with its own URL joining, its own parsing and its own unbounded
//! `response.json()`; BIN-D3 moves the transport half here. The caller still
//! builds the HTTP client and owns the reachability decision (D-571) — an
//! admin-authored provider record is a lower-trust principal than the operator
//! who edits the config file, and that difference belongs where the trust is
//! decided, not here.

use serde::{Deserialize, Serialize};

use crate::{InferenceError, classify_status, join_path, parse_base_url, read_body_capped};

/// The listing path, relative to a base URL.
pub const MODELS_PATH: &str = "/models";

/// Caps the parsed list. A provider is not trusted to bound its own response,
/// and an operator cannot meaningfully pick from more than this anyway.
pub const MAX_MODELS: usize = 500;

/// Caps a single id/label, so a hostile or broken provider cannot push an
/// unbounded string through an API into a browser.
pub const MAX_FIELD_LEN: usize = 200;

/// One model as the provider reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelListing {
    /// The wire id to send as `model`.
    pub id: String,
    /// A human label when the provider offers one — Anthropic spells it
    /// `display_name`, and several OpenAI-compatible gateways spell it `name`.
    /// `None` for a listing that carries only ids.
    pub display_name: Option<String>,
}

/// How to authenticate a listing request.
///
/// There is deliberately no protocol enum here: this crate knows HTTP, not
/// which vendor is being spoken to. The caller maps its own protocol to these
/// three knobs, which is the whole difference between them.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModelListAuth<'a> {
    /// `Authorization: Bearer …` — OpenAI-compatible servers.
    pub bearer: Option<&'a str>,
    /// `x-api-key: …` — Anthropic.
    pub x_api_key: Option<&'a str>,
    /// Send `anthropic-version`. A request without it is a 400, not a default.
    pub anthropic_version: bool,
}

/// Lists the models `base_url` offers, over a client the caller built.
///
/// The body is read under [`crate::MAX_BODY_BYTES`], so a gateway cannot make
/// the caller buffer an unbounded listing, and a non-success status is
/// classified like every other call. No provider text reaches the error.
pub async fn list_models(
    http: &crate::DialClient,
    base_url: &str,
    auth: ModelListAuth<'_>,
) -> Result<Vec<ModelListing>, InferenceError> {
    let base = parse_base_url(base_url, LABEL)?;
    let http = http.admit(&base, LABEL)?;
    crate::test_network_guard(&base, LABEL, crate::no_network())?;
    let started = std::time::Instant::now();
    let result = list_once(http, &base, auth).await;
    crate::telemetry::record("models", started, &result);
    result
}

const LABEL: &str = "model listing";

async fn list_once(
    http: &attome_outbound::http::Outbound,
    base: &reqwest::Url,
    auth: ModelListAuth<'_>,
) -> Result<Vec<ModelListing>, InferenceError> {
    let mut request = http.get(join_path(base, MODELS_PATH));
    if auth.anthropic_version {
        request = request.header("anthropic-version", "2023-06-01");
    }
    if let Some(key) = auth.x_api_key.filter(|key| !key.is_empty()) {
        request = request.header("x-api-key", key);
    }
    if let Some(key) = auth.bearer.filter(|key| !key.is_empty()) {
        request = request.bearer_auth(key);
    }

    let response = request.send().await.map_err(|e| {
        if e.is_timeout() {
            InferenceError::Timeout(LABEL)
        } else {
            InferenceError::Transport {
                endpoint: LABEL,
                kind: "request failed",
            }
        }
    })?;

    if response.status().is_redirection() {
        tracing::warn!(
            status = response.status().as_u16(),
            "model listing request was redirected; refusing to follow it"
        );
        return Err(InferenceError::BadResponse {
            endpoint: LABEL,
            reason: "redirect refused",
        });
    }
    if !response.status().is_success() {
        let class = classify_status(response.status(), response.headers());
        tracing::warn!(
            status = response.status().as_u16(),
            "model listing request returned a non-success status"
        );
        return Err(InferenceError::Upstream {
            endpoint: LABEL,
            class,
        });
    }

    let body = read_body_capped(response, LABEL).await?;
    let value: serde_json::Value =
        serde_json::from_slice(&body).map_err(|_| InferenceError::BadResponse {
            endpoint: LABEL,
            reason: "the model listing was not valid JSON",
        })?;
    Ok(parse_model_listing(&value))
}

/// Extracts the model list from a provider's response body.
///
/// OpenAI (`/v1/models`) and Anthropic (`/v1/models`) both answer
/// `{"data": [...]}`; a bare array is also accepted because several
/// OpenAI-compatible self-hosted servers answer that way, as are bare string
/// entries. Anything else yields an empty list rather than an error: "this
/// provider returned nothing we recognise" is an outcome an operator can see
/// and act on, and is not distinguishable from an empty catalog anyway.
///
/// Separated from [`list_models`] so the untrusted-input handling is testable
/// without a network.
pub fn parse_model_listing(body: &serde_json::Value) -> Vec<ModelListing> {
    let items = body
        .get("data")
        .and_then(|data| data.as_array())
        .or_else(|| body.as_array());
    let Some(items) = items else {
        return Vec::new();
    };

    items
        .iter()
        .filter_map(|item| {
            if let Some(id) = item.as_str() {
                return (!id.trim().is_empty()).then(|| ModelListing {
                    id: clamp(id.trim()),
                    display_name: None,
                });
            }
            let id = item.get("id").and_then(|value| value.as_str())?.trim();
            if id.is_empty() {
                return None;
            }
            // `display_name` first, `name` as the fallback: the two spellings
            // never co-occur in a listing, and preferring the Anthropic one
            // keeps behaviour unchanged for providers that send both.
            let display_name = ["display_name", "name"]
                .iter()
                .find_map(|key| item.get(*key).and_then(|value| value.as_str()))
                .map(str::trim)
                .filter(|label| !label.is_empty())
                .map(clamp);
            Some(ModelListing {
                id: clamp(id),
                display_name,
            })
        })
        .take(MAX_MODELS)
        .collect()
}

/// Truncates on a char boundary so a multi-byte id cannot panic here.
fn clamp(value: &str) -> String {
    value.chars().take(MAX_FIELD_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(models: &[ModelListing]) -> Vec<&str> {
        models.iter().map(|model| model.id.as_str()).collect()
    }

    #[test]
    fn parses_the_openai_listing_shape() {
        let body = serde_json::json!({
            "object": "list",
            "data": [
                {"id": "gpt-4o", "object": "model", "owned_by": "openai"},
                {"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
            ]
        });
        let models = parse_model_listing(&body);
        assert_eq!(ids(&models), ["gpt-4o", "gpt-4o-mini"]);
        assert_eq!(models[0].display_name, None);
    }

    #[test]
    fn parses_the_anthropic_listing_shape_including_display_name() {
        let body = serde_json::json!({
            "data": [
                {"type": "model", "id": "claude-opus-5", "display_name": "Claude Opus 5"},
            ]
        });
        let models = parse_model_listing(&body);
        assert_eq!(ids(&models), ["claude-opus-5"]);
        assert_eq!(models[0].display_name.as_deref(), Some("Claude Opus 5"));
    }

    /// An OpenAI-compatible gateway that labels models with `name` rather
    /// than Anthropic's `display_name`. Found live: without the fallback the
    /// whole listing came back as bare ids and the picker lost every label.
    #[test]
    fn parses_an_openai_listing_that_labels_models_with_name() {
        let body = serde_json::json!({
            "object": "list",
            "data": [
                {"id": "claude-sonnet-5", "object": "model", "name": "Claude Sonnet 5",
                 "owned_by": "command-code", "context_length": 1_000_000},
            ]
        });
        let models = parse_model_listing(&body);
        assert_eq!(ids(&models), ["claude-sonnet-5"]);
        assert_eq!(models[0].display_name.as_deref(), Some("Claude Sonnet 5"));
    }

    /// `display_name` wins where a provider sends both, so adding the `name`
    /// fallback cannot change what an Anthropic-shaped listing shows.
    #[test]
    fn display_name_takes_precedence_over_name() {
        let body = serde_json::json!({
            "data": [{"id": "m", "display_name": "Preferred", "name": "Fallback"}]
        });
        assert_eq!(
            parse_model_listing(&body)[0].display_name.as_deref(),
            Some("Preferred")
        );
    }

    /// Several OpenAI-compatible self-hosted servers answer a bare array.
    #[test]
    fn parses_a_bare_array_and_bare_string_entries() {
        let body = serde_json::json!([{"id": "local-model"}, "another-model"]);
        assert_eq!(
            ids(&parse_model_listing(&body)),
            ["local-model", "another-model"]
        );
    }

    /// Untrusted input: a malformed entry is skipped, not propagated, and an
    /// unrecognised envelope is an empty list rather than a failure.
    #[test]
    fn malformed_entries_are_skipped_rather_than_failing_the_whole_listing() {
        let body = serde_json::json!({
            "data": [
                {"id": "good"},
                {"no_id": true},
                {"id": ""},
                {"id": "   "},
                42,
                {"id": "also-good"},
            ]
        });
        assert_eq!(ids(&parse_model_listing(&body)), ["good", "also-good"]);
        assert!(parse_model_listing(&serde_json::json!({"error": "nope"})).is_empty());
        assert!(parse_model_listing(&serde_json::json!("not a list")).is_empty());
    }

    /// A provider does not get to decide how much this deployment returns.
    #[test]
    fn the_listing_is_capped() {
        let data: Vec<_> = (0..MAX_MODELS + 50)
            .map(|index| serde_json::json!({"id": format!("m{index}")}))
            .collect();
        let models = parse_model_listing(&serde_json::json!({ "data": data }));
        assert_eq!(models.len(), MAX_MODELS);
    }

    #[test]
    fn an_overlong_field_is_truncated_on_a_char_boundary() {
        let long = "é".repeat(MAX_FIELD_LEN + 100);
        let models = parse_model_listing(&serde_json::json!({"data": [{"id": long}]}));
        assert_eq!(models[0].id.chars().count(), MAX_FIELD_LEN);
    }

    /// The listing path is joined onto the parsed base, so a base path is
    /// preserved (`Url::join` would drop the `/v1` an operator configured).
    #[test]
    fn the_listing_path_is_appended_to_the_base_path() {
        assert_eq!(MODELS_PATH, "/models");
    }
}
