//! Z9-T2: Google Vertex AI's Gemini `generateContent` behind
//! [`ModelAdapter`].
//!
//! The base URL is a publisher's model collection,
//! `https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/publishers/google/models`
//! ([`Vertex::models_url`]), the endpoint's `model` the Gemini model id, and
//! its `api_key` an OAuth access token sent as a bearer token. The token
//! expires; whoever holds the endpoint replaces it (exchanging a service
//! account key for one is not done here).
//!
//! Gemini names no tool call: a call gets the id `call_{n}` from its position,
//! and a tool's result is answered by the function's name, found from the
//! call it replies to. Streaming runs as one whole call handed over as one
//! delta, as Bedrock's does.

use attome_config::InferenceEndpoint;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AdapterFuture, Caps, ModelAdapter};
use crate::{
    DialClient, EmbedKind, FinishReason, GenerationRequest, GenerationResult, InferenceError,
    KeyHeader, Role, ToolCall, ToolChoice, Transport, Usage,
};

/// One Gemini model on Vertex AI.
#[derive(Clone)]
pub struct Vertex {
    transport: Transport,
    max_output_tokens: u32,
}

impl std::fmt::Debug for Vertex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vertex")
            .field("model", &self.transport.model())
            .finish_non_exhaustive()
    }
}

impl Vertex {
    /// The base URL of Google's published models in `project` at `location`.
    pub fn models_url(project: &str, location: &str) -> String {
        format!(
            "https://{location}-aiplatform.googleapis.com/v1/projects/{project}/locations/{location}/publishers/google/models"
        )
    }

    /// For `endpoint`. Vertex is outside the data plane, so this needs
    /// `allow_external`.
    pub fn new(
        endpoint: InferenceEndpoint,
        max_output_tokens: u32,
        allow_external: bool,
    ) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::new(endpoint, "generation", allow_external)?
                .with_key_header(KeyHeader::Bearer),
            max_output_tokens,
        })
    }

    /// For an endpoint the caller has already decided is reachable, over
    /// its client.
    pub fn for_endpoint(
        endpoint: InferenceEndpoint,
        max_output_tokens: u32,
        http: DialClient,
    ) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::with_client(http, endpoint, "generation")?
                .with_key_header(KeyHeader::Bearer),
            max_output_tokens,
        })
    }

    async fn chat_once(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResult, InferenceError> {
        let max_tokens = request
            .max_output_tokens
            .unwrap_or(self.max_output_tokens)
            .min(self.max_output_tokens);
        let path = format!("/{}:generateContent", self.transport.model());
        let response: GenerateResponse = self
            .transport
            .post(&path, &to_wire(&request, max_tokens))
            .await?;
        Ok(response.into_result(self.transport.model()))
    }
}

impl ModelAdapter for Vertex {
    fn capabilities(&self) -> Caps {
        Caps {
            tools: true,
            streaming: false,
            embeddings: false,
        }
    }

    fn chat(&self, request: GenerationRequest) -> AdapterFuture<'_, GenerationResult> {
        Box::pin(async move {
            let started = std::time::Instant::now();
            let result = self.chat_once(request).await;
            crate::telemetry::record("generation", started, &result);
            result
        })
    }

    fn chat_stream<'a>(
        &'a self,
        request: GenerationRequest,
        on_delta: &'a mut (dyn FnMut(&str) + Send),
    ) -> AdapterFuture<'a, GenerationResult> {
        Box::pin(async move {
            let result = self.chat(request).await?;
            if !result.text.is_empty() {
                on_delta(&result.text);
            }
            Ok(result)
        })
    }

    fn embed<'a>(
        &'a self,
        _texts: &'a [&'a str],
        _kind: EmbedKind,
    ) -> AdapterFuture<'a, (Vec<Vec<f32>>, Usage)> {
        Box::pin(async { Err(InferenceError::NotConfigured("embedding")) })
    }
}

/// The `generateContent` request for `request`.
pub(crate) fn to_wire(request: &GenerationRequest, max_tokens: u32) -> Value {
    let mut system: Vec<Value> = Vec::new();
    let mut turns: Vec<(&'static str, Vec<Value>)> = Vec::new();
    // The function each earlier call named, by its id, for the results.
    let mut called: Vec<(&str, &str)> = Vec::new();
    for message in &request.messages {
        let (role, parts) = match message.role {
            Role::System => {
                if !message.content.is_empty() {
                    system.push(json!({"text": message.content}));
                }
                continue;
            }
            Role::User => ("user", text_part(&message.content)),
            Role::Assistant => {
                let mut parts = text_part(&message.content);
                for call in &message.tool_calls {
                    called.push((&call.id, &call.name));
                    let args = serde_json::from_str::<Value>(&call.arguments)
                        .ok()
                        .filter(Value::is_object)
                        .unwrap_or_else(|| json!({}));
                    parts.push(json!({"functionCall": {"name": call.name, "args": args}}));
                }
                ("model", parts)
            }
            Role::Tool => {
                let id = message.tool_call_id.as_deref().unwrap_or_default();
                let name = called
                    .iter()
                    .find(|(call_id, _)| *call_id == id)
                    .map_or(id, |(_, name)| *name);
                (
                    "user",
                    vec![json!({"functionResponse": {
                        "name": name,
                        "response": {"content": message.content},
                    }})],
                )
            }
        };
        if parts.is_empty() {
            continue;
        }
        match turns.last_mut() {
            Some((last, existing)) if *last == role => existing.extend(parts),
            _ => turns.push((role, parts)),
        }
    }
    let mut body = json!({
        "contents": turns
            .into_iter()
            .map(|(role, parts)| json!({"role": role, "parts": parts}))
            .collect::<Vec<_>>(),
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": request.temperature},
    });
    if !system.is_empty() {
        body["systemInstruction"] = json!({"parts": system});
    }
    if !request.tools.is_empty() {
        body["tools"] = json!([{"functionDeclarations": request.tools.iter().map(|t| json!({
            "name": t.name,
            "description": t.description,
            "parameters": t.parameters,
        })).collect::<Vec<_>>()}]);
        body["toolConfig"] = json!({"functionCallingConfig": {"mode": match request.tool_choice {
            ToolChoice::Auto => "AUTO",
            ToolChoice::Required => "ANY",
            ToolChoice::None => "NONE",
        }}});
    }
    body
}

fn text_part(text: &str) -> Vec<Value> {
    if text.is_empty() {
        Vec::new()
    } else {
        vec![json!({"text": text})]
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GenerateResponse {
    #[serde(default)]
    candidates: Vec<Candidate>,
    usage_metadata: Option<WireUsage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Candidate {
    content: Option<Content>,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct Content {
    #[serde(default)]
    parts: Vec<Value>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "camelCase")]
struct WireUsage {
    #[serde(default)]
    prompt_token_count: u32,
    #[serde(default)]
    candidates_token_count: u32,
    cached_content_token_count: Option<u32>,
}

impl GenerateResponse {
    fn into_result(self, model: &str) -> GenerationResult {
        let candidate = self.candidates.into_iter().next();
        let finish = candidate.as_ref().and_then(|c| c.finish_reason.clone());
        let parts = candidate
            .and_then(|c| c.content)
            .map(|c| c.parts)
            .unwrap_or_default();
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        for part in parts {
            if let Some(t) = part.get("text").and_then(Value::as_str) {
                text.push_str(t);
            } else if let Some(call) = part.get("functionCall") {
                let position = tool_calls.len();
                tool_calls.push(ToolCall {
                    id: call
                        .get("id")
                        .and_then(Value::as_str)
                        .map_or_else(|| format!("call_{position}"), str::to_owned),
                    name: call
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    arguments: call
                        .get("args")
                        .filter(|v| !v.is_null())
                        .map_or_else(|| "{}".to_owned(), Value::to_string),
                });
            }
        }
        // Gemini says STOP when it asks for a function too.
        let finish_reason = match finish.as_deref() {
            Some("STOP") | None if !tool_calls.is_empty() => FinishReason::ToolCalls,
            Some("STOP") | None => FinishReason::Stop,
            Some("MAX_TOKENS") => FinishReason::Length,
            Some("SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII") => {
                FinishReason::ContentFilter
            }
            Some(other) => FinishReason::Other(other.to_owned()),
        };
        let usage = self.usage_metadata;
        GenerationResult {
            truncated: finish_reason == FinishReason::Length,
            text,
            usage: Usage {
                model_id: model.to_owned(),
                prompt_tokens: usage.map_or(0, |u| u.prompt_token_count),
                completion_tokens: usage.map_or(0, |u| u.candidates_token_count),
                reported: usage.is_some(),
                cached_prompt_tokens: usage.and_then(|u| u.cached_content_token_count),
            },
            tool_calls,
            finish_reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChatMessage, ToolDefinition};

    #[test]
    fn a_tool_result_answers_by_the_function_s_name() {
        let request = GenerationRequest::new(vec![
            ChatMessage::system("Be brief."),
            ChatMessage::user("Weather?"),
            ChatMessage::assistant_tool_calls(
                "",
                vec![ToolCall {
                    id: "call_0".into(),
                    name: "weather".into(),
                    arguments: "{\"city\":\"Najran\"}".into(),
                }],
            ),
            ChatMessage::tool_result("call_0", "30C"),
        ])
        .with_tools(vec![ToolDefinition {
            name: "weather".into(),
            description: "Weather".into(),
            parameters: json!({"type": "object"}),
        }])
        .with_tool_choice(ToolChoice::None);
        let wire = to_wire(&request, 64);
        assert_eq!(wire["systemInstruction"]["parts"][0]["text"], "Be brief.");
        assert_eq!(wire["contents"][1]["role"], "model");
        assert_eq!(
            wire["contents"][1]["parts"][0]["functionCall"]["args"]["city"],
            "Najran"
        );
        assert_eq!(
            wire["contents"][2]["parts"][0]["functionResponse"]["name"],
            "weather"
        );
        assert_eq!(wire["toolConfig"]["functionCallingConfig"]["mode"], "NONE");
        assert_eq!(wire["generationConfig"]["maxOutputTokens"], 64);
    }

    #[test]
    fn a_function_call_with_stop_is_a_tool_call() {
        let response: GenerateResponse = serde_json::from_value(json!({
            "candidates": [{"content": {"role": "model", "parts": [
                {"functionCall": {"name": "weather", "args": {"city": "Qassim"}}}
            ]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 5}
        }))
        .unwrap();
        let result = response.into_result("gemini");
        assert_eq!(result.finish_reason, FinishReason::ToolCalls);
        assert_eq!(result.tool_calls[0].id, "call_0");
        assert_eq!(result.tool_calls[0].arguments, "{\"city\":\"Qassim\"}");
        assert_eq!(result.usage.completion_tokens, 5);
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn chat_posts_generate_content_with_the_token() {
        use crate::testing::{FakeModelServer, json as reply};
        let server = FakeModelServer::start(vec![reply(
            "{\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"ahlan\"}]},\"finishReason\":\"STOP\"}]}",
        )])
        .await;
        let endpoint = InferenceEndpoint {
            base_url: format!(
                "{}/v1/projects/p/locations/me-central2/publishers/google/models",
                server.base_url().trim_end_matches("/v1")
            ),
            model: "gemini-2.5-pro".into(),
            api_key: Some("ya29.token".into()),
            request_timeout_secs: 5,
        };
        let adapter = Vertex::new(endpoint, 256, false).unwrap();
        let mut deltas = String::new();
        let result = adapter
            .chat_stream(
                GenerationRequest::new(vec![ChatMessage::user("hello")]),
                &mut |d: &str| deltas.push_str(d),
            )
            .await
            .unwrap();
        assert_eq!(result.text, "ahlan");
        assert_eq!(deltas, "ahlan");
        assert!(!result.usage.reported);
        let raw = server.last_request().to_ascii_lowercase();
        assert!(
            raw.starts_with("post /v1/projects/p/locations/me-central2/publishers/google/models/gemini-2.5-pro:generatecontent "),
            "{raw}"
        );
        assert!(raw.contains("authorization: bearer ya29.token"), "{raw}");
    }
}
