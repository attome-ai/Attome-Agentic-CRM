//! Z9-T2: Anthropic's Messages API (`POST /v1/messages`) behind
//! [`ModelAdapter`]: chat whole or streamed, with tool use, in the crate's
//! provider-neutral shape.
//!
//! The wire differs from the OpenAI-compatible one in four ways this module
//! absorbs: system messages travel as a top-level `system`; a tool call is a
//! `tool_use` content block whose `input` is an object (the neutral shape
//! keeps it as the raw JSON text); a tool's result is a `tool_result` block in
//! a user turn, and consecutive turns of one role are merged into one message,
//! as the API requires; the key goes in `x-api-key` with an
//! `anthropic-version` header. Anthropic offers no embeddings.

use attome_config::InferenceEndpoint;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{AdapterFuture, Caps, ModelAdapter};
use crate::generate::{
    BYTES_PER_OUTPUT_TOKEN, MAX_SSE_LINE_BYTES, MAX_TOOL_CALLS, STREAM_IDLE_TIMEOUT,
};
use crate::{
    DialClient, EmbedKind, FinishReason, GenerationRequest, GenerationResult, InferenceError,
    KeyHeader, Role, ToolCall, ToolChoice, Transport, Usage,
};

/// The Messages API path, joined onto a base URL such as
/// `https://api.anthropic.com`.
pub const MESSAGES_PATH: &str = "/v1/messages";
/// The API version every request names.
pub const API_VERSION: &str = "2023-06-01";

/// Anthropic's models through the Messages API.
#[derive(Clone)]
pub struct Anthropic {
    transport: Transport,
    max_output_tokens: u32,
}

impl std::fmt::Debug for Anthropic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Anthropic")
            .field("model", &self.transport.model())
            .finish_non_exhaustive()
    }
}

impl Anthropic {
    /// For `endpoint` (its `api_key` is the Anthropic key). An endpoint
    /// outside the data plane needs `allow_external`, as every model
    /// endpoint does.
    pub fn new(
        endpoint: InferenceEndpoint,
        max_output_tokens: u32,
        allow_external: bool,
    ) -> Result<Self, InferenceError> {
        Ok(Self::over(
            Transport::new(endpoint, "generation", allow_external)?,
            max_output_tokens,
        ))
    }

    /// For an endpoint the caller has already decided is reachable, over
    /// its client (as `GenerationClient::for_endpoint`).
    pub fn for_endpoint(
        endpoint: InferenceEndpoint,
        max_output_tokens: u32,
        http: DialClient,
    ) -> Result<Self, InferenceError> {
        Ok(Self::over(
            Transport::with_client(http, endpoint, "generation")?,
            max_output_tokens,
        ))
    }

    fn over(transport: Transport, max_output_tokens: u32) -> Self {
        Self {
            transport: transport
                .with_key_header(KeyHeader::Named("x-api-key"))
                .with_header("anthropic-version", API_VERSION),
            max_output_tokens,
        }
    }

    fn max_tokens(&self, request: &GenerationRequest) -> u32 {
        request
            .max_output_tokens
            .unwrap_or(self.max_output_tokens)
            .min(self.max_output_tokens)
    }

    async fn chat_once(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResult, InferenceError> {
        let max_tokens = self.max_tokens(&request);
        let body = to_wire(&request, self.transport.model(), max_tokens, false);
        let response: MessagesResponse = self.transport.post(MESSAGES_PATH, &body).await?;
        Ok(response.into_result(self.transport.model()))
    }

    async fn stream_once(
        &self,
        request: GenerationRequest,
        on_delta: &mut (dyn FnMut(&str) + Send),
    ) -> Result<GenerationResult, InferenceError> {
        let label = self.transport.label();
        let max_tokens = self.max_tokens(&request);
        let body = to_wire(&request, self.transport.model(), max_tokens, true);
        let idle = STREAM_IDLE_TIMEOUT.min(self.transport.request_timeout());
        let mut response = self.transport.post_streaming(MESSAGES_PATH, &body).await?;
        let mut assembler = Assembler::new(max_tokens);
        loop {
            let chunk = match tokio::time::timeout(idle, response.chunk()).await {
                Err(_) => return Err(InferenceError::Timeout(label)),
                Ok(Err(e)) if e.is_timeout() => return Err(InferenceError::Timeout(label)),
                Ok(Err(_)) => {
                    return Err(InferenceError::Transport {
                        endpoint: label,
                        kind: "stream interrupted",
                    });
                }
                Ok(Ok(None)) => break,
                Ok(Ok(Some(bytes))) => bytes,
            };
            assembler.push(&chunk, &mut *on_delta).map_err(|reason| {
                InferenceError::BadResponse {
                    endpoint: label,
                    reason,
                }
            })?;
            if assembler.done {
                break;
            }
        }
        assembler
            .finish(self.transport.model())
            .map_err(|reason| InferenceError::BadResponse {
                endpoint: label,
                reason,
            })
    }
}

impl ModelAdapter for Anthropic {
    fn capabilities(&self) -> Caps {
        Caps {
            tools: true,
            streaming: true,
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
            let started = std::time::Instant::now();
            let result = self.stream_once(request, on_delta).await;
            crate::telemetry::record("generation", started, &result);
            result
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

/// The Messages API request for `request`.
pub(crate) fn to_wire(
    request: &GenerationRequest,
    model: &str,
    max_tokens: u32,
    stream: bool,
) -> Value {
    let mut system: Vec<&str> = Vec::new();
    // (role, content blocks), consecutive turns of one role merged.
    let mut turns: Vec<(&'static str, Vec<Value>)> = Vec::new();
    for message in &request.messages {
        let (role, blocks) = match message.role {
            Role::System => {
                if !message.content.is_empty() {
                    system.push(&message.content);
                }
                continue;
            }
            Role::User => ("user", text_block(&message.content)),
            Role::Assistant => {
                let mut blocks = text_block(&message.content);
                blocks.extend(message.tool_calls.iter().map(tool_use_block));
                ("assistant", blocks)
            }
            Role::Tool => (
                "user",
                vec![json!({
                    "type": "tool_result",
                    "tool_use_id": message.tool_call_id.clone().unwrap_or_default(),
                    "content": message.content,
                })],
            ),
        };
        if blocks.is_empty() {
            continue;
        }
        match turns.last_mut() {
            Some((last, existing)) if *last == role => existing.extend(blocks),
            _ => turns.push((role, blocks)),
        }
    }
    let mut body = json!({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": request.temperature,
        "messages": turns
            .into_iter()
            .map(|(role, content)| json!({"role": role, "content": content}))
            .collect::<Vec<_>>(),
    });
    if !system.is_empty() {
        body["system"] = json!(system.join("\n\n"));
    }
    if !request.tools.is_empty() {
        body["tools"] = request
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.parameters,
                })
            })
            .collect();
        body["tool_choice"] = json!({"type": match request.tool_choice {
            ToolChoice::Auto => "auto",
            ToolChoice::Required => "any",
            ToolChoice::None => "none",
        }});
    }
    if stream {
        body["stream"] = json!(true);
    }
    body
}

/// A text block, or none for empty text (the API refuses an empty one).
fn text_block(text: &str) -> Vec<Value> {
    if text.is_empty() {
        Vec::new()
    } else {
        vec![json!({"type": "text", "text": text})]
    }
}

/// A replayed tool call. The neutral shape holds the arguments as raw text;
/// the API wants an object, so text that is not one replays as `{}` (the
/// call was already refused as unusable when it was made).
fn tool_use_block(call: &ToolCall) -> Value {
    let input = serde_json::from_str::<Value>(&call.arguments)
        .ok()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    json!({"type": "tool_use", "id": call.id, "name": call.name, "input": input})
}

fn finish_reason(raw: Option<&str>, had_tool_calls: bool) -> FinishReason {
    match raw {
        Some("end_turn" | "stop_sequence") => FinishReason::Stop,
        Some("tool_use") => FinishReason::ToolCalls,
        Some("max_tokens") => FinishReason::Length,
        Some("refusal") => FinishReason::ContentFilter,
        Some(other) => FinishReason::Other(other.to_owned()),
        None if had_tool_calls => FinishReason::ToolCalls,
        None => FinishReason::Stop,
    }
}

#[derive(Deserialize)]
struct MessagesResponse {
    #[serde(default)]
    content: Vec<Block>,
    stop_reason: Option<String>,
    usage: Option<WireUsage>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Block {
    Text {
        text: String,
    },
    ToolUse {
        id: String,
        name: String,
        #[serde(default)]
        input: Value,
    },
    #[serde(other)]
    Other,
}

#[derive(Deserialize, Default, Clone, Copy)]
struct WireUsage {
    #[serde(default)]
    input_tokens: u32,
    #[serde(default)]
    output_tokens: u32,
    cache_read_input_tokens: Option<u32>,
}

fn usage(model: &str, wire: Option<WireUsage>) -> Usage {
    Usage {
        model_id: model.to_owned(),
        prompt_tokens: wire.map_or(0, |u| u.input_tokens),
        completion_tokens: wire.map_or(0, |u| u.output_tokens),
        reported: wire.is_some(),
        cached_prompt_tokens: wire.and_then(|u| u.cache_read_input_tokens),
    }
}

impl MessagesResponse {
    fn into_result(self, model: &str) -> GenerationResult {
        let mut text = String::new();
        let mut tool_calls = Vec::new();
        for block in self.content {
            match block {
                Block::Text { text: t } => text.push_str(&t),
                Block::ToolUse { id, name, input } => tool_calls.push(ToolCall {
                    id,
                    name,
                    arguments: if input.is_null() {
                        "{}".to_owned()
                    } else {
                        input.to_string()
                    },
                }),
                Block::Other => {}
            }
        }
        let finish_reason = finish_reason(self.stop_reason.as_deref(), !tool_calls.is_empty());
        GenerationResult {
            truncated: finish_reason == FinishReason::Length,
            text,
            usage: usage(model, self.usage),
            tool_calls,
            finish_reason,
        }
    }
}

/// One tool call being reassembled from its stream fragments.
#[derive(Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
}

/// Reassembles Anthropic's server-sent events into the result the whole call
/// returns. Pure bytes in, deltas and a result out, under the same caps as
/// the OpenAI-compatible assembler: line length, total size, text size and
/// the number of tool calls.
pub(crate) struct Assembler {
    buffer: Vec<u8>,
    text: String,
    /// By content block index.
    calls: std::collections::BTreeMap<u64, PartialCall>,
    stop_reason: Option<String>,
    usage: Option<WireUsage>,
    /// `message_stop` arrived.
    pub(crate) done: bool,
    max_text_bytes: usize,
    received: usize,
}

impl Assembler {
    pub(crate) fn new(max_tokens: u32) -> Self {
        Self {
            buffer: Vec::new(),
            text: String::new(),
            calls: std::collections::BTreeMap::new(),
            stop_reason: None,
            usage: None,
            done: false,
            max_text_bytes: (max_tokens as usize)
                .saturating_mul(BYTES_PER_OUTPUT_TOKEN)
                .min(crate::MAX_BODY_BYTES),
            received: 0,
        }
    }

    pub(crate) fn push(
        &mut self,
        bytes: &[u8],
        on_delta: &mut (dyn FnMut(&str) + Send),
    ) -> Result<(), &'static str> {
        self.received = self.received.saturating_add(bytes.len());
        if self.received > crate::MAX_BODY_BYTES {
            return Err("stream exceeded the size cap");
        }
        self.buffer.extend_from_slice(bytes);
        while let Some(end) = self.buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.buffer.drain(..=end).collect();
            let line = std::str::from_utf8(&line)
                .map_err(|_| "stream line was not UTF-8")?
                .trim_end();
            if let Some(data) = line.strip_prefix("data:") {
                self.event(data.trim(), on_delta)?;
            }
        }
        if self.buffer.len() > MAX_SSE_LINE_BYTES {
            return Err("stream line exceeded the size cap");
        }
        Ok(())
    }

    fn event(
        &mut self,
        data: &str,
        on_delta: &mut (dyn FnMut(&str) + Send),
    ) -> Result<(), &'static str> {
        let event: Value = serde_json::from_str(data).map_err(|_| "stream event did not parse")?;
        let index = event.get("index").and_then(Value::as_u64);
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                self.usage = event
                    .pointer("/message/usage")
                    .and_then(|u| serde_json::from_value(u.clone()).ok());
            }
            Some("content_block_start") => {
                let block = event.get("content_block");
                if block.and_then(|b| b.get("type")).and_then(Value::as_str) == Some("tool_use") {
                    let index = index.ok_or("tool call without an index")?;
                    if self.calls.len() >= MAX_TOOL_CALLS {
                        return Err("too many tool calls in one response");
                    }
                    let field = |name: &str| {
                        block
                            .and_then(|b| b.get(name))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    self.calls.insert(
                        index,
                        PartialCall {
                            id: field("id"),
                            name: field("name"),
                            arguments: String::new(),
                        },
                    );
                }
            }
            Some("content_block_delta") => {
                let delta = event.get("delta");
                match delta.and_then(|d| d.get("type")).and_then(Value::as_str) {
                    Some("text_delta") => {
                        let text = delta
                            .and_then(|d| d.get("text"))
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        if self.text.len() + text.len() > self.max_text_bytes {
                            return Err("streamed text exceeded the output cap");
                        }
                        self.text.push_str(text);
                        if !text.is_empty() {
                            on_delta(text);
                        }
                    }
                    Some("input_json_delta") => {
                        let index = index.ok_or("tool call fragment without an index")?;
                        let part = delta
                            .and_then(|d| d.get("partial_json"))
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let call = self
                            .calls
                            .get_mut(&index)
                            .ok_or("tool call fragment for no tool call")?;
                        if call.arguments.len() + part.len() > crate::MAX_BODY_BYTES {
                            return Err("tool call arguments exceeded the size cap");
                        }
                        call.arguments.push_str(part);
                    }
                    _ => {}
                }
            }
            Some("message_delta") => {
                if let Some(reason) = event.pointer("/delta/stop_reason").and_then(Value::as_str) {
                    self.stop_reason = Some(reason.to_owned());
                }
                if let Some(out) = event
                    .pointer("/usage/output_tokens")
                    .and_then(Value::as_u64)
                {
                    let usage = self.usage.get_or_insert_with(WireUsage::default);
                    usage.output_tokens = u32::try_from(out).unwrap_or(u32::MAX);
                }
            }
            Some("message_stop") => self.done = true,
            Some("error") => return Err("the provider reported an error mid-stream"),
            _ => {}
        }
        Ok(())
    }

    /// The whole result. A stream that ends before the model said why it
    /// stopped is an error, never a result (A-83).
    pub(crate) fn finish(self, model: &str) -> Result<GenerationResult, &'static str> {
        let stop_reason = self
            .stop_reason
            .ok_or("stream ended before the model said why it stopped")?;
        let tool_calls: Vec<ToolCall> = self
            .calls
            .into_values()
            .map(|c| ToolCall {
                id: c.id,
                name: c.name,
                arguments: if c.arguments.is_empty() {
                    "{}".to_owned()
                } else {
                    c.arguments
                },
            })
            .collect();
        let finish_reason = finish_reason(Some(&stop_reason), !tool_calls.is_empty());
        Ok(GenerationResult {
            truncated: finish_reason == FinishReason::Length,
            text: self.text,
            usage: usage(model, self.usage),
            tool_calls,
            finish_reason,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChatMessage, ToolDefinition};

    fn request() -> GenerationRequest {
        GenerationRequest::new(vec![
            ChatMessage::system("Be brief."),
            ChatMessage::user("Weather in Riyadh?"),
            ChatMessage::assistant_tool_calls(
                "",
                vec![ToolCall {
                    id: "toolu_1".into(),
                    name: "weather".into(),
                    arguments: "{\"city\":\"Riyadh\"}".into(),
                }],
            ),
            ChatMessage::tool_result("toolu_1", "41C"),
            ChatMessage::tool_result("toolu_2", "dry"),
        ])
        .with_tools(vec![ToolDefinition {
            name: "weather".into(),
            description: "The weather in a city".into(),
            parameters: json!({"type": "object", "properties": {"city": {"type": "string"}}}),
        }])
        .with_tool_choice(ToolChoice::Required)
    }

    #[test]
    fn the_request_takes_anthropic_s_shape() {
        let wire = to_wire(&request(), "claude-sonnet-5-5", 512, false);
        assert_eq!(wire["system"], "Be brief.");
        assert_eq!(wire["max_tokens"], 512);
        assert_eq!(wire["tool_choice"], json!({"type": "any"}));
        assert_eq!(wire["tools"][0]["input_schema"]["type"], "object");
        let messages = wire["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 3, "{wire}");
        assert_eq!(messages[1]["content"][0]["type"], "tool_use");
        assert_eq!(messages[1]["content"][0]["input"]["city"], "Riyadh");
        // Both tool results ride in one user turn.
        assert_eq!(messages[2]["role"], "user");
        assert_eq!(messages[2]["content"].as_array().unwrap().len(), 2);
        assert_eq!(messages[2]["content"][1]["tool_use_id"], "toolu_2");
        assert!(wire.get("stream").is_none());
    }

    #[test]
    fn a_tool_call_comes_back_as_raw_arguments() {
        let response: MessagesResponse = serde_json::from_value(json!({
            "content": [
                {"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "toolu_9", "name": "weather", "input": {"city": "Jeddah"}}
            ],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 20, "output_tokens": 7, "cache_read_input_tokens": 12}
        }))
        .unwrap();
        let result = response.into_result("claude");
        assert_eq!(result.text, "Checking.");
        assert_eq!(result.finish_reason, FinishReason::ToolCalls);
        assert!(result.tool_calls_are_usable());
        assert_eq!(result.tool_calls[0].arguments, "{\"city\":\"Jeddah\"}");
        assert_eq!(result.usage.prompt_tokens, 20);
        assert_eq!(result.usage.cached_prompt_tokens, Some(12));
    }

    fn sse(events: &[Value]) -> String {
        events
            .iter()
            .map(|e| {
                format!(
                    "event: {}\ndata: {e}\n\n",
                    e["type"].as_str().unwrap_or("ping")
                )
            })
            .collect()
    }

    #[test]
    fn a_stream_reassembles_text_and_a_tool_call() {
        let body = sse(&[
            json!({"type": "message_start", "message": {"usage": {"input_tokens": 9, "output_tokens": 1}}}),
            json!({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hel"}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "lo"}}),
            json!({"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_3", "name": "weather", "input": {}}}),
            json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"city\":"}}),
            json!({"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "\"Dammam\"}"}}),
            json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {"output_tokens": 15}}),
            json!({"type": "message_stop"}),
        ]);
        let mut assembler = Assembler::new(256);
        let mut seen = String::new();
        // Split anywhere, even mid-line.
        for piece in body.as_bytes().chunks(7) {
            assembler
                .push(piece, &mut |d: &str| seen.push_str(d))
                .unwrap();
        }
        assert!(assembler.done);
        let result = assembler.finish("claude").unwrap();
        assert_eq!(seen, "Hello");
        assert_eq!(result.text, "Hello");
        assert_eq!(result.tool_calls[0].arguments, "{\"city\":\"Dammam\"}");
        assert_eq!(result.usage.prompt_tokens, 9);
        assert_eq!(result.usage.completion_tokens, 15);
        assert_eq!(result.finish_reason, FinishReason::ToolCalls);
    }

    #[test]
    fn a_stream_cut_short_is_an_error() {
        let body = sse(&[
            json!({"type": "message_start", "message": {"usage": {"input_tokens": 9}}}),
            json!({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}}),
        ]);
        let mut assembler = Assembler::new(256);
        assembler.push(body.as_bytes(), &mut |_: &str| {}).unwrap();
        assert!(assembler.finish("claude").is_err());

        let mut capped = Assembler::new(1);
        let long = sse(&[json!({"type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": "x".repeat(64)}})]);
        assert!(capped.push(long.as_bytes(), &mut |_: &str| {}).is_err());
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn chat_sends_the_key_header_and_version() {
        use crate::testing::{FakeModelServer, json as reply};
        let server = FakeModelServer::start(vec![reply(
            "{\"content\":[{\"type\":\"text\",\"text\":\"hi\"}],\"stop_reason\":\"end_turn\",\
             \"usage\":{\"input_tokens\":3,\"output_tokens\":1}}",
        )])
        .await;
        let endpoint = InferenceEndpoint {
            base_url: server.base_url().trim_end_matches("/v1").to_owned(),
            model: "claude-haiku-5-5".into(),
            api_key: Some("sk-ant-test".into()),
            request_timeout_secs: 5,
        };
        let adapter = Anthropic::new(endpoint, 256, false).unwrap();
        let answer = adapter
            .chat(GenerationRequest::new(vec![ChatMessage::user("hello")]))
            .await
            .unwrap();
        assert_eq!(answer.text, "hi");
        let raw = server.last_request().to_ascii_lowercase();
        assert!(raw.starts_with("post /v1/messages "), "{raw}");
        assert!(raw.contains("x-api-key: sk-ant-test"), "{raw}");
        assert!(raw.contains("anthropic-version: 2023-06-01"), "{raw}");
        assert!(!raw.contains("authorization:"), "{raw}");
    }
}
