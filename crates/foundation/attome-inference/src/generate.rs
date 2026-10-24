//! Generation — the client `AiService::complete` should have been.
//!
//! `complete(&str) -> String` had no model identity, no token budget, no
//! timeout, no message roles, and — the part that matters most — **no way to
//! distinguish an instruction from retrieved content**, because there was only
//! one string. This client takes structured messages with roles.
//!
//! That is necessary but nowhere near sufficient for injection defense, and
//! this crate must not be mistaken for the defense. Roles are a wire format; a
//! model can be argued across them. The actual control is that an agent's
//! *capabilities* are gated outside the prompt, by the action registry's risk
//! gate reading a taint flag (D-360 ruling 5, I-10). What this crate
//! contributes is that `xrm-ai` is able to express the distinction at all.

use attome_config::InferenceSection;
use serde::{Deserialize, Serialize};

use crate::{InferenceError, Transport, Usage};

/// The chat-completions path, relative to an endpoint's `base_url`.
///
/// Public so a stand-in model server in another crate's tests can mount the
/// route this client calls without spelling the path itself: invariant I-11
/// allows the literal in production source only inside attome-inference (held by
/// review since D-768 removed its check script).
pub const CHAT_COMPLETIONS_PATH: &str = "/chat/completions";

/// Message roles, in the OpenAI-compatible sense.
///
/// Note what is absent: there is no `Retrieved` role, because no model
/// implements one. Retrieved content is rendered by `xrm-ai` into a delimited
/// block inside a `User` message and is tracked out-of-band by the taint flag
/// on `AiContext`. Adding a role here would suggest the wire format enforces
/// something it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    /// A tool's result being fed back to the model (D-554). The message
    /// carries the `tool_call_id` of the call it answers, which is how the
    /// model pairs result to request.
    ///
    /// This crate attaches no meaning to the content: whether a tool result is
    /// trustworthy is `xrm-ai`'s question (I-10), decided one layer up where
    /// the provenance is known.
    Tool,
}

/// One tool call a model asked for.
///
/// ## `name` is an opaque `String`, and that is the whole boundary (D-554)
///
/// **This crate knows that a tool call exists; it does not know what an Attome
/// action is.** `name` is never an `ActionId` — `xrm-ai` owns resolution from
/// this string into its closed registry, and it is the only crate that can,
/// because `ActionId` is `&'static str` by construction precisely so a runtime
/// string cannot become one. A type from `xrm-*` appearing in this file's
/// signatures breaks the layer rule (base-* never depends on xrm-*), which
/// review holds since D-768.
///
/// ## `arguments` stays a raw string, deliberately
///
/// The wire carries a JSON *string*, and this crate hands it on unparsed.
/// Parsing here would make a model's malformed output a transport error, which
/// collapses two outcomes `xrm-ai` must tell apart: a provider or network
/// failure (`ModelFailure`) and a model that emitted unusable arguments
/// (`InvalidToolCall`). Passing bytes through keeps that distinction where the
/// decision belongs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "WireToolCall", into = "WireToolCall")]
pub struct ToolCall {
    /// Provider-assigned. Stable across a retry of **this** call; a
    /// regenerated response produces a different one, which is why `xrm-ai`
    /// treats it as a proposal identity rather than a semantic key (D-553).
    pub id: String,
    pub name: String,
    /// Exactly as received. Never parsed here.
    pub arguments: String,
}

/// A tool as offered to the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "WireToolDefinition", into = "WireToolDefinition")]
pub struct ToolDefinition {
    pub name: String,
    /// What the model reads when choosing. Tool *selection* moves answer
    /// quality more than any one tool's ranking does, so this text is
    /// functional rather than decorative — but composing it is `xrm-ai`'s job.
    pub description: String,
    /// JSON Schema for the arguments object.
    pub parameters: serde_json::Value,
}

/// Whether the model may, must, or must not call a tool this turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolChoice {
    /// The model decides. The default whenever tools are offered.
    Auto,
    /// Tools are visible but must not be called — a plain answer is required.
    None,
    /// The model must call at least one tool.
    Required,
}

/// Why generation stopped.
///
/// Carried through rather than inferred. `Length` arriving alongside tool
/// calls is the single nastiest failure in this feature — a truncated call
/// whose `arguments` happen to parse runs an action with half its inputs and
/// nothing looks wrong — so the caller is given the fact rather than a guess.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinishReason {
    /// The model finished its answer.
    Stop,
    /// The model wants one or more tools called.
    ToolCalls,
    /// The token ceiling was hit. **Not a completion.**
    Length,
    /// The provider's own content filter stopped it.
    ContentFilter,
    /// Anything else a provider reports, preserved verbatim rather than
    /// flattened into `Stop`.
    Other(String),
}

impl FinishReason {
    fn from_wire(raw: Option<&str>, had_tool_calls: bool) -> Self {
        match raw {
            Some("stop") => Self::Stop,
            Some("tool_calls") | Some("function_call") => Self::ToolCalls,
            Some("length") | Some("max_tokens") => Self::Length,
            Some("content_filter") => Self::ContentFilter,
            Some(other) => Self::Other(other.to_owned()),
            // A provider that reports nothing: infer only the one thing that
            // is safe to infer, and never infer `Stop` over tool calls.
            None if had_tool_calls => Self::ToolCalls,
            None => Self::Stop,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
    /// Set on an `Assistant` message that is replaying tool calls back to the
    /// model as conversation history. Omitted from the wire when empty, so a
    /// request that uses no tools serialises exactly as it did before D-554.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// Set on a `Tool` message: which call this is the result of.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl ChatMessage {
    fn plain(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
        }
    }
    pub fn system(content: impl Into<String>) -> Self {
        Self::plain(Role::System, content)
    }
    pub fn user(content: impl Into<String>) -> Self {
        Self::plain(Role::User, content)
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::plain(Role::Assistant, content)
    }
    /// An assistant turn that asked for tools, replayed as history.
    pub fn assistant_tool_calls(content: impl Into<String>, tool_calls: Vec<ToolCall>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
            tool_calls,
            tool_call_id: None,
        }
    }
    /// A tool's result, answering `tool_call_id`.
    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: Some(tool_call_id.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire shapes. Private: the OpenAI-compatible envelope
// (`{"type":"function","function":{…}}`) is a serialisation detail, and the
// types above are what the rest of the workspace sees.
// ---------------------------------------------------------------------------

fn function_kind() -> String {
    "function".to_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireToolCall {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default = "function_kind")]
    kind: String,
    #[serde(default)]
    function: WireFunctionCall,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct WireFunctionCall {
    #[serde(default)]
    name: String,
    #[serde(default)]
    arguments: String,
}

impl From<WireToolCall> for ToolCall {
    fn from(w: WireToolCall) -> Self {
        Self {
            id: w.id,
            name: w.function.name,
            arguments: w.function.arguments,
        }
    }
}

impl From<ToolCall> for WireToolCall {
    fn from(t: ToolCall) -> Self {
        Self {
            id: t.id,
            kind: function_kind(),
            function: WireFunctionCall {
                name: t.name,
                arguments: t.arguments,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireToolDefinition {
    #[serde(rename = "type", default = "function_kind")]
    kind: String,
    function: WireFunctionDefinition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireFunctionDefinition {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    parameters: serde_json::Value,
}

impl From<WireToolDefinition> for ToolDefinition {
    fn from(w: WireToolDefinition) -> Self {
        Self {
            name: w.function.name,
            description: w.function.description,
            parameters: w.function.parameters,
        }
    }
}

impl From<ToolDefinition> for WireToolDefinition {
    fn from(t: ToolDefinition) -> Self {
        Self {
            kind: function_kind(),
            function: WireFunctionDefinition {
                name: t.name,
                description: t.description,
                parameters: t.parameters,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct GenerationRequest {
    pub messages: Vec<ChatMessage>,
    /// Tools offered this turn. Empty — the default — serialises to a request
    /// byte-identical to the pre-D-554 one, so nothing that does not use tools
    /// changes behaviour or starts sending a field its server may not know.
    pub tools: Vec<ToolDefinition>,
    /// Ignored by the wire when `tools` is empty.
    pub tool_choice: ToolChoice,
    /// Hard ceiling on output length. `None` takes
    /// `InferenceSection::max_output_tokens`, which is always set — an
    /// unbounded generation is a runaway loop with a latency budget nobody can
    /// set a timeout against.
    pub max_output_tokens: Option<u32>,
    /// 0.0 for the deterministic-ish behaviour every extraction and
    /// classification surface wants. Defaults low on purpose: a CRM field
    /// suggestion is not a creative writing task, and a confidently invented
    /// value in a customer record is the worst failure this platform has.
    pub temperature: f32,
}

impl GenerationRequest {
    pub fn new(messages: Vec<ChatMessage>) -> Self {
        Self {
            messages,
            tools: Vec::new(),
            tool_choice: ToolChoice::Auto,
            max_output_tokens: None,
            temperature: 0.2,
        }
    }

    /// Offers `tools` to the model for this turn.
    ///
    /// The list comes from `ActionRegistry::visible_to` and nowhere else; this
    /// crate neither builds nor filters it.
    pub fn with_tools(mut self, tools: Vec<ToolDefinition>) -> Self {
        self.tools = tools;
        self
    }

    pub fn with_tool_choice(mut self, choice: ToolChoice) -> Self {
        self.tool_choice = choice;
        self
    }

    /// The request's own wire size, in bytes (BIN-G2).
    ///
    /// Built from the **serialized** [`ChatRequest`] — the one shape that
    /// reaches the socket — rather than by hand-summing `content.len()`.
    /// `xrm_ai::budget_guard::estimate_tokens` counted only message content,
    /// so tool schemas and replayed `tool_calls` (re-sent on every step of a
    /// tool-using turn) were free, and a caller could sit under budget while
    /// sending an arbitrarily large body. A0.1 switches that estimate to this.
    ///
    /// **Bytes, not tokens.** The model's own tokenizer is not here, and a
    /// byte count is the honest pre-flight input: a character count divided by
    /// a nominal four under-counts Arabic, which this platform serves natively.
    ///
    /// `model` and `max_tokens` come from the caller because they live on the
    /// client, and the completion ceiling must be the one the request will
    /// actually run under — the caller's `max_output_tokens` never raises the
    /// deployment's.
    pub fn wire_bytes_estimate(&self, model: &str, max_tokens: u32) -> usize {
        let request = ChatRequest {
            model,
            messages: &self.messages,
            max_tokens,
            temperature: self.temperature,
            tools: &self.tools,
            tool_choice: (!self.tools.is_empty()).then_some(self.tool_choice),
            stream: false,
            stream_options: None,
        };
        match serde_json::to_vec(&request) {
            Ok(bytes) => bytes.len(),
            // Not reachable for this shape, but an estimate of zero would let a
            // request through unmetered. Fail to the refusal direction instead:
            // a budget that rejects one impossible request is harmless, one
            // that admits an unmetered request is not.
            Err(_) => usize::MAX,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GenerationResult {
    pub text: String,
    /// Provenance. `usage.model_id` rides onward to TODO-054's
    /// suggestion-outcome log, because "which model wrote this" is a question
    /// an auditor asks and one that cannot be reconstructed afterwards.
    pub usage: Usage,
    /// True when the model stopped because it hit the token ceiling rather
    /// than because it finished. A truncated suggestion presented as complete
    /// is worse than a refusal, so this is surfaced rather than inferred from
    /// a trailing character.
    ///
    /// Equivalent to `finish_reason == FinishReason::Length`; kept because
    /// every pre-D-554 caller reads it.
    pub truncated: bool,
    /// Tools the model asked for. Empty on an ordinary answer.
    pub tool_calls: Vec<ToolCall>,
    /// Why generation stopped, carried through rather than inferred.
    pub finish_reason: FinishReason,
}

impl GenerationResult {
    /// Whether this response is a usable proposal to act on.
    ///
    /// **`Length` with tool calls is not.** The last call is very likely
    /// truncated, and its `arguments` may still parse as JSON — an action run
    /// on half its inputs, with nothing that looks wrong. `xrm-ai` turns this
    /// into a `ModelFailure` terminal state and persists no proposal (D-554).
    pub fn tool_calls_are_usable(&self) -> bool {
        !self.tool_calls.is_empty() && self.finish_reason != FinishReason::Length
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    max_tokens: u32,
    temperature: f32,
    /// Omitted entirely when no tools are offered — see `GenerationRequest`.
    #[serde(skip_serializing_if = "<[ToolDefinition]>::is_empty")]
    tools: &'a [ToolDefinition],
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_choice: Option<ToolChoice>,
    /// Set only by [`GenerationClient::generate_stream`]. Omitted otherwise,
    /// so a non-streaming request stays byte-identical to what it was.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_options: Option<StreamOptions>,
}

/// Asks an OpenAI-compatible server to append a usage chunk to a stream, so a
/// streamed generation is metered like any other. A server that ignores it
/// reports no usage, and the caller's budget reservation stands as the charge.
#[derive(Serialize)]
struct StreamOptions {
    include_usage: bool,
}

#[derive(Deserialize)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<Choice>,
    #[serde(default)]
    usage: Option<ResponseUsage>,
}

#[derive(Deserialize)]
struct Choice {
    message: ResponseMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct ResponseMessage {
    /// Absent on a pure tool-call turn, which is why it defaults rather than
    /// failing the whole response.
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ToolCall>,
}

#[derive(Deserialize, Default)]
struct ResponseUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
    #[serde(default)]
    prompt_tokens_details: Option<PromptTokensDetails>,
}

#[derive(Deserialize, Default)]
struct PromptTokensDetails {
    #[serde(default)]
    cached_tokens: Option<u32>,
}

impl ResponseUsage {
    /// BIN-G3: `None` (no usage block) becomes an unreported [`Usage`].
    fn into_usage(usage: Option<Self>, model_id: &str) -> Usage {
        let reported = usage.is_some();
        let usage = usage.unwrap_or_default();
        Usage {
            model_id: model_id.to_owned(),
            // Tool definitions ride in the request body, so a provider's own
            // `prompt_tokens` already counts them; adding an estimate beside
            // a measurement would only invite the two to disagree.
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            reported,
            cached_prompt_tokens: usage.prompt_tokens_details.and_then(|d| d.cached_tokens),
        }
    }
}

/// Cheap to clone (BIN-FX1): the inner HTTP client is an `Arc`, so a
/// caller builds one per endpoint and clones it per turn, keeping the pooled
/// connection instead of a new TCP/TLS handshake every call.
#[derive(Clone)]
pub struct GenerationClient {
    transport: Transport,
    max_output_tokens: u32,
}

impl std::fmt::Debug for GenerationClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationClient")
            .field("max_output_tokens", &self.max_output_tokens)
            .finish_non_exhaustive()
    }
}

impl GenerationClient {
    pub fn new(section: &InferenceSection) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::new(
                section.generation.clone(),
                "generation",
                section.allow_external_provider,
            )?,
            max_output_tokens: section.max_output_tokens,
        })
    }

    /// A client for one explicit endpoint rather than `inference.generation`
    /// (D-571) — the endpoint a provider record describes.
    ///
    /// The caller builds `http` and owns the reachability decision: this does
    /// **not** consult `allow_external_provider`. That is deliberate and is the
    /// reason it is a separate constructor, not a parameter of
    /// [`GenerationClient::new`]: every existing caller of `new` keeps the
    /// deployment-wide gate it had, and only a caller that has made its own
    /// (per-provider, SSRF-screened) decision can reach this one.
    pub fn for_endpoint(
        endpoint: attome_config::InferenceEndpoint,
        max_output_tokens: u32,
        http: crate::DialClient,
    ) -> Result<Self, InferenceError> {
        Ok(Self {
            transport: Transport::with_client(http, endpoint, "generation")?,
            max_output_tokens,
        })
    }

    /// Z9-T2: a client over a transport an adapter set up (Azure's key
    /// header and `api-version`).
    pub(crate) fn from_transport(transport: Transport, max_output_tokens: u32) -> Self {
        Self {
            transport,
            max_output_tokens,
        }
    }

    pub fn model_id(&self) -> &str {
        self.transport.model()
    }

    pub async fn generate(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResult, InferenceError> {
        let started = std::time::Instant::now();
        let result = self.generate_once(request).await;
        crate::telemetry::record("generation", started, &result);
        result
    }

    async fn generate_once(
        &self,
        request: GenerationRequest,
    ) -> Result<GenerationResult, InferenceError> {
        // The caller's ceiling never raises the deployment's. A surface asking
        // for more than the operator budgeted gets the operator's number.
        let max_tokens = request
            .max_output_tokens
            .unwrap_or(self.max_output_tokens)
            .min(self.max_output_tokens);

        let response: ChatResponse = self
            .transport
            .post(
                CHAT_COMPLETIONS_PATH,
                &ChatRequest {
                    model: self.transport.model(),
                    messages: &request.messages,
                    max_tokens,
                    temperature: request.temperature,
                    tools: &request.tools,
                    tool_choice: (!request.tools.is_empty()).then_some(request.tool_choice),
                    stream: false,
                    stream_options: None,
                },
            )
            .await?;

        let choice = response
            .choices
            .into_iter()
            .next()
            .ok_or(InferenceError::BadResponse {
                endpoint: self.transport.label(),
                reason: "response carried no choices",
            })?;

        let usage = ResponseUsage::into_usage(response.usage, self.transport.model());
        let tool_calls = choice.message.tool_calls;
        let finish_reason =
            FinishReason::from_wire(choice.finish_reason.as_deref(), !tool_calls.is_empty());
        Ok(GenerationResult {
            truncated: finish_reason == FinishReason::Length,
            text: choice.message.content.unwrap_or_default(),
            tool_calls,
            finish_reason,
            usage,
        })
    }
}

// ---------------------------------------------------------------------------
// Streaming (C11 B3, P-3)
// ---------------------------------------------------------------------------

/// The longest silence tolerated between two chunks of a streamed response,
/// capped by the endpoint's whole-request timeout. A model server that stops
/// sending mid-answer is a failure, not a slow answer: the caller gets a
/// timeout rather than a turn that hangs until the whole-request bound.
pub const STREAM_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The most tool calls one streamed turn may carry (BIN-F1, row G-14).
///
/// A server-controlled `index` used to drive `Vec::resize_with(at + 1)`
/// directly: `usize::MAX` panicked on the overflow and a large-but-plausible
/// index aborted the process with an allocation failure, taking every
/// in-flight request on the node with it. An index at or beyond this cap is
/// refused instead — the same direction every other bound here takes.
pub const MAX_TOOL_CALLS: usize = 128;

/// The longest single SSE line the assembler will hold. A server that never
/// sends a newline must not be able to grow the line buffer without bound.
pub const MAX_SSE_LINE_BYTES: usize = 1024 * 1024;

/// Bytes of decoded text tolerated per allowed output token.
///
/// The whole assembled text is bounded by `max_output_tokens × this`. A token
/// decodes to at most a few bytes in any real vocabulary, so 16 is generous;
/// a server that exceeds it is not running the model it claims to.
pub const BYTES_PER_OUTPUT_TOKEN: usize = 16;

impl GenerationClient {
    /// [`GenerationClient::generate`], streamed.
    ///
    /// Text arrives at `on_delta` as the model produces it. Tool calls are
    /// **accumulated** from their fragments and never passed to `on_delta` —
    /// a half-received call is not something a caller may show or act on —
    /// and the returned [`GenerationResult`] is exactly what the non-streaming
    /// call returns for the same response, so nothing after a model step has
    /// to know it was streamed.
    ///
    /// **A stream that ends before the model said why it stopped is an
    /// error**, never a result: a connection dropped half-way through a tool
    /// call's arguments must not become a call whose arguments happen to
    /// parse. That is row A-06's rule, for a stream (A-83).
    ///
    /// `cancel` resolves when the caller wants the generation stopped (a user
    /// pressing Stop). The request is dropped at once and
    /// [`InferenceError::Cancelled`] returned. A caller that never cancels
    /// passes `std::future::pending()`.
    ///
    /// Usage is requested with `stream_options.include_usage`; a server that
    /// ignores it reports none, which the budget treats as "keep the estimate"
    /// rather than as free.
    pub async fn generate_stream<F, C>(
        &self,
        request: GenerationRequest,
        on_delta: F,
        cancel: C,
    ) -> Result<GenerationResult, InferenceError>
    where
        F: FnMut(&str) + Send,
        C: std::future::Future<Output = ()> + Send,
    {
        let started = std::time::Instant::now();
        let result = self.stream_once(request, on_delta, cancel).await;
        crate::telemetry::record("generation", started, &result);
        result
    }

    async fn stream_once<F, C>(
        &self,
        request: GenerationRequest,
        mut on_delta: F,
        cancel: C,
    ) -> Result<GenerationResult, InferenceError>
    where
        F: FnMut(&str) + Send,
        C: std::future::Future<Output = ()> + Send,
    {
        let label = self.transport.label();
        let max_tokens = request
            .max_output_tokens
            .unwrap_or(self.max_output_tokens)
            .min(self.max_output_tokens);
        let body = ChatRequest {
            model: self.transport.model(),
            messages: &request.messages,
            max_tokens,
            temperature: request.temperature,
            tools: &request.tools,
            tool_choice: (!request.tools.is_empty()).then_some(request.tool_choice),
            stream: true,
            stream_options: Some(StreamOptions {
                include_usage: true,
            }),
        };
        let idle = STREAM_IDLE_TIMEOUT.min(self.transport.request_timeout());

        let mut cancel = std::pin::pin!(cancel);
        let mut response = tokio::select! {
            biased;
            _ = &mut cancel => return Err(InferenceError::Cancelled(label)),
            response = self.transport.post_streaming(CHAT_COMPLETIONS_PATH, &body) => response?,
        };

        let mut assembler = StreamAssembler::new(max_tokens);
        loop {
            let chunk = tokio::select! {
                biased;
                _ = &mut cancel => return Err(InferenceError::Cancelled(label)),
                chunk = tokio::time::timeout(idle, response.chunk()) => chunk,
            };
            let chunk = match chunk {
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
            assembler.push(&chunk, &mut on_delta).map_err(|reason| {
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

/// One call being reassembled from its fragments, by position.
#[derive(Default)]
struct PartialCall {
    id: String,
    name: String,
    arguments: String,
}

/// Reassembles an OpenAI-compatible server-sent-event stream into the
/// [`GenerationResult`] a non-streaming call would have returned.
///
/// Pure bytes in, deltas and a result out — so every framing rule is testable
/// without a socket. Lines may be split anywhere, including inside a UTF-8
/// sequence, which is why the buffer is bytes.
pub(crate) struct StreamAssembler {
    buffer: Vec<u8>,
    text: String,
    calls: Vec<PartialCall>,
    finish_reason: Option<String>,
    usage: Option<ResponseUsage>,
    /// The server sent `data: [DONE]`.
    done: bool,
    /// Cap on `text`, derived from the request's own `max_output_tokens`.
    max_text_bytes: usize,
    /// Everything fed so far. A stream is one response, so it never gets more
    /// room than one response body.
    received: usize,
    /// How many bytes at the front of `buffer` have already been searched for
    /// a newline. Keeps the framing scan linear in the bytes received rather
    /// than quadratic in the length of a line.
    scanned: usize,
}

impl Default for StreamAssembler {
    /// No `max_output_tokens` to derive a text cap from: fall back to the
    /// whole-response bound, so an assembler built without one still cannot
    /// hold more than the transport would have accepted.
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            text: String::new(),
            calls: Vec::new(),
            finish_reason: None,
            usage: None,
            done: false,
            max_text_bytes: crate::MAX_BODY_BYTES,
            received: 0,
            scanned: 0,
        }
    }
}

#[derive(Deserialize)]
struct StreamChunk {
    #[serde(default)]
    choices: Vec<StreamChoice>,
    #[serde(default)]
    usage: Option<ResponseUsage>,
}

#[derive(Deserialize)]
struct StreamChoice {
    #[serde(default)]
    index: usize,
    #[serde(default)]
    delta: StreamDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Deserialize, Default)]
struct StreamDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<DeltaToolCall>,
}

#[derive(Deserialize)]
struct DeltaToolCall {
    #[serde(default)]
    index: Option<usize>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<DeltaFunction>,
}

#[derive(Deserialize)]
struct DeltaFunction {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    arguments: Option<String>,
}

impl StreamAssembler {
    /// An assembler whose text cap is the request's own `max_output_tokens`
    /// times [`BYTES_PER_OUTPUT_TOKEN`].
    pub(crate) fn new(max_output_tokens: u32) -> Self {
        Self {
            max_text_bytes: (max_output_tokens as usize).saturating_mul(BYTES_PER_OUTPUT_TOKEN),
            ..Self::default()
        }
    }

    /// Feeds raw bytes. Every complete `data:` line is applied; text content
    /// goes to `on_delta` as it is applied.
    ///
    /// Every dimension a server controls is bounded here (BIN-F1, row G-14):
    /// the whole stream by one response body, a single line by
    /// [`MAX_SSE_LINE_BYTES`], a tool-call position by [`MAX_TOOL_CALLS`], and
    /// the assembled text by the request's own output ceiling. None of them
    /// panics, aborts or resizes to a server-chosen length.
    pub(crate) fn push(
        &mut self,
        bytes: &[u8],
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(), &'static str> {
        self.received = self.received.saturating_add(bytes.len());
        if self.received > crate::MAX_BODY_BYTES {
            return Err("the stream exceeded the response size cap");
        }
        self.buffer.extend_from_slice(bytes);
        // `self.scanned` bytes at the front have already been searched for a
        // newline, so the search resumes where it stopped: each byte is
        // scanned once whatever the chunking. The line itself still starts at
        // `line_start`, which is where the last complete line ended.
        let mut line_start = 0;
        let mut search_from = self.scanned;
        while let Some(relative) = self.buffer[search_from..].iter().position(|b| *b == b'\n') {
            let end = search_from + relative;
            if end + 1 - line_start > MAX_SSE_LINE_BYTES {
                return Err("a stream line exceeded the line cap");
            }
            let line = self.buffer[line_start..=end].to_vec();
            line_start = end + 1;
            search_from = end + 1;
            let line = std::str::from_utf8(&line).map_err(|_| "a stream line was not UTF-8")?;
            let line = line.trim_end_matches(['\n', '\r']);
            // Comments (`: keep-alive`), `event:` and `id:` lines, and the
            // blank line ending each event carry nothing for us.
            let Some(payload) = line.strip_prefix("data:") else {
                continue;
            };
            let payload = payload.trim();
            if payload == "[DONE]" {
                self.done = true;
                continue;
            }
            if payload.is_empty() {
                continue;
            }
            let chunk: StreamChunk =
                serde_json::from_str(payload).map_err(|_| "a stream chunk was not valid JSON")?;
            self.apply(chunk, on_delta)?;
        }
        // Drop the consumed prefix once, then remember that everything left
        // has been searched. This is what keeps the framing scan linear in the
        // bytes received rather than quadratic in the length of a line.
        if line_start > 0 {
            self.buffer.drain(..line_start);
        }
        self.scanned = self.buffer.len();
        if self.buffer.len() > MAX_SSE_LINE_BYTES {
            return Err("a stream line exceeded the line cap");
        }
        Ok(())
    }

    fn apply(
        &mut self,
        chunk: StreamChunk,
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(), &'static str> {
        if let Some(usage) = chunk.usage {
            self.usage = Some(usage);
        }
        // One completion was asked for; any other choice is ignored, exactly
        // as the non-streaming path takes the first.
        for choice in chunk.choices.into_iter().filter(|c| c.index == 0) {
            if let Some(content) = choice.delta.content.filter(|c| !c.is_empty()) {
                if self.text.len() + content.len() > self.max_text_bytes {
                    return Err("the streamed text exceeded the output cap");
                }
                self.text.push_str(&content);
                on_delta(&content);
            }
            for fragment in choice.delta.tool_calls {
                let at = fragment.index.unwrap_or(0);
                // BIN-F1/row G-14: refuse, never resize to, a position the
                // server chose.
                if at >= MAX_TOOL_CALLS {
                    return Err("a tool-call index exceeded the cap");
                }
                if self.calls.len() <= at {
                    self.calls.resize_with(at + 1, PartialCall::default);
                }
                let call = &mut self.calls[at];
                if let Some(id) = fragment.id.filter(|id| !id.is_empty()) {
                    call.id = id;
                }
                if let Some(function) = fragment.function {
                    if let Some(name) = function.name {
                        call.name.push_str(&name);
                    }
                    if let Some(arguments) = function.arguments {
                        call.arguments.push_str(&arguments);
                    }
                }
            }
            if let Some(reason) = choice.finish_reason {
                self.finish_reason = Some(reason);
            }
        }
        Ok(())
    }

    /// The result, or why there is none. A stream with no `finish_reason` was
    /// cut short, whatever it carried.
    pub(crate) fn finish(self, model_id: &str) -> Result<GenerationResult, &'static str> {
        let Some(reason) = self.finish_reason else {
            return Err("the stream ended before the model finished");
        };
        let tool_calls: Vec<ToolCall> = self
            .calls
            .into_iter()
            .map(|c| ToolCall {
                id: c.id,
                name: c.name,
                arguments: c.arguments,
            })
            .collect();
        let finish_reason = FinishReason::from_wire(Some(&reason), !tool_calls.is_empty());
        let usage = ResponseUsage::into_usage(self.usage, model_id);
        Ok(GenerationResult {
            truncated: finish_reason == FinishReason::Length,
            text: self.text,
            tool_calls,
            finish_reason,
            usage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- C11 B3: the stream assembler ------------------------------------

    fn sse(chunks: &[serde_json::Value]) -> String {
        let mut out = String::new();
        for chunk in chunks {
            out.push_str(&format!("data: {chunk}\n\n"));
        }
        out
    }

    fn assemble(
        bytes: &[u8],
        split: usize,
    ) -> (Vec<String>, Result<GenerationResult, &'static str>) {
        let mut deltas = Vec::new();
        let mut assembler = StreamAssembler::default();
        let mut on_delta = |d: &str| deltas.push(d.to_owned());
        for piece in bytes.chunks(split.max(1)) {
            assembler.push(piece, &mut on_delta).expect("valid stream");
        }
        let result = assembler.finish("m");
        (deltas, result)
    }

    /// Text streams as deltas, and the result is what a non-streaming call
    /// would have returned — whatever the network's chunk boundaries were,
    /// including inside a multi-byte character.
    #[test]
    fn a_streamed_answer_assembles_whatever_the_chunking() {
        let body = sse(&[
            serde_json::json!({"choices":[{"index":0,"delta":{"content":"مرحبا "}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{"content":"world"}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
            serde_json::json!({"choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}),
        ]) + "data: [DONE]\n\n";
        for split in [1, 2, 3, 7, 64, 4096] {
            let (deltas, result) = assemble(body.as_bytes(), split);
            let result = result.expect("finished");
            assert_eq!(deltas.concat(), "مرحبا world", "split {split}");
            assert_eq!(result.text, "مرحبا world");
            assert_eq!(result.finish_reason, FinishReason::Stop);
            assert_eq!(result.usage.prompt_tokens, 7);
            assert_eq!(result.usage.completion_tokens, 3);
        }
    }

    /// Tool calls are reassembled from fragments and never surface as a
    /// delta: only text does.
    #[test]
    fn tool_call_fragments_reassemble_and_never_reach_the_delta_sink() {
        let body = sse(&[
            serde_json::json!({"choices":[{"index":0,"delta":{"content":"Checking."}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"record.get","arguments":""}}]}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"id\":"}}]}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"c2","function":{"name":"search.records","arguments":"{}"}}]}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"7}"}}]}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
        ]) + "data: [DONE]\n\n";
        let (deltas, result) = assemble(body.as_bytes(), 5);
        let result = result.expect("finished");
        assert_eq!(deltas, vec!["Checking.".to_owned()]);
        assert_eq!(result.tool_calls.len(), 2);
        assert_eq!(result.tool_calls[0].id, "c1");
        assert_eq!(result.tool_calls[0].name, "record.get");
        assert_eq!(result.tool_calls[0].arguments, r#"{"id":7}"#);
        assert_eq!(result.tool_calls[1].name, "search.records");
        assert_eq!(result.finish_reason, FinishReason::ToolCalls);
        assert_eq!(
            result.usage.prompt_tokens, 0,
            "no usage reported stays zero"
        );
    }

    /// **Row A-83.** A stream cut off mid-way through a tool call's arguments
    /// — or anywhere before the model said why it stopped — is an error, even
    /// when what arrived happens to parse.
    #[test]
    fn a_stream_without_a_finish_reason_is_not_a_result() {
        let body = sse(&[
            serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"record.delete","arguments":"{}"}}]}}]}),
        ]);
        let (_, result) = assemble(body.as_bytes(), 16);
        assert!(
            result.is_err(),
            "a truncated stream must never become a call"
        );
        let body = "data: [DONE]\n\n";
        let (_, result) = assemble(body.as_bytes(), 16);
        assert!(result.is_err(), "[DONE] alone is not a finish");
    }

    /// `length` with a tool call stays `Length`, so `xrm-ai` refuses it
    /// exactly as it refuses the non-streaming shape (A-06).
    #[test]
    fn a_streamed_truncation_is_reported_as_length() {
        let body = sse(&[
            serde_json::json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"record.update","arguments":"{\"a\":1}"}}]}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}),
        ]);
        let (_, result) = assemble(body.as_bytes(), 9);
        let result = result.expect("finished");
        assert_eq!(result.finish_reason, FinishReason::Length);
        assert!(!result.tool_calls_are_usable());
    }

    /// Keep-alive comments, `event:` lines and CRLF framing are tolerated;
    /// a chunk that is not JSON is refused rather than skipped.
    #[test]
    fn framing_noise_is_ignored_and_garbage_is_refused() {
        let body = ": keep-alive\r\nevent: message\r\ndata: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\r\n\r\n";
        let (deltas, result) = assemble(body.as_bytes(), 4);
        assert_eq!(deltas, vec!["ok".to_owned()]);
        assert!(result.is_ok());

        let mut assembler = StreamAssembler::default();
        let mut sink = |_: &str| {};
        assert!(assembler.push(b"data: {not json}\n", &mut sink).is_err());
    }

    /// A streamed request asks for a stream and for usage; nothing else about
    /// the request changes.
    #[test]
    fn a_streamed_request_asks_for_usage() {
        let request = ChatRequest {
            model: "m",
            messages: &[ChatMessage::user("hi")],
            max_tokens: 10,
            temperature: 0.2,
            tools: &[],
            tool_choice: None,
            stream: true,
            stream_options: Some(StreamOptions {
                include_usage: true,
            }),
        };
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["stream"], true);
        assert_eq!(wire["stream_options"]["include_usage"], true);
    }

    #[test]
    fn roles_serialize_to_the_wire_names_the_servers_expect() {
        assert_eq!(serde_json::to_string(&Role::System).unwrap(), "\"system\"");
        assert_eq!(serde_json::to_string(&Role::User).unwrap(), "\"user\"");
        assert_eq!(
            serde_json::to_string(&Role::Assistant).unwrap(),
            "\"assistant\""
        );
    }

    /// D-554: `Tool` is on the wire as `"tool"`, which is what an
    /// OpenAI-compatible server expects for a tool-result message.
    #[test]
    fn the_tool_role_serializes_to_the_wire_name() {
        assert_eq!(serde_json::to_string(&Role::Tool).unwrap(), "\"tool\"");
    }

    /// **The regression that matters most for compatibility.** A request that
    /// offers no tools must serialise exactly as it did before D-554 — no
    /// `tools` key, no `tool_choice` key, no empty arrays. A server that does
    /// not understand them must never see them.
    #[test]
    fn a_request_without_tools_carries_no_tool_fields() {
        let request = ChatRequest {
            model: "m",
            messages: &[ChatMessage::user("hi")],
            max_tokens: 10,
            temperature: 0.2,
            tools: &[],
            tool_choice: None,
            stream: false,
            stream_options: None,
        };
        let wire = serde_json::to_value(&request).unwrap();
        assert!(
            wire.get("stream").is_none(),
            "a plain request is not a stream"
        );
        assert!(wire.get("tools").is_none(), "empty tools must not be sent");
        assert!(wire.get("tool_choice").is_none());
        let message = &wire["messages"][0];
        assert!(
            message.get("tool_calls").is_none() && message.get("tool_call_id").is_none(),
            "a plain message must not grow tool fields"
        );
    }

    /// A tool definition goes out in the `{"type":"function","function":{…}}`
    /// envelope both serving paths speak.
    #[test]
    fn a_tool_definition_serializes_into_the_function_envelope() {
        let tool = ToolDefinition {
            name: "record.get".into(),
            description: "Fetch one record by id.".into(),
            parameters: serde_json::json!({"type": "object", "properties": {}}),
        };
        let wire = serde_json::to_value(&tool).unwrap();
        assert_eq!(wire["type"], "function");
        assert_eq!(wire["function"]["name"], "record.get");
        assert_eq!(wire["function"]["parameters"]["type"], "object");
    }

    /// **The boundary test (D-554).** A tool name round-trips as an opaque
    /// string — dots intact, no sanitisation, no transformation. `xrm-ai`
    /// resolves it against the closed registry, and that guarantee is
    /// strongest when nothing here rewrites it.
    #[test]
    fn a_tool_name_is_carried_verbatim() {
        let response: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"tool_calls":[
                 {"id":"call_1","type":"function",
                  "function":{"name":"record.update_field","arguments":"{\"a\":1}"}}]},
               "finish_reason":"tool_calls"}]}"#,
        )
        .unwrap();
        let call = &response.choices[0].message.tool_calls[0];
        assert_eq!(call.name, "record.update_field");
        assert_eq!(call.id, "call_1");
        assert_eq!(call.arguments, r#"{"a":1}"#);
    }

    /// Arguments are handed on **unparsed**. Parsing here would turn a model's
    /// malformed output into a transport error and collapse `InvalidToolCall`
    /// into `ModelFailure` — two outcomes `xrm-ai` must tell apart.
    #[test]
    fn malformed_arguments_are_carried_not_rejected() {
        let response: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"tool_calls":[
                 {"id":"c","type":"function","function":{"name":"n","arguments":"{oops"}}]}}]}"#,
        )
        .unwrap();
        assert_eq!(response.choices[0].message.tool_calls[0].arguments, "{oops");
    }

    /// Parallel tool calls in one turn are ordinary and must all survive.
    #[test]
    fn parallel_tool_calls_all_survive() {
        let response: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"tool_calls":[
                 {"id":"a","type":"function","function":{"name":"x","arguments":"{}"}},
                 {"id":"b","type":"function","function":{"name":"y","arguments":"{}"}}]},
               "finish_reason":"tool_calls"}]}"#,
        )
        .unwrap();
        let ids: Vec<_> = response.choices[0]
            .message
            .tool_calls
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        assert_eq!(ids, ["a", "b"]);
    }

    /// A pure tool-call turn carries no `content`. It must deserialize, not
    /// fail the whole response.
    #[test]
    fn a_response_with_no_content_still_deserializes() {
        let response: ChatResponse =
            serde_json::from_str(r#"{"choices":[{"message":{}}]}"#).unwrap();
        assert!(response.choices[0].message.content.is_none());
    }

    /// BIN-G3: a usage block (with cached tokens) is `reported`; none is not.
    #[test]
    fn usage_distinguishes_unreported_from_zero_and_reads_cached_tokens() {
        let with: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{}}],"usage":{"prompt_tokens":10,
                "completion_tokens":2,"prompt_tokens_details":{"cached_tokens":6}}}"#,
        )
        .unwrap();
        let usage = ResponseUsage::into_usage(with.usage, "m");
        assert!(usage.reported);
        assert_eq!(
            (usage.prompt_tokens, usage.cached_prompt_tokens),
            (10, Some(6))
        );

        let zero: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{}}],"usage":{"prompt_tokens":0,"completion_tokens":0}}"#,
        )
        .unwrap();
        let usage = ResponseUsage::into_usage(zero.usage, "m");
        assert!(usage.reported, "a reported zero is still reported");
        assert_eq!(usage.cached_prompt_tokens, None);

        let without: ChatResponse =
            serde_json::from_str(r#"{"choices":[{"message":{}}]}"#).unwrap();
        let usage = ResponseUsage::into_usage(without.usage, "m");
        assert!(!usage.reported);
        assert_eq!((usage.prompt_tokens, usage.completion_tokens), (0, 0));
    }

    /// **Row A-06.** `Length` alongside tool calls is never usable: the last
    /// call is very likely truncated and its arguments may still parse, which
    /// would run an action on half its inputs with nothing looking wrong.
    #[test]
    fn length_with_tool_calls_is_never_usable() {
        let truncated = GenerationResult {
            text: String::new(),
            usage: Usage {
                model_id: "m".into(),
                prompt_tokens: 1,
                completion_tokens: 1,
                reported: true,
                cached_prompt_tokens: None,
            },
            truncated: true,
            tool_calls: vec![ToolCall {
                id: "c".into(),
                name: "record.create".into(),
                arguments: r#"{"entity":"acc"#.into(),
            }],
            finish_reason: FinishReason::Length,
        };
        assert!(
            !truncated.tool_calls_are_usable(),
            "a truncated tool call must never be dispatched"
        );

        let complete = GenerationResult {
            finish_reason: FinishReason::ToolCalls,
            truncated: false,
            ..truncated
        };
        assert!(complete.tool_calls_are_usable());
    }

    /// `finish_reason` is mapped, never guessed — and a provider that omits it
    /// while returning tool calls must not be read as a finished answer.
    #[test]
    fn finish_reasons_map_and_never_infer_stop_over_tool_calls() {
        assert_eq!(
            FinishReason::from_wire(Some("stop"), false),
            FinishReason::Stop
        );
        assert_eq!(
            FinishReason::from_wire(Some("tool_calls"), true),
            FinishReason::ToolCalls
        );
        assert_eq!(
            FinishReason::from_wire(Some("length"), false),
            FinishReason::Length
        );
        assert_eq!(
            FinishReason::from_wire(Some("content_filter"), false),
            FinishReason::ContentFilter
        );
        assert_eq!(
            FinishReason::from_wire(Some("weird"), false),
            FinishReason::Other("weird".into())
        );
        assert_eq!(FinishReason::from_wire(None, true), FinishReason::ToolCalls);
        assert_eq!(FinishReason::from_wire(None, false), FinishReason::Stop);
    }

    /// A structurally invalid tool call — no id, no name — deserializes to
    /// empty strings rather than failing the response, so `xrm-ai` can refuse
    /// it as `ProtocolError` with the rest of the turn intact.
    #[test]
    fn a_structurally_invalid_tool_call_survives_as_empty() {
        let response: ChatResponse = serde_json::from_str(
            r#"{"choices":[{"message":{"tool_calls":[{"type":"function"}]}}]}"#,
        )
        .unwrap();
        let call = &response.choices[0].message.tool_calls[0];
        assert!(call.id.is_empty() && call.name.is_empty());
    }

    /// Tool-result and assistant-with-calls messages serialise into the shape
    /// the model needs to pair a result to its request.
    #[test]
    fn history_messages_carry_their_pairing_fields() {
        let result = ChatMessage::tool_result("call_1", "42");
        let wire = serde_json::to_value(&result).unwrap();
        assert_eq!(wire["role"], "tool");
        assert_eq!(wire["tool_call_id"], "call_1");

        let asked = ChatMessage::assistant_tool_calls(
            "",
            vec![ToolCall {
                id: "call_1".into(),
                name: "record.get".into(),
                arguments: "{}".into(),
            }],
        );
        let wire = serde_json::to_value(&asked).unwrap();
        assert_eq!(wire["tool_calls"][0]["id"], "call_1");
        assert_eq!(wire["tool_calls"][0]["function"]["name"], "record.get");
    }

    /// A CRM field suggestion is not a creative task. If this default ever
    /// drifts upward, invented values start appearing in customer records.
    #[test]
    fn the_default_temperature_is_low() {
        let request = GenerationRequest::new(vec![ChatMessage::user("hi")]);
        assert!(
            request.temperature <= 0.3,
            "generation into customer records must default to near-deterministic"
        );
        assert!(
            request.max_output_tokens.is_none(),
            "the deployment's ceiling is the default, not a per-call guess"
        );
    }

    /// **BIN-P1 (finding BIN-F1, row G-14).** A tool-call fragment's `index` is
    /// server-controlled, and it drives the assembler's `Vec::resize_with(at + 1)`
    /// directly: `usize::MAX` panics on the `at + 1` overflow and
    /// `usize::MAX / 2` aborts the process on the allocation (every in-flight
    /// request on the node dies with it). Phase 0 asserts the refusal; today
    /// this test fails by panicking, which *is* the finding.
    ///
    /// Deliberately only these two values: anything between ~10^7 and ~10^13
    /// would actually allocate hundreds of megabytes on a shared machine.
    #[test]
    fn a_tool_call_index_beyond_the_cap_is_refused() {
        for at in [usize::MAX, usize::MAX / 2] {
            let mut assembler = StreamAssembler::default();
            let mut sink = |_: &str| {};
            let line = format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":                 [{{\"index\":{at},\"id\":\"c\",\"function\":{{\"name\":\"n\",                 \"arguments\":\"{{}}\"}}}}]}}}}]}}\n"
            );
            assert!(
                assembler.push(line.as_bytes(), &mut sink).is_err(),
                "a tool-call index of {at} must be refused, never resized to"
            );
        }
    }

    /// **BIN-G2.** The estimate is the serialized `ChatRequest`, so tool
    /// schemas and replayed tool history are counted rather than free. A0.1
    /// switches `estimate_tokens` to this number.
    #[test]
    fn the_wire_estimate_is_the_serialized_request() {
        let tools: Vec<ToolDefinition> = (0..20)
            .map(|index| ToolDefinition {
                name: format!("record.action_{index}"),
                description: "Do a thing with a record, described at length.".into(),
                parameters: serde_json::json!({
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"]
                }),
            })
            .collect();
        let request = GenerationRequest::new(vec![ChatMessage::user("hi")]).with_tools(tools);

        let expected = serde_json::to_vec(&ChatRequest {
            model: "m",
            messages: &request.messages,
            max_tokens: 2_048,
            temperature: request.temperature,
            tools: &request.tools,
            tool_choice: Some(ToolChoice::Auto),
            stream: false,
            stream_options: None,
        })
        .unwrap()
        .len();
        assert_eq!(request.wire_bytes_estimate("m", 2_048), expected);

        // Twenty tool definitions are counted, not ignored: a no-tools request
        // of the same messages is far smaller.
        let bare = GenerationRequest::new(vec![ChatMessage::user("hi")]);
        assert!(
            request.wire_bytes_estimate("m", 2_048) > bare.wire_bytes_estimate("m", 2_048) + 1_000
        );
    }

    /// A request without tools is its own content plus a small envelope — the
    /// estimate must not have grown by a fixed, unmetered lump.
    #[test]
    fn a_request_without_tools_estimates_close_to_its_content() {
        let content = "x".repeat(1_000);
        let request = GenerationRequest::new(vec![ChatMessage::user(content.clone())]);
        let estimate = request.wire_bytes_estimate("m", 16);
        assert!(estimate >= content.len(), "{estimate} < {}", content.len());
        assert!(
            estimate < content.len() + 256,
            "the envelope is {} bytes, which is no longer an envelope",
            estimate - content.len()
        );
    }

    /// The replay of a tool call and its result — which every later step of a
    /// tool-using turn re-sends — is counted too.
    #[test]
    fn replayed_tool_calls_and_results_are_counted() {
        let with_history = GenerationRequest::new(vec![
            ChatMessage::assistant_tool_calls(
                "",
                vec![ToolCall {
                    id: "c1".into(),
                    name: "record.get".into(),
                    arguments: r#"{"id":7}"#.into(),
                }],
            ),
            ChatMessage::tool_result("c1", "the record body, which is long"),
        ]);
        let bare = GenerationRequest::new(vec![
            ChatMessage::assistant(""),
            ChatMessage::tool_result("c1", ""),
        ]);
        assert!(
            with_history.wire_bytes_estimate("m", 16) > bare.wire_bytes_estimate("m", 16),
            "tool history must not be free"
        );
    }

    fn tool_call_line(at: usize) -> String {
        format!(
            "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":{at},\"id\":\"c\",\"function\":{{\"name\":\"n\",\"arguments\":\"{{}}\"}}}}]}}}}]}}\n"
        )
    }

    /// The cap is a boundary, not an approximation: the last legal slot still
    /// works and the first illegal one is refused (BIN-A2).
    #[test]
    fn a_tool_call_index_at_the_cap_is_refused_and_below_it_is_not() {
        let mut sink = |_: &str| {};
        let mut allowed = StreamAssembler::default();
        allowed
            .push(tool_call_line(MAX_TOOL_CALLS - 1).as_bytes(), &mut sink)
            .expect("the last legal index must still be usable");
        let mut refused = StreamAssembler::default();
        assert!(
            refused
                .push(tool_call_line(MAX_TOOL_CALLS).as_bytes(), &mut sink)
                .is_err(),
            "an index at MAX_TOOL_CALLS must be refused"
        );
    }

    /// A server that never sends a newline must not be able to grow the line
    /// buffer without bound (BIN-A2).
    #[test]
    fn a_line_longer_than_the_cap_is_refused() {
        let mut assembler = StreamAssembler::default();
        let mut sink = |_: &str| {};
        let line = vec![b'a'; 2 * 1024 * 1024];
        for chunk in line.chunks(64 * 1024) {
            if assembler.push(chunk, &mut sink).is_err() {
                return;
            }
        }
        panic!("a 2 MiB line without a newline must be refused");
    }

    /// The assembled text is bounded by the request's own output ceiling
    /// (BIN-A2): one allowed token tolerates 16 bytes, not one more.
    #[test]
    fn streamed_text_beyond_the_output_cap_is_refused() {
        let mut assembler = StreamAssembler::new(1);
        let mut sink = |_: &str| {};
        let exactly =
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"0123456789abcdef\"}}]}\n";
        assembler
            .push(exactly.as_bytes(), &mut sink)
            .expect("exactly the cap must fit");
        let over = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"x\"}}]}\n";
        assert!(
            assembler.push(over.as_bytes(), &mut sink).is_err(),
            "one byte past the output cap must be refused"
        );
    }

    /// A long answer delivered in the worst possible chunking — one byte at a
    /// time — still assembles, and the framing scan stays linear (BIN-A2).
    #[test]
    fn a_large_stream_fed_one_byte_at_a_time_still_assembles() {
        let mut body = String::new();
        let mut remaining = 200_000usize;
        while remaining > 0 {
            let take = remaining.min(1_000);
            remaining -= take;
            body.push_str(&format!(
                "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"{}\"}}}}]}}\n\n",
                "x".repeat(take)
            ));
        }
        body.push_str(
            "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
        );

        let mut deltas: Vec<String> = Vec::new();
        let mut assembler = StreamAssembler::default();
        {
            let mut sink = |delta: &str| deltas.push(delta.to_owned());
            for byte in body.as_bytes() {
                assembler
                    .push(std::slice::from_ref(byte), &mut sink)
                    .expect("a valid stream must assemble whatever the chunking");
            }
        }
        let result = assembler.finish("m").expect("finished");
        assert_eq!(result.text.len(), 200_000);
        assert_eq!(deltas.concat().len(), 200_000);
    }

    /// **BIN-G4.** Arbitrary bytes, in arbitrary chunkings, are never a panic:
    /// whatever a server sends, the answer is a delta, a result, or one of the
    /// fixed `Err` strings. The first half pins split-equivalence — the same
    /// stream cut at any boundary produces the same result.
    #[test]
    fn the_assembler_never_panics_on_arbitrary_input() {
        let valid = sse(&[
            serde_json::json!({"choices":[{"index":0,"delta":{"content":"hello "}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{"content":"world"}}]}),
            serde_json::json!({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}),
        ]) + "data: [DONE]\n\n";
        let baseline = assemble(valid.as_bytes(), 4096).1.expect("baseline");
        for split in 1..=64 {
            let (deltas, result) = assemble(valid.as_bytes(), split);
            let result = result.expect("every split assembles");
            assert_eq!(result.text, baseline.text, "split {split}");
            assert_eq!(deltas.concat(), "hello world", "split {split}");
        }

        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % 4_096
        };
        for case in 0..2_000 {
            let len = next() as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| (next() % 256) as u8).collect();
            // Half the cases look like SSE, so the framing and JSON paths are
            // actually reached rather than short-circuiting immediately.
            if case % 2 == 0 && bytes.len() >= 6 {
                bytes[..6].copy_from_slice(b"data: ");
            }
            let mut assembler = StreamAssembler::default();
            let mut sink = |_: &str| {};
            let mut offset = 0;
            while offset < bytes.len() {
                let step = (next() as usize % 64).max(1);
                let end = (offset + step).min(bytes.len());
                // The contract is Ok or Err, never a panic and never an
                // unbounded allocation.
                let _ = assembler.push(&bytes[offset..end], &mut sink);
                offset = end;
            }
            let _ = assembler.finish("m");
        }
    }
}
