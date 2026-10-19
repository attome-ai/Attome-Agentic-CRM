//! The platform's single model-transport crate (D-360, invariant I-11).
//!
//! **What belongs here:** HTTP to a model server, batching, timeouts, retries,
//! token accounting, model identity. That is the whole list.
//!
//! **What does not:** prompts, templates, conversation state, security
//! contexts, entity or record knowledge, and — most importantly — any notion
//! of *trusted* versus *untrusted* text. This crate has zero `xrm-*`
//! dependencies (the layer rule, held by review since D-768) and cannot form an opinion about what a string means. Deciding
//! that a piece of text is retrieved content rather than an instruction is
//! `xrm-ai`'s job, one layer up, because that decision needs to know where the
//! text came from.
//!
//! **Why one crate at all.** The realistic failure is that the chatbot, the AI
//! fields, and the search embedder each grow "a small HTTP client, just for
//! now" — and then three timeouts, three retry policies, three token budgets,
//! and three answers to "which model wrote this" drift apart. Invariant I-11
//! says every module reaches models through here: no production source
//! outside this crate may spell a model path, and no manifest may declare a
//! known LLM client crate. No script checks it since D-768; review holds it.
//!
//! **Both servers speak the same wire format.** Generation and embedding run
//! as separate serving processes (D-360 ruling 3 — one vLLM instance serves
//! one task), but both expose the OpenAI-compatible HTTP surface, so one
//! client shape covers either. That is a hedge, not an endorsement: a
//! deployment with an approved external provider points the same client
//! elsewhere by configuration, with no second code path — and pays the
//! data-governance cost `InferenceSection::allow_external_provider` documents.
//!
//! **Retries are asymmetric** (D-645, amending D-360 ruling 1). Embedding is a
//! pure function of its input, so a transient failure is retried a bounded
//! number of times inside the request deadline. Generation is never retried at
//! the transport: a retry can mint new tool-call ids and double-spend one grant
//! (D-553).

use std::sync::Arc;
use std::time::Duration;

use attome_config::InferenceEndpoint;
use serde::{Deserialize, Serialize};

/// Z9-T1: one provider-neutral way to call a model.
pub mod adapter;
pub mod budget;
pub mod embed;
pub mod generate;
pub mod models;
pub mod ocr;
pub mod rerank;
pub mod speech;
pub mod telemetry;
#[cfg(feature = "test-support")]
pub mod testing;

pub use embed::{EMBEDDINGS_PATH, EmbedKind, EmbeddingClient};
pub use generate::{
    CHAT_COMPLETIONS_PATH, ChatMessage, FinishReason, GenerationClient, GenerationRequest,
    GenerationResult, Role, ToolCall, ToolChoice, ToolDefinition,
};
pub use models::{MODELS_PATH, ModelListAuth, ModelListing, list_models, parse_model_listing};
pub use ocr::{OcrClient, OcrText};
pub use rerank::RerankClient;
pub use speech::{Segment, SpeechClient, TRANSCRIPTIONS_PATH, Transcript};

/// An HTTP client a caller built, plus the check that caller requires before
/// every dial (attome-server plan B5).
///
/// This crate cannot depend on attome-server, so attome-server's SSRF literal
/// check arrives as a predicate: `GuardedClient::into_parts` supplies both
/// halves, and a refused URL never reaches the client. The guarded client's
/// resolver still screens every hostname at connect time.
#[derive(Clone)]
pub struct DialClient {
    http: reqwest::Client,
    precheck: Option<Arc<DialPrecheck>>,
}

type DialPrecheck = dyn Fn(&reqwest::Url) -> bool + Send + Sync;

impl std::fmt::Debug for DialClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialClient")
            .field("checked", &self.precheck.is_some())
            .finish_non_exhaustive()
    }
}

impl DialClient {
    /// No per-request check: the in-deployment case, where the SSRF guard
    /// would refuse exactly the addresses the caller has decided to allow.
    pub fn unchecked(http: reqwest::Client) -> Self {
        Self {
            http,
            precheck: None,
        }
    }

    /// `precheck` runs on every URL before it is dialled; `false` refuses it.
    pub fn checked(
        http: reqwest::Client,
        precheck: impl Fn(&reqwest::Url) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            http,
            precheck: Some(Arc::new(precheck)),
        }
    }

    pub(crate) fn admit(
        &self,
        url: &reqwest::Url,
        label: &'static str,
    ) -> Result<&reqwest::Client, InferenceError> {
        match &self.precheck {
            Some(precheck) if !precheck(url) => Err(InferenceError::Transport {
                endpoint: label,
                kind: "destination refused by the dial guard",
            }),
            _ => Ok(&self.http),
        }
    }
}

/// What [`DialClient::post_json`] received.
#[derive(Debug)]
pub struct DialResponse {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    /// At most [`MAX_BODY_BYTES`].
    pub body: Vec<u8>,
}

impl DialClient {
    /// One JSON `POST` through the dial guard, for an outbound call that is
    /// not a model call (roadmap N13-T1: an outside MCP server): the same
    /// destination check and the same body cap. Errors name a fixed category,
    /// never the remote body.
    pub async fn post_json(
        &self,
        url: &str,
        headers: &[(&str, String)],
        body: &serde_json::Value,
    ) -> Result<DialResponse, InferenceError> {
        const LABEL: &str = "outbound";
        let parsed = reqwest::Url::parse(url).map_err(|_| InferenceError::Transport {
            endpoint: LABEL,
            kind: "invalid URL",
        })?;
        let http = self.admit(&parsed, LABEL)?;
        let mut request = http.post(parsed).json(body);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let mut response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                InferenceError::Timeout(LABEL)
            } else {
                InferenceError::Transport {
                    endpoint: LABEL,
                    kind: "request failed",
                }
            }
        })?;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_BODY_BYTES as u64)
        {
            return Err(InferenceError::Transport {
                endpoint: LABEL,
                kind: "response too large",
            });
        }
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let mut out = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| InferenceError::Transport {
                endpoint: LABEL,
                kind: "response interrupted",
            })?
        {
            if out.len() + chunk.len() > MAX_BODY_BYTES {
                return Err(InferenceError::Transport {
                    endpoint: LABEL,
                    kind: "response too large",
                });
            }
            out.extend_from_slice(&chunk);
        }
        Ok(DialResponse {
            status,
            headers,
            body: out,
        })
    }
}

/// The largest response body this crate will buffer (BIN-C2, `S1`).
///
/// A model server is not trusted to bound its own answer, and `response.json()`
/// used to buffer whatever arrived. Every body is now read chunk by chunk and
/// refused the moment it would exceed this; a declared `Content-Length` above
/// it is refused before the first byte is buffered. The stream assembler shares
/// the constant, so one stream can never outgrow one response either.
pub const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

/// The longest a connect attempt may take, however generous the endpoint's own
/// request timeout is (BIN-C1). A model server that accepts a TCP connection
/// and then never answers is handled by the request timeout, not by this.
pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest `Retry-After` this crate will wait for.
///
/// A provider can name any delay it likes; honouring a day-long one would
/// convert its rate limit into this deployment's outage. Longer values are
/// clamped, and the retry still fails if the wait would cross the request
/// deadline (BIN-D1).
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// How a model server's *status* is classified.
///
/// One variant used to cover every non-2xx response, so a rotated key, a rate
/// limit and an oversized prompt were indistinguishable. Nothing here carries
/// provider text — the classes are fixed, and `Display` prints only the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpstreamClass {
    /// 401 — the credential is missing, wrong, or rotated.
    Unauthorized,
    /// 403 — the credential is understood and refused.
    Forbidden,
    /// 429, with the server's own hint when it sent one.
    RateLimited {
        /// `Retry-After`, clamped to [`MAX_RETRY_AFTER`]. `None` when the
        /// header was absent or was not the delta-seconds form this crate
        /// reads.
        retry_after: Option<Duration>,
    },
    /// Any other 4xx. The request itself was rejected — retrying it changes
    /// nothing.
    ClientError,
    /// 5xx: the server failed on its own side.
    ///
    /// `retryable` marks 502/503/504 — the serving process restarting or
    /// overloaded, which is the one 5xx subset D-645 (BIN-D1) retries for
    /// embeddings. Any other 5xx (a 500 from a broken handler) is not retried:
    /// the same request would produce the same failure.
    ServerError {
        /// True for 502/503/504; false for every other 5xx.
        retryable: bool,
    },
}

impl UpstreamClass {
    /// Whether an embedding call may be replayed for this outcome (BIN-D1).
    pub(crate) fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::ServerError { retryable: true }
        )
    }

    /// The server's own wait hint, when it gave one (429 only).
    pub(crate) fn retry_after(self) -> Option<Duration> {
        match self {
            Self::RateLimited { retry_after } => retry_after,
            _ => None,
        }
    }
}

impl std::fmt::Display for UpstreamClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fixed strings only, deliberately: a model server's error body can
        // echo the prompt, and the prompt is customer data.
        let text = match self {
            Self::Unauthorized => "401 Unauthorized",
            Self::Forbidden => "403 Forbidden",
            Self::RateLimited { .. } => "429 Too Many Requests",
            Self::ClientError => "4xx client error",
            Self::ServerError { .. } => "5xx server error",
        };
        f.write_str(text)
    }
}

/// Every failure this crate can produce, typed (guidelines §6). Callers map
/// these to `AppError`; nothing here reaches a client response directly, and
/// no variant carries a provider's raw error text — a model server's error
/// body can echo the prompt back, and the prompt is customer data.
///
/// `#[non_exhaustive]`: adding a class of failure must not be a breaking change
/// for a caller that maps what it understands and refuses the rest. The one
/// caller that matches a variant (`xrm-ai`'s turn loop, on `Cancelled`) already
/// carries a wildcard arm.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InferenceError {
    /// No endpoint configured. Distinct from a network failure: it means the
    /// deployment never turned this on, which is an operator-actionable
    /// message rather than an incident.
    #[error("inference endpoint '{0}' is not configured")]
    NotConfigured(&'static str),

    /// The endpoint's configured base URL is unusable — not an HTTP URL, not
    /// parseable, or carrying a query, fragment or userinfo that would make
    /// the dialled target differ from the classified host (BIN-A3). A
    /// configuration error: retrying changes nothing.
    #[error("inference endpoint '{endpoint}' is misconfigured: {reason}")]
    Misconfigured {
        endpoint: &'static str,
        /// One of a fixed set of reasons. Never provider-supplied.
        reason: &'static str,
    },

    /// The request exceeded [`InferenceEndpoint::request_timeout_secs`].
    #[error("inference request to '{0}' timed out")]
    Timeout(&'static str),

    /// Transport failure reaching the model server.
    #[error("inference transport failure on '{endpoint}': {kind}")]
    Transport {
        endpoint: &'static str,
        /// A category, never the provider's raw message — see the type-level
        /// comment.
        kind: &'static str,
    },

    /// The model server answered with a non-success status, classified.
    #[error("inference endpoint '{endpoint}' answered {class}")]
    Upstream {
        endpoint: &'static str,
        class: UpstreamClass,
    },

    /// The model server answered, but not with something usable — a body that
    /// did not parse, exceeded [`MAX_BODY_BYTES`], or broke a wire rule.
    #[error("inference response from '{endpoint}' was unusable: {reason}")]
    BadResponse {
        endpoint: &'static str,
        reason: &'static str,
    },

    /// The caller is over its token budget. Surfaced as a 429, never a queue:
    /// one card serves the index drain, query embeddings, reranking, and chat
    /// with no arbitration of its own, so an unbudgeted caller starving the
    /// drain is the predictable first incident (TODO-056).
    #[error("token budget exhausted for this caller")]
    BudgetExhausted,

    /// Configuration forbids this endpoint. Raised when an endpoint points
    /// outside the data plane and `allow_external_provider` is false — a
    /// prompt leaving the plane is customer data leaving the plane.
    #[error(
        "inference endpoint '{0}' is outside the data plane and external providers are disabled"
    )]
    ExternalProviderForbidden(&'static str),

    /// The caller stopped a streamed generation before it finished (C11 B4).
    /// Not a failure of the model or the transport: the caller asked for it,
    /// and what it does next is its own decision.
    #[error("inference stream on '{0}' was cancelled by the caller")]
    Cancelled(&'static str),
}

impl InferenceError {
    /// Whether replaying the call could succeed. Only the transport failure
    /// that means "the request never reached a serving process" and D-645's
    /// transient upstream classes qualify.
    pub(crate) fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { .. } => true,
            Self::Upstream { class, .. } => class.is_retryable(),
            _ => false,
        }
    }

    /// The server's own wait hint, when it gave one.
    pub(crate) fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Upstream { class, .. } => class.retry_after(),
            _ => None,
        }
    }
}

/// Which model answered, and how much it cost. Returned alongside every
/// result and carried onward as provenance: `model_id` reaches TODO-054's
/// suggestion-outcome log so an auditor can answer "which model wrote this",
/// and the token counts are the raw material for per-feature metering.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Usage {
    pub model_id: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    /// BIN-G3: the provider sent a usage block. `false` means the counts above
    /// are unknown, not zero, so a budget keeps its estimate.
    #[serde(default)]
    pub reported: bool,
    /// `prompt_tokens_details.cached_tokens`, when the provider reports it.
    #[serde(default)]
    pub cached_prompt_tokens: Option<u32>,
}

/// Shared HTTP plumbing for both clients.
#[derive(Clone)]
pub(crate) struct Transport {
    http: reqwest::Client,
    /// The base URL, parsed **once** here so the host that was classified is
    /// the host that is dialled (BIN-A3). Rebuilding it with
    /// `format!("{base}{path}")` was a retargeting hole: `http://h/v1?x`
    /// posted to `/v1?x/chat/completions`, and the string the classifier read
    /// was not the string the HTTP client parsed.
    base_url: reqwest::Url,
    endpoint: InferenceEndpoint,
    /// Static label used in errors and metrics — `"generation"` or
    /// `"embedding"`. `&'static str` so no error variant can ever carry a
    /// caller-supplied or provider-supplied string.
    label: &'static str,
}

/// Parses and validates an endpoint's base URL (BIN-A3).
///
/// The refusals are configuration errors with fixed reasons, not transport
/// failures: every one of them is visible in a config file and actionable by
/// an operator before any request is made. A query, a fragment or userinfo
/// would all make the URL the classifier read differ from the URL the client
/// dials, which is the whole finding (BIN-F16).
fn parse_base_url(base_url: &str, label: &'static str) -> Result<reqwest::Url, InferenceError> {
    let trimmed = base_url.trim();
    if trimmed.is_empty() {
        return Err(InferenceError::NotConfigured(label));
    }
    let url = reqwest::Url::parse(trimmed).map_err(|_| InferenceError::Misconfigured {
        endpoint: label,
        reason: "base_url is not a valid URL",
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(InferenceError::Misconfigured {
            endpoint: label,
            reason: "base_url must be http or https",
        });
    }
    if url.host_str().is_none() {
        return Err(InferenceError::Misconfigured {
            endpoint: label,
            reason: "base_url has no host",
        });
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(InferenceError::Misconfigured {
            endpoint: label,
            reason: "base_url must not carry userinfo",
        });
    }
    if url.query().is_some() {
        return Err(InferenceError::Misconfigured {
            endpoint: label,
            reason: "base_url must not carry a query",
        });
    }
    if url.fragment().is_some() {
        return Err(InferenceError::Misconfigured {
            endpoint: label,
            reason: "base_url must not carry a fragment",
        });
    }
    Ok(url)
}

/// Joins a request path onto the parsed base URL, preserving the base's own
/// path (BIN-A3).
///
/// `Url::join("/chat/completions")` would *replace* `/v1`, silently posting
/// to the wrong endpoint; this appends instead, and a base that already ends
/// in a slash joins the same way as one that does not.
fn join_path(base: &reqwest::Url, path: &str) -> reqwest::Url {
    let mut url = base.clone();
    let mut joined = url.path().trim_end_matches('/').to_owned();
    joined.push_str(path);
    url.set_path(&joined);
    url
}

/// Reads a response body chunk by chunk, refusing anything over
/// [`MAX_BODY_BYTES`] (BIN-C2).
async fn read_body_capped(
    mut response: reqwest::Response,
    label: &'static str,
) -> Result<Vec<u8>, InferenceError> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_BODY_BYTES as u64)
    {
        return Err(InferenceError::BadResponse {
            endpoint: label,
            reason: "response body exceeded the size cap",
        });
    }
    let mut body: Vec<u8> = Vec::new();
    loop {
        let chunk = response.chunk().await.map_err(|e| {
            if e.is_timeout() {
                InferenceError::Timeout(label)
            } else {
                InferenceError::Transport {
                    endpoint: label,
                    kind: "body read failed",
                }
            }
        })?;
        let Some(chunk) = chunk else {
            return Ok(body);
        };
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(InferenceError::BadResponse {
                endpoint: label,
                reason: "response body exceeded the size cap",
            });
        }
        body.extend_from_slice(&chunk);
    }
}

/// Reads `Retry-After` in the delta-seconds form. The HTTP-date form is not
/// read: it would need a clock comparison, and ignoring it is the safe
/// direction (the call is not retried early).
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let raw = headers.get(reqwest::header::RETRY_AFTER)?.to_str().ok()?;
    let secs: u64 = raw.trim().parse().ok()?;
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

/// Classifies a non-success status, with its `Retry-After` when it sent one.
pub(crate) fn classify_status(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> UpstreamClass {
    match status.as_u16() {
        401 => UpstreamClass::Unauthorized,
        403 => UpstreamClass::Forbidden,
        429 => UpstreamClass::RateLimited {
            retry_after: parse_retry_after(headers),
        },
        502..=504 => UpstreamClass::ServerError { retryable: true },
        400..=499 => UpstreamClass::ClientError,
        _ => UpstreamClass::ServerError { retryable: false },
    }
}

impl Transport {
    pub(crate) fn new(
        endpoint: InferenceEndpoint,
        label: &'static str,
        allow_external: bool,
    ) -> Result<Self, InferenceError> {
        let base_url = parse_base_url(&endpoint.base_url, label)?;
        if !allow_external && !is_loopback_or_private(&endpoint.base_url) {
            return Err(InferenceError::ExternalProviderForbidden(label));
        }
        let timeout = Duration::from_secs(endpoint.request_timeout_secs.max(1));
        let http = reqwest::Client::builder()
            .timeout(timeout)
            // Never longer than the request itself, and never a handshake that
            // outlives the caller's patience (BIN-C1).
            .connect_timeout(MAX_CONNECT_TIMEOUT.min(timeout))
            // BIN-C1/BIN-F3: a redirect re-sends method *and body* — a 307 to
            // an attacker's host would deliver the whole prompt, and an
            // https→http downgrade would deliver it in clear. A model server
            // has no legitimate reason to redirect.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| InferenceError::Transport {
                endpoint: label,
                kind: "client build failed",
            })?;
        Ok(Self {
            http,
            base_url,
            endpoint,
            label,
        })
    }

    /// A transport over an HTTP client the caller built, for an endpoint the
    /// caller has already decided is reachable (D-571). Unlike [`Transport::new`]
    /// it applies **no** loopback-or-private test of its own and consults no
    /// `allow_external_provider`: the caller owns that decision, and passes the
    /// client whose connect-time policy enforces it (the SSRF-pinning client for
    /// an external destination). The base URL is still parsed and validated
    /// here, so the dialled host is the classified host on this path too.
    pub(crate) fn with_client(
        http: DialClient,
        endpoint: InferenceEndpoint,
        label: &'static str,
    ) -> Result<Self, InferenceError> {
        let base_url = parse_base_url(&endpoint.base_url, label)?;
        // Checked once: every request joins a path onto this parsed base, and
        // redirects are off, so no later request can dial another host.
        let http = http.admit(&base_url, label)?.clone();
        Ok(Self {
            http,
            base_url,
            endpoint,
            label,
        })
    }

    pub(crate) fn model(&self) -> &str {
        &self.endpoint.model
    }

    pub(crate) fn label(&self) -> &'static str {
        self.label
    }

    /// Builds the authenticated request for `path`. The URL is joined from the
    /// parsed base, so nothing here can retarget the request.
    fn request<Req: Serialize>(&self, path: &str, body: &Req) -> reqwest::RequestBuilder {
        let mut request = self.http.post(join_path(&self.base_url, path)).json(body);
        if let Some(key) = self
            .endpoint
            .api_key
            .as_ref()
            .map(|k| k.expose())
            .filter(|k| !k.is_empty())
        {
            request = request.bearer_auth(key);
        }
        request
    }

    /// Sends and maps the transport half of a failure. The status is returned
    /// to the caller, which classifies it — the response body is never read
    /// here and never logged.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, InferenceError> {
        request.send().await.map_err(|e| {
            if e.is_timeout() {
                InferenceError::Timeout(self.label)
            } else {
                InferenceError::Transport {
                    endpoint: self.label,
                    kind: "request failed",
                }
            }
        })
    }

    /// POSTs `body` and returns the response for the caller to read
    /// incrementally — the streaming half of [`Transport::post`], with the same
    /// authentication, the same status handling and the same rule that a
    /// provider's error body is never logged.
    pub(crate) async fn post_streaming<Req: Serialize>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<reqwest::Response, InferenceError> {
        let response = self.send(self.request(path, body)).await?;
        self.refuse_redirect(&response)?;
        if !response.status().is_success() {
            let class = classify_status(response.status(), response.headers());
            tracing::warn!(
                endpoint = self.label,
                status = response.status().as_u16(),
                "inference stream request returned a non-success status"
            );
            return Err(InferenceError::Upstream {
                endpoint: self.label,
                class,
            });
        }
        Ok(response)
    }

    /// **BIN-C1.** A model server has no legitimate reason to redirect, and
    /// the client is built with `Policy::none()` so one is never followed. A
    /// server that answers 3xx anyway is a failure with a fixed reason — the
    /// status is logged, the `Location` is not (it is provider text, and
    /// following it is exactly what must not happen).
    fn refuse_redirect(&self, response: &reqwest::Response) -> Result<(), InferenceError> {
        if !response.status().is_redirection() {
            return Ok(());
        }
        tracing::warn!(
            endpoint = self.label,
            status = response.status().as_u16(),
            "inference server returned a redirect; refusing to follow it"
        );
        Err(InferenceError::BadResponse {
            endpoint: self.label,
            reason: "redirect refused",
        })
    }

    /// The configured whole-request timeout, which also bounds the silence a
    /// stream may keep between two chunks.
    pub(crate) fn request_timeout(&self) -> Duration {
        Duration::from_secs(self.endpoint.request_timeout_secs.max(1))
    }

    /// POSTs `body` to `{base_url}{path}` and deserialises the response.
    ///
    /// Timeouts are enforced by the `reqwest` client AND named explicitly in
    /// the error, because "the model is slow" and "the model server is
    /// unreachable" are different operator actions and a merged error makes an
    /// incident take longer. The body is read under [`MAX_BODY_BYTES`] and
    /// parsed from bytes, so a hostile or broken server cannot make this
    /// allocate without limit (BIN-C2).
    pub(crate) async fn post<Req: Serialize, Res: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Res, InferenceError> {
        let response = self.send(self.request(path, body)).await?;
        self.read_json(response).await
    }

    /// POSTs a raw body of `content_type` (a multipart upload) and
    /// deserialises the response, with [`Transport::post`]'s authentication,
    /// status handling and body cap.
    pub(crate) async fn post_bytes<Res: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        content_type: &str,
        body: Vec<u8>,
    ) -> Result<Res, InferenceError> {
        let mut request = self
            .http
            .post(join_path(&self.base_url, path))
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body);
        if let Some(key) = self
            .endpoint
            .api_key
            .as_ref()
            .map(|k| k.expose())
            .filter(|k| !k.is_empty())
        {
            request = request.bearer_auth(key);
        }
        let response = self.send(request).await?;
        self.read_json(response).await
    }

    /// Refuses a redirect or a failure status, then reads and parses the body
    /// under [`MAX_BODY_BYTES`].
    async fn read_json<Res: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::Response,
    ) -> Result<Res, InferenceError> {
        self.refuse_redirect(&response)?;

        // The status is logged; the body is NOT. A model server's error body
        // routinely echoes the prompt, and the prompt is customer data
        // (P-inference §4.7) — it must not reach a log sink.
        if !response.status().is_success() {
            let class = classify_status(response.status(), response.headers());
            tracing::warn!(
                endpoint = self.label,
                status = response.status().as_u16(),
                "inference request returned a non-success status"
            );
            return Err(InferenceError::Upstream {
                endpoint: self.label,
                class,
            });
        }

        let body = read_body_capped(response, self.label).await?;
        serde_json::from_slice(&body).map_err(|_| InferenceError::BadResponse {
            endpoint: self.label,
            reason: "response did not match the expected schema",
        })
    }
}

/// Whether a base URL points inside the deployment's own plane.
///
/// Deliberately conservative and deliberately dumb: it recognises loopback,
/// RFC1918 ranges, and single-label hostnames (Docker/Kubernetes service
/// names). **Anything it does not recognise is treated as external**, which is
/// the safe direction — the cost of a false "external" is that an operator
/// sets `allow_external_provider = true` for their own internal host and the
/// audit trail records the decision; the cost of a false "internal" is
/// customer data leaving the plane with nobody informed.
///
/// The classification itself is `attome_config::endpoint_is_in_deployment`, one
/// implementation shared with boot validation (BCF-2/BCF-D6) so the two can no
/// longer disagree.
fn is_loopback_or_private(base_url: &str) -> bool {
    attome_config::endpoint_is_in_deployment(base_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(base_url: &str) -> InferenceEndpoint {
        InferenceEndpoint {
            base_url: base_url.into(),
            model: "m".into(),
            ..InferenceEndpoint::default()
        }
    }

    #[test]
    fn loopback_and_private_hosts_are_internal() {
        for url in [
            "http://127.0.0.1:8000/v1",
            "http://localhost:8000/v1",
            "http://[::1]:8000/v1",
            "http://10.0.0.5:8000/v1",
            "http://192.168.1.20:8000/v1",
            "http://172.16.3.9:8000/v1",
            "http://vllm:8000/v1",
            "http://inference.local/v1",
        ] {
            assert!(is_loopback_or_private(url), "{url} must count as internal");
        }
    }

    /// The direction that matters. A public host must be recognised as
    /// external so `allow_external_provider = false` actually blocks it —
    /// this is the check standing between a default deployment and every
    /// prompt leaving the customer's plane.
    #[test]
    fn public_hosts_are_external() {
        for url in [
            "https://api.openai.com/v1",
            "https://generativelanguage.googleapis.com/v1",
            "https://some.vendor.example.com/v1",
            "http://8.8.8.8/v1",
        ] {
            assert!(!is_loopback_or_private(url), "{url} must count as external");
        }
    }

    #[test]
    fn an_external_endpoint_is_refused_unless_explicitly_allowed() {
        let endpoint = endpoint("https://api.example.com/v1");
        assert!(matches!(
            Transport::new(endpoint.clone(), "generation", false),
            Err(InferenceError::ExternalProviderForbidden("generation"))
        ));
        assert!(Transport::new(endpoint, "generation", true).is_ok());
    }

    #[test]
    fn an_unconfigured_endpoint_is_not_configured_rather_than_a_transport_error() {
        assert!(matches!(
            Transport::new(InferenceEndpoint::default(), "embedding", true),
            Err(InferenceError::NotConfigured("embedding"))
        ));
    }

    /// **BIN-A3.** Each of these would otherwise make the dialled target differ
    /// from the host the classifier approved: a query is appended to the path
    /// by string concatenation, userinfo is sent on the wire, and a non-HTTP
    /// scheme never reaches an HTTP server at all. All are refused at
    /// construction, with a fixed reason and no request.
    #[test]
    fn a_base_url_that_would_retarget_the_request_is_refused() {
        for bad in [
            "http://h/v1?x",
            "http://h/v1#f",
            "http://u:p@h/v1",
            "ftp://h/v1",
            "not a url",
        ] {
            let error = Transport::new(endpoint(bad), "generation", true)
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused"));
            assert!(
                matches!(error, InferenceError::Misconfigured { .. }),
                "{bad} must be a configuration refusal, got {error:?}"
            );
        }
    }

    /// A base path must survive the join: `Url::join` would drop `/v1`, and a
    /// trailing slash must not change the answer.
    #[test]
    fn paths_join_onto_the_base_without_dropping_it() {
        for base in ["http://h:8000/v1", "http://h:8000/v1/", "http://h:8000"] {
            let transport = Transport::new(endpoint(base), "generation", true).expect(base);
            assert_eq!(
                join_path(&transport.base_url, CHAT_COMPLETIONS_PATH).as_str(),
                if base.contains("/v1") {
                    "http://h:8000/v1/chat/completions"
                } else {
                    "http://h:8000/chat/completions"
                },
                "base {base}"
            );
        }
    }

    /// **BIN-A4** — the transport half of BCF-2's classifier table. Every URL
    /// here was read as *internal* by the old string-splitting classifier and
    /// so reached the socket with `allow_external_provider = false`. Each must
    /// now be refused before a request is built.
    #[test]
    fn the_bcf2_classifier_bypasses_are_refused_by_the_transport() {
        for bad in [
            "http://[2606:4700::1111]/v1",
            "http://evil.example#@vllm/v1",
            "http://evil.example?@vllm/v1",
            "http://evil.example\\@vllm/v1",
            "http://134744072/v1",
            "http://0x08080808/v1",
        ] {
            let error = Transport::new(endpoint(bad), "generation", false)
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused"));
            assert!(
                matches!(
                    error,
                    InferenceError::ExternalProviderForbidden(_)
                        | InferenceError::Misconfigured { .. }
                ),
                "{bad} must be refused as external or misconfigured, got {error:?}"
            );
        }
    }

    /// **BIN-E1.** A rotated key, a rate limit and a rejected request are
    /// different operator actions, and the class carries no provider text.
    #[test]
    fn upstream_statuses_are_classified_without_provider_text() {
        let no_headers = reqwest::header::HeaderMap::new();
        let mut limited = reqwest::header::HeaderMap::new();
        limited.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("7"),
        );
        let cases = [
            (401, &no_headers, UpstreamClass::Unauthorized),
            (403, &no_headers, UpstreamClass::Forbidden),
            (400, &no_headers, UpstreamClass::ClientError),
            (
                500,
                &no_headers,
                UpstreamClass::ServerError { retryable: false },
            ),
            (
                503,
                &no_headers,
                UpstreamClass::ServerError { retryable: true },
            ),
            (
                429,
                &limited,
                UpstreamClass::RateLimited {
                    retry_after: Some(Duration::from_secs(7)),
                },
            ),
            (
                429,
                &no_headers,
                UpstreamClass::RateLimited { retry_after: None },
            ),
        ];
        for (code, headers, expected) in cases {
            let status = reqwest::StatusCode::from_u16(code).unwrap();
            let class = classify_status(status, headers);
            assert_eq!(class, expected, "status {code}");
            // The Display text is fixed: no code path can smuggle a body
            // string into a log through an error's message.
            assert!(!class.to_string().is_empty());
        }
        // A sentinel planted in the body never reaches a rendered error: the
        // variants that could carry text take `&'static str` only.
        let sentinel = "SENTINEL-PROVIDER-BODY";
        let error = InferenceError::Upstream {
            endpoint: "generation",
            class: UpstreamClass::ServerError { retryable: false },
        };
        assert!(!format!("{error}").contains(sentinel));
    }

    /// The D-645 retry set is exact: connect failures and 429/502/503/504, and
    /// nothing else.
    #[test]
    fn only_the_d645_outcomes_are_retryable() {
        assert!(
            InferenceError::Transport {
                endpoint: "embedding",
                kind: "request failed",
            }
            .is_retryable()
        );
        for (class, expected) in [
            (UpstreamClass::Unauthorized, false),
            (UpstreamClass::Forbidden, false),
            (UpstreamClass::ClientError, false),
            (UpstreamClass::ServerError { retryable: false }, false),
            (UpstreamClass::ServerError { retryable: true }, true),
            (UpstreamClass::RateLimited { retry_after: None }, true),
        ] {
            let error = InferenceError::Upstream {
                endpoint: "embedding",
                class,
            };
            assert_eq!(error.is_retryable(), expected, "{class:?}");
        }
        assert!(!InferenceError::Timeout("embedding").is_retryable());
        assert!(!InferenceError::Cancelled("embedding").is_retryable());
    }

    /// A `Retry-After` a provider chooses cannot become this deployment's
    /// outage: it is clamped, and a non-numeric value is ignored.
    #[test]
    fn retry_after_is_parsed_in_seconds_and_clamped() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("86400"),
        );
        assert_eq!(parse_retry_after(&headers), Some(MAX_RETRY_AFTER));
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("Wed, 21 Oct 2026 07:28:00 GMT"),
        );
        assert_eq!(parse_retry_after(&headers), None);
    }
}
