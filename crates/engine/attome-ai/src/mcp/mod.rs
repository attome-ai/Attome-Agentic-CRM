//! M101 slice 2 — the Model Context Protocol surface.
//!
//! One route, `POST /api/v1/mcp`, speaking JSON-RPC 2.0. It exposes the
//! platform's existing action registry to an external MCP host — the
//! customer's own Claude, Copilot, Cursor, or anything else that speaks the
//! protocol — under the platform's own permission model.
//!
//! ## What this is not
//!
//! **It is not a second registry, a second catalogue, or a second dispatch
//! path.** `tools/list` is [`crate::registry::ActionRegistry::visible_to`] and
//! `tools/call` is [`crate::execute::dispatch`], with nothing in between but
//! wire-format translation. That is the whole design: invariant I-2 exists
//! because four consumers with four catalogues drift, and the copy that
//! drifts is the one that writes without a gate. An MCP server that built its
//! own tool list would be exactly that failure, wearing a standards badge.
//!
//! It therefore needs **no** change to the closed-registry rule (I-5): no
//! capability is added, nothing is registered at runtime, and a tool a model
//! names still either resolves against the compile-time set or does nothing
//! (I-9). This is a transport adapter.
//!
//! ## Three deliberate security positions
//!
//! **1. Every MCP invocation is `Initiator::Agent`, never `User`.** A model is
//! choosing the tool, which is the definition of an agent invocation. The
//! consequence is load-bearing: `gate::evaluate`'s
//! `(Consequential, Agent)` arm returns `RequiresApproval` unconditionally, so
//! no MCP client can auto-execute a destructive action through any argument —
//! the property `no_input_combination_lets_an_agent_auto_execute_a_consequential_action`
//! sweeps across 288 combinations. Treating an MCP call as `Initiator::User`
//! would have silently deleted that guarantee.
//!
//! **2. Every MCP session starts tainted.** I-10's taint tracking assumes the
//! platform owns the conversation and can see when tool-obtained text enters
//! it. Across MCP it does not: the context lives inside the external host,
//! which may have fetched a web page, read a file, or called another server's
//! tool before calling ours, and none of that is visible here. We cannot prove
//! the context is clean, so we assume it is not — [`SESSION_TAINTED`]. In
//! practice that degrades an agent's `Reversible` write to confirm-first,
//! which is the correct answer for a write proposed by a context we cannot
//! see.
//!
//! **3. Ordinary authentication, no bypass route.** The endpoint sits behind
//! the same `Authorized<SelfService>` extractor `/actions/{id}/invoke` uses,
//! so an MCP client authenticates with an API key or session cookie like any
//! other caller (guidelines §7 — no endpoint-specific authentication scheme).
//! It is deliberately **not** a public/bypass route, and OAuth 2.1
//! resource-server registration is not implemented here; adding either is a
//! security-sensitive middleware change that deserves its own review rather
//! than riding along with a transport adapter.
//!
//! ## Tool names are action ids, unchanged
//!
//! `record.get` is offered to the host as `record.get`. Some MCP servers
//! sanitise dots out of tool names; this one does not, because the mapping
//! back is where identity gets lost — `record.update_field` and a
//! hypothetical `record_update.field` both sanitise to `record_update_field`,
//! and a collision there means a model naming one tool invokes another. I-9's
//! guarantee is that a name either resolves against the closed set or does
//! nothing, and that guarantee is strongest when there is no transformation
//! at all.
//!
//! ## What is implemented
//!
//! `initialize`, `notifications/initialized`, `ping`, `tools/list`,
//! `tools/call`. Resources, prompts, sampling, completion, and subscriptions
//! are not — a host that asks for them gets a method-not-found, which is the
//! protocol's own way of saying a capability is absent, and
//! [`server_capabilities`] advertises only `tools` so a conforming host never
//! asks.

use std::sync::Arc;

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::post};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::RiskTier;
use crate::registry::VisibilityInputs;
use crate::session::{self, SessionStart};

pub mod admission;

/// The MCP revision this surface implements, echoed back from `initialize`.
///
/// Pinned as a constant rather than mirrored from whatever the client asks
/// for: a server that echoes the client's version claims conformance it has
/// not got. A host requesting a different revision still gets this one and
/// decides for itself whether to proceed — which is what the protocol's own
/// version-negotiation step is for.
pub const MCP_PROTOCOL_VERSION: &str = "2025-06-18";

/// Header carrying the agent session across calls. Lower-case because
/// `axum::http::HeaderMap` lookups are case-insensitive but the constant is
/// used verbatim in responses.
pub const SESSION_HEADER: &str = "mcp-session-id";

/// `agent_session.surface` for sessions opened here — what an
/// operator triaging "which surface is doing this" sees, and what
/// `/admin/agents/sessions` groups by.
pub const MCP_SURFACE: &str = "mcp";

/// How long a host may cache `tools/list` (plan item M1.7, spec finding F-9).
///
/// Five minutes: long enough that a chatty host stops re-listing on every turn,
/// short enough that a privilege grant, a licence change or a narrowed session
/// allow-list reaches the host quickly. It is a *freshness hint*, never a
/// security control — the gate re-checks every invocation regardless of what a
/// host cached, so a stale list can hide a tool but can never authorise one.
pub const TOOLS_LIST_TTL_MS: u64 = 300_000;

/// Every MCP session starts tainted. See the module doc's position 2 — this
/// is not a default that can be overridden, it is a statement about what this
/// surface can and cannot observe.
const SESSION_TAINTED: bool = true;

/// The ceiling an MCP session opens with.
///
/// `Consequential` looks alarming and is the safe choice, because the ceiling
/// bounds what an agent may *attempt* while the risk matrix decides what
/// happens when it does. At this ceiling a destructive action is reachable —
/// and reaching it produces an approval request that a human must clear, which
/// is the entire point of exposing four-eyes across the MCP boundary. Lowering
/// this to `Reversible` would not make the surface safer; it would make
/// `Consequential` actions invisible and the approval path untestable, while
/// the gate's own guarantee already makes auto-execution unreachable.
const SESSION_CEILING: RiskTier = RiskTier::Consequential;

// ── JSON-RPC 2.0 envelope ──────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    #[serde(default)]
    jsonrpc: String,
    /// Absent for a notification, which takes no response.
    #[serde(default)]
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

impl std::fmt::Debug for JsonRpcRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonRpcRequest").finish_non_exhaustive()
    }
}

impl JsonRpcRequest {
    /// The protocol version this request declares in `params._meta`, if any.
    ///
    /// **Presence is what makes a request modern.** The legacy revision has no
    /// `_meta`, so a request without one is served exactly as it always was —
    /// which is how a dual-era endpoint avoids breaking existing hosts (F-5).
    fn declared_protocol_version(&self) -> Option<&str> {
        self.params
            .as_ref()?
            .get("_meta")?
            .get(meta::PROTOCOL_VERSION)?
            .as_str()
    }

    /// `params.name`, which `tools/call` mirrors into the `Mcp-Name` header.
    fn params_name(&self) -> Option<&str> {
        self.params.as_ref()?.get("name")?.as_str()
    }
}

#[derive(Serialize, ToSchema)]
pub struct JsonRpcError {
    code: i32,
    message: String,
}

impl std::fmt::Debug for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonRpcError").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

impl std::fmt::Debug for JsonRpcResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JsonRpcResponse").finish_non_exhaustive()
    }
}

/// JSON-RPC 2.0 reserved codes, plus the two the MCP specification allocates
/// from the server-error range. Named rather than inlined so a wrong one is a
/// compile-time rename instead of a silent protocol violation.
mod code {
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL: i32 = -32603;

    /// The HTTP headers disagree with the request body, or a required one is
    /// missing. The specification reserves `-32020..-32099` for itself; these
    /// two are not ours to renumber.
    pub const HEADER_MISMATCH: i32 = -32020;
    /// The requested protocol version is one this server does not implement.
    pub const UNSUPPORTED_PROTOCOL_VERSION: i32 = -32022;
}

/// The modern revision this surface implements (plan item M1.2, finding F-5).
///
/// Stateless: no `initialize`, no protocol session, per-request `_meta`. Served
/// from the same endpoint as the legacy revision, because the specification's
/// own versioning rules allow a dual-era server — which is what lets the modern
/// era arrive without breaking a single existing host.
pub const MCP_MODERN_PROTOCOL_VERSION: &str = "2026-07-28";

/// Every revision this endpoint answers, newest first. Returned verbatim in an
/// `UnsupportedProtocolVersionError`'s `supported` list, so a client can pick
/// one and retry rather than guess.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &[MCP_MODERN_PROTOCOL_VERSION, MCP_PROTOCOL_VERSION];

/// `_meta` keys the modern revision puts on every request.
mod meta {
    pub const PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
}

/// The HTTP header mirroring `_meta`'s protocol version. It must agree with the
/// body, or an intermediary routing on the header and a server executing on the
/// body would disagree about what they are speaking.
const PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";

/// The HTTP header mirroring the JSON-RPC `method`.
const METHOD_HEADER: &str = "mcp-method";

impl JsonRpcResponse {
    fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    fn err(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
            }),
        }
    }
}

/// What this server advertises. `tools` only — see the module doc.
fn server_capabilities() -> Value {
    json!({ "tools": { "listChanged": false } })
}

// ── The route ──────────────────────────────────────────────────────────────

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/mcp", post(mcp_endpoint))
}

/// The MCP JSON-RPC endpoint.
///
/// Authenticated exactly like every other action surface. A notification (a
/// request with no `id`) is answered `202 Accepted` with no body, per
/// JSON-RPC: a notification has no response, and returning one would make a
/// conforming host log a protocol error.
#[utoipa::path(
    post,
    path = "/api/v1/mcp",
    tag = "mcp",
    request_body = JsonRpcRequest,
    // `initialize` opens an agent session (`Ai` + `Create`, session::start);
    // a `tools/call` that writes, or runs an approved action, writes `Ai` +
    // `Execute` (execute::run_executor). Reads (`tools/list`, read tools)
    // write no event.
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::Ai, attome_audit::AuditOperation::Execute),
    ])))),
    responses(
        (status = 200, description = "JSON-RPC response", body = JsonRpcResponse),
        (status = 202, description = "Notification accepted; no response body"),
        (status = 401, description = "Missing or invalid credentials", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn mcp_endpoint(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    headers: HeaderMap,
    Json(request): Json<JsonRpcRequest>,
) -> Response {
    let is_notification = request.id.is_none();
    let id = request.id.clone().unwrap_or(Value::Null);
    let security = ctx.into_inner();

    // M1.6 / finding F-7. The transport requires a server to validate `Origin`
    // on every connection and answer 403 when one is present and invalid —
    // DNS-rebinding protection, and it applies to *every* credential type.
    //
    // `csrf_protect` is not enough on its own: it only fires for a mutating
    // request that carries a browser cookie, so an API-key or (later) bearer
    // call from a hostile page is unchecked by it. The check reuses
    // `attome_server::middleware::csrf::origin_is_allowed`, so "allowed" means
    // one thing on this endpoint and on every other.
    //
    // Absent `Origin` is allowed: a non-browser host (the normal MCP client)
    // sends none, and the spec conditions the refusal on the header being
    // present. The refusal is a bare status, not a JSON-RPC error body — the
    // request never reached the protocol layer.
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if origin.is_some()
        && !attome_server::middleware::csrf::origin_is_allowed(
            origin,
            &state.base.config.allowed_origins(),
        )
    {
        tracing::warn!(
            user_id = %security.user_id,
            "rejected an MCP request carrying a disallowed Origin"
        );
        return StatusCode::FORBIDDEN.into_response();
    }

    // M1.2 / finding F-5. A request declaring `_meta`'s protocol version is
    // modern and must satisfy the transport's header rules; one that declares
    // nothing is legacy and is served exactly as before. Both eras share this
    // endpoint, which is what the specification's versioning rules allow and
    // what lets the modern era arrive without breaking an existing host.
    let is_modern = request.declared_protocol_version().is_some();
    if let Err(refusal) = check_modern_envelope(&request, &headers) {
        tracing::info!(
            method = %request.method,
            code = refusal.code,
            "refused an MCP request at the transport layer"
        );
        return refusal.into_response(id);
    }

    let outcome = match request.method.as_str() {
        // Modern only: the legacy revision has no discovery method, and a
        // legacy host asking for one is asking for something that did not
        // exist in the revision it speaks.
        "server/discover" if is_modern => Ok(discover_result()),
        "initialize" => initialize(&state, security, request.params.as_ref()).await,
        "ping" => Ok(json!({})),
        "tools/list" => tools_list(&state, security, &headers).await,
        "tools/call" => tools_call(&state, security, &headers, request.params).await,
        // Notifications the protocol defines but that need no work here.
        m if m.starts_with("notifications/") => Ok(json!({})),
        other => {
            let response = JsonRpcResponse::err(
                id,
                code::METHOD_NOT_FOUND,
                format!("unknown method {other}"),
            );
            // The modern transport answers an unimplemented method with 404,
            // so a client can tell "this server does not do that" from "this
            // path is not an MCP endpoint at all". Legacy keeps 200, because
            // that is what the revision it speaks expects.
            let status = if is_modern {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::OK
            };
            return (status, Json(response)).into_response();
        }
    };

    if is_notification {
        return StatusCode::ACCEPTED.into_response();
    }

    let response = match outcome {
        // Every modern result carries `resultType`. `server/discover` sets its
        // own, so stamping is skipped when one is already present rather than
        // overwriting a method's answer.
        Ok(mut result) if is_modern => {
            if let Some(object) = result.as_object_mut() {
                object
                    .entry("resultType")
                    .or_insert_with(|| Value::from("complete"));
            }
            JsonRpcResponse::ok(id, result)
        }
        Ok(result) => JsonRpcResponse::ok(id, result),
        Err(error) => JsonRpcResponse::err(id, json_rpc_code(&error), sanitized(&error)),
    };

    // M1.5 / finding F-1: the legacy transport hands a host its session in the
    // `Mcp-Session-Id` **response header**. Until now the id travelled only in
    // `result.sessionId`, which this surface's own client would find but a
    // standard host would not — so every call after `initialize` failed with
    // "missing mcp-session-id header" and the surface was, in practice,
    // unusable by a conforming client. The body keeps carrying it too: a header
    // is what the protocol specifies, and the body is what a JSON-RPC client is
    // guaranteed to read.
    let session_header = response
        .result
        .as_ref()
        .and_then(|result| result.get("sessionId"))
        .and_then(Value::as_str)
        .and_then(|id| axum::http::HeaderValue::from_str(id).ok());

    match session_header {
        Some(value) => {
            let mut response = (StatusCode::OK, Json(response)).into_response();
            response.headers_mut().insert(SESSION_HEADER, value);
            response
        }
        None => (StatusCode::OK, Json(response)).into_response(),
    }
}

/// A refusal that carries its own HTTP status, for the transport-level checks
/// the modern revision specifies. Everything past these answers `200 OK` with a
/// JSON-RPC body, as JSON-RPC intends; these three are the documented
/// exceptions, because the request never reached the protocol layer.
struct TransportRefusal {
    status: StatusCode,
    code: i32,
    message: String,
    /// `UnsupportedProtocolVersionError` carries the versions this server does
    /// implement, so a client can retry with one instead of guessing.
    data: Option<Value>,
}

impl TransportRefusal {
    fn into_response(self, id: Value) -> Response {
        let mut body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": self.code, "message": self.message },
        });
        if let Some(data) = self.data {
            body["error"]["data"] = data;
        }
        (self.status, Json(body)).into_response()
    }
}

/// Validates a modern request's transport envelope: the mirrored headers must
/// agree with the body, and the declared version must be one we implement.
///
/// Returns `Ok(())` for a legacy request — it declares no version, mirrors no
/// headers, and is served unchanged.
fn check_modern_envelope(
    request: &JsonRpcRequest,
    headers: &HeaderMap,
) -> Result<(), TransportRefusal> {
    let Some(declared) = request.declared_protocol_version() else {
        return Ok(());
    };

    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&declared) {
        return Err(TransportRefusal {
            status: StatusCode::BAD_REQUEST,
            code: code::UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version".to_string(),
            data: Some(json!({
                "supported": SUPPORTED_PROTOCOL_VERSIONS,
                "requested": declared,
            })),
        });
    }

    let header = |name: &str| headers.get(name).and_then(|value| value.to_str().ok());

    // The version header must be present and equal to the body's. An
    // intermediary that routes on the header while this server executes on the
    // body is exactly the split-brain the specification's header rules exist to
    // prevent.
    match header(PROTOCOL_VERSION_HEADER) {
        Some(value) if value == declared => {}
        _ => {
            return Err(TransportRefusal {
                status: StatusCode::BAD_REQUEST,
                code: code::HEADER_MISMATCH,
                message: format!(
                    "{PROTOCOL_VERSION_HEADER} must be present and match the request's \
                     declared protocol version"
                ),
                data: None,
            });
        }
    }

    match header(METHOD_HEADER) {
        Some(value) if value == request.method => {}
        _ => {
            return Err(TransportRefusal {
                status: StatusCode::BAD_REQUEST,
                code: code::HEADER_MISMATCH,
                message: format!("{METHOD_HEADER} must be present and match the request's method"),
                data: None,
            });
        }
    }

    // `Mcp-Name` mirrors `params.name`, and is required only for the methods
    // that carry one.
    if let Some(name) = request.params_name()
        && header("mcp-name") != Some(name)
    {
        return Err(TransportRefusal {
            status: StatusCode::BAD_REQUEST,
            code: code::HEADER_MISMATCH,
            message: "mcp-name must be present and match params.name".to_string(),
            data: None,
        });
    }

    Ok(())
}

/// What `server/discover` answers: the versions this endpoint implements, the
/// capabilities it advertises, and who it says it is.
///
/// `serverInfo` travels under `_meta`, where the modern revision puts it. It is
/// self-reported and the specification tells clients not to make security
/// decisions from it, which is why nothing here is derived from it either.
fn discover_result() -> Value {
    json!({
        "resultType": "complete",
        "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
        "capabilities": server_capabilities(),
        "_meta": {
            "io.modelcontextprotocol/serverInfo": {
                "name": "attome-xrm",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    })
}

/// Maps an `AppError` onto a JSON-RPC code.
///
/// Everything that is not obviously the caller's malformed input becomes
/// `INTERNAL`, because JSON-RPC's code space has no vocabulary for
/// authorization and this endpoint must not grow one — the *dark* behaviour
/// (a refused or unlicensed capability is indistinguishable from an absent
/// one) is already enforced by the gate, and a distinct code here would undo
/// it by leaking which of the two happened.
fn json_rpc_code(error: &AppError) -> i32 {
    match error {
        AppError::Validation(_) | AppError::FieldValidation(_) => code::INVALID_PARAMS,
        AppError::NotFound => code::INVALID_REQUEST,
        _ => code::INTERNAL,
    }
}

/// The message a client sees. Validation text is actionable and safe;
/// everything else is masked, per guidelines §6 (never expose internal state).
///
/// `Conflict` passes through too: its messages are static strings describing
/// retry state ("an identical invocation of this tool call is already in
/// progress", D-502), which a tool loop needs to tell "wait and retry" from
/// "give up" — and none of them says anything about authorization or licensing.
fn sanitized(error: &AppError) -> String {
    match error {
        AppError::Validation(message) => message.clone(),
        AppError::FieldValidation(errors) => attome_types::types::FieldError::summary(errors),
        AppError::Conflict(message) => (*message).to_string(),
        AppError::NotFound => "unknown or unavailable".to_string(),
        _ => "the request could not be completed".to_string(),
    }
}

// ── Methods ────────────────────────────────────────────────────────────────

/// Opens an agent session and returns the handshake.
///
/// **As an agent (N12-T4).** `params.agent` may name a published agent
/// object: the session then runs as that agent, its tools one more
/// allow-list and its `limits.daily` the per-day caps (V2-D487), on top of
/// the connecting person's own privileges and this surface's ceiling. It
/// only narrows; without it the session is the person's own, as before.
///
/// The session id comes back in `result.sessionId` rather than only as a
/// header because a JSON-RPC client reading a response body is guaranteed;
/// a client preserving response *headers* across calls is not.
async fn initialize(
    state: &EngineState,
    security: Arc<SecurityContext>,
    params: Option<&Value>,
) -> Result<Value, AppError> {
    let agent = match params.and_then(|p| p.get("agent")) {
        None | Some(Value::Null) => None,
        Some(value) => {
            let id = value
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| AppError::Validation("agent must be an agent object id".into()))?;
            let (tools, daily) = crate::agent::published_agent(state, id).await?;
            Some((id, tools, daily))
        }
    };
    let allowed_action_ids = agent
        .as_ref()
        .map(|(_, tools, _)| crate::agent::narrow_to_agent_tools(None, tools));
    let session = session::start(
        &state.base.db,
        &attome_audit::audit_service(state),
        SessionStart {
            owner_user_id: security.user_id,
            risk_ceiling: SESSION_CEILING,
            // Without an agent, `None`, not `Some(vec![])` — ceiling-bounded
            // rather than nothing-allowed. `session.rs`'s own doc calls that
            // distinction out as deliberate. With one, its tools.
            allowed_action_ids,
            surface: MCP_SURFACE,
            agent_definition_ref: None,
            integration_system_id: None,
            tainted: SESSION_TAINTED,
            // D-505 §1: an MCP session names no definition, so it has no
            // policy term.
            policy: session::PolicySnapshot::NONE,
        },
    )
    .await?;
    if let Some((agent, _, daily)) = agent
        && let Err(error) =
            session::attach_agent_object(&state.base.db, session.id, agent, daily).await
    {
        // Never leave a session running without the agent's limits.
        let _ = session::revoke(
            &state.base.db,
            session.id,
            security.user_id,
            "agent limits not attached",
        )
        .await;
        return Err(error);
    }

    tracing::info!(
        session_id = %session.id,
        user_id = %security.user_id,
        "opened an MCP agent session"
    );
    // M3.4: tell the operator, on every session open, when default-deny
    // admission will refuse every `record.*` call this session makes.
    admission::warn_if_nothing_admitted(state);

    Ok(json!({
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": server_capabilities(),
        "serverInfo": { "name": "attome-xrm", "version": env!("CARGO_PKG_VERSION") },
        "sessionId": session.id,
        "instructions": PLAYBOOK,
    }))
}

/// Resolves the session named by the `Mcp-Session-Id` header.
///
/// A missing, malformed, revoked, or expired session is a `Validation` error
/// naming the fix, not a silent fallback to a fresh one: an implicit session
/// would carry no ceiling anybody chose, and a killed session must stay killed
/// (`agent.kill` is not resumable — a client that could shrug and open a new
/// one on the next call would make the kill switch decorative).
///
/// **The session must be the caller's own, and an MCP one.** The header is a
/// handle, not a credential: a session carries its own ceiling, allow-list,
/// and taint flag, so accepting any live id would let a caller borrow another
/// user's untainted session — a webchat conversation, say — and have their
/// agent writes skip the confirm-first step their own MCP session imposes
/// (position 2 above). Someone else's session, another surface's session, and
/// no session at all produce the same error, so a guessed id reveals nothing.
async fn require_session(
    state: &EngineState,
    caller: &SecurityContext,
    headers: &HeaderMap,
) -> Result<session::AgentSession, AppError> {
    let raw = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            AppError::Validation(format!(
                "missing {SESSION_HEADER} header — call initialize first"
            ))
        })?;
    let id = Uuid::parse_str(raw)
        .map_err(|_| AppError::Validation(format!("{SESSION_HEADER} is not a valid session id")))?;

    session::load_live_owned(&state.base.db, id, caller.user_id, MCP_SURFACE)
        .await?
        .ok_or_else(|| {
            AppError::Validation(
            "this MCP session is no longer live — it was ended or revoked; call initialize again"
                .into(),
        )
        })
}

/// Builds the per-invocation context, through the mandated constructor.
///
/// `ActionContext::for_session`, never `ActionContext::agent` directly — see
/// that function's doc comment: it is the one place a session's stored taint
/// re-enters the gate decision, and bypassing it is how taint silently
/// disappears.
fn context_for(security: Arc<SecurityContext>, session: &session::AgentSession) -> ActionContext {
    ActionContext::for_session(security, session)
}

/// The visible tool set, filtered by exactly the conditions the gate applies
/// to an invocation — the session's allow-list included, because
/// `ActionContext::for_session` carries it and `visible_to` asks the gate.
/// How to work with Attome over MCP (N12-T2), sent as the `initialize`
/// result's `instructions`: how to find tools, how building works, and the
/// rules every call is held to.
pub const PLAYBOOK: &str = "Attome is a CRM whose data and screens are defined by metadata. \
`tools/list` gives the everyday tools; call `tools.search` with what you want to do to find the \
rest, including the metadata building tools. Building: `model.<kind>.describe` explains a kind \
and its document schema, `model.<kind>.list` shows what exists, and `model.<kind>.edit` saves a \
draft from add/remove/move/set commands against the draft's content hash (an empty hash for a new \
object). Edits are proposals: a person confirms each one, and nothing goes live until it is \
published. Rules: you act as the signed-in person and never beyond their permissions; \
consequential actions wait for a second person's approval; a refusal is a result to report, not \
an error to work around.";

/// The one tool that is not an action (N12-T2): searches the tools this
/// caller may use. `tools/list` returns a small core set plus this, so a
/// host is not handed every generated metadata tool up front.
pub const SEARCH_TOOL: &str = "tools.search";

/// Generated tools (`model.<kind>.*`) are found through [`SEARCH_TOOL`]
/// rather than listed; every other visible tool is in the core set.
fn is_core_tool(name: &str) -> bool {
    !name.starts_with("model.")
}

fn search_tool_definition() -> Value {
    json!({
        "name": SEARCH_TOOL,
        "description": "Find tools by what they do. Returns up to 20 tools you may call, \
                        with their input schemas. Metadata building tools (model.<kind>.edit, \
                        describe, list) are found here rather than listed up front.",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": { "query": { "type": "string", "minLength": 1 } },
            "additionalProperties": false
        }
    })
}

/// The tools whose name or description holds every word of `query`
/// (case-insensitive), best first: a name match ranks above a description
/// match. At most 20.
pub(crate) fn search_tools(tools: &[Value], query: &str) -> Vec<Value> {
    let words: Vec<String> = query
        .split(|c: char| c.is_whitespace() || c == '.' || c == '_')
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    if words.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(usize, &Value)> = tools
        .iter()
        .filter_map(|tool| {
            let name = tool["name"].as_str().unwrap_or_default().to_lowercase();
            let description = tool["description"]
                .as_str()
                .unwrap_or_default()
                .to_lowercase();
            let mut score = 0;
            for word in &words {
                if name.contains(word.as_str()) {
                    score += 2;
                } else if description.contains(word.as_str()) {
                    score += 1;
                } else {
                    return None;
                }
            }
            Some((score, tool))
        })
        .collect();
    scored.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1["name"].as_str().cmp(&b.1["name"].as_str()))
    });
    scored
        .into_iter()
        .take(20)
        .map(|(_, tool)| tool.clone())
        .collect()
}

/// Every tool this caller may use, rendered for MCP.
async fn visible_tools(
    state: &EngineState,
    action_ctx: &crate::context::ActionContext,
) -> Vec<Value> {
    // C11 B5: the tool list honours the runtime AI switch, as the gate does.
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let license = state.modules.load();
    let is_licensed = |module: attome_modules::ModuleId| license.has(module);
    let inputs = VisibilityInputs {
        is_licensed: &is_licensed,
        ai: attome_core::ai_runtime_switch::effective(&state.base.config.inference.ai),
        surface_of: &crate::engine::surface_for,
        external_effects_enabled: state.base.config.security.external_effects_enabled,
    };

    crate::engine::REGISTRY
        .visible_to(action_ctx, &inputs)
        .map(|descriptor| {
            json!({
                "name": descriptor.id.as_str(),
                "description": descriptor.description,
                "inputSchema": serde_json::from_str::<Value>(descriptor.input_schema)
                    .unwrap_or_else(|_| json!({ "type": "object", "properties": {} })),
            })
        })
        .collect()
}

async fn tools_list(
    state: &EngineState,
    security: Arc<SecurityContext>,
    headers: &HeaderMap,
) -> Result<Value, AppError> {
    let session = require_session(state, &security, headers).await?;
    let action_ctx = context_for(security, &session);
    let mut tools: Vec<Value> = visible_tools(state, &action_ctx)
        .await
        .into_iter()
        .filter(|tool| tool["name"].as_str().is_some_and(is_core_tool))
        .collect();
    tools.push(search_tool_definition());

    Ok(json!({
        "tools": tools,
        "ttlMs": TOOLS_LIST_TTL_MS,
        // **Never `public`.** `visible_to` filters by the caller's licence,
        // privileges, session ceiling and allow-list, so two callers legitimately
        // see different lists. A shared intermediary caching one caller's list
        // under a `public` scope would serve it to the next caller — a
        // disclosure of what exists, which is exactly what the dark gate (D-010)
        // spends its effort hiding.
        "cacheScope": "private",
    }))
}

#[derive(Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: Value,
}

/// Invokes one tool through `dispatch`, and translates the outcome.
///
/// Note what is absent: any interpretation of the tool's arguments, any
/// decision about whether it may run, and any way to reach an executor other
/// than `dispatch`. All three live where they already lived.
async fn tools_call(
    state: &EngineState,
    security: Arc<SecurityContext>,
    headers: &HeaderMap,
    params: Option<Value>,
) -> Result<Value, AppError> {
    let params: ToolCallParams = serde_json::from_value(params.unwrap_or(Value::Null))
        .map_err(|e| AppError::Validation(format!("invalid tools/call params: {e}")))?;

    let session = require_session(state, &security, headers).await?;

    // N12-T2: the search tool reads the caller's own visible list; it runs no
    // action and changes nothing.
    if params.name == SEARCH_TOOL {
        let query = params.arguments["query"].as_str().unwrap_or_default();
        let action_ctx = context_for(security, &session);
        let found = search_tools(&visible_tools(state, &action_ctx).await, query);
        return Ok(tool_result(&json!({ "tools": found }), false));
    }

    // The action's OWN module decides licensing, not this surface's — same
    // reasoning `engine::invoke_action` documents. An unknown id resolves to
    // NotFound inside `dispatch` and the module looked up for it is irrelevant.
    let module = crate::engine::REGISTRY
        .resolve(&params.name)
        .map(|d| d.module)
        .unwrap_or(attome_modules::MODULE_AI);
    let inputs = crate::engine::gate_inputs(state, module);

    // A tool loop retries. The gate refuses a `RequiresKey` action from an
    // agent without a key, so one is supplied per (session, tool, arguments):
    // a genuine retry of the same call reuses it and is de-duplicated by the
    // invocation ledger's unique index, while a deliberate second call with
    // different arguments gets its own.
    let idempotency_key = tool_call_key(session.id, &params.name, &params.arguments);
    let action_ctx = context_for(security, &session).with_idempotency_key(idempotency_key);

    let outcome = crate::execute::dispatch(
        state,
        &crate::engine::REGISTRY,
        &crate::engine::EXECUTORS,
        &params.name,
        &action_ctx,
        &inputs,
        &params.arguments,
    )
    .await;

    Ok(match outcome {
        Ok(crate::execute::ActionOutcome::Completed { result, provenance }) => {
            let mut payload = json!({ "result": result });
            if let Some(provenance) = provenance {
                payload["provenance"] = serde_json::to_value(provenance).unwrap_or(Value::Null);
            }
            tool_result(&payload, false)
        }

        // I-10 in the host's UI: a write the platform cannot prove was the
        // human's idea. Reported as a tool *result*, not an error, so the
        // model can relay it and the human can act on it.
        Ok(crate::execute::ActionOutcome::ConfirmationRequired { reason, proposal }) => {
            let mut payload = json!({
                "status": "confirmation_required",
                "reason": reason,
                "detail": "This action was proposed from a context the platform \
                           cannot see. A human must confirm this specific \
                           invocation before it runs. Nothing has executed.",
            });
            // M35 v1 C3: display data only — never a handle to redeem.
            if let Some(proposal) = proposal {
                payload["proposal"] = proposal;
            }
            tool_result(&payload, false)
        }

        // **The differentiator (M101 #107).** Four-eyes crossing the MCP
        // boundary: the request is recorded, a second human must approve it in
        // Attome, and nothing has run. The approval id is returned so the host
        // can tell the user what to chase.
        Ok(crate::execute::ActionOutcome::ApprovalRequired { approval_id }) => tool_result(
            &json!({
                "status": "approval_required",
                "approval_id": approval_id,
                "detail": "This action is consequential and never executes for an \
                           agent without human approval. A four-eyes request has \
                           been raised in Attome. Nothing has executed.",
            }),
            false,
        ),

        // A refusal is a tool result with `isError`, not a JSON-RPC error, so
        // the model sees it and can adapt. The message goes through
        // `sanitized`, which keeps an unlicensed, disabled, and non-existent
        // tool indistinguishable — the dark gate (D-010) must survive being
        // re-exported over a new protocol.
        Err(error) => {
            tracing::info!(
                tool = %params.name,
                session_id = %session.id,
                "MCP tool call refused"
            );
            tool_result(&refusal_payload(state, &error), true)
        }
    })
}

/// A refused call's body. AB5-T10: a call refused because a service is down
/// names it under `degraded` and says whether to retry: yes for a short
/// outage, no once it has lasted five minutes, so an agent stops instead of
/// looping. `system.status` lists every service.
fn refusal_payload(state: &EngineState, error: &AppError) -> Value {
    let mut payload = json!({ "error": sanitized(error) });
    if let AppError::CapabilityUnavailable(name) = error {
        let retryable = attome_server::Capability::from_name(name)
            .is_none_or(|c| state.base.capabilities.agent_should_retry(c));
        payload["degraded"] = json!(name);
        payload["retryable"] = json!(retryable);
    }
    payload
}

/// A stable idempotency key for one (session, tool, arguments) triple.
///
/// Hashed rather than concatenated: arguments can be large, and the ledger's
/// `tool_call_id` column is not a place to store a caller's payload.
fn tool_call_key(session_id: Uuid, name: &str, arguments: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(session_id.as_bytes());
    hasher.update(name.as_bytes());
    // `to_string` on a `serde_json::Value` is key-ordered for maps
    // (serde_json's default is BTreeMap-backed ordering unless the
    // `preserve_order` feature is on), so two logically-identical argument
    // objects hash the same regardless of how the host serialised them.
    hasher.update(arguments.to_string().as_bytes());
    format!("mcp:{:x}", hasher.finalize())
}

/// Wraps a payload in MCP's `content` envelope.
///
/// Text content carrying JSON, rather than a bespoke structured type: every
/// MCP host renders `text`, and a host that cannot parse the JSON still shows
/// the user something legible.
fn tool_result(payload: &Value, is_error: bool) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(payload).unwrap_or_else(|_| payload.to_string()),
        }],
        "isError": is_error,
    })
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(mcp_endpoint))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This module's own production source, with `//` comments and the whole
    /// `#[cfg(test)]` block removed.
    ///
    /// Both exclusions are load-bearing for a test that scans the file it
    /// lives in. The comment filter stops the prose *explaining* a rule from
    /// tripping the rule. Truncating at `#[cfg(test)]` stops an assertion's
    /// own string literal from doing the same — without it,
    /// `assert!(!code.contains("run_executor("))` fails on itself, which is
    /// exactly what happened when this test was first written.
    fn production_source() -> String {
        let whole = include_str!("mod.rs");
        let production = whole
            .split_once("\n#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(whole);
        production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **The position that carries the most weight.** An MCP session is
    /// tainted from the moment it opens, because this surface cannot observe
    /// what the external host put in the model's context.
    ///
    /// If this ever flips to `false`, an agent's `Reversible` write stops
    /// degrading to confirm-first and a write proposed by a web page the host
    /// fetched executes unattended.
    #[test]
    // Same `#[allow]` and same reasoning as `attome-s2s`'s
    // `nonce_ttl_covers_the_timestamp_window_in_both_directions`: the value is
    // a constant, so the lint is right that this cannot fail at runtime — and
    // naming it in the suite is the point, so a regression reads as a failing
    // test rather than as a diff nobody looked at.
    #[allow(clippy::assertions_on_constants)]
    fn every_mcp_session_starts_tainted() {
        assert!(
            SESSION_TAINTED,
            "an MCP session must start tainted — the platform cannot see the \
             host's context, so it must not assume the context is clean"
        );
    }

    /// The ceiling admits `Consequential` so that reaching one produces an
    /// approval rather than a `Forbidden`. Auto-execution is made unreachable
    /// by the gate, not by this ceiling — see the constant's doc.
    #[test]
    fn the_session_ceiling_admits_consequential_so_approvals_are_reachable() {
        assert_eq!(SESSION_CEILING, RiskTier::Consequential);
    }

    /// Tool names are action ids verbatim. A sanitising transformation is how
    /// two distinct actions collide onto one name — see the module doc.
    #[test]
    fn the_playbook_names_the_search_tool_and_the_rules() {
        assert!(PLAYBOOK.contains(SEARCH_TOOL));
        assert!(PLAYBOOK.contains("model.<kind>.edit"));
        assert!(PLAYBOOK.contains("approval"));
    }

    #[test]
    fn search_finds_tools_by_name_before_description() {
        let tools = vec![
            json!({ "name": "model.form.edit", "description": "Edit a draft form" }),
            json!({ "name": "record.update", "description": "Change a record's form fields" }),
            json!({ "name": "record.get", "description": "Read a record" }),
        ];
        let names = |found: Vec<Value>| -> Vec<String> {
            found
                .iter()
                .map(|t| t["name"].as_str().unwrap_or_default().to_owned())
                .collect()
        };
        assert_eq!(
            names(search_tools(&tools, "form")),
            ["model.form.edit", "record.update"]
        );
        assert_eq!(names(search_tools(&tools, "record get")), ["record.get"]);
        assert!(search_tools(&tools, "  ").is_empty());
        assert!(is_core_tool("record.get") && !is_core_tool("model.form.edit"));
        assert!(
            crate::registry::ActionRegistry::new()
                .resolve(SEARCH_TOOL)
                .is_none(),
            "the name is free"
        );
    }

    #[test]
    fn tool_names_are_action_ids_with_no_transformation() {
        for descriptor in crate::registry::ActionRegistry::new().all() {
            let name = descriptor.id.as_str();
            assert!(
                name.contains('.'),
                "{name} — action ids are '{{domain}}.{{verb}}'; if this ever \
                 stops holding, re-check that the MCP surface still needs no \
                 name mapping"
            );
            assert!(
                crate::registry::ActionRegistry::new()
                    .resolve(name)
                    .is_some(),
                "{name} must resolve back through the registry unchanged"
            );
        }
    }

    /// Every advertised tool carries the three fields an MCP host needs, and
    /// the schema is real JSON rather than an escaped string.
    #[test]
    fn every_registered_action_can_be_rendered_as_an_mcp_tool() {
        for descriptor in crate::registry::ActionRegistry::new().all() {
            let schema: Value = serde_json::from_str(descriptor.input_schema)
                .unwrap_or_else(|e| panic!("{}: {e}", descriptor.id));
            assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
            assert!(!descriptor.description.is_empty(), "{}", descriptor.id);
        }
    }

    /// The idempotency key is stable for identical calls and distinct for
    /// different ones — the property that makes a tool loop's retry a retry
    /// rather than a duplicate write.
    #[test]
    fn the_idempotency_key_is_stable_per_session_tool_and_arguments() {
        let session = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let args = json!({ "entity": "account", "record_id": "x" });

        assert_eq!(
            tool_call_key(session, "record.get", &args),
            tool_call_key(session, "record.get", &args),
            "an identical retry must reuse its key"
        );
        assert_ne!(
            tool_call_key(session, "record.get", &args),
            tool_call_key(other, "record.get", &args),
            "two sessions must not share a key"
        );
        assert_ne!(
            tool_call_key(session, "record.get", &args),
            tool_call_key(session, "record.summarize", &args),
            "two tools must not share a key"
        );
        assert_ne!(
            tool_call_key(session, "record.get", &args),
            tool_call_key(session, "record.get", &json!({ "entity": "contact" })),
            "different arguments must not share a key"
        );
    }

    /// Key-order independence: a host that serialises an argument object in a
    /// different field order must still hit the same key, or every retry looks
    /// like a new call.
    #[test]
    fn the_idempotency_key_ignores_argument_key_order() {
        let session = Uuid::from_u128(1);
        let a: Value = serde_json::from_str(r#"{"entity":"account","record_id":"x"}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"record_id":"x","entity":"account"}"#).unwrap();
        assert_eq!(
            tool_call_key(session, "record.get", &a),
            tool_call_key(session, "record.get", &b)
        );
    }

    /// **The dark gate must survive re-export.** A refusal's message must not
    /// distinguish "unlicensed", "switched off", and "does not exist" — that
    /// distinction is exactly what D-010 refuses to leak, and a new protocol
    /// is a new opportunity to leak it.
    #[test]
    fn a_refusal_message_does_not_reveal_why() {
        let masked = sanitized(&AppError::NotFound);
        assert_eq!(masked, "unknown or unavailable");
        assert!(!masked.to_lowercase().contains("licen"));
        assert!(!masked.to_lowercase().contains("forbidden"));

        assert_eq!(
            sanitized(&AppError::Forbidden),
            "the request could not be completed",
            "a privilege refusal must not be distinguishable from any other failure"
        );
        assert_eq!(json_rpc_code(&AppError::Forbidden), code::INTERNAL);
    }

    /// Validation text reaches the caller, because it is actionable and
    /// contains no internal state.
    #[test]
    fn validation_errors_stay_actionable() {
        let error = AppError::Validation("entity is required".into());
        assert_eq!(sanitized(&error), "entity is required");
        assert_eq!(json_rpc_code(&error), code::INVALID_PARAMS);

        // D-502: a tool loop must be able to tell "retry later" from "failed".
        let in_progress =
            AppError::Conflict("an identical invocation of this tool call is already in progress");
        assert_eq!(
            sanitized(&in_progress),
            "an identical invocation of this tool call is already in progress"
        );
    }

    /// Only `tools` is advertised, so a conforming host never asks for a
    /// capability this surface does not implement.
    #[test]
    fn only_the_tools_capability_is_advertised() {
        let capabilities = server_capabilities();
        let object = capabilities.as_object().expect("an object");
        assert_eq!(object.len(), 1);
        assert!(object.contains_key("tools"));
    }

    /// **M1.7 / finding F-9.** The tool list is cached `private`, never
    /// `public`.
    ///
    /// `visible_to` filters by the caller's licence, privileges, session
    /// ceiling and allow-list, so two callers legitimately receive different
    /// lists. A shared intermediary caching one caller's list under a `public`
    /// scope would hand it to the next caller — a disclosure of what exists,
    /// which is precisely what the dark gate (D-010) spends its effort hiding.
    /// Asserted against the source rather than by calling `tools_list`, which
    /// needs a live session; the string is the whole contract.
    #[test]
    fn the_tool_list_is_cached_private_and_never_public() {
        let code = production_source();
        assert!(
            code.contains("\"cacheScope\": \"private\""),
            "tools/list must declare cacheScope private"
        );
        assert!(
            !code.contains("\"cacheScope\": \"public\""),
            "a public cache scope would let a shared cache serve one caller's \
             tool list to another"
        );
        // No assertion on the TTL's value: it is a `u64` constant declared two
        // screens up, so a runtime `> 0` check proves nothing a reader cannot
        // see, and clippy is right to refuse it. What matters is the scope
        // above, which a future edit genuinely could get wrong.
    }

    /// The protocol version is a fixed constant, never echoed from the
    /// client's request — see [`MCP_PROTOCOL_VERSION`].
    #[test]
    fn the_protocol_version_is_pinned() {
        assert!(!MCP_PROTOCOL_VERSION.is_empty());
        assert!(
            !production_source().contains("protocolVersion\"]"),
            "the server must not echo the client's requested protocol version"
        );
    }

    /// **The structural claim.** This module reaches executors only through
    /// `dispatch`, and builds contexts only through `for_session`. Both are
    /// the properties that make the surface a transport adapter rather than a
    /// second way into the platform.
    #[test]
    fn the_surface_dispatches_and_never_bypasses_the_gate() {
        let code = production_source();

        assert!(
            code.contains("execute::dispatch("),
            "must go through dispatch"
        );
        assert!(
            !code.contains("run_executor("),
            "must never reach an executor directly (I-4)"
        );
        assert!(
            !code.contains("dispatch_approved_agent_action("),
            "the approval-execution bypass is for the approval callback only"
        );
        assert!(
            code.contains("ActionContext::for_session("),
            "contexts must come from for_session so session taint is carried"
        );
        assert!(
            !code.contains("ActionContext::user("),
            "an MCP invocation is an agent invocation, never a user one — \
             Initiator::User would let a Consequential action auto-execute"
        );
    }
}
