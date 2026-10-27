//! `EngineModel` registration and the HTTP surface.
//!
//! Two routes, both thin (guidelines §12: parse → call the engine → shape the
//! response). Neither contains a policy decision — every one of those lives in
//! [`crate::gate`], which `dispatch` calls before anything runs.
//!
//! The module bit is `MODULE_AI`, so the whole surface is dark on a deployment
//! that has not licensed AI. That is deliberately the *coarse* gate: an
//! individual action carries its own module bit too, and `record.get` belongs
//! to `MODULE_CORE`. Mounting the surface under AI and gating each action
//! independently means a deployment licensed for AI does not thereby gain
//! actions from modules it has not licensed.

use attome_config::AiSurface;
use attome_core::{EngineModel, EngineState};
use attome_modules::{MODULE_AI, ModuleId};
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, Privilege, RecordScoped, SelfService, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::comparison_report::{self, ComparisonFilter, ComparisonReport};
use crate::compliance_report::{self, ComplianceReport};
use crate::context::ActionContext;
use crate::execute::{ActionOutcome, Executors, dispatch};
use crate::gate::GateInputs;
use crate::prompt_registry::{self, DiffLine};
use crate::registry::{ActionRegistry, VisibilityInputs};
use crate::telemetry::{self, SuggestionOutcome};

#[derive(Debug)]
pub struct ActionModel;

/// Y4-T1: this engine's module manifest.
pub const MANIFEST: attome_core::module_manifest::ModuleManifest =
    attome_core::module_manifest::ModuleManifest {
        version: env!("CARGO_PKG_VERSION"),
        depends_on: &[],
        platform: attome_core::module_manifest::BUILT_IN_PLATFORM,
    };

impl EngineModel for ActionModel {
    fn manifest(&self) -> Option<attome_core::module_manifest::ModuleManifest> {
        Some(MANIFEST)
    }

    fn name(&self) -> &'static str {
        "attome-ai"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_AI
    }

    fn routes(&self) -> Router<EngineState> {
        // N9-T1: the agent kind checks an agent's tools against these ids.
        attome_model::kinds::agent::set_known_tools(
            REGISTRY.all().map(|descriptor| descriptor.id.0.to_owned()),
        );
        Router::new()
            .route("/api/v1/actions", get(list_invocable_actions))
            .route("/api/v1/actions/{id}/invoke", post(invoke_action))
            .route("/api/v1/actions/{name}", post(invoke_custom_action))
            .route("/api/v1/macros/{name}/preview", post(preview_macro))
            .route("/api/v1/macros/{name}/run", post(run_macro))
            // S1-T12: a record-bound action, invoked on one record.
            .route(
                "/api/v1/{entity}/{id}/actions/{name}",
                post(invoke_record_action),
            )
            .route(
                "/api/v1/ai/suggestions/{id}/outcome",
                post(record_suggestion_outcome),
            )
            // D-435 — the read-only prompt registry surface.
            .route("/api/v1/admin/ai/prompts", get(list_prompts))
            .route("/api/v1/admin/ai/prompts/diff", get(diff_prompts))
            // D-435 — the AI compliance report bundle.
            .route(
                "/api/v1/admin/ai/compliance-report",
                get(get_compliance_report),
            )
            // M96 Phase 1 — the on-demand model/prompt comparison report.
            .route(
                "/api/v1/admin/ai/model-comparison",
                get(get_model_comparison),
            )
            // M32 Phase 1 (D-450) — the session-from-definition route.
            // `agent::routes()` is its own small `Router` rather than
            // inlined here, the same "own file, merged in" shape
            // `crate::decision` uses for its one route (that module needs a
            // separate `EngineModel` for a license-bit reason this one does
            // not — `ai_agent` stays MODULE_AI like everything else on this
            // model).
            .merge(crate::agent::routes())
            // M33 Phase 1 (D-460) — the supervisor dashboard's one read.
            // `agent.pause`/`agent.resume`/`agent.kill` themselves need no
            // dedicated route: they dispatch through the generic
            // `/actions/{id}/invoke` above like every other action.
            .merge(crate::session_admin::routes())
            // M101 slice 2 — the MCP surface. Merged here rather than
            // mounted separately so it sits behind the identical
            // middleware stack and licence gate as every other action
            // route: an external protocol gets no special path in.
            .merge(crate::mcp::routes())
            // The two bespoke AI-provider routes (set/rotate the API key,
            // list the provider's models). Merged here for the same reason
            // the MCP surface is: they sit behind the identical middleware
            // stack and MODULE_AI licence gate as every other route on this
            // model. Ordinary provider CRUD is NOT here — creating a
            // provider, or editing its Provider ID, Display name, Base URL
            // or API protocol, is generic entity CRUD.
            .merge(crate::provider_admin::routes())
            // C4 — the chat HTTP API. Merged here so it sits behind the
            // identical middleware stack and MODULE_AI licence gate as every
            // other action route.
            .merge(crate::conversation_routes::routes())
            // AI4-T6 — follow-ups.
            .merge(crate::followup_routes::routes())
            // AI8-T3 — agent performance backfill, admin-gated.
            .merge(crate::agent_stats::routes())
            // AI8-T4 — agent performance, admin-gated.
            .merge(crate::agent_stats_routes::routes())
            .merge(crate::undo_routes::routes())
            .merge(crate::behaviour_routes::routes())
            .merge(crate::work_share_routes::routes())
            // AI5-T6 — collections promises and reminders.
            .merge(crate::collections_routes::routes())
            // AI6-T6 — meeting briefs and notes.
            .merge(crate::meeting::routes::routes())
            // C10-B — the chatbot analytics report, admin-gated.
            .merge(crate::analytics::routes())
            // C11 B5 — the runtime AI switch, admin-gated and audited.
            .merge(crate::runtime_switch::routes())
            .merge(crate::scope_switch::routes())
            // N24-T2 — the AI spend report, admin-gated.
            .merge(crate::spend_report::routes())
            // N28-T3 — what a model would receive, admin-only.
            .merge(crate::prompt_preview::routes())
            // N23-T3 — a bad answer becomes an eval case.
            .merge(crate::eval_capture::routes())
            // N23-T1 — run an eval suite against its agent.
            .merge(crate::eval_runner::routes())
            // N31-T2 — the AI status page.
            .merge(crate::ai_status::routes())
            // N14-T1 — agent cards and tasks for trusted partners.
            .merge(crate::a2a::routes())
            // N30-T5 — per-write approval policies, admin-only.
            .merge(crate::write_policy::routes())
            // AH8 — autonomy levels (admin-only) and the undo window.
            .merge(crate::autonomy::routes())
            .merge(crate::deferred::routes())
            // AH6 — trial report and go-live, admin-only.
            .merge(crate::trial::routes())
            // N29-T2 — AI evidence export, admin-only.
            .merge(crate::evidence::routes())
            // N13-T1 — outside MCP servers, admin-only.
            .merge(crate::mcp_client::routes())
    }

    // D-435, simplified by D-491 — `ai_model` (the AI Model catalog,
    // carrying its own `approval_status`; there is no separate approval
    // entity any more) is metadata-seeded by
    // `platform-bundles/attome-ai-model-catalog.json` (no Rust seed), so
    // generic CRUD on it (`/api/v1/ai_model`) must be gated on
    // MODULE_AI the same way this model's own routes above are (D-383).
    // `ai_agent` (M32 Phase 1, metadata-seeded by
    // `platform-bundles/attome-ai-agent.json`, applied from `boot.rs`) and
    // `ai_provider`/`ai_personality`/`ai_tone` join it for the
    // identical reason: without this, any of these entities' raw records
    // would stay readable/writable through the generic path on any license
    // holding only MODULE_CORE.
    fn owned_entities(&self) -> &'static [&'static str] {
        &[
            "ai_model",
            "ai_agent",
            // D-505 governance policy, metadata-seeded by the same
            // `platform-bundles/attome-ai-agent.json`.
            "ai_agent_policy",
            // C6 (D-556) capability packs, metadata-seeded by
            // `platform-bundles/attome-ai-capability-pack.json`. Same reason as
            // the policy: a raw record must not be readable/writable through
            // the generic path on a licence holding only MODULE_CORE.
            "ai_capability_pack",
            "ai_provider",
            "ai_personality",
            "ai_tone",
            // The AI agents' records: `platform-bundles/attome-ai-followup.json`,
            // `-collections`, `-meeting` and `-work-share`.
            "ai_followup_rule",
            "ai_collection_rule",
            "ai_payment_promise",
            "ai_meeting_brief",
            "ai_meeting_notes",
            "ai_work_measure",
        ]
    }
}

/// Registry and executor table, built once per process.
///
/// `LazyLock` rather than state: both are derived entirely from compile-time
/// data (the closed catalogue), so there is nothing per-deployment to
/// configure and nothing that can change at runtime — which is what "the
/// registry is closed" (I-5) means in practice.
///
/// `pub(crate)` — `crate::decision` (M28 Phase 1's `/decisions/{id}/execute`)
/// resolves a decision option's `action_id` against this same process-wide
/// registry rather than building its own, so a decision and `/actions/{id}/invoke`
/// can never disagree about what an action id resolves to.
pub(crate) static REGISTRY: std::sync::LazyLock<ActionRegistry> =
    std::sync::LazyLock::new(ActionRegistry::new);
pub(crate) static EXECUTORS: std::sync::LazyLock<Executors> =
    std::sync::LazyLock::new(Executors::new);

/// Which kill-switch surface, if any, gates an action in this module.
///
/// **Derived from the action's own module, not from the route.** An earlier
/// version passed `Some(AiSurface::Fields)` for everything reaching this
/// surface, which was wrong in a way that only shows up in a specific
/// deployment: `record.get` and `query.execute` are `MODULE_CORE`, and a
/// dashboard invoking a stored query is not an AI surface. Gating them on the
/// AI switch meant an operator turning AI off also broke structured reads that
/// have nothing to do with a model.
///
/// The gate's own `the_kill_switch_does_not_gate_a_non_ai_surface` test
/// already said `None` is the right answer for a non-AI caller; this is the
/// call site finally agreeing with it.
pub(crate) fn surface_for(module: ModuleId) -> Option<AiSurface> {
    (module.word == MODULE_AI.word && module.mask == MODULE_AI.mask).then_some(AiSurface::Fields)
}

/// Resolves the deployment's license + kill-switch state for this request.
///
/// `pub(crate)` — `crate::decision`'s execute route needs the identical
/// license/kill-switch computation `invoke_action` uses below, keyed off the
/// chosen option's own action module rather than this surface's `MODULE_AI`.
///
/// `ai` is `config AND runtime` (C11 B5): the runtime switch's snapshot, which
/// reads as all-off when it is stale — so a caller that uses this outside
/// `dispatch` refreshes it first (`ai_runtime_switch::refresh`).
pub(crate) fn gate_inputs<'a>(state: &'a EngineState, module: ModuleId) -> GateInputs<'a> {
    GateInputs {
        licensed: state.modules.load().has(module),
        ai: attome_core::ai_runtime_switch::effective(&state.base.config.inference.ai),
        surface: surface_for(module),
        // I-7's deployment-wide air-gap switch. `trd-engine`'s Phase 4 work
        // is the first real `Effect::External` consumer (indirectly — its
        // execution pipeline reads this same config field directly rather
        // than through `dispatch`, since automated order routing runs as
        // `Initiator::System`, which this crate's `Initiator` deliberately
        // does not have, I-3). See `SecuritySection::external_effects_enabled`
        // for the full reasoning.
        external_effects_enabled: state.base.config.security.external_effects_enabled,
    }
}

#[derive(Serialize, ToSchema)]
pub struct ActionSummary {
    pub id: String,
    pub description: String,
    pub risk: String,
    pub cacheable: bool,
    /// M101 slice 3 — the action's argument contract as a JSON Schema
    /// document, parsed rather than passed through as a string so a consumer
    /// reads structured JSON instead of re-parsing an escaped blob.
    ///
    /// Published, not enforced: validation lives in each executor (see
    /// `ActionDescriptor::input_schema`). This is what a tool-listing consumer
    /// — a model picking a tool, an agent-builder UI, an external tool
    /// protocol — needs in order to call an action correctly on the first try.
    ///
    /// `value_type = Object` is required, not cosmetic: `serde_json::Value` is
    /// a recursive enum, and letting utoipa derive an inline schema for it
    /// here overflowed even `main.rs`'s 64 MB schema-generation stack
    /// (`server --print-openapi` aborted with 0xC00000FD). Declaring it as a
    /// free-form object stops the recursion and is also the truthful
    /// description — a JSON Schema document is an arbitrary object.
    #[schema(value_type = Object)]
    pub input_schema: Value,
}

impl std::fmt::Debug for ActionSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionSummary").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct ActionListResponse {
    pub items: Vec<ActionSummary>,
}

impl std::fmt::Debug for ActionListResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionListResponse").finish_non_exhaustive()
    }
}

/// Lists the actions this caller may invoke.
///
/// Filtered by license, privilege, and the kill-switch — the same conditions
/// the gate applies to an invocation. A tool a caller can see but not invoke
/// wastes a turn for a model and misleads a human, so the list and the gate
/// must not disagree.
#[utoipa::path(
    get,
    path = "/api/v1/actions",
    tag = "action",
    responses(
        (status = 200, description = "Success", body = ActionListResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// Named `list_invocable_actions`, not `list_actions`: utoipa derives the
// operationId from the function name and `approval_admin` already owns
// `list_actions` (its four-eyes request list). Two operations sharing an id
// generate a duplicate TypeScript identifier and break the Angular build —
// which is how this was caught, and is the reason the name is deliberate
// rather than clumsy.
async fn list_invocable_actions(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<ActionListResponse>, AppError> {
    let action_ctx = ActionContext::user(ctx.into_inner());
    // C11 B5: what is listed honours the runtime AI switch, as the gate does.
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let license = state.modules.load();
    let is_licensed = |module: ModuleId| license.has(module);
    let inputs = VisibilityInputs {
        is_licensed: &is_licensed,
        ai: attome_core::ai_runtime_switch::effective(&state.base.config.inference.ai),
        surface_of: &surface_for,
        // Read from config, not hardcoded `false`. `visible_to`'s own doc
        // requires the list and the gate to agree — "a tool a model can see
        // but not invoke wastes a turn, and a tool it can invoke but cannot
        // see is a capability nobody audited" — and `gate_inputs` below has
        // always read this field. The literal `false` predated
        // `SecuritySection::external_effects_enabled` existing (it was
        // hardcoded at all three call sites until 2026-09-09) and was latent
        // only because no `Effect::External` action is registered yet: the
        // first one would have been invocable and invisible.
        external_effects_enabled: state.base.config.security.external_effects_enabled,
    };

    let items = REGISTRY
        .visible_to(&action_ctx, &inputs)
        .map(|d| ActionSummary {
            id: d.id.as_str().to_owned(),
            description: d.description.to_owned(),
            risk: format!("{:?}", d.risk),
            cacheable: d.cacheable,
            // `schemas_are_wellformed_and_describe_an_object` (lib.rs) proves
            // every registered schema parses, so this fallback is unreachable
            // in a build that passed its own tests. It is a permissive empty
            // object rather than `null` so a consumer's "read properties"
            // path never has to special-case a missing schema.
            input_schema: serde_json::from_str(d.input_schema).unwrap_or_else(|error| {
                tracing::error!(
                    action = %d.id,
                    %error,
                    "action input_schema is not valid JSON — serving an empty contract"
                );
                serde_json::json!({ "type": "object", "properties": {} })
            }),
        })
        .collect();
    Ok(Json(ActionListResponse { items }))
}

#[derive(Deserialize, ToSchema)]
pub struct InvokeRequest {
    /// The action's own arguments. Shape is per-action and validated by the
    /// executor, not here — a handler that understood every action's argument
    /// shape would be the business logic guidelines §12 keeps out of transport.
    #[serde(default)]
    pub args: Value,
    /// AH8: hold the action this many seconds (30 to 86400) before it runs,
    /// so it can be cancelled — the undo for an action that cannot be undone
    /// once it ran. Omit to run it now.
    #[serde(default)]
    pub undo_window_seconds: Option<u32>,
    /// AE1-T4: the person confirmed this invocation. A consequential action
    /// answers `confirmation_required` until it is called with this set.
    #[serde(default)]
    pub confirm: bool,
}

impl std::fmt::Debug for InvokeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvokeRequest").finish_non_exhaustive()
    }
}

/// Invokes an action as the calling human.
///
/// There is no way to invoke as anything else: `ActionContext::user` takes the
/// caller's own `SecurityContext` and there is no service-principal overload
/// (I-3). The agent path — which supplies a risk ceiling and a taint flag —
/// arrives with agent sessions (TODO-039) and goes through the same
/// `dispatch`.
#[utoipa::path(
    post,
    path = "/api/v1/actions/{id}/invoke",
    tag = "action",
    params(("id" = String, Path, description = "Action id, e.g. record.get")),
    request_body = InvokeRequest,
    responses(
        (status = 200, description = "Success", body = ActionOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown, unlicensed, or disabled action", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("dispatch -> the action's own executor"),
        "the mandatory Ai+Execute event `dispatch` writes is agent-attribution-gated \
         (ctx.is_agent(), C19/D-541 rule 4) and this route always invokes as the plain \
         calling human (ActionContext::user, see this fn's own doc comment) — never an \
         agent session — so that write never fires here; whatever the invoked action \
         itself mutates is audited by that action's own executor (e.g. a record write \
         goes through entity_crud)",
    )))),
)]
async fn invoke_action(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<String>,
    Json(body): Json<InvokeRequest>,
) -> Result<Json<ActionOutcome>, AppError> {
    // The descriptor's OWN module decides licensing, not this surface's — see
    // the module comment. An unknown id resolves to NotFound below, and the
    // module lookup for it is irrelevant.
    let module = REGISTRY.resolve(&id).map(|d| d.module).unwrap_or(MODULE_AI);
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = gate_inputs(&state, module);
    let mut action_ctx = ActionContext::person(ctx.into_inner(), body.confirm);
    if let Some(seconds) = body.undo_window_seconds {
        action_ctx = action_ctx.with_undo_window(seconds);
    }

    let outcome = dispatch(
        &state,
        &REGISTRY,
        &EXECUTORS,
        &id,
        &action_ctx,
        &inputs,
        &body.args,
    )
    .await?;
    Ok(Json(outcome))
}

/// AE1-T2: runs the published custom action `custom.{name}` as the calling
/// person. The arguments are checked against its input schema first (every
/// problem by field); a consequential action needs an `Idempotency-Key` (or
/// `x-idempotency-key`) header, which becomes the invocation's key, so a
/// retry with the same key never runs it twice. A completed action answers
/// 200; one that waits (a confirmation, an approval, an undo window) 202.
#[utoipa::path(
    post,
    path = "/api/v1/actions/{name}",
    tag = "action",
    params(
        ("name" = String, Path, description = "The custom action's name (its id without `custom.`)"),
        ("Idempotency-Key" = Option<String>, Header, description = "Required for a consequential action"),
        ("X-Confirm" = Option<String>, Header, description = "`true` once the person confirmed a consequential action; without it the action answers `confirmation_required`"),
    ),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "The action ran", body = ActionOutcome),
        (status = 202, description = "The action waits for a confirmation, an approval or its undo window", body = ActionOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks a privilege the action requires", body = ErrorResponse),
        (status = 404, description = "No published custom action by that name", body = ErrorResponse),
        (status = 422, description = "Arguments that do not fit the schema, or a missing Idempotency-Key", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("dispatch -> the custom action's flow"),
        "as /api/v1/actions/{id}/invoke: the route invokes as the calling human, never an \
         agent session, so dispatch's agent-gated Ai+Execute event never fires here; what the \
         custom action's flow changes is audited by the flow's own steps",
    )))),
)]
async fn invoke_custom_action(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    Json(args): Json<Value>,
) -> Result<(axum::http::StatusCode, Json<ActionOutcome>), AppError> {
    let id = format!("{}{}", crate::custom_action::ID_PREFIX, name.trim());
    let descriptor = crate::custom_action::descriptor(&id).ok_or(AppError::NotFound)?;
    let errors = crate::custom_action::validate_args(descriptor.input_schema, &args);
    if !errors.is_empty() {
        return Err(AppError::FieldValidation(errors));
    }
    let key = ["idempotency-key", "x-idempotency-key"]
        .iter()
        .find_map(|h| headers.get(*h))
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|k| !k.is_empty() && k.len() <= 200)
        .map(str::to_owned);
    if descriptor.risk == crate::descriptor::RiskTier::Consequential && key.is_none() {
        return Err(AppError::Validation(
            "a consequential action needs an Idempotency-Key header".into(),
        ));
    }
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = gate_inputs(&state, descriptor.module);
    let user = ctx.user_id;
    let confirmed = headers
        .get("x-confirm")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    let mut action_ctx = ActionContext::person(ctx.into_inner(), confirmed);
    action_ctx.idempotency_key = key.map(|k| format!("{id}:{user}:{k}"));
    let outcome = dispatch(
        &state,
        &REGISTRY,
        &EXECUTORS,
        &id,
        &action_ctx,
        &inputs,
        &args,
    )
    .await?;
    let status = if matches!(outcome, ActionOutcome::Completed { .. }) {
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::ACCEPTED
    };
    Ok((status, Json(outcome)))
}

/// Preview a macro
///
/// G6-T2: what running the macro on these records would do, step by step,
/// with each step's filled-in arguments and the problems found. Runs nothing.
#[utoipa::path(
    post,
    path = "/api/v1/macros/{name}/preview",
    tag = "action",
    params(("name" = String, Path, description = "The macro")),
    request_body = crate::macros::MacroRecords,
    responses(
        (status = 200, description = "The plan", body = crate::macros::MacroPreview),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No published macro by that name", body = ErrorResponse),
        (status = 422, description = "No records, or more than 200", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DryRun,
        None,
        "lists the steps a macro would run; runs and writes nothing",
    )))),
)]
async fn preview_macro(
    _ctx: Authorized<SelfService>,
    Path(name): Path<String>,
    Json(body): Json<crate::macros::MacroRecords>,
) -> Result<Json<crate::macros::MacroPreview>, AppError> {
    crate::macros::preview(name.trim(), &body.record_ids).map(Json)
}

/// Run a macro
///
/// G6-T2: runs the macro's steps on each record as the caller, through the
/// action gate; each step is held for the macro's undo window first, so it
/// can be cancelled. Each record's outcomes are listed.
#[utoipa::path(
    post,
    path = "/api/v1/macros/{name}/run",
    tag = "action",
    params(("name" = String, Path, description = "The macro")),
    request_body = crate::macros::MacroRecords,
    responses(
        (status = 200, description = "Each record's outcomes", body = crate::macros::MacroRun),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No published macro by that name", body = ErrorResponse),
        (status = 422, description = "No records, or more than 200", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("dispatch -> each step's own action"),
        "every step is an action dispatched as the calling human, audited by its own executor \
         (a record write through entity_crud), exactly as when the action is invoked alone",
    )))),
)]
async fn run_macro(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(name): Path<String>,
    Json(body): Json<crate::macros::MacroRecords>,
) -> Result<Json<crate::macros::MacroRun>, AppError> {
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let action_ctx = ActionContext::person(ctx.into_inner(), body.confirm);
    crate::macros::run(&state, &action_ctx, name.trim(), &body.record_ids)
        .await
        .map(Json)
}

/// S1-T12: whether an action works on one record: its arguments require
/// `entity` and `record_id`.
pub fn is_record_bound(input_schema: &str) -> bool {
    serde_json::from_str::<Value>(input_schema)
        .ok()
        .and_then(|schema| schema.get("required").and_then(Value::as_array).cloned())
        .is_some_and(|required| {
            ["entity", "record_id"]
                .iter()
                .all(|key| required.iter().any(|r| r == key))
        })
}

/// S1-T12: invokes a record-bound action on the record in the path, through
/// the same gate as `/api/v1/actions/{id}/invoke`; `entity` and `record_id`
/// come from the path and replace any in the body. An action that does not
/// work on one record answers 404 here.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/actions/{name}",
    tag = "action",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        ("name" = String, Path, description = "Action id, e.g. record.summarize"),
    ),
    request_body = InvokeRequest,
    responses(
        (status = 200, description = "Success", body = ActionOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "Unknown, unlicensed, disabled, or not a record action", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("dispatch -> the action's own executor"),
        "the same dispatch as POST /api/v1/actions/{id}/invoke, as the plain calling human; \
         whatever the action mutates is audited by its own executor",
    )))),
)]
async fn invoke_record_action(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity, id, name)): Path<(String, Uuid, String)>,
    Json(body): Json<InvokeRequest>,
) -> Result<Json<ActionOutcome>, AppError> {
    let descriptor = REGISTRY.resolve(&name).ok_or(AppError::NotFound)?;
    if !is_record_bound(descriptor.input_schema) {
        return Err(AppError::NotFound);
    }
    let module = descriptor.module;
    let mut args = match body.args {
        Value::Object(map) => map,
        Value::Null => serde_json::Map::new(),
        _ => return Err(AppError::Validation("args: an object".into())),
    };
    args.insert("entity".into(), Value::String(entity));
    args.insert("record_id".into(), Value::String(id.to_string()));
    attome_core::ai_runtime_switch::refresh(&state.base.db).await;
    let inputs = gate_inputs(&state, module);
    let action_ctx = ActionContext::person(ctx.into_inner(), body.confirm);
    let outcome = dispatch(
        &state,
        &REGISTRY,
        &EXECUTORS,
        &name,
        &action_ctx,
        &inputs,
        &Value::Object(args),
    )
    .await?;
    Ok(Json(outcome))
}

#[derive(Deserialize, ToSchema)]
pub struct SuggestionOutcomeRequest {
    /// `accepted` | `edited` | `rejected`. There is deliberately no `pending`:
    /// a decision cannot move a row back to undecided, which is what keeps an
    /// abandoned suggestion distinguishable from a rejected one.
    pub outcome: String,
    /// Required when `outcome = "edited"`, rejected otherwise — migration
    /// `0118`'s CHECK ties the two together in both directions.
    #[serde(default)]
    pub edit_distance: Option<i32>,
}

impl std::fmt::Debug for SuggestionOutcomeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuggestionOutcomeRequest")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct SuggestionOutcomeResponse {
    /// `false` when this decision was not the first one recorded. A
    /// double-submit from the UI must not overwrite an accept with a reject,
    /// so the first decision wins and the caller is told which theirs was.
    pub recorded: bool,
}

impl std::fmt::Debug for SuggestionOutcomeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuggestionOutcomeResponse")
            .finish_non_exhaustive()
    }
}

/// Records what the human did with a suggestion (TODO-054).
///
/// This is the unbackfillable half of the AI-fields stage: the outcome is the
/// only per-customer ground truth for generation quality that will ever exist.
#[utoipa::path(
    post,
    path = "/api/v1/ai/suggestions/{id}/outcome",
    tag = "action",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Telemetry,
        None,
        "the caller's accepted/edited/rejected verdict on their own AI suggestion, recorded once as a generation-quality signal; changes no record, access or configuration",
    )))),
    params(("id" = Uuid, Path, description = "The suggestion_id returned in the invocation's provenance")),
    request_body = SuggestionOutcomeRequest,
    responses(
        (status = 200, description = "Success", body = SuggestionOutcomeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn record_suggestion_outcome(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
    Json(body): Json<SuggestionOutcomeRequest>,
) -> Result<Json<SuggestionOutcomeResponse>, AppError> {
    let outcome = match (body.outcome.as_str(), body.edit_distance) {
        ("accepted", None) => SuggestionOutcome::Accepted,
        ("rejected", None) => SuggestionOutcome::Rejected,
        ("edited", Some(distance)) if distance >= 0 => SuggestionOutcome::Edited { distance },
        ("edited", None) => {
            return Err(AppError::Validation(
                "edit_distance is required when outcome is 'edited'".into(),
            ));
        }
        ("accepted" | "rejected", Some(_)) => {
            return Err(AppError::Validation(
                "edit_distance is only meaningful when outcome is 'edited'".into(),
            ));
        }
        ("edited", Some(_)) => {
            return Err(AppError::Validation(
                "edit_distance must not be negative".into(),
            ));
        }
        _ => {
            return Err(AppError::Validation(
                "outcome must be one of: accepted, edited, rejected".into(),
            ));
        }
    };

    // Owner-scoped: see `telemetry::record_outcome`. Someone else's suggestion
    // reads as `recorded: false`, indistinguishable from an already-decided one.
    let recorded = telemetry::record_outcome(&state.base.db, id, ctx.user_id, outcome).await?;
    Ok(Json(SuggestionOutcomeResponse { recorded }))
}

// ── D-435: the read-only prompt registry surface ───────────────────────────

#[derive(Serialize, ToSchema)]
struct PromptSummary {
    action_id: String,
    version: String,
    text: String,
}

#[derive(Serialize, ToSchema)]
struct PromptListResponse {
    items: Vec<PromptSummary>,
}

/// `GET /api/v1/admin/ai/prompts` — every prompt_version this build ships.
/// Admin-gated like every other admin-surface read in this workspace
/// (`security-model`'s documented convention: `attome-api/src/admin/` and
/// siblings require `system.admin` on every route including reads). Prompts
/// are code (see `prompt_registry.rs`'s doc comment) — this route is
/// deliberately read-only; there is no corresponding `POST`/`PUT`.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/prompts",
    tag = "action",
    responses(
        (status = 200, description = "Success", body = PromptListResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_prompts(_ctx: Authorized<Privilege<area::Ai>>) -> Json<PromptListResponse> {
    let items = prompt_registry::all_versions()
        .into_iter()
        .map(|p| PromptSummary {
            action_id: p.action_id.to_owned(),
            version: p.version.to_owned(),
            text: p.text,
        })
        .collect();
    Json(PromptListResponse { items })
}

#[derive(Deserialize, ToSchema)]
struct PromptDiffQuery {
    from: String,
    to: String,
}

#[derive(Serialize, ToSchema)]
struct PromptDiffResponse {
    from: String,
    to: String,
    lines: Vec<DiffLine>,
}

/// `GET /api/v1/admin/ai/prompts/diff?from=..&to=..` — a line diff between
/// two shipped prompt_versions.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/prompts/diff",
    tag = "action",
    params(
        ("from" = String, Query, description = "prompt_version to diff from"),
        ("to" = String, Query, description = "prompt_version to diff to"),
    ),
    responses(
        (status = 200, description = "Success", body = PromptDiffResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
        (status = 422, description = "Unknown prompt_version", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn diff_prompts(
    _ctx: Authorized<Privilege<area::Ai>>,
    Query(q): Query<PromptDiffQuery>,
) -> Result<Json<PromptDiffResponse>, AppError> {
    let lines = prompt_registry::diff(&q.from, &q.to)?;
    Ok(Json(PromptDiffResponse {
        from: q.from,
        to: q.to,
        lines,
    }))
}

// ── D-435: the AI compliance report bundle ──────────────────────────────────

/// `GET /api/v1/admin/ai/compliance-report` — models in use, their
/// approvals, token spend, acceptance rates, and outcomes recorded without
/// provenance. `system.admin`-gated: this bundles per-organization AI usage
/// and cost data, the same sensitivity class as the rest of `/admin/`.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/compliance-report",
    tag = "action",
    responses(
        (status = 200, description = "Success", body = ComplianceReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_compliance_report(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
) -> Result<Json<ComplianceReport>, AppError> {
    let report = compliance_report::build_report(&state.base.db).await?;
    Ok(Json(report))
}

// ── M96 Phase 1: the on-demand model/prompt comparison report ──────────────

/// `GET /api/v1/admin/ai/model-comparison?action=&model_id=&prompt_version=` —
/// acceptance/edit/reject rates with Wilson confidence intervals, per
/// `(action, model_id, prompt_version)` group. Every filter is optional and
/// independently applied, so a caller comparing two specific
/// `(model_id, prompt_version)` pairs for one action passes `action` alone
/// and reads both groups' rows out of the same response.
///
/// `system.admin`-gated, same sensitivity class as the compliance report
/// above — this bundles per-model, per-prompt usage data.
#[utoipa::path(
    get,
    path = "/api/v1/admin/ai/model-comparison",
    tag = "action",
    params(ComparisonFilter),
    responses(
        (status = 200, description = "Success", body = ComparisonReport),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks system.admin", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_model_comparison(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Ai>>,
    Query(filter): Query<ComparisonFilter>,
) -> Result<Json<ComparisonReport>, AppError> {
    let report = comparison_report::build_report(&state.base.db, &filter).await?;
    Ok(Json(report))
}

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `server::openapi::document`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_invocable_actions,
    invoke_action,
    invoke_custom_action,
    preview_macro,
    run_macro,
    invoke_record_action,
    record_suggestion_outcome,
    list_prompts,
    diff_prompts,
    get_compliance_report,
    get_model_comparison
))]
struct ApiDocFragment;

pub fn openapi() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod record_action_tests {
    use super::is_record_bound;

    /// S1-T12: only actions that take a record are offered on one.
    #[test]
    fn record_bound_actions_take_entity_and_record_id() {
        assert!(is_record_bound(
            r#"{"type":"object","required":["entity","record_id"],"properties":{}}"#
        ));
        assert!(is_record_bound(
            r#"{"type":"object","required":["entity","record_id","field"]}"#
        ));
        assert!(!is_record_bound(
            r#"{"type":"object","required":["entity"]}"#
        ));
        assert!(!is_record_bound(r#"{"type":"object"}"#));
        assert!(!is_record_bound("not json"));
    }
}
