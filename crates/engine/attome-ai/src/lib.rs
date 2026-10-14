//! `attome-ai` — the platform's one registry of typed, risk-classified,
//! permission-checked capabilities (D-360, invariant I-2).
//!
//! **The problem it exists to prevent.** Four modules need the same thing:
//! "invoke a capability as a principal with a known risk profile". The chatbot
//! needs it for tools, workflow nodes for graph steps, AI form fields for
//! suggestions, the dashboard for stored queries. Four catalogues would drift,
//! and the copy that drifts is the one that writes without a gate. The
//! realistic failure is not malice — it is a chatbot shipping "its own tool
//! list, temporarily".
//!
//! **The shape.**
//!
//! ```text
//! descriptor.rs   what an action IS — id, risk, effect, retry, module,
//!                 privileges. Constructible ONLY inside this crate.
//! actions/        the closed catalogue. New capability = code + release.
//! registry.rs     lookup and `visible_to` — license AND privilege AND
//!                 ceiling AND kill-switch.
//! telemetry.rs    the suggestion-outcome log (TODO-054) — unbackfillable,
//!                 which is why it ships with the first AI surface.
//! context.rs      who is invoking, on whose behalf, and whether the turn
//!                 carries tool-obtained text.
//! gate.rs         the decision, BEFORE dispatch, in Rust — never by prompt.
//! execute.rs      the Action trait and `dispatch` — the ONLY entry point,
//!                 and it gates before it runs.
//! decision.rs     M28 Phase 1 — `POST /decisions/{id}/execute`, the one
//!                 business action that runs a `dashboard_decision`'s chosen
//!                 option through `dispatch`. Lives here rather than in
//!                 `attome-dashboard` (which owns `dashboard_decision` itself and its
//!                 own `/decisions/{id}/approve`) — see that module's doc
//!                 comment for the dependency-cycle reasoning.
//! ```
//!
//! **What this crate deliberately does not own.** Prompts, templates, and
//! conversation state (`attome-ai`). Model transport (`attome-inference`). Approval
//! workflow (`attome-approval`, D-195 — there is exactly one four-eyes
//! primitive and this is not a second one).

/// This crate's advisory-lock namespace (D-351). Registered as id 25 in
/// `crates/server/tests/advisory_lock_namespaces.rs`, which is the one place
/// the ids are proven distinct. Every acquisition uses the two-argument form,
/// `pg_try_advisory_xact_lock($1, hashtext($2))`, binding this constant — the
/// one-argument form would put `"attome-ai/..."` keys back into one shared 32-bit
/// `hashtext` space with every other subsystem.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 25;

pub mod actions;
pub mod agent;
/// C10-B — deployment-wide chatbot figures (`/admin/ai/bot-analytics`).
pub mod analytics;
pub mod approval;
/// M101 slice 2 — the token budget, actually applied. `attome_inference::budget`
/// shipped with zero call sites; this is the one that gives it some.
pub mod budget_guard;
/// C6 (D-556) — capability packs: a named, versioned set of action ids a
/// policy references. Resolved once, at session start, into the same
/// `allowed_action_ids` snapshot a hand-picked list produces; nothing at
/// dispatch time reads a pack.
pub mod capability_pack;
/// C7 — the read projections the copilot panel renders (citations and
/// grounding, tool calls) and the record-context fold, over the C2 ledger.
pub mod chat_view;
pub mod comparison_report;
pub mod compliance_report;
/// C4 — the confirm round-trip: a human confirms a server-persisted agent
/// proposal, which then runs as that agent action (I-13, row A-41).
pub mod confirm;
pub mod context;
/// C11 B1 (P-1) — the context window: newest first, whole exchanges, bounded
/// by tokens, in native tool-call structure. Pure; `conversation` loads.
pub mod context_window;
/// C2 (D-552, I-12) — the durable conversational ledger: conversations,
/// the append-only message transcript, and the `context_messages` projection
/// that is the only thing permitted to shape model input from it (I-15).
pub mod conversation;
pub mod conversation_event;
/// C4 — the chat HTTP API over `conversation`, `turn` and `confirm`.
pub mod conversation_routes;
pub mod decision;
/// C11 B3 (P-3) — token deltas: transport-only `message.delta` over Redis
/// pub/sub, never persisted, never replayed, never on the public widget.
pub mod delta_stream;
pub mod descriptor;
pub mod engine;
pub mod eval_capture;
pub mod execute;
/// C10-B — thumbs feedback on a turn's answer.
pub mod feedback;
pub mod gate;
/// BIN-FX1 — the pooled generation client, built once per config.
pub mod inference_client;
/// M101 slice 2 — the Model Context Protocol surface over the existing
/// registry. A transport adapter: `tools/list` is `visible_to`, `tools/call`
/// is `dispatch`, and nothing is added to the closed catalogue (I-5).
pub mod mcp;
pub mod model_registry;
pub mod orchestrate;
pub mod outcome;
/// C11 B5 (P-5) — the runtime AI switch's audited admin routes. The read side
/// is `attome_core::ai_runtime_switch`.
pub mod output_filter;
pub mod pii_mask;
pub mod prompt;
pub mod prompt_preview;
pub mod prompt_registry;
/// The `ai_provider` record as this crate reads it, plus the API protocol
/// a provider speaks. A catalog with enough connection detail to enumerate a
/// provider's models — never a generation dispatch target (D-554, D-360
/// ruling 3).
pub mod provider;
/// The two bespoke provider routes: set/rotate the API key, list the models.
pub mod provider_admin;
/// `ai_provider_credential` (migration 0478) — the only place a provider
/// API key exists outside a request's own stack.
pub mod provider_credential;
/// The outbound "fetch available models" call, and the untrusted parse of what
/// comes back.
pub mod provider_models;
pub mod quality_monitor;
pub mod registry;
pub mod runtime_switch;
pub mod sanitize_input;
pub mod scope_switch;
pub mod session;
pub mod session_admin;
pub mod spend_report;
pub mod telemetry;
/// C2 (D-553, I-13) — the pending-proposal store. Holds the executable
/// payload a confirmation dispatches, and a claim/lease that is deliberately
/// NOT the concurrency control (that stays `session::claim_invocation`).
pub mod tool_call;
/// C3 (D-565) — the turn orchestrator: the loop that carries a model's tool
/// naming back and forth, as a state machine with twelve named terminal
/// states. Builds no tool list, checks no permission, counts no invocations,
/// and holds no transaction across inference.
pub mod turn;
/// C11 B4 (P-4) — Stop: a recorded request the turn loop honours at every
/// boundary, ending the turn as `Cancelled`.
pub mod turn_cancel;
/// C13.1 — the chatbot loop's Prometheus metrics (closed label sets only).
pub mod turn_metrics;
pub mod webchat;
pub mod write_guard;

pub use context::{ActionContext, Initiator};
pub use decision::DecisionExecutionModel;
pub use descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
pub use engine::ActionModel;
pub use execute::{Action, ActionOutcome, ActionResult, Executors, Provenance, dispatch};
pub use gate::{ConfirmReason, GateDecision, GateInputs, GateRefusal};
pub use outcome::OutcomeModel;
pub use registry::{ActionRegistry, VisibilityInputs};
pub use telemetry::{SuggestionOutcome, SuggestionRecord};

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `crates/server/src/openapi.rs`.
/// `engine::openapi()` covers `/actions`, `/actions/{id}/invoke`, and the
/// AI-suggestion outcome route; `decision::openapi_fragment()` adds M28
/// Phase 1's `/decisions/{id}/execute`; `agent::openapi_fragment()` adds M32
/// Phase 1's `/agents/{id}/sessions`; `session_admin::openapi_fragment()`
/// adds M33 Phase 1's `/admin/agents/sessions` supervisor dashboard read;
/// `outcome::openapi_fragment()` adds M97 Phase 1's `/admin/outcomes` +
/// `/admin/outcomes/summary` "proposals and their fates" reads;
/// `provider_admin::openapi_fragment()` adds the two bespoke AI-provider
/// routes (credential rotation and model discovery). Same
/// "top-level `openapi()` merges each submodule's fragment" convention
/// `attome_dashboard::openapi()` uses.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = engine::openapi();
    doc.merge(decision::openapi_fragment());
    doc.merge(agent::openapi_fragment());
    doc.merge(session_admin::openapi_fragment());
    doc.merge(outcome::openapi_fragment());
    // M101 slice 2 — `/api/v1/mcp`.
    doc.merge(mcp::openapi_fragment());
    // `/admin/ai/providers/{id}/credential` + `/models/fetch`.
    doc.merge(provider_admin::openapi_fragment());
    // C4 — `/ai/conversations…`, the chat HTTP API.
    doc.merge(conversation_routes::openapi_fragment());
    // C10-B — `/admin/ai/bot-analytics`.
    doc.merge(analytics::openapi_fragment());
    doc.merge(runtime_switch::openapi_fragment());
    doc.merge(scope_switch::openapi_fragment());
    doc.merge(spend_report::openapi_fragment());
    doc.merge(prompt_preview::openapi_fragment());
    doc.merge(eval_capture::openapi_fragment());
    doc
}

#[cfg(test)]
mod invariant_tests {
    use crate::descriptor::{Effect, RiskTier};
    use crate::registry::ActionRegistry;

    /// I-2, asserted structurally: nothing outside this crate can construct an
    /// `ActionDescriptor`, because it carries a private field and its only
    /// constructor is `pub(crate)`. This test documents the intent. The
    /// `action-registry-guard` CI grep that used to catch a workaround (e.g.
    /// making the field public in a later edit) was retired with CI, so this
    /// test is now the only thing standing behind the rule.
    #[test]
    fn the_registry_is_the_only_source_of_descriptors() {
        let registry = ActionRegistry::new();
        assert!(registry.all().count() > 0);
    }

    /// Every registered action's risk tier must be consistent with its effect.
    /// A `Write` or `External` effect classified as `Read` would sail straight
    /// through the gate's `(Read, _) => Execute` arm — the single most
    /// dangerous mistake a descriptor can contain, and one that looks
    /// completely ordinary in a diff.
    #[test]
    fn no_action_understates_its_risk_relative_to_its_effect() {
        for descriptor in ActionRegistry::new().all() {
            match descriptor.effect {
                Effect::Read => {}
                Effect::Write | Effect::External => assert!(
                    descriptor.risk > RiskTier::Read,
                    "{} has a side effect but is classified Read-tier, which \
                     makes it auto-execute for an agent",
                    descriptor.id
                ),
            }
        }
    }

    /// **M101 slice 3.** Every registered action declares a well-formed JSON
    /// Schema for its arguments, and that schema describes an object.
    ///
    /// This is the test that keeps `input_schema` from becoming fiction.
    /// Nothing in this workspace validates *arguments* against these schemas —
    /// there is no JSON Schema validator dependency and adding one is a
    /// separate decision — so the only thing standing between a published
    /// contract and a wrong one is that it must at minimum parse, describe an
    /// object, and enumerate properties. An action that forgets to declare one
    /// gets `UNDECLARED_SCHEMA` (the empty string) and fails here rather than
    /// shipping a tool nobody can call correctly.
    #[test]
    fn schemas_are_wellformed_and_describe_an_object() {
        for descriptor in ActionRegistry::new().all() {
            assert!(
                !descriptor.input_schema.is_empty(),
                "{} declares no input_schema — add `.input_schema(...)` to its \
                 descriptor",
                descriptor.id
            );

            let parsed: serde_json::Value = serde_json::from_str(descriptor.input_schema)
                .unwrap_or_else(|e| {
                    panic!("{}'s input_schema is not valid JSON: {e}", descriptor.id)
                });

            assert_eq!(
                parsed.get("type").and_then(|t| t.as_str()),
                Some("object"),
                "{}'s input_schema must describe an object — an action's args \
                 always arrive as a JSON object",
                descriptor.id
            );
            assert!(
                parsed.get("properties").is_some_and(|p| p.is_object()),
                "{}'s input_schema must carry a `properties` object, even when \
                 empty (use `descriptor::NO_ARGUMENTS`)",
                descriptor.id
            );

            // A `required` list naming a property that does not exist is the
            // most common hand-written-schema mistake, and it is invisible
            // without a validator.
            if let Some(required) = parsed.get("required").and_then(|r| r.as_array()) {
                let properties = parsed["properties"].as_object().expect("checked above");
                for name in required {
                    let name = name.as_str().unwrap_or_default();
                    assert!(
                        properties.contains_key(name),
                        "{}'s input_schema marks {name:?} required but does not \
                         define it under `properties`",
                        descriptor.id
                    );
                }
            }
        }
    }

    /// A `Read`-tier action must never require an idempotency key, and a
    /// non-idempotent action must never be cacheable. Both combinations are
    /// nonsense, and both would be silently wrong rather than loudly wrong.
    #[test]
    fn retry_and_cache_classifications_are_coherent() {
        use crate::descriptor::RetryClass;
        for descriptor in ActionRegistry::new().all() {
            if descriptor.risk == RiskTier::Read {
                assert_eq!(
                    descriptor.retry,
                    RetryClass::Idempotent,
                    "{} reads; replaying it must be safe",
                    descriptor.id
                );
            }
            if descriptor.cacheable {
                assert_eq!(
                    descriptor.retry,
                    RetryClass::Idempotent,
                    "{} is cacheable but not idempotent",
                    descriptor.id
                );
            }
        }
    }
}
