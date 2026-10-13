//! `record.update_field` — the platform's first `Effect::Write` action (M98
//! Phase 1 "Autonomous remediation", D-448). Everything else the registry
//! offers today (`read.*`, `article.draft`, `graph.traverse`) either reads or
//! produces a draft nobody can retrieve; this one changes a field an
//! organisation is already relying on, so it carries every containment the
//! plan calls "the ladder": a descriptor-scoped allow-list, a hard refusal
//! for special-category data, per-session/per-action blast-radius caps, a
//! policy-decided approval record even on the auto-execute path, and a
//! revert path built from the same row the invocation ledger already writes.
//!
//! ## Two boundaries, not one
//!
//! `RiskTier::Reversible` (via [`crate::gate::evaluate`]) answers "may this
//! caller reach this action at all, and does it need to pause for a human
//! first" — the taint-degrade (I-10) already covers "an agent whose context
//! holds tool-obtained text must confirm before writing." The gate has no
//! notion of `args`, so it cannot answer a narrower question this action
//! needs answered: *which* fields. That is [`allowlist_permits`]'s job,
//! resolved from `ai.record_update_field_allowlist`
//! (`attome-core::setting_catalog`) — an admin-configured, deployment-scope
//! setting, consulted for **every** caller, not only an agent. The action is
//! scoped to this set by definition, the same way `article.draft` can only
//! ever set `lifecycle = "draft"` — not a privilege check, a property of what
//! the action is.
//!
//! ## A third boundary the descriptor cannot express at all
//!
//! Plan §5: *"any write to a `sensitive_special_category` field is
//! Consequential regardless of descriptor."* A descriptor is one static
//! `RiskTier` per action id — it cannot vary per invocation, so "this
//! specific field is special-category" can never be encoded there. The gate
//! has already run and returned `Execute` by the time this executor sees the
//! arguments, so [`sensitive_write_is_blocked`] enforces the escalation here,
//! for an agent caller only: a hard refusal, not a degrade to confirm-first
//! and not an approval request — `(Consequential, Agent)` never gets either
//! of those either (`gate.rs`'s own comment: "NEVER auto-executes... This arm
//! is the reason the whole file exists"), so this executor does not invent a
//! softer outcome for the one case the static gate cannot see coming. A
//! human's own invocation is unaffected: it goes through the ordinary
//! `has_field_write_grant` check `entity_mutation` already applies to every
//! sensitive field, the same as any other write that field's grant system
//! covers.
//!
//! ## Auto-approval is still an approval (plan §5)
//!
//! By the time this executor runs, the gate has already returned `Execute`
//! for `(Reversible, Agent)` — which only happens when the context is
//! **untainted** (a tainted one gets `ConfirmFirst` and never reaches an
//! executor at all, see `execute::dispatch`). So every agent-initiated write
//! that reaches this function is the "policy allows" half of the ladder, and
//! the plan is explicit that auto-execute must still leave a real approval
//! record, not merely a log line: [`submit_and_auto_approve`] submits a
//! `attome_approval` request with the acting human as `requested_by` and
//! immediately decides it as `attome_approval::POLICY_ACTOR_ID` — which
//! `attome_approval::decide`'s separation-of-duties check accepts, because the
//! policy actor's nil UUID is never equal to a real user id, so this is not
//! self-approval, it is a *different* actor deciding. The audit trail can
//! always answer "who decided this" with "policy", never with a blank actor
//! next to an executed write. `mark_executed` is best-effort after the
//! record actually changes — same posture `record.summarize`'s suggestion
//! logging takes (`read.rs`): the write already succeeded, so a bookkeeping
//! failure here degrades the approval trail rather than reporting a failure
//! for a request that in fact completed.
//!
//! ## Reversibility is a promise the platform now keeps structurally
//!
//! `execute::dispatch` writes `action_invocation` for every
//! completed `Effect::Write` action (REVIEW-2026-09-02 finding #9,
//! `crate::write_guard`'s module doc) — this executor no longer records its
//! own invocation. What it still owns: putting the field's prior value into
//! `result` before returning, since that JSONB is the only place "what it
//! was before" survives, and [`revert`] reads it back from nowhere else.

use std::future::Future;
use std::pin::Pin;

use attome_core::{DataClassification, EngineState};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

/// The action id.
pub const RECORD_UPDATE_FIELD: &str = "record.update_field";

/// `attome-core::setting_catalog`'s key for the `(entity, field)`
/// allow-list. Declared here too (rather than only in the catalogue) so a
/// reader of this file does not have to cross-reference to know what governs
/// it.
const ALLOWLIST_SETTING_KEY: &str = "ai.record_update_field_allowlist";

/// How many completed writes one agent session may make through this action
/// per UTC calendar day. Deliberately small: plan §8 states the first write
/// action is meant to be low-blast-radius by construction, not merely by
/// good behaviour — raising this should follow evidence of a real workload
/// hitting it, not a complaint that it is annoying in testing.
pub const DAILY_WRITE_CAP: i64 = 50;

/// Sliding-window per-session rate cap (`attome_cache::rate_limit::check`'s
/// fixed 60-second window) — the second, independent blast-radius control
/// plan §5 names alongside the daily cap. Bounds burst behaviour (a runaway
/// tool loop calling this repeatedly in one minute) that a daily count alone
/// would not catch until far more damage was already done.
pub const PER_MINUTE_RATE_CAP: i32 = 10;

/// `attome_approval` `action_type` for the auto-approval record described in
/// the module doc. Distinct from `crate::approval::ACTION_TYPE_PREFIX`
/// (`"attome-ai/invoke"`) deliberately: that prefix names a request still
/// awaiting a *human* decision (the `RequiresApproval` gate outcome), and
/// this one is decided by policy before anyone but the acting user ever sees
/// it — conflating the two action_type spaces would make an approver UI
/// unable to tell "waiting on you" from "already resolved by policy" without
/// reading the payload.
const AUTO_APPROVAL_ACTION_TYPE: &str = "attome-ai/policy-approved:record.update_field";

/// TTL between `submit` and the `decide` this executor issues moments later.
/// Short because nothing should ever observe this request in a pending
/// state — `submit`/`decide` run back to back in the same call — but must be
/// nonzero because `submit` requires a positive TTL.
const AUTO_APPROVAL_TTL_MINUTES: i64 = 5;

/// M101 slice 3 — the argument contract, mirroring ``Args``.
/// See `descriptor::UNDECLARED_SCHEMA` for why every action carries one, and
/// `lib.rs`'s `schemas_are_wellformed_and_describe_an_object` for what keeps
/// it honest.
const RECORD_UPDATE_FIELD_SCHEMA: &str = r#"{
  "type": "object",
  "properties": {
    "entity": { "type": "string", "description": "Entity logical name." },
    "record_id": { "type": "string", "format": "uuid", "description": "The record to update." },
    "field": { "type": "string", "description": "Logical name of the single field to set." },
    "value": {
      "description": "The new value. Shape follows the field's own type; validated by the entity engine, not here."
    },
    "row_version": {
      "type": "integer",
      "description": "The row_version the caller read. Optimistic concurrency: a stale value is rejected rather than overwriting a concurrent edit."
    }
  },
  "required": ["entity", "record_id", "field", "value", "row_version"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        RECORD_UPDATE_FIELD,
        "Set one field on a record you can already update, from an \
         administrator-configured allow-list of fields this action may \
         touch. Records the prior value so an operator can revert it. \
         Cannot write a special-category field, and cannot write a field \
         not on the allow-list, regardless of who or what calls it.",
        RiskTier::Reversible,
        Effect::Write,
        // Idempotent, not RequiresKey: replaying "set field F to value V"
        // produces the same stored value, not a duplicate row — unlike
        // `article.draft`'s non-deterministic generation, there is nothing
        // here for a retry to duplicate.
        RetryClass::Idempotent,
        attome_modules::MODULE_AI,
        &[],
    )
    .input_schema(RECORD_UPDATE_FIELD_SCHEMA)
}

/// The arguments a model (or any other caller) supplies. Strict, named
/// fields — same rationale as `read.rs`'s `RecordArgs`: a malformed or
/// hostile argument set fails at deserialisation, before any resolution.
#[derive(Deserialize)]
struct Args {
    entity: String,
    record_id: Uuid,
    field: String,
    value: Value,
    /// Mandatory, matching `update_record_for`'s own contract (guidelines
    /// §2's If-Match preservation) — there is no version-less write path
    /// here any more than there is one over HTTP.
    row_version: i64,
}

fn parse_args(args: &Value) -> Result<Args, AppError> {
    serde_json::from_value(args.clone())
        .map_err(|e| AppError::Validation(format!("invalid action arguments: {e}")))
}

/// Whether `allowlist` (the resolved `ai.record_update_field_allowlist`
/// setting value, `{"<entity>": ["<field>", ...]}`) names this `(entity,
/// field)` pair. A pure function so the JSON-shape handling — an entity
/// absent from the map, a non-array value, a non-string element — is
/// testable without a database or a settings snapshot.
pub(crate) fn allowlist_permits(allowlist: &Value, entity: &str, field: &str) -> bool {
    allowlist
        .get(entity)
        .and_then(Value::as_array)
        .is_some_and(|fields| fields.iter().any(|f| f.as_str() == Some(field)))
}

/// Plan §5's escalation, decided purely: a special-category field is refused
/// for an agent regardless of the descriptor's own `Reversible` tier. Never
/// blocks a human's own invocation here — that caller is already subject to
/// the ordinary per-field write-grant check every sensitive field goes
/// through (`SecurityContextExt::has_field_write_grant`, D-141), enforced by
/// `entity_mutation` itself.
pub(crate) fn sensitive_write_is_blocked(
    is_agent: bool,
    classification: DataClassification,
) -> bool {
    is_agent && classification == DataClassification::SensitiveSpecialCategory
}

#[derive(Debug)]
pub struct RecordUpdateField;

impl Action for RecordUpdateField {
    fn id(&self) -> ActionId {
        ActionId(RECORD_UPDATE_FIELD)
    }

    fn execute<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let args = parse_args(args)?;

            // 1. The privilege check the HTTP extractor would perform for a
            // human caller — `update_record_for` deliberately does not do it
            // itself (see its own doc comment), same reasoning
            // `draft_article.rs` states for `create`.
            ctx.security.require(&args.entity, "update")?;

            // 2. The action's own scope: a pair not on the allow-list does
            // not exist as far as this action is concerned, for ANY caller.
            let allowlist_descriptor = attome_core::setting_registry()
                .get(ALLOWLIST_SETTING_KEY)
                .ok_or_else(|| {
                AppError::internal("record.update_field allow-list setting is not registered")
            })?;
            let (allowlist_value, _source) =
                state
                    .settings
                    .load()
                    .resolve(allowlist_descriptor, None, None);
            if !allowlist_permits(&allowlist_value, &args.entity, &args.field) {
                return Err(AppError::Forbidden);
            }

            // 3. Plan §5's escalation: a special-category field refuses an
            // agent outright, regardless of the descriptor's own Reversible
            // tier. Metadata is read and the classification copied out
            // before any `.await` below touches the arc-swap guard.
            let classification = {
                let registry = state.entities.load();
                let entity_meta = registry.get(&args.entity).ok_or(AppError::NotFound)?;
                let attr = entity_meta
                    .attrs
                    .iter()
                    .find(|a| a.logicalname == args.field)
                    .ok_or_else(|| {
                        AppError::Validation(format!(
                            "{} has no field named {}",
                            args.entity, args.field
                        ))
                    })?;
                attr.data_classification
            };
            if sensitive_write_is_blocked(ctx.is_agent(), classification) {
                return Err(AppError::Forbidden);
            }

            // 4. Blast-radius caps — agent invocations only. An agent
            // context with no session id cannot have its blast radius
            // bounded at all, so it is refused rather than treated as
            // uncapped (the DB CHECK `action_invocation_agent_needs_session`
            // would refuse the ledger write below anyway; refusing here is
            // the same answer without a failed insert to discover it by).
            if ctx.is_agent() {
                let Some(id) = ctx.agent_session_id else {
                    return Err(AppError::Forbidden);
                };
                crate::write_guard::enforce_write_caps(
                    state,
                    id,
                    RECORD_UPDATE_FIELD,
                    DAILY_WRITE_CAP,
                    PER_MINUTE_RATE_CAP,
                )
                .await?;
            }

            // 5. The prior value — read through the same gated path a plain
            // read would use, both because that is the reusable primitive
            // (guidelines §9) and because it doubles as the caller's own
            // visibility check on the field being changed.
            let record = attome_records::entity_crud::read_record_bulk(
                state,
                &ctx.security,
                &args.entity,
                args.record_id,
            )
            .await?;
            let prior_value = record
                .data()
                .get(&args.field)
                .cloned()
                .unwrap_or(Value::Null);

            // 6. Auto-approval bookkeeping (module doc's "auto-approval is
            // still an approval") — agent only. A human's own Reversible
            // write needs no policy decision; there is no policy standing in
            // for anyone, they decided it themselves.
            let approval = if ctx.is_agent() {
                let payload = serde_json::json!({
                    "action_id": RECORD_UPDATE_FIELD,
                    "entity": args.entity,
                    "record_id": args.record_id,
                    "field": args.field,
                    "prior_value": prior_value,
                    "new_value": args.value,
                });
                Some(
                    crate::write_guard::submit_and_auto_approve(
                        state,
                        AUTO_APPROVAL_ACTION_TYPE,
                        ctx.security.user_id,
                        payload,
                        AUTO_APPROVAL_TTL_MINUTES,
                    )
                    .await?,
                )
            } else {
                None
            };

            // 7. The write itself, through the same primitive the HTTP PATCH
            // route uses — never route-local SQL (guidelines §9).
            let body = serde_json::json!({ args.field.clone(): args.value.clone() });
            let response = attome_records::entity_crud::update_record_for(
                state,
                &ctx.security,
                ctx.security.user_id,
                &args.entity,
                args.record_id,
                args.row_version,
                body,
            )
            .await?;

            // 8. Close the approval out. Best-effort — see
            // `write_guard::close_auto_approval`'s own doc comment.
            let approval_id = approval.map(|(id, _)| id);
            if let Some((id, row_version)) = approval {
                crate::write_guard::close_auto_approval(state, id, row_version).await;
            }

            // The invocation ledger row (with `revertible`) is now written
            // centrally by `execute::dispatch` for every completed
            // `Effect::Write` action — see that function and this file's
            // module doc. `prior_value` rides in `result_value` below
            // exactly as before, so `revert` still finds it there.
            let result_value = serde_json::json!({
                "record_id": args.record_id,
                "entity": args.entity,
                "field": args.field,
                "prior_value": prior_value,
                "new_value": args.value,
                "row_version": response.row_version(),
                "approval_id": approval_id,
            });

            Ok(ActionResult::plain(result_value))
        })
    }
}

/// What was actually recorded for a completed `record.update_field`
/// invocation — [`revert`]'s only source for "what was it before".
#[derive(Deserialize)]
struct RecordedWrite {
    entity: String,
    record_id: Uuid,
    field: String,
    prior_value: Value,
}

/// Restores the field a completed `record.update_field` invocation changed,
/// back to the value it recorded as `prior_value`. Plan §4/§5's "reversible
/// must be real, revert path" requirement.
///
/// Deliberately **not** routed through `gate::evaluate`/`execute::dispatch`:
/// this is an operator restoring a write after the fact, not a model
/// choosing to invoke a capability, so there is no risk tier to gate and no
/// taint to consider — the one check that still applies is the caller's own
/// privilege on the target entity, performed exactly as the original write's
/// executor performed it. Mounting this behind an admin HTTP route with its
/// own `Authorized<...>` extractor is a natural follow-up; it is not part of
/// this Phase 1 slice, which the plan scopes to the action and its revert
/// mechanism, not a new admin surface.
pub async fn revert(
    state: &EngineState,
    ctx: &SecurityContext,
    acting_user_id: Uuid,
    invocation_id: Uuid,
) -> Result<Value, AppError> {
    let row: Option<(String, String, Option<Value>)> =
        sqlx::query_as("SELECT action_id, outcome, result FROM action_invocation WHERE id = $1")
            .bind(invocation_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (action_id, outcome, result) = row.ok_or(AppError::NotFound)?;

    if action_id != RECORD_UPDATE_FIELD {
        return Err(AppError::Validation(
            "this invocation is not a record.update_field write".to_string(),
        ));
    }
    if outcome != "completed" {
        return Err(AppError::Conflict(
            "this invocation did not complete and has nothing to revert",
        ));
    }
    let result = result.ok_or_else(|| {
        AppError::internal("a completed record.update_field invocation has no recorded result")
    })?;
    let recorded: RecordedWrite = serde_json::from_value(result).map_err(|e| {
        AppError::internal(format!(
            "stored record.update_field invocation result did not parse: {e}"
        ))
    })?;

    // Same privilege the original write required — an operator reverting a
    // write still needs to be able to update the entity themselves.
    ctx.require(&recorded.entity, "update")?;

    // The record's row_version has moved on since the write this reverts;
    // CAS against what it is NOW, not the version captured back then.
    let current =
        attome_records::entity_crud::read_record(state, ctx, &recorded.entity, recorded.record_id)
            .await?;

    let body = serde_json::json!({ recorded.field.clone(): recorded.prior_value.clone() });
    let reverted = attome_records::entity_crud::update_record_for(
        state,
        ctx,
        acting_user_id,
        &recorded.entity,
        recorded.record_id,
        current.row_version(),
        body,
    )
    .await?;

    serde_json::to_value(reverted)
        .map_err(|e| AppError::internal(format!("reverted record serialization failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── The write ladder's own descriptor shape ─────────────────────────

    #[test]
    fn the_descriptor_is_reversible_write_idempotent() {
        let d = descriptor();
        assert_eq!(d.risk, RiskTier::Reversible);
        assert_eq!(d.effect, Effect::Write);
        assert_eq!(d.retry, RetryClass::Idempotent);
    }

    // ── allowlist_permits: pure, no database ────────────────────────────

    #[test]
    fn an_empty_allowlist_permits_nothing() {
        assert!(!allowlist_permits(
            &serde_json::json!({}),
            "account",
            "status"
        ));
    }

    #[test]
    fn the_allowlist_is_exact_per_entity_and_field() {
        let allowlist = serde_json::json!({ "account": ["status", "credit_limit"] });
        assert!(allowlist_permits(&allowlist, "account", "status"));
        assert!(allowlist_permits(&allowlist, "account", "credit_limit"));
        assert!(!allowlist_permits(&allowlist, "account", "name"));
        assert!(
            !allowlist_permits(&allowlist, "contact", "status"),
            "a field allowed on one entity must not leak to another"
        );
    }

    #[test]
    fn a_malformed_allowlist_shape_permits_nothing_rather_than_panicking() {
        // Wrong type at every level a hostile or corrupted setting value
        // could take.
        assert!(!allowlist_permits(
            &serde_json::json!("account"),
            "account",
            "status"
        ));
        assert!(!allowlist_permits(
            &serde_json::json!({ "account": "status" }),
            "account",
            "status"
        ));
        assert!(!allowlist_permits(
            &serde_json::json!({ "account": [1, 2, 3] }),
            "account",
            "status"
        ));
        assert!(!allowlist_permits(&Value::Null, "account", "status"));
    }

    // ── sensitive_write_is_blocked: pure, no database ───────────────────

    #[test]
    fn a_special_category_field_is_blocked_for_an_agent() {
        assert!(sensitive_write_is_blocked(
            true,
            DataClassification::SensitiveSpecialCategory
        ));
    }

    #[test]
    fn a_special_category_field_is_not_blocked_here_for_a_human() {
        // Not because it is unguarded — `has_field_write_grant` (D-141)
        // already covers a human's own write to a sensitive field. This
        // function only encodes the AGENT-specific escalation plan §5 adds
        // on top of that.
        assert!(!sensitive_write_is_blocked(
            false,
            DataClassification::SensitiveSpecialCategory
        ));
    }

    #[test]
    fn an_agent_writing_a_general_field_is_not_blocked_by_this_check() {
        assert!(!sensitive_write_is_blocked(
            true,
            DataClassification::General
        ));
    }

    // ── The action id is what the constant says it is ───────────────────

    #[test]
    fn the_action_id_matches_the_constant() {
        assert_eq!(RecordUpdateField.id(), ActionId(RECORD_UPDATE_FIELD));
    }

    // ── The two gate-level negative paths, against THIS action's real
    // descriptor rather than a synthetic one — `gate.rs`'s own suite already
    // proves the general rule; these pin the real registered action to it,
    // the same way `gate.rs::a_reversible_agent_write_degrades_to_confirm_first_on_a_tainted_context`
    // pins the general rule. No database needed —
    // both are pure evaluations against `gate`/`registry`. ──

    /// **Negative path (I-10).** An agent invoking `record.update_field`
    /// with tool-obtained text in context does not auto-execute — it
    /// degrades to confirm-first, and nothing has run.
    #[test]
    fn agent_reversible_tainted_degrades_to_confirm_first() {
        use crate::context::ActionContext;
        use crate::context::tests::security_context;
        use crate::gate::{self, ConfirmReason, GateDecision, GateInputs};
        use attome_config::AiEnablement;

        let d = descriptor();
        let ai = AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        };
        let inputs = GateInputs {
            licensed: true,
            ai: &ai,
            surface: None,
            external_effects_enabled: false,
        };

        let clean = ActionContext::agent(security_context(), RiskTier::Reversible);
        assert_eq!(
            gate::evaluate(&d, &clean, &inputs),
            Ok(GateDecision::Execute),
            "an untainted agent invocation must auto-execute — this is the \
             case that then goes on to submit_and_auto_approve"
        );

        let tainted = clean.tainted();
        assert_eq!(
            gate::evaluate(&d, &tainted, &inputs),
            Ok(GateDecision::ConfirmFirst {
                reason: ConfirmReason::RetrievedContentInContext
            }),
            "record.update_field is exactly the write I-10 exists to protect: \
             tool-obtained text in context must degrade it to confirm-first"
        );
    }

    /// **Negative path.** With the AI kill-switch off, `record.update_field`
    /// is absent from the visible set entirely — not listed-and-refused.
    #[test]
    fn kill_switch_makes_record_update_field_invisible() {
        use crate::context::ActionContext;
        use crate::context::tests::security_context;
        use crate::registry::{ActionRegistry, VisibilityInputs};
        use attome_config::{AiEnablement, AiSurface};

        let registry = ActionRegistry::new();
        let off = AiEnablement::default();
        let licensed = |_: attome_modules::ModuleId| true;
        let surface_of = |_: attome_modules::ModuleId| Some(AiSurface::Fields);
        let ctx = ActionContext::user(security_context());

        let visible: Vec<_> = registry
            .visible_to(
                &ctx,
                &VisibilityInputs {
                    is_licensed: &licensed,
                    ai: &off,
                    surface_of: &surface_of,
                    external_effects_enabled: false,
                },
            )
            .map(|d| d.id.as_str())
            .collect();
        assert!(
            !visible.contains(&RECORD_UPDATE_FIELD),
            "record.update_field must be invisible with the kill-switch off, \
             not merely un-invocable"
        );
    }
}
