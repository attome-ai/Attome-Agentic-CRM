//! The one registry (invariant I-2).
//!
//! Four modules need "invoke a capability as a principal with a known risk
//! profile": the chatbot, workflow nodes, AI form fields, and the dashboard.
//! Four catalogues would drift, and the copy that drifts is the one that
//! writes without a gate. So there is one, it is closed (I-5 — new capability
//! means a code change and a release, exactly like `node_types.rs:3-5`), and
//! `ActionDescriptor` cannot be constructed outside this crate.

use std::collections::BTreeMap;

use crate::descriptor::{ActionDescriptor, ActionId};

/// Every action the build knows about, in id order.
///
/// `BTreeMap`, not `HashMap`: the visible-tool list handed to a model must be
/// stable across processes and restarts. A set of tools whose order changes
/// per process makes a model's behaviour non-reproducible and makes an
/// injection fixture's "tool selection is unchanged" assertion meaningless.
pub struct ActionRegistry {
    actions: BTreeMap<ActionId, ActionDescriptor>,
}

impl std::fmt::Debug for ActionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionRegistry").finish_non_exhaustive()
    }
}

impl ActionRegistry {
    /// Builds the registry from the crate's own action modules. There is no
    /// `insert` and no `register` — a consumer cannot add to it, which is what
    /// "closed" means.
    pub fn new() -> Self {
        let mut actions = BTreeMap::new();
        for descriptor in crate::actions::all() {
            let previous = actions.insert(descriptor.id, descriptor.clone());
            debug_assert!(
                previous.is_none(),
                "duplicate action id {} — the second registration would \
                 silently shadow the first, including its risk tier",
                descriptor.id
            );
        }
        Self { actions }
    }

    pub fn get(&self, id: ActionId) -> Option<&ActionDescriptor> {
        self.actions.get(&id)
    }

    /// Looks up by a runtime string — the ONLY place one is accepted, and it
    /// resolves against the closed set rather than constructing an id.
    ///
    /// This is the boundary invariant I-9 rests on for tool dispatch: a model
    /// names a tool, and either it matches a registered action or nothing
    /// happens. A model cannot invent a capability by naming one.
    ///
    /// AE1-T1: after the built-in actions, the published custom actions
    /// (`crate::custom_action`, ids `custom.<name>`, never a built-in id).
    pub fn resolve(&self, id: &str) -> Option<&ActionDescriptor> {
        self.builtin(id)
            .or_else(|| crate::custom_action::descriptor(id))
    }

    /// A built-in action only.
    pub fn builtin(&self, id: &str) -> Option<&ActionDescriptor> {
        self.actions
            .values()
            .find(|descriptor| descriptor.id.as_str() == id)
    }

    /// Every action: the built-in ones in id order, then the published
    /// custom ones (AE1-T1).
    pub fn all(&self) -> impl Iterator<Item = &ActionDescriptor> {
        let custom: Vec<&ActionDescriptor> = crate::custom_action::descriptors();
        self.actions.values().chain(custom)
    }

    /// The ids of every action that counts against `class` (AH4-T2).
    pub fn ids_of_class(&self, class: crate::descriptor::LimitClass) -> Vec<String> {
        self.all()
            .filter(|descriptor| descriptor.limit_class() == class)
            .map(|descriptor| descriptor.id.0.to_owned())
            .collect()
    }

    /// The set a given caller may see, in a given situation.
    ///
    /// Filtered by **license AND privilege AND (for an agent façade) risk
    /// ceiling AND the kill-switch** — the same four conditions the gate
    /// enforces, applied to the list rather than to one invocation. They have
    /// to agree: a tool a model can see but not invoke wastes a turn and
    /// teaches the model that refusals are normal, and a tool it can invoke
    /// but cannot see is a capability nobody audited.
    ///
    /// The gate still runs on invocation. This is not a substitute for it —
    /// `visible_to` shapes what is offered, `gate::evaluate` decides what
    /// happens.
    pub fn visible_to<'a>(
        &'a self,
        ctx: &'a crate::context::ActionContext,
        inputs: &'a VisibilityInputs<'a>,
    ) -> impl Iterator<Item = &'a ActionDescriptor> {
        self.all().filter(move |descriptor| {
            let gate_inputs = crate::gate::GateInputs {
                licensed: (inputs.is_licensed)(descriptor.module),
                ai: inputs.ai,
                // Per-descriptor, like the license check beside it: which
                // kill-switch surface applies depends on the ACTION's module,
                // not on which façade is asking. A core structured read is not
                // an AI surface even when an AI façade invokes it.
                surface: (inputs.surface_of)(descriptor.module),
                external_effects_enabled: inputs.external_effects_enabled,
            };
            // A descriptor is visible when the gate would not REFUSE it.
            // ConfirmFirst and RequiresApproval are still visible: an action
            // the human must confirm is one they can be offered.
            //
            // Except one refusal, which is about the INVOCATION, not about the
            // action: `IdempotencyKeyRequired` (gate step 5) refuses an agent
            // call to a `RequiresKey` action that arrives without a key. A
            // tool list is built before any call exists, from a context with
            // no key, and every surface that dispatches attaches one per call
            // (`turn::run` the provider's `tool_call_id`, MCP `tools/call` its
            // `tool_call_key`). Treating that refusal as "not offered" hid every
            // `RequiresKey` action — record.create/update/restore,
            // workflow.start, bot.handoff — from the chat model and from MCP
            // `tools/list`. The gate still refuses a keyless invocation.
            match crate::gate::evaluate(descriptor, ctx, &gate_inputs) {
                Ok(_) => true,
                // Step 5 runs after every admissibility check (licence,
                // surface, allow-list, privilege, ceiling), so reaching it
                // means the action is admissible for this caller.
                Err(crate::gate::GateRefusal::IdempotencyKeyRequired) => true,
                Err(_) => false,
            }
        })
    }
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// What `visible_to` needs from the deployment. Separate from
/// `GateInputs` only because the license check is per-descriptor here and
/// per-invocation there.
pub struct VisibilityInputs<'a> {
    pub is_licensed: &'a dyn Fn(attome_modules::ModuleId) -> bool,
    pub ai: &'a attome_config::AiEnablement,
    /// Which kill-switch surface gates an action in a given module, or `None`
    /// when that module is not an AI surface at all. A function rather than a
    /// value so one listing can hold actions from several modules — see the
    /// comment at the call site above.
    pub surface_of: &'a dyn Fn(attome_modules::ModuleId) -> Option<attome_config::AiSurface>,
    pub external_effects_enabled: bool,
}

impl std::fmt::Debug for VisibilityInputs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisibilityInputs").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ActionContext, tests::security_context};
    use crate::descriptor::RiskTier;
    use attome_config::{AiEnablement, AiSurface};

    /// AH4-T2: record writes, deletes and reads land in their classes.
    #[test]
    fn actions_fall_into_their_limit_classes() {
        use crate::descriptor::LimitClass;
        let registry = ActionRegistry::new();
        let class = |id: &str| {
            registry
                .resolve(id)
                .map(|d| d.limit_class())
                .unwrap_or_else(|| panic!("{id} is registered"))
        };
        assert_eq!(class("record.delete"), LimitClass::Delete);
        assert_eq!(class("record.update"), LimitClass::RecordChange);
        assert_eq!(class("record.get"), LimitClass::None);
        let deletes = registry.ids_of_class(LimitClass::Delete);
        assert!(deletes.contains(&"record.delete".to_owned()));
        assert!(!deletes.contains(&"record.update".to_owned()));
        // Every action that sends a person a message counts as one.
        for id in [
            "email.send",
            "followup.send_message",
            "collections.send_reminder",
            "lead.send_message",
        ] {
            assert_eq!(class(id), LimitClass::MessageSend, "{id}");
        }
    }

    fn all_on() -> AiEnablement {
        AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        }
    }

    /// Treats EVERY module as an AI surface, so the kill-switch tests below
    /// still exercise it. Production derives this from the module
    /// (`engine::surface_for`); a test that used the production mapping would
    /// silently stop testing the switch the moment an action moved to a
    /// non-AI module.
    fn all_ai(_: attome_modules::ModuleId) -> Option<AiSurface> {
        Some(AiSurface::Fields)
    }

    fn visibility<'a>(
        ai: &'a AiEnablement,
        licensed: &'a dyn Fn(attome_modules::ModuleId) -> bool,
    ) -> VisibilityInputs<'a> {
        VisibilityInputs {
            is_licensed: licensed,
            ai,
            surface_of: &all_ai,
            external_effects_enabled: false,
        }
    }

    #[test]
    fn the_registry_is_not_empty_and_has_no_duplicate_ids() {
        let registry = ActionRegistry::new();
        let ids: Vec<_> = registry.all().map(|d| d.id).collect();
        assert!(
            !ids.is_empty(),
            "the registry must register its own actions"
        );
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len(), "duplicate action id");
    }

    /// Iteration order must be stable — a model's tool list cannot reshuffle
    /// per process.
    #[test]
    fn iteration_order_is_stable() {
        let first: Vec<_> = ActionRegistry::new().all().map(|d| d.id).collect();
        let second: Vec<_> = ActionRegistry::new().all().map(|d| d.id).collect();
        assert_eq!(first, second);
        let mut sorted = first.clone();
        sorted.sort();
        assert_eq!(first, sorted, "the tool list must be deterministic");
    }

    /// A model naming a tool that does not exist resolves to nothing. It
    /// cannot invent a capability.
    #[test]
    fn resolving_an_unknown_id_yields_nothing() {
        let registry = ActionRegistry::new();
        assert!(registry.resolve("record.drop_table").is_none());
        assert!(registry.resolve("").is_none());
    }

    /// Unlicensed → not in the visible set at all. Not greyed out, not
    /// listed-and-refused: absent.
    #[test]
    fn an_unlicensed_module_contributes_nothing_to_the_visible_set() {
        let registry = ActionRegistry::new();
        let ai = all_on();
        let ctx = ActionContext::user(security_context());

        let none_licensed = |_: attome_modules::ModuleId| false;
        assert_eq!(
            registry
                .visible_to(&ctx, &visibility(&ai, &none_licensed))
                .count(),
            0
        );

        let all_licensed = |_: attome_modules::ModuleId| true;
        assert!(
            registry
                .visible_to(&ctx, &visibility(&ai, &all_licensed))
                .count()
                > 0
        );
    }

    /// The kill-switch empties the visible set for an AI surface, exactly as
    /// an unlicensed module does.
    #[test]
    fn the_kill_switch_empties_the_visible_set_for_an_ai_surface() {
        let registry = ActionRegistry::new();
        let off = AiEnablement::default();
        let licensed = |_: attome_modules::ModuleId| true;
        let ctx = ActionContext::user(security_context());
        assert_eq!(
            registry
                .visible_to(&ctx, &visibility(&off, &licensed))
                .count(),
            0
        );
    }

    /// An agent's ceiling narrows what it is offered, not just what it may
    /// invoke — a tool a model can see but never invoke wastes turns and
    /// teaches it that refusals are normal.
    #[test]
    fn a_risk_ceiling_narrows_the_visible_set() {
        let registry = ActionRegistry::new();
        let ai = all_on();
        let licensed = |_: attome_modules::ModuleId| true;
        let inputs = visibility(&ai, &licensed);

        let read_only = ActionContext::agent(security_context(), RiskTier::Read);
        for descriptor in registry.visible_to(&read_only, &inputs) {
            assert_eq!(
                descriptor.risk,
                RiskTier::Read,
                "a Read-ceiling agent must be offered only Read actions"
            );
        }
    }

    /// **Regression (C7 browser pass).** A tool list is built before any call
    /// exists, from a context with no idempotency key. A `RequiresKey` action
    /// must still be offered to an agent whose ceiling admits it — the key is
    /// attached per call — while an invocation without a key is still refused
    /// by the gate itself.
    #[test]
    fn requires_key_actions_are_offered_before_a_key_exists() {
        use crate::descriptor::RetryClass;
        let registry = ActionRegistry::new();
        let ai = all_on();
        let licensed = |_: attome_modules::ModuleId| true;
        let inputs = visibility(&ai, &licensed);
        let agent = ActionContext::agent(security_context(), RiskTier::Reversible);
        assert!(agent.idempotency_key.is_none());

        let visible: Vec<&str> = registry
            .visible_to(&agent, &inputs)
            .map(|d| d.id.as_str())
            .collect();
        for id in ["record.create", "record.update", "record.restore"] {
            assert!(visible.contains(&id), "{id} must be offered: {visible:?}");
        }

        let create = registry.resolve("record.create").expect("registered");
        assert_eq!(create.retry, RetryClass::RequiresKey);
        let gate_inputs = crate::gate::GateInputs {
            licensed: true,
            ai: &ai,
            surface: Some(AiSurface::Fields),
            external_effects_enabled: false,
        };
        assert!(
            matches!(
                crate::gate::evaluate(create, &agent, &gate_inputs),
                Err(crate::gate::GateRefusal::IdempotencyKeyRequired)
            ),
            "offering it does not let a keyless call through"
        );
    }
}
