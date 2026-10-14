//! What an action *is* — the typed, risk-classified, permission-carrying
//! description every consumer reads instead of keeping its own list.
//!
//! `attome-workflow`'s `node_types.rs` already proves the shape works: it
//! classifies side effects, crash-replay behaviour, and cache eligibility for
//! its ten node types, and that is exactly the metadata an LLM tool layer
//! needs. The difference here is who may read it — four consumers, not one.

use attome_modules::ModuleId;
use serde::Serialize;
use utoipa::ToSchema;

/// Stable identifier, `"{domain}.{verb}"` — `"record.get"`,
/// `"query.execute"`, `"record.summarize"`.
///
/// `&'static str` on purpose: an action id is code, never data. A runtime
/// string could name an action that does not exist, or — worse — be assembled
/// from model output, which is precisely the shape invariant I-9 exists to
/// prevent. The registry is closed (I-5): new capability = code change +
/// release, exactly like `node_types.rs:3-5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, ToSchema)]
pub struct ActionId(pub &'static str);

impl ActionId {
    pub fn as_str(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for ActionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// How much damage an action can do, which decides what has to happen before
/// it runs. This is the single most important field on a descriptor.
///
/// The tiers are ordered, and the ordering is load-bearing: an agent session
/// carries a ceiling and the gate compares against it. Adding a tier means
/// deciding where it sits relative to `Consequential`, which is a decision
/// somebody has to make deliberately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, ToSchema)]
pub enum RiskTier {
    /// Reads data the caller can already see. No confirmation, no approval.
    Read,
    /// Writes something a human can undo — a draft, a note, a suggestion
    /// applied to a field. Executes, reports what it did, offers undo.
    Reversible,
    /// Execution that no follow-up action reverses: sending an email to a
    /// customer, deleting a record, moving money, calling an external system
    /// that has its own side effects. **Never auto-executes for an agent.**
    Consequential,
}

/// What the action touches, independent of how risky it is. Kept separate from
/// [`RiskTier`] because they answer different questions: `Effect` decides
/// whether an air-gapped deployment can run it at all (I-7), `RiskTier`
/// decides who has to approve it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub enum Effect {
    /// Reads platform data only.
    Read,
    /// Writes platform data.
    Write,
    /// Reaches outside the deployment. **Config-gated, default-off** — an
    /// air-gapped deployment must refuse to register these rather than fail at
    /// invocation time (I-7).
    External,
}

/// Whether re-invoking after an ambiguous failure is safe.
///
/// LLM tool loops retry. That is not a hypothetical: a model that does not see
/// a tool result within its expectation will call the tool again, and a
/// retried `record.create` that produces two records is the defect
/// (TODO-043's idempotency key exists for exactly this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
pub enum RetryClass {
    /// Safe to replay: same inputs, same outcome.
    Idempotent,
    /// Replay produces a duplicate unless an idempotency key is supplied.
    /// The gate requires one for agent invocations.
    RequiresKey,
    /// Must never be replayed automatically under any circumstances.
    NeverRetry,
}

/// The full description of one capability.
///
/// **Only `attome-ai` may construct one** (invariant I-2). The realistic
/// failure this prevents is not malice — it is a chatbot shipping "its own
/// tool list, temporarily", which then drifts, and the copy that drifts is the
/// one that writes without a gate. A CI grep in the `layer-guard` family
/// enforces it; the private field below makes it awkward enough that someone
/// has to notice they are working around something.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ActionDescriptor {
    pub id: ActionId,
    /// Shown to a human in a picker, and given to a model as a tool
    /// description. Which tool a model reaches for moves answer quality more
    /// than how well any one of them performs, so this text is functional, not
    /// decorative.
    pub description: &'static str,
    pub risk: RiskTier,
    pub effect: Effect,
    pub retry: RetryClass,
    /// Whether an identical invocation may serve a cached result.
    pub cacheable: bool,
    /// The licensed module this belongs to. Unlicensed → the action is not in
    /// the registry's visible set at all, and its route 404s: the same dark
    /// shape as every other license gate (D-010), never a 403 that confirms
    /// the feature exists.
    #[serde(skip)]
    #[schema(value_type = u8)]
    pub module: ModuleId,
    /// Privilege keys the caller must hold, ALL of them. Checked before
    /// dispatch, against the caller's own `SecurityContext` — never against a
    /// service principal (I-3).
    pub required_privileges: &'static [&'static str],

    /// M97 Phase 1 (D-461) — the `outcome.kind` this action writes
    /// when it proposes something a human (or a later job) will judge, e.g.
    /// `Some("ai_suggestion")` for `record.summarize`. `None` for every
    /// action that does not produce a measurable proposal — most of the
    /// registry, including every `Effect::Read`/`RiskTier::Read` action that
    /// merely returns data.
    ///
    /// This is the declaration half of "if it proposes, it records an
    /// outcome row" (M97 plan §3). The enforcement half lives in
    /// `attome_ai::outcome::record_proposed`, which looks up the calling
    /// action's descriptor and refuses to write a row whose `kind` does not
    /// match what is declared here — so a suggestion-producing action that
    /// forgets to set this field fails closed at the first write, not
    /// silently missing the "proposals and their fates" report.
    pub outcome_kind: Option<&'static str>,

    /// M101 slice 3 — the action's argument contract, as a JSON Schema
    /// document.
    ///
    /// **What it is for.** `args` reaches an executor as an untyped
    /// `serde_json::Value` and each executor validates its own shape. That is
    /// fine for the executor and useless to everyone else: a model choosing a
    /// tool, an admin building an agent, and any external tool-protocol
    /// consumer all need to know what an action takes *before* invoking it,
    /// and the only machine-readable answer today is "some JSON". Which tool a
    /// model reaches for — and whether it fills the arguments correctly on the
    /// first try — moves answer quality more than how well any one of them
    /// performs, so this is functional, not documentation.
    ///
    /// **What it is not.** It is not enforced here. Nothing in this workspace
    /// validates a document against a JSON Schema — there is no validator
    /// dependency, and adding one is a workspace decision, not a side effect
    /// of this field. Validation stays exactly where it already lives, in each
    /// executor's own `parse_args`. This field is a *published contract*, and
    /// `schemas_are_wellformed_and_describe_an_object` below is what stops it
    /// drifting into fiction.
    ///
    /// `&'static str` rather than a parsed `serde_json::Value` for the same
    /// reason [`ActionId`] is: a descriptor is code. Parsing happens once, at
    /// the edge that serialises it.
    pub input_schema: &'static str,

    /// M35 v1 (confirmation invariant C1) — an agent may **propose** this
    /// action but never complete it: every `Initiator::Agent` invocation stops
    /// at `ConfirmFirst`, whether or not its context carries retrieved
    /// content, and the write happens only when the human invokes the action
    /// themselves. `false` for every action that keeps the ordinary
    /// risk/initiator/taint matrix. Consulted in the `Reversible` arm only; a
    /// `Consequential` agent invocation already never runs without approval.
    /// Not part of any wire shape.
    #[serde(skip)]
    pub agent_must_confirm: bool,

    /// Prevents construction outside this crate. See the type comment.
    #[serde(skip)]
    pub(crate) _sealed: Sealed,
}

/// The default [`ActionDescriptor::input_schema`] — deliberately invalid.
///
/// An action that never declares a schema fails
/// `schemas_are_wellformed_and_describe_an_object`, which is the point: a
/// permissive `{"type":"object"}` default would let a new action ship with no
/// contract and nothing would ever say so. Failing loudly at `cargo test` is
/// cheaper than a model guessing argument names in production.
pub(crate) const UNDECLARED_SCHEMA: &str = "";

/// The schema for an action that genuinely takes no arguments.
///
/// Spelled out as a shared constant so "takes nothing" is declared rather than
/// defaulted — the two are indistinguishable in a diff otherwise.
pub const NO_ARGUMENTS: &str = r#"{"type":"object","properties":{},"additionalProperties":false}"#;

/// Zero-sized private-field marker. Constructible only inside `attome-ai`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Sealed;

/// Which per-agent limit an invocation counts against (roadmap AH4-T2).
///
/// Derived from the descriptor rather than stored with each invocation, so
/// a ledger row can never disagree with the action it ran: usage is counted
/// by action id at read time ([`crate::session::used_today`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitClass {
    /// Counts against no limit (reads, and writes that change no record).
    None,
    /// Creates, updates or restores a record.
    RecordChange,
    /// Deletes a record.
    Delete,
    /// Sends a message to a person (email, WhatsApp, SMS).
    MessageSend,
    /// Reaches a service outside the deployment.
    ExternalCall,
}

impl ActionDescriptor {
    /// The limit this action counts against: an outside call by its effect,
    /// otherwise by what its id says it does.
    pub fn limit_class(&self) -> LimitClass {
        let id = self.id.0;
        match self.effect {
            Effect::Read => LimitClass::None,
            Effect::External => LimitClass::ExternalCall,
            Effect::Write if id.ends_with(".send") || id.starts_with("message.") => {
                LimitClass::MessageSend
            }
            Effect::Write if id.ends_with(".delete") && id.starts_with("record.") => {
                LimitClass::Delete
            }
            Effect::Write if id.starts_with("record.") => LimitClass::RecordChange,
            Effect::Write => LimitClass::None,
        }
    }

    /// The only constructor. `pub(crate)` — see [`ActionDescriptor`].
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        id: &'static str,
        description: &'static str,
        risk: RiskTier,
        effect: Effect,
        retry: RetryClass,
        module: ModuleId,
        required_privileges: &'static [&'static str],
    ) -> Self {
        Self {
            id: ActionId(id),
            description,
            risk,
            effect,
            retry,
            // Defaults chosen to be the SAFE answer, so a descriptor that
            // forgets to think about them is conservative rather than
            // permissive. An action opts into caching explicitly, via the
            // builder below.
            cacheable: false,
            module,
            required_privileges,
            // Same "conservative default, explicit opt-in" shape as
            // `cacheable` below: an action that never
            // considers whether it proposes something is assumed not to,
            // rather than silently eligible to write outcome rows nobody
            // declared.
            outcome_kind: None,
            // Same "conservative default, explicit opt-in" shape as the
            // fields above, taken one step further: this default does not
            // merely under-promise, it fails the invariant test outright. See
            // `UNDECLARED_SCHEMA`.
            input_schema: UNDECLARED_SCHEMA,
            // Off unless an action declares it: every other action keeps the
            // ordinary risk/initiator/taint matrix.
            agent_must_confirm: false,
            _sealed: Sealed,
        }
    }

    /// Declares that an agent may propose this action but only the human may
    /// complete it (M35 v1 C1). See the field's own doc comment.
    pub(crate) const fn agent_must_confirm(mut self) -> Self {
        self.agent_must_confirm = true;
        self
    }

    pub(crate) const fn cacheable(mut self) -> Self {
        self.cacheable = true;
        self
    }

    /// Declares the action's argument contract (M101 slice 3). Every
    /// registered action must call this — see [`UNDECLARED_SCHEMA`].
    pub(crate) const fn input_schema(mut self, schema: &'static str) -> Self {
        self.input_schema = schema;
        self
    }

    /// Declares the `outcome.kind` this action writes when it
    /// proposes something (M97 Phase 1, D-461). See the field's own doc
    /// comment for the enforcement this feeds.
    pub(crate) const fn outcome_kind(mut self, kind: &'static str) -> Self {
        self.outcome_kind = Some(kind);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ceiling comparison in the gate depends on this ordering. If
    /// `Consequential` ever stopped being the maximum, an agent session with a
    /// `Reversible` ceiling would silently admit it.
    #[test]
    fn risk_tiers_are_ordered_from_least_to_most_dangerous() {
        assert!(RiskTier::Read < RiskTier::Reversible);
        assert!(RiskTier::Reversible < RiskTier::Consequential);
        assert_eq!(
            [
                RiskTier::Consequential,
                RiskTier::Read,
                RiskTier::Reversible
            ]
            .iter()
            .max(),
            Some(&RiskTier::Consequential),
            "Consequential must remain the maximum tier"
        );
    }

    /// A descriptor that does not think about wait-capability or caching gets
    /// the conservative answer, not the convenient one.
    #[test]
    fn descriptor_defaults_are_the_safe_answers() {
        let d = ActionDescriptor::new(
            "test.thing",
            "d",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            attome_modules::MODULE_AI,
            &[],
        );
        assert!(!d.cacheable);
        assert_eq!(d.outcome_kind, None);
    }

    /// The builder round-trips — `outcome_kind` reads back what was set,
    /// same shape as `cacheable`'s own coverage above it in this file.
    #[test]
    fn outcome_kind_builder_sets_the_declared_kind() {
        let d = ActionDescriptor::new(
            "test.proposes",
            "d",
            RiskTier::Read,
            Effect::Read,
            RetryClass::Idempotent,
            attome_modules::MODULE_AI,
            &[],
        )
        .outcome_kind("ai_suggestion");
        assert_eq!(d.outcome_kind, Some("ai_suggestion"));
    }
}
