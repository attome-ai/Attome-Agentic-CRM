//! Fixed, closed node-type registry (P-workflow-engine.md §4.1/§5 step 3).
//!
//! v1 node set only — no runtime scripting/plugin sandbox (confirmed with
//! user in the plan doc): a new node type is a code change + release, same
//! trust model as everything else in this platform (guidelines §7). Port
//! compatibility, side-effect/crash-replay classification, and cache
//! eligibility all live here, not in the graph JSON — the graph only ever
//! names a node's `type` by string; this module is the single source of
//! truth for what that string means.

use std::fmt;

/// Every node type this platform ships. `Trigger` is the only entry-capable
/// type; `Wait`/`WaitForEvent`/`Approval`/`SubWorkflow` are the only
/// wait-capable (checkpoint) types (§4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeType {
    Trigger,
    Condition,
    CreateRecord,
    UpdateRecord,
    SendNotification,
    Approval,
    Wait,
    WaitForEvent,
    SubWorkflow,
    Webhook,
    /// Explicit parallel fan-out marker (M06 checklist item 1). Before this
    /// type existed, fan-out was *implicit* — any node's output port could
    /// already carry more than one outbound edge, and each downstream node
    /// simply ran once its own inputs settled. `Split` does not change that
    /// mechanism at all: it is a plain single-in/single-out passthrough node
    /// (`scheduler::execute_node`'s `Split` arm) whose only purpose is to
    /// give the graph a named location a `Join` can be validated against
    /// (`graph::validate`'s "every Split has a reachable Join" check) and a
    /// place for the designer to anchor a fan-out visually.
    Split,
    /// Explicit merge point for branches a `Split` fanned out (or for any
    /// ordinary multi-edge fan-in — `Join` does not require its inbound
    /// edges to originate at a `Split`). `config.mode` selects how many of
    /// its inbound branches must settle before it fires: `"all"` (default),
    /// `"any"`, or `"n_of_m"` with `config.n` giving the threshold — see
    /// `scheduler::join_mode_and_threshold`, which `ready_nodes` and
    /// `execute_node` both call so the readiness gate and the output can
    /// never disagree about what "enough branches arrived" means.
    ///
    /// No new persisted "token" structure was added for this: each branch's
    /// own `workflow_node_run.status` row *is* the durable per-branch
    /// token (already checkpointed every pass, per §4.4) — `ready_nodes`
    /// simply counts how many of a `Join`'s inbound edges currently read
    /// `succeeded`/`skipped` in that same table, the same "settled" test
    /// every other multi-input port already used before this node type
    /// existed.
    Join,
    /// M32 Phase 1 (AI Agent Platform, D-450) — invokes a session started
    /// from an `ai_agent` definition with a task and a step budget. The
    /// FIRST node type that genuinely IS an action in `attome-ai`'s sense
    /// (this file's own `capability()` doc comment anticipated it: "when a
    /// node type genuinely is an action... it resolves by `ActionId` through
    /// this same vocabulary"), except it resolves through
    /// `attome_ai::agent::start_session` rather than through a single
    /// `ActionId` — an agent step's ultimate risk is bounded by the
    /// SESSION's ceiling, not by one action's static descriptor.
    ///
    /// **Deliberately minimal (M32's own plan separates "planning"/the real
    /// tool loop into a later phase).** `scheduler::execute_agent_step`
    /// starts the session (`crate::node_types::NodeCapability`'s risk/effect
    /// below is what publish-time escalation validation sees when a graph
    /// author has not overridden it — see `escalation::GraphNode::risk`'s
    /// "the action's own risk wins" rule, which this node's `config
    /// .risk_ceiling` uses the exact same way an action-invoking node
    /// would) and completes with the session id and the still-unconsumed
    /// task/step_budget in its output — it does not yet run the actual
    /// multi-turn loop, because no generic write-capable tool loop exists
    /// anywhere in this workspace yet to run (only the read-only chatbot's,
    /// `attome_ai::chat`, which is deliberately not this). A future phase
    /// fills that in behind the same session id without changing this node's
    /// config/port contract.
    AgentStep,
    /// M33 Phase 1 (D-460) — picks a downstream branch via the read-only
    /// `route.classify` action (`attome_ai::actions::route_classify`)
    /// rather than a rule engine (M45 does not exist). Only two output
    /// ports, the same "closed vocabulary, `matched`/`unmatched` shape as
    /// `Condition`'s `true`/`false`" reasoning — a graph author composes an
    /// actual N-way choice by chaining `Condition` nodes after `matched` on
    /// the returned `route` label, rather than this node type needing
    /// graph-instance-specific dynamic ports the closed `&'static` table
    /// below cannot express. See `scheduler::execute_route`.
    Route,
    /// A18-T8: brings a deleted record back from the recycle bin through the
    /// same path as `POST /api/v1/bin/restore` (access, lookup liveness,
    /// unique values, audit). There is deliberately no purge node: purging
    /// goes through the retention sweep's propose/approve/execute path.
    RestoreRecord,
    /// A15-T9: "if a duplicate exists" — looks the record (wired
    /// `record_id`, of `config.entity`) up under every active duplicate rule
    /// of its entity and takes `found` (with the matches the flow's identity
    /// may read and a count of the rest) or `none`. Reads only.
    DuplicateCheck,
    /// M11-T1: sets the record's owner from a team, queue or role by a
    /// strategy (`rule`, `round_robin`, `least_loaded`, `skills`,
    /// `territory`), falling back to a queue when nobody fits; see
    /// `crate::assign` and `scheduler::execute_assign`.
    Assign,
    /// E8-T1/E8-T2: a step another engine contributes through
    /// `attome_core::workflow_step` (a journey's send email, wait for a
    /// reply, update a list). `config.handler` names the registered handler
    /// and `config.config` is its own configuration, checked by the handler
    /// at publish. Its effect is the handler's, unknown here, so it is
    /// classified as the most conservative step: an external effect behind
    /// the fired-marker mechanism.
    ModuleStep,
    /// M1-T4: runs the flow named by `config.definition_logicalname` once
    /// per batch of the wired `items` (an array; `config.batch_size`, at
    /// most 100, default 100), each batch as its own run with
    /// `{"items", "batch_index", "batch_count"}` as its input, and waits
    /// until every batch run has ended. Output: the batch count and how many
    /// runs completed, failed or were cancelled. The list may hold at most
    /// `limits.workflow.max_loop_items` items.
    ForEach,
}

/// M1-T4: the output port every node except a trigger may wire. When the
/// node fails for good it takes this port with `{error_kind, message,
/// node_id}` instead of failing the run; when it succeeds, whatever only
/// this port feeds is skipped.
pub const ON_ERROR_PORT: &str = "on_error";

impl NodeType {
    pub const ALL: [Self; 19] = [
        Self::Trigger,
        Self::Condition,
        Self::CreateRecord,
        Self::UpdateRecord,
        Self::SendNotification,
        Self::Approval,
        Self::Wait,
        Self::WaitForEvent,
        Self::SubWorkflow,
        Self::Webhook,
        Self::Split,
        Self::Join,
        Self::AgentStep,
        Self::Route,
        Self::RestoreRecord,
        Self::DuplicateCheck,
        Self::Assign,
        Self::ModuleStep,
        Self::ForEach,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trigger => "trigger",
            Self::Condition => "condition",
            Self::CreateRecord => "create_record",
            Self::UpdateRecord => "update_record",
            Self::SendNotification => "send_notification",
            Self::Approval => "approval",
            Self::Wait => "wait",
            Self::WaitForEvent => "wait_for_event",
            Self::SubWorkflow => "sub_workflow",
            Self::Webhook => "webhook",
            Self::Split => "split",
            Self::Join => "join",
            Self::AgentStep => "agent_step",
            Self::Route => "route",
            Self::RestoreRecord => "restore_record",
            Self::DuplicateCheck => "duplicate_check",
            Self::Assign => "assign",
            Self::ModuleStep => "module_step",
            Self::ForEach => "for_each",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }

    /// §4.1: a workflow instance is started by an entry trigger node
    /// embedded in the graph — only `Trigger` may have no inbound edges.
    pub fn is_entry(self) -> bool {
        matches!(self, Self::Trigger)
    }

    /// §4.4: a node the engine's in-memory pass stops at — the run
    /// checkpoints (persists) and ends the job rather than blocking a
    /// thread/connection for however long the wait lasts.
    pub fn is_wait_capable(self) -> bool {
        matches!(
            self,
            Self::Wait | Self::WaitForEvent | Self::Approval | Self::SubWorkflow | Self::ForEach
        )
    }

    /// §4.4 step 3: which of the two crash-replay mechanisms (if any) this
    /// node type's external effect must use.
    pub fn side_effect(self) -> SideEffect {
        match self {
            // `RestoreRecord` needs no stored key: restoring a record that is
            // already live is a no-op success, so a replay after the restore
            // committed changes nothing (`scheduler::execute_restore_record`).
            // M11-T1: `Assign` writes the owner through the same entity path.
            Self::CreateRecord | Self::UpdateRecord | Self::RestoreRecord | Self::Assign => {
                SideEffect::EntityIdempotencyKey
            }
            // `AgentStep` joins the fired-marker mechanism, not the entity
            // key one: starting a session is not an entity write with a
            // natural `(instance_id, node_id)` idempotency key the way
            // Create/UpdateRecord's writes are — it is a one-shot dispatch,
            // same shape as a notification or a webhook call, and checked
            // against `fired_side_effects` before firing for the same
            // reason: a crash-replay must not open a second session.
            Self::SendNotification | Self::Webhook | Self::AgentStep | Self::ModuleStep => {
                SideEffect::FiredSideEffectsMarker
            }
            // `Route` reads and classifies only — `route.classify` is
            // Read-tier/Read-effect (`node_capabilities_agree_with_side_effect_classification`
            // pins this against `capability()` below), so a crash-replay
            // simply re-runs it; there is no external effect to guard with a
            // fired-marker.
            Self::Trigger
            | Self::Condition
            | Self::Approval
            | Self::Wait
            | Self::WaitForEvent
            | Self::SubWorkflow
            | Self::ForEach
            | Self::Split
            | Self::Join
            | Self::Route
            | Self::DuplicateCheck => SideEffect::None,
        }
    }

    /// §4.4: cache participation is opt-in, and only for node types that are
    /// both side-effect-free *and* pure over their declared inputs — a node
    /// that reads live entity state (a real `Condition` implementation) is
    /// excluded too, since a hash match doesn't guarantee the underlying
    /// data hasn't changed. Only `Condition` over a *literal* config
    /// comparison (this v1's implementation — see `scheduler::eval_condition`)
    /// is actually pure; nodes with any external effect never participate.
    pub fn is_cacheable(self) -> bool {
        matches!(self, Self::Condition)
    }

    /// Declared input ports: `(name, PortType, required)`.
    pub fn input_ports(self) -> &'static [(&'static str, PortType, bool)] {
        match self {
            Self::Trigger => &[],
            Self::Condition => &[("value", PortType::Any, true)],
            Self::CreateRecord => &[("data", PortType::Json, true)],
            Self::UpdateRecord => &[
                ("record_id", PortType::RecordId, true),
                ("data", PortType::Json, true),
            ],
            Self::SendNotification => &[("variables", PortType::Json, false)],
            Self::Approval => &[("payload", PortType::Json, false)],
            Self::Wait => &[("in", PortType::Any, false)],
            Self::WaitForEvent => &[("in", PortType::Any, false)],
            Self::SubWorkflow => &[("input", PortType::Json, false)],
            Self::Webhook => &[("body", PortType::Json, false)],
            Self::Split => &[("in", PortType::Any, true)],
            Self::Join => &[("in", PortType::Any, true)],
            // The task text is a runtime value, wired in from an upstream
            // node — same "genuinely dynamic" reasoning `Trigger`'s "out"
            // output already documents, not a config-only field, since a
            // graph author routinely composes the task from upstream data
            // (a record's own text, a prior step's output).
            //
            // `handoff` (M33 Phase 1, D-460) is the STRUCTURED chaining port
            // — optional, `Json`. A chain of `AgentStep`s wires one step's
            // `outcome` (also `Json`) into the next step's `handoff`, never
            // into `task`: `task`/`Text` and `outcome`/`Json` are port-type
            // incompatible by design (`PortType::compatible_with`), which is
            // what keeps a graph author from accidentally wiring raw model
            // output where a literal instruction string belongs. `handoff`
            // is where record ids/decision ids/the upstream step's own
            // `tainted` flag travel — see `scheduler::execute_agent_step`.
            Self::AgentStep => &[
                ("task", PortType::Text, true),
                ("handoff", PortType::Json, false),
            ],
            // The data to classify — a prior node's output, an entity
            // snapshot. `Json` because a routing decision is almost always
            // made over structured context, not a bare string; `Any` would
            // also accept `Text`, which is not what this port wants (a
            // single string with no structure is a `Route` author error, not
            // something to silently coerce).
            Self::Route => &[("context", PortType::Json, true)],
            Self::RestoreRecord => &[("record_id", PortType::RecordId, true)],
            Self::DuplicateCheck => &[("record_id", PortType::RecordId, true)],
            Self::Assign => &[("record_id", PortType::RecordId, true)],
            Self::ModuleStep => &[("input", PortType::Json, false)],
            Self::ForEach => &[("items", PortType::Json, true)],
        }
    }

    /// Declared output ports: `(name, PortType)`. `Condition` is the only
    /// branching type — two mutually exclusive outputs (§4.4 skip logic).
    pub fn output_ports(self) -> &'static [(&'static str, PortType)] {
        match self {
            // `Any`, not `Json`: a trigger's output is whatever the trigger
            // context happens to be (an entity snapshot, a manual-start
            // payload, a schedule tick) — genuinely dynamic, so it must be
            // wireable into any downstream port a graph author chooses,
            // same reasoning `Condition`'s "value" input port already uses.
            Self::Trigger => &[("out", PortType::Any)],
            Self::Condition => &[("true", PortType::Any), ("false", PortType::Any)],
            Self::CreateRecord => &[("record", PortType::RecordId)],
            Self::UpdateRecord => &[("record", PortType::RecordId)],
            Self::SendNotification => &[("out", PortType::Any)],
            // Two branching ports, same shape as `Condition` — `approved`
            // fires for `ApprovalStatus::Approved`; `rejected` fires for
            // Rejected/Expired/Cancelled alike (see
            // `scheduler::approval_taken_port`). Resolved asynchronously (a
            // periodic sweep, not an in-pass evaluation — `attome_approval`
            // has no push/callback), so the untaken-port skip propagation
            // (`mark_untaken_branch`) runs from a post-load scan in
            // `execute_instance`, not synchronously inside `execute_node`
            // the way `Condition`'s does.
            Self::Approval => &[("approved", PortType::Any), ("rejected", PortType::Any)],
            Self::Wait => &[("out", PortType::Any)],
            Self::WaitForEvent => &[("event", PortType::Json)],
            Self::SubWorkflow => &[("output", PortType::Json)],
            Self::Webhook => &[("response", PortType::Json)],
            Self::Split => &[("out", PortType::Any)],
            Self::Join => &[("out", PortType::Any)],
            // The session's outcome — `{session_id, agent_definition_ref,
            // step_budget, status, handoff, tainted}` (Phase 1's minimal
            // shape; see this variant's own doc comment and
            // `scheduler::execute_agent_step`). `handoff`/`tainted` are what
            // a downstream `AgentStep`'s own `handoff` input port reads —
            // this is the SAME output value a chain re-uses, not a second
            // "summary" field.
            Self::AgentStep => &[("outcome", PortType::Json)],
            // `matched` carries `{"route": <label>, "applies": true, ...}`
            // when a configured route matched; `unmatched` carries the
            // decline shape when none did — same "declining is a valid
            // answer" branching shape `Approval`'s `approved`/`rejected`
            // pair already uses for an asynchronous outcome, applied here to
            // a synchronous classification instead.
            Self::Route => &[("matched", PortType::Json), ("unmatched", PortType::Json)],
            Self::RestoreRecord => &[("record", PortType::RecordId)],
            Self::DuplicateCheck => &[("found", PortType::Json), ("none", PortType::Json)],
            Self::Assign => &[("record", PortType::RecordId)],
            Self::ModuleStep => &[("output", PortType::Json)],
            Self::ForEach => &[("out", PortType::Json)],
        }
    }

    /// The half of this node type's classification that the action registry
    /// owns (TODO-035).
    ///
    /// **This is the inversion, narrowed to what is actually shared.**
    /// `P-action-registry` G1's observation is right: `node_types.rs` already
    /// owns side-effect/crash-replay classification and cache eligibility,
    /// which is exactly the metadata an LLM tool layer needs. But the *rest* of
    /// what lives here — `input_ports`, `output_ports`, `is_entry`,
    /// `is_wait_capable` — is graph-execution vocabulary with no meaning for an
    /// action, and moving it into `attome-ai` would relocate a concept rather
    /// than remove one, while making the action crate learn about ports.
    ///
    /// So the shared classification is expressed in the registry's own
    /// vocabulary, here, and the graph vocabulary stays where it belongs.
    /// `node_capabilities_agree_with_side_effect_classification` pins the two
    /// halves together so they cannot drift — which is the drift TODO-036's CI
    /// gate exists to prevent.
    ///
    /// When a node type genuinely *is* an action (P3b's AI nodes), it resolves
    /// by `ActionId` through this same vocabulary and inherits the gate. The
    /// ten shipped types are not actions and never appear as LLM tools, which
    /// is why nothing before P3b needed this.
    pub fn capability(self) -> NodeCapability {
        use attome_ai::descriptor::{Effect, RetryClass, RiskTier};
        match self {
            // Reads and pure evaluation. Nothing leaves the process.
            // A15-T9: `DuplicateCheck` reads the record and the match keys.
            Self::Trigger | Self::Condition | Self::DuplicateCheck => NodeCapability {
                risk: RiskTier::Read,
                effect: Effect::Read,
                retry: RetryClass::Idempotent,
            },
            // Entity writes, replayable because the entity path keys on
            // `(instance_id, node_id)` — the same reason `side_effect()`
            // returns `EntityIdempotencyKey`.
            Self::CreateRecord | Self::UpdateRecord | Self::RestoreRecord | Self::Assign => {
                NodeCapability {
                    risk: RiskTier::Reversible,
                    effect: Effect::Write,
                    retry: RetryClass::Idempotent,
                }
            }
            // Leaves the deployment. A notification cannot be un-sent, which is
            // why `side_effect()` gives it the fired-marker mechanism rather
            // than a replayable key — and why the retry class says a key is
            // required rather than claiming idempotence it does not have.
            Self::SendNotification | Self::Webhook => NodeCapability {
                risk: RiskTier::Consequential,
                effect: Effect::External,
                retry: RetryClass::RequiresKey,
            },
            // Wait-capable types. No effect of their own; they suspend.
            Self::Approval
            | Self::Wait
            | Self::WaitForEvent
            | Self::SubWorkflow
            | Self::ForEach => NodeCapability {
                risk: RiskTier::Read,
                effect: Effect::Read,
                retry: RetryClass::Idempotent,
            },
            // Pure graph-shape markers — a `Split` copies its input to its
            // output, a `Join` merges whichever branch outputs have settled.
            // Neither reaches outside the process.
            Self::Split | Self::Join => NodeCapability {
                risk: RiskTier::Read,
                effect: Effect::Read,
                retry: RetryClass::Idempotent,
            },
            // The CONTAINER's default when a graph author has not overridden
            // it (`escalation::GraphNode.action_risk`, which is where a real
            // published graph's actual risk for this node comes from — see
            // `config.risk_ceiling` and `admin::publish_version`'s escalation
            // check). Absent an override, this is the most conservative
            // classification the node type can carry: `Consequential`,
            // because an agent session can invoke anything up to its own
            // ceiling and a node that does not say otherwise must not be
            // assumed safe. `Effect::External`, not `Write`: from the
            // WORKFLOW graph's point of view, handing control to an
            // autonomous session is reaching outside what the graph itself
            // deterministically does — the same reasoning I-7's air-gap gate
            // uses for anything that leaves a bounded, reviewable path.
            // `RequiresKey`: never blindly replay starting a session.
            Self::AgentStep | Self::ModuleStep => NodeCapability {
                risk: RiskTier::Consequential,
                effect: Effect::External,
                retry: RetryClass::RequiresKey,
            },
            // Unlike `AgentStep`, `Route` genuinely dispatches ONE real
            // action (`route.classify`) on every execution — there is no
            // session, no multi-turn loop, and no container-default
            // ambiguity to resolve. So its capability is read straight off
            // that action's own descriptor rather than hand-classified a
            // second time, which is what keeps the two from drifting the
            // moment `route.classify`'s own risk/effect/retry ever changes.
            Self::Route => {
                let d = attome_ai::actions::route_classify::descriptor();
                NodeCapability {
                    risk: d.risk,
                    effect: d.effect,
                    retry: d.retry,
                }
            }
        }
    }

    /// `Condition`, `Approval`, and `Route` have mutually-exclusive outputs —
    /// a downstream node fed exclusively by the untaken port must be
    /// `skipped`, never left `pending` forever (§4.4 skip propagation,
    /// F090).
    pub fn is_branching(self) -> bool {
        matches!(
            self,
            Self::Condition | Self::Approval | Self::Route | Self::DuplicateCheck
        )
    }
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A node type's classification in the action registry's vocabulary.
///
/// Deliberately only the three fields that genuinely overlap. It is not an
/// `ActionDescriptor` and does not try to be — a descriptor is sealed and
/// carries an id, a module bit and privileges, none of which a graph node has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeCapability {
    pub risk: attome_ai::descriptor::RiskTier,
    pub effect: attome_ai::descriptor::Effect,
    pub retry: attome_ai::descriptor::RetryClass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideEffect {
    None,
    /// Create/Update Record — routes through the existing
    /// `X-Idempotency-Key`-equivalent entity-write path, keyed on
    /// `(instance_id, node_id, round)` (§4.4 mechanism 1, M3-T2).
    EntityIdempotencyKey,
    /// Send Notification / Webhook — checked against the checkpoint's
    /// `fired_side_effects` set before firing (§4.4 mechanism 2).
    FiredSideEffectsMarker,
}

/// Port data-shape tags. Compatibility is `Any` on either side, or an exact
/// match — no implicit widening (§5 step 3: "port-type compatibility rules
/// live here").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortType {
    Any,
    Text,
    Number,
    Bool,
    DateTime,
    Json,
    RecordId,
}

impl PortType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Text => "text",
            Self::Number => "number",
            Self::Bool => "bool",
            Self::DateTime => "datetime",
            Self::Json => "json",
            Self::RecordId => "record_id",
        }
    }

    pub fn compatible_with(self, other: Self) -> bool {
        self == Self::Any || other == Self::Any || self == other
    }
}

/// D-503 §3 — the one reading of an `agent_step` node's `config.risk_ceiling`.
///
/// Used by **both** publish-time escalation review (`admin::escalation_nodes`)
/// and runtime session start (`scheduler::execute_agent_step`), so the ceiling
/// a reviewer approved is the ceiling the session runs with. A node cannot be
/// reviewed at one ceiling and run at another. Missing or unrecognised reads
/// as `Consequential`: the conservative tier, which requires an `Approval`
/// upstream at publish and bounds the session at runtime.
pub fn agent_step_risk_ceiling(config: &serde_json::Value) -> attome_ai::descriptor::RiskTier {
    config
        .get("risk_ceiling")
        .and_then(serde_json::Value::as_str)
        .and_then(attome_ai::agent::parse_risk_ceiling)
        .unwrap_or(attome_ai::descriptor::RiskTier::Consequential)
}

/// D-503 §3 — an `agent_step` node's optional `config.allowed_action_ids`.
///
/// Absent or `null` → `None` (the session is bounded by its ceiling alone).
/// An array of strings → exactly that list; `[]` stays "nothing". Anything
/// else is refused, so a malformed list can never be read as unrestricted.
pub fn agent_step_allowed_action_ids(
    config: &serde_json::Value,
) -> Result<Option<Vec<String>>, String> {
    match config.get("allowed_action_ids") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(|id| id.trim().to_owned())
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| {
                        "config.allowed_action_ids must be an array of non-empty action ids"
                            .to_owned()
                    })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        Some(_) => Err("config.allowed_action_ids must be an array of action ids".to_owned()),
    }
}

/// B16-T13: the trigger kind a scan action's `run_workflow` starts a flow
/// with (`POST /api/v1/scan/act`). A `trigger` node whose
/// `config.trigger_type` is `scan` is where such a start enters.
pub const TRIGGER_SCAN: &str = "scan";

/// The trigger node a start enters at: the first trigger of `kind` when the
/// start names one and the flow has it, else the flow's first trigger. Pure.
pub fn entry_trigger(graph: &crate::graph::Graph, kind: Option<&str>) -> Option<String> {
    let triggers = || {
        graph
            .nodes
            .iter()
            .filter(|n| NodeType::parse(&n.node_type) == Some(NodeType::Trigger))
    };
    kind.and_then(|kind| {
        triggers().find(|n| {
            n.config
                .get("trigger_type")
                .and_then(serde_json::Value::as_str)
                == Some(kind)
        })
    })
    .or_else(|| triggers().next())
    .map(|n| n.id.clone())
}

#[cfg(test)]
mod entry_trigger_tests {
    use super::*;

    #[test]
    fn a_scan_start_enters_at_the_scan_trigger() {
        let graph = crate::graph::Graph::parse(&serde_json::json!({
            "nodes": [
                {"id": "manual", "type": "trigger", "config": {"trigger_type": "manual"}},
                {"id": "scan", "type": "trigger", "config": {"trigger_type": "scan"}},
                {"id": "step", "type": "update_record"}
            ]
        }))
        .unwrap();
        assert_eq!(
            entry_trigger(&graph, Some(TRIGGER_SCAN)).as_deref(),
            Some("scan")
        );
        assert_eq!(entry_trigger(&graph, None).as_deref(), Some("manual"));
        assert_eq!(
            entry_trigger(&graph, Some("webhook")).as_deref(),
            Some("manual")
        );
        assert!(entry_trigger(&crate::graph::Graph::default(), Some(TRIGGER_SCAN)).is_none());
    }
}

#[cfg(test)]
mod agent_step_governance_tests {
    use super::*;
    use attome_ai::descriptor::RiskTier;

    #[test]
    fn a_declared_ceiling_is_read_and_anything_else_is_consequential() {
        for (config, expected) in [
            (
                serde_json::json!({ "risk_ceiling": "read" }),
                RiskTier::Read,
            ),
            (
                serde_json::json!({ "risk_ceiling": "reversible" }),
                RiskTier::Reversible,
            ),
            (
                serde_json::json!({ "risk_ceiling": "consequential" }),
                RiskTier::Consequential,
            ),
            (serde_json::json!({}), RiskTier::Consequential),
            (
                serde_json::json!({ "risk_ceiling": "godmode" }),
                RiskTier::Consequential,
            ),
            (
                serde_json::json!({ "risk_ceiling": 1 }),
                RiskTier::Consequential,
            ),
        ] {
            assert_eq!(agent_step_risk_ceiling(&config), expected, "{config}");
        }
    }

    #[test]
    fn an_allow_list_is_optional_exact_and_fails_closed() {
        assert_eq!(
            agent_step_allowed_action_ids(&serde_json::json!({})),
            Ok(None)
        );
        assert_eq!(
            agent_step_allowed_action_ids(&serde_json::json!({ "allowed_action_ids": null })),
            Ok(None)
        );
        assert_eq!(
            agent_step_allowed_action_ids(&serde_json::json!({ "allowed_action_ids": [] })),
            Ok(Some(vec![]))
        );
        assert_eq!(
            agent_step_allowed_action_ids(
                &serde_json::json!({ "allowed_action_ids": ["record.get"] })
            ),
            Ok(Some(vec!["record.get".to_owned()]))
        );
        for malformed in [
            serde_json::json!({ "allowed_action_ids": "record.get" }),
            serde_json::json!({ "allowed_action_ids": [1] }),
            serde_json::json!({ "allowed_action_ids": [""] }),
            serde_json::json!({ "allowed_action_ids": {} }),
        ] {
            assert!(
                agent_step_allowed_action_ids(&malformed).is_err(),
                "{malformed} must not be read as unrestricted"
            );
        }
    }

    /// **Review and runtime read the same value.** Publish-time escalation and
    /// runtime session start both call [`agent_step_risk_ceiling`], and neither
    /// parses `risk_ceiling` on its own, so the two cannot drift apart.
    ///
    /// **And the runtime session carries the definition's policy (D-505).**
    /// The node's reviewed constraints go to `agent::start_session`, which
    /// combines them with the named definition's policy (lowest ceiling,
    /// intersected allow-lists) and snapshots its limits. Nothing here opens
    /// a session through the bare `session::start` primitive, which would skip
    /// the policy.
    #[test]
    fn publish_review_and_runtime_resolve_the_ceiling_through_one_function() {
        let admin = include_str!("admin.rs");
        let scheduler = include_str!("scheduler.rs");
        assert!(
            admin.contains("agent_step_risk_ceiling(&n.config)"),
            "publish-time escalation must use the shared resolver"
        );
        assert!(
            scheduler.contains("agent_step_risk_ceiling(&node.config)"),
            "runtime session start must use the shared resolver"
        );
        assert!(
            scheduler.contains("agent_step_allowed_action_ids(&node.config)"),
            "runtime session start must use the shared allow-list resolver"
        );
        // rustfmt may wrap the call, so compare with whitespace removed.
        let compact: String = scheduler.split_whitespace().collect();
        assert!(
            compact.contains(
                "attome_ai::agent::start_session(state,ctx,definition_ref,\"workflow\",constraints,tainted"
            ),
            "runtime session start must combine the node with the definition's policy"
        );
        for (name, source) in [("admin.rs", admin), ("scheduler.rs", scheduler)] {
            let production = source.split("#[cfg(test)]").next().unwrap_or(source);
            assert!(
                !production.contains(".get(\"risk_ceiling\")"),
                "{name} must not parse risk_ceiling outside the shared resolver"
            );
            assert!(
                !production.contains("session::start("),
                "{name} must not open a session without the definition's policy"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_node_type_round_trips_through_as_str_parse() {
        for t in NodeType::ALL {
            assert_eq!(NodeType::parse(t.as_str()), Some(t));
        }
    }

    #[test]
    fn only_trigger_is_an_entry_type() {
        for t in NodeType::ALL {
            assert_eq!(t.is_entry(), t == NodeType::Trigger, "{t}");
        }
    }

    #[test]
    fn every_side_effecting_type_declares_a_real_mechanism() {
        for t in [
            NodeType::CreateRecord,
            NodeType::UpdateRecord,
            NodeType::RestoreRecord,
            NodeType::Assign,
            NodeType::SendNotification,
            NodeType::Webhook,
            NodeType::AgentStep,
            NodeType::ModuleStep,
        ] {
            assert_ne!(t.side_effect(), SideEffect::None, "{t}");
        }
        for t in [
            NodeType::Trigger,
            NodeType::Condition,
            NodeType::Approval,
            NodeType::Wait,
            NodeType::WaitForEvent,
            NodeType::SubWorkflow,
            NodeType::Split,
            NodeType::Join,
            NodeType::Route,
        ] {
            assert_eq!(t.side_effect(), SideEffect::None, "{t}");
        }
    }

    #[test]
    fn no_side_effecting_type_is_cacheable() {
        for t in NodeType::ALL {
            if t.side_effect() != SideEffect::None {
                assert!(!t.is_cacheable(), "{t} is side-effecting but cacheable");
            }
        }
    }

    #[test]
    fn port_type_any_is_compatible_with_everything() {
        assert!(PortType::Any.compatible_with(PortType::Text));
        assert!(PortType::RecordId.compatible_with(PortType::Any));
        assert!(!PortType::Text.compatible_with(PortType::Number));
        assert!(PortType::Number.compatible_with(PortType::Number));
    }

    /// **The anti-drift assertion TODO-035 is really about.**
    ///
    /// `side_effect()` and `capability().effect` classify the same fact in two
    /// vocabularies, and the whole risk of keeping both is that they diverge —
    /// a node reclassified in one and not the other would execute under the
    /// crash-replay mechanism for an effect it no longer has. This makes the
    /// correspondence total and exact, so adding a node type without deciding
    /// both halves fails to compile or fails here.
    #[test]
    fn node_capabilities_agree_with_side_effect_classification() {
        use attome_ai::descriptor::Effect;

        for node in NodeType::ALL {
            let cap = node.capability();
            match node.side_effect() {
                // A replayable entity write.
                SideEffect::EntityIdempotencyKey => assert_eq!(
                    cap.effect,
                    Effect::Write,
                    "{node} replays through an entity key, so it writes"
                ),
                // Something left the deployment and cannot be un-done.
                SideEffect::FiredSideEffectsMarker => assert_eq!(
                    cap.effect,
                    Effect::External,
                    "{node} uses the fired-marker mechanism, which exists \
                     precisely because its effect leaves the deployment"
                ),
                SideEffect::None => assert_eq!(
                    cap.effect,
                    Effect::Read,
                    "{node} has no side effect, so it cannot be a write"
                ),
            }
        }
    }

    /// An external effect is never claimed to be idempotent.
    ///
    /// The dangerous direction: a node that says `Idempotent` is one a retry
    /// will happily re-run, and re-running a webhook or a notification sends it
    /// twice. `RequiresKey` is what forces the caller to make the replay safe.
    #[test]
    fn no_external_node_claims_idempotence() {
        use attome_ai::descriptor::{Effect, RetryClass};
        for node in NodeType::ALL {
            let cap = node.capability();
            if cap.effect == Effect::External {
                assert_eq!(
                    cap.retry,
                    RetryClass::RequiresKey,
                    "{node} leaves the deployment; a retry must not be free"
                );
            }
        }
    }

    /// Only a cacheable node may be `Read` + `Idempotent` *and* pure — and the
    /// converse must not be assumed. `Wait` is `Read`/`Idempotent` and is
    /// emphatically not cacheable, because caching a suspension point would
    /// skip the wait.
    #[test]
    fn read_and_idempotent_does_not_imply_cacheable() {
        assert!(NodeType::Wait.capability().effect == attome_ai::descriptor::Effect::Read);
        assert!(
            !NodeType::Wait.is_cacheable(),
            "caching a suspension point would skip the wait entirely"
        );
        assert!(NodeType::Condition.is_cacheable());
    }

    /// Every node type has a capability. Total by construction — the `match`
    /// in `capability()` is exhaustive — but asserted so that a future type
    /// added with a catch-all arm is still caught.
    #[test]
    fn every_node_type_declares_a_capability() {
        for node in NodeType::ALL {
            let _ = node.capability();
        }
        assert_eq!(NodeType::ALL.len(), 19, "the node set is closed (I-5)");
    }

    /// `Split`/`Join` are graph-shape markers, not the branching type
    /// `Condition`/`Approval` are — a node fed only by `Join`'s "out" always
    /// runs once `Join` itself settles, there is no untaken port to skip.
    #[test]
    fn split_and_join_are_not_branching() {
        assert!(!NodeType::Split.is_branching());
        assert!(!NodeType::Join.is_branching());
    }

    /// Neither is a suspension checkpoint — both settle within one pass once
    /// their (possibly partial, for `Join`) inputs are ready.
    #[test]
    fn split_and_join_are_not_wait_capable() {
        assert!(!NodeType::Split.is_wait_capable());
        assert!(!NodeType::Join.is_wait_capable());
    }

    /// M32 Phase 1's node, pinned: not an entry, not branching, and its
    /// container default is the CONSERVATIVE end of the risk scale — a graph
    /// author must explicitly declare a lower `config.risk_ceiling` (read by
    /// `escalation::GraphNode.action_risk`, not by this function) to get
    /// anything less than "publish requires an Approval node upstream".
    #[test]
    fn agent_step_defaults_to_the_conservative_classification() {
        assert!(!NodeType::AgentStep.is_entry());
        assert!(!NodeType::AgentStep.is_branching());
        assert!(!NodeType::AgentStep.is_cacheable());
        let cap = NodeType::AgentStep.capability();
        assert_eq!(cap.risk, attome_ai::descriptor::RiskTier::Consequential);
        assert_eq!(cap.effect, attome_ai::descriptor::Effect::External);
        assert_eq!(cap.retry, attome_ai::descriptor::RetryClass::RequiresKey);
    }

    /// M33 Phase 1's `AgentStep` chaining port: `handoff` exists, is
    /// optional (a graph without any handoff chaining still validates — see
    /// `graph.rs`'s equivalent test), and is `Json` — port-type incompatible
    /// with `task`'s `Text`, which is what stops a graph author from wiring
    /// a raw model output straight into a literal instruction string.
    #[test]
    fn agent_step_gained_an_optional_json_handoff_port() {
        let ports = NodeType::AgentStep.input_ports();
        let (_, handoff_type, required) = ports
            .iter()
            .find(|(name, _, _)| *name == "handoff")
            .copied()
            .expect("agent_step must declare a handoff port");
        assert_eq!(handoff_type, PortType::Json);
        assert!(!required, "handoff is optional — not every step chains");
        assert!(
            !handoff_type.compatible_with(PortType::Text),
            "handoff (Json) must stay port-incompatible with task (Text)"
        );
    }

    /// M33 Phase 1's `Route` node, pinned: read-tier (it dispatches
    /// `route.classify`, which is Read/Read/Idempotent), branching (two
    /// mutually exclusive outputs), never an entry, never cacheable (the
    /// underlying classification is model-based, not a literal comparison —
    /// same reasoning `Condition`'s own `is_cacheable` doc draws).
    #[test]
    fn route_is_read_tier_branching_and_not_cacheable() {
        assert!(!NodeType::Route.is_entry());
        assert!(NodeType::Route.is_branching());
        assert!(!NodeType::Route.is_cacheable());
        assert!(!NodeType::Route.is_wait_capable());
        assert_eq!(NodeType::Route.side_effect(), SideEffect::None);
        let cap = NodeType::Route.capability();
        assert_eq!(cap.risk, attome_ai::descriptor::RiskTier::Read);
        assert_eq!(cap.effect, attome_ai::descriptor::Effect::Read);
        assert_eq!(cap.retry, attome_ai::descriptor::RetryClass::Idempotent);
    }

    /// `Route`'s capability is read straight off `route.classify`'s own
    /// descriptor, not hand-classified a second time — this pins the two
    /// together so a future change to one cannot silently drift from the
    /// other, the same anti-drift reasoning
    /// `node_capabilities_agree_with_side_effect_classification` documents.
    #[test]
    fn route_capability_matches_route_classify_descriptor_exactly() {
        let d = attome_ai::actions::route_classify::descriptor();
        let cap = NodeType::Route.capability();
        assert_eq!(cap.risk, d.risk);
        assert_eq!(cap.effect, d.effect);
        assert_eq!(cap.retry, d.retry);
    }

    /// M1-T4's `for_each`, pinned: waits for its batch runs, starts them
    /// like a sub-flow (no external effect of its own), never branches.
    #[test]
    fn for_each_waits_reads_items_and_does_not_branch() {
        let t = NodeType::ForEach;
        assert_eq!(NodeType::parse("for_each"), Some(t));
        assert!(t.is_wait_capable());
        assert!(!t.is_branching());
        assert!(!t.is_entry());
        assert_eq!(t.side_effect(), SideEffect::None);
        assert_eq!(t.input_ports(), &[("items", PortType::Json, true)]);
        assert_eq!(t.output_ports(), &[("out", PortType::Json)]);
    }
}
