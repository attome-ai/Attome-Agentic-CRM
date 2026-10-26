//! M07 Phase 1 (D-406) — the in-memory snapshot of `state_model` /
//! `state_transition`, and the pure enforcement checks every entity
//! write consults.
//!
//! **Why this lives in `attome-core` rather than in `attome-state`.** State
//! transition enforcement has to run from `attome-server::entity_mutation`
//! (`create_one`/`update_one`) — the single shared path every interactive
//! CRUD, bulk, and upsert write already goes through — so *every* write can
//! be checked, not just the ones a caller remembers to route through
//! `attome-state`'s own `/transition` endpoint. `attome-state` (the licensed
//! engine, home of the admin CRUD + `/transition` HTTP surface) depends on
//! `attome-server` for the same reason `attome-workflow` does (reusing entity
//! read/write primitives for its own routes), so `attome-server` cannot also
//! depend on `attome-state` without a real dependency cycle. D-394 ("Option B")
//! is the precedent for exactly this shape: a cross-cutting primitive that a
//! relocated/shared handler needs from a sibling engine is pulled down into
//! `attome-core` rather than making either engine depend on the other.
//! `entity_mutation.rs` calls the functions here directly; `attome-state`'s
//! `/transition` handler writes through that same `update_one` (M07 §4.1),
//! so the two paths cannot diverge.
//!
//! **Cache shape.** A small, admin-authored table (state machines change by
//! human edit, not by request volume), so this deliberately does *not* reuse
//! `EntityMetaRegistry`'s incremental `metadata_change_log` catch-up
//! machinery — that table is entity/attribute-shaped
//! (`entity_ref -> entity_info`) and state models are not entities.
//! Instead this mirrors the simpler full-snapshot-reload pattern
//! `attome_security::SECURITY_VERSION_CHANNEL` / `EngineState::audit_users`
//! already use: an `ArcSwap`-backed `MetadataCache` pre-warmed at boot,
//! refreshed in full on a Redis pub/sub doorbell (`STATE_MODEL_VERSION_CHANNEL`)
//! and on subscriber reconnect (`attome-server/src/system.rs`) — never a
//! per-request DB read on the mutation hot path.

use std::collections::HashMap;

use attome_approval::ApprovalPlan;
use attome_db::DbPool;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Redis pub/sub channel: any node that writes `state_model`/
/// `state_transition` best-effort publishes here so every other
/// node's `EngineState::state_models` cache reloads promptly instead of only on
/// its next reconnect. Payload is unused (a doorbell, not an instruction) —
/// same posture as `attome_security::SECURITY_VERSION_CHANNEL`.
pub const STATE_MODEL_VERSION_CHANNEL: &str = "state_model_version";

/// M07 Phase F (D-770) — the `attome-approval` `action_type` of a request the
/// state engine submits when a write asks for a transition that carries an
/// [`TransitionDef::approval_plan`]. Its payload is a
/// [`TransitionApprovalPayload`]; `regarding` is the record. The request is
/// executed by `attome_state::approval` through the approval dispatcher
/// (`attome_server::approval_admin`), never by `gate()`.
pub const ACTION_STATE_TRANSITION: &str = "state.transition";

/// The payload of an [`ACTION_STATE_TRANSITION`] request — everything the
/// executor and the settle paths need, frozen at request time so a later
/// metadata edit cannot change what an open request does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionApprovalPayload {
    /// The transition row that carried the plan (provenance only).
    pub transition_id: Uuid,
    pub entity: String,
    /// The model's state field at request time.
    pub state_field: String,
    /// The origin state (`A`); where cancel, expiry and invalidation return.
    pub from: String,
    /// The requested target (`B`); where approval moves the record.
    pub to: String,
    /// Where the record sits while the request is open.
    pub pending_state: String,
    /// Where a rejection moves the record: the transition's
    /// `on_reject_state`, or `from` when it has none.
    pub on_reject_state: String,
    pub requested_by: Uuid,
    /// The record's `row_version` right after it moved into `pending_state`.
    /// Execution refuses (invalidates) when the record no longer has it.
    pub row_version: i64,
}

/// One `state_model` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateModelDef {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub name: String,
    /// A `Choice` attribute logicalname on `entity_logicalname`.
    pub state_field: String,
    pub initial_state: String,
    /// Business enable/disable toggle, distinct from soft-delete
    /// (`is_deleted`, never loaded into this snapshot at all): a model can be
    /// authored and left switched off while it's being built out.
    pub is_active: bool,
    pub row_version: i64,
}

/// One `state_transition` row.
#[derive(Clone, Debug, PartialEq)]
pub struct TransitionDef {
    pub id: Uuid,
    pub model_ref: Uuid,
    pub from_state: String,
    pub to_state: String,
    pub name: String,
    pub required_privilege: Option<String>,
    /// M45 (attome-rules `guard_expression`). Evaluated by
    /// `attome-records::entity_mutation::enforce_state_transition` against
    /// the record's effective fields plus `current_user` (the acting staff
    /// user, P0 0.7), fail closed. See `check_transition`'s doc comment.
    pub guard_expression: Option<String>,
    pub entry_actions: Vec<String>,
    pub exit_actions: Vec<String>,
    pub display_order: i32,
    pub row_version: i64,
    /// M07 Phase F (D-770): when set, a write asking for this transition does
    /// not reach `to_state`; it moves the record to `pending_state` and
    /// submits a `attome-approval` request running this plan. `None` for every
    /// transition that behaves as before.
    pub approval_plan: Option<ApprovalPlan>,
    /// Required with `approval_plan` (CHECK in migration 0514).
    pub pending_state: Option<String>,
    /// Where a rejection sends the record; `None` = `from_state`.
    pub on_reject_state: Option<String>,
    /// M8-T3: an attome-rules condition over the record's fields; when it
    /// holds for a record in `from_state`, the transition happens by itself
    /// (`attome_state::auto_transitions`). `None` for a transition people make.
    pub auto_condition: Option<String>,
}

impl TransitionDef {
    /// Whether this transition runs through an approval instead of happening
    /// on write (M07 Phase F).
    pub fn requires_approval(&self) -> bool {
        self.approval_plan.is_some() && self.pending_state.is_some()
    }
}

/// One entity's state machine: the model plus its live transitions,
/// display-ordered.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StateModelEntry {
    pub model: Option<StateModelDef>,
    pub transitions: Vec<TransitionDef>,
}

impl StateModelEntry {
    /// The approval-bearing transition whose `pending_state` is `current`, if
    /// any: `current` is a state a record only reaches while an approval for
    /// that transition is open (M07 Phase F). While a record is in such a
    /// state it is locked: no field write and no transition except the ones
    /// the approval flow itself performs. `None` when the model is inactive.
    pub fn approval_pending_in(&self, current: Option<&str>) -> Option<&TransitionDef> {
        let model = self.model.as_ref()?;
        if !model.is_active {
            return None;
        }
        let current = current?;
        self.transitions
            .iter()
            .find(|t| t.pending_state.as_deref() == Some(current))
    }

    /// Whether any live transition of an active model names a pending state:
    /// the zero-I/O pre-check the mutation path uses before reading a
    /// record's current state for the pending lock.
    pub fn has_approval_transitions(&self) -> bool {
        self.model.as_ref().is_some_and(|m| m.is_active)
            && self.transitions.iter().any(|t| t.pending_state.is_some())
    }
}

/// Snapshot of every active `state_model`, keyed by
/// `entity_logicalname`. Swapped in atomically by `EngineState::state_models` —
/// see `attome-server/src/system.rs`'s pre-warm + pub/sub reload, mirroring
/// `EntityMetaRegistry`'s own wiring one level down in complexity.
#[derive(Clone, Debug, Default)]
pub struct StateModelRegistry {
    by_entity: HashMap<String, StateModelEntry>,
}

impl StateModelRegistry {
    pub fn from_entries(entries: Vec<(String, StateModelEntry)>) -> Self {
        Self {
            by_entity: entries.into_iter().collect(),
        }
    }

    /// `None` means this entity has no configured lifecycle at all —
    /// enforcement is a no-op for it, same as today.
    pub fn get(&self, entity_logicalname: &str) -> Option<&StateModelEntry> {
        self.by_entity.get(entity_logicalname)
    }

    pub fn len(&self) -> usize {
        self.by_entity.len()
    }

    /// The entities with a configured lifecycle (M8-T3's daily sweep).
    pub fn entities(&self) -> impl Iterator<Item = &str> {
        self.by_entity.keys().map(String::as_str)
    }

    pub fn is_empty(&self) -> bool {
        self.by_entity.is_empty()
    }
}

#[derive(sqlx::FromRow)]
struct ModelRow {
    id: Uuid,
    entity_logicalname: String,
    name: String,
    state_field: String,
    initial_state: String,
    is_active: bool,
    row_version: i64,
}

#[derive(sqlx::FromRow)]
struct TransitionRow {
    id: Uuid,
    model_ref: Uuid,
    from_state: String,
    to_state: String,
    name: String,
    required_privilege: Option<String>,
    guard_expression: Option<String>,
    entry_actions: Vec<String>,
    exit_actions: Vec<String>,
    display_order: i32,
    row_version: i64,
    approval_plan: Option<serde_json::Value>,
    pending_state: Option<String>,
    on_reject_state: Option<String>,
    auto_condition: Option<String>,
}

/// Builds a full registry snapshot from Postgres: one query over
/// `state_model`, one over `state_transition` — no N+1.
/// Only active (`is_deleted = false`) rows; a model's own `is_active` flag
/// (business enable/disable) is loaded but not filtered on here — callers
/// decide whether a disabled model still enforces (it does not; see
/// `check_transition`).
pub async fn load(db: &DbPool) -> Result<StateModelRegistry, AppError> {
    let models: Vec<ModelRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, name, state_field, initial_state, is_active, row_version \
         FROM state_model WHERE is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let transitions: Vec<TransitionRow> = sqlx::query_as(
        "SELECT id, model_ref, from_state, to_state, name, required_privilege, \
                guard_expression, entry_actions, exit_actions, display_order, row_version, \
                approval_plan, pending_state, on_reject_state, auto_condition \
         FROM state_transition WHERE is_deleted = false \
         ORDER BY display_order, from_state, to_state",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut by_model: HashMap<Uuid, Vec<TransitionDef>> = HashMap::new();
    for t in transitions {
        // A plan the admin API or the bundle reconcile validated can only
        // fail to parse if the row was edited by hand. Fail closed for that
        // one transition: it keeps its pending_state, so the record lock
        // still applies and `check_transition_with` refuses the edge rather
        // than performing it without its approval.
        let approval_plan = match t.approval_plan {
            None => None,
            Some(raw) => match serde_json::from_value::<ApprovalPlan>(raw) {
                Ok(plan) => Some(plan),
                Err(e) => {
                    tracing::error!(
                        transition_id = %t.id,
                        error = %e,
                        "state_transition.approval_plan is corrupt; the transition \
                         is refused until an administrator repairs it"
                    );
                    None
                }
            },
        };
        by_model
            .entry(t.model_ref)
            .or_default()
            .push(TransitionDef {
                id: t.id,
                model_ref: t.model_ref,
                from_state: t.from_state,
                to_state: t.to_state,
                name: t.name,
                required_privilege: t.required_privilege,
                guard_expression: t.guard_expression,
                entry_actions: t.entry_actions,
                exit_actions: t.exit_actions,
                display_order: t.display_order,
                row_version: t.row_version,
                approval_plan,
                pending_state: t.pending_state,
                on_reject_state: t.on_reject_state,
                auto_condition: t.auto_condition,
            });
    }

    let mut entries = Vec::with_capacity(models.len());
    for m in models {
        let transitions = by_model.remove(&m.id).unwrap_or_default();
        entries.push((
            m.entity_logicalname.clone(),
            StateModelEntry {
                model: Some(StateModelDef {
                    id: m.id,
                    entity_logicalname: m.entity_logicalname,
                    name: m.name,
                    state_field: m.state_field,
                    initial_state: m.initial_state,
                    is_active: m.is_active,
                    row_version: m.row_version,
                }),
                transitions,
            },
        ));
    }

    Ok(StateModelRegistry::from_entries(entries))
}

/// C-18 — `spawn_doorbell_reload::<StateModelRegistry>` (`attome-server/src/
/// system.rs`) is the only caller of this impl's `load`; every other call
/// site keeps calling the free `load` fn above directly (unchanged).
impl crate::snapshot_source::SnapshotSource for StateModelRegistry {
    const CHANNEL: &'static str = STATE_MODEL_VERSION_CHANNEL;

    fn load(db: &DbPool) -> crate::snapshot_source::BoxFuture<'_, Result<Self, AppError>> {
        Box::pin(load(db))
    }
}

/// On create: `provided` is the caller's submitted value for the model's
/// `state_field`, if any. Returns the value that must end up on the row —
/// either the caller's own (already validated against `initial_state`) or
/// the model's `initial_state` when the caller left the field unset, so a
/// governed entity is never created with an ungoverned/NULL state.
pub fn check_initial_state(
    entry: &StateModelEntry,
    provided: Option<&str>,
) -> Result<Option<String>, AppError> {
    let Some(model) = &entry.model else {
        return Ok(None);
    };
    if !model.is_active {
        return Ok(None);
    }
    match provided {
        None => Ok(Some(model.initial_state.clone())),
        Some(v) if v == model.initial_state => Ok(None),
        Some(v) => Err(AppError::TransitionNotAllowed(format!(
            "{}.{}: a new record must be created in the model's initial state '{}', not '{v}'",
            model.entity_logicalname, model.state_field, model.initial_state
        ))),
    }
}

/// On update: `current` is the record's live `state_field` value (read
/// inside the same transaction, before the write); `new_value` is what the
/// caller's body sets it to. A no-op write (`current == Some(new_value)`)
/// always passes — this function is only meant to be called once the caller
/// has already established the field is actually changing.
///
/// **Guard ordering (per the plan doc): privilege -> guard expression ->
/// optimistic concurrency.** This function enforces only privilege (plus the
/// transition's existence) and, on success, returns the matched
/// `TransitionDef` so the caller can evaluate `guard_expression` itself —
/// deliberately not done here (REVIEW-2026-09-02 finding #8 / M45 Phase 3):
/// evaluating a `attome_rules` expression needs a `Schema`/`Context` built from
/// the record's own field values, which this pure, I/O-free registry lookup
/// never has (only `current`/`new_value`, the one field being transitioned).
/// `attome-records::entity_mutation::enforce_state_transition` is the
/// enforcing caller and does the guard evaluation (with the record's fields
/// and `current_user`, the acting principal — P0 0.7); `attome-state`'s
/// `/transition` route is a thin caller of that same update path (M07 §4.1),
/// so it has no check of its own. `Ok(None)` covers every case where there is nothing to guard-check
/// (no model, inactive model, no-op write); `row_version`/`If-Match`
/// concurrency is unchanged and enforced by the caller as it always was,
/// after this check (and any guard check) passes.
pub fn check_transition<'a>(
    entry: &'a StateModelEntry,
    ctx: &SecurityContext,
    current: Option<&str>,
    new_value: &str,
) -> Result<Option<&'a TransitionDef>, AppError> {
    check_transition_with(
        entry,
        |required| ctx.is_admin || ctx.privileges.contains(required),
        current,
        new_value,
    )
}

/// [`check_transition`] for a caller that is not a staff `SecurityContext`
/// (D-576: a web portal user's access plan). `holds` answers whether the
/// caller holds a transition's `required_privilege`; a portal user holds
/// none, so a privileged transition is refused for them.
pub fn check_transition_with<'a>(
    entry: &'a StateModelEntry,
    holds: impl Fn(&str) -> bool,
    current: Option<&str>,
    new_value: &str,
) -> Result<Option<&'a TransitionDef>, AppError> {
    let Some(model) = &entry.model else {
        return Ok(None);
    };
    if !model.is_active {
        return Ok(None);
    }
    if current == Some(new_value) {
        return Ok(None);
    }
    let current = current.unwrap_or("");
    let Some(transition) = entry
        .transitions
        .iter()
        .find(|t| t.from_state == current && t.to_state == new_value)
    else {
        return Err(AppError::TransitionNotAllowed(format!(
            "{}.{}: no transition configured from '{current}' to '{new_value}'",
            model.entity_logicalname, model.state_field
        )));
    };
    if let Some(required) = &transition.required_privilege
        && !holds(required)
    {
        return Err(AppError::Forbidden);
    }
    // A transition that names a pending state without a readable plan (only
    // possible for a hand-edited row: migration 0514's CHECK forbids a
    // pending state without a plan, and `load` drops a plan that fails to
    // parse) is refused rather than performed without its approval.
    if transition.pending_state.is_some() && transition.approval_plan.is_none() {
        return Err(AppError::TransitionNotAllowed(format!(
            "{}.{}: transition '{}' names a pending state but its approval plan could not be \
             read; an administrator must repair it",
            model.entity_logicalname, model.state_field, transition.name
        )));
    }
    Ok(Some(transition))
}

/// Every transition out of `current` (or every transition when `current` is
/// `None`, i.e. "what could this record ever move to") that `ctx` holds the
/// privilege for — the set `GET /{entity}/{id}/transitions` renders as
/// available buttons. Never includes one the caller lacks
/// `required_privilege` for (contract test in `attome-state`).
pub fn available_transitions<'a>(
    entry: &'a StateModelEntry,
    ctx: &SecurityContext,
    current: Option<&str>,
) -> Vec<&'a TransitionDef> {
    let Some(model) = &entry.model else {
        return Vec::new();
    };
    if !model.is_active {
        return Vec::new();
    }
    // M07 Phase F: a record waiting on an approval offers no buttons; only
    // the approval flow (approve, reject, cancel) moves it out.
    if entry.approval_pending_in(current).is_some() {
        return Vec::new();
    }
    let current = current.unwrap_or("");
    entry
        .transitions
        .iter()
        .filter(|t| t.from_state == current)
        .filter(|t| match &t.required_privilege {
            None => true,
            Some(p) => ctx.is_admin || ctx.privileges.contains(p),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::snapshot_source::SnapshotSource;

    #[test]
    fn snapshot_source_channel_matches_the_public_constant() {
        assert_eq!(
            <StateModelRegistry as SnapshotSource>::CHANNEL,
            STATE_MODEL_VERSION_CHANNEL
        );
    }

    fn ctx(privileges: &[&str], is_admin: bool) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::nil(),
            is_admin,
            privileges: privileges.iter().map(|s| s.to_string()).collect(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        }
    }

    fn model(entity: &str, state_field: &str, initial: &str, is_active: bool) -> StateModelDef {
        StateModelDef {
            id: Uuid::now_v7(),
            entity_logicalname: entity.to_owned(),
            name: entity.to_owned(),
            state_field: state_field.to_owned(),
            initial_state: initial.to_owned(),
            is_active,
            row_version: 0,
        }
    }

    fn transition(
        model_ref: Uuid,
        from: &str,
        to: &str,
        required_privilege: Option<&str>,
    ) -> TransitionDef {
        TransitionDef {
            id: Uuid::now_v7(),
            model_ref,
            from_state: from.to_owned(),
            to_state: to.to_owned(),
            name: format!("{from}->{to}"),
            required_privilege: required_privilege.map(str::to_owned),
            guard_expression: None,
            entry_actions: Vec::new(),
            exit_actions: Vec::new(),
            display_order: 0,
            row_version: 0,
            approval_plan: None,
            pending_state: None,
            on_reject_state: None,
            auto_condition: None,
        }
    }

    fn entry_with(transitions: Vec<TransitionDef>) -> (StateModelEntry, StateModelDef) {
        let m = model("service_ticket", "status", "new", true);
        (
            StateModelEntry {
                model: Some(m.clone()),
                transitions,
            },
            m,
        )
    }

    #[test]
    fn entity_with_no_model_is_ungoverned() {
        let entry = StateModelEntry::default();
        assert!(
            check_initial_state(&entry, Some("anything"))
                .unwrap()
                .is_none()
        );
        assert!(
            check_transition(&entry, &ctx(&[], false), Some("a"), "b").is_ok(),
            "no model configured -> any write passes"
        );
    }

    #[test]
    fn create_defaults_to_initial_state_when_unset() {
        let (entry, model) = entry_with(vec![]);
        let value = check_initial_state(&entry, None).unwrap();
        assert_eq!(value.as_deref(), Some(model.initial_state.as_str()));
    }

    #[test]
    fn create_rejects_a_non_initial_state() {
        let (entry, _) = entry_with(vec![]);
        let err = check_initial_state(&entry, Some("closed")).unwrap_err();
        assert!(matches!(err, AppError::TransitionNotAllowed(_)));
    }

    #[test]
    fn create_accepts_the_initial_state_explicitly() {
        let (entry, _) = entry_with(vec![]);
        assert!(check_initial_state(&entry, Some("new")).unwrap().is_none());
    }

    #[test]
    fn update_rejects_an_unconfigured_transition() {
        let (entry, _) = entry_with(vec![]);
        let err = check_transition(&entry, &ctx(&[], false), Some("new"), "closed").unwrap_err();
        assert!(matches!(err, AppError::TransitionNotAllowed(_)));
    }

    #[test]
    fn update_allows_a_configured_transition_with_no_required_privilege() {
        let model_id = Uuid::now_v7();
        let entry = StateModelEntry {
            model: Some(model("service_ticket", "status", "new", true)),
            transitions: vec![transition(model_id, "new", "in_progress", None)],
        };
        assert!(check_transition(&entry, &ctx(&[], false), Some("new"), "in_progress").is_ok());
    }

    #[test]
    fn update_no_op_write_always_passes() {
        let (entry, _) = entry_with(vec![]);
        assert!(check_transition(&entry, &ctx(&[], false), Some("new"), "new").is_ok());
    }

    #[test]
    fn update_enforces_required_privilege() {
        let model_id = Uuid::now_v7();
        let entry = StateModelEntry {
            model: Some(model("service_ticket", "status", "new", true)),
            transitions: vec![transition(
                model_id,
                "new",
                "closed",
                Some("service_ticket.close"),
            )],
        };
        let denied = check_transition(&entry, &ctx(&[], false), Some("new"), "closed");
        assert!(matches!(denied, Err(AppError::Forbidden)));

        let allowed = check_transition(
            &entry,
            &ctx(&["service_ticket.close"], false),
            Some("new"),
            "closed",
        );
        assert!(allowed.is_ok());

        let admin = check_transition(&entry, &ctx(&[], true), Some("new"), "closed");
        assert!(admin.is_ok(), "system.admin bypasses required_privilege");
    }

    #[test]
    fn a_disabled_model_enforces_nothing() {
        let model_id = Uuid::now_v7();
        let entry = StateModelEntry {
            model: Some(model("service_ticket", "status", "new", false)),
            transitions: vec![transition(model_id, "new", "closed", None)],
        };
        assert!(check_transition(&entry, &ctx(&[], false), Some("new"), "anything").is_ok());
        assert!(
            check_initial_state(&entry, Some("anything"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn available_transitions_never_lists_one_the_caller_lacks_privilege_for() {
        let model_id = Uuid::now_v7();
        let entry = StateModelEntry {
            model: Some(model("service_ticket", "status", "new", true)),
            transitions: vec![
                transition(model_id, "new", "in_progress", None),
                transition(model_id, "new", "closed", Some("service_ticket.close")),
            ],
        };
        let anon = available_transitions(&entry, &ctx(&[], false), Some("new"));
        assert_eq!(anon.len(), 1);
        assert_eq!(anon[0].to_state, "in_progress");

        let privileged =
            available_transitions(&entry, &ctx(&["service_ticket.close"], false), Some("new"));
        assert_eq!(privileged.len(), 2);
    }

    fn one_step_plan() -> ApprovalPlan {
        serde_json::from_value(serde_json::json!({
            "steps": [{
                "mode": "any",
                "approvers": ["user:00000000-0000-0000-0000-000000000001"],
                "sla_minutes": null
            }]
        }))
        .expect("plan json")
    }

    #[test]
    fn a_pending_state_offers_no_transitions_and_is_detected() {
        let model_id = Uuid::now_v7();
        let mut gated = transition(model_id, "new", "closed", None);
        gated.approval_plan = Some(one_step_plan());
        gated.pending_state = Some("pending".into());
        let entry = StateModelEntry {
            model: Some(model("service_ticket", "status", "new", true)),
            transitions: vec![gated, transition(model_id, "pending", "new", None)],
        };
        assert!(entry.has_approval_transitions());
        assert!(entry.approval_pending_in(Some("pending")).is_some());
        assert!(entry.approval_pending_in(Some("new")).is_none());
        assert!(
            available_transitions(&entry, &ctx(&[], true), Some("pending")).is_empty(),
            "a record waiting on an approval offers no buttons, even to an admin"
        );
        // The gated edge itself still resolves; the mutation path redirects it.
        let t = check_transition(&entry, &ctx(&[], false), Some("new"), "closed")
            .unwrap()
            .unwrap();
        assert!(t.requires_approval());
    }

    #[test]
    fn a_pending_state_without_a_readable_plan_is_refused() {
        let model_id = Uuid::now_v7();
        let mut broken = transition(model_id, "new", "closed", None);
        broken.pending_state = Some("pending".into());
        let entry = StateModelEntry {
            model: Some(model("service_ticket", "status", "new", true)),
            transitions: vec![broken],
        };
        let err = check_transition(&entry, &ctx(&[], true), Some("new"), "closed").unwrap_err();
        assert!(matches!(err, AppError::TransitionNotAllowed(_)));
    }
}
