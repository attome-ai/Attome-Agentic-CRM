//! Wire shapes for `attome-state`'s admin CRUD and record routes.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub struct StateModelListItem {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub name: String,
    pub state_field: String,
    pub initial_state: String,
    pub is_active: bool,
    pub row_version: i64,
    /// Solution 7 (D-785): the layer that owns this model — `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer may
    /// change or retire it.
    pub owner_layer: String,
}

impl std::fmt::Debug for StateModelListItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateModelListItem").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct StateModelDetail {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub name: String,
    pub state_field: String,
    pub initial_state: String,
    pub is_active: bool,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Solution 7 (D-785): the layer that owns this model.
    pub owner_layer: String,
    pub transitions: Vec<TransitionListItem>,
}

impl std::fmt::Debug for StateModelDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateModelDetail").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateStateModelBody {
    pub entity_logicalname: String,
    pub name: String,
    /// Must name an existing `Choice` attribute on `entity_logicalname`.
    pub state_field: String,
    pub initial_state: String,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

impl std::fmt::Debug for CreateStateModelBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateStateModelBody")
            .finish_non_exhaustive()
    }
}

fn default_true() -> bool {
    true
}

/// Full replacement of the model's mutable fields (`entity_logicalname` is
/// the immutable identity, same posture as an entity's own `logicalname`).
#[derive(Deserialize, ToSchema)]
pub struct UpdateStateModelBody {
    pub name: String,
    pub state_field: String,
    pub initial_state: String,
    pub is_active: bool,
    pub row_version: i64,
}

impl std::fmt::Debug for UpdateStateModelBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateStateModelBody")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct TransitionListItem {
    pub id: Uuid,
    pub model_ref: Uuid,
    pub from_state: String,
    pub to_state: String,
    pub name: String,
    pub required_privilege: Option<String>,
    /// M45 attome-rules expression, evaluated on every write path with the
    /// record's fields and `current_user`; fail closed.
    pub guard_expression: Option<String>,
    pub entry_actions: Vec<String>,
    pub exit_actions: Vec<String>,
    pub display_order: i32,
    pub row_version: i64,
    /// M07 Phase F (D-770): when set, asking for this transition moves the
    /// record to `pending_state` and opens a `attome-approval` request running
    /// this plan; approval moves it to `to_state`. Omitted when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_plan: Option<attome_approval::ApprovalPlan>,
    /// The state the record sits in while the approval is open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_state: Option<String>,
    /// Where a rejection sends the record; absent means `from_state`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_reject_state: Option<String>,
    /// Solution 7 (D-785): the layer that owns this transition (it may differ
    /// from its model's: a project may add a transition to a platform model).
    pub owner_layer: String,
}

impl std::fmt::Debug for TransitionListItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitionListItem").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateTransitionBody {
    pub from_state: String,
    pub to_state: String,
    pub name: String,
    #[serde(default)]
    pub required_privilege: Option<String>,
    #[serde(default)]
    pub guard_expression: Option<String>,
    #[serde(default)]
    pub entry_actions: Vec<String>,
    #[serde(default)]
    pub exit_actions: Vec<String>,
    #[serde(default)]
    pub display_order: i32,
    /// M07 Phase F (D-770): an approval plan (ordered `any`/`all`/`n_of_m`
    /// steps of `user:`/`role:`/`team:`/`position:manager_of_requester`
    /// tokens), validated with attome-approval's own validator. Requires
    /// `pending_state`.
    #[serde(default)]
    pub approval_plan: Option<attome_approval::ApprovalPlan>,
    /// An option of the model's state field, other than `from_state`,
    /// `to_state` and the model's initial state. Required with, and only
    /// allowed with, `approval_plan`.
    #[serde(default)]
    pub pending_state: Option<String>,
    /// An option of the state field; defaults to `from_state`. Only allowed
    /// with `approval_plan`.
    #[serde(default)]
    pub on_reject_state: Option<String>,
}

impl std::fmt::Debug for CreateTransitionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateTransitionBody")
            .finish_non_exhaustive()
    }
}

/// Full replacement of the transition's mutable fields + optimistic
/// concurrency, same shape as `UpdateStateModelBody`. `from_state`/`to_state`
/// are optional: omitted keeps the edge's current end, present moves it —
/// validated exactly as on create (an option of the model's state field; a
/// second live edge with the same `(from, to)` is `409`).
#[derive(Deserialize, ToSchema)]
pub struct UpdateTransitionBody {
    #[serde(default)]
    pub from_state: Option<String>,
    #[serde(default)]
    pub to_state: Option<String>,
    pub name: String,
    #[serde(default)]
    pub required_privilege: Option<String>,
    #[serde(default)]
    pub guard_expression: Option<String>,
    #[serde(default)]
    pub entry_actions: Vec<String>,
    #[serde(default)]
    pub exit_actions: Vec<String>,
    #[serde(default)]
    pub display_order: i32,
    pub row_version: i64,
    /// Full replacement like every other field here: omitted clears the
    /// approval (the transition happens on write again). See
    /// `CreateTransitionBody::approval_plan`.
    #[serde(default)]
    pub approval_plan: Option<attome_approval::ApprovalPlan>,
    #[serde(default)]
    pub pending_state: Option<String>,
    #[serde(default)]
    pub on_reject_state: Option<String>,
}

impl std::fmt::Debug for UpdateTransitionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateTransitionBody")
            .finish_non_exhaustive()
    }
}

/// One entry of `GET /api/v1/{entity}/{id}/transitions` — drives UI buttons
/// and kanban drop targets. Never lists a transition the caller lacks
/// `required_privilege` for.
#[derive(Serialize, ToSchema)]
pub struct AvailableTransition {
    pub to_state: String,
    pub name: String,
    pub display_order: i32,
}

impl std::fmt::Debug for AvailableTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvailableTransition")
            .finish_non_exhaustive()
    }
}

/// `POST /api/v1/{entity}/{id}/transition` — a state change by target state.
/// Runs the generic record update path (identical to a `PATCH` of the state
/// field, M07 §4.1); `comment` is recorded on the audit event. No
/// `row_version` in the body: send `If-Match` for optimistic concurrency, or
/// omit it to transition from the record's current version.
#[derive(Deserialize, ToSchema)]
pub struct TransitionRequestBody {
    pub to_state: String,
    #[serde(default)]
    pub comment: Option<String>,
}

impl std::fmt::Debug for TransitionRequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitionRequestBody")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct TransitionResult {
    pub record_id: Uuid,
    pub from_state: Option<String>,
    /// The state the record is in now. For a transition that requires
    /// approval (M07 Phase F) this is the transition's pending state, not the
    /// one asked for — see `approval_request_id`.
    pub to_state: String,
    pub row_version: i64,
    /// M07 Phase F (D-770): present only when the requested transition
    /// requires approval. The record is parked in `to_state` (the pending
    /// state) and this request decides it; approval moves the record to
    /// `requested_state`. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<Uuid>,
    /// The state that was asked for, when an approval now stands between the
    /// record and it. Omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_state: Option<String>,
}

impl std::fmt::Debug for TransitionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitionResult").finish_non_exhaustive()
    }
}

/// `POST /api/v1/{entity}/{id}/transition/cancel` — withdraws the record's
/// open transition approval (requester only) and returns the record to the
/// state it came from; or, when that approval was already closed without
/// executing (rejected, expired, invalidated) but the record is still
/// parked, finishes returning it (the requester or an administrator).
#[derive(Deserialize, ToSchema, Default)]
pub struct CancelTransitionBody {
    /// Recorded on the audit events. Optional.
    #[serde(default)]
    pub comment: Option<String>,
}

impl std::fmt::Debug for CancelTransitionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelTransitionBody")
            .finish_non_exhaustive()
    }
}
