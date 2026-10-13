//! Row shapes for `workflow_definition`/`workflow_definition_version`.
//! See `document/detailed-plans/P-workflow-engine.md` §4.3 for the full
//! table rationale — this admin CRUD slice only covers these two tables;
//! the execution tables (trigger_index/instance/node_run) land with the
//! execution engine slice.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub struct DefinitionListItem {
    pub id: Uuid,
    pub logicalname: String,
    pub name: String,
    pub is_active: bool,
    pub published_version: Option<i32>,
    pub created_at: DateTime<Utc>,
    /// Solution 7 (D-785): the layer that owns this workflow — `platform`,
    /// `product`, `project` or `customer`. Only a changeset of that layer may
    /// change, publish or retire it.
    pub owner_layer: String,
}

impl std::fmt::Debug for DefinitionListItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefinitionListItem").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct DefinitionDetail {
    pub id: Uuid,
    pub logicalname: String,
    pub name: String,
    pub is_active: bool,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Solution 7 (D-785): the layer that owns this workflow.
    pub owner_layer: String,
    pub versions: Vec<VersionSummary>,
}

impl std::fmt::Debug for DefinitionDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DefinitionDetail").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct VersionSummary {
    pub id: Uuid,
    pub version_number: i32,
    pub status: String,
    pub published_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

impl std::fmt::Debug for VersionSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionSummary").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct VersionDetail {
    pub id: Uuid,
    pub definition_id: Uuid,
    pub version_number: i32,
    pub graph: serde_json::Value,
    pub status: String,
    pub published_at: Option<DateTime<Utc>>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
}

impl std::fmt::Debug for VersionDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VersionDetail").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateDefinitionBody {
    pub logicalname: String,
    pub name: String,
}

impl std::fmt::Debug for CreateDefinitionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateDefinitionBody")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateDefinitionBody {
    pub name: Option<String>,
    pub is_active: Option<bool>,
    pub row_version: i64,
}

impl std::fmt::Debug for UpdateDefinitionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateDefinitionBody")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateVersionBody {
    #[serde(default)]
    pub graph: Option<serde_json::Value>,
}

impl std::fmt::Debug for CreateVersionBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateVersionBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateVersionGraphBody {
    pub graph: serde_json::Value,
    pub row_version: i64,
}

impl std::fmt::Debug for UpdateVersionGraphBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateVersionGraphBody")
            .finish_non_exhaustive()
    }
}

// ── Execution engine row shapes (P-workflow-engine.md §4.3) ────────────────

/// In-memory node_run state a pass reads/mutates — not the wire DTO (see
/// `NodeRunSummary` below for that). `id` is `None` until the row has been
/// assigned an id (a node reached for the first time this pass).
#[derive(Clone, Debug)]
pub struct NodeRunState {
    pub id: Option<Uuid>,
    pub node_id: String,
    pub status: String,
    pub output_hash: Option<String>,
    pub attempt_count: i32,
    pub last_error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub row_version: i64,
    /// True only for node_runs touched during the current pass — the
    /// checkpoint write only upserts these, per §4.4's "one checkpoint
    /// write per pass" cost model.
    pub dirty: bool,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub(crate) struct InstanceRow {
    pub id: Uuid,
    pub definition_version_id: Uuid,
    pub status: String,
    pub started_by: Option<Uuid>,
    pub context: serde_json::Value,
    pub node_data: serde_json::Value,
    pub fired_side_effects: serde_json::Value,
    pub row_version: i64,
}

#[derive(Clone, Debug, sqlx::FromRow)]
pub(crate) struct NodeRunRow {
    pub id: Uuid,
    pub node_id: String,
    pub status: String,
    pub output_hash: Option<String>,
    pub attempt_count: i32,
    pub last_error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub row_version: i64,
}

#[derive(Serialize, ToSchema)]
pub struct InstanceListItem {
    pub id: Uuid,
    pub definition_version_id: Uuid,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub correlation_entity_id: Option<Uuid>,
}

impl std::fmt::Debug for InstanceListItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceListItem").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct NodeRunSummary {
    pub node_id: String,
    pub status: String,
    pub attempt_count: i32,
    pub last_error: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for NodeRunSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeRunSummary").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct InstanceDetail {
    pub id: Uuid,
    pub definition_version_id: Uuid,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub started_by: Option<Uuid>,
    pub correlation_entity_id: Option<Uuid>,
    pub context: serde_json::Value,
    pub node_data: serde_json::Value,
    pub row_version: i64,
    pub node_runs: Vec<NodeRunSummary>,
}

impl std::fmt::Debug for InstanceDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceDetail").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct StartInstanceBody {
    pub definition_logicalname: String,
    #[serde(default)]
    pub context: serde_json::Value,
    #[serde(default)]
    pub correlation_entity_id: Option<Uuid>,
}

impl std::fmt::Debug for StartInstanceBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartInstanceBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CancelInstanceBody {
    pub row_version: i64,
}

impl std::fmt::Debug for CancelInstanceBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelInstanceBody").finish_non_exhaustive()
    }
}

// ── Simulate / dry-run (M06 checklist item 2) ───────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct SimulateRequestBody {
    /// Fed to the graph's entry `Trigger` node exactly as a real trigger
    /// context would be — see `instance_admin::start_instance_internal`'s
    /// `context` for the live equivalent.
    #[serde(default)]
    pub trigger_payload: serde_json::Value,
    /// `node_id -> "approved" | "rejected"`, consulted by an `Approval` node
    /// reached during the simulated run instead of filing a real
    /// `attome_approval` request. A node with no entry here defaults to
    /// `"approved"` so a simulate run doesn't dead-end at the first
    /// approval gate a caller didn't think to pre-decide.
    #[serde(default)]
    pub approval_decisions: std::collections::HashMap<String, String>,
}

impl std::fmt::Debug for SimulateRequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimulateRequestBody")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SimulateNodeTrace {
    pub node_id: String,
    pub node_type: String,
    /// `workflow_node_run.status` vocabulary — `succeeded`, `skipped`,
    /// `waiting` (this branch would have suspended for real), or `failed`.
    pub status: String,
    /// Set only for `Condition`/`Approval` — which output port fired.
    pub taken_port: Option<String>,
    pub output: serde_json::Value,
    /// Human-readable description of the real side effect this node would
    /// have performed outside a dry run — present only for a node whose
    /// live executor has one (D-431: this is the only thing standing in for
    /// it, never the effect itself).
    pub would_have: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SimulateResponse {
    /// `completed` (every reachable node settled), `would_wait` (the run hit
    /// a node that would have suspended for real — `WaitForEvent`/
    /// `SubWorkflow`, or a `Wait` past the iteration bound), or `failed`.
    pub status: String,
    pub trace: Vec<SimulateNodeTrace>,
}
