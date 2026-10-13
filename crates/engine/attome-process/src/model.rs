//! Wire types for `case_def_admin.rs`'s admin CRUD and `discovery.rs`'s
//! read routes. Mirrors the shape `attome-state/src/model.rs` uses for its own
//! migration-owned config table.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CaseDefListItem {
    pub id: Uuid,
    pub name: String,
    /// `"workflow:<definition_id>"` or `"entity:<logicalname>"`.
    pub source: String,
    pub is_active: bool,
    pub row_version: i64,
    pub last_extracted_at: Option<DateTime<Utc>>,
    /// Solution 7 (D-785): the layer that owns this definition —
    /// `platform`, `product`, `project` or `customer`. Only a changeset of
    /// that layer may change or retire it.
    pub owner_layer: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CaseDefDetail {
    pub id: Uuid,
    pub name: String,
    pub source: String,
    /// Interpretation depends on `source` — see `extraction.rs`'s doc
    /// comment for the exact shape each source kind expects.
    pub activity_mapping: serde_json::Value,
    pub resource_mapping: serde_json::Value,
    /// M41 §5 Permissions — a privilege key aggregate DFG/variant views will
    /// require of the caller. Stored and schema-ready; enforcing it on a
    /// self-service (non-admin) read surface is Phase 2+ (Phase 1 exposes
    /// only the admin-gated routes this crate mounts today).
    pub visibility_privilege: Option<String>,
    pub is_active: bool,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_extracted_at: Option<DateTime<Utc>>,
    /// Solution 7 (D-785): the layer that owns this definition.
    pub owner_layer: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateCaseDefBody {
    pub name: String,
    pub source: String,
    #[serde(default)]
    pub activity_mapping: serde_json::Value,
    #[serde(default)]
    pub resource_mapping: serde_json::Value,
    #[serde(default)]
    pub visibility_privilege: Option<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateCaseDefBody {
    pub name: String,
    #[serde(default)]
    pub activity_mapping: serde_json::Value,
    #[serde(default)]
    pub resource_mapping: serde_json::Value,
    #[serde(default)]
    pub visibility_privilege: Option<String>,
    pub is_active: bool,
    pub row_version: i64,
}

/// `GET /api/v1/process/case-defs/{id}/dfg` — the latest computed
/// directly-follows-graph snapshot.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct DfgSnapshotResponse {
    pub id: Uuid,
    pub case_def_ref: Uuid,
    pub period_start: chrono::NaiveDate,
    pub period_end: chrono::NaiveDate,
    pub computed_at: DateTime<Utc>,
    /// `{"nodes": [{"activity", "count"}], "edges": [{"from", "to", "frequency", "median_duration_seconds"}]}`
    pub graph: serde_json::Value,
    pub case_count: i32,
    pub event_count: i32,
}

/// `GET /api/v1/process/case-defs/{id}/variants` — the latest computed
/// variant list.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct VariantsResponse {
    pub id: Uuid,
    pub case_def_ref: Uuid,
    pub period_start: chrono::NaiveDate,
    pub period_end: chrono::NaiveDate,
    pub computed_at: DateTime<Utc>,
    /// `[{"sequence": [..], "hash", "count"}]`, ordered by count DESC.
    pub variants: serde_json::Value,
    /// `{"per_case": {...}, "per_step": {...}}` — cycle-time percentiles;
    /// carried alongside variants rather than exposed as a third route,
    /// since both read from the same snapshot row and the module plan's
    /// Phase 1 checklist does not call for a dedicated cycle-time endpoint.
    pub cycle_time: serde_json::Value,
    pub case_count: i32,
    pub event_count: i32,
}

/// Phase 2/3 route stubs (`/bottlenecks`, `/conformance`, `/findings`) —
/// mirrors the `not_computable` shape `attome-dashboard::scenario`'s
/// formula-backed-metric result already uses for "the mechanism this needs
/// is not implemented in this workspace yet", but as a standalone 501
/// response rather than a written row, since these routes have nothing to
/// persist. See `document/module-master-plans/M41-process-intelligence.md`
/// §6 Phase 2/3 for what each of these will actually compute.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct NotComputableResponse {
    pub status: &'static str,
    pub reason: String,
}
