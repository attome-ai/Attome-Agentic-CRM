use std::collections::HashMap;

use attome_core::{AttrInfo, EngineState};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::row_version::SYSTEM_COLS;
use utoipa::ToSchema;

// â”€â”€ Response type matching Angular EntityRecord interface â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

#[derive(Serialize, ToSchema)]
#[schema(
    description = "One record of any entity. P-api-contract Phase 1: the platform \
                        dispatches generic CRUD from runtime metadata (D-003), so `data`'s \
                        property names differ per entity and per deployment and cannot be \
                        enumerated in a static document — call \
                        `GET /api/v1/schema/{logicalname}` for a live entity's fields. \
                        Everything outside `data` is the same on every entity."
)]
pub struct EntityRecordResponse {
    id: Uuid,
    entity_id: Uuid,
    /// The record's own columns, keyed by attribute logical name. Values are
    /// whatever the attribute's field type maps to in JSON.
    #[schema(value_type = std::collections::HashMap<String, serde_json::Value>)]
    data: Value,
    /// UTC ISO-8601. Typed `Value` in Rust because it is read straight out of
    /// the dynamic row, but it is always a timestamp string or `null`.
    #[schema(value_type = Option<String>, format = DateTime)]
    created_at: Value,
    #[schema(value_type = Option<String>, format = DateTime)]
    updated_at: Value,
    pub(super) row_version: i64,
    /// P-entity-contract-hardening item (a) â€” supersedes D-057's read-time
    /// nulling (DECISIONS.md). `data` always carries the stored UUID for a
    /// lookup field, unmodified; this sibling map carries the tombstone
    /// metadata a client needs instead of a fabricated `null`. `None` (and
    /// therefore omitted from the JSON body â€” `skip_serializing_if`) for any
    /// entity with no populated lookup fields, so a non-lookup entity's
    /// response is byte-identical to before this field existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<std::collections::HashMap<String, LookupMeta>>)]
    lookups: Option<serde_json::Map<String, Value>>,
    /// M07 Phase F (D-770): present only on the response to an update that
    /// asked for a state transition requiring approval. The record was moved
    /// to the transition's pending state (visible in `data`) instead of the
    /// requested one, and this is the approval request that decides it
    /// (`/api/v1/approvals/{id}/decide`). Omitted on every other response, so
    /// those stay byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_request_id: Option<Uuid>,
    /// D-791 rule 6: the `warning`-severity business-rule `error` policies
    /// that fired on this create, update or upsert — the write succeeded;
    /// the form shows them. Omitted when there are none (and on reads), so
    /// every other response stays byte-identical.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<crate::business_rules::RuleWarning>,
}

impl std::fmt::Debug for EntityRecordResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityRecordResponse")
            .finish_non_exhaustive()
    }
}

impl EntityRecordResponse {
    /// See the `approval_request_id` field.
    pub(crate) fn with_approval_request_id(mut self, id: Option<Uuid>) -> Self {
        self.approval_request_id = id;
        self
    }

    /// See the `warnings` field.
    pub(crate) fn with_warnings(
        mut self,
        warnings: Vec<crate::business_rules::RuleWarning>,
    ) -> Self {
        self.warnings = warnings;
        self
    }

    /// The business-rule warnings this write returned (D-791 rule 6).
    pub fn warnings(&self) -> &[crate::business_rules::RuleWarning] {
        &self.warnings
    }

    /// The approval request this update submitted instead of performing its
    /// transition, if any (M07 Phase F).
    pub fn approval_request_id(&self) -> Option<Uuid> {
        self.approval_request_id
    }

    /// The record's own columns, already filtered to what this caller may
    /// read. Exposed as a reader (fields stay private) so `attome-ai`'s
    /// `record.summarize` can put the values in front of a model without
    /// anyone being able to CONSTRUCT one of these outside `build_response` —
    /// which is the function that applies the per-field grants.
    pub fn data(&self) -> &Value {
        &self.data
    }

    /// The row's `row_version` after this response was built — the value a
    /// caller must echo back as `expected_row_version` on the next write.
    ///
    /// Added for `attome-ai`'s `record.update_field` (M98 Phase 1): its
    /// executor reads a record first (to capture the field's prior value for
    /// the revert path) and then writes it, and the write needs the version
    /// the read just observed rather than a stale one the caller supplied
    /// earlier — the same reason an HTTP client is expected to round-trip
    /// `If-Match` from its own most recent read.
    pub fn row_version(&self) -> i64 {
        self.row_version
    }
}

/// The per-lookup-field value inside `EntityRecordResponse::lookups`. Declared
/// only so the generated contract (and any client generated from it) sees the
/// real shape instead of an opaque object — `resolve_lookup_meta` below builds
/// these with `json!`, so nothing constructs this type at runtime.
#[derive(Serialize, ToSchema)]
pub(super) struct LookupMeta {
    /// Whether the referenced record row still exists at all.
    exists: bool,
    /// Whether it exists *and* is live (not soft-deleted/deactivated).
    is_active: bool,
    /// The target's `primary_name_attribute` value, when it declares one.
    name: Option<String>,
}

/// One entry per populated lookup field on the row: whether the referenced
/// record still exists, is live, is visible under this caller's own RLS on
/// the target entity, plus its display value when the target entity
/// declares a `primary_name_attribute`. Supersedes `null_stale_lookups`
/// (D-057) â€” see `EntityRecordResponse::lookups`' doc comment and DECISIONS.md.
/// M01-core C-05: a target the caller's RLS excludes now renders exactly
/// like a target that doesn't exist â€” `{exists: false, is_active: false,
/// name: null}` â€” instead of leaking its `primary_name_attribute`.
///
/// Batches by distinct target entity: every lookup field on this row that
/// points at the same target entity is resolved by one call to
/// [`super::lookup_names::resolve_visible`] (one `WHERE id = ANY($1)` query,
/// RLS-spliced), not one query per field â€” typically zero or one query for a
/// whole row (most entities have zero or one distinct lookup target).
/// Best-effort, same stance as the code it replaces: a query failure is
/// logged and that target's fields are simply omitted from the map â€” this is
/// a data-hygiene concern, not a security control, and must never fail the
/// read.
pub(super) async fn resolve_lookup_meta(
    state: &EngineState,
    ctx: &SecurityContext,
    row: &Value,
    attrs: &[AttrInfo],
) -> Option<serde_json::Map<String, Value>> {
    let Value::Object(map) = row else {
        return None;
    };

    let mut by_target: HashMap<Uuid, Vec<(String, Uuid)>> = HashMap::new();
    for attr in attrs {
        if attr.field_type_int != 11 {
            continue;
        }
        let Some(target_id) = attr.lookup_entity_ref else {
            continue;
        };
        let Some(record_id) = map
            .get(&attr.logicalname)
            .and_then(Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
        else {
            continue;
        };
        by_target
            .entry(target_id)
            .or_default()
            .push((attr.logicalname.clone(), record_id));
    }
    if by_target.is_empty() {
        return None;
    }

    let mut out = serde_json::Map::new();
    for (target_id, fields) in by_target {
        let ids: Vec<Uuid> = fields.iter().map(|(_, id)| *id).collect();
        let found = super::lookup_names::resolve_visible(state, ctx, target_id, &ids).await;
        for (field_name, id) in fields {
            let (exists, is_active, name) = match found.get(&id) {
                Some(r) => (r.exists, r.is_active, r.name.clone()),
                None => (false, false, None),
            };
            out.insert(
                field_name,
                json!({ "exists": exists, "is_active": is_active, "name": name }),
            );
        }
    }

    if out.is_empty() { None } else { Some(out) }
}

/// Strips `SYSTEM_COLS` from the outgoing response always, and any
/// `is_sensitive` attribute (e.g. `api_key.secret_hash`) the caller
/// lacks a field-security read grant for.
///
/// Field-level security is per-field (F013/F135, D-111): each `is_sensitive`
/// attribute is gated independently via `ctx.has_field_read_grant(entity,
/// field)` (admin always satisfies it; otherwise a `field_security_profile`
/// reachable through one of the caller's roles must grant `can_read` for
/// that exact `(entity, field)` pair) — a caller can see one sensitive field
/// and not another, not an all-or-nothing row decision.
///
/// The SQL that produced `row` is the actual enforcement point for a caller
/// without a grant (`attome_core::select_columns_filtered` on the read
/// path, gated the same way) — a sensitive column the caller can't read is
/// never fetched at all, so this retain is a backstop for the mutation paths
/// (create/update/etc.), whose `row` always carries every column because the
/// audit diff needs it regardless of the HTTP caller's own visibility.
pub(super) fn build_response(
    entity_id: Uuid,
    row: Value,
    attrs: &[AttrInfo],
    lookups: Option<serde_json::Map<String, Value>>,
    ctx: &SecurityContext,
    entity_name: &str,
) -> EntityRecordResponse {
    let id = row
        .get("id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or_else(Uuid::nil);

    let created_at = row.get("created_at").cloned().unwrap_or(Value::Null);
    let updated_at = row
        .get("modified_at")
        .filter(|v| !v.is_null())
        .cloned()
        .unwrap_or_else(|| created_at.clone());

    let sensitive: std::collections::HashSet<&str> = attrs
        .iter()
        .filter(|a| a.is_sensitive && !ctx.has_field_read_grant(entity_name, &a.logicalname))
        .map(|a| a.logicalname.as_str())
        .collect();

    // F027: real value from the row; 0 only for rows created before the
    // column was backfilled â€” same as the default. Read before `row` is
    // consumed below.
    let row_version = row.get("row_version").and_then(|v| v.as_i64()).unwrap_or(0);

    // Filter in place (serde_json::Map::retain) instead of cloning every
    // retained key/value into a new map.
    let data = if let Value::Object(mut map) = row {
        map.retain(|k, _| !SYSTEM_COLS.contains(&k.as_str()) && !sensitive.contains(k.as_str()));
        Value::Object(map)
    } else {
        Value::Object(serde_json::Map::new())
    };

    EntityRecordResponse {
        id,
        entity_id,
        data,
        created_at,
        updated_at,
        row_version,
        lookups,
        approval_request_id: None,
        warnings: Vec::new(),
    }
}
