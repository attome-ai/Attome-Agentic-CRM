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
    /// S1-T13: present when the request named a language (`Accept-Language`
    /// `ar` or `en`): each choice field's value as its label in that
    /// language (a list for a multi-valued field), the value itself where no
    /// label is written. `data` keeps the stored values.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<std::collections::HashMap<String, serde_json::Value>>)]
    labels: Option<serde_json::Map<String, Value>>,
    /// M07 Phase F (D-770): present only on the response to an update that
    /// asked for a state transition requiring approval. The record was moved
    /// to the transition's pending state (visible in `data`) instead of the
    /// requested one, and this is the approval request that decides it
    /// (`/api/v1/approvals/{id}/decide`). Omitted on every other response, so
    /// those stay byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_request_id: Option<Uuid>,
    /// M9-T2: the attributes this update asked to change that an approval
    /// process watches. They keep their stored values (visible in `data`)
    /// until `approval_request_id` is approved. Omitted when nothing was
    /// held.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    held_attributes: Vec<String>,
    /// D-791 rule 6: the `warning`-severity business-rule `error` policies
    /// that fired on this create, update or upsert — the write succeeded;
    /// the form shows them. Omitted when there are none (and on reads), so
    /// every other response stays byte-identical.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<crate::business_rules::RuleWarning>,
    /// A15-T4: the existing records this create or update matches under a
    /// `warn` (or reasoned `allow_with_reason`) duplicate rule — the write
    /// succeeded. Omitted when there are none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    duplicate_warnings: Vec<crate::duplicate_check::DuplicateMatch>,
    /// A15-T4: how many more matches the caller may not read. Omitted when 0.
    #[serde(skip_serializing_if = "is_zero")]
    hidden_duplicates: i64,
    /// A15-T5: this record was merged into that one (the entity keeps merged
    /// records); omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    merged_into: Option<Uuid>,
    /// S1-T4: with `?expand=`, the records the named lookups point at, keyed
    /// by lookup attribute; a target the caller may not read is absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<std::collections::HashMap<String, serde_json::Value>>)]
    expanded: Option<serde_json::Map<String, Value>>,
    /// A16-T2: on an update sent with `If-Match-Merge: attributes` over a
    /// stale version, the attributes others changed since that version,
    /// which the update was merged over. Omitted otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    merged_over: Vec<String>,
    /// A16-T2: how many more such attributes the caller may not read.
    /// Omitted when 0.
    #[serde(skip_serializing_if = "is_zero")]
    merged_hidden: i64,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// S1-T5: what a write's `Prefer` header asks it to answer with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ReturnPref {
    /// `return=minimal`: the id and row version only.
    Minimal,
    /// The whole record (the default).
    Representation,
}

/// The `return=` preference across every `Prefer` header, case-insensitive;
/// the whole record unless `return=minimal` is asked for.
pub(super) fn return_pref(headers: &axum::http::HeaderMap) -> ReturnPref {
    let minimal = headers
        .get_all(axum::http::header::HeaderName::from_static("prefer"))
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|pref| {
            pref.trim()
                .split(';')
                .next()
                .is_some_and(|p| p.trim().eq_ignore_ascii_case("return=minimal"))
        });
    if minimal {
        ReturnPref::Minimal
    } else {
        ReturnPref::Representation
    }
}

/// S1-T5: the body of a write answered with `Prefer: return=minimal`.
#[derive(Debug, Serialize, ToSchema)]
pub struct MinimalRecord {
    id: Uuid,
    row_version: i64,
    /// As on the full record: present only when the write was held for approval.
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_request_id: Option<Uuid>,
    /// As on the full record: the attributes held for approval (M9-T2).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    held_attributes: Vec<String>,
    /// As on the full record: business-rule warnings that fired.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<crate::business_rules::RuleWarning>,
    /// As on the full record: likely duplicates (A15-T4).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    duplicate_warnings: Vec<crate::duplicate_check::DuplicateMatch>,
    #[serde(skip_serializing_if = "is_zero")]
    hidden_duplicates: i64,
    /// As on the full record: what an automatic merge went over (A16-T2).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    merged_over: Vec<String>,
    #[serde(skip_serializing_if = "is_zero")]
    merged_hidden: i64,
}

/// A write's answer: the whole record, or with `return=minimal` its id and
/// row version, a `Preference-Applied` header and the row version as `ETag`.
pub(super) fn write_response(
    status: axum::http::StatusCode,
    pref: ReturnPref,
    record: EntityRecordResponse,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    match pref {
        ReturnPref::Representation => (status, axum::Json(record)).into_response(),
        ReturnPref::Minimal => {
            let etag = super::row_version::row_version_etag(record.row_version);
            let body = MinimalRecord {
                id: record.id,
                row_version: record.row_version,
                approval_request_id: record.approval_request_id,
                held_attributes: record.held_attributes,
                warnings: record.warnings,
                duplicate_warnings: record.duplicate_warnings,
                hidden_duplicates: record.hidden_duplicates,
                merged_over: record.merged_over,
                merged_hidden: record.merged_hidden,
            };
            (
                status,
                [
                    (
                        axum::http::header::HeaderName::from_static("preference-applied"),
                        "return=minimal".to_owned(),
                    ),
                    (axum::http::header::ETAG, etag),
                ],
                axum::Json(body),
            )
                .into_response()
        }
    }
}

impl std::fmt::Debug for EntityRecordResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EntityRecordResponse")
            .finish_non_exhaustive()
    }
}

/// S1-T3: `?select=a,b` on a record read or write: the answer's `data` (and
/// `lookups`) carry only the named attributes.
#[derive(Debug, Default, serde::Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SelectParam {
    /// Comma-separated attribute names. `data` carries only these; `id`,
    /// `row_version` and the rest of the envelope always come back. A name
    /// that is not an attribute the caller may read is a 422.
    pub select: Option<String>,
}

/// The names in a `select` value, trimmed, empty ones dropped; `None` when
/// nothing is named.
pub(super) fn parse_select(raw: Option<&str>) -> Option<Vec<String>> {
    let names: Vec<String> = raw?
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect();
    (!names.is_empty()).then_some(names)
}

/// S1-T3: the checked `select` list for `entity_input`, before any write
/// runs, so a bad name refuses the request instead of answering a write that
/// already happened with an error.
pub(super) async fn resolve_select(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    raw: Option<&str>,
) -> Result<Option<Vec<String>>, attome_types::AppError> {
    let Some(names) = parse_select(raw) else {
        return Ok(None);
    };
    let (_, entity_name, attrs, _) = super::resolve::resolve_entity(state, entity_input).await?;
    for name in &names {
        let known = attrs.iter().any(|attr| &attr.logicalname == name);
        if !known || !ctx.has_field_read_grant(&entity_name, name) {
            return Err(attome_types::AppError::Validation(format!(
                "unknown attribute: {name}"
            )));
        }
    }
    Ok(Some(names))
}

/// S1-T13: the first `Accept-Language` tag the platform has labels for:
/// `ar` or `en` (a region such as `ar-SA` counts), else `None`.
pub(super) fn request_locale(headers: &axum::http::HeaderMap) -> Option<&'static str> {
    let raw = headers
        .get(axum::http::header::ACCEPT_LANGUAGE)?
        .to_str()
        .ok()?;
    raw.split(',').find_map(|tag| {
        let tag = tag.split(';').next().unwrap_or("").trim();
        let primary = tag.split('-').next().unwrap_or("").to_ascii_lowercase();
        match primary.as_str() {
            "ar" => Some("ar"),
            "en" => Some("en"),
            _ => None,
        }
    })
}

impl EntityRecordResponse {
    /// S1-T3: keeps only the selected attributes in `data` and `lookups`.
    /// A16-T2: marks this answer as an update merged over `shown` (and
    /// `hidden` unreadable) attributes others changed.
    pub(super) fn merged(mut self, shown: Vec<String>, hidden: i64) -> Self {
        self.merged_over = shown;
        self.merged_hidden = hidden;
        self
    }

    pub(super) fn selected(mut self, names: Option<&[String]>) -> Self {
        let Some(names) = names else {
            return self;
        };
        if let Some(data) = self.data.as_object_mut() {
            data.retain(|key, _| names.iter().any(|name| name == key));
        }
        if let Some(lookups) = self.lookups.as_mut() {
            lookups.retain(|key, _| names.iter().any(|name| name == key));
        }
        if let Some(labels) = self.labels.as_mut() {
            labels.retain(|key, _| names.iter().any(|name| name == key));
        }
        self
    }

    /// S1-T13: the choice labels in `locale` (see the `labels` field).
    pub(super) fn with_choice_labels(
        mut self,
        state: &attome_core::EngineState,
        entity: &str,
        attrs: &[attome_core::AttrInfo],
        locale: &str,
    ) -> Self {
        let snapshot = state.labels.load();
        let deployment = state.deployment_locale();
        let label = |field: &str, value: &Value| -> Value {
            let Some(code) = value.as_str() else {
                return value.clone();
            };
            let key = format!("{entity}.{field}.{code}");
            // The language's own row (`ar`, or a regional `ar-SA`), else the
            // deployment's, else the stored value.
            let rows = snapshot.rows_for("choice_option", &key);
            rows.iter()
                .find(|r| r.locale == locale)
                .or_else(|| {
                    rows.iter()
                        .find(|r| r.locale.split('-').next() == Some(locale))
                })
                .or_else(|| snapshot.resolve("choice_option", &key, None, &deployment))
                .map_or_else(
                    || Value::String(code.to_owned()),
                    |row| Value::String(row.display_name.clone()),
                )
        };
        let mut labels = serde_json::Map::new();
        if let Some(data) = self.data.as_object() {
            for attr in attrs {
                if attr.storage_type() != attome_core::FieldType::Choice {
                    continue;
                }
                let Some(value) = data.get(&attr.logicalname) else {
                    continue;
                };
                let shown = match value {
                    Value::Array(items) => {
                        Value::Array(items.iter().map(|v| label(&attr.logicalname, v)).collect())
                    }
                    Value::Null => continue,
                    single => label(&attr.logicalname, single),
                };
                labels.insert(attr.logicalname.clone(), shown);
            }
        }
        self.labels = Some(labels);
        self
    }

    /// See the `approval_request_id` field.
    pub(crate) fn with_approval_request_id(mut self, id: Option<Uuid>) -> Self {
        self.approval_request_id = id;
        self
    }

    /// See the `held_attributes` field.
    pub(crate) fn with_held_attributes(mut self, attributes: Vec<String>) -> Self {
        self.held_attributes = attributes;
        self
    }

    /// See the `merged_into` field.
    pub(crate) fn with_merged_into(mut self, merged_into: Option<Uuid>) -> Self {
        self.merged_into = merged_into;
        self
    }

    /// S1-T4: see the `expanded` field.
    pub(crate) fn with_expanded(mut self, expanded: serde_json::Map<String, Value>) -> Self {
        self.expanded = Some(expanded);
        self
    }

    /// See the `duplicate_warnings` and `hidden_duplicates` fields.
    pub(crate) fn with_duplicates(
        mut self,
        matches: Vec<crate::duplicate_check::DuplicateMatch>,
        hidden: i64,
    ) -> Self {
        self.duplicate_warnings = matches;
        self.hidden_duplicates = hidden;
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

    /// The lookup fields' target metadata (`exists`, `is_active`, `name`),
    /// resolved under the caller's row security: a target the caller may not
    /// see has no name. `record.summarize` names related records from it.
    pub fn lookups(&self) -> Option<&serde_json::Map<String, Value>> {
        self.lookups.as_ref()
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

    // Q15-T1: a field the caller may see only masked is kept, masked. A read
    // path's row already holds the masked form (masking it again changes
    // nothing); a mutation path's row holds the raw value for the audit diff,
    // which never reaches the response.
    let mut masked: std::collections::HashMap<&str, attome_core::field_mask::MaskFormat> =
        std::collections::HashMap::new();
    let sensitive: std::collections::HashSet<&str> = attrs
        .iter()
        .filter(|a| a.is_read_gated() && !ctx.has_field_read_grant(entity_name, &a.logicalname))
        .filter(|a| {
            match attome_security::field_gate::field_mask(ctx, entity_name, &a.logicalname) {
                Some(format) => {
                    masked.insert(a.logicalname.as_str(), format);
                    false
                }
                None => true,
            }
        })
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
        for (field, format) in &masked {
            if let Some(value) = map.get_mut(*field)
                && !value.is_null()
            {
                let text = match &*value {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                *value = Value::String(format.apply(&text));
            }
        }
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
        labels: None,
        approval_request_id: None,
        held_attributes: Vec::new(),
        warnings: Vec::new(),
        duplicate_warnings: Vec::new(),
        hidden_duplicates: 0,
        merged_into: None,
        expanded: None,
        merged_over: Vec::new(),
        merged_hidden: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(value: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT_LANGUAGE,
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn request_locale_prefers_first_supported_tag() {
        assert_eq!(request_locale(&accept("ar-SA,en;q=0.8")), Some("ar"));
        assert_eq!(
            request_locale(&accept("fr-FR, en-GB;q=0.7, ar")),
            Some("en")
        );
        assert_eq!(request_locale(&accept("EN")), Some("en"));
    }

    #[test]
    fn request_locale_ignores_unsupported() {
        assert_eq!(request_locale(&accept("fr, de;q=0.5")), None);
        assert_eq!(request_locale(&axum::http::HeaderMap::new()), None);
    }

    #[test]
    fn parse_select_trims_and_splits() {
        assert_eq!(
            parse_select(Some(" name, amount ,,owner_ref ")),
            Some(vec![
                "name".to_owned(),
                "amount".to_owned(),
                "owner_ref".to_owned()
            ])
        );
        assert_eq!(parse_select(Some(" , ")), None);
        assert_eq!(parse_select(None), None);
    }
}
