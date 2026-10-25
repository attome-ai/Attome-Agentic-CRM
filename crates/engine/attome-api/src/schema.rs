use attome_core::business_rules::{ConditionTree, PolicyDef, PolicyType, RuleAudience};
use attome_core::{EngineState, FieldType};
use attome_server::authz::{Admin, Authorized};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Router,
    extract::{Path, Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// M05 Phase 1 (D-426) — `?locale=` on `GET /api/v1/schema/{logicalname}`.
/// `get_schema` resolves every name through the chain: `locale` (when given
/// and a row exists) -> the deployment default (`core.locale`, M02/D-412) ->
/// the base `display_name` column this handler already reads.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct SchemaQuery {
    /// A BCP-47 tag, e.g. `"ar-AE"`. Omit to resolve straight to the
    /// deployment default.
    locale: Option<String>,
}

/// `pub(crate)` (M18 Data Catalog Phase 1, D-466) — `catalog_admin.rs`'s
/// entity-detail field list reuses this exact mapping rather than growing a
/// second copy that could silently drift from this one. C-16 (M01 §7): the
/// map itself lives once on `attome_core::FieldType`; this is just the
/// `&str` adapter both handlers need.
pub(crate) fn int_to_type(t: i32) -> &'static str {
    FieldType::from_int(t).unwrap_or(FieldType::Text).as_str()
}

#[derive(Serialize, ToSchema)]
struct FieldSchemaDef {
    id: Uuid,
    entity_id: Uuid,
    name: String,
    display_name: String,
    field_type: String,
    options: Value,
    sort_order: i32,
    is_required: bool,
}

/// M01 Core P3 gap (D-455) — one `relationship_info` row touching
/// this entity, oriented from the entity's own point of view. This is what
/// makes the entity form's generic relationship sub-grid data-driven
/// instead of the per-entity hardcoded `xrm-related-grid` blocks the legacy
/// hand-built `_mm_` tables still need.
#[derive(Serialize, ToSchema)]
struct RelationshipSchemaEntry {
    name: String,
    /// The label THIS entity's own form should show for the sub-grid of
    /// linked `other_entity` records — `role_b` when this entity is
    /// `entity_a` (role_b is "B's role, *from A's point of view*" —
    /// `RelationshipDef::role_b`'s own doc comment), and vice versa.
    label: String,
    other_entity: String,
    /// `"restrict" | "orphan" | "cascade-deactivate"` (C-21, M01 §7 —
    /// `attome_core::RelationshipCascade::as_db_str` always writes this
    /// hyphenated spelling).
    cascade: String,
}

#[derive(Serialize, ToSchema)]
struct EntitySchemaDef {
    id: Uuid,
    name: String,
    plural_name: String,
    fields: Vec<FieldSchemaDef>,
    relationships: Vec<RelationshipSchemaEntry>,
    /// D-789 §5 (additive): the active business rules that apply to the
    /// caller and carry a client-side policy (`hidden`, `disabled`, or an
    /// `error` attached to a field) under a structured condition. The form
    /// mirrors them for UX only; the server enforces every write.
    business_rules: Vec<BusinessRuleClient>,
    /// L1-T9: the entity is master data (it has golden records built from
    /// source systems), so its form shows the golden record panel. Sent only
    /// when true.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_master: bool,
}

/// One business rule as the form evaluates it (design §5): `set_value`
/// policies and advanced-expression conditions stay server-only. A6-T2:
/// field-attached `allowed_values` policies are sent, so the form offers
/// only the allowed choices.
#[derive(Serialize, ToSchema)]
struct BusinessRuleClient {
    name: String,
    display_name: Option<String>,
    condition: ConditionTree,
    policies: Vec<PolicyDef>,
}

/// The staff roles the caller holds, directly or through a team (D-789
/// §4.3): `SecurityContext::role_ids`, which the resolver fills for every
/// user context (live roles only, refreshed by the security epoch). A context
/// without them (`None`, one built in code) falls back to the resolver's own
/// query, `attome_security::db::resolve_role_ids`, for an interactive caller, so
/// the live-role semantics are identical either way; a service principal
/// without them holds no role here.
async fn held_role_ids<'a>(
    state: &EngineState,
    ctx: &'a SecurityContext,
) -> Result<std::borrow::Cow<'a, [Uuid]>, AppError> {
    use std::borrow::Cow;
    match ctx.role_ids.as_deref() {
        Some(ids) => Ok(Cow::Borrowed(ids)),
        None if !ctx.service_principal => {
            attome_security::db::resolve_role_ids(&state.base.db, ctx.user_id)
                .await
                .map(Cow::Owned)
        }
        None => Ok(Cow::Borrowed(&[][..])),
    }
}

/// The caller's client-side business rules for `entity` (design §5).
async fn client_business_rules(
    state: &EngineState,
    ctx: &SecurityContext,
    entity: &str,
) -> Result<Vec<BusinessRuleClient>, AppError> {
    let registry = state.rules.load();
    let Some(entry) = registry.get(entity) else {
        return Ok(Vec::new());
    };
    let client_policy = |p: &PolicyDef| {
        p.policy_type.is_lock()
            || (matches!(p.policy_type, PolicyType::Error | PolicyType::AllowedValues)
                && p.field.is_some())
    };
    let candidates: Vec<_> = entry
        .business
        .iter()
        .filter(|r| r.is_active && !r.condition.has_expression())
        .filter(|r| r.policies.iter().any(client_policy))
        .collect();
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let roles = if candidates
        .iter()
        .any(|r| r.applies_to == attome_core::business_rules::AppliesTo::Roles)
    {
        held_role_ids(state, ctx).await?
    } else {
        std::borrow::Cow::Borrowed(&[][..])
    };
    let audience = RuleAudience::Staff {
        role_ids: &roles,
        interactive: true,
    };
    Ok(candidates
        .into_iter()
        .filter(|r| r.applies_to_audience(&audience))
        .map(|r| BusinessRuleClient {
            name: r.name.clone(),
            display_name: r.display_name.clone(),
            condition: r.condition.clone(),
            policies: r
                .policies
                .iter()
                .filter(|p| client_policy(p))
                .cloned()
                .collect(),
        })
        .collect())
}

/// AA7-T2: the schema route's facts for `logicalname`: from the in-process
/// registry when it carries them, else (a registry snapshot from before
/// they were cached, or the registry switched off) the same two queries on
/// the migrator pool. `attome_readonly` cannot read the unregistered
/// `attribute_info` bootstrap table, and the route is admin-gated.
async fn schema_facts(
    state: &EngineState,
    logicalname: &str,
) -> Result<(Uuid, attome_core::SchemaEntity), AppError> {
    if state.base.config.cache.metadata_registry_enabled {
        let registry = state.entities.load();
        if let Some(meta) = registry.get(logicalname)
            && let Some(facts) = registry.schema(meta.entity_id)
        {
            return Ok((meta.entity_id, facts.clone()));
        }
    }
    let pool = &state.base.db_migrator;
    let entity_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(logicalname)
    .fetch_optional(pool)
    .await
    .map_err(AppError::internal)?;
    let entity_id = entity_id.ok_or(AppError::NotFound)?;
    let facts = attome_core::fetch_schema_facts(pool, Some(&[entity_id]))
        .await?
        .remove(&entity_id)
        .ok_or(AppError::NotFound)?;
    Ok((entity_id, facts))
}

/// AA7-T2: a weak validator over the exact body sent, so it changes with
/// any published metadata, label, relationship or rule the body reflects,
/// and two callers whose role sets yield different rules never share a
/// `304`.
pub(crate) fn schema_etag(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(body);
    let hex: String = digest.iter().take(16).map(|b| format!("{b:02x}")).collect();
    format!("W/\"{hex}\"")
}

/// Whether `If-None-Match` names `etag` (or is `*`), compared weakly.
pub(crate) fn not_modified(if_none_match: Option<&str>, etag: &str) -> bool {
    let bare = |t: &str| t.trim().trim_start_matches("W/").to_owned();
    if_none_match.is_some_and(|header| {
        header
            .split(',')
            .any(|tag| tag.trim() == "*" || bare(tag) == bare(etag))
    })
}

/// An entity's form schema
///
/// An entity's form schema. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/schema/{logicalname}",
    tag = "schema",
    params(("logicalname" = String, Path, description = "The entity's logical name"), SchemaQuery),
    responses(
        (status = 200, description = "Success; `ETag` validates it", body = EntitySchemaDef),
        (status = 304, description = "`If-None-Match` names the current `ETag`; no body"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entity", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_schema(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(logicalname): Path<String>,
    Query(query): Query<SchemaQuery>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, AppError> {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;
    let schema = build_schema(&state, &ctx, &logicalname, query.locale.as_deref()).await?;
    let body = serde_json::to_vec(&schema).map_err(AppError::internal)?;
    let etag = schema_etag(&body);
    let if_none_match = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok());
    let cache = [
        (header::ETAG, etag.clone()),
        (header::CACHE_CONTROL, "private, no-cache".to_owned()),
    ];
    if not_modified(if_none_match, &etag) {
        return Ok((StatusCode::NOT_MODIFIED, cache).into_response());
    }
    Ok((
        cache,
        [(header::CONTENT_TYPE, "application/json".to_owned())],
        body,
    )
        .into_response())
}

/// The schema `ctx` sees of `logicalname`, built from in-memory metadata.
async fn build_schema(
    state: &EngineState,
    ctx: &SecurityContext,
    logicalname: &str,
    requested_locale: Option<&str>,
) -> Result<EntitySchemaDef, AppError> {
    // M05 Phase 1 (D-426) — resolved once per request, consulted below for
    // the entity's own name, each attribute's name, and (for a `choice`
    // field) its option labels. `labels`/`dep_locale` are cheap: an arc-swap
    // load and one in-memory settings lookup, no extra query.
    let dep_locale = state.deployment_locale();
    let labels = state.labels.load();
    let (entity_id, facts) = schema_facts(state, logicalname).await?;
    let registry = state.entities.load();

    let fields: Vec<FieldSchemaDef> = facts
        .fields
        .into_iter()
        .enumerate()
        .map(|(i, row)| {
            let field_type = int_to_type(row.field_type_int.unwrap_or(3)).to_owned();
            let name = row.logicalname.clone().unwrap_or_default();
            let base_display_name = row.display_name.clone().unwrap_or_else(|| name.clone());
            // D-426 fallback chain: requested locale -> deployment default ->
            // this base column (never overwritten — see `label_store`'s
            // module doc).
            let display_name = labels
                .resolve(
                    "attribute",
                    &format!("{logicalname}.{name}"),
                    requested_locale,
                    &dep_locale,
                )
                .map(|r| r.display_name.clone())
                .unwrap_or(base_display_name);
            // A lookup's options are synthesized from its target, not stored
            // (`lookup_entity_ref` is its own column); every other type
            // serves the stored `options`. The target's name and primary
            // name attribute come from the live registry, else as read.
            let mut options = if field_type == "lookup" {
                let target = row.lookup_entity_ref.and_then(|id| registry.get_by_id(id));
                serde_json::json!({
                    "target_entity_id":   row.lookup_entity_ref,
                    "target_entity_name": target
                        .map(|t| Some(t.logicalname.clone()))
                        .unwrap_or(row.lookup_entity_ln),
                    "display_field":      target
                        .map(|t| t.primary_name_attribute.clone())
                        .unwrap_or(row.lookup_display_field),
                })
            } else {
                row.options.unwrap_or(Value::Null)
            };
            // D-426 — a choice field's individual option labels. Additive:
            // `option_labels` sits alongside the existing `choices`/`multi`
            // keys so a client that doesn't know about it yet is unaffected.
            // Only added when at least one choice actually resolved to a
            // label, so an entity with no translated options keeps the exact
            // options shape it always returned.
            if field_type == "choice"
                && let Some(choices) = options.get("choices").and_then(|c| c.as_array()).cloned()
            {
                let mut option_labels = serde_json::Map::new();
                for choice in &choices {
                    let Some(value) = choice.as_str() else {
                        continue;
                    };
                    if let Some(r) = labels.resolve(
                        "choice_option",
                        &format!("{logicalname}.{name}.{value}"),
                        requested_locale,
                        &dep_locale,
                    ) {
                        option_labels
                            .insert(value.to_owned(), Value::String(r.display_name.clone()));
                    }
                }
                if !option_labels.is_empty()
                    && let Some(obj) = options.as_object_mut()
                {
                    obj.insert("option_labels".to_owned(), Value::Object(option_labels));
                }
            }
            FieldSchemaDef {
                id: row.id,
                entity_id,
                name,
                display_name,
                field_type,
                options,
                sort_order: i as i32,
                is_required: row.required.unwrap_or(false),
            }
        })
        .collect();
    drop(registry);

    let base_display = facts.display_name.unwrap_or_default();
    let display = labels
        .resolve("entity", logicalname, requested_locale, &dep_locale)
        .map(|r| r.display_name.clone())
        .unwrap_or(base_display);

    // M01 Core P3 gap (D-455) — an arc-swap registry read, no extra query.
    let relationships: Vec<RelationshipSchemaEntry> = state
        .relationships
        .load()
        .for_entity(logicalname)
        .into_iter()
        .filter_map(|def| {
            let side = def.other_side(logicalname)?;
            Some(RelationshipSchemaEntry {
                name: def.name.clone(),
                // This entity is entity_a (this_column == "a_id") -> the
                // label for MY OWN sub-grid is role_b ("B's role, from A's
                // point of view" = exactly what A's form should show).
                label: if side.this_column == "a_id" {
                    def.role_b.clone()
                } else {
                    def.role_a.clone()
                },
                other_entity: side.other_entity.to_owned(),
                cascade: def.cascade.as_db_str().to_owned(),
            })
        })
        .collect();

    let business_rules = client_business_rules(state, ctx, logicalname).await?;
    let is_master = attome_records::entity_crud::master::is_master(state, logicalname).await?;

    Ok(EntitySchemaDef {
        id: entity_id,
        name: display.clone(),
        plural_name: format!("{display}s"),
        fields,
        relationships,
        business_rules,
        is_master,
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/schema/{logicalname}", get(get_schema))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(get_schema))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_etag_is_weak_stable_and_follows_the_body() {
        let a = schema_etag(br#"{"fields":[]}"#);
        assert!(a.starts_with("W/\""));
        assert_eq!(a, schema_etag(br#"{"fields":[]}"#));
        // A different rule set for another role is a different body.
        assert_ne!(a, schema_etag(br#"{"fields":[],"business_rules":[{}]}"#));
    }

    #[test]
    fn schema_if_none_match_compares_weakly_and_accepts_lists_and_star() {
        let tag = schema_etag(b"x");
        assert!(not_modified(Some(&tag), &tag));
        assert!(not_modified(Some(tag.trim_start_matches("W/")), &tag));
        assert!(not_modified(Some(&format!("W/\"other\", {tag}")), &tag));
        assert!(not_modified(Some("*"), &tag));
        assert!(!not_modified(Some("W/\"other\""), &tag));
        assert!(!not_modified(None, &tag));
    }
}
