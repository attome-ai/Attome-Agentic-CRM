//! `GET /api/v1/offline/profile` (roadmap B18-T4): what the caller's device
//! keeps offline.
//!
//! The profile is the first enabled `offline_profile` (the offline pack,
//! B18-T2) whose role the caller holds, by name. For each of its entities the
//! caller may read, the answer carries the attribute metadata **without any
//! sensitive attribute** (those never reach a device) and the rules a device
//! needs to validate an edit before it syncs:
//!
//! - expression rules as their source and language version. The browser
//!   evaluator is the same `attome-rules` compiler built for the web (Z11-T13),
//!   so the source *is* the portable program, and it compiles there exactly as
//!   it does here; a rule whose target field is sensitive is left out;
//! - business rules that apply to the caller, as their condition tree and the
//!   policies that bind the caller, in the rule API's wire shape.
//!
//! `bundle_version` is a SHA-256 over all of that, so a device refetches only
//! when it changed. No profile (or the pack not installed) is 404.

use std::collections::HashSet;

use attome_core::business_rules::{AppliesTo, ConditionTree, PolicyDef, RuleAudience};
use attome_core::{EngineState, FieldType};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{Json, extract::State};
use serde::Serialize;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// The language the server compiles expression rules in
/// (`attome_rules::compile_with_budgets`).
const RULE_LANGUAGE: &str = "v1";

/// The profile a device follows.
#[derive(Debug, Serialize, ToSchema)]
pub struct OfflineProfile {
    pub id: Uuid,
    pub name: String,
    pub max_storage_mb: Option<f64>,
    pub max_days_offline: Option<f64>,
    pub include_maps: bool,
    pub entities: Vec<OfflineEntity>,
    /// Hex SHA-256 of `entities`: changes whenever the metadata or rules do.
    pub bundle_version: String,
}

/// One entity the device keeps.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OfflineEntity {
    pub entity: String,
    /// The stored query that picks the records; none keeps what the caller
    /// may read, up to `max_rows`.
    pub stored_query: Option<String>,
    /// Lookup attributes whose targets come along.
    pub include_related: Vec<String>,
    pub include_files: bool,
    pub max_rows: Option<f64>,
    pub primary_name_attribute: Option<String>,
    pub attributes: Vec<OfflineAttribute>,
    pub rules: Vec<OfflineRule>,
    pub business_rules: Vec<OfflineBusinessRule>,
}

/// An attribute the device may hold; never a sensitive one.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OfflineAttribute {
    pub logicalname: String,
    /// The field type's name (`text`, `lookup`, …).
    pub field_type: String,
    pub is_required: bool,
    pub max_length: Option<i32>,
    /// Writable only with a field-security grant: shown, not edited offline.
    pub is_write_restricted: bool,
}

/// An expression rule, as source in its language version.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OfflineRule {
    pub id: Uuid,
    pub name: String,
    /// `visibility`, `requirement`, `policy`, `routing`, …
    pub kind: String,
    pub target_field: Option<String>,
    pub expression: String,
    pub language: String,
    pub message: Option<String>,
    pub severity: String,
    pub version: i32,
}

/// A business rule that applies to the caller.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OfflineBusinessRule {
    pub id: Uuid,
    pub name: String,
    pub label: String,
    pub applies_to: AppliesTo,
    pub condition: ConditionTree,
    pub policies: Vec<PolicyDef>,
    pub version: i32,
}

#[derive(Debug, sqlx::FromRow)]
struct ProfileRow {
    id: Uuid,
    name: String,
    max_storage_mb: Option<f64>,
    max_days_offline: Option<f64>,
    include_maps: Option<bool>,
}

#[derive(Debug, sqlx::FromRow)]
struct ProfileEntityRow {
    entity_logicalname: String,
    stored_query_ref: Option<String>,
    include_related: Option<String>,
    include_files: Option<bool>,
    max_rows: Option<f64>,
}

/// Comma-, semicolon- or whitespace-separated names, each once. Pure.
pub fn name_list(raw: Option<&str>) -> Vec<String> {
    let mut seen = HashSet::new();
    raw.unwrap_or_default()
        .split([',', ';', ' ', '\n', '\t'])
        .map(str::trim)
        .filter(|n| !n.is_empty() && seen.insert(n.to_owned()))
        .map(str::to_owned)
        .collect()
}

/// The hex SHA-256 of the entities' JSON. Pure.
pub fn bundle_version(entities: &[OfflineEntity]) -> String {
    let bytes = serde_json::to_vec(entities).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

/// Builds one entity's offline view from the live registries, or none when
/// the entity is unknown or the caller may not read it.
fn offline_entity(
    state: &EngineState,
    ctx: &SecurityContext,
    row: ProfileEntityRow,
) -> Option<OfflineEntity> {
    let entity = row.entity_logicalname.trim().to_owned();
    if ctx.require(&entity, "read").is_err() {
        return None;
    }
    let registry = state.entities.load();
    let meta = registry.get(&entity)?;
    let sensitive: HashSet<&str> = meta
        .attrs
        .iter()
        .filter(|a| a.is_sensitive)
        .map(|a| a.logicalname.as_str())
        .collect();
    let attributes = meta
        .attrs
        .iter()
        .filter(|a| !a.is_sensitive)
        .map(|a| OfflineAttribute {
            logicalname: a.logicalname.clone(),
            field_type: FieldType::from_int(a.field_type_int)
                .map(|t| t.as_str().to_owned())
                .unwrap_or_default(),
            is_required: a.is_required,
            max_length: a.max_length,
            is_write_restricted: a.is_write_restricted,
        })
        .collect();
    let include_related = name_list(row.include_related.as_deref())
        .into_iter()
        .filter(|n| {
            meta.attrs
                .iter()
                .any(|a| &a.logicalname == n && !a.is_sensitive)
        })
        .collect();

    let rules_snapshot = state.rules.load();
    let (rules, business_rules) = match rules_snapshot.get(&entity) {
        None => (Vec::new(), Vec::new()),
        Some(entry) => {
            let rules = entry
                .rules
                .iter()
                .filter(|r| r.is_active)
                .filter(|r| {
                    r.target_field
                        .as_deref()
                        .is_none_or(|f| !sensitive.contains(f))
                })
                .map(|r| OfflineRule {
                    id: r.id,
                    name: r.name.clone(),
                    kind: r.kind.clone(),
                    target_field: r.target_field.clone(),
                    expression: r.expression.clone(),
                    language: RULE_LANGUAGE.to_owned(),
                    message: r.message.clone(),
                    severity: r.severity.clone(),
                    version: r.version,
                })
                .collect();
            let audience = match ctx.role_ids.as_deref() {
                Some(role_ids) => RuleAudience::Staff {
                    role_ids,
                    interactive: !ctx.service_principal,
                },
                None => RuleAudience::System,
            };
            let business = entry
                .business_rules_for(&audience)
                .map(|r| OfflineBusinessRule {
                    id: r.id,
                    name: r.name.clone(),
                    label: r.label().to_owned(),
                    applies_to: r.applies_to,
                    condition: r.condition.clone(),
                    policies: r
                        .policies_for(&audience)
                        .filter(|p| p.field.as_deref().is_none_or(|f| !sensitive.contains(f)))
                        .cloned()
                        .collect(),
                    version: r.version,
                })
                .collect();
            (rules, business)
        }
    };
    Some(OfflineEntity {
        entity,
        stored_query: row
            .stored_query_ref
            .map(|q| q.trim().to_owned())
            .filter(|q| !q.is_empty()),
        include_related,
        include_files: row.include_files.unwrap_or(false),
        max_rows: row.max_rows,
        primary_name_attribute: meta.primary_name_attribute.clone(),
        attributes,
        rules,
        business_rules,
    })
}

/// The caller's offline profile, or none.
pub async fn resolve(
    state: &EngineState,
    ctx: &SecurityContext,
) -> Result<Option<OfflineProfile>, AppError> {
    let role_ids = ctx.role_ids.clone().unwrap_or_default();
    if role_ids.is_empty() {
        return Ok(None);
    }
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('offline_profile') IS NOT NULL \
            AND to_regclass('offline_profile_entity') IS NOT NULL",
    )
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(None);
    }
    let Some(profile): Option<ProfileRow> = sqlx::query_as(
        "SELECT id, name, max_storage_mb::float8 AS max_storage_mb, \
                max_days_offline::float8 AS max_days_offline, include_maps \
           FROM offline_profile \
          WHERE role_ref = ANY($1) AND coalesce(is_enabled, true) \
            AND (is_active IS NULL OR is_active = true) \
          ORDER BY name, id LIMIT 1",
    )
    .bind(&role_ids)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    else {
        return Ok(None);
    };
    let rows: Vec<ProfileEntityRow> = sqlx::query_as(
        "SELECT entity_logicalname, stored_query_ref, include_related, include_files, \
                max_rows::float8 AS max_rows \
           FROM offline_profile_entity \
          WHERE profile_ref = $1 AND (is_active IS NULL OR is_active = true) \
          ORDER BY entity_logicalname, id",
    )
    .bind(profile.id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let entities: Vec<OfflineEntity> = rows
        .into_iter()
        .filter_map(|row| offline_entity(state, ctx, row))
        .collect();
    Ok(Some(OfflineProfile {
        id: profile.id,
        name: profile.name,
        max_storage_mb: profile.max_storage_mb,
        max_days_offline: profile.max_days_offline,
        include_maps: profile.include_maps.unwrap_or(false),
        bundle_version: bundle_version(&entities),
        entities,
    }))
}

/// B18-T4: the caller's offline profile with entity metadata (no sensitive
/// attribute) and the rules a device evaluates before it syncs.
#[utoipa::path(
    get,
    path = "/api/v1/offline/profile",
    tag = "offline",
    responses(
        (status = 200, description = "Success", body = OfflineProfile),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No offline profile for the caller's roles", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_offline_profile(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<OfflineProfile>, AppError> {
    resolve(&state, &ctx)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_profile_name_lists_split_and_dedupe() {
        assert_eq!(
            name_list(Some("account_ref, owner;account_ref  contact_ref")),
            vec!["account_ref", "owner", "contact_ref"]
        );
        assert!(name_list(None).is_empty());
    }

    #[test]
    fn offline_profile_bundle_version_follows_content() {
        let entity = |name: &str| OfflineEntity {
            entity: name.into(),
            stored_query: None,
            include_related: Vec::new(),
            include_files: false,
            max_rows: Some(5000.0),
            primary_name_attribute: None,
            attributes: Vec::new(),
            rules: Vec::new(),
            business_rules: Vec::new(),
        };
        let a = bundle_version(&[entity("account")]);
        assert_eq!(a.len(), 64);
        assert_eq!(a, bundle_version(&[entity("account")]));
        assert_ne!(a, bundle_version(&[entity("contact")]));
    }
}
