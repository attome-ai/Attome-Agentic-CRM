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
//! - the entity's active state model (B18-T13): its state field, initial
//!   state and live transitions with their guard source, so a device offers
//!   only the moves the model allows and checks their guards before queuing
//!   one. A transition taken offline is an ordinary update of the state
//!   field; the push runs it through the same mutation path, which checks the
//!   transition and its guard again and fires the entity's triggers after
//!   the commit. A transition that needs an approval is listed but marked, as
//!   only the server can start the approval.
//!
//! `bundle_version` is a SHA-256 over all of that, so a device refetches only
//! when it changed. No profile (or the pack not installed) is 404.

use std::collections::HashSet;

use attome_core::business_rules::{AppliesTo, ConditionTree, PolicyDef, RuleAudience};
use attome_core::state_registry::StateModelEntry;
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
    /// B18-T13: the entity's active state model, if it has one.
    pub state_model: Option<OfflineStateModel>,
}

/// An entity's state model, as a device needs it.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct OfflineStateModel {
    pub name: String,
    pub state_field: String,
    pub initial_state: String,
    /// Live transitions, in display order.
    pub transitions: Vec<OfflineTransition>,
}

/// One allowed move.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct OfflineTransition {
    pub from_state: String,
    pub to_state: String,
    pub name: String,
    /// The guard's source in `language`; none when the move is unguarded.
    pub guard_expression: Option<String>,
    pub language: String,
    /// The privilege the move needs; the server checks it on push.
    pub required_privilege: Option<String>,
    /// Needs an approval: only the server can start it, so a device sends
    /// it only when online.
    pub requires_approval: bool,
}

/// The device's view of a state model: none when the entity has no model,
/// or its model is switched off. Pure.
pub fn offline_state_model(entry: Option<&StateModelEntry>) -> Option<OfflineStateModel> {
    let entry = entry?;
    let model = entry.model.as_ref().filter(|m| m.is_active)?;
    let mut transitions: Vec<_> = entry.transitions.iter().collect();
    transitions.sort_by_key(|t| t.display_order);
    Some(OfflineStateModel {
        name: model.name.clone(),
        state_field: model.state_field.clone(),
        initial_state: model.initial_state.clone(),
        transitions: transitions
            .into_iter()
            .map(|t| OfflineTransition {
                from_state: t.from_state.clone(),
                to_state: t.to_state.clone(),
                name: t.name.clone(),
                guard_expression: t.guard_expression.clone().filter(|g| !g.trim().is_empty()),
                language: RULE_LANGUAGE.to_owned(),
                required_privilege: t.required_privilege.clone(),
                requires_approval: t.requires_approval(),
            })
            .collect(),
    })
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
        .filter(|a| a.is_read_gated())
        .map(|a| a.logicalname.as_str())
        .collect();
    let attributes = meta
        .attrs
        .iter()
        .filter(|a| !a.is_read_gated())
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
                .any(|a| &a.logicalname == n && !a.is_read_gated())
        })
        .collect();

    let state_model = offline_state_model(state.state_models.load().get(&entity));
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
        state_model,
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
            state_model: None,
        };
        let a = bundle_version(&[entity("account")]);
        assert_eq!(a.len(), 64);
        assert_eq!(a, bundle_version(&[entity("account")]));
        assert_ne!(a, bundle_version(&[entity("contact")]));
    }

    fn transition(from: &str, to: &str, order: i32) -> attome_core::state_registry::TransitionDef {
        attome_core::state_registry::TransitionDef {
            id: Uuid::nil(),
            model_ref: Uuid::nil(),
            from_state: from.into(),
            to_state: to.into(),
            name: format!("{from}->{to}"),
            required_privilege: None,
            guard_expression: None,
            entry_actions: Vec::new(),
            exit_actions: Vec::new(),
            display_order: order,
            row_version: 1,
            approval_plan: None,
            pending_state: None,
            on_reject_state: None,
            auto_condition: None,
        }
    }

    #[test]
    fn offline_profile_state_model_lists_live_transitions() {
        let model = attome_core::state_registry::StateModelDef {
            id: Uuid::nil(),
            entity_logicalname: "activity".into(),
            name: "Activity Lifecycle".into(),
            state_field: "status".into(),
            initial_state: "open".into(),
            is_active: true,
            row_version: 1,
            rules: Default::default(),
        };
        let mut guarded = transition("open", "completed", 0);
        guarded.guard_expression = Some("subject != ''".into());
        let mut blank = transition("open", "cancelled", 1);
        blank.guard_expression = Some("  ".into());
        let entry = StateModelEntry {
            model: Some(model.clone()),
            transitions: vec![transition("completed", "open", 2), blank, guarded],
        };
        let offline = offline_state_model(Some(&entry)).unwrap();
        assert_eq!(offline.state_field, "status");
        assert_eq!(offline.initial_state, "open");
        assert_eq!(
            offline
                .transitions
                .iter()
                .map(|t| (t.from_state.as_str(), t.to_state.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("open", "completed"),
                ("open", "cancelled"),
                ("completed", "open")
            ]
        );
        assert_eq!(
            offline.transitions[0].guard_expression.as_deref(),
            Some("subject != ''")
        );
        assert_eq!(
            offline.transitions[1].guard_expression, None,
            "a blank guard is none"
        );
        assert_eq!(offline.transitions[0].language, "v1");
        assert!(!offline.transitions[0].requires_approval);

        let off = StateModelEntry {
            model: Some(attome_core::state_registry::StateModelDef {
                is_active: false,
                ..model
            }),
            transitions: Vec::new(),
        };
        assert_eq!(offline_state_model(Some(&off)), None);
        assert_eq!(offline_state_model(None), None);
    }
}
