//! M45 Phase 2 — Rules Engine: the in-memory snapshot of `rule`,
//! consulted on every entity write (`attome-server::entity_mutation`) and by the
//! admin API's test/publish actions.
//!
//! **Why this lives in `attome-core` rather than `attome-server`.** Same
//! reason `state_registry` does (see its own header comment, D-394
//! "Option B"): `entity_mutation::create_one`/`update_one`
//! live in `attome-server`, but the registry type also has to sit on `EngineState`
//! itself, and `EngineState` is defined here.
//!
//! **Cache shape.** A small, admin-authored table (rules change by human
//! edit, not by request volume) — this deliberately does *not* reuse
//! `EntityMetaRegistry`'s incremental `metadata_change_log` catch-up
//! machinery, for the same reason `state_registry` opts out: that table is
//! entity/attribute-shaped and rules are not entities. Instead this mirrors
//! the identical full-snapshot-reload pattern that registry already uses: an `ArcSwap`-backed `MetadataCache` pre-warmed at boot, refreshed in
//! full on a Redis pub/sub doorbell (`RULE_VERSION_CHANNEL`) and on
//! subscriber reconnect (`attome-server/src/system.rs`) — never a per-request
//! DB read on the entity-write hot path.
//!
//! **Deliberately holds no `attome_rules::Compiled` value.** This module is
//! pure metadata (strings), same posture `state_transition.
//! guard_expression` takes as a plain nullable `TEXT` column here. Parsing,
//! type-checking against an entity's live attribute schema, and caching the
//! compiled form is `attome-server::rule_engine`'s job — this crate has no
//! attribute-type mapping to build a `attome_rules::Schema` from (that mapping
//! is `FieldType::from_int` plus `rule_engine::rules_type_of`, one layer up), and
//! keeping the compile step there means a rule whose target field's type
//! changed after the rule was authored degrades to "skip + log", not a
//! crash inside this registry's reload path.
//!
//! **Business rules (D-789, D-791).** A `kind = 'business'` row carries no
//! expression; its condition tree, audience (`rule_role`) and
//! policies (`rule_policy`) load into [`RuleEntry::business`] as
//! [`BusinessRuleDef`]s — three queries per reload, no N+1. Expression kinds
//! stay in [`RuleEntry::rules`].

use std::collections::HashMap;

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

use crate::business_rules::{
    AppliesTo, BUSINESS_KIND, BusinessRuleDef, ConditionTree, PolicyDef, PolicyType, RuleAudience,
    SetMode, Severity, Stage,
};

/// Redis pub/sub channel: any node that writes `rule` best-effort
/// publishes here so every other node's `EngineState::rules` cache reloads
/// promptly instead of only on its next reconnect. Payload is unused (a
/// doorbell, not an instruction) — same posture as
/// `attome_core::FORM_VERSION_CHANNEL`/`STATE_MODEL_VERSION_CHANNEL`.
pub const RULE_VERSION_CHANNEL: &str = "rule_version";

/// One expression-kind `rule` row: `visibility | requirement |
/// policy | routing` (carried through for their consumers; see the M45 plan).
/// A `business` row is never a `RuleDef`: see [`BusinessRuleDef`].
#[derive(Clone, Debug, PartialEq)]
pub struct RuleDef {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub name: String,
    pub kind: String,
    pub target_field: Option<String>,
    pub expression: String,
    pub message: Option<String>,
    /// `error` | `warning`.
    pub severity: String,
    pub is_active: bool,
    pub display_order: i32,
    /// The currently-published snapshot number — bumped only by
    /// `POST .../publish`, so this can lag behind an in-progress edit that
    /// has been saved via PATCH but not yet published. Used as half of the
    /// compiled-rule cache key (`attome-server::rule_engine`) alongside `id`, so
    /// a publish invalidates the cached `Compiled` for the old version simply
    /// by no longer being looked up under it.
    pub version: i32,
    pub row_version: i64,
}

/// Every rule configured for one entity, in `display_order` order (the order
/// `entity_mutation.rs` evaluates them in, and the order the admin UI lists
/// them in).
#[derive(Clone, Debug, Default)]
pub struct RuleEntry {
    /// Expression-kind rows, in `display_order`.
    pub rules: Vec<RuleDef>,
    /// Business rules (active and inactive), in `display_order` then name.
    pub business: Vec<BusinessRuleDef>,
}

impl RuleEntry {
    /// The active business rules whose audience includes `audience`, in
    /// order. A rule may still hold no policy that binds this writer (a
    /// lock-only rule for a system context): use
    /// [`BusinessRuleDef::policies_for`].
    pub fn business_rules_for<'a>(
        &'a self,
        audience: &'a RuleAudience<'a>,
    ) -> impl Iterator<Item = &'a BusinessRuleDef> + 'a {
        self.business
            .iter()
            .filter(move |r| r.is_active && r.applies_to_audience(audience))
    }

    /// Whether any business-rule policy binds `audience` — the gate that lets
    /// an entity without applicable rules skip the merged-record read.
    pub fn has_business_rules_for(&self, audience: &RuleAudience<'_>) -> bool {
        self.business
            .iter()
            .any(|r| r.policies_for(audience).next().is_some())
    }

    /// Active rules of one `kind`, in configured order. `entity_mutation.rs`
    /// filters by kind in-process rather than the registry doing it, since a
    /// caller almost always wants all three evaluated kinds together for one
    /// write (validation, then default, then calculation) and the per-entity
    /// row count is small enough that a second index buys nothing.
    pub fn active_of_kind<'a>(&'a self, kind: &'a str) -> impl Iterator<Item = &'a RuleDef> {
        self.rules
            .iter()
            .filter(move |r| r.is_active && r.kind == kind)
    }
}

/// Snapshot of every `rule` row (active and inactive — callers
/// decide, same split `state_registry` uses), keyed by
/// `entity_logicalname`. Swapped in atomically by `EngineState::rules` — see
/// `attome-server/src/system.rs`'s pre-warm + pub/sub reload.
#[derive(Clone, Debug, Default)]
pub struct RuleRegistry {
    by_entity: HashMap<String, RuleEntry>,
    /// Business rows that could not be decoded (a malformed condition or
    /// policy — possible only by bypassing the admin API). They are left out
    /// of the snapshot, logged at `error` on load, and listed here so the
    /// admin surface can flag them.
    invalid: Vec<InvalidRule>,
}

/// A business rule the registry could not load.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidRule {
    pub id: Uuid,
    pub entity_logicalname: String,
    pub name: String,
    pub reason: String,
}

impl RuleRegistry {
    /// A registry of expression-kind rows only (tests and callers without
    /// business rules).
    pub fn from_entries(defs: Vec<RuleDef>) -> Self {
        Self::from_parts(defs, Vec::new(), Vec::new())
    }

    /// Builds the snapshot from expression-kind rows, business rules and the business
    /// rows that failed to decode.
    pub fn from_parts(
        defs: Vec<RuleDef>,
        business: Vec<BusinessRuleDef>,
        invalid: Vec<InvalidRule>,
    ) -> Self {
        let mut by_entity: HashMap<String, RuleEntry> = HashMap::new();
        for def in defs {
            by_entity
                .entry(def.entity_logicalname.clone())
                .or_default()
                .rules
                .push(def);
        }
        for rule in business {
            by_entity
                .entry(rule.entity_logicalname.clone())
                .or_default()
                .business
                .push(rule);
        }
        for entry in by_entity.values_mut() {
            entry.rules.sort_by_key(|r| r.display_order);
            entry
                .business
                .sort_by(|a, b| (a.display_order, &a.name).cmp(&(b.display_order, &b.name)));
        }
        Self { by_entity, invalid }
    }

    /// Business rows left out of this snapshot because they failed to decode.
    pub fn invalid(&self) -> &[InvalidRule] {
        &self.invalid
    }

    /// `None` means this entity has no configured rule at all — callers
    /// treat that as "nothing to enforce", same "no model configured ->
    /// no-op" posture `StateModelRegistry::get` uses.
    pub fn get(&self, entity_logicalname: &str) -> Option<&RuleEntry> {
        self.by_entity.get(entity_logicalname)
    }

    /// Rows in the snapshot: expression-kind rows plus business rows.
    pub fn len(&self) -> usize {
        self.by_entity
            .values()
            .map(|e| e.rules.len() + e.business.len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.by_entity.is_empty()
    }
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: Uuid,
    entity_logicalname: String,
    name: String,
    kind: String,
    target_field: Option<String>,
    expression: Option<String>,
    message: Option<String>,
    severity: String,
    is_active: bool,
    display_order: i32,
    version: i32,
    row_version: i64,
    display_name: Option<String>,
    applies_to: String,
    condition: Option<serde_json::Value>,
}

#[derive(sqlx::FromRow)]
struct RoleRow {
    rule_ref: Uuid,
    role_ref: Option<Uuid>,
    portal_role_ref: Option<Uuid>,
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    rule_ref: Uuid,
    ordinal: i32,
    policy_type: String,
    field_logicalname: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    value: Option<serde_json::Value>,
    expression: Option<String>,
    set_mode: Option<String>,
    stage: Option<String>,
    enforce_from: Option<chrono::NaiveDate>,
}

impl PolicyRow {
    fn into_def(self) -> Result<PolicyDef, String> {
        let policy_type = PolicyType::parse(&self.policy_type)
            .ok_or_else(|| format!("unknown policy type '{}'", self.policy_type))?;
        let severity = self
            .severity
            .as_deref()
            .map(|s| Severity::parse(s).ok_or_else(|| format!("unknown severity '{s}'")))
            .transpose()?;
        let mode = self
            .set_mode
            .as_deref()
            .map(|m| SetMode::parse(m).ok_or_else(|| format!("unknown set_mode '{m}'")))
            .transpose()?;
        let stage = self
            .stage
            .as_deref()
            .map(|s| Stage::parse(s).ok_or_else(|| format!("unknown stage '{s}'")))
            .transpose()?;
        let ordinal = self.ordinal;
        let def = PolicyDef {
            policy_type,
            field: self.field_logicalname,
            message: self.message,
            severity,
            value: self.value,
            expression: self.expression,
            mode,
            stage,
            enforce_from: self.enforce_from,
            ordinal,
        };
        if def.effect().is_none() {
            return Err(format!("policy {ordinal} is malformed"));
        }
        Ok(def)
    }
}

/// Builds a full registry snapshot from Postgres: three queries (rules, live
/// role associations, policies), no N+1. Only live (`is_deleted = false`)
/// rules; a rule's own `is_active` flag (business enable/disable) is loaded
/// but not filtered on here — same split `state_registry` already uses,
/// callers decide. A staff role association counts only while
/// the role is live (`role.is_deleted = false`); a soft-deleted
/// role's association is inert and the admin API drops it on the rule's next
/// save. A business row that fails to decode is left out and listed in
/// [`RuleRegistry::invalid`] (logged at `error`), so one malformed row
/// cannot stop every other rule from loading.
pub async fn load(db: &DbPool) -> Result<RuleRegistry, AppError> {
    let rows: Vec<RuleRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, name, kind, target_field, expression, message, \
                severity, is_active, display_order, version, row_version, \
                display_name, applies_to, condition \
         FROM rule WHERE is_deleted = false",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let role_rows: Vec<RoleRow> = sqlx::query_as(
        "SELECT rr.rule_ref, rr.role_ref, rr.portal_role_ref \
         FROM rule_role rr \
         JOIN rule r ON r.id = rr.rule_ref \
         LEFT JOIN role sr ON sr.id = rr.role_ref \
         WHERE r.is_deleted = false AND r.kind = $1 \
           AND (rr.portal_role_ref IS NOT NULL OR sr.is_deleted = false)",
    )
    .bind(BUSINESS_KIND)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let policy_rows: Vec<PolicyRow> = sqlx::query_as(
        "SELECT p.rule_ref, p.ordinal, p.policy_type, p.field_logicalname, p.message, \
                p.severity, p.value, p.expression, p.set_mode, p.stage, p.enforce_from \
         FROM rule_policy p \
         JOIN rule r ON r.id = p.rule_ref \
         WHERE r.is_deleted = false AND r.kind = $1 \
         ORDER BY p.rule_ref, p.ordinal",
    )
    .bind(BUSINESS_KIND)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let registry = assemble(rows, role_rows, policy_rows);
    for bad in registry.invalid() {
        tracing::error!(
            rule_id = %bad.id,
            entity = %bad.entity_logicalname,
            rule = %bad.name,
            reason = %bad.reason,
            "rule_registry: business rule failed to load and is not enforced"
        );
    }
    Ok(registry)
}

/// The pure half of [`load`]: rows in, snapshot out.
fn assemble(
    rows: Vec<RuleRow>,
    role_rows: Vec<RoleRow>,
    policy_rows: Vec<PolicyRow>,
) -> RuleRegistry {
    let mut staff_roles: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    let mut portal_roles: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for r in role_rows {
        if let Some(role) = r.role_ref {
            staff_roles.entry(r.rule_ref).or_default().push(role);
        }
        if let Some(role) = r.portal_role_ref {
            portal_roles.entry(r.rule_ref).or_default().push(role);
        }
    }
    let mut policies: HashMap<Uuid, Vec<Result<PolicyDef, String>>> = HashMap::new();
    for p in policy_rows {
        policies.entry(p.rule_ref).or_default().push(p.into_def());
    }

    let mut expression_rows = Vec::new();
    let mut business = Vec::new();
    let mut invalid = Vec::new();
    for r in rows {
        if r.kind != BUSINESS_KIND {
            // `ck_core_rule_shape` guarantees an expression on a non-business row;
            // a missing one is listed as invalid rather than failing every
            // rule's load.
            let Some(expression) = r.expression else {
                invalid.push(InvalidRule {
                    reason: format!("'{}' rule without an expression", r.kind),
                    id: r.id,
                    entity_logicalname: r.entity_logicalname,
                    name: r.name,
                });
                continue;
            };
            expression_rows.push(RuleDef {
                id: r.id,
                entity_logicalname: r.entity_logicalname,
                name: r.name,
                kind: r.kind,
                target_field: r.target_field,
                expression,
                message: r.message,
                severity: r.severity,
                is_active: r.is_active,
                display_order: r.display_order,
                version: r.version,
                row_version: r.row_version,
            });
            continue;
        }
        match decode_business(&r, &mut staff_roles, &mut portal_roles, &mut policies) {
            Ok(def) => business.push(def),
            Err(reason) => invalid.push(InvalidRule {
                id: r.id,
                entity_logicalname: r.entity_logicalname,
                name: r.name,
                reason,
            }),
        }
    }
    RuleRegistry::from_parts(expression_rows, business, invalid)
}

fn decode_business(
    r: &RuleRow,
    staff_roles: &mut HashMap<Uuid, Vec<Uuid>>,
    portal_roles: &mut HashMap<Uuid, Vec<Uuid>>,
    policies: &mut HashMap<Uuid, Vec<Result<PolicyDef, String>>>,
) -> Result<BusinessRuleDef, String> {
    let applies_to = AppliesTo::parse(&r.applies_to)
        .ok_or_else(|| format!("unknown applies_to '{}'", r.applies_to))?;
    let condition: ConditionTree = match &r.condition {
        Some(v) => serde_json::from_value(v.clone())
            .map_err(|e| format!("condition does not decode: {e}"))?,
        None => return Err("business rule without a condition".to_owned()),
    };
    let policies = policies
        .remove(&r.id)
        .unwrap_or_default()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BusinessRuleDef {
        id: r.id,
        entity_logicalname: r.entity_logicalname.clone(),
        name: r.name.clone(),
        display_name: r.display_name.clone(),
        is_active: r.is_active,
        display_order: r.display_order,
        version: r.version,
        row_version: r.row_version,
        applies_to,
        role_ids: staff_roles.remove(&r.id).unwrap_or_default(),
        portal_role_ids: portal_roles.remove(&r.id).unwrap_or_default(),
        condition,
        policies,
    })
}

/// C-18 — `spawn_doorbell_reload::<RuleRegistry>` (`attome-server/src/
/// system.rs`) is the only caller of this impl's `load`; every other call
/// site keeps calling the free `load` fn above directly (unchanged).
impl crate::snapshot_source::SnapshotSource for RuleRegistry {
    const CHANNEL: &'static str = RULE_VERSION_CHANNEL;

    fn load(db: &DbPool) -> crate::snapshot_source::BoxFuture<'_, Result<Self, AppError>> {
        Box::pin(load(db))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_source::SnapshotSource;

    #[test]
    fn snapshot_source_channel_matches_the_public_constant() {
        assert_eq!(
            <RuleRegistry as SnapshotSource>::CHANNEL,
            RULE_VERSION_CHANNEL
        );
    }

    fn def(entity: &str, name: &str, kind: &str, display_order: i32, is_active: bool) -> RuleDef {
        RuleDef {
            id: Uuid::now_v7(),
            entity_logicalname: entity.to_owned(),
            name: name.to_owned(),
            kind: kind.to_owned(),
            target_field: Some("amount".to_owned()),
            expression: "amount > 0".to_owned(),
            message: None,
            severity: "error".to_owned(),
            is_active,
            display_order,
            version: 1,
            row_version: 0,
        }
    }

    #[test]
    fn get_returns_none_for_an_unconfigured_entity() {
        let reg = RuleRegistry::default();
        assert!(reg.get("service_ticket").is_none());
    }

    #[test]
    fn rules_are_ordered_by_display_order() {
        let reg = RuleRegistry::from_entries(vec![
            def("service_ticket", "second", "validation", 20, true),
            def("service_ticket", "first", "validation", 10, true),
        ]);
        let entry = reg.get("service_ticket").unwrap();
        assert_eq!(entry.rules[0].name, "first");
        assert_eq!(entry.rules[1].name, "second");
    }

    #[test]
    fn active_of_kind_filters_both_kind_and_is_active() {
        let reg = RuleRegistry::from_entries(vec![
            def("service_ticket", "v1", "validation", 10, true),
            def("service_ticket", "v2_disabled", "validation", 20, false),
            def("service_ticket", "c1", "calculation", 30, true),
        ]);
        let entry = reg.get("service_ticket").unwrap();
        let validations: Vec<&str> = entry
            .active_of_kind("validation")
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(validations, vec!["v1"]);
    }

    #[test]
    fn entities_are_partitioned_independently() {
        let reg = RuleRegistry::from_entries(vec![
            def("service_ticket", "a", "validation", 10, true),
            def("support_case", "b", "validation", 10, true),
        ]);
        assert!(reg.get("service_ticket").is_some());
        assert!(reg.get("support_case").is_some());
        assert_eq!(reg.len(), 2);
    }

    fn rule_row(kind: &str, name: &str, condition: Option<serde_json::Value>) -> RuleRow {
        RuleRow {
            id: Uuid::now_v7(),
            entity_logicalname: "support_case".to_owned(),
            name: name.to_owned(),
            kind: kind.to_owned(),
            target_field: None,
            expression: (kind != BUSINESS_KIND).then(|| "true".to_owned()),
            message: None,
            severity: "error".to_owned(),
            is_active: true,
            display_order: 0,
            version: 1,
            row_version: 3,
            display_name: None,
            applies_to: "roles".to_owned(),
            condition,
        }
    }

    fn policy_row(rule_ref: Uuid, ordinal: i32, policy_type: &str) -> PolicyRow {
        PolicyRow {
            rule_ref,
            ordinal,
            policy_type: policy_type.to_owned(),
            field_logicalname: Some("amount".to_owned()),
            message: None,
            severity: None,
            value: None,
            expression: None,
            set_mode: None,
        }
    }

    #[test]
    fn assemble_joins_roles_and_policies_and_isolates_bad_rows() {
        let good = rule_row(
            BUSINESS_KIND,
            "good",
            Some(serde_json::json!({ "all": [] })),
        );
        let bad_condition = rule_row(
            BUSINESS_KIND,
            "bad_condition",
            Some(serde_json::json!({ "all": [], "any": [] })),
        );
        let bad_policy = rule_row(
            BUSINESS_KIND,
            "bad_policy",
            Some(serde_json::json!({ "all": [] })),
        );
        let routing = rule_row("routing", "route", None);
        let staff = Uuid::now_v7();
        let portal = Uuid::now_v7();
        let roles = vec![
            RoleRow {
                rule_ref: good.id,
                role_ref: Some(staff),
                portal_role_ref: None,
            },
            RoleRow {
                rule_ref: good.id,
                role_ref: None,
                portal_role_ref: Some(portal),
            },
        ];
        // set_value with neither a value nor an expression.
        let mut malformed = policy_row(bad_policy.id, 0, "set_value");
        malformed.set_mode = Some("always".to_owned());
        let policies = vec![
            policy_row(good.id, 0, "disabled"),
            policy_row(good.id, 1, "hidden"),
            malformed,
        ];
        let (good_id, bad_condition_id, bad_policy_id) = (good.id, bad_condition.id, bad_policy.id);
        let reg = assemble(
            vec![good, bad_condition, bad_policy, routing],
            roles,
            policies,
        );

        let entry = reg.get("support_case").unwrap();
        assert_eq!(entry.rules.len(), 1);
        assert_eq!(entry.business.len(), 1);
        let rule = &entry.business[0];
        assert_eq!(rule.id, good_id);
        assert_eq!(rule.applies_to, AppliesTo::Roles);
        assert_eq!(rule.role_ids, vec![staff]);
        assert_eq!(rule.portal_role_ids, vec![portal]);
        assert_eq!(rule.policies.len(), 2);
        assert_eq!(rule.policies[1].ordinal, 1);

        let invalid: Vec<Uuid> = reg.invalid().iter().map(|i| i.id).collect();
        assert_eq!(invalid, vec![bad_condition_id, bad_policy_id]);

        let held = [staff];
        let user = RuleAudience::Staff {
            role_ids: &held,
            interactive: true,
        };
        assert_eq!(entry.business_rules_for(&user).count(), 1);
        assert!(entry.has_business_rules_for(&user));
        // A lock-only rule binds neither a system context nor a service
        // principal (D-791 rule 3).
        assert!(!entry.has_business_rules_for(&RuleAudience::System));
        let service = RuleAudience::Staff {
            role_ids: &held,
            interactive: false,
        };
        assert!(!entry.has_business_rules_for(&service));
        let portal_user = RuleAudience::Portal { role_id: portal };
        assert!(entry.has_business_rules_for(&portal_user));
    }
}
