//! The `rule` store (M45/D-472, business rules D-789 as amended by
//! D-790/D-791; `document/general/BUSINESS-RULES-DESIGN.md` §6–§7): the wire
//! types of the `/api/v1/admin/business-rules` family, the normalized write
//! input, validation (§6.2), editor warnings (§6.4), the transaction-scoped
//! writes, the bundle/changeset reconcile (`reconcile_rule`, `retire_rule`)
//! and the export mapping. The HTTP handlers are `business_rule_admin.rs`.
//!
//! **Kinds.** `business` is the rule feature. The expression kinds
//! (`visibility`, `requirement`, `policy`, `routing`; Topic 15 #6) keep their
//! expression shape and are authored through the same family. Any other kind
//! is refused (`kind_unknown`). D-658's `quality` kind is not accepted: the
//! table CHECK (`ck_core_rule_kind`) does not allow it yet.
//!
//! **Concurrency (guidelines §2, design §6.3).** Create is idempotent by
//! `(entity, name)` among live rows (`core_rule_entity_name_idx`): a repeat
//! with the same definition answers 200, a different one 409 `rule_exists`.
//! PATCH takes `If-Match: "<row_version>"`. Each write is one transaction:
//! the rule row, its child rows replaced as sets, the audit event and the
//! changeset record. Publish serializes per rule on
//! `pg_try_advisory_xact_lock(attome_api::ADVISORY_LOCK_NAMESPACE,
//! hashtext('attome-api/rule-publish:{id}'))` (D-351).
//!
//! **Layers (D-785, D-791 rule 2).** A write under an open changeset (or a
//! break-glass window) is stamped with the changeset's layer and recorded as
//! `upsert_rule`/`retire_rule`/`publish_rule`. A write in `auto` mode with no
//! changeset is a customer edit: stamped `customer`, allowed only on
//! customer-layer rows, and not recorded (Phase 3 records customer
//! changesets). Our changesets may change or retire any rule.

use std::collections::{HashMap, HashSet};

use attome_core::business_rules::{
    self as br, AppliesTo, BUSINESS_KIND, BusinessRuleSpec, ConditionTree,
    MAX_ACTIVE_RULES_PER_ENTITY, PolicyDef, PolicyType, RuleIssue, SetMode, Severity,
};
use attome_core::changeset::{Layer, Op, Origin, RecordedOp, Recording, errors};
use attome_core::release_report::{self as rr, Baseline, ConflictValues, Decision, NewItem};
use attome_core::{AttrInfo, EngineState};
use attome_metadata::provision::{ReconcileOutcome, ReconcilePolicy};
use attome_records::query_admin::{
    ReconcileStep, customized_marker, map_unique_violation, reconcile_step, resolve_live_entity_id,
};
use attome_records::rule_engine;
use attome_rules::parse;
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use fred::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgConnection;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::admin_hooks as hooks;
use crate::bundle::model::{PortalRoleKey, RuleDef};

/// Kinds that keep their expression shape (Topic 15 #6).
pub(crate) const EXPRESSION_KINDS: [&str; 4] = ["visibility", "requirement", "policy", "routing"];
/// Expression kinds that act on one attribute.
const KINDS_REQUIRING_TARGET_FIELD: [&str; 2] = ["visibility", "requirement"];
/// Expression kinds whose expression must type as `Bool`.
const KINDS_REQUIRING_BOOL_RESULT: [&str; 1] = ["requirement"];
const MAX_NAME_CHARS: usize = 128;
const MAX_DISPLAY_NAME_CHARS: usize = 200;

// ── Wire types ──────────────────────────────────────────────────────────────

/// One role a business rule applies to.
#[derive(Clone, Debug, PartialEq, Serialize, ToSchema)]
pub(crate) struct RuleRoleRef {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    /// `true` for a web-portal role, `false` for a staff role.
    pub(crate) portal_role: bool,
    /// The portal's keyword (portal roles only; `None` when the portal is
    /// gone or the portal module is not installed).
    pub(crate) portal: Option<String>,
    /// `false` for a soft-deleted staff role: inert, dropped on the rule's
    /// next save (design §1.1, §8.4).
    pub(crate) live: bool,
}

/// An editor warning (design §6.4). Never blocks a write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub(crate) struct RuleEditorWarning {
    /// `required_field_locked`, `rule_applies_to_admins`, `no_matching_users`,
    /// `set_value_conflict`, `locks_everyone`.
    pub(crate) code: String,
    pub(crate) message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) field: Option<String>,
}

fn warning(code: &str, message: impl Into<String>, field: Option<&str>) -> RuleEditorWarning {
    RuleEditorWarning {
        code: code.to_owned(),
        message: message.into(),
        field: field.map(str::to_owned),
    }
}

fn issue(path: &str, code: &str, message: impl Into<String>) -> RuleIssue {
    RuleIssue {
        path: path.to_owned(),
        code: code.to_owned(),
        message: message.into(),
    }
}

/// A rule as the admin API returns it: the row, its roles and its policies.
/// An expression kind carries `expression`/`target_field`/`message`; a business
/// rule carries `applies_to`/`roles`/`condition`/`policies`.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub(crate) struct BusinessRule {
    pub(crate) id: Uuid,
    pub(crate) entity_logicalname: String,
    pub(crate) name: String,
    /// `business`, or an expression kind (`visibility`, `requirement`,
    /// `policy`, `routing`).
    pub(crate) kind: String,
    pub(crate) display_name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) applies_to: AppliesTo,
    pub(crate) roles: Vec<RuleRoleRef>,
    pub(crate) condition: Option<ConditionTree>,
    pub(crate) policies: Vec<PolicyDef>,
    pub(crate) target_field: Option<String>,
    pub(crate) expression: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) severity: String,
    pub(crate) is_active: bool,
    pub(crate) display_order: i32,
    pub(crate) version: i32,
    pub(crate) row_version: i64,
    /// Solution 7 (D-785): `platform`, `product`, `project` or `customer`.
    pub(crate) owner_layer: String,
    /// Set when a Solution 7 hook turned the rule off (`field_deleted:<f>`,
    /// `field_retyped:<f>`); cleared when an admin turns it back on.
    pub(crate) disabled_reason: Option<String>,
    /// `applies_to = roles` with no live role: the rule applies to nobody.
    pub(crate) applies_to_nobody: bool,
    /// Why the stored condition or a policy could not be decoded (possible
    /// only by bypassing this API); the registry does not enforce such a rule.
    pub(crate) load_error: Option<String>,
    /// Editor warnings (single-rule reads and writes; empty in lists).
    pub(crate) warnings: Vec<RuleEditorWarning>,
}

/// `POST /api/v1/admin/business-rules` and `/validate` (design §6.1).
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
pub(crate) struct BusinessRuleBody {
    #[serde(alias = "entity_logicalname")]
    pub(crate) entity: String,
    pub(crate) name: String,
    /// `business` (default) or an expression kind.
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) display_name: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) applies_to: Option<AppliesTo>,
    #[serde(default)]
    pub(crate) role_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub(crate) portal_role_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub(crate) condition: Option<ConditionTree>,
    #[serde(default)]
    pub(crate) policies: Option<Vec<PolicyDef>>,
    #[serde(default)]
    pub(crate) target_field: Option<String>,
    #[serde(default)]
    pub(crate) expression: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) severity: Option<String>,
    #[serde(default)]
    pub(crate) is_active: Option<bool>,
    #[serde(default)]
    pub(crate) display_order: Option<i32>,
}

/// `PATCH /api/v1/admin/business-rules/{id}`: any field of
/// [`BusinessRuleBody`]; `entity` and `name` may be sent but not changed.
#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
pub(crate) struct BusinessRulePatch {
    #[serde(default, alias = "entity_logicalname")]
    pub(crate) entity: Option<String>,
    #[serde(default)]
    pub(crate) name: Option<String>,
    #[serde(default)]
    pub(crate) kind: Option<String>,
    #[serde(default)]
    pub(crate) display_name: Option<String>,
    #[serde(default)]
    pub(crate) description: Option<String>,
    #[serde(default)]
    pub(crate) applies_to: Option<AppliesTo>,
    #[serde(default)]
    pub(crate) role_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub(crate) portal_role_ids: Option<Vec<Uuid>>,
    #[serde(default)]
    pub(crate) condition: Option<ConditionTree>,
    #[serde(default)]
    pub(crate) policies: Option<Vec<PolicyDef>>,
    #[serde(default)]
    pub(crate) target_field: Option<String>,
    #[serde(default)]
    pub(crate) expression: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) severity: Option<String>,
    #[serde(default)]
    pub(crate) is_active: Option<bool>,
    #[serde(default)]
    pub(crate) display_order: Option<i32>,
}

// ── The normalized write input ──────────────────────────────────────────────

/// A rule as it will be stored: a business rule (condition + policies +
/// audience) or an expression kind (expression). Compared whole for the
/// idempotent create and the compare-first reconcile.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RuleInput {
    pub(crate) entity: String,
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) display_name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) applies_to: AppliesTo,
    /// Sorted, de-duplicated.
    pub(crate) role_ids: Vec<Uuid>,
    /// Sorted, de-duplicated.
    pub(crate) portal_role_ids: Vec<Uuid>,
    pub(crate) condition: Option<ConditionTree>,
    /// `ordinal` = list index.
    pub(crate) policies: Vec<PolicyDef>,
    pub(crate) target_field: Option<String>,
    pub(crate) expression: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) severity: String,
    pub(crate) is_active: bool,
    pub(crate) display_order: i32,
}

impl RuleInput {
    pub(crate) fn is_business(&self) -> bool {
        self.kind == BUSINESS_KIND
    }

    pub(crate) fn same_definition(&self, other: &RuleInput) -> bool {
        self == other
    }
}

fn trimmed(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn sorted(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    ids.sort();
    ids.dedup();
    ids
}

fn numbered(mut policies: Vec<PolicyDef>) -> Vec<PolicyDef> {
    for (i, p) in policies.iter_mut().enumerate() {
        p.ordinal = i32::try_from(i).unwrap_or(i32::MAX);
    }
    policies
}

/// Normalizes a body into a [`RuleInput`]: kind default and routing, the
/// legacy conversion, and the shape checks that need no attributes. Issues
/// are reported, not raised, so `/validate` can return them.
pub(crate) fn input_from_body(body: BusinessRuleBody) -> Result<RuleInput, Vec<RuleIssue>> {
    let mut issues = Vec::new();
    let entity = body.entity.trim().to_owned();
    let name = body.name.trim().to_owned();
    if entity.is_empty() {
        issues.push(issue("entity", "entity_required", "entity is required"));
    }
    if name.is_empty() {
        issues.push(issue("name", "name_required", "rule name is required"));
    } else if name.chars().count() > MAX_NAME_CHARS {
        issues.push(issue(
            "name",
            "name_too_long",
            format!("a rule name may hold at most {MAX_NAME_CHARS} characters"),
        ));
    }
    let display_name = trimmed(body.display_name);
    if display_name
        .as_deref()
        .is_some_and(|d| d.chars().count() > MAX_DISPLAY_NAME_CHARS)
    {
        issues.push(issue(
            "display_name",
            "display_name_too_long",
            format!("a display name may hold at most {MAX_DISPLAY_NAME_CHARS} characters"),
        ));
    }
    let kind = trimmed(body.kind).unwrap_or_else(|| BUSINESS_KIND.to_owned());
    let is_active = body.is_active.unwrap_or(true);
    let display_order = body.display_order.unwrap_or(0);
    let has_business_fields = body.condition.is_some()
        || body.policies.as_ref().is_some_and(|p| !p.is_empty())
        || body.role_ids.as_ref().is_some_and(|r| !r.is_empty())
        || body.portal_role_ids.as_ref().is_some_and(|r| !r.is_empty())
        || body.applies_to == Some(AppliesTo::Roles);
    let has_legacy_fields =
        body.expression.is_some() || body.target_field.is_some() || body.message.is_some();

    let mut input = RuleInput {
        entity,
        name,
        kind: kind.clone(),
        display_name,
        description: trimmed(body.description),
        applies_to: AppliesTo::All,
        role_ids: Vec::new(),
        portal_role_ids: Vec::new(),
        condition: None,
        policies: Vec::new(),
        target_field: None,
        expression: None,
        message: None,
        severity: "error".to_owned(),
        is_active,
        display_order,
    };

    if kind == BUSINESS_KIND {
        if has_legacy_fields {
            issues.push(issue(
                "expression",
                "legacy_field_on_business_rule",
                "a business rule takes a condition and policies, not expression, target_field or message",
            ));
        }
        match body.condition {
            Some(c) => input.condition = Some(c),
            None => issues.push(issue(
                "condition",
                "condition_required",
                "a business rule needs a condition ({\"all\": []} means always)",
            )),
        }
        input.applies_to = body.applies_to.unwrap_or_default();
        input.role_ids = sorted(body.role_ids.unwrap_or_default());
        input.portal_role_ids = sorted(body.portal_role_ids.unwrap_or_default());
        input.policies = numbered(body.policies.unwrap_or_default());
    } else if EXPRESSION_KINDS.contains(&kind.as_str()) {
        if has_business_fields {
            issues.push(issue(
                "kind",
                "business_field_on_legacy_rule",
                format!(
                    "a '{kind}' rule takes an expression; use kind 'business' for conditions, roles and policies"
                ),
            ));
        }
        let severity = trimmed(body.severity).unwrap_or_else(|| "error".to_owned());
        if Severity::parse(&severity).is_none() {
            issues.push(issue(
                "severity",
                "severity_unknown",
                format!("severity '{severity}' is not one of error|warning"),
            ));
        }
        let expression = body.expression.filter(|e| !e.trim().is_empty());
        let Some(expression) = expression else {
            issues.push(issue(
                "expression",
                "expression_required",
                "expression is required",
            ));
            return Err(issues);
        };
        let target_field = trimmed(body.target_field);
        if KINDS_REQUIRING_TARGET_FIELD.contains(&kind.as_str()) && target_field.is_none() {
            issues.push(issue(
                "target_field",
                "target_field_required",
                format!("kind '{kind}' requires target_field"),
            ));
        }
        input.target_field = target_field;
        input.expression = Some(expression);
        input.message = body.message;
        input.severity = severity;
    } else {
        issues.push(issue(
            "kind",
            "kind_unknown",
            format!(
                "kind '{kind}' is not one of business|{}",
                EXPRESSION_KINDS.join("|")
            ),
        ));
    }
    if issues.is_empty() {
        Ok(input)
    } else {
        Err(issues)
    }
}

/// The body a stored rule would be re-submitted as (PATCH merges onto it).
/// Soft-deleted staff roles are dropped here: "the admin API removes it on
/// the rule's next save" (design §1.1).
pub(crate) fn body_of(rule: &BusinessRule) -> BusinessRuleBody {
    let business = rule.kind == BUSINESS_KIND;
    BusinessRuleBody {
        entity: rule.entity_logicalname.clone(),
        name: rule.name.clone(),
        kind: Some(rule.kind.clone()),
        display_name: rule.display_name.clone(),
        description: rule.description.clone(),
        applies_to: business.then_some(rule.applies_to),
        role_ids: business.then(|| {
            rule.roles
                .iter()
                .filter(|r| !r.portal_role && r.live)
                .map(|r| r.id)
                .collect()
        }),
        portal_role_ids: business.then(|| {
            rule.roles
                .iter()
                .filter(|r| r.portal_role)
                .map(|r| r.id)
                .collect()
        }),
        condition: rule.condition.clone(),
        policies: business.then(|| rule.policies.clone()),
        target_field: rule.target_field.clone(),
        expression: rule.expression.clone(),
        message: rule.message.clone(),
        severity: (!business).then(|| rule.severity.clone()),
        is_active: Some(rule.is_active),
        display_order: Some(rule.display_order),
    }
}

/// Merges a PATCH onto the stored rule. A patch that changes `kind` replaces
/// the definition (it must carry the new kind's fields); `display_name`,
/// `description`, `is_active` and `display_order` carry over.
pub(crate) fn merge_patch(
    rule: &BusinessRule,
    patch: BusinessRulePatch,
) -> Result<BusinessRuleBody, AppError> {
    if patch
        .entity
        .as_deref()
        .is_some_and(|e| e.trim() != rule.entity_logicalname)
        || patch.name.as_deref().is_some_and(|n| n.trim() != rule.name)
    {
        return Err(AppError::Validation(
            "a rule's entity and name cannot be changed; create a new rule instead".into(),
        ));
    }
    let base = body_of(rule);
    let kind_changes = patch.kind.as_deref().is_some_and(|k| k.trim() != rule.kind);
    let mut body = if kind_changes {
        BusinessRuleBody {
            entity: base.entity.clone(),
            name: base.name.clone(),
            display_name: base.display_name.clone(),
            description: base.description.clone(),
            is_active: base.is_active,
            display_order: base.display_order,
            ..BusinessRuleBody::default()
        }
    } else {
        base
    };
    macro_rules! over {
        ($($f:ident),*) => { $( if patch.$f.is_some() { body.$f = patch.$f; } )* };
    }
    over!(
        kind,
        display_name,
        description,
        applies_to,
        role_ids,
        portal_role_ids,
        condition,
        policies,
        target_field,
        expression,
        message,
        severity,
        is_active,
        display_order
    );
    Ok(body)
}

/// The issues as one 422 message (`path: message; ...`).
pub(crate) fn issues_error(issues: &[RuleIssue]) -> AppError {
    AppError::Validation(
        issues
            .iter()
            .map(|i| format!("{}: {}", i.path, i.message))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

// ── Reading ─────────────────────────────────────────────────────────────────

pub(crate) const RULE_COLUMNS: &str = "id, entity_logicalname, name, kind, display_name, \
     description, applies_to, condition, target_field, expression, message, severity, \
     is_active, display_order, version, row_version, owner_layer, disabled_reason";

#[derive(sqlx::FromRow)]
pub(crate) struct RuleRow {
    id: Uuid,
    entity_logicalname: String,
    name: String,
    kind: String,
    display_name: Option<String>,
    description: Option<String>,
    applies_to: String,
    condition: Option<Value>,
    target_field: Option<String>,
    expression: Option<String>,
    message: Option<String>,
    severity: String,
    is_active: bool,
    display_order: i32,
    version: i32,
    row_version: i64,
    owner_layer: String,
    disabled_reason: Option<String>,
}

#[derive(sqlx::FromRow)]
struct RoleLinkRow {
    rule_ref: Uuid,
    role_ref: Option<Uuid>,
    portal_role_ref: Option<Uuid>,
    name: Option<String>,
    webportal_id: Option<Uuid>,
    live: bool,
}

#[derive(sqlx::FromRow)]
struct PolicyRow {
    rule_ref: Uuid,
    ordinal: i32,
    policy_type: String,
    field_logicalname: Option<String>,
    message: Option<String>,
    severity: Option<String>,
    value: Option<Value>,
    expression: Option<String>,
    set_mode: Option<String>,
}

fn decode_policy(p: PolicyRow) -> Result<PolicyDef, String> {
    let policy_type = PolicyType::parse(&p.policy_type)
        .ok_or_else(|| format!("unknown policy type '{}'", p.policy_type))?;
    let severity = match p.severity.as_deref() {
        Some(s) => Some(Severity::parse(s).ok_or_else(|| format!("unknown severity '{s}'"))?),
        None => None,
    };
    let mode = match p.set_mode.as_deref() {
        Some(m) => Some(SetMode::parse(m).ok_or_else(|| format!("unknown set_mode '{m}'"))?),
        None => None,
    };
    Ok(PolicyDef {
        policy_type,
        field: p.field_logicalname,
        message: p.message,
        severity,
        value: p.value,
        expression: p.expression,
        mode,
        ordinal: p.ordinal,
    })
}

/// Whether the runtime-provisioned `webportal` table exists (only where
/// the portal module was installed): checked before every read of it so a
/// deployment without portals never 500s.
async fn has_portal_table(conn: &mut PgConnection) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass('webportal') IS NOT NULL")
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)
}

/// Portal keywords by portal id.
async fn portal_keywords(
    conn: &mut PgConnection,
    ids: &[Uuid],
) -> Result<HashMap<Uuid, String>, AppError> {
    if ids.is_empty() || !has_portal_table(conn).await? {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT id, keyword FROM webportal WHERE id = ANY($1)")
            .bind(ids)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .filter_map(|(id, k)| k.map(|k| (id, k)))
        .collect())
}

/// Rows plus their roles and policies (three queries, no N+1).
pub(crate) async fn assemble_rules(
    conn: &mut PgConnection,
    rows: Vec<RuleRow>,
) -> Result<Vec<BusinessRule>, AppError> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut roles: HashMap<Uuid, Vec<RuleRoleRef>> = HashMap::new();
    let mut policies: HashMap<Uuid, Vec<Result<PolicyDef, String>>> = HashMap::new();
    if !ids.is_empty() {
        let links: Vec<RoleLinkRow> = sqlx::query_as(
            "SELECT rr.rule_ref, rr.role_ref, rr.portal_role_ref, \
                    COALESCE(sr.name, pr.name) AS name, pr.webportal_id, \
                    COALESCE(rr.portal_role_ref IS NOT NULL OR sr.is_deleted = false, false) AS live \
             FROM rule_role rr \
             LEFT JOIN role sr ON sr.id = rr.role_ref \
             LEFT JOIN webportal_role pr ON pr.id = rr.portal_role_ref \
             WHERE rr.rule_ref = ANY($1) \
             ORDER BY rr.rule_ref, name",
        )
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let portal_ids: Vec<Uuid> = links.iter().filter_map(|l| l.webportal_id).collect();
        let keywords = portal_keywords(conn, &portal_ids).await?;
        for l in links {
            let (id, portal_role) = match (l.role_ref, l.portal_role_ref) {
                (Some(id), _) => (id, false),
                (None, Some(id)) => (id, true),
                (None, None) => continue,
            };
            roles.entry(l.rule_ref).or_default().push(RuleRoleRef {
                id,
                name: l.name.unwrap_or_default(),
                portal_role,
                portal: l.webportal_id.and_then(|p| keywords.get(&p).cloned()),
                live: l.live,
            });
        }
        let policy_rows: Vec<PolicyRow> = sqlx::query_as(
            "SELECT rule_ref, ordinal, policy_type, field_logicalname, message, severity, \
                    value, expression, set_mode \
             FROM rule_policy WHERE rule_ref = ANY($1) ORDER BY rule_ref, ordinal",
        )
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        for p in policy_rows {
            policies
                .entry(p.rule_ref)
                .or_default()
                .push(decode_policy(p));
        }
    }
    Ok(rows
        .into_iter()
        .map(|r| {
            let mut load_error = None;
            let condition = match r.condition {
                Some(v) => match serde_json::from_value::<ConditionTree>(v) {
                    Ok(c) => Some(c),
                    Err(e) => {
                        load_error = Some(format!("condition does not decode: {e}"));
                        None
                    }
                },
                None => None,
            };
            let mut decoded = Vec::new();
            for p in policies.remove(&r.id).unwrap_or_default() {
                match p {
                    Ok(p) => decoded.push(p),
                    Err(e) => load_error = Some(e),
                }
            }
            let applies_to = AppliesTo::parse(&r.applies_to).unwrap_or(AppliesTo::All);
            let roles = roles.remove(&r.id).unwrap_or_default();
            let applies_to_nobody = applies_to == AppliesTo::Roles && !roles.iter().any(|x| x.live);
            BusinessRule {
                id: r.id,
                entity_logicalname: r.entity_logicalname,
                name: r.name,
                kind: r.kind,
                display_name: r.display_name,
                description: r.description,
                applies_to,
                roles,
                condition,
                policies: decoded,
                target_field: r.target_field,
                expression: r.expression,
                message: r.message,
                severity: r.severity,
                is_active: r.is_active,
                display_order: r.display_order,
                version: r.version,
                row_version: r.row_version,
                owner_layer: r.owner_layer,
                disabled_reason: r.disabled_reason,
                applies_to_nobody,
                load_error,
                warnings: Vec::new(),
            }
        })
        .collect())
}

/// One live (not deleted) rule, any activity.
pub(crate) async fn read_rule(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<BusinessRule>, AppError> {
    let row: Option<RuleRow> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM rule WHERE id = $1 AND is_deleted = false"
    ))
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else { return Ok(None) };
    Ok(assemble_rules(conn, vec![row]).await?.pop())
}

/// The live rule keyed by `(entity, name)`.
pub(crate) async fn read_rule_by_key(
    conn: &mut PgConnection,
    entity: &str,
    name: &str,
) -> Result<Option<BusinessRule>, AppError> {
    let row: Option<RuleRow> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM rule \
         WHERE entity_logicalname = $1 AND name = $2 AND is_deleted = false"
    ))
    .bind(entity)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else { return Ok(None) };
    Ok(assemble_rules(conn, vec![row]).await?.pop())
}

/// The stored rule as a [`RuleInput`] (for comparison). `None` when it no
/// longer converts (a decode error): it then never compares equal.
pub(crate) fn input_of(rule: &BusinessRule) -> Option<RuleInput> {
    if rule.load_error.is_some() {
        return None;
    }
    input_from_body(body_of(rule)).ok()
}

// ── Validation (§6.2) and warnings (§6.4) ───────────────────────────────────

/// What [`check`] found: blocking issues and editor warnings.
#[derive(Debug, Default)]
pub(crate) struct Checked {
    pub(crate) issues: Vec<RuleIssue>,
    pub(crate) warnings: Vec<RuleEditorWarning>,
}

pub(crate) fn attrs_for_entity(state: &EngineState, entity: &str) -> Option<Vec<AttrInfo>> {
    state.entities.load().get(entity).map(|m| m.attrs.clone())
}

/// The entity's live attributes read straight from Postgres. The in-memory
/// registry follows the metadata change log asynchronously (pub/sub
/// doorbell), so an entity or a field created a moment ago can be missing
/// from it; rule authoring is a rare admin write, so it validates against
/// the database instead of failing `entity_unknown` / "not a field".
async fn attrs_for_entity_fresh(
    conn: &mut PgConnection,
    state: &EngineState,
    entity: &str,
) -> Result<Option<Vec<AttrInfo>>, AppError> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM entity_info \
         WHERE logicalname = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(entity)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = id else {
        return Ok(None);
    };
    Ok(attome_core::fetch_entity_snapshot(&state.base.db, id)
        .await?
        .map(|meta| meta.attrs))
}

fn advanced_expressions<'a>(tree: &'a ConditionTree, out: &mut Vec<&'a str>) {
    match tree {
        ConditionTree::All(g) => g.all.iter().for_each(|c| advanced_expressions(c, out)),
        ConditionTree::Any(g) => g.any.iter().for_each(|c| advanced_expressions(c, out)),
        ConditionTree::Expression(e) => out.push(e.expression.as_str()),
        ConditionTree::Leaf(_) => {}
    }
}

/// `rule_engine::check_field_read_access` as an issue (M45 plan §5: an admin
/// never authors a rule over a sensitive field they cannot read).
fn read_access_issue(
    ctx: Option<&SecurityContext>,
    entity: &str,
    attrs: &[AttrInfo],
    path: &str,
    expression: &str,
) -> Option<RuleIssue> {
    let ctx = ctx?;
    let expr = parse(expression).ok()?; // a parse error is reported by the compiler
    rule_engine::check_field_read_access(ctx, entity, attrs, &expr)
        .err()
        .map(|e| issue(path, "field_not_readable", e.to_string()))
}

/// Validates a normalized rule against the live schema, roles and limits
/// (design §6.2) and computes its warnings (§6.4). `ctx` is the authoring
/// admin (field read access); `None` for trusted bundle/changeset content.
/// `self_id` is the rule being updated (excluded from the limit and from
/// `set_value_conflict`).
pub(crate) async fn check(
    conn: &mut PgConnection,
    state: &EngineState,
    ctx: Option<&SecurityContext>,
    input: &RuleInput,
    self_id: Option<Uuid>,
) -> Result<Checked, AppError> {
    let mut out = Checked::default();
    let Some(attrs) = attrs_for_entity_fresh(conn, state, &input.entity).await? else {
        out.issues.push(issue(
            "entity",
            "entity_unknown",
            format!(
                "no registered entity found with logicalname '{}'",
                input.entity
            ),
        ));
        return Ok(out);
    };
    if input.is_business() {
        check_business(conn, state, ctx, input, self_id, &attrs, &mut out).await?;
    } else {
        check_legacy(ctx, input, &attrs, &mut out);
    }
    Ok(out)
}

fn check_legacy(
    ctx: Option<&SecurityContext>,
    input: &RuleInput,
    attrs: &[AttrInfo],
    out: &mut Checked,
) {
    let Some(expression) = input.expression.as_deref() else {
        out.issues.push(issue(
            "expression",
            "expression_required",
            "expression is required",
        ));
        return;
    };
    if let Some(target) = input.target_field.as_deref()
        && !attrs.iter().any(|a| a.logicalname == target)
    {
        out.issues.push(issue(
            "target_field",
            "field_unknown",
            format!("'{target}' is not a field of this entity"),
        ));
    }
    if let Some(i) = read_access_issue(ctx, &input.entity, attrs, "expression", expression) {
        out.issues.push(i);
    }
    let schema = rule_engine::schema_for_entity(attrs);
    match attome_rules::compile(expression, &schema) {
        Ok(compiled) => {
            if KINDS_REQUIRING_BOOL_RESULT.contains(&input.kind.as_str())
                && let Err(e) = rule_engine::check_boolean_result_type(&compiled)
            {
                out.issues
                    .push(issue("expression", "expression_not_boolean", e.to_string()));
            }
        }
        Err(e) => out.issues.push(issue(
            "expression",
            e.code(),
            format!("expression failed to compile: {e}"),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
async fn check_business(
    conn: &mut PgConnection,
    state: &EngineState,
    ctx: Option<&SecurityContext>,
    input: &RuleInput,
    self_id: Option<Uuid>,
    attrs: &[AttrInfo],
    out: &mut Checked,
) -> Result<(), AppError> {
    let Some(condition) = input.condition.as_ref() else {
        out.issues.push(issue(
            "condition",
            "condition_required",
            "a business rule needs a condition",
        ));
        return Ok(());
    };
    let spec = BusinessRuleSpec {
        applies_to: input.applies_to,
        staff_role_count: input.role_ids.len(),
        portal_role_count: input.portal_role_ids.len(),
        condition,
        policies: &input.policies,
    };
    let compiled = match br::validate_rule(&spec, attrs) {
        Ok(c) => Some(c),
        Err(mut issues) => {
            out.issues.append(&mut issues);
            None
        }
    };

    // Field read access: structured leaves, advanced leaves, set_value
    // expressions.
    if let Some(ctx) = ctx {
        for field in condition.leaf_fields() {
            if attrs
                .iter()
                .any(|a| a.logicalname == field && a.is_sensitive)
                && !ctx.has_field_read_grant(&input.entity, field)
            {
                out.issues.push(issue(
                    "condition",
                    "field_not_readable",
                    format!("rule references field '{field}' you do not have read access to"),
                ));
            }
        }
    }
    let mut exprs = Vec::new();
    advanced_expressions(condition, &mut exprs);
    for e in exprs {
        if let Some(i) = read_access_issue(ctx, &input.entity, attrs, "condition", e) {
            out.issues.push(i);
        }
    }
    for (i, p) in input.policies.iter().enumerate() {
        if let Some(e) = p.expression.as_deref()
            && let Some(iss) = read_access_issue(
                ctx,
                &input.entity,
                attrs,
                &format!("policies[{i}].expression"),
                e,
            )
        {
            out.issues.push(iss);
        }
    }

    // Roles: every staff role live, every portal role existing.
    if !input.role_ids.is_empty() {
        let live: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM role WHERE id = ANY($1) AND is_deleted = false")
                .bind(&input.role_ids)
                .fetch_all(&mut *conn)
                .await
                .map_err(AppError::internal)?;
        for id in input.role_ids.iter().filter(|id| !live.contains(id)) {
            out.issues.push(issue(
                "role_ids",
                "role_not_live",
                format!("staff role {id} does not exist or was deleted"),
            ));
        }
    }
    if !input.portal_role_ids.is_empty() {
        let found: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM webportal_role WHERE id = ANY($1)")
                .bind(&input.portal_role_ids)
                .fetch_all(&mut *conn)
                .await
                .map_err(AppError::internal)?;
        for id in input
            .portal_role_ids
            .iter()
            .filter(|id| !found.contains(id))
        {
            out.issues.push(issue(
                "portal_role_ids",
                "portal_role_unknown",
                format!("portal role {id} does not exist"),
            ));
        }
    }

    // The per-entity limit on active business rules.
    if input.is_active {
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rule WHERE entity_logicalname = $1 AND kind = $2 \
               AND is_deleted = false AND is_active = true AND ($3::uuid IS NULL OR id <> $3)",
        )
        .bind(&input.entity)
        .bind(BUSINESS_KIND)
        .bind(self_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        if usize::try_from(active).unwrap_or(usize::MAX) >= MAX_ACTIVE_RULES_PER_ENTITY {
            out.issues.push(issue(
                "is_active",
                "too_many_rules",
                format!(
                    "an entity may hold at most {MAX_ACTIVE_RULES_PER_ENTITY} active business rules"
                ),
            ));
        }
    }

    if compiled.is_some() {
        out.warnings = warnings(conn, state, input, self_id, attrs).await?;
    }
    Ok(())
}

/// The editor warnings of design §6.4. Never blocking.
async fn warnings(
    conn: &mut PgConnection,
    state: &EngineState,
    input: &RuleInput,
    self_id: Option<Uuid>,
    attrs: &[AttrInfo],
) -> Result<Vec<RuleEditorWarning>, AppError> {
    let mut out = Vec::new();
    let locks: Vec<&str> = input
        .policies
        .iter()
        .filter(|p| p.policy_type.is_lock())
        .filter_map(|p| p.field.as_deref())
        .collect();
    for field in &locks {
        if attrs
            .iter()
            .any(|a| a.logicalname == *field && a.is_required)
        {
            out.push(warning(
                "required_field_locked",
                format!(
                    "'{field}' is required; a save that leaves it empty while it is locked will fail"
                ),
                Some(field),
            ));
        }
    }
    let always = input
        .condition
        .as_ref()
        .is_some_and(ConditionTree::is_always);
    if !locks.is_empty() && input.applies_to == AppliesTo::All {
        out.push(warning(
            "rule_applies_to_admins",
            "this rule applies to all users, administrators included",
            None,
        ));
        if always {
            out.push(warning(
                "locks_everyone",
                "the condition is always true: these fields are locked for every user",
                None,
            ));
        }
    }
    if input.applies_to == AppliesTo::Roles {
        if !locks.is_empty() && !input.role_ids.is_empty() {
            let admin_holds: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM user_account_mm_role ur \
                   JOIN user_account_mm_role ur2 \
                     ON ur2.user_ref = ur.user_ref AND ur2.is_deleted = false \
                   JOIN role_mm_privilege rp \
                     ON rp.role_ref = ur2.role_ref AND rp.is_deleted = false \
                   JOIN privilege p \
                     ON p.id = rp.privilege_ref AND p.key = 'system.admin' AND p.is_active = true \
                  WHERE ur.role_ref = ANY($1) AND ur.is_deleted = false)",
            )
            .bind(&input.role_ids)
            .fetch_one(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            if admin_holds {
                out.push(warning(
                    "rule_applies_to_admins",
                    "an administrator holds one of these roles and is restricted by this rule",
                    None,
                ));
            }
        }
        let empty_staff: Vec<Uuid> = sqlx::query_scalar(
            "SELECT r.id FROM unnest($1::uuid[]) AS r(id) \
              WHERE NOT EXISTS (SELECT 1 FROM user_account_mm_role ur \
                                 WHERE ur.role_ref = r.id AND ur.is_deleted = false) \
                AND NOT EXISTS (SELECT 1 FROM role_mm_team rt \
                                  JOIN user_account_mm_team ut \
                                    ON ut.team_ref = rt.team_ref AND ut.is_deleted = false \
                                 WHERE rt.role_ref = r.id AND rt.is_deleted = false)",
        )
        .bind(&input.role_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let empty_portal: Vec<Uuid> = sqlx::query_scalar(
            "SELECT r.id FROM unnest($1::uuid[]) AS r(id) \
              WHERE NOT EXISTS (SELECT 1 FROM webportal_user_role u WHERE u.role_id = r.id)",
        )
        .bind(&input.portal_role_ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        for id in empty_staff.iter().chain(&empty_portal) {
            out.push(warning(
                "no_matching_users",
                format!("role {id} has no members yet"),
                None,
            ));
        }
        if input.role_ids.is_empty() && input.portal_role_ids.is_empty() {
            out.push(warning(
                "no_matching_users",
                "this rule applies to roles but names none that still exist: it applies to nobody",
                None,
            ));
        }
    }
    let registry = state.rules.load();
    if let Some(entry) = registry.get(&input.entity) {
        let others: HashSet<&str> = entry
            .business
            .iter()
            .filter(|r| r.is_active && Some(r.id) != self_id)
            .flat_map(|r| r.policies.iter())
            .filter(|p| p.policy_type == PolicyType::SetValue)
            .filter_map(|p| p.field.as_deref())
            .collect();
        for p in &input.policies {
            if p.policy_type == PolicyType::SetValue
                && let Some(field) = p.field.as_deref()
                && others.contains(field)
            {
                out.push(warning(
                    "set_value_conflict",
                    format!("another active rule also sets '{field}'; the later rule wins"),
                    Some(field),
                ));
            }
        }
    }
    Ok(out)
}

// ── Layers and recording (§7, D-791 rule 2) ─────────────────────────────────

/// How one admin write is stamped and recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WriteMode {
    /// The layer a new row gets.
    pub(crate) layer: Layer,
    /// Whether the write records its changeset op.
    pub(crate) record: bool,
    /// A customer edit (`auto` mode, no changeset): only customer-layer rows.
    pub(crate) customer: bool,
}

/// Resolves the changeset (or refuses) before any write. In `auto` mode
/// without a changeset the write is a customer edit (design §7): stamped
/// `customer`, not recorded. A break-glass request and an open changeset keep
/// the recorder's stamping and recording.
pub(crate) async fn write_mode(
    state: &EngineState,
    recording: &Recording,
) -> Result<WriteMode, AppError> {
    let resolved = recording.preflight(&state.base.db).await?;
    Ok(mode_of(resolved.automatic, recording.stamp()?))
}

fn mode_of(automatic: Option<Origin>, stamped: Layer) -> WriteMode {
    if automatic == Some(Origin::Auto) {
        WriteMode {
            layer: Layer::Customer,
            record: false,
            customer: true,
        }
    } else {
        WriteMode {
            layer: stamped,
            record: true,
            customer: false,
        }
    }
}

/// The owner-layer rule for an update, publish or retire.
pub(crate) fn check_owner(
    recording: &Recording,
    mode: WriteMode,
    owner_layer: &str,
) -> Result<(), AppError> {
    if mode.customer {
        if owner_layer == Layer::Customer.as_str() {
            Ok(())
        } else {
            Err(AppError::Conflict(errors::LAYER_MISMATCH))
        }
    } else {
        hooks::check_row_owner(recording, owner_layer)
    }
}

/// Locks the live rule `id` (active too when `only_active`) and returns its
/// `(owner_layer, row_version)`.
pub(crate) async fn lock_rule(
    conn: &mut PgConnection,
    id: Uuid,
    only_active: bool,
) -> Result<(String, i64), AppError> {
    sqlx::query_as(
        "SELECT owner_layer, row_version FROM rule \
         WHERE id = $1 AND is_deleted = false AND (NOT $2 OR is_active = true) FOR UPDATE",
    )
    .bind(id)
    .bind(only_active)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

// ── Writes ──────────────────────────────────────────────────────────────────

fn condition_json(input: &RuleInput) -> Result<Option<Value>, AppError> {
    input
        .condition
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(AppError::internal)
}

/// Inserts a new rule row and its children.
pub(crate) async fn insert_rule(
    conn: &mut PgConnection,
    id: Uuid,
    input: &RuleInput,
    layer: Layer,
    is_customized: bool,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO rule \
             (id, entity_logicalname, name, kind, display_name, description, applies_to, \
              condition, target_field, expression, message, severity, is_active, \
              display_order, version, is_customized, owner_layer) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 1, $15, $16)",
    )
    .bind(id)
    .bind(&input.entity)
    .bind(&input.name)
    .bind(&input.kind)
    .bind(input.display_name.as_deref())
    .bind(input.description.as_deref())
    .bind(input.applies_to.as_str())
    .bind(condition_json(input)?)
    .bind(input.target_field.as_deref())
    .bind(input.expression.as_deref())
    .bind(input.message.as_deref())
    .bind(&input.severity)
    .bind(input.is_active)
    .bind(input.display_order)
    .bind(is_customized)
    .bind(layer.as_str())
    .execute(&mut *conn)
    .await
    .map_err(map_unique_violation)?;
    replace_children(conn, id, input).await
}

/// Updates a rule row in place and replaces its children as sets. Does not
/// touch `version` (publish is its own action) or `owner_layer`. Turning a
/// rule back on clears `disabled_reason`. `is_customized`: `None` keeps it.
pub(crate) async fn update_rule(
    conn: &mut PgConnection,
    id: Uuid,
    input: &RuleInput,
    is_customized: Option<bool>,
) -> Result<(), AppError> {
    let changed = sqlx::query(
        "UPDATE rule SET kind = $2, display_name = $3, description = $4, \
             applies_to = $5, condition = $6, target_field = $7, expression = $8, \
             message = $9, severity = $10, is_active = $11, display_order = $12, \
             disabled_reason = CASE WHEN $11 THEN NULL ELSE disabled_reason END, \
             is_customized = COALESCE($13, is_customized), \
             row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false",
    )
    .bind(id)
    .bind(&input.kind)
    .bind(input.display_name.as_deref())
    .bind(input.description.as_deref())
    .bind(input.applies_to.as_str())
    .bind(condition_json(input)?)
    .bind(input.target_field.as_deref())
    .bind(input.expression.as_deref())
    .bind(input.message.as_deref())
    .bind(&input.severity)
    .bind(input.is_active)
    .bind(input.display_order)
    .bind(is_customized)
    .execute(&mut *conn)
    .await
    .map_err(map_unique_violation)?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::NotFound);
    }
    replace_children(conn, id, input).await
}

/// Replaces the rule's role associations and policies (at most
/// `MAX_ROLES_PER_RULE` + `MAX_POLICIES_PER_RULE` rows, validated before).
async fn replace_children(
    conn: &mut PgConnection,
    id: Uuid,
    input: &RuleInput,
) -> Result<(), AppError> {
    sqlx::query("DELETE FROM rule_role WHERE rule_ref = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    sqlx::query("DELETE FROM rule_policy WHERE rule_ref = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !input.is_business() {
        return Ok(());
    }
    if !input.role_ids.is_empty() {
        sqlx::query(
            "INSERT INTO rule_role (rule_ref, role_ref) \
             SELECT $1, r FROM unnest($2::uuid[]) AS r",
        )
        .bind(id)
        .bind(&input.role_ids)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    if !input.portal_role_ids.is_empty() {
        sqlx::query(
            "INSERT INTO rule_role (rule_ref, portal_role_ref) \
             SELECT $1, r FROM unnest($2::uuid[]) AS r",
        )
        .bind(id)
        .bind(&input.portal_role_ids)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    for (i, p) in input.policies.iter().enumerate() {
        sqlx::query(
            "INSERT INTO rule_policy \
                 (rule_ref, ordinal, policy_type, field_logicalname, message, severity, value, \
                  expression, set_mode) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(i32::try_from(i).unwrap_or(i32::MAX))
        .bind(p.policy_type.as_str())
        .bind(p.field.as_deref())
        .bind(p.message.as_deref())
        .bind(p.severity.map(Severity::as_str))
        .bind(p.value.as_ref())
        .bind(p.expression.as_deref())
        .bind(p.mode.map(SetMode::as_str))
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

/// The DELETE's write: a soft retire (`is_active = false`).
pub(crate) async fn retire_in_tx(conn: &mut PgConnection, id: Uuid) -> Result<(), AppError> {
    let changed = sqlx::query(
        "UPDATE rule SET is_active = false, is_customized = true, \
             row_version = row_version + 1, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false AND is_active = true",
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if changed == 0 {
        return Err(AppError::NotFound);
    }
    Ok(())
}

/// A publish that lost the per-rule lock to a concurrent one: retry shortly.
fn publish_lock_busy() -> AppError {
    AppError::Conflict("this rule is being published by another request, retry shortly")
}

/// The publish's write: takes the per-rule publish lock (D-351 two-argument
/// form, namespace `attome_api::ADVISORY_LOCK_NAMESPACE`), bumps `version`
/// and snapshots `rule` (already re-validated) into `rule_version`:
/// a business rule's whole definition in `definition`, a legacy rule's
/// expression columns. The caller has locked the row and checked its owner.
pub(crate) async fn publish_in_tx(
    conn: &mut PgConnection,
    rule: &BusinessRule,
    actor: Uuid,
) -> Result<(), AppError> {
    let lock_key = format!("attome-api/rule-publish:{}", rule.id);
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(publish_lock_busy());
    }
    let new_version: i32 = sqlx::query_scalar(
        "UPDATE rule SET version = version + 1, updated_at = NOW() \
         WHERE id = $1 AND is_deleted = false RETURNING version",
    )
    .bind(rule.id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    let definition = if rule.kind == BUSINESS_KIND {
        Some(serde_json::to_value(def_of(rule)).map_err(AppError::internal)?)
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO rule_version \
             (id, rule_id, version, entity_logicalname, kind, target_field, expression, \
              message, severity, definition, created_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), $11)",
    )
    .bind(Uuid::now_v7())
    .bind(rule.id)
    .bind(new_version)
    .bind(&rule.entity_logicalname)
    .bind(&rule.kind)
    .bind(rule.target_field.as_deref())
    .bind(rule.expression.as_deref())
    .bind(rule.message.as_deref())
    .bind(&rule.severity)
    .bind(definition)
    .bind(actor)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Definitions (bundle, changeset snapshot) ────────────────────────────────

/// A stored rule as its portable definition: roles by name, portal roles by
/// `{portal keyword, role name}`, never UUIDs. A portal role whose portal
/// cannot be named (portal gone) carries the portal id as its key, which the
/// target refuses on apply rather than binding it to the wrong portal.
pub(crate) fn def_of(rule: &BusinessRule) -> RuleDef {
    let business = rule.kind == BUSINESS_KIND;
    let mut roles: Vec<String> = rule
        .roles
        .iter()
        .filter(|r| !r.portal_role && r.live)
        .map(|r| r.name.clone())
        .collect();
    roles.sort();
    let mut portal_roles: Vec<PortalRoleKey> = rule
        .roles
        .iter()
        .filter(|r| r.portal_role)
        .map(|r| PortalRoleKey {
            portal: r.portal.clone().unwrap_or_else(|| r.id.to_string()),
            role: r.name.clone(),
        })
        .collect();
    portal_roles.sort();
    RuleDef {
        entity_logicalname: rule.entity_logicalname.clone(),
        name: rule.name.clone(),
        kind: rule.kind.clone(),
        target_field: rule.target_field.clone(),
        expression: rule.expression.clone(),
        message: rule.message.clone(),
        severity: rule.severity.clone(),
        is_active: rule.is_active,
        display_order: rule.display_order,
        display_name: rule.display_name.clone(),
        description: rule.description.clone(),
        applies_to: business.then_some(rule.applies_to),
        roles: if business { roles } else { Vec::new() },
        portal_roles: if business { portal_roles } else { Vec::new() },
        condition: rule.condition.clone(),
        policies: if business {
            rule.policies.clone()
        } else {
            Vec::new()
        },
    }
}

/// The recorded op for a rule: target `{entity, rule}`; the snapshot is the
/// rule's portable definition (what `changeset::translate` reads back as a
/// `RuleDef`) plus the bookkeeping columns translation drops.
pub(crate) fn rule_op(op: Op, rule: &BusinessRule) -> Result<RecordedOp, AppError> {
    let mut snapshot = serde_json::to_value(def_of(rule)).map_err(AppError::internal)?;
    if let Some(map) = snapshot.as_object_mut() {
        map.insert("id".into(), Value::String(rule.id.to_string()));
        map.insert("version".into(), Value::from(rule.version));
        map.insert("row_version".into(), Value::from(rule.row_version));
        map.insert(
            "owner_layer".into(),
            Value::String(rule.owner_layer.clone()),
        );
    }
    hooks::recorded(
        op,
        "rule",
        rule.id,
        serde_json::json!({ "entity": rule.entity_logicalname, "rule": rule.name }),
        &snapshot,
    )
}

/// Every live rule as its bundle definition (export and the pre-apply
/// snapshot).
pub async fn export_defs(db: &attome_db::DbPool) -> Result<Vec<RuleDef>, AppError> {
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let rows: Vec<RuleRow> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM rule WHERE is_deleted = false"
    ))
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let rules = assemble_rules(&mut conn, rows).await?;
    for r in rules.iter().filter(|r| r.load_error.is_some()) {
        tracing::warn!(rule_id = %r.id, "rule export: a rule failed to decode and exports without it");
    }
    Ok(rules.iter().map(def_of).collect())
}

/// A definition's roles resolved to ids on this deployment. Unknown names are
/// a validation error (a bundle naming a role the target lacks).
async fn input_from_def(conn: &mut PgConnection, desc: &RuleDef) -> Result<RuleInput, AppError> {
    let mut role_ids = Vec::new();
    if !desc.roles.is_empty() {
        let found: Vec<(Uuid, String)> =
            sqlx::query_as("SELECT id, name FROM role WHERE name = ANY($1) AND is_deleted = false")
                .bind(&desc.roles)
                .fetch_all(&mut *conn)
                .await
                .map_err(AppError::internal)?;
        for name in &desc.roles {
            let id = found
                .iter()
                .find(|(_, n)| n == name)
                .map(|(id, _)| *id)
                .ok_or_else(|| {
                    AppError::Validation(format!(
                        "rule {}: no staff role named '{name}'",
                        desc.key()
                    ))
                })?;
            role_ids.push(id);
        }
    }
    let mut portal_role_ids = Vec::new();
    if !desc.portal_roles.is_empty() {
        if !has_portal_table(conn).await? {
            return Err(AppError::Validation(format!(
                "rule {}: names portal roles but this deployment has no portals",
                desc.key()
            )));
        }
        let names: Vec<String> = desc.portal_roles.iter().map(|k| k.role.clone()).collect();
        let found: Vec<(Uuid, Option<String>, String)> = sqlx::query_as(
            "SELECT pr.id, w.keyword, pr.name FROM webportal_role pr \
             JOIN webportal w ON w.id = pr.webportal_id WHERE pr.name = ANY($1)",
        )
        .bind(&names)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        for key in &desc.portal_roles {
            let id = found
                .iter()
                .find(|(_, portal, role)| {
                    portal.as_deref() == Some(key.portal.as_str()) && *role == key.role
                })
                .map(|(id, _, _)| *id)
                .ok_or_else(|| {
                    AppError::Validation(format!(
                        "rule {}: no portal role '{}' on portal '{}'",
                        desc.key(),
                        key.role,
                        key.portal
                    ))
                })?;
            portal_role_ids.push(id);
        }
    }
    let business = desc.is_business();
    input_from_body(BusinessRuleBody {
        entity: desc.entity_logicalname.clone(),
        name: desc.name.clone(),
        kind: Some(desc.kind.clone()),
        display_name: desc.display_name.clone(),
        description: desc.description.clone(),
        applies_to: desc.applies_to,
        role_ids: business.then_some(role_ids),
        portal_role_ids: business.then_some(portal_role_ids),
        condition: desc.condition.clone(),
        policies: business.then(|| desc.policies.clone()),
        target_field: desc.target_field.clone(),
        expression: desc.expression.clone(),
        message: desc.message.clone(),
        severity: (!business).then(|| desc.severity.clone()),
        is_active: Some(desc.is_active),
        display_order: Some(desc.display_order),
    })
    .map_err(|issues| {
        AppError::Validation(format!(
            "rule {}: {}",
            desc.key(),
            issues_error_text(&issues)
        ))
    })
}

fn issues_error_text(issues: &[RuleIssue]) -> String {
    match issues_error(issues) {
        AppError::Validation(m) => m,
        other => other.to_string(),
    }
}

// ── Bundle / changeset reconcile ────────────────────────────────────────────

/// Compare-first reconcile of one rule keyed by `(entity, name)` (bundle
/// apply `Step::Rule`, changeset `upsert_rule`). A business definition's
/// roles resolve by name. The rule is
/// re-validated against this deployment's schema like a hand-authored one.
///
/// D-791 rule 2: our changesets may change any rule, customer-layer ones
/// included; the row keeps its `owner_layer`. **The customer wins** (Topic
/// 14; design §9): inside a changeset apply (an operation of the ambient
/// release report), a customer-layer rule goes through the three-way rule
/// against its baseline (`record_baseline`, entity `rule`,
/// field `definition`): changed only by us, it is written; changed by the
/// customer since our last release and by us too, the customer's version
/// stays and a release-report `conflict` item (their definition, ours —
/// sealed) offers Use mine ([`force_rule`]).
pub async fn reconcile_rule(
    state: &EngineState,
    desc: &RuleDef,
    policy: ReconcilePolicy,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    reconcile_rule_with(state, desc, policy, true).await
}

/// "Use mine" on a rule conflict: writes our definition over the customer's,
/// no three-way check (the owner decided). The baseline's stored form
/// becomes ours.
pub(crate) async fn force_rule(
    state: &EngineState,
    desc: &RuleDef,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    reconcile_rule_with(
        state,
        desc,
        ReconcilePolicy::Bundle {
            is_customized: false,
        },
        false,
    )
    .await
}

/// The canonical JSON a rule definition is hashed from (the normalized
/// input).
fn rule_input_json(input: &RuleInput) -> Value {
    serde_json::json!({
        "entity": input.entity,
        "name": input.name,
        "kind": input.kind,
        "display_name": input.display_name,
        "description": input.description,
        "applies_to": input.applies_to,
        "role_ids": input.role_ids,
        "portal_role_ids": input.portal_role_ids,
        "condition": input.condition,
        "policies": input.policies,
        "target_field": input.target_field,
        "expression": input.expression,
        "message": input.message,
        "severity": input.severity,
        "is_active": input.is_active,
        "display_order": input.display_order,
    })
}

/// The baseline hash of a rule definition (`None`: a live rule that no
/// longer converts, which never equals ours).
fn rule_hash(input: Option<&RuleInput>) -> Result<String, AppError> {
    match input {
        Some(i) => crate::bundle::record_sets::value_hash(&rule_input_json(i)),
        None => Ok(rr::hash_text("null")),
    }
}

/// What the three-way rule made of one customer rule our operation changes.
enum RuleThreeWay {
    /// Not a customer rule under an apply: the ordinary reconcile.
    NotApplicable,
    /// Write ours; then this baseline.
    Write(Baseline, (Uuid, i32)),
    /// Write nothing; record this baseline (agreeing values) or nothing.
    Keep(Option<(Baseline, (Uuid, i32))>),
    /// Both changed it: the customer's stays; this baseline and an item.
    Conflict(Baseline, (Uuid, i32)),
}

/// Decides a customer-layer rule (D-791 rule 2) against its baseline. Only
/// inside an applied operation (the ambient report names one); the bundle
/// engine and the admin routes keep their own rules.
async fn rule_three_way(
    conn: &mut PgConnection,
    live: &BusinessRule,
    ours_hash: &str,
    live_input: Option<&RuleInput>,
    live_eq_ours: bool,
) -> Result<RuleThreeWay, AppError> {
    if live.owner_layer != Layer::Customer.as_str() {
        return Ok(RuleThreeWay::NotApplicable);
    }
    let Some(op) = rr::current().and_then(|c| c.op) else {
        return Ok(RuleThreeWay::NotApplicable);
    };
    let live_hash = rule_hash(live_input)?;
    let baselines = rr::read_baselines(conn, rr::RULE_BASELINE_ENTITY, live.id).await?;
    let ours_baseline = |stored: Option<String>| Baseline {
        value_hash: ours_hash.to_owned(),
        live_hash: stored,
    };
    Ok(
        match rr::decide(
            &live_hash,
            ours_hash,
            live_eq_ours,
            baselines.get(rr::RULE_BASELINE_FIELD),
        ) {
            Decision::Write => RuleThreeWay::Write(ours_baseline(Some(ours_hash.to_owned())), op),
            Decision::Rebase => RuleThreeWay::Keep(Some((ours_baseline(Some(live_hash)), op))),
            Decision::Noop | Decision::KeepTheirs => RuleThreeWay::Keep(None),
            Decision::Conflict => RuleThreeWay::Conflict(ours_baseline(None), op),
        },
    )
}

/// Writes a kept rule conflict: the baseline and the release-report item
/// (their definition and ours, sealed), one transaction.
#[allow(clippy::too_many_arguments)] // one conflict's parts, named at its two call sites
async fn write_rule_conflict(
    state: &EngineState,
    rule_id: Uuid,
    entity: &str,
    name: &str,
    change: &str,
    theirs: Value,
    ours: Value,
    baseline: &Baseline,
    op: (Uuid, i32),
) -> Result<(), AppError> {
    let ring = attome_core::recovery_archive::ring(state.base.config.as_ref());
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    rr::write_baseline(
        &mut tx,
        rr::RULE_BASELINE_ENTITY,
        rule_id,
        rr::RULE_BASELINE_FIELD,
        baseline,
        op,
    )
    .await?;
    rr::insert_items(
        &mut tx,
        ring,
        vec![NewItem {
            kind: rr::ItemKind::Conflict,
            entity: entity.to_owned(),
            field: None,
            record_id: None,
            object_kind: Some(RULE_OBJECT_KIND.to_owned()),
            object_ref: Some(rule_id),
            detail: serde_json::json!({ "rule": name, "change": change,
                                        "values_stored": ring.is_some() }),
            values: Some(ConflictValues {
                theirs,
                ours,
                key: None,
            }),
            op: Some(op),
        }],
        &format!("{change} {entity}.{name}"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    tracing::info!(
        entity,
        rule = name,
        change,
        "rule reconcile: the customer changed this rule since our last release; their version \
         stays and the release report offers Use mine"
    );
    Ok(())
}

/// The report item's `object_kind` of a rule conflict.
pub(crate) const RULE_OBJECT_KIND: &str = "business_rule";

/// What "Use mine" replays for a rule conflict whose change was a retire.
pub(crate) const RULE_RETIRE_CHANGE: &str = "retire_rule";
/// ... and whose change was an upsert.
pub(crate) const RULE_UPSERT_CHANGE: &str = "upsert_rule";

async fn reconcile_rule_with(
    state: &EngineState,
    desc: &RuleDef,
    policy: ReconcilePolicy,
    three_way: bool,
) -> Result<(Uuid, ReconcileOutcome), AppError> {
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    let input = input_from_def(&mut conn, desc).await?;
    let current = read_rule_by_key(&mut conn, &input.entity, &input.name).await?;
    let checked = check(
        &mut conn,
        state,
        None,
        &input,
        current.as_ref().map(|r| r.id),
    )
    .await?;
    if !checked.issues.is_empty() {
        return Err(AppError::Validation(format!(
            "rule {}: {}",
            desc.key(),
            issues_error_text(&checked.issues)
        )));
    }
    resolve_live_entity_id(&state.base.db, &input.entity).await?;
    let customized: Option<bool> = match &current {
        Some(r) => sqlx::query_scalar("SELECT is_customized FROM rule WHERE id = $1")
            .bind(r.id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(AppError::internal)?,
        None => None,
    };
    let live_input = current.as_ref().and_then(input_of);
    let state_differs = current.as_ref().is_some_and(|_| {
        !live_input
            .as_ref()
            .is_some_and(|live| live.same_definition(&input))
    });
    let ours_hash = rule_hash(Some(&input))?;
    let decided = match (&current, three_way) {
        (Some(live), true) => {
            rule_three_way(
                &mut conn,
                live,
                &ours_hash,
                live_input.as_ref(),
                !state_differs,
            )
            .await?
        }
        _ => RuleThreeWay::NotApplicable,
    };
    drop(conn);
    let key = desc.key();
    let pending_baseline = match decided {
        RuleThreeWay::NotApplicable => None,
        RuleThreeWay::Write(baseline, op) => Some((baseline, op)),
        RuleThreeWay::Keep(rebase) => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            if let Some((baseline, op)) = rebase {
                let mut tx = attome_db::tx::begin(&state.base.db).await?;
                rr::write_baseline(
                    &mut tx,
                    rr::RULE_BASELINE_ENTITY,
                    id,
                    rr::RULE_BASELINE_FIELD,
                    &baseline,
                    op,
                )
                .await?;
                attome_db::tx::commit(tx).await?;
            }
            return Ok((id, ReconcileOutcome::Unchanged));
        }
        RuleThreeWay::Conflict(baseline, op) => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            let theirs = live_input.as_ref().map_or(Value::Null, rule_input_json);
            let ours = serde_json::to_value(desc).map_err(AppError::internal)?;
            write_rule_conflict(
                state,
                id,
                &input.entity,
                &input.name,
                RULE_UPSERT_CHANGE,
                theirs,
                ours,
                &baseline,
                op,
            )
            .await?;
            return Ok((id, ReconcileOutcome::Unchanged));
        }
    };

    let status = current
        .as_ref()
        .map(|r| (customized.unwrap_or(false), r.is_active));
    let step = reconcile_step(policy, status, state_differs);
    match step {
        ReconcileStep::Unchanged => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            Ok((id, ReconcileOutcome::Unchanged))
        }
        ReconcileStep::SkippedCustomized => {
            let id = current.as_ref().map(|r| r.id).ok_or(AppError::NotFound)?;
            tracing::info!(rule = %key, "rule reconcile: seed skipped a customized rule (is_customized = true)");
            Ok((id, ReconcileOutcome::SkippedCustomized))
        }
        ReconcileStep::Create | ReconcileStep::Update => {
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let id = match current.as_ref() {
                Some(r) => {
                    lock_rule(&mut tx, r.id, false).await?;
                    update_rule(&mut tx, r.id, &input, customized_marker(policy)).await?;
                    r.id
                }
                None => {
                    let id = Uuid::now_v7();
                    insert_rule(
                        &mut tx,
                        id,
                        &input,
                        hooks::reconcile_layer(policy),
                        customized_marker(policy).unwrap_or(false),
                    )
                    .await?;
                    id
                }
            };
            if let Some((baseline, op)) = &pending_baseline {
                rr::write_baseline(
                    &mut tx,
                    rr::RULE_BASELINE_ENTITY,
                    id,
                    rr::RULE_BASELINE_FIELD,
                    baseline,
                    *op,
                )
                .await?;
            }
            tx.commit().await.map_err(AppError::internal)?;
            let outcome = step.outcome();
            tracing::info!(rule = %key, ?outcome, ?policy, "rule reconcile: reconciled rule");
            invalidate(state).await;
            Ok((id, outcome))
        }
    }
}

/// Soft-retire (`is_active = false`) the rule keyed by `(entity, name)`.
/// Idempotent. Never drops. Any owner layer (D-791 rule 2); a customer rule
/// the customer changed since our last release is kept and reported, as in
/// [`reconcile_rule`] ("Use mine" retires it: [`force_retire_rule`]).
pub async fn retire_rule(
    state: &EngineState,
    entity: &str,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    retire_rule_with(state, entity, name, true).await
}

/// "Use mine" on a retire conflict: retires the rule, no three-way check.
pub(crate) async fn force_retire_rule(
    state: &EngineState,
    entity: &str,
    name: &str,
) -> Result<ReconcileOutcome, AppError> {
    retire_rule_with(state, entity, name, false).await
}

async fn retire_rule_with(
    state: &EngineState,
    entity: &str,
    name: &str,
    three_way: bool,
) -> Result<ReconcileOutcome, AppError> {
    let mut pending_baseline: Option<(Uuid, Baseline, (Uuid, i32))> = None;
    if three_way {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        let live = read_rule_by_key(&mut conn, entity.trim(), name.trim()).await?;
        if let Some(live) = live.filter(|r| r.is_active) {
            let live_input = input_of(&live);
            // Ours is the same definition, retired: what the row reads as
            // after the retire.
            let ours_input = live_input.clone().map(|mut i| {
                i.is_active = false;
                i
            });
            let ours_hash = rule_hash(ours_input.as_ref())?;
            match rule_three_way(&mut conn, &live, &ours_hash, live_input.as_ref(), false).await? {
                RuleThreeWay::NotApplicable => {}
                RuleThreeWay::Write(baseline, op) => {
                    pending_baseline = Some((live.id, baseline, op));
                }
                RuleThreeWay::Keep(_) => return Ok(ReconcileOutcome::Unchanged),
                RuleThreeWay::Conflict(baseline, op) => {
                    drop(conn);
                    let theirs = live_input.as_ref().map_or(Value::Null, rule_input_json);
                    write_rule_conflict(
                        state,
                        live.id,
                        entity.trim(),
                        name.trim(),
                        RULE_RETIRE_CHANGE,
                        theirs,
                        serde_json::json!({ "retire": true, "entity": entity.trim(),
                                            "rule": name.trim() }),
                        &baseline,
                        op,
                    )
                    .await?;
                    return Ok(ReconcileOutcome::Unchanged);
                }
            }
        }
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let n = sqlx::query(
        "UPDATE rule SET is_active = false, row_version = row_version + 1, \
             updated_at = NOW() \
         WHERE entity_logicalname = $1 AND name = $2 AND is_deleted = false AND is_active = true",
    )
    .bind(entity.trim())
    .bind(name.trim())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if n == 0 {
        return Ok(ReconcileOutcome::Unchanged);
    }
    if let Some((rule_id, baseline, op)) = &pending_baseline {
        rr::write_baseline(
            &mut tx,
            rr::RULE_BASELINE_ENTITY,
            *rule_id,
            rr::RULE_BASELINE_FIELD,
            baseline,
            *op,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(entity, name, "rule reconcile: retired");
    invalidate(state).await;
    Ok(ReconcileOutcome::Updated)
}

/// Plan side of D-791 rule 2 (`changeset::plan`): whether applying `desc`
/// to a customer-layer rule now would be a kept conflict — the customer
/// changed the rule since our last release (or we never wrote it) and our
/// definition differs from theirs. Read-only; the apply decides again.
pub(crate) async fn upsert_would_conflict(
    conn: &mut PgConnection,
    desc: &RuleDef,
) -> Result<bool, AppError> {
    let input = input_from_def(conn, desc).await?;
    let Some(live) = read_rule_by_key(conn, &input.entity, &input.name).await? else {
        return Ok(false);
    };
    if live.owner_layer != Layer::Customer.as_str() {
        return Ok(false);
    }
    let live_input = input_of(&live);
    let live_eq_ours = live_input
        .as_ref()
        .is_some_and(|l| l.same_definition(&input));
    let baselines = rr::read_baselines(conn, rr::RULE_BASELINE_ENTITY, live.id).await?;
    Ok(rr::decide(
        &rule_hash(live_input.as_ref())?,
        &rule_hash(Some(&input))?,
        live_eq_ours,
        baselines.get(rr::RULE_BASELINE_FIELD),
    ) == Decision::Conflict)
}

/// Plan side of a `retire_rule` on a customer-layer rule: whether the apply
/// would keep it (the customer changed it since our last release, or we
/// never wrote it). Read-only.
pub(crate) async fn retire_would_conflict(
    conn: &mut PgConnection,
    entity: &str,
    name: &str,
) -> Result<bool, AppError> {
    let Some(live) = read_rule_by_key(conn, entity.trim(), name.trim()).await? else {
        return Ok(false);
    };
    if live.owner_layer != Layer::Customer.as_str() || !live.is_active {
        return Ok(false);
    }
    let live_input = input_of(&live);
    let ours_input = live_input.clone().map(|mut i| {
        i.is_active = false;
        i
    });
    let baselines = rr::read_baselines(conn, rr::RULE_BASELINE_ENTITY, live.id).await?;
    Ok(rr::decide(
        &rule_hash(live_input.as_ref())?,
        &rule_hash(ours_input.as_ref())?,
        false,
        baselines.get(rr::RULE_BASELINE_FIELD),
    ) == Decision::Conflict)
}

/// Reloads this node's `rules` snapshot and best-effort publishes on
/// `RULE_VERSION_CHANNEL` so every other node reloads too — after commit,
/// never inside the transaction (guidelines §4/§5).
pub(crate) async fn invalidate(state: &EngineState) {
    match attome_core::rule_registry::load(&state.base.db).await {
        Ok(fresh) => state.rules.swap(fresh),
        Err(e) => {
            tracing::warn!(error = %e, "rule_admin: local registry reload failed after write")
        }
    }
    let publish_result = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        state
            .base
            .redis
            .next()
            .publish::<i64, _, _>(attome_core::RULE_VERSION_CHANNEL, "1"),
    )
    .await;
    match publish_result {
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "rule_admin: failed to publish invalidation doorbell")
        }
        Err(_) => tracing::warn!("rule_admin: publishing invalidation doorbell timed out"),
        Ok(Ok(_)) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(v: Value) -> BusinessRuleBody {
        serde_json::from_value(v).expect("body")
    }

    fn rule(kind: &str) -> BusinessRule {
        BusinessRule {
            id: Uuid::now_v7(),
            entity_logicalname: "account".into(),
            name: "lock_closed".into(),
            kind: kind.into(),
            display_name: None,
            description: None,
            applies_to: AppliesTo::Roles,
            roles: vec![
                RuleRoleRef {
                    id: Uuid::now_v7(),
                    name: "sales".into(),
                    portal_role: false,
                    portal: None,
                    live: true,
                },
                RuleRoleRef {
                    id: Uuid::now_v7(),
                    name: "gone".into(),
                    portal_role: false,
                    portal: None,
                    live: false,
                },
                RuleRoleRef {
                    id: Uuid::now_v7(),
                    name: "customer".into(),
                    portal_role: true,
                    portal: Some("support".into()),
                    live: true,
                },
            ],
            condition: Some(ConditionTree::always()),
            policies: vec![PolicyDef {
                policy_type: PolicyType::Disabled,
                field: Some("amount".into()),
                message: None,
                severity: None,
                value: None,
                expression: None,
                mode: None,
                ordinal: 0,
            }],
            target_field: None,
            expression: None,
            message: None,
            severity: "error".into(),
            is_active: true,
            display_order: 0,
            version: 2,
            row_version: 3,
            owner_layer: "project".into(),
            disabled_reason: None,
            applies_to_nobody: false,
            load_error: None,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn a_rule_hash_follows_the_definition() {
        let input = input_from_body(body(json!({
            "entity_logicalname": "account", "name": "route", "kind": "routing",
            "expression": "priority == \"high\""
        })))
        .expect("valid");
        let hash = rule_hash(Some(&input)).expect("hash");
        assert_eq!(hash, rule_hash(Some(&input.clone())).expect("hash"));
        assert_ne!(hash, rule_hash(None).expect("hash"));
        let mut retired = input.clone();
        retired.is_active = !retired.is_active;
        assert_ne!(hash, rule_hash(Some(&retired)).expect("hash"));
    }

    #[test]
    fn a_business_body_defaults_its_kind_and_numbers_its_policies() {
        let input = input_from_body(body(json!({
            "entity": "account", "name": "r",
            "condition": { "all": [] },
            "policies": [ { "type": "hidden", "field": "a" }, { "type": "disabled", "field": "b" } ]
        })))
        .expect("valid");
        assert_eq!(input.kind, BUSINESS_KIND);
        assert_eq!(input.policies[1].ordinal, 1);
        assert_eq!(input.applies_to, AppliesTo::All);
    }

    #[test]
    fn a_retired_kind_is_refused() {
        let issues = input_from_body(body(json!({
            "entity_logicalname": "account", "name": "positive", "kind": "validation",
            "expression": "amount > 0", "message": "must be positive"
        })))
        .expect_err("validation is not a kind");
        assert!(issues.iter().any(|i| i.code == "kind_unknown"));
    }

    #[test]
    fn expression_kinds_keep_their_expression() {
        let input = input_from_body(body(json!({
            "entity": "service_work_request", "name": "route", "kind": "routing",
            "expression": "priority == \"high\""
        })))
        .expect("valid");
        assert_eq!(input.kind, "routing");
        assert!(input.condition.is_none());
        let refused = input_from_body(body(json!({
            "entity": "a", "name": "v", "kind": "visibility", "expression": "true"
        })))
        .expect_err("needs a target");
        assert_eq!(refused[0].code, "target_field_required");
    }

    #[test]
    fn mixed_shapes_and_unknown_kinds_are_issues() {
        let issues = input_from_body(body(json!({
            "entity": "a", "name": "r", "condition": { "all": [] }, "expression": "true"
        })))
        .expect_err("mixed");
        assert!(
            issues
                .iter()
                .any(|i| i.code == "legacy_field_on_business_rule")
        );
        let issues = input_from_body(body(json!({
            "entity": "a", "name": "r", "kind": "quality", "expression": "true"
        })))
        .expect_err("unknown");
        assert_eq!(issues[0].code, "kind_unknown");
        let issues =
            input_from_body(body(json!({ "entity": "a", "name": "r" }))).expect_err("no condition");
        assert_eq!(issues[0].code, "condition_required");
    }

    #[test]
    fn a_patch_keeps_the_rest_drops_dead_roles_and_refuses_a_rename() {
        let stored = rule(BUSINESS_KIND);
        let merged = merge_patch(
            &stored,
            BusinessRulePatch {
                display_order: Some(5),
                ..Default::default()
            },
        )
        .expect("merge");
        assert_eq!(merged.display_order, Some(5));
        assert_eq!(
            merged.role_ids.as_ref().map(Vec::len),
            Some(1),
            "dead role dropped"
        );
        assert_eq!(merged.portal_role_ids.as_ref().map(Vec::len), Some(1));
        assert!(
            merge_patch(
                &stored,
                BusinessRulePatch {
                    name: Some("other".into()),
                    ..Default::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn the_stored_rule_round_trips_to_an_equal_input() {
        let stored = rule(BUSINESS_KIND);
        let a = input_of(&stored).expect("input");
        let b = input_from_body(body_of(&stored)).expect("input");
        assert!(a.same_definition(&b));
    }

    #[test]
    fn a_definition_names_roles_never_uuids() {
        let def = def_of(&rule(BUSINESS_KIND));
        assert_eq!(def.roles, vec!["sales".to_owned()]);
        assert_eq!(
            def.portal_roles,
            vec![PortalRoleKey {
                portal: "support".into(),
                role: "customer".into()
            }]
        );
        assert_eq!(def.expression, None);
        let text = serde_json::to_string(&def).expect("json");
        assert!(!text.contains(&rule(BUSINESS_KIND).roles[0].id.to_string()));
    }

    #[test]
    fn a_rule_op_targets_entity_and_rule_and_translates_back_to_a_rule_def() {
        let stored = rule(BUSINESS_KIND);
        for op in [Op::UpsertRule, Op::PublishRule, Op::RetireRule] {
            let recorded = rule_op(op, &stored).expect("op");
            assert_eq!(
                recorded.target,
                json!({ "entity": "account", "rule": "lock_closed" })
            );
            assert!(recorded.check().is_ok(), "{op:?}");
        }
        let snapshot = rule_op(Op::UpsertRule, &stored).expect("op").snapshot;
        assert_eq!(snapshot["version"], 2);
        let def: RuleDef = serde_json::from_value(snapshot).expect("a RuleDef");
        assert_eq!(def, def_of(&stored));
    }

    #[test]
    fn a_legacy_definition_keeps_its_old_serialized_shape() {
        let mut legacy = rule("routing");
        legacy.condition = None;
        legacy.policies.clear();
        legacy.roles.clear();
        legacy.applies_to = AppliesTo::All;
        legacy.expression = Some("true".into());
        let v = serde_json::to_value(def_of(&legacy)).expect("json");
        let keys: Vec<&str> = v
            .as_object()
            .expect("obj")
            .keys()
            .map(String::as_str)
            .collect();
        for k in [
            "entity_logicalname",
            "name",
            "kind",
            "target_field",
            "expression",
            "message",
            "severity",
            "is_active",
            "display_order",
        ] {
            assert!(keys.contains(&k), "{k}");
        }
        assert_eq!(
            keys.len(),
            9,
            "no business field on a legacy definition: {keys:?}"
        );
    }

    #[test]
    fn auto_mode_without_a_changeset_is_a_customer_edit() {
        let auto = mode_of(Some(Origin::Auto), Layer::Project);
        assert_eq!(auto.layer, Layer::Customer);
        assert!(!auto.record && auto.customer);
        let authored = mode_of(None, Layer::Project);
        assert_eq!(authored.layer, Layer::Project);
        assert!(authored.record && !authored.customer);
        let glass = mode_of(Some(Origin::BreakGlass), Layer::Project);
        assert!(glass.record && !glass.customer);
        let seed = Recording::Seed;
        assert!(check_owner(&seed, auto, "customer").is_ok());
        assert!(matches!(
            check_owner(&seed, auto, "project"),
            Err(AppError::Conflict(_))
        ));
        assert!(check_owner(&seed, authored, "project").is_ok());
    }

    #[test]
    fn issues_become_one_validation_message() {
        let e = issues_error(&[issue("a", "x", "first"), issue("b", "y", "second")]);
        let AppError::Validation(m) = e else {
            panic!("validation");
        };
        assert_eq!(m, "a: first; b: second");
    }
}
