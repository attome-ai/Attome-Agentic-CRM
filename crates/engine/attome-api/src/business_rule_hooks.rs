//! D-789 §8 (`BUSINESS-RULES-DESIGN.md`; Solution 7 Phase 2 §7.4) — the
//! `business_rules` field-reference hook. It replaces Phase 2's `rules` hook
//! and covers every rule of the entity, in every layer:
//!
//! - business rows: condition leaves (`field`), advanced-leaf expressions,
//!   policy fields (`rule_policy.field_logicalname`) and `set_value`
//!   expressions;
//! - legacy rows (`visibility`, `requirement`, `policy`, `routing`):
//!   `target_field` and expression identifiers.
//!
//! | change | our rules | customer rules |
//! |---|---|---|
//! | rename | rewritten | rewritten, reported `customer_object_adjusted` |
//! | delete | block (`field_referenced`); a legacy visibility/requirement rule that only styles the field is removed | policies on the field deleted; a rule whose condition or an expression uses it is turned off (`disabled_reason = field_deleted:<f>`); a rule left with no policy is removed; each reported |
//! | retype | a rule that no longer validates blocks | turned off (`field_retyped:<f>`), reported |
//!
//! Role deletion (§8.4) needs no hook: a hard-deleted role cascades its
//! association, a soft-deleted one is inert (the registry loads live roles
//! only) and dropped on the rule's next save; the admin list flags a rule
//! left with no live role (`applies_to_nobody`). No report item.
//!
//! The condition tree is walked as JSON so a row that no longer decodes is
//! still found and rewritten.

use std::collections::HashMap;

use attome_core::business_rules::{self as br, BUSINESS_KIND, BusinessRuleSpec};
use attome_core::changeset::field_hooks::{
    Blocker, CacheTouch, FieldRef, FieldReferenceHook, HookFuture, HookOutcome, RefOwner, RefScan,
    ReportItemDraft,
};
use attome_core::{AttrInfo, EngineState, FieldType};
use attome_metadata::provision::field_change::{expression_names, rewrite_expression};
use attome_types::AppError;
use serde_json::{Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::rule_admin as store;

pub const HOOK_NAME: &str = "business_rules";
const OBJECT_KIND: &str = "business_rule";

// ── Condition JSON walkers ──────────────────────────────────────────────────

/// Whether a condition (as stored JSON) reads `field`.
pub(crate) fn condition_uses(node: &Value, field: &str) -> bool {
    let Some(map) = node.as_object() else {
        return false;
    };
    if let Some(children) = map.get("all").or_else(|| map.get("any")) {
        return children
            .as_array()
            .is_some_and(|c| c.iter().any(|n| condition_uses(n, field)));
    }
    if let Some(expr) = map.get("expression").and_then(Value::as_str) {
        return expression_names(expr, field);
    }
    map.get("field").and_then(Value::as_str) == Some(field)
}

/// Rewrites `old` to `new` in a condition; returns whether anything changed.
pub(crate) fn condition_rename(node: &mut Value, old: &str, new: &str) -> bool {
    let Some(map) = node.as_object_mut() else {
        return false;
    };
    for key in ["all", "any"] {
        if let Some(Value::Array(children)) = map.get_mut(key) {
            let mut changed = false;
            for c in children {
                changed |= condition_rename(c, old, new);
            }
            return changed;
        }
    }
    if let Some(Value::String(expr)) = map.get_mut("expression") {
        if expression_names(expr, old) {
            *expr = rewrite_expression(expr, old, new);
            return true;
        }
        return false;
    }
    if map.get("field").and_then(Value::as_str) == Some(old) {
        map.insert("field".into(), Value::String(new.to_owned()));
        return true;
    }
    false
}

// ── Rows ────────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct HookRule {
    id: Uuid,
    name: String,
    kind: String,
    target_field: Option<String>,
    expression: Option<String>,
    condition: Option<Value>,
    owner_layer: String,
}

#[derive(sqlx::FromRow, Clone)]
struct HookPolicy {
    id: Uuid,
    rule_ref: Uuid,
    field_logicalname: Option<String>,
    expression: Option<String>,
}

struct Loaded {
    rule: HookRule,
    policies: Vec<HookPolicy>,
}

impl Loaded {
    fn customer(&self) -> bool {
        self.rule.owner_layer == "customer"
    }

    fn owner(&self) -> RefOwner {
        if self.customer() {
            RefOwner::Customer
        } else {
            RefOwner::Ours
        }
    }

    /// The field is read by the condition or an expression (not only a
    /// policy target).
    fn reads(&self, field: &str) -> bool {
        self.rule
            .condition
            .as_ref()
            .is_some_and(|c| condition_uses(c, field))
            || self
                .rule
                .expression
                .as_deref()
                .is_some_and(|e| expression_names(e, field))
            || self.policies.iter().any(|p| {
                p.expression
                    .as_deref()
                    .is_some_and(|e| expression_names(e, field))
            })
    }

    fn targets(&self, field: &str) -> bool {
        self.rule.target_field.as_deref() == Some(field)
            || self
                .policies
                .iter()
                .any(|p| p.field_logicalname.as_deref() == Some(field))
    }

    fn references(&self, field: &str) -> bool {
        self.reads(field) || self.targets(field)
    }

    /// A legacy visibility/requirement rule that only styles the field: its
    /// consequence, removed with the field rather than blocking (Phase 2 §3.2).
    fn only_styles(&self, field: &str) -> bool {
        matches!(self.rule.kind.as_str(), "visibility" | "requirement")
            && self.rule.target_field.as_deref() == Some(field)
            && !self.reads(field)
    }

    fn is_business(&self) -> bool {
        self.rule.kind == BUSINESS_KIND
    }
}

async fn load(conn: &mut PgConnection, entity: &str) -> Result<Vec<Loaded>, AppError> {
    let rules: Vec<HookRule> = sqlx::query_as(
        "SELECT id, name, kind, target_field, expression, condition, owner_layer \
         FROM rule WHERE entity_logicalname = $1 AND is_deleted = false",
    )
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let ids: Vec<Uuid> = rules.iter().map(|r| r.id).collect();
    let mut policies: HashMap<Uuid, Vec<HookPolicy>> = HashMap::new();
    if !ids.is_empty() {
        let rows: Vec<HookPolicy> = sqlx::query_as(
            "SELECT id, rule_ref, field_logicalname, expression FROM rule_policy \
             WHERE rule_ref = ANY($1) ORDER BY rule_ref, ordinal",
        )
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        for p in rows {
            policies.entry(p.rule_ref).or_default().push(p);
        }
    }
    Ok(rules
        .into_iter()
        .map(|rule| Loaded {
            policies: policies.remove(&rule.id).unwrap_or_default(),
            rule,
        })
        .collect())
}

fn draft(
    kind: &'static str,
    entity: &str,
    field: &str,
    rule: &HookRule,
    detail: Value,
) -> ReportItemDraft {
    ReportItemDraft {
        kind,
        entity: entity.to_owned(),
        field: Some(field.to_owned()),
        object_kind: Some(OBJECT_KIND.to_owned()),
        object_ref: Some(rule.id),
        detail,
    }
}

async fn deactivate(conn: &mut PgConnection, id: Uuid, reason: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE rule SET is_active = false, disabled_reason = $2, \
             row_version = row_version + 1, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(reason)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn remove_rule(conn: &mut PgConnection, id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE rule SET is_deleted = true, is_active = false, \
             row_version = row_version + 1, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── The hook ────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct BusinessRulesHook;

impl FieldReferenceHook for BusinessRulesHook {
    fn name(&self) -> &'static str {
        HOOK_NAME
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let mut out = RefScan::default();
            for r in load(conn, entity).await? {
                if !r.references(field) {
                    continue;
                }
                if !renaming && r.owner() == RefOwner::Ours && !r.only_styles(field) {
                    out.blockers.push(Blocker {
                        hook: HOOK_NAME,
                        object_kind: OBJECT_KIND.into(),
                        object_ref: Some(r.rule.id),
                        name: r.rule.name.clone(),
                        reason: "field_referenced: a business rule of ours uses the field; \
                                 change or remove it in the same changeset first"
                            .into(),
                    });
                }
                out.refs.push(FieldRef {
                    hook: HOOK_NAME,
                    object_kind: format!("rule:{}", r.rule.kind),
                    object_ref: Some(r.rule.id),
                    owner: r.owner(),
                    name: r.rule.name,
                });
            }
            Ok(out)
        })
    }

    fn rename<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        old: &'a str,
        new: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            for mut r in load(conn, entity).await? {
                if !r.references(old) {
                    continue;
                }
                let target = match r.rule.target_field.as_deref() {
                    Some(t) if t == old => Some(new.to_owned()),
                    other => other.map(str::to_owned),
                };
                let expression = r
                    .rule
                    .expression
                    .as_deref()
                    .map(|e| rewrite_expression(e, old, new));
                if let Some(c) = r.rule.condition.as_mut() {
                    condition_rename(c, old, new);
                }
                sqlx::query(
                    "UPDATE rule SET target_field = $2, expression = $3, condition = $4, \
                         row_version = row_version + 1, updated_at = NOW() WHERE id = $1",
                )
                .bind(r.rule.id)
                .bind(target)
                .bind(expression)
                .bind(r.rule.condition.as_ref())
                .execute(&mut *conn)
                .await
                .map_err(AppError::internal)?;
                for p in &r.policies {
                    let field = match p.field_logicalname.as_deref() {
                        Some(f) if f == old => Some(new.to_owned()),
                        other => other.map(str::to_owned),
                    };
                    let expression = p
                        .expression
                        .as_deref()
                        .map(|e| rewrite_expression(e, old, new));
                    if field == p.field_logicalname && expression == p.expression {
                        continue;
                    }
                    sqlx::query(
                        "UPDATE rule_policy SET field_logicalname = $2, expression = $3 \
                         WHERE id = $1",
                    )
                    .bind(p.id)
                    .bind(field)
                    .bind(expression)
                    .execute(&mut *conn)
                    .await
                    .map_err(AppError::internal)?;
                }
                out.touched += 1;
                if r.customer() {
                    out.report.push(draft(
                        "customer_object_adjusted",
                        entity,
                        old,
                        &r.rule,
                        json!({ "name": r.rule.name, "change": "renamed_reference", "to": new,
                                "message": format!("the rule {} now refers to {new}", r.rule.name) }),
                    ));
                }
            }
            if out.touched > 0 {
                out.caches.push(CacheTouch::Rules);
            }
            Ok(out)
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let mut out = HookOutcome::default();
            for r in load(conn, entity).await? {
                if !r.references(field) {
                    continue;
                }
                if !r.customer() {
                    if r.only_styles(field) {
                        remove_rule(conn, r.rule.id).await?;
                        out.touched += 1;
                    }
                    continue; // any other reference of ours was refused by scan
                }
                out.touched += 1;
                if !r.is_business() {
                    deactivate(conn, r.rule.id, &format!("field_deleted:{field}")).await?;
                    out.report.push(draft(
                        "customer_object_adjusted",
                        entity,
                        field,
                        &r.rule,
                        json!({ "name": r.rule.name, "kind": r.rule.kind, "change": "deactivated",
                                "message": format!("rule {} was turned off because it used {field}; edit and turn it back on", r.rule.name) }),
                    ));
                    continue;
                }
                let deleted = sqlx::query(
                    "DELETE FROM rule_policy WHERE rule_ref = $1 AND field_logicalname = $2",
                )
                .bind(r.rule.id)
                .bind(field)
                .execute(&mut *conn)
                .await
                .map_err(AppError::internal)?
                .rows_affected();
                let remaining: Vec<&HookPolicy> = r
                    .policies
                    .iter()
                    .filter(|p| p.field_logicalname.as_deref() != Some(field))
                    .collect();
                if remaining.is_empty() {
                    remove_rule(conn, r.rule.id).await?;
                    out.report.push(draft(
                        "customer_object_removed",
                        entity,
                        field,
                        &r.rule,
                        json!({ "name": r.rule.name, "change": "removed: every policy named the deleted field" }),
                    ));
                    continue;
                }
                let reads = r
                    .rule
                    .condition
                    .as_ref()
                    .is_some_and(|c| condition_uses(c, field))
                    || remaining.iter().any(|p| {
                        p.expression
                            .as_deref()
                            .is_some_and(|e| expression_names(e, field))
                    });
                if reads {
                    deactivate(conn, r.rule.id, &format!("field_deleted:{field}")).await?;
                } else {
                    sqlx::query(
                        "UPDATE rule SET row_version = row_version + 1, \
                             updated_at = NOW() WHERE id = $1",
                    )
                    .bind(r.rule.id)
                    .execute(&mut *conn)
                    .await
                    .map_err(AppError::internal)?;
                }
                out.report.push(draft(
                    "customer_object_adjusted",
                    entity,
                    field,
                    &r.rule,
                    json!({ "name": r.rule.name, "policies_removed": deleted,
                            "change": if reads { "deactivated" } else { "policies_removed" },
                            "message": if reads {
                                format!("rule {} was turned off because it used {field}; edit and turn it back on", r.rule.name)
                            } else {
                                format!("rule {} no longer acts on {field}", r.rule.name)
                            } }),
                ));
            }
            if out.touched > 0 {
                out.caches.push(CacheTouch::Rules);
            }
            Ok(out)
        })
    }
}

// ── Type change (§8.3) ──────────────────────────────────────────────────────

/// What a retype would do to the entity's rules.
#[derive(Debug, Default, Clone)]
pub struct RetypeScan {
    /// Our rules that no longer validate: the change is refused.
    pub blockers: Vec<Blocker>,
    /// Customer rules that no longer validate: turned off on apply.
    customer: Vec<(Uuid, String)>,
}

fn field_type_named(name: &str) -> Option<FieldType> {
    (1..=18)
        .filter_map(FieldType::from_int)
        .find(|t| t.as_str() == name)
}

fn retyped_attrs(
    state: &EngineState,
    entity: &str,
    field: &str,
    to_type: &str,
) -> Option<Vec<AttrInfo>> {
    let target = field_type_named(to_type)?;
    let mut attrs = store::attrs_for_entity(state, entity)?;
    for a in attrs.iter_mut().filter(|a| a.logicalname == field) {
        a.field_type_int = target.to_int();
    }
    Some(attrs)
}

/// Re-validates every rule that uses `entity.field` against the field's new
/// type. Reads only; run before the conversion.
pub async fn retype_scan(
    conn: &mut PgConnection,
    state: &EngineState,
    entity: &str,
    field: &str,
    to_type: &str,
) -> Result<RetypeScan, AppError> {
    let mut out = RetypeScan::default();
    let Some(attrs) = retyped_attrs(state, entity, field, to_type) else {
        return Ok(out);
    };
    let rows: Vec<store::RuleRow> = sqlx::query_as(&format!(
        "SELECT {} FROM rule WHERE entity_logicalname = $1 AND is_deleted = false \
           AND is_active = true",
        store::RULE_COLUMNS
    ))
    .bind(entity)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let loaded = load(conn, entity).await?;
    let uses: HashMap<Uuid, bool> = loaded
        .iter()
        .map(|l| (l.rule.id, l.references(field)))
        .collect();
    for rule in store::assemble_rules(conn, rows).await? {
        if !uses.get(&rule.id).copied().unwrap_or(false) {
            continue;
        }
        if still_valid(&rule, &attrs) {
            continue;
        }
        if rule.owner_layer == "customer" {
            out.customer.push((rule.id, rule.name.clone()));
        } else {
            out.blockers.push(Blocker {
                hook: HOOK_NAME,
                object_kind: OBJECT_KIND.into(),
                object_ref: Some(rule.id),
                name: rule.name.clone(),
                reason: format!(
                    "field_referenced: the business rule no longer validates once the field is {to_type}; \
                     change it in the same changeset first"
                ),
            });
        }
    }
    Ok(out)
}

fn still_valid(rule: &store::BusinessRule, attrs: &[AttrInfo]) -> bool {
    if rule.kind == BUSINESS_KIND {
        let Some(condition) = rule.condition.as_ref() else {
            return false;
        };
        let staff = rule
            .roles
            .iter()
            .filter(|r| !r.portal_role && r.live)
            .count();
        let portal = rule.roles.iter().filter(|r| r.portal_role).count();
        let spec = BusinessRuleSpec {
            applies_to: rule.applies_to,
            staff_role_count: staff,
            portal_role_count: portal,
            condition,
            policies: &rule.policies,
        };
        // A rule whose roles were all deleted is still "valid" for a retype.
        let spec = if staff + portal == 0 {
            BusinessRuleSpec {
                applies_to: br::AppliesTo::All,
                ..spec
            }
        } else {
            spec
        };
        return br::validate_rule(&spec, attrs).is_ok();
    }
    let Some(expression) = rule.expression.as_deref() else {
        return false;
    };
    attome_rules::compile(
        expression,
        &attome_records::rule_engine::schema_for_entity(attrs),
    )
    .is_ok()
}

/// Turns off the customer rules [`retype_scan`] found, in the retype's
/// transaction, and reports each.
pub async fn retype_apply(
    conn: &mut PgConnection,
    entity: &str,
    field: &str,
    scan: &RetypeScan,
) -> Result<HookOutcome, AppError> {
    let mut out = HookOutcome::default();
    for (id, name) in &scan.customer {
        deactivate(conn, *id, &format!("field_retyped:{field}")).await?;
        out.touched += 1;
        out.report.push(ReportItemDraft {
            kind: "customer_object_adjusted",
            entity: entity.to_owned(),
            field: Some(field.to_owned()),
            object_kind: Some(OBJECT_KIND.to_owned()),
            object_ref: Some(*id),
            detail: json!({ "name": name, "change": "deactivated",
                            "message": format!("rule {name} was turned off because {field} changed type; edit and turn it back on") }),
        });
    }
    if out.touched > 0 {
        out.caches.push(CacheTouch::Rules);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_walkers_find_and_rewrite_leaves_and_expressions() {
        let mut c = json!({ "any": [
            { "all": [ { "field": "status", "op": "eq", "value": "closed" } ] },
            { "expression": "amount > 10 and region == \"eu\"" }
        ] });
        assert!(condition_uses(&c, "status"));
        assert!(condition_uses(&c, "amount"));
        assert!(!condition_uses(&c, "owner"));
        assert!(condition_rename(&mut c, "amount", "total"));
        assert!(condition_uses(&c, "total"));
        assert!(!condition_uses(&c, "amount"));
        assert!(condition_rename(&mut c, "status", "stage"));
        assert_eq!(c["any"][0]["all"][0]["field"], "stage");
        assert!(!condition_rename(&mut c, "missing", "x"));
    }

    #[test]
    fn field_types_resolve_by_name() {
        assert_eq!(field_type_named("currency"), Some(FieldType::Currency));
        assert_eq!(field_type_named("rich_text"), Some(FieldType::RichText));
        assert_eq!(field_type_named("nope"), None);
    }
}
