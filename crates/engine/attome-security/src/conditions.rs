//! D-369: bounded per-grant record conditions on role<->privilege
//! assignments. Two halves live here:
//!
//! - [`eligible_condition_field`] — the admin-write-time eligibility check
//!   (belongs to the grant's entity, has a supporting index, not
//!   `is_sensitive`, condition-eligible scalar type). Called by the admin
//!   condition-CRUD endpoints before a row is ever inserted.
//! - [`condition_predicate`] — the request-time SQL-fragment renderer,
//!   consulted only by [`crate::rls::rls_predicate_with_conditions`], which
//!   only `entity_crud.rs`'s direct paths call (D-369 v1 scope). Every other
//!   `rls_predicate`/`rls_predicate_by_column` caller is untouched.
//!
//! C-16 (M01 §7): the field-type int<->PG-type map itself lives once, on
//! `attome_core::FieldType` (already in scope for `AttrInfo` below) —
//! [`pg_type_for_storage`] is only the condition-eligible *subset* of
//! it (see its doc comment), not a second copy of the map.

use attome_core::{AttrInfo, FieldType};
use attome_server::security::{ConditionOperator, GrantCondition, SecurityContext};

use crate::rls_fragment::text_array_literal;

/// `field_type_int` -> Postgres scalar type, for the condition-eligible
/// subset only. `choice` and `file` are excluded outright — both are
/// multi-valued/complex storage shapes (`TEXT[]`/`JSONB`) a simple scalar
/// comparison can't meaningfully target, and out of v1's stated scope
/// (D-369).
/// U9: by *storage* type — a formula is conditioned on as its result type
/// (its column is that type), rich text as text, and an image (a file) is
/// excluded like `file`.
fn pg_type_for_storage(ft: &FieldType) -> Option<&'static str> {
    match ft {
        FieldType::Choice | FieldType::File | FieldType::Image => None,
        ft => Some(ft.pg_type(false)),
    }
}

/// Admin-write-time eligibility check (D-369): `field_logicalname` must
/// belong to the entity `attrs` describes, carry a supporting index
/// (`is_filterable` — the same flag P1.11(h) already computes with no DB
/// call), not be `is_sensitive`, and have a condition-eligible scalar type.
/// Returns the matched [`AttrInfo`] together with the Postgres type this
/// same check already resolved, so [`render_condition`] never re-derives it
/// from a second lookup that could in principle diverge from this one and
/// `.expect()`-panic on a live request path.
pub fn eligible_condition_field<'a>(
    attrs: &'a [AttrInfo],
    field_logicalname: &str,
) -> Result<(&'a AttrInfo, &'static str), &'static str> {
    let attr = attrs
        .iter()
        .find(|a| a.logicalname == field_logicalname)
        .ok_or("field does not belong to this entity")?;
    if attr.is_sensitive {
        return Err("condition may not reference a sensitive field");
    }
    if !attr.is_filterable {
        return Err("field has no supporting index for a condition");
    }
    let pg_type = pg_type_for_storage(&attr.storage_type())
        .ok_or("field type is not eligible for a condition")?;
    Ok((attr, pg_type))
}

/// One rendered condition comparison plus its bind value, in the same
/// text-with-explicit-cast convention [`crate::rls::RlsBinds::to_text_params`]
/// already uses — every placeholder's SQL carries its own `::type` cast, so
/// a plain Postgres text bind is correct regardless of the caller's own
/// binding convention.
pub struct RenderedCondition {
    pub sql: String,
    pub bind_text: String,
}

impl std::fmt::Debug for RenderedCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderedCondition").finish_non_exhaustive()
    }
}

/// JSON scalar -> Postgres text representation. `Null`/`Array`/`Object` are
/// rejected — only a scalar leaf ever binds to a scalar column comparison.
fn json_scalar_to_text(value: &serde_json::Value) -> Result<String, &'static str> {
    match value {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        _ => Err("condition value must be a string, number, or boolean"),
    }
}

/// Renders one [`GrantCondition`] into a `{alias}.{field} {op} $N::{type}`
/// (or `= ANY($N::{type}[])` for `In`) comparison. `pg_type` is resolved by
/// the caller from the *current* `attrs` snapshot, not stored on the cached
/// condition — a field whose type changed or whose index was dropped since
/// the condition was created is re-validated against live metadata on every
/// render, never trusted from whenever the grant was cached.
/// Renders one condition against `attrs` (D-369's eligibility rules apply:
/// the field must exist, be filterable, not sensitive, and scalar). `pub` so
/// a web portal's access plan (D-574/D-576) renders its row conditions with
/// this same code rather than a second renderer.
pub fn render_condition(
    condition: &GrantCondition,
    attrs: &[AttrInfo],
    table_alias: &str,
    placeholder: usize,
) -> Result<RenderedCondition, &'static str> {
    let (_attr, pg_type) = eligible_condition_field(attrs, &condition.field_logicalname)?;
    let col = if table_alias.is_empty() {
        condition.field_logicalname.clone()
    } else {
        format!("{table_alias}.{}", condition.field_logicalname)
    };

    if condition.operator == ConditionOperator::In {
        let serde_json::Value::Array(items) = &condition.value else {
            return Err("`in` condition value must be a JSON array");
        };
        let texts = items
            .iter()
            .map(json_scalar_to_text)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(RenderedCondition {
            sql: format!("{col} = ANY(${placeholder}::{pg_type}[])"),
            bind_text: text_array_literal(&texts),
        });
    }

    let text = json_scalar_to_text(&condition.value)?;
    Ok(RenderedCondition {
        sql: format!(
            "{col} {} ${placeholder}::{pg_type}",
            condition.operator.as_sql()
        ),
        bind_text: text,
    })
}

/// Resolution result: the AND/OR-combined SQL fragment (already wrapped in
/// its own parens, ready to `AND`-splice into a caller's WHERE clause) plus
/// its bind values in placeholder order (`$first_placeholder`..).
pub struct ConditionPredicate {
    pub sql: String,
    pub binds: Vec<String>,
}

impl std::fmt::Debug for ConditionPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConditionPredicate").finish_non_exhaustive()
    }
}

/// D-369's resolution semantics, applied to `ctx.condition_grants[privilege_key]`:
/// within one role's AND-set, every condition must hold (`AND`); across the
/// roles present in this map entry, any one role's AND-set holding is enough
/// (`OR`) — a role with a *clean* (unconditional) grant for this privilege
/// never reaches this map at all (see the field's doc comment on
/// `SecurityContext`), so every `Vec<GrantCondition>` this function sees is a
/// real, non-empty AND-set to render.
///
/// Returns `None` when the privilege key is absent from the map (no active
/// condition for this caller) or every condition set failed to render
/// (fail-closed: a condition referencing metadata that no longer validates —
/// e.g. the field was deleted, or the index was dropped — is dropped from
/// the OR rather than silently treated as "no restriction"; the caller
/// treats a completely-empty render as "deny", not "allow", by ANDing this
/// fragment onto the query the same way the tier/share/deny fragment already
/// is — a fragment that renders to no valid OR-arm becomes `FALSE`, not
/// absent, on this function's return path so a metadata-drift condition
/// fails closed instead of silently opening up).
pub fn condition_predicate(
    ctx: &SecurityContext,
    privilege_key: &str,
    attrs: &[AttrInfo],
    table_alias: &str,
    first_placeholder: usize,
) -> Option<ConditionPredicate> {
    let role_sets = ctx.condition_grants.get(privilege_key)?;

    let mut binds = Vec::new();
    let mut or_arms = Vec::new();
    let mut placeholder = first_placeholder;
    let mut any_set_failed_to_render = false;

    for and_set in role_sets {
        let mut and_arms = Vec::with_capacity(and_set.len());
        let mut set_ok = true;
        let mut set_binds = Vec::with_capacity(and_set.len());
        for condition in and_set {
            match render_condition(condition, attrs, table_alias, placeholder) {
                Ok(rendered) => {
                    and_arms.push(rendered.sql);
                    set_binds.push(rendered.bind_text);
                    placeholder += 1;
                }
                Err(_) => {
                    set_ok = false;
                    break;
                }
            }
        }
        if set_ok && !and_arms.is_empty() {
            or_arms.push(format!("({})", and_arms.join(" AND ")));
            binds.extend(set_binds);
        } else {
            any_set_failed_to_render = true;
        }
    }

    if or_arms.is_empty() {
        // Fail closed: this privilege key carries at least one condition
        // grant that could not be rendered against current metadata (drift
        // since the grant was cached) and no other role's grant covers it —
        // "FALSE" denies rather than falling through to "no restriction".
        debug_assert!(
            any_set_failed_to_render,
            "condition_grants must never carry an empty AND-set for a present privilege key"
        );
        return Some(ConditionPredicate {
            sql: "FALSE".to_owned(),
            binds: Vec::new(),
        });
    }

    Some(ConditionPredicate {
        sql: or_arms.join(" OR "),
        binds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use uuid::Uuid;

    fn attr(
        logicalname: &str,
        field_type_int: i32,
        is_sensitive: bool,
        is_filterable: bool,
    ) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive,
            is_write_restricted: false,
            is_sortable: is_filterable,
            is_filterable,
            lookup_entity_ref: None,
            on_target_delete: Default::default(),
            data_classification: Default::default(),
            options: None,
        }
    }

    fn ctx(condition_grants: HashMap<String, Vec<Vec<GrantCondition>>>) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin: false,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants,
            role_ids: None,
            service_principal: false,
        }
    }

    fn cond(field: &str, op: ConditionOperator, value: serde_json::Value) -> GrantCondition {
        GrantCondition {
            field_logicalname: field.to_owned(),
            operator: op,
            value,
        }
    }

    #[test]
    fn eligible_field_rejects_sensitive() {
        let attrs = vec![attr("ssn", 3, true, true)];
        assert!(eligible_condition_field(&attrs, "ssn").is_err());
    }

    #[test]
    fn eligible_field_rejects_unindexed() {
        let attrs = vec![attr("notes", 3, false, false)];
        assert!(eligible_condition_field(&attrs, "notes").is_err());
    }

    #[test]
    fn eligible_field_rejects_choice_and_file_types() {
        let attrs = vec![
            attr("tags", 7, false, true),
            attr("attachment", 12, false, true),
        ];
        assert!(eligible_condition_field(&attrs, "tags").is_err());
        assert!(eligible_condition_field(&attrs, "attachment").is_err());
    }

    #[test]
    fn eligible_field_rejects_unknown_field() {
        let attrs = vec![attr("industry", 3, false, true)];
        assert!(eligible_condition_field(&attrs, "revenue").is_err());
    }

    #[test]
    fn eligible_field_accepts_indexed_non_sensitive_scalar() {
        let attrs = vec![attr("industry", 3, false, true)];
        assert!(eligible_condition_field(&attrs, "industry").is_ok());
    }

    #[test]
    fn no_entry_means_no_restriction() {
        let c = ctx(HashMap::new());
        assert!(condition_predicate(&c, "account.read", &[], "t", 2).is_none());
    }

    #[test]
    fn single_role_and_set_ands_conditions() {
        let attrs = vec![
            attr("industry", 3, false, true),
            attr("revenue", 1, false, true),
        ];
        let mut map = HashMap::new();
        map.insert(
            "account.read".to_owned(),
            vec![vec![
                cond(
                    "industry",
                    ConditionOperator::Eq,
                    serde_json::json!("Active"),
                ),
                cond("revenue", ConditionOperator::Gt, serde_json::json!(10000)),
            ]],
        );
        let c = ctx(map);
        let pred = condition_predicate(&c, "account.read", &attrs, "t", 2).unwrap();
        assert!(pred.sql.contains("AND"));
        assert!(pred.sql.contains("t.industry ="));
        assert!(pred.sql.contains("t.revenue >"));
        assert_eq!(pred.binds, vec!["Active".to_owned(), "10000".to_owned()]);
    }

    #[test]
    fn two_roles_with_conditions_are_ored() {
        let attrs = vec![attr("industry", 3, false, true)];
        let mut map = HashMap::new();
        map.insert(
            "account.read".to_owned(),
            vec![
                vec![cond(
                    "industry",
                    ConditionOperator::Eq,
                    serde_json::json!("Active"),
                )],
                vec![cond(
                    "industry",
                    ConditionOperator::Eq,
                    serde_json::json!("Prospect"),
                )],
            ],
        );
        let c = ctx(map);
        let pred = condition_predicate(&c, "account.read", &attrs, "t", 2).unwrap();
        assert!(pred.sql.contains(" OR "));
        assert_eq!(pred.binds.len(), 2);
    }

    #[test]
    fn in_operator_renders_any_array() {
        let attrs = vec![attr("industry", 3, false, true)];
        let mut map = HashMap::new();
        map.insert(
            "account.read".to_owned(),
            vec![vec![cond(
                "industry",
                ConditionOperator::In,
                serde_json::json!(["Active", "Prospect"]),
            )]],
        );
        let c = ctx(map);
        let pred = condition_predicate(&c, "account.read", &attrs, "t", 2).unwrap();
        assert!(pred.sql.contains("= ANY($2::TEXT[])"));
        assert_eq!(pred.binds, vec!["{\"Active\",\"Prospect\"}".to_owned()]);
    }

    #[test]
    fn metadata_drift_fails_closed_not_open() {
        // The field the cached condition references no longer exists in
        // `attrs` (e.g. deleted since the grant was cached) — must render
        // FALSE, never silently drop to "no restriction".
        let mut map = HashMap::new();
        map.insert(
            "account.read".to_owned(),
            vec![vec![cond(
                "deleted_field",
                ConditionOperator::Eq,
                serde_json::json!("x"),
            )]],
        );
        let c = ctx(map);
        let pred = condition_predicate(&c, "account.read", &[], "t", 2).unwrap();
        assert_eq!(pred.sql, "FALSE");
    }

    #[test]
    fn empty_table_alias_omits_prefix() {
        let attrs = vec![attr("industry", 3, false, true)];
        let mut map = HashMap::new();
        map.insert(
            "account.read".to_owned(),
            vec![vec![cond(
                "industry",
                ConditionOperator::Eq,
                serde_json::json!("Active"),
            )]],
        );
        let c = ctx(map);
        let pred = condition_predicate(&c, "account.read", &attrs, "", 2).unwrap();
        // Each role's AND-set renders wrapped in its own parens (the OR-arm
        // shape `condition_predicate` always produces, even for one arm) —
        // this asserts the *column* has no alias prefix, not the outer shape.
        assert!(pred.sql.contains("industry ="));
        assert!(!pred.sql.contains(".industry"));
    }
}
