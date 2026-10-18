//! M45 Phase 2 (D-472) — bridges `attome_core::rule_registry`'s plain-data
//! `RuleDef` to `attome-rules`' pure evaluator. Since D-789 the entity write
//! path no longer evaluates legacy `validation`/`calculation`/`default` rows
//! through this module: they are business rules, run by
//! `crate::business_rules`; this module still compiles formula fields,
//! transition guards, and the legacy kinds the admin routes test. It owns
//! building a `Schema`/`Context` from an entity's live `AttrInfo` list, compiling-and-caching the result
//! (`EngineState::rule_compiled`), evaluating a rule, and the field-security
//! check `rule_admin.rs` runs on every save. Both consumers of this module —
//! `entity_mutation.rs` (the create/update retrofit) and `rule_admin.rs`
//! (CRUD/test/publish) — share it so the two paths cannot silently diverge
//! on how a rule is compiled or what a "pass" means.
//!
//! **No I/O here, ever** (coding-guidelines §9/§10, M45 plan §3.3). Every
//! function in this module is synchronous and pure except `get_or_compile`,
//! whose only "I/O" is an in-process moka cache read/write — no database
//! query, no HTTP call, no Redis round trip. Cross-record (`lookup.field`)
//! context resolution is Phase 4's concern (M45 plan §3.3, "Cross-record
//! context"); Phase 2's `Schema`/`Context` cover only an entity's own fields.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use attome_core::{AttrInfo, EngineState, RuleDef};
use attome_rules::{
    Compiled, Context as RulesContext, Expr, Schema, Type, Value as RulesValue, compile,
};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

/// Maps an `attome-core` field-type int (`AttrInfo::field_type_int`) to
/// the `attome_rules::Type` it corresponds to. `None` for `File` —
/// `attome-rules` has no `Value::File`/`Type` counterpart (rules do not
/// operate on file content, M45 plan §10). C-16 (M01 §7): the int-range
/// matching itself is `attome_core::FieldType::from_int`'s job now, not a
/// second hand-copied copy of it — only the "which `attome_rules::Type` (if
/// any)" translation stays local, since `attome_rules::Type` (7 variants, no
/// `File`) has no slot `File` could map to. `Icon`/`Color` are plain
/// TEXT-backed columns (a CSS glyph class, a `#rrggbb` hex string) with the
/// same evaluation semantics as `Text` — no dedicated `Type` needed for
/// either. `Currency` is a plain NUMERIC amount in the system base (USD) —
/// evaluated identically to `Number`; display conversion to a viewer's
/// preferred currency never reaches this engine.
///
/// U9 (D-604): the map itself moved to `attome_core::formula::rules_type`
/// so `attome-metadata`'s reconcile can compile a formula field's expression
/// before the field exists; this reads the attribute's *storage* type, so a
/// formula field evaluates as its result type, `rich_text` as text and
/// `image` (a file) not at all.
fn rules_type_of(attr: &AttrInfo) -> Option<Type> {
    attome_core::formula::attr_rules_type(attr)
}

/// The compile-time `Schema` for one entity's own fields. Phase 2 declares no
/// `related` hop at all (M45 plan §4, "Cross-record rules | Phase 4") — a
/// `lookup_field.target_field` reference in a Phase-2-authored rule is
/// therefore rejected at compile time with `RulesError::UnknownField`, the
/// same conservative-by-construction posture as any other not-yet-built
/// capability, not a special case this module has to detect.
pub fn schema_for_entity(attrs: &[AttrInfo]) -> Schema {
    let mut schema = Schema::new();
    for attr in attrs {
        if let Some(ty) = rules_type_of(attr) {
            schema = schema.with_field(attr.logicalname.clone(), ty);
        }
    }
    schema
}

/// Converts one field's submitted/stored JSON value into the
/// `attome_rules::Value` its declared field type produces. Absent or JSON
/// `null` maps to `Value::Null` for every type — the same "missing means
/// null" posture the rest of the entity engine takes — rather than a parse
/// error, since a rule referencing a field the caller left blank on a
/// partial update is an ordinary, expected case, not malformed input.
pub fn rules_value_of(field_type_int: i32, v: Option<&Value>) -> RulesValue {
    let ft =
        attome_core::FieldType::from_int(field_type_int).unwrap_or(attome_core::FieldType::Text);
    rules_value_of_type(&ft.storage(None), v)
}

/// [`rules_value_of`] for an attribute: decodes by its storage type, so a
/// formula field's stored value reads as its result type (U9, D-604).
pub fn rules_value_of_attr(attr: &AttrInfo, v: Option<&Value>) -> RulesValue {
    rules_value_of_type(&attr.storage_type(), v)
}

fn rules_value_of_type(ft: &attome_core::FieldType, v: Option<&Value>) -> RulesValue {
    use attome_core::FieldType;
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return RulesValue::Null;
    };
    match ft {
        FieldType::Number | FieldType::Currency => v
            .as_f64()
            .map(RulesValue::Number)
            .unwrap_or(RulesValue::Null),
        FieldType::Date => v
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| RulesValue::Date(d.with_timezone(&Utc)))
            .unwrap_or(RulesValue::Null),
        FieldType::Bool => v
            .as_bool()
            .map(RulesValue::Bool)
            .unwrap_or(RulesValue::Null),
        FieldType::Choice => v
            .as_str()
            .map(|s| RulesValue::Choice(s.to_owned()))
            .unwrap_or(RulesValue::Null),
        FieldType::Lookup => v
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .map(RulesValue::Lookup)
            .unwrap_or(RulesValue::Null),
        // File types have no attome_rules counterpart (see `rules_type_of`) —
        // never referenced by a compiled rule (compile would already have
        // rejected it as UnknownField), so this arm is unreachable in
        // practice; `Null` is the safe default if it's ever hit anyway.
        FieldType::File | FieldType::Image => RulesValue::Null,
        FieldType::Text
        | FieldType::Icon
        | FieldType::Color
        | FieldType::RichText
        | FieldType::Formula => v
            .as_str()
            .map(|s| RulesValue::Text(s.to_owned()))
            .unwrap_or(RulesValue::Null),
    }
}

/// The inverse of `rules_value_of` — used to merge a `calculation`/`default`
/// rule's computed result back into the JSON body `entity_mutation.rs`
/// writes.
pub fn json_from_rules_value(v: &RulesValue) -> Value {
    match v {
        RulesValue::Null => Value::Null,
        RulesValue::Bool(b) => Value::Bool(*b),
        RulesValue::Number(n) => serde_json::Number::from_f64(*n)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        RulesValue::Text(s) => Value::String(s.clone()),
        RulesValue::Date(d) => Value::String(d.to_rfc3339()),
        RulesValue::Choice(c) => Value::String(c.clone()),
        RulesValue::Lookup(id) => Value::String(id.to_string()),
        RulesValue::List(items) => Value::Array(items.iter().map(json_from_rules_value).collect()),
        RulesValue::Record(fields) => Value::Object(
            fields
                .iter()
                .map(|(name, value)| (name.clone(), json_from_rules_value(value)))
                .collect(),
        ),
    }
}

/// Builds the runtime `Context` for one record: every field the entity
/// declares a `attome_rules::Type` for (not just the ones present in `obj`) is
/// populated, `Value::Null` when absent — so a compiled expression's field
/// reference is always resolvable in `Context` whenever it resolved in
/// `Schema` (both are built off the same `attrs` list, by construction).
/// `now` is the only clock a rule can see — `attome-rules` is I/O-free and has
/// no clock of its own (M45 plan §3.1, "Pure").
pub fn context_for_record(
    now: DateTime<Utc>,
    attrs: &[AttrInfo],
    obj: &serde_json::Map<String, Value>,
) -> RulesContext {
    let mut ctx = RulesContext::new(now);
    for attr in attrs {
        if rules_type_of(attr).is_none() {
            continue;
        }
        ctx = ctx.with_field(
            attr.logicalname.clone(),
            rules_value_of_attr(attr, obj.get(&attr.logicalname)),
        );
    }
    ctx
}

/// Every base field name an expression references — a one-hop
/// `lookup_field.target_field` reference contributes only `lookup_field`
/// (the hop target is Phase 4's concern; Phase 2 has no related schema for
/// it to resolve against, so it never appears in a Phase-2-compiled rule).
/// Used by `rule_admin.rs::check_field_read_access` to enforce "an
/// expression referencing a field the caller can't read is rejected at
/// save" (M45 plan §5, explainability/leak-prevention).
pub fn referenced_fields(expr: &Expr) -> HashSet<String> {
    let mut out = HashSet::new();
    walk(expr, &mut out);
    out
}

fn walk(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::NullLit | Expr::BoolLit(_) | Expr::NumberLit(_) | Expr::StringLit(_) => {}
        Expr::FieldRef(r) => {
            out.insert(r.base.clone());
        }
        Expr::ListLit(items) => items.iter().for_each(|e| walk(e, out)),
        Expr::Unary { expr, .. } => walk(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            walk(lhs, out);
            walk(rhs, out);
        }
        Expr::Call { args, .. } => args.iter().for_each(|e| walk(e, out)),
        // Z11-T3: the parameter is the element, not a field of the record.
        Expr::Lambda { param, body } => {
            let mut inner = HashSet::new();
            walk(body, &mut inner);
            inner.remove(param);
            out.extend(inner);
        }
    }
}

/// Rejects `expr` if it references a sensitive field `ctx` cannot read (M45
/// plan §5). Called by `rule_admin.rs` on every create/update, BEFORE the
/// rule is stored, so an admin without read access to a sensitive field can
/// never author a rule whose failure message/trace would leak that field's
/// value. A non-sensitive field is never gated — same convention
/// `has_field_read_grant`'s other call sites already follow.
pub fn check_field_read_access(
    ctx: &SecurityContext,
    entity: &str,
    attrs: &[AttrInfo],
    expr: &Expr,
) -> Result<(), AppError> {
    let by_name: HashMap<&str, &AttrInfo> =
        attrs.iter().map(|a| (a.logicalname.as_str(), a)).collect();
    for field in referenced_fields(expr) {
        if let Some(attr) = by_name.get(field.as_str())
            && attr.is_sensitive
            && !ctx.has_field_read_grant(entity, &field)
        {
            return Err(AppError::Validation(format!(
                "rule references field '{field}' you do not have read access to"
            )));
        }
    }
    Ok(())
}

/// For `validation`/`requirement` rules: rejects an expression whose
/// statically-inferred type isn't `Bool` — `Type::unify` so a bare
/// `if(c, true, null)` (result type `Bool` after unifying `null`'s
/// unresolved type) still passes.
pub fn check_boolean_result_type(compiled: &Compiled) -> Result<(), AppError> {
    if compiled.result_type().unify(&Type::Bool).is_none() {
        return Err(AppError::Validation(format!(
            "a validation/requirement rule's expression must produce a boolean, not '{}'",
            compiled.result_type()
        )));
    }
    Ok(())
}

/// For `calculation`/`default` rules: rejects a rule whose expression's
/// statically-inferred type doesn't match `target_field`'s declared type
/// (M45 plan §3.1 — "a rule that would produce a value its target column
/// cannot store is rejected at save, not at runtime").
pub fn check_target_field_type(
    compiled: &Compiled,
    attrs: &[AttrInfo],
    target_field: &str,
) -> Result<(), AppError> {
    let attr = attrs
        .iter()
        .find(|a| a.logicalname == target_field)
        .ok_or_else(|| {
            AppError::Validation(format!(
                "target_field '{target_field}' does not exist on this entity"
            ))
        })?;
    if attr.is_formula() {
        return Err(AppError::Validation(format!(
            "target_field '{target_field}' is a formula field — its value comes from its own expression"
        )));
    }
    let Some(target_ty) = rules_type_of(attr) else {
        return Err(AppError::Validation(format!(
            "target_field '{target_field}' is a file field — rules cannot target file fields"
        )));
    };
    if compiled.result_type().unify(&target_ty).is_none() {
        return Err(AppError::Validation(format!(
            "rule's expression produces '{}' but target_field '{target_field}' is '{target_ty}'",
            compiled.result_type()
        )));
    }
    Ok(())
}

/// `EngineState::rule_compiled`'s key shape. `row_version` is part of the key:
/// the registry's `expression` is the latest *saved* text, and a `PATCH`
/// bumps `row_version` without bumping the published `version`. Keying on
/// `version` alone kept enforcing the pre-edit compiled program until the
/// next publish (D-789 finding). With `row_version` every edit recompiles, so
/// the cache stays safe with no TTL.
pub fn cache_key(rule_id: Uuid, version: i32, row_version: i64) -> String {
    format!("{rule_id}:{version}:{row_version}")
}

/// B-R6 (D-604): one `calculation` rule per `formula` field of the entity,
/// built from the field's own options — `(target_field, rule)`. The rule is
/// a plain [`RuleDef`] so it runs through the exact evaluator a stored
/// `calculation` rule does ([`evaluate_value`]); its id is nil (it has no
/// `rule` row) and its name names the field, so an evaluation
/// failure reads "rule 'formula:total' failed to evaluate: ...".
///
/// A formula whose options no longer parse is skipped rather than failing
/// every write to the entity: the options were validated when the field was
/// saved, so this can only be a hand-edited metadata row, and
/// [`get_or_compile_formula`] would reject it anyway.
pub fn formula_rules(entity_name: &str, attrs: &[AttrInfo]) -> Vec<(String, RuleDef)> {
    attrs
        .iter()
        .filter(|a| a.is_formula())
        .filter_map(|attr| {
            let opts = attome_core::formula::parse_options(attr.options.as_ref()).ok()?;
            Some((
                attr.logicalname.clone(),
                RuleDef {
                    id: Uuid::nil(),
                    entity_logicalname: entity_name.to_owned(),
                    name: format!("formula:{}", attr.logicalname),
                    kind: "calculation".to_owned(),
                    target_field: Some(attr.logicalname.clone()),
                    expression: opts.expression,
                    message: None,
                    severity: "error".to_owned(),
                    is_active: true,
                    display_order: 0,
                    version: 0,
                    row_version: 0,
                },
            ))
        })
        .collect()
}

/// Whether any field `rule`'s expression reads is blank (absent or null) in
/// `ctx` — the one case a formula's evaluation failure stores NULL instead
/// of blocking the write (D-604).
pub fn has_blank_input(rule: &RuleDef, ctx: &RulesContext) -> bool {
    let Ok(expr) = attome_rules::parse(&rule.expression) else {
        return false;
    };
    referenced_fields(&expr)
        .iter()
        .any(|field| ctx.field(field).is_none_or(RulesValue::is_null))
}

/// The compile-cache key of one formula: its entity, field, expression and
/// a fingerprint of the entity's field names and storage types — a changed
/// expression, or a changed type of any field it could read, is a different
/// key, so a stale compile is never reused (the cache is the same bounded
/// `EngineState::rule_compiled` moka cache stored rules use).
fn formula_cache_key(rule: &RuleDef, attrs: &[AttrInfo]) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    rule.expression.hash(&mut hasher);
    entity_types_fingerprint(attrs).hash(&mut hasher);
    format!(
        "formula:{}:{}:{:016x}",
        rule.entity_logicalname,
        rule.target_field.as_deref().unwrap_or_default(),
        hasher.finish()
    )
}

/// D-789 §9: the fingerprint of an entity's field names and the types a
/// compiled program sees them as — storage type, formula flag and
/// multi-choice flag. Part of every compile-cache key that depends on the
/// entity's schema (formula fields; business-rule conditions and `set_value`
/// expressions, `crate::business_rules`), so a changed field type is a new
/// key and a program compiled against the old type is never reused.
/// Process-local (`DefaultHasher`), like the caches it keys.
pub fn entity_types_fingerprint(attrs: &[AttrInfo]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for attr in attrs {
        attr.logicalname.hash(&mut hasher);
        attr.storage_type().as_str().hash(&mut hasher);
        attr.is_formula().hash(&mut hasher);
        attome_core::FieldType::Choice
            .is_multi_valued(attr.options.as_ref().unwrap_or(&Value::Null))
            .hash(&mut hasher);
    }
    hasher.finish()
}

/// [`get_or_compile`] for a formula field's synthetic rule
/// ([`formula_rules`]): compiles through
/// `attome_core::formula::compile_formula`, the same check that ran when
/// the field was saved, so a formula that no longer type-checks against the
/// entity's live fields fails the write with a 422 instead of storing a
/// value its column cannot hold.
pub async fn get_or_compile_formula(
    state: &EngineState,
    attrs: &[AttrInfo],
    rule: &RuleDef,
) -> Result<Arc<Compiled>, AppError> {
    let key = formula_cache_key(rule, attrs);
    if let Some(hit) = state.rule_compiled.get(&key).await {
        return Ok(hit);
    }
    let field = rule.target_field.as_deref().unwrap_or_default();
    let options = attrs
        .iter()
        .find(|a| a.logicalname == field)
        .and_then(|a| a.options.as_ref());
    let compiled = attome_core::formula::compile_formula(attrs, options).map_err(|e| match e {
        AppError::Validation(msg) => {
            AppError::Validation(format!("formula field '{field}' is invalid: {msg}"))
        }
        other => other,
    })?;
    let compiled = Arc::new(compiled);
    state.rule_compiled.insert(key, compiled.clone()).await;
    Ok(compiled)
}

/// Compiles-and-caches, or returns the cached `Compiled` for `(rule.id,
/// rule.version, rule.row_version)`. A cache miss recompiles against `schema` — a genuine
/// compile error here means the stored expression no longer type-checks
/// against the entity's LIVE schema (e.g. `target_field`'s type changed
/// after the rule was authored), surfaced as `AppError::Validation` so the
/// write fails loud rather than silently skip a rule that should apply.
pub async fn get_or_compile(
    state: &EngineState,
    rule: &RuleDef,
    schema: &Schema,
) -> Result<Arc<Compiled>, AppError> {
    let key = cache_key(rule.id, rule.version, rule.row_version);
    if let Some(hit) = state.rule_compiled.get(&key).await {
        return Ok(hit);
    }
    let compiled = compile(&rule.expression, schema).map_err(|e| {
        AppError::Validation(format!("rule '{}' failed to compile: {e}", rule.name))
    })?;
    let compiled = Arc::new(compiled);
    state.rule_compiled.insert(key, compiled.clone()).await;
    Ok(compiled)
}

/// Evaluates one `kind = validation` (or `requirement`, Phase 4) rule
/// against `ctx`. `Ok(())` covers a passing rule (`Value::Bool(true)`) and a
/// non-blocking `severity = "warning"` failure — logged, not surfaced; Phase
/// 2 has no warnings-response channel on the write contract yet (documented
/// gap, see the M45 plan's Phase 3+ scope). `Err(AppError::RuleViolation)`
/// covers a blocking `severity = "error"` failure, whether the expression
/// evaluated to `false`/a non-bool or failed to evaluate at all (a
/// budget/runtime error on an already-type-checked rule is still "this
/// write cannot be confirmed to pass this rule" — same 422 either way, which
/// is what makes "budget exhaustion returns 422 not 500" hold).
///
/// BRU-E3b (BRU-D5): the one exception is a **transient** failure —
/// RulesError::is_transient(), true only for the wall-clock breaker. That is
/// the node being busy, not the rule being wrong, so a blocking rule returns a
/// retryable AppError::Overloaded (503) at warn instead of a 422;
/// warning-severity rules still pass, and every permanent failure keeps the
/// 422 above unchanged.
pub fn evaluate_validation(
    rule: &RuleDef,
    compiled: &Compiled,
    ctx: &RulesContext,
) -> Result<(), AppError> {
    let outcome = compiled.eval(ctx);
    let passed = matches!(&outcome, Ok(RulesValue::Bool(true)));
    if passed {
        return Ok(());
    }
    let detail = match &outcome {
        Err(e) => format!(" ({e})"),
        Ok(_) => String::new(),
    };
    if rule.severity == "warning" {
        tracing::warn!(
            rule_id = %rule.id,
            rule = %rule.name,
            entity = %rule.entity_logicalname,
            "rule_engine: warning-severity validation rule failed{detail}"
        );
        return Ok(());
    }
    // BRU-E3b / BRU-D5: a wall-clock budget trip is a load-dependent failure,
    // not a rule failure — the same write can pass on an idle node, so it must
    // not be reported as a rule violation (422). Permanent failures (a
    // false/non-bool result, a step/node budget, a missing field, a type
    // error) fall through to the RuleViolation below, exactly as before.
    if let Err(e) = &outcome
        && e.is_transient()
    {
        tracing::warn!(
            rule_id = %rule.id,
            rule = %rule.name,
            entity = %rule.entity_logicalname,
            error = %e,
            "rule_engine: rule evaluation hit a transient wall-clock budget; retryable"
        );
        return Err(AppError::Overloaded("rule_engine.rule_eval_wall_clock"));
    }
    let message = rule
        .message
        .clone()
        .unwrap_or_else(|| format!("rule '{}' failed", rule.name));
    Err(AppError::RuleViolation {
        rule_id: rule.id,
        message: format!("{message}{detail}"),
        details: None,
    })
}

/// Evaluates one `kind = calculation`/`default` rule, returning the computed
/// value or a blocking error. `entity_mutation.rs` (the only caller) reacts
/// differently to the two kinds' errors — a `calculation` rule's failure
/// blocks the whole write (the derived field is meant to be authoritative,
/// no safe fallback), a `default` rule's failure is skip-and-log (a
/// best-effort convenience, not a hard constraint) — but both call this same
/// function; the difference is entirely in the caller.
pub fn evaluate_value(
    rule: &RuleDef,
    compiled: &Compiled,
    ctx: &RulesContext,
) -> Result<RulesValue, AppError> {
    compiled.eval(ctx).map_err(|e| AppError::RuleViolation {
        rule_id: rule.id,
        message: format!("rule '{}' failed to evaluate: {e}", rule.name),
        details: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D-789 finding: a PATCH bumps `row_version` but not the published
    /// `version`; the compiled cache must not serve the pre-edit program.
    #[test]
    fn an_unpublished_edit_changes_the_compiled_cache_key() {
        let id = Uuid::now_v7();
        assert_ne!(cache_key(id, 3, 7), cache_key(id, 3, 8));
        assert_eq!(cache_key(id, 3, 7), cache_key(id, 3, 7));
    }
    use attome_core::{DataClassification, OnTargetDelete};

    fn attr(logicalname: &str, field_type_int: i32, is_sensitive: bool) -> AttrInfo {
        AttrInfo {
            logicalname: logicalname.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive,
            is_write_restricted: false,
            is_sortable: true,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            options: None,
        }
    }

    fn rule(entity: &str, name: &str, kind: &str, expr: &str, severity: &str) -> RuleDef {
        RuleDef {
            id: Uuid::now_v7(),
            entity_logicalname: entity.to_owned(),
            name: name.to_owned(),
            kind: kind.to_owned(),
            target_field: None,
            expression: expr.to_owned(),
            message: None,
            severity: severity.to_owned(),
            is_active: true,
            display_order: 0,
            version: 1,
            row_version: 0,
        }
    }

    fn ctx(admin: bool) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::nil(),
            is_admin: admin,
            privileges: HashSet::new(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        }
    }

    fn formula_attr(name: &str, expr: &str, result_type: &str) -> AttrInfo {
        let mut a = attr(name, 16, false);
        a.options = Some(serde_json::json!({"expression": expr, "result_type": result_type}));
        a
    }

    #[test]
    fn formula_rules_become_calculation_rules_targeting_their_field() {
        let attrs = vec![
            attr("quantity", 1, false),
            attr("price", 2, false),
            formula_attr("total", "quantity * price", "number"),
        ];
        let rules = formula_rules("order_line", &attrs);
        assert_eq!(rules.len(), 1);
        let (target, rule) = &rules[0];
        assert_eq!(target, "total");
        assert_eq!(rule.kind, "calculation");
        assert_eq!(rule.target_field.as_deref(), Some("total"));
        assert_eq!(rule.expression, "quantity * price");

        // Evaluated by the same evaluator a stored calculation rule uses.
        let compiled = attome_core::formula::compile_formula(&attrs, attrs[2].options.as_ref())
            .expect("compiles");
        let mut obj = serde_json::Map::new();
        obj.insert("quantity".into(), serde_json::json!(3));
        obj.insert("price".into(), serde_json::json!(2.5));
        let ctx = context_for_record(Utc::now(), &attrs, &obj);
        let value = evaluate_value(rule, &compiled, &ctx).expect("evaluates");
        assert_eq!(json_from_rules_value(&value), serde_json::json!(7.5));
    }

    #[test]
    fn has_blank_input_sees_an_absent_or_null_referenced_field() {
        let attrs = vec![attr("label", 3, false), attr("quantity", 1, false)];
        let (_, rule) = formula_rules("e", &[formula_attr("shout", "upper(label)", "text")])
            .pop()
            .unwrap();
        let blank = context_for_record(Utc::now(), &attrs, &serde_json::Map::new());
        assert!(has_blank_input(&rule, &blank));
        let mut obj = serde_json::Map::new();
        obj.insert("label".into(), serde_json::json!("x"));
        let filled = context_for_record(Utc::now(), &attrs, &obj);
        assert!(!has_blank_input(&rule, &filled));
    }

    #[test]
    fn a_formula_field_evaluates_as_its_result_type_in_other_rules() {
        let attrs = vec![
            attr("quantity", 1, false),
            formula_attr("total", "quantity * 2", "number"),
        ];
        let schema = schema_for_entity(&attrs);
        assert_eq!(schema.field_type("total"), Some(&Type::Number));
    }

    #[test]
    fn a_rule_cannot_target_a_formula_field() {
        let attrs = vec![
            attr("quantity", 1, false),
            formula_attr("total", "quantity * 2", "number"),
        ];
        let schema = schema_for_entity(&attrs);
        let compiled = compile("quantity + 1", &schema).expect("compiles");
        assert!(check_target_field_type(&compiled, &attrs, "total").is_err());
    }

    #[test]
    fn schema_skips_file_typed_attrs() {
        let attrs = vec![attr("amount", 1, false), attr("attachment", 12, false)];
        let schema = schema_for_entity(&attrs);
        assert!(schema.field_type("amount").is_some());
        assert!(schema.field_type("attachment").is_none());
    }

    #[test]
    fn context_for_record_fills_missing_fields_as_null() {
        let attrs = vec![attr("amount", 1, false)];
        let obj = serde_json::Map::new();
        let ctx = context_for_record(Utc::now(), &attrs, &obj);
        assert_eq!(ctx.field("amount"), Some(&RulesValue::Null));
    }

    #[test]
    fn referenced_fields_walks_binary_and_call_nodes() {
        let schema = Schema::new()
            .with_field("amount", Type::Number)
            .with_field("threshold", Type::Number);
        let compiled = compile("if(amount > threshold, true, false)", &schema).unwrap();
        // `Compiled` doesn't expose its `Expr`; re-parse the same source to
        // exercise the walker (same posture `rule_admin.rs` takes: parse
        // once for field extraction, compile once for type-checking).
        let expr = attome_rules::parse("if(amount > threshold, true, false)").unwrap();
        let fields = referenced_fields(&expr);
        assert!(fields.contains("amount"));
        assert!(fields.contains("threshold"));
        assert_eq!(compiled.result_type(), &Type::Bool);
    }

    #[test]
    fn check_field_read_access_rejects_an_unreadable_sensitive_field() {
        let attrs = vec![attr("salary", 1, true)];
        let expr = attome_rules::parse("salary > 0").unwrap();
        let denied = check_field_read_access(&ctx(false), "employee", &attrs, &expr);
        assert!(denied.is_err());
        let allowed = check_field_read_access(&ctx(true), "employee", &attrs, &expr);
        assert!(allowed.is_ok());
    }

    #[test]
    fn check_field_read_access_ignores_a_non_sensitive_field() {
        let attrs = vec![attr("amount", 1, false)];
        let expr = attome_rules::parse("amount > 0").unwrap();
        assert!(check_field_read_access(&ctx(false), "invoice", &attrs, &expr).is_ok());
    }

    #[test]
    fn check_boolean_result_type_rejects_a_non_bool_rule() {
        let schema = Schema::new().with_field("amount", Type::Number);
        let compiled = compile("amount + 1", &schema).unwrap();
        assert!(check_boolean_result_type(&compiled).is_err());
    }

    #[test]
    fn check_target_field_type_rejects_a_type_mismatch() {
        let attrs = vec![attr("amount", 1, false), attr("name", 0, false)];
        let schema = schema_for_entity(&attrs);
        let compiled = compile("amount + 1", &schema).unwrap();
        assert!(check_target_field_type(&compiled, &attrs, "name").is_err());
        assert!(check_target_field_type(&compiled, &attrs, "amount").is_ok());
    }

    #[test]
    fn evaluate_validation_passes_on_true() {
        let attrs = vec![attr("amount", 1, false)];
        let schema = schema_for_entity(&attrs);
        let compiled = compile("amount > 0", &schema).unwrap();
        let r = rule("invoice", "positive", "validation", "amount > 0", "error");
        let mut obj = serde_json::Map::new();
        obj.insert("amount".into(), serde_json::json!(10));
        let ctx = context_for_record(Utc::now(), &attrs, &obj);
        assert!(evaluate_validation(&r, &compiled, &ctx).is_ok());
    }

    #[test]
    fn evaluate_validation_blocks_on_false_for_error_severity() {
        let attrs = vec![attr("amount", 1, false)];
        let schema = schema_for_entity(&attrs);
        let compiled = compile("amount > 0", &schema).unwrap();
        let r = rule("invoice", "positive", "validation", "amount > 0", "error");
        let mut obj = serde_json::Map::new();
        obj.insert("amount".into(), serde_json::json!(-5));
        let ctx = context_for_record(Utc::now(), &attrs, &obj);
        let err = evaluate_validation(&r, &compiled, &ctx).unwrap_err();
        assert!(matches!(err, AppError::RuleViolation { rule_id, .. } if rule_id == r.id));
    }

    #[test]
    fn evaluate_validation_does_not_block_on_false_for_warning_severity() {
        let attrs = vec![attr("amount", 1, false)];
        let schema = schema_for_entity(&attrs);
        let compiled = compile("amount > 0", &schema).unwrap();
        let r = rule("invoice", "positive", "validation", "amount > 0", "warning");
        let mut obj = serde_json::Map::new();
        obj.insert("amount".into(), serde_json::json!(-5));
        let ctx = context_for_record(Utc::now(), &attrs, &obj);
        assert!(evaluate_validation(&r, &compiled, &ctx).is_ok());
    }

    /// Negative test: an eval-time `RulesError` (here, a budget exceeded on
    /// an already-type-checked rule) still returns a typed `RuleViolation`
    /// (-> 422 at the HTTP layer, `attome_types::AppError`'s own mapping),
    /// never a panic or an `Internal`/500.
    #[test]
    fn evaluate_validation_maps_a_budget_error_to_rule_violation_not_a_panic() {
        let attrs = vec![attr("amount", 1, false)];
        let schema = schema_for_entity(&attrs);
        let tiny_budget = attome_rules::Budgets {
            max_eval_steps: 0,
            ..attome_rules::Budgets::default()
        };
        let compiled =
            attome_rules::compile_with_budgets("amount > 0", &schema, tiny_budget).unwrap();
        let r = rule("invoice", "positive", "validation", "amount > 0", "error");
        let mut obj = serde_json::Map::new();
        obj.insert("amount".into(), serde_json::json!(10));
        let ctx = context_for_record(Utc::now(), &attrs, &obj);
        let err = evaluate_validation(&r, &compiled, &ctx).unwrap_err();
        assert!(matches!(err, AppError::RuleViolation { .. }));
    }

    /// BRU-E3b (BRU-D5): a transient wall-clock trip is a retryable 503
    /// (AppError::Overloaded), never a 422 rule violation — the rule did not
    /// fail, the node was busy. A warning-severity rule stays non-blocking,
    /// and permanent failures keep their 422 (the test above).
    #[test]
    fn evaluate_validation_maps_a_transient_wall_clock_error_to_a_retryable_503() {
        let attrs = vec![attr("amount", 1, false)];
        let schema = schema_for_entity(&attrs);
        // A zero wall-clock ceiling plus an expression with hundreds of nodes,
        // so the breaker cannot miss: it trips within the first few steps.
        let args = std::iter::repeat_n("1", 600).collect::<Vec<_>>().join(", ");
        let src = format!("min({args})");
        let zero_clock = attome_rules::Budgets {
            max_wall_clock: std::time::Duration::ZERO,
            ..attome_rules::Budgets::default()
        };
        let compiled = attome_rules::compile_with_budgets(&src, &schema, zero_clock).unwrap();
        let r = rule("invoice", "transient", "validation", &src, "error");
        let mut obj = serde_json::Map::new();
        obj.insert("amount".into(), serde_json::json!(10));
        let ctx = context_for_record(Utc::now(), &attrs, &obj);

        // The fixture is only meaningful if the error really is transient.
        match compiled.eval(&ctx) {
            Err(e) => assert!(e.is_transient(), "expected a transient error, got {e:?}"),
            Ok(value) => panic!("expected the zero wall clock to trip, got {value:?}"),
        }

        let err = evaluate_validation(&r, &compiled, &ctx).unwrap_err();
        assert!(matches!(err, AppError::Overloaded(_)), "got {err:?}");

        // A warning-severity rule is non-blocking whatever the failure, as
        // before: there is nothing for the caller to retry.
        let warning = rule("invoice", "transient_warn", "validation", &src, "warning");
        assert!(evaluate_validation(&warning, &compiled, &ctx).is_ok());
    }

    #[test]
    fn evaluate_value_computes_a_calculation_result() {
        let attrs = vec![attr("amount", 1, false), attr("tax", 1, false)];
        let schema = schema_for_entity(&attrs);
        let compiled = compile("amount * 1.1", &schema).unwrap();
        let r = rule(
            "invoice",
            "total_with_tax",
            "calculation",
            "amount * 1.1",
            "error",
        );
        let mut obj = serde_json::Map::new();
        obj.insert("amount".into(), serde_json::json!(100.0));
        let ctx = context_for_record(Utc::now(), &attrs, &obj);
        let value = evaluate_value(&r, &compiled, &ctx).unwrap();
        assert_eq!(value, RulesValue::Number(110.00000000000001));
    }

    #[test]
    fn json_from_rules_value_round_trips_common_shapes() {
        assert_eq!(
            json_from_rules_value(&RulesValue::Bool(true)),
            Value::Bool(true)
        );
        assert_eq!(
            json_from_rules_value(&RulesValue::Number(42.0)),
            serde_json::json!(42.0)
        );
        assert_eq!(json_from_rules_value(&RulesValue::Null), Value::Null);
    }
}
