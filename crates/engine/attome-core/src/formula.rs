//! Formula fields (basic-units U9, ruling B-R6, D-604).
//!
//! A `formula` field (field type 16) is the existing M45 `calculation` rule
//! kind surfaced as a field: its `options` carry an `expression` in the one
//! `attome-rules` grammar and a `result_type`, and the entity engine computes
//! the value on every write with the same evaluator
//! (`attome_records::rule_engine::evaluate_value`) and stores it in a
//! native column of the result type. There is no second evaluator and no
//! `GENERATED` column.
//!
//! This module owns the parts both the provisioning layer (`attome-metadata`'s
//! reconcile, which rejects an invalid expression before the field exists)
//! and the entity engine (which evaluates it) need: the options shape, the
//! field-type -> `attome_rules::Type` map, and the compile check. It lives here
//! because `attome-metadata` sits below the entity engine.
//!
//! Y2-T11 (V2-D116): a formula saved with `"generated": true` is instead a
//! PostgreSQL `GENERATED ALWAYS AS (...) STORED` column, so the database
//! keeps it right whichever path writes the row. Only the part of the
//! language whose SQL meaning is the evaluator's translates
//! ([`to_generated_sql`]); any other expression is refused at save. The
//! entity engine skips such a field when it computes formulas.
//!
//! A9-T1: a formula's `mode` is `stored` (the default: computed on every
//! write and kept in its column) or `read_time` (computed whenever a record
//! is read, so an expression over `today()` or `now()` is never stale; its
//! column stays empty). A stored formula reads only its own record's fields,
//! so it recomputes in the write that changes them.
//!
//! A9-T2: a `read_time` formula may also read through lookups, up to
//! [`MAX_FORMULA_HOPS`] of them (`account.owner.manager.region`), resolved
//! when the record is read. A stored formula may not: nothing would
//! recompute it when the related record changes. A path may end at another
//! entity's formula; a `read_time` one there is computed in turn, so the
//! formulas reading each other through lookups form a graph, and a save
//! that would close a cycle in it is refused naming the cycle
//! ([`formula_cycle`]).

use attome_rules::{BinaryOp, Compiled, Expr, Schema, Type, UnaryOp, compile};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::field_type::{FORMULA_RESULT_TYPES, FieldType};
use crate::meta_registry::AttrInfo;

/// A9-T2: the most lookups a `read_time` formula follows to a value.
pub const MAX_FORMULA_HOPS: usize = 5;

/// Longest expression a formula may carry. The evaluator has its own node
/// and step budgets; this only keeps an absurd metadata value out of the
/// attribute row.
pub const MAX_FORMULA_EXPRESSION_LEN: usize = 2000;

/// `attribute_info.options` of a `formula` field.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FormulaOptions {
    /// A `attome-rules` expression over this entity's own (non-formula) fields.
    pub expression: String,
    /// One of [`FORMULA_RESULT_TYPES`]; picks the column type.
    pub result_type: String,
    /// Y2-T11: stored as a database generated column.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub generated: bool,
    /// A9-T1: when the value is computed.
    #[serde(default, skip_serializing_if = "FormulaMode::is_stored")]
    pub mode: FormulaMode,
}

/// A9-T1: when a formula's value is computed.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FormulaMode {
    /// On every write, kept in the field's column.
    #[default]
    Stored,
    /// On every read; the column stays empty.
    ReadTime,
}

impl FormulaMode {
    pub fn is_stored(&self) -> bool {
        *self == Self::Stored
    }
}

/// A9-T3: whether `expression` reads the clock (`today()` or `now()`), so a
/// stored value goes stale as days pass and is recomputed daily. Pure; an
/// expression that does not parse reads no clock.
pub fn is_time_based(expression: &str) -> bool {
    fn reads_clock(expr: &Expr) -> bool {
        match expr {
            Expr::Call { name, args } => {
                matches!(name.as_str(), "today" | "now") || args.iter().any(reads_clock)
            }
            Expr::Unary { expr, .. } => reads_clock(expr),
            Expr::Binary { lhs, rhs, .. } => reads_clock(lhs) || reads_clock(rhs),
            Expr::ListLit(items) => items.iter().any(reads_clock),
            Expr::Lambda { body, .. } => reads_clock(body),
            _ => false,
        }
    }
    attome_rules::parse(expression).is_ok_and(|expr| reads_clock(&expr))
}

/// A9-T3: whether `attr` is a stored formula whose expression reads the
/// clock: a `read_time` one is never stale and a generated one is the
/// database's.
pub fn is_time_based_stored(attr: &AttrInfo) -> bool {
    attr.is_formula()
        && !attr.is_generated_formula()
        && !is_read_time(attr.options.as_ref())
        && parse_options(attr.options.as_ref()).is_ok_and(|o| is_time_based(&o.expression))
}

/// A9-T1: whether a formula field's options say `mode: read_time`.
pub fn is_read_time(options: Option<&Value>) -> bool {
    options.and_then(|o| o.get("mode")).and_then(Value::as_str) == Some("read_time")
}

/// Parses and shape-checks a formula field's options. Does not compile the
/// expression — that needs the entity's fields ([`compile_formula`]).
pub fn parse_options(options: Option<&Value>) -> Result<FormulaOptions, AppError> {
    let options = options.ok_or_else(|| {
        AppError::Validation(
            "a formula field requires options {\"expression\": ..., \"result_type\": ...}".into(),
        )
    })?;
    let opts: FormulaOptions = serde_json::from_value(options.clone())
        .map_err(|e| AppError::Validation(format!("invalid formula options: {e}")))?;
    let expression = opts.expression.trim();
    if expression.is_empty() {
        return Err(AppError::Validation(
            "formula options.expression must not be empty".into(),
        ));
    }
    if expression.chars().count() > MAX_FORMULA_EXPRESSION_LEN {
        return Err(AppError::Validation(format!(
            "formula options.expression must not exceed {MAX_FORMULA_EXPRESSION_LEN} characters"
        )));
    }
    if !FORMULA_RESULT_TYPES.contains(&opts.result_type.as_str()) {
        return Err(AppError::Validation(format!(
            "formula options.result_type '{}' is not one of {}",
            opts.result_type,
            FORMULA_RESULT_TYPES.join("|")
        )));
    }
    if opts.generated && opts.mode == FormulaMode::ReadTime {
        return Err(AppError::Validation(
            "a formula is generated (a stored column) or read_time, not both".into(),
        ));
    }
    Ok(FormulaOptions {
        expression: expression.to_owned(),
        result_type: opts.result_type,
        generated: opts.generated,
        mode: opts.mode,
    })
}

/// The SQL types a generated expression is tracked in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SqlTy {
    Number,
    Text,
    /// A `null` literal, which takes the type of what it is combined with.
    Null,
}

fn sql_ty_of(ft: &FieldType) -> Option<SqlTy> {
    match ft {
        FieldType::Number | FieldType::Currency => Some(SqlTy::Number),
        FieldType::Text | FieldType::Icon | FieldType::Color | FieldType::RichText => {
            Some(SqlTy::Text)
        }
        _ => None,
    }
}

fn generated_part(expr: &Expr, attrs: &[AttrInfo]) -> Option<(String, SqlTy)> {
    match expr {
        Expr::NullLit => Some(("NULL".to_owned(), SqlTy::Null)),
        Expr::NumberLit(n) if n.is_finite() => Some((format!("{n}::numeric"), SqlTy::Number)),
        Expr::StringLit(s) => Some((format!("'{}'::text", s.replace('\'', "''")), SqlTy::Text)),
        Expr::FieldRef(field) if field.hop.is_none() => {
            let attr = attrs
                .iter()
                .find(|a| a.logicalname == field.base && !a.is_formula())?;
            let ty = sql_ty_of(&attr.storage_type())?;
            Some((crate::quote_ident(&attr.logicalname), ty))
        }
        Expr::Unary {
            op: UnaryOp::Neg,
            expr,
        } => {
            let (sql, ty) = generated_part(expr, attrs)?;
            (ty == SqlTy::Number).then(|| (format!("(-{sql})"), SqlTy::Number))
        }
        Expr::Binary { op, lhs, rhs } => {
            let (l, lt) = generated_part(lhs, attrs)?;
            let (r, rt) = generated_part(rhs, attrs)?;
            match (op, lt, rt) {
                (BinaryOp::Add, SqlTy::Number, SqlTy::Number) => {
                    Some((format!("({l} + {r})"), SqlTy::Number))
                }
                (BinaryOp::Add, SqlTy::Text, SqlTy::Text) => {
                    Some((format!("({l} || {r})"), SqlTy::Text))
                }
                (BinaryOp::Sub, SqlTy::Number, SqlTy::Number) => {
                    Some((format!("({l} - {r})"), SqlTy::Number))
                }
                (BinaryOp::Mul, SqlTy::Number, SqlTy::Number) => {
                    Some((format!("({l} * {r})"), SqlTy::Number))
                }
                // Division and remainder stay in the evaluator: a zero
                // divisor blocks the write there with a 422, while a
                // generated column would fail the statement.
                _ => None,
            }
        }
        Expr::Call { name, args } if name == "coalesce" && !args.is_empty() => {
            let mut parts = Vec::with_capacity(args.len());
            let mut ty = SqlTy::Null;
            for arg in args {
                let (sql, t) = generated_part(arg, attrs)?;
                match (ty, t) {
                    (_, SqlTy::Null) => {}
                    (SqlTy::Null, t) => ty = t,
                    (a, b) if a == b => {}
                    _ => return None,
                }
                parts.push(sql);
            }
            Some((format!("COALESCE({})", parts.join(", ")), ty))
        }
        _ => None,
    }
}

/// Y2-T11: `expression` as the SQL of a generated column over `attrs`, or
/// `None` when it uses anything beyond number and text fields of this
/// entity (no formulas, no lookups), number and text literals, `+ - *`,
/// unary `-`, text joins (`+` of two texts) and `coalesce`. Pure.
pub fn to_generated_sql(expression: &str, attrs: &[AttrInfo]) -> Option<String> {
    let expr = attome_rules::parse(expression).ok()?;
    generated_part(&expr, attrs).map(|(sql, _)| sql)
}

/// Y2-T11: the generated column SQL of a formula saved with
/// `"generated": true`, `None` for any other formula, and a 422 when the
/// expression cannot be a generated column or does not produce the
/// `result_type`.
pub fn generated_sql(
    attrs: &[AttrInfo],
    options: Option<&Value>,
) -> Result<Option<String>, AppError> {
    let opts = parse_options(options)?;
    if !opts.generated {
        return Ok(None);
    }
    let refuse = || {
        AppError::Validation(
            "a generated formula may use only this entity's number and text fields, \
             literals, + - *, text joins and coalesce, and must produce a number or text"
                .into(),
        )
    };
    let expr = attome_rules::parse(&opts.expression).map_err(|_| refuse())?;
    let (sql, ty) = generated_part(&expr, attrs).ok_or_else(refuse)?;
    let wanted = FieldType::try_from(opts.result_type.as_str())
        .ok()
        .and_then(|ft| sql_ty_of(&ft));
    if wanted != Some(ty) {
        return Err(refuse());
    }
    Ok(Some(sql))
}

/// The `attome_rules::Type` a value of storage type `ft` evaluates as. `None`
/// for file-backed fields: rules never operate on file content (M45 plan
/// §10). `Icon`/`Color`/`RichText` are TEXT columns and evaluate as text;
/// `Currency` is a plain NUMERIC amount and evaluates as a number.
pub fn rules_type(ft: &FieldType) -> Option<Type> {
    match ft {
        // A rollup reaches here as its storage type; its own arm is the
        // options-less default.
        FieldType::Number | FieldType::Currency | FieldType::Rollup => Some(Type::Number),
        FieldType::Date | FieldType::DateTime => Some(Type::Date),
        FieldType::Bool => Some(Type::Bool),
        FieldType::Choice => Some(Type::Choice),
        FieldType::Lookup => Some(Type::Lookup),
        // A2-T1: a time of day has no rules type yet; A2-T3: nor a point
        // or a JSON document.
        FieldType::File
        | FieldType::Image
        | FieldType::Time
        | FieldType::Geolocation
        | FieldType::Json => None,
        FieldType::Text
        | FieldType::Icon
        | FieldType::Color
        | FieldType::RichText
        | FieldType::Formula => Some(Type::Text),
    }
}

/// [`rules_type`] of an attribute's storage type — a formula evaluates as
/// its result type wherever another rule reads it.
pub fn attr_rules_type(attr: &AttrInfo) -> Option<Type> {
    rules_type(&attr.storage_type())
}

/// The schema a formula's expression compiles against: every field of the
/// entity that has a rules type, **except formula fields** (including the
/// formula itself). Formulas are computed in one pass against the row being
/// written, so one formula reading another would see the other's previous
/// value; refusing the reference at save is the honest answer.
pub fn formula_input_schema(attrs: &[AttrInfo]) -> Schema {
    let mut schema = Schema::new();
    for attr in attrs.iter().filter(|a| !a.is_formula()) {
        if let Some(ty) = attr_rules_type(attr) {
            schema = schema.with_field(attr.logicalname.clone(), ty);
        }
    }
    schema
}

/// Compiles a formula's expression against the entity's fields and checks
/// that its inferred type fits the declared `result_type`. `attrs` is the
/// entity's attribute list; the formula field itself may or may not be in
/// it (it is excluded either way). A failure is `AppError::Validation` —
/// a 422 at field save, before the field exists.
pub fn compile_formula(attrs: &[AttrInfo], options: Option<&Value>) -> Result<Compiled, AppError> {
    compile_formula_in(attrs, options, None)
}

/// A9-T2: whether `expression` reads anything through a lookup
/// (`owner.region`, `account.owner.manager.region`). Pure; an expression
/// that does not parse reads none.
pub fn reads_through_lookup(expression: &str) -> bool {
    fn walk(expr: &Expr) -> bool {
        match expr {
            Expr::FieldRef(r) => r.hop.is_some(),
            Expr::Path(_) => true,
            Expr::Unary { expr, .. } => walk(expr),
            Expr::Binary { lhs, rhs, .. } => walk(lhs) || walk(rhs),
            Expr::Call { args, .. } | Expr::ListLit(args) => args.iter().any(walk),
            Expr::Lambda { body, .. } => walk(body),
            Expr::NullLit | Expr::BoolLit(_) | Expr::NumberLit(_) | Expr::StringLit(_) => false,
        }
    }
    attome_rules::parse(expression).is_ok_and(|e| walk(&e))
}

/// A9-T2: the lookup paths a formula's `expression` on an entity with
/// `attrs` reads, resolved in `registry` (at most [`MAX_FORMULA_HOPS`]
/// lookups; one that does not resolve is left out, so the compile names it).
pub fn formula_paths(
    expression: &str,
    attrs: &[AttrInfo],
    registry: &crate::EntityMetaRegistry,
) -> Vec<crate::business_rules::RelatedRef> {
    crate::business_rules::related_refs_within(expression, attrs, registry, MAX_FORMULA_HOPS)
}

/// [`compile_formula`] with the other entities in `registry`: a `read_time`
/// formula's lookup paths are declared, and a stored formula reading
/// through a lookup is refused. Without a registry no path resolves.
pub fn compile_formula_in(
    attrs: &[AttrInfo],
    options: Option<&Value>,
    registry: Option<&crate::EntityMetaRegistry>,
) -> Result<Compiled, AppError> {
    let opts = parse_options(options)?;
    let mut schema = formula_input_schema(attrs);
    let through_lookup = reads_through_lookup(&opts.expression);
    if through_lookup && opts.mode.is_stored() {
        return Err(AppError::Validation(
            "a stored formula reads only its own record's fields; to read through a lookup, set \
             mode to read_time (computed when the record is read)"
                .into(),
        ));
    }
    if through_lookup && let Some(registry) = registry {
        schema = crate::business_rules::with_related_schema(
            schema,
            &formula_paths(&opts.expression, attrs, registry),
        );
    }
    let compiled = if through_lookup {
        attome_rules::compile_versioned(
            &opts.expression,
            &schema,
            attome_rules::LanguageVersion::V2,
            attome_rules::Budgets::default(),
        )
    } else {
        compile(&opts.expression, &schema)
    }
    .map_err(|e| AppError::Validation(format!("formula expression does not compile: {e}")))?;
    let target = FieldType::try_from(opts.result_type.as_str())
        .ok()
        .and_then(|ft| rules_type(&ft))
        .unwrap_or(Type::Text);
    let produced = compiled.result_type();
    // A choice value is a string label, which a text column stores as is.
    let fits = produced.unify(&target).is_some()
        || (target == Type::Text && produced.unify(&Type::Choice).is_some());
    if !fits {
        return Err(AppError::Validation(format!(
            "formula expression produces '{produced}' but result_type is '{}'",
            opts.result_type
        )));
    }
    Ok(compiled)
}

/// A9-T2: the formula fields `expression` (a formula on `entity` with
/// `attrs`) depends on through lookups: each path that ends at another
/// formula computed when read, as `(entity, field)`. A path ending at a
/// stored formula reads its stored value, which depends on nothing here.
fn formula_dependencies(
    expression: &str,
    attrs: &[AttrInfo],
    registry: &crate::EntityMetaRegistry,
) -> Vec<(String, String)> {
    formula_paths(expression, attrs, registry)
        .into_iter()
        .filter_map(|r| {
            let entity = r.entities.last()?.clone();
            let field = r.segments.last()?.clone();
            let target = registry
                .get(&entity)?
                .attrs
                .iter()
                .find(|a| a.logicalname == field)?;
            (target.is_formula() && is_read_time(target.options.as_ref()))
                .then_some((entity, field))
        })
        .collect()
}

/// A9-T2: the cycle saving `expression` as formula `entity.field` would
/// close among the formulas that read each other through lookups, as
/// `["a.f", "b.g", "a.f"]`; `None` when there is none. Every other formula
/// is read from `registry` as it is now. Pure.
pub fn formula_cycle(
    registry: &crate::EntityMetaRegistry,
    entity: &str,
    field: &str,
    expression: &str,
) -> Option<Vec<String>> {
    let start = (entity.to_owned(), field.to_owned());
    let attrs = registry.get(entity).map_or(&[][..], |m| m.attrs.as_slice());
    let mut path = vec![start.clone()];
    let mut seen = std::collections::BTreeSet::new();
    let found = walk_cycle(
        registry,
        &start,
        formula_dependencies(expression, attrs, registry),
        &mut path,
        &mut seen,
    );
    found.then(|| path.iter().map(|(e, f)| format!("{e}.{f}")).collect())
}

/// Depth-first from the node on top of `path` (whose dependencies are
/// `deps`); `true` with `path` ending at `start` again when a cycle closes.
fn walk_cycle(
    registry: &crate::EntityMetaRegistry,
    start: &(String, String),
    deps: Vec<(String, String)>,
    path: &mut Vec<(String, String)>,
    seen: &mut std::collections::BTreeSet<(String, String)>,
) -> bool {
    for dep in deps {
        if &dep == start {
            path.push(dep);
            return true;
        }
        if !seen.insert(dep.clone()) {
            continue;
        }
        let Some(meta) = registry.get(&dep.0) else {
            continue;
        };
        let Some(expression) = meta
            .attrs
            .iter()
            .find(|a| a.logicalname == dep.1)
            .and_then(|a| parse_options(a.options.as_ref()).ok())
            .map(|o| o.expression)
        else {
            continue;
        };
        let next = formula_dependencies(&expression, &meta.attrs, registry);
        path.push(dep);
        if walk_cycle(registry, start, next, path, seen) {
            return true;
        }
        path.pop();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta_registry::{DataClassification, OnTargetDelete};
    use serde_json::json;

    #[test]
    fn formula_time_based_sees_today_and_now_anywhere() {
        for expression in [
            "today()",
            "date_diff(today(), due_date)",
            "if(is_null(closed_on), date_diff(now(), opened_on), 0)",
            "-date_diff(today(), due_date)",
            "max(1, date_diff(today(), due_date))",
        ] {
            assert!(is_time_based(expression), "{expression}");
        }
        for expression in [
            "amount * 2",
            "date_diff(closed_on, opened_on)",
            "lower(name)",
            "today(",
            "",
        ] {
            assert!(!is_time_based(expression), "{expression}");
        }
    }

    /// A9-T1: `mode` defaults to stored, reads `read_time`, and cannot be
    /// combined with a generated column.
    #[test]
    fn formula_mode_defaults_to_stored_and_reads_read_time() {
        let stored = json!({"expression": "1", "result_type": "number"});
        assert_eq!(
            parse_options(Some(&stored)).unwrap().mode,
            FormulaMode::Stored
        );
        assert!(!is_read_time(Some(&stored)));
        let live = json!({"expression": "today()", "result_type": "date", "mode": "read_time"});
        assert_eq!(
            parse_options(Some(&live)).unwrap().mode,
            FormulaMode::ReadTime
        );
        assert!(is_read_time(Some(&live)));
        let both = json!({"expression": "1", "result_type": "number", "mode": "read_time", "generated": true});
        assert!(parse_options(Some(&both)).is_err());
        let unknown = json!({"expression": "1", "result_type": "number", "mode": "later"});
        assert!(parse_options(Some(&unknown)).is_err());
        // a stored formula serialises without a mode, as before
        let back = serde_json::to_value(parse_options(Some(&stored)).unwrap()).unwrap();
        assert!(back.get("mode").is_none());
    }

    fn attr(name: &str, type_int: i32, options: Option<Value>) -> AttrInfo {
        AttrInfo {
            logicalname: name.into(),
            field_type_int: type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: false,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::default(),
            data_classification: DataClassification::default(),
            sensitivity: Default::default(),
            sensitivity_confirmed: false,
            options,
        }
    }

    fn fields() -> Vec<AttrInfo> {
        vec![
            attr("quantity", 1, None),
            attr("unit_price", 2, None),
            attr("name", 3, None),
            attr("due", 5, None),
        ]
    }

    #[test]
    fn a_numeric_formula_compiles() {
        let opts = json!({"expression": "quantity * unit_price", "result_type": "number"});
        assert!(compile_formula(&fields(), Some(&opts)).is_ok());
    }

    #[test]
    fn missing_or_malformed_options_are_rejected() {
        assert!(compile_formula(&fields(), None).is_err());
        let empty = json!({"expression": "  ", "result_type": "number"});
        assert!(compile_formula(&fields(), Some(&empty)).is_err());
        let bad_type = json!({"expression": "quantity", "result_type": "lookup"});
        assert!(compile_formula(&fields(), Some(&bad_type)).is_err());
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let opts = json!({"expression": "nope * 2", "result_type": "number"});
        let err = compile_formula(&fields(), Some(&opts)).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");
    }

    #[test]
    fn a_type_mismatch_is_rejected() {
        let opts = json!({"expression": "quantity * 2", "result_type": "date"});
        assert!(compile_formula(&fields(), Some(&opts)).is_err());
    }

    #[test]
    fn a_formula_cannot_read_another_formula() {
        let mut attrs = fields();
        attrs.push(attr(
            "total",
            16,
            Some(json!({"expression": "quantity * unit_price", "result_type": "number"})),
        ));
        let opts = json!({"expression": "total * 2", "result_type": "number"});
        assert!(compile_formula(&attrs, Some(&opts)).is_err());
    }

    #[test]
    fn translates_arithmetic_and_rejects_lookups() {
        let mut attrs = fields();
        attrs.push(attr("account", 11, None));
        assert_eq!(
            to_generated_sql("quantity * unit_price + 1", &attrs).as_deref(),
            Some(r#"(("quantity" * "unit_price") + 1::numeric)"#)
        );
        assert_eq!(
            to_generated_sql(r#"coalesce(name, "-") + "x""#, &attrs).as_deref(),
            Some(r#"(COALESCE("name", '-'::text) || 'x'::text)"#)
        );
        assert_eq!(
            to_generated_sql("-quantity", &attrs).as_deref(),
            Some(r#"(-"quantity")"#)
        );
        assert!(to_generated_sql("account.name", &attrs).is_none());
        assert!(to_generated_sql("account", &attrs).is_none());
        assert!(to_generated_sql("quantity / unit_price", &attrs).is_none());
        assert!(to_generated_sql("quantity + name", &attrs).is_none());
        assert!(to_generated_sql("due", &attrs).is_none());
        assert!(to_generated_sql("round(quantity, 2)", &attrs).is_none());
    }

    #[test]
    fn generated_sql_needs_the_flag_and_a_matching_type() {
        let attrs = fields();
        let plain = json!({"expression": "quantity + 1", "result_type": "number"});
        assert_eq!(generated_sql(&attrs, Some(&plain)).unwrap(), None);
        let on = json!({"expression": "quantity + 1", "result_type": "number", "generated": true});
        assert!(generated_sql(&attrs, Some(&on)).unwrap().is_some());
        let wrong = json!({"expression": "quantity + 1", "result_type": "text", "generated": true});
        assert!(generated_sql(&attrs, Some(&wrong)).is_err());
        let division =
            json!({"expression": "quantity / 2", "result_type": "number", "generated": true});
        assert!(generated_sql(&attrs, Some(&division)).is_err());
    }

    #[test]
    fn rich_text_reads_as_text_and_image_is_not_readable() {
        assert_eq!(rules_type(&FieldType::RichText), Some(Type::Text));
        assert_eq!(rules_type(&FieldType::Image), None);
        let formula = attr(
            "total",
            16,
            Some(json!({"expression": "1", "result_type": "number"})),
        );
        assert_eq!(attr_rules_type(&formula), Some(Type::Number));
    }

    // ── A9-T2: reading through lookups ──────────────────────────────────────

    fn lookup(name: &str, target: uuid::Uuid) -> AttrInfo {
        let mut a = attr(name, 11, None);
        a.lookup_entity_ref = Some(target);
        a
    }

    fn formula(name: &str, expression: &str, read_time: bool) -> AttrInfo {
        let mut options = json!({"expression": expression, "result_type": "text"});
        if read_time {
            options["mode"] = json!("read_time");
        }
        attr(name, 16, Some(options))
    }

    fn meta(id: uuid::Uuid, name: &str, attrs: Vec<AttrInfo>) -> crate::EntityMeta {
        crate::EntityMeta {
            entity_id: id,
            logicalname: name.to_owned(),
            attrs,
            is_append_only: false,
            primary_name_attribute: None,
        }
    }

    /// contact -> account -> owner (user) -> manager (user) -> region.
    fn people() -> (crate::EntityMetaRegistry, Vec<AttrInfo>) {
        let user = uuid::Uuid::now_v7();
        let account = uuid::Uuid::now_v7();
        let registry = crate::EntityMetaRegistry::from_entities(vec![
            meta(
                user,
                "app_user",
                vec![attr("region", 0, None), lookup("manager", user)],
            ),
            meta(
                account,
                "account",
                vec![attr("name", 0, None), lookup("owner", user)],
            ),
        ]);
        (
            registry,
            vec![attr("name", 0, None), lookup("account", account)],
        )
    }

    #[test]
    fn formula_cross_entity_paths_compile_only_when_read() {
        let (registry, contact) = people();
        let live = json!({"expression": "account.owner.manager.region", "result_type": "text", "mode": "read_time"});
        assert!(compile_formula_in(&contact, Some(&live), Some(&registry)).is_ok());
        assert!(reads_through_lookup("account.owner.manager.region"));
        assert!(reads_through_lookup("account.name"));
        assert!(!reads_through_lookup("upper(name)"));
        // Without the other entities nothing resolves.
        assert!(compile_formula_in(&contact, Some(&live), None).is_err());
        // A stored formula would never be recomputed when the account changes.
        let stored = json!({"expression": "account.name", "result_type": "text"});
        let err = compile_formula_in(&contact, Some(&stored), Some(&registry)).unwrap_err();
        assert!(err.to_string().contains("read_time"), "{err}");
    }

    #[test]
    fn formula_cross_entity_follows_at_most_five_lookups() {
        let user = uuid::Uuid::now_v7();
        let registry = crate::EntityMetaRegistry::from_entities(vec![meta(
            user,
            "app_user",
            vec![attr("region", 0, None), lookup("manager", user)],
        )]);
        let me = vec![lookup("manager", user)];
        let five = json!({"expression": "manager.manager.manager.manager.manager.region", "result_type": "text", "mode": "read_time"});
        assert!(compile_formula_in(&me, Some(&five), Some(&registry)).is_ok());
        let six = json!({"expression": "manager.manager.manager.manager.manager.manager.region", "result_type": "text", "mode": "read_time"});
        assert!(compile_formula_in(&me, Some(&six), Some(&registry)).is_err());
    }

    #[test]
    fn formula_cross_entity_cycle_is_refused_naming_the_path() {
        let a = uuid::Uuid::now_v7();
        let b = uuid::Uuid::now_v7();
        let registry = crate::EntityMetaRegistry::from_entities(vec![
            meta(
                a,
                "ent_a",
                vec![lookup("b_ref", b), formula("f", "b_ref.g", true)],
            ),
            meta(
                b,
                "ent_b",
                vec![lookup("a_ref", a), formula("g", "a_ref.f", true)],
            ),
        ]);
        assert_eq!(
            formula_cycle(&registry, "ent_a", "f", "b_ref.g"),
            Some(vec![
                "ent_a.f".to_owned(),
                "ent_b.g".to_owned(),
                "ent_a.f".to_owned()
            ])
        );
        // Wrapping the path in a function still reads it; a constant reads nothing.
        assert_eq!(
            formula_cycle(&registry, "ent_a", "f", "upper(b_ref.g)"),
            formula_cycle(&registry, "ent_a", "f", "b_ref.g")
        );
        assert_eq!(formula_cycle(&registry, "ent_a", "f", "\"x\""), None);
    }

    #[test]
    fn formula_cross_entity_stored_target_is_no_dependency() {
        let a = uuid::Uuid::now_v7();
        let b = uuid::Uuid::now_v7();
        // g is stored: reading it reads its column, which depends on nothing.
        let registry = crate::EntityMetaRegistry::from_entities(vec![
            meta(
                a,
                "ent_a",
                vec![lookup("b_ref", b), formula("f", "b_ref.g", true)],
            ),
            meta(
                b,
                "ent_b",
                vec![
                    lookup("a_ref", a),
                    attr("label", 0, None),
                    formula("g", "upper(label)", false),
                ],
            ),
        ]);
        assert_eq!(formula_cycle(&registry, "ent_a", "f", "b_ref.g"), None);
        // A self-lookup to the same formula is a cycle too (a parent chain
        // could loop in the data).
        let p = uuid::Uuid::now_v7();
        let tree = crate::EntityMetaRegistry::from_entities(vec![meta(
            p,
            "node",
            vec![lookup("parent", p), formula("path", "parent.path", true)],
        )]);
        assert_eq!(
            formula_cycle(&tree, "node", "path", "parent.path"),
            Some(vec!["node.path".to_owned(), "node.path".to_owned()])
        );
    }
}
