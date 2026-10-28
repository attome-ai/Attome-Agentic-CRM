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

use attome_rules::{BinaryOp, Compiled, Expr, Schema, Type, UnaryOp, compile};
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::field_type::{FORMULA_RESULT_TYPES, FieldType};
use crate::meta_registry::AttrInfo;

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
    Ok(FormulaOptions {
        expression: expression.to_owned(),
        result_type: opts.result_type,
        generated: opts.generated,
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
        FieldType::Number | FieldType::Currency => Some(Type::Number),
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
    let opts = parse_options(options)?;
    let schema = formula_input_schema(attrs);
    let compiled = compile(&opts.expression, &schema)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meta_registry::{DataClassification, OnTargetDelete};
    use serde_json::json;

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
}
