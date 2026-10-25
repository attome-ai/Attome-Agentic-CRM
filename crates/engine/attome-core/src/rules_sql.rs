//! Z11-T10: a rule expression as a bound SQL predicate, for the part of the
//! language whose SQL meaning is the same as the evaluator's. A saved view or
//! a sharing rule written as `amount > 100 and status == "open"` then runs
//! in the database: `("amount" > $1::numeric AND "status" IS NOT DISTINCT
//! FROM $2)`, every literal a bound parameter and every column a quoted name
//! from the entity's metadata.
//!
//! Translated: literals, plain fields of a single-valued column, `and`,
//! `or`, `not`, comparisons, `+ - * / %`, `in(...)`, `is_null`, `lower`,
//! `upper`, `contains`/`startswith`/`endswith` on text, and `if` as `CASE`.
//! Equality is the evaluator's, null-safe (`IS NOT DISTINCT FROM`); `+` of
//! two texts is `||`.
//!
//! Everything else is [`NotTranslatable`]: lookups and paths, lists outside
//! `in`, lambdas, user and list functions, the clock (`today`, `now`), and
//! the functions whose SQL meaning differs or needs a function the database
//! does not have: `trim` (Unicode whitespace), `normalize_ar`, `matches`,
//! the Hijri and working-day functions, currency and rounding.
//!
//! Where the evaluator refuses a null operand (`null > 1`, `null and x`) the
//! SQL predicate is NULL, so the row does not match: a filter's reading of
//! an evaluation error.

use std::collections::HashMap;

use attome_rules::{BinaryOp, Expr, UnaryOp};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{AttrInfo, FieldType, quote_ident};

/// One bound value.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlParam {
    Number(f64),
    Text(String),
    Bool(bool),
    Date(DateTime<Utc>),
    Uuid(Uuid),
    Null,
}

/// Why an expression stays in the evaluator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not translatable to SQL: {reason}")]
pub struct NotTranslatable {
    pub reason: String,
}

fn refuse<T>(reason: impl Into<String>) -> Result<T, NotTranslatable> {
    Err(NotTranslatable {
        reason: reason.into(),
    })
}

/// The SQL types the translation tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Number,
    Text,
    Bool,
    Date,
    Uuid,
    Null,
}

/// A translated sub-expression: its SQL, its type and, for a column, the
/// cast a bind compared with it needs.
struct Part {
    sql: String,
    ty: Ty,
    cast: &'static str,
    /// The literal text, when the part is a text literal (for `LIKE`).
    literal_text: Option<String>,
}

struct Translator<'a> {
    attrs: &'a HashMap<String, AttrInfo>,
    params: Vec<SqlParam>,
    first: usize,
}

/// `expr` as a predicate (or value) with its parameters, numbered from
/// `first_param` (`$first_param`, `$first_param + 1`, ...).
pub fn to_sql(
    expr: &Expr,
    attrs: &HashMap<String, AttrInfo>,
    first_param: usize,
) -> Result<(String, Vec<SqlParam>), NotTranslatable> {
    let mut t = Translator {
        attrs,
        params: Vec::new(),
        first: first_param.max(1),
    };
    let part = t.part(expr)?;
    Ok((part.sql, t.params))
}

/// Whether `expr` translates against `attrs`, for the editor to tell a
/// builder which rules run in the database.
pub fn translatable(expr: &Expr, attrs: &HashMap<String, AttrInfo>) -> Result<(), NotTranslatable> {
    to_sql(expr, attrs, 1).map(|_| ())
}

impl Translator<'_> {
    fn bind(&mut self, value: SqlParam) -> String {
        self.params.push(value);
        format!("${}", self.first + self.params.len() - 1)
    }

    fn part(&mut self, expr: &Expr) -> Result<Part, NotTranslatable> {
        match expr {
            Expr::NullLit => Ok(Part {
                sql: "NULL".to_owned(),
                ty: Ty::Null,
                cast: "",
                literal_text: None,
            }),
            Expr::BoolLit(b) => {
                let sql = format!("{}::boolean", self.bind(SqlParam::Bool(*b)));
                Ok(Part {
                    sql,
                    ty: Ty::Bool,
                    cast: "",
                    literal_text: None,
                })
            }
            Expr::NumberLit(n) => {
                let sql = format!("{}::numeric", self.bind(SqlParam::Number(*n)));
                Ok(Part {
                    sql,
                    ty: Ty::Number,
                    cast: "",
                    literal_text: None,
                })
            }
            // A text literal's cast is decided by what it is compared with
            // (`literal_text` keeps it until then).
            Expr::StringLit(s) => Ok(Part {
                sql: String::new(),
                ty: Ty::Text,
                cast: "",
                literal_text: Some(s.clone()),
            }),
            Expr::FieldRef(field) => {
                if field.hop.is_some() {
                    return refuse(format!(
                        "{}.{} reads a related record",
                        field.base,
                        field.hop.as_deref().unwrap_or_default()
                    ));
                }
                self.column(&field.base)
            }
            Expr::Path(segments) => refuse(format!("{} is a lookup path", segments.join("."))),
            Expr::ListLit(_) => refuse("a list outside in(...)"),
            Expr::Lambda { .. } => refuse("a lambda"),
            Expr::Unary { op, expr } => {
                let inner = self.part(expr)?;
                let inner = self.settle(inner, "");
                match op {
                    UnaryOp::Not => {
                        expect(&inner, Ty::Bool, "not")?;
                        Ok(value(format!("(NOT {})", inner.sql), Ty::Bool))
                    }
                    UnaryOp::Neg => {
                        expect(&inner, Ty::Number, "-")?;
                        Ok(value(format!("(-{})", inner.sql), Ty::Number))
                    }
                }
            }
            Expr::Binary { op, lhs, rhs } => self.binary(*op, lhs, rhs),
            Expr::Call { name, args } => self.call(name, args),
        }
    }

    fn column(&self, name: &str) -> Result<Part, NotTranslatable> {
        let Some(attr) = self.attrs.get(name) else {
            return refuse(format!("{name} is not a column of this entity"));
        };
        let storage = attr.storage_type();
        if attr
            .options
            .as_ref()
            .is_some_and(|o| storage.is_multi_valued(o))
        {
            return refuse(format!("{name} holds several values"));
        }
        let ty = match storage {
            FieldType::Number | FieldType::Currency => Ty::Number,
            FieldType::Bool => Ty::Bool,
            FieldType::Date | FieldType::DateTime => Ty::Date,
            FieldType::Lookup => Ty::Uuid,
            FieldType::Text
            | FieldType::Choice
            | FieldType::Icon
            | FieldType::Color
            | FieldType::RichText => Ty::Text,
            FieldType::File | FieldType::Image | FieldType::Formula | FieldType::Time => {
                return refuse(format!("{name} is not a comparable column"));
            }
        };
        Ok(Part {
            sql: quote_ident(name),
            ty,
            cast: storage.sql_cast(false),
            literal_text: None,
        })
    }

    /// A pending text literal becomes a bind, cast to `cast` (the column it
    /// meets) when it has one.
    fn settle(&mut self, part: Part, cast: &'static str) -> Part {
        match part.literal_text {
            Some(text) if part.sql.is_empty() => {
                let ty = match cast {
                    "::numeric" => Ty::Number,
                    "::timestamptz" => Ty::Date,
                    "::boolean" => Ty::Bool,
                    "::uuid" => Ty::Uuid,
                    _ => Ty::Text,
                };
                let sql = match Uuid::parse_str(&text) {
                    Ok(id) if ty == Ty::Uuid => self.bind(SqlParam::Uuid(id)),
                    _ => format!("{}{cast}", self.bind(SqlParam::Text(text.clone()))),
                };
                Part {
                    sql,
                    ty,
                    cast: "",
                    literal_text: Some(text),
                }
            }
            _ => part,
        }
    }

    /// Both sides, a text literal cast to the column on the other side.
    fn pair(&mut self, lhs: &Expr, rhs: &Expr) -> Result<(Part, Part), NotTranslatable> {
        let l = self.part(lhs)?;
        let r = self.part(rhs)?;
        let (lc, rc) = (l.cast, r.cast);
        let l = self.settle(l, rc);
        let r = self.settle(r, lc);
        Ok((l, r))
    }

    fn binary(&mut self, op: BinaryOp, lhs: &Expr, rhs: &Expr) -> Result<Part, NotTranslatable> {
        let (l, r) = self.pair(lhs, rhs)?;
        let both = |ty: Ty| l.ty == ty && r.ty == ty;
        let sql = match op {
            BinaryOp::And | BinaryOp::Or => {
                expect(&l, Ty::Bool, "and/or")?;
                expect(&r, Ty::Bool, "and/or")?;
                let word = if op == BinaryOp::And { "AND" } else { "OR" };
                return Ok(value(format!("({} {word} {})", l.sql, r.sql), Ty::Bool));
            }
            BinaryOp::Eq => format!("({} IS NOT DISTINCT FROM {})", l.sql, r.sql),
            BinaryOp::Ne => format!("({} IS DISTINCT FROM {})", l.sql, r.sql),
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                if !(both(Ty::Number) || both(Ty::Text) || both(Ty::Date)) {
                    return refuse("an ordering of mixed or unordered types");
                }
                let sym = match op {
                    BinaryOp::Lt => "<",
                    BinaryOp::Le => "<=",
                    BinaryOp::Gt => ">",
                    _ => ">=",
                };
                format!("({} {sym} {})", l.sql, r.sql)
            }
            BinaryOp::Add if both(Ty::Text) => {
                return Ok(value(format!("({} || {})", l.sql, r.sql), Ty::Text));
            }
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                if !both(Ty::Number) {
                    return refuse("arithmetic on something that is not a number");
                }
                let sym = match op {
                    BinaryOp::Add => "+",
                    BinaryOp::Sub => "-",
                    BinaryOp::Mul => "*",
                    BinaryOp::Div => "/",
                    _ => "%",
                };
                return Ok(value(format!("({} {sym} {})", l.sql, r.sql), Ty::Number));
            }
        };
        Ok(value(sql, Ty::Bool))
    }

    fn call(&mut self, name: &str, args: &[Expr]) -> Result<Part, NotTranslatable> {
        match (name, args) {
            ("is_null", [x]) => {
                let x = self.part(x)?;
                let x = self.settle(x, "");
                Ok(value(format!("({} IS NULL)", x.sql), Ty::Bool))
            }
            ("lower" | "upper", [x]) => {
                let x = self.part(x)?;
                let x = self.settle(x, "");
                expect(&x, Ty::Text, name)?;
                Ok(value(format!("{name}({})", x.sql), Ty::Text))
            }
            ("contains" | "startswith" | "endswith", [hay, needle]) => {
                let hay = self.part(hay)?;
                let hay = self.settle(hay, "");
                expect(&hay, Ty::Text, name)?;
                let needle = self.part(needle)?;
                if let (Some(text), true) = (&needle.literal_text, needle.sql.is_empty()) {
                    let escaped = like_escape(text);
                    let pattern = match name {
                        "contains" => format!("%{escaped}%"),
                        "startswith" => format!("{escaped}%"),
                        _ => format!("%{escaped}"),
                    };
                    let p = self.bind(SqlParam::Text(pattern));
                    return Ok(value(
                        format!("({} LIKE {p} ESCAPE '\\')", hay.sql),
                        Ty::Bool,
                    ));
                }
                let needle = self.settle(needle, "");
                expect(&needle, Ty::Text, name)?;
                let sql = match name {
                    "contains" => format!("(strpos({}, {}) > 0)", hay.sql, needle.sql),
                    "startswith" => format!("starts_with({}, {})", hay.sql, needle.sql),
                    _ => format!(
                        "(right({h}, length({n})) = {n})",
                        h = hay.sql,
                        n = needle.sql
                    ),
                };
                Ok(value(sql, Ty::Bool))
            }
            ("in", [needle, rest @ ..]) if !rest.is_empty() => {
                let items: Vec<&Expr> = match rest {
                    [Expr::ListLit(items)] => items.iter().collect(),
                    _ => rest.iter().collect(),
                };
                if items.is_empty() {
                    return Ok(value("false".to_owned(), Ty::Bool));
                }
                let n = self.part(needle)?;
                let cast = n.cast;
                let n = self.settle(n, "");
                let mut terms = Vec::with_capacity(items.len());
                for item in items {
                    let i = self.part(item)?;
                    let i = self.settle(i, cast);
                    terms.push(format!("{} IS NOT DISTINCT FROM {}", n.sql, i.sql));
                }
                Ok(value(format!("({})", terms.join(" OR ")), Ty::Bool))
            }
            ("if", [cond, then, otherwise]) => {
                let c = self.part(cond)?;
                expect(&c, Ty::Bool, "if")?;
                let (a, b) = self.pair(then, otherwise)?;
                let ty = if a.ty == Ty::Null { b.ty } else { a.ty };
                Ok(value(
                    format!("(CASE WHEN {} THEN {} ELSE {} END)", c.sql, a.sql, b.sql),
                    ty,
                ))
            }
            (other, _) => refuse(format!("{other}() has no SQL translation")),
        }
    }
}

fn value(sql: String, ty: Ty) -> Part {
    Part {
        sql,
        ty,
        cast: "",
        literal_text: None,
    }
}

fn expect(part: &Part, ty: Ty, what: &str) -> Result<(), NotTranslatable> {
    if part.ty == ty || part.ty == Ty::Null {
        Ok(())
    } else {
        refuse(format!("{what} on a {:?}, not a {ty:?}", part.ty))
    }
}

/// `text` with `\`, `%` and `_` escaped for `LIKE ... ESCAPE '\'`.
fn like_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DataClassification, OnTargetDelete};

    fn attr(name: &str, ty: FieldType) -> (String, AttrInfo) {
        let field_type_int = crate::FieldType::to_int(&ty);
        (
            name.to_owned(),
            AttrInfo {
                logicalname: name.to_owned(),
                field_type_int,
                is_required: false,
                max_length: None,
                is_sensitive: false,
                is_write_restricted: false,
                is_sortable: true,
                is_filterable: true,
                lookup_entity_ref: None,
                on_target_delete: OnTargetDelete::default(),
                data_classification: DataClassification::default(),
                options: None,
            },
        )
    }

    fn attrs() -> HashMap<String, AttrInfo> {
        HashMap::from([
            attr("amount", FieldType::Number),
            attr("status", FieldType::Choice),
            attr("name", FieldType::Text),
            attr("owner_ref", FieldType::Lookup),
            attr("opened", FieldType::Date),
        ])
    }

    fn sql(src: &str) -> Result<(String, Vec<SqlParam>), NotTranslatable> {
        let expr = attome_rules::parse(src).unwrap();
        to_sql(&expr, &attrs(), 1)
    }

    #[test]
    fn translates_comparison_with_bind() {
        let (text, params) = sql("amount > 100 and status == \"open\"").unwrap();
        assert_eq!(
            text,
            "((\"amount\" > $1::numeric) AND (\"status\" IS NOT DISTINCT FROM $2))"
        );
        assert_eq!(
            params,
            vec![SqlParam::Number(100.0), SqlParam::Text("open".into())]
        );
        let (text, _) = sql("in(status, [\"a\", \"b\"]) or is_null(name)").unwrap();
        assert_eq!(
            text,
            "((\"status\" IS NOT DISTINCT FROM $1 OR \"status\" IS NOT DISTINCT FROM $2) OR (\"name\" IS NULL))"
        );
        let (text, params) = sql("owner_ref == \"0190a8b4-0000-7000-8000-000000000001\"").unwrap();
        assert_eq!(text, "(\"owner_ref\" IS NOT DISTINCT FROM $1)");
        assert!(matches!(params[0], SqlParam::Uuid(_)));
        let (text, _) = sql("if(amount > 1, name, \"x\") == lower(name)").unwrap();
        assert!(text.starts_with("((CASE WHEN"), "{text}");
    }

    #[test]
    fn quotes_column_names() {
        let expr = attome_rules::parse("amount > 1").unwrap();
        let (text, _) = to_sql(&expr, &attrs(), 3).unwrap();
        assert_eq!(text, "(\"amount\" > $3::numeric)");
        assert!(sql("missing > 1").is_err());
    }

    #[test]
    fn rejects_hijri_function() {
        for src in [
            "hijri_year(opened) > 1440",
            "normalize_ar(name) == \"x\"",
            "trim(name) == \"x\"",
            "today() > opened",
            "owner_ref.name == \"x\"",
        ] {
            assert!(sql(src).is_err(), "{src}");
        }
        assert!(translatable(&attome_rules::parse("amount + 1 > 2").unwrap(), &attrs()).is_ok());
    }

    #[test]
    fn like_escapes_percent() {
        let (text, params) = sql("contains(name, \"50%_off\\\\\")").unwrap();
        assert_eq!(text, "(\"name\" LIKE $1 ESCAPE '\\')");
        assert_eq!(params, vec![SqlParam::Text("%50\\%\\_off\\\\%".into())]);
        let (text, _) = sql("startswith(name, lower(name))").unwrap();
        assert_eq!(text, "starts_with(\"name\", lower(\"name\"))");
    }
}
