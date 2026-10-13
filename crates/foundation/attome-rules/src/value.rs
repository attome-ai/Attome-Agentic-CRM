//! The 7 platform field types + `List` (M45 plan §3.1), independent of
//! `xrm-foundation::FieldType` by construction — a `base-*` crate cannot name
//! an `xrm-*` type (the layer rule).
//! `FieldType::File` has no counterpart here:
//! rules do not operate on file content, so there is no `Value::File`.
//!
//! `Date` is `DateTime<Utc>` because the platform stores the `date` field
//! type as `TIMESTAMPTZ` (`xrm-entity/src/provision/table.rs`), not a
//! calendar date — `today()` is `now()` truncated to midnight UTC, not a
//! distinct type.

use std::fmt;

use chrono::{DateTime, Utc};
use uuid::Uuid;

/// A runtime value. Mirrors [`Type`] one-for-one.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    /// IEEE-754 double. A `Value::Number` is **always finite** (BRU-B1): the
    /// lexer rejects an overflowing literal (`1e999`) as
    /// `RulesError::NumericOverflow`, every arithmetic and `round` result is
    /// checked, and so is every `Number` arriving through `Context`. Division
    /// and modulo by zero are `RulesError::DivideByZero` rather than
    /// producing a non-finite value.
    Number(f64),
    Text(String),
    Date(DateTime<Utc>),
    /// A choice option's stable string key, not its display label — the
    /// same representation the entity engine stores.
    Choice(String),
    Lookup(Uuid),
    List(Vec<Value>),
}

impl Value {
    /// The [`Type`] this value belongs to. A `List`'s element type is the
    /// unified type of its elements (see [`Type::unify`]); an empty list has
    /// element type `Type::Null` ("unresolved" — unifies with anything).
    pub fn ty(&self) -> Type {
        match self {
            Value::Null => Type::Null,
            Value::Bool(_) => Type::Bool,
            Value::Number(_) => Type::Number,
            Value::Text(_) => Type::Text,
            Value::Date(_) => Type::Date,
            Value::Choice(_) => Type::Choice,
            Value::Lookup(_) => Type::Lookup,
            Value::List(items) => {
                let mut elem = Type::Null;
                for item in items {
                    match elem.unify(&item.ty()) {
                        Some(u) => elem = u,
                        None => return Type::List(Box::new(Type::Null)),
                    }
                }
                Type::List(Box::new(elem))
            }
        }
    }

    /// True for `Value::Null` only — `is_null(x)`'s implementation.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Number(n) => write!(f, "{n}"),
            Value::Text(s) => write!(f, "{s:?}"),
            Value::Date(d) => write!(f, "{}", d.to_rfc3339()),
            Value::Choice(c) => write!(f, "{c}"),
            Value::Lookup(id) => write!(f, "{id}"),
            Value::List(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
        }
    }
}

/// The 7 platform field types + `List<T>` (M45 plan §3.1): `Text | Number |
/// Date | Bool | Choice | Lookup | Null` are the 7, `List` is the 8th, list
/// wrapper. Deliberately excludes `xrm-foundation::FieldType::File` — rules
/// do not operate on file content (out of scope, plan §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    /// Unresolved / "no value yet" — unifies with any other type. Also the
    /// type of a bare `null` literal and of an empty list's element type.
    Null,
    Bool,
    Number,
    Text,
    Date,
    Choice,
    Lookup,
    List(Box<Type>),
}

impl Type {
    /// Two types unify when they're equal, or one of them is `Null`
    /// (`Null` is the "unknown/no value" type, compatible with anything —
    /// this is what lets `if(c, x, null)` and an empty list literal
    /// type-check against a concrete branch/element type). Returns the more
    /// specific of the two, or `None` if they're incompatible.
    pub fn unify(&self, other: &Type) -> Option<Type> {
        match (self, other) {
            (Type::Null, t) | (t, Type::Null) => Some(t.clone()),
            (Type::List(a), Type::List(b)) => a.unify(b).map(|u| Type::List(Box::new(u))),
            (a, b) if a == b => Some(a.clone()),
            _ => None,
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Null => write!(f, "null"),
            Type::Bool => write!(f, "bool"),
            Type::Number => write!(f, "number"),
            Type::Text => write!(f, "text"),
            Type::Date => write!(f, "date"),
            Type::Choice => write!(f, "choice"),
            Type::Lookup => write!(f, "lookup"),
            Type::List(t) => write!(f, "list<{t}>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unify_null_is_absorbing() {
        assert_eq!(Type::Null.unify(&Type::Number), Some(Type::Number));
        assert_eq!(Type::Text.unify(&Type::Null), Some(Type::Text));
        assert_eq!(Type::Null.unify(&Type::Null), Some(Type::Null));
    }

    #[test]
    fn unify_mismatched_types_reject() {
        assert_eq!(Type::Number.unify(&Type::Text), None);
    }

    #[test]
    fn unify_lists_recurse() {
        assert_eq!(
            Type::List(Box::new(Type::Null)).unify(&Type::List(Box::new(Type::Number))),
            Some(Type::List(Box::new(Type::Number)))
        );
        assert_eq!(
            Type::List(Box::new(Type::Number)).unify(&Type::List(Box::new(Type::Text))),
            None
        );
    }

    #[test]
    fn empty_list_value_type_is_null_element() {
        assert_eq!(Value::List(vec![]).ty(), Type::List(Box::new(Type::Null)));
    }

    #[test]
    fn homogeneous_list_value_type() {
        let v = Value::List(vec![Value::Number(1.0), Value::Null, Value::Number(2.0)]);
        assert_eq!(v.ty(), Type::List(Box::new(Type::Number)));
    }
}
