//! A30-T2: environment variables in expressions, read as `env.<name>`.
//!
//! An `environment_variable` definition (A30-T1) travels with the
//! configuration; its value is set on each deployment. An expression reads
//! one as `env.erp_url`, typed from the definition and valued from this
//! deployment's setting (or the definition's default). The caller resolves
//! both before compiling and evaluating, as with every other input
//! ([`crate::Context`] is a bag of resolved data): [`Schema::with_env`] and
//! [`Context::with_env`] put the variables in place, and [`check`] is the
//! publish-time test that every variable an expression names exists, may be
//! read, and has a value here.
//!
//! A `secret` variable is never readable by an expression: its value would
//! reach traces, previews and results. It is refused as unreadable.

use std::collections::{BTreeSet, HashMap};

use crate::ast::Expr;
use crate::context::{Context, Schema};
use crate::value::{Type, Value};

/// The name expressions read variables under.
pub const ENV: &str = "env";

/// One variable as the caller resolved it on this deployment.
#[derive(Debug, Clone, PartialEq)]
pub struct EnvVar {
    pub name: String,
    /// The definition's `type`: `text`, `number`, `boolean`, `url` or `secret`.
    pub value_type: String,
    pub required: bool,
    /// This deployment's value, else the definition's default, as an
    /// expression value; `None` when neither is set.
    pub value: Option<Value>,
}

/// Why an expression's variables cannot be published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvIssue {
    /// No variable has this name.
    Unknown(String),
    /// A `secret` variable, which expressions may not read.
    Unreadable(String),
    /// A required variable with no value on this deployment.
    MissingValue(String),
}

impl std::fmt::Display for EnvIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(name) => write!(f, "env.{name} is not a defined environment variable"),
            Self::Unreadable(name) => {
                write!(f, "env.{name} is a secret, which an expression cannot read")
            }
            Self::MissingValue(name) => write!(
                f,
                "env.{name} is required and has no value on this deployment"
            ),
        }
    }
}

/// The expression type of a variable type; `None` for a secret.
pub fn expression_type(value_type: &str) -> Option<Type> {
    match value_type {
        "text" | "url" => Some(Type::Text),
        "number" => Some(Type::Number),
        "boolean" => Some(Type::Bool),
        _ => None,
    }
}

/// The variable names `expr` reads (`env.<name>`), sorted.
pub fn references(expr: &Expr) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect(expr, &mut out);
    out
}

fn collect(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        Expr::FieldRef(r) if r.base == ENV => {
            if let Some(name) = &r.hop {
                out.insert(name.clone());
            }
        }
        Expr::ListLit(items) => items.iter().for_each(|i| collect(i, out)),
        Expr::Unary { expr, .. } => collect(expr, out),
        Expr::Binary { lhs, rhs, .. } => {
            collect(lhs, out);
            collect(rhs, out);
        }
        Expr::Call { args, .. } => args.iter().for_each(|a| collect(a, out)),
        Expr::Lambda { param, body } if param != ENV => collect(body, out),
        _ => {}
    }
}

/// The publish check: every variable `expr` reads is defined in `vars`, is
/// not a secret, and has a value when it is required. All issues, sorted by
/// name.
pub fn check(expr: &Expr, vars: &[EnvVar]) -> Result<(), Vec<EnvIssue>> {
    let issues: Vec<EnvIssue> = references(expr)
        .into_iter()
        .filter_map(|name| match vars.iter().find(|v| v.name == name) {
            None => Some(EnvIssue::Unknown(name)),
            Some(v) if expression_type(&v.value_type).is_none() => Some(EnvIssue::Unreadable(name)),
            Some(v) if v.required && matches!(v.value, None | Some(Value::Null)) => {
                Some(EnvIssue::MissingValue(name))
            }
            Some(_) => None,
        })
        .collect();
    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

impl Schema {
    /// A30-T2: lets expressions read `vars` as `env.<name>`. A secret is left
    /// out, so reading one fails to compile as an unknown field. An entity
    /// whose own lookup is named `env` keeps it: the variables are not added.
    #[must_use]
    pub fn with_env(self, vars: &[EnvVar]) -> Self {
        if self.has_related(ENV) || self.field_type(ENV).is_some() {
            return self;
        }
        let types: HashMap<String, Type> = vars
            .iter()
            .filter_map(|v| Some((v.name.clone(), expression_type(&v.value_type)?)))
            .collect();
        self.with_related(ENV, types)
    }
}

impl Context {
    /// A30-T2: the values [`Schema::with_env`] declared; a variable with no
    /// value reads as null.
    #[must_use]
    pub fn with_env(self, vars: &[EnvVar]) -> Self {
        if self.has_related(ENV) || self.field(ENV).is_some() {
            return self;
        }
        let values: HashMap<String, Value> = vars
            .iter()
            .filter(|v| expression_type(&v.value_type).is_some())
            .map(|v| (v.name.clone(), v.value.clone().unwrap_or(Value::Null)))
            .collect();
        self.with_related(ENV, values)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;

    fn var(name: &str, value_type: &str, required: bool, value: Option<Value>) -> EnvVar {
        EnvVar {
            name: name.into(),
            value_type: value_type.into(),
            required,
            value,
        }
    }

    fn vars() -> Vec<EnvVar> {
        vec![
            var(
                "erp_url",
                "url",
                true,
                Some(Value::Text("https://erp.example.com".into())),
            ),
            var("limit", "number", false, Some(Value::Number(5000.0))),
            var("pilot", "boolean", false, None),
            var("token", "secret", true, Some(Value::Text("s3cret".into()))),
            var("region", "text", true, None),
        ]
    }

    #[test]
    fn env_lookup_reads_typed_values() {
        let vars = vars();
        let schema = Schema::new()
            .with_field("amount", Type::Number)
            .with_env(&vars);
        let ctx = Context::new(Utc::now())
            .with_field("amount", Value::Number(7000.0))
            .with_env(&vars);
        let rule = crate::compile(
            "amount > env.limit and startswith(env.erp_url, \"https://\")",
            &schema,
        )
        .expect("compiles");
        assert_eq!(rule.eval(&ctx).unwrap(), Value::Bool(true));
        let unset = crate::compile("is_null(env.pilot)", &schema).unwrap();
        assert_eq!(unset.eval(&ctx).unwrap(), Value::Bool(true));
    }

    #[test]
    fn env_lookup_never_reads_a_secret() {
        let vars = vars();
        let schema = Schema::new().with_env(&vars);
        assert!(crate::compile("env.token == \"x\"", &schema).is_err());
        let expr = crate::parse("env.token == \"x\"").unwrap();
        assert_eq!(
            check(&expr, &vars),
            Err(vec![EnvIssue::Unreadable("token".into())])
        );
    }

    #[test]
    fn env_lookup_publish_check_names_each_problem() {
        let vars = vars();
        let expr = crate::parse(
            "env.region == \"gcc\" or env.nope > 1 or env.limit > 0 or env.erp_url == \"\"",
        )
        .unwrap();
        assert_eq!(
            references(&expr).into_iter().collect::<Vec<_>>(),
            ["erp_url", "limit", "nope", "region"]
        );
        assert_eq!(
            check(&expr, &vars),
            Err(vec![
                EnvIssue::Unknown("nope".into()),
                EnvIssue::MissingValue("region".into()),
            ])
        );
        let fine = crate::parse("env.limit > 0 and is_null(env.pilot)").unwrap();
        assert_eq!(check(&fine, &vars), Ok(()));
    }

    #[test]
    fn env_lookup_yields_to_an_entity_lookup_named_env() {
        let schema = Schema::new()
            .with_related("env", HashMap::from([("code".to_owned(), Type::Text)]))
            .with_env(&vars());
        assert!(crate::compile("env.code == \"a\"", &schema).is_ok());
        assert!(crate::compile("env.limit > 1", &schema).is_err());
    }
}
