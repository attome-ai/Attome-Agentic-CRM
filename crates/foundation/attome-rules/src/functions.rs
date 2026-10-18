//! User-defined functions (roadmap Z11-T8): typed, pure and non-recursive.
//!
//! A [`UserFunction`] is a V2 expression over its own parameters, nothing
//! else: no record fields, no related records, no clock beyond the caller's.
//! [`FunctionLibrary::build`] checks the names, compiles every body once in
//! dependency order (a body may call built-ins and functions it does not
//! depend on through itself) and refuses a cycle, direct or mutual, with
//! `rules.function.recursive`. [`compile_with_library`] compiles a rule that
//! may call them; a call type-checks its arguments against the parameters,
//! and its body's steps are charged to the calling rule's budget.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::{
    Budgets, Compiled, Expr, LanguageVersion, RulesError, Schema, Type, compile_versioned,
};

/// The most functions a library may hold.
pub const MAX_FUNCTIONS: usize = 200;
/// The most parameters one function may take.
pub const MAX_PARAMS: usize = 8;

/// One function as a builder writes it.
#[derive(Debug, Clone, PartialEq)]
pub struct UserFunction {
    pub name: String,
    pub params: Vec<(String, Type)>,
    pub returns: Type,
    /// A V2 expression over `params`.
    pub body: String,
}

/// A compiled function.
#[derive(Debug, Clone)]
pub(crate) struct CompiledFunction {
    pub(crate) params: Vec<(String, Type)>,
    pub(crate) returns: Type,
    pub(crate) body: Compiled,
}

/// Every function of a deployment, compiled.
#[derive(Debug, Clone, Default)]
pub struct FunctionLibrary {
    functions: BTreeMap<String, Arc<CompiledFunction>>,
}

/// `^[a-z][a-z0-9_]{0,62}$`.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Words of the grammar itself, which a call could otherwise shadow.
const RESERVED: &[&str] = &["and", "or", "not", "true", "false", "null", "it"];

/// Whether `name` already means something in the language: a built-in
/// function, or a word the grammar reserves. Built-ins are asked of the
/// compiler itself, so the answer cannot drift from the list of built-ins.
fn is_builtin(name: &str, budgets: Budgets) -> bool {
    RESERVED.contains(&name)
        || !matches!(
            compile_versioned(
                &format!("{name}()"),
                &Schema::new(),
                LanguageVersion::V2,
                budgets
            ),
            Err(RulesError::UnknownFunction(_))
        )
}

/// The user functions `expr` calls, by name.
fn calls(expr: &Expr, names: &BTreeSet<&str>, out: &mut BTreeSet<String>) {
    match expr {
        Expr::Call { name, args } => {
            if names.contains(name.as_str()) {
                out.insert(name.clone());
            }
            for arg in args {
                calls(arg, names, out);
            }
        }
        Expr::Unary { expr, .. } => calls(expr, names, out),
        Expr::Binary { lhs, rhs, .. } => {
            calls(lhs, names, out);
            calls(rhs, names, out);
        }
        Expr::ListLit(items) => items.iter().for_each(|e| calls(e, names, out)),
        _ => {}
    }
}

impl FunctionLibrary {
    /// Checks and compiles `functions` (see the module doc).
    pub fn build(functions: Vec<UserFunction>, budgets: Budgets) -> Result<Self, RulesError> {
        if functions.len() > MAX_FUNCTIONS {
            return Err(RulesError::InvalidFunction(format!(
                "a library holds at most {MAX_FUNCTIONS} functions"
            )));
        }
        let mut by_name: BTreeMap<&str, &UserFunction> = BTreeMap::new();
        for f in &functions {
            if !valid_name(&f.name) {
                return Err(RulesError::InvalidFunction(format!(
                    "{:?} is not a function name (a lowercase letter, then letters, digits or _)",
                    f.name
                )));
            }
            if is_builtin(&f.name, budgets) {
                return Err(RulesError::InvalidFunction(format!(
                    "{} is a built-in name",
                    f.name
                )));
            }
            if f.params.len() > MAX_PARAMS {
                return Err(RulesError::InvalidFunction(format!(
                    "{} takes at most {MAX_PARAMS} parameters",
                    f.name
                )));
            }
            if by_name.insert(&f.name, f).is_some() {
                return Err(RulesError::InvalidFunction(format!(
                    "{} is defined twice",
                    f.name
                )));
            }
        }
        // Who calls whom, from the parsed bodies.
        let names: BTreeSet<&str> = by_name.keys().copied().collect();
        let mut deps: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for (name, f) in &by_name {
            let body = crate::parse(&f.body)?;
            let mut found = BTreeSet::new();
            calls(&body, &names, &mut found);
            deps.insert(*name, found);
        }
        // Kahn's order; whatever never becomes ready sits on a cycle.
        let mut order: Vec<&str> = Vec::with_capacity(by_name.len());
        let mut placed: BTreeSet<&str> = BTreeSet::new();
        loop {
            let ready: Vec<&str> = deps
                .iter()
                .filter(|(name, needs)| {
                    !placed.contains(**name) && needs.iter().all(|n| placed.contains(n.as_str()))
                })
                .map(|(name, _)| *name)
                .collect();
            if ready.is_empty() {
                break;
            }
            for name in ready {
                placed.insert(name);
                order.push(name);
            }
        }
        if let Some(stuck) = deps.keys().find(|n| !placed.contains(**n)) {
            return Err(RulesError::Recursive((*stuck).to_owned()));
        }
        let mut library = FunctionLibrary::default();
        for name in order {
            let f = by_name[name];
            let mut schema = Schema::new();
            for (param, ty) in &f.params {
                schema = schema.with_field(param.clone(), ty.clone());
            }
            let schema = schema.with_functions(Arc::new(library.clone()));
            let body = compile_versioned(&f.body, &schema, LanguageVersion::V2, budgets)?;
            if body.result_type().unify(&f.returns).is_none() {
                return Err(RulesError::Type(format!(
                    "{} returns {} but its body is {}",
                    f.name,
                    f.returns,
                    body.result_type()
                )));
            }
            library.functions.insert(
                f.name.clone(),
                Arc::new(CompiledFunction {
                    params: f.params.clone(),
                    returns: f.returns.clone(),
                    body,
                }),
            );
        }
        Ok(library)
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Arc<CompiledFunction>> {
        self.functions.get(name)
    }

    /// The functions' names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.functions.keys().map(String::as_str)
    }
}

/// [`compile_versioned`] for a rule that may call `library`'s functions.
pub fn compile_with_library(
    src: &str,
    schema: &Schema,
    version: LanguageVersion,
    budgets: Budgets,
    library: &FunctionLibrary,
) -> Result<Compiled, RulesError> {
    let schema = schema.clone().with_functions(Arc::new(library.clone()));
    compile_versioned(src, &schema, version, budgets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_pattern() {
        assert!(valid_name("vat_of"));
        assert!(valid_name("a1"));
        assert!(!valid_name("1a"));
        assert!(!valid_name("Vat"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"a".repeat(64)));
    }

    #[test]
    fn builtins_are_known() {
        let budgets = Budgets::default();
        assert!(is_builtin("round", budgets));
        assert!(is_builtin("if", budgets));
        assert!(is_builtin("and", budgets), "a reserved word");
        assert!(!is_builtin("vat_of", budgets));
    }
}
