//! Language versions (roadmap Z11-T1): a stored expression records the
//! version it was written in, so it keeps its meaning when the language
//! grows. A function added after V1 is accepted only from the version that
//! added it; compiling V1 text rejects it as an unknown function.

use crate::ast::Expr;
use crate::error::RulesError;

/// A version of the rule language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LanguageVersion {
    V1,
    V2,
}

impl LanguageVersion {
    pub const LATEST: Self = Self::V2;

    /// `v1` or `v2`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "v1" => Some(Self::V1),
            "v2" => Some(Self::V2),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        }
    }
}

/// Functions and the version that added them; anything not listed is V1.
const ADDED: &[(&str, LanguageVersion)] = &[
    ("endswith", LanguageVersion::V2),
    // Z11-T2: text and number functions.
    ("normalize_ar", LanguageVersion::V2),
    ("concat", LanguageVersion::V2),
    ("substr", LanguageVersion::V2),
    ("replace", LanguageVersion::V2),
    ("abs", LanguageVersion::V2),
    ("floor", LanguageVersion::V2),
    ("ceil", LanguageVersion::V2),
    ("power", LanguageVersion::V2),
    ("clamp", LanguageVersion::V2),
    // Z11-T5: currency functions.
    ("round_currency", LanguageVersion::V2),
    ("convert", LanguageVersion::V2),
    ("minor_units", LanguageVersion::V2),
    // Z11-T6: full-string pattern matching.
    ("matches", LanguageVersion::V2),
    // Z11-T3: list functions over related lists.
    ("sum", LanguageVersion::V2),
    ("count", LanguageVersion::V2),
    ("avg", LanguageVersion::V2),
    ("any", LanguageVersion::V2),
    ("all", LanguageVersion::V2),
    ("filter", LanguageVersion::V2),
    ("map", LanguageVersion::V2),
    ("first", LanguageVersion::V2),
    // Z11-T4: Hijri, zone and working-day functions.
    ("hijri_year", LanguageVersion::V2),
    ("hijri_month", LanguageVersion::V2),
    ("hijri_day", LanguageVersion::V2),
    ("hijri_date", LanguageVersion::V2),
    ("add_workdays", LanguageVersion::V2),
    ("workdays_between", LanguageVersion::V2),
    ("is_working", LanguageVersion::V2),
    ("to_zone", LanguageVersion::V2),
];

/// The version a function needs.
pub(crate) fn function_version(name: &str) -> LanguageVersion {
    ADDED
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(LanguageVersion::V1, |(_, v)| *v)
}

/// Refuses any call to a function newer than `version`.
pub(crate) fn check(expr: &Expr, version: LanguageVersion) -> Result<(), RulesError> {
    match expr {
        Expr::Call { name, args } => {
            if function_version(name) > version {
                return Err(RulesError::UnknownFunction(name.clone()));
            }
            args.iter().try_for_each(|a| check(a, version))
        }
        Expr::Unary { expr, .. } => check(expr, version),
        Expr::Binary { lhs, rhs, .. } => {
            check(lhs, version)?;
            check(rhs, version)
        }
        Expr::ListLit(items) => items.iter().try_for_each(|a| check(a, version)),
        Expr::Path(segments) => {
            if version < LanguageVersion::V2 {
                return Err(RulesError::MultiHopLookup(segments.join(".")));
            }
            Ok(())
        }
        Expr::Lambda { body, .. } => {
            if version < LanguageVersion::V2 {
                return Err(RulesError::UnknownFunction("=>".to_owned()));
            }
            check(body, version)
        }
        _ => Ok(()),
    }
}

/// Rewrites `src`, written in `from`, for `to`. No V1 construct changes
/// meaning in V2, so V1 text is V2 text unchanged once it parses.
pub fn upgrade(
    src: &str,
    from: LanguageVersion,
    to: LanguageVersion,
) -> Result<String, RulesError> {
    let expr = crate::parse(src)?;
    check(&expr, from)?;
    if to < from {
        check(&expr, to)?;
    }
    Ok(src.to_owned())
}
