//! C10-T1: the business glossary in search, translation and agent context.
//!
//! Approved `glossary_term` records carry a term, its synonyms (separated
//! by commas, semicolons or Arabic commas), a definition and translations
//! (JSON, language code to rendering). From them:
//!
//! - **search** — a query naming a term or one of its synonyms also matches
//!   records that use the others ([`alternatives`], run as their own lexical
//!   leg so a synonym hit ranks a little below a literal one);
//! - **translation** — `text.translate` renders a term as its glossary
//!   translation ([`translations`]);
//! - **agents** — a turn whose question names a term gets the term's
//!   definition as data ([`definitions_in`]).

use std::collections::BTreeMap;

use attome_types::AppError;
use sqlx::PgPool;

use crate::lang::normalize_ar;

/// Most alternatives one query is widened with.
pub const MAX_ALTERNATIVES: usize = 6;
/// Most definitions one turn is given.
pub const MAX_DEFINITIONS: usize = 8;
/// Most approved terms read.
const MAX_TERMS: i64 = 2000;

/// One approved glossary term.
#[derive(Debug, Clone, Default, PartialEq, Eq, sqlx::FromRow)]
pub struct GlossaryTerm {
    pub term: String,
    pub definition: Option<String>,
    pub synonyms: Option<String>,
    pub translations: Option<String>,
}

/// The approved terms; none when the glossary is not installed.
pub async fn approved_terms(db: &PgPool) -> Result<Vec<GlossaryTerm>, AppError> {
    let installed: bool = sqlx::query_scalar("SELECT to_regclass('glossary_term') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    if !installed {
        return Ok(Vec::new());
    }
    sqlx::query_as(
        "SELECT term, definition, synonyms, translations FROM glossary_term \
          WHERE status = 'approved' AND (is_active IS NULL OR is_active = true) \
          ORDER BY term LIMIT $1",
    )
    .bind(MAX_TERMS)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// A term and its synonyms, as written. Pure.
pub fn members(term: &GlossaryTerm) -> Vec<String> {
    let mut out = vec![term.term.trim().to_owned()];
    out.extend(
        term.synonyms
            .as_deref()
            .unwrap_or_default()
            .split([',', ';', '،'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
    );
    out.retain(|m| !m.is_empty());
    out
}

fn folded(text: &str) -> String {
    normalize_ar(&text.to_lowercase())
}

/// Whether `phrase` occurs in `text` as whole words. Both already folded.
fn mentions(text: &str, phrase: &str) -> bool {
    !phrase.is_empty() && format!(" {text} ").contains(&format!(" {phrase} "))
}

/// The other words for what the query names: for every term whose name or
/// synonym the query contains, its remaining members, each once, at most
/// [`MAX_ALTERNATIVES`]. Pure.
pub fn alternatives(query: &str, terms: &[GlossaryTerm]) -> Vec<String> {
    let q = folded(query);
    let mut out: Vec<String> = Vec::new();
    for term in terms {
        let group = members(term);
        let hit = group.iter().any(|m| mentions(&q, &folded(m)));
        if !hit {
            continue;
        }
        for member in group {
            let f = folded(&member);
            if mentions(&q, &f) || out.iter().any(|o| folded(o) == f) {
                continue;
            }
            out.push(member);
            if out.len() == MAX_ALTERNATIVES {
                return out;
            }
        }
    }
    out
}

/// Term renderings by language, for translation: term → language → text.
/// Malformed translations are skipped. Pure.
pub fn translations(terms: &[GlossaryTerm]) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for term in terms {
        let Some(raw) = term.translations.as_deref() else {
            continue;
        };
        let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(raw)
        else {
            continue;
        };
        let renderings: BTreeMap<String, String> = map
            .into_iter()
            .filter_map(|(lang, v)| v.as_str().map(|s| (lang, s.trim().to_owned())))
            .filter(|(_, s)| !s.is_empty())
            .collect();
        if !renderings.is_empty() {
            out.insert(term.term.trim().to_owned(), renderings);
        }
    }
    out
}

/// The terms `text` names (by name or synonym) that have a definition, as
/// (term, definition), at most [`MAX_DEFINITIONS`]. Pure.
pub fn definitions_in(text: &str, terms: &[GlossaryTerm]) -> Vec<(String, String)> {
    let t = folded(text);
    terms
        .iter()
        .filter(|term| members(term).iter().any(|m| mentions(&t, &folded(m))))
        .filter_map(|term| {
            let definition = term.definition.as_deref()?.trim();
            (!definition.is_empty()).then(|| (term.term.trim().to_owned(), definition.to_owned()))
        })
        .take(MAX_DEFINITIONS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(name: &str, synonyms: &str, definition: &str, translations: &str) -> GlossaryTerm {
        GlossaryTerm {
            term: name.into(),
            definition: Some(definition.into()).filter(|d: &String| !d.is_empty()),
            synonyms: Some(synonyms.into()).filter(|s: &String| !s.is_empty()),
            translations: Some(translations.into()).filter(|t: &String| !t.is_empty()),
        }
    }

    #[test]
    fn glossary_widens_a_query_with_synonyms() {
        let terms = vec![
            term("Purchase Order", "PO; طلب شراء", "", ""),
            term("Invoice", "bill", "", ""),
        ];
        assert_eq!(
            alternatives("late PO from acme", &terms),
            vec!["Purchase Order", "طلب شراء"]
        );
        assert_eq!(
            alternatives("طلب شراء متأخر", &terms),
            vec!["Purchase Order", "PO"]
        );
        assert!(
            alternatives("purchase orders", &terms).is_empty(),
            "whole words only"
        );
        assert!(alternatives("acme", &terms).is_empty());
    }

    #[test]
    fn glossary_gives_translations_and_definitions() {
        let terms = vec![
            term(
                "Lead",
                "prospect",
                "Someone who may buy.",
                r#"{"ar": "عميل محتمل"}"#,
            ),
            term("Quote", "", "", "not json"),
        ];
        let tr = translations(&terms);
        assert_eq!(tr["Lead"]["ar"], "عميل محتمل");
        assert!(!tr.contains_key("Quote"));
        assert_eq!(
            definitions_in("Convert this prospect", &terms),
            vec![("Lead".to_owned(), "Someone who may buy.".to_owned())]
        );
        assert!(
            definitions_in("send the quote", &terms).is_empty(),
            "no definition, nothing given"
        );
    }
}
