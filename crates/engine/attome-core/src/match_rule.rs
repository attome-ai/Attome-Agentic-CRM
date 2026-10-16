//! A15: the duplicate-rule vocabulary two engines share: the background
//! sweep and scan (`attome-api`'s `duplicates_match`) and the check before
//! a record is saved (`attome-records`' `duplicate_check`). A rule
//! (`match_rule`) names fields, a comparator for each, weights and a
//! threshold; `on_save` says what a save that matches an existing record
//! does.

use std::future::Future;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::match_normalize as norm;

/// How one field of a rule compares two records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Comparator {
    Exact,
    Normalized,
    Trigram,
    /// Schema-accepted, never runnable: there is no per-field embedding
    /// source (search embeds its own corpus, not attribute values).
    Embedding,
    /// A15-T3: the international phone number.
    Phone,
    /// A15-T3: the lowercased email address.
    Email,
    /// A15-T3: an id without spaces, dashes or dots.
    Id,
    /// A15-T3: the name, titles dropped and word order ignored.
    Name,
    /// A15-T3: the transliteration skeleton (Arabic meets Latin).
    Phonetic,
}

impl Comparator {
    /// A15-T3: compared through stored keys in `match_key`.
    pub fn is_key(self) -> bool {
        matches!(
            self,
            Self::Phone | Self::Email | Self::Id | Self::Name | Self::Phonetic
        )
    }
}

/// One field of a match rule (`match_rule.fields`).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MatchField {
    pub field: String,
    pub comparator: Comparator,
    pub weight: f64,
    /// `trigram` only — the `pg_trgm` similarity floor a pair must clear to
    /// count as a match on this field (0.3 when absent).
    #[serde(default)]
    pub min_similarity: Option<f64>,
    /// The sweep first narrows the peers to rows that agree on this field
    /// (record-linkage blocking); absent on rules saved before it existed.
    #[serde(default)]
    pub is_blocking_key: bool,
    /// A15-T3: `phone` only — the country a local number (leading `0`)
    /// belongs to: `SA` or its calling code `966`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_country: Option<String>,
}

impl MatchField {
    /// A15-T3: this field's key for a value, for a key comparator.
    pub fn key_of(&self, value: &str) -> Option<String> {
        let non_empty = |s: String| (!s.is_empty()).then_some(s);
        match self.comparator {
            Comparator::Phone => {
                norm::phone_key(value, self.default_country.as_deref().unwrap_or(""))
            }
            Comparator::Email => norm::email_key(value),
            Comparator::Id => non_empty(norm::id_key(value)),
            Comparator::Name => non_empty(norm::name_key(value)),
            Comparator::Phonetic => non_empty(norm::translit_key(value)),
            _ => None,
        }
    }
}

/// A15-T8: a rule's fields are usable: at least one; each names a field the
/// entity has (`known`), with a positive weight, a runnable comparator
/// (not `embedding`), a phone field's `default_country`, and a trigram
/// floor between 0 and 1. Shared by the rule routes and the agent that
/// proposes rules.
pub fn validate_fields(
    known: &std::collections::HashSet<&str>,
    fields: &[MatchField],
) -> Result<(), attome_types::AppError> {
    use attome_types::AppError;
    if fields.is_empty() {
        return Err(AppError::Validation(
            "a match rule must specify at least one field".into(),
        ));
    }
    for f in fields {
        if f.comparator == Comparator::Embedding {
            return Err(AppError::Validation(format!(
                "field '{}': comparator 'embedding' is schema-accepted but not implemented yet \
                 — there is no per-field embedding source (attome-search's embeddings cover its own \
                 title/body search corpus, not arbitrary attribute values); use 'exact', \
                 'normalized', 'trigram', 'phone', 'email', 'id', 'name' or 'phonetic'",
                f.field
            )));
        }
        if !known.contains(f.field.as_str()) {
            return Err(AppError::Validation(format!(
                "field '{}' does not exist on this entity",
                f.field
            )));
        }
        if f.weight <= 0.0 {
            return Err(AppError::Validation(format!(
                "field '{}': weight must be positive",
                f.field
            )));
        }
        // A15-T3: a phone field names the country its local numbers belong
        // to, or it could never compare `05...` with `+9665...`.
        if f.comparator == Comparator::Phone
            && norm::phone_key("0500000000", f.default_country.as_deref().unwrap_or("")).is_none()
        {
            return Err(AppError::Validation(format!(
                "field '{}': a phone comparator needs default_country (such as SA or 966)",
                f.field
            )));
        }
        if let Some(m) = f.min_similarity
            && !(0.0..=1.0).contains(&m)
        {
            return Err(AppError::Validation(format!(
                "field '{}': min_similarity must be between 0 and 1",
                f.field
            )));
        }
    }
    Ok(())
}

/// A15-T4: what saving a record that matches an existing one does
/// (`match_rule.on_save`), ordered from the mildest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OnSave {
    Off,
    /// The save goes through and the response lists the matches.
    Warn,
    /// The save needs a reason (`Attome-Duplicate-Reason`), kept in the
    /// audit.
    AllowWithReason,
    /// The save is refused.
    Block,
}

impl OnSave {
    pub fn parse(raw: &str) -> Self {
        match raw {
            "warn" => Self::Warn,
            "allow_with_reason" => Self::AllowWithReason,
            "block" => Self::Block,
            _ => Self::Off,
        }
    }
}

/// A15-T4: a rule's score over the fields with evidence on both sides:
/// `Σ weight × matched / Σ weight`, the formula the sweep computes in SQL.
/// `None` when no field has evidence.
pub fn weighted_score(evidence: &[(f64, bool)]) -> Option<f64> {
    let total: f64 = evidence.iter().map(|(weight, _)| weight).sum();
    if evidence.is_empty() || total <= 0.0 {
        return None;
    }
    let matched: f64 = evidence
        .iter()
        .filter(|(_, matched)| *matched)
        .map(|(weight, _)| weight)
        .sum();
    Some(matched / total)
}

tokio::task_local! {
    /// A15-T4: the reason the caller gave for saving a likely duplicate.
    static DUPLICATE_REASON: Option<String>;
}

/// A15-T4: runs `f` with the reason the request gave for saving a likely
/// duplicate (its `Attome-Duplicate-Reason` header), read by the save path
/// through [`duplicate_reason`].
pub async fn with_duplicate_reason<F: Future>(reason: Option<String>, f: F) -> F::Output {
    DUPLICATE_REASON.scope(reason, f).await
}

tokio::task_local! {
    /// S1-T14: the request skips the write-time duplicate check.
    static DUPLICATE_SKIP: bool;
}

/// S1-T14: runs `f` with the write-time duplicate check skipped when `skip`
/// (the caller has checked the `duplicate.bypass` privilege).
pub async fn with_duplicate_skip<F: Future>(skip: bool, f: F) -> F::Output {
    DUPLICATE_SKIP.scope(skip, f).await
}

/// S1-T14: whether the write in scope skips the duplicate check.
pub fn duplicate_check_skipped() -> bool {
    DUPLICATE_SKIP.try_with(|skip| *skip).unwrap_or(false)
}

/// A15-T4: the reason in scope, if a request gave one.
pub fn duplicate_reason() -> Option<String> {
    DUPLICATE_REASON
        .try_with(Clone::clone)
        .ok()
        .flatten()
        .filter(|r| !r.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_score_over_fields_with_evidence() {
        assert_eq!(weighted_score(&[]), None);
        assert_eq!(weighted_score(&[(1.0, true)]), Some(1.0));
        assert_eq!(weighted_score(&[(3.0, true), (1.0, false)]), Some(0.75));
    }

    #[test]
    fn on_save_orders_from_mildest() {
        assert!(OnSave::Block > OnSave::AllowWithReason);
        assert!(OnSave::AllowWithReason > OnSave::Warn);
        assert_eq!(OnSave::parse("block"), OnSave::Block);
        assert_eq!(OnSave::parse("nonsense"), OnSave::Off);
    }

    #[tokio::test]
    async fn the_reason_is_read_inside_its_scope_only() {
        assert_eq!(duplicate_reason(), None);
        let inside = with_duplicate_reason(Some("same name, other person".into()), async {
            duplicate_reason()
        })
        .await;
        assert_eq!(inside.as_deref(), Some("same name, other person"));
    }
}
