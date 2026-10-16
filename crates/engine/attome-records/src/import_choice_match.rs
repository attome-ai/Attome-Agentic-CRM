//! Imported text to allowed values (roadmap A6-T3). A spreadsheet rarely
//! spells a choice the way the field stores it: `Closed Won` for
//! `closed_won`, `إغلاق` typed without its hamza, `مُغلق` with diacritics.
//! Both sides are folded the same way before comparing: Arabic normalised
//! (`attome_rules::arabic::normalize_ar`: alef forms, alef maqsura, taa
//! marbuta, diacritics and tatweel), case folded, `_` and `-` read as
//! spaces, runs of space squashed. A value matches a choice when the folded
//! texts are equal, or when it equals the folded form of one of that
//! choice's labels. Text that matches nothing, or more than one choice, is
//! an error naming the text, so the import reports that row.
//!
//! A multi-select cell lists its values separated by `,`, `;`, `|` or the
//! Arabic comma.

use std::collections::HashMap;

use attome_rules::arabic::normalize_ar;

/// Why a cell did not map to an allowed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoiceMatchError {
    Unmatched(String),
    Ambiguous(String),
}

impl std::fmt::Display for ChoiceMatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmatched(text) => write!(f, "{text:?} is not one of the allowed values"),
            Self::Ambiguous(text) => write!(f, "{text:?} matches more than one allowed value"),
        }
    }
}

/// Folds text for comparison.
pub fn fold(text: &str) -> String {
    normalize_ar(text)
        .to_lowercase()
        .replace(['_', '-'], " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The allowed values of one field, folded once.
#[derive(Debug, Clone, Default)]
pub struct ChoiceMatcher {
    /// Folded text to the stored values it names.
    by_folded: HashMap<String, Vec<String>>,
}

impl ChoiceMatcher {
    /// `choices` are the stored values; `labels` are `(value, label)` pairs
    /// in any language.
    pub fn new(choices: &[String], labels: &[(String, String)]) -> Self {
        let mut by_folded: HashMap<String, Vec<String>> = HashMap::new();
        let mut add = |key: String, value: &String| {
            let entry = by_folded.entry(key).or_default();
            if !entry.contains(value) {
                entry.push(value.clone());
            }
        };
        for choice in choices {
            add(fold(choice), choice);
        }
        for (value, label) in labels {
            if choices.contains(value) {
                add(fold(label), value);
            }
        }
        by_folded.remove("");
        Self { by_folded }
    }

    /// The stored value `text` names.
    pub fn match_one(&self, text: &str) -> Result<&str, ChoiceMatchError> {
        match self.by_folded.get(&fold(text)).map(Vec::as_slice) {
            Some([value]) => Ok(value),
            Some([_, _, ..]) => Err(ChoiceMatchError::Ambiguous(text.to_owned())),
            _ => Err(ChoiceMatchError::Unmatched(text.to_owned())),
        }
    }

    /// The stored values a multi-select cell names, in order, without
    /// repeats.
    pub fn match_many(&self, text: &str) -> Result<Vec<String>, ChoiceMatchError> {
        let mut out: Vec<String> = Vec::new();
        for part in text.split([',', ';', '|', '\u{060C}']) {
            if part.trim().is_empty() {
                continue;
            }
            let value = self.match_one(part.trim())?.to_owned();
            if !out.contains(&value) {
                out.push(value);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod import_choice_match {
    use super::*;

    fn matcher() -> ChoiceMatcher {
        let choices = vec![
            "closed_won".to_owned(),
            "closed_lost".to_owned(),
            "open".to_owned(),
        ];
        let labels = vec![
            ("closed_won".to_owned(), "مغلقة - ربح".to_owned()),
            ("closed_lost".to_owned(), "مغلقة - خسارة".to_owned()),
            ("open".to_owned(), "مفتوحة".to_owned()),
        ];
        ChoiceMatcher::new(&choices, &labels)
    }

    #[test]
    fn english_spellings_match_the_stored_value() {
        let m = matcher();
        assert_eq!(m.match_one("Closed Won"), Ok("closed_won"));
        assert_eq!(m.match_one("  closed-lost "), Ok("closed_lost"));
        assert_eq!(m.match_one("OPEN"), Ok("open"));
    }

    #[test]
    fn arabic_variant_spellings_match_the_label() {
        let m = matcher();
        // Taa marbuta written as ha, diacritics and tatweel added.
        assert_eq!(m.match_one("مفتوحه"), Ok("open"));
        assert_eq!(m.match_one("مَفْتـوحَة"), Ok("open"));
        assert_eq!(m.match_one("مغلقه ربح"), Ok("closed_won"));
    }

    #[test]
    fn unmatched_and_ambiguous_text_is_reported() {
        let m = matcher();
        assert_eq!(
            m.match_one("pending"),
            Err(ChoiceMatchError::Unmatched("pending".into()))
        );
        let choices = vec!["a".to_owned(), "b".to_owned()];
        let labels = vec![
            ("a".to_owned(), "Same".to_owned()),
            ("b".to_owned(), "same".to_owned()),
        ];
        let m = ChoiceMatcher::new(&choices, &labels);
        assert_eq!(
            m.match_one("SAME"),
            Err(ChoiceMatchError::Ambiguous("SAME".into()))
        );
    }

    #[test]
    fn multi_select_cells_split_on_commas_including_arabic() {
        let m = matcher();
        assert_eq!(
            m.match_many("open، Closed Won; open"),
            Ok(vec!["open".to_owned(), "closed_won".to_owned()])
        );
        assert!(m.match_many("open, nope").is_err());
    }
}
