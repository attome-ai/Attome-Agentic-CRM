//! Arabic normalization (TODO-009).
//!
//! **Why this is the first thing search builds.** F206 names Arabic as the
//! platform's moat, and Arabic search without normalization *looks like it
//! works*: a user types محمد, the record holds مُحَمَّد, and they get zero results
//! with no error and no signal that anything went wrong. There is no failing
//! test to notice, no exception in a log, and no way for the user to tell the
//! difference between "no such customer" and "the search is broken". That is
//! the failure mode this file exists to prevent, and it is why
//! `tests/fixtures/arabic_vectors.json` was written before a line of the
//! implementation.
//!
//! **The same function must run at index time and at query time.** If the two
//! ever diverge — a stemmer applied on one side only, a new fold added to one
//! path — matching degrades silently and gradually. That is also why
//! [`normalize_ar`] is idempotent and why the fixture asserts it: a re-indexed
//! row must not drift away from the query form.
//!
//! **This is deliberately Rust, not a PostgreSQL function alone.** The
//! companion migration installs an IMMUTABLE SQL `normalize_ar` for use in
//! index expressions, but the drain normalizes in Rust before writing, so the
//! two must agree. `sql_definition_matches_rust_behaviour` in the test module
//! is the tripwire for that; the live-Postgres half lives in the integration
//! test.

/// A15-T2: the fold itself lives in `attome-core` so duplicate matching
/// uses exactly what search indexes and queries with.
pub use attome_core::match_normalize::normalize_ar;

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Vectors {
        groups: Vec<Group>,
        must_not_match: Vec<MustNotMatch>,
    }

    #[derive(Deserialize)]
    struct Group {
        name: String,
        normalized: String,
        variants: Vec<String>,
    }

    #[derive(Deserialize)]
    struct MustNotMatch {
        pairs: Vec<Vec<String>>,
    }

    fn vectors() -> Vectors {
        serde_json::from_str(include_str!("../../tests/fixtures/arabic_vectors.json"))
            .expect("arabic_vectors.json must parse")
    }

    /// The F206 acceptance gate. Every variant in a group must normalize to
    /// that group's stated value — asserted absolutely, not just "equal to
    /// each other", because a function returning the empty string for
    /// everything would satisfy a pairwise-equality test perfectly.
    #[test]
    fn every_arabic_vector_group_folds_to_its_stated_form() {
        for group in vectors().groups {
            for variant in &group.variants {
                assert_eq!(
                    normalize_ar(variant),
                    group.normalized,
                    "group '{}': {variant:?} must normalize to {:?}",
                    group.name,
                    group.normalized
                );
            }
        }
    }

    /// The failure mode opposite to under-normalizing, and the one nobody
    /// tests for: folding so aggressively that genuinely different words
    /// collapse into each other. A search that returns أحمد for محمد is not
    /// better than one that returns nothing.
    #[test]
    fn distinct_words_keep_distinct_normalized_forms() {
        for entry in vectors().must_not_match {
            for pair in entry.pairs {
                let (a, b) = (&pair[0], &pair[1]);
                assert_ne!(
                    normalize_ar(a),
                    normalize_ar(b),
                    "{a:?} and {b:?} are different words and must not collapse"
                );
            }
        }
    }

    /// Idempotence, asserted over every variant rather than a hand-picked
    /// example. `normalize_ar` runs at index time AND query time; if it were
    /// not idempotent, a re-indexed row would drift away from the query form
    /// and matching would degrade silently over successive reindexes.
    #[test]
    fn normalization_is_idempotent() {
        for group in vectors().groups {
            for variant in &group.variants {
                let once = normalize_ar(variant);
                let twice = normalize_ar(&once);
                assert_eq!(once, twice, "normalize_ar is not idempotent on {variant:?}");
            }
        }
    }

    /// Never panics and never produces a lone surrogate or a broken grapheme,
    /// whatever it is handed. This function runs over every record's title in
    /// the platform, including whatever a legacy import left there.
    #[test]
    fn arbitrary_input_is_safe() {
        for input in [
            "",
            "   ",
            "\u{0640}\u{0640}\u{0640}",
            "\u{064B}\u{064C}\u{064D}",
            "🙂 محمد 🙂",
            "\u{0000}\u{FFFD}",
            &"محمّد ".repeat(1000),
        ] {
            let out = normalize_ar(input);
            assert!(out.chars().all(|c| c != '\u{0640}'), "tatweel survived");
            assert!(!out.starts_with(' ') && !out.ends_with(' '));
        }
    }

    /// Digits fold from both ranges, and the ASCII range is untouched.
    #[test]
    fn both_arabic_indic_digit_ranges_fold_to_ascii() {
        assert_eq!(normalize_ar("٠١٢٣٤٥٦٧٨٩"), "0123456789");
        assert_eq!(normalize_ar("۰۱۲۳۴۵۶۷۸۹"), "0123456789");
        assert_eq!(normalize_ar("0123456789"), "0123456789");
    }
}
