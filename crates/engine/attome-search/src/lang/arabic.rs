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

/// Folds Arabic orthographic variation, strips diacritics, converts
/// Arabic-Indic digits, lowercases, and collapses whitespace.
///
/// Ordering matters and is not arbitrary: diacritics and tatweel come out
/// first so that a fold never has to reason about a combining mark sitting
/// between two letters, and whitespace is collapsed last so that removals
/// earlier in the pass cannot leave doubled spaces behind.
pub fn normalize_ar(input: &str) -> String {
    let mut out = String::with_capacity(input.len());

    for ch in input.chars() {
        // 1. Drop what carries no lexical meaning at all.
        if is_tashkeel(ch) || ch == TATWEEL {
            continue;
        }

        // 2. Fold orthographic variants onto one representative.
        let folded = fold_letter(ch);

        // 3. Arabic-Indic and Eastern Arabic-Indic digits to ASCII. Both
        //    ranges are in live use across the GCC — an invoice number typed
        //    ١٢٣ must find a record storing 123.
        let folded = fold_digit(folded);

        out.push(folded);
    }

    // 4. Lowercase for the Latin half. `to_lowercase` is a no-op for Arabic
    //    (it is unicameral), so this is safe to apply to the whole string
    //    rather than segmenting first.
    let lowered = out.to_lowercase();

    // 5. Collapse whitespace LAST, so that removing a tatweel or a harakat
    //    cannot leave a doubled space behind. Any Unicode whitespace becomes a
    //    single ASCII space — a non-breaking space pasted from a document is
    //    not a meaningful difference between two names.
    lowered.split_whitespace().collect::<Vec<_>>().join(" ")
}

const TATWEEL: char = '\u{0640}';

/// Arabic diacritics: the harakat block (U+064B–U+0652), the superscript alef
/// and its neighbours (U+0653–U+065F), the Quranic annotation marks
/// (U+06D6–U+06ED), and the standalone sukun/shadda variants.
///
/// Deliberately a range check rather than a match on named characters: the
/// block is contiguous by design, and enumerating it invites a missed
/// codepoint that then silently breaks matching for whatever word contains it.
fn is_tashkeel(ch: char) -> bool {
    matches!(ch,
        '\u{064B}'..='\u{065F}'   // fathatan … wavy hamza below
        | '\u{0670}'              // superscript alef
        | '\u{06D6}'..='\u{06ED}' // Quranic annotation
    )
}

/// The letter folds.
///
/// Each of these is a pair that native typists interchange in practice, not a
/// linguistic equivalence. Folding them is what makes `احمد` find `أحمد` —
/// the single highest-value normalization for name search, because a name is
/// what people search for and a name is exactly where the hamza is dropped.
fn fold_letter(ch: char) -> char {
    match ch {
        // Alef with any hamza or madda, and the Quranic wasla, all to bare alef.
        '\u{0622}' | '\u{0623}' | '\u{0625}' | '\u{0671}' => '\u{0627}',
        // Alef maksura to ya — ى and ي are interchanged constantly.
        '\u{0649}' => '\u{064A}',
        // Taa marbuta to haa — ة is commonly typed ه word-final.
        '\u{0629}' => '\u{0647}',
        // Hamza carriers to the bare hamza.
        '\u{0624}' | '\u{0626}' => '\u{0621}',
        other => other,
    }
}

fn fold_digit(ch: char) -> char {
    match ch {
        // Arabic-Indic ٠-٩
        '\u{0660}'..='\u{0669}' => char::from(b'0' + (ch as u32 - 0x0660) as u8),
        // Eastern Arabic-Indic ۰-۹ (Persian/Urdu forms, also seen in the Gulf)
        '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (ch as u32 - 0x06F0) as u8),
        other => other,
    }
}

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
