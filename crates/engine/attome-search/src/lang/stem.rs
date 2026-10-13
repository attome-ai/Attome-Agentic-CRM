//! Light stemming for Arabic and English (TODO-010).
//!
//! **Why both, and why in Rust.** `P-search-and-retrieval` Q7/Q7b: the index
//! uses a single `simple`-configuration tsvector, which means PostgreSQL
//! applies **no stemming at all** — "invoices" stops matching "invoice", which
//! is a plain regression against any competitor. And mixed Arabic/English
//! inside one record is the GCC norm rather than an edge case, so a
//! single-language answer is not an answer.
//!
//! Doing it here rather than in a PostgreSQL dictionary buys the property that
//! matters most: **one implementation runs at index time and at query time.**
//! A Snowball dictionary underneath would be a second, differently-behaving
//! stemmer, and a word stemmed twice by two algorithms still produces a lexeme
//! — just not the one the query produced. That failure is invisible: no error,
//! no log line, just fewer results.
//!
//! **Light, deliberately.** Both stemmers strip only affixes that are
//! productive and unambiguous. Aggressive stemming (full Khoja/ISRI, or Porter
//! with its later steps) conflates words that a CRM user means to distinguish —
//! and in name search, which is most of what a CRM does, over-stemming is worse
//! than none: it returns the wrong person confidently. The
//! `must_not_conflate` tests below are the guard on that, and they are the half
//! of stemming that usually goes untested.

/// The shortest a stem may be after stripping.
///
/// Below this, an affix strip is almost always wrong: Arabic triliteral roots
/// are three letters, and a two-letter English "stem" matches half the
/// dictionary. Every rule below respects this floor, which is why "كتب" keeps
/// its ك rather than being read as a prefix.
const MIN_ARABIC_STEM: usize = 3;
const MIN_ENGLISH_STEM: usize = 3;

/// Arabic light stemmer.
///
/// The ISRI/Khoja family reduced to the affixes that actually matter for names
/// and business nouns — the algorithm, not the dependency (there is no
/// maintained, permissively-licensed Rust port, and vendoring a full stemmer
/// for the subset used here would be a large dependency for a small gain).
///
/// Expects [`super::normalize_ar`]-normalized input: the folds there mean this
/// only has to reason about one spelling of each letter.
pub fn stem_ar(word: &str) -> String {
    let chars: Vec<char> = word.chars().collect();
    if chars.len() <= MIN_ARABIC_STEM {
        return word.to_owned();
    }

    let mut start = 0usize;
    let mut end = chars.len();

    // Definite article and conjunction/preposition prefixes, longest first so
    // "وال" is not mistaken for a bare "و". Only stripped when enough stem
    // remains — "الف" (a thousand) must not become "ف".
    for prefix in ["وال", "بال", "كال", "فال", "ال", "لل"] {
        let plen = prefix.chars().count();
        if end - start > plen + MIN_ARABIC_STEM - 1
            && chars[start..].starts_with(&prefix.chars().collect::<Vec<_>>()[..])
        {
            start += plen;
            break;
        }
    }

    // Suffixes: plural/dual endings and attached pronouns, longest first —
    // "ات" must be tried before any shorter ending.
    //
    // **No single-letter suffixes.** A bare ه, ي, or ا is far more often part
    // of the word than an attached pronoun, and stripping it conflates real
    // pairs: شركه (company) would become شرك, and علي (a name) would lose its
    // final letter. That is the over-stemming failure this file's header calls
    // worse than no stemming at all — in name search it returns the wrong
    // person, confidently. The two-letter endings below are productive enough
    // to be worth the risk; one-letter ones are not.
    for suffix in [
        "تمام", "كمام", "هما", "كما", "تها", "نا", "ها", "ان", "ات", "ون", "ين", "ية",
    ] {
        let slen = suffix.chars().count();
        if end - start > slen + MIN_ARABIC_STEM - 1
            && chars[start..end].ends_with(&suffix.chars().collect::<Vec<_>>()[..])
        {
            end -= slen;
            break;
        }
    }

    chars[start..end].iter().collect()
}

/// English light stemmer — roughly Porter's step 1, and deliberately no
/// further.
///
/// Step 1 (plurals and past/progressive) is where nearly all the recall comes
/// from for CRM text: "invoices"/"invoice", "shipped"/"ship". Porter's later
/// steps handle derivational morphology ("national" -> "nation") that
/// conflates terms a business user means to keep apart, and they are where
/// most of the surprising results come from.
pub fn stem_en(word: &str) -> String {
    let lower = word.to_ascii_lowercase();
    let len = lower.len();
    if len <= MIN_ENGLISH_STEM || !lower.is_ascii() {
        return lower;
    }

    // Plurals. "sses" -> "ss" and "ies" -> "y" before the bare "s", or
    // "addresses" becomes "addresse".
    for (suffix, replacement) in [("sses", "ss"), ("ies", "y"), ("ss", "ss")] {
        if lower.ends_with(suffix) {
            let stem = format!("{}{replacement}", &lower[..len - suffix.len()]);
            return if stem.len() >= MIN_ENGLISH_STEM {
                stem
            } else {
                lower
            };
        }
    }
    if lower.ends_with('s') && !lower.ends_with("us") && !lower.ends_with("ss") {
        let stem = &lower[..len - 1];
        if stem.len() >= MIN_ENGLISH_STEM {
            return stem.to_owned();
        }
    }

    // Past and progressive. Only when a vowel remains in the stem — "bed"
    // must not become "b", and "sing" must not become "s".
    for suffix in ["ing", "ed"] {
        if let Some(stem) = lower.strip_suffix(suffix)
            && stem.len() >= MIN_ENGLISH_STEM
            && stem.chars().any(|c| "aeiou".contains(c))
        {
            // Undouble a final consonant ("shipping" -> "ship"), but not the
            // legitimate doubles Porter also preserves.
            let bytes = stem.as_bytes();
            let n = bytes.len();
            if n >= 2 && bytes[n - 1] == bytes[n - 2] && !b"lsz".contains(&bytes[n - 1]) {
                return stem[..n - 1].to_owned();
            }
            return stem.to_owned();
        }
    }

    lower
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The recall case: these pairs must reach the same stem, or the index and
    /// the query disagree about an ordinary word.
    #[test]
    fn english_plurals_and_tenses_reach_one_stem() {
        for (a, b) in [
            ("invoice", "invoices"),
            ("address", "addresses"),
            ("company", "companies"),
            ("ship", "shipping"),
            ("ship", "shipped"),
            ("order", "orders"),
            ("account", "accounts"),
        ] {
            assert_eq!(
                stem_en(a),
                stem_en(b),
                "{a:?} and {b:?} must stem alike — this is the 'invoices stops \
                 matching invoice' regression Q7 names"
            );
        }
    }

    /// The precision case, and the half of stemming that usually goes
    /// untested. Over-stemming returns the wrong record confidently, which in a
    /// CRM is worse than returning nothing.
    #[test]
    fn english_stemming_does_not_conflate_distinct_words() {
        for (a, b) in [
            ("bed", "bee"),
            ("sing", "sin"),
            ("business", "busy"),
            ("status", "statu"),
            ("access", "acce"),
        ] {
            assert_ne!(
                stem_en(a),
                stem_en(b),
                "{a:?} and {b:?} are different words and must not collapse"
            );
        }
    }

    /// Short words are left alone — a three-letter "stem" matches half the
    /// dictionary.
    #[test]
    fn english_short_words_are_untouched() {
        for word in ["is", "as", "us", "gas", "bus"] {
            assert_eq!(stem_en(word), word.to_ascii_lowercase());
        }
    }

    #[test]
    fn english_stemming_is_idempotent() {
        for word in [
            "invoices",
            "companies",
            "shipping",
            "addresses",
            "orders",
            "shipped",
        ] {
            let once = stem_en(word);
            assert_eq!(
                stem_en(&once),
                once,
                "stem_en is not idempotent on {word:?}"
            );
        }
    }

    /// Arabic recall: the definite article and the common plural endings.
    /// Inputs are already `normalize_ar`-folded, which is what the stemmer
    /// expects.
    #[test]
    fn arabic_affixes_are_stripped() {
        assert_eq!(stem_ar("الشركه"), "شركه");
        assert_eq!(stem_ar("والشركه"), "شركه");
        assert_eq!(stem_ar("للشركه"), "شركه");
        assert_eq!(stem_ar("معلمات"), "معلم");
        assert_eq!(stem_ar("معلمون"), "معلم");
    }

    /// Arabic precision: the triliteral-root floor. A three-letter word is a
    /// root already, and stripping its first letter as an article turns a real
    /// word into a fragment.
    #[test]
    fn arabic_short_words_keep_their_letters() {
        for word in ["كتب", "علي", "الف", "ابن"] {
            assert_eq!(
                stem_ar(word),
                word,
                "{word:?} is at or below the triliteral floor and must not be \
                 stripped"
            );
        }
    }

    #[test]
    fn arabic_stemming_does_not_conflate_distinct_words() {
        for (a, b) in [("كتاب", "كتب"), ("عالي", "علي"), ("شركه", "شريك")] {
            assert_ne!(
                stem_ar(a),
                stem_ar(b),
                "{a:?} and {b:?} are different words and must not collapse"
            );
        }
    }

    #[test]
    fn arabic_stemming_is_idempotent() {
        for word in ["الشركه", "معلمات", "والمدرسه", "معلمون"] {
            let once = stem_ar(word);
            assert_eq!(
                stem_ar(&once),
                once,
                "stem_ar is not idempotent on {word:?}"
            );
        }
    }

    /// Neither stemmer may panic or produce a broken grapheme, whatever it is
    /// handed — both run over every token of every record in the platform.
    #[test]
    fn arbitrary_input_is_safe() {
        for word in ["", " ", "🙂", "\u{0000}", "a", "ا", &"م".repeat(500)] {
            let _ = stem_ar(word);
            let _ = stem_en(word);
        }
    }
}
