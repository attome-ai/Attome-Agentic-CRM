//! Claim checking for grounded answers (roadmap N15-T3): every sentence of a
//! `knowledge.answer` reply is compared with the passages it cites.
//!
//! A sentence is **supported** when enough of its content words (stop words
//! dropped, Arabic normalised as `article.draft` normalises titles) appear
//! in the cited passages, at least [`MIN_SUPPORT`] of them, and every number
//! it states appears there too: a figure the passages never mention is the
//! most dangerous kind of invented detail. Unsupported sentences are flagged
//! with the reason, and the answer also comes back without them, so a caller
//! can show the checked text or the original with its flags. Lexical on
//! purpose: it runs on every answer, locally, and says exactly why.

use serde::Serialize;

/// The share of a sentence's content words the passages must contain.
pub const MIN_SUPPORT: f64 = 0.5;
/// A sentence with fewer content words than this is not judged (a short
/// connective such as "Yes." carries no claim of its own).
pub const MIN_WORDS: usize = 3;

const STOP: &[&str] = &[
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with", "is", "are", "was",
    "were", "be", "been", "it", "this", "that", "these", "those", "you", "your", "we", "our",
    "can", "will", "may", "must", "should", "as", "at", "by", "from", "if", "then", "than", "not",
    "no", "do", "does", "have", "has", "had", "within", "after", "before", "also", "please", "في",
    "من", "على", "إلى", "الى", "عن", "مع", "هذا", "هذه", "ذلك", "التي", "الذي", "أن", "ان", "إن",
    "او", "أو", "ثم", "قد", "لا", "ما", "كل", "بعد", "قبل", "عند", "يمكن", "يجب", "هو", "هي",
];

/// One sentence that failed the check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Unsupported {
    pub sentence: String,
    /// `few_words_found` or `number_not_found`.
    pub reason: &'static str,
}

/// The check of one answer.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ClaimCheck {
    /// The answer without its unsupported sentences.
    pub supported_answer: String,
    pub unsupported: Vec<Unsupported>,
}

fn normalize(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    for c in word.chars() {
        let c = match c {
            '\u{064B}'..='\u{0652}' | '\u{0670}' | '\u{0640}' => continue,
            '\u{0622}' | '\u{0623}' | '\u{0625}' | '\u{0671}' => '\u{0627}',
            '\u{0649}' => '\u{064A}',
            '\u{0629}' => '\u{0647}',
            c if c.is_alphanumeric() => c,
            _ => continue,
        };
        out.extend(c.to_lowercase());
    }
    // A leading Arabic definite article or conjunction is not the word.
    for prefix in ["وال", "بال", "فال", "ال"] {
        if let Some(rest) = out.strip_prefix(prefix)
            && rest.chars().count() >= 3
        {
            return rest.to_owned();
        }
    }
    out
}

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| {
        c.is_whitespace() || matches!(c, ',' | '.' | ';' | ':' | '،' | '؛' | '(' | ')')
    })
    .map(normalize)
    .filter(|w| !w.is_empty())
    .collect()
}

fn is_number(word: &str) -> bool {
    word.chars()
        .any(|c| c.is_ascii_digit() || ('\u{0660}'..='\u{0669}').contains(&c))
}

/// Splits an answer into sentences (Latin and Arabic sentence ends, and
/// line breaks).
pub fn sentences(answer: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in answer.chars() {
        current.push(c);
        if matches!(c, '.' | '!' | '?' | '؟' | '\n') {
            let s = current.trim().to_owned();
            if !s.is_empty() {
                out.push(s);
            }
            current.clear();
        }
    }
    let s = current.trim().to_owned();
    if !s.is_empty() {
        out.push(s);
    }
    out
}

/// Checks `answer` against the text of the passages it cites.
pub fn check(answer: &str, passages: &[&str]) -> ClaimCheck {
    let mut vocabulary = std::collections::HashSet::new();
    for passage in passages {
        vocabulary.extend(words(passage));
    }
    let mut kept = Vec::new();
    let mut unsupported = Vec::new();
    for sentence in sentences(answer) {
        let content: Vec<String> = words(&sentence)
            .into_iter()
            .filter(|w| !STOP.contains(&w.as_str()))
            .collect();
        let missing_number = content
            .iter()
            .any(|w| is_number(w) && !vocabulary.contains(w));
        let verdict = if missing_number {
            Some("number_not_found")
        } else if content.len() >= MIN_WORDS {
            let found = content.iter().filter(|w| vocabulary.contains(*w)).count();
            #[allow(clippy::cast_precision_loss, reason = "sentence word counts are small")]
            let share = found as f64 / content.len() as f64;
            (share < MIN_SUPPORT).then_some("few_words_found")
        } else {
            None
        };
        match verdict {
            Some(reason) => unsupported.push(Unsupported { sentence, reason }),
            None => kept.push(sentence),
        }
    }
    ClaimCheck {
        supported_answer: kept.join(" "),
        unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSAGE: &str = "Customers may return unused items within 30 days of delivery for a full refund. \
                           Refunds are paid to the original payment method within 5 working days.";

    #[test]
    fn supported_sentences_pass() {
        let result = check(
            "You can return unused items within 30 days of delivery. The refund goes to the original payment method.",
            &[PASSAGE],
        );
        assert!(result.unsupported.is_empty(), "{:?}", result.unsupported);
    }

    #[test]
    fn an_invented_number_or_claim_is_flagged_and_dropped() {
        let result = check(
            "You can return unused items within 60 days. Shipping labels are printed free at any branch office nationwide.",
            &[PASSAGE],
        );
        let reasons: Vec<&str> = result.unsupported.iter().map(|u| u.reason).collect();
        assert_eq!(reasons, ["number_not_found", "few_words_found"]);
        assert!(result.supported_answer.is_empty());
    }

    #[test]
    fn arabic_is_checked_after_normalising() {
        let passage = "يمكن للعملاء إرجاع المنتجات غير المستخدمة خلال 30 يوماً من التسليم.";
        let result = check("يمكن إرجاع المنتجات غير المستخدمة خلال 30 يوما.", &[passage]);
        assert!(result.unsupported.is_empty(), "{:?}", result.unsupported);
        let invented = check("يمكن إرجاع المنتجات خلال 90 يوما.", &[passage]);
        assert_eq!(invented.unsupported[0].reason, "number_not_found");
    }

    #[test]
    fn short_connectives_are_not_judged() {
        assert!(check("Yes.", &[PASSAGE]).unsupported.is_empty());
    }
}
