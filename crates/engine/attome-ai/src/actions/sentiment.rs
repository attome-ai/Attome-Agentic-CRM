//! `text.sentiment` (roadmap N19-T1): how a customer's message feels,
//! scored locally, in English and Arabic, with no model call.
//!
//! A lexicon classifier: each word found in the positive or negative lists
//! adds or subtracts one, a negation in the two words before it flips it,
//! an intensifier before it doubles it. The score is the sum over the
//! square root of the words matched (so a long message does not saturate),
//! clamped to -1..1, and the label is `negative` below -0.2, `positive`
//! above 0.2, else `neutral`. Arabic text is normalised first (diacritics,
//! tatweel and letter forms, as titles are in `article.draft`) and the
//! common clitics (و، ف، ب، ال) are stripped before lookup.
//!
//! Local and cheap on purpose: it runs on every inbound message without a
//! budget, and its `matched` words say why it decided what it did. A
//! deployment that wants a learned model can add one behind the same action.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_modules::MODULE_AI;
use attome_types::AppError;
use serde_json::{Value, json};

use crate::context::ActionContext;
use crate::descriptor::{ActionDescriptor, ActionId, Effect, RetryClass, RiskTier};
use crate::execute::{Action, ActionResult};

pub const TEXT_SENTIMENT: &str = "text.sentiment";
/// The longest text scored.
pub const MAX_TEXT_CHARS: usize = 20_000;

const POSITIVE: &[&str] = &[
    // English
    "good",
    "great",
    "excellent",
    "happy",
    "thanks",
    "thank",
    "love",
    "perfect",
    "helpful",
    "fast",
    "quick",
    "resolved",
    "satisfied",
    "amazing",
    "pleased",
    "appreciate",
    "wonderful",
    "best",
    "easy",
    "recommend",
    // Arabic (normalised)
    "شكرا",
    "ممتاز",
    "رائع",
    "جيد",
    "سعيد",
    "مشكور",
    "جميل",
    "سريع",
    "تم",
    "حل",
    "راض",
    "راضي",
    "احسنت",
    "افضل",
    "سهل",
    "يعطيك",
    "العافيه",
    "ممتن",
    "مبدع",
    "انصح",
];

const NEGATIVE: &[&str] = &[
    // English
    "bad",
    "terrible",
    "awful",
    "angry",
    "slow",
    "broken",
    "refund",
    "complaint",
    "worst",
    "disappointed",
    "useless",
    "never",
    "problem",
    "issue",
    "late",
    "cancel",
    "poor",
    "rude",
    "waiting",
    "unacceptable",
    "frustrated",
    "wrong",
    "failed",
    "hate",
    // Arabic (normalised)
    "سيء",
    "سيئ",
    "زعلان",
    "غاضب",
    "متاخر",
    "تاخير",
    "مشكله",
    "شكوي",
    "سيئه",
    "اسوا",
    "خربان",
    "عطل",
    "معطل",
    "الغاء",
    "استرجاع",
    "بطيء",
    "بطء",
    "مزعج",
    "محبط",
    "خطا",
    "فاشل",
    "اكره",
];

const NEGATIONS: &[&str] = &[
    "not", "no", "never", "dont", "don't", "isn't", "wasn't", "didn't", "cannot", "can't", "لا",
    "لم", "لن", "ليس", "مش", "ما", "مو", "بدون", "غير",
];

const INTENSIFIERS: &[&str] = &[
    "very",
    "really",
    "extremely",
    "so",
    "too",
    "totally",
    "جدا",
    "كثير",
    "مره",
    "مرا",
    "للغايه",
    "تماما",
];

/// A sentiment decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Sentiment {
    pub label: &'static str,
    /// -1 (negative) to 1 (positive).
    pub score: f64,
    /// The sentiment words found, as matched.
    pub matched: Vec<String>,
}

/// One word as looked up: lower case, Arabic normalised.
fn normalize_word(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    for c in word.chars() {
        let c = match c {
            '\u{064B}'..='\u{0652}' | '\u{0670}' | '\u{0640}' => continue,
            '\u{0622}' | '\u{0623}' | '\u{0625}' | '\u{0671}' => '\u{0627}',
            '\u{0649}' => '\u{064A}',
            '\u{0629}' => '\u{0647}',
            '\'' => '\'',
            c if c.is_alphanumeric() => c,
            _ => continue,
        };
        out.extend(c.to_lowercase());
    }
    out
}

/// The lexicon entry a word is, trying it bare and without one Arabic
/// clitic prefix (و، ف، ب، ال, and و/ف before ال).
fn lookup<'a>(word: &str, list: &'a [&'a str]) -> Option<&'a str> {
    let mut forms = vec![word.to_owned()];
    for prefix in ["وال", "فال", "بال", "ال", "و", "ف", "ب"] {
        if let Some(rest) = word.strip_prefix(prefix)
            && rest.chars().count() >= 2
        {
            forms.push(rest.to_owned());
        }
    }
    forms
        .iter()
        .find_map(|form| list.iter().find(|entry| **entry == form.as_str()).copied())
}

/// Scores `text`.
pub fn classify(text: &str) -> Sentiment {
    let words: Vec<String> = text
        .split(|c: char| {
            c.is_whitespace() || matches!(c, '.' | ',' | '!' | '?' | '،' | '؟' | '؛' | ';' | ':')
        })
        .map(normalize_word)
        .filter(|w| !w.is_empty())
        .collect();
    let mut total = 0.0;
    let mut matched = Vec::new();
    for (i, word) in words.iter().enumerate() {
        let polarity = if lookup(word, POSITIVE).is_some() {
            1.0
        } else if lookup(word, NEGATIVE).is_some() {
            -1.0
        } else {
            continue;
        };
        let before = &words[i.saturating_sub(2)..i];
        let negated = before.iter().any(|w| NEGATIONS.contains(&w.as_str()));
        let intensified = i > 0 && INTENSIFIERS.contains(&words[i - 1].as_str());
        let mut weight = polarity;
        if negated {
            weight = -weight;
        }
        if intensified {
            weight *= 2.0;
        }
        total += weight;
        matched.push(word.clone());
    }
    let score = if matched.is_empty() {
        0.0
    } else {
        (total / (matched.len() as f64).sqrt() / 2.0).clamp(-1.0, 1.0)
    };
    let label = if score < -0.2 {
        "negative"
    } else if score > 0.2 {
        "positive"
    } else {
        "neutral"
    };
    Sentiment {
        label,
        score: (score * 100.0).round() / 100.0,
        matched,
    }
}

const INPUT: &str = r#"{
  "type": "object",
  "properties": {
    "text": { "type": "string", "description": "A customer's message, in English or Arabic." }
  },
  "required": ["text"],
  "additionalProperties": false
}"#;

pub fn descriptor() -> ActionDescriptor {
    ActionDescriptor::new(
        TEXT_SENTIMENT,
        "How a customer's message feels: positive, neutral or negative, with a \
         score from -1 to 1 and the words that decided it. English and Arabic. \
         Local and free; writes nothing.",
        RiskTier::Read,
        Effect::Read,
        RetryClass::Idempotent,
        MODULE_AI,
        &[],
    )
    .input_schema(INPUT)
}

pub(crate) struct TextSentiment;

impl Action for TextSentiment {
    fn id(&self) -> ActionId {
        ActionId(TEXT_SENTIMENT)
    }

    fn execute<'a>(
        &'a self,
        _state: &'a EngineState,
        _ctx: &'a ActionContext,
        args: &'a Value,
    ) -> Pin<Box<dyn Future<Output = Result<ActionResult, AppError>> + Send + 'a>> {
        Box::pin(async move {
            let text = args["text"]
                .as_str()
                .ok_or_else(|| AppError::Validation("text is required".into()))?;
            if text.chars().count() > MAX_TEXT_CHARS {
                return Err(AppError::Validation(format!(
                    "text must be at most {MAX_TEXT_CHARS} characters"
                )));
            }
            let sentiment = classify(text);
            Ok(ActionResult::plain(json!({
                "label": sentiment.label,
                "score": sentiment.score,
                "matched": sentiment.matched,
            })))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn english_messages_are_scored() {
        assert_eq!(
            classify("Thanks, the issue was resolved fast!").label,
            "positive"
        );
        assert_eq!(
            classify("This is terrible, I want a refund").label,
            "negative"
        );
        assert_eq!(
            classify("Please send the invoice for order 42").label,
            "neutral"
        );
    }

    #[test]
    fn negation_and_intensifiers_change_the_score() {
        assert_eq!(classify("The service was not good").label, "negative");
        let plain = classify("good").score;
        let very = classify("very good").score;
        assert!(very > plain, "{very} > {plain}");
    }

    #[test]
    fn arabic_messages_are_scored_after_normalising() {
        assert_eq!(classify("شكراً جزيلاً، الخدمة ممتازة").label, "positive");
        assert_eq!(classify("الخدمة سيئة جداً وفيه تأخير").label, "negative");
        // Negation: "not happy".
        assert_eq!(classify("أنا مش سعيد بالخدمة").label, "negative");
        assert_eq!(classify("غير راضي عن الخدمة").label, "negative");
        // A clitic in front of the word.
        assert!(classify("وممتاز").matched.iter().any(|w| w == "وممتاز"));
    }

    #[test]
    fn empty_text_is_neutral() {
        let s = classify("   ");
        assert_eq!(s.label, "neutral");
        assert_eq!(s.score, 0.0);
        assert!(s.matched.is_empty());
    }
}
