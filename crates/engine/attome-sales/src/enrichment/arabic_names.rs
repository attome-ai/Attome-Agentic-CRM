//! D24-T8: Arabic forms of Latin names, as suggestions a person accepts.
//!
//! The pairs a suggestion can fill are [`NAME_PAIRS`] (today the account's
//! legal name; the person fields have no Arabic counterpart yet). A
//! suggestion is an enrichment proposal of kind `review` from the source
//! [`MODEL_SOURCE`], never a fill. Sources rank (L1 survivorship): the
//! registry above any other provider above the model ([`source_rank`]); a
//! record whose Arabic field is filled, or has a pending proposal from a
//! source ranked above the model, gets no suggestion ([`needs_suggestion`]).
//! Names go to the model [`BATCH`] at a time; its reply is a JSON array of
//! the Arabic forms in order ([`parse_reply`]).

use serde_json::Value;

/// The source a model's suggestion carries.
pub const MODEL_SOURCE: &str = "model";

/// Names asked of the model in one call.
pub const BATCH: usize = 20;

/// `(entity, Latin field, Arabic field)`.
pub const NAME_PAIRS: [(&str, &str, &str); 1] = [("account", "legal_name_en", "legal_name_ar")];

/// A source's rank: the registry 3, any other provider 2, the model 1.
/// Pure.
pub fn source_rank(source: &str) -> u8 {
    match source {
        "registry" => 3,
        MODEL_SOURCE => 1,
        _ => 2,
    }
}

/// Whether `text` is a Latin-script name: some ASCII letters and no Arabic
/// letters. Pure.
pub fn is_latin(text: &str) -> bool {
    text.chars().any(|c| c.is_ascii_alphabetic())
        && !text.chars().any(|c| ('\u{0600}'..='\u{06FF}').contains(&c))
}

/// Whether a record whose Arabic field holds `arabic` and has pending
/// proposals for it from `pending_sources` should get a model suggestion
/// for the Latin name `latin`. Pure.
pub fn needs_suggestion(
    latin: Option<&str>,
    arabic: Option<&Value>,
    pending_sources: &[&str],
) -> bool {
    let Some(latin) = latin.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let arabic_filled = arabic
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    is_latin(latin)
        && !arabic_filled
        && !pending_sources
            .iter()
            .any(|s| source_rank(s) > source_rank(MODEL_SOURCE))
}

/// The model's reply as one Arabic form per name asked, in order; a form
/// that is missing, empty or not Arabic is `None`. Pure.
pub fn parse_reply(reply: &str, asked: usize) -> Vec<Option<String>> {
    let start = reply.find('[');
    let end = reply.rfind(']');
    let parsed: Vec<Value> = match (start, end) {
        (Some(s), Some(e)) if e > s => serde_json::from_str(&reply[s..=e]).unwrap_or_default(),
        _ => Vec::new(),
    };
    (0..asked)
        .map(|i| {
            parsed
                .get(i)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| s.chars().any(|c| ('\u{0600}'..='\u{06FF}').contains(&c)))
                .map(str::to_owned)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn registry_name_outranks_suggestion() {
        assert!(source_rank("registry") > source_rank("website"));
        assert!(source_rank("website") > source_rank(MODEL_SOURCE));
        // A Latin name with an empty Arabic field is suggested ...
        assert!(needs_suggestion(Some("Al Nakheel Foods"), None, &[]));
        // ... unless the registry's Arabic name is pending or filled.
        assert!(!needs_suggestion(
            Some("Al Nakheel Foods"),
            None,
            &["registry"]
        ));
        assert!(!needs_suggestion(
            Some("Al Nakheel Foods"),
            Some(&json!("شركة النخيل للأغذية")),
            &[]
        ));
        // An earlier model suggestion does not stop a new one.
        assert!(needs_suggestion(
            Some("Al Nakheel Foods"),
            None,
            &[MODEL_SOURCE]
        ));
        assert!(!needs_suggestion(Some("شركة النخيل"), None, &[]));

        // A canned reply: one Arabic form per name, a non-Arabic one dropped.
        let reply = "Here you go: [\"شركة النخيل للأغذية\", \"Gulf Co\", \"مؤسسة الأمل\"]";
        assert_eq!(
            parse_reply(reply, 3),
            vec![
                Some("شركة النخيل للأغذية".to_owned()),
                None,
                Some("مؤسسة الأمل".to_owned())
            ]
        );
        assert_eq!(parse_reply("no list", 2), vec![None, None]);
    }
}
