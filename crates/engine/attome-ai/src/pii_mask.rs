//! Masks personal values before text goes to a model that may not see them
//! (roadmap N28-T1), and restores them afterwards for a viewer who may.
//!
//! A [`Masker`] lives for one turn. [`Masker::mask_value`] replaces a value
//! the metadata labels (a sensitive attribute) with a token such as
//! `[PERSON_1]`; [`Masker::mask_text`] finds unlabelled emails, phone numbers
//! and IBANs (checksum-verified) in free text. The same value always gets the
//! same token within a turn, so the model can still reason about "the same
//! person". [`Masker::unmask`] puts real values back. Which model may see
//! which labels (the Z9 catalogue) decides whether a turn masks at all.

use std::collections::BTreeMap;

/// What kind of value a token stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MaskKind {
    Person,
    Email,
    Phone,
    Iban,
    Value,
}

impl MaskKind {
    fn label(self) -> &'static str {
        match self {
            Self::Person => "PERSON",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::Iban => "IBAN",
            Self::Value => "VALUE",
        }
    }
}

/// One turn's token map.
#[derive(Default)]
pub struct Masker {
    by_value: BTreeMap<(MaskKind, String), String>,
    by_token: BTreeMap<String, String>,
    counters: BTreeMap<MaskKind, usize>,
}

impl std::fmt::Debug for Masker {
    // Never print the map: it holds the personal values.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Masker")
            .field("tokens", &self.by_token.len())
            .finish_non_exhaustive()
    }
}

fn is_email(word: &str) -> bool {
    let Some((local, domain)) = word.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._%+-".contains(c))
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn is_phone(word: &str) -> bool {
    let digits = word.chars().filter(char::is_ascii_digit).count();
    word.starts_with('+')
        && (8..=15).contains(&digits)
        && word[1..].chars().all(|c| c.is_ascii_digit() || c == '-')
}

/// An IBAN: two letters, two check digits, then letters and digits, with a
/// valid mod-97 checksum.
fn is_iban(word: &str) -> bool {
    let bytes = word.as_bytes();
    if !(15..=34).contains(&bytes.len())
        || !bytes[..2].iter().all(u8::is_ascii_uppercase)
        || !bytes[2..4].iter().all(u8::is_ascii_digit)
        || !bytes.iter().all(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    let rearranged = word[4..].chars().chain(word[..4].chars());
    let mut remainder: u32 = 0;
    for c in rearranged {
        let value = match c.to_digit(36) {
            Some(v) => v,
            None => return false,
        };
        let digits = if value >= 10 { 100 } else { 10 };
        remainder = (remainder * digits + value) % 97;
    }
    remainder == 1
}

impl Masker {
    pub fn new() -> Self {
        Self::default()
    }

    fn token_for(&mut self, kind: MaskKind, value: &str) -> String {
        if let Some(token) = self.by_value.get(&(kind, value.to_owned())) {
            return token.clone();
        }
        let n = self.counters.entry(kind).or_insert(0);
        *n += 1;
        let token = format!("[{}_{n}]", kind.label());
        self.by_value
            .insert((kind, value.to_owned()), token.clone());
        self.by_token.insert(token.clone(), value.to_owned());
        token
    }

    /// A labelled value's token (a sensitive attribute's value).
    pub fn mask_value(&mut self, kind: MaskKind, value: &str) -> String {
        if value.trim().is_empty() {
            return value.to_owned();
        }
        self.token_for(kind, value)
    }

    /// `text` with every email, phone number and IBAN replaced by its token.
    pub fn mask_text(&mut self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut word = String::new();
        let flush = |word: &mut String, out: &mut String, masker: &mut Masker| {
            if word.is_empty() {
                return;
            }
            // Trailing punctuation belongs to the sentence, not the value.
            let trimmed = word.trim_end_matches(['.', ',', ';', ':', '!', '?', ')']);
            let tail = &word[trimmed.len()..];
            let kind = if is_email(trimmed) {
                Some(MaskKind::Email)
            } else if is_phone(trimmed) {
                Some(MaskKind::Phone)
            } else if is_iban(trimmed) {
                Some(MaskKind::Iban)
            } else {
                None
            };
            match kind {
                Some(kind) => {
                    let token = masker.token_for(kind, trimmed);
                    out.push_str(&token);
                    out.push_str(tail);
                }
                None => out.push_str(word),
            }
            word.clear();
        };
        for c in text.chars() {
            if c.is_whitespace() || c == '(' || c == '<' || c == '>' {
                flush(&mut word, &mut out, self);
                out.push(c);
            } else {
                word.push(c);
            }
        }
        flush(&mut word, &mut out, self);
        out
    }

    /// `text` with every token this turn issued replaced by its real value.
    pub fn unmask(&self, text: &str) -> String {
        let mut out = text.to_owned();
        // Longest tokens first, so `[PERSON_12]` is never read as `[PERSON_1]`.
        let mut tokens: Vec<&String> = self.by_token.keys().collect();
        tokens.sort_by_key(|t| std::cmp::Reverse(t.len()));
        for token in tokens {
            if let Some(value) = self.by_token.get(token) {
                out = out.replace(token.as_str(), value);
            }
        }
        out
    }

    /// How many distinct values were masked this turn.
    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_phones_and_ibans_are_tokenised_and_restored() {
        let mut masker = Masker::new();
        let text = "Mail ada@example.com, call +966-50-123-4567 or pay SA0380000000608010167519. \
                    Again: ada@example.com.";
        let masked = masker.mask_text(text);
        assert!(!masked.contains("ada@example.com"), "{masked}");
        assert!(!masked.contains("123-4567"), "{masked}");
        assert!(!masked.contains("SA0380000000608010167519"), "{masked}");
        assert_eq!(
            masked.matches("[EMAIL_1]").count(),
            2,
            "one token per value: {masked}"
        );
        assert!(masked.contains("[PHONE_1]") && masked.contains("[IBAN_1]"));
        assert_eq!(masker.unmask(&masked), text);
    }

    #[test]
    fn labelled_values_and_lookalikes() {
        let mut masker = Masker::new();
        assert_eq!(
            masker.mask_value(MaskKind::Person, "Ada Lovelace"),
            "[PERSON_1]"
        );
        assert_eq!(
            masker.mask_value(MaskKind::Person, "Ada Lovelace"),
            "[PERSON_1]"
        );
        assert_eq!(masker.mask_value(MaskKind::Person, "Grace"), "[PERSON_2]");
        // Not an IBAN (bad checksum), not a phone (no +), not an email.
        let plain = "SA0380000000608010167518 0501234567 name@localhost";
        assert_eq!(masker.mask_text(plain), plain);
        assert_eq!(masker.len(), 2);
        assert!(
            !format!("{masker:?}").contains("Ada"),
            "Debug never prints values"
        );
    }
}
