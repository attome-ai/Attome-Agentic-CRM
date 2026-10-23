//! Data-quality fix transforms (roadmap L2-T5), pure: the changes a bulk
//! fix applies to a text value. Each returns `None` when the value is
//! already clean, so a preview counts only the records it would change.
//!
//! Bulk edit's `fix` operation ([`crate::bulk_edit`]) applies a [`Fix`] to
//! each picked record's current value, so a fix runs as one undoable bulk
//! update through the normal update path.

/// A fix bulk edit can apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    TrimSpaces,
    TitleCase,
    DigitsToWestern,
    /// A national number read in this country (ISO 3166 alpha-2).
    PhoneE164(String),
}

impl Fix {
    /// The fix a bulk-edit operation names: `"trim_spaces"`, `"title_case"`,
    /// `"digits_to_western"`, `"phone_e164"` (in `default_country`), or
    /// `{"fix": "phone_e164", "country": "AE"}`.
    pub fn parse(value: &serde_json::Value, default_country: &str) -> Option<Self> {
        let (name, country) = match value {
            serde_json::Value::String(name) => (name.as_str(), None),
            serde_json::Value::Object(o) => (
                o.get("fix")?.as_str()?,
                o.get("country").and_then(serde_json::Value::as_str),
            ),
            _ => return None,
        };
        match name {
            "trim_spaces" => Some(Self::TrimSpaces),
            "title_case" => Some(Self::TitleCase),
            "digits_to_western" => Some(Self::DigitsToWestern),
            "phone_e164" => {
                let country = country.unwrap_or(default_country);
                country_rule(country)?;
                Some(Self::PhoneE164(country.to_ascii_uppercase()))
            }
            _ => None,
        }
    }

    /// The fixed value, or `None` when `value` is already clean or cannot
    /// be read.
    pub fn apply(&self, value: &str) -> Option<String> {
        match self {
            Self::TrimSpaces => trim_spaces(value),
            Self::TitleCase => title_case(value),
            Self::DigitsToWestern => digits_to_western(value),
            Self::PhoneE164(country) => phone_e164(value, country),
        }
    }
}

/// Spaces trimmed and runs of space squashed.
pub fn trim_spaces(value: &str) -> Option<String> {
    let fixed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    (fixed != value).then_some(fixed)
}

/// Each word's first letter upper case and the rest lower case; words
/// without Latin letters are left alone.
pub fn title_case(value: &str) -> Option<String> {
    let fixed = value
        .split(' ')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) if first.is_ascii_alphabetic() => {
                    first.to_ascii_uppercase().to_string() + &chars.as_str().to_lowercase()
                }
                _ => word.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    (fixed != value).then_some(fixed)
}

/// Arabic-Indic and Persian digits written as Western digits.
pub fn digits_to_western(value: &str) -> Option<String> {
    let fixed: String = value
        .chars()
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => char::from(b'0' + (c as u32 - 0x0660) as u8),
            '\u{06F0}'..='\u{06F9}' => char::from(b'0' + (c as u32 - 0x06F0) as u8),
            other => other,
        })
        .collect();
    (fixed != value).then_some(fixed)
}

/// The dialling code and national-number length of the countries the
/// platform's region presets cover.
fn country_rule(country: &str) -> Option<(&'static str, usize)> {
    match country.to_ascii_uppercase().as_str() {
        "SA" => Some(("966", 9)),
        "AE" => Some(("971", 9)),
        "KW" => Some(("965", 8)),
        "BH" => Some(("973", 8)),
        "OM" => Some(("968", 8)),
        "QA" => Some(("974", 8)),
        "JO" => Some(("962", 9)),
        "EG" => Some(("20", 10)),
        _ => None,
    }
}

/// A phone number in E.164 (`+9665…`), reading a national number in
/// `default_country`; `None` when it is already E.164 or cannot be read.
pub fn phone_e164(value: &str, default_country: &str) -> Option<String> {
    let western = digits_to_western(value).unwrap_or_else(|| value.to_owned());
    let trimmed = western.trim();
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let fixed = if trimmed.starts_with('+') {
        format!("+{digits}")
    } else if let Some(rest) = digits.strip_prefix("00") {
        format!("+{rest}")
    } else {
        let (code, length) = country_rule(default_country)?;
        let national = digits.strip_prefix('0').unwrap_or(&digits);
        if let Some(rest) = national.strip_prefix(code)
            && rest.len() == length
        {
            format!("+{code}{rest}")
        } else if national.len() == length {
            format!("+{code}{national}")
        } else {
            return None;
        }
    };
    (fixed != value).then_some(fixed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixes_parse_by_name_and_country() {
        use serde_json::json;
        assert_eq!(
            Fix::parse(&json!("trim_spaces"), "SA"),
            Some(Fix::TrimSpaces)
        );
        assert_eq!(
            Fix::parse(&json!("phone_e164"), "sa"),
            Some(Fix::PhoneE164("SA".into()))
        );
        assert_eq!(
            Fix::parse(&json!({"fix": "phone_e164", "country": "AE"}), "SA"),
            Some(Fix::PhoneE164("AE".into()))
        );
        assert_eq!(
            Fix::parse(&json!("phone_e164"), "ZZ"),
            None,
            "no rule for ZZ"
        );
        assert_eq!(Fix::parse(&json!("shout"), "SA"), None);
        assert_eq!(
            Fix::PhoneE164("SA".into()).apply("0501234567").as_deref(),
            Some("+966501234567")
        );
    }

    #[test]
    fn trims_spaces() {
        assert_eq!(
            trim_spaces("  Acme   Trading "),
            Some("Acme Trading".into())
        );
        assert_eq!(trim_spaces("Acme Trading"), None);
    }

    #[test]
    fn title_cases() {
        assert_eq!(
            title_case("ACME trading co"),
            Some("Acme Trading Co".into())
        );
        assert_eq!(title_case("شركة acme"), Some("شركة Acme".into()));
        assert_eq!(title_case("Acme"), None);
    }

    #[test]
    fn phone_to_e164_saudi() {
        assert_eq!(
            phone_e164("050 123 4567", "SA"),
            Some("+966501234567".into())
        );
        assert_eq!(
            phone_e164("00966501234567", "SA"),
            Some("+966501234567".into())
        );
        assert_eq!(
            phone_e164("966501234567", "SA"),
            Some("+966501234567".into())
        );
        assert_eq!(phone_e164("+966501234567", "SA"), None);
        assert_eq!(phone_e164("٠٥٠١٢٣٤٥٦٧", "SA"), Some("+966501234567".into()));
        assert_eq!(phone_e164("12345", "SA"), None, "too short to read");
    }

    #[test]
    fn arabic_indic_digits_to_western() {
        assert_eq!(digits_to_western("٢٠٢٦/١٠/١٦"), Some("2026/10/16".into()));
        assert_eq!(digits_to_western("۱۲۳"), Some("123".into()));
        assert_eq!(digits_to_western("123"), None);
    }
}
