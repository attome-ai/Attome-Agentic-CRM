//! A2-T2: the built-in formats a text attribute may declare
//! (`options.format`), enforced on every write by [`crate::validate`] after
//! [`crate::normalize`] has put the value in shape (Arabic digits as Western
//! ones, separators dropped where the format ignores them).
//!
//! | name | accepts |
//! |---|---|
//! | `email` | one `@`, a dotted domain, no spaces |
//! | `phone` | E.164: `+`, 8 to 15 digits |
//! | `url` | `http://` or `https://` and a host |
//! | `iban` | ISO 13616: country, check digits passing mod 97, the country's length where known |
//! | `saudi_national_id` | 10 digits starting with 1, Luhn check digit |
//! | `iqama` | 10 digits starting with 2, Luhn check digit |
//! | `uae_emirates_id` | 15 digits starting with 784, Luhn check digit |
//! | `percent` | a number from 0 to 100, an optional `%` |
//! | `duration` | ISO 8601 (`P1DT2H`, `PT30M`) or `H:MM` |
//!
//! Pure functions: no regex cache, no I/O.

/// Every built-in format's name.
pub const FORMATS: [&str; 9] = [
    "email",
    "phone",
    "url",
    "iban",
    "saudi_national_id",
    "iqama",
    "uae_emirates_id",
    "percent",
    "duration",
];

/// Whether `name` is a built-in format.
pub fn is_format(name: &str) -> bool {
    FORMATS.contains(&name)
}

/// IBAN lengths by country, for the countries a MENA deployment meets most.
/// A country not listed is held to ISO 13616's 15 to 34 characters only.
const IBAN_LENGTHS: [(&str, usize); 16] = [
    ("AE", 23),
    ("BH", 22),
    ("DE", 22),
    ("EG", 29),
    ("FR", 27),
    ("GB", 22),
    ("IQ", 23),
    ("JO", 30),
    ("KW", 30),
    ("LB", 28),
    ("NL", 18),
    ("OM", 23),
    ("PK", 24),
    ("QA", 29),
    ("SA", 24),
    ("TR", 26),
];

/// The value as `format` stores it, before checking: Western digits, and
/// for the identifiers and IBANs their separators dropped and letters
/// upper-cased; a phone becomes E.164-shaped and an email lower-cased.
pub fn normalize(format: &str, text: &str) -> String {
    let western = crate::western_digits(text.trim());
    match format {
        "email" => western.to_lowercase(),
        "phone" => crate::phone_e164(&western),
        "iban" | "saudi_national_id" | "iqama" | "uae_emirates_id" => western
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
            .to_uppercase(),
        _ => western,
    }
}

/// Checks `text` against the built-in `format`; `Err` carries the message a
/// person reads. An unknown format name is an error too.
pub fn check(format: &str, text: &str) -> Result<(), String> {
    let ok = match format {
        "email" => email_ok(text),
        "phone" => phone_ok(text),
        "url" => url_ok(text),
        "iban" => iban_ok(text),
        "saudi_national_id" => national_id_ok(text, b'1', 10),
        "iqama" => national_id_ok(text, b'2', 10),
        "uae_emirates_id" => text.starts_with("784") && national_id_ok(text, b'7', 15),
        "percent" => percent_ok(text),
        "duration" => duration_ok(text),
        other => return Err(format!("'{other}' is not a known format")),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("'{text}' is not a valid {}", label(format)))
    }
}

fn label(format: &str) -> &'static str {
    match format {
        "email" => "email address",
        "phone" => "phone number (E.164, such as +966501234567)",
        "url" => "web address (http or https)",
        "iban" => "IBAN",
        "saudi_national_id" => "Saudi national ID",
        "iqama" => "iqama number",
        "uae_emirates_id" => "Emirates ID",
        "percent" => "percentage (0 to 100)",
        "duration" => "duration (such as PT30M or 1:30)",
        _ => "value",
    }
}

fn email_ok(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && text.len() <= 254
        && !domain.contains('@')
        && !text.chars().any(char::is_whitespace)
        && domain.contains('.')
        && domain
            .split('.')
            .all(|label| !label.is_empty() && !label.starts_with('-') && !label.ends_with('-'))
}

fn phone_ok(text: &str) -> bool {
    text.strip_prefix('+').is_some_and(|digits| {
        (8..=15).contains(&digits.len())
            && digits.bytes().all(|b| b.is_ascii_digit())
            && !digits.starts_with('0')
    })
}

fn url_ok(text: &str) -> bool {
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"));
    rest.is_some_and(|rest| {
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        !host.is_empty() && !text.chars().any(char::is_whitespace)
    })
}

fn iban_ok(text: &str) -> bool {
    let bytes = text.as_bytes();
    if !(15..=34).contains(&bytes.len())
        || !bytes[..2].iter().all(u8::is_ascii_uppercase)
        || !bytes[2..4].iter().all(u8::is_ascii_digit)
        || !bytes.iter().all(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    if let Some((_, len)) = IBAN_LENGTHS
        .iter()
        .find(|(c, _)| c.as_bytes() == &bytes[..2])
        && *len != bytes.len()
    {
        return false;
    }
    // Move the first four characters to the end, letters as 10..35, and
    // take the number mod 97 a digit at a time.
    let mut remainder: u32 = 0;
    for &b in bytes[4..].iter().chain(&bytes[..4]) {
        let value = if b.is_ascii_digit() {
            u32::from(b - b'0')
        } else {
            u32::from(b - b'A') + 10
        };
        remainder = if value >= 10 {
            (remainder * 100 + value) % 97
        } else {
            (remainder * 10 + value) % 97
        };
    }
    remainder == 1
}

/// `len` digits, the first `first`, with a valid Luhn check digit.
fn national_id_ok(text: &str, first: u8, len: usize) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == len
        && bytes[0] == first
        && bytes.iter().all(u8::is_ascii_digit)
        && luhn_ok(bytes)
}

fn luhn_ok(digits: &[u8]) -> bool {
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

fn percent_ok(text: &str) -> bool {
    let number = text.strip_suffix('%').unwrap_or(text).trim();
    number
        .parse::<f64>()
        .is_ok_and(|n| n.is_finite() && (0.0..=100.0).contains(&n))
}

fn duration_ok(text: &str) -> bool {
    if let Some((hours, minutes)) = text.split_once(':') {
        return !hours.is_empty()
            && hours.bytes().all(|b| b.is_ascii_digit())
            && minutes.len() == 2
            && minutes.bytes().all(|b| b.is_ascii_digit())
            && minutes.parse::<u8>().is_ok_and(|m| m < 60);
    }
    iso_duration_ok(text)
}

/// `P[nY][nM][nW][nD][T[nH][nM][nS]]` with at least one part, and a `T`
/// followed by at least one time part. Seconds may have a fraction.
fn iso_duration_ok(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('P') else {
        return false;
    };
    let (date, time) = match rest.split_once('T') {
        Some((date, time)) => {
            if time.is_empty() {
                return false;
            }
            (date, Some(time))
        }
        None => (rest, None),
    };
    let parts = |s: &str, units: &[u8], fraction_unit: Option<u8>| -> Option<usize> {
        let mut count = 0;
        let mut number = String::new();
        let mut next_unit = 0;
        for c in s.chars() {
            if c.is_ascii_digit() || (c == '.' && fraction_unit.is_some()) {
                number.push(c);
                continue;
            }
            let unit = u8::try_from(c).ok()?;
            let at = units[next_unit..].iter().position(|u| *u == unit)? + next_unit;
            if number.is_empty() || (number.contains('.') && Some(unit) != fraction_unit) {
                return None;
            }
            number.parse::<f64>().ok()?;
            number.clear();
            next_unit = at + 1;
            count += 1;
        }
        number.is_empty().then_some(count)
    };
    let date_parts = match parts(date, b"YMWD", None) {
        Some(n) => n,
        None => return false,
    };
    let time_parts = match time {
        Some(time) => match parts(time, b"HMS", Some(b'S')) {
            Some(0) | None => return false,
            Some(n) => n,
        },
        None => 0,
    };
    date_parts + time_parts > 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(format: &str, raw: &str) -> bool {
        check(format, &normalize(format, raw)).is_ok()
    }

    #[test]
    fn email_and_url() {
        assert!(ok("email", " Sara@Example.COM "));
        assert!(!ok("email", "sara@example"));
        assert!(!ok("email", "sara example@x.com"));
        assert!(ok("url", "https://attome.example/path?q=1"));
        assert!(!ok("url", "ftp://attome.example"));
        assert!(!ok("url", "https://"));
    }

    #[test]
    fn phone_is_e164_after_normalising_arabic_digits() {
        assert!(ok("phone", "+966 50 123 4567"));
        assert!(ok("phone", "٠٠٩٦٦٥٠١٢٣٤٥٦٧"));
        assert!(!ok("phone", "0501234567"));
        assert!(!ok("phone", "+12"));
    }

    #[test]
    fn iban_passes_mod_97_and_its_country_length() {
        assert!(ok("iban", "SA03 8000 0000 6080 1016 7519"));
        assert!(ok("iban", "GB82 WEST 1234 5698 7654 32"));
        assert!(ok("iban", "AE07 0331 2345 6789 0123 456"));
        assert!(!ok("iban", "SA03 8000 0000 6080 1016 7518"), "bad check");
        assert!(!ok("iban", "SA03 8000 0000 6080 1016 751"), "SA is 24");
        assert!(!ok("iban", "1234"));
    }

    #[test]
    fn gulf_identity_numbers_have_luhn_check_digits() {
        // 1000000008: Luhn sum 1*2→2 + 8 = 10.
        assert!(ok("saudi_national_id", "1000000008"));
        assert!(ok("saudi_national_id", "١٠٠٠٠٠٠٠٠٨"));
        assert!(!ok("saudi_national_id", "1000000009"));
        assert!(
            !ok("saudi_national_id", "2000000008"),
            "an iqama, not an ID"
        );
        assert!(ok("iqama", "2000000006"));
        assert!(!ok("iqama", "2000000005"));
        assert!(ok("uae_emirates_id", "784-1990-1234567-6"));
        assert!(!ok("uae_emirates_id", "784-1990-1234567-8"));
        assert!(!ok("uae_emirates_id", "785-1990-1234567-0"));
    }

    #[test]
    fn percent_and_duration() {
        assert!(ok("percent", "12.5%"));
        assert!(ok("percent", "١٠٠"));
        assert!(!ok("percent", "101"));
        assert!(ok("duration", "PT30M"));
        assert!(ok("duration", "P1DT2H"));
        assert!(ok("duration", "PT1.5S"));
        assert!(ok("duration", "1:30"));
        assert!(!ok("duration", "P"));
        assert!(!ok("duration", "PT"));
        assert!(!ok("duration", "P1H"), "hours need T");
        assert!(!ok("duration", "1:75"));
    }

    #[test]
    fn unknown_format_is_refused() {
        assert!(check("colour", "red").is_err());
        assert!(is_format("iban"));
        assert!(!is_format("colour"));
    }
}
