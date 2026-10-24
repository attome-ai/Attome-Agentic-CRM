//! L6-T4: personal data found in unlabelled attributes.
//!
//! A profile runs these detectors on the sampled values of every text
//! attribute that carries no label yet (`is_sensitive` false, classification
//! `general`). Each value counts for the first detector it matches:
//!
//! - a Saudi national ID: 10 digits starting with 1, passing the ID's
//!   checksum (the Luhn sum over the ten digits, doubling the digits in odd
//!   positions counted from one);
//! - an Iqama (resident ID): the same, starting with 2;
//! - an IBAN: 15 to 34 letters and digits, country letters, check digits,
//!   and the ISO 13616 mod 97 check equal to 1;
//! - a phone: E.164 (`+` and 8 to 15 digits) or a Saudi mobile written
//!   locally (`05` and 8 digits, or `9665` and 8 digits);
//! - an email address.
//!
//! Eastern (Arabic-Indic) digits count as their Western digits, and spaces,
//! dashes, dots and brackets inside a number are ignored. When more than
//! [`PROPOSAL_SHARE_PCT`] of an attribute's non-blank sampled values match
//! one detector, the profile proposes the `personal` label for it
//! (`data_label_proposal`, migration 0221) with the counts only: no matched
//! value is kept. Nothing is labelled automatically; a builder decides and
//! sets the label through the attribute admin API, after which the attribute
//! is no longer scanned and its open proposals are closed.

use serde::Serialize;

/// The share of an attribute's values above which a label is proposed.
pub const PROPOSAL_SHARE_PCT: f64 = 5.0;

/// The label a proposal names.
pub const PROPOSED_LABEL: &str = "personal";

/// What a detector found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    SaudiNationalId,
    Iqama,
    Iban,
    Phone,
    Email,
}

impl Detector {
    pub const ALL: [Detector; 5] = [
        Detector::SaudiNationalId,
        Detector::Iqama,
        Detector::Iban,
        Detector::Phone,
        Detector::Email,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Detector::SaudiNationalId => "saudi_national_id",
            Detector::Iqama => "iqama",
            Detector::Iban => "iban",
            Detector::Phone => "phone",
            Detector::Email => "email",
        }
    }
}

/// `value` with Eastern digits as Western ones and number separators
/// (spaces, `-`, `.`, `(`, `)`) dropped.
fn compact(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.' | '(' | ')' | '\u{a0}'))
        .map(|c| match c {
            '\u{0660}'..='\u{0669}' => char::from_digit(c as u32 - 0x0660, 10).unwrap_or(c),
            '\u{06F0}'..='\u{06F9}' => char::from_digit(c as u32 - 0x06F0, 10).unwrap_or(c),
            other => other,
        })
        .collect()
}

/// The Saudi ID checksum over ten digits: the Luhn sum, doubling the digits
/// in odd positions counted from one, is a multiple of ten.
pub fn saudi_id_checksum(digits: &str) -> bool {
    if digits.len() != 10 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let sum: u32 = digits
        .bytes()
        .enumerate()
        .map(|(i, b)| {
            let d = u32::from(b - b'0');
            if i % 2 == 0 {
                let twice = d * 2;
                twice / 10 + twice % 10
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

/// The ISO 13616 check: the IBAN, its first four characters moved to the
/// end and letters read as 10 to 35, is 1 modulo 97.
pub fn iban_mod97(value: &str) -> bool {
    let iban: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    let bytes = iban.as_bytes();
    if !(15..=34).contains(&bytes.len())
        || !bytes[..2].iter().all(u8::is_ascii_uppercase)
        || !bytes[2..4].iter().all(u8::is_ascii_digit)
        || !bytes.iter().all(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    let mut remainder: u32 = 0;
    for &b in bytes[4..].iter().chain(&bytes[..4]) {
        let n = if b.is_ascii_digit() {
            u32::from(b - b'0')
        } else {
            u32::from(b - b'A') + 10
        };
        remainder = if n >= 10 {
            (remainder * 100 + n) % 97
        } else {
            (remainder * 10 + n) % 97
        };
    }
    remainder == 1
}

fn is_phone(compact: &str) -> bool {
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = compact.strip_prefix('+') {
        return (8..=15).contains(&rest.len()) && digits(rest);
    }
    if let Some(rest) = compact.strip_prefix("9665") {
        return rest.len() == 8 && digits(rest);
    }
    compact.len() == 10 && compact.starts_with("05") && digits(compact)
}

fn is_email(value: &str) -> bool {
    let value = value.trim();
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    let Some((host, tld)) = domain.rsplit_once('.') else {
        return false;
    };
    !local.is_empty()
        && !host.is_empty()
        && tld.len() >= 2
        && tld.chars().all(|c| c.is_alphabetic())
        && !domain.contains('@')
        && !value.chars().any(char::is_whitespace)
}

/// The first detector `value` matches.
pub fn detect(value: &str) -> Option<Detector> {
    if is_email(value) {
        return Some(Detector::Email);
    }
    let compact = compact(value);
    if saudi_id_checksum(&compact) {
        return match compact.as_bytes()[0] {
            b'1' => Some(Detector::SaudiNationalId),
            b'2' => Some(Detector::Iqama),
            _ => None,
        }
        .or_else(|| is_phone(&compact).then_some(Detector::Phone));
    }
    if iban_mod97(value) {
        return Some(Detector::Iban);
    }
    is_phone(&compact).then_some(Detector::Phone)
}

/// One attribute's detector counts.
#[derive(Debug, Default, Clone)]
pub struct PiiStats {
    /// Non-blank values seen.
    pub sampled: u64,
    counts: [u64; 5],
}

/// A label proposal: counts only.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Proposal {
    pub detector: Detector,
    pub matches: u64,
    pub sampled: u64,
    pub share_pct: f64,
}

impl PiiStats {
    pub fn push(&mut self, value: &str) {
        if value.trim().is_empty() {
            return;
        }
        self.sampled += 1;
        if let Some(detector) = detect(value) {
            let i = Detector::ALL
                .iter()
                .position(|d| *d == detector)
                .unwrap_or_default();
            self.counts[i] += 1;
        }
    }

    /// The detectors that matched more than [`PROPOSAL_SHARE_PCT`] of the
    /// values.
    pub fn proposals(&self) -> Vec<Proposal> {
        if self.sampled == 0 {
            return Vec::new();
        }
        Detector::ALL
            .iter()
            .zip(self.counts)
            .filter_map(|(detector, matches)| {
                let share_pct = matches as f64 * 100.0 / self.sampled as f64;
                (share_pct > PROPOSAL_SHARE_PCT).then_some(Proposal {
                    detector: *detector,
                    matches,
                    sampled: self.sampled,
                    share_pct,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iban_mod97() {
        assert!(super::iban_mod97("SA0380000000608010167519"));
        assert!(super::iban_mod97("SA03 8000 0000 6080 1016 7519"));
        assert!(super::iban_mod97("gb82west12345698765432"));
        assert!(
            !super::iban_mod97("SA0380000000608010167518"),
            "one digit off"
        );
        assert!(!super::iban_mod97("SA03"), "too short");
        assert_eq!(
            detect("SA03 8000 0000 6080 1016 7519"),
            Some(Detector::Iban)
        );
    }

    #[test]
    fn saudi_id_checksum() {
        assert!(super::saudi_id_checksum("1045678909"));
        assert!(!super::saudi_id_checksum("1045678908"));
        assert!(!super::saudi_id_checksum("104567890"), "nine digits");
        assert_eq!(detect("1045678909"), Some(Detector::SaudiNationalId));
        assert_eq!(detect("2123456788"), Some(Detector::Iqama));
        assert_eq!(
            detect("١٠٤٥٦٧٨٩٠٩"),
            Some(Detector::SaudiNationalId),
            "Eastern digits"
        );
        assert_eq!(detect("+966 50 123 4567"), Some(Detector::Phone));
        assert_eq!(detect("050-123-4567"), Some(Detector::Phone));
        assert_eq!(detect("sara@example.sa"), Some(Detector::Email));
        assert_eq!(detect("Riyadh"), None);
        assert_eq!(detect("12345"), None);
    }

    #[test]
    fn proposal_threshold_5_percent() {
        let mut stats = PiiStats::default();
        for _ in 0..95 {
            stats.push("Riyadh branch");
        }
        for _ in 0..5 {
            stats.push("0501234567");
        }
        stats.push("   ");
        assert_eq!(stats.sampled, 100, "a blank value is not sampled");
        assert!(stats.proposals().is_empty(), "exactly 5% proposes nothing");
        stats.push("+966501234567");
        let proposals = stats.proposals();
        assert_eq!(proposals.len(), 1);
        assert_eq!(
            (
                proposals[0].detector,
                proposals[0].matches,
                proposals[0].sampled
            ),
            (Detector::Phone, 6, 101)
        );
        let json = serde_json::to_value(&proposals[0]).unwrap();
        assert!(
            !json.to_string().contains("0501234567"),
            "a proposal keeps counts, never values"
        );
    }
}
