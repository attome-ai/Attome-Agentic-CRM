//! L10-T1: masking a sandbox copy with deterministic fakes.
//!
//! `attome scratch create` (T5-T1) masks every labelled field of the copy
//! before it boots. The rule follows the field's label unless its options
//! name one (`{"masking": "fake" | "null" | "shuffle" | "keep"}`):
//!
//! | Label | Rule |
//! |---|---|
//! | Personal | fake |
//! | Financial | shuffle (the values stay, moved between records) |
//! | Health, Secret, or sensitive with no label | null |
//!
//! A fake is derived from the real value with HMAC-SHA256 under a key made
//! for this copy and never stored: the same real value gets the same fake
//! everywhere in the copy (a person's email on a contact and on a lead stay
//! equal, so lookups and duplicate rules still meet), and nobody can work
//! back from a fake without the key. Names are Arabic and English names from
//! fixed lists; phones are Saudi (`+9665…`) or Emirati (`+9715…`) mobile
//! numbers; national ids are ten digits starting 1 (Saudi citizen) or 2
//! (resident); emails end in `example.invalid`. A required column whose rule
//! is null is faked instead, so the copy keeps its constraints.

use sha2::{Digest, Sha256};

/// How one field is masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskRule {
    Fake,
    Null,
    Shuffle,
    Keep,
}

impl MaskRule {
    /// The rule an options value names. Pure.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "fake" => Some(Self::Fake),
            "null" => Some(Self::Null),
            "shuffle" => Some(Self::Shuffle),
            "keep" => Some(Self::Keep),
            _ => None,
        }
    }
}

/// The rule for a field with `label` (`personal`, `financial`, `health`,
/// `secret`, or another label when only `is_sensitive` marks it), an
/// override from its options, and whether its column is required. Pure.
pub fn rule_for(label: &str, override_rule: Option<&str>, required: bool) -> MaskRule {
    let rule = override_rule
        .and_then(MaskRule::parse)
        .unwrap_or(match label {
            "personal" => MaskRule::Fake,
            "financial" => MaskRule::Shuffle,
            _ => MaskRule::Null,
        });
    if rule == MaskRule::Null && required {
        MaskRule::Fake
    } else {
        rule
    }
}

/// HMAC-SHA256 of `message` under `key`. Pure.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner);
    outer.finalize().into()
}

/// What a field holds, from its name. Pure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    Email,
    Phone,
    NationalId,
    Name,
    Other,
}

pub fn kind_of(field: &str) -> FieldKind {
    let f = field.to_ascii_lowercase();
    if f.contains("email") {
        FieldKind::Email
    } else if f.contains("phone") || f.contains("mobile") || f.contains("whatsapp") {
        FieldKind::Phone
    } else if f.contains("national_id")
        || f.contains("iqama")
        || f.contains("id_number")
        || f.contains("emirates_id")
    {
        FieldKind::NationalId
    } else if f.contains("name") {
        FieldKind::Name
    } else {
        FieldKind::Other
    }
}

const FIRST_NAMES: &[&str] = &[
    "محمد",
    "أحمد",
    "عبدالله",
    "فاطمة",
    "نورة",
    "سارة",
    "خالد",
    "مريم",
    "يوسف",
    "ليلى",
    "Omar",
    "Huda",
    "Faisal",
    "Reem",
    "Salem",
    "Aisha",
];
const FAMILY_NAMES: &[&str] = &[
    "العتيبي",
    "القحطاني",
    "الشمري",
    "المطيري",
    "الزهراني",
    "الكعبي",
    "المنصوري",
    "الهاشمي",
    "Al-Harbi",
    "Al-Mansoori",
    "Al-Qasimi",
    "Al-Dosari",
];

fn word(bytes: &[u8], at: usize) -> usize {
    let mut n = [0u8; 8];
    n.copy_from_slice(&bytes[at..at + 8]);
    // Only the value's spread matters, so any fixed byte order does.
    usize::try_from(u64::from_le_bytes(n) % u64::from(u32::MAX)).unwrap_or(0)
}

fn digits(bytes: &[u8], count: usize) -> String {
    bytes
        .iter()
        .cycle()
        .take(count)
        .map(|b| char::from(b'0' + b % 10))
        .collect()
}

/// The fake of `value` for a field named `field` under `key`: the same for
/// the same inputs, unrelated to the value without the key. Pure.
pub fn fake(key: &[u8], field: &str, value: &str) -> String {
    let kind = kind_of(field);
    // Keyed by kind, not field, so one person's email masks the same in
    // every entity it appears in.
    let tag = format!("{kind:?}:{}", value.trim().to_lowercase());
    let h = hmac_sha256(key, tag.as_bytes());
    match kind {
        FieldKind::Email => format!("user{}@example.invalid", &hex(&h)[..10]),
        FieldKind::Phone => {
            if h[0].is_multiple_of(2) {
                format!("+9665{}", digits(&h[1..], 8))
            } else {
                format!("+9715{}", digits(&h[1..], 8))
            }
        }
        FieldKind::NationalId => {
            let first = if h[0].is_multiple_of(2) { '1' } else { '2' };
            format!("{first}{}", digits(&h[1..], 9))
        }
        FieldKind::Name => format!(
            "{} {}",
            FIRST_NAMES[word(&h, 0) % FIRST_NAMES.len()],
            FAMILY_NAMES[word(&h, 8) % FAMILY_NAMES.len()]
        ),
        FieldKind::Other => format!("masked-{}", &hex(&h)[..12]),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking_rules_follow_the_label() {
        assert_eq!(rule_for("personal", None, false), MaskRule::Fake);
        assert_eq!(rule_for("financial", None, false), MaskRule::Shuffle);
        assert_eq!(rule_for("secret", None, false), MaskRule::Null);
        assert_eq!(rule_for("health", None, false), MaskRule::Null);
        assert_eq!(rule_for("internal", None, false), MaskRule::Null);
        assert_eq!(rule_for("secret", None, true), MaskRule::Fake);
        assert_eq!(rule_for("personal", Some("keep"), false), MaskRule::Keep);
        assert_eq!(rule_for("personal", Some("bogus"), false), MaskRule::Fake);
    }

    #[test]
    fn fakes_are_consistent_and_keyed() {
        let key = b"copy key";
        let a = fake(key, "email", "Sara@Example.com");
        assert_eq!(a, fake(key, "work_email", " sara@example.com"));
        assert!(a.ends_with("@example.invalid"));
        assert_ne!(a, fake(b"other key", "email", "sara@example.com"));
        let phone = fake(key, "mobile_phone", "0501234567");
        assert!(
            phone.starts_with("+9665") || phone.starts_with("+9715"),
            "{phone}"
        );
        assert_eq!(phone.len(), 13);
        let id = fake(key, "national_id", "1012345678");
        assert_eq!(id.len(), 10);
        assert!(id.starts_with('1') || id.starts_with('2'));
        let name = fake(key, "full_name", "Sara Ali");
        assert_eq!(name.split(' ').count(), 2, "{name}");
        assert!(!name.contains("Sara Ali"));
        assert!(fake(key, "notes", "x").starts_with("masked-"));
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }
}
