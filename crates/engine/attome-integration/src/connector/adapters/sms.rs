//! J4-T1: what the SMS providers share — the segment count of a message, the
//! sender id for a recipient's country, and the answer and receipt shapes.

/// How a message is encoded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// The GSM 03.38 7-bit alphabet: 160 characters, 153 per part.
    Gsm7,
    /// UCS-2 (any other character, Arabic included): 70, 67 per part.
    Ucs2,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gsm7 => "gsm7",
            Self::Ucs2 => "ucs2",
        }
    }
}

/// The GSM 03.38 basic character set.
const GSM_BASIC: &str = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?\
¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
/// The GSM 03.38 extension table: each takes two septets.
const GSM_EXTENDED: &str = "^{}\\[~]|€\u{000C}";

/// A message's encoding and the number of parts (segments) it is sent in.
/// Pure.
pub fn segments(text: &str) -> (Encoding, u32) {
    let mut septets: u32 = 0;
    let mut gsm = true;
    for c in text.chars() {
        if GSM_BASIC.contains(c) {
            septets += 1;
        } else if GSM_EXTENDED.contains(c) {
            septets += 2;
        } else {
            gsm = false;
            break;
        }
    }
    if gsm {
        let parts = if septets <= 160 {
            1
        } else {
            septets.div_ceil(153)
        };
        return (Encoding::Gsm7, parts.max(1));
    }
    let units = u32::try_from(text.encode_utf16().count()).unwrap_or(u32::MAX);
    let parts = if units <= 70 { 1 } else { units.div_ceil(67) };
    (Encoding::Ucs2, parts.max(1))
}

/// Country calling codes the sender table is keyed by, longest first so a
/// three-digit code wins over a one-digit one.
const COUNTRY_CODES: &[(&str, &str)] = &[
    ("966", "SA"),
    ("971", "AE"),
    ("965", "KW"),
    ("974", "QA"),
    ("973", "BH"),
    ("968", "OM"),
    ("962", "JO"),
    ("961", "LB"),
    ("964", "IQ"),
    ("967", "YE"),
    ("212", "MA"),
    ("213", "DZ"),
    ("216", "TN"),
    ("218", "LY"),
    ("249", "SD"),
    ("20", "EG"),
    ("44", "GB"),
    ("49", "DE"),
    ("33", "FR"),
    ("90", "TR"),
    ("91", "IN"),
    ("92", "PK"),
    ("1", "US"),
];

/// The ISO country of an E.164 number, when known. Pure.
pub fn country_of(e164: &str) -> Option<&'static str> {
    let digits: String = e164.chars().filter(char::is_ascii_digit).collect();
    COUNTRY_CODES
        .iter()
        .filter(|(code, _)| digits.starts_with(code))
        .max_by_key(|(code, _)| code.len())
        .map(|(_, iso)| *iso)
}

/// The sender id for a recipient: the provider config's `senders` entry for
/// the recipient's country, else its `*` entry. Pure.
pub fn sender_for(senders: &serde_json::Value, e164: &str) -> Option<String> {
    country_of(e164)
        .and_then(|iso| senders.get(iso))
        .or_else(|| senders.get("*"))
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// A number in E.164 form (`+` and 8 to 15 digits), or none. Pure.
pub fn e164(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    let international = trimmed.starts_with('+') || trimmed.starts_with("00");
    let digits = if trimmed.starts_with("00") {
        digits[2..].to_owned()
    } else {
        digits
    };
    (international && (8..=15).contains(&digits.len())).then(|| format!("+{digits}"))
}

/// A provider's answer to a send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendAnswer {
    Accepted { provider_message_id: String },
    Refused { code: String },
}

/// Where a message stands, as the ledger keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryStatus {
    Queued,
    Sent,
    Delivered,
    Undelivered,
    Failed,
}

impl DeliveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Undelivered => "undelivered",
            Self::Failed => "failed",
        }
    }

    /// Receipts can arrive out of order; a later state never goes back.
    pub fn rank(self) -> u8 {
        match self {
            Self::Queued => 0,
            Self::Sent => 1,
            Self::Delivered | Self::Undelivered | Self::Failed => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_segments_follow_gsm7_and_ucs2_limits() {
        assert_eq!(segments("Hello"), (Encoding::Gsm7, 1));
        assert_eq!(segments(&"a".repeat(160)), (Encoding::Gsm7, 1));
        assert_eq!(segments(&"a".repeat(161)), (Encoding::Gsm7, 2));
        assert_eq!(segments(&"a".repeat(306)), (Encoding::Gsm7, 2));
        assert_eq!(segments(&"a".repeat(307)), (Encoding::Gsm7, 3));
        // An extension character takes two septets.
        assert_eq!(
            segments(&format!("{}€", "a".repeat(159))),
            (Encoding::Gsm7, 2)
        );
        assert_eq!(segments("مرحبا"), (Encoding::Ucs2, 1));
        assert_eq!(segments(&"م".repeat(70)), (Encoding::Ucs2, 1));
        assert_eq!(segments(&"م".repeat(71)), (Encoding::Ucs2, 2));
        assert_eq!(segments(&"م".repeat(135)), (Encoding::Ucs2, 3));
        assert_eq!(segments(""), (Encoding::Gsm7, 1));
    }

    #[test]
    fn sms_sender_follows_the_recipients_country() {
        let senders = serde_json::json!({"SA": "Attome", "*": "+15550001111"});
        assert_eq!(
            sender_for(&senders, "+966551234567").as_deref(),
            Some("Attome")
        );
        assert_eq!(
            sender_for(&senders, "+447700900123").as_deref(),
            Some("+15550001111")
        );
        assert_eq!(country_of("+971501234567"), Some("AE"));
        assert_eq!(country_of("+12025550123"), Some("US"));
        assert_eq!(e164("+966 55 123 4567").as_deref(), Some("+966551234567"));
        assert_eq!(e164("00966551234567").as_deref(), Some("+966551234567"));
        assert_eq!(e164("0551234567"), None, "a local number has no country");
    }

    #[test]
    fn sms_receipts_never_go_backwards() {
        assert!(DeliveryStatus::Delivered.rank() > DeliveryStatus::Sent.rank());
        assert!(DeliveryStatus::Sent.rank() > DeliveryStatus::Queued.rank());
    }
}
