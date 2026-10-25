//! Z8-T5: what providers and bounce emails say about our mail.
//!
//! - **Amazon SES** publishes bounces and complaints to an SNS topic, which
//!   posts them to the webhook. Each SNS message is signed (RSA, SHA-1 for
//!   `SignatureVersion` 1 and SHA-256 for 2) with the certificate at its
//!   `SigningCertURL`, which must be an `https://sns.<region>.amazonaws.com/`
//!   `.pem` address ([`sns_cert_url_ok`]); [`verify_sns`] checks the
//!   signature over the canonical string ([`sns_string_to_sign`]).
//! - **SendGrid**'s signed event webhook signs `timestamp + body` with
//!   ECDSA P-256 (SHA-256, DER); the operator configures its public key
//!   ([`verify_sendgrid`]).
//! - **SMTP senders** get delivery status notifications back by mail;
//!   [`parse_dsn`] reads their `Final-Recipient` and `Status`.
//!
//! [`apply`] turns the events into suppressions: a hard bounce or complaint
//! blocks every stream, an unsubscribe blocks bulk mail only (Z8-T3), and a
//! soft bounce is counted, suppressing after five in seven days.

use base64::Engine;
use serde_json::Value;

use crate::suppression::{self, SuppressionReason};

/// What one event says about an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedbackKind {
    HardBounce,
    SoftBounce,
    Complaint,
    Unsubscribe,
}

/// One event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Feedback {
    pub email: String,
    pub kind: FeedbackKind,
    pub detail: Option<String>,
}

/// Soft bounces in [`SOFT_WINDOW_DAYS`] that suppress an address.
pub const SOFT_BOUNCE_LIMIT: i64 = 5;
pub const SOFT_WINDOW_DAYS: i32 = 7;

fn feedback(email: &str, kind: FeedbackKind, detail: Option<&str>) -> Option<Feedback> {
    let email = email.trim();
    (email.contains('@') && email.len() <= 320).then(|| Feedback {
        email: email.to_owned(),
        kind,
        detail: detail
            .map(|d| d.chars().take(500).collect::<String>())
            .filter(|d| !d.is_empty()),
    })
}

// ── DER, just enough to reach a certificate's public key ─────────────────────

/// One tag-length-value: the tag, the content and what follows. Pure.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, b| (acc << 8) | usize::from(*b));
        (len, &rest[n..])
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The public key bits (the BIT STRING's content after its unused-bits
/// byte) of a SubjectPublicKeyInfo. Pure.
pub fn spki_key_bits(spki: &[u8]) -> Option<&[u8]> {
    let (tag, body, _) = tlv(spki)?;
    if tag != 0x30 {
        return None;
    }
    let (_, _algorithm, rest) = tlv(body)?;
    let (tag, bits, _) = tlv(rest)?;
    (tag == 0x03 && bits.first() == Some(&0)).then(|| &bits[1..])
}

/// The SubjectPublicKeyInfo of an X.509 certificate (DER). Pure.
pub fn certificate_spki(cert: &[u8]) -> Option<&[u8]> {
    let (tag, body, _) = tlv(cert)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, tbs, _) = tlv(body)?;
    if tag != 0x30 {
        return None;
    }
    let mut rest = tbs;
    // [0] version, when present.
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.2;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        rest = tlv(rest)?.2;
    }
    let (tag, _, after) = tlv(rest)?;
    (tag == 0x30).then(|| &rest[..rest.len() - after.len()])
}

/// The DER inside a PEM block. Pure.
pub fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .flat_map(|l| l.trim().chars())
        .collect();
    base64::engine::general_purpose::STANDARD.decode(body).ok()
}

// ── Amazon SES through SNS ───────────────────────────────────────────────────

/// Whether `url` is an SNS signing certificate address. Pure.
pub fn sns_cert_url_ok(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let Some((host, path)) = rest.split_once('/') else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let region_ok = |region: &str| {
        !region.is_empty()
            && region
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    };
    let in_aws = host
        .strip_prefix("sns.")
        .and_then(|h| {
            h.strip_suffix(".amazonaws.com")
                .or_else(|| h.strip_suffix(".amazonaws.com.cn"))
        })
        .is_some_and(region_ok);
    in_aws && path.ends_with(".pem") && !path.contains("..") && !path.contains('?')
}

/// The string an SNS message's signature covers, or `None` for a message
/// type this does not handle. Pure.
pub fn sns_string_to_sign(msg: &Value) -> Option<String> {
    let kind = msg["Type"].as_str()?;
    let keys: &[&str] = match kind {
        "Notification" => &[
            "Message",
            "MessageId",
            "Subject",
            "Timestamp",
            "TopicArn",
            "Type",
        ],
        "SubscriptionConfirmation" | "UnsubscribeConfirmation" => &[
            "Message",
            "MessageId",
            "SubscribeURL",
            "Timestamp",
            "Token",
            "TopicArn",
            "Type",
        ],
        _ => return None,
    };
    let mut out = String::new();
    for key in keys {
        match msg.get(*key).and_then(Value::as_str) {
            Some(value) => {
                out.push_str(key);
                out.push('\n');
                out.push_str(value);
                out.push('\n');
            }
            // Only a notification's Subject may be absent.
            None if *key == "Subject" => {}
            None => return None,
        }
    }
    Some(out)
}

/// Whether an SNS message is signed by the certificate `cert_pem`. Pure.
pub fn verify_sns(msg: &Value, cert_pem: &str) -> bool {
    use ring::signature::{
        RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey,
    };
    let Some(text) = sns_string_to_sign(msg) else {
        return false;
    };
    let Some(signature) = msg["Signature"]
        .as_str()
        .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
    else {
        return false;
    };
    let Some(der) = pem_to_der(cert_pem) else {
        return false;
    };
    let Some(key) = certificate_spki(&der).and_then(spki_key_bits) else {
        return false;
    };
    let algorithm = match msg["SignatureVersion"].as_str() {
        Some("1") => &RSA_PKCS1_2048_8192_SHA1_FOR_LEGACY_USE_ONLY,
        Some("2") => &RSA_PKCS1_2048_8192_SHA256,
        _ => return false,
    };
    UnparsedPublicKey::new(algorithm, key)
        .verify(text.as_bytes(), &signature)
        .is_ok()
}

/// The events in an SES notification (the SNS message's `Message`). Pure.
pub fn parse_ses(message: &str) -> Vec<Feedback> {
    let Ok(event) = serde_json::from_str::<Value>(message) else {
        return Vec::new();
    };
    let kind = event["notificationType"]
        .as_str()
        .or_else(|| event["eventType"].as_str())
        .unwrap_or_default();
    match kind {
        "Bounce" => {
            let bounce = &event["bounce"];
            let hard = bounce["bounceType"].as_str() == Some("Permanent");
            bounce["bouncedRecipients"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| {
                    feedback(
                        r["emailAddress"].as_str()?,
                        if hard {
                            FeedbackKind::HardBounce
                        } else {
                            FeedbackKind::SoftBounce
                        },
                        r["diagnosticCode"].as_str(),
                    )
                })
                .collect()
        }
        "Complaint" => event["complaint"]["complainedRecipients"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| {
                feedback(
                    r["emailAddress"].as_str()?,
                    FeedbackKind::Complaint,
                    event["complaint"]["complaintFeedbackType"].as_str(),
                )
            })
            .collect(),
        _ => Vec::new(),
    }
}

// ── SendGrid ─────────────────────────────────────────────────────────────────

/// Whether SendGrid signed `timestamp + body` with the key whose
/// SubjectPublicKeyInfo is `public_key_b64`. Pure.
pub fn verify_sendgrid(
    public_key_b64: &str,
    signature_b64: &str,
    timestamp: &str,
    body: &[u8],
) -> bool {
    use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    let engine = base64::engine::general_purpose::STANDARD;
    let (Ok(spki), Ok(signature)) = (
        engine.decode(public_key_b64.trim()),
        engine.decode(signature_b64.trim()),
    ) else {
        return false;
    };
    let Some(point) = spki_key_bits(&spki) else {
        return false;
    };
    let mut message = timestamp.as_bytes().to_vec();
    message.extend_from_slice(body);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point)
        .verify(&message, &signature)
        .is_ok()
}

/// The events in a SendGrid event webhook body. Pure.
pub fn parse_sendgrid(body: &[u8]) -> Vec<Feedback> {
    let Ok(Value::Array(events)) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    events
        .iter()
        .filter_map(|e| {
            let email = e["email"].as_str()?;
            let reason = e["reason"].as_str();
            let kind = match (e["event"].as_str()?, e["type"].as_str()) {
                ("bounce", Some("blocked")) => FeedbackKind::SoftBounce,
                ("bounce", _) => FeedbackKind::HardBounce,
                ("spamreport", _) => FeedbackKind::Complaint,
                ("unsubscribe" | "group_unsubscribe", _) => FeedbackKind::Unsubscribe,
                _ => return None,
            };
            feedback(email, kind, reason)
        })
        .collect()
}

// ── Delivery status notifications ───────────────────────────────────────────

/// The failures a delivery status notification (RFC 3464) reports: each
/// `Final-Recipient` with a `5.x.x` status is a hard bounce, `4.x.x` soft.
/// Pure.
pub fn parse_dsn(raw: &str) -> Vec<Feedback> {
    let mut out = Vec::new();
    let mut recipient: Option<String> = None;
    for line in raw.lines() {
        let line = line.trim();
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("final-recipient:") {
            recipient = value
                .split_once(';')
                .map(|(_, address)| address.trim().to_owned());
        } else if let Some(status) = lower.strip_prefix("status:")
            && let Some(email) = recipient.take()
        {
            let status = status.trim();
            let kind = if status.starts_with('5') {
                FeedbackKind::HardBounce
            } else if status.starts_with('4') {
                FeedbackKind::SoftBounce
            } else {
                continue;
            };
            out.extend(feedback(&email, kind, Some(status)));
        }
    }
    out
}

/// Records the events as suppressions; answers how many addresses were
/// suppressed now.
pub async fn apply(db: &attome_db::DbPool, events: &[Feedback]) -> Result<usize, sqlx::Error> {
    let mut suppressed = 0;
    for event in events {
        let reason = match event.kind {
            FeedbackKind::HardBounce => SuppressionReason::HardBounce,
            FeedbackKind::Complaint => SuppressionReason::Complaint,
            FeedbackKind::Unsubscribe => SuppressionReason::Unsubscribe,
            FeedbackKind::SoftBounce => {
                let recent: i64 = sqlx::query_scalar(
                    "WITH added AS (INSERT INTO email_soft_bounce (email) VALUES (lower($1)) RETURNING email) \
                     SELECT 1 + COUNT(*) FROM email_soft_bounce \
                      WHERE email = lower($1) AND at > now() - make_interval(days => $2::int)",
                )
                .bind(&event.email)
                .bind(SOFT_WINDOW_DAYS)
                .fetch_one(db)
                .await?;
                if recent < SOFT_BOUNCE_LIMIT {
                    continue;
                }
                SuppressionReason::HardBounce
            }
        };
        suppression::suppress(db, &event.email, reason, event.detail.as_deref(), None).await?;
        suppressed += 1;
    }
    Ok(suppressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/feedback_vectors.json")).unwrap()
    }

    #[test]
    fn feedback_sns_signature_verifies_and_tampering_fails() {
        let v = vectors();
        let pem = v["cert_pem"].as_str().unwrap();
        let msg = v["sns"].clone();
        assert!(verify_sns(&msg, pem));
        let mut tampered = msg.clone();
        tampered["Message"] = Value::String("{}".into());
        assert!(!verify_sns(&tampered, pem));
        let mut unsigned = msg.clone();
        unsigned["Signature"] = Value::String(String::new());
        assert!(!verify_sns(&unsigned, pem));
        let events = parse_ses(msg["Message"].as_str().unwrap());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].email, "gone@example.com");
        assert_eq!(events[0].kind, FeedbackKind::HardBounce);
    }

    #[test]
    fn feedback_sns_cert_url_must_be_amazon() {
        assert!(sns_cert_url_ok(
            "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-abc.pem"
        ));
        assert!(sns_cert_url_ok(
            "https://sns.cn-north-1.amazonaws.com.cn/x.pem"
        ));
        assert!(!sns_cert_url_ok("http://sns.us-east-1.amazonaws.com/x.pem"));
        assert!(!sns_cert_url_ok(
            "https://sns.us-east-1.amazonaws.com.evil.io/x.pem"
        ));
        assert!(!sns_cert_url_ok(
            "https://evil.io/sns.us-east-1.amazonaws.com/x.pem"
        ));
        assert!(!sns_cert_url_ok(
            "https://sns.us-east-1.amazonaws.com/x.txt"
        ));
    }

    #[test]
    fn feedback_sendgrid_signature_and_events() {
        let v = vectors();
        let key = v["sg_key"].as_str().unwrap();
        let sig = v["sg_sig"].as_str().unwrap();
        let ts = v["sg_ts"].as_str().unwrap();
        let body = v["sg_body"].as_str().unwrap().as_bytes();
        assert!(verify_sendgrid(key, sig, ts, body));
        assert!(!verify_sendgrid(key, sig, "1793001601", body));
        assert!(!verify_sendgrid(key, sig, ts, b"[]"));
        let kinds: Vec<FeedbackKind> = parse_sendgrid(body).iter().map(|f| f.kind).collect();
        assert_eq!(
            kinds,
            [
                FeedbackKind::Complaint,
                FeedbackKind::Unsubscribe,
                FeedbackKind::SoftBounce,
                FeedbackKind::HardBounce
            ]
        );
    }

    #[test]
    fn feedback_dsn_reports_hard_and_soft() {
        let dsn = "Content-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.example.com\r\n\r\n\
                   Final-Recipient: rfc822; gone@example.com\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n\
                   Final-Recipient: rfc822; full@example.com\r\nAction: delayed\r\nStatus: 4.2.2\r\n";
        let events = parse_dsn(dsn);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].email, "gone@example.com");
        assert_eq!(events[0].kind, FeedbackKind::HardBounce);
        assert_eq!(events[1].kind, FeedbackKind::SoftBounce);
        assert!(parse_dsn("Status: 2.0.0").is_empty());
    }
}
