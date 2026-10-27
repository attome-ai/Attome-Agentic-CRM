//! E19-T1: Google Ads lead forms, Customer Match audiences and offline
//! click conversions, as pure request and answer codecs (the caller does the
//! HTTP with the account's OAuth token and developer token).
//!
//! - **Lead forms.** Google posts each lead form answer to the webhook with
//!   the `google_key` the advertiser set; [`lead_from_webhook`] checks the
//!   key in constant time and maps `user_column_data` onto a lead.
//! - **Customer Match.** Only consenting people, hashed the way Google
//!   matches: e-mail trimmed and lower-cased (dots and `+tags` removed from
//!   gmail.com and googlemail.com local parts), phone in E.164 with its `+`,
//!   SHA-256 in lower-case hex ([`hashed_email`], [`hashed_phone`]), as
//!   `OfflineUserDataJob` create operations ([`customer_match_operations`]).
//! - **Offline conversions.** A won deal with the click id it came from is a
//!   `ClickConversion` ([`click_conversion`]).

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::ads_meta::{AudienceMember, sha256_hex};

/// Operations per `addOperations` request.
pub const OPERATIONS_BATCH: usize = 10_000;

/// An e-mail as Google matches it, hashed. Pure.
pub fn hashed_email(email: &str) -> Option<String> {
    let normal = email.trim().to_lowercase();
    let (local, domain) = normal.split_once('@')?;
    if local.is_empty() || domain.is_empty() {
        return None;
    }
    let local = if domain == "gmail.com" || domain == "googlemail.com" {
        local.split('+').next().unwrap_or(local).replace('.', "")
    } else {
        local.to_owned()
    };
    Some(sha256_hex(&format!("{local}@{domain}")))
}

/// A phone in E.164 (`+` and digits), hashed; `None` when it is not
/// international. Pure.
pub fn hashed_phone(phone: &str) -> Option<String> {
    let trimmed = phone.trim();
    let digits: String = trimmed.chars().filter(char::is_ascii_digit).collect();
    let international = trimmed.starts_with('+') || trimmed.starts_with("00");
    let digits = digits
        .strip_prefix("00")
        .map_or(digits.clone(), str::to_owned);
    (international && digits.len() >= 7).then(|| sha256_hex(&format!("+{digits}")))
}

/// The `OfflineUserDataJob` create operations for consenting `members`, in
/// batches of at most [`OPERATIONS_BATCH`]. Pure.
pub fn customer_match_operations(members: &[AudienceMember]) -> Vec<Value> {
    let ops: Vec<Value> = members
        .iter()
        .filter(|m| m.consented)
        .filter_map(|m| {
            let mut ids = Vec::new();
            if let Some(e) = m.email.as_deref().and_then(hashed_email) {
                ids.push(json!({ "hashedEmail": e }));
            }
            if let Some(p) = m.phone.as_deref().and_then(hashed_phone) {
                ids.push(json!({ "hashedPhoneNumber": p }));
            }
            (!ids.is_empty()).then(|| json!({ "create": { "userIdentifiers": ids } }))
        })
        .collect();
    ops.chunks(OPERATIONS_BATCH)
        .map(|chunk| json!({ "operations": chunk, "enablePartialFailure": true }))
        .collect()
}

/// A won deal as a `ClickConversion` (`conversionDateTime` as Google wants
/// it, `yyyy-mm-dd hh:mm:ss+00:00`). Pure.
pub fn click_conversion(
    conversion_action: &str,
    gclid: &str,
    won_at: DateTime<Utc>,
    value: f64,
    currency: &str,
) -> Option<Value> {
    if gclid.trim().is_empty() || conversion_action.trim().is_empty() {
        return None;
    }
    Some(json!({
        "conversions": [{
            "conversionAction": conversion_action,
            "gclid": gclid.trim(),
            "conversionDateTime": won_at.format("%Y-%m-%d %H:%M:%S+00:00").to_string(),
            "conversionValue": value,
            "currencyCode": currency.to_uppercase(),
        }],
        "partialFailure": true,
    }))
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A lead form answer's lead, when the body carries the right `google_key`;
/// `None` otherwise. Pure.
pub fn lead_from_webhook(body: &Value, google_key: &str) -> Option<Map<String, Value>> {
    let key = body.get("google_key").and_then(Value::as_str)?;
    if google_key.is_empty() || !same(key.as_bytes(), google_key.as_bytes()) {
        return None;
    }
    let mut columns = Map::new();
    for c in body
        .get("user_column_data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(id), Some(v)) = (
            c.get("column_id").and_then(Value::as_str),
            c.get("string_value").and_then(Value::as_str),
        ) {
            columns.insert(id.to_uppercase(), json!(v.trim()));
        }
    }
    let get = |k: &str| {
        columns
            .get(k)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let mut lead = Map::new();
    let name = get("FULL_NAME").map(str::to_owned).or_else(|| {
        let parts: Vec<&str> = [get("FIRST_NAME"), get("LAST_NAME")]
            .into_iter()
            .flatten()
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    });
    if let Some(name) = name {
        lead.insert("name".into(), json!(name));
    }
    for (from, to) in [
        ("EMAIL", "email"),
        ("PHONE_NUMBER", "phone"),
        ("COMPANY_NAME", "company_name"),
        ("CITY", "city"),
    ] {
        if let Some(v) = get(from) {
            lead.insert(to.into(), json!(v));
        }
    }
    lead.insert("source".into(), json!("google_lead_form"));
    if let Some(gclid) = body.get("gcl_id").and_then(Value::as_str) {
        lead.insert("gclid".into(), json!(gclid));
    }
    Some(lead)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ads_google_hashes_as_google_matches() {
        assert_eq!(
            hashed_email("Sara.Ali+news@Gmail.com"),
            Some(sha256_hex("saraali@gmail.com"))
        );
        assert_eq!(
            hashed_email("sara.ali@acme.sa"),
            Some(sha256_hex("sara.ali@acme.sa"))
        );
        assert_eq!(
            hashed_phone("+966 50 000 0001"),
            Some(sha256_hex("+966500000001"))
        );
        assert_eq!(hashed_phone("0500000001"), None, "not international");
    }

    #[test]
    fn ads_google_customer_match_skips_unconsented() {
        let members = vec![
            AudienceMember {
                email: Some("a@acme.sa".into()),
                phone: Some("+966500000001".into()),
                consented: true,
            },
            AudienceMember {
                email: Some("b@acme.sa".into()),
                phone: None,
                consented: false,
            },
        ];
        let requests = customer_match_operations(&members);
        let ops = requests[0]["operations"].as_array().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(
            ops[0]["create"]["userIdentifiers"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(!requests[0].to_string().contains("a@acme.sa"));
    }

    #[test]
    fn ads_google_lead_forms_and_conversions() {
        let body = json!({
            "lead_id": "L1", "google_key": "s3cret-key", "gcl_id": "G-123",
            "user_column_data": [
                { "column_id": "FULL_NAME", "string_value": "Sara Ali" },
                { "column_id": "EMAIL", "string_value": "sara@acme.sa" }
            ]
        });
        let lead = lead_from_webhook(&body, "s3cret-key").unwrap();
        assert_eq!(lead["name"], "Sara Ali");
        assert_eq!(lead["gclid"], "G-123");
        assert!(lead_from_webhook(&body, "other-key").is_none());
        let at = DateTime::from_timestamp(1_761_566_400, 0).unwrap();
        let c =
            click_conversion("customers/1/conversionActions/2", "G-123", at, 900.0, "sar").unwrap();
        assert_eq!(
            c["conversions"][0]["conversionDateTime"],
            "2025-10-27 12:00:00+00:00"
        );
        assert!(click_conversion("customers/1/conversionActions/2", " ", at, 1.0, "SAR").is_none());
    }
}
