//! E19-T1: Meta lead ads, custom audiences and offline conversions, as pure
//! request and answer codecs (the caller does the HTTP with the page or
//! system-user token).
//!
//! - **Lead ads.** A `leadgen` change on the page webhook names the lead
//!   ([`leadgen_refs`]); `GET /{version}/{leadgen_id}?fields=field_data,...`
//!   ([`lead_url`]) answers its form fields, which [`lead_fields`] maps onto
//!   a lead's attributes (`name`, `email`, `phone`, `company_name`, `city`).
//! - **Audiences.** Only people who consented are uploaded, and only hashed:
//!   e-mail trimmed and lower-cased, phone reduced to its international
//!   digits, each SHA-256 in lower-case hex ([`hash_email`], [`hash_phone`]),
//!   in batches of at most [`AUDIENCE_BATCH`] (`POST /{audience_id}/users`,
//!   [`audience_payloads`]).
//! - **Offline conversions.** A won deal is a `Purchase` event for the
//!   Conversions API with the buyer's hashed e-mail and phone and the deal's
//!   value ([`conversion_event`]).

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// People per audience request (Meta's limit).
pub const AUDIENCE_BATCH: usize = 10_000;

/// Lower-case hex SHA-256 of `text`. Pure.
pub fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// An e-mail as Meta matches it, hashed; `None` for one without an `@`. Pure.
pub fn hash_email(email: &str) -> Option<String> {
    let normal = email.trim().to_lowercase();
    (normal.contains('@') && !normal.starts_with('@')).then(|| sha256_hex(&normal))
}

/// A phone as Meta matches it (international digits, no `+`), hashed; `None`
/// for fewer than seven digits. Pure.
pub fn hash_phone(phone: &str) -> Option<String> {
    let digits: String = phone.chars().filter(char::is_ascii_digit).collect();
    let digits = digits
        .strip_prefix("00")
        .map_or(digits.clone(), str::to_owned);
    (digits.len() >= 7).then(|| sha256_hex(&digits))
}

/// One person who may be uploaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudienceMember {
    pub email: Option<String>,
    pub phone: Option<String>,
    /// Whether the person consented to ad matching for the audience's purpose.
    pub consented: bool,
}

/// The `POST /{audience_id}/users` bodies for `members`: consenting people
/// with at least one usable identifier, hashed, in batches. Pure.
pub fn audience_payloads(members: &[AudienceMember]) -> Vec<Value> {
    let rows: Vec<Value> = members
        .iter()
        .filter(|m| m.consented)
        .filter_map(|m| {
            let email = m.email.as_deref().and_then(hash_email);
            let phone = m.phone.as_deref().and_then(hash_phone);
            (email.is_some() || phone.is_some())
                .then(|| json!([email.unwrap_or_default(), phone.unwrap_or_default()]))
        })
        .collect();
    rows.chunks(AUDIENCE_BATCH)
        .map(|chunk| json!({ "payload": { "schema": ["EMAIL_SHA256", "PHONE_SHA256"], "data": chunk } }))
        .collect()
}

/// A lead a `leadgen` change names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeadgenRef {
    pub leadgen_id: String,
    pub form_id: Option<String>,
    pub page_id: Option<String>,
    pub ad_id: Option<String>,
}

/// The leads a page webhook body names. Pure.
pub fn leadgen_refs(body: &Value) -> Vec<LeadgenRef> {
    body.get("entry")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("changes").and_then(Value::as_array))
        .flatten()
        .filter(|c| c.get("field").and_then(Value::as_str) == Some("leadgen"))
        .filter_map(|c| {
            let v = c.get("value")?;
            let text = |k: &str| {
                v.get(k).and_then(|x| match x {
                    Value::String(s) => Some(s.clone()),
                    Value::Number(n) => Some(n.to_string()),
                    _ => None,
                })
            };
            Some(LeadgenRef {
                leadgen_id: text("leadgen_id")?,
                form_id: text("form_id"),
                page_id: text("page_id"),
                ad_id: text("ad_id"),
            })
        })
        .collect()
}

/// The Graph API address of one lead's form answers. Pure.
pub fn lead_url(version: &str, leadgen_id: &str) -> String {
    format!(
        "https://graph.facebook.com/{version}/{leadgen_id}?fields=created_time,ad_id,form_id,field_data"
    )
}

/// A lead's attributes from its form answers (`field_data`). Pure.
pub fn lead_fields(body: &Value) -> Map<String, Value> {
    let mut answers: Map<String, Value> = Map::new();
    for f in body
        .get("field_data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let (Some(name), Some(value)) = (
            f.get("name").and_then(Value::as_str),
            f.pointer("/values/0").and_then(Value::as_str),
        ) {
            answers.insert(name.to_lowercase(), json!(value.trim()));
        }
    }
    let get = |k: &str| {
        answers
            .get(k)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
    };
    let mut lead = Map::new();
    let name = get("full_name").map(str::to_owned).or_else(|| {
        let parts: Vec<&str> = [get("first_name"), get("last_name")]
            .into_iter()
            .flatten()
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    });
    if let Some(name) = name {
        lead.insert("name".into(), json!(name));
    }
    for (from, to) in [
        ("email", "email"),
        ("phone_number", "phone"),
        ("company_name", "company_name"),
        ("city", "city"),
    ] {
        if let Some(v) = get(from) {
            lead.insert(to.into(), json!(v));
        }
    }
    lead.insert("source".into(), json!("meta_lead_ads"));
    lead
}

/// A won deal as a Conversions API `Purchase` event. Pure.
pub fn conversion_event(
    event_id: &str,
    won_at: DateTime<Utc>,
    email: Option<&str>,
    phone: Option<&str>,
    value: f64,
    currency: &str,
) -> Option<Value> {
    let em = email.and_then(hash_email);
    let ph = phone.and_then(hash_phone);
    if em.is_none() && ph.is_none() {
        return None;
    }
    let mut user = Map::new();
    if let Some(em) = em {
        user.insert("em".into(), json!([em]));
    }
    if let Some(ph) = ph {
        user.insert("ph".into(), json!([ph]));
    }
    Some(json!({ "data": [{
        "event_name": "Purchase",
        "event_time": won_at.timestamp(),
        "event_id": event_id,
        "action_source": "system_generated",
        "user_data": user,
        "custom_data": { "currency": currency.to_uppercase(), "value": value },
    }] }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ads_meta_hashes_normalised_identifiers() {
        assert_eq!(
            hash_email("  Sara@Example.COM "),
            Some(sha256_hex("sara@example.com"))
        );
        assert_eq!(hash_email("not-an-email"), None);
        assert_eq!(
            hash_phone("+966 50 000 0001"),
            Some(sha256_hex("966500000001"))
        );
        assert_eq!(
            hash_phone("00966500000001"),
            Some(sha256_hex("966500000001"))
        );
        assert_eq!(hash_phone("123"), None);
        assert_eq!(sha256_hex("a").len(), 64);
    }

    #[test]
    fn ads_meta_uploads_only_consenting_people_hashed() {
        let members = vec![
            AudienceMember {
                email: Some("a@x.sa".into()),
                phone: None,
                consented: true,
            },
            AudienceMember {
                email: Some("b@x.sa".into()),
                phone: None,
                consented: false,
            },
            AudienceMember {
                email: None,
                phone: Some("+966500000002".into()),
                consented: true,
            },
            AudienceMember {
                email: None,
                phone: None,
                consented: true,
            },
        ];
        let payloads = audience_payloads(&members);
        assert_eq!(payloads.len(), 1);
        let data = payloads[0]["payload"]["data"].as_array().unwrap();
        assert_eq!(data.len(), 2, "the unconsented and the empty are left out");
        assert_eq!(data[0][0], json!(sha256_hex("a@x.sa")));
        assert_eq!(data[1][1], json!(sha256_hex("966500000002")));
        assert!(
            !payloads[0].to_string().contains("a@x.sa"),
            "nothing goes in clear"
        );
    }

    #[test]
    fn ads_meta_lead_ads_become_leads() {
        let hook = json!({ "object": "page", "entry": [{ "id": "p1", "changes": [
            { "field": "leadgen", "value": { "leadgen_id": 444, "form_id": "f1", "page_id": "p1", "ad_id": "a1" } },
            { "field": "feed", "value": {} }
        ] }] });
        let refs = leadgen_refs(&hook);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].leadgen_id, "444");
        assert!(lead_url("v21.0", "444").contains("/444?fields="));
        let answer = json!({ "field_data": [
            { "name": "first_name", "values": ["Sara"] },
            { "name": "last_name", "values": ["Ali"] },
            { "name": "email", "values": ["sara@acme.sa"] },
            { "name": "phone_number", "values": ["+966500000001"] }
        ] });
        let lead = lead_fields(&answer);
        assert_eq!(lead["name"], "Sara Ali");
        assert_eq!(lead["phone"], "+966500000001");
        assert_eq!(lead["source"], "meta_lead_ads");
        let at = DateTime::from_timestamp(1_761_566_400, 0).unwrap();
        let event =
            conversion_event("deal-1", at, Some("sara@acme.sa"), None, 1500.0, "sar").unwrap();
        assert_eq!(event["data"][0]["custom_data"]["currency"], "SAR");
        assert_eq!(
            event["data"][0]["user_data"]["em"][0],
            json!(sha256_hex("sara@acme.sa"))
        );
        assert!(conversion_event("d", at, None, None, 1.0, "SAR").is_none());
    }
}
