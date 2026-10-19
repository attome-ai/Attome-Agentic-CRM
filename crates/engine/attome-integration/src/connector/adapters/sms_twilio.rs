//! J4-T1: Twilio Programmable Messaging, as pure request and answer codecs.
//! The sender ([`crate::sms`]) does the HTTP; everything here is testable
//! with recorded answers.
//!
//! Send: `POST https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json`
//! with HTTP basic auth (account SID, auth token) and a form of `To`, `From`,
//! `Body` and `StatusCallback`. Receipts: Twilio posts a form with
//! `MessageSid`, `MessageStatus` and, on failure, `ErrorCode` to the
//! `StatusCallback` URL.

use serde_json::Value;

use crate::connector::adapters::sms::{DeliveryStatus, SendAnswer};

/// The send URL for an account.
pub fn send_url(account_sid: &str) -> String {
    format!("https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json")
}

/// The send form, in Twilio's field names.
pub fn send_form<'a>(
    to: &'a str,
    from: &'a str,
    body: &'a str,
    status_callback: &'a str,
) -> Vec<(&'static str, &'a str)> {
    vec![
        ("To", to),
        ("From", from),
        ("Body", body),
        ("StatusCallback", status_callback),
    ]
}

/// Reads a send answer: the message SID on success, the error otherwise.
pub fn parse_send(status: u16, body: &str) -> SendAnswer {
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        if let Some(sid) = json.get("sid").and_then(Value::as_str) {
            return SendAnswer::Accepted {
                provider_message_id: sid.to_owned(),
            };
        }
    }
    let code = json
        .get("code")
        .map(|c| c.to_string().trim_matches('"').to_owned())
        .unwrap_or_else(|| status.to_string());
    SendAnswer::Refused { code }
}

/// Maps Twilio's `MessageStatus`.
pub fn status(raw: &str) -> Option<DeliveryStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "accepted" | "queued" | "scheduled" | "sending" => Some(DeliveryStatus::Queued),
        "sent" => Some(DeliveryStatus::Sent),
        "delivered" | "read" => Some(DeliveryStatus::Delivered),
        "undelivered" => Some(DeliveryStatus::Undelivered),
        "failed" | "canceled" => Some(DeliveryStatus::Failed),
        _ => None,
    }
}

/// Reads a status callback form: the message SID, its status and any error.
pub fn parse_receipt(
    form: &[(String, String)],
) -> Option<(String, DeliveryStatus, Option<String>)> {
    let get = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let sid = get("MessageSid").or_else(|| get("SmsSid"))?;
    let state = status(&get("MessageStatus").or_else(|| get("SmsStatus"))?)?;
    Some((sid, state, get("ErrorCode").filter(|c| !c.is_empty())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_twilio_reads_recorded_answers() {
        // Recorded from the Messages API.
        let ok = r#"{"sid": "SM1a2b3c", "status": "queued", "num_segments": "1"}"#;
        assert_eq!(
            parse_send(201, ok),
            SendAnswer::Accepted {
                provider_message_id: "SM1a2b3c".into()
            }
        );
        let bad = r#"{"code": 21211, "message": "The 'To' number is not a valid phone number.", "status": 400}"#;
        assert_eq!(
            parse_send(400, bad),
            SendAnswer::Refused {
                code: "21211".into()
            }
        );
        assert_eq!(
            parse_send(500, "oops"),
            SendAnswer::Refused { code: "500".into() }
        );
        assert_eq!(
            send_url("AC123"),
            "https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json"
        );
    }

    #[test]
    fn sms_twilio_reads_receipts() {
        let form = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            parse_receipt(&form(&[
                ("MessageSid", "SM1"),
                ("MessageStatus", "delivered")
            ])),
            Some(("SM1".into(), DeliveryStatus::Delivered, None))
        );
        assert_eq!(
            parse_receipt(&form(&[
                ("MessageSid", "SM1"),
                ("MessageStatus", "undelivered"),
                ("ErrorCode", "30003")
            ])),
            Some((
                "SM1".into(),
                DeliveryStatus::Undelivered,
                Some("30003".into())
            ))
        );
        assert_eq!(parse_receipt(&form(&[("MessageStatus", "sent")])), None);
        assert_eq!(status("weird"), None);
    }
}
