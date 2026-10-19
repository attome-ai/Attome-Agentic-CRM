//! J4-T1: Unifonic SMS, as pure request and answer codecs (the sender in
//! [`crate::sms`] does the HTTP).
//!
//! Send: `POST https://el.cloud.unifonic.com/rest/SMS/messages` with a form
//! of `AppSid`, `SenderID`, `Body`, `Recipient` (international digits, no
//! `+`) and `responseType=JSON`. The answer carries `success`, `errorCode`
//! and `data.MessageID`. Delivery receipts are Unifonic's webhook, a JSON
//! body naming the message id and its status.

use serde_json::Value;

use crate::connector::adapters::sms::{DeliveryStatus, SendAnswer};

pub const SEND_URL: &str = "https://el.cloud.unifonic.com/rest/SMS/messages";

/// The recipient as Unifonic wants it: digits only. Pure.
pub fn recipient(e164: &str) -> String {
    e164.chars().filter(char::is_ascii_digit).collect()
}

/// The send form, in Unifonic's field names.
pub fn send_form<'a>(
    app_sid: &'a str,
    sender: &'a str,
    body: &'a str,
    to_digits: &'a str,
) -> Vec<(&'static str, &'a str)> {
    vec![
        ("AppSid", app_sid),
        ("SenderID", sender),
        ("Body", body),
        ("Recipient", to_digits),
        ("responseType", "JSON"),
    ]
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Reads a send answer.
pub fn parse_send(status: u16, body: &str) -> SendAnswer {
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if (200..300).contains(&status) && truthy(json.get("success")) {
        let id = json
            .pointer("/data/MessageID")
            .map(|v| v.to_string().trim_matches('"').to_owned());
        if let Some(id) = id.filter(|i| !i.is_empty() && i != "null") {
            return SendAnswer::Accepted {
                provider_message_id: id,
            };
        }
    }
    let code = json
        .get("errorCode")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| status.to_string());
    SendAnswer::Refused { code }
}

/// Maps a Unifonic message status.
pub fn status(raw: &str) -> Option<DeliveryStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "queued" | "pending" => Some(DeliveryStatus::Queued),
        "sent" => Some(DeliveryStatus::Sent),
        "delivered" => Some(DeliveryStatus::Delivered),
        "undeliverable" | "undelivered" | "expired" => Some(DeliveryStatus::Undelivered),
        "failed" | "rejected" => Some(DeliveryStatus::Failed),
        _ => None,
    }
}

/// Reads a delivery webhook: the message id, its status and any error.
pub fn parse_receipt(body: &Value) -> Option<(String, DeliveryStatus, Option<String>)> {
    let field = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| body.get(*n))
            .map(|v| v.to_string().trim_matches('"').to_owned())
    };
    let id = field(&["messageId", "MessageID", "message_id"])?;
    let state = status(&field(&["status", "Status"])?)?;
    Some((
        id,
        state,
        field(&["errorCode", "ErrorCode"]).filter(|c| !c.is_empty() && c != "null"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sms_unifonic_reads_recorded_answers() {
        let ok = r#"{"success": "true", "message": "", "errorCode": "ER-00",
                     "data": {"MessageID": 4785632, "Status": "Sent", "NumberOfUnits": 1}}"#;
        assert_eq!(
            parse_send(200, ok),
            SendAnswer::Accepted {
                provider_message_id: "4785632".into()
            }
        );
        let bad = r#"{"success": "false", "message": "Invalid sender ID", "errorCode": "ER-04", "data": null}"#;
        assert_eq!(
            parse_send(200, bad),
            SendAnswer::Refused {
                code: "ER-04".into()
            }
        );
        assert_eq!(recipient("+966 55 123 4567"), "966551234567");
    }

    #[test]
    fn sms_unifonic_reads_receipts() {
        let receipt = serde_json::json!({"messageId": 4785632, "status": "Delivered"});
        assert_eq!(
            parse_receipt(&receipt),
            Some(("4785632".into(), DeliveryStatus::Delivered, None))
        );
        let failed =
            serde_json::json!({"messageId": "77", "status": "Undeliverable", "errorCode": "DL-12"});
        assert_eq!(
            parse_receipt(&failed),
            Some((
                "77".into(),
                DeliveryStatus::Undelivered,
                Some("DL-12".into())
            ))
        );
        assert_eq!(parse_receipt(&serde_json::json!({"status": "Sent"})), None);
    }
}
