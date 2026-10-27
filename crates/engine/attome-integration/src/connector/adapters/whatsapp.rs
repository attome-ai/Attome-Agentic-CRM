//! J5-T1: the WhatsApp Cloud API, as pure request and answer codecs (the
//! sender does the HTTP, as for SMS).
//!
//! **Send.** `POST https://graph.facebook.com/{version}/{phone_number_id}/messages`
//! with a bearer token and a JSON body ([`message_body`]): text (with or
//! without a link preview), an approved template with its language and body
//! parameters, media (image, document, audio, video) by link or uploaded id,
//! or an interactive message with up to three reply buttons or a list. The
//! answer's `messages[0].id` is the provider message id; an `error` object's
//! `code` is the refusal ([`parse_send`]).
//!
//! **The 24-hour window.** WhatsApp lets a business send a free-form message
//! only within 24 hours of the person's last message; outside it only an
//! approved template goes ([`check_window`]). The caller passes the time of
//! the person's last inbound message.
//!
//! **Receive.** Calls arrive at an inbound hook with the `whatsapp` preset
//! (`X-Hub-Signature-256` with the app secret, and Meta's `hub.verify_token`
//! subscription check, as the `meta` preset). [`parse_webhook`] reads the
//! messages (text, button and list replies, media ids, locations) and the
//! delivery statuses out of `entry[].changes[].value`.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};

use crate::connector::adapters::sms::{DeliveryStatus, SendAnswer};

/// The Graph API version the messages endpoint is called with.
pub const DEFAULT_GRAPH_VERSION: &str = "v21.0";
/// How long after the person's last message free-form messages may go.
pub const SERVICE_WINDOW_HOURS: i64 = 24;
/// Reply buttons one interactive message may carry.
pub const MAX_BUTTONS: usize = 3;

/// The messages endpoint of a phone number. Pure.
pub fn send_url(version: &str, phone_number_id: &str) -> String {
    format!("https://graph.facebook.com/{version}/{phone_number_id}/messages")
}

/// The recipient as WhatsApp wants it: international digits, no `+`. Pure.
pub fn recipient(e164: &str) -> String {
    e164.chars().filter(char::is_ascii_digit).collect()
}

/// Where a media message's file comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaSource {
    /// A public HTTPS link.
    Link(String),
    /// A media id from an earlier upload.
    Id(String),
}

/// One outbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outbound {
    Text {
        body: String,
        preview_url: bool,
    },
    Template {
        name: String,
        language: String,
        parameters: Vec<String>,
    },
    Media {
        /// `image`, `document`, `audio` or `video`.
        kind: String,
        source: MediaSource,
        caption: Option<String>,
        filename: Option<String>,
    },
    Buttons {
        body: String,
        /// `(id, title)`, at most [`MAX_BUTTONS`].
        buttons: Vec<(String, String)>,
    },
    List {
        body: String,
        button: String,
        /// `(id, title)` rows of one section.
        rows: Vec<(String, String)>,
    },
}

impl Outbound {
    /// Whether this message may go outside the 24-hour window.
    pub fn is_template(&self) -> bool {
        matches!(self, Self::Template { .. })
    }
}

/// Why a message may not be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Outside the 24-hour window and not a template.
    OutsideWindow,
    /// The message itself is malformed.
    Invalid(String),
}

/// Whether `message` may go now, given the person's last inbound message. Pure.
pub fn check_window(
    message: &Outbound,
    last_inbound: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Result<(), Refusal> {
    if message.is_template() {
        return Ok(());
    }
    match last_inbound {
        Some(at) if now - at < Duration::hours(SERVICE_WINDOW_HOURS) && at <= now => Ok(()),
        _ => Err(Refusal::OutsideWindow),
    }
}

/// The JSON body of a send to `to` (E.164). Pure.
pub fn message_body(to: &str, message: &Outbound) -> Result<Value, Refusal> {
    let mut body = json!({
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": recipient(to),
    });
    match message {
        Outbound::Text {
            body: text,
            preview_url,
        } => {
            if text.trim().is_empty() || text.chars().count() > 4096 {
                return Err(Refusal::Invalid(
                    "a text message is 1 to 4096 characters".into(),
                ));
            }
            body["type"] = json!("text");
            body["text"] = json!({ "body": text, "preview_url": preview_url });
        }
        Outbound::Template {
            name,
            language,
            parameters,
        } => {
            if name.trim().is_empty() || language.trim().is_empty() {
                return Err(Refusal::Invalid(
                    "a template needs its name and language".into(),
                ));
            }
            let mut template = json!({ "name": name, "language": { "code": language } });
            if !parameters.is_empty() {
                let params: Vec<Value> = parameters
                    .iter()
                    .map(|p| json!({ "type": "text", "text": p }))
                    .collect();
                template["components"] = json!([{ "type": "body", "parameters": params }]);
            }
            body["type"] = json!("template");
            body["template"] = template;
        }
        Outbound::Media {
            kind,
            source,
            caption,
            filename,
        } => {
            if !["image", "document", "audio", "video"].contains(&kind.as_str()) {
                return Err(Refusal::Invalid(format!("{kind} is not a media type")));
            }
            let mut media = match source {
                MediaSource::Link(link) if link.starts_with("https://") => json!({ "link": link }),
                MediaSource::Link(_) => {
                    return Err(Refusal::Invalid("a media link is https".into()));
                }
                MediaSource::Id(id) => json!({ "id": id }),
            };
            if let Some(caption) = caption.as_deref().filter(|_| kind != "audio") {
                media["caption"] = json!(caption);
            }
            if let Some(filename) = filename.as_deref().filter(|_| kind == "document") {
                media["filename"] = json!(filename);
            }
            body["type"] = json!(kind);
            body[kind.as_str()] = media;
        }
        Outbound::Buttons {
            body: text,
            buttons,
        } => {
            if buttons.is_empty() || buttons.len() > MAX_BUTTONS {
                return Err(Refusal::Invalid(format!(
                    "an interactive message has 1 to {MAX_BUTTONS} buttons"
                )));
            }
            let buttons: Vec<Value> = buttons
                .iter()
                .map(
                    |(id, title)| json!({ "type": "reply", "reply": { "id": id, "title": title } }),
                )
                .collect();
            body["type"] = json!("interactive");
            body["interactive"] = json!({
                "type": "button",
                "body": { "text": text },
                "action": { "buttons": buttons },
            });
        }
        Outbound::List {
            body: text,
            button,
            rows,
        } => {
            if rows.is_empty() || rows.len() > 10 {
                return Err(Refusal::Invalid("a list has 1 to 10 rows".into()));
            }
            let rows: Vec<Value> = rows
                .iter()
                .map(|(id, title)| json!({ "id": id, "title": title }))
                .collect();
            body["type"] = json!("interactive");
            body["interactive"] = json!({
                "type": "list",
                "body": { "text": text },
                "action": { "button": button, "sections": [{ "rows": rows }] },
            });
        }
    }
    Ok(body)
}

/// Reads a send answer.
pub fn parse_send(status: u16, body: &str) -> SendAnswer {
    let json: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    if (200..300).contains(&status)
        && let Some(id) = json.pointer("/messages/0/id").and_then(Value::as_str)
        && !id.is_empty()
    {
        return SendAnswer::Accepted {
            provider_message_id: id.to_owned(),
        };
    }
    let code = json
        .pointer("/error/code")
        .map(|c| c.to_string().trim_matches('"').to_owned())
        .unwrap_or_else(|| status.to_string());
    SendAnswer::Refused { code }
}

/// Maps a WhatsApp message status.
pub fn status(raw: &str) -> Option<DeliveryStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "sent" => Some(DeliveryStatus::Sent),
        "delivered" | "read" => Some(DeliveryStatus::Delivered),
        "failed" => Some(DeliveryStatus::Failed),
        _ => None,
    }
}

/// One message a person sent.
#[derive(Debug, Clone, PartialEq)]
pub struct Inbound {
    /// The provider message id.
    pub id: String,
    /// The sender, international digits.
    pub from: String,
    pub at: Option<DateTime<Utc>>,
    /// `text`, `button`, `interactive`, `image`, `document`, `audio`,
    /// `video`, `location` or what WhatsApp sent.
    pub kind: String,
    /// The text, the button or list reply's title, or a media caption.
    pub text: Option<String>,
    /// A button or list reply's id.
    pub reply_id: Option<String>,
    /// A media message's media id.
    pub media_id: Option<String>,
}

/// One delivery status: the message id, its status and any error code.
pub type StatusUpdate = (String, DeliveryStatus, Option<String>);

fn str_at(v: &Value, pointer: &str) -> Option<String> {
    v.pointer(pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn unix_time(v: &Value) -> Option<DateTime<Utc>> {
    let secs = match v {
        Value::String(s) => s.parse::<i64>().ok()?,
        Value::Number(n) => n.as_i64()?,
        _ => return None,
    };
    DateTime::from_timestamp(secs, 0)
}

fn inbound(m: &Value) -> Option<Inbound> {
    let id = str_at(m, "/id")?;
    let from = str_at(m, "/from")?;
    let kind = str_at(m, "/type").unwrap_or_else(|| "unknown".into());
    let (text, reply_id, media_id) = match kind.as_str() {
        "text" => (str_at(m, "/text/body"), None, None),
        "button" => (
            str_at(m, "/button/text"),
            str_at(m, "/button/payload"),
            None,
        ),
        "interactive" => {
            let reply = m
                .pointer("/interactive/button_reply")
                .or_else(|| m.pointer("/interactive/list_reply"));
            (
                reply.and_then(|r| str_at(r, "/title")),
                reply.and_then(|r| str_at(r, "/id")),
                None,
            )
        }
        "image" | "document" | "audio" | "video" | "sticker" => (
            str_at(m, &format!("/{kind}/caption")),
            None,
            str_at(m, &format!("/{kind}/id")),
        ),
        "location" => {
            let lat = m.pointer("/location/latitude").and_then(Value::as_f64);
            let lng = m.pointer("/location/longitude").and_then(Value::as_f64);
            (lat.zip(lng).map(|(a, b)| format!("{a},{b}")), None, None)
        }
        _ => (None, None, None),
    };
    Some(Inbound {
        id,
        from,
        at: m.get("timestamp").and_then(unix_time),
        kind,
        text,
        reply_id,
        media_id,
    })
}

/// The messages and delivery statuses of a webhook body. Pure.
pub fn parse_webhook(body: &Value) -> (Vec<Inbound>, Vec<StatusUpdate>) {
    let mut messages = Vec::new();
    let mut statuses = Vec::new();
    let values = body
        .get("entry")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|e| e.get("changes").and_then(Value::as_array))
        .flatten()
        .filter_map(|c| c.get("value"));
    for value in values {
        for m in value
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            messages.extend(inbound(m));
        }
        for s in value
            .get("statuses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let (Some(id), Some(st)) = (
                str_at(s, "/id"),
                s.get("status").and_then(Value::as_str).and_then(status),
            ) {
                let error = s
                    .pointer("/errors/0/code")
                    .map(|c| c.to_string().trim_matches('"').to_owned());
                statuses.push((id, st, error));
            }
        }
    }
    (messages, statuses)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[test]
    fn whatsapp_free_form_only_inside_the_window() {
        let text = Outbound::Text {
            body: "Hi".into(),
            preview_url: false,
        };
        let template = Outbound::Template {
            name: "order_update".into(),
            language: "ar".into(),
            parameters: vec!["1001".into()],
        };
        let now = at("2026-11-02T12:00:00Z");
        assert_eq!(
            check_window(&text, Some(at("2026-11-02T00:00:00Z")), now),
            Ok(())
        );
        assert_eq!(
            check_window(&text, Some(at("2026-11-01T11:59:00Z")), now),
            Err(Refusal::OutsideWindow)
        );
        assert_eq!(check_window(&text, None, now), Err(Refusal::OutsideWindow));
        assert_eq!(check_window(&template, None, now), Ok(()));
    }

    #[test]
    fn whatsapp_message_bodies_follow_the_cloud_api() {
        let body = message_body(
            "+966 50 000 0001",
            &Outbound::Text {
                body: "Hi".into(),
                preview_url: true,
            },
        )
        .unwrap();
        assert_eq!(body["to"], "966500000001");
        assert_eq!(body["type"], "text");
        assert_eq!(body["text"]["preview_url"], true);

        let t = message_body(
            "+966500000001",
            &Outbound::Template {
                name: "order_update".into(),
                language: "ar".into(),
                parameters: vec!["1001".into()],
            },
        )
        .unwrap();
        assert_eq!(t["template"]["language"]["code"], "ar");
        assert_eq!(
            t["template"]["components"][0]["parameters"][0]["text"],
            "1001"
        );

        let doc = message_body(
            "+966500000001",
            &Outbound::Media {
                kind: "document".into(),
                source: MediaSource::Link("https://example.com/invoice.pdf".into()),
                caption: Some("Invoice".into()),
                filename: Some("invoice.pdf".into()),
            },
        )
        .unwrap();
        assert_eq!(doc["document"]["filename"], "invoice.pdf");
        assert!(
            message_body(
                "+966500000001",
                &Outbound::Media {
                    kind: "image".into(),
                    source: MediaSource::Link("http://x".into()),
                    caption: None,
                    filename: None
                },
            )
            .is_err()
        );

        let four = (0..4).map(|n| (format!("b{n}"), format!("B{n}"))).collect();
        assert!(
            message_body(
                "+1",
                &Outbound::Buttons {
                    body: "Pick".into(),
                    buttons: four
                }
            )
            .is_err()
        );
        let two = vec![("yes".into(), "Yes".into()), ("no".into(), "No".into())];
        let b = message_body(
            "+1",
            &Outbound::Buttons {
                body: "Pick".into(),
                buttons: two,
            },
        )
        .unwrap();
        assert_eq!(
            b["interactive"]["action"]["buttons"][1]["reply"]["id"],
            "no"
        );
    }

    #[test]
    fn whatsapp_send_answers_and_webhooks_parse() {
        assert_eq!(
            parse_send(
                200,
                r#"{"messaging_product":"whatsapp","messages":[{"id":"wamid.HBgM"}]}"#
            ),
            SendAnswer::Accepted {
                provider_message_id: "wamid.HBgM".into()
            }
        );
        assert_eq!(
            parse_send(
                400,
                r#"{"error":{"message":"Re-engagement message","code":131047}}"#
            ),
            SendAnswer::Refused {
                code: "131047".into()
            }
        );
        let hook = json!({
            "object": "whatsapp_business_account",
            "entry": [{ "id": "1", "changes": [{ "field": "messages", "value": {
                "messaging_product": "whatsapp",
                "messages": [
                    { "from": "966500000001", "id": "wamid.1", "timestamp": "1761566400", "type": "text", "text": { "body": "مرحبا" } },
                    { "from": "966500000001", "id": "wamid.2", "timestamp": "1761566460", "type": "interactive",
                      "interactive": { "type": "button_reply", "button_reply": { "id": "yes", "title": "Yes" } } },
                    { "from": "966500000001", "id": "wamid.3", "timestamp": "1761566470", "type": "image", "image": { "id": "media-9", "caption": "Receipt" } }
                ],
                "statuses": [{ "id": "wamid.out", "status": "read" }, { "id": "wamid.bad", "status": "failed", "errors": [{ "code": 131026 }] }]
            } }] }]
        });
        let (messages, statuses) = parse_webhook(&hook);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].text.as_deref(), Some("مرحبا"));
        assert_eq!(messages[0].at, DateTime::from_timestamp(1_761_566_400, 0));
        assert_eq!(messages[1].reply_id.as_deref(), Some("yes"));
        assert_eq!(messages[2].media_id.as_deref(), Some("media-9"));
        assert_eq!(
            statuses[0],
            ("wamid.out".into(), DeliveryStatus::Delivered, None)
        );
        assert_eq!(
            statuses[1],
            (
                "wamid.bad".into(),
                DeliveryStatus::Failed,
                Some("131026".into())
            )
        );
        assert_eq!(
            send_url("v21.0", "123"),
            "https://graph.facebook.com/v21.0/123/messages"
        );
    }
}
