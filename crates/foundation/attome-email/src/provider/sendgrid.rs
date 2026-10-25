//! Z8-T1: SendGrid's v3 mail send. SendGrid takes the message as JSON, not
//! MIME, so the body, files and threading headers are sent as its fields;
//! the answer is `202 Accepted` with the id in `X-Message-Id`.

use attome_config::SendGridSettings;
use serde_json::{Map, Value, json};

use super::{
    EmailProvider, OutgoingEmail, ProviderMessageId, SENDGRID, classify_http_status,
    classify_transport, http_client,
};
use crate::error::SendError;

const DEFAULT_ENDPOINT: &str = "https://api.sendgrid.com";
const PATH: &str = "/v3/mail/send";

pub struct SendGrid<'a> {
    pub settings: &'a SendGridSettings,
}

impl std::fmt::Debug for SendGrid<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendGrid").finish_non_exhaustive()
    }
}

/// The v3 request body for `msg`.
pub(crate) fn request_body(msg: &OutgoingEmail<'_>) -> Value {
    let message = msg.message;
    let mut from = Map::new();
    from.insert("email".into(), json!(msg.from.email.to_string()));
    if let Some(name) = &msg.from.name {
        from.insert("name".into(), json!(name));
    }
    let mut content = vec![json!({ "type": "text/plain", "value": message.text_body })];
    if let Some(html) = &message.html_body {
        content.push(json!({ "type": "text/html", "value": html }));
    }
    let mut headers = Map::new();
    for (name, value) in [
        ("Message-ID", message.message_id.as_deref()),
        ("In-Reply-To", message.in_reply_to.as_deref()),
        ("References", message.references.as_deref()),
        ("X-Attome-Original-To", msg.original_to),
    ] {
        if let Some(value) = value {
            headers.insert(name.into(), json!(value));
        }
    }
    let mut body = json!({
        "personalizations": [{ "to": [{ "email": msg.to.email.to_string() }] }],
        "from": from,
        "subject": message.subject,
        "content": content,
    });
    // E3-T1: one-click unsubscribe for bulk mail (RFC 8058).
    if let Some(url) = &message.list_unsubscribe {
        headers.insert("List-Unsubscribe".into(), json!(format!("<{url}>")));
        headers.insert(
            "List-Unsubscribe-Post".into(),
            json!("List-Unsubscribe=One-Click"),
        );
    }
    if !headers.is_empty() {
        body["headers"] = Value::Object(headers);
    }
    if !message.attachments.is_empty() {
        body["attachments"] = message
            .attachments
            .iter()
            .map(|file| {
                json!({
                    "content": file.content_base64,
                    "filename": file.filename,
                    "type": file.content_type,
                    "disposition": "attachment",
                })
            })
            .collect();
    }
    body
}

impl EmailProvider for SendGrid<'_> {
    fn name(&self) -> &str {
        SENDGRID
    }

    async fn send(&self, msg: &OutgoingEmail<'_>) -> Result<ProviderMessageId, SendError> {
        let endpoint = self
            .settings
            .endpoint
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .unwrap_or(DEFAULT_ENDPOINT)
            .trim_end_matches('/');
        let response = http_client(endpoint)?
            .post(format!("{endpoint}{PATH}"))
            .bearer_auth(self.settings.api_key.expose())
            .json(&request_body(msg))
            .send()
            .await
            .map_err(|e| classify_transport(SENDGRID, &e))?;
        let status = response.status().as_u16();
        let id = response
            .headers()
            .get("x-message-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        if !(200..300).contains(&status) {
            let text = response.text().await.unwrap_or_default();
            return Err(classify_http_status(SENDGRID, status, &text));
        }
        Ok(ProviderMessageId(id))
    }
}

#[cfg(test)]
mod tests {
    use lettre::message::Mailbox;

    use super::*;
    use crate::message::{EmailAttachment, EmailMessage};
    use crate::provider::mock::serve_once;

    fn message() -> EmailMessage {
        EmailMessage {
            to: "user@example.com".into(),
            subject: "Hello".into(),
            text_body: "body".into(),
            html_body: Some("<p>body</p>".into()),
            delivery_id: None,
            from_override: None,
            message_id: Some("<m1@example.com>".into()),
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: vec![EmailAttachment {
                filename: "a.pdf".into(),
                content_type: "application/pdf".into(),
                content_base64: "JVBERi0xLjQK".into(),
            }],
            stream: Default::default(),
            list_unsubscribe: None,
        }
    }

    async fn send_to(url: String, msg: &EmailMessage) -> Result<ProviderMessageId, SendError> {
        let settings = SendGridSettings {
            api_key: "SG.test-key".into(),
            endpoint: Some(url),
        };
        let from: Mailbox = "Attome <noreply@example.com>".parse().unwrap();
        let to: Mailbox = msg.to.parse().unwrap();
        let mime = lettre::Message::builder()
            .from(from.clone())
            .to(to.clone())
            .subject("Hello")
            .body("body".to_string())
            .unwrap();
        let outgoing = OutgoingEmail {
            message: msg,
            mime: &mime,
            from: &from,
            to: &to,
            original_to: None,
        };
        SendGrid {
            settings: &settings,
        }
        .send(&outgoing)
        .await
    }

    #[tokio::test]
    async fn sendgrid_accepts_a_v3_mail_send() {
        let (url, request) = serve_once(202, "x-message-id: sg-123\r\n", "").await;
        let msg = message();
        let id = send_to(url, &msg).await.unwrap();
        assert_eq!(id, ProviderMessageId(Some("sg-123".into())));
        let request = request.await.unwrap();
        assert!(request.starts_with("POST /v3/mail/send "), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer sg.test-key")
        );
        let body = &request[request.find("\r\n\r\n").unwrap() + 4..];
        let json: Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            json["personalizations"][0]["to"][0]["email"],
            "user@example.com"
        );
        assert_eq!(json["from"]["email"], "noreply@example.com");
        assert_eq!(json["from"]["name"], "Attome");
        assert_eq!(json["content"][1]["type"], "text/html");
        assert_eq!(json["headers"]["Message-ID"], "<m1@example.com>");
        assert_eq!(json["attachments"][0]["filename"], "a.pdf");
    }

    #[tokio::test]
    async fn sendgrid_refusals_classify() {
        let msg = message();
        let (url, _) = serve_once(401, "", r#"{"errors":[{"message":"bad key"}]}"#).await;
        assert!(matches!(
            send_to(url, &msg).await,
            Err(SendError::Config { .. })
        ));
        let (url, _) = serve_once(500, "", "").await;
        assert!(matches!(
            send_to(url, &msg).await,
            Err(SendError::Transient { .. })
        ));
    }
}
