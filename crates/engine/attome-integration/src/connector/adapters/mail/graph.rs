//! J2-T1: a Microsoft 365 mailbox through Graph's delta query.
//!
//! The app reads one mailbox with an application token (client credentials
//! for `tenant`), `GET /users/{mailbox}/mailFolders/inbox/messages/delta`,
//! asking for plain-text bodies. Pages are followed until the delta link (or
//! [`super::MAX_PER_PULL`] messages, when the page link is the cursor); the
//! next pull starts from the cursor. Messages marked `@removed` are skipped.

use std::time::Duration;

use attome_types::AppError;
use serde_json::Value;

use super::{MAX_PER_PULL, MailAddress, MailAttachment, MailMessage, bare_id, required};
use crate::system::IntegrationSystem;

const GRAPH: &str = "https://graph.microsoft.com/v1.0";
const TIMEOUT: Duration = Duration::from_secs(30);
const SELECT: &str = "subject,from,toRecipients,ccRecipients,receivedDateTime,internetMessageId,\
                      body,hasAttachments,conversationId,sensitivity";

fn address(v: &Value) -> Option<MailAddress> {
    let e = v.get("emailAddress")?;
    let address = e.get("address")?.as_str()?.trim().to_owned();
    (!address.is_empty()).then(|| MailAddress {
        name: e
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .filter(|n| !n.is_empty() && *n != address),
        address,
    })
}

fn addresses(v: Option<&Value>) -> Vec<MailAddress> {
    v.and_then(Value::as_array)
        .map(|list| list.iter().filter_map(address).collect())
        .unwrap_or_default()
}

/// One page of a delta answer: its messages, the next page and the delta
/// link. Pure.
pub fn parse_page(body: &str) -> Option<(Vec<MailMessage>, Option<String>, Option<String>)> {
    let v: Value = serde_json::from_str(body).ok()?;
    let items = v.get("value")?.as_array()?;
    let messages = items
        .iter()
        .filter(|m| m.get("@removed").is_none())
        .filter_map(|m| {
            let id = m.get("id")?.as_str()?.to_owned();
            let body = m.get("body");
            let content = body
                .and_then(|b| b.get("content"))
                .and_then(Value::as_str)
                .map(str::to_owned);
            let is_html = body
                .and_then(|b| b.get("contentType"))
                .and_then(Value::as_str)
                .is_some_and(|t| t.eq_ignore_ascii_case("html"));
            Some(MailMessage {
                provider: "graph",
                id,
                message_id: m
                    .get("internetMessageId")
                    .and_then(Value::as_str)
                    .and_then(bare_id),
                thread_hint: m
                    .get("conversationId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                from: m.get("from").and_then(address),
                to: addresses(m.get("toRecipients")),
                cc: addresses(m.get("ccRecipients")),
                subject: m.get("subject").and_then(Value::as_str).map(str::to_owned),
                date: m
                    .get("receivedDateTime")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                text: if is_html { None } else { content.clone() },
                html: if is_html { content } else { None },
                private: m
                    .get("sensitivity")
                    .and_then(Value::as_str)
                    .is_some_and(|v| {
                        v.eq_ignore_ascii_case("private") || v.eq_ignore_ascii_case("confidential")
                    }),
                has_attachments: m
                    .get("hasAttachments")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                ..MailMessage::default()
            })
        })
        .collect();
    let link = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    Some((messages, link("@odata.nextLink"), link("@odata.deltaLink")))
}

/// The attachments in an attachments list answer. Pure.
pub fn parse_attachments(message_id: &str, body: &str) -> Vec<MailAttachment> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    v.get("value")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|a| {
                    Some(MailAttachment {
                        name: a.get("name").and_then(Value::as_str).map(str::to_owned),
                        content_type: a
                            .get("contentType")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        size: a.get("size").and_then(Value::as_u64).unwrap_or(0),
                        reference: format!("graph:{message_id}/{}", a.get("id")?.as_str()?),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether a cursor is a Graph link this reader may follow. Pure.
pub fn cursor_ok(cursor: &str) -> bool {
    cursor.starts_with("https://graph.microsoft.com/")
}

/// Q21-T1: the provider's public API only.
fn client() -> Result<attome_outbound::http::Outbound, AppError> {
    attome_outbound::http::client(
        attome_outbound::http::Purpose::public("microsoft-graph"),
        |b| b.timeout(TIMEOUT),
    )
    .map_err(AppError::internal)
}

async fn app_token(
    cfg: &Value,
    system: &IntegrationSystem,
    secret: &str,
) -> Result<String, AppError> {
    let tenant = required(cfg, system, "tenant")?;
    if !tenant
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err(AppError::Validation(
            "tenant: not a tenant id or domain".into(),
        ));
    }
    let res = client()?
        .post(format!(
            "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        ))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", required(cfg, system, "client_id")?),
            ("client_secret", secret),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::Validation(format!("Microsoft refused the app token ({status})")))
}

pub(super) async fn pull(
    system: &IntegrationSystem,
    cfg: &Value,
    secret: &str,
    cursor: Option<&str>,
) -> Result<(Vec<MailMessage>, Option<String>), AppError> {
    let mailbox = required(cfg, system, "mailbox")?;
    let token = app_token(cfg, system, secret).await?;
    let path = format!(
        "users/{}",
        url::form_urlencoded::byte_serialize(mailbox.as_bytes()).collect::<String>()
    );
    read(&token, &path, "inbox", cursor).await
}

/// Reads one folder (`inbox`, `sentitems`) of a mailbox from `cursor` with
/// `token`: `mailbox_path` is `me` for the person the token belongs to
/// (D15-T2), or `users/{address}` for an app reading a shared mailbox.
pub async fn read(
    token: &str,
    mailbox_path: &str,
    folder: &str,
    cursor: Option<&str>,
) -> Result<(Vec<MailMessage>, Option<String>), AppError> {
    let client = client()?;
    let mut url = match cursor.filter(|c| cursor_ok(c)) {
        Some(link) => link.to_owned(),
        None => {
            format!("{GRAPH}/{mailbox_path}/mailFolders/{folder}/messages/delta?$select={SELECT}")
        }
    };
    let mut out: Vec<MailMessage> = Vec::new();
    loop {
        let res = client
            .get(&url)
            .bearer_auth(token)
            .header(
                "Prefer",
                "odata.maxpagesize=50, outlook.body-content-type=\"text\"",
            )
            .send()
            .await
            .map_err(AppError::internal)?;
        let status = res.status().as_u16();
        let body = res.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(AppError::Validation(format!(
                "Graph refused the mailbox read ({status})"
            )));
        }
        let (messages, next, delta) = parse_page(&body)
            .ok_or_else(|| AppError::Validation("Graph answered an unreadable page".into()))?;
        for mut message in messages {
            if message.id.is_empty() {
                continue;
            }
            if message.has_attachments {
                let attachments_url = format!(
                    "{GRAPH}/{mailbox_path}/messages/{}/attachments?$select=id,name,contentType,size",
                    url::form_urlencoded::byte_serialize(message.id.as_bytes()).collect::<String>()
                );
                if let Ok(res) = client.get(attachments_url).bearer_auth(token).send().await
                    && res.status().is_success()
                {
                    message.attachments =
                        parse_attachments(&message.id, &res.text().await.unwrap_or_default());
                }
            }
            out.push(message);
        }
        match (next, delta) {
            (Some(next), _) if out.len() < MAX_PER_PULL && cursor_ok(&next) => url = next,
            (Some(next), _) if cursor_ok(&next) => return Ok((out, Some(next))),
            (_, Some(delta)) if cursor_ok(&delta) => return Ok((out, Some(delta))),
            _ => return Ok((out, Some(url))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"{"@odata.context":"x","value":[
        {"id":"AAMk1","subject":"طلب عرض سعر","internetMessageId":"<q1@client.sa>",
         "conversationId":"conv1","receivedDateTime":"2026-10-19T08:00:00Z","hasAttachments":true,
         "from":{"emailAddress":{"name":"Fahad","address":"fahad@client.sa"}},
         "toRecipients":[{"emailAddress":{"name":"sales@us.sa","address":"sales@us.sa"}}],
         "ccRecipients":[],"body":{"contentType":"text","content":"نحتاج عرضًا"}},
        {"id":"AAMk2","@removed":{"reason":"deleted"}}],
        "@odata.deltaLink":"https://graph.microsoft.com/v1.0/users/x/mailFolders/inbox/messages/delta?$deltatoken=abc"}"#;

    #[test]
    fn mailbox_graph_reads_a_delta_page() {
        let (messages, next, delta) = parse_page(PAGE).unwrap();
        assert_eq!(messages.len(), 1, "removed items are skipped");
        let m = &messages[0];
        assert_eq!((m.provider, m.id.as_str()), ("graph", "AAMk1"));
        assert_eq!(m.message_id.as_deref(), Some("q1@client.sa"));
        assert_eq!(
            m.from.as_ref().map(|f| f.address.as_str()),
            Some("fahad@client.sa")
        );
        assert_eq!(m.to[0].name, None, "a name equal to the address is dropped");
        assert_eq!(m.text.as_deref(), Some("نحتاج عرضًا"));
        assert_eq!(m.thread_hint.as_deref(), Some("conv1"));
        assert!(m.has_attachments);
        assert!(!m.private);
        let private = PAGE.replace(
            r#""hasAttachments":true"#,
            r#""hasAttachments":false,"sensitivity":"private""#,
        );
        let (p, _, _) = parse_page(&private).unwrap();
        assert!(p[0].private && !p[0].has_attachments);
        assert_eq!(next, None);
        assert!(delta.unwrap().contains("deltatoken=abc"));
        assert!(cursor_ok("https://graph.microsoft.com/v1.0/x"));
        assert!(!cursor_ok("https://evil.example/graph"));
    }

    #[test]
    fn mailbox_graph_lists_attachments() {
        let a = parse_attachments(
            "AAMk1",
            r#"{"value":[{"id":"att1","name":"RFQ.pdf","contentType":"application/pdf","size":2048}]}"#,
        );
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].reference, "graph:AAMk1/att1");
        assert_eq!(a[0].size, 2048);
        assert!(parse_attachments("x", "nope").is_empty());
    }
}
