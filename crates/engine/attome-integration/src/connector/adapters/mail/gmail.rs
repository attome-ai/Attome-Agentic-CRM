//! J2-T1: a Gmail or Google Workspace mailbox through the Gmail API.
//!
//! The first pull lists the newest inbox messages and keeps the mailbox's
//! history id; later pulls read `history.list` from that id for messages
//! added to the inbox. A history id Google no longer keeps (404) starts
//! over from the newest messages. Each message is read in `full` format,
//! whose parts carry their own decoded headers and base64url bodies, so no
//! MIME parsing is needed.

use std::time::Duration;

use attome_types::AppError;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use super::{
    MAX_PER_PULL, MailAddress, MailAttachment, MailMessage, bare_id, reference_ids, required,
};
use crate::system::IntegrationSystem;

const API: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const TIMEOUT: Duration = Duration::from_secs(30);
/// Messages read on the first pull.
const FIRST_PULL: usize = 50;

fn header<'a>(headers: &'a [Value], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|h| {
        (h.get("name")?.as_str()?.eq_ignore_ascii_case(name)).then(|| h.get("value")?.as_str())?
    })
}

/// `Name <a@b>`, `a@b` or a comma-separated list of them. Pure.
pub fn parse_addresses(raw: &str) -> Vec<MailAddress> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut current = String::new();
    let mut parts = Vec::new();
    for c in raw.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                current.push(c);
            }
            ',' if !quoted => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, address) = match (part.rfind('<'), part.rfind('>')) {
            (Some(open), Some(close)) if open < close => {
                let name = part[..open].trim().trim_matches('"').trim();
                (
                    (!name.is_empty()).then(|| name.to_owned()),
                    part[open + 1..close].trim().to_owned(),
                )
            }
            _ => (None, part.trim_matches('"').to_owned()),
        };
        if address.contains('@') {
            out.push(MailAddress { name, address });
        }
    }
    out
}

fn decode(data: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(data.trim_end_matches('=')).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Walks a payload's parts: the first plain and HTML bodies, and every part
/// with a file name as an attachment.
fn walk(part: &Value, message_id: &str, out: &mut MailMessage) {
    let mime = part
        .get("mimeType")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let body = part.get("body");
    let filename = part
        .get("filename")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !filename.is_empty() {
        if let Some(id) = body
            .and_then(|b| b.get("attachmentId"))
            .and_then(Value::as_str)
        {
            out.attachments.push(MailAttachment {
                name: Some(filename.to_owned()),
                content_type: (!mime.is_empty()).then(|| mime.to_owned()),
                size: body
                    .and_then(|b| b.get("size"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                reference: format!("gmail:{message_id}/{id}"),
            });
        }
    } else if let Some(data) = body.and_then(|b| b.get("data")).and_then(Value::as_str) {
        if mime.eq_ignore_ascii_case("text/plain") && out.text.is_none() {
            out.text = decode(data);
        } else if mime.eq_ignore_ascii_case("text/html") && out.html.is_none() {
            out.html = decode(data);
        }
    }
    for child in part
        .get("parts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk(child, message_id, out);
    }
}

/// One message in `full` format. Pure.
pub fn parse_message(body: &str) -> Option<MailMessage> {
    let v: Value = serde_json::from_str(body).ok()?;
    let id = v.get("id")?.as_str()?.to_owned();
    let payload = v.get("payload")?;
    let headers: Vec<Value> = payload
        .get("headers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let h = |name: &str| header(&headers, name).map(str::to_owned);
    let mut message = MailMessage {
        provider: "gmail",
        message_id: h("Message-ID").as_deref().and_then(bare_id),
        in_reply_to: h("In-Reply-To").as_deref().and_then(bare_id),
        references: h("References")
            .as_deref()
            .map(reference_ids)
            .unwrap_or_default(),
        thread_hint: v.get("threadId").and_then(Value::as_str).map(str::to_owned),
        from: h("From")
            .as_deref()
            .map(parse_addresses)
            .and_then(|a| a.into_iter().next()),
        to: h("To").as_deref().map(parse_addresses).unwrap_or_default(),
        cc: h("Cc").as_deref().map(parse_addresses).unwrap_or_default(),
        subject: h("Subject"),
        date: v
            .get("internalDate")
            .and_then(Value::as_str)
            .and_then(|ms| ms.parse::<i64>().ok())
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|d| d.to_rfc3339()),
        auto_submitted: h("Auto-Submitted"),
        precedence: h("Precedence"),
        list_id: h("List-Id"),
        ..MailMessage::default()
    };
    walk(payload, &id, &mut message);
    message.id = id;
    Some(message)
}

/// The ids of messages added in a history answer, its next page and the
/// mailbox's history id now. Pure.
pub fn parse_history(body: &str) -> Option<(Vec<String>, Option<String>, Option<String>)> {
    let v: Value = serde_json::from_str(body).ok()?;
    let mut ids = Vec::new();
    for h in v
        .get("history")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for added in h
            .get("messagesAdded")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = added
                .get("message")
                .and_then(|m| m.get("id"))
                .and_then(Value::as_str)
                && !ids.iter().any(|x| x == id)
            {
                ids.push(id.to_owned());
            }
        }
    }
    let text = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_owned);
    Some((ids, text("nextPageToken"), text("historyId")))
}

fn client() -> Result<reqwest::Client, AppError> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .build()
        .map_err(AppError::internal)
}

async fn access_token(
    cfg: &Value,
    system: &IntegrationSystem,
    credential: &str,
) -> Result<String, AppError> {
    let secrets: Value = serde_json::from_str(credential).map_err(|_| {
        AppError::Validation(format!(
            "{}: the credential is not a JSON object",
            system.name
        ))
    })?;
    let secret = |k: &str| {
        secrets
            .get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::Validation(format!("the credential has no {k}")))
    };
    let res = client()?
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", required(cfg, system, "client_id")?),
            ("client_secret", secret("client_secret")?),
            ("refresh_token", secret("refresh_token")?),
        ])
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let body: Value = res.json().await.unwrap_or(Value::Null);
    body.get("access_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AppError::Validation(format!("Google refused the token refresh ({status})")))
}

async fn get_json(
    client: &reqwest::Client,
    token: &str,
    url: &str,
) -> Result<(u16, String), AppError> {
    let res = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    Ok((status, res.text().await.unwrap_or_default()))
}

pub(super) async fn pull(
    system: &IntegrationSystem,
    cfg: &Value,
    credential: &str,
    cursor: Option<&str>,
) -> Result<(Vec<MailMessage>, Option<String>), AppError> {
    let token = access_token(cfg, system, credential).await?;
    let client = client()?;
    let refused = |what: &str, status: u16| {
        AppError::Validation(format!("Gmail refused the {what} ({status})"))
    };

    let mut ids: Vec<String> = Vec::new();
    let mut next_cursor: Option<String> = None;
    let mut start_over = cursor.is_none_or(|c| !c.chars().all(|ch| ch.is_ascii_digit()));
    if !start_over {
        let mut page: Option<String> = None;
        loop {
            let mut url = format!(
                "{API}/history?historyTypes=messageAdded&labelId=INBOX&maxResults=100&startHistoryId={}",
                cursor.unwrap_or_default()
            );
            if let Some(p) = &page {
                url.push_str("&pageToken=");
                url.push_str(
                    &url::form_urlencoded::byte_serialize(p.as_bytes()).collect::<String>(),
                );
            }
            let (status, body) = get_json(&client, &token, &url).await?;
            if status == 404 {
                start_over = true;
                break;
            }
            if !(200..300).contains(&status) {
                return Err(refused("history read", status));
            }
            let (added, next_page, history_id) =
                parse_history(&body).ok_or_else(|| refused("history read", status))?;
            for id in added {
                if !ids_contains(&ids, &id) {
                    ids.push(id);
                }
            }
            next_cursor = history_id.or(next_cursor);
            match next_page {
                Some(p) if ids.len() < MAX_PER_PULL => page = Some(p),
                _ => break,
            }
        }
    }
    if start_over {
        ids.clear();
        let (status, body) = get_json(&client, &token, &format!("{API}/profile")).await?;
        if !(200..300).contains(&status) {
            return Err(refused("profile read", status));
        }
        next_cursor = serde_json::from_str::<Value>(&body).ok().and_then(|v| {
            v.get("historyId")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        let (status, body) = get_json(
            &client,
            &token,
            &format!("{API}/messages?labelIds=INBOX&maxResults={FIRST_PULL}"),
        )
        .await?;
        if !(200..300).contains(&status) {
            return Err(refused("message list", status));
        }
        let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        ids = v
            .get("messages")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|m| m.get("id")?.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
    }
    ids.truncate(MAX_PER_PULL);
    let mut out = Vec::new();
    for id in ids {
        if !id.chars().all(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        let (status, body) =
            get_json(&client, &token, &format!("{API}/messages/{id}?format=full")).await?;
        if status == 404 {
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(refused("message read", status));
        }
        if let Some(message) = parse_message(&body) {
            out.push(message);
        }
    }
    Ok((out, next_cursor.or_else(|| cursor.map(str::to_owned))))
}

fn ids_contains(ids: &[String], id: &str) -> bool {
    ids.iter().any(|x| x == id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s)
    }

    #[test]
    fn mailbox_gmail_reads_a_full_message() {
        let body = format!(
            r#"{{"id":"18a1","threadId":"t9","internalDate":"1760860800000","payload":{{
              "mimeType":"multipart/mixed","headers":[
                {{"name":"From","value":"\"Al-Qahtani, Sara\" <sara@client.sa>"}},
                {{"name":"To","value":"sales@us.sa, Ops <ops@us.sa>"}},
                {{"name":"Subject","value":"Re: Quote"}},
                {{"name":"Message-ID","value":"<m2@client.sa>"}},
                {{"name":"In-Reply-To","value":"<m1@us.sa>"}},
                {{"name":"References","value":"<m0@us.sa> <m1@us.sa>"}},
                {{"name":"Auto-Submitted","value":"no"}}],
              "parts":[
                {{"mimeType":"multipart/alternative","filename":"","body":{{"size":0}},"parts":[
                  {{"mimeType":"text/plain","filename":"","body":{{"size":5,"data":"{}"}}}},
                  {{"mimeType":"text/html","filename":"","body":{{"size":12,"data":"{}"}}}}]}},
                {{"mimeType":"application/pdf","filename":"PO.pdf","body":{{"size":4096,"attachmentId":"ANGj"}}}}]}}}}"#,
            b64("موافق"),
            b64("<p>موافق</p>")
        );
        let m = parse_message(&body).unwrap();
        assert_eq!((m.provider, m.id.as_str()), ("gmail", "18a1"));
        assert_eq!(
            m.from.as_ref().map(|f| f.name.as_deref()),
            Some(Some("Al-Qahtani, Sara"))
        );
        assert_eq!(m.to.len(), 2);
        assert_eq!(m.to[1].name.as_deref(), Some("Ops"));
        assert_eq!(m.text.as_deref(), Some("موافق"));
        assert_eq!(m.html.as_deref(), Some("<p>موافق</p>"));
        assert_eq!(m.in_reply_to.as_deref(), Some("m1@us.sa"));
        assert_eq!(m.references, vec!["m0@us.sa", "m1@us.sa"]);
        assert_eq!(m.attachments[0].reference, "gmail:18a1/ANGj");
        assert_eq!(m.date.as_deref(), Some("2025-10-19T08:00:00+00:00"));
        assert_eq!(m.auto_submitted.as_deref(), Some("no"));
    }

    #[test]
    fn mailbox_gmail_reads_history_once_each() {
        let (ids, next, history) = parse_history(
            r#"{"history":[{"id":"1","messagesAdded":[{"message":{"id":"a"}},{"message":{"id":"b"}}]},
               {"id":"2","messagesAdded":[{"message":{"id":"a"}}]}],"historyId":"777","nextPageToken":"p2"}"#,
        )
        .unwrap();
        assert_eq!(ids, vec!["a", "b"], "a message added twice is read once");
        assert_eq!(
            (next.as_deref(), history.as_deref()),
            (Some("p2"), Some("777"))
        );
        assert_eq!(
            parse_history(r#"{"historyId":"778"}"#).unwrap().0,
            Vec::<String>::new()
        );
    }
}
