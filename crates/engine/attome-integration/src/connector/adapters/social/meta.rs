//! J8-T1: Meta's webhooks and Graph API for a Facebook page and its
//! Instagram account.
//!
//! **Subscribing.** Meta checks the callback URL with a `GET` carrying
//! `hub.mode=subscribe`, `hub.verify_token` and `hub.challenge`; the token
//! must equal the system's `verify_token` and the challenge is echoed.
//!
//! **Events.** Each `POST` is signed: `X-Hub-Signature-256: sha256=<hex>`,
//! HMAC-SHA256 of the raw body with the app secret, checked in constant
//! time. A page's `messaging` events are Messenger messages and its `feed`
//! changes with `item: comment` are page comments; an Instagram account's
//! `messaging` events are direct messages and its `comments` changes are
//! comments on posts. Echoes of the page's own messages and its own
//! comments are skipped.
//!
//! **Replies** go to `me/messages` for a conversation, `{comment}/comments`
//! for a page comment and `{comment}/replies` for an Instagram comment, with
//! the page access token.

use std::collections::HashMap;
use std::time::Duration;

use attome_types::AppError;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use super::{ReplyTarget, SocialMessage};

const GRAPH: &str = "https://graph.facebook.com/v21.0";
const TIMEOUT: Duration = Duration::from_secs(15);

/// Whether `header` is the body's signature with `app_secret`. Pure.
pub fn signature_ok(app_secret: &str, body: &[u8], header: Option<&str>) -> bool {
    let Some(hex_sig) = header.and_then(|h| h.trim().strip_prefix("sha256=")) else {
        return false;
    };
    let Ok(expected) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&expected).is_ok()
}

/// The challenge to echo when Meta's subscription check carries the right
/// token; none otherwise. Pure.
pub fn verify_challenge(params: &HashMap<String, String>, verify_token: &str) -> Option<String> {
    let mode = params.get("hub.mode")?;
    let token = params.get("hub.verify_token")?;
    let challenge = params.get("hub.challenge")?;
    use sha2::Digest;
    let same = verify_token.len() >= 16
        && Sha256::digest(token.as_bytes()) == Sha256::digest(verify_token.as_bytes());
    (mode == "subscribe" && same && !challenge.is_empty() && challenge.len() <= 200)
        .then(|| challenge.clone())
}

fn text(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// The messages and comments in one webhook body, in order. Pure.
pub fn parse_webhook(body: &[u8]) -> Vec<SocialMessage> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    let instagram = match v.get("object").and_then(Value::as_str) {
        Some("page") => false,
        Some("instagram") => true,
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    for entry in v
        .get("entry")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let own_id = entry.get("id").and_then(Value::as_str).unwrap_or_default();
        for event in entry
            .get("messaging")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(message) = event.get("message") else {
                continue;
            };
            if message.get("is_echo").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            let Some(sender) = event.get("sender").and_then(|s| text(s, "id")) else {
                continue;
            };
            if sender == own_id {
                continue;
            }
            let body = text(message, "text").unwrap_or_else(|| {
                if message.get("attachments").is_some() {
                    "[attachment]".to_owned()
                } else {
                    String::new()
                }
            });
            if body.is_empty() {
                continue;
            }
            let (target, channel, subject) = if instagram {
                (
                    ReplyTarget::InstagramDm(sender),
                    "instagram",
                    "Instagram message",
                )
            } else {
                (
                    ReplyTarget::MessengerDm(sender),
                    "messenger",
                    "Messenger message",
                )
            };
            out.push(SocialMessage {
                channel,
                address: target.address(),
                author: None,
                subject: subject.to_owned(),
                text: body,
            });
        }
        for change in entry
            .get("changes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let field = change
                .get("field")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some(value) = change.get("value") else {
                continue;
            };
            let from = value.get("from");
            let from_id = from.and_then(|f| text(f, "id")).unwrap_or_default();
            if !from_id.is_empty() && from_id == own_id {
                continue;
            }
            if instagram && field == "comments" {
                let (Some(id), Some(body)) = (text(value, "id"), text(value, "text")) else {
                    continue;
                };
                out.push(SocialMessage {
                    channel: "instagram",
                    address: ReplyTarget::InstagramComment(id).address(),
                    author: from.and_then(|f| text(f, "username")),
                    subject: "Instagram comment".to_owned(),
                    text: body,
                });
            } else if !instagram
                && field == "feed"
                && value.get("item").and_then(Value::as_str) == Some("comment")
                && value.get("verb").and_then(Value::as_str) == Some("add")
            {
                let (Some(id), Some(body)) = (text(value, "comment_id"), text(value, "message"))
                else {
                    continue;
                };
                out.push(SocialMessage {
                    channel: "facebook",
                    address: ReplyTarget::FacebookComment(id).address(),
                    author: from.and_then(|f| text(f, "name")),
                    subject: "Facebook comment".to_owned(),
                    text: body,
                });
            }
        }
    }
    out
}

/// The Graph path and body of a reply. Pure; `None` for a target Meta does
/// not take.
pub fn reply_request(target: &ReplyTarget, text: &str) -> Option<(String, Value)> {
    Some(match target {
        ReplyTarget::MessengerDm(id) | ReplyTarget::InstagramDm(id) => (
            "me/messages".to_owned(),
            json!({
                "recipient": { "id": id },
                "messaging_type": "RESPONSE",
                "message": { "text": text },
            }),
        ),
        ReplyTarget::FacebookComment(id) => (format!("{id}/comments"), json!({ "message": text })),
        ReplyTarget::InstagramComment(id) => (format!("{id}/replies"), json!({ "message": text })),
        ReplyTarget::GoogleReview(_) => return None,
    })
}

/// The id Meta gives the reply. Pure.
pub fn reply_id(status: u16, body: &str) -> Option<String> {
    if !(200..300).contains(&status) {
        return None;
    }
    let v: Value = serde_json::from_str(body).ok()?;
    text(&v, "message_id").or_else(|| text(&v, "id"))
}

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: std::sync::OnceLock<attome_outbound::http::Outbound> =
        std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("meta"), |b| {
            b.timeout(TIMEOUT)
        })
    })
}

/// Sends a reply with the page access token.
pub async fn send_reply(
    page_token: &str,
    target: &ReplyTarget,
    text: &str,
) -> Result<Option<String>, AppError> {
    let (path, body) = reply_request(target, text)
        .ok_or_else(|| AppError::Validation("not a Meta conversation or comment".into()))?;
    let res = client()
        .post(format!("{GRAPH}/{path}"))
        .bearer_auth(page_token)
        .json(&body)
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let answer = res.text().await.unwrap_or_default();
    match reply_id(status, &answer) {
        Some(id) => Ok(Some(id)),
        None if (200..300).contains(&status) => Ok(None),
        None => Err(AppError::Validation(format!(
            "Meta refused the reply ({status})"
        ))),
    }
}

/// E17-T1: a page post's body. Pure.
pub fn page_post_body(message: &str, link: Option<&str>) -> Value {
    let mut body = serde_json::json!({ "message": message });
    if let Some(link) = link.filter(|l| !l.trim().is_empty()) {
        body["link"] = Value::String(link.trim().to_owned());
    }
    body
}

/// E17-T1: a post's engagement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PostMetrics {
    pub likes: i64,
    pub comments: i64,
    pub shares: i64,
}

/// E17-T1: the fields read for a post's engagement. Pure.
pub fn metrics_url(post_id: &str) -> String {
    format!(
        "{GRAPH}/{post_id}?fields=likes.summary(true).limit(0),comments.summary(true).limit(0),shares"
    )
}

/// E17-T1: a post's engagement from its fields. Pure.
pub fn parse_metrics(body: &str) -> Option<PostMetrics> {
    let v: Value = serde_json::from_str(body).ok()?;
    let count = |path: &str| v.pointer(path).and_then(Value::as_i64).unwrap_or(0);
    Some(PostMetrics {
        likes: count("/likes/summary/total_count"),
        comments: count("/comments/summary/total_count"),
        shares: count("/shares/count"),
    })
}

/// E17-T1: publishes a post on the page; returns its id.
pub async fn publish_page_post(
    page_token: &str,
    page_id: &str,
    message: &str,
    link: Option<&str>,
) -> Result<String, AppError> {
    if page_id.is_empty() || !page_id.chars().all(|c| c.is_ascii_digit()) {
        return Err(AppError::Validation(
            "the page id is not a Meta page id".into(),
        ));
    }
    let res = client()
        .post(format!("{GRAPH}/{page_id}/feed"))
        .bearer_auth(page_token)
        .json(&page_post_body(message, link))
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let answer = res.text().await.unwrap_or_default();
    reply_id(status, &answer)
        .ok_or_else(|| AppError::Validation(format!("Meta refused the post ({status})")))
}

/// E17-T1: a published post's engagement now.
pub async fn fetch_metrics(page_token: &str, post_id: &str) -> Result<PostMetrics, AppError> {
    let res = client()
        .get(metrics_url(post_id))
        .bearer_auth(page_token)
        .send()
        .await
        .map_err(AppError::internal)?;
    let status = res.status().as_u16();
    let answer = res.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        return Err(AppError::Validation(format!(
            "Meta refused the metrics request ({status})"
        )));
    }
    parse_metrics(&answer)
        .ok_or_else(|| AppError::Validation("Meta answered unreadable metrics".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSENGER: &str = r#"{"object":"page","entry":[{"id":"PAGE1","time":1,"messaging":[
        {"sender":{"id":"PSID9"},"recipient":{"id":"PAGE1"},"timestamp":1,
         "message":{"mid":"m_1","text":"هل الطلب جاهز؟"}},
        {"sender":{"id":"PAGE1"},"recipient":{"id":"PSID9"},"timestamp":2,
         "message":{"mid":"m_2","text":"نعم","is_echo":true}},
        {"sender":{"id":"PSID9"},"recipient":{"id":"PAGE1"},"timestamp":3,"read":{"watermark":3}}],
        "changes":[{"field":"feed","value":{"item":"comment","verb":"add","comment_id":"111_222",
         "post_id":"111","message":"Great service","from":{"id":"U5","name":"Sara"}}},
         {"field":"feed","value":{"item":"comment","verb":"add","comment_id":"111_333",
         "message":"Thanks!","from":{"id":"PAGE1","name":"Us"}}}]}]}"#;

    const INSTAGRAM: &str = r#"{"object":"instagram","entry":[{"id":"IG1","time":1,
        "messaging":[{"sender":{"id":"IGSID4"},"recipient":{"id":"IG1"},"timestamp":1,
          "message":{"mid":"ig_m","attachments":[{"type":"image"}]}}],
        "changes":[{"field":"comments","value":{"id":"C77","text":"Price?",
          "from":{"id":"F2","username":"noura"},"media":{"id":"M1"}}}]}]}"#;

    #[test]
    fn social_meta_reads_messenger_and_page_comments() {
        let got = parse_webhook(MESSENGER.as_bytes());
        assert_eq!(
            got.len(),
            2,
            "the echo, the read receipt and our own comment are skipped"
        );
        assert_eq!(got[0].channel, "messenger");
        assert_eq!(got[0].address, "fb_dm:PSID9");
        assert_eq!(got[0].text, "هل الطلب جاهز؟");
        assert_eq!(got[1].channel, "facebook");
        assert_eq!(got[1].address, "fb_comment:111_222");
        assert_eq!(got[1].author.as_deref(), Some("Sara"));
    }

    #[test]
    fn social_meta_reads_instagram_messages_and_comments() {
        let got = parse_webhook(INSTAGRAM.as_bytes());
        assert_eq!(got.len(), 2);
        assert_eq!(
            (got[0].channel, got[0].address.as_str()),
            ("instagram", "ig_dm:IGSID4")
        );
        assert_eq!(got[0].text, "[attachment]");
        assert_eq!(got[1].address, "ig_comment:C77");
        assert_eq!(got[1].author.as_deref(), Some("noura"));
        assert!(parse_webhook(b"not json").is_empty());
        assert!(parse_webhook(br#"{"object":"whatsapp_business_account","entry":[]}"#).is_empty());
    }

    #[test]
    fn social_meta_checks_signatures_and_the_subscription() {
        let body = MESSENGER.as_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(b"app-secret").unwrap();
        mac.update(body);
        let good = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(signature_ok("app-secret", body, Some(&good)));
        assert!(!signature_ok("other-secret", body, Some(&good)));
        assert!(!signature_ok("app-secret", b"tampered", Some(&good)));
        assert!(!signature_ok("app-secret", body, None));
        assert!(!signature_ok("app-secret", body, Some("sha1=abc")));

        let params = |token: &str| {
            HashMap::from([
                ("hub.mode".to_owned(), "subscribe".to_owned()),
                ("hub.verify_token".to_owned(), token.to_owned()),
                ("hub.challenge".to_owned(), "1158201444".to_owned()),
            ])
        };
        assert_eq!(
            verify_challenge(&params("verify-token-1234567"), "verify-token-1234567"),
            Some("1158201444".into())
        );
        assert_eq!(
            verify_challenge(&params("wrong-token-12345678"), "verify-token-1234567"),
            None
        );
        assert_eq!(
            verify_challenge(&params("short"), "short"),
            None,
            "a short token is refused"
        );
    }

    #[test]
    fn social_meta_builds_replies() {
        let (path, body) = reply_request(&ReplyTarget::MessengerDm("PSID9".into()), "Yes").unwrap();
        assert_eq!(path, "me/messages");
        assert_eq!(body["recipient"]["id"], "PSID9");
        assert_eq!(body["messaging_type"], "RESPONSE");
        assert_eq!(
            reply_request(&ReplyTarget::FacebookComment("111_222".into()), "Thanks")
                .unwrap()
                .0,
            "111_222/comments"
        );
        assert_eq!(
            reply_request(&ReplyTarget::InstagramComment("C77".into()), "DM us")
                .unwrap()
                .0,
            "C77/replies"
        );
        assert_eq!(
            reply_request(&ReplyTarget::GoogleReview("r".into()), "x"),
            None
        );
        assert_eq!(
            reply_id(200, r#"{"recipient_id":"PSID9","message_id":"m_9"}"#),
            Some("m_9".into())
        );
        assert_eq!(reply_id(200, r#"{"id":"C78"}"#), Some("C78".into()));
        assert_eq!(reply_id(400, r#"{"error":{"message":"bad"}}"#), None);
    }
}
