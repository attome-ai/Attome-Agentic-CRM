//! C5-T1: a Microsoft Teams bot, registered with the customer's own Azure
//! app (its app id and client secret).
//!
//! - [`TeamsBot::send`] posts an activity into a conversation through the
//!   Bot Connector API, with a token from the Bot Framework's client
//!   credentials grant ([`TeamsBot::token`]); the service URL is the one
//!   Teams gave for the conversation and must be `https`.
//! - [`notification_card`] and [`approval_card`] are Adaptive Cards (1.4).
//!   An approval card opens the request's single-use approval link (M9-T3,
//!   `/approval-link?token=…`), so the person decides on the same page an
//!   approval email leads to, and the link works once whichever channel
//!   used it first; the card itself carries no decision the bot would have
//!   to trust.
//! - Link unfurling: [`query_link`] reads the URL out of a
//!   `composeExtension/queryLink` invoke and [`unfurl_response`] wraps a
//!   record's card as the answer Teams shows under the pasted link.
//!
//! Checked against recorded answers only: no Azure bot is registered here.

use attome_types::AppError;
use serde_json::{Value, json};

use crate::connector::sdk::{Request, Secret, Transport};

/// Where a Bot Framework token is asked for.
pub const TOKEN_URL: &str = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token";
/// The scope a Bot Connector token is asked for.
pub const SCOPE: &str = "https://api.botframework.com/.default";
/// The Adaptive Card schema version cards are written in.
pub const CARD_VERSION: &str = "1.4";
/// The most facts a card lists.
pub const MAX_FACTS: usize = 10;

/// A Teams bot connection.
pub struct TeamsBot<'a> {
    pub app_id: String,
    pub app_secret: Secret,
    pub token_url: String,
    pub transport: &'a dyn Transport,
}

impl std::fmt::Debug for TeamsBot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeamsBot")
            .field("app_id", &self.app_id)
            .finish_non_exhaustive()
    }
}

fn form(pairs: &[(&str, &str)]) -> String {
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        out.append_pair(k, v);
    }
    out.finish()
}

/// A Bot Framework or Bot Connector answer as JSON, or why it was refused.
pub fn parse_answer(status: u16, body: &str) -> Result<Value, AppError> {
    let value: Option<Value> = serde_json::from_str(body).ok();
    let message = || {
        value
            .as_ref()
            .and_then(|v| {
                v.get("error_description")
                    .or_else(|| v.pointer("/error/message"))
                    .or_else(|| v.get("error"))
            })
            .and_then(Value::as_str)
            .unwrap_or("no reason given")
            .to_owned()
    };
    match status {
        400 | 401 | 403 => Err(AppError::Validation(format!(
            "Teams refused the bot: {}",
            message()
        ))),
        404 => Err(AppError::Validation(
            "Teams does not know that conversation".into(),
        )),
        429 => Err(AppError::TooManyRequests {
            retry_after_secs: None,
        }),
        s if s >= 400 => Err(AppError::internal(format!("Teams answered {s}"))),
        _ => Ok(value.unwrap_or(Value::Null)),
    }
}

/// The Bot Connector address of a conversation's activities, when the
/// service URL is `https` and the conversation id has no path characters.
/// Pure.
pub fn activities_url(service_url: &str, conversation_id: &str) -> Option<String> {
    let base = url::Url::parse(service_url).ok()?;
    if base.scheme() != "https" || base.host_str().is_none() || conversation_id.is_empty() {
        return None;
    }
    let encoded: String =
        url::form_urlencoded::byte_serialize(conversation_id.as_bytes()).collect();
    Some(format!(
        "{}/v3/conversations/{encoded}/activities",
        service_url.trim_end_matches('/')
    ))
}

impl<'a> TeamsBot<'a> {
    pub fn new(app_id: &str, app_secret: Secret, transport: &'a dyn Transport) -> Self {
        TeamsBot {
            app_id: app_id.trim().to_owned(),
            app_secret,
            token_url: TOKEN_URL.to_owned(),
            transport,
        }
    }

    /// A Bot Connector access token.
    pub async fn token(&self) -> Result<String, AppError> {
        let answer = self
            .transport
            .send(Request {
                method: "POST".into(),
                url: self.token_url.clone(),
                headers: vec![(
                    "Content-Type".into(),
                    "application/x-www-form-urlencoded".into(),
                )],
                body: Some(form(&[
                    ("grant_type", "client_credentials"),
                    ("client_id", &self.app_id),
                    ("client_secret", self.app_secret.wire_value()),
                    ("scope", SCOPE),
                ])),
            })
            .await?;
        parse_answer(answer.status, &answer.body)?["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| AppError::internal("the Bot Framework answered no access token"))
    }

    /// Posts `activity` into a conversation; returns the activity id.
    pub async fn send(
        &self,
        service_url: &str,
        conversation_id: &str,
        activity: &Value,
    ) -> Result<Option<String>, AppError> {
        let url = activities_url(service_url, conversation_id).ok_or_else(|| {
            AppError::Validation("not a Teams service URL and conversation".into())
        })?;
        let token = self.token().await?;
        let answer = self
            .transport
            .send(Request {
                method: "POST".into(),
                url,
                headers: vec![
                    ("Content-Type".into(), "application/json".into()),
                    ("Authorization".into(), format!("Bearer {token}")),
                ],
                body: Some(activity.to_string()),
            })
            .await?;
        Ok(parse_answer(answer.status, &answer.body)?["id"]
            .as_str()
            .map(str::to_owned))
    }
}

fn facts(facts: &[(String, String)]) -> Value {
    Value::Array(
        facts
            .iter()
            .take(MAX_FACTS)
            .map(|(t, v)| json!({"title": t, "value": v}))
            .collect(),
    )
}

/// A message activity carrying one Adaptive Card. Pure.
pub fn card_activity(card: Value, summary: &str) -> Value {
    json!({
        "type": "message",
        "summary": summary,
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": card,
        }],
    })
}

/// A notification card: a title, its text, facts and an Open button. Pure.
pub fn notification_card(
    title: &str,
    text: &str,
    facts_list: &[(String, String)],
    open_url: &str,
    rtl: bool,
) -> Value {
    json!({
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": CARD_VERSION,
        "rtl": rtl,
        "body": [
            {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": true},
            {"type": "TextBlock", "text": text, "wrap": true},
            {"type": "FactSet", "facts": facts(facts_list)},
        ],
        "actions": [{"type": "Action.OpenUrl", "title": if rtl { "فتح" } else { "Open" }, "url": open_url}],
    })
}

/// An approval card: what is asked, its facts, and one button to the
/// request's single-use approval link. Pure.
pub fn approval_card(
    title: &str,
    facts_list: &[(String, String)],
    base_url: &str,
    approval_token: &str,
    rtl: bool,
) -> Value {
    let link = format!(
        "{}/approval-link?token={}",
        base_url.trim_end_matches('/'),
        url::form_urlencoded::byte_serialize(approval_token.as_bytes()).collect::<String>()
    );
    json!({
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": CARD_VERSION,
        "rtl": rtl,
        "body": [
            {"type": "TextBlock", "text": if rtl { "مطلوب موافقتك" } else { "Your approval is needed" },
             "weight": "Bolder", "color": "Accent", "wrap": true},
            {"type": "TextBlock", "text": title, "size": "Medium", "wrap": true},
            {"type": "FactSet", "facts": facts(facts_list)},
        ],
        "actions": [{"type": "Action.OpenUrl", "title": if rtl { "مراجعة واتخاذ القرار" } else { "Review and decide" }, "url": link}],
    })
}

/// The URL a `composeExtension/queryLink` invoke asks Teams to unfurl;
/// `None` for any other activity. Pure.
pub fn query_link(activity: &Value) -> Option<String> {
    (activity["type"] == "invoke" && activity["name"] == "composeExtension/queryLink")
        .then(|| activity["value"]["url"].as_str().map(str::to_owned))
        .flatten()
        .filter(|u| u.starts_with("https://"))
}

/// The invoke answer that shows `card` under a pasted link. Pure.
pub fn unfurl_response(card: Value, preview_title: &str) -> Value {
    json!({
        "composeExtension": {
            "type": "result",
            "attachmentLayout": "list",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": card,
                "preview": {
                    "contentType": "application/vnd.microsoft.card.thumbnail",
                    "content": {"title": preview_title},
                },
            }],
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::sdk::Response;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    struct Recorded {
        answers: Mutex<Vec<(u16, &'static str)>>,
        asked: Mutex<Vec<Request>>,
    }

    impl Transport for Recorded {
        fn send<'a>(
            &'a self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send + 'a>> {
            self.asked.lock().unwrap().push(request);
            let (status, body) = self.answers.lock().unwrap().remove(0);
            Box::pin(async move {
                Ok(Response {
                    status,
                    headers: Vec::new(),
                    body: body.to_owned(),
                })
            })
        }
    }

    #[tokio::test]
    async fn teams_bot_sends_a_card_with_a_connector_token() {
        let transport = Recorded {
            answers: Mutex::new(vec![
                (
                    200,
                    r#"{"token_type":"Bearer","expires_in":3599,"access_token":"tok-1"}"#,
                ),
                (201, r#"{"id":"1729850000000"}"#),
            ]),
            asked: Mutex::new(Vec::new()),
        };
        let bot = TeamsBot::new("app-1", Secret::new("s3cret"), &transport);
        let card = approval_card(
            "Discount of 18% on Example Trading",
            &[("Amount".into(), "SAR 120,000".into())],
            "https://crm.example.sa/",
            "tok+en/1",
            false,
        );
        let id = bot
            .send(
                "https://smba.trafficmanager.net/emea/",
                "19:abc@thread.tacv2;messageid=1",
                &card_activity(card, "Approval needed"),
            )
            .await
            .unwrap();
        assert_eq!(id.as_deref(), Some("1729850000000"));
        let asked = transport.asked.lock().unwrap();
        assert_eq!(asked[0].url, TOKEN_URL);
        let token_body = asked[0].body.as_deref().unwrap();
        assert!(token_body.contains("grant_type=client_credentials"));
        assert!(token_body.contains("client_secret=s3cret"));
        assert!(token_body.contains("scope=https%3A%2F%2Fapi.botframework.com%2F.default"));
        assert_eq!(
            asked[1].url,
            "https://smba.trafficmanager.net/emea/v3/conversations/19%3Aabc%40thread.tacv2%3Bmessageid%3D1/activities"
        );
        assert!(
            asked[1]
                .headers
                .contains(&("Authorization".into(), "Bearer tok-1".into()))
        );
        let sent: Value = serde_json::from_str(asked[1].body.as_deref().unwrap()).unwrap();
        assert_eq!(
            sent["attachments"][0]["content"]["actions"][0]["url"],
            "https://crm.example.sa/approval-link?token=tok%2Ben%2F1"
        );
    }

    #[tokio::test]
    async fn teams_bot_refuses_plain_http_and_a_bad_secret() {
        let transport = Recorded {
            answers: Mutex::new(vec![(
                401,
                r#"{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret"}"#,
            )]),
            asked: Mutex::new(Vec::new()),
        };
        let bot = TeamsBot::new("app-1", Secret::new("wrong"), &transport);
        assert!(
            bot.send("http://smba.example", "c1", &json!({}))
                .await
                .is_err()
        );
        assert!(matches!(
            bot.token().await,
            Err(AppError::Validation(m)) if m.contains("AADSTS7000215")
        ));
    }

    #[test]
    fn teams_bot_unfurls_a_pasted_link() {
        let invoke = json!({
            "type": "invoke",
            "name": "composeExtension/queryLink",
            "value": {"url": "https://crm.example.sa/xrm/entity/account/01a1"}
        });
        assert_eq!(
            query_link(&invoke).as_deref(),
            Some("https://crm.example.sa/xrm/entity/account/01a1")
        );
        assert_eq!(query_link(&json!({"type": "message", "text": "hi"})), None);
        let answer = unfurl_response(
            notification_card(
                "Example Trading",
                "Account",
                &[("Owner".into(), "Sara".into())],
                "https://crm.example.sa/xrm/entity/account/01a1",
                true,
            ),
            "Example Trading",
        );
        assert_eq!(answer["composeExtension"]["type"], "result");
        let card = &answer["composeExtension"]["attachments"][0]["content"];
        assert_eq!(card["rtl"], true);
        assert_eq!(card["actions"][0]["title"], "فتح");
    }
}
