//! C6-T1: a Slack app, installed per workspace with the customer's own
//! Slack app (its client id, client secret and signing secret), as pure
//! request and answer codecs (the caller does the HTTP with the workspace's
//! bot token). Requests from Slack reach an inbound hook with the `slack`
//! preset, which checks `X-Slack-Signature` and the timestamp window
//! (`inbound.rs`); nothing here trusts a body that did not pass it.
//!
//! - **Install.** [`install_url`] is the "Add to Slack" link (OAuth v2 with
//!   the bot scopes [`BOT_SCOPES`] and a `state` the caller checks on the
//!   way back); [`parse_install`] reads `oauth.v2.access`'s answer: the
//!   workspace (`team.id`), the bot token and the bot user, kept per
//!   workspace by the caller as a secret.
//! - **Events.** [`parse_event`] reads an Events API body: the one-time
//!   `url_verification` challenge, `link_shared` (links to unfurl) and
//!   `app_mention`.
//! - **Notifications and approvals.** [`notification_blocks`] and
//!   [`approval_blocks`] are Block Kit messages for `chat.postMessage`
//!   ([`post_message`]). An approval opens the request's single-use
//!   approval link (M9-T3, `/approval-link?token=…`), as the Teams card and
//!   the approval email do, so the person decides on Attome's own page and
//!   the link works once whichever channel used it first; the message
//!   carries no decision the app would have to trust.
//! - **Unfurls.** [`unfurl_body`] answers `link_shared` through
//!   `chat.unfurl` with one record's blocks per link.
//! - **`/attome search`.** [`parse_command`] reads a slash command's form
//!   body; [`search_reply`] is the ephemeral answer with the hits the
//!   searching person may read (the caller searches as the Attome user the
//!   Slack user is linked to).
//!
//! Checked against recorded answers only: no Slack app is registered here.

use serde_json::{Map, Value, json};

/// The OAuth v2 authorise page.
pub const AUTHORIZE_URL: &str = "https://slack.com/oauth/v2/authorize";
/// Where the install code is exchanged.
pub const ACCESS_URL: &str = "https://slack.com/api/oauth.v2.access";
/// Where messages are posted.
pub const POST_MESSAGE_URL: &str = "https://slack.com/api/chat.postMessage";
/// Where links are unfurled.
pub const UNFURL_URL: &str = "https://slack.com/api/chat.unfurl";
/// The bot scopes the app asks for: post, read the links it unfurls, answer
/// its slash command, and look a person up by email to link them.
pub const BOT_SCOPES: &[&str] = &[
    "chat:write",
    "links:read",
    "links:write",
    "commands",
    "users:read",
    "users:read.email",
];
/// Hits a search answer lists.
pub const MAX_HITS: usize = 10;
/// Fields a message shows.
pub const MAX_FIELDS: usize = 10;

/// Text as Slack's `mrkdwn` reads it literally: `&`, `<` and `>` escaped.
/// Pure.
pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn enc(text: &str) -> String {
    url::form_urlencoded::byte_serialize(text.as_bytes()).collect()
}

/// The "Add to Slack" link. Pure.
pub fn install_url(client_id: &str, redirect_uri: &str, state: &str) -> String {
    format!(
        "{AUTHORIZE_URL}?client_id={}&scope={}&redirect_uri={}&state={}",
        enc(client_id),
        enc(&BOT_SCOPES.join(",")),
        enc(redirect_uri),
        enc(state)
    )
}

/// The form body that exchanges an install code. Pure.
pub fn access_form(client_id: &str, client_secret: &str, code: &str, redirect_uri: &str) -> String {
    format!(
        "client_id={}&client_secret={}&code={}&redirect_uri={}",
        enc(client_id),
        enc(client_secret),
        enc(code),
        enc(redirect_uri)
    )
}

/// One workspace's installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installation {
    pub team_id: String,
    pub team_name: Option<String>,
    /// The bot token (`xoxb-…`): a secret.
    pub bot_token: String,
    pub bot_user_id: Option<String>,
    pub scopes: Vec<String>,
}

/// `oauth.v2.access`'s answer: the installation, or Slack's error code.
/// Pure.
pub fn parse_install(body: &Value) -> Result<Installation, String> {
    if body["ok"] != true {
        return Err(body["error"].as_str().unwrap_or("unknown_error").to_owned());
    }
    let text = |v: &Value| v.as_str().filter(|s| !s.is_empty()).map(str::to_owned);
    let bot_token = text(&body["access_token"])
        .filter(|t| t.starts_with("xoxb-"))
        .ok_or_else(|| "no_bot_token".to_owned())?;
    let team_id = text(&body["team"]["id"]).ok_or_else(|| "no_team".to_owned())?;
    Ok(Installation {
        team_id,
        team_name: text(&body["team"]["name"]),
        bot_token,
        bot_user_id: text(&body["bot_user_id"]),
        scopes: body["scope"]
            .as_str()
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
    })
}

/// What an Events API body asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackEvent {
    /// Slack checking the request URL: answer with the challenge.
    UrlVerification { challenge: String },
    /// Links to Attome were posted; unfurl them.
    LinkShared {
        team_id: String,
        channel: String,
        message_ts: String,
        links: Vec<String>,
    },
    /// Someone mentioned the app.
    AppMention {
        team_id: String,
        channel: String,
        user: String,
        text: String,
    },
    /// Anything else: acknowledged, nothing done.
    Other,
}

/// Reads an Events API body. Pure.
pub fn parse_event(body: &Value) -> SlackEvent {
    let s = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    match body["type"].as_str() {
        Some("url_verification") => match body["challenge"].as_str() {
            Some(challenge) => SlackEvent::UrlVerification {
                challenge: challenge.to_owned(),
            },
            None => SlackEvent::Other,
        },
        Some("event_callback") => {
            let event = &body["event"];
            let team_id = s(&body["team_id"]);
            match event["type"].as_str() {
                Some("link_shared") => SlackEvent::LinkShared {
                    team_id,
                    channel: s(&event["channel"]),
                    message_ts: s(&event["message_ts"]),
                    links: event["links"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|l| l["url"].as_str())
                        .filter(|u| u.starts_with("https://"))
                        .map(str::to_owned)
                        .collect(),
                },
                Some("app_mention") => SlackEvent::AppMention {
                    team_id,
                    channel: s(&event["channel"]),
                    user: s(&event["user"]),
                    text: s(&event["text"]),
                },
                _ => SlackEvent::Other,
            }
        }
        _ => SlackEvent::Other,
    }
}

fn fields(list: &[(String, String)]) -> Value {
    Value::Array(
        list.iter()
            .take(MAX_FIELDS)
            .map(|(k, v)| json!({ "type": "mrkdwn", "text": format!("*{}*\n{}", escape(k), escape(v)) }))
            .collect(),
    )
}

fn button(label: &str, url: &str, primary: bool) -> Value {
    let mut b =
        json!({ "type": "button", "text": { "type": "plain_text", "text": label }, "url": url });
    if primary {
        b["style"] = json!("primary");
    }
    b
}

/// A notification: a title, its text, fields and an Open button. Pure.
pub fn notification_blocks(
    title: &str,
    text: &str,
    field_list: &[(String, String)],
    open_url: &str,
    arabic: bool,
) -> Value {
    let mut blocks = vec![
        json!({ "type": "header", "text": { "type": "plain_text", "text": title } }),
        json!({ "type": "section", "text": { "type": "mrkdwn", "text": escape(text) } }),
    ];
    if !field_list.is_empty() {
        blocks.push(json!({ "type": "section", "fields": fields(field_list) }));
    }
    blocks.push(json!({ "type": "actions", "elements": [button(if arabic { "فتح" } else { "Open" }, open_url, false)] }));
    Value::Array(blocks)
}

/// An approval: what is asked, its fields, and one button to the request's
/// single-use approval link. Pure.
pub fn approval_blocks(
    title: &str,
    field_list: &[(String, String)],
    base_url: &str,
    approval_token: &str,
    arabic: bool,
) -> Value {
    let link = format!(
        "{}/approval-link?token={}",
        base_url.trim_end_matches('/'),
        enc(approval_token)
    );
    let mut blocks = vec![
        json!({ "type": "header", "text": { "type": "plain_text",
                "text": if arabic { "مطلوب موافقتك" } else { "Your approval is needed" } } }),
        json!({ "type": "section", "text": { "type": "mrkdwn", "text": escape(title) } }),
    ];
    if !field_list.is_empty() {
        blocks.push(json!({ "type": "section", "fields": fields(field_list) }));
    }
    blocks.push(json!({ "type": "actions", "elements": [
        button(if arabic { "مراجعة واتخاذ القرار" } else { "Review and decide" }, &link, true)
    ] }));
    Value::Array(blocks)
}

/// The `chat.postMessage` body: `text` is the notification's plain fallback.
/// Pure.
pub fn post_message(channel: &str, text: &str, blocks: Value) -> Value {
    json!({ "channel": channel, "text": text, "blocks": blocks, "unfurl_links": false })
}

/// The `chat.unfurl` body: each link with its record's blocks. Pure.
pub fn unfurl_body(channel: &str, message_ts: &str, unfurls: &[(String, Value)]) -> Value {
    let mut map = Map::new();
    for (url, blocks) in unfurls {
        map.insert(url.clone(), json!({ "blocks": blocks }));
    }
    json!({ "channel": channel, "ts": message_ts, "unfurls": map })
}

/// A slash command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub team_id: String,
    pub user_id: String,
    pub command: String,
    /// What follows the command, e.g. `search acme`.
    pub text: String,
    pub response_url: Option<String>,
}

impl Command {
    /// The search text of `/attome search <text>`, if that is what was asked.
    pub fn search_text(&self) -> Option<&str> {
        let rest = self.text.trim();
        let rest = rest
            .strip_prefix("search")
            .filter(|r| r.is_empty() || r.starts_with(' '))?;
        Some(rest.trim()).filter(|r| !r.is_empty())
    }
}

/// A slash command's form body (`application/x-www-form-urlencoded`); `None`
/// without a team, user or command. Pure.
pub fn parse_command(form: &str) -> Option<Command> {
    let mut team_id = None;
    let mut user_id = None;
    let mut command = None;
    let mut text = String::new();
    let mut response_url = None;
    for (k, v) in url::form_urlencoded::parse(form.as_bytes()) {
        match k.as_ref() {
            "team_id" => team_id = Some(v.into_owned()),
            "user_id" => user_id = Some(v.into_owned()),
            "command" => command = Some(v.into_owned()),
            "text" => text = v.into_owned(),
            "response_url" => {
                response_url =
                    Some(v.into_owned()).filter(|u| u.starts_with("https://hooks.slack.com/"))
            }
            _ => {}
        }
    }
    Some(Command {
        team_id: team_id.filter(|t| !t.is_empty())?,
        user_id: user_id.filter(|u| !u.is_empty())?,
        command: command.filter(|c| c.starts_with('/'))?,
        text,
        response_url,
    })
}

/// One search hit as the answer lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub title: String,
    /// What kind of record it is, e.g. `Account`.
    pub kind: String,
    pub url: String,
}

/// The ephemeral answer to `/attome search`: up to [`MAX_HITS`] hits as
/// links, or a line saying nothing was found. Pure.
pub fn search_reply(query: &str, hits: &[Hit], arabic: bool) -> Value {
    let mut blocks = Vec::new();
    if hits.is_empty() {
        let none = if arabic {
            "لا نتائج لـ"
        } else {
            "Nothing found for"
        };
        blocks.push(json!({ "type": "section", "text": { "type": "mrkdwn", "text": format!("{none} *{}*", escape(query)) } }));
    } else {
        let lines: Vec<String> = hits
            .iter()
            .take(MAX_HITS)
            .map(|h| {
                format!(
                    "<{}|{}>  _{}_",
                    h.url,
                    escape(&h.title).replace('|', "¦"),
                    escape(&h.kind)
                )
            })
            .collect();
        blocks.push(
            json!({ "type": "section", "text": { "type": "mrkdwn", "text": lines.join("\n") } }),
        );
    }
    json!({ "response_type": "ephemeral", "blocks": blocks })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slack_app_install_link_and_answer() {
        let link = install_url(
            "123.456",
            "https://crm.acme.sa/api/v1/integrations/slack/oauth",
            "st&1",
        );
        assert!(link.starts_with(AUTHORIZE_URL));
        assert!(link.contains("scope=chat%3Awrite%2Clinks%3Aread"));
        assert!(link.contains("state=st%261"));
        let ok = json!({
            "ok": true, "access_token": "xoxb-1-2-abc", "scope": "chat:write,commands",
            "bot_user_id": "U0BOT", "team": { "id": "T123", "name": "Acme" }
        });
        let install = parse_install(&ok).unwrap();
        assert_eq!(install.team_id, "T123");
        assert_eq!(install.scopes, ["chat:write", "commands"]);
        assert_eq!(
            parse_install(&json!({ "ok": false, "error": "invalid_code" })),
            Err("invalid_code".into())
        );
        assert_eq!(
            parse_install(
                &json!({ "ok": true, "access_token": "xoxp-user", "team": { "id": "T1" } })
            ),
            Err("no_bot_token".into()),
            "only a bot token is kept"
        );
        assert!(access_form("a", "s&s", "c", "r").contains("client_secret=s%26s"));
    }

    #[test]
    fn slack_app_reads_events() {
        assert_eq!(
            parse_event(&json!({ "type": "url_verification", "challenge": "abc" })),
            SlackEvent::UrlVerification {
                challenge: "abc".into()
            }
        );
        let shared = json!({ "type": "event_callback", "team_id": "T1", "event": {
            "type": "link_shared", "channel": "C1", "message_ts": "1.2",
            "links": [{ "url": "https://crm.acme.sa/r/account/9" }, { "url": "http://insecure" }]
        } });
        assert_eq!(
            parse_event(&shared),
            SlackEvent::LinkShared {
                team_id: "T1".into(),
                channel: "C1".into(),
                message_ts: "1.2".into(),
                links: vec!["https://crm.acme.sa/r/account/9".into()],
            }
        );
        assert_eq!(
            parse_event(
                &json!({ "type": "event_callback", "event": { "type": "reaction_added" } })
            ),
            SlackEvent::Other
        );
        let unfurl = unfurl_body(
            "C1",
            "1.2",
            &[("https://crm.acme.sa/r/account/9".into(), json!([]))],
        );
        assert!(unfurl["unfurls"]["https://crm.acme.sa/r/account/9"]["blocks"].is_array());
    }

    #[test]
    fn slack_app_approvals_open_the_single_use_link() {
        let blocks = approval_blocks(
            "Discount of 30% on <Acme>",
            &[("Amount".into(), "SAR 90,000".into())],
            "https://crm.acme.sa/",
            "tok/en+1",
            false,
        );
        let text = blocks.to_string();
        assert!(text.contains("https://crm.acme.sa/approval-link?token=tok%2Fen%2B1"));
        assert!(text.contains("&lt;Acme&gt;"), "user text is escaped");
        assert!(
            !text.contains("\"action_id\""),
            "no decision travels through Slack"
        );
        let ar = approval_blocks("x", &[], "https://a", "t", true).to_string();
        assert!(ar.contains("مطلوب موافقتك"));
        let note = post_message(
            "C1",
            "Deal won",
            notification_blocks("Deal won", "Acme signed", &[], "https://a/r/1", false),
        );
        assert_eq!(note["channel"], "C1");
        assert_eq!(note["blocks"][0]["type"], "header");
    }

    #[test]
    fn slack_app_search_command() {
        let cmd = parse_command(
            "team_id=T1&user_id=U9&command=%2Fattome&text=search+acme+holdings&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2Fx",
        )
        .unwrap();
        assert_eq!(cmd.search_text(), Some("acme holdings"));
        assert_eq!(
            cmd.response_url.as_deref(),
            Some("https://hooks.slack.com/commands/x")
        );
        assert!(
            parse_command("team_id=T1&command=%2Fattome").is_none(),
            "no user"
        );
        let other = parse_command("team_id=T1&user_id=U9&command=%2Fattome&text=searching&response_url=https%3A%2F%2Fevil.test").unwrap();
        assert_eq!(other.search_text(), None);
        assert_eq!(
            other.response_url, None,
            "answers go only to Slack's own hooks"
        );
        let reply = search_reply(
            "acme",
            &[Hit {
                title: "Acme | KSA".into(),
                kind: "Account".into(),
                url: "https://a/r/account/1".into(),
            }],
            false,
        );
        assert_eq!(reply["response_type"], "ephemeral");
        assert!(
            reply
                .to_string()
                .contains("<https://a/r/account/1|Acme ¦ KSA>")
        );
        assert!(
            search_reply("zzz", &[], false)
                .to_string()
                .contains("Nothing found for *zzz*")
        );
    }
}
