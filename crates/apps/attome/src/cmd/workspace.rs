//! T4-T3: `attome workspace list|create|switch|preview|publish|refresh|rollback`
//! — Develop workspaces (T5) from the command line, through the admin API as
//! the signed-in person (`--target`, T4-T1) or an API key (`--url`,
//! `ATTOME_API_KEY`).
//!
//! - `list` shows the workspaces not discarded, and which one this target
//!   works in.
//! - `create <name> [--purpose <text>] [--data sample|masked|none]
//!   [--per-entity <n>] [--percent <n>]` makes one.
//! - `switch <id>|live` makes the target's later `config`, `data`, `flags`
//!   and `model` commands run inside the workspace (or on live again). It is
//!   kept with the target in `targets.json`; without a target, set
//!   `ATTOME_WORKSPACE` instead.
//! - `preview <id>` shows what publishing would change live and any
//!   conflicts.
//! - `publish <id> [--backup-ref <ref>]` publishes it to live.
//! - `refresh <id>` brings in live's changes the workspace has not made its
//!   own.
//! - `rollback <id>` throws the workspace's changes away: it is discarded
//!   with its schema. Live is untouched.
//!
//! The workspace routes always run on live, so these requests never carry the
//! workspace header. `publish` and `rollback` write to live or discard work,
//! so they need `--yes`, and on a production target `--confirm-target
//! <name>` (T4-T5).

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::Path;

use serde_json::{Value, json};

use crate::cmd::login::{Auth, ChosenWorkspace, Targets, credentials};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
const ROUTES: &str = "/api/v1/admin/workspaces";
const USAGE: &str = "usage: attome workspace list\n       attome workspace create <name> [--purpose <text>] [--data sample|masked|none] [--per-entity <n>] [--percent <n>]\n       attome workspace switch <id>|live\n       attome workspace preview <id>\n       attome workspace publish <id> [--backup-ref <ref>] [--yes] [--confirm-target <name>]\n       attome workspace refresh <id>\n       attome workspace rollback <id> [--yes] [--confirm-target <name>]\n  each with [--target <name> | --url <url>] [--json]";

/// A parsed `attome workspace` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceCommand {
    List,
    Create {
        name: String,
        body: Value,
    },
    Switch {
        to: Option<String>,
    },
    Preview {
        id: String,
    },
    Publish {
        id: String,
        backup_ref: Option<String>,
    },
    Refresh {
        id: String,
    },
    Rollback {
        id: String,
    },
}

impl WorkspaceCommand {
    /// The name `--yes` confirms, when the command writes to live or throws
    /// work away. Pure.
    fn writes(&self) -> Option<&'static str> {
        match self {
            Self::Publish { .. } => Some("workspace publish"),
            Self::Rollback { .. } => Some("workspace rollback"),
            _ => None,
        }
    }
}

/// The options `create` and `publish` take, already removed from the words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Options {
    pub purpose: Option<String>,
    pub data: Option<String>,
    pub per_entity: Option<String>,
    pub percent: Option<String>,
    pub backup_ref: Option<String>,
}

fn number(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|_| format!("{flag}: a whole number, not {value:?}"))
}

/// The body of a new workspace. Pure.
fn create_body(name: &str, options: &Options) -> Result<Value, String> {
    let mut body = json!({ "name": name });
    if let Some(purpose) = &options.purpose {
        body["purpose"] = json!(purpose);
    }
    if options.data.is_some() || options.per_entity.is_some() || options.percent.is_some() {
        let mode = options.data.as_deref().unwrap_or("sample");
        if !matches!(mode, "sample" | "masked" | "none") {
            return Err(format!("--data: sample, masked or none, not {mode:?}"));
        }
        let mut data = json!({ "mode": mode });
        if let Some(n) = &options.per_entity {
            data["per_entity"] = json!(number("--per-entity", n)?);
        }
        if let Some(n) = &options.percent {
            data["percent"] = json!(number("--percent", n)?);
        }
        body["data"] = data;
    }
    Ok(body)
}

/// Parses what follows `attome workspace`, the shared options already
/// taken. Pure.
pub fn parse(words: &[String], options: &Options) -> Result<WorkspaceCommand, String> {
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let only = |what: &str| -> Result<(), String> {
        let stray = (options.purpose.is_some() && what != "create")
            || ((options.data.is_some()
                || options.per_entity.is_some()
                || options.percent.is_some())
                && what != "create")
            || (options.backup_ref.is_some() && what != "publish");
        if stray { Err(USAGE.to_owned()) } else { Ok(()) }
    };
    let command = match words.as_slice() {
        ["list"] => {
            only("list")?;
            WorkspaceCommand::List
        }
        ["create", name] if !name.trim().is_empty() => {
            only("create")?;
            WorkspaceCommand::Create {
                name: (*name).to_owned(),
                body: create_body(name, options)?,
            }
        }
        ["switch", to] => {
            only("switch")?;
            WorkspaceCommand::Switch {
                to: (*to != "live").then(|| (*to).to_owned()),
            }
        }
        ["preview", id] => {
            only("preview")?;
            WorkspaceCommand::Preview {
                id: (*id).to_owned(),
            }
        }
        ["publish", id] => {
            only("publish")?;
            WorkspaceCommand::Publish {
                id: (*id).to_owned(),
                backup_ref: options.backup_ref.clone(),
            }
        }
        ["refresh", id] => {
            only("refresh")?;
            WorkspaceCommand::Refresh {
                id: (*id).to_owned(),
            }
        }
        ["rollback", id] => {
            only("rollback")?;
            WorkspaceCommand::Rollback {
                id: (*id).to_owned(),
            }
        }
        _ => return Err(USAGE.to_owned()),
    };
    Ok(command)
}

/// Q21-T1: `url` is the operator's own server, named on the command line.
fn client(url: &str) -> Result<attome_outbound::http::Outbound, String> {
    let purpose = attome_outbound::http::Purpose::public("cli-workspace").with_private_urls([url]);
    attome_outbound::http::client(purpose, |b| b.timeout(std::time::Duration::from_secs(300)))
        .map_err(|error| format!("build the HTTP client: {error}"))
}

/// One call to the workspace routes; `None` for an answer with no body.
pub(crate) async fn send(
    url: &str,
    auth: &Auth,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = client(url)?.request(method, format!("{url}{ROUTES}{path}"));
    if let Some(value) = auth {
        request = request.header("authorization", value);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("reach {url}: {error}"))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|error| format!("read the response: {error}"))?;
    let body: Value = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&text).map_err(|error| format!("read the response: {error}"))?
    };
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("the server answered {status}: {body}"))
    }
}

/// One line per workspace, the current one marked. Pure.
pub fn list_lines(page: &Value, current: Option<&str>) -> String {
    let items = page["items"].as_array().cloned().unwrap_or_default();
    if items.is_empty() {
        return "no workspaces".to_owned();
    }
    items
        .iter()
        .map(|w| {
            let id = w["id"].as_str().unwrap_or("?");
            format!(
                "{} {id}  {:<10} {}",
                if Some(id) == current { "*" } else { " " },
                w["status"].as_str().unwrap_or("?"),
                w["name"].as_str().unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One line for a publish preview. Pure.
pub fn preview_line(preview: &Value) -> String {
    let conflicts = preview["conflicts"].as_array().map_or(0, Vec::len);
    let operations = preview["operations"].as_i64().unwrap_or(0);
    if preview["publishable"] == true {
        format!("{operations} change(s); can be published")
    } else if conflicts > 0 {
        format!(
            "{operations} change(s); {conflicts} conflict(s) with live block publishing: \
             refresh, or undo the clashing changes"
        )
    } else if preview["plan"].is_null() {
        "nothing to publish".to_owned()
    } else {
        format!("{operations} change(s); the plan against live has blocked operations")
    }
}

/// Stores (or clears) the workspace `target` works in, in `dir`'s
/// `targets.json`.
pub fn store_switch(
    dir: &Path,
    target: Option<&str>,
    to: Option<ChosenWorkspace>,
) -> Result<String, String> {
    let mut targets = Targets::load(dir)?;
    let (name, _) = targets.resolve(target)?;
    let entry = targets
        .targets
        .get_mut(&name)
        .ok_or_else(|| format!("no target `{name}`"))?;
    entry.workspace = to;
    targets.save(dir)?;
    Ok(name)
}

/// The workspace `target` works in, as `targets.json` keeps it.
fn current(target: Option<&str>) -> Option<ChosenWorkspace> {
    let dir = crate::cmd::login::config_dir().ok()?;
    let (_, found) = Targets::load(&dir).ok()?.resolve(target).ok()?;
    found.workspace
}

pub fn run(args: &[String]) -> Result<(), String> {
    use crate::cmd::output::{confirm, envelope, take_flag, take_value};
    let mut args = args.to_vec();
    let json = take_flag(&mut args, "--json");
    let yes = take_flag(&mut args, "--yes");
    let confirm_target = take_value(&mut args, "--confirm-target")?;
    let target = take_value(&mut args, "--target")?;
    let url = take_value(&mut args, "--url")?
        .or_else(|| std::env::var("ATTOME_URL").ok())
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let options = Options {
        purpose: take_value(&mut args, "--purpose")?,
        data: take_value(&mut args, "--data")?,
        per_entity: take_value(&mut args, "--per-entity")?,
        percent: take_value(&mut args, "--percent")?,
        backup_ref: take_value(&mut args, "--backup-ref")?,
    };
    let command = parse(&args, &options)?;
    if let Some(action) = command.writes() {
        let named = target
            .as_deref()
            .map(|t| (t, crate::cmd::login::is_production(Some(t))));
        confirm(action, yes, confirm_target.as_deref(), named)?;
    }
    if matches!(command, WorkspaceCommand::Switch { .. }) && target.is_none() {
        return Err(
            "switch keeps the workspace with a signed-in target: name one with --target, or \
             set ATTOME_WORKSPACE=<id> (or live) for commands run with --url"
                .to_owned(),
        );
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    runtime.block_on(async {
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth) = credentials(
            url.trim_end_matches('/').to_owned(),
            api_key,
            target.clone(),
        )
        .await?;
        let current_id = current(target.as_deref()).map(|w| w.id);
        let (kind, answer, line) = execute(
            &url,
            &auth,
            target.as_deref(),
            current_id.as_deref(),
            command,
        )
        .await?;
        if json {
            println!("{}", envelope(kind, answer));
        } else {
            println!("{line}");
        }
        Ok(())
    })
}

/// Runs one command against `url`; what to print as JSON and as a line.
pub async fn execute(
    url: &str,
    auth: &Auth,
    target: Option<&str>,
    current_id: Option<&str>,
    command: WorkspaceCommand,
) -> Result<(&'static str, Value, String), String> {
    use reqwest::Method;
    let leave_if_current = |id: &str| -> Result<(), String> {
        if current_id == Some(id) {
            let dir = crate::cmd::login::config_dir()?;
            store_switch(&dir, target, None)?;
        }
        Ok(())
    };
    Ok(match command {
        WorkspaceCommand::List => {
            let page = send(url, auth, Method::GET, "?page_size=100", None).await?;
            let line = list_lines(&page, current_id);
            ("workspace_list", page, line)
        }
        WorkspaceCommand::Create { name, body } => {
            let made = send(url, auth, Method::POST, "", Some(body)).await?;
            let line = format!(
                "made the workspace {name} ({}) with {} record(s); `attome workspace switch {}` \
                 to work in it",
                made["id"].as_str().unwrap_or("?"),
                made["data"]["records"].as_i64().unwrap_or(0),
                made["id"].as_str().unwrap_or("?"),
            );
            ("workspace_create", made, line)
        }
        WorkspaceCommand::Switch { to } => {
            let dir = crate::cmd::login::config_dir()?;
            match to {
                None => {
                    let name = store_switch(&dir, target, None)?;
                    (
                        "workspace_switch",
                        json!({ "workspace": null }),
                        format!("`{name}` works on live"),
                    )
                }
                Some(id) => {
                    let found = send(url, auth, Method::GET, &format!("/{id}"), None).await?;
                    if found["status"] != "open" {
                        return Err(format!(
                            "the workspace {id} is {}; only an open workspace can be worked in",
                            found["status"].as_str().unwrap_or("not open")
                        ));
                    }
                    let chosen = ChosenWorkspace {
                        id: id.clone(),
                        name: found["name"].as_str().unwrap_or(&id).to_owned(),
                    };
                    let name = store_switch(&dir, target, Some(chosen.clone()))?;
                    let line = format!(
                        "`{name}` works in the workspace {} ({id}); `attome workspace switch live` \
                         to go back",
                        chosen.name
                    );
                    ("workspace_switch", found, line)
                }
            }
        }
        WorkspaceCommand::Preview { id } => {
            let preview = send(url, auth, Method::GET, &format!("/{id}/publish"), None).await?;
            let line = preview_line(&preview);
            ("workspace_preview", preview, line)
        }
        WorkspaceCommand::Publish { id, backup_ref } => {
            let body = match backup_ref {
                Some(r) => json!({ "backup_ref": r }),
                None => json!({}),
            };
            let published = send(
                url,
                auth,
                Method::POST,
                &format!("/{id}/publish"),
                Some(body),
            )
            .await?;
            leave_if_current(&id)?;
            let line = if published["apply"]["approval_pending"] == true {
                format!("the workspace {id} is published; its apply waits for an approval")
            } else {
                format!("the workspace {id} is published; its changes are being applied to live")
            };
            ("workspace_publish", published, line)
        }
        WorkspaceCommand::Refresh { id } => {
            let report = send(url, auth, Method::POST, &format!("/{id}/refresh"), None).await?;
            let line = format!(
                "refreshed {id}: {} metadata row(s) added, {} updated, {} table(s), {} column(s)",
                report["metadata_rows_added"].as_u64().unwrap_or(0),
                report["metadata_rows_updated"].as_u64().unwrap_or(0),
                report["tables_added"].as_array().map_or(0, Vec::len),
                report["columns_added"].as_array().map_or(0, Vec::len),
            );
            ("workspace_refresh", report, line)
        }
        WorkspaceCommand::Rollback { id } => {
            send(url, auth, Method::DELETE, &format!("/{id}"), None).await?;
            leave_if_current(&id)?;
            (
                "workspace_rollback",
                json!({ "workspace": id, "discarded": true }),
                format!("the workspace {id} and its changes are thrown away; live is untouched"),
            )
        }
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test code: a failed step should panic with its message"
)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use axum::{Json, Router, extract::Request, http::StatusCode};

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn commands_parse_with_their_own_options() {
        let none = Options::default();
        assert_eq!(parse(&words("list"), &none), Ok(WorkspaceCommand::List));
        assert_eq!(
            parse(&words("switch live"), &none),
            Ok(WorkspaceCommand::Switch { to: None })
        );
        assert_eq!(
            parse(&words("switch abc"), &none),
            Ok(WorkspaceCommand::Switch {
                to: Some("abc".into())
            })
        );
        let masked = Options {
            data: Some("masked".into()),
            percent: Some("25".into()),
            ..Options::default()
        };
        assert_eq!(
            parse(&words("create Pricing"), &masked),
            Ok(WorkspaceCommand::Create {
                name: "Pricing".into(),
                body: json!({ "name": "Pricing", "data": { "mode": "masked", "percent": 25 } }),
            })
        );
        // An option of another command is refused.
        assert!(parse(&words("list"), &masked).is_err());
        assert!(
            parse(
                &words("create X"),
                &Options {
                    data: Some("everything".into()),
                    ..Options::default()
                }
            )
            .is_err()
        );
        assert!(parse(&words("publish"), &none).is_err());
        assert_eq!(
            parse(&words("rollback w1"), &none).unwrap().writes(),
            Some("workspace rollback")
        );
        assert_eq!(parse(&words("refresh w1"), &none).unwrap().writes(), None);
    }

    #[test]
    fn a_switch_is_kept_with_the_target() {
        let dir = std::env::temp_dir().join(format!("attome-ws-switch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut targets = Targets::default();
        targets.targets.insert(
            "dev".into(),
            crate::cmd::login::Target {
                url: "http://127.0.0.1:7865".into(),
                production: false,
                workspace: None,
            },
        );
        targets.default = Some("dev".into());
        targets.save(&dir).unwrap();
        let chosen = ChosenWorkspace {
            id: "w1".into(),
            name: "Pricing".into(),
        };
        assert_eq!(
            store_switch(&dir, None, Some(chosen.clone())),
            Ok("dev".into())
        );
        let loaded = Targets::load(&dir).unwrap();
        assert_eq!(loaded.targets["dev"].workspace, Some(chosen));
        store_switch(&dir, Some("dev"), None).unwrap();
        assert_eq!(Targets::load(&dir).unwrap().targets["dev"].workspace, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn lines_say_what_happened() {
        let page = json!({ "items": [
            { "id": "w1", "status": "open", "name": "Pricing" },
            { "id": "w2", "status": "published", "name": "Old" },
        ]});
        let lines = list_lines(&page, Some("w1"));
        assert!(lines.starts_with("* w1"), "{lines}");
        assert!(lines.contains("  w2"), "{lines}");
        assert_eq!(list_lines(&json!({ "items": [] }), None), "no workspaces");
        assert_eq!(
            preview_line(&json!({ "publishable": true, "operations": 3, "conflicts": [] })),
            "3 change(s); can be published"
        );
        assert!(
            preview_line(&json!({
                "publishable": false, "operations": 1, "conflicts": [{}], "plan": {}
            }))
            .contains("1 conflict(s)")
        );
    }

    /// What the mock server saw: method, path and query, the workspace
    /// header, and the body.
    type Seen = Arc<Mutex<Vec<(String, String, Option<String>, Value)>>>;

    async fn mock() -> (String, Seen) {
        let seen: Seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let app = Router::new().fallback(move |request: Request| {
            let record = Arc::clone(&record);
            async move {
                let method = request.method().to_string();
                let path = request
                    .uri()
                    .path_and_query()
                    .map(|p| p.as_str().to_owned())
                    .unwrap_or_default();
                if method == "GET" && path.starts_with("/api/v1/admin/workspaces?") {
                    return (
                        StatusCode::OK,
                        Json(
                            json!({ "items": [{ "id": "w1", "status": "open", "name": "Pricing" }],
                                         "total": 1, "page": 1, "page_size": 100 }),
                        ),
                    );
                }
                let header = request
                    .headers()
                    .get(crate::cmd::login::WORKSPACE_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned);
                let bytes = axum::body::to_bytes(request.into_body(), 1 << 20)
                    .await
                    .unwrap();
                let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                record
                    .lock()
                    .unwrap()
                    .push((method.clone(), path.clone(), header, body));
                if method == "DELETE" {
                    return (StatusCode::NO_CONTENT, Json(Value::Null));
                }
                if path.ends_with("/missing/publish") {
                    return (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" })));
                }
                if path.ends_with("/publish") && method == "POST" {
                    return (
                        StatusCode::OK,
                        Json(json!({ "apply": { "status": "queued", "approval_pending": false } })),
                    );
                }
                (
                    StatusCode::CREATED,
                    Json(json!({ "id": "w9", "name": "New", "data": { "records": 40 } })),
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (url, seen)
    }

    #[tokio::test]
    async fn commands_call_the_workspace_routes_on_live() {
        let (url, seen) = mock().await;
        let auth: Auth = Some("ApiKey p:s".into());

        let (kind, page, line) = execute(&url, &auth, None, Some("w1"), WorkspaceCommand::List)
            .await
            .unwrap();
        assert_eq!(kind, "workspace_list");
        assert_eq!(page["total"], 1);
        assert!(line.starts_with("* w1"), "{line}");

        let created = parse(
            &words("create New"),
            &Options {
                data: Some("none".into()),
                ..Options::default()
            },
        )
        .unwrap();
        let (_, made, line) = execute(&url, &auth, None, None, created).await.unwrap();
        assert_eq!(made["id"], "w9");
        assert!(line.contains("switch w9"), "{line}");

        let (_, _, line) = execute(
            &url,
            &auth,
            None,
            None,
            WorkspaceCommand::Publish {
                id: "w1".into(),
                backup_ref: Some("snap-1".into()),
            },
        )
        .await
        .unwrap();
        assert!(line.contains("being applied"), "{line}");
        execute(
            &url,
            &auth,
            None,
            None,
            WorkspaceCommand::Rollback { id: "w2".into() },
        )
        .await
        .unwrap();

        let refused = execute(
            &url,
            &auth,
            None,
            None,
            WorkspaceCommand::Publish {
                id: "missing".into(),
                backup_ref: None,
            },
        )
        .await;
        assert!(refused.unwrap_err().contains("404"));

        let seen = seen.lock().unwrap().clone();
        let calls: Vec<(&str, &str)> = seen
            .iter()
            .map(|(m, p, _, _)| (m.as_str(), p.as_str()))
            .collect();
        assert_eq!(
            calls,
            vec![
                ("POST", "/api/v1/admin/workspaces"),
                ("POST", "/api/v1/admin/workspaces/w1/publish"),
                ("DELETE", "/api/v1/admin/workspaces/w2"),
                ("POST", "/api/v1/admin/workspaces/missing/publish"),
            ]
        );
        assert_eq!(
            seen[0].3,
            json!({ "name": "New", "data": { "mode": "none" } })
        );
        assert_eq!(seen[1].3, json!({ "backup_ref": "snap-1" }));
        // The workspace routes run on live: no request names a workspace.
        assert!(seen.iter().all(|(_, _, header, _)| header.is_none()));
    }
}
