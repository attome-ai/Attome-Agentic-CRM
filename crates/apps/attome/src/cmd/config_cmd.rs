//! T4-T2: `attome config pull|push|plan|diff|rollback` — a deployment's
//! configuration as a folder, through its admin API as the signed-in person
//! (`--target`, T4-T1) or an API key (`--url`, `ATTOME_API_KEY`).
//!
//! The folder holds `bundle.json` (`GET /api/v1/admin/metadata/export`) and
//! `objects/`, one file per metadata object (`attome model export`).
//!
//! - `pull --out <dir>` writes the folder.
//! - `plan --dir <dir> [--allow-retire]` shows what the bundle would change
//!   (`POST .../metadata/import?mode=plan`) and changes nothing.
//! - `diff` shows the drift from the last applied bundle
//!   (`GET .../metadata/drift`).
//! - `push --dir <dir> [--allow-retire]` plans, refuses a plan with blocked
//!   entries, applies it (`mode=apply`, which may wait for a second
//!   administrator's approval) and saves `objects/` as drafts, unpublished.
//! - `rollback <bundle> --to <version> [--allow-retire]` queues a rollback.
//!
//! `push` and `rollback` write, so they need `--yes`, and on a production
//! target `--confirm-target <name>` (T4-T5).

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::cmd::login::{Auth, credentials};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
const BUNDLE_FILE: &str = "bundle.json";
const OBJECTS_DIR: &str = "objects";
const USAGE: &str = "usage: attome config pull --out <dir>\n       attome config plan --dir <dir> [--allow-retire]\n       attome config diff\n       attome config push --dir <dir> [--allow-retire] [--yes] [--confirm-target <name>]\n       attome config rollback <bundle> --to <version> [--allow-retire] [--yes] [--confirm-target <name>]\n  each with [--target <name> | --url <url>] [--json]";

/// A parsed `attome config` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigCommand {
    Pull {
        out: PathBuf,
    },
    Plan {
        dir: PathBuf,
        allow_retire: bool,
    },
    Diff,
    Push {
        dir: PathBuf,
        allow_retire: bool,
    },
    Rollback {
        bundle: String,
        to_version: String,
        allow_retire: bool,
    },
}

impl ConfigCommand {
    /// The name `--yes` confirms, when the command writes. Pure.
    fn writes(&self) -> Option<&'static str> {
        match self {
            Self::Push { .. } => Some("config push"),
            Self::Rollback { .. } => Some("config rollback"),
            _ => None,
        }
    }
}

/// Parses what follows `attome config`, the shared options already taken. Pure.
pub fn parse(words: &[String], allow_retire: bool) -> Result<ConfigCommand, String> {
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["pull", "--out", out] => Ok(ConfigCommand::Pull { out: out.into() }),
        ["plan", "--dir", dir] => Ok(ConfigCommand::Plan {
            dir: dir.into(),
            allow_retire,
        }),
        ["diff"] => Ok(ConfigCommand::Diff),
        ["push", "--dir", dir] => Ok(ConfigCommand::Push {
            dir: dir.into(),
            allow_retire,
        }),
        ["rollback", bundle, "--to", version] => Ok(ConfigCommand::Rollback {
            bundle: (*bundle).to_owned(),
            to_version: (*version).to_owned(),
            allow_retire,
        }),
        _ => Err(USAGE.to_owned()),
    }
}

/// One line for a plan's outcome. Pure.
pub fn plan_line(plan: &Value) -> String {
    let count = |key: &str| plan[key].as_array().map_or(0, Vec::len);
    format!(
        "{} change(s), {} retire(s), {} blocked; {}",
        count("entries"),
        count("retires"),
        count("blocked"),
        if plan["applicable"] == true {
            "can be applied"
        } else {
            "cannot be applied until the blocked entries are resolved"
        }
    )
}

/// `bundle.json` from the folder.
fn read_bundle(dir: &Path) -> Result<Value, String> {
    let path = dir.join(BUNDLE_FILE);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
}

/// Q21-T1: `url` is the operator's own server, named on the command line.
fn client(url: &str) -> Result<attome_outbound::http::Outbound, String> {
    let purpose = attome_outbound::http::Purpose::public("cli-config").with_private_urls([url]);
    attome_outbound::http::client(purpose, |b| b.timeout(std::time::Duration::from_secs(120)))
        .map_err(|error| format!("build the HTTP client: {error}"))
}

pub(crate) async fn send(
    url: &str,
    auth: &Auth,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<Value, String> {
    let mut request = client(url)?.request(method, format!("{url}/api/v1/admin/metadata{path}"));
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
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("read the response: {error}"))?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!("the server answered {status}: {body}"))
    }
}

pub(crate) async fn plan(
    url: &str,
    auth: &Auth,
    dir: &Path,
    allow_retire: bool,
) -> Result<Value, String> {
    send(
        url,
        auth,
        reqwest::Method::POST,
        "/import?mode=plan",
        Some(json!({ "bundle": read_bundle(dir)?, "allow_retire": allow_retire })),
    )
    .await
}

pub fn run(args: &[String]) -> Result<(), String> {
    use crate::cmd::output::{confirm, envelope, take_flag, take_value};
    let mut args = args.to_vec();
    let json = take_flag(&mut args, "--json");
    let yes = take_flag(&mut args, "--yes");
    let allow_retire = take_flag(&mut args, "--allow-retire");
    let confirm_target = take_value(&mut args, "--confirm-target")?;
    let target = take_value(&mut args, "--target")?;
    let url = take_value(&mut args, "--url")?
        .or_else(|| std::env::var("ATTOME_URL").ok())
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let command = parse(&args, allow_retire)?;
    if let Some(action) = command.writes() {
        let named = target
            .as_deref()
            .map(|t| (t, crate::cmd::login::is_production(Some(t))));
        confirm(action, yes, confirm_target.as_deref(), named)?;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    runtime.block_on(async {
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth) =
            credentials(url.trim_end_matches('/').to_owned(), api_key, target).await?;
        let (kind, answer, line) = match command {
            ConfigCommand::Pull { out } => {
                let bundle = send(&url, &auth, reqwest::Method::GET, "/export", None).await?;
                std::fs::create_dir_all(&out)
                    .map_err(|error| format!("create {}: {error}", out.display()))?;
                let text = serde_json::to_string_pretty(&bundle)
                    .map_err(|error| format!("write the bundle: {error}"))?;
                let path = out.join(BUNDLE_FILE);
                std::fs::write(&path, text + "\n")
                    .map_err(|error| format!("write {}: {error}", path.display()))?;
                let objects =
                    crate::cmd::model_files::export(&url, auth, &out.join(OBJECTS_DIR)).await?;
                let line = format!(
                    "pulled the bundle and {objects} object(s) to {}",
                    out.display()
                );
                let answer = json!({ "objects": objects, "out": out.display().to_string() });
                ("config_pull", answer, line)
            }
            ConfigCommand::Plan { dir, allow_retire } => {
                let answer = plan(&url, &auth, &dir, allow_retire).await?;
                let line = plan_line(&answer);
                ("config_plan", answer, line)
            }
            ConfigCommand::Diff => {
                let answer = send(&url, &auth, reqwest::Method::GET, "/drift", None).await?;
                let line = if answer["drift"].is_null() {
                    "no drift".to_owned()
                } else {
                    serde_json::to_string_pretty(&answer["drift"])
                        .map_err(|error| format!("print the drift: {error}"))?
                };
                ("config_diff", answer, line)
            }
            ConfigCommand::Push { dir, allow_retire } => {
                let planned = plan(&url, &auth, &dir, allow_retire).await?;
                if planned["applicable"] != true {
                    return Err(format!("not applied: {}", plan_line(&planned)));
                }
                let applied = send(
                    &url,
                    &auth,
                    reqwest::Method::POST,
                    "/import?mode=apply",
                    Some(json!({ "plan_id": planned["plan_id"] })),
                )
                .await?;
                let objects = dir.join(OBJECTS_DIR);
                let drafts = if objects.is_dir() {
                    crate::cmd::model_files::import(&url, auth, &objects)
                        .await?
                        .1
                } else {
                    0
                };
                let line = format!(
                    "plan {} {}; {drafts} object draft(s) saved, publish them to make them live",
                    applied["plan_id"].as_str().unwrap_or("?"),
                    if applied["approval_pending"] == true {
                        "waits for a second administrator's approval"
                    } else {
                        "queued"
                    },
                );
                let answer = json!({ "apply": applied, "drafts": drafts });
                ("config_push", answer, line)
            }
            ConfigCommand::Rollback {
                bundle,
                to_version,
                allow_retire,
            } => {
                let answer = send(
                    &url,
                    &auth,
                    reqwest::Method::POST,
                    &format!("/bundles/{bundle}/rollback"),
                    Some(json!({ "to_version": to_version, "allow_retire": allow_retire })),
                )
                .await?;
                let line = format!(
                    "rollback of {bundle} to {to_version} queued as plan {}",
                    answer["plan_id"].as_str().unwrap_or("?")
                );
                ("config_rollback", answer, line)
            }
        };
        if json {
            println!("{}", envelope(kind, answer));
        } else {
            println!("{line}");
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn config_commands_parse() {
        assert_eq!(
            parse(&words(&["pull", "--out", "cfg"]), false),
            Ok(ConfigCommand::Pull { out: "cfg".into() })
        );
        assert_eq!(
            parse(&words(&["push", "--dir", "cfg"]), true),
            Ok(ConfigCommand::Push {
                dir: "cfg".into(),
                allow_retire: true
            })
        );
        assert_eq!(parse(&words(&["diff"]), false), Ok(ConfigCommand::Diff));
        assert_eq!(
            parse(&words(&["rollback", "sales", "--to", "1.2.0"]), false),
            Ok(ConfigCommand::Rollback {
                bundle: "sales".into(),
                to_version: "1.2.0".into(),
                allow_retire: false
            })
        );
        assert!(parse(&words(&["pull"]), false).is_err());
        assert!(parse(&words(&["apply"]), false).is_err());
    }

    #[test]
    fn only_push_and_rollback_need_confirming() {
        let plan = parse(&words(&["plan", "--dir", "cfg"]), false).expect("plan");
        assert_eq!(plan.writes(), None);
        let push = parse(&words(&["push", "--dir", "cfg"]), false).expect("push");
        assert_eq!(push.writes(), Some("config push"));
    }

    #[test]
    fn a_plan_reads_as_one_line() {
        let plan = json!({ "entries": [1, 2], "retires": [], "blocked": [1], "applicable": false });
        assert_eq!(
            plan_line(&plan),
            "2 change(s), 0 retire(s), 1 blocked; cannot be applied until the blocked entries are resolved"
        );
    }
}
