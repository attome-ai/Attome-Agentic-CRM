//! A22-T2: `attome promote` moves a configuration folder to a named
//! environment, a target from `attome login` (T4-T1).
//!
//! ```text
//! attome promote --dir <dir> --to <target> [--copy <target>] [--at <rfc3339>]
//!                [--only <entity,...>] [--allow-retire] [--report <file>] --yes
//!                [--confirm-target <name>]
//! ```
//!
//! It plans on `--to` and refuses a blocked plan. With `--copy`, a masked copy
//! of that environment (`attome scratch create`), the change is applied there
//! first and a failure stops the promotion. With `--at` it waits until then.
//! Then it applies to `--to`, where a production target's approval rule holds
//! it for a second administrator. `--report` writes what changed, the dry run's
//! result and where the apply stands. It changes nothing a push does not.
//!
//! `--only` (A22-T3) promotes the named entities with their fields, the
//! entities their lookups need, and their queries, views and relationships,
//! as a partial bundle, which leaves everything else on the target alone.
//! Environment variable values never travel: each deployment keeps its own.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::cmd::config_cmd::{plan, plan_line, send};
use crate::cmd::login::{Auth, credentials, is_production};

const USAGE: &str = "usage: attome promote --dir <dir> --to <target> [--copy <target>] [--at <rfc3339>] [--only <entity,...>] [--allow-retire] [--report <file>] --yes [--confirm-target <name>]";
/// How long a dry run on a copy may take.
const DRY_RUN_WAIT: Duration = Duration::from_secs(600);

/// The bundle holding `only`, what their lookups need, and the queries, views
/// and relationships among them, marked partial. Pure.
pub fn select(bundle: &Value, only: &[String]) -> Result<Value, String> {
    let entities = bundle["entities"].as_array().cloned().unwrap_or_default();
    let named = |name: &str| {
        entities
            .iter()
            .find(|entity| entity["logicalname"] == name)
            .cloned()
    };
    let mut chosen: BTreeMap<String, Value> = BTreeMap::new();
    let mut waiting: Vec<String> = only.to_vec();
    while let Some(name) = waiting.pop() {
        if chosen.contains_key(&name) {
            continue;
        }
        let entity =
            named(&name).ok_or_else(|| format!("--only: no entity `{name}` in the bundle"))?;
        for attribute in entity["attributes"].as_array().into_iter().flatten() {
            if let Some(target) = attribute["lookup_entity"].as_str()
                && named(target).is_some()
            {
                waiting.push(target.to_owned());
            }
        }
        chosen.insert(name, entity);
    }
    let among = |list: &str, keep: &dyn Fn(&Value) -> bool| -> Value {
        Value::Array(
            bundle[list]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|item| keep(item))
                .cloned()
                .collect(),
        )
    };
    let has = |value: &Value| value.as_str().is_some_and(|name| chosen.contains_key(name));
    let mut selected = json!({
        "format": bundle["format"],
        "requires": bundle["requires"],
        "partial": true,
        "entities": chosen.values().collect::<Vec<_>>(),
        "queries": among("queries", &|query| has(&query["entity"])),
        "views": among("views", &|view| has(&view["entity"])),
        "relationships": among("relationships", &|relation| {
            has(&relation["entity_a"]) && has(&relation["entity_b"])
        }),
    });
    for key in ["name", "version"] {
        if !bundle[key].is_null() {
            selected[key] = bundle[key].clone();
        }
    }
    Ok(selected)
}

/// The folder to promote: `--dir`, or a temporary one holding the selection.
fn selection(args: &PromoteArgs) -> Result<Option<PathBuf>, String> {
    if args.only.is_empty() {
        return Ok(None);
    }
    let bundle = crate::cmd::config_cmd::read_bundle(&args.dir)?;
    let selected = select(&bundle, &args.only)?;
    let dir = std::env::temp_dir().join(format!("attome-promote-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join(crate::cmd::config_cmd::BUNDLE_FILE);
    std::fs::write(&path, selected.to_string())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(Some(dir))
}

/// A parsed `attome promote`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromoteArgs {
    pub dir: PathBuf,
    pub to: String,
    pub copy: Option<String>,
    pub at: Option<DateTime<Utc>>,
    pub allow_retire: bool,
    /// A22-T3: the entities to promote; empty promotes the whole folder.
    pub only: Vec<String>,
    pub report: Option<PathBuf>,
    pub yes: bool,
    pub confirm_target: Option<String>,
}

/// Parses what follows `attome promote`. Pure.
pub fn parse(args: &[String]) -> Result<PromoteArgs, String> {
    use crate::cmd::output::{take_flag, take_value};
    let mut args = args.to_vec();
    let yes = take_flag(&mut args, "--yes");
    let allow_retire = take_flag(&mut args, "--allow-retire");
    let dir = take_value(&mut args, "--dir")?.ok_or(USAGE)?;
    let to = take_value(&mut args, "--to")?.ok_or(USAGE)?;
    let copy = take_value(&mut args, "--copy")?;
    let at = take_value(&mut args, "--at")?
        .map(|at| {
            DateTime::parse_from_rfc3339(&at)
                .map(|at| at.with_timezone(&Utc))
                .map_err(|_| format!("--at: `{at}` is not an RFC 3339 time"))
        })
        .transpose()?;
    let only: Vec<String> = take_value(&mut args, "--only")?
        .map(|names| {
            names
                .split(',')
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let report = take_value(&mut args, "--report")?.map(PathBuf::from);
    let confirm_target = take_value(&mut args, "--confirm-target")?;
    if !args.is_empty() {
        return Err(USAGE.to_owned());
    }
    if copy.as_deref() == Some(to.as_str()) {
        return Err("--copy must not be the target it rehearses".to_owned());
    }
    Ok(PromoteArgs {
        dir: dir.into(),
        to,
        copy,
        at,
        allow_retire,
        only,
        report,
        yes,
        confirm_target,
    })
}

/// How a queued plan ended, or `None` while it runs. Pure.
pub fn finished(status: &str) -> Option<Result<(), String>> {
    match status {
        "succeeded" => Some(Ok(())),
        "planned" | "queued" | "claimed" | "applying" => None,
        other => Some(Err(format!("the plan ended {other}"))),
    }
}

/// Applies the plan on the copy and waits for it to end.
async fn dry_run(url: &str, auth: &Auth, dir: &Path, allow_retire: bool) -> Result<Value, String> {
    let planned = plan(url, auth, dir, allow_retire).await?;
    if planned["applicable"] != true {
        return Err(format!("dry run: {}", plan_line(&planned)));
    }
    let plan_id = planned["plan_id"].as_str().ok_or("dry run: no plan id")?;
    let applied = send(
        url,
        auth,
        reqwest::Method::POST,
        "/import?mode=apply",
        Some(json!({ "plan_id": plan_id })),
    )
    .await?;
    if applied["approval_pending"] == true {
        return Err("dry run: the copy holds applies for approval".to_owned());
    }
    let deadline = tokio::time::Instant::now() + DRY_RUN_WAIT;
    loop {
        let plan = send(
            url,
            auth,
            reqwest::Method::GET,
            &format!("/plans/{plan_id}"),
            None,
        )
        .await?;
        let status = plan["status"].as_str().unwrap_or("").to_owned();
        match finished(&status) {
            Some(Ok(())) => return Ok(json!({ "plan_id": plan_id, "status": status })),
            Some(Err(message)) => return Err(format!("dry run: {message}: {plan}")),
            None if tokio::time::Instant::now() >= deadline => {
                return Err(format!("dry run: still {status} after {DRY_RUN_WAIT:?}"));
            }
            None => tokio::time::sleep(Duration::from_secs(2)).await,
        }
    }
}

async fn promote(args: &PromoteArgs, dir: &Path) -> Result<Value, String> {
    let (url, auth) = credentials(String::new(), None, Some(args.to.clone())).await?;
    let planned = plan(&url, &auth, dir, args.allow_retire).await?;
    println!("{}: {}", args.to, plan_line(&planned));
    if planned["applicable"] != true {
        return Err("not promoted: the plan has blocked entries".to_owned());
    }
    let mut report = json!({
        "to": args.to,
        "planned_at": Utc::now(),
        "changes": { "entries": planned["entries"], "retires": planned["retires"] },
    });
    if let Some(copy) = &args.copy {
        let (copy_url, copy_auth) = credentials(String::new(), None, Some(copy.clone())).await?;
        let result = dry_run(&copy_url, &copy_auth, dir, args.allow_retire).await?;
        println!("dry run on {copy} succeeded");
        report["dry_run"] = json!({ "copy": copy, "result": result });
    }
    if let Some(at) = args.at {
        let wait = (at - Utc::now()).to_std().unwrap_or(Duration::ZERO);
        println!("applying to {} at {at}", args.to);
        tokio::time::sleep(wait).await;
        // What the plan was checked against may have moved while it waited.
    }
    let planned = plan(&url, &auth, dir, args.allow_retire).await?;
    if planned["applicable"] != true {
        return Err(format!("not promoted: {}", plan_line(&planned)));
    }
    let applied = send(
        &url,
        &auth,
        reqwest::Method::POST,
        "/import?mode=apply",
        Some(json!({ "plan_id": planned["plan_id"] })),
    )
    .await?;
    println!(
        "plan {} {}",
        applied["plan_id"].as_str().unwrap_or("?"),
        if applied["approval_pending"] == true {
            "waits for a second administrator's approval"
        } else {
            "queued"
        }
    );
    report["apply"] = applied;
    Ok(report)
}

/// `attome promote`.
pub fn run(args: &[String]) -> Result<(), String> {
    let args = parse(args)?;
    crate::cmd::output::confirm(
        "promote",
        args.yes,
        args.confirm_target.as_deref(),
        Some((&args.to, is_production(Some(&args.to)))),
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    let selected = selection(&args)?;
    let report = runtime.block_on(promote(&args, selected.as_deref().unwrap_or(&args.dir)));
    if let Some(dir) = &selected {
        let _ = std::fs::remove_dir_all(dir);
    }
    let report = report?;
    if let Some(path) = &args.report {
        let text = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        std::fs::write(path, text + "\n")
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        println!("report: {}", path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn promotion_arguments_parse() {
        let args = parse(&words(&[
            "--dir",
            "cfg",
            "--to",
            "prod",
            "--copy",
            "prod-copy",
            "--at",
            "2026-11-01T22:00:00Z",
            "--yes",
        ]))
        .expect("arguments");
        assert_eq!(args.to, "prod");
        assert_eq!(args.copy.as_deref(), Some("prod-copy"));
        assert!(args.at.is_some() && args.yes);
        assert!(parse(&words(&["--dir", "cfg"])).is_err());
        assert!(parse(&words(&["--dir", "c", "--to", "a", "--copy", "a"])).is_err());
        assert!(parse(&words(&["--dir", "c", "--to", "a", "--at", "soon"])).is_err());
    }

    #[test]
    fn selecting_an_entity_brings_what_it_needs_and_nothing_else() {
        let bundle = json!({
            "format": "attome-bundle/v1",
            "requires": {},
            "entities": [
                { "logicalname": "deal", "attributes": [{ "lookup_entity": "account" }] },
                { "logicalname": "account", "attributes": [] },
                { "logicalname": "other", "attributes": [] },
            ],
            "queries": [{ "entity": "deal" }, { "entity": "other" }],
            "views": [{ "entity": "account" }],
            "relationships": [
                { "entity_a": "deal", "entity_b": "account" },
                { "entity_a": "deal", "entity_b": "other" },
            ],
            "roles": [{ "name": "everything" }],
        });
        let selected = select(&bundle, &["deal".to_owned()]).expect("selected");
        let names: Vec<&str> = selected["entities"]
            .as_array()
            .expect("entities")
            .iter()
            .filter_map(|e| e["logicalname"].as_str())
            .collect();
        assert_eq!(names, ["account", "deal"], "a lookup brings its target");
        assert_eq!(selected["partial"], true);
        assert_eq!(selected["queries"].as_array().map(Vec::len), Some(1));
        assert_eq!(selected["views"].as_array().map(Vec::len), Some(1));
        assert_eq!(selected["relationships"].as_array().map(Vec::len), Some(1));
        assert!(selected.get("roles").is_none());
        assert!(select(&bundle, &["nothing".to_owned()]).is_err());
    }

    #[test]
    fn a_plan_finishes_only_when_it_ends() {
        assert_eq!(finished("succeeded"), Some(Ok(())));
        assert_eq!(finished("applying"), None);
        assert!(matches!(finished("failed"), Some(Err(_))));
    }
}
