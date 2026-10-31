//! A21-T4: `attome app export|install|remove`, one app's metadata objects
//! moved as a unit through a deployment's admin API.
//!
//! ```text
//! attome app export <app> --out <dir>
//! attome app install --dir <dir> [--yes] [--confirm-target <name>]
//! attome app remove <app>
//!   each with [--target <name> | --url <url>] [--json]
//! ```
//!
//! An app's objects are the store's files under `<kind>/<app>/`. `install`
//! shows what is new, changed and the same on the target; with `--yes` it
//! imports them and publishes each one, stopping at the first refusal. `remove`
//! changes nothing: the model store has no way to retire an object, so it lists
//! what would go and what stays behind.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::cmd::login::credentials;
use crate::cmd::model_files::{
    exported_files, import_files, publish_object, read_tree, safe_write,
};
use crate::cmd::output::{confirm, envelope, take_flag, take_value};

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
const USAGE: &str = "usage: attome app export <app> --out <dir>\n       attome app install --dir <dir> [--yes] [--confirm-target <name>]\n       attome app remove <app>\n  each with [--target <name> | --url <url>] [--json]";

/// What a deployment already has of an app's files.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Diff {
    pub new: Vec<String>,
    pub changed: Vec<String>,
    pub same: Vec<String>,
}

/// Compares the files of a folder with a deployment's. Pure.
pub fn diff(files: &[(String, String)], live: &BTreeMap<String, String>) -> Diff {
    let mut diff = Diff::default();
    for (path, text) in files {
        match live.get(path) {
            None => diff.new.push(path.clone()),
            Some(current) if current.replace("\r\n", "\n") == text.replace("\r\n", "\n") => {
                diff.same.push(path.clone());
            }
            Some(_) => diff.changed.push(path.clone()),
        }
    }
    diff
}

/// Whether `path` is one of `app`'s object files. Pure.
pub fn in_app(path: &str, app: &str) -> bool {
    path.split('/').nth(1) == Some(app) && path.split('/').count() >= 3
}

/// The `kind/app/name` an object file holds. Pure.
fn object_of(path: &str) -> String {
    path.strip_suffix(".json").unwrap_or(path).to_owned()
}

/// The drafts an import saved, as (kind, id): `drafts` follow the files, less
/// the ones it left `unchanged`. Pure.
pub fn drafted(
    files: &[(String, String)],
    unchanged: &[String],
    drafts: &[Value],
) -> Result<Vec<(String, String)>, String> {
    let saved: Vec<&String> = files
        .iter()
        .map(|(path, _)| path)
        .filter(|path| !unchanged.contains(&object_of(path)))
        .collect();
    if saved.len() != drafts.len() {
        return Err(format!(
            "the server saved {} draft(s) for {} changed file(s); publish them by hand",
            drafts.len(),
            saved.len()
        ));
    }
    saved
        .iter()
        .zip(drafts)
        .map(|(path, draft)| {
            let kind = path.split('/').next().unwrap_or_default().to_owned();
            let id = draft["id"].as_str().ok_or("a draft without an id")?;
            Ok((kind, id.to_owned()))
        })
        .collect()
}

fn lines(diff: &Diff) -> String {
    let mut out = format!(
        "{} new, {} changed, {} the same",
        diff.new.len(),
        diff.changed.len(),
        diff.same.len()
    );
    for (mark, paths) in [("+", &diff.new), ("~", &diff.changed)] {
        for path in paths {
            out.push_str(&format!("\n{mark} {path}"));
        }
    }
    out
}

/// `attome app`.
pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let as_json = take_flag(&mut args, "--json");
    let yes = take_flag(&mut args, "--yes");
    let confirm_target = take_value(&mut args, "--confirm-target")?;
    let target = take_value(&mut args, "--target")?;
    let out = take_value(&mut args, "--out")?;
    let dir = take_value(&mut args, "--dir")?;
    let url = take_value(&mut args, "--url")?
        .or_else(|| std::env::var("ATTOME_URL").ok())
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    let (kind, answer, line) = runtime.block_on(async {
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth) = credentials(
            url.trim_end_matches('/').to_owned(),
            api_key,
            target.clone(),
        )
        .await?;
        match words.as_slice() {
            ["export", app] => {
                let out = PathBuf::from(out.ok_or(USAGE)?);
                let files = exported_files(&url, auth).await?;
                let mine: Vec<_> = files.iter().filter(|(p, _)| in_app(p, app)).collect();
                for (path, text) in &mine {
                    safe_write(&out, path, text)?;
                }
                let line = format!("exported {} object(s) to {}", mine.len(), out.display());
                Ok::<_, String>(("app_export", json!({ "objects": mine.len() }), line))
            }
            ["install"] => {
                let dir = PathBuf::from(dir.ok_or(USAGE)?);
                let files = read_tree(&dir)?;
                let live: BTreeMap<_, _> = exported_files(&url, auth.clone())
                    .await?
                    .into_iter()
                    .collect();
                let changes = diff(&files, &live);
                let preview = lines(&changes);
                if !yes {
                    let line = format!("{preview}\nnothing changed; add --yes to install");
                    return Ok(("app_install", json!({ "diff": changes }), line));
                }
                let named = target
                    .as_deref()
                    .map(|t| (t, crate::cmd::login::is_production(Some(t))));
                confirm("app install", yes, confirm_target.as_deref(), named)?;
                let body = import_files(&url, auth.clone(), &dir).await?;
                let unchanged: Vec<String> = body["unchanged"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect();
                let drafts = body["drafts"].as_array().cloned().unwrap_or_default();
                let objects = drafted(&files, &unchanged, &drafts)?;
                for (kind, id) in &objects {
                    publish_object(&url, auth.clone(), kind, id).await?;
                }
                let line = format!("{preview}\npublished {} object(s)", objects.len());
                Ok((
                    "app_install",
                    json!({ "diff": changes, "published": objects.len() }),
                    line,
                ))
            }
            ["remove", app] => {
                let files = exported_files(&url, auth).await?;
                let mine: Vec<&String> = files
                    .iter()
                    .map(|(path, _)| path)
                    .filter(|path| in_app(path, app))
                    .collect();
                let line = format!(
                    "{} object(s) belong to {app}; nothing was removed, objects cannot be \
                     retired yet. Entities, their records and the fields they added stay.\n{}",
                    mine.len(),
                    mine.iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                Ok(("app_remove", json!({ "objects": mine }), line))
            }
            _ => Err(USAGE.to_owned()),
        }
    })?;
    if as_json {
        println!("{}", envelope(kind, answer));
    } else {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, text: &str) -> (String, String) {
        (path.to_owned(), text.to_owned())
    }

    #[test]
    fn install_shows_what_is_new_changed_and_the_same() {
        let live: BTreeMap<_, _> = [
            file("form/sales/a.json", "1\n"),
            file("form/sales/b.json", "2\n"),
        ]
        .into_iter()
        .collect();
        let changes = diff(
            &[
                file("form/sales/a.json", "1\r\n"),
                file("form/sales/b.json", "3\n"),
                file("form/sales/c.json", "4\n"),
            ],
            &live,
        );
        assert_eq!(changes.same, ["form/sales/a.json"]);
        assert_eq!(changes.changed, ["form/sales/b.json"]);
        assert_eq!(changes.new, ["form/sales/c.json"]);
    }

    #[test]
    fn an_app_is_its_folder() {
        assert!(in_app("form/sales/a.json", "sales"));
        assert!(!in_app("form/service/a.json", "sales"));
        assert!(!in_app("sales", "sales"));
    }

    #[test]
    fn drafts_follow_the_files_less_the_unchanged() {
        let files = [file("form/s/a.json", ""), file("page/s/b.json", "")];
        let unchanged = ["form/s/a".to_owned()];
        let got = drafted(&files, &unchanged, &[json!({ "id": "1" })]).expect("drafted");
        assert_eq!(got, [("page".to_owned(), "1".to_owned())]);
        assert!(drafted(&files, &[], &[json!({ "id": "1" })]).is_err());
    }
}
