//! The maintainer's advisory sweep (roadmap AC7-T10):
//! `attome release advisories`.
//!
//! For every supported release (each `lts` entry in the stability ledger plus
//! the latest release), it checks the tag out into a throwaway worktree, runs
//! `cargo deny check advisories` and `npm audit --omit=dev` there, prints one
//! line per finding and writes `target/advisories/<date>.json`. The worktrees
//! are removed on every path. SECURITY.md states the response deadlines.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

/// The tags to sweep: every `lts` release in the ledger plus the latest
/// release (the last entry that was not rolled back), without duplicates.
pub fn supported_tags(ledger: &Value) -> Vec<String> {
    let releases = ledger["releases"].as_array().cloned().unwrap_or_default();
    let mut tags: Vec<String> = releases
        .iter()
        .filter(|r| r["type"] == "lts")
        .filter_map(|r| r["version"].as_str().map(|v| format!("v{v}")))
        .collect();
    if let Some(latest) = releases
        .iter()
        .rev()
        .find(|r| r["rolled_back"] != Value::Bool(true))
        .and_then(|r| r["version"].as_str())
    {
        let tag = format!("v{latest}");
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    tags
}

/// Removes the worktree when dropped, so every exit path cleans up.
struct Worktree<'a> {
    root: &'a Path,
    path: PathBuf,
}

impl Drop for Worktree<'_> {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force"])
            .arg(&self.path)
            .current_dir(self.root)
            .output();
    }
}

fn sweep_tag(root: &Path, tag: &str) -> Value {
    let path =
        std::env::temp_dir().join(format!("attome-advisories-{}-{}", tag, std::process::id()));
    let added = Command::new("git")
        .args(["worktree", "add", "--detach"])
        .arg(&path)
        .arg(tag)
        .current_dir(root)
        .output();
    if !added.as_ref().is_ok_and(|out| out.status.success()) {
        return json!({ "tag": tag, "error": "cannot check the tag out" });
    }
    let _guard = Worktree {
        root,
        path: path.clone(),
    };
    let deny = Command::new("cargo")
        .args(["deny", "check", "advisories"])
        .current_dir(&path)
        .output();
    let npm = Command::new(crate::npm_program("npm"))
        .args(["audit", "--omit=dev", "--json"])
        .current_dir(path.join("web"))
        .output();
    let npm_findings: Vec<Value> = npm
        .ok()
        .and_then(|out| serde_json::from_slice::<Value>(&out.stdout).ok())
        .and_then(|report| report["vulnerabilities"].as_object().cloned())
        .map(|found| {
            found
                .iter()
                .map(|(name, v)| json!({ "package": name, "severity": v["severity"] }))
                .collect()
        })
        .unwrap_or_default();
    let (deny_passed, deny_text) = match deny {
        Ok(out) => (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(error) => (false, format!("cannot run cargo deny: {error}")),
    };
    let rust_findings: Vec<Value> = deny_text
        .lines()
        .filter(|line| line.contains("RUSTSEC-"))
        .map(|line| json!(line.trim()))
        .collect();
    json!({
        "tag": tag,
        "cargo_deny_advisories_passed": deny_passed,
        "rust": rust_findings,
        "npm": npm_findings,
    })
}

/// `attome release advisories`.
pub fn run(root: &Path, today: &str) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join(crate::release::LEDGER))
        .map_err(|error| format!("{}: {error}", crate::release::LEDGER))?;
    let ledger: Value = serde_json::from_str(&text).map_err(|error| error.to_string())?;
    let tags = supported_tags(&ledger);
    if tags.is_empty() {
        crate::say("no released versions in the stability ledger yet; nothing to sweep");
        return Ok(());
    }
    let results: Vec<Value> = tags.iter().map(|tag| sweep_tag(root, tag)).collect();
    for result in &results {
        let tag = result["tag"].as_str().unwrap_or("?");
        for finding in result["rust"].as_array().into_iter().flatten() {
            crate::say(&format!("{tag}  rust  {}", finding.as_str().unwrap_or("")));
        }
        for finding in result["npm"].as_array().into_iter().flatten() {
            crate::say(&format!(
                "{tag}  npm   {} ({})",
                finding["package"].as_str().unwrap_or("?"),
                finding["severity"].as_str().unwrap_or("?")
            ));
        }
    }
    let dir = root.join("target").join("advisories");
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let path = dir.join(format!("{today}.json"));
    let body = json!({ "date": today, "tags": results });
    std::fs::write(&path, body.to_string() + "\n")
        .map_err(|error| format!("{}: {error}", path.display()))?;
    crate::say(&format!("wrote {}", path.display()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_tags_are_lts_plus_latest() {
        let ledger = json!({ "releases": [
            { "version": "2.0.0", "type": "lts", "rolled_back": false },
            { "version": "2.1.0", "type": "release", "rolled_back": false },
            { "version": "2.2.0", "type": "release", "rolled_back": false },
            { "version": "2.3.0", "type": "release", "rolled_back": true }
        ]});
        assert_eq!(supported_tags(&ledger), ["v2.0.0", "v2.2.0"]);
        assert!(supported_tags(&json!({ "releases": [] })).is_empty());
        let only_lts = json!({ "releases": [{ "version": "2.0.0", "type": "lts" }] });
        assert_eq!(
            supported_tags(&only_lts),
            ["v2.0.0"],
            "the latest is not listed twice"
        );
    }
}
