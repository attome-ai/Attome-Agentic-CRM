//! Cutting a release (roadmap AC4-T10) and the stability ledger (AC4-T12).
//!
//! `attome release tag <version>` refuses unless the tracked tree is clean,
//! the tag is new, `CHANGELOG.md`'s `[Unreleased]` section says something,
//! and both operating systems' gate reports for this commit are green
//! ([`crate::parity`]). Then it bumps `[workspace.package] version` in
//! `Cargo.toml`, moves `[Unreleased]` under `## [x.y.z] - YYYY-MM-DD`,
//! appends the release to `docs/releases/stability.json`, commits
//! `release: vX.Y.Z` and creates an annotated tag. It never pushes.
//!
//! The ledger records, per release, the defects that escaped into it, whether
//! it was a hotfix of another and whether it was rolled back:
//! `attome release stability add-defect <version> <issue-ref>` and
//! `attome release stability rollback <version>`.

use std::path::Path;

use serde_json::{Value, json};

pub const LEDGER: &str = "docs/releases/stability.json";

/// `Cargo.toml` with `[workspace.package] version` set to `version`.
pub fn bump_workspace_version(cargo_toml: &str, version: &str) -> Result<String, String> {
    let mut out = String::with_capacity(cargo_toml.len());
    let mut in_package = false;
    let mut done = false;
    for line in cargo_toml.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[workspace.package]";
        }
        if in_package && !done && trimmed.starts_with("version") && trimmed.contains('=') {
            let indent_end = line.find('=').unwrap_or(0);
            let ending = if line.ends_with('\n') { "\n" } else { "" };
            out.push_str(&format!("{}= \"{version}\"{ending}", &line[..indent_end]));
            done = true;
        } else {
            out.push_str(line);
        }
    }
    if done {
        Ok(out)
    } else {
        Err("Cargo.toml has no [workspace.package] version".to_owned())
    }
}

/// `CHANGELOG.md` with `[Unreleased]` moved under the new version and a
/// fresh, empty `[Unreleased]` above it. Refuses an empty `[Unreleased]`.
pub fn move_unreleased(changelog: &str, version: &str, date: &str) -> Result<String, String> {
    let marker = "## [Unreleased]";
    let start = changelog
        .find(marker)
        .ok_or("CHANGELOG.md has no ## [Unreleased] section")?;
    let after = start + marker.len();
    let end = changelog[after..]
        .find("\n## [")
        .map_or(changelog.len(), |offset| after + offset + 1);
    let body = &changelog[after..end];
    let says_something = body
        .lines()
        .any(|line| !line.trim().is_empty() && !line.trim_start().starts_with("###"));
    if !says_something {
        return Err("CHANGELOG.md's [Unreleased] section is empty; say what changed".to_owned());
    }
    Ok(format!(
        "{}{marker}\n\n## [{version}] - {date}{body}{}",
        &changelog[..start],
        &changelog[end..]
    ))
}

fn read_ledger(text: Option<&str>) -> Result<Value, String> {
    match text {
        None => Ok(json!({ "releases": [] })),
        Some(text) => serde_json::from_str(text).map_err(|error| format!("{LEDGER}: {error}")),
    }
}

fn releases(ledger: &mut Value) -> Result<&mut Vec<Value>, String> {
    ledger["releases"]
        .as_array_mut()
        .ok_or_else(|| format!("{LEDGER} has no releases list"))
}

/// The ledger with a new release entry (hotfix of nothing, not rolled back).
pub fn ledger_add_release(text: Option<&str>, version: &str, date: &str) -> Result<String, String> {
    let mut ledger = read_ledger(text)?;
    let list = releases(&mut ledger)?;
    if list.iter().any(|r| r["version"] == version) {
        return Err(format!("{LEDGER} already lists {version}"));
    }
    list.push(json!({
        "version": version,
        "date": date,
        "type": "release",
        "escaped_defects": [],
        "hotfix_of": Value::Null,
        "rolled_back": false,
    }));
    render(&ledger)
}

fn entry<'a>(ledger: &'a mut Value, version: &str) -> Result<&'a mut Value, String> {
    releases(ledger)?
        .iter_mut()
        .find(|r| r["version"] == version)
        .ok_or_else(|| format!("{LEDGER} has no release {version}"))
}

/// The ledger with `issue` recorded as a defect that escaped into `version`.
pub fn ledger_add_defect(text: &str, version: &str, issue: &str) -> Result<String, String> {
    let mut ledger = read_ledger(Some(text))?;
    let release = entry(&mut ledger, version)?;
    let defects = release["escaped_defects"]
        .as_array_mut()
        .ok_or("escaped_defects is not a list")?;
    if !defects.iter().any(|d| d == issue) {
        defects.push(Value::String(issue.to_owned()));
    }
    render(&ledger)
}

/// The ledger with `version` marked rolled back.
pub fn ledger_rollback(text: &str, version: &str) -> Result<String, String> {
    let mut ledger = read_ledger(Some(text))?;
    entry(&mut ledger, version)?["rolled_back"] = Value::Bool(true);
    render(&ledger)
}

fn render(ledger: &Value) -> Result<String, String> {
    serde_json::to_string_pretty(ledger)
        .map(|text| text + "\n")
        .map_err(|error| error.to_string())
}

/// `attome release stability add-defect|rollback ...`.
pub fn stability(root: &Path, args: &[String]) -> Result<(), String> {
    let path = root.join(LEDGER);
    let text = std::fs::read_to_string(&path).map_err(|error| format!("{LEDGER}: {error}"))?;
    let updated = match args {
        [verb, version, issue] if verb == "add-defect" => ledger_add_defect(&text, version, issue)?,
        [verb, version] if verb == "rollback" => ledger_rollback(&text, version)?,
        _ => {
            return Err(
                "usage: attome release stability add-defect <version> <issue-ref> | rollback <version>"
                    .to_owned(),
            );
        }
    };
    std::fs::write(&path, updated).map_err(|error| format!("{LEDGER}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHANGELOG: &str = "# Changelog\n\nIntro.\n\n## [Unreleased]\n\n### Added\n- A thing.\n\n## [0.1.0] - 2026-01-01\n\n- Old.\n";

    #[test]
    fn changelog_unreleased_moves_to_version() {
        let moved = move_unreleased(CHANGELOG, "0.2.0", "2026-10-14").unwrap();
        assert!(moved.contains(
            "## [Unreleased]\n\n## [0.2.0] - 2026-10-14\n\n### Added\n- A thing.\n\n## [0.1.0]"
        ));
        assert!(moved.starts_with("# Changelog\n\nIntro.\n\n"));
    }

    #[test]
    fn tag_refuses_empty_unreleased() {
        let empty = "# Changelog\n\n## [Unreleased]\n\n### Added\n\n## [0.1.0] - 2026-01-01\n";
        assert!(move_unreleased(empty, "0.2.0", "2026-10-14").is_err());
        assert!(move_unreleased("# nothing\n", "0.2.0", "2026-10-14").is_err());
    }

    #[test]
    fn the_workspace_version_is_bumped_only_in_workspace_package() {
        let toml = "[workspace]\nmembers = []\n\n[workspace.package]\nversion      = \"0.1.0\"\nedition = \"2024\"\n\n[workspace.dependencies]\nx = { version = \"1\" }\n";
        let bumped = bump_workspace_version(toml, "0.2.0").unwrap();
        assert!(bumped.contains("version      = \"0.2.0\"\n"));
        assert!(bumped.contains("x = { version = \"1\" }"));
        assert!(bump_workspace_version("[workspace]\n", "1.0.0").is_err());
    }

    #[test]
    fn add_defect_appends_ref() {
        let ledger = ledger_add_release(None, "0.2.0", "2026-10-14").unwrap();
        let ledger = ledger_add_defect(&ledger, "0.2.0", "#42").unwrap();
        let ledger = ledger_add_defect(&ledger, "0.2.0", "#42").unwrap();
        let value: Value = serde_json::from_str(&ledger).unwrap();
        assert_eq!(value["releases"][0]["escaped_defects"], json!(["#42"]));
        assert!(ledger_add_defect(&ledger, "9.9.9", "#1").is_err());
    }

    #[test]
    fn rollback_sets_flag() {
        let ledger = ledger_add_release(None, "0.2.0", "2026-10-14").unwrap();
        let value: Value =
            serde_json::from_str(&ledger_rollback(&ledger, "0.2.0").unwrap()).unwrap();
        assert_eq!(value["releases"][0]["rolled_back"], true);
        assert!(ledger_add_release(Some(&ledger), "0.2.0", "2026-10-14").is_err());
    }
}
