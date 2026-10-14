//! Supply-chain gate steps (roadmap AC7-T1, AC7-T2).
//!
//! - `waivers`: every waiver is reviewable and still in date: each
//!   `deny.toml` advisory ignore carries a `reason` naming an `Owner:` and a
//!   `revisit YYYY-MM-DD` that has not passed; each `web/audit-waivers.yaml`
//!   entry has an owner, a severity npm's thresholds can actually let through
//!   (`low`/`moderate`, and `low` only for `prod`) and a `revisit` date that has
//!   not passed; each `.trivyignore.yaml` entry (when the file exists) has
//!   `purls`, an owner and an `expired_at` that has not passed.
//! - `cargo_deny`: `cargo deny check` (advisories, licences, bans, sources).
//! - `npm_licences`: every production package in `web/package-lock.json`
//!   carries a licence on `deny.toml`'s allow-list.
//!
//! The files are line-based by design, so they are read line by line here,
//! with no YAML or TOML parser.

use std::path::Path;

use serde_json::Value;

/// A dated, owned waiver problem.
fn problem(file: &str, what: &str) -> String {
    format!("{file}: {what}")
}

/// `YYYY-MM-DD` dates in `text`, in order.
fn dates(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    for start in 0..bytes.len().saturating_sub(9) {
        if !text.is_char_boundary(start) || !text.is_char_boundary(start + 10) {
            continue;
        }
        let window = &text[start..start + 10];
        let shape = window.char_indices().all(|(i, c)| match i {
            4 | 7 => c == '-',
            _ => c.is_ascii_digit(),
        });
        if shape {
            out.push(window.to_owned());
        }
    }
    out
}

/// Problems with `deny.toml`'s advisory ignores.
pub fn deny_waivers(text: &str, today: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with("{ id = ") && !line.starts_with("{id=") {
            continue;
        }
        let id = line.split('"').nth(1).unwrap_or("?");
        if !line.contains("reason") {
            out.push(problem("deny.toml", &format!("{id} has no reason")));
            continue;
        }
        if !line.contains("Owner:") {
            out.push(problem(
                "deny.toml",
                &format!("{id}: the reason names no Owner:"),
            ));
        }
        match line
            .split("revisit")
            .nth(1)
            .and_then(|rest| dates(rest).into_iter().next())
        {
            Some(date) if date.as_str() < today => {
                out.push(problem(
                    "deny.toml",
                    &format!("{id}: revisit {date} has passed"),
                ));
            }
            Some(_) => {}
            None => out.push(problem(
                "deny.toml",
                &format!("{id}: no `revisit YYYY-MM-DD`"),
            )),
        }
    }
    out
}

/// One `- id:` entry of a line-based YAML list: its `key: value` lines.
fn entries(text: &str) -> Vec<Vec<(String, String)>> {
    let mut out: Vec<Vec<(String, String)>> = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("- id:") {
            out.push(vec![("id".to_owned(), unquote(rest))]);
        } else if let Some(entry) = out.last_mut()
            && let Some((key, value)) = trimmed.split_once(':')
            && !key.contains(' ')
            && !key.starts_with('-')
        {
            entry.push((key.to_owned(), unquote(value)));
        } else if let Some(entry) = out.last_mut()
            && trimmed.starts_with("- ")
        {
            // A list item under the previous key (`purls`, `packages`).
            entry.push(("item".to_owned(), unquote(&trimmed[2..])));
        }
    }
    out
}

fn unquote(value: &str) -> String {
    value.trim().trim_matches('"').trim_matches('\'').to_owned()
}

fn field<'a>(entry: &'a [(String, String)], key: &str) -> Option<&'a str> {
    entry
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Problems with `web/audit-waivers.yaml`.
pub fn npm_waivers(text: &str, today: &str) -> Vec<String> {
    let file = "web/audit-waivers.yaml";
    let mut out = Vec::new();
    for entry in entries(text) {
        let id = field(&entry, "id").unwrap_or("?").to_owned();
        let severity = field(&entry, "severity").unwrap_or_default();
        let scope = field(&entry, "scope").unwrap_or_default();
        if !field(&entry, "statement").is_some_and(|s| s.starts_with("Owner: ")) {
            out.push(problem(
                file,
                &format!("{id}: statement must start with `Owner: `"),
            ));
        }
        if !matches!(severity, "low" | "moderate") {
            out.push(problem(
                file,
                &format!("{id}: severity must be low or moderate"),
            ));
        }
        match scope {
            "prod" if severity != "low" => out.push(problem(
                file,
                &format!("{id}: a prod waiver must be low (audit:prod fails at moderate)"),
            )),
            "prod" | "dev" => {}
            _ => out.push(problem(file, &format!("{id}: scope must be dev or prod"))),
        }
        match field(&entry, "revisit") {
            Some(date) if date.len() == 10 && date >= today => {}
            Some(date) if date.len() == 10 => {
                out.push(problem(file, &format!("{id}: revisit {date} has passed")));
            }
            _ => out.push(problem(file, &format!("{id}: revisit must be YYYY-MM-DD"))),
        }
    }
    out
}

/// Problems with `.trivyignore.yaml`.
pub fn trivy_waivers(text: &str, today: &str) -> Vec<String> {
    let file = ".trivyignore.yaml";
    let mut out = Vec::new();
    for entry in entries(text) {
        let id = field(&entry, "id").unwrap_or("?").to_owned();
        if field(&entry, "item").is_none() {
            out.push(problem(file, &format!("{id}: no purls")));
        }
        if !field(&entry, "statement").is_some_and(|s| s.starts_with("Owner: ")) {
            out.push(problem(
                file,
                &format!("{id}: statement must start with `Owner: `"),
            ));
        }
        match field(&entry, "expired_at").map(|e| e.get(..10).unwrap_or(e).to_owned()) {
            Some(date) if date.len() == 10 && date.as_str() >= today => {}
            Some(date) => out.push(problem(
                file,
                &format!("{id}: expired_at {date} has passed"),
            )),
            None => out.push(problem(file, &format!("{id}: no expired_at"))),
        }
    }
    out
}

/// The licence allow-list from `deny.toml`'s `[licenses] allow = [...]`:
/// the quoted strings in the list, comments dropped.
pub fn allowed_licences(deny: &str) -> Vec<String> {
    let Some(start) = deny.find("allow = [") else {
        return Vec::new();
    };
    let rest = &deny[start + "allow = [".len()..];
    let mut out = Vec::new();
    for line in rest.lines() {
        let code = line.split('#').next().unwrap_or_default();
        let mut parts = code.split('"');
        // Odd-numbered pieces are inside quotes.
        parts.next();
        while let Some(inside) = parts.next() {
            out.push(inside.to_owned());
            parts.next();
        }
        if code.contains(']') {
            break;
        }
    }
    out
}

/// Whether an SPDX expression is satisfied by the allow-list: any `OR`
/// branch whose every `AND` term is allowed.
fn licence_ok(expression: &str, allowed: &[String]) -> bool {
    let cleaned = expression.replace(['(', ')'], " ");
    cleaned.split(" OR ").any(|branch| {
        branch
            .split(" AND ")
            .map(str::trim)
            .all(|term| allowed.iter().any(|a| a == term))
    })
}

/// Production packages in a `package-lock.json` (v2/v3) whose licence is not
/// allowed, as `name@version licence`.
pub fn npm_licence_problems(lock: &Value, allowed: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(packages) = lock["packages"].as_object() else {
        return vec!["package-lock.json has no `packages` map".to_owned()];
    };
    for (path, package) in packages {
        // The root, dev-only packages, and the workspace's own libraries
        // (linked, or outside node_modules) are not third-party code.
        if path.is_empty()
            || package["dev"].as_bool() == Some(true)
            || package["link"].as_bool() == Some(true)
            || !path.contains("node_modules/")
        {
            continue;
        }
        let name = path.rsplit("node_modules/").next().unwrap_or(path);
        let version = package["version"].as_str().unwrap_or("?");
        let licence = package["license"].as_str().unwrap_or("");
        if licence.is_empty() || !licence_ok(licence, allowed) {
            out.push(format!(
                "{name}@{version} {}",
                if licence.is_empty() {
                    "(none)"
                } else {
                    licence
                }
            ));
        }
    }
    out
}

/// The `waivers` gate step.
pub fn waivers_step(root: &Path, today: &str) -> Result<(), String> {
    let mut problems = Vec::new();
    if let Ok(text) = std::fs::read_to_string(root.join("deny.toml")) {
        problems.extend(deny_waivers(&text, today));
    }
    if let Ok(text) = std::fs::read_to_string(root.join("web").join("audit-waivers.yaml")) {
        problems.extend(npm_waivers(&text, today));
    }
    if let Ok(text) = std::fs::read_to_string(root.join(".trivyignore.yaml")) {
        problems.extend(trivy_waivers(&text, today));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "waivers need attention (re-triage; never just extend the date):\n  {}",
            problems.join("\n  ")
        ))
    }
}

/// The `npm_licences` gate step. The e2e tooling is not shipped, so only
/// `web/package-lock.json` is read.
pub fn npm_licences_step(root: &Path) -> Result<(), String> {
    let deny = std::fs::read_to_string(root.join("deny.toml"))
        .map_err(|error| format!("deny.toml: {error}"))?;
    let allowed = allowed_licences(&deny);
    let lock_text = std::fs::read_to_string(root.join("web").join("package-lock.json"))
        .map_err(|error| format!("web/package-lock.json: {error}"))?;
    let lock: Value = serde_json::from_str(&lock_text)
        .map_err(|error| format!("web/package-lock.json: {error}"))?;
    let problems = npm_licence_problems(&lock, &allowed);
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "production npm packages with a licence outside deny.toml's allow-list:\n  {}",
            problems.join("\n  ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn allowed() -> Vec<String> {
        allowed_licences(include_str!("../../../../deny.toml"))
    }

    #[test]
    fn the_allow_list_is_read_from_deny_toml() {
        let list = allowed();
        assert!(list.contains(&"MIT".to_owned()));
        assert!(
            list.contains(&"OFL-1.1".to_owned()),
            "comments in the list are skipped"
        );
        assert!(list.contains(&"Apache-2.0 WITH LLVM-exception".to_owned()));
        assert!(!list.iter().any(|l| l.contains("GPL")));
    }

    #[test]
    fn mit_package_passes() {
        let lock = json!({ "packages": {
            "": { "name": "web" },
            "node_modules/a": { "version": "1.0.0", "license": "MIT" },
            "node_modules/b": { "version": "2.0.0", "license": "(MIT OR GPL-3.0)" }
        }});
        assert!(npm_licence_problems(&lock, &allowed()).is_empty());
    }

    #[test]
    fn gpl_package_fails() {
        let lock = json!({ "packages": {
            "node_modules/x/node_modules/g": { "version": "3.1.0", "license": "GPL-3.0" },
            "node_modules/n": { "version": "1.0.0" }
        }});
        let problems = npm_licence_problems(&lock, &allowed());
        assert!(problems.contains(&"g@3.1.0 GPL-3.0".to_owned()));
        assert!(problems.contains(&"n@1.0.0 (none)".to_owned()));
    }

    #[test]
    fn dev_only_package_is_ignored() {
        let lock = json!({ "packages": {
            "node_modules/t": { "version": "1.0.0", "license": "GPL-3.0", "dev": true }
        }});
        assert!(npm_licence_problems(&lock, &allowed()).is_empty());
    }

    #[test]
    fn expired_trivy_waiver_fails() {
        let text = "vulnerabilities:\n  - id: CVE-1\n    purls:\n      - \"pkg:deb/x\"\n    \
                    statement: \"Owner: A — why\"\n    expired_at: \"2026-01-01T00:00:00Z\"\n";
        let problems = trivy_waivers(text, "2026-10-14");
        assert_eq!(
            problems,
            [".trivyignore.yaml: CVE-1: expired_at 2026-01-01 has passed"]
        );
        assert!(trivy_waivers(text, "2025-12-31").is_empty());
    }

    #[test]
    fn missing_owner_fails() {
        let deny = "ignore = [\n    { id = \"RUSTSEC-1\", reason = \"no owner here — revisit 2027-01-01\" },\n]\n";
        assert_eq!(
            deny_waivers(deny, "2026-10-14"),
            ["deny.toml: RUSTSEC-1: the reason names no Owner:"]
        );
        let late = "    { id = \"RUSTSEC-2\", reason = \"Owner: A — revisit 2026-01-01\" },\n";
        assert_eq!(
            deny_waivers(late, "2026-10-14"),
            ["deny.toml: RUSTSEC-2: revisit 2026-01-01 has passed"]
        );
    }

    #[test]
    fn prod_moderate_npm_waiver_fails() {
        let text = "advisories:\n  - id: GHSA-1\n    packages:\n      - \"a@1.0.0\"\n    \
                    severity: moderate\n    scope: prod\n    statement: \"Owner: A — why\"\n    \
                    revisit: 2027-01-01\n";
        assert_eq!(
            npm_waivers(text, "2026-10-14"),
            [
                "web/audit-waivers.yaml: GHSA-1: a prod waiver must be low (audit:prod fails at moderate)"
            ]
        );
    }

    #[test]
    fn the_checked_in_waivers_are_in_date() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap();
        assert_eq!(waivers_step(root, "2026-10-14"), Ok(()));
    }
}
