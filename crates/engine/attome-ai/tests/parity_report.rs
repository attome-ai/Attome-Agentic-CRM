//! Y9-T4 (V2-D1610 (2)): the parity report. MCP tools stay the closed,
//! compile-time action registry; this report shows where the API has
//! capabilities that neither an agent action nor the web app reaches, so
//! the gaps become hand-written actions or screens. It prints and never
//! fails.
//!
//! - **No agent action**: an OpenAPI tag whose operations no action's
//!   module prefix (the part of its id before the first dot) names.
//! - **No UI**: an operation whose path, with its parameters as wildcards,
//!   appears in no TypeScript file of `web/projects` or `web/src`.
//!
//! ```powershell
//! cargo test -p attome-ai --test parity_report -- --nocapture
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "a report test prints what it found"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn typescript(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            if !matches!(name, "node_modules" | "generated" | "dist") {
                typescript(&path, out);
            }
        } else if name.ends_with(".ts")
            && !name.ends_with(".spec.ts")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push_str(&text);
            out.push('\n');
        }
    }
}

/// The fixed segments of an OpenAPI path, in order (`{id}` dropped). Pure.
fn fixed_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|s| !s.is_empty() && !s.starts_with('{'))
        .collect()
}

/// Whether `source` names `path`: its fixed segments appear in order on one
/// line. Pure.
fn used_in(source: &str, path: &str) -> bool {
    let segments = fixed_segments(path);
    let last = match segments.last() {
        Some(last) => *last,
        None => return true,
    };
    source.lines().filter(|l| l.contains(last)).any(|line| {
        let mut rest = line;
        segments.iter().all(|seg| match rest.find(seg) {
            Some(at) => {
                rest = &rest[at + seg.len()..];
                true
            }
            None => false,
        })
    })
}

/// The web source's lines, indexed by every word they hold (letters,
/// digits, `_` and `-`), so a path is checked against the few lines naming
/// its last segment instead of the whole source once per operation: that
/// rescan took over a minute on Linux and stalled the Windows runner.
struct WebIndex<'a> {
    lines: Vec<&'a str>,
    by_word: std::collections::HashMap<&'a str, Vec<usize>>,
}

impl<'a> WebIndex<'a> {
    fn new(source: &'a str) -> Self {
        let lines: Vec<&str> = source.lines().collect();
        let mut by_word: std::collections::HashMap<&str, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, line) in lines.iter().enumerate() {
            for word in line
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
                .filter(|w| !w.is_empty())
            {
                let at = by_word.entry(word).or_default();
                if at.last() != Some(&i) {
                    at.push(i);
                }
            }
        }
        Self { lines, by_word }
    }

    /// [`used_in`] over the lines that name the path's last segment.
    fn uses(&self, path: &str) -> bool {
        let Some(last) = fixed_segments(path).last().copied() else {
            return true;
        };
        // A segment such as `schedules:build` holds two words; its last one
        // finds the candidate lines, which `used_in` then checks in full.
        let word = last
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .rfind(|w| !w.is_empty())
            .unwrap_or(last);
        self.by_word
            .get(word)
            .into_iter()
            .flatten()
            .any(|&i| used_in(self.lines[i], path))
    }
}

#[test]
fn parity_report() {
    let Ok(text) = std::fs::read_to_string(repo().join("openapi.json")) else {
        println!("parity report skipped: openapi.json not found");
        return;
    };
    let doc: Value = serde_json::from_str(&text).expect("openapi.json parses");
    let mut web = String::new();
    typescript(&repo().join("web/projects"), &mut web);
    typescript(&repo().join("web/src"), &mut web);

    let action_modules: BTreeSet<String> = attome_ai::actions::all()
        .iter()
        .filter_map(|d| d.id.0.split('.').next().map(str::to_owned))
        .collect();

    let index = WebIndex::new(&web);
    let mut by_tag: BTreeMap<String, usize> = BTreeMap::new();
    let mut no_ui: Vec<String> = Vec::new();
    let methods = ["get", "post", "put", "patch", "delete"];
    for (path, item) in doc["paths"].as_object().into_iter().flatten() {
        for method in methods {
            let Some(op) = item.get(method) else {
                continue;
            };
            let tag = op["tags"][0].as_str().unwrap_or("untagged").to_owned();
            *by_tag.entry(tag).or_default() += 1;
            if !web.is_empty() && !index.uses(path) {
                no_ui.push(format!("{} {path}", method.to_uppercase()));
            }
        }
    }
    let no_agent: Vec<(&String, &usize)> = by_tag
        .iter()
        .filter(|(tag, _)| {
            let tag = tag.to_lowercase().replace('-', "_");
            !action_modules
                .iter()
                .any(|m| m == &tag || tag.starts_with(m.as_str()))
        })
        .collect();

    println!("== Parity report ==");
    println!(
        "{} operations in {} tags; {} action modules",
        by_tag.values().sum::<usize>(),
        by_tag.len(),
        action_modules.len()
    );
    println!("-- Tags with no agent action ({}):", no_agent.len());
    for (tag, count) in &no_agent {
        println!("   {tag}: {count} operation(s)");
    }
    println!("-- Operations no web screen calls ({}):", no_ui.len());
    for op in &no_ui {
        println!("   {op}");
    }
}

#[test]
fn parity_path_matching() {
    let source = "this.sdk.get(`/api/v1/billing/subscriptions/${id}`)";
    assert!(used_in(source, "/api/v1/billing/subscriptions/{id}"));
    assert!(!used_in(source, "/api/v1/billing/usage"));
    assert_eq!(fixed_segments("/api/v1/x/{id}/y"), ["api", "v1", "x", "y"]);
    let index = WebIndex::new(source);
    assert!(index.uses("/api/v1/billing/subscriptions/{id}"));
    assert!(!index.uses("/api/v1/billing/usage"));
}
