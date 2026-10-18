//! Y13-T3: every in-process queue and cache has a size bound.
//!
//! A source scan, the same technique as `list_shape_census.rs`: production
//! code under `crates/*/*/src` (test modules and `tests/` excluded) may not
//! open an unbounded channel (`tokio::sync::mpsc::unbounded_channel`,
//! `std::sync::mpsc::channel`, `flume::unbounded`, crossbeam's `unbounded`)
//! or build a moka cache without `max_capacity`, so one stuck consumer or a
//! key flood cannot grow a node's memory without limit. A reviewed exception
//! goes in `bounded_state_allow.txt` with its reason; an allow-list line that
//! no longer matches anything fails the test, so the list cannot rot.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

/// Calls that make a queue with no capacity.
const UNBOUNDED: &[&str] = &[
    "unbounded_channel(",
    "std::sync::mpsc::channel(",
    "std::sync::mpsc::channel::<",
    "flume::unbounded",
    "crossbeam_channel::unbounded",
    "async_channel::unbounded",
];

/// How many lines after `Cache::builder()` the builder chain may run.
const BUILDER_WINDOW: usize = 12;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("the workspace root")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target"
                || name == "tests"
                || name == "node_modules"
                || name.starts_with('.')
            {
                continue;
            }
            rust_sources(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// The production part of a source file: everything before its test module.
fn production_lines(text: &str) -> Vec<&str> {
    let lines: Vec<&str> = text.lines().collect();
    let end = lines
        .windows(2)
        .position(|w| w[0].trim() == "#[cfg(test)]" && w[1].trim_start().starts_with("mod "))
        .unwrap_or(lines.len());
    lines[..end].to_vec()
}

/// `file:line: what` for every unbounded queue or cache in `text`.
fn findings(relative: &str, text: &str) -> Vec<(String, String)> {
    let lines = production_lines(text);
    let mut found = Vec::new();
    for (n, line) in lines.iter().enumerate() {
        let code = line.split("//").next().unwrap_or_default();
        for needle in UNBOUNDED {
            if code.contains(needle) {
                found.push((relative.to_owned(), format!("{}: {needle}", n + 1)));
            }
        }
        if code.contains("Cache::builder()") {
            let chain = lines[n..(n + BUILDER_WINDOW).min(lines.len())].join("\n");
            let built = chain
                .find(".build()")
                .map_or(chain.as_str(), |at| &chain[..at]);
            if !built.contains("max_capacity") {
                found.push((
                    relative.to_owned(),
                    format!("{}: Cache::builder() without max_capacity", n + 1),
                ));
            }
        }
    }
    found
}

/// `path | what | reason` lines; `what` is a needle the finding contains.
fn allow_list() -> Vec<(String, String)> {
    let text = include_str!("bounded_state_allow.txt");
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let parts: Vec<&str> = l.split('|').map(str::trim).collect();
            assert!(
                parts.len() == 3 && !parts[2].is_empty(),
                "bounded_state_allow.txt: `path | what | reason`, got {l:?}"
            );
            (parts[0].to_owned(), parts[1].to_owned())
        })
        .collect()
}

#[test]
fn every_queue_and_cache_is_bounded() {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_sources(&root.join("crates"), &mut files);
    assert!(files.len() > 100, "the scan reaches the workspace sources");
    let allowed = allow_list();
    let mut used = vec![false; allowed.len()];
    let mut unbounded = Vec::new();
    for file in &files {
        let relative = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(file).expect("read a source file");
        for (path, what) in findings(&relative, &text) {
            match allowed
                .iter()
                .position(|(p, w)| *p == path && what.contains(w.as_str()))
            {
                Some(i) => used[i] = true,
                None => unbounded.push(format!("{path}:{what}")),
            }
        }
    }
    assert!(
        unbounded.is_empty(),
        "bound these (a capacity, or `max_capacity`), or list a reviewed exception in \
         bounded_state_allow.txt:\n{}",
        unbounded.join("\n")
    );
    let stale: Vec<_> = allowed
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|((p, w), _)| format!("{p} | {w}"))
        .collect();
    assert!(
        stale.is_empty(),
        "these allow-list lines match nothing now; remove them: {stale:?}"
    );
}

#[test]
fn the_scan_sees_what_it_should() {
    let source = "fn a() {\n    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();\n}\n\
                  fn b() {\n    let c = moka::sync::Cache::builder()\n        .time_to_live(t)\n        .build();\n}\n\
                  fn c() {\n    let d = moka::sync::Cache::builder()\n        .max_capacity(10)\n        .build();\n}\n\
                  // unbounded_channel( in a comment is fine\n\
                  #[cfg(test)]\nmod tests {\n    fn t() { let _ = std::sync::mpsc::channel::<()>(); }\n}\n";
    let found = findings("x.rs", source);
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found[0].1.contains("unbounded_channel("));
    assert!(found[1].1.contains("without max_capacity"));
}
