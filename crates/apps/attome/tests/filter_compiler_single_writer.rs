//! C-15 (M01 §7) proof: the `attome_core::Filter` -> WHERE-fragment
//! compiler has exactly one writer now — `attome_core::filter::compile`
//! — not the independent hand-copies (`query_exec.rs`'s WHERE-loop,
//! `attome-search::aggregate`'s `push_filter_condition`, `data_export.rs`'s
//! `plan_export` loop, `legal_matter_admin.rs`'s `build_scope_predicate`)
//! this module-master-plan item found. Each migrated caller now implements
//! `attome_core::filter::FilterSchema` over its own whitelist and calls
//! `compile` — see that module's doc comment for why the whitelist itself
//! stays per-caller while the operator-matching/cast-rendering logic
//! downstream of it does not.
//!
//! This test fails on a second `fn push_filter_condition` (the exact name
//! `attome-search::aggregate`'s pre-C-15 helper used) anywhere in the
//! workspace, and on a `fn render_condition` anywhere *other than* the one
//! legitimate, unrelated survivor: `attome-security::conditions`. That one is
//! D-369's `GrantCondition`/`ConditionOperator` grammar — a genuinely
//! different, already-typed operator model with its own `In` array form and
//! no `contains` family at all, not a copy of `Filter`'s grammar — so it is
//! deliberately not migrated onto `compile` (see that module's own doc
//! comment) and is allow-listed here by name, not ignored by accident.
//!
//! Deliberately a narrow name-based scan, not a semantic one: it cannot
//! catch a hand-copied filter->WHERE loop written under some other function
//! name. It exists to catch regression under the two names this repo's own
//! history has already used for one, matching `orphan_source_files.rs`'s
//! same "narrow, cheap, catches the known failure mode" scope in this same
//! directory.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// Repo root: this test's crate is `crates/server`, so up two levels — same
/// helper `orphan_source_files.rs`/`crate_list_drift.rs` already use.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/server always has two ancestors")
        .to_path_buf()
}

/// Every `.rs` file beneath `dir`, recursively.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Whether trimmed source `line` declares a function literally named
/// `name` — tolerates any visibility qualifier, `async`, and generic
/// parameters ahead of the argument list, rejects a longer identifier that
/// merely starts with `name` (`fn render_condition_extra(` must not match a
/// search for `render_condition`), and requires the name to be immediately
/// followed by `(` or `<` (skipping whitespace) so a mention of the name
/// inside a doc comment's code span or an `assert!` message's prose — this
/// file's own error messages name both functions by design — cannot
/// self-trigger a hit.
fn declares_fn(line: &str, name: &str) -> bool {
    let needle = format!("fn {name}");
    let mut search_from = 0;
    while let Some(pos) = line[search_from..].find(needle.as_str()) {
        let idx = search_from + pos;
        let after = idx + needle.len();
        let next_char = line[after..].chars().next();
        let is_word_boundary = !matches!(next_char, Some(c) if c.is_alphanumeric() || c == '_');
        let is_declaration = line[after..].trim_start().starts_with(['(', '<']);
        if is_word_boundary && is_declaration {
            return true;
        }
        search_from = after;
    }
    false
}

/// The one known, unrelated `fn render_condition` — D-369's grant-condition
/// renderer, not a `Filter` grammar copy. See this file's own module doc.
const ALLOWED_RENDER_CONDITION: &str = "crates/engine/attome-security/src/conditions.rs";

#[test]
fn filter_to_sql_has_exactly_one_writer() {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    assert!(
        crates_dir.is_dir(),
        "expected the workspace crate directory at {}",
        crates_dir.display()
    );

    let mut files = Vec::new();
    rust_files(&crates_dir, &mut files);
    files.sort();
    assert!(
        !files.is_empty(),
        "found no source files under {} — the scan is not looking where it thinks it is",
        crates_dir.display()
    );

    let mut push_filter_condition_hits: Vec<String> = Vec::new();
    let mut render_condition_hits: Vec<(String, usize)> = Vec::new();

    for file in &files {
        let Ok(src) = fs::read_to_string(file) else {
            continue;
        };
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(file)
            .display()
            .to_string()
            .replace('\\', "/");
        for (i, raw) in src.lines().enumerate() {
            let trimmed = raw.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if declares_fn(trimmed, "push_filter_condition") {
                push_filter_condition_hits.push(format!("{rel}:{}", i + 1));
            }
            if declares_fn(trimmed, "render_condition") {
                render_condition_hits.push((rel.clone(), i + 1));
            }
        }
    }

    assert!(
        push_filter_condition_hits.is_empty(),
        "C-15 (M01 §7): found a `fn push_filter_condition` — the exact per-caller \
         WHERE-loop helper name that existed before the shared \
         `attome_core::filter::compile` writer. Implement \
         `attome_core::filter::FilterSchema` over this caller's whitelist and call \
         `compile` instead of hand-copying the loop again:\n  {}",
        push_filter_condition_hits.join("\n  "),
    );

    let unexpected: Vec<String> = render_condition_hits
        .iter()
        .filter(|(rel, _)| rel != ALLOWED_RENDER_CONDITION)
        .map(|(rel, line)| format!("{rel}:{line}"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "C-15 (M01 §7): found a `fn render_condition` outside the one known, \
         unrelated survivor ({ALLOWED_RENDER_CONDITION} — D-369's `GrantCondition` \
         grammar, not `Filter`). If this is a genuine new hand-copy of the `Filter` \
         grammar, migrate it onto `attome_core::filter::compile` instead; if it is \
         a second, legitimately different grammar that happens to reuse this name, \
         rename it (this name is reserved for the D-369 survivor) rather than \
         extending this allow-list silently:\n  {}",
        unexpected.join("\n  "),
    );
    assert!(
        render_condition_hits
            .iter()
            .any(|(rel, _)| rel == ALLOWED_RENDER_CONDITION),
        "expected to find the known `render_condition` at {ALLOWED_RENDER_CONDITION} — \
         did it move or get renamed? Update this test's allow-list if so, rather than \
         leaving it silently unable to prove anything.",
    );
}
