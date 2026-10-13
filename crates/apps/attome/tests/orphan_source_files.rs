//! Every `.rs` file under a workspace crate's `src/` must be reachable from
//! that crate's root through `mod` declarations — i.e. it must actually be
//! *compiled*.
//!
//! # Why this guard exists
//!
//! `crates/server/src/auth/admin.rs` sat in the tree carrying two handlers,
//! `get_auth_system_status` and `get_auth_system_health`, mounted on
//! `/api/v1/auth/admin/system/{status,health}`. `crates/server/src/auth/mod.rs`
//! never declared `mod admin;` — `git log -S "mod admin;"` finds no commit that
//! ever added it — so the file was never part of the crate. Nothing compiled
//! it, and that is what made it dangerous rather than merely untidy
//! (PLATFORM-REVIEW-2026-08-24 SEC-7):
//!
//! - **Every automated control skipped it.** `cargo build`, `clippy -D
//!   warnings`, `cargo test` and the coverage jobs only see code the compiler
//!   sees. The file used `Extension` without importing it — a hard compile
//!   error that sat on `main` indefinitely, which is the cheapest possible
//!   proof that no gate was looking.
//! - **The OpenAPI guard could not catch it either.** `scripts/openapi-
//!   coverage.mjs` fails on an operation nothing mounts, but it reads the
//!   *generated* document. An uncompiled `#[utoipa::path]` never reaches the
//!   document, so the annotation looked like a mounted, documented admin API
//!   while being invisible to the one check designed to find exactly that.
//! - **It was a loaded gun for the next reader.** Both handlers' doc comments
//!   said "Requires admin privileges", but their only extractor was
//!   `Extension<SessionClaims>` — authentication, not authorization. Anyone who
//!   noticed the dead file, added `mod admin;` and wired the routes would have
//!   trusted the comment and shipped two admin-labelled endpoints callable by
//!   any authenticated user. `route_authz.rs`'s ratchet cannot help here: it
//!   asserts things about routes that exist in the compiled router.
//!
//! The file was deleted rather than gated. Gating it would have meant building
//! a real auth-system status/health endpoint, and `attome-server` already owns
//! `/health`, `/health/ready`, `/version` and `/health/dependencies` — a second
//! health surface returning hardcoded `"healthy"` strings (which is all those
//! handlers did, above an explicit "in a real implementation" comment) is both
//! a duplicate framework (guidelines §13) and a readiness signal that does not
//! represent the ability to serve (§11).
//!
//! # What this test proves
//!
//! An orphan cannot come back silently. A `.rs` file added under any root-
//! workspace crate's `src/` without a `mod` declaration reaching it fails here,
//! at the point where it is cheap to fix, instead of surviving until someone
//! mounts it years later.
//!
//! # Scope and limits
//!
//! Scans `crates/**` — the root Cargo workspace, the only one since D-792
//! retired the separate `attome-fleet/` workspace.
//!
//! Only `src/` is scanned. `tests/`, `benches/` and `examples/` files are
//! auto-discovered targets, so an unreferenced file there is still compiled and
//! cannot hide the way an orphan under `src/` can.
//!
//! The parser is deliberately literal: it reads `mod name;` declarations and
//! `#[path = "..."]` overrides, and skips `//` comments. Inline `mod name { … }`
//! blocks have no file of their own and are correctly ignored (they do not end
//! in `;`). A `mod` declaration hidden inside a block comment would be missed;
//! nothing in this workspace writes one, and the failure mode is a false
//! *positive* that names the file, not a silent pass.
//!
//! This is a pure filesystem check — no database, no fixtures — so it runs in
//! every `cargo test -p server`, the same way `advisory_lock_namespaces.rs`
//! does.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Repo root: this test's crate is `crates/server`, so up two levels.
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

/// Every directory under `crates/` that is a crate: a `Cargo.toml` beside a
/// `src/`. The `crates/base` and `crates/xrm` grouping directories have no
/// manifest and are walked through rather than treated as crates.
fn crate_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    if dir.join("Cargo.toml").is_file() && dir.join("src").is_dir() {
        out.push(dir.to_path_buf());
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            crate_dirs(&path, out);
        }
    }
}

/// One `mod` declaration found in a source file.
struct ModDecl {
    name: String,
    /// The `#[path = "…"]` override, if the declaration carried one.
    path_override: Option<String>,
}

/// Strip leading `#[…]` attributes off a trimmed line, returning the remainder
/// and any `path = "…"` value seen along the way.
///
/// Handles both the common `#[cfg(test)]` on its own line and the same
/// attribute written inline ahead of the `mod`, so neither shape can smuggle a
/// declaration past the scan.
fn strip_attributes(line: &str) -> (String, Option<String>) {
    let mut rest = line.trim();
    let mut path_override = None;
    while rest.starts_with("#[") {
        // Find the `]` that closes this attribute, respecting nesting such as
        // `#[cfg(all(a, b))]`.
        let mut depth = 0usize;
        let mut end = None;
        for (i, ch) in rest.char_indices() {
            match ch {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else { break };
        let attr = &rest[..=end];
        if attr.contains("path")
            && let Some(value) = attr
                .split_once('"')
                .and_then(|(_, tail)| tail.split_once('"').map(|(v, _)| v))
        {
            path_override = Some(value.to_string());
        }
        rest = rest[end + 1..].trim();
    }
    (rest.to_string(), path_override)
}

/// Read the `mod name;` declarations out of one source file.
fn mod_decls(file: &Path) -> Vec<ModDecl> {
    let Ok(src) = fs::read_to_string(file) else {
        return Vec::new();
    };
    let mut decls = Vec::new();
    // A `#[path = "…"]` written on its own line applies to the next `mod`.
    let mut pending_path: Option<String> = None;

    for raw in src.lines() {
        let trimmed = raw.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        let (rest, inline_path) = strip_attributes(trimmed);
        if let Some(p) = inline_path {
            pending_path = Some(p);
        }
        if rest.is_empty() {
            continue;
        }

        // Allow any visibility qualifier ahead of the keyword.
        let after_vis = rest
            .strip_prefix("pub")
            .map(|r| {
                // `pub(crate)`, `pub(super)`, `pub(in path)` …
                let r = r.trim_start();
                r.strip_prefix('(')
                    .and_then(|r| r.split_once(')'))
                    .map(|(_, tail)| tail.trim_start())
                    .unwrap_or(r)
            })
            .unwrap_or(rest.as_str());

        let Some(after_kw) = after_vis.strip_prefix("mod ") else {
            // Any other statement clears a dangling `#[path]`.
            if !rest.starts_with('#') {
                pending_path = None;
            }
            continue;
        };
        // `mod name;` — an inline `mod name { … }` has no file and is skipped.
        let Some(name) = after_kw.trim().strip_suffix(';') else {
            pending_path = None;
            continue;
        };
        let name = name.trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            pending_path = None;
            continue;
        }
        decls.push(ModDecl {
            name: name.to_string(),
            path_override: pending_path.take(),
        });
    }
    decls
}

/// The directory a file's child modules resolve against: the containing
/// directory for a crate/module root (`lib.rs`, `main.rs`, `mod.rs`), and the
/// same-named sibling directory for any other module file.
fn child_dir(file: &Path) -> PathBuf {
    let stem = file.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let parent = file.parent().unwrap_or(Path::new("."));
    if matches!(stem, "lib" | "main" | "mod") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    }
}

/// Walk one crate's module tree from its roots, returning the files reached and
/// any `mod` declaration whose file could not be located.
fn reachable(src: &Path, all: &[PathBuf]) -> (BTreeSet<PathBuf>, Vec<String>) {
    let mut queue: Vec<PathBuf> = Vec::new();
    for root in ["lib.rs", "main.rs"] {
        let candidate = src.join(root);
        if candidate.is_file() {
            queue.push(candidate);
        }
    }
    // `src/bin/*.rs` and `src/bin/*/main.rs` are auto-discovered binary
    // targets: compiled without any `mod` declaration pointing at them.
    let bin = src.join("bin");
    if bin.is_dir() {
        for file in all {
            let direct = file.parent() == Some(bin.as_path());
            let nested = file.file_name().is_some_and(|n| n == "main.rs")
                && file.parent().and_then(Path::parent) == Some(bin.as_path());
            if direct || nested {
                queue.push(file.clone());
            }
        }
    }

    let mut seen = BTreeSet::new();
    let mut unresolved = Vec::new();
    while let Some(file) = queue.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let dir = child_dir(&file);
        for decl in mod_decls(&file) {
            if let Some(rel) = decl.path_override {
                let target = file.parent().unwrap_or(Path::new(".")).join(rel);
                if target.is_file() {
                    queue.push(target);
                    continue;
                }
            }
            let flat = dir.join(format!("{}.rs", decl.name));
            let nested = dir.join(&decl.name).join("mod.rs");
            if flat.is_file() {
                queue.push(flat);
            } else if nested.is_file() {
                queue.push(nested);
            } else {
                unresolved.push(format!("mod {}; declared in {}", decl.name, file.display()));
            }
        }
    }
    (seen, unresolved)
}

/// A file under `src/` that no `mod` declaration reaches is not compiled, so no
/// build, lint, test or coverage gate applies to it — see this file's header
/// for what that cost us.
#[test]
fn every_source_file_is_reachable_from_its_crate_root() {
    let root = workspace_root();
    let crates_dir = root.join("crates");
    assert!(
        crates_dir.is_dir(),
        "expected the workspace crate directory at {}",
        crates_dir.display()
    );

    let mut crates = Vec::new();
    crate_dirs(&crates_dir, &mut crates);
    crates.sort();
    assert!(
        !crates.is_empty(),
        "found no crates under {} — the scan is not looking where it thinks it is",
        crates_dir.display()
    );

    let mut orphans: Vec<String> = Vec::new();
    let mut unresolved: Vec<String> = Vec::new();

    for krate in &crates {
        let src = krate.join("src");
        let mut all = Vec::new();
        rust_files(&src, &mut all);
        all.sort();

        let (seen, mut crate_unresolved) = reachable(&src, &all);
        unresolved.append(&mut crate_unresolved);

        for file in all {
            if !seen.contains(&file) {
                let shown = file.strip_prefix(&root).unwrap_or(&file);
                orphans.push(shown.display().to_string().replace('\\', "/"));
            }
        }
    }

    assert!(
        orphans.is_empty(),
        "these files sit under a crate's src/ but no `mod` declaration reaches them, \
         so they are never compiled and no build, lint, test or coverage gate applies \
         to them:\n  {}\n\nEither declare the module in its parent (`mod <name>;`) or \
         delete the file. Do not leave it in the tree: an uncompiled file with route \
         annotations reads as a live, documented endpoint while being invisible to \
         every check, which is exactly how PLATFORM-REVIEW-2026-08-24 SEC-7 happened.\
         \n\nunresolved `mod` declarations seen while scanning (parser diagnostics, \
         not failures): {:?}",
        orphans.join("\n  "),
        unresolved,
    );
}
