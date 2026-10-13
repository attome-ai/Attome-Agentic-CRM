//! C-25 (API contract hygiene): a source-scan census over every list-shaped
//! handler in the workspace, same technique as `route_authz.rs` — Axum
//! exposes no route-introspection API, so the router itself cannot be
//! walked; the source is the enumerable form.
//!
//! Guidelines §12: "List-shaped responses use `attome_types::
//! PaginatedResponse<T>` ... unless the access pattern genuinely needs a
//! different envelope." A handler whose signature reads
//! `-> Result<Json<Vec<T>>, AppError>` is the literal, greppable violation
//! of that rule — a list with no `total`/paging metadata at all, as opposed
//! to a query/execute-style cursor response or a depth-bounded structural
//! walk, both of which the guideline explicitly carves out and which this
//! scan does not flag (see `EXEMPT_BARE_LIST_HANDLERS` below).
//!
//! This is a ratchet, not a snapshot: `MAX_BARE_LIST_HANDLERS` is the
//! current count, and the test fails if it ever goes up OR down without the
//! constant being updated in the same commit — the same "cannot rust in the
//! loose direction either" property `route_authz.rs`'s
//! `MAX_BARE_RECORD_SCOPED` has. Migrating one of the counted handlers to
//! `PaginatedResponse<T>` (or documenting a new, genuine exemption) means
//! lowering this number in the same commit; adding a new bare-list handler
//! without a documented exemption means the count goes up and the test
//! catches it before review does.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

/// Current count of `-> Result<Json<Vec<...>>, AppError>` handler signatures
/// across the workspace (2026-09-07, this session) — down from 35 named in
/// `document/module-master-plans/M01-core.md` §7's C-25 problem statement
/// after this session migrated `sidebar.rs`'s admin/legacy handlers (one
/// retired outright), `attome-security/src/admin/shares.rs` (both list
/// handlers), `teams.rs` (2), `roles.rs` (`list_role_users`), `api_keys.rs`,
/// `field_security.rs`, `organizations.rs`, and `user_roles.rs` onto
/// `PaginatedResponse<T>`. The remaining count is real backlog, not
/// something this scan is trying to hide — see each file's own list below.
///
/// v2 re-baseline (2026-10-14): 28. The v1 scan walked `crates/server` and two
/// layers; the v2 workspace has three (`crates/<layer>/<name>`), so the same
/// scan now reaches the engines under `crates/engine` that v1 counted from a
/// different root. The three added are backlog like the rest, not new
/// handlers. The ratchet still only goes down from here.
const MAX_BARE_LIST_HANDLERS: usize = 28;

/// Handler return-type signatures that are a *deliberate* exception to the
/// `PaginatedResponse<T>` rule, not backlog — this scan still counts them
/// (so `MAX_BARE_LIST_HANDLERS` reflects the true total a reviewer sees on
/// `grep`), but a reviewer reading this list finds the reasoning already
/// written down instead of re-litigating it:
///
/// - `attome-security/src/admin/role_grant_conditions.rs::list_conditions` — a
///   grant carries at most `MAX_CONDITIONS_PER_GRANT = 3` conditions,
///   enforced under a row lock at write time (D-369). Not merely small in
///   practice; hard-capped by the same handler that writes it.
/// - `attome-api/src/sidebar.rs::list_sidebar_admin` and `get_sidebar` — a
///   navigation tree, not a growing per-tenant list: guidelines §12's own
///   "depth-bounded structural walk ... returns its whole, inherently-capped
///   result in one response" carve-out (the entity ancestors/descendants
///   example) applies equally here. The sidebar is admin-curated, bounded by
///   how much nav a deployment's operators author, not by record volume.
const EXEMPT_BARE_LIST_HANDLERS: &[&str] = &[
    "attome-security/src/admin/role_grant_conditions.rs",
    "attome-api/src/sidebar.rs",
];

/// Every non-test, non-target `.rs` file under `crates/`.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "target" || name == "tests" {
            continue;
        }
        if path.is_dir() {
            rust_files(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// One `(file, line)` per bare-list handler signature found. Skips any line
/// that is itself a doc/regular comment (`//`, `///`, `//!`) — this pattern
/// legitimately appears inside `attome-server/src/authz.rs`'s module doc as
/// an illustrative code sample, not a real handler.
fn find_bare_list_handlers(root: &Path) -> Vec<(PathBuf, usize)> {
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);

    let mut hits = Vec::new();
    for file in files {
        let Ok(src) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (idx, line) in src.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            if trimmed.starts_with(')') && trimmed.contains("-> Result<Json<Vec<") {
                hits.push((file.clone(), idx + 1));
            }
        }
    }
    hits
}

fn workspace_root() -> PathBuf {
    // `crates/server` -> workspace root is two levels up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three levels above crates/apps/attome")
        .to_path_buf()
}

#[test]
fn bare_list_handler_count_matches_the_ratchet() {
    let hits = find_bare_list_handlers(&workspace_root());
    let lines: Vec<String> = hits
        .iter()
        .map(|(file, line)| format!("{}:{line}", file.display()))
        .collect();

    assert_eq!(
        hits.len(),
        MAX_BARE_LIST_HANDLERS,
        "the bare `Json<Vec<T>>` list-handler count drifted from the ratchet \
         (expected {MAX_BARE_LIST_HANDLERS}, found {}) — if you migrated one \
         to PaginatedResponse<T>, lower MAX_BARE_LIST_HANDLERS in this same \
         commit; if you added a new one, either paginate it or add a \
         documented, reasoned exemption to EXEMPT_BARE_LIST_HANDLERS (and \
         raise the ratchet). Current hits:\n{}",
        hits.len(),
        lines.join("\n"),
    );
}

#[test]
fn every_documented_exemption_still_has_at_least_one_real_hit() {
    // Regression guard, same shape as route_authz.rs's
    // `every_csrf_enforced_path_is_actually_a_bypass_path`: a stale exemption
    // entry that matches nothing is silently inert and misleads a reviewer
    // into thinking it still explains something.
    let hits = find_bare_list_handlers(&workspace_root());
    for exempt in EXEMPT_BARE_LIST_HANDLERS {
        assert!(
            hits.iter()
                .any(|(file, _)| file.to_string_lossy().replace('\\', "/").ends_with(*exempt)),
            "{exempt} is listed as an exemption but no bare-list handler was \
             found in it any more — remove the stale entry"
        );
    }
}
