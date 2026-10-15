//! Z2-T7: pgbouncer transaction-mode compatibility, held by a census.
//!
//! Behind pgbouncer in transaction mode a pooled connection is shared between
//! clients from one transaction to the next, so session state set on it
//! leaks to whoever gets the server connection next, and session-level
//! features break: a plain `SET`, `LISTEN`, a session advisory lock
//! (`pg_advisory_lock(`) and `PREPARE`. Transaction-scoped forms (`SET
//! LOCAL`, `SET TRANSACTION`, `pg_try_advisory_xact_lock`) are fine.
//!
//! This test scans every crate's `src/` for SQL string literals using one of
//! those session features and requires each file that does to be listed in
//! [`ALLOWED_SESSION_STATE`] with the reason it is safe: every listed site
//! runs on a direct or unpooled connection, never on a pooled one. It fails
//! on a new hit and on a stale entry, so the list keeps describing the code.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Files allowed to set session state, with why it is safe there.
const ALLOWED_SESSION_STATE: &[(&str, &str)] = &[
    (
        "crates/foundation/attome-db/src/migrate.rs",
        "Migrations run on their own unpooled direct connection, which sets \
         statement_timeout and lock_timeout for the whole run.",
    ),
    (
        "crates/foundation/attome-db/src/pool.rs",
        "The direct pool's after_connect and connect_unpooled set timeouts on \
         connections that go straight to PostgreSQL, never through pgbouncer.",
    ),
    (
        "crates/foundation/attome-testkit/src/lib.rs",
        "The test template build holds a session advisory lock on its own \
         direct connection to serialize parallel test processes.",
    ),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root is three levels above crates/apps/attome")
        .to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {dir:?}: {e}"));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if matches!(
                name.as_deref(),
                Some("target" | "tests" | "benches" | "migrations" | "node_modules")
            ) {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every string literal in `source`, raw strings included, with comments and
/// character literals skipped.
fn string_literals(source: &str) -> Vec<String> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
        } else if c == 'r'
            && (next == Some('"') || next == Some('#'))
            && (i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '_'))
        {
            let mut j = i + 1;
            let mut hashes = 0;
            while chars.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if chars.get(j) != Some(&'"') {
                i += 1;
                continue;
            }
            j += 1;
            let start = j;
            loop {
                if j >= chars.len() {
                    break;
                }
                if chars[j] == '"' && (0..hashes).all(|h| chars.get(j + 1 + h) == Some(&'#')) {
                    break;
                }
                j += 1;
            }
            out.push(chars[start..j.min(chars.len())].iter().collect());
            i = j + 1 + hashes;
        } else if c == '"' {
            let mut j = i + 1;
            let mut text = String::new();
            while j < chars.len() && chars[j] != '"' {
                if chars[j] == '\\' && j + 1 < chars.len() {
                    // A `\` line continuation joins the next line's text.
                    if chars[j + 1] == '\n' || chars[j + 1] == '\r' {
                        j += 1;
                        while j < chars.len() && chars[j].is_whitespace() {
                            j += 1;
                        }
                        text.push(' ');
                        continue;
                    }
                    text.push(chars[j + 1]);
                    j += 2;
                    continue;
                }
                text.push(chars[j]);
                j += 1;
            }
            out.push(text);
            i = j + 1;
        } else if c == '\'' {
            // A char literal (`'"'`, `'\''`) or a lifetime; skip a char
            // literal whole so its quote is not read as a string's start.
            if next == Some('\\') && chars.get(i + 3) == Some(&'\'') {
                i += 4;
            } else if chars.get(i + 2) == Some(&'\'') {
                i += 3;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// `true` when `sql` uses a session-level feature. Case-sensitive: this
/// codebase writes SQL keywords in capitals, and matching any case would
/// flag English messages ("Set up your account").
fn sets_session_state(sql: &str) -> bool {
    let statement_set = sql.split(';').any(|statement| {
        let statement = statement.trim_start();
        statement.starts_with("SET ")
            && !statement.starts_with("SET LOCAL ")
            && !statement.starts_with("SET TRANSACTION ")
    });
    let prepare = sql
        .split(';')
        .any(|statement| statement.trim_start().starts_with("PREPARE "));
    let listen = sql
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|word| word == "LISTEN");
    statement_set || prepare || listen || sql.contains("pg_advisory_lock(")
}

#[test]
fn the_detector_tells_session_state_from_transaction_state() {
    assert!(sets_session_state("SET statement_timeout = 0"));
    assert!(sets_session_state("SELECT 1; SET search_path = x"));
    assert!(sets_session_state("LISTEN change_feed"));
    assert!(sets_session_state("SELECT pg_advisory_lock($1)"));
    assert!(sets_session_state("PREPARE q AS SELECT 1"));
    assert!(!sets_session_state("SET LOCAL statement_timeout = '5s'"));
    assert!(!sets_session_state("SET TRANSACTION READ ONLY"));
    assert!(!sets_session_state("UPDATE t SET a = 1"));
    assert!(!sets_session_state(
        "SELECT pg_try_advisory_xact_lock($1, hashtext($2))"
    ));
    assert!(!sets_session_state("SELECT listener_id FROM t"));
    assert!(!sets_session_state("Set up your account"));
}

#[test]
fn raw_and_continued_literals_are_read_whole() {
    let source = "let a = r#\"UPDATE \"t\" SET x = 1\"#;\n\
                  let b = \"first \\\n      SET y = 2\";\n\
                  let c = '\"'; // \"SET z = 3\"\n";
    let literals = string_literals(source);
    assert_eq!(literals[0], "UPDATE \"t\" SET x = 1");
    assert_eq!(literals[1], "first  SET y = 2");
    assert_eq!(literals.len(), 2, "{literals:?}");
}

#[test]
fn session_state_only_where_the_connection_is_direct() {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root.join("crates"), &mut files);
    let mut hits: BTreeSet<String> = BTreeSet::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .expect("under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");
        if !rel.contains("/src/") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read source");
        if string_literals(&source)
            .iter()
            .any(|sql| sets_session_state(sql))
        {
            hits.insert(rel);
        }
    }
    let allowed: BTreeSet<String> = ALLOWED_SESSION_STATE
        .iter()
        .map(|(path, _)| (*path).to_owned())
        .collect();
    let unlisted: Vec<&String> = hits.difference(&allowed).collect();
    let stale: Vec<&String> = allowed.difference(&hits).collect();
    assert!(
        unlisted.is_empty(),
        "these files set session state (SET, LISTEN, pg_advisory_lock, PREPARE), which leaks \
         across clients behind pgbouncer in transaction mode. Use SET LOCAL or \
         pg_try_advisory_xact_lock, or run it on a direct connection and list the file in \
         ALLOWED_SESSION_STATE with why: {unlisted:?}"
    );
    assert!(
        stale.is_empty(),
        "these ALLOWED_SESSION_STATE entries no longer set session state; remove them: {stale:?}"
    );
    for (path, reason) in ALLOWED_SESSION_STATE {
        assert!(reason.len() >= 20, "{path}: give the reason it is safe");
    }
}
