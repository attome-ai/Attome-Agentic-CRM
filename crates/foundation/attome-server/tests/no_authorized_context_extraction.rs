//! BSV-F03 / B3 — `AuthorizedContext` is `Clone` with a public `get()`, and
//! authn/strict-authz insert it into the request extensions, so
//! `Extension<AuthorizedContext>` (or a raw `extensions().get::<…>()`) would
//! hand a handler the caller's full context without any policy having run.
//! The only readers allowed are the `Authorized<P>` extractor itself, the
//! layer that inserts it, and xrm-security's strict-authz layer. This guard
//! scans every workspace crate's source and fails on any other reader.
//!
//! `cargo test -p attome-server --test no_authorized_context_extraction`

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

const ALLOWED: &[&str] = &[
    "crates/foundation/attome-server/src/authz.rs",
    "crates/foundation/attome-server/src/middleware/auth.rs",
    "crates/engine/attome-security/src/strict_authz.rs",
    "crates/foundation/attome-server/tests/no_authorized_context_extraction.rs",
    // `RecordingCtx` reads the caller's id only to stamp the changeset it
    // records into. It decides nothing: every route that takes it also takes an
    // `Authorized<P>` extractor, which is where the policy runs.
    "crates/engine/attome-core/src/changeset/extract.rs",
];

/// A line reads the context outside a policy when it names the type as an
/// `Extension` extractor or as a typed extensions lookup.
fn reads_the_context(line: &str) -> bool {
    let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    compact.contains("Extension<AuthorizedContext>")
        || compact.contains("get::<AuthorizedContext>")
        || compact.contains("get_mut::<AuthorizedContext>")
        || compact.contains("remove::<AuthorizedContext>")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name.starts_with('.') || name == "node_modules" {
                continue;
            }
            rust_files(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

#[test]
fn the_matcher_catches_a_planted_offender() {
    assert!(reads_the_context(
        "async fn h(Extension(ctx): Extension<AuthorizedContext>) {}"
    ));
    assert!(reads_the_context(
        "let c = req.extensions().get::< AuthorizedContext >();"
    ));
    assert!(!reads_the_context(
        "async fn h(auth: Authorized<SelfService>) {}"
    ));
}

#[test]
fn no_handler_extracts_an_authorized_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let root = root.canonicalize().expect("workspace root");
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    assert!(files.len() > 100, "the source walk found too few files");

    let mut offenders = Vec::new();
    for file in files {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (n, line) in source.lines().enumerate() {
            if reads_the_context(line) {
                offenders.push(format!("{rel}:{}", n + 1));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these read AuthorizedContext without a policy — take `Authorized<P>` instead \
         (BSV-F03): {offenders:?}"
    );
}
