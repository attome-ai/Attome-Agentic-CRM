//! D-589 guard: a bulk surface decides field visibility only through
//! `attome_security::field_gate`.
//!
//! Every non-test source file in the workspace that calls
//! `has_field_read_grant(` directly must be on [`INTERACTIVE`] below, with the
//! reason it is an interactive surface (D-111 applies there unchanged). A new
//! file that calls it fails this test until someone decides which kind of
//! surface it is: interactive, and it joins the list; bulk, and it calls
//! `field_gate` instead. The bulk surfaces D-589 names are also checked the
//! other way: each must reach the gate.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

/// Files allowed to call `has_field_read_grant(` directly, relative to the
/// workspace root, with forward slashes.
const INTERACTIVE: &[(&str, &str)] = &[
    (
        "crates/engine/attome-security/src/context.rs",
        "defines the grant check",
    ),
    (
        "crates/engine/attome-security/src/field_gate.rs",
        "the gate itself",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/response.rs",
        "interactive record responses",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/mutations.rs",
        "interactive record reads; bulk reads go through read_record_bulk",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/related.rs",
        "interactive related lists",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/hierarchy.rs",
        "interactive hierarchy view",
    ),
    (
        "crates/engine/attome-records/src/rule_engine.rs",
        "rule evaluation on a record the caller is writing, not a read surface",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/timeline.rs",
        "one record's timeline, viewed interactively",
    ),
    (
        "crates/engine/attome-api/src/audit_read.rs",
        "one record's audit history, viewed interactively",
    ),
    (
        "crates/engine/attome-api/src/rule_admin.rs",
        "rule authoring: refuses a rule that names a field its author cannot read; not a read surface",
    ),
];

/// D-589's bulk surfaces: each must call the gate.
const BULK: &[&str] = &[
    "crates/engine/attome-api/src/data_export.rs",
    "crates/engine/attome-records/src/query_exec.rs",
    "crates/engine/attome-dashboard/src/pages.rs",
    "crates/engine/attome-search/src/aggregate.rs",
    "crates/engine/attome-search/src/graph.rs",
    "crates/engine/attome-events/src/payload.rs",
    "crates/engine/attome-docgen/src/merge.rs",
    "crates/engine/attome-ai/src/actions/read.rs",
    "crates/engine/attome-ai/src/actions/classify.rs",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
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
            if name == "tests" || name == "target" || name.starts_with('.') {
                continue;
            }
            rust_sources(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

/// Code lines only: `//` comments and every unit-test module (`#[cfg(test)]`
/// followed by `mod name {`, up to its closing brace) are left out, since a
/// test module may build contexts however it likes. Production code after an
/// inline test module is still scanned, and a `#[cfg(test)]` on some other
/// item (a helper, a `use`) is not skipped.
fn code_lines(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("#[cfg(test)]")
            && lines
                .peek()
                .is_some_and(|next| next.trim_start().starts_with("mod ") && next.contains('{'))
        {
            // Skip the module: count braces until they balance.
            let mut depth: i64 = 0;
            for module_line in lines.by_ref() {
                depth += module_line.matches('{').count() as i64;
                depth -= module_line.matches('}').count() as i64;
                if depth <= 0 {
                    break;
                }
            }
            continue;
        }
        if !line.trim_start().starts_with("//") {
            out.push(line);
        }
    }
    out
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn only_classified_interactive_surfaces_check_field_grants_directly() {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_sources(&root.join("crates"), &mut files);
    assert!(
        files.len() > 100,
        "found {} sources under {root:?}",
        files.len()
    );

    let mut unclassified = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        if !code_lines(&text)
            .iter()
            .any(|l| l.contains("has_field_read_grant("))
        {
            continue;
        }
        let rel = relative(&root, file);
        if !INTERACTIVE.iter().any(|(allowed, _)| *allowed == rel) {
            unclassified.push(rel);
        }
    }
    assert!(
        unclassified.is_empty(),
        "these files decide field visibility without attome_security::field_gate (D-589). \
         A bulk surface must call field_gate; an interactive one joins INTERACTIVE with its \
         reason: {unclassified:#?}"
    );
}

#[test]
fn every_named_bulk_surface_goes_through_the_gate() {
    let root = workspace_root();
    for rel in BULK {
        // An engine that has not moved into v2 yet has no file to check; its
        // entry applies from the commit that brings it in.
        let Ok(text) = std::fs::read_to_string(root.join(rel)) else {
            continue;
        };
        let code = code_lines(&text);
        assert!(
            code.iter()
                .any(|l| l.contains("field_gate::") || l.contains("read_record_bulk(")),
            "{rel} is a D-589 bulk surface but never reaches field_gate"
        );
        assert!(
            !code.iter().any(|l| l.contains("has_field_read_grant(")),
            "{rel} is a D-589 bulk surface but still checks field grants itself"
        );
    }
}
