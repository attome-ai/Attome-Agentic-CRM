//! AA10-T11: every request path that can touch more rows than the inline
//! limit sizes the work first or hands it to a job. The list below names the
//! handlers known to be heavy; for each, the function's own code (comments
//! left out) must call the size check (`size_check*`), the table-size gate
//! (`table_row_count_exceeds`) or enqueue a job. A new heavy path joins the
//! list in the change that adds it.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

/// (source file from the workspace root, function, what it does).
const HEAVY: &[(&str, &str, &str)] = &[
    (
        "crates/engine/attome-records/src/mass.rs",
        "start",
        "mass update, delete, reassign and restore over a filter",
    ),
    (
        "crates/engine/attome-records/src/bulk.rs",
        "enqueue_inner",
        "bulk create, update and delete",
    ),
    (
        "crates/engine/attome-records/src/bulk.rs",
        "approve_staged_import",
        "staged-import approve",
    ),
    (
        "crates/engine/attome-api/src/admin/attribute.rs",
        "do_create_attribute_recorded",
        "attribute index build on create",
    ),
    (
        "crates/engine/attome-api/src/admin/attribute.rs",
        "do_update_attribute_recorded",
        "attribute index build on update",
    ),
    (
        "crates/engine/attome-metadata/src/provision/schema_change.rs",
        "classify_schema_change",
        "schema change apply",
    ),
    (
        "crates/engine/attome-metadata/src/provision/change_plan.rs",
        "plan_changes",
        "schema change plan",
    ),
    (
        "crates/engine/attome-metadata/src/provision/business_key.rs",
        "ensure_business_key_index",
        "business-key index build",
    ),
    (
        "crates/engine/attome-records/src/entity_crud/upsert.rs",
        "upsert_record_inner",
        "upsert's supporting index",
    ),
    (
        "crates/engine/attome-api/src/admin/orphans.rs",
        "list_orphans",
        "orphaned lookup scan",
    ),
];

/// What counts as sizing the work first or moving it to a job.
const MARKERS: &[&str] = &["size_check", "table_row_count_exceeds", "enqueue"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The code of the top-level function `name` in `source`: from its `fn`
/// line to the first closing brace at the start of a line, comment lines
/// left out. `None` when there is no such function.
fn function_code(source: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let start = lines.iter().position(|line| {
        let line = line.trim_start();
        let rest = line
            .strip_prefix("pub(crate) ")
            .or_else(|| line.strip_prefix("pub(super) "))
            .or_else(|| line.strip_prefix("pub "))
            .unwrap_or(line);
        let rest = rest.strip_prefix("async ").unwrap_or(rest);
        rest.starts_with(&format!("fn {name}(")) || rest.starts_with(&format!("fn {name}<"))
    })?;
    let mut code = String::new();
    for line in &lines[start..] {
        if !line.trim_start().starts_with("//") {
            code.push_str(line);
            code.push('\n');
        }
        if *line == "}" {
            break;
        }
    }
    Some(code)
}

#[test]
fn every_heavy_operation_uses_size_check() {
    let root = workspace_root();
    let mut missing = Vec::new();
    for (file, function, what) in HEAVY {
        let source = std::fs::read_to_string(root.join(file))
            .unwrap_or_else(|e| panic!("{file} is readable: {e}"));
        let Some(code) = function_code(&source, function) else {
            missing.push(format!("{file}: {function} ({what}) no longer exists"));
            continue;
        };
        if !MARKERS.iter().any(|m| code.contains(m)) {
            missing.push(format!(
                "{file}: {function} ({what}) neither sizes the work first nor enqueues a job"
            ));
        }
    }
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[test]
fn function_code_skips_comments_and_stops_at_the_end() {
    let source = "fn other() {}\n\npub async fn heavy(x: i32) {\n    // enqueue in a comment\n    run(x);\n}\n\nfn after() { enqueue(); }\n";
    let code = function_code(source, "heavy").unwrap();
    assert!(code.contains("run(x)"));
    assert!(!code.contains("enqueue"));
    assert!(function_code(source, "absent").is_none());
}
