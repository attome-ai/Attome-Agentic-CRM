//! M07 Phase A (§4.1) — source scan: `attome-state` never writes a governed
//! record itself. A state change through `POST /{entity}/{id}/transition`
//! goes through `entity_crud::update_record_for_with_comment` ->
//! `entity_mutation::update_one`, the one write path every generic PATCH,
//! bulk and upsert write uses. The only `UPDATE` statements this crate may
//! contain are on its own metadata tables (`state_model`,
//! `state_transition`); anything else is a second write path and
//! fails here. Same idea as `crates/server/tests/filter_compiler_single_writer.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::Path;

const ALLOWED_TABLE_PREFIX: &str = "state_";

/// Every `UPDATE <target>` in `src` whose target is not one of this crate's
/// own metadata tables, as `"file:line: text"`. `DO UPDATE` (an upsert's
/// conflict arm, whose target is the INSERT's own table) is skipped.
fn foreign_updates(file: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            continue;
        }
        let mut rest = line;
        while let Some(pos) = rest.find("UPDATE ") {
            let before = rest[..pos].trim_end();
            let after = rest[pos + "UPDATE ".len()..].trim_start();
            rest = &rest[pos + "UPDATE ".len()..];
            if before.ends_with("DO") {
                continue;
            }
            let target: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '{' || *c == '}')
                .collect();
            if !target.starts_with(ALLOWED_TABLE_PREFIX) {
                out.push(format!("{file}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    out
}

#[test]
fn state_has_no_record_update_of_its_own() {
    let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    let mut scanned = 0;
    for entry in std::fs::read_dir(&src_dir).expect("read attome-state/src") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).expect("read source file");
        scanned += 1;
        offenders.extend(foreign_updates(&path.display().to_string(), &src));
    }
    assert!(
        scanned >= 4,
        "expected to scan attome-state/src, found {scanned} files"
    );
    assert!(
        offenders.is_empty(),
        "attome-state must not write a record itself — route the write through \
         entity_crud::update_record_for_with_comment (M07 §4.1):\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_scan_catches_a_record_update_and_allows_metadata_updates() {
    let bad = r#"let sql = format!("UPDATE {table} SET {field} = $1 WHERE id = $2");"#;
    assert_eq!(foreign_updates("x.rs", bad).len(), 1);
    let ok = r#""UPDATE state_model SET name = $2 WHERE id = $1""#;
    assert!(foreign_updates("x.rs", ok).is_empty());
    let upsert = r#""ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name""#;
    assert!(foreign_updates("x.rs", upsert).is_empty());
    let comment = "//! the old route ran its own `UPDATE {table}`";
    assert!(foreign_updates("x.rs", comment).is_empty());
}
