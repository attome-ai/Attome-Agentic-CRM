//! Z10-T12: one approval engine. Only `attome-approval` writes approval
//! requests and decisions; every feature that needs an approval goes
//! through it, so the lifecycle rules (steps, delegation, expiry, claims)
//! hold everywhere. Policies, versions, delegations and recommendations
//! are other tables and are not matched.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

const WRITES: &[&str] = &[
    "INSERT INTO approval_request ",
    "INSERT INTO approval_request(",
    "UPDATE approval_request ",
    "INSERT INTO approval_grant ",
    "INSERT INTO approval_grant(",
    "UPDATE approval_grant ",
];

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            // Build output, test suites (they seed fixtures) and migrations
            // are not application code.
            if matches!(name.as_deref(), Some("target" | "tests" | "migrations")) {
                continue;
            }
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn only_base_approval_writes_approval_requests() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let engine = crates.join("foundation").join("attome-approval");
    let mut files = Vec::new();
    walk(&crates, &mut files);
    assert!(files.len() > 100, "the source scan found too little");
    let offenders: Vec<String> = files
        .iter()
        .filter(|f| !f.starts_with(&engine))
        .filter(|f| {
            let text = std::fs::read_to_string(f).unwrap_or_default();
            WRITES.iter().any(|w| text.contains(w))
        })
        .map(|f| f.display().to_string())
        .collect();
    assert!(
        offenders.is_empty(),
        "only attome-approval may write approval_request / approval_grant; found: {offenders:?}"
    );
}
