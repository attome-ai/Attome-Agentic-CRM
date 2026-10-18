//! AA9-T9: the limits registry stays honest. Every limit is a resource or an
//! abuse limit, no code counts statements per transaction, and every limit
//! is documented in `docs/limits.md`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

use attome_config::limits::{LIMITS, LimitKind};

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
            if name == "target" || name.starts_with('.') {
                continue;
            }
            rust_sources(&path, out);
        } else if name.ends_with(".rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_limit_is_resource_or_abuse() {
    for limit in LIMITS {
        // Exhaustive on purpose: a third kind fails to compile here.
        match limit.kind {
            LimitKind::Resource | LimitKind::Abuse => {}
        }
    }
}

/// V2-D151: a cap on how many statements one request or transaction runs
/// fails real work at an arbitrary size; such work goes to the background.
#[test]
fn no_count_per_transaction_constant() {
    let mut files = Vec::new();
    rust_sources(&workspace_root().join("crates"), &mut files);
    let mut hits = Vec::new();
    for file in files {
        if !file.components().any(|c| c.as_os_str() == "src") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            for prefix in ["MAX_QUERIES_PER", "MAX_STATEMENTS_PER", "MAX_DML_PER"] {
                if line.contains(prefix) {
                    hits.push(format!("{}:{}", file.display(), n + 1));
                }
            }
        }
    }
    assert!(hits.is_empty(), "per-transaction count limits: {hits:?}");
}

#[test]
fn registry_documented() {
    let doc =
        std::fs::read_to_string(workspace_root().join("docs/limits.md")).expect("docs/limits.md");
    for limit in LIMITS {
        assert!(
            doc.contains(&format!("`{}`", limit.key)),
            "docs/limits.md does not list {}",
            limit.key
        );
    }
}
