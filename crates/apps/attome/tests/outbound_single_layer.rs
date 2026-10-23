//! AB6-T11: every HTTP client a server crate uses is built by
//! `attome_outbound::http` (behind the SSRF guard, with the outbound
//! policies). A crate that builds its own `reqwest` client skips both, so
//! this scans every crate's `src/` and fails, naming the file and line, on
//! `reqwest::Client::new`, `reqwest::Client::builder` or
//! `ClientBuilder::new` anywhere outside the allow-list. Test code (a file's
//! `#[cfg(test)]` part) and comments are not scanned.
//!
//! ```text
//! cargo test -p attome --test outbound_single_layer
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

/// Where building a client is the point, with why. A new entry names the
/// task that will remove it.
const ALLOWED: &[(&str, &str)] = &[(
    "crates/foundation/attome-outbound/",
    "the outbound layer itself: the one place clients are built",
)];

const PATTERNS: &[&str] = &[
    "reqwest::Client::new(",
    "reqwest::Client::builder(",
    "ClientBuilder::new(",
    "reqwest::blocking::Client",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root")
}

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name == "target" || name == "tests" || name == "benches" || name == "examples" {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// `path` relative to the workspace, with forward slashes.
fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn no_outbound_client_outside_base_outbound() {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_sources(&root.join("crates"), &mut files);
    assert!(
        files.len() > 100,
        "the scan found the crates ({})",
        files.len()
    );

    let mut found = Vec::new();
    for file in files {
        let rel = relative(&root, &file);
        if !rel.contains("/src/") || ALLOWED.iter().any(|(prefix, _)| rel.starts_with(prefix)) {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("read a source file");
        for (number, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            // A file's tests follow its first `#[cfg(test)]`, by convention.
            if trimmed.starts_with("#[cfg(test)]") {
                break;
            }
            if trimmed.starts_with("//") {
                continue;
            }
            if PATTERNS.iter().any(|p| line.contains(p)) {
                found.push(format!("{rel}:{}: {}", number + 1, line.trim()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "HTTP clients built outside attome_outbound::http (build them with \
         attome_outbound::http::client, or allow-list the crate here with a reason):\n{}",
        found.join("\n")
    );
}
