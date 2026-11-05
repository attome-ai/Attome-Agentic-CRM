//! Y4-T4: a module reaches another module only through the SDK and
//! relationships, never by depending on its engine crate.
//!
//! A source scan, no database: every `crates/engine/*/Cargo.toml`'s
//! `[dependencies]` is read and each dependency on another engine crate is
//! an edge. An edge into a platform crate ([`PLATFORM`], the services every
//! module is built on) is fine; any other edge between two engines must be
//! listed in `module_boundaries_allow.txt` with its reason. The list was
//! seeded with every edge that existed on 2026-11-05 and only shrinks: a new
//! direct engine-to-engine dependency fails, and a listed edge that no
//! longer exists fails too, so the list cannot rot. The remaining edges are
//! printed as a report.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Engine crates that are the platform itself: any module may depend on
/// them. Composition crates ([`COMPOSITION`]) are not checked as sources.
const PLATFORM: &[&str] = &[
    "attome-ai",
    "attome-audit",
    "attome-core",
    "attome-docgen",
    "attome-document",
    "attome-events",
    "attome-integration",
    "attome-metadata",
    "attome-model",
    "attome-modules",
    "attome-notification",
    "attome-records",
    "attome-s2s",
    "attome-search",
    "attome-security",
    "attome-state",
    "attome-workflow",
];

/// Crates whose job is to see every engine: they compose, they are not
/// modules.
const COMPOSITION: &[&str] = &["attome-api", "attome-testapp"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("the repository root is three levels above crates/apps/attome")
        .to_path_buf()
}

/// The package names a `Cargo.toml` lists under `[dependencies]` or a
/// `[target.….dependencies]` table (dev and build dependencies excluded).
fn dependencies(manifest: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_deps = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            let header = line.trim_matches(|c| c == '[' || c == ']');
            in_deps = header == "dependencies"
                || (header.starts_with("target.") && header.ends_with(".dependencies"));
            continue;
        }
        if !in_deps || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let key = line
            .split(['=', '.'])
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('"');
        if !key.is_empty() {
            out.insert(key.to_owned());
        }
    }
    out
}

/// Every engine-to-engine edge between two modules, as `from -> to`.
fn module_edges(root: &Path) -> BTreeSet<String> {
    let engine_dir = root.join("crates").join("engine");
    let mut manifests = Vec::new();
    for entry in std::fs::read_dir(&engine_dir).expect("crates/engine is readable") {
        let dir = entry.expect("a crates/engine entry").path();
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file() {
            let name = dir.file_name().unwrap().to_string_lossy().into_owned();
            manifests.push((name, std::fs::read_to_string(&manifest).unwrap()));
        }
    }
    let engines: BTreeSet<&str> = manifests.iter().map(|(n, _)| n.as_str()).collect();
    let mut edges = BTreeSet::new();
    for (name, manifest) in &manifests {
        if COMPOSITION.contains(&name.as_str()) {
            continue;
        }
        for dep in dependencies(manifest) {
            if dep != *name && engines.contains(dep.as_str()) && !PLATFORM.contains(&dep.as_str()) {
                edges.insert(format!("{name} -> {dep}"));
            }
        }
    }
    edges
}

/// The allow-list's edges, each line `from -> to  # reason`.
fn allowed(root: &Path) -> Vec<(String, String)> {
    let path = root
        .join("crates")
        .join("apps")
        .join("attome")
        .join("tests")
        .join("module_boundaries_allow.txt");
    std::fs::read_to_string(path)
        .expect("module_boundaries_allow.txt is readable")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (edge, reason) = l.split_once('#').unwrap_or((l, ""));
            (edge.trim().to_owned(), reason.trim().to_owned())
        })
        .collect()
}

#[test]
fn a_module_depends_on_another_module_only_through_the_allow_list() {
    let root = repo_root();
    let edges = module_edges(&root);
    let allow = allowed(&root);

    let unreasoned: Vec<&str> = allow
        .iter()
        .filter(|(_, reason)| reason.is_empty())
        .map(|(edge, _)| edge.as_str())
        .collect();
    assert!(
        unreasoned.is_empty(),
        "every allowed edge carries a reason after `#`: {unreasoned:?}"
    );

    let listed: BTreeSet<&str> = allow.iter().map(|(edge, _)| edge.as_str()).collect();
    let new: Vec<&String> = edges
        .iter()
        .filter(|e| !listed.contains(e.as_str()))
        .collect();
    assert!(
        new.is_empty(),
        "a module depends directly on another module's engine crate: {new:?}. Reach it \
         through attome-sdk or a relationship; only a reviewed exception goes in \
         module_boundaries_allow.txt with its reason"
    );

    let gone: Vec<&&str> = listed.iter().filter(|e| !edges.contains(**e)).collect();
    assert!(
        gone.is_empty(),
        "allowed edges that no longer exist; delete them from module_boundaries_allow.txt: {gone:?}"
    );

    eprintln!("module edges still allowed ({}):", edges.len());
    for (edge, reason) in &allow {
        eprintln!("  {edge}  ({reason})");
    }
}

#[test]
fn dependency_tables_are_read_and_dev_dependencies_are_not() {
    let manifest = "[package]\nname = \"x\"\n\n[dependencies]\nattome-core.workspace = true\n\
                    attome-sales = { workspace = true }\n# attome-hr.workspace = true\n\n\
                    [target.'cfg(windows)'.dependencies]\nattome-billing.workspace = true\n\n\
                    [dev-dependencies]\nattome-hr.workspace = true\n";
    let deps = dependencies(manifest);
    assert_eq!(
        deps.into_iter().collect::<Vec<_>>(),
        ["attome-billing", "attome-core", "attome-sales"]
    );
}
