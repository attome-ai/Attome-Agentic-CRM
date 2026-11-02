//! Every pack's changesets (`packs/<name>/changesets/*.json`) are well-formed:
//! they parse, carry a correct checksum, sit in the product layer under their
//! own scope, and are numbered from 0001 without gaps. No database needed.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::PathBuf;

use attome_api::changeset::plan::parse_document;

fn packs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

#[test]
fn every_pack_changeset_is_a_valid_product_changeset() {
    let mut checked = 0;
    for pack in std::fs::read_dir(packs_dir()).expect("packs/").flatten() {
        let changesets = pack.path().join("changesets");
        if !changesets.is_dir() {
            continue;
        }
        let name = pack.file_name().to_string_lossy().into_owned();
        let mut files: Vec<PathBuf> = std::fs::read_dir(&changesets)
            .expect("read changesets")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        files.sort();
        assert!(!files.is_empty(), "{name}: no changesets");
        for (index, file) in files.iter().enumerate() {
            let text = std::fs::read_to_string(file).expect("read changeset");
            let value: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{}: not JSON: {e}", file.display()));
            let document = parse_document(&value)
                .unwrap_or_else(|errs| panic!("{}: {}", file.display(), errs.join("; ")));
            assert_eq!(value["layer"], "product", "{}", file.display());
            assert_eq!(value["scope"], name.as_str(), "{}", file.display());
            let stem = file.file_stem().unwrap().to_string_lossy();
            assert!(
                stem.starts_with(&format!("{:04}-", index + 1)),
                "{}: numbering must run 0001.. without gaps",
                file.display()
            );
            assert!(!document.reference().is_empty());
            checked += 1;
        }
    }
    assert!(
        checked >= 9,
        "expected the nine packs, found {checked} changesets"
    );
}

/// X2-T1: every pack carries a `pack.json` manifest: its own name, a level,
/// a version whose minor part is its changeset count (adding a changeset
/// bumps it), dependencies that are packs and form no cycle, and contents
/// that exist; a `complete` pack ships golden workflows and model objects.
#[test]
fn every_pack_has_a_manifest() {
    let mut manifests = std::collections::BTreeMap::new();
    for pack in std::fs::read_dir(packs_dir()).expect("packs/").flatten() {
        let dir = pack.path();
        if !dir.join("changesets").is_dir() {
            continue;
        }
        let name = pack.file_name().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(dir.join("pack.json"))
            .unwrap_or_else(|e| panic!("{name}: no pack.json: {e}"));
        let manifest: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: pack.json: {e}"));
        assert_eq!(manifest["format"], "attome-pack/v1", "{name}");
        assert_eq!(manifest["name"], name.as_str(), "{name}");
        assert!(
            manifest["title"].as_str().is_some_and(|t| !t.is_empty()),
            "{name}: a title"
        );
        let changesets = std::fs::read_dir(dir.join("changesets"))
            .expect("read changesets")
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .count();
        assert_eq!(
            manifest["version"],
            format!("1.{changesets}.0").as_str(),
            "{name}: the minor version is the changeset count"
        );
        let level = manifest["level"].as_str().unwrap_or_default();
        assert!(
            ["starter", "standard", "complete"].contains(&level),
            "{name}: level {level:?}"
        );
        let contents: Vec<&str> = manifest["contents"]
            .as_array()
            .map(|c| c.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        for item in &contents {
            let path = match *item {
                "golden" => dir.join("golden").join("golden.json"),
                other => dir.join(other),
            };
            assert!(
                path.exists(),
                "{name}: contents names {item}, which is missing"
            );
        }
        if level == "complete" {
            assert!(
                contents.contains(&"golden") && contents.contains(&"model"),
                "{name}: a complete pack ships golden workflows and model objects"
            );
        }
        let depends: Vec<String> = manifest["depends"]
            .as_array()
            .expect("depends is a list")
            .iter()
            .map(|d| d.as_str().expect("a pack name").to_owned())
            .collect();
        manifests.insert(name, depends);
    }
    assert!(manifests.len() >= 30, "found {} packs", manifests.len());
    for (name, depends) in &manifests {
        for dep in depends {
            assert!(
                manifests.contains_key(dep),
                "{name} depends on unknown pack {dep}"
            );
            assert_ne!(dep, name, "{name} depends on itself");
        }
    }
    // No cycle: repeatedly take the packs whose dependencies are all taken.
    let mut done = std::collections::BTreeSet::new();
    while done.len() < manifests.len() {
        let ready: Vec<&String> = manifests
            .iter()
            .filter(|(name, deps)| !done.contains(*name) && deps.iter().all(|d| done.contains(d)))
            .map(|(name, _)| name)
            .collect();
        assert!(!ready.is_empty(), "pack dependencies form a cycle");
        for name in ready {
            done.insert(name.clone());
        }
    }
}
