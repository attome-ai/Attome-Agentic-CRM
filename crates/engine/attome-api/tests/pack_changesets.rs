//! Every pack's changesets (`packs/<name>/changesets/*.json`) are well-formed:
//! they parse, carry a correct checksum, sit in the product layer under their
//! own scope, and are numbered from 0001 without gaps. No database needed.

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
    assert!(checked >= 9, "expected the nine packs, found {checked} changesets");
}
