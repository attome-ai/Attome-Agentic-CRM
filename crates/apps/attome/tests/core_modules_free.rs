//! AF6-T1: no core feature sits behind a paid flag or a licence check
//! (V2-D473: the platform is AGPL; module management only switches modules
//! off, it never sells them). Every built-in module is on when a deployment
//! has no module configuration, and no crate carries licence-verification
//! code. No database needed.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

use attome_modules::{MODULE_MAP, ModuleSet};

#[test]
fn every_module_is_on_without_any_configuration() {
    let default = ModuleSet::default();
    for (name, id) in MODULE_MAP {
        assert!(default.has(*id), "module '{name}' is off by default");
    }
    // Configuration can only narrow the set, never require anything to be
    // bought: no configuration means everything.
    assert_eq!(default.narrowed_by(None), ModuleSet::all());
}

/// Words that only licence enforcement would need. A hit means someone
/// started gating a feature on a licence again.
const LICENCE_ENFORCEMENT: &[&str] = &[
    "verify_license",
    "verify_licence",
    "license_key",
    "licence_key",
    "LicenseToken",
    "license_signature",
    "requires_paid",
    "paid_feature",
    "PaidFeature",
    "is_paid",
];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_crate_carries_licence_enforcement() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let this_file = Path::new(file!())
        .file_name()
        .expect("file name")
        .to_owned();
    let mut files = Vec::new();
    rust_sources(&crates, &mut files);
    assert!(files.len() > 100, "found only {} sources", files.len());
    let mut hits = Vec::new();
    for file in files {
        if file.file_name() == Some(this_file.as_os_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&file).expect("read source");
        for word in LICENCE_ENFORCEMENT {
            if text.contains(word) {
                hits.push(format!("{}: {word}", file.display()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "licence enforcement found:\n{}",
        hits.join("\n")
    );
}
