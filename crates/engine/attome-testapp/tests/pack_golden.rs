//! X2/X3-T2: every pack's golden workflows pass. A pack keeps them in
//! `packs/<pack>/golden/golden.json` (`attome-pack-golden/v1`): the packs to
//! install, in order, and customer tests (T7) over the pack's sample
//! records. This test installs each pack's list and runs its tests as an
//! administrator; nothing a test does is kept. It runs in the release gate's
//! `tests` step, so the golden workflows run on every release.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};

use attome_records::customer_tests::{run_test, validate};
use attome_testapp::TestApp;
use serde_json::Value;

const FORMAT: &str = "attome-pack-golden/v1";

fn packs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

/// Every `packs/<pack>/golden/golden.json`, by pack name.
fn golden_files() -> Vec<(String, Value)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(packs_dir()).expect("packs/").flatten() {
        let file = entry.path().join("golden").join("golden.json");
        if !file.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let doc: Value = serde_json::from_str(
            &std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display())),
        )
        .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        out.push((name, doc));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

async fn install(app: &TestApp, pack: &str) {
    let dir = packs_dir().join(pack).join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    files.sort();
    for file in &files {
        let value: Value = serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
            .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .unwrap_or_else(|e| panic!("{}: {e}", file.display()));
    }
}

// feature: X3
#[test]
fn golden_files_read() {
    let files = golden_files();
    assert!(
        files.iter().any(|(name, _)| name == "financial-services"),
        "the financial services pack has golden workflows"
    );
    for (pack, doc) in &files {
        assert_eq!(doc["format"], FORMAT, "{pack}");
        assert!(
            doc["packs"].as_array().is_some_and(|p| !p.is_empty()),
            "{pack}: packs"
        );
        let tests = doc["tests"].as_array().expect("tests");
        assert!(!tests.is_empty(), "{pack}: tests");
        for test in tests {
            let name = test["name"].as_str().expect("name");
            validate(name, &test["definition"]).unwrap_or_else(|e| panic!("{pack}: {name}: {e}"));
        }
    }
}

// feature: X3
#[test]
fn pack_golden_workflows_pass() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        let admin = attome_security::resolve_uncached(&app.state.base.db, app.admin.id)
            .await
            .unwrap();
        let mut failed = Vec::new();
        for (pack, doc) in golden_files() {
            for needed in doc["packs"].as_array().into_iter().flatten() {
                install(&app, needed.as_str().expect("a pack name")).await;
            }
            for test in doc["tests"].as_array().into_iter().flatten() {
                let name = test["name"].as_str().unwrap_or("(unnamed)");
                let definition = validate(name, &test["definition"]).expect("a golden test reads");
                let outcome = run_test(&app.state, &admin, &definition).await;
                if !outcome.passed {
                    failed.push(format!("{pack}: {name}: {}", outcome.failures.join("; ")));
                }
            }
        }
        assert!(
            failed.is_empty(),
            "golden workflows failed:\n{}",
            failed.join("\n")
        );
    });
}
