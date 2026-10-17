//! Every pack in `packs/` installs on a fresh deployment, in some order, and
//! a second install changes nothing. The order is found here, not declared:
//! a pack whose lookups name an entity another pack has not installed yet is
//! retried after the others, so a cycle between packs or a lookup no pack
//! provides fails the test with the packs and errors left.

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_testapp::TestApp;

fn packs_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../packs")
}

/// Every pack folder with changesets, by name.
fn packs() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(packs_dir())
        .expect("read packs")
        .flatten()
        .filter(|e| e.path().join("changesets").is_dir())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Applies one pack's changesets in file order; the first error, if any.
async fn install(app: &TestApp, pack: &str) -> Result<(), String> {
    let dir = packs_dir().join(pack).join("changesets");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    for file in &files {
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).expect("read"))
                .expect("pack changeset JSON");
        attome_api::changeset::boot::apply_pack_document(&app.state, &value)
            .await
            .map_err(|e| format!("{}: {e}", file.display()))?;
    }
    Ok(())
}

/// A failure another pack can cure by installing first.
fn waits_on_another_pack(error: &str) -> bool {
    error.contains("lookup target") && error.contains("not found")
        || error.contains("does not exist")
}

// feature: T8
#[test]
fn every_pack_installs_on_a_fresh_deployment() {
    attome_testkit::run_shared(async {
        let Some(app) = TestApp::start().await else {
            return;
        };
        // The server applies every platform definition at boot.
        attome_api::changeset::boot::apply_platform_changesets(&app.state)
            .await
            .expect("platform changesets");
        let mut left = packs();
        let mut order = Vec::new();
        loop {
            let mut progressed = false;
            let mut still = Vec::new();
            let mut errors = Vec::new();
            for pack in left {
                match install(&app, &pack).await {
                    Ok(()) => {
                        order.push(pack);
                        progressed = true;
                    }
                    Err(e) if waits_on_another_pack(&e) => {
                        errors.push(e);
                        still.push(pack);
                    }
                    Err(e) => panic!("{pack} does not install: {e}"),
                }
            }
            left = still;
            if left.is_empty() {
                break;
            }
            assert!(
                progressed,
                "these packs never install (a cycle, or a lookup no pack provides): {left:?}\n{errors:#?}"
            );
        }
        // A second install of everything changes nothing.
        for pack in &order {
            install(&app, pack)
                .await
                .unwrap_or_else(|e| panic!("{pack} does not reinstall: {e}"));
        }
        eprintln!("install order: {order:?}");
    });
}
