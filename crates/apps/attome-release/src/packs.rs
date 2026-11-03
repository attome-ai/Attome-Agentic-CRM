//! X1-T1: the gate's `packs` step. Every pack that ships golden workflows
//! (`packs/<pack>/golden/golden.json`) is installed, in its list's order, on
//! the throwaway database of a fresh test deployment and its golden
//! workflows run (attome-testapp's `pack_golden` target); any failure fails
//! the gate. The `tests` step runs the same target among the others, but
//! there a missing database only skips it; here a skip is a failure
//! (`ATTOME_TEST_REQUIRE_DB`), and the step names the packs it covered.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The test target that installs each pack and runs its golden workflows.
pub const GOLDEN_TARGET: (&str, &str) = ("attome-testapp", "pack_golden");

/// The packs with golden workflows under `root/packs`, sorted.
pub fn golden_packs(root: &Path) -> Vec<String> {
    let mut packs: Vec<String> = std::fs::read_dir(root.join("packs"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| golden_file(&entry.path()).is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    packs.sort();
    packs
}

fn golden_file(pack: &Path) -> PathBuf {
    pack.join("golden").join("golden.json")
}

/// The `cargo test` arguments that run [`GOLDEN_TARGET`].
pub fn packs_gate_args() -> Vec<&'static str> {
    vec![
        "test",
        "-p",
        GOLDEN_TARGET.0,
        "--test",
        GOLDEN_TARGET.1,
        "--",
        "--test-threads=1",
    ]
}

/// Runs the step. A lane without a test database (`DATABASE_URL`) does not
/// run it, as with the other database steps.
pub fn step(root: &Path) -> Result<(), String> {
    let packs = golden_packs(root);
    if packs.is_empty() {
        return Err(
            "packs: no pack ships golden workflows (packs/<pack>/golden/golden.json)".to_owned(),
        );
    }
    if std::env::var_os("DATABASE_URL").is_none() {
        crate::say(
            "    packs: DATABASE_URL is not set; installing packs needs a database; not run",
        );
        return Ok(());
    }
    crate::say(&format!(
        "    packs: {} ({})",
        packs.len(),
        packs.join(", ")
    ));
    let status = Command::new("cargo")
        .args(packs_gate_args())
        .env("ATTOME_TEST_REQUIRE_DB", "1")
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not start the pack golden workflows: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("the pack golden workflows exited with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_gate_runs_the_golden_target_one_thread_at_a_time() {
        let args = packs_gate_args();
        assert_eq!(
            args,
            [
                "test",
                "-p",
                "attome-testapp",
                "--test",
                "pack_golden",
                "--",
                "--test-threads=1"
            ]
        );
    }

    #[test]
    fn packs_gate_finds_every_pack_with_golden_workflows() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let packs = golden_packs(&root);
        assert!(packs.contains(&"healthcare".to_owned()), "{packs:?}");
        assert!(
            !packs.contains(&"crm".to_owned()),
            "crm ships no golden workflows: {packs:?}"
        );
        let mut sorted = packs.clone();
        sorted.sort();
        assert_eq!(packs, sorted);
        let target = root
            .join("crates/engine")
            .join(GOLDEN_TARGET.0)
            .join("tests")
            .join(format!("{}.rs", GOLDEN_TARGET.1));
        assert!(target.is_file(), "{}", target.display());
    }
}
