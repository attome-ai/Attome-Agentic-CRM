//! `attome release --check`: the one release gate (see `docs/architecture.md`). The same command
//! runs on a developer's machine, on the build machine and, once the project
//! takes contributions, in public CI, on Windows and Linux alike.
//!
//! Steps, all run so one report shows every failure:
//! 1. **format**: `rustfmt --check` on every `.rs` file under `crates/`, in
//!    batches, so a large workspace never overflows the Windows command line
//!    (which `cargo fmt --all` does).
//! 2. **clippy**: `cargo clippy --workspace --all-targets -- -D warnings`.
//! 3. **tests**: `cargo test --workspace`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::say;

/// Files handed to one `rustfmt` call. Small enough for any command line.
const FORMAT_BATCH: usize = 40;

type Step = fn(&Path) -> Result<(), String>;

pub(crate) fn check() -> ExitCode {
    let root = match workspace_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("attome release --check: {error}");
            return ExitCode::from(2);
        }
    };
    let steps: [(&str, Step); 3] = [("format", format), ("clippy", clippy), ("tests", tests)];
    let mut failed = Vec::new();
    for (name, step) in steps {
        say(&format!("==> {name}"));
        match step(&root) {
            Ok(()) => say(&format!("    {name}: ok")),
            Err(error) => {
                eprintln!("    {name}: FAILED: {error}");
                failed.push(name);
            }
        }
    }
    if failed.is_empty() {
        say("release check: ok");
        ExitCode::SUCCESS
    } else {
        eprintln!("release check: failed ({})", failed.join(", "));
        ExitCode::FAILURE
    }
}

fn format(root: &Path) -> Result<(), String> {
    let files = rust_files(&root.join("crates"))?;
    for batch in files.chunks(FORMAT_BATCH) {
        let mut command = Command::new("rustfmt");
        command.args(["--check", "--edition", "2024"]).args(batch);
        run(&mut command, root, "rustfmt --check")?;
    }
    Ok(())
}

fn clippy(root: &Path) -> Result<(), String> {
    let mut command = Command::new("cargo");
    command.args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]);
    run(&mut command, root, "cargo clippy")
}

fn tests(root: &Path) -> Result<(), String> {
    let mut command = Command::new("cargo");
    command.args(["test", "--workspace"]);
    run(&mut command, root, "cargo test")
}

fn run(command: &mut Command, root: &Path, what: &str) -> Result<(), String> {
    let status = command
        .current_dir(root)
        .status()
        .map_err(|error| format!("could not start {what}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{what} exited with {status}"))
    }
}

/// The nearest directory, from the current one upwards, whose `Cargo.toml`
/// declares a `[workspace]`.
fn workspace_root() -> Result<PathBuf, String> {
    let start = std::env::current_dir().map_err(|error| format!("no current directory: {error}"))?;
    for dir in start.ancestors() {
        let manifest = dir.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&manifest)
            && text.lines().any(|line| line.trim() == "[workspace]")
        {
            return Ok(dir.to_path_buf());
        }
    }
    Err("not inside the Attome workspace (no Cargo.toml with [workspace] found)".to_owned())
}

/// Every `.rs` file under `dir`, sorted, skipping `target` directories.
fn rust_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|error| format!("cannot read {}: {error}", current.display()))?;
        for entry in entries {
            let entry = entry.map_err(|error| format!("cannot read {}: {error}", current.display()))?;
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "attome-release-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rust_files_finds_nested_sources_and_skips_target() {
        let dir = scratch("files");
        std::fs::create_dir_all(dir.join("a/src")).unwrap();
        std::fs::create_dir_all(dir.join("a/target/debug")).unwrap();
        std::fs::write(dir.join("a/src/lib.rs"), "").unwrap();
        std::fs::write(dir.join("a/src/notes.md"), "").unwrap();
        std::fs::write(dir.join("a/target/debug/build.rs"), "").unwrap();

        let files = rust_files(&dir).unwrap();
        assert_eq!(files, vec![dir.join("a/src/lib.rs")]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_batches_stay_small() {
        let paths: Vec<PathBuf> = (0..101).map(|i| PathBuf::from(format!("f{i}.rs"))).collect();
        let sizes: Vec<usize> = paths.chunks(FORMAT_BATCH).map(<[PathBuf]>::len).collect();
        assert_eq!(sizes, vec![40, 40, 21]);
    }
}
