//! `attome release --check`: the one release gate (see `docs/architecture.md`). The same command
//! runs on a developer's machine, on the build machine and, once the project
//! takes contributions, in public CI, on Windows and Linux alike.
//!
//! Steps, all run so one report shows every failure:
//! 1. **format**: `rustfmt --check` on every `.rs` file under `crates/`, in
//!    batches, so a large workspace never overflows the Windows command line
//!    (which `cargo fmt --all` does).
//! 2. **clippy**: `cargo clippy --workspace --all-targets --keep-going -- -D warnings`
//!    (`--keep-going` so one broken crate does not hide the others' errors).
//! 3. **tests**: `cargo test --workspace --no-fail-fast -- --test-threads=1`, so one run
//!    reports every failing test.
//! 4. **contract**: this commit's `openapi.json` against the previous release
//!    tag's; a breaking change must be named under `### Breaking` in
//!    `CHANGELOG.md`'s `[Unreleased]` section (roadmap AC4-T4). Skipped until
//!    the first release is tagged.
//! 5. **web** (with `--web`): the web app's builds, lints and unit tests, in
//!    dependency order, under `web/` (roadmap AC4-T3). `npm ci` is the
//!    caller's: the step uses the installed `node_modules`.
//!
//! Every run writes `target/release-gate/gate-<os>.json`: the commit, the
//! operating system, the toolchain, and each step's outcome and duration
//! (roadmap AC4). A release is tagged only from a commit whose reports from
//! both Windows and Linux are green.

mod contract;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Files handed to one `rustfmt` call. Small enough for any command line.
const FORMAT_BATCH: usize = 40;

type Step = fn(&Path) -> Result<(), String>;

/// What a gate run includes beyond the Rust steps.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Also build, lint and test the web app.
    pub web: bool,
}

/// The gate with the default options (Rust steps and the contract check).
pub fn check() -> ExitCode {
    check_with(Options::default())
}

/// The gate with `options`.
pub fn check_with(options: Options) -> ExitCode {
    let root = match workspace_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("attome release --check: {error}");
            return ExitCode::from(2);
        }
    };
    let mut steps: Vec<(&str, Step)> = vec![
        ("format", format as Step),
        ("clippy", clippy as Step),
        ("tests", tests as Step),
        ("contract", contract_step as Step),
    ];
    if options.web {
        steps.push(("web", web as Step));
    }
    let started_at = unix_seconds();
    let mut failed = Vec::new();
    let mut outcomes = Vec::new();
    for (name, step) in steps {
        say(&format!("==> {name}"));
        let clock = Instant::now();
        let result = step(&root);
        let duration_ms = u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX);
        match &result {
            Ok(()) => say(&format!("    {name}: ok")),
            Err(error) => {
                eprintln!("    {name}: FAILED: {error}");
                failed.push(name);
            }
        }
        outcomes.push(StepOutcome {
            id: name,
            passed: result.is_ok(),
            duration_ms,
            error: result.err(),
        });
    }
    match write_report(&root, started_at, &outcomes) {
        Ok(path) => say(&format!("report: {}", path.display())),
        // The report is evidence, not a gate step: failing to write it is
        // reported, and the gate's verdict stands.
        Err(error) => eprintln!("could not write the gate report: {error}"),
    }
    if failed.is_empty() {
        say("release check: ok");
        ExitCode::SUCCESS
    } else {
        eprintln!("release check: failed ({})", failed.join(", "));
        ExitCode::FAILURE
    }
}

/// One step's outcome, as the report records it.
#[derive(Debug)]
struct StepOutcome {
    id: &'static str,
    passed: bool,
    duration_ms: u64,
    error: Option<String>,
}

/// Writes `target/release-gate/gate-<os>.json` and returns its path.
fn write_report(root: &Path, started_at: u64, outcomes: &[StepOutcome]) -> Result<PathBuf, String> {
    let steps: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|step| {
            serde_json::json!({
                "id": step.id,
                "status": if step.passed { "passed" } else { "failed" },
                "duration_ms": step.duration_ms,
                "error": step.error,
            })
        })
        .collect();
    let report = serde_json::json!({
        "format": "attome-release-gate/v1",
        "commit": command_output(root, "git", &["rev-parse", "HEAD"]),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "rustc": command_output(root, "rustc", &["-V"]),
        "started_at_unix": started_at,
        "finished_at_unix": unix_seconds(),
        "passed": outcomes.iter().all(|step| step.passed),
        "steps": steps,
    });
    let dir = root.join("target").join("release-gate");
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let path = dir.join(format!("gate-{}.json", std::env::consts::OS));
    let text = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("cannot serialise the report: {error}"))?;
    std::fs::write(&path, text + "\n")
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    Ok(path)
}

/// A command's trimmed standard output, or `None` when it cannot run or fails.
fn command_output(root: &Path, program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// The contract-diff step (see [`contract`]).
fn contract_step(root: &Path) -> Result<(), String> {
    let Some(tag) = command_output(root, "git", &["describe", "--tags", "--abbrev=0"]) else {
        say("    contract: no previous release tag; skipped");
        return Ok(());
    };
    let old_text = command_output(root, "git", &["show", &format!("{tag}:openapi.json")])
        .ok_or_else(|| format!("cannot read openapi.json at {tag}"))?;
    let new_text = std::fs::read_to_string(root.join("openapi.json"))
        .map_err(|error| format!("cannot read openapi.json: {error}"))?;
    let old: serde_json::Value = serde_json::from_str(&old_text)
        .map_err(|error| format!("openapi.json at {tag} is not JSON: {error}"))?;
    let new: serde_json::Value = serde_json::from_str(&new_text)
        .map_err(|error| format!("openapi.json is not JSON: {error}"))?;
    let changes = contract::breaking_changes(&old, &new);

    let diff = serde_json::json!({
        "base": tag,
        "breaking": changes.iter().map(contract::Breaking::to_json).collect::<Vec<_>>(),
    });
    let dir = root.join("target").join("release-gate");
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let text = serde_json::to_string_pretty(&diff)
        .map_err(|error| format!("cannot serialise the contract diff: {error}"))?;
    std::fs::write(dir.join("contract-diff.json"), text + "\n")
        .map_err(|error| format!("cannot write the contract diff: {error}"))?;

    let changelog = std::fs::read_to_string(root.join("CHANGELOG.md")).unwrap_or_default();
    let silent = contract::unannounced(&changes, &changelog);
    if silent.is_empty() {
        return Ok(());
    }
    let list: Vec<String> = silent
        .iter()
        .map(|change| format!("{} {}: {}", change.method, change.path, change.what))
        .collect();
    Err(format!(
        "breaking API changes since {tag} not named under `### Breaking` in CHANGELOG.md [Unreleased]: {}",
        list.join("; ")
    ))
}

/// The web app's gate: every build, lint and unit-test script, in order.
/// Every script runs, so one run reports every failure.
fn web(root: &Path) -> Result<(), String> {
    let web = root.join("web");
    if !web.join("node_modules").is_dir() {
        return Err("web/node_modules is missing: run `npm ci` in web/ first".to_owned());
    }
    let mut failed = Vec::new();
    for script in WEB_SCRIPTS {
        let mut command = Command::new(npm_program("npm"));
        command.args(["run", script]);
        if run(&mut command, &web, &format!("npm run {script}")).is_err() {
            failed.push((*script).to_owned());
        }
    }
    let mut host_lint = Command::new(npm_program("npx"));
    host_lint.args(["ng", "lint", "attome-website"]);
    if run(&mut host_lint, &web, "ng lint attome-website").is_err() {
        failed.push("ng lint attome-website".to_owned());
    }
    let mut host_tests = Command::new(npm_program("npm"));
    host_tests.arg("test");
    if run(&mut host_tests, &web, "npm test").is_err() {
        failed.push("test".to_owned());
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("web scripts failed: {}", failed.join(", ")))
    }
}

/// The web scripts the gate runs, libraries before the app that uses them.
const WEB_SCRIPTS: [&str; 10] = [
    "build:base",
    "build:xrm",
    "build:sdk",
    "build",
    "lint:base",
    "lint:xrm",
    "lint:sdk",
    "test:base",
    "test:xrm",
    "test:sdk",
];

/// `npm`/`npx` are `.cmd` shims on Windows, which `Command` does not resolve
/// by itself.
fn npm_program(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.cmd")
    } else {
        name.to_owned()
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
        "--keep-going",
        "--",
        "-D",
        "warnings",
    ]);
    run(&mut command, root, "cargo clippy")
}

fn tests(root: &Path) -> Result<(), String> {
    let mut command = Command::new("cargo");
    // One test thread per binary: the database-backed suites share one throwaway
    // database per process, and concurrent metadata writes in it conflict.
    command.args([
        "test",
        "--workspace",
        "--no-fail-fast",
        "--",
        "--test-threads=1",
    ]);
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
    let start =
        std::env::current_dir().map_err(|error| format!("no current directory: {error}"))?;
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
            let entry =
                entry.map_err(|error| format!("cannot read {}: {error}", current.display()))?;
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

/// Writes one line to standard output. A closed pipe is not an error worth
/// failing a check over, so the write result is ignored.
fn say(text: &str) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("attome-release-test-{name}-{}", std::process::id()));
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
    fn the_report_records_every_step_and_the_verdict() {
        let dir = scratch("report");
        let outcomes = [
            StepOutcome {
                id: "format",
                passed: true,
                duration_ms: 5,
                error: None,
            },
            StepOutcome {
                id: "tests",
                passed: false,
                duration_ms: 9,
                error: Some("cargo test exited with 101".to_owned()),
            },
        ];
        let path = write_report(&dir, 1, &outcomes).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(report["passed"], false);
        assert_eq!(report["os"], std::env::consts::OS);
        assert_eq!(report["steps"][0]["status"], "passed");
        assert_eq!(report["steps"][1]["status"], "failed");
        assert_eq!(report["steps"][1]["error"], "cargo test exited with 101");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn format_batches_stay_small() {
        let paths: Vec<PathBuf> = (0..101)
            .map(|i| PathBuf::from(format!("f{i}.rs")))
            .collect();
        let sizes: Vec<usize> = paths.chunks(FORMAT_BATCH).map(<[PathBuf]>::len).collect();
        assert_eq!(sizes, vec![40, 40, 21]);
    }
}
