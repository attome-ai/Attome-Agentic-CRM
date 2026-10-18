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
//! both Windows and Linux are green (`attome release tag`, [`parity`]).
//!
//! A failed step can be **overridden** only by name and reason
//! (`--override <step>=<reason> --by <person>`, AC4-T6): the step still runs,
//! its failure is kept in the report as `overridden` with who and why, and
//! `format` and `clippy` can never be overridden (they are always fixable).

pub mod advisories;
pub mod chaos;
mod contract;
pub mod intake;
pub mod notes;
pub mod parity;
pub mod release;
pub mod repro;
pub mod sbom;
pub mod slo;
pub mod slo_report;
pub mod supply;
pub mod test_cmd;
pub mod test_coverage;
pub mod test_flaky;
pub mod test_map;
pub mod test_mutants;
pub mod test_scan;
pub mod test_stack;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Files handed to one `rustfmt` call. Small enough for any command line.
const FORMAT_BATCH: usize = 40;

type Step = fn(&Path) -> Result<(), String>;

/// What a gate run includes beyond the Rust steps.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Also build, lint and test the web app.
    pub web: bool,
    /// Also run the load-test matrix and write the SLO report (AA13-T6);
    /// needs Docker, PowerShell and the load-test stack.
    pub slo_evidence: bool,
    /// Also build the release binary twice and compare (AC7-T7).
    pub reproducible: bool,
    /// Named overrides of failing steps.
    pub overrides: Vec<Override>,
    /// The person taking responsibility for the overrides.
    pub by: Option<String>,
}

/// One override: the step and why its failure may be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub step: String,
    pub reason: String,
}

/// Steps that can never be overridden: they are always fixable before a
/// release.
const NEVER_OVERRIDDEN: [&str; 2] = ["format", "clippy"];

/// The shortest reason an override may give.
const MIN_REASON_CHARS: usize = 20;

/// Parses `<step>=<reason>`.
pub fn parse_override(text: &str) -> Result<Override, String> {
    let (step, reason) = text
        .split_once('=')
        .ok_or_else(|| format!("--override takes <step>=<reason>, got `{text}`"))?;
    Ok(Override {
        step: step.trim().to_owned(),
        reason: reason.trim().to_owned(),
    })
}

/// Checks overrides against the steps this run has.
fn validate_overrides(options: &Options, steps: &[&str]) -> Result<(), String> {
    if options.overrides.is_empty() {
        return Ok(());
    }
    if options.by.as_deref().is_none_or(|by| by.trim().is_empty()) {
        return Err(
            "an override needs --by <name>: a person takes responsibility for it".to_owned(),
        );
    }
    for item in &options.overrides {
        if NEVER_OVERRIDDEN.contains(&item.step.as_str()) {
            return Err(format!("`{}` cannot be overridden; fix it", item.step));
        }
        if !steps.contains(&item.step.as_str()) {
            return Err(format!("`{}` is not a step of this run", item.step));
        }
        if item.reason.chars().count() < MIN_REASON_CHARS {
            return Err(format!(
                "the reason for overriding `{}` must be at least {MIN_REASON_CHARS} characters",
                item.step
            ));
        }
    }
    Ok(())
}

/// The gate with the default options (Rust steps and the contract check).
pub fn check() -> ExitCode {
    check_with(&Options::default())
}

/// The gate with `options`.
pub fn check_with(options: &Options) -> ExitCode {
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
        ("waivers", waivers as Step),
        ("cargo_deny", cargo_deny as Step),
        ("dependency_intake", dependency_intake as Step),
        ("npm_licences", supply::npm_licences_step as Step),
        ("sbom", sbom_step as Step),
        ("slo", slo_step as Step),
        ("rules", rules_step as Step),
        ("install_timing", install_timing as Step),
        ("smoke", smoke as Step),
    ];
    if options.web {
        steps.push(("web", web as Step));
    }
    if options.reproducible {
        steps.push(("reproducible", repro::step as Step));
    }
    if options.slo_evidence {
        steps.push(("slo_evidence", slo_evidence as Step));
    }
    let ids: Vec<&str> = steps.iter().map(|(id, _)| *id).collect();
    if let Err(error) = validate_overrides(options, &ids) {
        eprintln!("attome release --check: {error}");
        return ExitCode::from(2);
    }
    let started_at = unix_seconds();
    let mut failed = Vec::new();
    let mut outcomes = Vec::new();
    for (name, step) in steps {
        say(&format!("==> {name}"));
        let clock = Instant::now();
        let result = step(&root);
        let duration_ms = u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX);
        let overridden = options.overrides.iter().find(|item| item.step == name);
        let status = match (&result, overridden) {
            (Ok(()), _) => {
                say(&format!("    {name}: ok"));
                Status::Passed
            }
            (Err(error), Some(item)) => {
                eprintln!("    {name}: FAILED, overridden: {error}");
                Status::Overridden {
                    by: options.by.clone().unwrap_or_default(),
                    reason: item.reason.clone(),
                }
            }
            (Err(error), None) => {
                eprintln!("    {name}: FAILED: {error}");
                failed.push(name);
                Status::Failed
            }
        };
        outcomes.push(StepOutcome {
            id: name,
            status,
            duration_ms,
            error: result.err(),
        });
    }
    let overridden: Vec<&StepOutcome> = outcomes
        .iter()
        .filter(|step| matches!(step.status, Status::Overridden { .. }))
        .collect();
    if !overridden.is_empty() {
        say("overrides:");
        for step in overridden {
            if let Status::Overridden { by, reason } = &step.status {
                say(&format!("    {} by {by}: {reason}", step.id));
            }
        }
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
    status: Status,
    duration_ms: u64,
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Passed,
    Failed,
    Overridden { by: String, reason: String },
}

impl Status {
    fn label(&self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Overridden { .. } => "overridden",
        }
    }
}

/// Writes `target/release-gate/gate-<os>.json` and returns its path.
fn write_report(root: &Path, started_at: u64, outcomes: &[StepOutcome]) -> Result<PathBuf, String> {
    let steps: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|step| {
            let mut entry = serde_json::json!({
                "id": step.id,
                "status": step.status.label(),
                "duration_ms": step.duration_ms,
                "error": step.error,
            });
            if let Status::Overridden { by, reason } = &step.status {
                entry["override"] = serde_json::json!({ "by": by, "reason": reason });
            }
            entry
        })
        .collect();
    let report = serde_json::json!({
        "format": "attome-release-gate/v1",
        "commit": command_output(root, "git", &["rev-parse", "HEAD"]),
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "rustc": command_output(root, "rustc", &["-V"]),
        "node": command_output(root, &npm_program("node"), &["-v"])
            .or_else(|| command_output(root, "node", &["-v"])),
        "started_at_unix": started_at,
        "finished_at_unix": unix_seconds(),
        "passed": outcomes.iter().all(|step| step.status != Status::Failed),
        "steps": steps,
    });
    let dir = gate_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
    let path = parity::report_path(&dir, std::env::consts::OS);
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

/// Runs a gate command from its arguments (after `attome release`, or
/// `attome-release`); `None` when they are not a gate command.
pub fn dispatch(args: &[String]) -> Option<ExitCode> {
    match args.first().map(String::as_str) {
        Some("import-report") => match args.get(1..) {
            Some([path]) => Some(import_report(Path::new(path))),
            _ => None,
        },
        Some("tag") => match args.get(1..) {
            Some([version]) => Some(tag(version)),
            _ => None,
        },
        Some("test") if args.get(1).map(String::as_str) == Some("map") => {
            let scan_only = match args.get(2..) {
                Some([]) => false,
                Some([flag]) if flag == "--scan-only" => true,
                _ => return None,
            };
            Some(
                match workspace_root().and_then(|root| test_map::run(&root, scan_only)) {
                    Ok(paths) => {
                        for path in paths {
                            say(&format!("wrote {}", path.display()));
                        }
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        eprintln!("attome test map: {error}");
                        ExitCode::FAILURE
                    }
                },
            )
        }
        Some("test") if args.get(1).map(String::as_str) == Some("mutants") => {
            let write_baseline = match args.get(2..) {
                Some([]) => false,
                Some([flag]) if flag == "--write-baseline" => true,
                _ => return None,
            };
            Some(match workspace_root() {
                Ok(root) => test_mutants::run(&root, write_baseline),
                Err(error) => {
                    eprintln!("attome test mutants: {error}");
                    ExitCode::FAILURE
                }
            })
        }
        Some("test") => {
            let parsed = test_cmd::parse_args(&args[1..])?;
            Some(match workspace_root() {
                Ok(root) => test_cmd::run(&parsed, &root, unix_seconds()),
                Err(error) => {
                    eprintln!("attome test: {error}");
                    ExitCode::from(2)
                }
            })
        }
        Some("slo") => match args.get(1..) {
            Some([generate]) if generate == "generate" => Some(slo_generate(false)),
            Some([generate, check]) if generate == "generate" && check == "--check" => {
                Some(slo_generate(true))
            }
            Some([report, matrix]) if report == "report" => Some(slo_report(Path::new(matrix))),
            _ => None,
        },
        Some("advisories") => Some(
            match workspace_root().and_then(|root| {
                advisories::run(&root, &test_flaky::date_from_unix(unix_seconds()))
            }) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("attome release advisories: {error}");
                    ExitCode::FAILURE
                }
            },
        ),
        Some("stability") => Some(match workspace_root() {
            Ok(root) => match release::stability(&root, &args[1..]) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("attome release stability: {error}");
                    ExitCode::from(2)
                }
            },
            Err(error) => {
                eprintln!("attome release stability: {error}");
                ExitCode::from(2)
            }
        }),
        Some("--check") => {
            let mut options = Options::default();
            let mut rest = args[1..].iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    "--web" => options.web = true,
                    "--slo-evidence" => options.slo_evidence = true,
                    "--reproducible" => options.reproducible = true,
                    "--by" => options.by = Some(rest.next()?.clone()),
                    "--override" => match parse_override(rest.next()?) {
                        Ok(item) => options.overrides.push(item),
                        Err(error) => {
                            eprintln!("attome release --check: {error}");
                            return Some(ExitCode::from(2));
                        }
                    },
                    _ => return None,
                }
            }
            Some(check_with(&options))
        }
        _ => None,
    }
}

/// `attome slo generate [--check]`, from the workspace root.
fn slo_generate(check: bool) -> ExitCode {
    match workspace_root() {
        Ok(root) => slo::generate(&root, check),
        Err(error) => {
            eprintln!("attome slo generate: {error}");
            ExitCode::from(2)
        }
    }
}

/// `attome slo report <matrix-summary.json>`: the SLO release report and its
/// release-notes fragment, in `target/release-gate/`.
fn slo_report(matrix: &Path) -> ExitCode {
    let root = match workspace_root() {
        Ok(root) => root,
        Err(error) => {
            eprintln!("attome slo report: {error}");
            return ExitCode::from(2);
        }
    };
    match write_slo_report(&root, matrix) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("attome slo report: {error}");
            ExitCode::FAILURE
        }
    }
}

fn write_slo_report(root: &Path, matrix: &Path) -> Result<(), String> {
    let commit = command_output(root, "git", &["rev-parse", "HEAD"]);
    let written = slo_report::write(
        root,
        matrix,
        &gate_dir(root),
        commit.as_deref(),
        unix_seconds(),
    )?;
    for path in written {
        say(&format!("    wrote {}", path.display()));
    }
    Ok(())
}

/// The load-test matrix at one node, then the SLO report (AA13-T6). A missed
/// class does not fail the step; the report and the notes say so.
fn slo_evidence(root: &Path) -> Result<(), String> {
    let shell = if cfg!(windows) && Command::new("pwsh").arg("-Version").output().is_err() {
        "powershell"
    } else {
        "pwsh"
    };
    run(
        Command::new(shell).args([
            "-NoProfile",
            "-File",
            "loadtest/scripts/run-matrix.ps1",
            "-NodeCounts",
            "1",
            "-RunTag",
            "release",
        ]),
        root,
        "the load-test matrix",
    )?;
    write_slo_report(
        root,
        &root.join("loadtest/results/matrix-summary-release.json"),
    )
}

/// The SLO outputs match the catalogue (AA13-T2).
fn slo_step(root: &Path) -> Result<(), String> {
    let stale = slo::drift(root)?;
    if stale.is_empty() {
        return Ok(());
    }
    let names: Vec<String> = stale.iter().map(|p| p.display().to_string()).collect();
    Err(format!(
        "generated SLO files are out of date ({}); run `attome slo generate`",
        names.join(", ")
    ))
}

/// The Prometheus rules load and their unit tests pass (AA13-T3): `promtool
/// check rules` and `promtool test rules`. `ATTOME_PROMTOOL` names the binary
/// when it is not `promtool` on the PATH.
fn rules_step(root: &Path) -> Result<(), String> {
    let promtool = std::env::var("ATTOME_PROMTOOL").unwrap_or_else(|_| "promtool".to_owned());
    let observability = root.join("observability");
    run(
        Command::new(&promtool).args(["check", "rules", "alerts.yml"]),
        &observability,
        "promtool check rules",
    )?;
    run(
        Command::new(&promtool).args(["test", "rules", "alerts_test.yml"]),
        &observability,
        "promtool test rules",
    )
}

/// `attome release import-report <path>`: brings the other OS's gate report
/// into `target/release-gate/` after checking it was made from this commit.
pub fn import_report(source: &Path) -> ExitCode {
    let Ok(root) = workspace_root() else {
        eprintln!("attome release import-report: not inside the Attome workspace");
        return ExitCode::from(2);
    };
    let Some(head) = command_output(&root, "git", &["rev-parse", "HEAD"]) else {
        eprintln!("attome release import-report: cannot read the current commit");
        return ExitCode::from(2);
    };
    match parity::import(&gate_dir(&root), source, &head) {
        Ok(path) => {
            say(&format!("imported: {}", path.display()));
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("attome release import-report: {error}");
            ExitCode::FAILURE
        }
    }
}

/// `attome release tag <version>`: tags the current commit `v<version>` only
/// when its Windows and Linux gate reports are present and green; exit 3
/// otherwise, naming what is missing.
pub fn tag(version: &str) -> ExitCode {
    match tag_release(version) {
        Ok(message) => {
            say(&message);
            ExitCode::SUCCESS
        }
        Err((code, message)) => {
            eprintln!("attome release tag: {message}");
            ExitCode::from(code)
        }
    }
}

/// The release steps; `Err((exit code, message))` on the first refusal.
fn tag_release(version: &str) -> Result<String, (u8, String)> {
    let version = version.trim_start_matches('v');
    let name = format!("v{version}");
    let root = workspace_root().map_err(|error| (2u8, error))?;
    let head = command_output(&root, "git", &["rev-parse", "HEAD"])
        .ok_or((2u8, "cannot read the current commit".to_owned()))?;
    let dirty = command_output(
        &root,
        "git",
        &["status", "--porcelain", "--untracked-files=no"],
    )
    .unwrap_or_default();
    if !dirty.is_empty() {
        return Err((
            2u8,
            format!("the working tree has uncommitted changes:\n{dirty}"),
        ));
    }
    if command_output(
        &root,
        "git",
        &["rev-parse", "-q", "--verify", &format!("refs/tags/{name}")],
    )
    .is_some()
    {
        return Err((2u8, format!("tag {name} already exists")));
    }
    let problems = parity::check(&gate_dir(&root), &head);
    if !problems.is_empty() {
        let lines: Vec<String> = problems.iter().map(ToString::to_string).collect();
        return Err((3u8, lines.join("\n")));
    }

    let today = test_flaky::date_from_unix(unix_seconds());
    let read = |rel: &str| {
        std::fs::read_to_string(root.join(rel)).map_err(|e| (2u8, format!("{rel}: {e}")))
    };
    let changelog = release::move_unreleased(&read("CHANGELOG.md")?, version, &today)
        .map_err(|error| (2u8, error))?;
    let cargo = release::bump_workspace_version(&read("Cargo.toml")?, version)
        .map_err(|error| (2u8, error))?;
    let ledger_text = std::fs::read_to_string(root.join(release::LEDGER)).ok();
    let ledger = release::ledger_add_release(ledger_text.as_deref(), version, &today)
        .map_err(|error| (2u8, error))?;
    // AC6-T1: the version's notes in English and Arabic.
    let areas = notes::sections(&changelog, version).map_err(|error| (2u8, error))?;
    let notes_en = format!("release-notes/v{version}.en.md");
    let notes_ar = format!("release-notes/v{version}.ar.md");

    let write = |rel: &str, text: &str| {
        let path = root.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| (1u8, format!("{rel}: {e}")))?;
        }
        std::fs::write(&path, text).map_err(|e| (1u8, format!("{rel}: {e}")))
    };
    write("CHANGELOG.md", &changelog)?;
    write("Cargo.toml", &cargo)?;
    write(release::LEDGER, &ledger)?;
    write(notes_en.as_str(), &notes::english(version, &today, &areas))?;
    write(notes_ar.as_str(), &notes::arabic(version, &today, &areas))?;

    let git = |args: &[&str], what: &str| {
        run(Command::new("git").args(args), &root, what).map_err(|error| (1u8, error))
    };
    git(
        &[
            "add",
            "CHANGELOG.md",
            "Cargo.toml",
            release::LEDGER,
            notes_en.as_str(),
            notes_ar.as_str(),
        ],
        "git add",
    )?;
    git(
        &["commit", "-q", "-m", &format!("release: {name}")],
        "git commit",
    )?;
    git(
        &["tag", "-a", &name, "-m", &format!("Attome {name}")],
        "git tag",
    )?;
    Ok(format!(
        "tagged {name} (release commit on top of the gated commit {head}); push the branch and the tag yourself"
    ))
}

fn gate_dir(root: &Path) -> PathBuf {
    root.join("target").join("release-gate")
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
    // AC7-T4: the web app's SBOM, from npm itself (production packages).
    match Command::new(npm_program("npm"))
        .args(["sbom", "--sbom-format", "cyclonedx", "--omit", "dev"])
        .current_dir(&web)
        .output()
    {
        Ok(out) if out.status.success() => {
            let path = gate_dir(root).join("sbom-web.cdx.json");
            if std::fs::create_dir_all(gate_dir(root)).is_err()
                || std::fs::write(&path, &out.stdout).is_err()
            {
                failed.push("sbom".to_owned());
            }
        }
        _ => failed.push("npm sbom".to_owned()),
    }
    // AC7-T1: the npm advisory thresholds (moderate for production
    // dependencies, high for development ones); waivers live in
    // web/audit-waivers.yaml and are checked by the `waivers` step.
    for script in ["audit:prod", "audit:dev"] {
        let mut audit = Command::new(npm_program("npm"));
        audit.args(["run", script]);
        if run(&mut audit, &web, &format!("npm run {script}")).is_err() {
            failed.push(script.to_owned());
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(format!("web scripts failed: {}", failed.join(", ")))
    }
}

/// The web scripts the gate runs, libraries before the app that uses them.
const WEB_SCRIPTS: [&str; 13] = [
    "check:i18n",
    "check:colours",
    "check:logical-css",
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

/// The port the gate's installed server listens on, clear of a development
/// server's 7865.
const SMOKE_PORT: &str = "17865";

/// AC4-T8 (D-764): the server the gate just installed boots. `attome
/// preflight` must pass on its configuration, `attome serve` must answer
/// `/health/ready` with 200 within two minutes, and the server is stopped on
/// every path. Runs only after `install_timing` installed something.
fn smoke(root: &Path) -> Result<(), String> {
    let dir = gate_dir(root).join("install");
    let config = dir.join("config.json");
    if !config.is_file() {
        say("    smoke: nothing was installed (ATTOME_INSTALL_DATABASE_URL unset); not run");
        return Ok(());
    }
    let exe = root.join("target").join("debug").join(if cfg!(windows) {
        "attome.exe"
    } else {
        "attome"
    });
    run(
        Command::new(&exe)
            .arg("preflight")
            .env("CONFIG_FILE", &config),
        root,
        "attome preflight",
    )?;
    let log = std::fs::File::create(dir.join("serve.log"))
        .map_err(|error| format!("serve.log: {error}"))?;
    let err_log = log
        .try_clone()
        .map_err(|error| format!("serve.log: {error}"))?;
    let mut server = Command::new(&exe)
        .arg("serve")
        .env("CONFIG_FILE", &config)
        .current_dir(root)
        .stdout(log)
        .stderr(err_log)
        .spawn()
        .map_err(|error| format!("cannot start attome serve: {error}"))?;
    let address = format!("127.0.0.1:{SMOKE_PORT}");
    let deadline = Instant::now() + std::time::Duration::from_secs(120);
    let mut ready = false;
    while Instant::now() < deadline {
        if let Ok(Some(status)) = server.try_wait() {
            return Err(format!(
                "attome serve exited during start-up ({status}); see {}",
                dir.join("serve.log").display()
            ));
        }
        let probe = Command::new(&exe)
            .args(["healthcheck", address.as_str(), "/health/ready"])
            .output();
        if probe.is_ok_and(|out| out.status.success()) {
            ready = true;
            break;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the release CLI's own synchronous poll loop"
        )]
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let _ = server.kill();
    let _ = server.wait();
    if ready {
        say("    smoke: preflight passed and /health/ready answered 200");
        Ok(())
    } else {
        Err(format!(
            "/health/ready did not answer 200 within 120 s; see {}",
            dir.join("serve.log").display()
        ))
    }
}

/// The time budget for a Solo install (roadmap AF4: under ten minutes).
const INSTALL_BUDGET: std::time::Duration = std::time::Duration::from_secs(600);

/// AF4-T1: times `attome init` against the empty database named by
/// `ATTOME_INSTALL_DATABASE_URL` (configuration, schema and roles; the build
/// is not counted) and fails over [`INSTALL_BUDGET`]. Without the variable
/// there is nothing to install into, and the step says so and passes.
fn install_timing(root: &Path) -> Result<(), String> {
    let Ok(url) = std::env::var("ATTOME_INSTALL_DATABASE_URL") else {
        say("    install_timing: ATTOME_INSTALL_DATABASE_URL is not set; not measured");
        return Ok(());
    };
    run(
        Command::new("cargo").args(["build", "-p", "attome", "--bin", "attome"]),
        root,
        "cargo build -p attome",
    )?;
    let exe = root.join("target").join("debug").join(if cfg!(windows) {
        "attome.exe"
    } else {
        "attome"
    });
    let dir = gate_dir(root).join("install");
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let config = dir.join("config.json");
    let started = Instant::now();
    run(
        Command::new(&exe).args([
            "init",
            "--database-url",
            url.as_str(),
            "--out",
            &config.display().to_string(),
            "--port",
            SMOKE_PORT,
            "--force",
        ]),
        root,
        "attome init",
    )?;
    let took = started.elapsed();
    say(&format!(
        "    install_timing: attome init took {:.1} s (budget {} s)",
        took.as_secs_f64(),
        INSTALL_BUDGET.as_secs()
    ));
    if took > INSTALL_BUDGET {
        return Err(format!(
            "attome init took {:.0} s, over the {} s budget",
            took.as_secs_f64(),
            INSTALL_BUDGET.as_secs()
        ));
    }
    Ok(())
}

/// AC7-T4: `target/release-gate/sbom-rust.cdx.json` from `Cargo.lock`. The
/// serial number is derived from the commit, so the same commit always
/// produces the same document apart from its timestamp.
fn sbom_step(root: &Path) -> Result<(), String> {
    let commit = command_output(root, "git", &["rev-parse", "HEAD"]).unwrap_or_default();
    let hex: String = commit
        .chars()
        .filter(char::is_ascii_hexdigit)
        .chain(std::iter::repeat('0'))
        .take(32)
        .collect();
    let serial = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    let timestamp = format!("{}T00:00:00Z", test_flaky::date_from_unix(unix_seconds()));
    sbom::write_rust_sbom(root, &gate_dir(root), &serial, &timestamp)
}

/// AC7-T9: dependencies added since the previous release tag have intake
/// entries (see [`intake`]).
fn dependency_intake(root: &Path) -> Result<(), String> {
    let tag = command_output(root, "git", &["describe", "--tags", "--abbrev=0"]);
    intake::step(root, tag.as_deref())
}

/// AC7-T2: every waiver is owned and in date (see [`supply`]).
fn waivers(root: &Path) -> Result<(), String> {
    supply::waivers_step(root, &test_flaky::date_from_unix(unix_seconds()))
}

/// AC7-T1: `cargo deny check` (advisories, licences, bans, sources) against
/// `deny.toml`.
fn cargo_deny(root: &Path) -> Result<(), String> {
    let installed = Command::new("cargo")
        .args(["deny", "--version"])
        .output()
        .is_ok_and(|out| out.status.success());
    if !installed {
        return Err("cargo-deny is not installed: cargo install cargo-deny --locked".to_owned());
    }
    run(
        Command::new("cargo").args(["deny", "check"]),
        root,
        "cargo deny check",
    )
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
pub(crate) fn say(text: &str) {
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
                status: Status::Passed,
                duration_ms: 5,
                error: None,
            },
            StepOutcome {
                id: "tests",
                status: Status::Failed,
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

    fn options_with(overrides: &[(&str, &str)], by: Option<&str>) -> Options {
        Options {
            web: false,
            slo_evidence: false,
            reproducible: false,
            overrides: overrides
                .iter()
                .map(|(step, reason)| Override {
                    step: (*step).to_owned(),
                    reason: (*reason).to_owned(),
                })
                .collect(),
            by: by.map(str::to_owned),
        }
    }

    const STEPS: [&str; 4] = ["format", "clippy", "tests", "contract"];
    const REASON: &str = "flaky upstream mirror, tracked in issue 42";

    #[test]
    fn override_without_by_errors() {
        let options = options_with(&[("tests", REASON)], None);
        assert!(validate_overrides(&options, &STEPS).is_err());
    }

    #[test]
    fn override_short_reason_errors() {
        let options = options_with(&[("tests", "flaky")], Some("Ahmed"));
        assert!(validate_overrides(&options, &STEPS).is_err());
    }

    #[test]
    fn override_of_fmt_is_refused() {
        let options = options_with(&[("format", REASON)], Some("Ahmed"));
        assert!(validate_overrides(&options, &STEPS).is_err());
        let options = options_with(&[("clippy", REASON)], Some("Ahmed"));
        assert!(validate_overrides(&options, &STEPS).is_err());
    }

    #[test]
    fn valid_override_marks_step_overridden() {
        let options = options_with(&[("tests", REASON)], Some("Ahmed"));
        assert!(validate_overrides(&options, &STEPS).is_ok());
        assert_eq!(
            parse_override("tests=a reason long enough to count").unwrap(),
            Override {
                step: "tests".to_owned(),
                reason: "a reason long enough to count".to_owned()
            }
        );
        assert!(parse_override("no-equals-sign").is_err());
        let dir = scratch("override");
        let outcomes = [StepOutcome {
            id: "tests",
            status: Status::Overridden {
                by: "Ahmed".to_owned(),
                reason: REASON.to_owned(),
            },
            duration_ms: 1,
            error: Some("cargo test exited with 101".to_owned()),
        }];
        let path = write_report(&dir, 1, &outcomes).unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(report["passed"], true);
        assert_eq!(report["steps"][0]["status"], "overridden");
        assert_eq!(report["steps"][0]["override"]["by"], "Ahmed");
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
