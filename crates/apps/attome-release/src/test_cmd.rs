//! `attome test` (roadmap Z15-T1): the scoped test runner.
//!
//! ```text
//! attome test [--tier unit|db|contract|security|browser|all] [--changed] [--release] [--dry-run] [--no-stack] [--coverage]
//! ```
//!
//! - `unit` runs each crate's library tests, `db` its integration targets,
//!   `contract` and `security` fixed lists of API-contract and access tests,
//!   `browser` the Playwright suite when one exists.
//! - `--changed` scopes the crate tiers to the crates the working tree touches
//!   (`git diff HEAD`, the index and untracked files), and adds the web
//!   library rows the touched web paths need. Without it the crate tiers run
//!   for the whole workspace.
//! - `--release` runs every tier unscoped and sets `ATTOME_TEST_REQUIRE_DB`,
//!   `ATTOME_TEST_REQUIRE_REDIS` and `ATTOME_TEST_REQUIRE_S3`, so a test that
//!   would skip for a missing service fails instead.
//! - `--dry-run` prints the commands and runs nothing.
//! - A failing test is rerun once on its own; one that then passes is
//!   reported FLAKY and still fails the run. `tests/quarantine.json` skips
//!   listed tests until their date ([`crate::test_flaky`]).
//! - `--coverage` runs the cargo commands under `cargo llvm-cov` and prints
//!   line coverage per crate ([`crate::test_coverage`]).
//! - A tier that needs PostgreSQL starts the test stack when `DATABASE_URL`
//!   is not set (see [`crate::test_stack`]); `--no-stack` skips that.
//!
//! Each command's output goes to `target/attome-test/<unix seconds>/NN.log`.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

/// A test tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Unit,
    Db,
    Contract,
    Security,
    Browser,
    All,
}

impl Tier {
    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "unit" => Self::Unit,
            "db" => Self::Db,
            "contract" => Self::Contract,
            "security" => Self::Security,
            "browser" => Self::Browser,
            "all" => Self::All,
            _ => return None,
        })
    }

    fn includes(self, other: Self) -> bool {
        self == Self::All || self == other
    }

    /// Whether the tier's tests need PostgreSQL (and Redis).
    pub fn needs_services(self) -> bool {
        !matches!(self, Self::Unit | Self::Browser)
    }
}

/// Parsed `attome test` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestArgs {
    pub tier: Tier,
    pub changed: bool,
    pub release: bool,
    pub dry_run: bool,
    /// Do not start the test stack; the caller manages the services.
    pub no_stack: bool,
    /// Run the cargo commands under `cargo llvm-cov` and print line coverage
    /// per crate.
    pub coverage: bool,
}

impl Default for TestArgs {
    fn default() -> Self {
        Self {
            tier: Tier::Unit,
            changed: false,
            release: false,
            dry_run: false,
            no_stack: false,
            coverage: false,
        }
    }
}

/// Parses the arguments after `test`; `None` on anything unknown.
pub fn parse_args(args: &[String]) -> Option<TestArgs> {
    let mut parsed = TestArgs::default();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--tier" => parsed.tier = Tier::parse(rest.next()?)?,
            "--changed" => parsed.changed = true,
            "--release" => parsed.release = true,
            "--dry-run" => parsed.dry_run = true,
            "--no-stack" => parsed.no_stack = true,
            "--coverage" => parsed.coverage = true,
            _ => return None,
        }
    }
    if parsed.release {
        parsed.tier = Tier::All;
        parsed.changed = false;
    }
    Some(parsed)
}

/// Environment the test processes get: `--release` turns every
/// missing-service skip into a failure.
pub fn env_for(args: &TestArgs) -> Vec<(&'static str, &'static str)> {
    if args.release {
        vec![
            ("ATTOME_TEST_REQUIRE_DB", "1"),
            ("ATTOME_TEST_REQUIRE_REDIS", "1"),
            ("ATTOME_TEST_REQUIRE_S3", "1"),
        ]
    } else {
        Vec::new()
    }
}

/// API-contract tests: OpenAPI references, list shapes, route coverage of
/// changesets and audit declarations.
const CONTRACT: &[(&str, &str)] = &[
    ("attome-api", "openapi_refs_resolve"),
    ("attome", "list_shape_census"),
    ("attome", "changeset_route_coverage"),
    ("attome", "audit_coverage_emission"),
];

/// Access tests: route authorization, admin-only routes, record-level
/// security, portal isolation and step-up.
const SECURITY: &[(&str, &str)] = &[
    ("attome", "route_authz"),
    ("attome", "admin_routes_forbid_non_admin"),
    ("attome-api", "record_level_security"),
    ("attome", "portal_isolation"),
    ("attome", "step_up_http"),
];

/// One command to run, as program and arguments, with the directory it runs
/// in relative to the workspace root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub dir: &'static str,
    pub program: String,
    pub args: Vec<String>,
}

impl Planned {
    fn cargo(args: &[&str]) -> Self {
        Self {
            dir: ".",
            program: "cargo".to_owned(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    fn npm(args: &[&str]) -> Self {
        Self {
            dir: "web",
            program: crate::npm_program("npm"),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    fn npx(args: &[&str]) -> Self {
        Self {
            dir: "web",
            program: crate::npm_program("npx"),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    /// The command as a person would type it.
    pub fn display(&self) -> String {
        let line = format!("{} {}", self.program, self.args.join(" "));
        if self.dir == "." {
            line
        } else {
            format!("(cd {}) {line}", self.dir)
        }
    }
}

/// The package that owns `path` (relative to `root`): the nearest ancestor
/// directory whose `Cargo.toml` has a `[package]` name.
pub fn owning_crate(root: &Path, path: &str) -> Option<String> {
    let mut dir = root.join(path);
    loop {
        dir = dir.parent()?.to_path_buf();
        if !dir.starts_with(root) || dir == root {
            return None;
        }
        if let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml"))
            && let Some(name) = package_name(&text)
        {
            return Some(name);
        }
    }
}

fn package_name(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package
            && let Some(value) = line.strip_prefix("name")
            && let Some(value) = value.trim_start().strip_prefix('=')
        {
            return Some(value.trim().trim_matches('"').to_owned());
        }
    }
    None
}

/// The web build gate rows a changed path needs (CLAUDE.md's table, with
/// `angular/` now `web/`). Libraries build in order: base before xrm.
pub fn web_rows(path: &str) -> Vec<Planned> {
    if path.starts_with("web/projects/base/") {
        vec![
            Planned::npm(&["run", "build:base"]),
            Planned::npm(&["run", "lint:base"]),
            Planned::npm(&["run", "test:base"]),
        ]
    } else if path.starts_with("web/projects/xrm/") {
        vec![
            Planned::npm(&["run", "build:base"]),
            Planned::npm(&["run", "build:xrm"]),
            Planned::npm(&["run", "lint:xrm"]),
            Planned::npm(&["run", "test:xrm"]),
        ]
    } else if path.starts_with("web/projects/sdk/") {
        vec![
            Planned::npm(&["run", "build:sdk"]),
            Planned::npm(&["run", "lint:sdk"]),
            Planned::npm(&["run", "test:sdk"]),
        ]
    } else if path.starts_with("web/src/") {
        vec![
            Planned::npm(&["run", "build"]),
            Planned::npx(&["ng", "lint", "attome-website"]),
        ]
    } else {
        Vec::new()
    }
}

/// Paths the working tree changes: tracked edits against HEAD, staged edits
/// and untracked files.
fn changed_paths(root: &Path) -> Result<Vec<String>, String> {
    let mut paths = BTreeSet::new();
    for args in [
        &["diff", "--name-only", "HEAD"][..],
        &["diff", "--name-only", "--cached"][..],
        &["ls-files", "--others", "--exclude-standard"][..],
    ] {
        let out = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|error| format!("cannot run git: {error}"))?;
        if !out.status.success() {
            return Err(format!(
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let line = line.trim();
            if !line.is_empty() {
                paths.insert(line.replace('\\', "/"));
            }
        }
    }
    Ok(paths.into_iter().collect())
}

/// The commands a run executes, in order, without duplicates.
pub fn plan(args: &TestArgs, root: &Path, changed: Option<&[String]>) -> Vec<Planned> {
    let mut steps: Vec<Planned> = Vec::new();
    let mut push = |step: Planned| {
        if !steps.contains(&step) {
            steps.push(step);
        }
    };
    let crates: Option<BTreeSet<String>> = changed.map(|paths| {
        paths
            .iter()
            .filter_map(|path| owning_crate(root, path))
            .collect()
    });

    if args.tier.includes(Tier::Unit) {
        match &crates {
            Some(crates) => {
                for name in crates {
                    push(Planned::cargo(&["test", "-p", name.as_str(), "--lib"]));
                }
            }
            None => push(Planned::cargo(&["test", "--workspace", "--lib"])),
        }
    }
    if args.tier.includes(Tier::Db) {
        match &crates {
            Some(crates) => {
                for name in crates {
                    push(Planned::cargo(&["test", "-p", name.as_str(), "--tests"]));
                }
            }
            None => push(Planned::cargo(&[
                "test",
                "--workspace",
                "--tests",
                "--no-fail-fast",
                "--",
                "--test-threads=1",
            ])),
        }
    }
    if args.tier.includes(Tier::Contract) {
        for (package, target) in CONTRACT {
            push(Planned::cargo(&["test", "-p", *package, "--test", *target]));
        }
    }
    if args.tier.includes(Tier::Security) {
        for (package, target) in SECURITY {
            push(Planned::cargo(&["test", "-p", *package, "--test", *target]));
        }
    }
    if let Some(paths) = changed {
        for path in paths {
            for row in web_rows(path) {
                push(row);
            }
        }
    }
    if args.tier.includes(Tier::Browser) && root.join("e2e").join("package.json").is_file() {
        push(Planned {
            dir: "e2e",
            program: crate::npm_program("npx"),
            args: vec!["playwright".to_owned(), "test".to_owned()],
        });
    }
    steps
}

/// Runs `attome test` from its arguments.
pub fn run(args: &TestArgs, root: &Path, started_at: u64) -> ExitCode {
    let changed = if args.changed {
        match changed_paths(root) {
            Ok(paths) => Some(paths),
            Err(error) => {
                eprintln!("attome test: {error}");
                return ExitCode::from(2);
            }
        }
    } else {
        None
    };
    let steps = plan(args, root, changed.as_deref());
    let mut env: Vec<(String, String)> = env_for(args)
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect();
    if args.tier.needs_services() && !args.no_stack && !steps.is_empty() {
        match crate::test_stack::ensure(args.dry_run) {
            Ok(stack) => env.extend(stack),
            Err(error) => {
                eprintln!("attome test: {error} (or pass --no-stack and set DATABASE_URL)");
                return ExitCode::from(2);
            }
        }
    }
    if args.tier.includes(Tier::Browser) && !root.join("e2e").join("package.json").is_file() {
        crate::say("attome test: no browser suite yet (e2e/ is added by Z15-T9)");
    }
    if steps.is_empty() {
        crate::say("attome test: nothing to run for this change");
        return ExitCode::SUCCESS;
    }
    if args.dry_run {
        for (name, value) in &env {
            crate::say(&format!("{name}={value}"));
        }
        for step in &steps {
            crate::say(&step.display());
        }
        return ExitCode::SUCCESS;
    }
    let logs = root
        .join("target")
        .join("attome-test")
        .join(started_at.to_string());
    if let Err(error) = std::fs::create_dir_all(&logs) {
        eprintln!("attome test: {}: {error}", logs.display());
        return ExitCode::FAILURE;
    }
    let quarantine = match crate::test_flaky::load(root) {
        Ok(quarantine) => quarantine,
        Err(error) => {
            eprintln!("attome test: {error}");
            return ExitCode::from(2);
        }
    };
    let today = crate::test_flaky::date_from_unix(started_at);
    let stale = crate::test_flaky::expired(&quarantine, &today);
    if !stale.is_empty() {
        eprintln!(
            "attome test: tests/quarantine.json has entries past their date or without an owner:"
        );
        for entry in stale {
            eprintln!(
                "  {} {} (until {}, owner {:?})",
                entry.target, entry.name, entry.until, entry.owner
            );
        }
        return ExitCode::from(2);
    }
    if args.coverage && !crate::test_coverage::available() {
        eprintln!(
            "attome test: --coverage needs cargo-llvm-cov: {}",
            crate::test_coverage::INSTALL_HINT
        );
        return ExitCode::from(2);
    }

    let mut failed = Vec::new();
    let mut flaky: Vec<String> = Vec::new();
    let mut coverage_files = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let log = logs.join(format!("{:02}.log", index + 1));
        let mut step_args = step.args.clone();
        let package = package_of(&step_args);
        if step.program == "cargo" {
            match &package {
                Some(package) => {
                    crate::test_flaky::apply_skips(&mut step_args, package, &quarantine)
                }
                None => {
                    let packages: BTreeSet<&str> = quarantine
                        .tests
                        .iter()
                        .map(crate::test_flaky::Entry::package)
                        .collect();
                    for package in packages {
                        crate::test_flaky::apply_skips(&mut step_args, package, &quarantine);
                    }
                }
            }
            if args.coverage {
                let output = logs.join(format!("coverage-{:02}.json", index + 1));
                step_args = crate::test_coverage::wrap(&step_args, &output);
                coverage_files.push(output);
            }
        }
        crate::say(&format!(
            "==> {} {}  [{}]",
            step.program,
            step_args.join(" "),
            log.display()
        ));
        match exec(&step.program, &step_args, &root.join(step.dir), &env, &log) {
            Ok(true) => {}
            Ok(false) => {
                crate::say(&format!("    failed; see {}", log.display()));
                failed.push(step.display());
                if step.program == "cargo"
                    && let Some(package) = &package
                {
                    let text = std::fs::read_to_string(&log).unwrap_or_default();
                    for (attempt, test) in crate::test_flaky::parse_failed(&text).iter().enumerate()
                    {
                        let rerun_log =
                            logs.join(format!("{:02}-rerun-{}.log", index + 1, attempt + 1));
                        let rerun = crate::test_flaky::rerun_args(package, test);
                        if let Ok(true) = exec("cargo", &rerun, root, &env, &rerun_log) {
                            let id = format!("{package}::{}::{}", test.binary, test.name);
                            crate::say(&format!(
                                "    FLAKY {id} (passed on rerun; still a failure)"
                            ));
                            flaky.push(id);
                        }
                    }
                }
            }
            Err(error) => {
                crate::say(&format!("    could not start: {error}"));
                failed.push(step.display());
            }
        }
    }
    if !flaky.is_empty() {
        let path = root.join("target").join("attome-test").join("flaky.json");
        let body = serde_json::json!({ "date": today, "flaky": flaky });
        if let Err(error) = std::fs::write(
            &path,
            body.to_string()
                + "
",
        ) {
            eprintln!("attome test: {}: {error}", path.display());
        }
    }
    if args.coverage {
        let mut totals = std::collections::BTreeMap::new();
        for file in &coverage_files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            let Ok(report) = serde_json::from_str::<serde_json::Value>(&text) else {
                continue;
            };
            for (package, (covered, count)) in crate::test_coverage::per_crate(&report, root) {
                let entry: &mut (u64, u64) = totals.entry(package).or_default();
                entry.0 += covered;
                entry.1 += count;
            }
        }
        crate::say(&crate::test_coverage::render(&totals));
    }
    if failed.is_empty() {
        crate::say(&format!("attome test: {} command(s) passed", steps.len()));
        ExitCode::SUCCESS
    } else {
        eprintln!("attome test: {} failed:", failed.len());
        for line in failed {
            eprintln!("  {line}");
        }
        ExitCode::FAILURE
    }
}

/// The package a `cargo test` argument list names with `-p`.
fn package_of(args: &[String]) -> Option<String> {
    args.iter()
        .position(|arg| arg == "-p")
        .and_then(|at| args.get(at + 1))
        .cloned()
}

/// Runs one command with its output in `log`; `Ok(true)` when it passed.
fn exec(
    program: &str,
    args: &[String],
    dir: &Path,
    env: &[(String, String)],
    log: &Path,
) -> Result<bool, String> {
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let err = file
        .try_clone()
        .map_err(|error| format!("{}: {error}", log.display()))?;
    Command::new(program)
        .args(args)
        .envs(env.iter().map(|(name, value)| (name, value)))
        .current_dir(dir)
        .stdout(Stdio::from(file))
        .stderr(Stdio::from(err))
        .status()
        .map(|status| status.success())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(3)
            .unwrap()
            .to_path_buf()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn path_maps_to_owning_crate() {
        let root = workspace();
        assert_eq!(
            owning_crate(&root, "crates/apps/attome-release/src/test_cmd.rs").as_deref(),
            Some("attome-release")
        );
        assert_eq!(
            owning_crate(&root, "crates/engine/attome-api/tests/x.rs").as_deref(),
            Some("attome-api")
        );
        assert_eq!(owning_crate(&root, "docs/release.md"), None);
        assert_eq!(owning_crate(&root, "README.md"), None);
    }

    #[test]
    fn web_xrm_path_maps_to_xrm_row() {
        let rows: Vec<String> = web_rows("web/projects/xrm/core/x.ts")
            .iter()
            .map(|p| p.args.join(" "))
            .collect();
        assert_eq!(
            rows,
            strings(&[
                "run build:base",
                "run build:xrm",
                "run lint:xrm",
                "run test:xrm"
            ])
        );
        assert!(web_rows("crates/x.rs").is_empty());
    }

    #[test]
    fn release_flag_sets_require_db() {
        let args = parse_args(&strings(&["--release", "--changed"])).unwrap();
        assert_eq!(args.tier, Tier::All);
        assert!(!args.changed, "--release is never scoped");
        assert!(env_for(&args).contains(&("ATTOME_TEST_REQUIRE_DB", "1")));
        assert!(env_for(&TestArgs::default()).is_empty());
    }

    #[test]
    fn changed_unit_tier_runs_only_touched_crates() {
        let root = workspace();
        let args = parse_args(&strings(&["--changed"])).unwrap();
        let changed = strings(&[
            "crates/apps/attome-release/src/lib.rs",
            "crates/apps/attome-release/src/slo.rs",
            "docs/slo.md",
        ]);
        let steps: Vec<String> = plan(&args, &root, Some(&changed))
            .iter()
            .map(Planned::display)
            .collect();
        assert_eq!(steps, strings(&["cargo test -p attome-release --lib"]));
        assert!(parse_args(&strings(&["--tier", "nope"])).is_none());
    }
}
