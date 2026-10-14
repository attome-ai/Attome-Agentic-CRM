//! `attome test` (roadmap Z15-T1): the scoped test runner.
//!
//! ```text
//! attome test [--tier unit|db|contract|security|browser|all] [--changed] [--release] [--dry-run]
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
//!
//! Each command's output goes to `target/attome-test/<unix seconds>/NN.log`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
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
}

/// Parsed `attome test` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestArgs {
    pub tier: Tier,
    pub changed: bool,
    pub release: bool,
    pub dry_run: bool,
}

impl Default for TestArgs {
    fn default() -> Self {
        Self {
            tier: Tier::Unit,
            changed: false,
            release: false,
            dry_run: false,
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
    let env = env_for(args);
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
    let mut failed = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let log: PathBuf = logs.join(format!("{:02}.log", index + 1));
        crate::say(&format!("==> {}  [{}]", step.display(), log.display()));
        let outcome = std::fs::File::create(&log)
            .and_then(|file| Ok((file.try_clone()?, file)))
            .map_err(|error| error.to_string())
            .and_then(|(out, err)| {
                Command::new(&step.program)
                    .args(&step.args)
                    .envs(env.iter().copied())
                    .current_dir(root.join(step.dir))
                    .stdout(Stdio::from(out))
                    .stderr(Stdio::from(err))
                    .status()
                    .map_err(|error| error.to_string())
            });
        match outcome {
            Ok(status) if status.success() => {}
            Ok(status) => {
                crate::say(&format!("    failed ({status}); see {}", log.display()));
                failed.push(step.display());
            }
            Err(error) => {
                crate::say(&format!("    could not start: {error}"));
                failed.push(step.display());
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
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
