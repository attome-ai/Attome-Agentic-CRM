//! The release commands end to end (roadmap AC4-T13): the real
//! `attome-release` binary, in a throwaway git repository shaped like the
//! workspace, refusing and allowing a tag on the strength of its gate
//! reports, and refusing a bad override before running anything.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_attome-release");

/// A fresh git repository with a `[workspace]` manifest and one commit;
/// `None` when git is not installed (the test then has nothing to drive).
fn fixture(name: &str) -> Option<(PathBuf, String)> {
    Command::new("git").arg("--version").output().ok()?;
    let dir =
        std::env::temp_dir().join(format!("attome-release-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[workspace]\nmembers = []\n\n[workspace.package]\nversion = \"0.0.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("CHANGELOG.md"),
        "# Changelog\n\n## [Unreleased]\n\n### Added\n- The first thing.\n",
    )
    .unwrap();
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid",
            ])
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    git(&["init", "-q"]);
    // `git tag -a` (what `attome-release tag` runs) needs an identity.
    git(&["config", "user.name", "test"]);
    git(&["config", "user.email", "test@example.invalid"]);
    git(&["add", "Cargo.toml", "CHANGELOG.md"]);
    git(&["commit", "-q", "-m", "fixture"]);
    let head = git(&["rev-parse", "HEAD"]);
    Some((dir, head))
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn report(dir: &Path, os: &str, commit: &str, status: &str) -> PathBuf {
    let path = dir.join(format!("incoming-{os}.json"));
    let body = serde_json::json!({
        "format": "attome-release-gate/v1",
        "os": os,
        "commit": commit,
        "steps": [{ "id": "tests", "status": status }],
    });
    std::fs::write(&path, body.to_string()).unwrap();
    path
}

#[test]
fn tag_is_refused_until_both_reports_are_green_then_allowed() {
    let Some((dir, head)) = fixture("tag") else {
        eprintln!("SKIP: git is not installed");
        return;
    };

    // Nothing imported: refused with exit 3.
    let out = run(&dir, &["tag", "0.0.1"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A report from another commit is not imported.
    let stale = report(&dir, "linux", "0000000", "passed");
    let out = run(&dir, &["import-report", stale.to_str().unwrap()]);
    assert!(!out.status.success());

    // Linux green, Windows red: still refused, naming windows.
    let linux = report(&dir, "linux", &head, "passed");
    let windows_red = report(&dir, "windows", &head, "failed");
    assert!(
        run(&dir, &["import-report", linux.to_str().unwrap()])
            .status
            .success()
    );
    assert!(
        run(&dir, &["import-report", windows_red.to_str().unwrap()])
            .status
            .success()
    );
    let out = run(&dir, &["tag", "0.0.1"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("windows"));

    // Both green: tagged.
    let windows = report(&dir, "windows", &head, "overridden");
    assert!(
        run(&dir, &["import-report", windows.to_str().unwrap()])
            .status
            .success()
    );
    let out = run(&dir, &["tag", "0.0.1"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tags = Command::new("git")
        .args(["tag"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&tags.stdout).contains("v0.0.1"));
    // The release commit bumped the version, moved the changelog and opened
    // the stability ledger.
    let cargo = std::fs::read_to_string(dir.join("Cargo.toml")).unwrap();
    assert!(cargo.contains("version = \"0.0.1\""));
    let changelog = std::fs::read_to_string(dir.join("CHANGELOG.md")).unwrap();
    assert!(changelog.contains("## [0.0.1] - "));
    assert!(dir.join("docs/releases/stability.json").is_file());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_bad_override_is_refused_before_any_step_runs() {
    let Some((dir, _)) = fixture("override") else {
        eprintln!("SKIP: git is not installed");
        return;
    };
    let out = run(
        &dir,
        &["--check", "--override", "tests=short", "--by", "Someone"],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("at least"));
    let out = run(
        &dir,
        &[
            "--check",
            "--override",
            "format=a reason that is long enough",
        ],
    );
    assert_eq!(out.status.code(), Some(2), "an override needs --by");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_arguments_print_usage() {
    let out = Command::new(BIN).arg("--nonsense").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}
