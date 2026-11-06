//! AC7-T8: `attome verify` — offline verification of a release file before
//! it is installed or upgraded to.
//!
//! ```text
//! attome verify file <path> [--key <cosign.pub>] [--allow-unsigned --reason <text>]
//! attome verify dir <path>  [--key <cosign.pub>] [--allow-unsigned --reason <text>]
//! ```
//!
//! `file` checks `<path>.sig` with `cosign verify-blob` against the release
//! public key, offline (`--insecure-ignore-tlog`, D-673 item 5); an `.msi` on
//! Windows is also checked with `signtool verify /pa`. `dir` checks every
//! file in a folder that has a `.sig` beside it (the air-gapped case: the
//! release files copied over together), and refuses a folder with none.
//!
//! Exit 0 when verified, 5 when unsigned, altered or unverifiable. With
//! `--allow-unsigned --reason <text>` (at least 20 characters) a 5 becomes
//! 0, and a line with the time, the user and the reason is appended to
//! `attome-overrides.log` beside the installed binary. `attome upgrade
//! apply` runs the same check on `--new-binary` and takes the same flags.
//!
//! Adjusted (V2-D1923): the public key is not embedded yet. The task's
//! `include_str!("deploy/cosign.pub")` waits for the key pair (AC4-T9's
//! custody), and a placeholder key must never be built in; until then the
//! key is `--key`, else `cosign.pub` beside the installed binary, else the
//! repository's `deploy/cosign.pub`. v2 ships no container images, so there
//! is no `verify image`.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line command reports to its terminal"
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cmd::output::{take_flag, take_value};

const USAGE: &str = "usage: attome verify file|dir <path> [--key <cosign.pub>] \
                     [--allow-unsigned --reason <text>]";

/// The exit code of an unsigned, altered or unverifiable file.
pub const EXIT_UNVERIFIED: u8 = 5;
/// The shortest reason an override accepts.
pub const MIN_REASON_CHARS: usize = 20;
/// The override log, beside the installed binary.
pub const OVERRIDE_LOG: &str = "attome-overrides.log";

/// Runs an external verifier; injected so tests need no cosign.
pub trait Runner {
    /// Whether `program args` exited successfully; `Err` when it could not
    /// run at all.
    fn run(&self, program: &str, args: &[String]) -> Result<bool, String>;
}

/// The real runner.
pub struct System;

impl Runner for System {
    fn run(&self, program: &str, args: &[String]) -> Result<bool, String> {
        std::process::Command::new(program)
            .args(args)
            .status()
            .map(|s| s.success())
            .map_err(|e| format!("cannot run {program} ({e})"))
    }
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Verified,
    /// Why it is not verified.
    Unverified(String),
}

/// The signature beside `file`.
pub fn signature_of(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// Checks one file against `key`.
pub fn check_file(runner: &dyn Runner, file: &Path, key: Option<&Path>) -> Outcome {
    if !file.is_file() {
        return Outcome::Unverified(format!("{} does not exist", file.display()));
    }
    let Some(key) = key else {
        return Outcome::Unverified(
            "no release public key: pass --key, or install cosign.pub beside attome".into(),
        );
    };
    let signature = signature_of(file);
    if !signature.is_file() {
        return Outcome::Unverified(format!(
            "{} is unsigned (no {})",
            file.display(),
            signature.display()
        ));
    }
    let args: Vec<String> = vec![
        "verify-blob".into(),
        "--insecure-ignore-tlog=true".into(),
        "--key".into(),
        key.display().to_string(),
        "--signature".into(),
        signature.display().to_string(),
        file.display().to_string(),
    ];
    match runner.run("cosign", &args) {
        Ok(true) => {}
        Ok(false) => {
            return Outcome::Unverified(format!(
                "{} does not match its signature: altered, or signed by another key",
                file.display()
            ));
        }
        Err(error) => return Outcome::Unverified(error),
    }
    let is_msi = file
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("msi"));
    if is_msi && cfg!(windows) {
        let args = vec!["verify".into(), "/pa".into(), file.display().to_string()];
        match runner.run("signtool", &args) {
            Ok(true) => {}
            Ok(false) => {
                return Outcome::Unverified(format!(
                    "{} has no valid Authenticode signature",
                    file.display()
                ));
            }
            Err(error) => return Outcome::Unverified(error),
        }
    }
    Outcome::Verified
}

/// Checks every file in `dir` that has a signature beside it.
pub fn check_dir(runner: &dyn Runner, dir: &Path, key: Option<&Path>) -> Outcome {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Outcome::Unverified(format!("cannot read {}", dir.display()));
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && signature_of(p).is_file())
        .collect();
    files.sort();
    if files.is_empty() {
        return Outcome::Unverified(format!("{} holds no signed file", dir.display()));
    }
    for file in &files {
        if let Outcome::Unverified(why) = check_file(runner, file, key) {
            return Outcome::Unverified(why);
        }
    }
    Outcome::Verified
}

/// The public key to use: `--key`, else `cosign.pub` beside the installed
/// binary, else the repository's `deploy/cosign.pub`.
pub fn key_path(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(key) = explicit {
        return Some(PathBuf::from(key));
    }
    let beside = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("cosign.pub")))
        .filter(|p| p.is_file());
    beside.or_else(|| Some(PathBuf::from("deploy/cosign.pub")).filter(|p| p.is_file()))
}

/// The line an override appends to the log. Pure.
pub fn override_line(when: &str, user: &str, file: &str, reason: &str) -> String {
    format!(
        "{when}\t{user}\t{file}\t{}\n",
        reason.replace(['\n', '\t'], " ")
    )
}

/// Applies `outcome` with an optional override (`reason`); the exit code.
/// An override is logged in `log_dir`.
pub fn decide(
    outcome: &Outcome,
    file: &str,
    reason: Option<&str>,
    log_dir: &Path,
) -> Result<u8, String> {
    match outcome {
        Outcome::Verified => Ok(0),
        Outcome::Unverified(why) => {
            let Some(reason) = reason else {
                eprintln!("not verified: {why}");
                return Ok(EXIT_UNVERIFIED);
            };
            if reason.trim().chars().count() < MIN_REASON_CHARS {
                return Err(format!(
                    "--reason needs at least {MIN_REASON_CHARS} characters saying why this file is trusted"
                ));
            }
            let user = std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_else(|_| "unknown".into());
            let when = chrono::Utc::now().to_rfc3339();
            let line = override_line(&when, &user, file, reason.trim());
            use std::io::Write as _;
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_dir.join(OVERRIDE_LOG))
                .and_then(|mut f| f.write_all(line.as_bytes()))
                .map_err(|e| format!("cannot write {OVERRIDE_LOG}: {e}"))?;
            eprintln!("not verified ({why}); allowed by override, logged in {OVERRIDE_LOG}");
            Ok(0)
        }
    }
}

/// The override flags: `--allow-unsigned --reason <text>`, taken from `args`.
pub fn take_override(args: &mut Vec<String>) -> Result<Option<String>, String> {
    let allow = take_flag(args, "--allow-unsigned");
    let reason = take_value(args, "--reason")?;
    match (allow, reason) {
        (false, None) => Ok(None),
        (true, Some(reason)) => Ok(Some(reason)),
        _ => Err("--allow-unsigned and --reason <text> come together".into()),
    }
}

/// The directory beside the installed binary, where overrides are logged.
pub fn install_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// `attome verify …` (`args` after `verify`).
pub fn run(args: &[String]) -> ExitCode {
    match run_inner(args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("attome verify: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_inner(args: &[String]) -> Result<u8, String> {
    let mut args = args.to_vec();
    let key = take_value(&mut args, "--key")?;
    let reason = take_override(&mut args)?;
    let [what, path] = args.as_slice() else {
        return Err(USAGE.to_owned());
    };
    let key = key_path(key.as_deref());
    let outcome = match what.as_str() {
        "file" => check_file(&System, Path::new(path), key.as_deref()),
        "dir" => check_dir(&System, Path::new(path), key.as_deref()),
        "image" => return Err("v2 ships no container images; verify the downloaded file".into()),
        _ => return Err(USAGE.to_owned()),
    };
    if outcome == Outcome::Verified {
        println!("verified: {path}");
    }
    decide(&outcome, path, reason.as_deref(), &install_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fake(bool);
    impl Runner for Fake {
        fn run(&self, _program: &str, _args: &[String]) -> Result<bool, String> {
            Ok(self.0)
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("attome-verify-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unsigned_without_override_exits_5() {
        let dir = temp("unsigned");
        let file = dir.join("attome-linux-x86_64.tar.gz");
        std::fs::write(&file, "x").unwrap();
        let key = dir.join("cosign.pub");
        std::fs::write(&key, "k").unwrap();
        let outcome = check_file(&Fake(true), &file, Some(&key));
        assert!(matches!(outcome, Outcome::Unverified(ref why) if why.contains("unsigned")));
        assert_eq!(decide(&outcome, "f", None, &dir).unwrap(), EXIT_UNVERIFIED);
        // A signature that does not match is refused too.
        std::fs::write(signature_of(&file), "sig").unwrap();
        assert!(matches!(
            check_file(&Fake(false), &file, Some(&key)),
            Outcome::Unverified(_)
        ));
        assert_eq!(
            check_file(&Fake(true), &file, Some(&key)),
            Outcome::Verified
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_writes_log_line() {
        let dir = temp("override");
        let outcome = Outcome::Unverified("unsigned".into());
        assert!(decide(&outcome, "attome.exe", Some("too short"), &dir).is_err());
        let code = decide(
            &outcome,
            "attome.exe",
            Some("built locally from tag v2.1.0 by the operator"),
            &dir,
        )
        .unwrap();
        assert_eq!(code, 0);
        let log = std::fs::read_to_string(dir.join(OVERRIDE_LOG)).unwrap();
        assert!(log.contains("attome.exe\tbuilt locally from tag v2.1.0 by the operator"));
        assert_eq!(log.lines().count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_flags_come_together() {
        let mut both: Vec<String> = ["--allow-unsigned", "--reason", "why"]
            .map(String::from)
            .to_vec();
        assert_eq!(take_override(&mut both).unwrap().as_deref(), Some("why"));
        let mut one: Vec<String> = vec!["--allow-unsigned".into()];
        assert!(take_override(&mut one).is_err());
        let mut none: Vec<String> = Vec::new();
        assert_eq!(take_override(&mut none).unwrap(), None);
    }
}
