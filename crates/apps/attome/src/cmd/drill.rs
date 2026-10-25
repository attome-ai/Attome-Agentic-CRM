//! `attome drill` (roadmap AB4-T3): the recovery drills' key, evidence and
//! readiness commands, on Windows and Linux alike.
//!
//! - `attome drill keygen --out <dir>` writes `drill-signing.key` (the
//!   Ed25519 seed, base64; owner-only on Linux) and `drill-signing.pub` (the
//!   public key, base64, for `ops.drill_public_keys`). On Windows the file
//!   takes the folder's permissions, so the command says to keep the folder
//!   private.
//! - `attome drill verify <file> [--public-key <file>]` checks an
//!   `attome-evidence/v1` report's signature against the given public key, or
//!   else against `ops.drill_public_keys` in the configuration.
//! - `attome drill readiness [--config <path>]` runs the preflight checks
//!   (`attome preflight`'s, not a copy) plus the drill's own: the signing key
//!   is readable, and the size of the last backup, which a restore drill needs
//!   twice over in free disk.
//!
//! The scenarios (`restore`, `failover`, `standby-promote`, `chaos`,
//! `upgrade-check`) are arms of [`Command`] that later tasks fill in; until
//! then they answer that the scenario is not in this build.
//!
//! Exit codes: 0 ok, 1 usage, 2 bad signature, 3 drill failed (or the
//! verified report says it failed), 4 not ready.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use attome_config::AppConfig;
use attome_ops::evidence;

pub const EXIT_OK: u8 = 0;
pub const EXIT_USAGE: u8 = 1;
pub const EXIT_BAD_SIGNATURE: u8 = 2;
pub const EXIT_DRILL_FAILED: u8 = 3;
pub const EXIT_NOT_READY: u8 = 4;

/// The key file names `keygen` writes.
pub const KEY_FILE: &str = "drill-signing.key";
pub const PUBLIC_FILE: &str = "drill-signing.pub";

/// The drill scenarios later tasks add.
pub const SCENARIOS: &[&str] = &[
    "restore",
    "failover",
    "standby-promote",
    "chaos",
    "upgrade-check",
];

const USAGE: &str = "usage:
  attome drill keygen --out <dir>
  attome drill verify <file> [--public-key <file>]
  attome drill readiness [--config <path>]
  attome drill <restore|failover|standby-promote|chaos|upgrade-check> ...";

/// One parsed `attome drill` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Keygen {
        out: PathBuf,
    },
    Verify {
        file: PathBuf,
        public_key: Option<PathBuf>,
    },
    Readiness {
        config: Option<String>,
    },
    /// A scenario: its name and its own arguments.
    Scenario {
        name: String,
        args: Vec<String>,
    },
}

/// Parses the arguments after `drill`. Pure.
pub fn parse(args: &[String]) -> Result<Command, String> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["keygen", "--out", dir] => Ok(Command::Keygen {
            out: PathBuf::from(dir),
        }),
        ["verify", file] => Ok(Command::Verify {
            file: PathBuf::from(file),
            public_key: None,
        }),
        ["verify", file, "--public-key", key] | ["verify", "--public-key", key, file] => {
            Ok(Command::Verify {
                file: PathBuf::from(file),
                public_key: Some(PathBuf::from(key)),
            })
        }
        ["readiness"] => Ok(Command::Readiness { config: None }),
        ["readiness", "--config", path] => Ok(Command::Readiness {
            config: Some((*path).to_owned()),
        }),
        [name, rest @ ..] if SCENARIOS.contains(name) => Ok(Command::Scenario {
            name: (*name).to_owned(),
            args: rest.iter().map(|a| (*a).to_owned()).collect(),
        }),
        [] => Err("a drill command is required".into()),
        [first, ..] => Err(format!("unknown or incomplete drill command `{first}`")),
    }
}

pub fn run(args: &[String]) -> ExitCode {
    if matches!(args, [flag] if flag == "--help" || flag == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let command = match parse(args) {
        Ok(command) => command,
        Err(message) => {
            eprintln!("attome drill: {message}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    ExitCode::from(match command {
        Command::Keygen { out } => keygen(&out),
        Command::Verify { file, public_key } => verify(&file, public_key.as_deref()),
        Command::Readiness { config } => readiness(config),
        Command::Scenario { name, .. } => {
            eprintln!("attome drill: the `{name}` scenario is not in this build");
            EXIT_USAGE
        }
    })
}

/// Writes a new key pair under `out`; never overwrites an existing key.
fn keygen(out: &Path) -> u8 {
    let key_path = out.join(KEY_FILE);
    let public_path = out.join(PUBLIC_FILE);
    if key_path.exists() || public_path.exists() {
        eprintln!(
            "attome drill: {} already holds a drill key; move it away first",
            out.display()
        );
        return EXIT_USAGE;
    }
    if let Err(error) = std::fs::create_dir_all(out) {
        eprintln!("attome drill: {}: {error}", out.display());
        return EXIT_USAGE;
    }
    let key = evidence::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    if let Err(error) = write_private(&key_path, evidence::encode_signing_key(&key).as_bytes()) {
        eprintln!("attome drill: {}: {error}", key_path.display());
        return EXIT_USAGE;
    }
    let public = format!("{}\n", evidence::public_key_base64(&key));
    if let Err(error) = std::fs::write(&public_path, public.as_bytes()) {
        eprintln!("attome drill: {}: {error}", public_path.display());
        return EXIT_USAGE;
    }
    println!("wrote {}", key_path.display());
    println!("wrote {}", public_path.display());
    println!("key id {}", evidence::key_id(&key.verifying_key()));
    if cfg!(windows) {
        println!(
            "warning: on Windows the key file takes {}'s permissions; keep that folder readable by the drill's account only",
            out.display()
        );
    }
    EXIT_OK
}

/// Creates `path` readable by its owner only (Linux) and writes `bytes`.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

/// The public keys `verify` trusts: the `--public-key` file, else the
/// configuration's `ops.drill_public_keys`.
fn trusted_keys(public_key: Option<&Path>) -> Result<Vec<evidence::VerifyingKey>, String> {
    let encoded: Vec<String> = match public_key {
        Some(path) => {
            vec![std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?]
        }
        None => {
            let config = AppConfig::from_file().map_err(|e| {
                format!("no --public-key given and the configuration did not load: {e}")
            })?;
            config.ops.drill_public_keys
        }
    };
    if encoded.is_empty() {
        return Err("no public key: pass --public-key or set ops.drill_public_keys".into());
    }
    encoded
        .iter()
        .map(|k| evidence::verifying_key(k).map_err(|e| e.to_string()))
        .collect()
}

/// Checks a signed report; see the module's exit codes.
fn verify(file: &Path, public_key: Option<&Path>) -> u8 {
    let trusted = match trusted_keys(public_key) {
        Ok(keys) => keys,
        Err(message) => {
            eprintln!("attome drill: {message}");
            return EXIT_USAGE;
        }
    };
    let signed = match evidence::read_signed(file) {
        Ok(signed) => signed,
        Err(error) => {
            println!("signature bad: {error}");
            return EXIT_BAD_SIGNATURE;
        }
    };
    verify_signed(&signed, &trusted)
}

/// The verdict on a report already read. Prints it.
fn verify_signed(signed: &evidence::SignedEvidence, trusted: &[evidence::VerifyingKey]) -> u8 {
    if let Err(error) = evidence::verify(signed, trusted) {
        println!("signature bad: {error}");
        return EXIT_BAD_SIGNATURE;
    }
    println!("signature ok (key {})", signed.key_id);
    println!("overall_ok {}", signed.evidence.overall_ok);
    if signed.evidence.overall_ok {
        EXIT_OK
    } else {
        EXIT_DRILL_FAILED
    }
}

/// The preflight checks plus the drill's own, printed PASS/FAIL.
#[tokio::main]
async fn readiness(config_path: Option<String>) -> u8 {
    let config_path = config_path.unwrap_or_else(AppConfig::config_file_path);
    let mut results = super::preflight::collect(config_path.clone()).await;
    let loaded = results.iter().all(|r| r.ok);
    if loaded && let Ok(config) = AppConfig::from_path(config_path) {
        results.push(signing_key_check(&config));
        results.push(backup_size_check(&config).await);
    }
    for r in &results {
        println!(
            "{} {:<36} {}",
            if r.ok { "PASS" } else { "FAIL" },
            r.name,
            r.detail
        );
    }
    if results.iter().all(|r| r.ok) {
        EXIT_OK
    } else {
        EXIT_NOT_READY
    }
}

fn check(name: &str, ok: bool, detail: String) -> super::preflight::CheckResult {
    super::preflight::CheckResult {
        name: name.into(),
        ok,
        detail,
    }
}

/// The drill signing key is configured and readable.
fn signing_key_check(config: &AppConfig) -> super::preflight::CheckResult {
    match config.ops.drill_signing_key_path.as_deref() {
        None => check(
            "drill.signing_key",
            false,
            "ops.drill_signing_key_path is not set; `attome drill keygen --out <dir>` writes one"
                .into(),
        ),
        Some(path) => match evidence::read_signing_key(Path::new(path)) {
            Ok(key) => check(
                "drill.signing_key",
                true,
                format!(
                    "readable, key id {}",
                    evidence::key_id(&key.verifying_key())
                ),
            ),
            Err(error) => check("drill.signing_key", false, error.to_string()),
        },
    }
}

/// The last backup's size: a restore drill needs twice that free. This
/// build does not measure free disk space (that would take a native call),
/// so the size is reported for the operator to compare; it never fails.
async fn backup_size_check(config: &AppConfig) -> super::preflight::CheckResult {
    let dir = crate::backup::backup_dir(config);
    let mut names = Vec::new();
    if let Ok(mut entries) = tokio::fs::read_dir(&dir).await {
        while let Ok(Some(entry)) = entries.next_entry().await {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    let size = match crate::backup::latest_archive(&names) {
        Some(name) => tokio::fs::metadata(dir.join(name))
            .await
            .ok()
            .map(|m| m.len()),
        None => None,
    };
    match size {
        Some(bytes) => check(
            "drill.disk",
            true,
            format!(
                "last backup {bytes} bytes; keep at least {} bytes free for a restore drill (free space is not measured)",
                bytes.saturating_mul(2)
            ),
        ),
        None => check(
            "drill.disk",
            true,
            format!("no backup in {} yet; size unknown", dir.display()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn parses_verify_args() {
        assert_eq!(
            parse(&args(&["verify", "report.json"])),
            Ok(Command::Verify {
                file: "report.json".into(),
                public_key: None
            })
        );
        let with_key = Command::Verify {
            file: "report.json".into(),
            public_key: Some("drill.pub".into()),
        };
        assert_eq!(
            parse(&args(&[
                "verify",
                "report.json",
                "--public-key",
                "drill.pub"
            ])),
            Ok(with_key.clone())
        );
        assert_eq!(
            parse(&args(&[
                "verify",
                "--public-key",
                "drill.pub",
                "report.json"
            ])),
            Ok(with_key)
        );
        assert_eq!(
            parse(&args(&["readiness", "--config", "c.json"])),
            Ok(Command::Readiness {
                config: Some("c.json".into())
            })
        );
    }

    #[test]
    fn unknown_subcommand_is_usage_error() {
        assert!(parse(&args(&["explode"])).is_err());
        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["keygen"])).is_err());
        assert!(parse(&args(&["verify"])).is_err());
        assert_eq!(run(&args(&["explode"])), ExitCode::from(EXIT_USAGE));
        assert!(matches!(
            parse(&args(&["restore", "--to", "x"])),
            Ok(Command::Scenario { name, .. }) if name == "restore"
        ));
    }

    #[test]
    fn keygen_then_verify_round_trip() {
        let dir = std::env::temp_dir().join(format!("attome-drill-{}", uuid::Uuid::new_v4()));
        assert_eq!(keygen(&dir), EXIT_OK);
        // A second keygen into the same folder refuses to overwrite.
        assert_eq!(keygen(&dir), EXIT_USAGE);

        let key = evidence::read_signing_key(&dir.join(KEY_FILE)).expect("key");
        let at = chrono::Utc::now();
        let mut report = evidence::Evidence {
            schema: evidence::SCHEMA.into(),
            kind: evidence::EvidenceKind::Restore,
            drill_id: uuid::Uuid::now_v7(),
            started_at: at,
            finished_at: at,
            platform_version: env!("CARGO_PKG_VERSION").into(),
            image_digest: None,
            deployment_id: None,
            checks: vec![evidence::Check {
                name: "restore".into(),
                result: evidence::CheckResult::Pass,
                detail: None,
            }],
            rpo_seconds: Some(0.0),
            rto_seconds: Some(1.0),
            data_size_bytes: None,
            restore_ok: true,
            provenance_ok: true,
            overall_ok: false,
            extra: serde_json::Map::new(),
        };
        report.compute_overall();
        let file = dir.join("report.json");
        evidence::write_signed(&file, &report, &key).expect("write");

        let public = dir.join(PUBLIC_FILE);
        assert_eq!(verify(&file, Some(&public)), EXIT_OK);

        // A changed report no longer matches its signature.
        let mut signed = evidence::read_signed(&file).expect("read");
        let trusted = trusted_keys(Some(&public)).expect("trusted");
        signed.evidence.rto_seconds = Some(0.5);
        assert_eq!(verify_signed(&signed, &trusted), EXIT_BAD_SIGNATURE);

        // A correctly signed report of a failed drill exits 3.
        report.restore_ok = false;
        report.compute_overall();
        evidence::write_signed(&file, &report, &key).expect("rewrite");
        assert_eq!(verify(&file, Some(&public)), EXIT_DRILL_FAILED);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
