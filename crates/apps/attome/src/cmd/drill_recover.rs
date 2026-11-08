//! AB3-T3 (V2-D1930): `attome drill recover`, part 1 of a disaster recovery:
//! the database rebuilt from the daily `pg_dump` archive and the
//! configuration's secrets proven to resolve, on a target host, with the
//! server binary pinned by digest. Part 2 (AB3-T4) continues from the
//! `recover-state.json` this writes.
//!
//! ```text
//! attome drill recover --server-binary <path> --expected-digest <sha256> --out <dir>
//!                      (--approval-id <uuid> --base-url <url> --api-key-file <path>
//!                       | --offline-two-person <name1>,<name2>)
//!                      [--archive latest|<name>] [--side-copy <database>] [--config <path>]
//! ```
//!
//! Adjusted to v2 (V2-D1930): v2 backs up with `pg_dump` (no pgBackRest, so
//! no point-in-time target: the archive is the recovery point) and keeps its
//! secrets in the configured secret sources and key service (`docs/secrets.md`)
//! rather than an age-encrypted escrow file, so "secrets restored" means the
//! configuration loads with every placeholder resolved, which is what the
//! server needs to boot. No secret is printed, logged or written.
//!
//! - It refuses to start without a second person: an approved AB3-T7
//!   disaster approval (`GET /api/v1/ops/disasters/approvals/{id}` on the
//!   deployment), or, when the deployment cannot answer, two distinct names
//!   given with `--offline-two-person`, both kept in the state file.
//! - `--side-copy <database>` restores into a new database of that name and
//!   never the configured one; without it the configured database is the
//!   target and must not exist yet (a new host), so nothing is overwritten.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line command reports to standard output"
)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::cmd::drill_restore::{provenance_ok, sha256_file};
use crate::cmd::output::take_value;

const USAGE: &str = "usage: attome drill recover --server-binary <path> --expected-digest <sha256> --out <dir> (--approval-id <uuid> --base-url <url> --api-key-file <path> | --offline-two-person <name1>,<name2>) [--archive latest|<name>] [--side-copy <database>] [--config <path>]";

/// The state file part 2 continues from.
pub const STATE_FILE: &str = "recover-state.json";

const EXIT_OK: u8 = 0;
const EXIT_USAGE: u8 = 1;
const EXIT_REFUSED: u8 = 5;
const EXIT_FAILED: u8 = 3;

/// Who allowed the recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Approval {
    /// An AB3-T7 approval request, checked on the deployment.
    Online {
        approval_id: Uuid,
        base_url: String,
        #[serde(skip)]
        api_key_file: PathBuf,
    },
    /// The deployment could not answer: two people named themselves.
    Offline { first: String, second: String },
}

/// What `drill recover` was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverArgs {
    pub server_binary: PathBuf,
    pub expected_digest: String,
    pub out: PathBuf,
    pub approval: Approval,
    pub archive: String,
    pub side_copy: Option<String>,
    pub config: Option<String>,
}

/// Two distinct, non-empty names from `<name1>,<name2>`. Pure.
pub fn offline_names(value: &str) -> Result<(String, String), String> {
    let names: Vec<&str> = value.split(',').map(str::trim).collect();
    match names.as_slice() {
        [a, b] if !a.is_empty() && !b.is_empty() => {
            if a.eq_ignore_ascii_case(b) {
                Err("--offline-two-person needs two different people".into())
            } else {
                Ok(((*a).to_owned(), (*b).to_owned()))
            }
        }
        _ => Err("--offline-two-person takes exactly two names: <name1>,<name2>".into()),
    }
}

/// The database the recovery restores into: the side copy when given (never
/// the configured database), else the configured one. Pure.
pub fn target_database(side_copy: Option<&str>, configured: &str) -> Result<String, String> {
    match side_copy {
        Some(name) if name == configured => Err(format!(
            "--side-copy {name} is the configured database; a side copy needs a new name"
        )),
        Some(name) if !attome_db::ident::is_identifier(name) => Err(format!(
            "--side-copy {name}: letters, digits and underscores only"
        )),
        Some(name) => Ok(name.to_owned()),
        None => Ok(configured.to_owned()),
    }
}

/// Whether an approval answer says approved. Pure.
pub fn approval_granted(body: &Value) -> bool {
    body["status"].as_str() == Some("approved")
}

/// Parses the arguments after `drill recover`. Pure.
pub fn parse_args(args: &[String]) -> Result<RecoverArgs, String> {
    let mut args = args.to_vec();
    let need = |v: Option<String>, flag: &str| v.ok_or_else(|| format!("{flag} is required"));
    let server_binary = need(take_value(&mut args, "--server-binary")?, "--server-binary")?;
    let expected_digest = need(
        take_value(&mut args, "--expected-digest")?,
        "--expected-digest",
    )?;
    let out = need(take_value(&mut args, "--out")?, "--out")?;
    let approval_id = take_value(&mut args, "--approval-id")?;
    let base_url = take_value(&mut args, "--base-url")?;
    let api_key_file = take_value(&mut args, "--api-key-file")?;
    let offline = take_value(&mut args, "--offline-two-person")?;
    let archive = take_value(&mut args, "--archive")?.unwrap_or_else(|| "latest".to_owned());
    let side_copy = take_value(&mut args, "--side-copy")?;
    let config = take_value(&mut args, "--config")?;
    if !args.is_empty() {
        return Err(format!("unexpected arguments: {}", args.join(" ")));
    }
    if expected_digest.len() != 64 || !expected_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("--expected-digest must be 64 hexadecimal characters".into());
    }
    let approval = match (approval_id, offline) {
        (Some(_), Some(_)) => {
            return Err("give --approval-id or --offline-two-person, not both".into());
        }
        (Some(id), None) => Approval::Online {
            approval_id: Uuid::parse_str(&id).map_err(|_| format!("--approval-id: `{id}`"))?,
            base_url: need(base_url, "--base-url (with --approval-id)")?
                .trim_end_matches('/')
                .to_owned(),
            api_key_file: PathBuf::from(need(api_key_file, "--api-key-file (with --approval-id)")?),
        },
        (None, Some(names)) => {
            let (first, second) = offline_names(&names)?;
            Approval::Offline { first, second }
        }
        (None, None) => {
            return Err(
                "a recovery needs a second person: --approval-id, or --offline-two-person".into(),
            );
        }
    };
    Ok(RecoverArgs {
        server_binary: PathBuf::from(server_binary),
        expected_digest: expected_digest.to_ascii_lowercase(),
        out: PathBuf::from(out),
        approval,
        archive,
        side_copy,
        config,
    })
}

/// What part 1 leaves for part 2 (AB3-T4). Holds no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverState {
    pub recovery_id: Uuid,
    pub started_at: chrono::DateTime<Utc>,
    pub finished_at: chrono::DateTime<Utc>,
    pub approval: Approval,
    pub archive: String,
    pub target_database: String,
    pub side_copy: bool,
    pub database_rto_seconds: f64,
    pub secrets_restored: bool,
    pub server_binary: String,
    pub server_digest: String,
    pub provenance_ok: bool,
    pub config_path: String,
}

async fn check_online_approval(
    approval_id: Uuid,
    base: &str,
    key_file: &PathBuf,
) -> Result<(), String> {
    let key = std::fs::read_to_string(key_file)
        .map_err(|e| format!("{}: {e}", key_file.display()))?
        .trim()
        .to_owned();
    if key.is_empty() {
        return Err(format!("{} is empty", key_file.display()));
    }
    let client = attome_outbound::http::client(
        attome_outbound::http::Purpose::public("drill_recover_approval").with_private_urls([base]),
        |builder| builder.timeout(Duration::from_secs(15)),
    )
    .map_err(|e| e.to_string())?;
    let response = client
        .get(format!(
            "{base}/api/v1/ops/disasters/approvals/{approval_id}"
        ))
        .header("authorization", format!("ApiKey {key}"))
        .send()
        .await
        .map_err(|e| {
            format!(
                "the deployment did not answer ({e}); with no deployment, use --offline-two-person"
            )
        })?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(format!("the approval lookup answered {status}"));
    }
    let body: Value = response.json().await.map_err(|e| e.to_string())?;
    if approval_granted(&body) {
        Ok(())
    } else {
        Err(format!(
            "approval {approval_id} is {}, not approved",
            body["status"].as_str().unwrap_or("unknown")
        ))
    }
}

/// Whether `name` exists on the server `admin` is connected to.
async fn database_exists(admin: &mut sqlx::PgConnection, name: &str) -> Result<bool, String> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
        .bind(name)
        .fetch_one(admin)
        .await
        .map_err(|e| format!("look up {name}: {e}"))
}

#[tokio::main]
pub async fn run_cli(args: &[String]) -> u8 {
    use sqlx::Connection;
    // AB3-T4: part 2 continues from the state part 1 wrote.
    if args.iter().any(|a| a == "--continue") {
        return crate::cmd::drill_recover_finish::run(args).await;
    }
    let args = match parse_args(args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("attome drill recover: {message}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    // Step 2: a second person, before anything else.
    if let Approval::Online {
        approval_id,
        base_url,
        api_key_file,
    } = &args.approval
        && let Err(e) = check_online_approval(*approval_id, base_url, api_key_file).await
    {
        eprintln!("attome drill recover: refused: {e}");
        return EXIT_REFUSED;
    }
    if let Err(e) = std::fs::create_dir_all(&args.out) {
        eprintln!("attome drill recover: {}: {e}", args.out.display());
        return EXIT_USAGE;
    }
    let started = Utc::now();

    // Step 4 (v2): the configuration loads with every secret resolved.
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(attome_config::AppConfig::config_file_path);
    let config = match crate::secret_sources::load_config_from(config_path.clone()).await {
        Ok(config) => config,
        Err(e) => {
            // The error names the placeholder or source, never a value.
            eprintln!("attome drill recover: secrets_restored failed: {e}");
            return EXIT_FAILED;
        }
    };
    println!("secrets_restored pass: the configuration loads with every secret resolved");

    // Step 5: provenance.
    let digest = match sha256_file(&args.server_binary).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("attome drill recover: {e}");
            return EXIT_FAILED;
        }
    };
    let provenance = provenance_ok(&digest, &args.expected_digest);
    if !provenance {
        eprintln!(
            "attome drill recover: refused: {} is not the binary of digest {}",
            args.server_binary.display(),
            args.expected_digest
        );
        return EXIT_REFUSED;
    }

    // Step 3: the database, into a new database only.
    let target = match target_database(args.side_copy.as_deref(), &config.database.dbname) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("attome drill recover: {e}");
            return EXIT_USAGE;
        }
    };
    let archive = match crate::backup::archive_for(&config, &args.archive).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("attome drill recover: {e}");
            return EXIT_USAGE;
        }
    };
    // The maintenance database: the target may not exist yet.
    let mut admin = match sqlx::PgConnection::connect_with(&crate::backup::connect_options(
        &config, "postgres",
    ))
    .await
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("attome drill recover: connect the database server: {e}");
            return EXIT_FAILED;
        }
    };
    match database_exists(&mut admin, &target).await {
        Ok(false) => {}
        Ok(true) => {
            eprintln!(
                "attome drill recover: refused: database {target} already exists; recover onto a new host or give --side-copy <new name>"
            );
            let _ = admin.close().await;
            return EXIT_REFUSED;
        }
        Err(e) => {
            eprintln!("attome drill recover: {e}");
            let _ = admin.close().await;
            return EXIT_FAILED;
        }
    }
    let clock = Instant::now();
    let restored = crate::backup::restore_into(&config, &mut admin, &archive, &target).await;
    let rto = clock.elapsed().as_secs_f64();
    let _ = admin.close().await;
    if let Err(e) = restored {
        eprintln!("attome drill recover: database restore failed: {e}");
        return EXIT_FAILED;
    }
    println!("database_restore pass: {target} restored in {rto:.1} s");

    // Step 6: the state part 2 continues from.
    let state = RecoverState {
        recovery_id: Uuid::now_v7(),
        started_at: started,
        finished_at: Utc::now(),
        approval: args.approval.clone(),
        archive: archive
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        target_database: target,
        side_copy: args.side_copy.is_some(),
        database_rto_seconds: rto,
        secrets_restored: true,
        server_binary: args.server_binary.display().to_string(),
        server_digest: digest,
        provenance_ok: provenance,
        config_path,
    };
    let path = args.out.join(STATE_FILE);
    match serde_json::to_vec_pretty(&state)
        .map_err(|e| e.to_string())
        .and_then(|bytes| std::fs::write(&path, bytes).map_err(|e| e.to_string()))
    {
        Ok(()) => {
            println!("wrote {}", path.display());
            EXIT_OK
        }
        Err(e) => {
            eprintln!("attome drill recover: {}: {e}", path.display());
            EXIT_FAILED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    fn base() -> String {
        format!(
            "--server-binary bin --expected-digest {} --out o",
            "a".repeat(64)
        )
    }

    #[test]
    fn refuses_without_approval() {
        let err = parse_args(&words(&base())).unwrap_err();
        assert!(err.contains("second person"), "{err}");
        let id = Uuid::now_v7();
        assert!(parse_args(&words(&format!("{} --approval-id {id}", base()))).is_err());
        let ok = parse_args(&words(&format!(
            "{} --approval-id {id} --base-url https://crm.example/ --api-key-file k",
            base()
        )))
        .unwrap();
        assert!(
            matches!(ok.approval, Approval::Online { ref base_url, .. } if base_url == "https://crm.example")
        );
        assert!(approval_granted(
            &serde_json::json!({ "status": "approved" })
        ));
        assert!(!approval_granted(
            &serde_json::json!({ "status": "pending" })
        ));
        assert!(
            parse_args(&words(&format!(
                "{} --approval-id {id} --base-url u --api-key-file k --offline-two-person a,b",
                base()
            )))
            .is_err()
        );
    }

    #[test]
    fn offline_mode_needs_two_distinct_names() {
        assert_eq!(
            offline_names("Sara, Omar").unwrap(),
            ("Sara".to_owned(), "Omar".to_owned())
        );
        assert!(offline_names("Sara,sara").is_err());
        assert!(offline_names("Sara").is_err());
        assert!(offline_names("Sara,").is_err());
        assert!(offline_names("a,b,c").is_err());
        let ok = parse_args(&words(&format!(
            "{} --offline-two-person Sara,Omar",
            base()
        )))
        .unwrap();
        assert_eq!(
            ok.approval,
            Approval::Offline {
                first: "Sara".into(),
                second: "Omar".into()
            }
        );
    }

    #[test]
    fn side_copy_never_targets_live_database() {
        assert!(target_database(Some("attome"), "attome").is_err());
        assert_eq!(
            target_database(Some("attome_recovered"), "attome").unwrap(),
            "attome_recovered"
        );
        assert!(target_database(Some("bad-name; drop"), "attome").is_err());
        assert_eq!(target_database(None, "attome").unwrap(), "attome");
    }
}
