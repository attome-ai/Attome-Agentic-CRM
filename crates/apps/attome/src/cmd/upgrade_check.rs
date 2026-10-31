//! AB8-T2: `attome upgrade check` and `attome upgrade sign-manifest`.
//!
//! ```text
//! attome upgrade check --manifest <file> [--config <path>] [--free-bytes <n>] [--json]
//! attome upgrade sign-manifest --in <file> --key <file> --out <file>
//! ```
//!
//! `check` verifies the signed manifest, then reports the version path,
//! preflight's dependency checks, free disk against the largest table, the
//! last proven restore, and the deprecated features in use, each pass, warn
//! or fail, with what the upgrade pauses. It reads the database directly, so
//! it works while the API is down, and writes nothing. It exits 0 with no
//! fail, 5 otherwise.
//!
//! The current version is this binary's: the database records migrations,
//! not releases. Free disk is on the database's volume, which SQL cannot see,
//! so the operator passes it with `--free-bytes`; without it the check warns.
//!
//! A manifest's `how_to_check` names a check here:
//! `uses_table:<table>` (the table exists and holds a row).

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::process::ExitCode;

use attome_ops::release_manifest::{ReleaseManifest, sign_with_seed, verify_manifest};
use attome_ops::upgrade_check::{self, Finding, Report, Verdict};

const USAGE: &str = "usage: attome upgrade check --manifest <file> [--config <path>] [--free-bytes <n>] [--json]\n       attome upgrade sign-manifest --in <file> --key <file> --out <file>";
/// Exit code of a report with a fail.
const REFUSED: u8 = 5;

/// A parsed `attome upgrade check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckArgs {
    pub manifest: String,
    pub config: Option<String>,
    pub free_bytes: Option<u64>,
    pub json: bool,
}

/// Parses what follows `attome upgrade check`. Pure.
pub fn parse_check(args: &[String]) -> Result<CheckArgs, String> {
    use crate::cmd::output::{take_flag, take_value};
    let mut args = args.to_vec();
    let json = take_flag(&mut args, "--json");
    let manifest = take_value(&mut args, "--manifest")?.ok_or(USAGE)?;
    let config = take_value(&mut args, "--config")?;
    let free_bytes = take_value(&mut args, "--free-bytes")?
        .map(|n| n.parse().map_err(|_| format!("--free-bytes: `{n}`")))
        .transpose()?;
    if !args.is_empty() {
        return Err(USAGE.to_owned());
    }
    Ok(CheckArgs {
        manifest,
        config,
        free_bytes,
        json,
    })
}

/// The table `how_to_check` asks about, for a check this binary has. Pure.
fn table_check(how_to_check: &str) -> Option<&str> {
    how_to_check
        .strip_prefix("uses_table:")
        .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
}

async fn uses_table(db: &attome_db::DbPool, table: &str) -> Result<bool, String> {
    let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(db)
        .await
        .map_err(|error| format!("read {table}: {error}"))?;
    if !exists {
        return Ok(false);
    }
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM {})",
        attome_core::quote_ident(table)
    );
    sqlx::query_scalar(&sql)
        .fetch_one(db)
        .await
        .map_err(|error| format!("read {table}: {error}"))
}

/// The read-only checks that need the database.
async fn database_findings(
    config_path: Option<String>,
    manifest: &ReleaseManifest,
    free_bytes: Option<u64>,
) -> Result<Vec<Finding>, String> {
    let path = config_path.unwrap_or_else(attome_config::AppConfig::config_file_path);
    let config = crate::secret_sources::load_config_from(path)
        .await
        .map_err(|error| format!("load the configuration: {error}"))?;
    let db = attome_db::create_pool(&config)
        .await
        .map_err(|error| format!("connect the database: {error}"))?;
    let largest: i64 = sqlx::query_scalar(
        "SELECT COALESCE(max(pg_total_relation_size(c.oid)), 0)::bigint FROM pg_class c \
           JOIN pg_namespace n ON n.oid = c.relnamespace \
          WHERE c.relkind = 'r' AND n.nspname = current_schema()",
    )
    .fetch_one(&db)
    .await
    .map_err(|error| format!("read table sizes: {error}"))?;
    let restore =
        attome_ops::freshness::freshness(&db, attome_ops::evidence::EvidenceKind::Restore)
            .await
            .map_err(|error| format!("read the drill evidence: {error}"))?;
    let mut findings = vec![
        upgrade_check::disk(free_bytes, u64::try_from(largest).unwrap_or(0)),
        upgrade_check::backup(&restore),
    ];
    for item in &manifest.deprecated {
        let in_use = match table_check(&item.how_to_check) {
            Some(table) => Some(uses_table(&db, table).await?),
            None => None,
        };
        findings.push(upgrade_check::deprecated(
            &item.feature,
            &item.removed_in,
            in_use,
        ));
    }
    Ok(findings)
}

pub fn print(report: &Report, json: bool) -> Result<(), String> {
    if json {
        let text = serde_json::to_string_pretty(report).map_err(|error| error.to_string())?;
        println!("{text}");
        return Ok(());
    }
    println!(
        "upgrade {} -> {}: {}",
        report.from_version,
        report.to_version,
        match (report.requires_pause, report.pause_estimate_seconds) {
            (true, Some(seconds)) => format!("pauses writes for about {seconds} s"),
            (true, None) => "pauses writes".to_owned(),
            (false, _) => "no pause".to_owned(),
        }
    );
    for finding in &report.findings {
        let verdict = match finding.verdict {
            Verdict::Pass => "PASS",
            Verdict::Warn => "WARN",
            Verdict::Fail => "FAIL",
        };
        println!("{verdict} {}: {}", finding.check, finding.detail);
    }
    Ok(())
}

/// Verifies the manifest and runs every check; changes nothing.
pub fn build_report(args: &CheckArgs) -> Result<Report, String> {
    let bytes = std::fs::read(&args.manifest)
        .map_err(|error| format!("read {}: {error}", args.manifest))?;
    let manifest = verify_manifest(&bytes, crate::release_keys::RELEASE_PUBLIC_KEYS)
        .map_err(|error| format!("{}: {error}", args.manifest))?;
    let current = env!("CARGO_PKG_VERSION");
    let mut findings = vec![upgrade_check::version_path(current, &manifest)];
    let config = args.config.clone();
    let path = config
        .clone()
        .unwrap_or_else(attome_config::AppConfig::config_file_path);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    for result in runtime.block_on(crate::cmd::preflight::collect(path)) {
        let verdict = if result.ok {
            Verdict::Pass
        } else {
            Verdict::Fail
        };
        findings.push(Finding::new(&result.name, verdict, result.detail));
    }
    findings.extend(runtime.block_on(database_findings(config, &manifest, args.free_bytes))?);
    Ok(Report {
        from_version: current.to_owned(),
        to_version: manifest.version.clone(),
        requires_pause: manifest.requires_pause,
        pause_estimate_seconds: manifest.pause_estimate_seconds,
        findings,
    })
}

fn check(args: &[String]) -> Result<ExitCode, String> {
    let args = parse_check(args)?;
    let report = build_report(&args)?;
    print(&report, args.json)?;
    Ok(if report.passes() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(REFUSED)
    })
}

fn sign_manifest(args: &[String]) -> Result<ExitCode, String> {
    use crate::cmd::output::take_value;
    let mut args = args.to_vec();
    let input = take_value(&mut args, "--in")?.ok_or(USAGE)?;
    let key = take_value(&mut args, "--key")?.ok_or(USAGE)?;
    let out = take_value(&mut args, "--out")?.ok_or(USAGE)?;
    let text = std::fs::read_to_string(&input).map_err(|error| format!("read {input}: {error}"))?;
    let manifest: ReleaseManifest =
        serde_json::from_str(&text).map_err(|error| format!("{input}: {error}"))?;
    let seed = std::fs::read_to_string(&key).map_err(|error| format!("read {key}: {error}"))?;
    let seed: [u8; 32] =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, seed.trim())
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| format!("{key} does not hold a base64 Ed25519 seed"))?;
    let signed = sign_with_seed(&manifest, &seed).map_err(|error| error.to_string())?;
    let text = serde_json::to_string_pretty(&signed).map_err(|error| error.to_string())?;
    std::fs::write(&out, text + "\n").map_err(|error| format!("write {out}: {error}"))?;
    println!("signed {input} as {out} (key {})", signed.key_id);
    Ok(ExitCode::SUCCESS)
}

/// `attome upgrade check|sign-manifest`.
pub fn run(args: &[String]) -> ExitCode {
    let outcome = match args {
        [command, rest @ ..] if command == "check" => check(rest),
        [command, rest @ ..] if command == "sign-manifest" => sign_manifest(rest),
        _ => Err(USAGE.to_owned()),
    };
    outcome.unwrap_or_else(|message| {
        println!("{message}");
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(list: &[&str]) -> Vec<String> {
        list.iter().map(|w| (*w).to_owned()).collect()
    }

    #[test]
    fn check_arguments_parse() {
        let args = parse_check(&words(&[
            "--manifest",
            "m.json",
            "--free-bytes",
            "9",
            "--json",
        ]))
        .expect("arguments");
        assert_eq!(args.manifest, "m.json");
        assert_eq!(args.free_bytes, Some(9));
        assert!(args.json);
        assert!(parse_check(&words(&[])).is_err());
        assert!(parse_check(&words(&["--manifest", "m", "--free-bytes", "x"])).is_err());
        assert!(parse_check(&words(&["--manifest", "m", "extra"])).is_err());
    }

    #[test]
    fn a_table_check_names_a_plain_table() {
        assert_eq!(table_check("uses_table:old_thing"), Some("old_thing"));
        assert_eq!(table_check("uses_table:a;drop"), None);
        assert_eq!(table_check("uses_route_prefix:/x"), None);
    }
}
