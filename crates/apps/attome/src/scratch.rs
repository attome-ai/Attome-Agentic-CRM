//! T5-T1: `attome scratch create`, a sandbox copy of this deployment's
//! database.
//!
//! `attome scratch create --name <database> [--from latest|<archive>]`
//! restores a backup (a fresh `pg_dump` when `--from` is absent) into a new
//! database on the same PostgreSQL server, with the deployment's own
//! credentials, then masks it before anything boots on it:
//!
//! - every value of a field labelled sensitive, or with a confirmed Personal,
//!   Financial, Health or Secret label, is cleared (a required column keeps
//!   its value and is listed, for L10-T1's deterministic fakes to replace);
//! - API keys, refresh and portal tokens, connector OAuth tokens, SCIM
//!   tokens and pending reset, invitation and verification links are
//!   removed, so nothing issued for the source works against the copy;
//! - one `sandbox_copy` row marks it, and boot then refuses to send real
//!   email from it: with email on, `email.test_mode_catch_all` must be set
//!   (Z8-T6).
//!
//! Only the `full` mode is built. `metadata` (the model without records) and
//! `sample` (a share of each entity with its references) are refused: both
//! need a copy that boots before it is filled, which this command does not
//! drive. The copy API the task names is not built either: creating a
//! database needs the server's own credentials, which the HTTP process does
//! not hold apart from the migrator's.

use std::path::PathBuf;

use attome_config::AppConfig;

/// What one copy did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScratchReport {
    pub database: String,
    pub archive: PathBuf,
    /// Fields cleared, as `entity.field`.
    pub masked: Vec<String>,
    /// Labelled fields left as they were because their column is required.
    pub unmasked_required: Vec<String>,
}

/// The modes a copy may be made in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScratchMode {
    Full,
    Metadata,
    Sample,
}

impl ScratchMode {
    /// The mode a `--mode` value names. Pure.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "full" => Some(Self::Full),
            "metadata" => Some(Self::Metadata),
            "sample" => Some(Self::Sample),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Metadata => "metadata",
            Self::Sample => "sample",
        }
    }
}

/// A copy's arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScratchArgs {
    pub name: String,
    pub from: Option<String>,
    pub mode: ScratchMode,
}

/// Whether `name` may name a copy: lowercase letters, digits and
/// underscores, starting with a letter, 3 to 63 characters, and not the
/// source database. Pure.
pub fn valid_name(name: &str, source: &str) -> bool {
    let shaped = (3..=63).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    shaped && name != source
}

/// The arguments of `attome scratch create`. Pure.
pub fn parse_args(args: &[String], source: &str) -> Result<ScratchArgs, String> {
    let mut name = None;
    let mut from = None;
    let mut mode = ScratchMode::Full;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--name" => name = Some(value()?),
            "--from" => from = Some(value()?),
            "--mode" => {
                let raw = value()?;
                mode = ScratchMode::parse(&raw)
                    .ok_or_else(|| format!("--mode is full, metadata or sample, not {raw}"))?;
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    let name = name.ok_or("--name is required")?;
    if !valid_name(&name, source) {
        return Err(format!(
            "{name}: a copy's name is 3 to 63 lowercase letters, digits or underscores, \
             starting with a letter, and not the source database"
        ));
    }
    if mode != ScratchMode::Full {
        return Err(format!(
            "--mode {} is not built yet; only full copies are",
            mode.as_str()
        ));
    }
    Ok(ScratchArgs { name, from, mode })
}

/// The tables whose rows are credentials issued for the source, cleared in
/// the copy when they exist.
const CREDENTIAL_TABLES: &[&str] = &[
    "api_key",
    "refresh_token",
    "agent_session_token",
    "impersonation_session",
    "integration_oauth_token",
    "scim_token",
    "webportal_token",
    "webportal_refresh_token",
    "password_reset_token",
    "invitation_token",
    "email_verification_token",
];

/// Makes the copy `args` names.
pub async fn create(config: &AppConfig, args: &ScratchArgs) -> Result<ScratchReport, String> {
    use sqlx::Connection;
    let archive = match args.from.as_deref() {
        Some(target) => crate::backup::archive_for(config, target).await?,
        None => crate::backup::run_once(config).await?,
    };
    let mut admin = sqlx::PgConnection::connect_with(&crate::backup::connect_options(
        config,
        &config.database.dbname,
    ))
    .await
    .map_err(|e| format!("cannot connect: {e}"))?;
    crate::backup::restore_into(config, &mut admin, &archive, &args.name).await?;
    let _ = admin.close().await;

    let mut copy =
        sqlx::PgConnection::connect_with(&crate::backup::connect_options(config, &args.name))
            .await
            .map_err(|e| format!("cannot open the copy: {e}"))?;
    let schema = config.database.schema.clone();
    sqlx::query("SELECT set_config('search_path', $1, false)")
        .bind(&schema)
        .execute(&mut copy)
        .await
        .map_err(|e| format!("cannot set the copy's schema: {e}"))?;

    let labelled: Vec<(String, String, bool)> = sqlx::query_as(
        "SELECT e.logicalname::text, a.logicalname::text, \
                COALESCE(c.is_nullable = 'YES', false) \
           FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
           LEFT JOIN information_schema.columns c \
                  ON c.table_schema = current_schema() \
                 AND c.table_name = e.logicalname AND c.column_name = a.logicalname \
          WHERE (a.is_sensitive OR (a.sensitivity_confirmed \
                 AND a.sensitivity IN ('personal', 'financial', 'health', 'secret'))) \
            AND c.column_name IS NOT NULL \
          ORDER BY 1, 2",
    )
    .fetch_all(&mut copy)
    .await
    .map_err(|e| format!("cannot read the copy's labelled fields: {e}"))?;
    let mut masked = Vec::new();
    let mut unmasked_required = Vec::new();
    for (entity, field, nullable) in labelled {
        if !nullable {
            unmasked_required.push(format!("{entity}.{field}"));
            continue;
        }
        let sql = format!(
            "UPDATE {t} SET {c} = NULL WHERE {c} IS NOT NULL",
            t = attome_core::quote_ident(&entity),
            c = attome_core::quote_ident(&field)
        );
        sqlx::query(&sql)
            .execute(&mut copy)
            .await
            .map_err(|e| format!("cannot clear {entity}.{field}: {e}"))?;
        masked.push(format!("{entity}.{field}"));
    }
    for table in CREDENTIAL_TABLES {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass(quote_ident($1)) IS NOT NULL")
            .bind(table)
            .fetch_one(&mut copy)
            .await
            .map_err(|e| format!("cannot look for {table}: {e}"))?;
        if exists {
            let sql = format!("DELETE FROM {t}", t = attome_core::quote_ident(table));
            sqlx::query(&sql)
                .execute(&mut copy)
                .await
                .map_err(|e| format!("cannot clear {table}: {e}"))?;
        }
    }
    sqlx::query(
        "INSERT INTO sandbox_copy (source_database, mode, masked_fields) VALUES ($1, $2, $3)",
    )
    .bind(&config.database.dbname)
    .bind(args.mode.as_str())
    .bind(i32::try_from(masked.len()).unwrap_or(i32::MAX))
    .execute(&mut copy)
    .await
    .map_err(|e| format!("cannot mark the copy: {e}"))?;
    let _ = copy.close().await;
    Ok(ScratchReport {
        database: args.name.clone(),
        archive,
        masked,
        unmasked_required,
    })
}

/// Why boot refuses a database, or `None`: a sandbox copy with email on and
/// no catch-all address would mail real people. Pure.
pub fn sandbox_email_refusal(
    is_sandbox: bool,
    email_enabled: bool,
    catch_all: bool,
) -> Option<&'static str> {
    (is_sandbox && email_enabled && !catch_all).then_some(
        "this database is a sandbox copy (sandbox_copy); set email.test_mode_catch_all or \
         email.enabled = false before it boots, so it never mails a real person",
    )
}

/// `attome scratch …`.
#[allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]
#[tokio::main]
pub async fn run(args: Vec<String>) -> std::process::ExitCode {
    let config = match AppConfig::from_file() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("attome scratch: cannot read the configuration: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let Some((command, rest)) = args.split_first() else {
        eprintln!("usage: attome scratch create --name <database> [--from latest|<archive>]");
        return std::process::ExitCode::FAILURE;
    };
    if command != "create" {
        eprintln!("attome scratch: unknown command {command}");
        return std::process::ExitCode::FAILURE;
    }
    let parsed = match parse_args(rest, &config.database.dbname) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("attome scratch create: {error}");
            return std::process::ExitCode::FAILURE;
        }
    };
    match create(&config, &parsed).await {
        Ok(report) => {
            println!(
                "sandbox copy {} made from {}: {} labelled field(s) cleared",
                report.database,
                report.archive.display(),
                report.masked.len()
            );
            for field in &report.unmasked_required {
                println!("  left as is (required column): {field}");
            }
            println!(
                "point a configuration at database {} with email.test_mode_catch_all set before booting it",
                report.database
            );
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("attome scratch create: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn scratch_args_parse_and_refuse() {
        let parsed = parse_args(
            &strings(&["--name", "attome_copy", "--from", "latest"]),
            "attome",
        )
        .expect("valid");
        assert_eq!(parsed.name, "attome_copy");
        assert_eq!(parsed.from.as_deref(), Some("latest"));
        assert_eq!(parsed.mode, ScratchMode::Full);
        assert!(parse_args(&strings(&[]), "attome").is_err());
        assert!(parse_args(&strings(&["--name", "attome"]), "attome").is_err());
        assert!(parse_args(&strings(&["--name", "Bad-Name"]), "attome").is_err());
        assert!(
            parse_args(
                &strings(&["--name", "copy_a", "--mode", "sample"]),
                "attome"
            )
            .is_err()
        );
        assert!(parse_args(&strings(&["--name"]), "attome").is_err());
        assert!(parse_args(&strings(&["--name", "copy_a", "--x"]), "attome").is_err());
    }

    #[test]
    fn sandbox_copy_never_mails_real_people() {
        assert!(sandbox_email_refusal(true, true, false).is_some());
        assert!(sandbox_email_refusal(true, true, true).is_none());
        assert!(sandbox_email_refusal(true, false, false).is_none());
        assert!(sandbox_email_refusal(false, true, false).is_none());
    }
}
