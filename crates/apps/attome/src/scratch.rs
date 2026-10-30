//! T5-T1: `attome scratch create`, a sandbox copy of this deployment's
//! database.
//!
//! `attome scratch create --name <database> [--from latest|<archive>]`
//! restores a backup (a fresh `pg_dump` when `--from` is absent) into a new
//! database on the same PostgreSQL server, with the deployment's own
//! credentials, then masks it before anything boots on it:
//!
//! - every labelled field is masked by `crate::masking` (L10-T1): Personal
//!   values become keyed fakes, Financial values are shuffled between
//!   records, Health, Secret and unlabelled sensitive values are cleared;
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

/// One labelled field of the copy: entity, field, label (`sensitive` when
/// only `is_sensitive` marks it), the masking override, whether its column
/// is nullable and whether it is text.
type LabelledField = (String, String, String, Option<String>, bool, bool);

/// The copy's labelled fields, as [`LabelledField`] rows.
const LABELLED_FIELDS: &str = "SELECT e.logicalname::text, a.logicalname::text, \
                CASE WHEN a.sensitivity_confirmed THEN a.sensitivity::text ELSE 'sensitive' END, \
                a.options->>'masking', \
                COALESCE(c.is_nullable = 'YES', false), \
                COALESCE(c.data_type IN ('text', 'character varying', 'character'), false) \
           FROM attribute_info a \
           JOIN entity_info e ON e.id = a.entity_ref \
           LEFT JOIN information_schema.columns c \
                  ON c.table_schema = current_schema() \
                 AND c.table_name = e.logicalname AND c.column_name = a.logicalname \
          WHERE (a.is_sensitive OR (a.sensitivity_confirmed \
                 AND a.sensitivity IN ('personal', 'financial', 'health', 'secret'))) \
            AND c.column_name IS NOT NULL \
          ORDER BY 1, 2";

/// Rows faked per statement.
const FAKE_BATCH: i64 = 1000;

/// The rule a field is masked with: its label's or its override, a fake
/// only for text (another type is cleared, or left when required). Pure.
pub fn effective_rule(
    label: &str,
    override_rule: Option<&str>,
    nullable: bool,
    is_text: bool,
) -> crate::masking::MaskRule {
    use crate::masking::MaskRule;
    let rule = crate::masking::rule_for(label, override_rule, !nullable);
    match rule {
        MaskRule::Fake if !is_text && nullable => MaskRule::Null,
        MaskRule::Fake if !is_text => MaskRule::Keep,
        other => other,
    }
}

fn hex_key(key: &[u8]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Replaces every value of a text column with its keyed fake, a batch of
/// rows at a time in id order.
async fn fake_column(
    copy: &mut sqlx::PgConnection,
    entity: &str,
    field: &str,
    key: &[u8],
) -> Result<(), sqlx::Error> {
    let read = format!(
        "SELECT id, {c}::text FROM {t} WHERE {c} IS NOT NULL AND id > $1 ORDER BY id LIMIT $2",
        t = attome_core::quote_ident(entity),
        c = attome_core::quote_ident(field)
    );
    let write = format!(
        "UPDATE {t} SET {c} = u.v FROM unnest($1::uuid[], $2::text[]) AS u(id, v) \
          WHERE {t}.id = u.id",
        t = attome_core::quote_ident(entity),
        c = attome_core::quote_ident(field)
    );
    let mut after = uuid::Uuid::nil();
    loop {
        let rows: Vec<(uuid::Uuid, String)> = sqlx::query_as(&read)
            .bind(after)
            .bind(FAKE_BATCH)
            .fetch_all(&mut *copy)
            .await?;
        let Some(last) = rows.last().map(|r| r.0) else {
            return Ok(());
        };
        let ids: Vec<uuid::Uuid> = rows.iter().map(|r| r.0).collect();
        let fakes: Vec<String> = rows
            .iter()
            .map(|(_, value)| crate::masking::fake(key, field, value))
            .collect();
        sqlx::query(&write)
            .bind(&ids)
            .bind(&fakes)
            .execute(&mut *copy)
            .await?;
        after = last;
    }
}

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

    let labelled: Vec<LabelledField> =
        sqlx::query_as(LABELLED_FIELDS)
            .fetch_all(&mut copy)
            .await
            .map_err(|e| format!("cannot read the copy's labelled fields: {e}"))?;
    // L10-T1: one key for this copy, never stored.
    let key: [u8; 32] = rand::random();
    let mut masked = Vec::new();
    let mut unmasked_required = Vec::new();
    for (entity, field, label, override_rule, nullable, is_text) in labelled {
        let name = format!("{entity}.{field}");
        let rule = effective_rule(&label, override_rule.as_deref(), nullable, is_text);
        match rule {
            crate::masking::MaskRule::Keep => {
                unmasked_required.push(name);
                continue;
            }
            crate::masking::MaskRule::Null => {
                let sql = format!(
                    "UPDATE {t} SET {c} = NULL WHERE {c} IS NOT NULL",
                    t = attome_core::quote_ident(&entity),
                    c = attome_core::quote_ident(&field)
                );
                sqlx::query(&sql)
                    .execute(&mut copy)
                    .await
                    .map_err(|e| format!("cannot clear {name}: {e}"))?;
            }
            crate::masking::MaskRule::Shuffle => {
                // The values stay in the column, each moved to another
                // record in an order only this copy's key decides.
                let sql = format!(
                    "WITH src AS (SELECT {c} AS v, row_number() OVER (ORDER BY id) AS n \
                                   FROM {t} WHERE {c} IS NOT NULL), \
                          dst AS (SELECT id, row_number() OVER (ORDER BY md5(id::text || $1)) AS n \
                                   FROM {t} WHERE {c} IS NOT NULL) \
                     UPDATE {t} SET {c} = src.v FROM src JOIN dst USING (n) WHERE {t}.id = dst.id",
                    t = attome_core::quote_ident(&entity),
                    c = attome_core::quote_ident(&field)
                );
                sqlx::query(&sql)
                    .bind(hex_key(&key))
                    .execute(&mut copy)
                    .await
                    .map_err(|e| format!("cannot shuffle {name}: {e}"))?;
            }
            crate::masking::MaskRule::Fake => {
                fake_column(&mut copy, &entity, &field, &key)
                    .await
                    .map_err(|e| format!("cannot fake {name}: {e}"))?;
            }
        }
        masked.push(name);
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

/// L10-T2: one field's verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldCheck {
    pub field: String,
    pub rule: crate::masking::MaskRule,
    /// Source records compared.
    pub sampled: usize,
    /// Of those, records whose copy holds the source's value.
    pub matches: usize,
}

impl FieldCheck {
    /// Whether a match here is an unmasked value. A shuffled value can land
    /// on a record that held the same one, and a kept field is kept on
    /// purpose. Pure.
    pub fn counts_as_unmasked(&self) -> bool {
        matches!(
            self.rule,
            crate::masking::MaskRule::Fake | crate::masking::MaskRule::Null
        )
    }
}

/// Source records sampled per field.
pub const VERIFY_SAMPLE: i64 = 200;

/// L10-T2: compares a sample of each labelled field's values in the source
/// with the copy `name`, record by record, by hash; returns each field's
/// result. The copy must be a sandbox copy.
pub async fn verify(config: &AppConfig, name: &str) -> Result<Vec<FieldCheck>, String> {
    use sqlx::Connection;
    let open = |db: String| async move {
        let mut conn =
            sqlx::PgConnection::connect_with(&crate::backup::connect_options(config, &db))
                .await
                .map_err(|e| format!("cannot open {db}: {e}"))?;
        sqlx::query("SELECT set_config('search_path', $1, false)")
            .bind(&config.database.schema)
            .execute(&mut conn)
            .await
            .map_err(|e| format!("cannot set the schema of {db}: {e}"))?;
        Ok::<_, String>(conn)
    };
    let mut source = open(config.database.dbname.clone()).await?;
    let mut copy = open(name.to_owned()).await?;
    let marked: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM sandbox_copy)")
        .fetch_one(&mut copy)
        .await
        .map_err(|e| format!("{name} is not a sandbox copy: {e}"))?;
    if !marked {
        return Err(format!("{name} is not a sandbox copy"));
    }
    let labelled: Vec<LabelledField> =
        sqlx::query_as(LABELLED_FIELDS)
            .fetch_all(&mut copy)
            .await
            .map_err(|e| format!("cannot read the copy's labelled fields: {e}"))?;
    let mut checks = Vec::new();
    for (entity, field, label, override_rule, nullable, is_text) in labelled {
        let rule = effective_rule(&label, override_rule.as_deref(), nullable, is_text);
        let read = format!(
            "SELECT id, md5({c}::text) FROM {t} WHERE {c} IS NOT NULL ORDER BY id LIMIT $1",
            t = attome_core::quote_ident(&entity),
            c = attome_core::quote_ident(&field)
        );
        let sample: Vec<(uuid::Uuid, String)> = sqlx::query_as(&read)
            .bind(VERIFY_SAMPLE)
            .fetch_all(&mut source)
            .await
            .map_err(|e| format!("cannot sample {entity}.{field}: {e}"))?;
        let ids: Vec<uuid::Uuid> = sample.iter().map(|r| r.0).collect();
        let compare = format!(
            "SELECT id, md5({c}::text) FROM {t} WHERE id = ANY($1) AND {c} IS NOT NULL",
            t = attome_core::quote_ident(&entity),
            c = attome_core::quote_ident(&field)
        );
        let copied: Vec<(uuid::Uuid, String)> = sqlx::query_as(&compare)
            .bind(&ids)
            .fetch_all(&mut copy)
            .await
            .map_err(|e| format!("cannot read {entity}.{field} in the copy: {e}"))?;
        checks.push(FieldCheck {
            field: format!("{entity}.{field}"),
            rule,
            sampled: sample.len(),
            matches: count_matches(&sample, &copied),
        });
    }
    let _ = source.close().await;
    let _ = copy.close().await;
    Ok(checks)
}

/// How many of `source`'s (id, hash) pairs `copy` holds unchanged. Pure.
pub fn count_matches(source: &[(uuid::Uuid, String)], copy: &[(uuid::Uuid, String)]) -> usize {
    let copied: std::collections::HashMap<&uuid::Uuid, &String> =
        copy.iter().map(|(id, hash)| (id, hash)).collect();
    source
        .iter()
        .filter(|(id, hash)| copied.get(id).is_some_and(|h| *h == hash))
        .count()
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
    if command == "verify" {
        return run_verify(&config, rest).await;
    }
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
                "sandbox copy {} made from {}: {} labelled field(s) masked",
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

/// `attome scratch verify --name <copy>`: fails when a sampled value is
/// still the source's.
#[allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]
async fn run_verify(config: &AppConfig, args: &[String]) -> std::process::ExitCode {
    let name = match args {
        [flag, name] if flag == "--name" => name,
        _ => {
            eprintln!("usage: attome scratch verify --name <copy>");
            return std::process::ExitCode::FAILURE;
        }
    };
    match verify(config, name).await {
        Ok(checks) => {
            let unmasked: usize = checks
                .iter()
                .filter(|c| c.counts_as_unmasked())
                .map(|c| c.matches)
                .sum();
            for check in &checks {
                println!(
                    "{}: {:?}, {} sampled, {} unchanged",
                    check.field, check.rule, check.sampled, check.matches
                );
            }
            if unmasked == 0 {
                println!("verified: no unmasked value in {name}");
                std::process::ExitCode::SUCCESS
            } else {
                eprintln!("attome scratch verify: {unmasked} unmasked value(s) in {name}");
                std::process::ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("attome scratch verify: {error}");
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
    fn verifier_counts_unchanged_values_only() {
        let a = uuid::Uuid::from_u128(1);
        let b = uuid::Uuid::from_u128(2);
        let source = vec![(a, "h1".to_owned()), (b, "h2".to_owned())];
        assert_eq!(count_matches(&source, &[(a, "h1".to_owned())]), 1);
        assert_eq!(
            count_matches(&source, &[(a, "x".to_owned()), (b, "y".to_owned())]),
            0
        );
        assert_eq!(count_matches(&source, &[]), 0);
        let check = |rule| FieldCheck {
            field: "contact.email".into(),
            rule,
            sampled: 2,
            matches: 1,
        };
        assert!(check(crate::masking::MaskRule::Fake).counts_as_unmasked());
        assert!(!check(crate::masking::MaskRule::Shuffle).counts_as_unmasked());
        assert!(!check(crate::masking::MaskRule::Keep).counts_as_unmasked());
        assert_eq!(
            effective_rule("personal", None, true, false),
            crate::masking::MaskRule::Null
        );
        assert_eq!(
            effective_rule("personal", None, false, false),
            crate::masking::MaskRule::Keep
        );
    }

    #[test]
    fn sandbox_copy_never_mails_real_people() {
        assert!(sandbox_email_refusal(true, true, false).is_some());
        assert!(sandbox_email_refusal(true, true, true).is_none());
        assert!(sandbox_email_refusal(true, false, false).is_none());
        assert!(sandbox_email_refusal(false, true, false).is_none());
    }
}
