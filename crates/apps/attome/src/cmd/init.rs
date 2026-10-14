//! `attome init`: install a Solo deployment on an existing PostgreSQL.
//!
//! Solo is the binary and PostgreSQL, nothing else (`docs/architecture.md`):
//! the shared state Redis would hold lives in process memory
//! (`docs/solo-memory-backend.md`). This command writes the configuration for
//! that shape, with freshly generated secrets, and applies the schema:
//!
//! ```text
//! attome init --database-url postgres://postgres:secret@localhost:5432/attome
//! attome serve --bootstrap-admin you@example.com   # prints a one-time password
//! attome serve
//! ```
//!
//! Or in one command, as a Windows service or a systemd unit (U1-T1):
//!
//! ```text
//! attome init --database-url <url> --admin you@example.com --service
//! ```
//!
//! which writes the configuration to the platform data directory, applies the
//! schema, creates the first administrator (printing a one-time password),
//! installs and starts the service and waits until it answers.
//!
//! The database must exist and the connecting role must be able to create
//! roles and tables in it (the migrations create the three application roles).
//! Before writing anything it checks the machine against the Solo minimums
//! ([`super::sizing`]): below them it warns, and it refuses only when the
//! disk is nearly full.
//!
//! The command never touches an existing configuration file unless `--force`
//! is given, and it never prints a secret other than where it writes it.

use std::path::PathBuf;
use std::str::FromStr;

use attome_config::AppConfig;
use rand::RngCore;
use serde_json::{Value, json};
use sqlx::postgres::PgConnectOptions;

const USAGE: &str = "\
attome init: install a Solo deployment (the binary and PostgreSQL, no Redis)

Usage:
  attome init --database-url <url> [--out <file>] [--port <n>] [--force]
              [--no-migrate] [--from-bundle <dir>] [--admin <email>] [--service]

  --database-url  postgres://user:password@host:port/database, a database that
                  exists, reached as a role that can create roles and tables
  --out           where to write the configuration (default ./config.json)
  --port          the HTTP port (default 7865)
  --force         overwrite an existing configuration file
  --no-migrate    write the configuration only; apply the schema later with
                  `attome migrate`
  --from-bundle   an offline bundle directory to verify first
                  (`attome bundle offline` makes one)
  --admin         create the first administrator and print a one-time password
  --service       install and start Attome as a Windows service or a systemd
                  unit and wait until it answers; the configuration goes to
                  %ProgramData%\\Attome or /var/lib/attome unless --out names it
";

/// What the command was asked to do.
#[derive(Debug)]
struct Args {
    database_url: String,
    out: PathBuf,
    port: u16,
    force: bool,
    migrate: bool,
    /// An offline bundle to verify before installing (U1-T4).
    from_bundle: Option<PathBuf>,
    /// The first administrator's email.
    admin: Option<String>,
    /// Install and start the service (U1-T1).
    service: bool,
}

fn parse_args(raw: &[String]) -> Result<Args, String> {
    let mut database_url = None;
    let mut out = None;
    let mut port = 7865u16;
    let mut force = false;
    let mut migrate = true;
    let mut from_bundle = None;
    let mut admin = None;
    let mut service = false;
    let mut it = raw.iter();
    while let Some(arg) = it.next() {
        let mut value = |name: &str| -> Result<String, String> {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--database-url" => database_url = Some(value("--database-url")?),
            "--out" => out = Some(PathBuf::from(value("--out")?)),
            "--port" => {
                port = value("--port")?
                    .parse()
                    .map_err(|_| "--port must be a number from 1 to 65535".to_owned())?;
            }
            "--force" => force = true,
            "--no-migrate" => migrate = false,
            "--from-bundle" => from_bundle = Some(PathBuf::from(value("--from-bundle")?)),
            "--admin" => admin = Some(value("--admin")?),
            "--service" => service = true,
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown option `{other}`\n\n{USAGE}")),
        }
    }
    let database_url =
        database_url.ok_or_else(|| format!("--database-url is required\n\n{USAGE}"))?;
    if (service || admin.is_some()) && !migrate {
        return Err("--service and --admin need the schema; drop --no-migrate".to_owned());
    }
    let out = out.unwrap_or_else(|| {
        if service {
            super::service::default_dir().join("config.json")
        } else {
            PathBuf::from("config.json")
        }
    });
    Ok(Args {
        database_url,
        out,
        port,
        force,
        migrate,
        from_bundle,
        admin,
        service,
    })
}

/// 32 random bytes as hex, for secrets and role passwords.
fn secret() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The Solo configuration, as JSON. Pure, so a test can build it.
fn solo_config(db: &PgConnectOptions, port: u16) -> Value {
    json!({
        "app": {
            "port": port,
            "server_host": "127.0.0.1",
            "frontend_host": "localhost",
            "frontend_port": port,
            "log_level": "info",
            "threads": 0,
            "max_body_size_bytes": 10_485_760,
            "request_timeout_secs": 30,
            "enable_session": true,
            "max_connection_num": 1024,
            "max_connection_num_per_ip": 64,
            "use_gzip": true,
            "enable_compression": true,
            "gzip_level": 4,
            "br_level": 4,
            "idle_connection_timeout": 60,
            "keepalive_requests": 1000,
            "static_files_cache_time": 3600,
            "server_header_field": "attome",
            "deployment_profile": "development"
        },
        "database": {
            "host": db.get_host(),
            "port": db.get_port(),
            "dbname": db.get_database().unwrap_or("attome"),
            "user": db.get_username(),
            "password": "__DB_PASSWORD__",
            "schema": "public",
            "connection_number": 10,
            "timeout": 5.0,
            "migrate_on_boot": true,
            "runtime": { "user": "attome_runtime", "password": secret() },
            "migrator": { "user": "attome_migrator", "password": secret() },
            "readonly": { "user": "attome_readonly", "password": secret() }
        },
        // Solo keeps its shared state in process memory: no Redis.
        "cache": {
            "backend": "memory",
            "l1_cache_size_mb": 64,
            "l1_cache_ttl_seconds": 60,
            "metadata_registry_enabled": true
        },
        "storage": {
            "s3_endpoint": "http://127.0.0.1:9000",
            "s3_public_endpoint": "",
            "s3_region": "us-east-1",
            "s3_access_key": "unset",
            "s3_secret_key": "unset",
            "s3_bucket": "attome",
            "s3_use_path_style": true,
            "s3_verify_ssl": false
        },
        "auth": {
            "jwt_secret": secret(),
            "jwt_issuer": "attome",
            "jwt_expiry_hours": 1,
            "apikey_hash_pepper": secret(),
            "apikey_hash_pepper_id": 0,
            // Solo is reached over plain http on this machine until a TLS
            // front is configured; a Secure cookie would never be sent back.
            "secure_cookies": false,
            "oauth_google_client_id": "",
            "oauth_google_client_secret": ""
        },
        "rate_limit": { "anonymous_rpm": 120, "authenticated_rpm": 1200 },
        "observability": {
            "metrics_port": 0,
            "log_sampling_rate": 1.0,
            "trace_sampling_rate": 0.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "attome@localhost",
            "smtp_from_name": "Attome", "smtp_use_tls": false,
            "queue_poll_seconds": 30, "max_retries": 3, "batch_size": 20
        },
        "google_ai": {
            "api_key": "", "base_url": "https://example.invalid",
            "default_model": "none", "timeout_seconds": 30
        },
        "llm_api": {},
        "external_api": {},
        "s2s": { "enabled": false },
        "security": { "bootstrap_admin_email": null },
        "cors": { "allowed_origins": [format!("http://localhost:{port}")] },
        "jobs": { "run_worker_inline": true }
    })
}

/// Renders the configuration with the bootstrap password filled in. The
/// password comes from the URL the operator passed; it is written to the file
/// the operator chose and nowhere else.
fn render(db: &PgConnectOptions, port: u16, password: &str) -> Result<String, String> {
    let mut config = solo_config(db, port);
    config["database"]["password"] = Value::String(password.to_owned());
    serde_json::to_string_pretty(&config).map_err(|e| e.to_string())
}

fn password_of(url: &str) -> Option<String> {
    // `PgConnectOptions` does not expose the password, so read it from the
    // URL (percent-decoded, as the driver would).
    let parsed = url::Url::parse(url).ok()?;
    let raw = parsed.password()?;
    Some(percent_decode(raw))
}

/// Decodes `%XX` escapes; anything malformed is kept as written.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&raw[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Writes one line to standard output; a closed pipe is not worth failing over.
fn say(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout().lock(), "{text}");
}

#[tokio::main]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let raw: Vec<String> = std::env::args().skip(2).collect();
    let args = match parse_args(&raw) {
        Ok(args) => args,
        Err(message) => {
            say(&message);
            return Err("attome init: invalid arguments".into());
        }
    };

    // U1-T4: an air-gapped install checks the bundle it came in first.
    if let Some(bundle) = &args.from_bundle {
        super::bundle_offline::verify_or_refuse(bundle)?;
    }

    let db = PgConnectOptions::from_str(&args.database_url)
        .map_err(|e| format!("--database-url is not a PostgreSQL URL: {e}"))?;
    let password = password_of(&args.database_url)
        .ok_or("--database-url must carry the role's password: postgres://user:password@host/db")?;

    if args.out.exists() && !args.force {
        return Err(format!(
            "{} already exists; pass --force to replace it (its secrets would be lost)",
            args.out.display()
        )
        .into());
    }
    // Sizing (U1-T3): warn below the Solo minimums, refuse on a nearly full disk.
    if let Some(parent) = args.out.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let install_dir = args
        .out
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let findings = super::sizing::judge(
        &super::sizing::read(install_dir, args.port),
        &super::sizing::SOLO,
        args.port,
    );
    let mut refused = Vec::new();
    for finding in findings {
        match finding {
            super::sizing::Finding::Warn(text) => say(&format!("warning: {text}")),
            super::sizing::Finding::Refuse(text) => refused.push(text),
        }
    }
    if !refused.is_empty() {
        return Err(format!("attome init: {}", refused.join("; ")).into());
    }

    let text = render(&db, args.port, &password)?;
    // Parse and validate what we are about to write, so a bad value is found
    // here and not at the first boot.
    let config: AppConfig = serde_json::from_str(&text)?;
    config.validate()?;
    std::fs::write(&args.out, &text)?;
    say(&format!("wrote {}", args.out.display()));

    if args.migrate {
        say("applying the schema (this creates the application roles and tables)...");
        let migration_db = crate::boot::apply_schema_migrations(&config).await?;
        crate::role_seed_lock::seed_roles_and_pepper_registry(&migration_db, &config).await?;
        migration_db.close().await;
        say("schema applied");
    }

    if let Some(email) = &args.admin {
        crate::serve::run_bootstrap_admin(&config, email).await?;
    }

    if args.service {
        super::service::run(&[
            "install".to_owned(),
            "--dir".to_owned(),
            install_dir.display().to_string(),
        ])?;
        wait_until_ready(args.port).await?;
        say(&format!(
            "\nAttome is running. Open http://localhost:{}/ and sign in{}.",
            args.port,
            if args.admin.is_some() {
                " with the one-time password above"
            } else {
                ""
            }
        ));
        return Ok(());
    }

    let path = args.out.display();
    let admin_step = if args.admin.is_some() {
        String::new()
    } else {
        format!("CONFIG_FILE={path} attome serve --bootstrap-admin you@example.com\n  ")
    };
    say(&format!(
        "\nNext:\n  {admin_step}CONFIG_FILE={path} attome serve\n\nThen open http://localhost:{}/",
        args.port
    ));
    Ok(())
}

/// Polls `/health/ready` on this machine until the service answers, for at
/// most three minutes.
async fn wait_until_ready(port: u16) -> Result<(), String> {
    say("waiting for the service to answer...");
    let addr = format!("127.0.0.1:{port}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    loop {
        let probe_addr = addr.clone();
        let ready = tokio::task::spawn_blocking(move || {
            super::healthcheck::probe(&probe_addr, "/health/ready").unwrap_or(false)
        })
        .await
        .unwrap_or(false);
        if ready {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err(format!(
                "the service did not answer on {addr} within 3 minutes; check its log \
                 (Windows: Event Viewer, Linux: journalctl -u attome)"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> PgConnectOptions {
        PgConnectOptions::from_str("postgres://postgres:pw@localhost:5432/attome").unwrap()
    }

    #[test]
    fn the_solo_configuration_is_valid_and_uses_no_redis() {
        let text = render(&db(), 7865, "pw").unwrap();
        let config: AppConfig = serde_json::from_str(&text).expect("deserialises");
        config.validate().expect("validates");
        assert_eq!(config.cache.backend, attome_config::CacheBackend::Memory);
        assert!(config.jobs.run_worker_inline);
    }

    #[test]
    fn each_init_generates_distinct_secrets() {
        let a = solo_config(&db(), 7865);
        let b = solo_config(&db(), 7865);
        assert_ne!(a["auth"]["jwt_secret"], b["auth"]["jwt_secret"]);
        assert_ne!(
            a["database"]["runtime"]["password"],
            b["database"]["runtime"]["password"]
        );
        assert_eq!(a["auth"]["jwt_secret"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn the_password_is_read_from_the_url() {
        assert_eq!(
            password_of("postgres://u:p%40ss@h:5432/d").as_deref(),
            Some("p@ss")
        );
        assert_eq!(password_of("postgres://u@h/d"), None);
    }

    #[test]
    fn arguments_require_a_database_url_and_reject_unknown_options() {
        assert!(parse_args(&[]).is_err());
        assert!(
            parse_args(&[
                "--database-url".into(),
                "postgres://u:p@h/d".into(),
                "--bogus".into()
            ])
            .is_err()
        );
        let ok = parse_args(&[
            "--database-url".into(),
            "postgres://u:p@h/d".into(),
            "--port".into(),
            "8080".into(),
            "--no-migrate".into(),
        ])
        .unwrap();
        assert_eq!(ok.port, 8080);
        assert!(!ok.migrate);
        assert_eq!(ok.out, PathBuf::from("config.json"));
    }

    #[test]
    fn service_installs_into_the_data_directory_and_needs_the_schema() {
        let url = || vec!["--database-url".to_owned(), "postgres://u:p@h/d".to_owned()];
        let mut args = url();
        args.extend([
            "--service".to_owned(),
            "--admin".to_owned(),
            "a@b.c".to_owned(),
        ]);
        let parsed = parse_args(&args).unwrap();
        assert!(parsed.service);
        assert_eq!(parsed.admin.as_deref(), Some("a@b.c"));
        assert_eq!(
            parsed.out,
            super::super::service::default_dir().join("config.json")
        );
        let mut args = url();
        args.extend(["--service".to_owned(), "--no-migrate".to_owned()]);
        assert!(parse_args(&args).is_err(), "a service needs the schema");
    }
}
