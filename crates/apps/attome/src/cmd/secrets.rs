//! `attome secrets` (roadmap Z1-T9): fill the secrets an install generates
//! itself, rotate one key-ring secret, and start the rewrap that moves stored
//! data onto the new key.
//!
//! ```text
//! attome secrets generate --env-file .env [--config config.json]
//! attome secrets rotate JWT_SECRET --env-file .env [--config config.json]
//! attome secrets rewrap mfa [--url http://127.0.0.1:7865] [--api-key <key>]
//! ```
//!
//! The configuration names each secret through a `${VAR}` placeholder; the
//! command reads the configuration file to learn which variable holds which
//! secret ([`attome_config::secret_inventory::SECRETS`]), so it never guesses
//! a name. `generate` fills only the secrets the platform issues itself
//! ([`GENERATED`]: encryption keys, peppers, the application roles'
//! passwords), and only those missing or empty in the file; a value already
//! there is never touched, and a provider's credential (an SMTP password, an
//! API key) is never invented. `rotate` turns a key-ring secret's value into
//! `ring:<new id>=<new>;<old id>=<old>`, so the new key signs or encrypts from
//! the next start while the old one stays readable, after copying the file
//! to `<file>.bak`. Both write through a temporary file and a rename.
//!
//! No command prints a secret: they print the variable names they wrote.
//! `rewrap` calls the API (`POST /api/v1/admin/security/rewrap/{domain}`,
//! guidelines §4) with the API key from `--api-key` or `ATTOME_API_KEY`; the
//! route enqueues the job (or files an approval request when rewraps need
//! one) and answers without a job id, so the command reports that.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use attome_config::BARE_STRING_KEY_ID;
use attome_config::secret_inventory::{Rotation, SECRETS};
use rand::RngCore;
use serde_json::Value;

const USAGE: &str = "\
usage: attome secrets generate --env-file <path> [--config <file>]
       attome secrets rotate <VAR> --env-file <path> [--config <file>]
       attome secrets rewrap <mfa|s2s|erasure> [--url <base>] [--api-key <key>]";

/// The secrets the platform issues itself: 32 random bytes as 64 hex
/// characters suit each (the key rings' hex check included). Anything else
/// in [`SECRETS`] comes from a provider or an operator.
pub const GENERATED: &[&str] = &[
    "audit.erasure_key_encryption_key",
    "audit.signing_private_key",
    "auth.apikey_hash_pepper",
    "auth.jwt_secret",
    "auth.mfa_encryption_key",
    "cache.encryption_key",
    "database.migrator.password",
    "database.readonly.password",
    "database.runtime.password",
    "einvoice.key_encryption_key",
    "events.webhook_signing_key",
    "fleet.credential_encryption_key",
    "idempotency.response_encryption_key",
    "inference.provider_credential_key",
    "integration.credential_encryption_key",
    "metadata.recovery_archive_key_encryption_key",
    "s2s.key_encryption_key",
];

/// The key rings whose stored data a rewrap job moves onto the active key,
/// and that job's domain.
const REWRAP: &[(&str, &str)] = &[
    ("auth.mfa_encryption_key", "mfa"),
    ("s2s.key_encryption_key", "s2s"),
    ("audit.erasure_key_encryption_key", "erasure"),
];

/// 32 random bytes as hex.
fn fresh() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// The variable a configuration value names, when it is exactly `${VAR}`.
fn placeholder(value: &Value) -> Option<&str> {
    let text = value.as_str()?.trim();
    let name = text.strip_prefix("${")?.strip_suffix('}')?;
    (!name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
        .then_some(name)
}

/// Each secret path the configuration names by a variable: (path, VAR).
/// Paths over every list element or map entry are not followed.
pub fn variables(config: &Value) -> Vec<(&'static str, String)> {
    SECRETS
        .iter()
        .filter(|spec| !spec.config_path.contains("[]") && !spec.config_path.contains("{}"))
        .filter_map(|spec| {
            let value = spec
                .config_path
                .split('.')
                .try_fold(config, |node, key| node.get(key))?;
            Some((spec.config_path, placeholder(value)?.to_owned()))
        })
        .collect()
}

/// An env file's `NAME=value` lines, as written; comments and blanks kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFile {
    lines: Vec<String>,
}

impl EnvFile {
    pub fn parse(text: &str) -> Self {
        Self {
            lines: text.lines().map(str::to_owned).collect(),
        }
    }

    fn position(&self, name: &str) -> Option<usize> {
        self.lines.iter().position(|line| {
            let line = line.trim_start();
            let line = line.strip_prefix("export ").unwrap_or(line);
            line.split_once('=')
                .is_some_and(|(key, _)| key.trim() == name)
        })
    }

    /// The value of `name`, unquoted; `None` when absent.
    pub fn get(&self, name: &str) -> Option<String> {
        let line = &self.lines[self.position(name)?];
        let (_, value) = line.split_once('=')?;
        let value = value.trim();
        let unquoted = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        Some(unquoted.to_owned())
    }

    /// Sets `name`, replacing its line or appending one.
    pub fn set(&mut self, name: &str, value: &str) {
        let line = format!("{name}={value}");
        match self.position(name) {
            Some(at) => self.lines[at] = line,
            None => self.lines.push(line),
        }
    }

    pub fn render(&self) -> String {
        let mut out = self.lines.join("\n");
        out.push('\n');
        out
    }
}

/// Fills every generated secret the configuration names whose variable is
/// missing or empty in `env`; answers the variables filled.
pub fn generate(config: &Value, env: &mut EnvFile) -> Vec<String> {
    let mut filled = Vec::new();
    for (path, var) in variables(config) {
        if !GENERATED.contains(&path) || filled.contains(&var) {
            continue;
        }
        if env.get(&var).is_some_and(|value| !value.is_empty()) {
            continue;
        }
        env.set(&var, &fresh());
        filled.push(var);
    }
    filled
}

/// What a rotation did: the new active key id and the rewrap domain to run
/// next, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    pub new_key_id: String,
    pub rewrap: Option<&'static str>,
}

/// Rotates key-ring secret `var`: a new key, active, in front of the old
/// ones. `today` is `YYYYMMDD`, the new key id's stem.
pub fn rotate(
    config: &Value,
    env: &mut EnvFile,
    var: &str,
    today: &str,
) -> Result<Rotated, String> {
    let path = variables(config)
        .into_iter()
        .find(|(_, name)| name == var)
        .map(|(path, _)| path)
        .ok_or_else(|| {
            format!(
                "the configuration does not name a secret by ${{{var}}}; a key ring written \
                 inline as JSON in the configuration file is rotated by editing that file"
            )
        })?;
    let spec = SECRETS
        .iter()
        .find(|spec| spec.config_path == path)
        .ok_or("unknown secret")?;
    if spec.rotation != Rotation::KeyRing || !GENERATED.contains(&path) {
        return Err(format!(
            "{path} is not a key ring this tool issues; replace its value where it was issued"
        ));
    }
    let current = env
        .get(var)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!("{var} is not set in the env file; run `attome secrets generate`")
        })?;
    let mut keys: Vec<(String, String)> = match current.strip_prefix("ring:") {
        Some(entries) => entries
            .split(';')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                entry
                    .split_once('=')
                    .map(|(id, value)| (id.trim().to_owned(), value.trim().to_owned()))
                    .ok_or_else(|| format!("{var}: a ring entry is `id=secret`"))
            })
            .collect::<Result<_, _>>()?,
        None => vec![(BARE_STRING_KEY_ID.to_owned(), current)],
    };
    let stem = format!("k{today}");
    let new_key_id = std::iter::once(stem.clone())
        .chain(('b'..='z').map(|suffix| format!("{stem}{suffix}")))
        .find(|id| keys.iter().all(|(existing, _)| existing != id))
        .ok_or("too many rotations today")?;
    keys.insert(0, (new_key_id.clone(), fresh()));
    let ring: Vec<String> = keys
        .iter()
        .map(|(id, value)| format!("{id}={value}"))
        .collect();
    env.set(var, &format!("ring:{}", ring.join(";")));
    Ok(Rotated {
        new_key_id,
        rewrap: REWRAP
            .iter()
            .find(|(ring_path, _)| *ring_path == path)
            .map(|(_, domain)| *domain),
    })
}

/// Writes `text` to `path` through a temporary file and a rename.
fn write_atomically(path: &Path, text: &str) -> Result<(), String> {
    let tmp = path.with_extension("secrets-tmp");
    std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_config(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn read_env(path: &Path) -> Result<EnvFile, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(EnvFile::parse(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(EnvFile::parse("")),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// The parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    Generate {
        env: PathBuf,
        config: PathBuf,
    },
    Rotate {
        var: String,
        env: PathBuf,
        config: PathBuf,
    },
    Rewrap {
        domain: String,
        url: String,
        api_key: Option<String>,
    },
}

fn parse(args: &[String]) -> Result<Command, String> {
    let (verb, rest) = args.split_first().ok_or(USAGE)?;
    let mut positional = Vec::new();
    let mut env_file = None;
    let mut config = PathBuf::from(attome_config::AppConfig::config_file_path());
    let mut url = "http://127.0.0.1:7865".to_owned();
    let mut api_key = std::env::var("ATTOME_API_KEY").ok();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or(format!("{arg} needs a value\n{USAGE}"))
        };
        match arg.as_str() {
            "--env-file" => env_file = Some(PathBuf::from(value()?)),
            "--config" => config = PathBuf::from(value()?),
            "--url" => url = value()?.trim_end_matches('/').to_owned(),
            "--api-key" => api_key = Some(value()?),
            flag if flag.starts_with("--") => {
                return Err(format!("unknown option `{flag}`\n{USAGE}"));
            }
            _ => positional.push(arg.clone()),
        }
    }
    let env = || {
        env_file
            .clone()
            .ok_or(format!("--env-file is required\n{USAGE}"))
    };
    match (verb.as_str(), positional.as_slice()) {
        ("generate", []) => Ok(Command::Generate {
            env: env()?,
            config,
        }),
        ("rotate", [var]) => Ok(Command::Rotate {
            var: var.clone(),
            env: env()?,
            config,
        }),
        ("rewrap", [domain]) if REWRAP.iter().any(|(_, d)| d == domain) => Ok(Command::Rewrap {
            domain: domain.clone(),
            url,
            api_key,
        }),
        _ => Err(USAGE.to_owned()),
    }
}

#[tokio::main]
async fn rewrap(domain: &str, url: &str, api_key: Option<String>) -> Result<(), String> {
    let api_key =
        api_key.ok_or("an administrator's API key is needed: --api-key or ATTOME_API_KEY")?;
    // Q21-T1: `url` is the operator's own server, named on the command line.
    let purpose = attome_outbound::http::Purpose::public("cli-secrets").with_private_urls([url]);
    let client = attome_outbound::http::client(purpose, |b| b.timeout(Duration::from_secs(30)))
        .map_err(|e| e.to_string())?;
    let response = client
        .post(format!("{url}/api/v1/admin/security/rewrap/{domain}"))
        .header("authorization", format!("ApiKey {api_key}"))
        .send()
        .await
        .map_err(|e| format!("{url}: {e}"))?;
    let status = response.status();
    let body: Value = response.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        let detail = body["message"]
            .as_str()
            .or(body["error"].as_str())
            .unwrap_or("");
        return Err(format!("the rewrap was refused ({status}): {detail}"));
    }
    if body["approval_pending"] == Value::Bool(true) {
        println!(
            "rewrap {domain}: waiting for a second administrator's approval (request {})",
            body["approval_request_id"].as_str().unwrap_or("-")
        );
    } else {
        println!("rewrap {domain}: enqueued; it runs in the background");
    }
    Ok(())
}

/// `attome secrets`.
pub fn run(args: &[String]) -> ExitCode {
    let result = parse(args).and_then(|command| match command {
        Command::Generate { env, config } => {
            let config = read_config(&config)?;
            let mut file = read_env(&env)?;
            let filled = generate(&config, &mut file);
            if filled.is_empty() {
                println!("nothing to generate: every generated secret is already set");
                return Ok(());
            }
            write_atomically(&env, &file.render())?;
            println!("wrote {} to {}", filled.join(", "), env.display());
            Ok(())
        }
        Command::Rotate { var, env, config } => {
            let config = read_config(&config)?;
            let mut file = read_env(&env)?;
            let today = chrono::Utc::now().format("%Y%m%d").to_string();
            let rotated = rotate(&config, &mut file, &var, &today)?;
            let backup = PathBuf::from(format!("{}.bak", env.display()));
            std::fs::copy(&env, &backup).map_err(|e| format!("{}: {e}", backup.display()))?;
            write_atomically(&env, &file.render())?;
            println!(
                "rotated {var}: key {} is active from the next start; the old keys stay \
                 readable (previous file: {})",
                rotated.new_key_id,
                backup.display()
            );
            match rotated.rewrap {
                Some(domain) => println!(
                    "next: restart every node, then `attome secrets rewrap {domain}` to move \
                     stored data onto the new key"
                ),
                None => println!("next: restart every node; no rewrap needed"),
            }
            Ok(())
        }
        Command::Rewrap {
            domain,
            url,
            api_key,
        } => rewrap(&domain, &url, api_key),
    });
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            println!("attome secrets: {message}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> Value {
        json!({
            "auth": {
                "jwt_secret": "${JWT_SECRET}",
                "mfa_encryption_key": "${MFA_KEY}",
                "apikey_hash_pepper": "${PEPPER}",
                "oauth_google_client_secret": "${GOOGLE_SECRET}"
            },
            "email": { "smtp_password": "${SMTP_PASSWORD}" },
            "s2s": { "key_encryption_key": { "keys": { "a": "x" }, "active_key_id": "a" } }
        })
    }

    #[test]
    fn every_generated_secret_is_in_the_inventory() {
        for path in GENERATED {
            assert!(SECRETS.iter().any(|s| s.config_path == *path), "{path}");
        }
        for (path, _) in REWRAP {
            assert!(GENERATED.contains(path), "{path}");
        }
    }

    #[test]
    fn generate_fills_only_missing() {
        let mut env = EnvFile::parse("# kept\nJWT_SECRET=already\nMFA_KEY=\n");
        let mut filled = generate(&config(), &mut env);
        filled.sort_unstable();
        assert_eq!(filled, ["MFA_KEY", "PEPPER"]);
        assert_eq!(env.get("JWT_SECRET").as_deref(), Some("already"));
        assert_eq!(env.get("MFA_KEY").map(|v| v.len()), Some(64));
        assert!(
            env.get("SMTP_PASSWORD").is_none(),
            "a provider's credential is never invented"
        );
        assert!(env.get("GOOGLE_SECRET").is_none());
        assert!(env.render().starts_with("# kept\n"));
        assert!(
            generate(&config(), &mut env).is_empty(),
            "a second run changes nothing"
        );
    }

    #[test]
    fn rotate_keeps_old_key_second() {
        let mut env = EnvFile::parse("MFA_KEY=oldvalue\n");
        let rotated = rotate(&config(), &mut env, "MFA_KEY", "20261019").expect("rotate");
        assert_eq!(rotated.new_key_id, "k20261019");
        assert_eq!(rotated.rewrap, Some("mfa"));
        let value = env.get("MFA_KEY").expect("set");
        let ring: attome_config::KeyRing =
            serde_json::from_value(Value::String(value.clone())).expect("a ring the config reads");
        assert_eq!(ring.active_key_id, "k20261019");
        assert_eq!(ring.get(BARE_STRING_KEY_ID), Some("oldvalue"));

        let again = rotate(&config(), &mut env, "MFA_KEY", "20261019").expect("again");
        assert_eq!(again.new_key_id, "k20261019b");
        let value = env.get("MFA_KEY").expect("set");
        let ids: Vec<&str> = value["ring:".len()..]
            .split(';')
            .map(|e| e.split_once('=').expect("entry").0)
            .collect();
        assert_eq!(ids, ["k20261019b", "k20261019", BARE_STRING_KEY_ID]);
    }

    #[test]
    fn rotate_refuses_what_it_cannot_rotate() {
        let mut env = EnvFile::parse("SMTP_PASSWORD=x\nPEPPER=y\n");
        assert!(rotate(&config(), &mut env, "SMTP_PASSWORD", "20261019").is_err());
        assert!(
            rotate(&config(), &mut env, "PEPPER", "20261019").is_err(),
            "not a ring"
        );
        assert!(
            rotate(&config(), &mut env, "JWT_SECRET", "20261019").is_err(),
            "not set"
        );
        assert!(
            rotate(&config(), &mut env, "S2S_KEY", "20261019").is_err(),
            "inline JSON ring"
        );
    }

    #[test]
    fn rotate_writes_backup() {
        let dir = std::env::temp_dir().join(format!("attome-secrets-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).expect("dir");
        let env = dir.join(".env");
        let config_path = dir.join("config.json");
        std::fs::write(&env, "JWT_SECRET=first\n").expect("env");
        std::fs::write(&config_path, config().to_string()).expect("config");
        let args: Vec<String> = ["rotate", "JWT_SECRET", "--env-file"]
            .into_iter()
            .map(str::to_owned)
            .chain([
                env.display().to_string(),
                "--config".into(),
                config_path.display().to_string(),
            ])
            .collect();
        assert_eq!(run(&args), ExitCode::SUCCESS);
        let backup = std::fs::read_to_string(dir.join(".env.bak")).expect("backup");
        assert_eq!(backup, "JWT_SECRET=first\n");
        let now = EnvFile::parse(&std::fs::read_to_string(&env).expect("env"));
        assert!(now.get("JWT_SECRET").expect("set").starts_with("ring:k"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_command_line_parses() {
        let args = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(matches!(
            parse(&args(&[
                "generate",
                "--env-file",
                ".env",
                "--config",
                "c.json"
            ])),
            Ok(Command::Generate { .. })
        ));
        assert!(
            parse(&args(&["generate"])).is_err(),
            "--env-file is required"
        );
        assert!(parse(&args(&["rewrap", "nope"])).is_err());
        assert!(matches!(
            parse(&args(&["rewrap", "s2s", "--url", "http://a:1/"])),
            Ok(Command::Rewrap { url, .. }) if url == "http://a:1"
        ));
    }
}
