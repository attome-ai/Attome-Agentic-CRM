//! T4-T1: `attome login`, `attome logout` and `attome targets` — the CLI
//! signs a person in to a deployment once per named target, through the
//! device grant (RFC 8628, `docs/device-sign-in.md`), and later commands use
//! it with `--target <name>`.
//!
//! - `attome login --target prod --url https://crm.example.com` asks the
//!   deployment for a device grant, prints the code and the page to approve
//!   it on, and polls until the person decides. The session's tokens are
//!   kept in the operating system's credential store under
//!   `attome:<target>`: Windows Credential Manager on Windows, elsewhere a
//!   file only the user can read in the user's config directory. The target's
//!   URL goes in `targets.json` in that directory; the first target signed in
//!   becomes the default.
//! - `attome targets` lists the targets, the default and whether each is
//!   signed in. `attome logout --target prod` forgets its tokens.
//! - A command taking `--target` (`attome model export|import`) calls
//!   [`target_bearer`], which refreshes the access token at the device token
//!   endpoint when it is about to expire.
//!
//! The config directory is `%APPDATA%\attome` on Windows,
//! `~/Library/Application Support/attome` on macOS and
//! `$XDG_CONFIG_HOME/attome` (or `~/.config/attome`) elsewhere;
//! `ATTOME_CONFIG_DIR` overrides it.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The CLI's device grant client id.
pub const CLIENT_ID: &str = "attome-cli";
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// An access token this close to expiry is refreshed before use.
const REFRESH_MARGIN_SECS: i64 = 60;

const USAGE: &str = "usage: attome login --target <name> --url <url>\n       attome logout --target <name>\n       attome targets";

/// The named deployments the user signs in to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Targets {
    /// The target a command uses when it names none.
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub targets: BTreeMap<String, Target>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub url: String,
    /// T4-T5: a writing command here also needs `--confirm-target <name>`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub production: bool,
}

/// A target's session, as the credential store keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix seconds when the access token expires.
    pub expires_at: i64,
}

/// Where a target's tokens are kept. One entry per target.
pub trait CredentialStore {
    fn get(&self, target: &str) -> Result<Option<Tokens>, String>;
    fn set(&self, target: &str, tokens: &Tokens) -> Result<(), String>;
    fn delete(&self, target: &str) -> Result<(), String>;
}

/// A target name: letters, digits, `-` and `_`, at most 64. Pure.
pub fn valid_target(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The CLI's config directory (see the module docs).
pub fn config_dir() -> Result<PathBuf, String> {
    if let Ok(dir) = std::env::var("ATTOME_CONFIG_DIR")
        && !dir.trim().is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    let home = || std::env::var("HOME").ok().filter(|h| !h.is_empty());
    let base = if cfg!(windows) {
        std::env::var("APPDATA").ok().map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home().map(|h| PathBuf::from(h).join("Library/Application Support"))
    } else {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| home().map(|h| PathBuf::from(h).join(".config")))
    };
    base.map(|b| b.join("attome"))
        .ok_or_else(|| "cannot find the user's config directory; set ATTOME_CONFIG_DIR".to_owned())
}

impl Targets {
    pub fn load(dir: &std::path::Path) -> Result<Self, String> {
        let path = dir.join("targets.json");
        match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|error| format!("read {}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("read {}: {error}", path.display())),
        }
    }

    pub fn save(&self, dir: &std::path::Path) -> Result<(), String> {
        std::fs::create_dir_all(dir)
            .map_err(|error| format!("create {}: {error}", dir.display()))?;
        let path = dir.join("targets.json");
        let text = serde_json::to_string_pretty(self).map_err(|error| error.to_string())?;
        std::fs::write(&path, text + "\n")
            .map_err(|error| format!("write {}: {error}", path.display()))
    }

    /// The target `name`, or the default when `name` is `None`.
    pub fn resolve(&self, name: Option<&str>) -> Result<(String, Target), String> {
        let name = name
            .map(str::to_owned)
            .or_else(|| self.default.clone())
            .ok_or_else(|| {
                "no target named and no default target; run `attome login`".to_owned()
            })?;
        let target = self.targets.get(&name).cloned().ok_or_else(|| {
            format!("no target `{name}`; run `attome login --target {name} --url <url>`")
        })?;
        Ok((name, target))
    }
}

/// A target's tokens in a file only the user can read
/// (`<config>/credentials/<target>.json`), for systems without a credential
/// store this build talks to.
#[derive(Debug, Clone)]
pub struct FileCredentials {
    pub dir: PathBuf,
}

impl FileCredentials {
    fn path(&self, target: &str) -> PathBuf {
        self.dir.join("credentials").join(format!("{target}.json"))
    }
}

impl CredentialStore for FileCredentials {
    fn get(&self, target: &str) -> Result<Option<Tokens>, String> {
        match std::fs::read_to_string(self.path(target)) {
            Ok(text) => serde_json::from_str(&text)
                .map(Some)
                .map_err(|error| error.to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn set(&self, target: &str, tokens: &Tokens) -> Result<(), String> {
        let path = self.path(target);
        let dir = path.parent().unwrap_or(&self.dir).to_path_buf();
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("create {}: {error}", dir.display()))?;
        let text = serde_json::to_string(tokens).map_err(|error| error.to_string())?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        std::io::Write::write_all(&mut file, text.as_bytes())
            .map_err(|error| format!("write {}: {error}", path.display()))
    }

    fn delete(&self, target: &str) -> Result<(), String> {
        match std::fs::remove_file(self.path(target)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// Windows Credential Manager: one generic credential `attome:<target>` per
/// target, kept for this user on this machine.
#[cfg(windows)]
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsCredentials;

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "the Win32 Credential Manager is a C API; each call is documented and its result checked"
)]
mod windows_store {
    use super::{CredentialStore, Tokens, WindowsCredentials};
    use windows_sys::Win32::Security::Credentials::{
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree,
        CredReadW, CredWriteW,
    };

    /// `CRED_MAX_CREDENTIAL_BLOB_SIZE`.
    const MAX_BLOB: usize = 5 * 512;
    const ERROR_NOT_FOUND: i32 = 1168;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn name(target: &str) -> Vec<u16> {
        wide(&format!("attome:{target}"))
    }

    fn not_found() -> bool {
        std::io::Error::last_os_error().raw_os_error() == Some(ERROR_NOT_FOUND)
    }

    impl CredentialStore for WindowsCredentials {
        fn get(&self, target: &str) -> Result<Option<Tokens>, String> {
            let name = name(target);
            let mut found: *mut CREDENTIALW = std::ptr::null_mut();
            // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives
            // the call; `found` receives a buffer the system allocates, read
            // only while it lives and released with `CredFree` exactly once.
            unsafe {
                if CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut found) == 0 {
                    return if not_found() {
                        Ok(None)
                    } else {
                        Err(format!(
                            "read the Credential Manager: {}",
                            std::io::Error::last_os_error()
                        ))
                    };
                }
                let credential = &*found;
                // An empty blob may come with a null pointer, which
                // `from_raw_parts` must never be given.
                let blob =
                    if credential.CredentialBlob.is_null() || credential.CredentialBlobSize == 0 {
                        Vec::new()
                    } else {
                        std::slice::from_raw_parts(
                            credential.CredentialBlob,
                            credential.CredentialBlobSize as usize,
                        )
                        .to_vec()
                    };
                CredFree(found.cast());
                serde_json::from_slice(&blob)
                    .map(Some)
                    .map_err(|error| error.to_string())
            }
        }

        fn set(&self, target: &str, tokens: &Tokens) -> Result<(), String> {
            let mut blob = serde_json::to_vec(tokens).map_err(|error| error.to_string())?;
            if blob.len() > MAX_BLOB {
                return Err("the session is too large for the Credential Manager".into());
            }
            let mut name = name(target);
            let mut user = wide("attome");
            // SAFETY: `credential` is zero-initialised (a valid empty
            // CREDENTIALW) and every pointer it holds (`name`, `user`,
            // `blob`) points into a buffer that outlives `CredWriteW`, which
            // copies them.
            unsafe {
                let mut credential: CREDENTIALW = std::mem::zeroed();
                credential.Type = CRED_TYPE_GENERIC;
                credential.TargetName = name.as_mut_ptr();
                credential.UserName = user.as_mut_ptr();
                credential.CredentialBlobSize =
                    u32::try_from(blob.len()).map_err(|_| "the session is too large".to_owned())?;
                credential.CredentialBlob = blob.as_mut_ptr();
                credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
                if CredWriteW(&credential, 0) == 0 {
                    return Err(format!(
                        "write the Credential Manager: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            Ok(())
        }

        fn delete(&self, target: &str) -> Result<(), String> {
            let name = name(target);
            // SAFETY: `name` is a NUL-terminated UTF-16 string that outlives
            // the call.
            unsafe {
                if CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) == 0 && !not_found() {
                    return Err(format!(
                        "delete from the Credential Manager: {}",
                        std::io::Error::last_os_error()
                    ));
                }
            }
            Ok(())
        }
    }
}

/// The credential store of this system.
pub fn system_store(dir: &std::path::Path) -> Box<dyn CredentialStore> {
    #[cfg(windows)]
    {
        let _ = dir;
        Box::new(WindowsCredentials)
    }
    #[cfg(not(windows))]
    {
        Box::new(FileCredentials {
            dir: dir.to_path_buf(),
        })
    }
}

/// A parsed `attome login|logout|targets` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginCommand {
    Login {
        target: String,
        url: String,
        production: bool,
    },
    Logout {
        target: String,
    },
    Targets,
}

/// Parses `attome <verb> <args>` for the three verbs. Pure.
pub fn parse(verb: &str, args: &[String]) -> Result<LoginCommand, String> {
    let mut target: Option<String> = None;
    let mut url: Option<String> = None;
    let mut production = false;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match (verb, flag.as_str()) {
            ("login" | "logout", "--target") => target = Some(value()?),
            ("login", "--url") => url = Some(value()?),
            ("login", "--production") => production = true,
            _ => return Err(format!("unknown flag `{flag}`\n{USAGE}")),
        }
    }
    let named = |target: Option<String>| {
        let target = target.ok_or_else(|| format!("--target is required\n{USAGE}"))?;
        if valid_target(&target) {
            Ok(target)
        } else {
            Err("a target name is letters, digits, `-` and `_`".to_owned())
        }
    };
    match verb {
        "login" => {
            let url = url.ok_or_else(|| format!("--url is required\n{USAGE}"))?;
            let url = url.trim().trim_end_matches('/').to_owned();
            if !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err("--url is the deployment's http(s) address".into());
            }
            Ok(LoginCommand::Login {
                target: named(target)?,
                url,
                production,
            })
        }
        "logout" => Ok(LoginCommand::Logout {
            target: named(target)?,
        }),
        "targets" => Ok(LoginCommand::Targets),
        _ => Err(USAGE.to_owned()),
    }
}

/// Runs `attome login|logout|targets`.
pub fn run(verb: &str, args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let json = crate::cmd::output::take_flag(&mut args, "--json");
    let command = parse(verb, &args)?;
    let dir = config_dir()?;
    let store = system_store(&dir);
    match command {
        LoginCommand::Targets => {
            let targets = Targets::load(&dir)?;
            if json {
                let mut listed = Vec::new();
                for (name, target) in &targets.targets {
                    listed.push(serde_json::json!({
                        "name": name,
                        "url": target.url,
                        "production": target.production,
                        "signed_in": store.get(name)?.is_some(),
                    }));
                }
                let out = crate::cmd::output::envelope(
                    "targets",
                    serde_json::json!({ "default": targets.default, "targets": listed }),
                );
                println!("{out}");
                return Ok(());
            }
            if targets.targets.is_empty() {
                println!("no targets; run `attome login --target <name> --url <url>`");
            }
            for (name, target) in &targets.targets {
                let mark = if targets.default.as_deref() == Some(name) {
                    "*"
                } else {
                    " "
                };
                let state = if store.get(name)?.is_some() {
                    "signed in"
                } else {
                    "signed out"
                };
                println!("{mark} {name}\t{}\t{state}", target.url);
            }
            Ok(())
        }
        LoginCommand::Logout { target } => {
            store.delete(&target)?;
            if json {
                let out = crate::cmd::output::envelope(
                    "logout",
                    serde_json::json!({ "target": target, "signed_in": false }),
                );
                println!("{out}");
            } else {
                println!("signed out of {target}");
            }
            Ok(())
        }
        LoginCommand::Login {
            target,
            url,
            production,
        } => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| format!("start the runtime: {error}"))?;
            let tokens = runtime.block_on(device_login(&url, json))?;
            store.set(&target, &tokens)?;
            let mut targets = Targets::load(&dir)?;
            targets.targets.insert(
                target.clone(),
                Target {
                    url: url.clone(),
                    production,
                },
            );
            if targets.default.is_none() {
                targets.default = Some(target.clone());
            }
            targets.save(&dir)?;
            if json {
                let out = crate::cmd::output::envelope(
                    "login",
                    serde_json::json!({
                        "target": target, "url": url, "production": production, "signed_in": true,
                    }),
                );
                println!("{out}");
            } else {
                println!("signed in to {target} ({url})");
            }
            Ok(())
        }
    }
}

/// `url` is the operator's own deployment, named on the command line.
fn client(url: &str) -> Result<attome_outbound::http::Outbound, String> {
    let purpose = attome_outbound::http::Purpose::public("cli-login").with_private_urls([url]);
    attome_outbound::http::client(purpose, |b| b.timeout(std::time::Duration::from_secs(30)))
        .map_err(|error| format!("build the HTTP client: {error}"))
}

async fn form(
    http: &attome_outbound::http::Outbound,
    url: &str,
    path: &str,
    fields: &[(&str, &str)],
) -> Result<(reqwest::StatusCode, Value), String> {
    let response = http
        .post(format!("{url}{path}"))
        .form(fields)
        .send()
        .await
        .map_err(|error| format!("reach {url}: {error}"))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .map_err(|error| format!("read the response: {error}"))?;
    Ok((status, body))
}

/// The session `body` (a token response) carries. Pure.
pub fn tokens_of(body: &Value, now: i64) -> Result<Tokens, String> {
    let text = |key: &str| {
        body[key]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("the server sent no {key}"))
    };
    Ok(Tokens {
        access_token: text("access_token")?,
        refresh_token: text("refresh_token")?,
        expires_at: now + body["expires_in"].as_i64().unwrap_or(0),
    })
}

/// The device flow against `url` (see the module docs).
/// With `json`, what the person must do goes to standard error, so standard
/// output carries only the JSON answer.
async fn device_login(url: &str, json: bool) -> Result<Tokens, String> {
    let say = |line: String| {
        if json {
            eprintln!("{line}");
        } else {
            println!("{line}");
        }
    };
    let http = client(url)?;
    let (status, grant) = form(
        &http,
        url,
        "/api/v1/oauth/device_authorization",
        &[("client_id", CLIENT_ID)],
    )
    .await?;
    if !status.is_success() {
        return Err(format!("the server refused the sign-in: {status} {grant}"));
    }
    let device_code = grant["device_code"]
        .as_str()
        .ok_or("the server sent no device code")?
        .to_owned();
    say(format!(
        "To sign in, open {} and enter the code {}",
        grant["verification_uri"].as_str().unwrap_or_default(),
        grant["user_code"].as_str().unwrap_or_default()
    ));
    if let Some(link) = grant["verification_uri_complete"].as_str() {
        say(format!("(or open {link})"));
    }
    let mut interval = grant["interval"].as_u64().unwrap_or(5).max(1);
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(grant["expires_in"].as_u64().unwrap_or(600));
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        if std::time::Instant::now() > deadline {
            return Err("the code expired before it was approved; run `attome login` again".into());
        }
        let (status, body) = form(
            &http,
            url,
            "/api/v1/oauth/device/token",
            &[
                ("grant_type", DEVICE_CODE_GRANT),
                ("client_id", CLIENT_ID),
                ("device_code", &device_code),
            ],
        )
        .await?;
        if status.is_success() {
            return tokens_of(&body, chrono::Utc::now().timestamp());
        }
        match body["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some("access_denied") => return Err("the sign-in was denied".into()),
            Some("expired_token") => {
                return Err(
                    "the code expired before it was approved; run `attome login` again".into(),
                );
            }
            _ => return Err(format!("the server refused the sign-in: {status} {body}")),
        }
    }
}

/// The `Authorization` header value a command sends, if any.
pub type Auth = Option<String>;

/// The server and credential a command uses: a signed-in target's URL and
/// bearer token, else `url` and the API key (`ApiKey <public>:<secret>`).
pub async fn credentials(
    url: String,
    api_key: Option<String>,
    target: Option<String>,
) -> Result<(String, Auth), String> {
    match target {
        Some(target) => {
            let (url, token) = target_bearer(Some(&target)).await?;
            Ok((url, Some(format!("Bearer {token}"))))
        }
        None => Ok((url, api_key.map(|key| format!("ApiKey {key}")))),
    }
}

/// T4-T5: whether the target `name` (or the default) is marked production.
pub fn is_production(name: Option<&str>) -> bool {
    config_dir()
        .and_then(|dir| Targets::load(&dir))
        .and_then(|targets| targets.resolve(name))
        .is_ok_and(|(_, target)| target.production)
}

/// The URL and a live access token of `target` (or the default), refreshed
/// at the device token endpoint when it is about to expire.
pub async fn target_bearer(target: Option<&str>) -> Result<(String, String), String> {
    let dir = config_dir()?;
    let (name, found) = Targets::load(&dir)?.resolve(target)?;
    let store = system_store(&dir);
    bearer_from(&*store, &name, &found.url, chrono::Utc::now().timestamp()).await
}

async fn bearer_from(
    store: &dyn CredentialStore,
    name: &str,
    url: &str,
    now: i64,
) -> Result<(String, String), String> {
    let tokens = store.get(name)?.ok_or_else(|| {
        format!("not signed in to `{name}`; run `attome login --target {name} --url {url}`")
    })?;
    if tokens.expires_at - REFRESH_MARGIN_SECS > now {
        return Ok((url.to_owned(), tokens.access_token));
    }
    let http = client(url)?;
    let (status, body) = form(
        &http,
        url,
        "/api/v1/oauth/device/token",
        &[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", &tokens.refresh_token),
        ],
    )
    .await?;
    if !status.is_success() {
        store.delete(name)?;
        return Err(format!(
            "the session for `{name}` has ended; run `attome login --target {name} --url {url}`"
        ));
    }
    let fresh = tokens_of(&body, now)?;
    store.set(name, &fresh)?;
    Ok((url.to_owned(), fresh.access_token))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test code: a failed step should panic with its message"
)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A credential store in memory, standing in for the system's.
    #[derive(Default)]
    struct FakeStore(RefCell<BTreeMap<String, Tokens>>);

    impl CredentialStore for FakeStore {
        fn get(&self, target: &str) -> Result<Option<Tokens>, String> {
            Ok(self.0.borrow().get(target).cloned())
        }
        fn set(&self, target: &str, tokens: &Tokens) -> Result<(), String> {
            self.0
                .borrow_mut()
                .insert(target.to_owned(), tokens.clone());
            Ok(())
        }
        fn delete(&self, target: &str) -> Result<(), String> {
            self.0.borrow_mut().remove(target);
            Ok(())
        }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    fn tokens(expires_at: i64) -> Tokens {
        Tokens {
            access_token: "a.b.c".into(),
            refresh_token: "r".into(),
            expires_at,
        }
    }

    #[test]
    fn commands_parse() {
        assert_eq!(
            parse(
                "login",
                &args(&["--target", "prod", "--url", "https://crm.example.com/"])
            ),
            Ok(LoginCommand::Login {
                target: "prod".into(),
                url: "https://crm.example.com".into(),
                production: false,
            })
        );
        assert!(parse("login", &args(&["--target", "prod"])).is_err());
        assert!(parse("login", &args(&["--target", "../x", "--url", "https://a"])).is_err());
        assert!(parse("login", &args(&["--target", "p", "--url", "ftp://a"])).is_err());
        assert_eq!(
            parse("logout", &args(&["--target", "prod"])),
            Ok(LoginCommand::Logout {
                target: "prod".into()
            })
        );
        assert_eq!(parse("targets", &[]), Ok(LoginCommand::Targets));
    }

    #[test]
    fn targets_are_stored_in_the_config_directory() {
        let dir = std::env::temp_dir().join(format!("attome-targets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(Targets::load(&dir), Ok(Targets::default()));
        let mut targets = Targets::default();
        targets.targets.insert(
            "prod".into(),
            Target {
                url: "https://a".into(),
                production: true,
            },
        );
        targets.default = Some("prod".into());
        targets.save(&dir).expect("save");
        let loaded = Targets::load(&dir).expect("load");
        assert_eq!(loaded, targets);
        assert_eq!(loaded.resolve(None).map(|(n, _)| n), Ok("prod".to_owned()));
        assert!(loaded.resolve(Some("staging")).is_err());

        let file = FileCredentials { dir: dir.clone() };
        assert_eq!(file.get("prod"), Ok(None));
        file.set("prod", &tokens(10)).expect("set");
        assert_eq!(file.get("prod"), Ok(Some(tokens(10))));
        file.delete("prod").expect("delete");
        assert_eq!(file.get("prod"), Ok(None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_live_token_is_used_and_a_missing_one_asks_to_sign_in() {
        let store = FakeStore::default();
        assert!(bearer_from(&store, "prod", "https://a", 100).await.is_err());
        store.set("prod", &tokens(1_000)).expect("set");
        assert_eq!(
            bearer_from(&store, "prod", "https://a", 100).await,
            Ok(("https://a".to_owned(), "a.b.c".to_owned()))
        );
    }

    #[test]
    fn a_token_response_becomes_a_session() {
        let body = serde_json::json!({
            "access_token": "x.y.z", "refresh_token": "id.secret", "expires_in": 900, "token_type": "Bearer"
        });
        assert_eq!(
            tokens_of(&body, 1_000),
            Ok(Tokens {
                access_token: "x.y.z".into(),
                refresh_token: "id.secret".into(),
                expires_at: 1_900
            })
        );
        assert!(tokens_of(&serde_json::json!({}), 0).is_err());
    }
}
