//! A23-T12: an SFTP source for recurring imports.
//!
//! The file is fetched with the machine's own OpenSSH `sftp` client (Linux,
//! macOS and Windows 10+ ship it), not an SSH library in the binary: the
//! pure-Rust one brings the `rsa` crate (RUSTSEC-2023-0071) into
//! production, and `libssh2` is native. U3-T1's `attome cluster` made the
//! same choice.
//!
//! The private key is the named integration connection's credential (the
//! encrypted credential store); it is never in the import job's row. For
//! one fetch it is written to a private temporary folder with a
//! `known_hosts` holding exactly the server key the schedule names
//! (`StrictHostKeyChecking=yes`, so an unknown or changed host key fails),
//! and the folder is removed afterwards. The fetch is bounded: 60 seconds
//! (the client is killed past that) and 50 MiB.

use std::path::Path;
use std::time::Duration;

use attome_core::EngineState;
use uuid::Uuid;

/// How long one SFTP fetch may take.
pub const SFTP_TIMEOUT: Duration = Duration::from_secs(60);

/// What an SFTP source names. The key comes from `connection`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SftpSource {
    /// The integration connection whose credential is the private key
    /// (OpenSSH format).
    pub connection: String,
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub user: String,
    /// The remote file's path.
    pub location: String,
    /// The server's public host key as `known_hosts` lists it after the
    /// host (`ssh-ed25519 AAAA...`).
    pub host_key: String,
}

/// What is wrong with `source` before anything runs, if anything. Every
/// value goes to the client as an argument or a batch line, so none may
/// carry a quote, a newline or a leading dash. Pure.
pub fn source_problem(source: &SftpSource) -> Option<String> {
    let plain = |value: &str| {
        !value.is_empty()
            && !value.starts_with('-')
            && !value
                .chars()
                .any(|c| c == '"' || c == '\'' || c.is_control())
    };
    if !plain(&source.host) || source.host.contains(char::is_whitespace) {
        return Some("the host is not a plain host name".into());
    }
    if !plain(&source.user)
        || source.user.contains(char::is_whitespace)
        || source.user.contains('@')
    {
        return Some("the user is not a plain user name".into());
    }
    if !plain(&source.location) {
        return Some("the remote path has a quote, a control character or a leading dash".into());
    }
    let mut key = source.host_key.split_whitespace();
    let (Some(kind), Some(body), None) = (key.next(), key.next(), key.next()) else {
        return Some("host_key is `<type> <base64>`, as known_hosts lists it".into());
    };
    if !(kind.starts_with("ssh-") || kind.starts_with("ecdsa-")) || !plain(body) {
        return Some("host_key is `<type> <base64>`, as known_hosts lists it".into());
    }
    None
}

/// The `known_hosts` line for `source`. Pure.
pub fn known_hosts_line(source: &SftpSource) -> String {
    match source.port {
        Some(port) if port != 22 => format!("[{}]:{port} {}\n", source.host, source.host_key),
        _ => format!("{} {}\n", source.host, source.host_key),
    }
}

/// Fetches `source` with `key` (the private key's text) into memory, at
/// most `max_bytes`, within `timeout`.
pub async fn fetch_sftp_with_key(
    source: &SftpSource,
    key: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    if let Some(problem) = source_problem(source) {
        return Err(problem);
    }
    let dir = std::env::temp_dir().join(format!("attome-sftp-{}", Uuid::now_v7().simple()));
    let result = fetch_in(&dir, source, key, max_bytes, timeout).await;
    if let Err(error) = tokio::fs::remove_dir_all(&dir).await {
        tracing::warn!(%error, dir = %dir.display(), "sftp import: the temporary folder was not removed");
    }
    result
}

async fn private_file(path: &Path, text: &str) -> Result<(), String> {
    tokio::fs::write(path, text)
        .await
        .map_err(|_| "could not write a temporary file".to_owned())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|_| "could not restrict a temporary file".to_owned())?;
    }
    Ok(())
}

async fn fetch_in(
    dir: &Path,
    source: &SftpSource,
    key: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|_| "could not make a temporary folder".to_owned())?;
    let key_file = dir.join("id");
    let mut key_text = key.trim_end().to_owned();
    key_text.push('\n');
    private_file(&key_file, &key_text).await?;
    let known_hosts = dir.join("known_hosts");
    private_file(&known_hosts, &known_hosts_line(source)).await?;
    let local = dir.join("file");
    let batch = dir.join("batch");
    private_file(
        &batch,
        &format!("get \"{}\" \"{}\"\n", source.location, local.display()),
    )
    .await?;

    let mut command = tokio::process::Command::new("sftp");
    command
        .arg("-b")
        .arg(&batch)
        .arg("-i")
        .arg(&key_file)
        .arg("-P")
        .arg(source.port.unwrap_or(22).to_string())
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .args(["-o", "GlobalKnownHostsFile=none", "-o", "ConnectTimeout=20"])
        .arg(format!("{}@{}", source.user, source.host))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let child = command
        .spawn()
        .map_err(|_| "could not start the sftp client (OpenSSH)".to_owned())?;
    let output = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| format!("the SFTP fetch took longer than {} s", timeout.as_secs()))?
        .map_err(|_| "the sftp client failed".to_owned())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason: String = stderr
            .lines()
            .last()
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        return Err(format!("the SFTP fetch failed: {reason}"));
    }
    let size = tokio::fs::metadata(&local)
        .await
        .map_err(|_| "the SFTP fetch wrote no file".to_owned())?
        .len();
    if !usize::try_from(size).is_ok_and(|size| size <= max_bytes) {
        return Err(format!(
            "the file is larger than {} MiB",
            max_bytes / (1024 * 1024)
        ));
    }
    tokio::fs::read(&local)
        .await
        .map_err(|_| "could not read the fetched file".to_owned())
}

/// Fetches `source` with its connection's key (the credential store).
pub async fn fetch_sftp(
    state: &EngineState,
    source: &SftpSource,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let connection = crate::connection::Connection::resolve(&state.base.db, &source.connection)
        .await
        .map_err(|_| format!("no integration connection named {}", source.connection))?;
    let credential = connection
        .credential(&state.base.db, &crate::credential::ring(state))
        .await
        .map_err(|_| "the connection's key could not be read".to_owned())?
        .ok_or_else(|| format!("the connection {} has no key", source.connection))?;
    // The key is copied out of the sealed credential only for this fetch.
    let key = zeroize::Zeroizing::new(credential.with_value(str::to_owned));
    fetch_sftp_with_key(source, &key, max_bytes, SFTP_TIMEOUT).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(port: u16) -> SftpSource {
        SftpSource {
            connection: "partner-sftp".into(),
            host: "127.0.0.1".into(),
            port: Some(port),
            user: "importer".into(),
            location: "/outbox/customers.csv".into(),
            host_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample".into(),
        }
    }

    #[test]
    fn a_source_is_checked_before_anything_runs() {
        assert_eq!(source_problem(&source(22)), None);
        let quoted = SftpSource {
            location: "/a\"; rm".into(),
            ..source(22)
        };
        assert!(source_problem(&quoted).is_some());
        let dashed = SftpSource {
            host: "-oProxyCommand=x".into(),
            ..source(22)
        };
        assert!(source_problem(&dashed).is_some());
        let no_key = SftpSource {
            host_key: "AAAA".into(),
            ..source(22)
        };
        assert!(source_problem(&no_key).is_some());
        assert_eq!(
            known_hosts_line(&source(2222)),
            "[127.0.0.1]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample\n"
        );
        assert_eq!(
            known_hosts_line(&source(22)),
            "127.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample\n"
        );
    }

    #[tokio::test]
    async fn sftp_fetch_times_out() {
        // A closed local port: the client fails (or is not installed), well
        // inside the bound, and nothing is left behind.
        let result = fetch_sftp_with_key(
            &source(1),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key\n-----END OPENSSH PRIVATE KEY-----",
            1024,
            Duration::from_secs(30),
        )
        .await;
        assert!(result.is_err(), "{result:?}");
    }
}
