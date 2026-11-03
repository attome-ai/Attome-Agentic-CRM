//! T5-T3 (V2-D274): a Develop workspace is served by a process of its own.
//!
//! The engine keeps process-wide caches (the cooked model registry, extension
//! and switch snapshots and the like); a workspace sharing live's process
//! would leak its metadata into them. So each open workspace in use gets its
//! own `attome serve --workspace <id> --workspace-port <port>`: the same
//! binary and configuration, with `database.schema` set to
//! `ws_<id>,<live schema>` so an unqualified table resolves to the
//! workspace's copy first and to live otherwise (people, sessions, audit and
//! jobs stay shared), migrations and job workers off, and bound to 127.0.0.1.
//!
//! - **Workspace side.** [`workspace_arg`] and [`prepare`] turn the loaded
//!   configuration into the workspace's; [`require_token`] refuses every
//!   request without the token the live server gave the process, so nothing
//!   reaches it by its port alone.
//! - **Live side.** [`WorkspaceHosts`] is the
//!   [`attome_api::workspace::proxy::WorkspaceForwarder`]: it starts a
//!   workspace's process on first use (ready within [`START_WAIT`]), proxies
//!   the request to it, and stops it after [`IDLE_STOP`] unused.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use attome_api::workspace::proxy::WorkspaceForwarder;
use attome_config::AppConfig;
use attome_types::AppError;
use axum::{
    body::Body,
    extract::Request,
    http::{HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use tokio::sync::Mutex;
use uuid::Uuid;

/// The flag naming the workspace a `serve` process serves.
pub const WORKSPACE_FLAG: &str = "--workspace";
/// The flag naming the port it binds.
pub const PORT_FLAG: &str = "--workspace-port";
/// The environment variable carrying the token the live server gave it.
pub const TOKEN_VAR: &str = "ATTOME_WORKSPACE_TOKEN";
/// The header the live server sends the token in.
pub const TOKEN_HEADER: &str = "x-attome-workspace-token";
/// How long a starting workspace process has to answer `/health`.
pub const START_WAIT: Duration = Duration::from_secs(30);
/// How long a workspace process may sit unused before it is stopped.
pub const IDLE_STOP: Duration = Duration::from_secs(15 * 60);
/// The most bytes of a request or a response proxied.
const MAX_BODY: usize = 64 * 1024 * 1024;

// ── Workspace side ──────────────────────────────────────────────────────────

/// The value after `flag` on the command line, as `--flag v` or `--flag=v`.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let prefix = format!("{flag}=");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value.to_owned());
        }
        if arg == flag {
            return iter.next().cloned();
        }
    }
    None
}

/// The workspace and port `attome serve` was started for, if any.
pub fn workspace_arg() -> Option<(Uuid, u16)> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let id = flag_value(&args, WORKSPACE_FLAG)?.parse().ok()?;
    let port = flag_value(&args, PORT_FLAG)?.parse().ok()?;
    Some((id, port))
}

/// The configuration a workspace process runs on: the workspace schema
/// first on the search path, no migrations, no job workers, no packs, no
/// metrics listener, plain HTTP on 127.0.0.1:`port`. Pure.
pub fn workspace_config(mut config: AppConfig, schema: &str, live: &str, port: u16) -> AppConfig {
    config.database.schema = format!("{schema},{live}");
    config.database.migrate_on_boot = false;
    config.jobs.run_worker_inline = false;
    config.app.packs = Vec::new();
    config.app.port = port;
    config.app.server_host = "127.0.0.1".to_owned();
    config.app.tls.enabled = false;
    config.observability.metrics_port = 0;
    config.observability.builtin_store = Some(false);
    config
}

/// Reads workspace `id` from the live database and answers the configuration
/// its process runs on; refuses a workspace that is not open.
pub async fn prepare(config: AppConfig, id: Uuid, port: u16) -> Result<AppConfig, String> {
    let db = attome_db::create_pool(&config)
        .await
        .map_err(|e| format!("workspace {id}: connect: {e}"))?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT schema_name, status FROM develop_workspace WHERE id = $1")
            .bind(id)
            .fetch_optional(&db)
            .await
            .map_err(|e| format!("workspace {id}: read: {e}"))?;
    let (schema, status) = row.ok_or_else(|| format!("workspace {id} does not exist"))?;
    if status != "open" {
        return Err(format!("workspace {id} is {status}, not open"));
    }
    if !attome_api::workspace::schema::is_workspace_schema(&schema) {
        return Err(format!("workspace {id} names no workspace schema"));
    }
    let live: String = sqlx::query_scalar("SELECT current_schema()::text")
        .fetch_one(&db)
        .await
        .map_err(|e| format!("workspace {id}: live schema: {e}"))?;
    db.close().await;
    Ok(workspace_config(config, &schema, &live, port))
}

/// Whether `given` is the expected token, compared in constant time. Pure.
pub fn token_matches(expected: &str, given: &str) -> bool {
    let (a, b) = (expected.as_bytes(), given.as_bytes());
    if a.len() != b.len() || a.is_empty() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The workspace process's outermost layer: a request without the live
/// server's token is refused.
pub async fn require_token(expected: Arc<String>, request: Request, next: Next) -> Response {
    let given = request
        .headers()
        .get(TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if token_matches(&expected, given) {
        next.run(request).await
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

// ── Live side ───────────────────────────────────────────────────────────────

/// One running workspace process.
#[derive(Debug)]
struct Host {
    child: tokio::process::Child,
    port: u16,
    token: String,
    last_used: Instant,
}

/// The live server's workspace processes, by workspace.
#[derive(Debug)]
pub struct WorkspaceHosts {
    hosts: Mutex<HashMap<Uuid, Host>>,
    client: attome_outbound::http::Outbound,
}

impl WorkspaceHosts {
    /// The hosts, with a reaper stopping idle ones.
    pub fn start() -> Result<Arc<Self>, String> {
        let client = attome_outbound::http::client(
            attome_outbound::http::Purpose::public("workspace_host")
                .with_private_hosts(["127.0.0.1".to_owned()])
                .no_redirects(),
            |builder| builder.timeout(Duration::from_secs(300)),
        )
        .map_err(|e| format!("workspace host client: {e}"))?;
        let hosts = Arc::new(Self {
            hosts: Mutex::new(HashMap::new()),
            client,
        });
        let reaper = Arc::clone(&hosts);
        // Process-lifetime supervision (guidelines §10): stops idle workspace
        // processes; losing it only leaves them running.
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                reaper.stop_idle().await;
            }
        });
        Ok(hosts)
    }

    async fn stop_idle(&self) {
        let mut hosts = self.hosts.lock().await;
        let idle: Vec<Uuid> = hosts
            .iter()
            .filter(|(_, host)| host.last_used.elapsed() > IDLE_STOP)
            .map(|(id, _)| *id)
            .collect();
        for id in idle {
            if let Some(mut host) = hosts.remove(&id) {
                if let Err(error) = host.child.kill().await {
                    tracing::warn!(workspace = %id, %error, "workspace: an idle process was not stopped");
                } else {
                    tracing::info!(workspace = %id, "workspace: idle process stopped");
                }
            }
        }
    }

    /// The port and token of `id`'s process, started when it is not running.
    async fn ensure(&self, id: Uuid) -> Result<(u16, String), AppError> {
        let mut hosts = self.hosts.lock().await;
        if let Some(host) = hosts.get_mut(&id) {
            let alive = matches!(host.child.try_wait(), Ok(None));
            if alive {
                host.last_used = Instant::now();
                return Ok((host.port, host.token.clone()));
            }
            hosts.remove(&id);
        }
        let host = self.spawn(id).await?;
        let found = (host.port, host.token.clone());
        hosts.insert(id, host);
        Ok(found)
    }

    async fn spawn(&self, id: Uuid) -> Result<Host, AppError> {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .and_then(|l| l.local_addr())
            .map_err(AppError::internal)?
            .port();
        let token = {
            use rand::RngCore;
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            hex::encode(bytes)
        };
        let exe = std::env::current_exe().map_err(AppError::internal)?;
        let child = tokio::process::Command::new(exe)
            .arg("serve")
            .arg(WORKSPACE_FLAG)
            .arg(id.to_string())
            .arg(PORT_FLAG)
            .arg(port.to_string())
            .env(TOKEN_VAR, &token)
            .env_remove(crate::listener::LISTEN_FD_VAR)
            .env_remove(crate::listener::LISTEN_PROTOCOL_INFO_VAR)
            .stdin(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(AppError::internal)?;
        let mut host = Host {
            child,
            port,
            token,
            last_used: Instant::now(),
        };
        let deadline = Instant::now() + START_WAIT;
        loop {
            if let Ok(Some(status)) = host.child.try_wait() {
                tracing::error!(workspace = %id, %status, "workspace: the process stopped while starting");
                return Err(AppError::CapabilityUnavailable("workspace"));
            }
            let ready = self
                .client
                .get(format!("http://127.0.0.1:{port}/health"))
                .header(TOKEN_HEADER, &host.token)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success());
            if ready {
                tracing::info!(workspace = %id, port, "workspace: process ready");
                return Ok(host);
            }
            if Instant::now() > deadline {
                if let Err(error) = host.child.kill().await {
                    tracing::warn!(workspace = %id, %error, "workspace: a process that did not start was not stopped");
                }
                return Err(AppError::CapabilityUnavailable("workspace"));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn proxy(&self, id: Uuid, request: Request<Body>) -> Result<Response, AppError> {
        let (port, token) = self.ensure(id).await?;
        let (parts, body) = request.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map_or_else(|| parts.uri.path().to_owned(), |pq| pq.as_str().to_owned());
        let bytes = axum::body::to_bytes(body, MAX_BODY)
            .await
            .map_err(|_| AppError::PayloadTooLarge)?;
        let mut outgoing = self
            .client
            .request(
                parts.method.clone(),
                format!("http://127.0.0.1:{port}{path}"),
            )
            .header(TOKEN_HEADER, token)
            .body(bytes);
        for (name, value) in &parts.headers {
            if name == axum::http::header::HOST || name.as_str() == TOKEN_HEADER {
                continue;
            }
            outgoing = outgoing.header(name, value);
        }
        let answer = outgoing.send().await.map_err(|error| {
            tracing::warn!(workspace = %id, %error, "workspace: the process did not answer");
            AppError::CapabilityUnavailable("workspace")
        })?;
        let status = answer.status();
        let headers = answer.headers().clone();
        let body = answer.bytes().await.map_err(AppError::internal)?;
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        for (name, value) in &headers {
            if name == axum::http::header::TRANSFER_ENCODING
                || name == axum::http::header::CONNECTION
                || name == axum::http::header::CONTENT_LENGTH
            {
                continue;
            }
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_str().as_bytes()),
                HeaderValue::from_bytes(value.as_bytes()),
            ) {
                response.headers_mut().append(name, value);
            }
        }
        Ok(response)
    }
}

impl WorkspaceForwarder for WorkspaceHosts {
    fn forward(
        &self,
        workspace: Uuid,
        request: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = Result<Response, AppError>> + Send>> {
        // `self` is borrowed for the call only; the hosts live in an `Arc`
        // the installer keeps, so the future holds its own handle.
        let this = HOSTS.get().cloned();
        Box::pin(async move {
            let Some(this) = this else {
                return Err(AppError::CapabilityUnavailable("workspace"));
            };
            this.proxy(workspace, request).await
        })
    }

    fn stop(&self, workspace: Uuid) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let this = HOSTS.get().cloned();
        Box::pin(async move {
            let Some(this) = this else {
                return;
            };
            let host = this.hosts.lock().await.remove(&workspace);
            if let Some(mut host) = host {
                match host.child.kill().await {
                    Ok(()) => tracing::info!(workspace = %workspace, "workspace: process stopped"),
                    Err(error) => {
                        tracing::warn!(workspace = %workspace, %error, "workspace: a process was not stopped");
                    }
                }
            }
        })
    }
}

static HOSTS: std::sync::OnceLock<Arc<WorkspaceHosts>> = std::sync::OnceLock::new();

/// Starts the live server's workspace hosts and installs them as the
/// workspace forwarder.
pub fn install() -> Result<(), String> {
    let hosts = WorkspaceHosts::start()?;
    if HOSTS.set(Arc::clone(&hosts)).is_err() {
        return Ok(());
    }
    attome_api::workspace::proxy::install(hosts);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_are_read_in_both_forms() {
        let args: Vec<String> = ["serve", "--workspace", "a", "--workspace-port=9"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        assert_eq!(flag_value(&args, WORKSPACE_FLAG).as_deref(), Some("a"));
        assert_eq!(flag_value(&args, PORT_FLAG).as_deref(), Some("9"));
        assert_eq!(flag_value(&args, "--other"), None);
    }

    #[test]
    fn tokens_match_only_exactly() {
        assert!(token_matches("abc", "abc"));
        assert!(!token_matches("abc", "abd"));
        assert!(!token_matches("abc", "ab"));
        assert!(!token_matches("", ""));
    }
}
