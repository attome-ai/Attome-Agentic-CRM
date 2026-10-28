//! `attome supervise` (roadmap AB7-T4): replaces the server without refusing
//! a connection. The supervisor binds the public socket once and hands it to
//! the server it starts (AB7-T3's `listener::bind_or_inherit`); on a restart
//! it starts a new server on the same socket, waits for it to say `READY`,
//! and only then tells the old one to drain. Both accept on the one socket
//! while they overlap, so a client never meets a closed port.
//!
//! ```text
//! attome supervise --token-file <path> [--listen 127.0.0.1:7865]
//!                  [--control-addr 127.0.0.1:7866] [--server-exe <path>]
//!                  [--child-arg <arg>]...
//! ```
//!
//! - The server is `<server-exe> serve` (the running binary by default;
//!   `--child-arg` replaces the `serve` arguments). It runs with
//!   `ATTOME_SUPERVISED=1`: it prints `READY` on stdout once it serves, and
//!   treats its stdin closing as a graceful stop.
//! - The socket reaches it as `ATTOME_LISTEN_FD` on Unix (the descriptor,
//!   inheritable), and on Windows as `ATTOME_LISTEN_PROTOCOL_INFO=-` with
//!   the `WSADuplicateSocketW` information for its process id on the first
//!   line of its stdin.
//! - `POST /restart` on the control address (loopback only) with header
//!   `X-Supervisor-Token` equal to the token file's content restarts it. A
//!   new server that is not `READY` within two minutes is stopped and the
//!   old one keeps serving (the answer is 500).
//! - Ctrl+C, SIGTERM or a Windows stop closes the server's stdin, waits for
//!   it to drain, and exits.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin};
use tokio::sync::{mpsc, oneshot};

/// How long a new server has to print `READY`.
const READY_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a draining server has to exit before it is killed.
const STOP_TIMEOUT: Duration = Duration::from_secs(90);
/// The line a supervised server prints once it serves.
pub const READY_LINE: &str = "READY";
/// The variable that tells a server it is supervised.
pub const SUPERVISED_VAR: &str = "ATTOME_SUPERVISED";
/// The control request's token header.
pub const TOKEN_HEADER: &str = "x-supervisor-token";

const USAGE: &str = "\
attome supervise: serve with zero-downtime restarts

Usage:
  attome supervise --token-file <path> [--listen <addr>] [--control-addr <addr>]
                   [--server-exe <path>] [--child-arg <arg>]...

  --token-file    a file holding the secret POST /restart must present
  --listen        the public address to bind (default 127.0.0.1:7865)
  --control-addr  the loopback address of the control endpoint (default 127.0.0.1:7866)
  --server-exe    the server binary (default: this one)
  --child-arg     an argument for the server, repeatable (default: serve)
";

#[derive(Debug, Clone, PartialEq)]
struct Options {
    listen: String,
    control_addr: SocketAddr,
    token: String,
    server_exe: PathBuf,
    child_args: Vec<String>,
}

/// Parses the arguments; the token is read from its file. Pure apart from
/// that read.
fn parse(args: &[String]) -> Result<Options, String> {
    let mut listen = "127.0.0.1:7865".to_owned();
    let mut control = "127.0.0.1:7866".to_owned();
    let mut token_file: Option<PathBuf> = None;
    let mut server_exe: Option<PathBuf> = None;
    let mut child_args = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value\n\n{USAGE}"))
        };
        match arg.as_str() {
            "--listen" => listen = value()?,
            "--control-addr" => control = value()?,
            "--token-file" => token_file = Some(PathBuf::from(value()?)),
            "--server-exe" => server_exe = Some(PathBuf::from(value()?)),
            "--child-arg" => child_args.push(value()?),
            "--help" | "-h" => return Err(USAGE.to_owned()),
            other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
        }
    }
    let control_addr: SocketAddr = control
        .parse()
        .map_err(|_| format!("--control-addr {control:?} is not an address"))?;
    if !control_addr.ip().is_loopback() {
        return Err("--control-addr must be a loopback address".into());
    }
    let token_file = token_file.ok_or_else(|| format!("--token-file is required\n\n{USAGE}"))?;
    let token = std::fs::read_to_string(&token_file)
        .map_err(|e| format!("cannot read {}: {e}", token_file.display()))?
        .trim()
        .to_owned();
    if token.len() < 16 {
        return Err("the token file must hold at least 16 characters".into());
    }
    let server_exe = match server_exe {
        Some(exe) => exe,
        None => std::env::current_exe().map_err(|e| format!("cannot find this binary: {e}"))?,
    };
    if child_args.is_empty() {
        child_args.push("serve".into());
    }
    Ok(Options {
        listen,
        control_addr,
        token,
        server_exe,
        child_args,
    })
}

/// Whether `presented` is `expected`, compared in constant time for equal
/// lengths. Pure.
fn token_matches(presented: &str, expected: &str) -> bool {
    presented.len() == expected.len()
        && presented
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// A running server and the stdin whose closing stops it.
struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
}

pub fn run(args: &[String]) -> Result<(), String> {
    let options = parse(args)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("cannot start the runtime: {e}"))?;
    runtime.block_on(supervise(options))
}

#[cfg(unix)]
fn make_inheritable(listener: &std::net::TcpListener) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let fd = listener.as_raw_fd();
    #[allow(
        unsafe_code,
        reason = "clearing FD_CLOEXEC so the server process inherits the socket"
    )]
    // SAFETY: `fd` is the open listening socket this process owns for its
    // whole life; F_GETFD and F_SETFD only read and write its descriptor
    // flags and touch no memory.
    let done = unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == 0
    };
    if done {
        Ok(())
    } else {
        Err(format!(
            "cannot make the socket inheritable: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(not(unix))]
fn make_inheritable(_listener: &std::net::TcpListener) -> Result<(), String> {
    // Windows hands the socket over with WSADuplicateSocketW per process.
    Ok(())
}

async fn supervise(options: Options) -> Result<(), String> {
    let listener = std::net::TcpListener::bind(&options.listen)
        .map_err(|e| format!("cannot bind {}: {e}", options.listen))?;
    make_inheritable(&listener)?;
    println!("supervise: listening on {}", options.listen);
    let mut current = start(&options, &listener).await?;

    let (restart_tx, mut restart_rx) = mpsc::channel::<oneshot::Sender<Result<(), String>>>(1);
    let control = tokio::net::TcpListener::bind(options.control_addr)
        .await
        .map_err(|e| format!("cannot bind the control address: {e}"))?;
    let token = options.token.clone();
    let app = axum::Router::new().route(
        "/restart",
        axum::routing::post(move |headers: axum::http::HeaderMap| {
            let (token, restart_tx) = (token.clone(), restart_tx.clone());
            async move {
                let presented = headers
                    .get(TOKEN_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default();
                if !token_matches(presented, &token) {
                    return (axum::http::StatusCode::UNAUTHORIZED, "refused".to_owned());
                }
                let (reply_tx, reply_rx) = oneshot::channel();
                if restart_tx.send(reply_tx).await.is_err() {
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "stopping".to_owned(),
                    );
                }
                match reply_rx.await {
                    Ok(Ok(())) => (axum::http::StatusCode::OK, "restarted".to_owned()),
                    Ok(Err(e)) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e),
                    Err(_) => (
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "no answer".to_owned(),
                    ),
                }
            }
        }),
    );
    tokio::spawn(async move {
        if let Err(e) = axum::serve(control, app).await {
            eprintln!("supervise: the control endpoint stopped: {e}");
        }
    });

    loop {
        tokio::select! {
            Some(reply) = restart_rx.recv() => {
                match start(&options, &listener).await {
                    Ok(next) => {
                        let old = std::mem::replace(&mut current, next);
                        stop(old).await;
                        println!("supervise: restarted");
                        let _ = reply.send(Ok(()));
                    }
                    Err(e) => {
                        eprintln!("supervise: restart failed, the running server stays: {e}");
                        let _ = reply.send(Err(e));
                    }
                }
            }
            () = crate::boot::wait_for_shutdown_signal() => {
                stop(current).await;
                return Ok(());
            }
            status = current.child.wait() => {
                return Err(format!("the server exited on its own ({status:?})"));
            }
        }
    }
}

/// Starts a server on `listener` and waits for its `READY`; a server that
/// does not get there in time is killed.
async fn start(options: &Options, listener: &std::net::TcpListener) -> Result<Server, String> {
    let mut command = tokio::process::Command::new(&options.server_exe);
    command
        .args(&options.child_args)
        .env(SUPERVISED_VAR, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        command.env(
            crate::listener::LISTEN_FD_VAR,
            listener.as_raw_fd().to_string(),
        );
    }
    #[cfg(windows)]
    command.env(crate::listener::LISTEN_PROTOCOL_INFO_VAR, "-");
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot start {}: {e}", options.server_exe.display()))?;
    let mut stdin = child.stdin.take();
    #[cfg(windows)]
    {
        use base64::Engine;
        let pid = child.id().ok_or("the server exited at once")?;
        let info = crate::listener::windows::duplicate_for(listener, pid)
            .map_err(|e| format!("cannot hand the socket over: {e}"))?;
        let line = format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(info)
        );
        if let Some(stdin) = stdin.as_mut() {
            stdin
                .write_all(line.as_bytes())
                .await
                .map_err(|e| format!("cannot hand the socket over: {e}"))?;
            stdin
                .flush()
                .await
                .map_err(|e| format!("cannot hand the socket over: {e}"))?;
        }
    }
    #[cfg(not(windows))]
    let _ = listener;
    if let Some(stdin) = stdin.as_mut() {
        stdin.flush().await.ok();
    }
    let stdout = child.stdout.take().ok_or("the server has no stdout")?;
    let mut lines = BufReader::new(stdout).lines();
    let ready = tokio::time::timeout(READY_TIMEOUT, async {
        while let Ok(Some(line)) = lines.next_line().await {
            println!("{line}");
            if line.trim() == READY_LINE {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    if !ready {
        let _ = child.kill().await;
        return Err("the new server did not become ready".into());
    }
    // The rest of its output passes through.
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            println!("{line}");
        }
    });
    Ok(Server { child, stdin })
}

/// Closes `server`'s stdin (its signal to drain) and waits for it to exit,
/// killing it after [`STOP_TIMEOUT`].
async fn stop(mut server: Server) {
    drop(server.stdin.take());
    if tokio::time::timeout(STOP_TIMEOUT, server.child.wait())
        .await
        .is_err()
    {
        eprintln!("supervise: the old server did not stop in time; killing it");
        let _ = server.child.kill().await;
    }
}

/// AB7-T4: in a supervised server, prints `READY` once it serves and turns
/// its stdin closing into a graceful stop. Does nothing otherwise.
pub fn announce_ready_when_supervised() {
    if std::env::var(SUPERVISED_VAR).as_deref() != Ok("1") {
        return;
    }
    use std::io::Write;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{READY_LINE}");
    let _ = out.flush();
    // stdin closes when the supervisor wants this server to drain. A
    // detached thread: reading stdin blocks, and the process ends with it.
    std::thread::spawn(|| {
        use std::io::Read;
        let mut sink = Vec::new();
        let _ = std::io::stdin().read_to_end(&mut sink);
        crate::boot::request_stop();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_must_match_exactly() {
        assert!(token_matches("0123456789abcdef", "0123456789abcdef"));
        assert!(!token_matches("0123456789abcdeX", "0123456789abcdef"));
        assert!(!token_matches("0123456789abcde", "0123456789abcdef"));
    }

    #[test]
    fn the_control_address_must_be_loopback() {
        let dir = std::env::temp_dir().join(format!("supervise-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        let token = dir.join("token");
        std::fs::write(&token, "a-long-enough-test-token").unwrap();
        let args = |control: &str| {
            vec![
                "--token-file".to_owned(),
                token.display().to_string(),
                "--control-addr".to_owned(),
                control.to_owned(),
            ]
        };
        assert!(parse(&args("0.0.0.0:7866")).is_err());
        let options = parse(&args("127.0.0.1:7866")).unwrap();
        assert_eq!(options.child_args, vec!["serve".to_owned()]);
        assert_eq!(options.token, "a-long-enough-test-token");
        let _ = std::fs::remove_dir_all(dir);
    }
}
