//! Minimal, dependency-free Docker `HEALTHCHECK`/compose `healthcheck.test`
//! probe — replaces `curl -f http://localhost:<port>/health/ready`.
//!
//! P-supply-chain-pinning follow-up (2026-08-06): the runtime image installed
//! `curl` for this exact check, which drags in `libcurl4` and (via Debian's
//! curl build) `libssh2-1`/`libldap-2.5-0` as runtime dependencies — none of
//! them used for anything else `attome-server` does. The first real
//! `release.yml` run found 9 of that run's 23 unique CRITICAL/HIGH Trivy
//! findings traced straight back to curl and that dependency chain. This
//! binary does the same "GET the path, fail unless 2xx" check `curl -f` did,
//! using only `std::net::TcpStream` — no new runtime package, no TLS stack,
//! same "ship a small purpose-built binary in the image" pattern as
//! `preflight`/`verify_audit_chain` already use.
//!
//! Usage: `healthcheck [host:port] [path]` — defaults to `127.0.0.1:8080` and
//! `/health/ready` (this image's own `SERVER_PORT`/health-route defaults).
//! Exits 0 on any 2xx status line, exits 1 otherwise (connection failure,
//! non-2xx status, or a response that doesn't even look like HTTP).

use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

pub fn run() -> ExitCode {
    let mut args = env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let path = args.next().unwrap_or_else(|| "/health/ready".to_string());

    match probe(&addr, &path) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => {
            eprintln!("healthcheck: {addr}{path} did not return a 2xx status");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("healthcheck: {addr}{path} unreachable: {e}");
            ExitCode::FAILURE
        }
    }
}

fn probe(addr: &str, path: &str) -> std::io::Result<bool> {
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let host = addr.split(':').next().unwrap_or(addr);
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let status_line = response
        .split(|&b| b == b'\n')
        .next()
        .unwrap_or(&[])
        .to_owned();
    let status_line = String::from_utf8_lossy(&status_line);
    // "HTTP/1.1 200 OK\r" -> the status code is the second whitespace-separated field.
    let ok = status_line
        .split_whitespace()
        .nth(1)
        .map(|code| code.starts_with('2'))
        .unwrap_or(false);
    Ok(ok)
}
