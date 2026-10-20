//! Q21-T1: every server-initiated HTTP call goes through
//! `attome_outbound::http::client`. These tests prove the guard refuses the
//! cloud metadata address (as a literal, through a listed private host, and
//! as a redirect target), reaches a private host only when the purpose lists
//! it, and that no source file outside the guard builds a `reqwest` client of
//! its own.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use attome_outbound::http::{Purpose, REFUSED_SCHEME, client};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A one-route HTTP server on loopback answering every request with
/// `response`; returns its port.
async fn serve(response: &'static [u8]) -> u16 {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let _ = sock.write_all(response).await;
        }
    });
    port
}

fn timeout(b: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
    b.timeout(Duration::from_secs(5))
}

#[tokio::test]
async fn the_metadata_address_is_refused() {
    for purpose in [
        Purpose::public("test"),
        Purpose::public("test").with_private_hosts(["169.254.169.254"]),
    ] {
        let http = client(purpose, timeout).unwrap();
        let err = http
            .get("http://169.254.169.254/latest/meta-data/")
            .send()
            .await
            .expect_err("the metadata address must be refused");
        assert!(err.to_string().contains(REFUSED_SCHEME), "{err}");
    }
}

#[tokio::test]
async fn a_private_host_is_reached_only_when_the_purpose_lists_it() {
    let port = serve(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
    for host in ["127.0.0.1", "localhost"] {
        let url = format!("http://{host}:{port}/");
        let public = client(Purpose::public("test"), timeout).unwrap();
        assert!(
            public.get(&url).send().await.is_err(),
            "{host} reached by a public purpose"
        );
        let listed = client(Purpose::public("test").with_private_hosts([host]), timeout).unwrap();
        let res = listed.get(&url).send().await.unwrap();
        assert_eq!(res.status(), 200, "{host}");
    }
}

#[tokio::test]
async fn a_redirect_to_the_metadata_address_is_refused() {
    let port = serve(
        b"HTTP/1.1 302 Found\r\nLocation: http://169.254.169.254/latest/meta-data/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    let http = client(
        Purpose::public("test").with_private_hosts(["127.0.0.1"]),
        timeout,
    )
    .unwrap();
    let err = http
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .expect_err("the redirect must be refused");
    assert!(err.is_redirect(), "{err:?}");
}

/// What building a client looks like in source. `Client::builder()` and
/// `Client::new()` count only in a file that imports reqwest's `Client`.
const DIRECT: &[&str] = &[
    "reqwest::Client::new(",
    "reqwest::Client::builder(",
    "reqwest::Client::default(",
    "reqwest::ClientBuilder::new(",
];
const BARE: &[&str] = &["Client::new(", "Client::builder("];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !matches!(name.as_str(), "target" | "tests" | "benches" | "examples") {
                rust_sources(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The source without its `#[cfg(test)]` module: a unit test may build a
/// plain client to talk to a fake.
fn non_test(source: &str) -> &str {
    source
        .find("#[cfg(test)]\nmod tests")
        .map_or(source, |at| &source[..at])
}

#[test]
fn no_crate_builds_its_own_http_client() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let guard = crates.join("foundation/attome-outbound/src/http");
    let mut files = Vec::new();
    rust_sources(&crates, &mut files);
    let mut offenders = Vec::new();
    for file in files {
        if file.starts_with(&guard) {
            continue;
        }
        let text = std::fs::read_to_string(&file)
            .unwrap()
            .replace("\r\n", "\n");
        // Comments may name the forbidden calls; only code counts.
        let code: String = non_test(&text)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let imports_client = code.contains("use reqwest::Client;")
            || code.contains("use reqwest::{Client")
            || (code.contains(", Client}") && code.contains("use reqwest::{"));
        let hit = DIRECT.iter().any(|p| code.contains(p))
            || (imports_client && BARE.iter().any(|p| code.contains(p)));
        if hit {
            offenders.push(
                file.strip_prefix(&crates)
                    .unwrap_or(&file)
                    .display()
                    .to_string(),
            );
        }
    }
    assert!(
        offenders.is_empty(),
        "build HTTP clients with attome_outbound::http::client (Q21-T1), not reqwest directly: {offenders:#?}"
    );
}
