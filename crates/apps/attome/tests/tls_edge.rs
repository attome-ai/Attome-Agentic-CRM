//! Z5-T6: the server terminates TLS itself. A listener built from a
//! certificate and key answers HTTPS, speaks HTTP/2 when the client offers
//! it through ALPN, and still serves HTTP/1.1 to a client that does not.
//!
//! The certificate in `tests/fixtures/tls/` is a self-signed one for
//! `localhost` made for this test only (valid for a century), like the one
//! attome-storage's tests use; it protects nothing.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::path::PathBuf;

use attome::tls::{TlsListener, server_config};
use attome_config::TlsSection;
use axum::{Router, routing::get};

fn fixture(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn section() -> TlsSection {
    TlsSection {
        enabled: true,
        cert_path: fixture("cert.pem"),
        key_path: fixture("key.pem"),
        min_version: None,
        acme: Default::default(),
    }
}

async fn serve() -> String {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let listener = TlsListener::start(tcp, &section()).expect("the fixture builds a config");
    let app = Router::new().route("/health", get(|| async { "ok" }));
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("https://localhost:{port}/health")
}

fn client(http1_only: bool) -> reqwest::Client {
    let pem = std::fs::read(fixture("cert.pem")).unwrap();
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
        .resolve("localhost", "127.0.0.1:0".parse().unwrap());
    if http1_only {
        builder = builder.http1_only();
    }
    builder.build().unwrap()
}

#[tokio::test]
async fn tls_listener_serves_h2() {
    let url = serve().await;

    let response = client(false)
        .get(&url)
        .send()
        .await
        .expect("an HTTPS answer");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.version(),
        reqwest::Version::HTTP_2,
        "ALPN chose h2"
    );
    assert_eq!(response.text().await.unwrap(), "ok");

    let response = client(true)
        .get(&url)
        .send()
        .await
        .expect("an HTTP/1.1 answer");
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), reqwest::Version::HTTP_11);

    // Plain HTTP on the TLS port is not answered.
    let plain = url.replace("https://", "http://");
    assert!(reqwest::Client::new().get(&plain).send().await.is_err());
}

#[test]
fn tls_config_names_the_file_that_is_wrong() {
    let mut tls = section();
    tls.key_path = fixture("cert.pem");
    let err = server_config(&tls).unwrap_err().to_string();
    assert!(err.contains("app.tls.key_path"), "{err}");
    assert!(server_config(&section()).is_ok());
    let mut strict = section();
    strict.min_version = Some("1.3".into());
    assert!(server_config(&strict).is_ok());
}
