//! BST-5 (C6): the client's TLS semantics, proven against a real TLS
//! listener rather than by inspecting URL schemes.
//!
//! Invariant I5: the endpoint's scheme alone decides plaintext vs TLS, and
//! `verify_ssl` only decides whether the certificate is checked. The
//! listener here serves `tests/fixtures/self_signed_cert.pem` — a test-only,
//! self-signed P-256 certificate for `localhost`/`127.0.0.1` (valid until
//! 2126; regenerate with the `openssl req -x509 ... -addext
//! "subjectAltName=DNS:localhost,IP:127.0.0.1"` recipe if it is ever
//! replaced). Its private key is committed on purpose and protects nothing.
//!
//! No backend or credentials are needed:
//!
//! ```powershell
//! cargo test -p attome-storage --test tls_semantics
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use attome_config::S3Target;
use attome_storage::{StorageClient, create_storage_client_for, health_check};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const CERT_PEM: &[u8] = include_bytes!("fixtures/self_signed_cert.pem");
const KEY_PEM: &[u8] = include_bytes!("fixtures/self_signed_key.pem");

const EMPTY_LIST_RESPONSE: &str =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult></ListBucketResult>";

/// What the listener saw, so a test can tell "the handshake was refused" from
/// "the request was answered with an error".
#[derive(Default)]
struct Observed {
    connections: AtomicUsize,
    handshakes_completed: AtomicUsize,
    requests_answered: AtomicUsize,
    /// Connections whose first byte was a TLS record (0x16, handshake).
    tls_client_hellos: AtomicUsize,
}

/// The same process-level provider `crates/server/src/boot.rs` installs: the
/// workspace builds rustls with both *ring* and aws-lc-rs, so none is implied.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn server_config() -> Arc<rustls::ServerConfig> {
    let certs = CertificateDer::pem_slice_iter(CERT_PEM)
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture certificate parses");
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM).expect("fixture key parses");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("default protocol versions")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("fixture certificate and key match");
    Arc::new(config)
}

/// Reads one HTTP request head and answers it like an S3 bucket that exists
/// but holds no probe key: `HEAD` → 404, anything else (the list) → an empty
/// `ListBucketResult`. That pair is exactly what `health_check` reports as
/// reachable.
fn answer_like_an_empty_bucket(stream: &mut impl ReadWrite, observed: &Observed) {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    let (status, body) = if request.starts_with(b"HEAD ") {
        ("404 Not Found", "")
    } else {
        ("200 OK", EMPTY_LIST_RESPONSE)
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    if stream.write_all(response.as_bytes()).is_ok() && stream.flush().is_ok() {
        observed.requests_answered.fetch_add(1, Ordering::SeqCst);
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn serve_tls(mut tcp: TcpStream, config: Arc<rustls::ServerConfig>, observed: &Observed) {
    let Ok(mut conn) = rustls::ServerConnection::new(config) else {
        return;
    };
    while conn.is_handshaking() {
        if conn.complete_io(&mut tcp).is_err() {
            return;
        }
    }
    observed.handshakes_completed.fetch_add(1, Ordering::SeqCst);
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    answer_like_an_empty_bucket(&mut stream, observed);
    stream.conn.send_close_notify();
    let _ = stream.flush();
}

/// A listener on 127.0.0.1 that records every connection. With `tls` it
/// terminates TLS with the fixture certificate; without it, it speaks
/// plaintext HTTP and also records whether the client opened with a TLS
/// ClientHello instead.
fn spawn_listener(tls: bool) -> (SocketAddr, Arc<Observed>) {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener address");
    let observed = Arc::new(Observed::default());
    let config = server_config();
    let shared = Arc::clone(&observed);
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };
            let observed = Arc::clone(&shared);
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                observed.connections.fetch_add(1, Ordering::SeqCst);
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = tcp.set_write_timeout(Some(Duration::from_secs(5)));
                let mut first = [0u8; 1];
                if tcp.peek(&mut first).ok() == Some(1) && first[0] == 0x16 {
                    observed.tls_client_hellos.fetch_add(1, Ordering::SeqCst);
                }
                if tls {
                    serve_tls(tcp, config, &observed);
                } else {
                    let mut tcp = tcp;
                    answer_like_an_empty_bucket(&mut tcp, &observed);
                }
            });
        }
    });
    (addr, observed)
}

async fn client(endpoint: &str, verify_ssl: bool) -> StorageClient {
    let target = S3Target {
        endpoint,
        public_endpoint: "",
        region: "us-east-1",
        bucket: "tls-semantics",
        access_key: "test-access-key",
        secret_key: "test-secret-key",
        verify_ssl,
    };
    create_storage_client_for(target, "tls-semantics")
        .await
        .expect("client construction is local, no network access")
}

#[tokio::test]
async fn verify_ssl_true_rejects_a_self_signed_certificate() {
    let (addr, observed) = spawn_listener(true);

    let health =
        health_check(&client(&format!("https://localhost:{}", addr.port()), true).await).await;

    assert!(
        !health.reachable,
        "a self-signed certificate must not be trusted with verify_ssl = true"
    );
    assert!(
        observed.tls_client_hellos.load(Ordering::SeqCst) >= 1,
        "the client must have attempted a TLS handshake"
    );
    assert_eq!(
        observed.handshakes_completed.load(Ordering::SeqCst),
        0,
        "no handshake may complete against an untrusted certificate"
    );
    assert_eq!(observed.requests_answered.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn verify_ssl_false_accepts_the_same_certificate_over_tls() {
    let (addr, observed) = spawn_listener(true);

    let health =
        health_check(&client(&format!("https://localhost:{}", addr.port()), false).await).await;

    assert!(
        health.reachable,
        "verify_ssl = false must accept the self-signed certificate (error: {:?})",
        health.error
    );
    assert!(observed.handshakes_completed.load(Ordering::SeqCst) >= 1);
    assert!(
        observed.requests_answered.load(Ordering::SeqCst) >= 2,
        "the HEAD and the list must both have been answered over TLS"
    );
}

/// `verify_ssl = false` relaxes certificate checks only; it never lets an
/// `https://` endpoint fall back to plaintext.
#[tokio::test]
async fn an_https_endpoint_never_falls_back_to_plaintext() {
    let (addr, observed) = spawn_listener(false);

    let health =
        health_check(&client(&format!("https://127.0.0.1:{}", addr.port()), false).await).await;

    assert!(
        !health.reachable,
        "an https endpoint answered in plaintext must not be reachable"
    );
    assert!(
        observed.tls_client_hellos.load(Ordering::SeqCst) >= 1,
        "the client must open with a TLS ClientHello"
    );
    assert_eq!(observed.requests_answered.load(Ordering::SeqCst), 0);
}

/// `verify_ssl = true` never upgrades an `http://` endpoint to TLS.
#[tokio::test]
async fn an_http_endpoint_stays_plaintext_even_with_verify_ssl() {
    let (addr, observed) = spawn_listener(false);

    let health =
        health_check(&client(&format!("http://127.0.0.1:{}", addr.port()), true).await).await;

    assert!(health.reachable, "error: {:?}", health.error);
    assert_eq!(observed.tls_client_hellos.load(Ordering::SeqCst), 0);
    assert!(observed.requests_answered.load(Ordering::SeqCst) >= 2);
}

/// The fixture decodes through rustls-pki-types' `PemObject` exactly as it did
/// through rustls-pemfile (RUSTSEC-2025-0134): one certificate, one PKCS#8
/// key, and empty or non-PEM input yields nothing rather than a bogus item.
#[test]
fn fixture_pem_decodes_and_bad_input_yields_nothing() {
    let certs = CertificateDer::pem_slice_iter(CERT_PEM)
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture certificate parses");
    assert_eq!(certs.len(), 1);
    assert!(matches!(
        PrivateKeyDer::from_pem_slice(KEY_PEM),
        Ok(PrivateKeyDer::Pkcs8(_))
    ));

    for bad in [&b""[..], &b"not pem at all\n"[..]] {
        assert_eq!(CertificateDer::pem_slice_iter(bad).count(), 0);
        assert!(PrivateKeyDer::from_pem_slice(bad).is_err());
    }
    let truncated = b"-----BEGIN PRIVATE KEY-----\nMIGH\n";
    assert!(PrivateKeyDer::from_pem_slice(truncated).is_err());
}
