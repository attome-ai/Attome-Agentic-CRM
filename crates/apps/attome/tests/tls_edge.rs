//! Z5-T6: the server terminates TLS itself. A listener built from a
//! certificate and key answers HTTPS, speaks HTTP/2 when the client offers
//! it through ALPN, and still serves HTTP/1.1 to a client that does not.
//!
//! The certificate in `tests/fixtures/tls/` is a self-signed one for
//! `localhost` made for this test only (valid for a century), like the one
//! attome-storage's tests use; it protects nothing. It is not a CA
//! (`CA:FALSE`): on Linux the client's verifier refuses a CA certificate
//! presented as the server's own.

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
        http3: false,
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

/// Z5-T8: without the `http3` feature, `app.tls.http3 = true` fails at boot
/// with a message naming the feature, instead of serving TCP alone.
#[cfg(not(feature = "http3"))]
#[test]
fn http3_feature_off_rejects_config() {
    let mut tls = section();
    assert!(attome::tls::check_http3(&tls).is_ok(), "off by default");
    tls.http3 = true;
    let err = attome::tls::check_http3(&tls).unwrap_err().to_string();
    assert!(
        err.contains("app.tls.http3") && err.contains("--features http3"),
        "{err}"
    );
}

/// S11-T3: the thumbprint of a fixture client certificate, as the token
/// endpoint binds it.
fn fixture_thumbprint(name: &str) -> String {
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let der = CertificateDer::from_pem_file(fixture(name)).unwrap();
    attome_auth::mtls::thumbprint(&der)
}

fn mtls_client(identity: Option<&str>) -> reqwest::Client {
    let pem = std::fs::read(fixture("cert.pem")).unwrap();
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(&pem).unwrap())
        .resolve("localhost", "127.0.0.1:0".parse().unwrap());
    if let Some(name) = identity {
        let mut both = std::fs::read(fixture(&format!("{name}.key"))).unwrap();
        both.extend(std::fs::read(fixture(&format!("{name}.pem"))).unwrap());
        builder = builder.identity(reqwest::Identity::from_pem(&both).unwrap());
    }
    builder.build().unwrap()
}

/// S11-T3: with a client CA the listener asks for a certificate, puts the
/// verified one's thumbprint on each request, and a token bound to client
/// A's certificate passes only over that certificate: client B's
/// certificate, or none, is refused. A client without a certificate still
/// connects (asked, not required).
#[tokio::test]
async fn mtls_bound_token_fails_with_another_certificate() {
    use attome_auth::mtls::{ClientCertificate, check_binding};
    use attome_auth::oauth_token::{AccessClaims, Confirmation};
    use axum::Extension;

    let bound_to = fixture_thumbprint("client-a.pem");
    assert_ne!(bound_to, fixture_thumbprint("client-b.pem"));
    let claims = AccessClaims {
        claims: attome_auth::SessionClaims {
            sub: uuid::Uuid::nil(),
            iat: 0,
            exp: 600,
            jti: uuid::Uuid::nil(),
            epoch: 0,
            iss: "attome-test".into(),
            aud: "attome-test".into(),
            typ: attome_auth::TokenType::S2sAccess,
        },
        client_id: "erp-sync".into(),
        scope: String::new(),
        cnf: Some(Confirmation {
            x5t_s256: bound_to.clone(),
        }),
    };

    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let listener = TlsListener::start_with(tcp, &section(), Some(&fixture("client-ca.pem")))
        .expect("the fixtures build a config");
    let app = Router::new().route(
        "/bound",
        get(move |certificate: Option<Extension<ClientCertificate>>| {
            let claims = claims.clone();
            async move {
                let presented = certificate.map(|Extension(c)| c.thumbprint);
                match check_binding(&claims, presented.as_deref()) {
                    Ok(()) => (axum::http::StatusCode::OK, presented.unwrap_or_default()),
                    Err(_) => (axum::http::StatusCode::UNAUTHORIZED, String::new()),
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, attome::tls::TlsMakeService::new(app)).await });
    let url = format!("https://localhost:{port}/bound");

    let a = mtls_client(Some("client-a"))
        .get(&url)
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), 200, "the bound certificate passes");
    assert_eq!(
        a.text().await.unwrap(),
        bound_to,
        "the thumbprint reached the request"
    );
    let b = mtls_client(Some("client-b"))
        .get(&url)
        .send()
        .await
        .unwrap();
    assert_eq!(b.status(), 401, "another certificate is refused");
    let none = mtls_client(None).get(&url).send().await.unwrap();
    assert_eq!(
        none.status(),
        401,
        "no certificate is refused, but connects"
    );
}

/// S11-T3: a client CA file that holds no certificate fails at boot and
/// names the setting.
#[test]
fn mtls_client_ca_names_the_setting() {
    let err = attome::tls::server_config_with(&section(), Some(&fixture("key.pem")))
        .unwrap_err()
        .to_string();
    assert!(err.contains("s2s.mtls.client_ca_path"), "{err}");
    assert!(attome::tls::server_config_with(&section(), Some(&fixture("client-ca.pem"))).is_ok());
}
