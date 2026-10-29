//! Z5-T6: the server terminates TLS itself when `app.tls.enabled`, so one
//! server needs no reverse proxy in front of it.
//!
//! [`server_config`] reads the PEM certificate chain and key into a rustls
//! configuration on the `ring` provider (no CMake or NASM on Windows), TLS
//! 1.2 or later (or 1.3 only), with ALPN `h2` then `http/1.1`, so HTTP/2 is
//! spoken when the client offers it. [`TlsListener`] is the
//! `axum::serve::Listener` the server serves through: one task accepts TCP
//! connections and completes each handshake on its own task (a slow or
//! broken client never holds up the others; a handshake gets ten seconds),
//! and hands finished TLS streams to the server. The configuration sits in an
//! `ArcSwap`, re-read from the files every twelve hours and on SIGHUP (Unix),
//! so a renewed certificate is picked up without a restart; a reload that
//! fails keeps the configuration in use and logs why.
//!
//! Z5-T7: with `app.tls.acme.enabled` the certificate comes from an ACME
//! server instead (`rustls-acme` on the `ring` provider): the server answers
//! the TLS-ALPN-01 challenge on its own port (ALPN `acme-tls/1`), keeps the
//! account and certificate in `cache_dir` so a restart does not order again,
//! and renews in the background. Every certificate's expiry is logged at
//! `info` when it is loaded and when it is renewed, and exported as the gauge
//! `tls_certificate_expiry_seconds` (the Unix time it expires).
//!
//! S11-T3: with `s2s.mtls.enabled` the listener asks every client for a
//! certificate chaining to `s2s.mtls.client_ca_path` (asked, not required:
//! a browser connects without one), and [`TlsMakeService`] hands each
//! request on a connection with a verified certificate its thumbprint as an
//! [`attome_auth::mtls::ClientCertificate`] extension, beside the usual
//! `ConnectInfo<SocketAddr>`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use attome_config::TlsSection;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

/// How long a client has to finish its handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the certificate files are read again.
const RELOAD_EVERY: Duration = Duration::from_secs(12 * 60 * 60);

/// Finished handshakes waiting for the server to take them.
const READY_QUEUE: usize = 256;

/// Why the TLS configuration could not be built. Names the file, never its
/// contents.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("app.tls.cert_path {path:?}: {reason}")]
    Certificate { path: String, reason: String },
    #[error("app.tls.key_path {path:?}: {reason}")]
    Key { path: String, reason: String },
    #[error("the certificate and key do not form a usable TLS configuration: {0}")]
    Config(String),
    #[error("s2s.mtls.client_ca_path {path:?}: {reason}")]
    ClientCa { path: String, reason: String },
}

/// S11-T3: a verifier asking for (not requiring) a client certificate that
/// chains to the CA certificates in `path`.
pub fn client_verifier(path: &str) -> Result<Arc<dyn ClientCertVerifier>, TlsError> {
    let path = path.trim();
    let failed = |reason: String| TlsError::ClientCa {
        path: path.to_owned(),
        reason,
    };
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path).map_err(|e| failed(e.to_string()))? {
        roots
            .add(cert.map_err(|e| failed(e.to_string()))?)
            .map_err(|e| failed(e.to_string()))?;
    }
    if roots.is_empty() {
        return Err(failed("no CA certificate in the file".into()));
    }
    WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .allow_unauthenticated()
    .build()
    .map_err(|e| failed(e.to_string()))
}

/// The client verifier `client_ca` names, or none.
fn verifier_for(client_ca: Option<&str>) -> Result<Option<Arc<dyn ClientCertVerifier>>, TlsError> {
    client_ca.map(client_verifier).transpose()
}

/// The rustls server configuration `tls` describes, without client
/// certificates.
pub fn server_config(tls: &TlsSection) -> Result<Arc<ServerConfig>, TlsError> {
    server_config_with(tls, None)
}

/// [`server_config`], asking for client certificates chaining to the CA
/// file `client_ca` when it is given (S11-T3).
pub fn server_config_with(
    tls: &TlsSection,
    client_ca: Option<&str>,
) -> Result<Arc<ServerConfig>, TlsError> {
    let cert_path = tls.cert_path.trim();
    let key_path = tls.key_path.trim();
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| TlsError::Certificate {
            path: cert_path.to_owned(),
            reason: e.to_string(),
        })?
        .collect::<Result<_, _>>()
        .map_err(|e| TlsError::Certificate {
            path: cert_path.to_owned(),
            reason: e.to_string(),
        })?;
    if certs.is_empty() {
        return Err(TlsError::Certificate {
            path: cert_path.to_owned(),
            reason: "no certificate in the file".into(),
        });
    }
    record_expiry(&certs[0], "file");
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| TlsError::Key {
        path: key_path.to_owned(),
        reason: e.to_string(),
    })?;

    let versions: &[&'static rustls::SupportedProtocolVersion] = if tls.tls13_only() {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .map_err(|e| TlsError::Config(e.to_string()))?;
    let builder = match verifier_for(client_ca)? {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };
    let mut config = builder
        .with_single_cert(certs, key)
        .map_err(|e| TlsError::Config(e.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The server's listener when TLS is on: TLS streams, already handshaken.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<tokio::net::TcpStream>, SocketAddr)>,
    local_addr: SocketAddr,
    current: Arc<ArcSwap<ServerConfig>>,
}

impl std::fmt::Debug for TlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsListener")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

impl TlsListener {
    /// Starts accepting on `tcp` with the configuration `tls` describes, and
    /// the periodic (and, on Unix, SIGHUP) reload of its files.
    pub fn start(tcp: TcpListener, tls: &TlsSection) -> Result<Self, TlsError> {
        Self::start_with(tcp, tls, None)
    }

    /// [`TlsListener::start`], asking clients for certificates chaining to
    /// the CA file `client_ca` when it is given (S11-T3).
    pub fn start_with(
        tcp: TcpListener,
        tls: &TlsSection,
        client_ca: Option<&str>,
    ) -> Result<Self, TlsError> {
        let current = if tls.acme.enabled {
            // Z5-T7: the ACME resolver swaps the certificate itself.
            Arc::new(ArcSwap::new(acme::start(tls, verifier_for(client_ca)?)?))
        } else {
            let current = Arc::new(ArcSwap::new(server_config_with(tls, client_ca)?));
            spawn_reload(current.clone(), tls.clone(), client_ca.map(str::to_owned));
            current
        };
        let local_addr = tcp
            .local_addr()
            .map_err(|e| TlsError::Config(e.to_string()))?;
        let (tx, ready) = mpsc::channel(READY_QUEUE);
        let accepting = current.clone();
        // Process-lifetime supervision: it ends when the server stops taking
        // streams (guidelines §10).
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match tcp.accept().await {
                    Ok(accepted) => accepted,
                    Err(e) => {
                        tracing::warn!(error = %e, "tls: accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let acceptor = TlsAcceptor::from(accepting.load_full());
                let sender = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            // Z5-T7: a TLS-ALPN-01 validation ends at the
                            // handshake; it is never served.
                            if tls.get_ref().1.alpn_protocol() == Some(acme::ALPN) {
                                tracing::info!(%peer, "tls: answered an ACME TLS-ALPN-01 validation");
                                return;
                            }
                            let _ = sender.send((tls, peer)).await;
                        }
                        Ok(Err(e)) => tracing::debug!(%peer, error = %e, "tls: handshake failed"),
                        Err(_) => tracing::debug!(%peer, "tls: handshake timed out"),
                    }
                });
                if tx.is_closed() {
                    break;
                }
            }
        });
        Ok(Self {
            ready,
            local_addr,
            current,
        })
    }

    /// The rustls configuration in use now (Z5-T8 serves HTTP/3 with it).
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.current.load_full()
    }
}

/// Z5-T8: `app.tls.http3` needs a server built with the `http3` feature;
/// asking for it without one fails at boot with this message rather than
/// serving TCP only and advertising nothing.
pub fn check_http3(tls: &TlsSection) -> Result<(), TlsError> {
    if tls.http3 && !cfg!(feature = "http3") {
        return Err(TlsError::Config(
            "app.tls.http3 is on, but this server was built without the `http3` feature (cargo build --features http3)"
                .into(),
        ));
    }
    Ok(())
}

/// S11-T3: the make-service the server serves a [`TlsListener`] with. Each
/// connection's requests carry `ConnectInfo<SocketAddr>` (as
/// `into_make_service_with_connect_info` gives them) and, when the client
/// presented a verified certificate, its
/// [`attome_auth::mtls::ClientCertificate`].
#[derive(Clone)]
pub struct TlsMakeService {
    app: axum::Router,
}

impl std::fmt::Debug for TlsMakeService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsMakeService").finish_non_exhaustive()
    }
}

impl TlsMakeService {
    pub fn new(app: axum::Router) -> Self {
        Self { app }
    }
}

impl<'a> tower::Service<axum::serve::IncomingStream<'a, TlsListener>> for TlsMakeService {
    type Response = WithConnection;
    type Error = Infallible;
    type Future = std::future::Ready<Result<WithConnection, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, stream: axum::serve::IncomingStream<'a, TlsListener>) -> Self::Future {
        // rustls verified the chain in the handshake; the leaf comes first.
        let certificate = stream
            .io()
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|leaf| attome_auth::mtls::ClientCertificate {
                thumbprint: attome_auth::mtls::thumbprint(leaf),
            });
        std::future::ready(Ok(WithConnection {
            app: self.app.clone(),
            peer: *stream.remote_addr(),
            certificate,
        }))
    }
}

/// One connection's service: the app, with the connection's peer address and
/// client certificate put on every request.
#[derive(Clone)]
pub struct WithConnection {
    app: axum::Router,
    peer: SocketAddr,
    certificate: Option<attome_auth::mtls::ClientCertificate>,
}

impl std::fmt::Debug for WithConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithConnection")
            .field("peer", &self.peer)
            .field("certificate", &self.certificate)
            .finish_non_exhaustive()
    }
}

impl tower::Service<axum::extract::Request> for WithConnection {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = <axum::Router as tower::Service<axum::extract::Request>>::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        <axum::Router as tower::Service<axum::extract::Request>>::poll_ready(&mut self.app, cx)
    }

    fn call(&mut self, mut req: axum::extract::Request) -> Self::Future {
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(self.peer));
        if let Some(certificate) = &self.certificate {
            req.extensions_mut().insert(certificate.clone());
        }
        tower::Service::call(&mut self.app, req)
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(next) => next,
            // The accept task only ends once the server stopped taking
            // streams; nothing is left to hand out.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

fn spawn_reload(current: Arc<ArcSwap<ServerConfig>>, tls: TlsSection, client_ca: Option<String>) {
    let reload = move |why: &str| match server_config_with(&tls, client_ca.as_deref()) {
        Ok(config) => {
            current.store(config);
            tracing::info!(why, "tls: certificate reloaded");
        }
        Err(e) => {
            tracing::error!(why, error = %e, "tls: reload failed; the current certificate stays")
        }
    };
    tokio::spawn(async move {
        let mut every = tokio::time::interval(RELOAD_EVERY);
        every.tick().await;
        #[cfg(unix)]
        let mut hangup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
        loop {
            #[cfg(unix)]
            {
                let on_hangup = async {
                    match hangup.as_mut() {
                        Some(signal) => {
                            signal.recv().await;
                        }
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    _ = every.tick() => reload("interval"),
                    () = on_hangup => reload("SIGHUP"),
                }
            }
            #[cfg(not(unix))]
            {
                every.tick().await;
                reload("interval");
            }
        }
    });
}

/// Z5-T7: logs `der`'s expiry at `info` and sets the
/// `tls_certificate_expiry_seconds` gauge to it (Unix seconds). A
/// certificate that does not parse is logged and leaves the gauge alone.
pub fn record_expiry(der: &[u8], source: &'static str) {
    match certificate_expiry(der) {
        Some(expires) => {
            let left_days = (expires - chrono::Utc::now().timestamp()) / 86_400;
            tracing::info!(source, expires, left_days, "tls: certificate expiry");
            metrics::gauge!("tls_certificate_expiry_seconds").set(expires as f64);
        }
        None => tracing::warn!(source, "tls: the certificate's expiry could not be read"),
    }
}

/// The Unix time `der` (a DER certificate) stops being valid.
pub fn certificate_expiry(der: &[u8]) -> Option<i64> {
    x509_parser::parse_x509_certificate(der)
        .ok()
        .map(|(_, cert)| cert.validity().not_after.timestamp())
}

mod acme {
    //! Z5-T7: the ACME half of the edge.

    use std::sync::Arc;

    use attome_config::TlsSection;
    use futures_util::StreamExt;
    use rustls::ServerConfig;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    use rustls_acme::caches::DirCache;
    use rustls_acme::{AccountCache, AcmeConfig, CertCache, EventOk};

    use super::TlsError;

    /// The ALPN protocol of a TLS-ALPN-01 validation.
    pub(super) const ALPN: &[u8] = rustls_acme::acme::ACME_TLS_ALPN_NAME;

    /// The directory cache, recording each certificate's expiry as it is
    /// loaded (a restart) or stored (an order or renewal).
    struct ExpiryCache(DirCache<String>);

    fn record_pem(pem: &[u8]) {
        match CertificateDer::pem_slice_iter(pem).next() {
            Some(Ok(cert)) => super::record_expiry(&cert, "acme"),
            _ => tracing::warn!("tls: the ACME certificate holds no readable certificate"),
        }
    }

    #[async_trait::async_trait]
    impl CertCache for ExpiryCache {
        type EC = std::io::Error;

        async fn load_cert(
            &self,
            domains: &[String],
            directory_url: &str,
        ) -> Result<Option<Vec<u8>>, Self::EC> {
            let cert = self.0.load_cert(domains, directory_url).await?;
            if let Some(pem) = &cert {
                record_pem(pem);
            }
            Ok(cert)
        }

        async fn store_cert(
            &self,
            domains: &[String],
            directory_url: &str,
            cert: &[u8],
        ) -> Result<(), Self::EC> {
            record_pem(cert);
            self.0.store_cert(domains, directory_url, cert).await
        }
    }

    #[async_trait::async_trait]
    impl AccountCache for ExpiryCache {
        type EA = std::io::Error;

        async fn load_account(
            &self,
            contact: &[String],
            directory_url: &str,
        ) -> Result<Option<Vec<u8>>, Self::EA> {
            self.0.load_account(contact, directory_url).await
        }

        async fn store_account(
            &self,
            contact: &[String],
            directory_url: &str,
            account: &[u8],
        ) -> Result<(), Self::EA> {
            self.0.store_account(contact, directory_url, account).await
        }
    }

    /// The server configuration whose certificate the ACME state keeps
    /// current, and the task that orders and renews it.
    pub(super) fn start(
        tls: &TlsSection,
        client_verifier: Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>,
    ) -> Result<Arc<ServerConfig>, TlsError> {
        let acme = &tls.acme;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let domains: Vec<String> = acme
            .domains
            .iter()
            .map(|d| d.trim().to_owned())
            .filter(|d| !d.is_empty())
            .collect();
        let mut state = AcmeConfig::new_with_provider(domains.clone(), provider.clone())
            .contact_push(format!("mailto:{}", acme.contact_email.trim()))
            .directory(acme.directory_url.trim())
            .cache(ExpiryCache(DirCache::new(acme.cache_dir.trim().to_owned())))
            .state();
        let versions: &[&'static rustls::SupportedProtocolVersion] = if tls.tls13_only() {
            &[&rustls::version::TLS13]
        } else {
            &[&rustls::version::TLS13, &rustls::version::TLS12]
        };
        let builder = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| TlsError::Config(e.to_string()))?;
        let builder = match client_verifier {
            Some(verifier) => builder.with_client_cert_verifier(verifier),
            None => builder.with_no_client_auth(),
        };
        let mut config = builder.with_cert_resolver(state.resolver());
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), ALPN.to_vec()];
        tracing::info!(?domains, directory = %acme.directory_url, "tls: certificates over ACME (TLS-ALPN-01)");
        // Process-lifetime supervision (guidelines §10): the state orders,
        // renews and swaps the certificate for as long as the server runs.
        tokio::spawn(async move {
            while let Some(event) = state.next().await {
                match event {
                    Ok(EventOk::DeployedNewCert) => tracing::info!("tls: ACME certificate renewed"),
                    Ok(ok) => tracing::info!(event = ?ok, "tls: ACME"),
                    Err(error) => {
                        tracing::warn!(%error, "tls: ACME order or renewal failed; retrying")
                    }
                }
            }
        });
        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod expiry_tests {
    use super::certificate_expiry;

    #[test]
    fn the_fixture_certificate_expiry_is_read() {
        let pem = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/tls/cert.pem"
        ))
        .expect("the tls_edge fixture");
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let der = CertificateDer::pem_slice_iter(&pem)
            .next()
            .unwrap()
            .unwrap();
        let expires = certificate_expiry(&der).expect("a parsable certificate");
        assert!(expires > 1_600_000_000, "{expires}");
        assert_eq!(certificate_expiry(b"not a certificate"), None);
    }
}
