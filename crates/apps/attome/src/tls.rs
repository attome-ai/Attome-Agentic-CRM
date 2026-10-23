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

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use attome_config::TlsSection;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
}

/// The rustls server configuration `tls` describes.
pub fn server_config(tls: &TlsSection) -> Result<Arc<ServerConfig>, TlsError> {
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
    let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| TlsError::Key {
        path: key_path.to_owned(),
        reason: e.to_string(),
    })?;

    let versions: &[&'static rustls::SupportedProtocolVersion] = if tls.tls13_only() {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .map_err(|e| TlsError::Config(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| TlsError::Config(e.to_string()))?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The server's listener when TLS is on: TLS streams, already handshaken.
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<tokio::net::TcpStream>, SocketAddr)>,
    local_addr: SocketAddr,
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
        let current = Arc::new(ArcSwap::new(server_config(tls)?));
        spawn_reload(current.clone(), tls.clone());
        let local_addr = tcp
            .local_addr()
            .map_err(|e| TlsError::Config(e.to_string()))?;
        let (tx, ready) = mpsc::channel(READY_QUEUE);
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
                let acceptor = TlsAcceptor::from(current.load_full());
                let sender = tx.clone();
                tokio::spawn(async move {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
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
        Ok(Self { ready, local_addr })
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

fn spawn_reload(current: Arc<ArcSwap<ServerConfig>>, tls: TlsSection) {
    let reload = move |why: &str| match server_config(&tls) {
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
