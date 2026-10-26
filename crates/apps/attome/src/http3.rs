//! Z5-T8: HTTP/3 over QUIC from the built-in edge, behind the `http3` cargo
//! feature and `app.tls.http3`. A quinn endpoint binds the HTTPS port over
//! UDP with the edge's own rustls configuration (ALPN `h3`, TLS 1.3, which
//! QUIC requires) and hands every request to the same axum router the TCP
//! listener serves, with the peer's address as `ConnectInfo`, so every
//! middleware layer applies unchanged. A request body is read up to
//! `app.max_body_size_bytes`; past it the request is answered 413 without
//! reaching the router. The certificate is the one in use at start: a file
//! reload or an ACME renewal reaches HTTP/3 at the next restart, while TCP
//! picks it up at once.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::ConnectInfo;
use axum::http;
use bytes::Buf;
use futures_util::StreamExt;
use tower::ServiceExt;

/// The ALPN protocol of HTTP/3.
const ALPN_H3: &[u8] = b"h3";

/// Serves `router` over HTTP/3 on `addr` (UDP) until the endpoint closes.
pub async fn serve(
    router: Router,
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    max_body_bytes: usize,
) -> std::io::Result<()> {
    let mut tls = (*tls).clone();
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| std::io::Error::other(format!("http3: TLS for QUIC: {e}")))?;
    let endpoint =
        quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(crypto)), addr)?;
    tracing::info!(%addr, "serving HTTP/3 (QUIC over UDP)");
    while let Some(incoming) = endpoint.accept().await {
        let router = router.clone();
        // Disposable per-connection task: losing it drops that connection only.
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(e) => {
                    tracing::debug!(error = %e, "http3: handshake failed");
                    return;
                }
            };
            let peer = connection.remote_address();
            let mut h3 = match h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(
                connection,
            ))
            .await
            {
                Ok(h3) => h3,
                Err(e) => {
                    tracing::debug!(%peer, error = %e, "http3: connection setup failed");
                    return;
                }
            };
            loop {
                match h3.accept().await {
                    Ok(Some(resolver)) => {
                        let router = router.clone();
                        tokio::spawn(async move {
                            if let Err(e) = answer(router, peer, resolver, max_body_bytes).await {
                                tracing::debug!(%peer, error = %e, "http3: request failed");
                            }
                        });
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(%peer, error = %e, "http3: connection ended");
                        break;
                    }
                }
            }
        });
    }
    Ok(())
}

async fn answer(
    router: Router,
    peer: SocketAddr,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    max_body_bytes: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (request, mut stream) = resolver.resolve_request().await?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        if body.len() + chunk.remaining() > max_body_bytes {
            let refused = http::Response::builder()
                .status(http::StatusCode::PAYLOAD_TOO_LARGE)
                .body(())?;
            stream.send_response(refused).await?;
            stream.finish().await?;
            return Ok(());
        }
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        body.extend_from_slice(&bytes);
    }
    let mut request = request.map(|()| Body::from(body));
    request.extensions_mut().insert(ConnectInfo(peer));
    let response = match router.oneshot(request).await {
        Ok(response) => response,
        Err(never) => match never {},
    };
    let (parts, body) = response.into_parts();
    stream
        .send_response(http::Response::from_parts(parts, ()))
        .await?;
    let mut data = body.into_data_stream();
    while let Some(chunk) = data.next().await {
        stream.send_data(chunk?).await?;
    }
    stream.finish().await?;
    Ok(())
}
