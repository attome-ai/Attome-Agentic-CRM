//! S11-T3: the client certificate a request presents, for certificate-bound
//! OAuth access tokens (RFC 8705; [`attome_auth::mtls`]).

use std::net::SocketAddr;

use attome_auth::mtls::{ClientCertificate, thumbprint_from_escaped_pem};
use attome_config::AppConfig;
use axum::extract::ConnectInfo;
use axum::http::{Extensions, HeaderMap};

/// The thumbprint of the verified client certificate a request presents,
/// when `s2s.mtls.enabled`: the one the built-in TLS edge verified, or,
/// behind a TLS-terminating proxy, the one in `s2s.mtls.proxy_header` when
/// the request's direct peer is a trusted proxy (any other peer could set
/// the header itself). `None` when mTLS is off or nothing was presented.
pub fn presented_certificate(
    extensions: &Extensions,
    headers: &HeaderMap,
    config: &AppConfig,
) -> Option<String> {
    let mtls = &config.s2s.mtls;
    if !mtls.enabled {
        return None;
    }
    if let Some(certificate) = extensions.get::<ClientCertificate>() {
        return Some(certificate.thumbprint.clone());
    }
    let header = mtls.proxy_header.trim();
    if header.is_empty() {
        return None;
    }
    let peer = extensions.get::<ConnectInfo<SocketAddr>>()?.0.ip();
    if !config.is_trusted_proxy(peer) {
        return None;
    }
    thumbprint_from_escaped_pem(headers.get(header)?.to_str().ok()?)
}
