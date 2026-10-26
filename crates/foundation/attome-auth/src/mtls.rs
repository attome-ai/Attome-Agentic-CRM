//! S11-T3: certificate-bound access tokens (RFC 8705 §3).
//!
//! When `s2s.mtls.enabled`, a client that presents a TLS client certificate
//! at the token endpoint gets an access token carrying the certificate's
//! SHA-256 thumbprint (`cnf.x5t#S256`, base64url without padding). A bound
//! token is then accepted only on a connection presenting that same
//! certificate: a stolen token is useless without the private key.
//!
//! The certificate reaches a request one of two ways, both as a
//! [`ClientCertificate`] request extension or header the caller resolves:
//! the built-in TLS edge inserts it after a verified handshake, or, when TLS
//! ends at nginx, the proxy forwards the verified certificate URL-escaped
//! (`$ssl_client_escaped_cert`) in a header that is read only from a peer in
//! `security.trusted_proxy_cidrs` ([`thumbprint_from_escaped_pem`]).
//!
//! A thumbprint names a public certificate; it is no secret, so it is
//! compared plainly and may be logged.

use attome_types::AppError;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::oauth_token::AccessClaims;

/// The verified client certificate of the connection a request came on, as
/// its RFC 8705 thumbprint. The TLS edge inserts it as a request extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertificate {
    pub thumbprint: String,
}

/// The RFC 8705 `x5t#S256` of a DER certificate: base64url (no padding) of
/// its SHA-256.
pub fn thumbprint(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

/// The thumbprint of the first certificate in a URL-escaped PEM, as nginx's
/// `$ssl_client_escaped_cert` sends it. `None` for an empty value (nginx sends
/// one when the client presented no certificate) or anything that is not a
/// PEM certificate.
pub fn thumbprint_from_escaped_pem(value: &str) -> Option<String> {
    let pem = percent_decode(value.trim())?;
    let body = pem
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)?
        .split("-----END CERTIFICATE-----")
        .next()?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if b64.is_empty() {
        return None;
    }
    let der = STANDARD.decode(b64).ok()?;
    Some(thumbprint(&der))
}

/// `%XX` decoding (`+` is left alone: nginx escapes it). `None` on a broken
/// escape or a result that is not UTF-8.
fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Refuses a certificate-bound token presented without its certificate:
/// a token carrying `cnf.x5t#S256` passes only when `presented` is the same
/// thumbprint. An unbound token passes whatever is presented.
pub fn check_binding(claims: &AccessClaims, presented: Option<&str>) -> Result<(), AppError> {
    match (&claims.cnf, presented) {
        (None, _) => Ok(()),
        (Some(cnf), Some(presented)) if cnf.x5t_s256 == presented => Ok(()),
        (Some(_), _) => Err(AppError::Unauthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth_token::Confirmation;
    use crate::{SessionClaims, TokenType};
    use uuid::Uuid;

    fn claims(cnf: Option<&str>) -> AccessClaims {
        AccessClaims {
            claims: SessionClaims {
                sub: Uuid::nil(),
                iat: 0,
                exp: 600,
                jti: Uuid::nil(),
                epoch: 0,
                iss: "attome-test".into(),
                aud: "attome-test".into(),
                typ: TokenType::S2sAccess,
            },
            client_id: "erp-sync".into(),
            scope: String::new(),
            cnf: cnf.map(|t| Confirmation {
                x5t_s256: t.to_owned(),
            }),
        }
    }

    #[test]
    fn mtls_bound_thumbprint_is_base64url_sha256() {
        // SHA-256 of the empty input.
        assert_eq!(
            thumbprint(b""),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    #[test]
    fn mtls_bound_token_needs_its_certificate() {
        let bound = claims(Some("thumb-a"));
        assert!(check_binding(&bound, Some("thumb-a")).is_ok());
        assert!(
            check_binding(&bound, Some("thumb-b")).is_err(),
            "another certificate is refused"
        );
        assert!(
            check_binding(&bound, None).is_err(),
            "no certificate is refused"
        );
    }

    #[test]
    fn mtls_bound_unbound_token_passes_with_or_without_a_certificate() {
        let unbound = claims(None);
        assert!(check_binding(&unbound, None).is_ok());
        assert!(check_binding(&unbound, Some("thumb-a")).is_ok());
    }

    #[test]
    fn mtls_bound_cnf_serializes_as_rfc8705() {
        let json = serde_json::to_value(claims(Some("thumb-a"))).unwrap();
        assert_eq!(json["cnf"]["x5t#S256"], "thumb-a");
        let unbound = serde_json::to_value(claims(None)).unwrap();
        assert!(unbound.get("cnf").is_none(), "no cnf on an unbound token");
    }

    #[test]
    fn mtls_bound_escaped_pem_matches_the_der_thumbprint() {
        let der = [0x30u8, 0x03, 0x02, 0x01, 0x05];
        let pem = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            STANDARD.encode(der)
        );
        let escaped = pem
            .replace('\n', "%0A")
            .replace(' ', "%20")
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        assert_eq!(
            thumbprint_from_escaped_pem(&escaped).as_deref(),
            Some(thumbprint(&der).as_str())
        );
        assert_eq!(
            thumbprint_from_escaped_pem(""),
            None,
            "nginx: no certificate"
        );
        assert_eq!(thumbprint_from_escaped_pem("%ZZ"), None);
        assert_eq!(thumbprint_from_escaped_pem("not a certificate"), None);
    }
}
