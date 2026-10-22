//! Z6-T1: upload and download links for the local-disk backend.
//!
//! A bucket signs its own presigned URLs; a folder cannot. So with
//! `storage.backend = "local"`, [`crate::presign_upload`] and
//! [`crate::presign_download`] hand out links to the server's own route,
//! [`LOCAL_LINK_PATH`], carrying the object key, an expiry and an HMAC-SHA256
//! signature over the method, the key and the expiry under
//! `storage.local.url_signing_key`. The route checks the signature with
//! [`verify_local_link`] and then reads or writes that one object.
//!
//! The permission check is the same as for a presigned bucket URL: the engine
//! that mints the link has already authorized the caller for that object, and
//! the link is a bearer credential for it until it expires (the crate doc's
//! "Presigned URLs are bearer credentials" applies unchanged). A link signed
//! for `GET` does not open a `PUT`, and a changed key or expiry fails the
//! signature.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, Mac};
use http::Method;
use object_store::path::Path;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{StorageError, client::Presign, client::StorageClient};

/// The server route local-disk links point at. One exact path; the object key
/// travels in the query string, so no wildcard route is needed.
pub const LOCAL_LINK_PATH: &str = "/api/v1/storage/local";

/// Separates these signatures from every other HMAC made with a key that an
/// operator might, against advice, reuse.
const DOMAIN: &[u8] = b"attome-storage/local-link/v1";

type HmacSha256 = Hmac<Sha256>;

/// Signs local-disk links. Cheap to clone; the key is zeroed on drop.
#[derive(Clone)]
pub(crate) struct LinkSigner {
    key: Arc<Zeroizing<Vec<u8>>>,
    /// `storage.local.public_base_url` without a trailing slash; empty for
    /// links relative to the server.
    base: String,
}

impl LinkSigner {
    pub(crate) fn new(key: &[u8], base: &str) -> Self {
        Self {
            key: Arc::new(Zeroizing::new(key.to_vec())),
            base: base.trim().trim_end_matches('/').to_owned(),
        }
    }

    /// `None` only if HMAC refused the key, which it never does: HMAC takes
    /// a key of any length.
    fn mac(&self, method: &Method, key: &str, expires: u64) -> Option<HmacSha256> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key).ok()?;
        mac.update(DOMAIN);
        for part in [method.as_str().as_bytes(), key.as_bytes()] {
            mac.update(b"\n");
            mac.update(part);
        }
        mac.update(b"\n");
        mac.update(expires.to_string().as_bytes());
        Some(mac)
    }

    /// The link for `method` on `key`, valid until `now + expires_in`.
    pub(crate) fn link(
        &self,
        method: &Method,
        key: &str,
        expires_in: Duration,
    ) -> Result<String, StorageError> {
        let expires = unix_now().saturating_add(expires_in.as_secs());
        let mac = self
            .mac(method, key, expires)
            .ok_or_else(|| StorageError::Setup("HMAC refused the link signing key".into()))?;
        let signature = hex::encode(mac.finalize().into_bytes());
        Ok(format!(
            "{base}{LOCAL_LINK_PATH}?key={key}&expires={expires}&signature={signature}",
            base = self.base,
            key = encode_query_value(key),
        ))
    }

    fn verify(&self, method: &Method, key: &str, expires: u64, signature: &str) -> bool {
        let Ok(signature) = hex::decode(signature) else {
            return false;
        };
        // `verify_slice` compares in constant time.
        expires >= unix_now()
            && self
                .mac(method, key, expires)
                .is_some_and(|mac| mac.verify_slice(&signature).is_ok())
    }
}

/// Checks a local-disk link and returns the object it opens.
///
/// [`StorageError::InvalidLink`] when the client is not on the local backend,
/// the link has expired, or the signature does not match this method, key and
/// expiry; the caller answers every one of those the same way, so a guess
/// learns nothing.
pub fn verify_local_link(
    client: &StorageClient,
    method: &Method,
    key: &str,
    expires: u64,
    signature: &str,
) -> Result<Path, StorageError> {
    let Presign::Local(signer) = &client.presign else {
        return Err(StorageError::InvalidLink);
    };
    if !signer.verify(method, key, expires, signature) {
        return Err(StorageError::InvalidLink);
    }
    Path::parse(key).map_err(|e| StorageError::InvalidPath(e.to_string()))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Percent-encodes everything but the URL-unreserved characters, so a key
/// with `/`, `+`, `&` or spaces survives the query string unchanged.
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use object_store::memory::InMemory;

    use super::*;
    use crate::client::client_over;

    const KEY: &str = "tenants/t1/files/a b+c.pdf";
    const SIGNING_KEY: &[u8] = b"test-only-local-link-key-32-bytes-min";

    fn client(base: &str) -> StorageClient {
        client_over(Arc::new(InMemory::new()), SIGNING_KEY, base)
    }

    /// The query parameters of a link, decoded.
    fn params(link: &str) -> (String, u64, String) {
        let query = link.split_once('?').expect("a link has a query").1;
        let mut key = String::new();
        let mut expires = 0;
        let mut signature = String::new();
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').expect("name=value");
            match name {
                "key" => key = decode(value),
                "expires" => expires = value.parse().expect("expiry is a number"),
                "signature" => signature = value.to_owned(),
                other => panic!("unexpected parameter {other}"),
            }
        }
        (key, expires, signature)
    }

    fn decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("ascii");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).expect("utf-8")
    }

    #[test]
    fn backend_local_link_opens_its_own_object_and_method_only() {
        let client = client("");
        let Presign::Local(signer) = &client.presign else {
            panic!("local client");
        };
        let link = signer
            .link(&Method::GET, KEY, Duration::from_secs(300))
            .expect("signing is local");
        assert!(link.starts_with("/api/v1/storage/local?key="));
        let (key, expires, signature) = params(&link);
        assert_eq!(key, KEY, "the key survives the query string");

        let path = verify_local_link(&client, &Method::GET, &key, expires, &signature)
            .expect("the link opens its object");
        assert_eq!(path.as_ref(), KEY);

        for (method, key, expires) in [
            (Method::PUT, KEY, expires),
            (Method::GET, "tenants/t1/files/other.pdf", expires),
            (Method::GET, KEY, expires + 1),
        ] {
            assert!(
                matches!(
                    verify_local_link(&client, &method, key, expires, &signature),
                    Err(StorageError::InvalidLink)
                ),
                "{method} {key} {expires} must not verify"
            );
        }
        assert!(matches!(
            verify_local_link(&client, &Method::GET, KEY, expires, "zz"),
            Err(StorageError::InvalidLink)
        ));
    }

    #[test]
    fn backend_local_link_expires_and_needs_the_same_key() {
        let client = client("https://crm.example.com/");
        let Presign::Local(signer) = &client.presign else {
            panic!("local client");
        };
        let link = signer
            .link(&Method::PUT, KEY, Duration::from_secs(60))
            .expect("signing is local");
        assert!(link.starts_with("https://crm.example.com/api/v1/storage/local?"));
        let (key, expires, signature) = params(&link);

        let past = unix_now() - 1;
        let stale = hex::encode(
            signer
                .mac(&Method::PUT, &key, past)
                .expect("HMAC takes any key")
                .finalize()
                .into_bytes(),
        );
        assert!(matches!(
            verify_local_link(&client, &Method::PUT, &key, past, &stale),
            Err(StorageError::InvalidLink)
        ));

        let other = client_over(
            Arc::new(InMemory::new()),
            b"another-key-of-32-bytes-or-more!!",
            "",
        );
        assert!(matches!(
            verify_local_link(&other, &Method::PUT, &key, expires, &signature),
            Err(StorageError::InvalidLink)
        ));
    }

    #[test]
    fn backend_local_link_is_refused_on_a_bucket_client() {
        let config = crate::test_support::test_config("b", "http://localhost:9000");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let bucket = runtime
            .block_on(crate::create_storage_client(&config))
            .expect("S3 client builds without dialling");
        assert!(matches!(
            verify_local_link(&bucket, &Method::GET, KEY, unix_now() + 60, "00"),
            Err(StorageError::InvalidLink)
        ));
    }
}
