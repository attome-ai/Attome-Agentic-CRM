use std::time::Duration;

use http::Method;
use object_store::{path::Path, signer::Signer};

use crate::{StorageError, client::StorageClient};

/// SigV4's ceiling for a presigned URL's lifetime (`X-Amz-Expires`): 7 days.
pub(crate) const MAX_PRESIGN_EXPIRY: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Returns a presigned URL for uploading a file (PUT).
/// `key` is the object path inside the bucket, e.g. `"tenants/uuid/files/photo.jpg"`.
///
/// The URL is signed for `storage.s3_public_endpoint` when that is set,
/// otherwise for `s3_endpoint`. `expires_in` must be between 1 second and
/// 7 days ([`StorageError::InvalidExpiry`] otherwise).
pub async fn presign_upload(
    client: &StorageClient,
    key: &str,
    expires_in: Duration,
) -> Result<String, StorageError> {
    presign(client, Method::PUT, key, expires_in).await
}

/// Returns a presigned URL for downloading a file (GET). Same endpoint and
/// expiry rules as [`presign_upload`].
pub async fn presign_download(
    client: &StorageClient,
    key: &str,
    expires_in: Duration,
) -> Result<String, StorageError> {
    presign(client, Method::GET, key, expires_in).await
}

async fn presign(
    client: &StorageClient,
    method: Method,
    key: &str,
    expires_in: Duration,
) -> Result<String, StorageError> {
    let outcome = presign_url(client, method, key, expires_in).await;
    if outcome.is_err() {
        // C8/BST-10: a signing failure is a caller-visible 500 on the upload
        // and download routes, and until now it lived only in a log line.
        // The URL itself is never logged or put in a message — it is a
        // working credential until it expires (I10).
        metrics::counter!("storage_presign_failures_total").increment(1);
    }
    outcome
}

async fn presign_url(
    client: &StorageClient,
    method: Method,
    key: &str,
    expires_in: Duration,
) -> Result<String, StorageError> {
    // `X-Amz-Expires` is whole seconds, so anything under 1s would sign as 0.
    if expires_in < Duration::from_secs(1) || expires_in > MAX_PRESIGN_EXPIRY {
        return Err(StorageError::InvalidExpiry(expires_in));
    }

    let path = Path::parse(key).map_err(|e| StorageError::InvalidPath(e.to_string()))?;

    let url = client
        .presign_store
        .signed_url(method, &path, expires_in)
        .await
        .map_err(StorageError::Presign)?;

    Ok(url.to_string())
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// SigV4 presigning is a local HMAC over the given static credentials, so these
// run against fake endpoints with no backend. They inspect the URL only;
// `tests/presign_roundtrip.rs` proves a real backend accepts it. URLs are
// parsed and compared part by part — never byte-compared (`X-Amz-Date`
// changes every second) and never printed in assertion messages.
#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::client::{create_storage_client, create_storage_client_for};
    use crate::test_support::{target, test_config_with_public_endpoint};

    const KEY: &str = "tenants/t1/files/photo.jpg";
    const TTL: Duration = Duration::from_secs(300);

    struct SignedUrl {
        scheme: String,
        authority: String,
        path: String,
        query: String,
    }

    impl SignedUrl {
        fn parse(url: &str) -> Self {
            let uri: http::Uri = url.parse().expect("a presigned URL must parse as a URI");
            Self {
                scheme: uri.scheme_str().unwrap_or_default().to_owned(),
                authority: uri
                    .authority()
                    .map(|a| a.as_str().to_owned())
                    .unwrap_or_default(),
                path: uri.path().to_owned(),
                query: uri.query().unwrap_or_default().to_owned(),
            }
        }

        fn param(&self, name: &str) -> Option<&str> {
            self.query.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                k.eq_ignore_ascii_case(name).then_some(v)
            })
        }
    }

    async fn client(endpoint: &str, public_endpoint: &str) -> StorageClient {
        let config = test_config_with_public_endpoint("my-bucket", endpoint, public_endpoint);
        create_storage_client(&config)
            .await
            .expect("client construction is local, no network access")
    }

    async fn both_urls(client: &StorageClient) -> [String; 2] {
        [
            presign_upload(client, KEY, TTL)
                .await
                .expect("presigning is a local SigV4 computation"),
            presign_download(client, KEY, TTL)
                .await
                .expect("presigning is a local SigV4 computation"),
        ]
    }

    #[tokio::test]
    async fn with_no_public_endpoint_urls_are_signed_for_the_internal_endpoint() {
        let client = client("http://localhost:9000", "").await;

        for url in both_urls(&client).await {
            let signed = SignedUrl::parse(&url);
            assert_eq!(signed.scheme, "http");
            assert_eq!(signed.authority, "localhost:9000");
            assert_eq!(signed.path, format!("/my-bucket/{KEY}"));
            assert_eq!(signed.param("X-Amz-Expires"), Some("300"));
            assert!(
                signed.param("X-Amz-Signature").is_some(),
                "a presigned URL must carry a SigV4 signature"
            );
        }
    }

    #[tokio::test]
    async fn with_a_public_endpoint_urls_are_signed_for_the_public_endpoint() {
        // Wired end to end from `storage.s3_public_endpoint`, not just from
        // an `S3Target` built by hand.
        let client = client("http://rustfs-dev:9000", "https://files.example.com").await;

        for url in both_urls(&client).await {
            let signed = SignedUrl::parse(&url);
            assert_eq!(signed.scheme, "https");
            assert_eq!(signed.authority, "files.example.com");
            assert_eq!(signed.path, format!("/my-bucket/{KEY}"));
            assert_eq!(signed.param("X-Amz-Expires"), Some("300"));
            assert!(signed.param("X-Amz-Signature").is_some());
        }
    }

    #[tokio::test]
    async fn verify_ssl_never_changes_the_signed_scheme() {
        for (endpoint, verify_ssl, expected_scheme) in [
            ("https://s3.example.com", true, "https"),
            ("https://s3.example.com", false, "https"),
            ("http://localhost:9000", true, "http"),
            ("http://localhost:9000", false, "http"),
            ("", true, "https"),
            ("", false, "https"),
        ] {
            let client =
                create_storage_client_for(target("my-bucket", endpoint, "", verify_ssl), "test")
                    .await
                    .expect("client construction is local, no network access");
            let url = presign_download(&client, KEY, TTL)
                .await
                .expect("presigning is a local SigV4 computation");

            assert_eq!(
                SignedUrl::parse(&url).scheme,
                expected_scheme,
                "endpoint {endpoint:?}, verify_ssl {verify_ssl}"
            );
        }
    }

    #[tokio::test]
    async fn presign_upload_and_download_sign_different_http_methods() {
        let client = client("http://localhost:9000", "").await;
        let [upload_url, download_url] = both_urls(&client).await;

        // Different signed methods (PUT vs GET) must not produce identical
        // signatures for the same key.
        assert_ne!(
            SignedUrl::parse(&upload_url).param("X-Amz-Signature"),
            SignedUrl::parse(&download_url).param("X-Amz-Signature")
        );
    }

    #[tokio::test]
    async fn presign_upload_rejects_a_path_traversal_key() {
        let client = client("http://localhost:9000", "").await;

        let result = presign_upload(&client, "../../etc/passwd", Duration::from_secs(60)).await;
        assert!(
            matches!(result, Err(StorageError::InvalidPath(_))),
            "a '..' path segment must be rejected"
        );
    }

    /// BST-10: every failed signing attempt increments the counter the
    /// presign-failure alert watches. `cargo test` runs a binary's tests in
    /// parallel, so this compares a before/after delta rather than a total.
    #[tokio::test]
    async fn a_failed_presign_increments_the_failure_counter() {
        let recorder = crate::test_support::TestRecorder::install();
        let client = client("http://localhost:9000", "").await;

        let before = recorder.counter("storage_presign_failures_total");
        assert!(
            presign_upload(&client, KEY, Duration::ZERO).await.is_err(),
            "a zero expiry must fail"
        );
        assert!(
            presign_upload(&client, "../../etc/passwd", TTL)
                .await
                .is_err(),
            "a traversal key must fail"
        );
        assert!(
            recorder.counter("storage_presign_failures_total") >= before + 2,
            "both failed attempts must be counted"
        );
    }

    #[tokio::test]
    async fn expiry_must_be_between_one_second_and_seven_days() {
        let client = client("http://localhost:9000", "").await;

        for rejected in [
            Duration::ZERO,
            Duration::from_millis(999),
            MAX_PRESIGN_EXPIRY + Duration::from_secs(1),
        ] {
            assert!(
                matches!(
                    presign_upload(&client, KEY, rejected).await,
                    Err(StorageError::InvalidExpiry(d)) if d == rejected
                ),
                "upload expiry {rejected:?} must be rejected"
            );
            assert!(
                matches!(
                    presign_download(&client, KEY, rejected).await,
                    Err(StorageError::InvalidExpiry(d)) if d == rejected
                ),
                "download expiry {rejected:?} must be rejected"
            );
        }

        for accepted in [Duration::from_secs(1), MAX_PRESIGN_EXPIRY] {
            let url = presign_upload(&client, KEY, accepted)
                .await
                .unwrap_or_else(|e| panic!("expiry {accepted:?} must be accepted: {e}"));
            assert_eq!(
                SignedUrl::parse(&url).param("X-Amz-Expires"),
                Some(accepted.as_secs().to_string().as_str())
            );
        }
    }
}
