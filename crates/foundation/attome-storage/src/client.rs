use std::{sync::Arc, time::Duration};

use attome_config::{AppConfig, S3Target};
use object_store::{
    BackoffConfig, ClientOptions, ObjectStore, RetryConfig,
    aws::{AmazonS3, AmazonS3Builder},
};
use tracing::info;

use crate::StorageError;

// Timeout and retry policy (guidelines §10: external calls get an explicit
// bound, not an implicit library default). There is no `StorageSection` knob
// for any of these.
//
// - `S3_REQUEST_TIMEOUT` applies per attempt and covers the whole request,
//   including reading the response body. A streaming GET that needs longer
//   than this fails that attempt and a retry starts from byte zero.
// - Connect errors, and timeouts on idempotent requests (GET, HEAD, DELETE,
//   overwrite PUT), are retried with backoff.
// - No new attempt starts once `S3_MAX_RETRIES` retries have happened or
//   `S3_RETRY_TIMEOUT` has elapsed since the first attempt. An attempt already
//   running can still use its full `S3_REQUEST_TIMEOUT`, so one call against a
//   hung backend can take roughly 180-210s. Don't multiply retries by timeout;
//   `S3_RETRY_TIMEOUT` is the controlling limit.
//
// The retry values equal object_store 0.14's defaults: stating them here
// changes no behaviour, it makes the policy visible. Change them only with
// measured evidence of real object sizes and transfer times.
const S3_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const S3_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const S3_MAX_RETRIES: usize = 10;
const S3_RETRY_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Clone)]
pub struct StorageClient {
    /// Server-side object traffic. Built from `S3Target::endpoint`, and the
    /// only client `store()`, `store_arc()` and `health_check` ever use.
    pub(crate) inner: Arc<AmazonS3>,
    /// Used only to sign presigned URLs that browsers or other clients request
    /// directly. Built from `S3Target::public_endpoint` when that is set (same
    /// bucket, region and credentials; only the endpoint differs), otherwise
    /// the same `Arc` as `inner`. Never return this from `store()` or
    /// `store_arc()`: server-side traffic must not go through the public
    /// endpoint.
    pub(crate) presign_store: Arc<AmazonS3>,
    pub(crate) bucket: String,
}

impl std::fmt::Debug for StorageClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageClient")
            .field("bucket", &self.bucket)
            .finish_non_exhaustive()
    }
}

impl StorageClient {
    pub fn store(&self) -> &dyn ObjectStore {
        self.inner.as_ref()
    }

    /// Owned trait-object handle, for APIs that need `Arc<dyn ObjectStore>`
    /// rather than a borrow — e.g. `object_store::buffered::BufWriter::new`,
    /// which outlives the borrow of any single call site (streaming
    /// multipart export; see `xrm_server::retention`). Cloning the `Arc` is
    /// cheap; it does not open a new connection.
    pub fn store_arc(&self) -> Arc<dyn ObjectStore> {
        self.inner.clone()
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}

/// This deployment's general upload bucket — `config.storage`.
pub async fn create_storage_client(config: &AppConfig) -> Result<StorageClient, StorageError> {
    create_storage_client_for(config.storage.s3_target(), "storage").await
}

/// Builds a client for **any** one S3-compatible bucket named by an
/// [`S3Target`], rather than only `config.storage`.
///
/// D-352 split this out of `create_storage_client` because a deployment now
/// has two buckets with two credentials that must not be interchangeable: the
/// upload bucket (whose credential holds `DeleteObject`) and the audit-anchor
/// bucket (whose credential must not). `label` names which one, for the log
/// line only — nothing branches on it, so this function has no notion of
/// "anchor" and stays a generic base-layer builder.
///
/// When `target.public_endpoint` is set, a second `AmazonS3` is built for
/// presigning only. Building it does no network I/O; it adds client state,
/// plus connection resources once presigned URLs are generated through it.
///
/// Note what this does NOT do: nothing here can verify the target bucket's
/// Object Lock configuration, and no code path in this crate attempts to set
/// it. WORM is provisioned out-of-band on the bucket; see
/// `deploy/audit-anchor/README.md` and `AnchorStoreSection`'s doc.
pub async fn create_storage_client_for(
    target: S3Target<'_>,
    label: &str,
) -> Result<StorageClient, StorageError> {
    let inner = Arc::new(build_s3(&target, target.endpoint)?);
    let presign_store = if target.public_endpoint.is_empty() {
        Arc::clone(&inner)
    } else {
        Arc::new(build_s3(&target, target.public_endpoint)?)
    };

    info!(
        %label,
        bucket = %target.bucket,
        endpoint = %target.endpoint,
        public_endpoint = %target.public_endpoint,
        "storage client ready"
    );

    Ok(StorageClient {
        inner,
        presign_store,
        bucket: target.bucket.to_owned(),
    })
}

/// One `AmazonS3` for `target`'s bucket, region and credentials, pointed at
/// `endpoint`. An empty endpoint selects AWS S3 proper.
///
/// TLS semantics: the endpoint's scheme alone decides whether plaintext HTTP
/// is allowed (`http://` is plaintext; `https://` or empty is TLS).
/// `verify_ssl` only decides whether HTTPS certificates are verified;
/// `verify_ssl = true` never turns an `http://` endpoint into HTTPS.
fn build_s3(target: &S3Target<'_>, endpoint: &str) -> Result<AmazonS3, StorageError> {
    // Every client option goes on this one value: `with_client_options`
    // replaces options set on the builder earlier (including
    // `with_allow_http`), so splitting them across the two would be
    // order-dependent.
    let client_options = ClientOptions::new()
        .with_connect_timeout(S3_CONNECT_TIMEOUT)
        .with_timeout(S3_REQUEST_TIMEOUT)
        .with_allow_http(endpoint.starts_with("http://"))
        .with_allow_invalid_certificates(!target.verify_ssl);

    let mut builder = AmazonS3Builder::new()
        .with_region(target.region)
        .with_bucket_name(target.bucket)
        .with_access_key_id(target.access_key)
        .with_secret_access_key(target.secret_key)
        .with_client_options(client_options)
        .with_retry(RetryConfig {
            backoff: BackoffConfig::default(),
            max_retries: S3_MAX_RETRIES,
            retry_timeout: S3_RETRY_TIMEOUT,
        });

    // RustFS / MinIO: custom endpoint. Path-style addressing
    // (`{endpoint}/{bucket}/{key}`) is object_store's default for it.
    if !endpoint.is_empty() {
        builder = builder.with_endpoint(endpoint);
    }

    Ok(builder.build()?)
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// `AmazonS3Builder::build()` only assembles local config/HTTP-client state
// from the static credentials given — it never dials the endpoint (that only
// happens on the first actual `ObjectStore` request) — so this is safe to
// run without a live RustFS/MinIO/S3 backend. Nothing here issues a request.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{target, test_config};

    fn data_ptr(store: &dyn ObjectStore) -> *const () {
        store as *const dyn ObjectStore as *const ()
    }

    #[tokio::test]
    async fn wires_the_configured_bucket_through_with_no_network_access() {
        let config = test_config("my-test-bucket", "http://localhost:9000");

        let client = create_storage_client(&config)
            .await
            .expect("building the client is local config assembly, no connection attempted");

        assert_eq!(client.bucket(), "my-test-bucket");
    }

    #[tokio::test]
    async fn store_arc_yields_a_usable_trait_object_without_a_new_connection() {
        let config = test_config("my-test-bucket", "http://localhost:9000");
        let client = create_storage_client(&config)
            .await
            .expect("building the client is local config assembly, no connection attempted");

        let store_arc = client.store_arc();
        // Compare the data pointer (not the fat pointer, whose vtable half
        // isn't meaningful here) against `store()`'s borrow of the same
        // field, confirming this is a cheap clone of the existing client,
        // not a second one built from scratch.
        assert!(std::ptr::eq(
            data_ptr(store_arc.as_ref()),
            data_ptr(client.store())
        ));
    }

    #[tokio::test]
    async fn with_a_public_endpoint_store_never_hands_out_the_presign_client() {
        let client = create_storage_client_for(
            target(
                "b",
                "http://localhost:9000",
                "https://files.example.com",
                true,
            ),
            "test",
        )
        .await
        .expect("client construction is local, no network access");

        assert!(!Arc::ptr_eq(&client.inner, &client.presign_store));
        let presign = data_ptr(client.presign_store.as_ref());
        assert!(!std::ptr::eq(data_ptr(client.store()), presign));
        assert!(!std::ptr::eq(
            data_ptr(client.store_arc().as_ref()),
            presign
        ));
        assert!(std::ptr::eq(
            data_ptr(client.store()),
            data_ptr(client.inner.as_ref())
        ));
    }

    #[tokio::test]
    async fn with_no_public_endpoint_presigning_reuses_the_internal_client() {
        let client =
            create_storage_client_for(target("b", "http://localhost:9000", "", true), "test")
                .await
                .expect("client construction is local, no network access");

        assert!(Arc::ptr_eq(&client.inner, &client.presign_store));
    }
}
