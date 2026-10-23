use std::{sync::Arc, time::Duration};

use attome_config::{
    AppConfig, AzureStorageSettings, GcsStorageSettings, LocalStorageSettings, S3Target,
    StorageBackend,
};
use object_store::{
    BackoffConfig, ClientOptions, ObjectStore, RetryConfig,
    aws::{AmazonS3, AmazonS3Builder},
    azure::{MicrosoftAzure, MicrosoftAzureBuilder},
    gcp::{GoogleCloudStorage, GoogleCloudStorageBuilder},
    local::LocalFileSystem,
    signer::Signer,
};
use tracing::info;

use crate::{StorageError, local::LinkSigner};

// Timeout and retry policy (guidelines §10: external calls get an explicit
// bound, not an implicit library default). There is no `StorageSection` knob
// for any of these, and every cloud backend (S3, Azure, GCS) uses the same
// values.
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
//
// AB6-T4: a cloud store's own retries are off (`S3_MAX_RETRIES` is not used
// for server-side traffic): every call goes through `crate::outbound`, which
// retries idempotent calls within the `object_storage` service's budget, so a
// failing store is not retried twice over. The presign-only client keeps the
// policy above; it signs locally and never retries anything.
const S3_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const S3_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const S3_MAX_RETRIES: usize = 10;
const S3_RETRY_TIMEOUT: Duration = Duration::from_secs(180);

/// How presigned links are made for one client.
#[derive(Clone)]
pub(crate) enum Presign {
    /// The bucket signs its own URLs (S3 SigV4, an Azure SAS, a GCS V4
    /// signature), which browsers then use against the bucket directly.
    Store(Arc<dyn Signer>),
    /// Local disk has no URL of its own: links point at the server's signed
    /// `/api/v1/storage/local` route ([`crate::local`]).
    Local(LinkSigner),
}

#[derive(Clone)]
pub struct StorageClient {
    /// Server-side object traffic. Built from `S3Target::endpoint` for S3,
    /// and the only client `store()`, `store_arc()` and `health_check` ever
    /// use.
    pub(crate) inner: Arc<dyn ObjectStore>,
    /// How presigned URLs are made. For S3 with `S3Target::public_endpoint`
    /// set, the signer is a second client for that endpoint (same bucket,
    /// region and credentials; only the endpoint differs).
    pub(crate) presign: Presign,
    /// That second S3 client, kept for
    /// [`crate::public_endpoint_health_check`]; `None` in every other case.
    /// Never return this from `store()` or `store_arc()`: server-side
    /// traffic must not go through the public endpoint.
    pub(crate) public_store: Option<Arc<dyn ObjectStore>>,
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

    /// The bucket or container name; for local disk, the folder.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Z6-T1: whether presigned links point at the server's own
    /// `/api/v1/storage/local` route rather than at a bucket.
    pub fn is_local(&self) -> bool {
        matches!(self.presign, Presign::Local(_))
    }
}

/// This deployment's general upload store — `config.storage`, on the backend
/// `storage.backend` names.
pub async fn create_storage_client(config: &AppConfig) -> Result<StorageClient, StorageError> {
    let storage = &config.storage;
    match storage.backend {
        StorageBackend::S3 => create_storage_client_for(storage.s3_target(), "storage").await,
        StorageBackend::Local => create_local_client(&storage.local).await,
        StorageBackend::Azure => create_azure_client(&storage.azure),
        StorageBackend::Gcs => create_gcs_client(&storage.gcs),
    }
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
    let s3 = Arc::new(build_s3(&target, target.endpoint)?);
    let inner: Arc<dyn ObjectStore> = Arc::new(crate::outbound::Guarded::new(Arc::new(
        build_s3_with(&target, target.endpoint, no_retries())?,
    )));
    let (signer, public_store): (Arc<dyn Signer>, Option<Arc<dyn ObjectStore>>) =
        if target.public_endpoint.is_empty() {
            (s3, None)
        } else {
            let public = Arc::new(build_s3(&target, target.public_endpoint)?);
            (public.clone(), Some(public))
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
        presign: Presign::Store(signer),
        public_store,
        bucket: target.bucket.to_owned(),
    })
}

/// Z6-T1: a folder on this machine. The folder is created when it does not
/// exist; empty folders a delete leaves behind are removed.
async fn create_local_client(
    settings: &LocalStorageSettings,
) -> Result<StorageClient, StorageError> {
    tokio::fs::create_dir_all(&settings.path)
        .await
        .map_err(|e| StorageError::Setup(format!("storage.local.path: {e}")))?;
    let store = LocalFileSystem::new_with_prefix(&settings.path)?.with_automatic_cleanup(true);
    let signer = LinkSigner::new(
        settings.url_signing_key.expose().as_bytes(),
        &settings.public_base_url,
    );
    info!(path = %settings.path, "local storage ready");
    Ok(StorageClient {
        inner: Arc::new(store),
        presign: Presign::Local(signer),
        public_store: None,
        bucket: settings.path.clone(),
    })
}

/// Z6-T1: an Azure Blob Storage container, signed with the account key.
fn create_azure_client(settings: &AzureStorageSettings) -> Result<StorageClient, StorageError> {
    let endpoint = settings.endpoint.trim();
    let mut builder = MicrosoftAzureBuilder::new()
        .with_account(&settings.account)
        .with_container_name(&settings.container)
        .with_access_key(settings.access_key.expose())
        .with_client_options(client_options(endpoint.starts_with("http://"), true))
        .with_retry(no_retries());
    if !endpoint.is_empty() {
        builder = builder.with_endpoint(endpoint.to_owned());
    }
    let store: Arc<MicrosoftAzure> = Arc::new(builder.build()?);
    info!(account = %settings.account, container = %settings.container, "azure storage ready");
    Ok(StorageClient {
        inner: Arc::new(crate::outbound::Guarded::new(store.clone())),
        presign: Presign::Store(store),
        public_store: None,
        bucket: settings.container.clone(),
    })
}

/// Z6-T1: a Google Cloud Storage bucket, signed with the service account's
/// private key.
fn create_gcs_client(settings: &GcsStorageSettings) -> Result<StorageClient, StorageError> {
    let store: Arc<GoogleCloudStorage> = Arc::new(
        GoogleCloudStorageBuilder::new()
            .with_bucket_name(&settings.bucket)
            .with_service_account_key(settings.service_account_key.expose())
            .with_client_options(client_options(false, true))
            .with_retry(no_retries())
            .build()?,
    );
    info!(bucket = %settings.bucket, "gcs storage ready");
    Ok(StorageClient {
        inner: Arc::new(crate::outbound::Guarded::new(store.clone())),
        presign: Presign::Store(store),
        public_store: None,
        bucket: settings.bucket.clone(),
    })
}

/// Every client option goes on this one value: `with_client_options`
/// replaces options set on a builder earlier (including `with_allow_http`),
/// so splitting them across the two would be order-dependent.
fn client_options(allow_http: bool, verify_ssl: bool) -> ClientOptions {
    ClientOptions::new()
        .with_connect_timeout(S3_CONNECT_TIMEOUT)
        .with_timeout(S3_REQUEST_TIMEOUT)
        .with_allow_http(allow_http)
        .with_allow_invalid_certificates(!verify_ssl)
}

fn retry_config() -> RetryConfig {
    RetryConfig {
        backoff: BackoffConfig::default(),
        max_retries: S3_MAX_RETRIES,
        retry_timeout: S3_RETRY_TIMEOUT,
    }
}

/// AB6-T4: the store's own retry layer off; `crate::outbound` retries.
fn no_retries() -> RetryConfig {
    RetryConfig {
        backoff: BackoffConfig::default(),
        max_retries: 0,
        retry_timeout: S3_REQUEST_TIMEOUT,
    }
}

/// One `AmazonS3` for `target`'s bucket, region and credentials, pointed at
/// `endpoint`. An empty endpoint selects AWS S3 proper.
///
/// TLS semantics: the endpoint's scheme alone decides whether plaintext HTTP
/// is allowed (`http://` is plaintext; `https://` or empty is TLS).
/// `verify_ssl` only decides whether HTTPS certificates are verified;
/// `verify_ssl = true` never turns an `http://` endpoint into HTTPS.
fn build_s3(target: &S3Target<'_>, endpoint: &str) -> Result<AmazonS3, StorageError> {
    build_s3_with(target, endpoint, retry_config())
}

fn build_s3_with(
    target: &S3Target<'_>,
    endpoint: &str,
    retry: RetryConfig,
) -> Result<AmazonS3, StorageError> {
    let mut builder = AmazonS3Builder::new()
        .with_region(target.region)
        .with_bucket_name(target.bucket)
        .with_access_key_id(target.access_key)
        .with_secret_access_key(target.secret_key)
        .with_client_options(client_options(
            endpoint.starts_with("http://"),
            target.verify_ssl,
        ))
        .with_retry(retry);

    // RustFS / MinIO: custom endpoint. Path-style addressing
    // (`{endpoint}/{bucket}/{key}`) is object_store's default for it.
    if !endpoint.is_empty() {
        builder = builder.with_endpoint(endpoint);
    }

    Ok(builder.build()?)
}

/// Z6-T1: a client over any store with local-disk links, for tests that need
/// a working store without a disk or a bucket (an in-memory store, most
/// often).
#[cfg(test)]
pub(crate) fn client_over(store: Arc<dyn ObjectStore>, key: &[u8], base: &str) -> StorageClient {
    StorageClient {
        inner: store,
        presign: Presign::Local(LinkSigner::new(key, base)),
        public_store: None,
        bucket: "memory".to_owned(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// `AmazonS3Builder::build()` only assembles local config/HTTP-client state
// from the static credentials given — it never dials the endpoint (that only
// happens on the first actual `ObjectStore` request) — so this is safe to
// run without a live RustFS/MinIO/S3 backend. Nothing here issues a request.
// The Azure and GCS builders are the same; the local backend writes to a
// temporary folder.
#[cfg(test)]
mod tests {
    use object_store::{ObjectStoreExt, PutPayload, memory::InMemory, path::Path};

    use super::*;
    use crate::test_support::{target, test_config, test_config_with_storage};

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
        assert!(!client.is_local());
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

        let public = client
            .public_store
            .clone()
            .expect("a public endpoint builds its own client");
        let presign = data_ptr(public.as_ref());
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

        assert!(client.public_store.is_none());
        assert!(
            matches!(client.presign, Presign::Store(_)),
            "an S3 client signs its own URLs"
        );
    }

    #[tokio::test]
    async fn backend_local_creates_its_folder_and_round_trips_an_object() {
        let dir = std::env::temp_dir().join(format!(
            "attome-storage-local-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        let path = dir.join("files");
        let config = test_config_with_storage(serde_json::json!({
            "backend": "local",
            "local": {
                "path": path.to_string_lossy(),
                "url_signing_key": "test-only-local-link-key-32-bytes-min",
            }
        }));

        let client = create_storage_client(&config)
            .await
            .expect("the local backend builds over a new folder");
        assert!(client.is_local());
        assert!(path.is_dir(), "the folder is created at boot");

        let key = Path::from("tenants/t1/files/a.txt");
        client
            .store()
            .put(&key, PutPayload::from_static(b"hello"))
            .await
            .expect("write to local disk");
        let body = client
            .store()
            .get(&key)
            .await
            .expect("read back")
            .bytes()
            .await
            .expect("body");
        assert_eq!(&body[..], b"hello");
        client.store().delete(&key).await.expect("delete");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn backend_azure_and_gcs_build_without_network_access() {
        let azure = test_config_with_storage(serde_json::json!({
            "backend": "azure",
            "azure": {
                "account": "devstoreaccount1",
                "container": "attome",
                // Azurite's published development key, not a secret.
                "access_key": "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
                "endpoint": "http://127.0.0.1:10000/devstoreaccount1",
            }
        }));
        let client = create_storage_client(&azure)
            .await
            .expect("the Azure builder assembles a client without dialling");
        assert_eq!(client.bucket(), "attome");
        assert!(!client.is_local());

        let gcs = test_config_with_storage(serde_json::json!({
            "backend": "gcs",
            "gcs": { "bucket": "attome-gcs", "service_account_key": "not a key" }
        }));
        assert!(
            create_storage_client(&gcs).await.is_err(),
            "a service account key that is not Google's JSON is refused at boot"
        );
    }

    #[tokio::test]
    async fn backend_in_memory_serves_objects_behind_local_links() {
        let client = client_over(Arc::new(InMemory::new()), b"k".repeat(32).as_slice(), "");
        let key = Path::from("exports/e1.csv");
        client
            .store()
            .put(&key, PutPayload::from_static(b"a,b"))
            .await
            .expect("write to memory");
        assert!(client.is_local());
        assert_eq!(
            client.store().head(&key).await.expect("head").size,
            3,
            "the in-memory store keeps what was written"
        );
    }
}
