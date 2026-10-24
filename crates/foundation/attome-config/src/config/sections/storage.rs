//! `storage` section — the object-storage backend (S3-compatible, local disk,
//! Azure Blob or GCS) and its upload-quota/malware-scan knobs, plus
//! [`S3Target`], the connection-parameter view every S3-backed bucket in this
//! platform is built from.

use serde::Deserialize;

use crate::Secret;

use crate::config::helpers::default_true;

/// The values `attome_storage` needs to build a client for **one**
/// S3-compatible bucket, borrowed from whichever config section owns them.
///
/// Introduced by D-352 (TODO-004): a deployment now has more than one bucket
/// with more than one credential — the general upload bucket
/// ([`StorageSection`], whose credential must keep `DeleteObject` because
/// `xrm_document::files`/`files_scan` really do delete uploads and quarantine
/// objects) and the audit-anchor bucket
/// ([`AnchorStoreSection`](crate::AnchorStoreSection), whose credential must
/// NOT have it). Rather than teach `create_storage_client` a second special
/// case, both sections project into this one shape and `attome-storage` builds
/// from it — so the anchor path stays a plain second client, not a fork of
/// the storage layer.
#[derive(Clone, Copy)]
pub struct S3Target<'a> {
    /// Endpoint for server-side object traffic. Empty selects AWS S3 proper.
    pub endpoint: &'a str,
    /// Endpoint embedded in presigned URLs that browsers or other clients
    /// request directly. Never used for server-side traffic. Empty means
    /// presigned URLs are signed for `endpoint`.
    pub public_endpoint: &'a str,
    pub region: &'a str,
    pub bucket: &'a str,
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub verify_ssl: bool,
}

/// Hand-rolled for the same reason [`StorageSection`]'s is: `access_key`/
/// `secret_key` are live object-storage credentials and the derived `Debug`
/// would print both raw.
impl std::fmt::Debug for S3Target<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Target")
            .field("endpoint", &self.endpoint)
            .field("public_endpoint", &self.public_endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("access_key", &"[REDACTED]")
            .field("secret_key", &"[REDACTED]")
            .field("verify_ssl", &self.verify_ssl)
            .finish()
    }
}

/// Z6-T1: which object store holds this deployment's files. Every backend
/// goes through the `object_store` crate, so engines see one `ObjectStore`
/// whatever is behind it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    /// An S3-compatible bucket (AWS S3, RustFS, MinIO): the `s3_*` settings.
    /// The default.
    #[default]
    S3,
    /// A folder on this machine: `storage.local`. One node only, since other
    /// nodes cannot see the folder. Browsers upload and download through the
    /// server's own signed `/api/v1/storage/local/` route instead of
    /// presigned bucket URLs.
    Local,
    /// An Azure Blob Storage container: `storage.azure`.
    Azure,
    /// A Google Cloud Storage bucket: `storage.gcs`.
    Gcs,
}

/// Z6-T1: `storage.local`, used when `storage.backend = "local"`.
#[derive(Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct LocalStorageSettings {
    /// The folder that holds the files. Created at boot when it does not
    /// exist. Required with the local backend.
    #[serde(default)]
    pub path: String,
    /// Key that signs the short-lived upload and download links the server
    /// hands out in place of presigned bucket URLs (at least 32 bytes). Every
    /// process of the deployment needs the same value, so a link one process
    /// mints is accepted by another.
    #[serde(default)]
    pub url_signing_key: Secret,
    /// Address browsers reach the server at, put in front of the signed
    /// links (`https://crm.example.com`). Empty (the default) hands out links
    /// relative to the server, which a browser on the same origin follows.
    #[serde(default)]
    pub public_base_url: String,
}

impl std::fmt::Debug for LocalStorageSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalStorageSettings")
            .field("path", &self.path)
            .field("url_signing_key", &"[REDACTED]")
            .field("public_base_url", &self.public_base_url)
            .finish()
    }
}

/// Z6-T1: `storage.azure`, used when `storage.backend = "azure"`.
#[derive(Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct AzureStorageSettings {
    /// The storage account name.
    #[serde(default)]
    pub account: String,
    /// The blob container that holds the files.
    #[serde(default)]
    pub container: String,
    /// The storage account's shared access key. Presigned links are signed
    /// with it, so it must be a key rather than a token.
    #[serde(default)]
    pub access_key: Secret,
    /// A custom endpoint (an Azurite emulator, a sovereign cloud). Empty (the
    /// default) is the public Azure endpoint for the account.
    #[serde(default)]
    pub endpoint: String,
}

impl std::fmt::Debug for AzureStorageSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AzureStorageSettings")
            .field("account", &self.account)
            .field("container", &self.container)
            .field("access_key", &"[REDACTED]")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Z6-T1: `storage.gcs`, used when `storage.backend = "gcs"`.
#[derive(Clone, Default, Deserialize, schemars::JsonSchema)]
pub struct GcsStorageSettings {
    /// The bucket that holds the files.
    #[serde(default)]
    pub bucket: String,
    /// The service account key, as the JSON document Google issues. Presigned
    /// links are signed with its private key.
    #[serde(default)]
    pub service_account_key: Secret,
}

impl std::fmt::Debug for GcsStorageSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsStorageSettings")
            .field("bucket", &self.bucket)
            .field("service_account_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Deserialize, schemars::JsonSchema)]
pub struct StorageSection {
    /// `s3` (the default), `local`, `azure` or `gcs`. Only the chosen
    /// backend's settings are used; the `s3_*` settings may be left out for
    /// the others.
    #[serde(default)]
    pub backend: StorageBackend,
    #[serde(default)]
    pub local: LocalStorageSettings,
    #[serde(default)]
    pub azure: AzureStorageSettings,
    #[serde(default)]
    pub gcs: GcsStorageSettings,
    #[serde(default)]
    pub s3_endpoint: String,
    /// Endpoint embedded in presigned upload/download URLs, which browsers
    /// (or any other client) request directly. SigV4 signs the `Host`, so the
    /// URL must be signed for the address the client will actually contact;
    /// a proxy rewriting the host afterwards invalidates the signature.
    ///
    /// When set, it must be reachable by those clients, serve this same
    /// `s3_bucket`, route path-style `/{bucket}/{key}` requests with path and
    /// query preserved, and accept the `Host` it was signed for. It never
    /// replaces `s3_endpoint`: server-side reads and writes always use
    /// `s3_endpoint`. Empty (the default) signs presigned URLs for
    /// `s3_endpoint`, which is right whenever that address is already
    /// client-reachable (e.g. AWS S3 proper).
    #[serde(default)]
    pub s3_public_endpoint: String,
    #[serde(default)]
    pub s3_region: String,
    #[serde(default)]
    pub s3_access_key: String,
    #[serde(default)]
    pub s3_secret_key: Secret,
    #[serde(default)]
    pub s3_bucket: String,
    /// Whether HTTPS certificates from the S3 endpoints are verified. It does
    /// not choose the transport: the endpoint's scheme does (`http://` is
    /// plaintext whatever this says; `https://`, or empty for AWS S3, is TLS).
    /// `false` accepts any certificate on a TLS endpoint. Production refuses
    /// `false`.
    #[serde(default = "default_true")]
    pub s3_verify_ssl: bool,
    /// Max `declared_size_bytes` an upload session may declare; enforced at
    /// finalize (HEAD-verified against what was actually PUT), not at
    /// presign time (§4.2's documented limitation).
    ///
    /// TODO(item 26): true presign-time enforcement — S3 itself refusing an
    /// oversized PUT before it ever lands in quarantine storage — is still
    /// not possible with this crate. Confirmed against `object_store` 0.14's
    /// `Signer` trait (`attome-storage/src/presign.rs`): `signed_url(method,
    /// path, expires_in)` takes no content-length/policy constraint, so
    /// there is no signed header or condition this code can attach to the
    /// presigned PUT URL to make S3/RustFS reject a too-large body itself.
    /// Closing this fully needs an architecture change — either switching
    /// upload sessions to presigned POST-policy uploads (S3's
    /// `content-length-range` condition), which changes the client contract
    /// (`create_upload_session`'s response shape and the Angular
    /// `file-upload.service.ts` PUT flow both), or a storage client that
    /// exposes SigV4 signed-header control — not attempted here per
    /// guidelines' scope-discipline ("implement a safe containment... report
    /// the remaining work"). What *is* implemented as containment: the
    /// `max_user_storage_bytes`/`max_deployment_storage_bytes` quotas below
    /// bound how much quarantine exposure one user (or the deployment as a
    /// whole) can accumulate before finalize/orphan-sweep clears it, and the
    /// `presign` rate-limit category
    /// (`attome-server/middleware/rate_limit.rs`) bounds how fast a single
    /// caller can mint new quarantine capacity.
    #[serde(default = "default_max_upload_size_bytes")]
    pub max_upload_size_bytes: u64,
    /// Soft cap on one user's total upload-session footprint: the sum of
    /// `declared_max_size_bytes` across their non-terminal sessions
    /// (`pending`/`uploaded`/`scanning`) plus `actual_size_bytes` across
    /// their `clean` ones. Checked in `create_upload_session` before a new
    /// session is created (item 26 remediation — a per-user quota). `None`
    /// (the default) disables the check: an unmeasured cap would be a guess,
    /// not evidence (guidelines §14) — TODO(item 26): pick a real number
    /// with the ops/customer team once there is usage data, then set this in
    /// each deployment's `config.json`.
    #[serde(default)]
    pub max_user_storage_bytes: Option<u64>,
    /// Soft cap on the whole deployment's promoted (`clean`) file storage —
    /// meaningful because D-099's data-plane model is one dedicated
    /// deployment per customer, so this is that customer's total quota, not
    /// a cross-customer figure. `None` (the default) disables the check,
    /// same reasoning and TODO as `max_user_storage_bytes` above.
    #[serde(default)]
    pub max_deployment_storage_bytes: Option<u64>,
    /// Z6-T7: caps on the files of one entity's records, by the entity's
    /// logical name (`{"contract": 10737418240}`), counted like the user cap.
    /// An entity not named has no cap of its own; the user and deployment
    /// caps still apply. Empty (the default) sets none.
    #[serde(default)]
    pub max_entity_storage_bytes: std::collections::BTreeMap<String, u64>,
    /// Z6-T7: the share of a cap, in percent, past which administrators are
    /// told (once a day per cap). 80 by default.
    #[serde(default = "default_quota_warning_pct")]
    pub quota_warning_pct: u8,
    /// `host:port` of a ClamAV `clamd` daemon (INSTREAM protocol) the async
    /// scan job submits uploaded bytes to. Empty (the default) means no
    /// scanner is configured — the scan job then fails closed (rejects,
    /// never promotes) rather than silently skipping malware scanning.
    #[serde(default)]
    pub clamd_address: String,
}

impl StorageSection {
    /// This deployment's general upload bucket as an [`S3Target`]. Its
    /// credential is the one that legitimately holds `DeleteObject` —
    /// quarantine cleanup (`xrm_document::files_scan`), the orphan sweep, and
    /// record erasure all delete real objects through it. That is exactly why
    /// audit anchors cannot live in this bucket; see
    /// [`AnchorStoreSection`](crate::AnchorStoreSection).
    pub fn s3_target(&self) -> S3Target<'_> {
        S3Target {
            endpoint: &self.s3_endpoint,
            public_endpoint: &self.s3_public_endpoint,
            region: &self.s3_region,
            bucket: &self.s3_bucket,
            access_key: &self.s3_access_key,
            secret_key: self.s3_secret_key.expose(),
            verify_ssl: self.s3_verify_ssl,
        }
    }
}

/// Hand-rolled: `s3_access_key`/`s3_secret_key` are live object-storage
/// credentials — the derived `Debug` would print both raw.
impl std::fmt::Debug for StorageSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageSection")
            .field("backend", &self.backend)
            .field("local", &self.local)
            .field("azure", &self.azure)
            .field("gcs", &self.gcs)
            .field("s3_endpoint", &self.s3_endpoint)
            .field("s3_public_endpoint", &self.s3_public_endpoint)
            .field("s3_region", &self.s3_region)
            .field("s3_access_key", &"[REDACTED]")
            .field("s3_secret_key", &"[REDACTED]")
            .field("s3_bucket", &self.s3_bucket)
            .field("s3_verify_ssl", &self.s3_verify_ssl)
            .field("max_upload_size_bytes", &self.max_upload_size_bytes)
            .field("max_user_storage_bytes", &self.max_user_storage_bytes)
            .field(
                "max_deployment_storage_bytes",
                &self.max_deployment_storage_bytes,
            )
            .field("max_entity_storage_bytes", &self.max_entity_storage_bytes)
            .field("quota_warning_pct", &self.quota_warning_pct)
            .field("clamd_address", &self.clamd_address)
            .finish()
    }
}

fn default_quota_warning_pct() -> u8 {
    80
}

fn default_max_upload_size_bytes() -> u64 {
    25 * 1024 * 1024
}
