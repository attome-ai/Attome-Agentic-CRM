//! Object storage for the platform: S3-compatible (AWS S3 / RustFS / MinIO)
//! by default, or a local folder, Azure Blob Storage or Google Cloud Storage
//! (`storage.backend`, Z6-T1). Every backend goes through `object_store`, so
//! engines see one `ObjectStore` whatever is behind it.
//!
//! # What this crate owns
//!
//! - Building an authenticated, timeout- and retry-bounded `object_store`
//!   client for any one bucket described by a [`attome_config::S3Target`]:
//!   [`create_storage_client`] for `config.storage`,
//!   [`create_storage_client_for`] for any other bucket (the audit-anchor
//!   store, D-352).
//! - Presigned upload/download URLs ([`presign_upload`],
//!   [`presign_download`]): SigV4 for S3, a SAS for Azure, a V4 signature for
//!   GCS, and for local disk a signed link to the server's own
//!   [`LOCAL_LINK_PATH`] route, checked there by [`verify_local_link`].
//! - The storage reachability probe ([`health_check`]), and its operator-only
//!   twin for the presign endpoint ([`public_endpoint_health_check`]).
//!
//! # What it deliberately does not own
//!
//! Engines take the raw `ObjectStore` from [`StorageClient::store`] /
//! [`StorageClient::store_arc`] and do their own put/get/head/delete. They
//! also own object-key layout, key-ownership checks, and authorization. A
//! wrapper over object_store's data API here would duplicate it without
//! adding an invariant.
//!
//! # Endpoint invariants
//!
//! - Server-side object traffic always uses `S3Target::endpoint`.
//! - `S3Target::public_endpoint` is used only to sign presigned URLs. The
//!   presign client is never returned from `store()`/`store_arc()`. It shares
//!   the bucket, region and credentials; only the endpoint differs.
//! - An empty public endpoint signs presigned URLs for `endpoint`.
//! - The endpoint's scheme decides http vs https. `verify_ssl` only decides
//!   whether HTTPS certificates are verified.
//!
//! # Operational facts
//!
//! - S3 credentials are read once, from config, when the client is built at
//!   boot. Rotating S3 keys needs a process restart.
//! - The retry/timeout policy is explicit in `client.rs`. Don't change it
//!   without measurement.
//!
//! # The ClamAV probe
//!
//! [`clamav_health_check`] lives here only because `clamd_address` sits in
//! `StorageSection`; clamd is not object storage. Moving it next to
//! `xrm_document`'s scan client would mean rewiring `preflight` and
//! `system_health` for tidiness alone, so it stays.
//!
//! # Presigned URLs are bearer credentials
//!
//! A presigned URL is not a link to a page: it is a signed, multi-use
//! credential to one object, valid until `X-Amz-Expires` elapses, for anyone
//! holding it. Never log one, never echo one in an error or an assertion
//! message, and never attach one to a trace — this crate's own tests follow
//! that rule even in `panic!` text (I10). Deployments that put an HTTP proxy
//! in front of the object store must configure it **not to log query
//! strings** on that path: the SigV4 signature, the credential id and the
//! expiry all ride in the query string, and a proxy access log writes them
//! to disk verbatim.
//!
//! # Stored object metadata is served verbatim
//!
//! A GET (presigned or not) returns the object's stored `Content-Type` and
//! `Content-Disposition` unchanged. Nothing between the bucket and the
//! browser reinterprets them, and a presigned PUT signs the `host` only —
//! `object_store`'s query signer cannot pin `response-content-*` and cannot
//! express a POST policy (attome-storage plan §4.2) — so an uploader's own
//! `Content-Type` is what a directly-PUT object ends up stored with. That is
//! why the engines that promote a scanned object write the final object's
//! metadata themselves, server-side, and why those downloads are forced to
//! `Content-Disposition: attachment`: a `text/html` object served inline
//! from a presigned URL is a stored-XSS primitive on the object store's own
//! origin.
//!
//! # Bucket permissions
//!
//! The upload bucket's credential needs `GetObject`, `PutObject`,
//! `DeleteObject`, `ListBucket`, `ListBucketMultipartUploads` and
//! `AbortMultipartUpload` — the promote path streams through
//! `put_multipart_opts` once a body passes `BufWriter`'s buffer threshold.
//! `ListBucket` is not optional: [`health_check`]'s probe lists the bucket
//! when its `HEAD` 404s, and a credential that cannot list reports
//! `bucket_unavailable`. The audit-anchor bucket's deliberately narrower
//! permission set is documented in `deploy/audit-anchor/README.md`.
//!
//! # Credential rotation
//!
//! S3 credentials are read once, at boot — D-549 made secrets
//! restart-rotated, so there is no hot reload and no code path to add. To
//! rotate: put the new key pair in the deployment's secret store and `.env`,
//! then restart **every** process that builds a storage client — the server,
//! the worker, and `audit_chainer` (which holds its own anchor-bucket
//! client) — and finally run `server preflight`, which probes both the
//! upload bucket and, when external anchoring is enabled, the anchor bucket.
//! A process still running on a revoked key reports `unauthenticated` from
//! [`health_check`] rather than failing quietly.

mod client;
pub mod encrypt;
mod error;
pub mod health;
mod local;
pub mod mirror;
/// Z6-T2: resumable multipart uploads.
pub mod multipart;
/// AB6-T4: object store calls through `attome_outbound`.
mod outbound;
mod presign;
#[cfg(test)]
mod test_support;

pub use client::{StorageClient, create_storage_client, create_storage_client_for};
pub use error::StorageError;
pub use health::{
    ClamAvHealth, StorageHealth, clamav_health_check, health_check, public_endpoint_health_check,
};
pub use local::{LOCAL_LINK_PATH, verify_local_link};
/// The object store API engines and tools use with a [`StorageClient`].
pub use object_store;
pub use presign::{presign_download, presign_upload};
