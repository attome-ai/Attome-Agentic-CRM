//! Real-backend round trip through presigned URLs.
//!
//! These tests send real HTTP requests to the exact presigned URLs this crate
//! generates. `xrm-server/tests/file_upload_pipeline.rs` writes through
//! `object_store` with server credentials instead, and the unit tests in
//! `src/presign.rs` only inspect the URL, so neither proves a client can use
//! one.
//!
//! The same RustFS/MinIO answers on both `localhost:9000` and
//! `127.0.0.1:9000`, and SigV4 treats those as different hosts. That lets
//! one backend prove the URL was signed for the public endpoint, with no
//! second backend or proxy.
//!
//! Requires a reachable RustFS/MinIO on port 9000, the bucket
//! `TEST_S3_BUCKET` (default `attomebase`), and `S3_ACCESS_KEY` /
//! `S3_SECRET_KEY`. Without them every test here prints a `SKIP` line and
//! returns — unless `ATTOME_TEST_REQUIRE_S3=1`, this suite's fail-loud
//! switch, which turns that skip
//! into a panic: a run that is supposed to prove the real round trip must
//! never pass by not running it.
//!
//! ```powershell
//! $env:S3_ACCESS_KEY = "<key>"; $env:S3_SECRET_KEY = "<secret>"
//! cargo test -p attome-storage --test presign_roundtrip
//! # or, to fail instead of skipping:
//! $env:ATTOME_TEST_REQUIRE_S3 = "1"; cargo test -p attome-storage --test presign_roundtrip
//! ```
//!
//! Never print a presigned URL, or an error that embeds one, in an assertion
//! message: it is a working credential until it expires (I10).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use attome_config::S3Target;
use attome_storage::{
    StorageClient, create_storage_client_for, health_check, presign_download, presign_upload,
};
use object_store::{Attribute, Attributes, ObjectStoreExt, PutOptions, path::Path};

const TTL: Duration = Duration::from_secs(300);

struct Creds {
    access_key: String,
    secret_key: String,
    bucket: String,
}

/// Set this to make a missing S3 backend a failure rather than a skip. It is
/// separate from the database switch because CI runs PostgreSQL and Redis but
/// no object store.
const REQUIRE_S3_ENV: &str = "ATTOME_TEST_REQUIRE_S3";

fn require_s3() -> bool {
    std::env::var_os(REQUIRE_S3_ENV).is_some()
}

fn creds() -> Option<Creds> {
    let access_key = std::env::var("S3_ACCESS_KEY")
        .ok()
        .filter(|v| !v.is_empty())?;
    let secret_key = std::env::var("S3_SECRET_KEY")
        .ok()
        .filter(|v| !v.is_empty())?;
    let bucket = std::env::var("TEST_S3_BUCKET").unwrap_or_else(|_| "attomebase".into());
    Some(Creds {
        access_key,
        secret_key,
        bucket,
    })
}

/// `None` when there is no real backend configured *and* this run is allowed
/// to skip; a panic when the run declared it must not (BST-2, D-616).
fn creds_or_skip() -> Option<Creds> {
    match creds() {
        Some(creds) => Some(creds),
        None if require_s3() => panic!(
            "S3_ACCESS_KEY/S3_SECRET_KEY are unset but {REQUIRE_S3_ENV} is set — a run that is \
             supposed to exercise the real presign round trip must never pass by not running it"
        ),
        None => {
            eprintln!(
                "SKIP: S3_ACCESS_KEY/S3_SECRET_KEY unset, so the real presign round trip did not \
                 run. Point them at a reachable RustFS/MinIO on port 9000, or set \
                 {REQUIRE_S3_ENV}=1 to make this a failure instead."
            );
            None
        }
    }
}

async fn client(creds: &Creds, endpoint: &str, public_endpoint: &str) -> StorageClient {
    let target = S3Target {
        endpoint,
        public_endpoint,
        region: "us-east-1",
        bucket: &creds.bucket,
        access_key: &creds.access_key,
        secret_key: &creds.secret_key,
        // An `http://` endpoint with `verify_ssl = true` must still work: the
        // scheme alone decides plaintext vs TLS.
        verify_ssl: true,
    };
    create_storage_client_for(target, "presign-roundtrip")
        .await
        .expect("client construction is local, no network access")
}

/// A per-call unique suffix, so two runs (or two tests in one run) never
/// collide on an object key or a bucket name.
fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos()
}

fn unique_key(case: &str) -> String {
    format!(
        "attome-storage-presign-roundtrip/{case}-{}.txt",
        unique_suffix()
    )
}

fn authority(url: &str) -> String {
    let uri: http::Uri = url.parse().expect("a presigned URL must parse as a URI");
    uri.authority()
        .map(|a| a.as_str().to_owned())
        .unwrap_or_default()
}

/// PUTs `body` through a presigned upload URL, then GETs it back through a
/// presigned download URL. Both requests go to the exact URLs returned.
async fn put_and_get_through_presigned_urls(client: &StorageClient, key: &str, body: &[u8]) {
    let http = reqwest::Client::new();

    let upload_url = presign_upload(client, key, TTL)
        .await
        .expect("presign upload");
    let response = http
        .put(&upload_url)
        .body(body.to_vec())
        .send()
        .await
        .unwrap_or_else(|e| panic!("PUT to the presigned URL failed: {}", e.without_url()));
    assert!(
        response.status().is_success(),
        "PUT through the presigned URL was rejected with {}",
        response.status()
    );

    let download_url = presign_download(client, key, TTL)
        .await
        .expect("presign download");
    let response = http
        .get(&download_url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET of the presigned URL failed: {}", e.without_url()));
    assert!(
        response.status().is_success(),
        "GET through the presigned URL was rejected with {}",
        response.status()
    );
    let got = response
        .bytes()
        .await
        .unwrap_or_else(|e| panic!("reading the GET body failed: {}", e.without_url()));
    assert_eq!(
        got.as_ref(),
        body,
        "GET through the presigned URL returned different bytes"
    );
}

#[tokio::test]
async fn presigned_urls_signed_for_the_public_endpoint_work_end_to_end() {
    let Some(creds) = creds_or_skip() else {
        return;
    };
    let client = client(&creds, "http://localhost:9000", "http://127.0.0.1:9000").await;
    let key = unique_key("public-endpoint");

    for url in [
        presign_upload(&client, &key, TTL)
            .await
            .expect("presign upload"),
        presign_download(&client, &key, TTL)
            .await
            .expect("presign download"),
    ] {
        assert_eq!(
            authority(&url),
            "127.0.0.1:9000",
            "presigned URLs must be signed for the public endpoint"
        );
    }

    put_and_get_through_presigned_urls(&client, &key, b"signed for the public endpoint").await;

    client
        .store()
        .delete(&Path::from(key.as_str()))
        .await
        .expect("cleanup delete through the internal endpoint");
}

#[tokio::test]
async fn server_side_traffic_uses_the_internal_endpoint_not_the_public_one() {
    let Some(creds) = creds_or_skip() else {
        return;
    };
    // Nothing listens on port 1: if store() used the public endpoint, the
    // put below would fail.
    let client = client(&creds, "http://localhost:9000", "http://127.0.0.1:1").await;
    let key = unique_key("internal-endpoint");
    let path = Path::from(key.as_str());
    let body = b"server-side traffic stays internal".to_vec();

    client
        .store()
        .put(&path, body.clone().into())
        .await
        .expect("store().put must go to the internal endpoint");
    let got = client
        .store()
        .get(&path)
        .await
        .expect("store().get must go to the internal endpoint")
        .bytes()
        .await
        .expect("read the object body");
    assert_eq!(got.as_ref(), body.as_slice());

    let url = presign_upload(&client, &key, TTL)
        .await
        .expect("presign upload");
    assert_eq!(
        authority(&url),
        "127.0.0.1:1",
        "presigned URLs must still point at the public endpoint"
    );

    client
        .store()
        .delete(&path)
        .await
        .expect("cleanup delete through the internal endpoint");
}

#[tokio::test]
async fn presigned_urls_work_with_no_public_endpoint() {
    let Some(creds) = creds_or_skip() else {
        return;
    };
    let client = client(&creds, "http://127.0.0.1:9000", "").await;
    let key = unique_key("no-public-endpoint");

    let url = presign_upload(&client, &key, TTL)
        .await
        .expect("presign upload");
    assert_eq!(
        authority(&url),
        "127.0.0.1:9000",
        "with no public endpoint, URLs are signed for the internal endpoint"
    );

    put_and_get_through_presigned_urls(&client, &key, b"signed for the internal endpoint").await;

    client
        .store()
        .delete(&Path::from(key.as_str()))
        .await
        .expect("cleanup delete");
}

/// BST-0a: a bucket that does not exist must be reported `unreachable` with
/// the `bucket_unavailable` category, not `reachable` just because
/// `object_store` maps the missing bucket's 404 to `NotFound`.
#[tokio::test]
async fn the_public_endpoint_probe_reaches_the_real_backend() {
    let Some(creds) = creds_or_skip() else {
        return;
    };
    // BST-8: the presign client signs for `127.0.0.1:9000`, a different SigV4
    // host from the internal `localhost:9000` — the probe passing proves the
    // signed request went to, and was accepted by, the public authority.
    let right = client(&creds, "http://localhost:9000", "http://127.0.0.1:9000").await;
    let health = attome_storage::public_endpoint_health_check(&right)
        .await
        .expect("a configured public endpoint is probed");
    assert!(health.reachable, "error: {:?}", health.error);

    // Nothing listens on port 1: a wrong public endpoint must not pass.
    let wrong = client(&creds, "http://localhost:9000", "http://127.0.0.1:1").await;
    let health = attome_storage::public_endpoint_health_check(&wrong)
        .await
        .expect("a configured public endpoint is probed");
    assert!(!health.reachable);
}

#[tokio::test]
async fn health_reports_a_missing_bucket_as_unreachable() {
    let Some(creds) = creds_or_skip() else {
        return;
    };

    // A bucket this backend has never had, and that no test creates.
    let bucket = format!("attome-no-such-bucket-{}", unique_suffix());
    let target = S3Target {
        endpoint: "http://127.0.0.1:9000",
        public_endpoint: "",
        region: "us-east-1",
        bucket: &bucket,
        access_key: &creds.access_key,
        secret_key: &creds.secret_key,
        verify_ssl: true,
    };
    let client = create_storage_client_for(target, "missing-bucket-roundtrip")
        .await
        .expect("client construction is local, no network access");

    let health = health_check(&client).await;

    assert!(
        !health.reachable,
        "a bucket that does not exist must not be reported reachable"
    );
    assert_eq!(
        health.error.as_deref(),
        Some("bucket_unavailable"),
        "the public category must name the missing bucket, not just `other`"
    );
}

/// BST-6/C1: an object written with the *server-chosen* metadata the promote
/// path writes — an allowlisted `Content-Type` and
/// `Content-Disposition: attachment` — is served exactly that way through a
/// presigned GET, never as the `text/html` the uploader declared. This is the
/// stored-XSS half of BST-F2: the only thing that saves an inline-rendered
/// object is the metadata the platform writes at promote time.
#[tokio::test]
async fn a_presigned_download_is_served_as_an_attachment() {
    let Some(creds) = creds_or_skip() else {
        return;
    };
    let client = client(&creds, "http://127.0.0.1:9000", "").await;
    let source_key = unique_key("attachment-source");
    let final_key = unique_key("attachment-final");
    let http = reqwest::Client::new();

    // 1. What the browser's presigned PUT stores: the uploader's own
    //    declaration, `text/html`, which the store keeps verbatim.
    let upload_url = presign_upload(&client, &source_key, TTL)
        .await
        .expect("presign upload");
    let response = http
        .put(&upload_url)
        .header("content-type", "text/html")
        .body(b"<script>alert(1)</script>".to_vec())
        .send()
        .await
        .unwrap_or_else(|e| panic!("PUT to the presigned URL failed: {}", e.without_url()));
    assert!(
        response.status().is_success(),
        "PUT was rejected with {}",
        response.status()
    );
    let source_path = Path::from(source_key.as_str());

    // 2. The promote step (xrm-document's `files_scan::process`): read the
    //    scanned bytes back server-side, then write the final object with the
    //    metadata the server chooses. Two `PUT`s to the same key would keep
    //    the uploader's metadata, which is the whole point.
    let scanned = client
        .store()
        .get(&source_path)
        .await
        .expect("read the quarantined object server-side")
        .bytes()
        .await
        .expect("read the object body");
    let mut attributes = Attributes::new();
    attributes.insert(Attribute::ContentType, "text/plain".to_string().into());
    attributes.insert(
        Attribute::ContentDisposition,
        "attachment; filename*=UTF-8''report.txt".to_string().into(),
    );
    let final_path = Path::from(final_key.as_str());
    client
        .store()
        .put_opts(&final_path, scanned.into(), PutOptions::from(attributes))
        .await
        .expect("promote the scanned object with server-chosen metadata");

    // 3. A presigned GET serves the stored metadata — the server's
    //    `text/plain` and an attachment disposition, never `text/html`.
    let download_url = presign_download(&client, &final_key, TTL)
        .await
        .expect("presign download");
    let response = http
        .get(&download_url)
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET of the presigned URL failed: {}", e.without_url()));
    assert!(
        response.status().is_success(),
        "GET was rejected with {}",
        response.status()
    );
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_owned()
    };
    let disposition = header("content-disposition");
    assert!(
        disposition.starts_with("attachment"),
        "a promoted object must download as an attachment, got {disposition:?}"
    );
    let content_type = header("content-type");
    assert!(
        content_type.starts_with("text/plain"),
        "the server-chosen content type must win over the uploader's, got {content_type:?}"
    );

    client
        .store()
        .delete(&source_path)
        .await
        .expect("cleanup delete of the source object");
    client
        .store()
        .delete(&final_path)
        .await
        .expect("cleanup delete of the promoted object");
}
