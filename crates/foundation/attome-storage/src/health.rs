//! P-health-readiness — read-only reachability check for the storage
//! backend (S3/RustFS, local disk, Azure, GCS), consumed by `xrm-server`'s `/health/dependencies` diagnostic
//! endpoint (never `/health/ready` — a down storage backend must not pull an
//! otherwise-healthy, DB-serving node out of load-balancer rotation).
//!
//! `/health/dependencies` is unauthenticated, so each probe splits its
//! failure report in two. `error` is a stable, public-safe category taken
//! only from structured information, never by parsing an error's text.
//! `detail` holds the full error for tools running on the host (e.g.
//! `preflight`); it is never serialized and is also logged at `warn`.

use std::time::{Duration, Instant};

use object_store::{ObjectStoreExt, path::Path};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tracing::warn;

use crate::client::StorageClient;

// Found live: 5s here raced against `attome_server::app`'s own global
// `TimeoutLayer` (`config.request_timeout()`, wraps every route including
// this one, no per-route exemption) -- with both timeouts equal, a
// genuinely-down backend could trip the OUTER layer's `server_timeout` 503 instead of
// this function's own graceful `reachable: false` JSON, defeating the whole
// point of this endpoint. 2s keeps a real margin below the smallest
// `request_timeout_secs` used anywhere in this codebase's own configs (5s).
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(2);

/// A key that will essentially never exist — `HEAD` against it proves the
/// endpoint answers authenticated requests without needing an object to
/// actually be present.
const HEALTH_CHECK_KEY: &str = "__attome_health_check__";

/// List prefix for the second half of the probe: when the `HEAD` above 404s,
/// a `list_with_delimiter` under this prefix is what distinguishes "the bucket
/// exists, the probe key does not" from "this deployment points at a bucket
/// that does not exist" (BST-4). Empty in practice, like the key itself.
const HEALTH_CHECK_LIST_PREFIX: &str = "__attome_health_check__/";

/// Bound on how many bytes of a clamd reply the liveness probe will buffer
/// (BST-11). `"PONG\0"` is 5 bytes; this leaves ample room for a differently
/// formatted but still-short reply, and none for a daemon — or a wrong port —
/// that streams bytes without end.
const CLAMAV_MAX_REPLY_BYTES: u64 = 64;

#[derive(Debug, Serialize)]
pub struct StorageHealth {
    pub reachable: bool,
    pub latency_ms: Option<f64>,
    /// Public-safe failure category: `"timeout"`, `"unauthenticated"`,
    /// `"forbidden"`, `"bucket_unavailable"`, or `"other"`. Never carries a
    /// host, bucket name, URI, or backend error text.
    pub error: Option<String>,
    /// The full backend error, for operator tools running on the host. Never
    /// serialized, so it cannot reach a public response.
    #[serde(skip)]
    pub detail: Option<String>,
}

impl StorageHealth {
    fn reachable(start: Instant) -> Self {
        Self {
            reachable: true,
            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            error: None,
            detail: None,
        }
    }

    fn unreachable(category: &'static str, detail: String) -> Self {
        warn!(category, error = %detail, "storage health probe failed");
        Self {
            reachable: false,
            latency_ms: None,
            error: Some(category.to_owned()),
            detail: Some(detail),
        }
    }
}

/// What one bounded probe attempt established, before it is turned into a
/// [`StorageHealth`].
enum Probe {
    Reachable,
    /// The authenticated `HEAD` itself failed — categorized by
    /// [`storage_error_category`].
    HeadFailed(object_store::Error),
    /// The `HEAD` was a 404 and the follow-up list also failed, so the bucket
    /// — not just the probe key — is absent or unlistable.
    BucketUnavailable(object_store::Error),
}

/// Probes the configured bucket.
///
/// A `HEAD` against the never-written `HEALTH_CHECK_KEY` proves the endpoint answers an
/// authenticated request, and its typed 401/403/timeout categories are kept.
/// What a `HEAD` cannot do is tell a missing *bucket* from a missing *key*:
/// `object_store` maps every HTTP 404 to `NotFound`. Treating that 404 as
/// reachable reported a misnamed bucket, or one that was never created, as
/// healthy (BST-F1). The 404 case therefore runs one bounded
/// `list_with_delimiter` inside the same 2 s budget — a successful list
/// proves the bucket is real, and any list failure is the new
/// `"bucket_unavailable"` category. That category is also what a credential
/// without `s3:ListBucket` gets (BST-F10); its wording covers both.
pub async fn health_check(client: &StorageClient) -> StorageHealth {
    let start = Instant::now();
    let health = probe(client.store(), start).await;

    // C7 (BST-10): the probe's own measured latency, so a probe creeping
    // toward `HEALTH_CHECK_TIMEOUT` is visible before it starts reporting
    // `timeout`. Recorded for every outcome — a failed probe's latency is
    // still the number an operator wants, and the timeout arm reports the
    // elapsed budget. The gauge is in SECONDS (the metric name's unit, and
    // what the `ObjectStorageProbeLatencyHigh > 1.5` rule assumes), while
    // `latency_ms` on the public body stays in milliseconds.
    metrics::gauge!("object_storage_probe_latency_seconds").set(
        health
            .latency_ms
            .map(|ms| ms / 1000.0)
            .unwrap_or_else(|| start.elapsed().as_secs_f64()),
    );

    health
}

/// BST-8: the same bounded probe, sent through the client that signs
/// presigned URLs — i.e. addressed to `S3Target::public_endpoint`. `None`
/// when no public endpoint is configured (presigned URLs are then signed for
/// `endpoint`, which [`health_check`] already covers).
///
/// For operator tools only (`preflight`), and warn-only there (BST-D2): the
/// public host is often unreachable from the server by design (split-horizon
/// DNS, a browser-only ingress), so a failure here is a hint to check
/// `s3_public_endpoint`, never a readiness signal. It records no metric and
/// is never wired into `/health/dependencies`.
///
/// A signed `HEAD` is what a presigned GET proves, minus the URL: the same
/// host, bucket, region and credentials, SigV4-signed for the public
/// authority. A wrong host, a proxy that rewrites the `Host` header (which
/// breaks every presigned URL's signature), or a public endpoint that serves
/// a different bucket all surface as a failed category here.
pub async fn public_endpoint_health_check(client: &StorageClient) -> Option<StorageHealth> {
    let public = client.public_store.as_ref()?;
    Some(probe(public.as_ref(), Instant::now()).await)
}

async fn probe(store: &dyn object_store::ObjectStore, start: Instant) -> StorageHealth {
    let path = Path::from(HEALTH_CHECK_KEY);
    let probe_prefix = Path::from(HEALTH_CHECK_LIST_PREFIX.trim_end_matches('/'));

    let result = tokio::time::timeout(HEALTH_CHECK_TIMEOUT, async {
        match store.head(&path).await {
            Ok(_) => Probe::Reachable,
            Err(object_store::Error::NotFound { .. }) => {
                match store.list_with_delimiter(Some(&probe_prefix)).await {
                    Ok(_) => Probe::Reachable,
                    Err(list_error) => Probe::BucketUnavailable(list_error),
                }
            }
            Err(e) => Probe::HeadFailed(e),
        }
    })
    .await;

    match result {
        Ok(Probe::Reachable) => StorageHealth::reachable(start),
        Ok(Probe::HeadFailed(e)) => {
            StorageHealth::unreachable(storage_error_category(&e), e.to_string())
        }
        Ok(Probe::BucketUnavailable(e)) => {
            StorageHealth::unreachable("bucket_unavailable", e.to_string())
        }
        Err(_) => StorageHealth::unreachable(
            "timeout",
            format!("timed out after {}s", HEALTH_CHECK_TIMEOUT.as_secs()),
        ),
    }
}

/// object_store maps HTTP 401 and 403 to typed variants. Connect and timeout
/// errors are not typed (its `RetryError` is crate-private) and are retried,
/// so within the probe window they surface as the probe's own timeout.
/// Everything else is `"other"`.
fn storage_error_category(e: &object_store::Error) -> &'static str {
    match e {
        object_store::Error::Unauthenticated { .. } => "unauthenticated",
        object_store::Error::PermissionDenied { .. } => "forbidden",
        _ => "other",
    }
}

#[derive(Debug, Serialize)]
pub struct ClamAvHealth {
    pub reachable: bool,
    pub latency_ms: Option<f64>,
    /// Public-safe failure category: `"timeout"`, `"unexpected_response"`,
    /// or `"other"`. Never carries the daemon address or raw error text.
    pub error: Option<String>,
    /// The full error, for operator tools running on the host. Never
    /// serialized, so it cannot reach a public response.
    #[serde(skip)]
    pub detail: Option<String>,
}

impl ClamAvHealth {
    fn unreachable(category: &'static str, detail: String) -> Self {
        warn!(category, error = %detail, "clamav health probe failed");
        Self {
            reachable: false,
            latency_ms: None,
            error: Some(category.to_owned()),
            detail: Some(detail),
        }
    }
}

/// Minimal clamd liveness probe (`zPING\0`, the same one-shot
/// null-terminated-command protocol shape `xrm_document::files_scan`'s
/// `zINSTREAM` scan client already uses, just the cheaper command) — proves
/// the daemon is up and answering without submitting anything to scan.
/// `storage.clamd_address` empty is a deliberate "malware scanning disabled"
/// configuration (see `AppConfig::validate_production_profile`'s
/// `check_not_placeholder` doc comment) — callers should skip this check
/// entirely in that case rather than treat it as unreachable.
pub async fn clamav_health_check(address: &str) -> ClamAvHealth {
    let start = Instant::now();
    match tokio::time::timeout(HEALTH_CHECK_TIMEOUT, async {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(b"zPING\0").await?;
        // BST-11: `PONG\0` is the longest reply this probe ever expects, so
        // the read is bounded rather than `read_to_end` — a daemon that
        // streams bytes forever (or a wrong port that answers with a log
        // tail) must not be able to grow this buffer without limit inside
        // the probe budget. Anything past the bound is an unexpected reply
        // either way, and the category is what matters, not the whole text.
        let mut response = Vec::new();
        stream
            .take(CLAMAV_MAX_REPLY_BYTES)
            .read_to_end(&mut response)
            .await?;
        Ok::<String, std::io::Error>(
            String::from_utf8_lossy(&response)
                .trim_end_matches('\0')
                .trim()
                .to_string(),
        )
    })
    .await
    {
        Ok(Ok(resp)) if resp == "PONG" => ClamAvHealth {
            reachable: true,
            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            error: None,
            detail: None,
        },
        Ok(Ok(resp)) => ClamAvHealth::unreachable(
            "unexpected_response",
            format!("unexpected clamd response: {resp:?}"),
        ),
        Ok(Err(e)) => ClamAvHealth::unreachable("other", e.to_string()),
        Err(_) => ClamAvHealth::unreachable(
            "timeout",
            format!("timed out after {}s", HEALTH_CHECK_TIMEOUT.as_secs()),
        ),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// No real backend: tiny local TCP servers stand in for S3 and clamd. Each
// failure test also serializes the result exactly as `/health/dependencies`
// would, and checks the body leaks no address, port, bucket, or key.
#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::net::TcpListener;

    use super::*;
    use crate::client::create_storage_client_for;
    use crate::test_support::target;

    const BUCKET: &str = "health-probe-bucket";

    /// An S3 that answers by method: `HEAD` with `head_status`, every other
    /// request (the list probe) with `list_status`/`list_body`. The two-stage
    /// probe needs both — the healthy case for a real bucket is exactly
    /// `HEAD 404` plus a list that succeeds.
    async fn fake_s3_split(
        head_status: &'static str,
        list_status: &'static str,
        list_body: &'static str,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake S3");
        let addr = listener.local_addr().expect("fake S3 address");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 1024];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let (status, body) = if request.starts_with(b"HEAD ") {
                        (head_status, "")
                    } else {
                        (list_status, list_body)
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    /// Answers every request with `status_line` and an empty body.
    async fn fake_s3(status_line: &'static str) -> SocketAddr {
        fake_s3_split(status_line, status_line, "").await
    }

    /// The smallest S3 `ListBucketResult` `object_store` will parse: every
    /// field it reads is `#[serde(default)]`, so an empty result is a
    /// present, listable bucket with nothing in it.
    const EMPTY_LIST_RESPONSE: &str =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult></ListBucketResult>";

    async fn storage_client(addr: SocketAddr) -> StorageClient {
        let endpoint = format!("http://{addr}");
        create_storage_client_for(target(BUCKET, &endpoint, "", true), "test")
            .await
            .expect("client construction is local, no network access")
    }

    fn assert_public_body_is_safe(body: &str, addr: SocketAddr) {
        for leak in [
            addr.ip().to_string(),
            addr.port().to_string(),
            BUCKET.to_owned(),
            HEALTH_CHECK_KEY.to_owned(),
            "detail".to_owned(),
        ] {
            assert!(
                !body.contains(&leak),
                "public health body leaks {leak:?}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn a_403_is_reported_as_forbidden_without_leaking_host_or_bucket() {
        let addr = fake_s3("403 Forbidden").await;

        let health = health_check(&storage_client(addr).await).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("forbidden"));
        assert!(health.detail.as_deref().is_some_and(|d| !d.is_empty()));
        assert_public_body_is_safe(&serde_json::to_string(&health).unwrap(), addr);
    }

    /// BST-0a (unit twin): a bucket that does not exist must not be reported as
    /// healthy just because `object_store` maps its 404 to `NotFound`. Red
    /// before BST-4, which adds the list probe that tells the two 404s apart.
    #[tokio::test]
    async fn a_404_on_the_probe_is_not_reported_reachable() {
        let addr = fake_s3("404 Not Found").await;

        let health = health_check(&storage_client(addr).await).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("bucket_unavailable"));
        assert!(health.detail.as_deref().is_some_and(|d| !d.is_empty()));
        assert_public_body_is_safe(&serde_json::to_string(&health).unwrap(), addr);
    }

    /// BST-4's positive half: the ordinary healthy case for a real bucket is a
    /// `HEAD` 404 (the probe key is never written) plus a list that answers.
    #[tokio::test]
    async fn a_404_head_with_a_listable_bucket_is_reachable() {
        let addr = fake_s3_split("404 Not Found", "200 OK", EMPTY_LIST_RESPONSE).await;

        let health = health_check(&storage_client(addr).await).await;

        assert!(health.reachable, "a listable bucket must be reachable");
        assert_eq!(health.error, None);
        assert_public_body_is_safe(&serde_json::to_string(&health).unwrap(), addr);
    }

    /// BST-F10's documented AWS case: the credential can HEAD (404) but not
    /// list. The bucket is unusable for uploads until `ListBucket` is granted,
    /// and the category says so rather than reporting healthy.
    #[tokio::test]
    async fn a_list_denied_after_a_404_head_is_bucket_unavailable() {
        let addr = fake_s3_split("404 Not Found", "403 Forbidden", "").await;

        let health = health_check(&storage_client(addr).await).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("bucket_unavailable"));
        assert_public_body_is_safe(&serde_json::to_string(&health).unwrap(), addr);
    }

    /// BST-10: every probe records its own latency, so a probe creeping
    /// toward `HEALTH_CHECK_TIMEOUT` is visible before it reports `timeout`.
    #[tokio::test]
    async fn the_probe_records_its_latency_gauge() {
        let recorder = crate::test_support::TestRecorder::install();
        let addr = fake_s3_split("404 Not Found", "200 OK", EMPTY_LIST_RESPONSE).await;

        let health = health_check(&storage_client(addr).await).await;

        assert!(health.reachable);
        let recorded = recorder
            .gauge("object_storage_probe_latency_seconds")
            .expect("the probe must set object_storage_probe_latency_seconds");
        assert!(recorded >= 0.0, "latency must be a real measurement");
        // The gauge is in seconds. The recorder is process-wide, so a
        // concurrent test's timed-out probe (elapsed just past
        // HEALTH_CHECK_TIMEOUT) may be the last write; the 2x slack absorbs
        // that while a millisecond-valued gauge (the pre-fix bug) from such a
        // probe (~2000) still fails.
        assert!(
            recorded <= HEALTH_CHECK_TIMEOUT.as_secs_f64() * 2.0,
            "object_storage_probe_latency_seconds must be seconds, bounded by the \
             probe's own timeout (got {recorded})"
        );
    }

    #[tokio::test]
    async fn a_401_is_reported_as_unauthenticated() {
        let addr = fake_s3("401 Unauthorized").await;

        let health = health_check(&storage_client(addr).await).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("unauthenticated"));
        assert_public_body_is_safe(&serde_json::to_string(&health).unwrap(), addr);
    }

    /// BST-8: with no `s3_public_endpoint` there is nothing separate to probe.
    #[tokio::test]
    async fn no_public_endpoint_means_no_public_probe() {
        let addr = fake_s3_split("404 Not Found", "200 OK", EMPTY_LIST_RESPONSE).await;

        assert!(
            public_endpoint_health_check(&storage_client(addr).await)
                .await
                .is_none()
        );
    }

    /// BST-8 (BST-F6): a public endpoint that refuses the signed request is
    /// reported through its own category while the internal endpoint stays
    /// healthy — the two probes address different hosts.
    #[tokio::test]
    async fn the_public_probe_reaches_the_public_endpoint_not_the_internal_one() {
        let internal = fake_s3_split("404 Not Found", "200 OK", EMPTY_LIST_RESPONSE).await;
        let public = fake_s3("403 Forbidden").await;
        let internal_endpoint = format!("http://{internal}");
        let public_endpoint = format!("http://{public}");
        let client = create_storage_client_for(
            target(BUCKET, &internal_endpoint, &public_endpoint, true),
            "test",
        )
        .await
        .expect("client construction is local, no network access");

        assert!(health_check(&client).await.reachable);
        let public_health = public_endpoint_health_check(&client)
            .await
            .expect("a configured public endpoint is probed");
        assert!(!public_health.reachable);
        assert_eq!(public_health.error.as_deref(), Some("forbidden"));
        assert_public_body_is_safe(&serde_json::to_string(&public_health).unwrap(), public);
    }

    #[tokio::test]
    async fn a_healthy_public_endpoint_is_reachable() {
        let internal = fake_s3("403 Forbidden").await;
        let public = fake_s3_split("404 Not Found", "200 OK", EMPTY_LIST_RESPONSE).await;
        let internal_endpoint = format!("http://{internal}");
        let public_endpoint = format!("http://{public}");
        let client = create_storage_client_for(
            target(BUCKET, &internal_endpoint, &public_endpoint, true),
            "test",
        )
        .await
        .expect("client construction is local, no network access");

        let public_health = public_endpoint_health_check(&client)
            .await
            .expect("a configured public endpoint is probed");
        assert!(public_health.reachable);
        assert_eq!(public_health.error, None);
    }

    #[tokio::test]
    async fn a_closed_port_is_reported_as_timeout_without_leaking_the_address() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        drop(listener);

        let health = health_check(&storage_client(addr).await).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("timeout"));
        assert_public_body_is_safe(&serde_json::to_string(&health).unwrap(), addr);
    }

    /// A one-connection fake clamd that reads `zPING\0` and then does `reply`.
    async fn fake_clamd(reply: Option<&'static [u8]>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake clamd");
        let addr = listener.local_addr().expect("fake clamd address");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut ping = [0u8; 6];
            let _ = stream.read_exact(&mut ping).await;
            match reply {
                Some(bytes) => {
                    let _ = stream.write_all(bytes).await;
                    let _ = stream.shutdown().await;
                }
                // Hold the connection open without answering.
                None => tokio::time::sleep(Duration::from_secs(10)).await,
            }
        });
        addr
    }

    /// Same one-connection fake clamd, but with an owned (possibly huge)
    /// reply — the bound is what the test is about.
    async fn fake_clamd_replying(reply: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake clamd");
        let addr = listener.local_addr().expect("fake clamd address");
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut ping = [0u8; 6];
            let _ = stream.read_exact(&mut ping).await;
            let _ = stream.write_all(&reply).await;
            let _ = stream.shutdown().await;
        });
        addr
    }

    #[tokio::test]
    async fn clamd_answering_pong_is_reachable() {
        let addr = fake_clamd(Some(b"PONG\0")).await;

        let health = clamav_health_check(&addr.to_string()).await;

        assert!(health.reachable);
        assert_eq!(health.error, None);
    }

    #[tokio::test]
    async fn clamd_answering_garbage_is_an_unexpected_response_without_leaking_it() {
        let addr = fake_clamd(Some(b"NOT-A-PONG\0")).await;

        let health = clamav_health_check(&addr.to_string()).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("unexpected_response"));
        let body = serde_json::to_string(&health).unwrap();
        assert!(!body.contains("NOT-A-PONG"), "public body leaks the reply");
        assert_public_body_is_safe(&body, addr);
    }

    /// BST-11: a daemon that answers with a megabyte of bytes must not be
    /// buffered whole inside the probe budget. The category is unchanged;
    /// what the bound buys is that `detail` stays a bounded prefix instead of
    /// the entire stream.
    #[tokio::test]
    async fn clamd_answering_a_huge_reply_is_read_bounded() {
        let addr = fake_clamd_replying(vec![b'A'; 1024 * 1024]).await;

        let health = clamav_health_check(&addr.to_string()).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("unexpected_response"));
        let detail = health.detail.as_deref().expect("operator detail");
        assert!(
            detail.len() < 200,
            "the probe reads at most {CLAMAV_MAX_REPLY_BYTES} bytes of a clamd reply, not a whole stream (detail was {} bytes)",
            detail.len()
        );
    }

    #[tokio::test]
    async fn clamd_that_never_answers_is_a_timeout() {
        let addr = fake_clamd(None).await;

        let health = clamav_health_check(&addr.to_string()).await;

        assert!(!health.reachable);
        assert_eq!(health.error.as_deref(), Some("timeout"));
        assert_public_body_is_safe(&serde_json::to_string(&health).unwrap(), addr);
    }
}
