use std::time::Duration;

use attome_auth::session::SessionClaims;
use attome_cache::Store;
use attome_types::AppError;
use axum::{
    body::Body,
    extract::{MatchedPath, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::middleware::idempotency_durable::{self, AcquireOutcome};
use crate::state::AppState;

/// The deduplication window. Every state this gate writes under a key expires
/// this long after its last write, so a key stays deduplicated for at least a
/// day after it was acquired. All states share the window on purpose: a
/// shorter `pending` or `unknown` TTL would make a key executable again while
/// the outcome it guards may already be committed. After the window, the same
/// key is a new request.
const TTL_SECS: i64 = 24 * 60 * 60;
const HEADER: &str = "x-idempotency-key";
/// S9-T1: the standard name (IETF `Idempotency-Key`), accepted beside
/// [`HEADER`]. It is outside the S2S signature, so a signed request's copy
/// is ignored: there only `x-idempotency-key` counts, as before.
pub const STANDARD_HEADER: &str = "idempotency-key";

/// The request's idempotency key from either header. Both, with different
/// values, is the caller's mistake and answers 422.
pub fn request_key(headers: &axum::http::HeaderMap) -> Result<Option<String>, AppError> {
    let read = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let legacy = read(HEADER);
    let standard = if headers.contains_key("x-s2s-client-id") {
        None
    } else {
        read(STANDARD_HEADER)
    };
    match (legacy, standard) {
        (Some(a), Some(b)) if a != b => Err(AppError::Validation(
            "x-idempotency-key and Idempotency-Key carry different keys; send one".into(),
        )),
        (a, b) => Ok(a.or(b)),
    }
}
/// Every Redis call on this gate is bounded (guidelines §10). A failed acquire
/// or duplicate lookup refuses the request; a failed post-handler write leaves
/// the key `pending`, which is answered as outcome unknown once stale.
const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// Slack added to the request timeout before a `pending` marker is answered as
/// outcome unknown rather than "still in progress". The marker is written by
/// whichever node took the original request and read by whichever node takes
/// the retry, so a few seconds of clock skew must not make a request that is
/// still legitimately running look finished.
const PENDING_GRACE_SECS: u64 = 5;

/// Response extension meaning "refused before the handler body ran, so nothing
/// was written". The gate releases the key for a 5xx only when this is present.
/// It is set by `capability::CapabilityRejection` alone: the same `AppError`
/// raised from handler logic may follow a write and must stay outcome-unknown.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MutationNotApplied;

#[derive(Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    #[serde(default)]
    content_type: Option<String>,
    /// End-to-end response headers clients need when replaying a successful
    /// operation (notably `Location` and validators).  This remains a strict
    /// allow-list: never replay hop-by-hop or credential-bearing headers.
    #[serde(default)]
    headers: Vec<(String, String)>,
    body_b64: String,
    /// Digest of the original request's content type + body.  The client key
    /// identifies an operation; this digest makes accidental reuse of that
    /// key for a *different* operation fail safely rather than replaying an
    /// unrelated response.
    #[serde(default)]
    request_digest: String,
}

use super::is_mutating;

/// Route-template operation name (`"{METHOD} {route}"`, e.g.
/// `"POST /api/v1/{entity}/bulk"`) — matched against
/// `idempotency.mandatory_operations` (P-idempotency-hardening §4.1/§4.5) to
/// decide whether a mutating request must go through the durable Postgres
/// tier (`idempotency_durable`) instead of this file's default Redis-only
/// gate. Prefers axum's `MatchedPath` (the registered route template) over
/// the raw request path — a literal path like `/api/v1/contact/bulk` would
/// never match a config entry written as `/api/v1/{entity}/bulk`. Falls back
/// to the raw path if `MatchedPath` is ever unavailable (degrades to
/// finer-grained matching rather than panicking or silently skipping the
/// operation dimension — see this crate's `app.rs::apply_inner_layers` doc
/// comment for why `MatchedPath` should already be resolved by the time this
/// router-level layer runs).
///
/// P-idempotency-hardening §8's risk note — "confirm `MatchedPath` is
/// actually populated here" — is closed by
/// `operation_name_reports_the_route_template_not_the_concrete_path` in this
/// module's tests, which drives a real `axum::Router` and asserts the
/// template comes back rather than the concrete path (TODO-029, run
/// 2026-08-12).
pub(crate) fn operation_name(req: &Request) -> String {
    let path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or_else(|| req.uri().path());
    format!("{} {}", req.method(), path)
}

/// S9-T2: whether `operation` (`"{METHOD} {route}"`) is consequential: a
/// custom action, a bulk job, a payment or invoice change, or a message sent
/// to someone. Such a key always takes the durable Postgres tier, whose
/// record survives a Redis restart; the rest use Redis when it is there.
pub fn is_consequential(operation: &str) -> bool {
    let Some(path) = operation.strip_prefix("POST ") else {
        return false;
    };
    path.starts_with("/api/v1/actions/")
        || path.starts_with("/api/v1/billing/")
        || path.starts_with("/api/v1/pay/")
        || path.contains("/actions/")
        || path.ends_with("/bulk")
        || path.ends_with("/bulk-edit")
        || path.ends_with("/bulk-edit/undo")
        || path.ends_with("/bulk-transform")
        || path.ends_with("/mass")
        || (path.starts_with("/api/v1/mass/") && path.ends_with("/undo"))
        || path.contains("/communications")
}

/// Idempotency gate. A client key is scoped to user, method and route; its
/// content type and exact body are fingerprinted separately.
///
/// No-op unless the request is a mutating verb, carries the header, and has
/// `SessionClaims` (set by `authn`, which runs before this in the pipeline) —
/// anonymous bypass routes (login/register) have nothing to scope the key to and
/// rely on their own advisory-lock + upsert retry-safety per the coding guidelines.
///
/// Operations named in `idempotency.mandatory_operations` take the durable
/// Postgres flow; everything else takes the Redis flow (`redis_gate`), which
/// never runs a handler twice for a key whose earlier outcome is unknown.
pub async fn idempotency(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !is_mutating(req.method()) {
        return next.run(req).await;
    }

    // P-idempotency-hardening §4.5: a route named in
    // idempotency.mandatory_operations must go through the durable tier and
    // must require the header outright — computed before the header check
    // below so a missing header on a mandatory route is a 422, not a silent
    // skip.
    let operation = operation_name(&req);
    let mandatory = state
        .config
        .idempotency
        .mandatory_operations
        .iter()
        .any(|op| op == &operation);

    let idem_key = match request_key(req.headers()) {
        Ok(key) => key,
        Err(error) => return error.into_response(),
    };

    if mandatory && idem_key.is_none() {
        return AppError::Validation(format!("{HEADER} header is required for {operation}"))
            .into_response();
    }

    let Some(idem_key) = idem_key else {
        return next.run(req).await;
    };
    let Some(claims) = req.extensions().get::<SessionClaims>().cloned() else {
        if mandatory {
            // P-idempotency-hardening §8: anonymous mandatory routes are
            // explicitly out of scope (no principal to key a durable record
            // on) — falls through unprotected like today's anonymous-bypass
            // behavior, but logged since a mandatory-listed route with no
            // SessionClaims is a likely config mistake, not an expected case.
            tracing::warn!(
                operation = %operation,
                "idempotency: mandatory operation has no SessionClaims in request extensions — \
                 falling through unprotected; mandatory_operations should only ever name \
                 session-authenticated routes"
            );
        }
        return next.run(req).await;
    };

    // `Body` is a one-shot stream.  Buffer and rebuild it before the handler
    // so a fingerprint covers what the handler will actually receive.  The
    // outer request-size guard runs first; this bounded read is defense in
    // depth and never permits a larger body than the configured maximum.
    let (parts, body) = req.into_parts();
    let body = match axum::body::to_bytes(body, state.config.app.max_body_size_bytes).await {
        Ok(body) => body,
        Err(_) => return AppError::PayloadTooLarge.into_response(),
    };
    let request_digest = request_digest(&parts.headers, &body);
    let req = Request::from_parts(parts, Body::from(body));

    // S9-T2: a consequential operation, and every key on a deployment
    // without Redis (whose in-process store a restart empties), takes the
    // durable tier too.
    let durable = mandatory
        || is_consequential(&operation)
        || matches!(state.redis_coordination, attome_cache::Store::Memory(_));
    if durable {
        return idempotency_durable_flow(
            state,
            req,
            next,
            claims.sub,
            operation,
            idem_key,
            request_digest,
        )
        .await;
    }

    // Scope the client key by user, method and route.
    let scope = Sha256::digest(
        format!(
            "{}:{}:{}:{}",
            claims.sub,
            req.method(),
            req.uri().path(),
            idem_key
        )
        .as_bytes(),
    );
    let redis_key = format!("base:idem:{scope:x}");
    let settings = GateSettings {
        replay_max_bytes: state.config.idempotency.replay_max_bytes,
        stale_after: pending_stale_after(&state),
        operation: &operation,
    };

    redis_gate(
        &RedisStore(&state.redis_coordination),
        settings,
        &redis_key,
        &request_digest,
        req,
        next,
    )
    .await
}

// ── Redis flow ──────────────────────────────────────────────────────────────

/// The Redis flow's tunables, resolved once per request.
#[derive(Clone, Copy, Debug)]
struct GateSettings<'a> {
    /// Largest successful response body stored for replay.
    replay_max_bytes: usize,
    /// Age past which a `pending` marker is answered as outcome unknown.
    stale_after: Duration,
    /// The route template, the `operation` label on the duplicate counters.
    operation: &'a str,
}

/// The Redis flow's only I/O. A crate-private seam so a test can fail one
/// specific write; production uses [`RedisStore`]. Errors are plain strings
/// so the caller decides whether a failure refuses the request (acquire, get)
/// or is only logged (post-handler writes).
trait IdempotencyStore {
    /// `SET key value NX EX ttl` — `true` when this call created the key.
    async fn acquire(&self, key: &str, value: String) -> Result<bool, String>;
    async fn get(&self, key: &str) -> Result<Option<String>, String>;
    /// `SET key value EX ttl`, replacing whatever the key holds.
    async fn put(&self, key: &str, value: String) -> Result<(), String>;
    async fn delete(&self, key: &str) -> Result<(), String>;
}

struct RedisStore<'a>(&'a Store);

impl IdempotencyStore for RedisStore<'_> {
    async fn acquire(&self, key: &str, value: String) -> Result<bool, String> {
        tokio::time::timeout(
            OP_TIMEOUT,
            self.0
                .set_nx(key, &value, Some(Duration::from_secs(TTL_SECS as u64))),
        )
        .await
        .map_err(|_| "redis idempotency acquire timed out".to_owned())?
        .map_err(|e| format!("redis idempotency acquire failed: {e}"))
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        tokio::time::timeout(OP_TIMEOUT, self.0.get(key))
            .await
            .map_err(|_| "redis idempotency get timed out".to_owned())?
            .map_err(|e| format!("redis idempotency get failed: {e}"))
    }

    async fn put(&self, key: &str, value: String) -> Result<(), String> {
        tokio::time::timeout(
            OP_TIMEOUT,
            self.0
                .set(key, &value, Some(Duration::from_secs(TTL_SECS as u64))),
        )
        .await
        .map_err(|_| "redis idempotency write timed out".to_owned())?
        .map_err(|e| format!("redis idempotency write failed: {e}"))
    }

    async fn delete(&self, key: &str) -> Result<(), String> {
        tokio::time::timeout(OP_TIMEOUT, self.0.del(key))
            .await
            .map_err(|_| "redis idempotency delete timed out".to_owned())?
            .map(|_| ())
            .map_err(|e| format!("redis idempotency delete failed: {e}"))
    }
}

/// Acquires `key` and runs the handler, or answers the duplicate from what the
/// key already holds. A stale `pending` marker is never reclaimed: it proves
/// only that the original request's future is gone, not that its write did
/// not commit.
async fn redis_gate<S: IdempotencyStore>(
    store: &S,
    settings: GateSettings<'_>,
    key: &str,
    request_digest: &str,
    req: Request,
    next: Next,
) -> Response {
    let pending = format_marker(MarkerKind::Pending, unix_now(), request_digest);
    match store.acquire(key, pending).await {
        Ok(true) => {}
        Ok(false) => return answer_duplicate(store, settings, key, request_digest).await,
        Err(error) => return AppError::internal(error).into_response(),
    }

    let original_request_id = original_request_id(req.headers());
    let response = next.run(req).await;
    let not_applied = response.extensions().get::<MutationNotApplied>().is_some();
    match disposition(response.status(), not_applied) {
        Disposition::Release => {
            if let Err(error) = store.delete(key).await {
                record_write_failure("release", &error);
            }
            response
        }
        Disposition::Unknown => {
            let marker = format_marker(MarkerKind::Unknown, unix_now(), request_digest);
            if let Err(error) = store.put(key, marker).await {
                record_write_failure("unknown", &error);
            }
            response
        }
        Disposition::Completed => {
            store_completed(
                store,
                settings,
                key,
                request_digest,
                original_request_id,
                response,
            )
            .await
        }
    }
}

async fn answer_duplicate<S: IdempotencyStore>(
    store: &S,
    settings: GateSettings<'_>,
    key: &str,
    request_digest: &str,
) -> Response {
    let raw = match store.get(key).await {
        Ok(raw) => raw,
        Err(error) => return AppError::internal(error).into_response(),
    };
    let Some(raw) = raw else {
        // Lost the NX race and the key has since vanished (the original
        // request was released, or the TTL fired between the two calls).
        // Refuse rather than run unguarded; the client's next retry takes the
        // NX path cleanly.
        return AppError::Conflict("duplicate request already in progress").into_response();
    };
    let existing = classify_existing(&raw, request_digest, unix_now(), settings.stale_after);
    count_duplicate(settings.operation, &existing);
    match existing {
        Existing::Replay(cached) => replay_cached(cached),
        Existing::InProgress => {
            AppError::Conflict("duplicate request already in progress").into_response()
        }
        Existing::OutcomeUnknown => AppError::IdempotencyOutcomeUnknown.into_response(),
        Existing::ReplayUnavailable => AppError::IdempotencyReplayUnavailable.into_response(),
        Existing::DifferentRequest => AppError::IdempotencyConflict(
            "idempotency key was already used for a different request",
        )
        .into_response(),
    }
}

/// A successful response: cache it for replay when it fits under the replay
/// cap, otherwise mark the key `done-unreplayable`. Either way the client gets
/// the real response.
async fn store_completed<S: IdempotencyStore>(
    store: &S,
    settings: GateSettings<'_>,
    key: &str,
    request_digest: &str,
    original_request_id: Option<(String, String)>,
    response: Response,
) -> Response {
    let (parts, body) = response.into_parts();
    match buffer_up_to(body, settings.replay_max_bytes).await {
        Buffered::Complete(bytes) => {
            let cached = CachedResponse {
                status: parts.status.as_u16(),
                content_type: parts
                    .headers
                    .get(axum::http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
                headers: replay_headers(&parts.headers)
                    .into_iter()
                    .chain(original_request_id)
                    .collect(),
                body_b64: base64_encode(&bytes),
                request_digest: request_digest.to_owned(),
            };
            match serde_json::to_string(&cached) {
                Ok(serialized) => {
                    if let Err(error) = store.put(key, serialized).await {
                        record_write_failure("cache", &error);
                    }
                }
                Err(error) => record_write_failure("cache", &error.to_string()),
            }
            Response::from_parts(parts, Body::from(bytes))
        }
        Buffered::Unreplayable(body) => {
            let marker = format_marker(MarkerKind::DoneUnreplayable, unix_now(), request_digest);
            if let Err(error) = store.put(key, marker).await {
                record_write_failure("done_unreplayable", &error);
            }
            Response::from_parts(parts, body)
        }
    }
}

/// S9-T6: the counter a duplicate request's answer increments, if any.
fn duplicate_counter(existing: &Existing) -> Option<&'static str> {
    match existing {
        Existing::Replay(_) | Existing::ReplayUnavailable => Some("idempotency_replays_total"),
        Existing::DifferentRequest => Some("idempotency_mismatch_total"),
        Existing::OutcomeUnknown => Some("idempotency_unknown_total"),
        Existing::InProgress => None,
    }
}

/// S9-T6: counts a duplicate by what it was answered with, per operation
/// (the route template, so the label set stays bounded).
fn count_duplicate(operation: &str, existing: &Existing) {
    if let Some(name) = duplicate_counter(existing) {
        metrics::counter!(name, "operation" => operation.to_owned()).increment(1);
    }
}

fn record_write_failure(write: &'static str, error: &str) {
    metrics::counter!("idempotency_marker_write_failures_total", "write" => write).increment(1);
    tracing::error!(
        write,
        %error,
        "idempotency: post-handler write failed; the key stays pending and is answered as \
         outcome unknown once stale"
    );
}

pub(crate) enum Buffered {
    /// The whole body, at most the replay cap.
    Complete(Bytes),
    /// A body that exceeded the cap, or whose stream failed, rebuilt from the
    /// part already read chained with the rest — the client still gets every
    /// byte (or the same stream error) the handler produced.
    Unreplayable(Body),
}

pub(crate) async fn buffer_up_to(body: Body, cap: usize) -> Buffered {
    let mut stream = body.into_data_stream();
    let mut chunks: Vec<Result<Bytes, axum::Error>> = Vec::new();
    let mut total = 0usize;
    while let Some(item) = stream.next().await {
        match item {
            Ok(chunk) => {
                total += chunk.len();
                chunks.push(Ok(chunk));
                if total > cap {
                    let rebuilt = futures_util::stream::iter(chunks).chain(stream);
                    return Buffered::Unreplayable(Body::from_stream(rebuilt));
                }
            }
            Err(error) => {
                chunks.push(Err(error));
                let rebuilt = futures_util::stream::iter(chunks).chain(stream);
                return Buffered::Unreplayable(Body::from_stream(rebuilt));
            }
        }
    }
    let mut buf = BytesMut::with_capacity(total);
    for chunk in chunks.into_iter().flatten() {
        buf.extend_from_slice(&chunk);
    }
    Buffered::Complete(buf.freeze())
}

fn replay_cached(cached: CachedResponse) -> Response {
    let body = base64_decode(&cached.body_b64).unwrap_or_default();
    let status = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);

    let mut builder = Response::builder().status(status);
    if cached.headers.is_empty()
        && let Some(ct) = cached.content_type
    {
        builder = builder.header(axum::http::header::CONTENT_TYPE, ct);
    }
    for (name, value) in cached.headers {
        builder = builder.header(name, value);
    }
    builder
        .header(REPLAYED_HEADER, "true")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ── Markers and decisions (pure) ────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MarkerKind {
    /// The request that acquired the key is running, or its future is gone.
    Pending,
    /// The handler returned an error that may have followed a write.
    Unknown,
    /// The handler succeeded, but its response was too large to store.
    DoneUnreplayable,
}

impl MarkerKind {
    fn as_str(self) -> &'static str {
        match self {
            MarkerKind::Pending => "pending",
            MarkerKind::Unknown => "unknown",
            MarkerKind::DoneUnreplayable => "done-unreplayable",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Marker {
    kind: MarkerKind,
    /// `None` only for the pre-3.10 bare `pending` sentinel.
    written_at: Option<i64>,
    /// `None` only for legacy markers written before fingerprints were stored.
    digest: Option<String>,
}

/// `v1:{kind}:{unix_seconds}:{request_digest}`. The digest is 64 hex chars and
/// the other fields contain no `:`, so the format splits unambiguously.
fn format_marker(kind: MarkerKind, written_at: i64, request_digest: &str) -> String {
    format!("v1:{}:{written_at}:{request_digest}", kind.as_str())
}

/// Parses a `v1` marker, or a legacy `pending:{ts}` / bare `pending` marker a
/// node running older code can still write during a rolling upgrade. `None`
/// for anything else.
fn parse_marker(raw: &str) -> Option<Marker> {
    if let Some(rest) = raw.strip_prefix("v1:") {
        let mut fields = rest.splitn(3, ':');
        let kind = match fields.next()? {
            "pending" => MarkerKind::Pending,
            "unknown" => MarkerKind::Unknown,
            "done-unreplayable" => MarkerKind::DoneUnreplayable,
            _ => return None,
        };
        let written_at = fields.next()?.parse::<i64>().ok()?;
        let digest = fields.next()?;
        if digest.is_empty() {
            return None;
        }
        return Some(Marker {
            kind,
            written_at: Some(written_at),
            digest: Some(digest.to_owned()),
        });
    }
    if raw == "pending" {
        return Some(Marker {
            kind: MarkerKind::Pending,
            written_at: None,
            digest: None,
        });
    }
    let written_at = raw.strip_prefix("pending:")?.parse::<i64>().ok()?;
    Some(Marker {
        kind: MarkerKind::Pending,
        written_at: Some(written_at),
        digest: None,
    })
}

/// What a duplicate request gets, decided from the raw value under its key.
enum Existing {
    Replay(CachedResponse),
    InProgress,
    OutcomeUnknown,
    ReplayUnavailable,
    DifferentRequest,
}

fn classify_existing(raw: &str, request_digest: &str, now: i64, stale_after: Duration) -> Existing {
    if let Ok(cached) = serde_json::from_str::<CachedResponse>(raw) {
        // Older cache values have no digest. Treat them as a mismatch instead
        // of replaying a response whose request identity cannot be proven.
        return if cached.request_digest == request_digest {
            Existing::Replay(cached)
        } else {
            Existing::DifferentRequest
        };
    }
    let Some(marker) = parse_marker(raw) else {
        // A corrupted value is treated as a request still in flight: refusing
        // is the only answer that can never run the handler twice.
        return Existing::InProgress;
    };
    if let Some(digest) = &marker.digest
        && digest != request_digest
    {
        return Existing::DifferentRequest;
    }
    match marker.kind {
        MarkerKind::Unknown => Existing::OutcomeUnknown,
        MarkerKind::DoneUnreplayable => Existing::ReplayUnavailable,
        MarkerKind::Pending => match marker.written_at {
            Some(at) if now.saturating_sub(at) > stale_after.as_secs() as i64 => {
                Existing::OutcomeUnknown
            }
            _ => Existing::InProgress,
        },
    }
}

/// What happens to the key once the handler has returned.
#[derive(Debug, PartialEq, Eq)]
enum Disposition {
    /// Success — cache the response, or mark it unreplayable.
    Completed,
    /// Known not applied — delete the key so a retry can run.
    Release,
    /// The outcome cannot be known — never run the handler again for this key.
    Unknown,
}

/// A 4xx is a known failure (engine contract: a handler never commits and then
/// returns 4xx). A 5xx is unknown unless it carries `MutationNotApplied`.
fn disposition(status: StatusCode, not_applied: bool) -> Disposition {
    if status.is_server_error() {
        if not_applied {
            Disposition::Release
        } else {
            Disposition::Unknown
        }
    } else if status.is_client_error() {
        Disposition::Release
    } else {
        Disposition::Completed
    }
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// How old a `pending` marker must be before a duplicate is answered as
/// outcome unknown rather than "in progress": the request timeout plus skew
/// grace. `apply_outer_layers`' timeout wraps this gate, so past that age the
/// original request's future has been dropped — but its write may already have
/// committed, which is why staleness never hands the key to the retry.
fn pending_stale_after(state: &AppState) -> Duration {
    state.config.request_timeout() + Duration::from_secs(PENDING_GRACE_SECS)
}

// ── Durable flow ────────────────────────────────────────────────────────────

/// P-idempotency-hardening §4.4 — durable-tier counterpart to the Redis flow
/// above, for a mandatory operation. Acquires (or resolves) a
/// `idempotency_record` row before running the handler, threads a
/// `DurableIdempotencyHandle` into request extensions so a specially-wired
/// handler (`xrm_server::bulk::enqueue`/`approve_staged_import`) can
/// complete it atomically inside its own mutation transaction
/// (`idempotency_durable::complete_in_tx`), and otherwise completes it
/// generically after the response comes back
/// (`idempotency_durable::complete_best_effort` — a no-op if the handler
/// already self-completed the row).
async fn idempotency_durable_flow(
    state: AppState,
    req: Request,
    next: Next,
    principal_ref: Uuid,
    operation: String,
    idem_key: String,
    request_digest: String,
) -> Response {
    let outcome = match idempotency_durable::acquire_or_check(
        &state,
        principal_ref,
        req.method().as_str(),
        &operation,
        &idem_key,
        &request_digest,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(e) => return e.into_response(),
    };

    let record_id = match outcome {
        AcquireOutcome::Acquired { record_id } => record_id,
        AcquireOutcome::Replay(cached) => {
            metrics::counter!("idempotency_replays_total", "operation" => operation).increment(1);
            return replay_from_durable(cached);
        }
        AcquireOutcome::InProgress => {
            return AppError::Conflict("duplicate request already in progress").into_response();
        }
        AcquireOutcome::DifferentRequest => {
            metrics::counter!("idempotency_mismatch_total", "operation" => operation).increment(1);
            return AppError::IdempotencyConflict(
                "idempotency key was already used for a different request",
            )
            .into_response();
        }
    };

    let original_request_id = original_request_id(req.headers());
    let mut req = req;
    req.extensions_mut()
        .insert(idempotency_durable::DurableIdempotencyHandle { record_id });

    let response = next.run(req).await;

    if response.status().is_client_error() || response.status().is_server_error() {
        idempotency_durable::release_on_failure(&state, record_id).await;
        return response;
    }

    let (parts, body) = response.into_parts();
    let max_bytes = state.config.app.max_body_size_bytes;
    let bytes = match axum::body::to_bytes(body, max_bytes).await {
        Ok(b) => b,
        Err(_) => {
            return AppError::internal("failed to buffer response for idempotency cache")
                .into_response();
        }
    };
    let headers: Vec<(String, String)> = replay_headers(&parts.headers)
        .into_iter()
        .chain(original_request_id)
        .collect();
    idempotency_durable::complete_best_effort(
        &state,
        record_id,
        parts.status.as_u16(),
        &headers,
        &bytes,
    )
    .await;

    Response::from_parts(parts, Body::from(bytes))
}

fn replay_from_durable(cached: idempotency_durable::CachedRecord) -> Response {
    let status = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);
    for (name, value) in cached.headers {
        builder = builder.header(name, value);
    }
    builder
        .header(REPLAYED_HEADER, "true")
        .body(Body::from(cached.body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// S9-T4: set on every replayed response, so a client can tell a replay
/// from a fresh execution.
pub const REPLAYED_HEADER: &str = "idempotency-replayed";
/// S9-T4: the request id of the request that actually ran, on a replay; the
/// replay's own `x-request-id` is the retry's.
pub const ORIGINAL_REQUEST_ID_HEADER: &str = "x-original-request-id";

/// The running request's id, stored with its response as the replay's
/// [`ORIGINAL_REQUEST_ID_HEADER`].
fn original_request_id(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(|id| (ORIGINAL_REQUEST_ID_HEADER.to_owned(), id.to_owned()))
}

fn replay_headers(headers: &axum::http::HeaderMap) -> Vec<(String, String)> {
    const ALLOWED: &[&str] = &[
        "cache-control",
        "content-language",
        "content-type",
        "etag",
        "last-modified",
        "location",
    ];
    headers
        .iter()
        .filter(|(name, _)| ALLOWED.contains(&name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

fn request_digest(headers: &axum::http::HeaderMap, body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        headers
            .get(axum::http::header::CONTENT_TYPE)
            .map(|value| value.as_bytes())
            .unwrap_or_default(),
    );
    // Prevent an ambiguous content-type/body concatenation.
    hasher.update([0]);
    hasher.update(body);
    format!("{:x}", hasher.finalize())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

#[cfg(test)]
mod consequential_tests {
    use super::is_consequential;

    #[test]
    fn consequential_operations_take_the_durable_tier() {
        assert!(is_consequential("POST /api/v1/actions/{id}/invoke"));
        assert!(is_consequential("POST /api/v1/{entity}/bulk"));
        assert!(is_consequential("POST /api/v1/billing/payments"));
        assert!(is_consequential(
            "POST /api/v1/{entity}/{id}/communications"
        ));
        assert!(!is_consequential("POST /api/v1/{entity}"));
        assert!(!is_consequential("PATCH /api/v1/{entity}/{id}"));
        assert!(!is_consequential("POST /api/v1/{entity}/bulk-edit/preview"));
        assert!(is_consequential("POST /api/v1/{entity}/mass"));
        assert!(is_consequential("POST /api/v1/mass/{id}/undo"));
        assert!(!is_consequential("POST /api/v1/{entity}/mass/estimate"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S9-T1: either header name carries the key; two different keys are
    /// refused; a signed S2S request's standard header is not read.
    #[test]
    fn the_standard_header_name_is_accepted_beside_the_legacy_one() {
        use axum::http::{HeaderMap, HeaderValue};
        let with = |pairs: &[(&'static str, &'static str)]| {
            let mut headers = HeaderMap::new();
            for (name, value) in pairs {
                headers.insert(*name, HeaderValue::from_static(value));
            }
            headers
        };
        assert_eq!(request_key(&with(&[])).ok().flatten(), None);
        assert_eq!(
            request_key(&with(&[("idempotency-key", "k1")]))
                .ok()
                .flatten()
                .as_deref(),
            Some("k1")
        );
        assert_eq!(
            request_key(&with(&[
                ("x-idempotency-key", "k1"),
                ("idempotency-key", "k1")
            ]))
            .ok()
            .flatten()
            .as_deref(),
            Some("k1")
        );
        assert!(
            request_key(&with(&[
                ("x-idempotency-key", "k1"),
                ("idempotency-key", "k2")
            ]))
            .is_err()
        );
        assert_eq!(
            request_key(&with(&[
                ("x-s2s-client-id", "c"),
                ("idempotency-key", "k1")
            ]))
            .ok()
            .flatten(),
            None
        );
    }
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// TODO-029, closing `operation_name`'s own "not yet exercised against a
    /// live router" note. Drives a REAL `axum::Router` rather than
    /// hand-inserting a `MatchedPath` extension, because hand-inserting it
    /// would assert only that the getter works — the open question was
    /// whether axum populates the extension by the time a router-level layer
    /// observes the request, which nothing but a real router can answer.
    ///
    /// If it ever stops being populated, `operation_name` silently degrades
    /// to the raw path and every record id becomes its own operation
    /// dimension: `/api/v1/contact/{id}` would stop matching a config entry
    /// written against the template, and idempotency keys would stop
    /// colliding where they are supposed to. That is a quiet correctness
    /// failure, which is exactly the kind worth a test.
    #[tokio::test]
    async fn operation_name_reports_the_route_template_not_the_concrete_path() {
        use axum::{Router, body::Body, http::Request, middleware, routing::post};
        use tower::ServiceExt as _;

        let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&seen);

        let app = Router::new()
            .route("/api/v1/{entity}/{id}", post(|| async { "ok" }))
            .layer(middleware::from_fn(
                move |req: axum::extract::Request, next: middleware::Next| {
                    let captured = Arc::clone(&captured);
                    async move {
                        *captured.lock().expect("capture mutex poisoned") =
                            Some(operation_name(&req));
                        next.run(req).await
                    }
                },
            ));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/contact/0198f0a1-0000-7000-8000-000000000000")
                    .body(Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router call");
        assert!(response.status().is_success());

        assert_eq!(
            seen.lock().expect("capture mutex poisoned").as_deref(),
            Some("POST /api/v1/{entity}/{id}"),
            "operation_name fell back to the raw path — MatchedPath was not \
             populated by the time a router-level layer ran, so every record \
             id would become its own operation dimension",
        );
    }

    // ── Markers ─────────────────────────────────────────────────────────

    const DIGEST: &str = "a1b2c3";
    const OTHER_DIGEST: &str = "ffff00";
    const NOW: i64 = 1_700_000_000;
    const STALE_AFTER: Duration = Duration::from_secs(35);

    /// S9-T6: replays, mismatches and unknown outcomes each have a counter;
    /// a request still in progress is not counted.
    #[test]
    fn each_duplicate_answer_counts_under_its_own_name() {
        let cached = CachedResponse {
            status: 201,
            content_type: None,
            headers: Vec::new(),
            body_b64: String::new(),
            request_digest: DIGEST.to_owned(),
        };
        assert_eq!(
            duplicate_counter(&Existing::Replay(cached)),
            Some("idempotency_replays_total")
        );
        assert_eq!(
            duplicate_counter(&Existing::ReplayUnavailable),
            Some("idempotency_replays_total")
        );
        assert_eq!(
            duplicate_counter(&Existing::DifferentRequest),
            Some("idempotency_mismatch_total")
        );
        assert_eq!(
            duplicate_counter(&Existing::OutcomeUnknown),
            Some("idempotency_unknown_total")
        );
        assert_eq!(duplicate_counter(&Existing::InProgress), None);
    }

    #[test]
    fn a_v1_marker_round_trips_for_every_kind() {
        for kind in [
            MarkerKind::Pending,
            MarkerKind::Unknown,
            MarkerKind::DoneUnreplayable,
        ] {
            let raw = format_marker(kind, NOW, DIGEST);
            assert_eq!(
                parse_marker(&raw),
                Some(Marker {
                    kind,
                    written_at: Some(NOW),
                    digest: Some(DIGEST.to_owned()),
                }),
                "{raw}"
            );
        }
    }

    #[test]
    fn malformed_v1_markers_do_not_parse() {
        for raw in [
            "v1:pending:not-a-timestamp:abc",
            "v1:reclaimed:1700000000:abc",
            "v1:pending:1700000000:",
            "v1:pending:1700000000",
            "v1:",
            "",
            "garbage",
        ] {
            assert_eq!(parse_marker(raw), None, "{raw:?}");
        }
    }

    #[test]
    fn legacy_markers_parse_without_a_digest() {
        assert_eq!(
            parse_marker("pending:1700000000"),
            Some(Marker {
                kind: MarkerKind::Pending,
                written_at: Some(NOW),
                digest: None,
            })
        );
        assert_eq!(
            parse_marker("pending"),
            Some(Marker {
                kind: MarkerKind::Pending,
                written_at: None,
                digest: None,
            })
        );
    }

    #[test]
    fn no_marker_ever_parses_as_a_cached_response() {
        for kind in [
            MarkerKind::Pending,
            MarkerKind::Unknown,
            MarkerKind::DoneUnreplayable,
        ] {
            let raw = format_marker(kind, NOW, DIGEST);
            assert!(serde_json::from_str::<CachedResponse>(&raw).is_err());
        }
    }

    // ── classify_existing: every cell of the state table ────────────────

    fn classify(raw: &str, digest: &str, now: i64) -> &'static str {
        match classify_existing(raw, digest, now, STALE_AFTER) {
            Existing::Replay(_) => "replay",
            Existing::InProgress => "in_progress",
            Existing::OutcomeUnknown => "outcome_unknown",
            Existing::ReplayUnavailable => "replay_unavailable",
            Existing::DifferentRequest => "different_request",
        }
    }

    #[test]
    fn a_fresh_pending_marker_is_in_progress_or_a_different_request() {
        let raw = format_marker(MarkerKind::Pending, NOW, DIGEST);
        assert_eq!(classify(&raw, DIGEST, NOW), "in_progress");
        assert_eq!(
            classify(&raw, DIGEST, NOW + 35),
            "in_progress",
            "at the bound"
        );
        assert_eq!(classify(&raw, OTHER_DIGEST, NOW), "different_request");
    }

    #[test]
    fn a_stale_pending_marker_is_outcome_unknown_never_reclaimed() {
        let raw = format_marker(MarkerKind::Pending, NOW, DIGEST);
        assert_eq!(classify(&raw, DIGEST, NOW + 36), "outcome_unknown");
        assert_eq!(
            classify(&raw, DIGEST, NOW + 24 * 60 * 60 - 1),
            "outcome_unknown"
        );
        assert_eq!(classify(&raw, OTHER_DIGEST, NOW + 36), "different_request");
    }

    #[test]
    fn an_unknown_marker_is_outcome_unknown_or_a_different_request() {
        let raw = format_marker(MarkerKind::Unknown, NOW, DIGEST);
        assert_eq!(classify(&raw, DIGEST, NOW), "outcome_unknown");
        assert_eq!(classify(&raw, OTHER_DIGEST, NOW), "different_request");
    }

    #[test]
    fn a_done_unreplayable_marker_is_replay_unavailable_or_a_different_request() {
        let raw = format_marker(MarkerKind::DoneUnreplayable, NOW, DIGEST);
        assert_eq!(classify(&raw, DIGEST, NOW), "replay_unavailable");
        assert_eq!(classify(&raw, OTHER_DIGEST, NOW), "different_request");
    }

    #[test]
    fn a_cached_response_replays_only_for_the_same_digest() {
        let cached = serde_json::to_string(&CachedResponse {
            status: 201,
            content_type: None,
            headers: Vec::new(),
            body_b64: base64_encode(b"{}"),
            request_digest: DIGEST.to_owned(),
        })
        .unwrap();
        assert_eq!(classify(&cached, DIGEST, NOW), "replay");
        assert_eq!(classify(&cached, OTHER_DIGEST, NOW), "different_request");
    }

    #[test]
    fn legacy_and_corrupt_values_never_run_the_handler_again() {
        assert_eq!(classify("pending:1700000000", DIGEST, NOW), "in_progress");
        assert_eq!(
            classify("pending:1700000000", DIGEST, NOW + 36),
            "outcome_unknown"
        );
        // No timestamp and no digest: no evidence either way, so refuse.
        assert_eq!(classify("pending", DIGEST, NOW + 999_999), "in_progress");
        assert_eq!(classify("garbage", DIGEST, NOW), "in_progress");
    }

    #[test]
    fn a_marker_from_a_clock_ahead_of_ours_is_in_progress() {
        let raw = format_marker(MarkerKind::Pending, NOW + 10, DIGEST);
        assert_eq!(classify(&raw, DIGEST, NOW), "in_progress");
    }

    // ── disposition ─────────────────────────────────────────────────────

    #[test]
    fn disposition_follows_status_and_the_not_applied_marker() {
        assert_eq!(disposition(StatusCode::OK, false), Disposition::Completed);
        assert_eq!(
            disposition(StatusCode::CREATED, false),
            Disposition::Completed
        );
        assert_eq!(
            disposition(StatusCode::SEE_OTHER, false),
            Disposition::Completed
        );
        assert_eq!(
            disposition(StatusCode::UNPROCESSABLE_ENTITY, false),
            Disposition::Release
        );
        assert_eq!(
            disposition(StatusCode::INTERNAL_SERVER_ERROR, false),
            Disposition::Unknown
        );
        assert_eq!(
            disposition(StatusCode::SERVICE_UNAVAILABLE, false),
            Disposition::Unknown
        );
        assert_eq!(
            disposition(StatusCode::SERVICE_UNAVAILABLE, true),
            Disposition::Release
        );
    }

    // ── The gate against an in-memory store ─────────────────────────────

    /// NX semantics under a mutex, plus switches to fail one kind of write.
    #[derive(Clone, Default)]
    struct MemoryStore {
        map: Arc<Mutex<HashMap<String, String>>>,
        /// `put` fails for any value starting with this prefix.
        fail_put_prefix: Arc<Mutex<Option<&'static str>>>,
        fail_delete: Arc<AtomicBool>,
    }

    impl MemoryStore {
        fn value(&self, key: &str) -> Option<String> {
            self.map.lock().unwrap().get(key).cloned()
        }
    }

    impl IdempotencyStore for MemoryStore {
        async fn acquire(&self, key: &str, value: String) -> Result<bool, String> {
            let mut map = self.map.lock().unwrap();
            if map.contains_key(key) {
                return Ok(false);
            }
            map.insert(key.to_owned(), value);
            Ok(true)
        }

        async fn get(&self, key: &str) -> Result<Option<String>, String> {
            Ok(self.map.lock().unwrap().get(key).cloned())
        }

        async fn put(&self, key: &str, value: String) -> Result<(), String> {
            if let Some(prefix) = *self.fail_put_prefix.lock().unwrap()
                && value.starts_with(prefix)
            {
                return Err("injected put failure".to_owned());
            }
            self.map.lock().unwrap().insert(key.to_owned(), value);
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), String> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err("injected delete failure".to_owned());
            }
            self.map.lock().unwrap().remove(key);
            Ok(())
        }
    }

    const KEY: &str = "idem-key";
    const LONG: Duration = Duration::from_secs(3600);

    /// Ages every `v1` marker in `store` well past `LONG`, standing in for time
    /// passing: a gate built with `LONG` as its stale age then sees the marker
    /// as stale. Markers carry whole-second timestamps, so a same-second retry
    /// cannot rely on a zero stale age instead.
    fn backdated(store: MemoryStore) -> MemoryStore {
        {
            let mut map = store.map.lock().unwrap();
            for value in map.values_mut() {
                if let Some(mut marker) = parse_marker(value.as_str())
                    && let Some(digest) = marker.digest.take()
                    && let Some(at) = marker.written_at
                {
                    *value = format_marker(marker.kind, at - 2 * LONG.as_secs() as i64, &digest);
                }
            }
        }
        store
    }

    /// Mounts `routes` behind `redis_gate` over `store`, keyed by the
    /// `x-idempotency-key` header exactly as the production middleware keys it.
    fn gated(
        store: MemoryStore,
        stale_after: Duration,
        cap: usize,
        routes: axum::Router,
    ) -> axum::Router {
        let settings = GateSettings {
            replay_max_bytes: cap,
            stale_after,
            operation: "POST /test",
        };
        routes.layer(axum::middleware::from_fn(
            move |req: Request, next: Next| {
                let store = store.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
                    let digest = request_digest(&parts.headers, &bytes);
                    let key = parts.headers[HEADER].to_str().unwrap().to_owned();
                    let req = Request::from_parts(parts, Body::from(bytes));
                    redis_gate(&store, settings, &key, &digest, req, next).await
                }
            },
        ))
    }

    fn post(uri: &str, body: &'static str) -> Request {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(HEADER, KEY)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    async fn send(app: &axum::Router, req: Request) -> Response {
        use tower::ServiceExt as _;
        app.clone()
            .oneshot(req)
            .await
            .expect("router is infallible")
    }

    async fn error_code(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned))
            .unwrap_or_default()
    }

    /// A route whose body counts how often it ran and then produces `make()`.
    fn counting<F, R>(calls: Arc<AtomicUsize>, make: F) -> axum::routing::MethodRouter
    where
        F: Fn() -> R + Clone + Send + Sync + 'static,
        R: IntoResponse,
    {
        axum::routing::post(move || {
            let calls = calls.clone();
            let make = make.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                make().into_response()
            }
        })
    }

    #[tokio::test]
    async fn a_completed_response_replays_without_running_the_handler_again() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                counting(calls.clone(), || (StatusCode::CREATED, "made")),
            ),
        );

        let first = send(&app, post("/r", "{}")).await;
        assert_eq!(first.status(), StatusCode::CREATED);
        let second = send(&app, post("/r", "{}")).await;
        assert_eq!(second.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(second.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"made");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// S9-T4: a replayed create carries the original Location and ETag, says
    /// it is a replay and names the request that ran.
    #[tokio::test]
    async fn a_replayed_create_returns_the_same_location_and_etag() {
        use axum::http::header::{ETAG, LOCATION};
        let calls = Arc::new(AtomicUsize::new(0));
        let app = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                counting(calls.clone(), || {
                    (
                        StatusCode::CREATED,
                        [(LOCATION, "/r/1"), (ETAG, "\"3\"")],
                        "made",
                    )
                }),
            ),
        );
        let with_id = |id: &'static str| {
            let mut req = post("/r", "{}");
            req.headers_mut()
                .insert("x-request-id", axum::http::HeaderValue::from_static(id));
            req
        };

        let first = send(&app, with_id("req-1")).await;
        assert!(first.headers().get(REPLAYED_HEADER).is_none());
        let second = send(&app, with_id("req-2")).await;
        assert_eq!(second.status(), StatusCode::CREATED);
        assert_eq!(second.headers()[LOCATION], "/r/1");
        assert_eq!(second.headers()[ETAG], "\"3\"");
        assert_eq!(second.headers()[REPLAYED_HEADER], "true");
        assert_eq!(second.headers()[ORIGINAL_REQUEST_ID_HEADER], "req-1");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failed_cache_write_leaves_pending_and_a_stale_retry_is_outcome_unknown() {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = MemoryStore::default();
        *store.fail_put_prefix.lock().unwrap() = Some("{");
        let routes = axum::Router::new().route("/r", counting(calls.clone(), || "ok"));

        let first = send(
            &gated(store.clone(), LONG, 1024, routes.clone()),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(
            first.status(),
            StatusCode::OK,
            "the client still gets its response"
        );
        assert!(store.value(KEY).unwrap().starts_with("v1:pending:"));

        let retry = send(
            &gated(backdated(store), LONG, 1024, routes),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(retry.status(), StatusCode::CONFLICT);
        assert_eq!(error_code(retry).await, "idempotency_outcome_unknown");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failed_done_unreplayable_write_is_also_outcome_unknown_once_stale() {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = MemoryStore::default();
        *store.fail_put_prefix.lock().unwrap() = Some("v1:done-unreplayable");
        let routes = axum::Router::new().route("/r", counting(calls.clone(), || "twelve bytes"));

        let first = send(
            &gated(store.clone(), LONG, 4, routes.clone()),
            post("/r", "{}"),
        )
        .await;
        let body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"twelve bytes");

        let retry = send(&gated(backdated(store), LONG, 4, routes), post("/r", "{}")).await;
        assert_eq!(error_code(retry).await, "idempotency_outcome_unknown");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failed_unknown_write_after_a_5xx_is_outcome_unknown_once_stale() {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = MemoryStore::default();
        *store.fail_put_prefix.lock().unwrap() = Some("v1:unknown");
        let routes = axum::Router::new().route(
            "/r",
            counting(calls.clone(), || AppError::Internal("boom".into())),
        );

        let first = send(
            &gated(store.clone(), LONG, 1024, routes.clone()),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let retry = send(
            &gated(backdated(store), LONG, 1024, routes),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(error_code(retry).await, "idempotency_outcome_unknown");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_failed_release_after_a_4xx_is_outcome_unknown_once_stale() {
        let calls = Arc::new(AtomicUsize::new(0));
        let store = MemoryStore::default();
        store.fail_delete.store(true, Ordering::SeqCst);
        let routes = axum::Router::new().route(
            "/r",
            counting(calls.clone(), || AppError::Validation("bad".into())),
        );

        let first = send(
            &gated(store.clone(), LONG, 1024, routes.clone()),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(first.status(), StatusCode::UNPROCESSABLE_ENTITY);

        let retry = send(
            &gated(backdated(store), LONG, 1024, routes),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(error_code(retry).await, "idempotency_outcome_unknown");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_4xx_releases_the_key_so_a_retry_runs() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                counting(calls.clone(), || AppError::Validation("bad".into())),
            ),
        );
        send(&app, post("/r", "{}")).await;
        send(&app, post("/r", "{}")).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_body_exactly_at_the_cap_is_cached_and_one_byte_over_is_unreplayable() {
        let calls = Arc::new(AtomicUsize::new(0));
        let at_cap = gated(
            MemoryStore::default(),
            LONG,
            4,
            axum::Router::new().route("/r", counting(calls.clone(), || "four")),
        );
        send(&at_cap, post("/r", "{}")).await;
        let replay = send(&at_cap, post("/r", "{}")).await;
        let body = axum::body::to_bytes(replay.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"four", "exactly at the cap replays");

        let over_calls = Arc::new(AtomicUsize::new(0));
        let over = gated(
            MemoryStore::default(),
            LONG,
            4,
            axum::Router::new().route("/r", counting(over_calls.clone(), || "fives")),
        );
        let first = send(&over, post("/r", "{}")).await;
        assert_eq!(first.status(), StatusCode::OK);
        let body = axum::body::to_bytes(first.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"fives", "the client gets the whole body");
        let retry = send(&over, post("/r", "{}")).await;
        assert_eq!(retry.status(), StatusCode::CONFLICT);
        assert_eq!(error_code(retry).await, "idempotency_replay_unavailable");
        assert_eq!(over_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_multi_chunk_oversized_body_reaches_the_client_intact() {
        let app = gated(
            MemoryStore::default(),
            LONG,
            5,
            axum::Router::new().route(
                "/r",
                axum::routing::post(|| async {
                    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
                        Ok(Bytes::from_static(b"abc")),
                        Ok(Bytes::from_static(b"def")),
                        Ok(Bytes::from_static(b"ghi")),
                    ];
                    Body::from_stream(futures_util::stream::iter(chunks))
                }),
            ),
        );
        let response = send(&app, post("/r", "{}")).await;
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"abcdefghi");
    }

    #[tokio::test]
    async fn a_body_stream_that_errors_after_partial_output_is_unreplayable() {
        let calls = Arc::new(AtomicUsize::new(0));
        let app = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                counting(calls.clone(), || {
                    let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
                        Ok(Bytes::from_static(b"partial")),
                        Err(std::io::Error::other("stream broke")),
                    ];
                    Body::from_stream(futures_util::stream::iter(chunks))
                }),
            ),
        );
        let first = send(&app, post("/r", "{}")).await;
        assert!(
            axum::body::to_bytes(first.into_body(), usize::MAX)
                .await
                .is_err(),
            "the client sees the same stream error the handler produced"
        );
        let retry = send(&app, post("/r", "{}")).await;
        assert_eq!(error_code(retry).await, "idempotency_replay_unavailable");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_client_disconnect_mid_handler_never_lets_the_retry_run() {
        use tower::ServiceExt as _;
        let calls = Arc::new(AtomicUsize::new(0));
        let store = MemoryStore::default();
        let slow_calls = calls.clone();
        let routes = axum::Router::new().route(
            "/r",
            axum::routing::post(move || {
                let calls = slow_calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    "done"
                }
            }),
        );

        let dropped = tokio::time::timeout(
            Duration::from_millis(50),
            gated(store.clone(), LONG, 1024, routes.clone()).oneshot(post("/r", "{}")),
        )
        .await;
        assert!(
            dropped.is_err(),
            "the request future was dropped mid-handler"
        );

        let immediate = send(
            &gated(store.clone(), LONG, 1024, routes.clone()),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(error_code(immediate).await, "conflict");
        let stale = send(
            &gated(backdated(store), LONG, 1024, routes),
            post("/r", "{}"),
        )
        .await;
        assert_eq!(error_code(stale).await, "idempotency_outcome_unknown");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_not_applied_5xx_releases_the_key_but_an_unmarked_5xx_does_not() {
        let released_calls = Arc::new(AtomicUsize::new(0));
        let released = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                counting(released_calls.clone(), || {
                    let mut response =
                        AppError::CapabilityUnavailable("object_storage").into_response();
                    response.extensions_mut().insert(MutationNotApplied);
                    response
                }),
            ),
        );
        send(&released, post("/r", "{}")).await;
        send(&released, post("/r", "{}")).await;
        assert_eq!(released_calls.load(Ordering::SeqCst), 2);

        let unknown_calls = Arc::new(AtomicUsize::new(0));
        let unknown = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                counting(unknown_calls.clone(), || {
                    AppError::CapabilityUnavailable("object_storage")
                }),
            ),
        );
        send(&unknown, post("/r", "{}")).await;
        let retry = send(&unknown, post("/r", "{}")).await;
        assert_eq!(error_code(retry).await, "idempotency_outcome_unknown");
        let different = send(&unknown, post("/r", r#"{"other":true}"#)).await;
        assert_eq!(error_code(different).await, "idempotency_conflict");
        assert_eq!(unknown_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_in_flight_request_refuses_duplicates_by_digest() {
        let calls = Arc::new(AtomicUsize::new(0));
        let slow_calls = calls.clone();
        let app = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                axum::routing::post(move || {
                    let calls = slow_calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        "done"
                    }
                }),
            ),
        );

        let first = tokio::spawn({
            let app = app.clone();
            async move { send(&app, post("/r", "{}")).await }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let same = send(&app, post("/r", "{}")).await;
        assert_eq!(error_code(same).await, "conflict");
        let different = send(&app, post("/r", r#"{"other":true}"#)).await;
        assert_eq!(error_code(different).await, "idempotency_conflict");
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_hundred_concurrent_identical_requests_run_the_handler_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let slow_calls = calls.clone();
        let app = gated(
            MemoryStore::default(),
            LONG,
            1024,
            axum::Router::new().route(
                "/r",
                axum::routing::post(move || {
                    let calls = slow_calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        (StatusCode::CREATED, "made")
                    }
                }),
            ),
        );

        let handles: Vec<_> = (0..100)
            .map(|_| {
                let app = app.clone();
                tokio::spawn(async move { send(&app, post("/r", "{}")).await.status() })
            })
            .collect();
        for handle in handles {
            let status = handle.await.unwrap();
            assert!(
                status == StatusCode::CREATED || status == StatusCode::CONFLICT,
                "{status}"
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    #[test]
    fn base64_roundtrips_arbitrary_bytes() {
        let original = b"\x00\x01\xff cached response body \xfe";
        let encoded = base64_encode(original);
        assert_eq!(base64_decode(&encoded).unwrap(), original);
    }

    #[test]
    fn base64_decode_rejects_invalid_input() {
        assert_eq!(base64_decode("not valid base64!!"), None);
    }

    #[test]
    fn request_digest_binds_content_type_and_body() {
        let mut json = axum::http::HeaderMap::new();
        json.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        );
        let mut text = axum::http::HeaderMap::new();
        text.insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain"),
        );

        assert_ne!(
            request_digest(&json, b"same"),
            request_digest(&json, b"other")
        );
        assert_ne!(
            request_digest(&json, b"same"),
            request_digest(&text, b"same")
        );
        assert_eq!(
            request_digest(&json, b"same"),
            request_digest(&json, b"same")
        );
    }

    /// The `MatchedPath`-present branch (the actually-intended case for
    /// mandatory-operation matching) needs a live `Router` to populate that
    /// extension — axum gives no public constructor for it outside routing —
    /// so it isn't unit-testable here; see this function's own TODO doc
    /// comment for the integration test this owes.
    #[test]
    fn operation_name_falls_back_to_the_raw_path_without_a_matched_path_extension() {
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/contact/bulk")
            .body(Body::empty())
            .unwrap();
        assert_eq!(operation_name(&req), "POST /api/v1/contact/bulk");
    }

    #[test]
    fn replay_headers_preserves_only_safe_end_to_end_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("location", axum::http::HeaderValue::from_static("/new"));
        headers.insert("etag", axum::http::HeaderValue::from_static("\"v1\""));
        headers.insert("set-cookie", axum::http::HeaderValue::from_static("secret"));
        headers.insert("connection", axum::http::HeaderValue::from_static("close"));

        assert_eq!(
            replay_headers(&headers),
            vec![
                ("location".to_owned(), "/new".to_owned()),
                ("etag".to_owned(), "\"v1\"".to_owned()),
            ]
        );
    }
}
