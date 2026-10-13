use axum::{Json, extract::State, http::StatusCode};
use serde_json::{Value, json};
use std::future::Future;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::state::AppState;

// M01 Core C-23: this handler takes no request body, query, or path
// parameters — there is nothing for it to fail validation on, so the 422
// this operation used to declare could never actually happen.
#[utoipa::path(
    get,
    path = "/health",
    tag = "operations",
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
    ),
)]
pub async fn health_check() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// P-deployment-preflight follow-up (deployment manifest) — unauthenticated,
/// read-only, same convention as `/health`/`/health/ready`/`/health/dependencies`:
/// an operator or support engineer confirming what a running node actually is,
/// without needing a shell into the container.
///
/// `image_digest` is deliberately absent: a running process cannot know its
/// own image's registry digest (the digest is computed by the registry from
/// the final pushed layers, after this binary was already built) — that half
/// of "the deployment manifest" is generated once, at release time, as a
/// `deployment-manifest.json` release asset instead (see
/// `document/general/plans/P-deployment-preflight.md`; the GitHub Actions
/// release workflow that once generated it was retired with the rest of CI).
///
/// `configuration_version` (P-environment-promotion §5 step 20, amends the
/// D-099/D-211-era "same as `application_version`" convention) is the sha256
/// of this deployment's canonical metadata export
/// (`xrm_server::bundle::canonical::bundle_hash`) — a real, deployment-
/// computed fact rather than the binary's own release version, because two
/// nodes running the identical release can legitimately hold different
/// metadata (mid-promotion, or a customization). `state.configuration_version`
/// is set once at the end of `XrmSystem::build()` and again after every
/// successful bundle apply (`xrm_server::bundle::apply::run_apply_job`); this
/// is what makes `fleetctl sync`/`drift` (which already compare this field on
/// every run) the scheduled drift check, with no scheduler inside the
/// deployment. Falls back to `application_version` — the old value — whenever
/// nothing has set it yet (attome-server tests, or a boot path that hasn't
/// reached `XrmSystem::build()`), so every existing call site keeps working.
// M01 Core C-23: no request body/query/path parameters here either — same
// impossible-422 fix as `/health` above.
#[utoipa::path(
    get,
    path = "/version",
    tag = "operations",
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
    ),
)]
pub async fn version(State(state): State<AppState>) -> Json<Value> {
    let schema = attome_db::schema_state(&state.db).await.ok();
    let app_version = env!("CARGO_PKG_VERSION");
    let configuration_version = state
        .configuration_version
        .load_full()
        .map(|hash| (*hash).clone())
        .unwrap_or_else(|| app_version.to_string());
    Json(json!({
        "application_version": app_version,
        "git_revision": std::env::var("APP_REVISION").unwrap_or_else(|_| "unknown".into()),
        "schema_version": schema.as_ref().and_then(|s| s.applied_max_version),
        "schema_dirty": schema.as_ref().map(|s| s.dirty),
        "configuration_version": configuration_version,
        "components": {
            "server": app_version,
        },
    }))
}

// ── Readiness (T4-5, review item 3.25) ─────────────────────────────────────────

/// How long one node reuses its last readiness verdict before probing DB and
/// Redis again. One second is below any sane probe interval (Kubernetes'
/// default `periodSeconds` is 10, compose's `healthcheck.interval` default is
/// 30 s), so a single checker never sees a stale answer, while N concurrent
/// checkers — the LB, the orchestrator, the `healthcheck` binary, a human —
/// cost one probe per second between them instead of one each.
///
/// Failure semantics: a `not_ready` verdict is memoised for the same TTL as a
/// `ready` one. That is deliberate — the alternative (retry immediately on a
/// failure) is exactly the probe storm against an already-struggling
/// dependency this cache exists to prevent, and a dependency that recovers
/// is still reported within one second. The drain flag (`AppState::draining`)
/// is checked *before* the cache and is never memoised, so a shutdown is
/// visible on the very next probe.
pub const READY_VERDICT_TTL: Duration = Duration::from_secs(1);

/// A3 (BSV-F07) — the overall deadline for one readiness probe. Each
/// dependency probe is individually bounded (fred's command timeout, sqlx's
/// pool acquire timeout), but their sum is not, and `cache.timeout = 0` used
/// to remove even the Redis bound. A probe that cannot answer within this
/// window is reported as not-ready — honest, and it keeps the `/health/ready`
/// handler (and anything behind the single-flight guard) from being held open
/// for as long as the slowest dependency takes. 2 s is well under the 10 s
/// Kubernetes `timeoutSeconds` default and above any healthy probe's cost.
pub(crate) const READY_PROBE_DEADLINE: Duration = Duration::from_secs(2);

/// One readiness probe's per-dependency outcome. `ready` iff every field is
/// `true`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadyVerdict {
    pub db: bool,
    pub redis: bool,
    pub redis_coordination: bool,
    pub registry: bool,
    pub schema: bool,
}

impl ReadyVerdict {
    pub fn is_ready(&self) -> bool {
        self.db && self.redis && self.redis_coordination && self.registry && self.schema
    }
}

/// Per-node memo of the last readiness probe (guidelines §5: request-local/
/// observational state that is rebuilt from the live dependencies on every
/// miss, never a source of truth for anything, never shared across nodes).
///
/// Single-flight: a miss serializes on `probe` so concurrent probers at a cold
/// cache cost exactly one probe, and the value lock (`last`) is held only to
/// read the memo and to publish the result. BSV-F07: holding `last`'s write
/// lock across the probe made every cached reader queue behind a slow
/// dependency, so the lock covering the value no longer covers the probe.
#[derive(Default)]
pub struct ReadinessCache {
    last: RwLock<Option<(Instant, ReadyVerdict)>>,
    /// Single-flight guard for the probe itself, deliberately separate from
    /// `last` so a cache hit never waits on an in-flight probe (BSV-F07).
    probe: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for ReadinessCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadinessCache").finish_non_exhaustive()
    }
}

impl ReadinessCache {
    /// Returns the memoised verdict if it is younger than `ttl`, otherwise
    /// runs `probe`, memoises its result, and returns it.
    pub async fn get_or_probe<F, Fut>(&self, ttl: Duration, probe: F) -> ReadyVerdict
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = ReadyVerdict>,
    {
        if let Some((at, verdict)) = *self.last.read().await
            && at.elapsed() < ttl
        {
            return verdict;
        }
        let _flight = self.probe.lock().await;
        // Re-check under the single-flight guard: another prober may have
        // refreshed the slot while this one waited.
        if let Some((at, verdict)) = *self.last.read().await
            && at.elapsed() < ttl
        {
            return verdict;
        }
        let verdict = probe().await;
        *self.last.write().await = Some((Instant::now(), verdict));
        verdict
    }
}

/// The actual dependency probes — one `SELECT 1`, two Redis pings, the
/// registry pre-warm flag, and (when configured) the applied schema version.
async fn probe_readiness(state: &AppState) -> ReadyVerdict {
    let db = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();

    // P1.15: pinged in parallel — when `cache.roles.coordination` isn't set
    // this is a clone of the same pool, so the second ping is a harmless
    // no-op; when it IS set, readiness now actually reflects both endpoints.
    let (redis, redis_coordination) = tokio::join!(
        attome_cache::redis_ping(&state.redis),
        attome_cache::redis_ping(&state.redis_coordination),
    );
    let registry = state.registry_ready.load(Ordering::Relaxed);

    // P-migration-governance: `None` (no expected version attached) always
    // passes -- test/back-compat default, same convention as the other
    // opt-in AppState fields. `Some(expected)` requires the connected
    // database's applied migrations to have reached *at least* `expected`
    // (never exact-match -- see `expected_schema_version`'s doc comment for
    // why exact-match would incorrectly bounce already-running old-version
    // pods during a rolling deploy) and requires no dirty/interrupted
    // migration row, fail-closed per D-038.
    let schema = match state.expected_schema_version {
        None => true,
        Some(expected) => match attome_db::schema_state(&state.db).await {
            Ok(s) => {
                !s.dirty
                    && s.applied_max_version
                        .is_some_and(|applied| applied >= expected)
            }
            Err(_) => false,
        },
    };

    ReadyVerdict {
        db,
        redis,
        redis_coordination,
        registry,
        schema,
    }
}

/// A3 (BSV-F07) — run a dependency probe under an explicit overall deadline.
/// On expiry every field is reported not-ready: the node's ability to serve is
/// unknown, and unknown must never read as ready (the same posture
/// `replica_caught_up_to` takes for an unknown watermark).
pub(crate) async fn bounded_verdict<F>(deadline: Duration, probe: F) -> ReadyVerdict
where
    F: Future<Output = ReadyVerdict>,
{
    match tokio::time::timeout(deadline, probe).await {
        Ok(verdict) => verdict,
        Err(_) => {
            tracing::warn!(
                deadline_secs = deadline.as_secs_f64(),
                "readiness probe exceeded its deadline — reporting not ready"
            );
            ReadyVerdict {
                db: false,
                redis: false,
                redis_coordination: false,
                registry: false,
                schema: false,
            }
        }
    }
}

/// The 503 a draining node answers with. Every dependency field is reported
/// as `false` on purpose: nothing about the node is *broken*, but no
/// consumer of this body should be able to read it as "ready" by looking at
/// the fields rather than the status code.
fn draining_response() -> (StatusCode, Json<Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "status":              "draining",
            "db":                  false,
            "redis":               false,
            "redis_coordination":  false,
            "registry":            false,
            "schema":              false,
        })),
    )
}

fn ready_response(verdict: ReadyVerdict) -> (StatusCode, Json<Value>) {
    let ready = verdict.is_ready();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status":              if ready { "ready" } else { "not_ready" },
            "db":                  verdict.db,
            "redis":               verdict.redis,
            "redis_coordination":  verdict.redis_coordination,
            "registry":            verdict.registry,
            "schema":              verdict.schema,
        })),
    )
}

// T4-5 (review item 3.25), kept out of the `///` block on purpose: utoipa
// turns that block into the operation's OpenAPI `summary`, so this note
// would otherwise dirty `openapi.json`/`api-types.ts` for a behaviour that is
// invisible on the wire. Two things changed here that the summary doesn't say:
//   - a node that has received its shutdown signal (`AppState::draining`)
//     answers 503 immediately, ahead of any probe, so the LB stops routing
//     to it while `with_graceful_shutdown` finishes in-flight requests;
//   - the probe verdict is memoised per node for `READY_VERDICT_TTL` (see
//     that constant for the TTL and failure semantics). The drain check runs
//     ahead of the cache and is never memoised.
/// Readiness probe — returns 503 unless DB, Redis, the metadata registry
/// pre-warm (`registry_ready`, Plan 1.2), and the applied schema version
/// (P-migration-governance) are all confirmed. Load balancer / Kubernetes
/// gates traffic on the status code, not the body.
///
/// M01 Core C-23: dropped the 422 this operation used to declare — the
/// handler takes no request body/query/path parameters, so validation
/// failure was never a reachable outcome here. The genuine non-200 outcome
/// (503, `not_ready`/`draining`) is this same custom `serde_json::Value`
/// body, not `ErrorResponse` — see `ready_response`/`draining_response`.
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "operations",
    responses(
        (status = 200, description = "Success", body = serde_json::Value),
        (status = 503, description = "Not ready, or draining for shutdown", body = serde_json::Value),
    ),
)]
pub async fn health_ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    if state.draining.load(Ordering::Relaxed) {
        return draining_response();
    }
    let verdict = state
        .readiness
        .get_or_probe(READY_VERDICT_TTL, || {
            bounded_verdict(READY_PROBE_DEADLINE, probe_readiness(&state))
        })
        .await;
    ready_response(verdict)
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(health_check, version, health_ready))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Tests (T4-5) — pure in-memory: the cache and the response shaping, no
// AppState (which needs live pools) ─────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    const ALL_OK: ReadyVerdict = ReadyVerdict {
        db: true,
        redis: true,
        redis_coordination: true,
        registry: true,
        schema: true,
    };

    #[tokio::test]
    async fn second_probe_within_the_ttl_reuses_the_memoised_verdict() {
        let cache = ReadinessCache::default();
        let probes = Arc::new(AtomicUsize::new(0));
        let probe = || {
            let probes = probes.clone();
            async move {
                probes.fetch_add(1, Ordering::SeqCst);
                ALL_OK
            }
        };

        let first = cache.get_or_probe(READY_VERDICT_TTL, probe).await;
        let second = cache.get_or_probe(READY_VERDICT_TTL, probe).await;

        assert_eq!(first, ALL_OK);
        assert_eq!(second, ALL_OK);
        assert_eq!(
            probes.load(Ordering::SeqCst),
            1,
            "the second call inside the TTL must not re-probe"
        );
    }

    #[tokio::test]
    async fn a_not_ready_verdict_is_memoised_for_the_same_ttl() {
        // The failure branch is memoised too (see READY_VERDICT_TTL's doc):
        // a flapping dependency must not turn every probe into a fresh hit.
        let cache = ReadinessCache::default();
        let probes = Arc::new(AtomicUsize::new(0));
        let probe = || {
            let probes = probes.clone();
            async move {
                probes.fetch_add(1, Ordering::SeqCst);
                ReadyVerdict {
                    db: false,
                    ..ALL_OK
                }
            }
        };

        let first = cache.get_or_probe(READY_VERDICT_TTL, probe).await;
        let second = cache.get_or_probe(READY_VERDICT_TTL, probe).await;

        assert!(!first.is_ready());
        assert_eq!(first, second);
        assert_eq!(probes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_expired_verdict_is_probed_again() {
        let cache = ReadinessCache::default();
        let probes = Arc::new(AtomicUsize::new(0));
        let probe = || {
            let probes = probes.clone();
            async move {
                probes.fetch_add(1, Ordering::SeqCst);
                ALL_OK
            }
        };

        cache.get_or_probe(Duration::ZERO, probe).await;
        cache.get_or_probe(Duration::ZERO, probe).await;
        assert_eq!(
            probes.load(Ordering::SeqCst),
            2,
            "a zero TTL means every call is a miss"
        );
    }

    #[tokio::test]
    async fn concurrent_probers_at_a_cold_cache_share_one_probe() {
        let cache = Arc::new(ReadinessCache::default());
        let probes = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache = cache.clone();
            let probes = probes.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_or_probe(READY_VERDICT_TTL, || async move {
                        probes.fetch_add(1, Ordering::SeqCst);
                        // Long enough that every spawned task is queued on
                        // the write lock before the first probe finishes.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        ALL_OK
                    })
                    .await
            }));
        }
        for h in handles {
            assert_eq!(h.await.unwrap(), ALL_OK);
        }
        assert_eq!(probes.load(Ordering::SeqCst), 1, "single-flight");
    }

    #[test]
    fn draining_answers_503_with_a_draining_status() {
        let (status, Json(body)) = draining_response();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "draining");
        assert_eq!(body["db"], false);
    }

    #[test]
    fn ready_response_maps_the_verdict_onto_the_status_code() {
        let (status, Json(body)) = ready_response(ALL_OK);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "ready");

        let (status, Json(body)) = ready_response(ReadyVerdict {
            redis_coordination: false,
            ..ALL_OK
        });
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "not_ready");
        assert_eq!(body["redis_coordination"], false);
        assert_eq!(body["db"], true);
    }

    /// A3 (BSV-F07) — a probe that cannot answer inside the deadline reports
    /// not-ready rather than holding the handler (and everything behind the
    /// single-flight guard) open.
    #[tokio::test]
    async fn get_or_probe_returns_not_ready_within_the_deadline() {
        let cache = ReadinessCache::default();
        let start = Instant::now();
        let verdict = cache
            .get_or_probe(READY_VERDICT_TTL, || {
                bounded_verdict(
                    Duration::from_millis(20),
                    std::future::pending::<ReadyVerdict>(),
                )
            })
            .await;
        assert!(
            !verdict.is_ready(),
            "a probe past its deadline must report not-ready"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the deadline must bound the wait, took {:?}",
            start.elapsed()
        );
    }

    /// A3 (BSV-F07) — a cache hit is served while a probe is in flight: the
    /// lock covering the memoised value no longer covers the probe, so a slow
    /// dependency cannot queue every other readiness checker behind it.
    #[tokio::test]
    async fn a_cached_verdict_is_served_while_a_probe_is_in_flight() {
        let cache = Arc::new(ReadinessCache::default());
        cache
            .get_or_probe(READY_VERDICT_TTL, || async { ALL_OK })
            .await;

        let slow = {
            let cache = cache.clone();
            tokio::spawn(async move {
                cache
                    .get_or_probe(Duration::ZERO, || async {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        ALL_OK
                    })
                    .await
            })
        };
        // Let the slow prober take the single-flight guard.
        tokio::time::sleep(Duration::from_millis(20)).await;

        let served = tokio::time::timeout(
            Duration::from_millis(50),
            cache.get_or_probe(READY_VERDICT_TTL, || async {
                panic!("a cache hit must not re-probe")
            }),
        )
        .await
        .expect("a cache hit must not wait behind an in-flight probe");
        assert_eq!(served, ALL_OK);
        assert_eq!(slow.await.unwrap(), ALL_OK);
    }
}
