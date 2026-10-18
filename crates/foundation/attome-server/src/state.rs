use arc_swap::ArcSwapOption;
use attome_auth::PepperRing;
use attome_cache::sticky_primary::PinCheck;
use attome_cache::{MetadataCache, Store};
use attome_config::AppConfig;
use attome_db::DbPool;
use attome_storage::StorageClient;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8};
use uuid::Uuid;

use crate::capability::{CapabilityRegistry, CapabilityStatuses};
use crate::replica_watermark::ReplicaWatermark;
use crate::secrets::SecretRings;
use crate::security::SecurityResolverHandle;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: DbPool,
    /// SELECT-only pool for `/api/v1/query/execute` (P1.1e). Falls back to a
    /// clone of `db` (with a loud startup warning) when `database.readonly`
    /// isn't configured — see `crates/server/src/main.rs`.
    /// Never `None`: callers always have a valid pool to query.
    pub db_readonly: DbPool,
    /// P-api-consistency-hardening (a) — the same `attome_readonly` role as
    /// `db_readonly`, connected to the primary host/port instead
    /// (`attome_db::create_readonly_primary_pool`). `None` whenever
    /// `database.readonly` isn't configured, or (today) whenever the
    /// deployment's boot path hasn't been updated to attach it — see
    /// `with_readonly_primary`. `readonly_query_pool` is the only intended
    /// reader; do not use this directly from a handler.
    pub db_readonly_primary: Option<DbPool>,
    /// P-db-privilege-separation / D-117 — DDL-capable pool
    /// (`attome_db::create_migrator_pool`) for schema/entity provisioning
    /// (`xrm-entity::provision`) and boot-time seeding. Falls back to the
    /// same identity as `db` when `database.migrator` isn't configured (see
    /// that constructor's doc comment) — never `None`, same pattern as
    /// `db_readonly`. Ordinary request-time entity/record CRUD must keep
    /// using `db`, not this — this pool exists so `db` can eventually be
    /// locked down to DML-only without breaking schema administration.
    pub db_migrator: DbPool,
    pub redis: Store,
    /// P1.15 — coordination-role Redis pool (S2S nonce/rate-limit, general
    /// HTTP rate limiter, idempotency gate). A clone of `redis` unless the
    /// deployment configured `cache.roles.coordination`, in which case it's a
    /// dedicated pool against that endpoint — see
    /// `attome_cache::create_role_redis_pool`.
    pub redis_coordination: Store,
    pub storage: StorageClient,
    /// Hot-read secrets — seeded at boot from whatever `config` already
    /// resolved (see `SecretRings::from_config`) and never refreshed after
    /// that; rotating any of them is a config edit plus a restart. The
    /// rotatable fields stay full `KeyRing`s (current + previous key) so a
    /// manual rotation gets an overlap window instead of instantly
    /// invalidating everything signed/encrypted under the previous value —
    /// see `attome_server::secrets` module doc.
    pub secrets: MetadataCache<SecretRings>,
    /// Fails closed (`DenyAllResolver`) until `XrmSystemBuilder::build()` stores
    /// the real `xrm-security` resolver — see `security.rs`.
    pub security: SecurityResolverHandle,
    /// Per-node liveness flag, not shared business state (same class as the
    /// license arc-swap): flips true once the caller's first-build/pre-warm
    /// step succeeds. Generic here so attome-server stays free of xrm-* deps;
    /// `XrmSystemBuilder::build()` (xrm-server) sets it after the metadata
    /// registry pre-warm completes. `/health/ready` gates on it (Plan 1.2/1.3e).
    pub registry_ready: Arc<AtomicBool>,
    /// P-read-your-writes-lsn — the read replica's last-polled replay
    /// position, fed by `replica_watermark::spawn_watermark_refresh`
    /// (`main.rs`, unconditional whenever `database.readonly` is
    /// configured). `None` until the first successful poll, or whenever
    /// `database.readonly` isn't configured at all (the poller is never
    /// spawned) — `read_pool`/`route_if_lag_ok` treat that identically to a
    /// replica that hasn't caught up yet, i.e. fail closed toward the
    /// primary. Each node maintains its own watermark independently
    /// (rebuilt from Postgres, never a cross-node source of truth) — same
    /// CRITICAL Multi-Server posture as `security`/the metadata registry.
    pub replica_watermark: Arc<ArcSwapOption<ReplicaWatermark>>,
    /// P-audit-chain-hardening item (e) — ingest circuit breaker. `true`
    /// once `xrm_audit_ingest`'s undrained backlog has crossed
    /// `config.audit.ingest_backlog_threshold`; the
    /// `middleware::mutation_gate` layer rejects new mutating requests with
    /// `AppError::Overloaded` while it stays true, GETs unaffected. Generic
    /// here (same reasoning as `registry_ready`) so attome-server stays free
    /// of xrm-* deps — `xrm_server::spawn_ingest_backlog_refresh` (the only
    /// writer) computes the actual backlog via `xrm_audit::chainer`. Never
    /// true until that poll task is spawned and has run at least once, so a
    /// deployment that never calls it (or hasn't yet) behaves exactly as
    /// before this flag existed.
    pub audit_ingest_backlog_exceeded: Arc<AtomicBool>,
    /// AB5-T6: why this node refuses writes, as a
    /// [`crate::read_only::ReadOnlyReason`] (0 = it does not). Same split
    /// as the backlog flag: this crate owns the flag and the gate,
    /// `attome_api::spawn_read_only_refresh` decides it.
    pub read_only: Arc<AtomicU8>,
    /// P-migration-governance — the highest migration version this
    /// binary was compiled against (`MIGRATOR`'s own max version,
    /// `crates/server/src/boot.rs`), so `/health/ready` can confirm the
    /// connected database has actually reached it, not just that Postgres
    /// answers `SELECT 1`. `None` (the `AppState::new` default, and every
    /// existing test call site) disables the check entirely -- same
    /// opt-in-by-attachment pattern as `db_readonly_primary`. `Some` value
    /// checks *at least* this version, deliberately not exact equality: in
    /// a rolling deployment the one-shot `migrate` binary runs ahead of the
    /// pod rollout, so already-running old-version pods (compiled against
    /// a lower expected version) must keep passing readiness once the new
    /// migrations land underneath them, not get bounced out of rotation --
    /// see the db-and-migrations skill's expand/dual-write/backfill/switch/
    /// contract discipline (D-127c), which is what keeps an "at least"
    /// check safe for old pods to read against.
    pub expected_schema_version: Option<i64>,
    /// D-344 (amends D-167) — per-capability durability status, read by the
    /// `capability::Available<C>` extractor on the handful of routes that
    /// cannot durably complete without a specific dependency (upload, bulk
    /// import, mail resend).
    ///
    /// Generic here for the same reason as `registry_ready` and
    /// `audit_ingest_backlog_exceeded` — attome-server owns the flag and the
    /// gate, `xrm_server::spawn_capability_refresh` (the only writer) owns
    /// the probes. Every capability starts `Unknown`, which admits, so a
    /// deployment (or test) that never spawns that task behaves exactly as
    /// it did before this field existed.
    ///
    /// **Never consulted by `/health/ready`.** That gate stays exactly as
    /// D-167 specifies; this one refuses individual operations instead of
    /// evicting the node.
    pub capabilities: Arc<crate::capability::CapabilityRegistry>,
    /// P-environment-promotion §5 step 20 — the sha256 of the canonical
    /// metadata export (`xrm_server::bundle::canonical::bundle_hash`),
    /// recomputed once at the end of `XrmSystem::build()` and again after
    /// every successful bundle apply. `/version`'s `configuration_version`
    /// reports this when set, falling back to `CARGO_PKG_VERSION` (this
    /// binary's own version, as it always has) when it is not — a test/
    /// back-compat default, same opt-in-by-attachment pattern as
    /// `expected_schema_version`. Generic here (not `Option<String>` behind
    /// a plain field) for the same reason as `replica_watermark`:
    /// attome-server has no `xrm-*` dependency to compute the hash itself, so
    /// `xrm_server::system` writes through this handle after the fact.
    /// `ArcSwapOption` rather than a `Mutex` because it is read on every
    /// `/version` call and written only at boot and after an apply — the
    /// same read-hot/write-cold shape `replica_watermark` already has.
    pub configuration_version: Arc<ArcSwapOption<String>>,
    /// T4-5 (review item 3.25) — set exactly once, by the shutdown-signal
    /// task in `main.rs`, the instant SIGTERM/ctrl-c arrives and *before*
    /// the graceful-shutdown watch channel is signalled. `/health/ready`
    /// answers 503 the moment this is `true` so the load balancer stops
    /// routing new traffic to this node while `with_graceful_shutdown`
    /// finishes in-flight requests. `/health` (liveness) never reads it — a
    /// draining node is alive, it just doesn't want work. Per-node,
    /// observational, never shared: same class as `registry_ready`.
    pub draining: Arc<AtomicBool>,
    /// U9-T1 — every boot step (migrations, seeds, pre-warm) has finished and
    /// the listener is about to serve. `/health/startup` answers 503 until
    /// then. Per-node and observational, like `draining`.
    pub started: Arc<AtomicBool>,
    /// Y8-T5 — this node's metadata registry has stayed behind the database's
    /// change log for two polls in a row. Readiness reports the registry not
    /// ready meanwhile, so a load balancer stops sending this node work it
    /// would answer from stale metadata. Per-node and observational.
    pub metadata_lagging: Arc<AtomicBool>,
    /// Y8-T7 — the last metadata change this node's registry has applied
    /// (`metadata_change_log.id`), sent on every response as
    /// `Attome-Metadata-Version` so clients notice a new model. `0` until
    /// the registry is warm.
    pub metadata_version: Arc<std::sync::atomic::AtomicI64>,
    /// Y8-T6 — what the engine lends the metadata-pin layer (reading the
    /// change-log watermark, starting a catch-up); set once at engine start.
    pub metadata_hooks:
        Arc<std::sync::OnceLock<Arc<crate::middleware::metadata_pin::MetadataHooks>>>,
    /// AB5-T7 — the load-shedding slots, sized from `shed` at start.
    pub shedder: Arc<crate::middleware::shed::Shedder>,
    /// S3 (BSV-F15) — the same drain event as `AppState::draining`, in a form a
    /// long-lived stream can `.await`: a stream that holds the graceful-shutdown
    /// deadline open (xrm-ai's chat stream, trd-engine's quote stream) creates
    /// `AppState::shutdown_signal()` once and ends its loop when it resolves,
    /// instead of running to its own multi-minute lifetime and making every
    /// rolling restart hit the deadline and log an error. Flipped by
    /// `server::boot::begin_drain` at the same instant as `draining`, so the
    /// two can never disagree. Per-node, observational, rebuildable — same
    /// class as `draining`.
    pub drain_signal: tokio::sync::watch::Sender<bool>,
    /// T4-5 — per-node memo of the last `/health/ready` probe result, so a
    /// burst of probes (several LB/orchestrator checkers, `healthcheck`
    /// binary, humans) costs one DB round trip + Redis ping per
    /// `health::READY_VERDICT_TTL` instead of one per call. Rebuilt from
    /// the live dependencies on every miss; see `health::ReadinessCache`
    /// for the TTL and failure semantics.
    pub readiness: Arc<crate::health::ReadinessCache>,
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState").finish_non_exhaustive()
    }
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: AppConfig,
        db: DbPool,
        db_readonly: DbPool,
        db_migrator: DbPool,
        redis: impl Into<Store>,
        redis_coordination: impl Into<Store>,
        storage: StorageClient,
    ) -> Self {
        let secrets = MetadataCache::new(SecretRings::from_config(&config));
        let shedder = Arc::new(crate::middleware::shed::Shedder::new(&config.shed));
        // S9-T3: every process that completes or replays a durable
        // idempotency record builds an AppState first.
        crate::middleware::idempotency_durable::install_response_key(
            config.idempotency.response_encryption_key.as_ref(),
        );
        Self {
            config: Arc::new(config),
            db,
            db_readonly,
            db_readonly_primary: None,
            db_migrator,
            redis: redis.into(),
            redis_coordination: redis_coordination.into(),
            storage,
            secrets,
            security: SecurityResolverHandle::default_deny(),
            registry_ready: Arc::new(AtomicBool::new(false)),
            replica_watermark: Arc::new(ArcSwapOption::from(None)),
            audit_ingest_backlog_exceeded: Arc::new(AtomicBool::new(false)),
            read_only: Arc::new(AtomicU8::new(0)),
            expected_schema_version: None,
            capabilities: Arc::new(crate::capability::CapabilityRegistry::inert()),
            configuration_version: Arc::new(ArcSwapOption::from(None)),
            draining: Arc::new(AtomicBool::new(false)),
            started: Arc::new(AtomicBool::new(false)),
            metadata_lagging: Arc::new(AtomicBool::new(false)),
            metadata_version: Arc::new(std::sync::atomic::AtomicI64::new(0)),
            metadata_hooks: Arc::new(std::sync::OnceLock::new()),
            shedder,
            // S3 — no receivers at construction, so the initial `send` is a
            // no-op; `shutdown_signal()` subscribes on demand.
            drain_signal: tokio::sync::watch::channel(false).0,
            readiness: Arc::new(crate::health::ReadinessCache::default()),
        }
    }

    /// S3 (BSV-F15) — a `'static`, re-creatable future that completes when this
    /// node begins draining. Create one per stream and `select!` it against the
    /// stream loop; because it is backed by a `watch` channel, calling it after
    /// the drain has already started resolves immediately rather than waiting
    /// for the next flip.
    pub fn shutdown_signal(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        shutdown_signal_from(&self.drain_signal)
    }

    /// Attaches `db_readonly_primary` after construction rather than adding it
    /// as a positional `new()` argument — this constructor already has 23
    /// call sites across this workspace's tests (a repo-wide grep confirms
    /// it), and every one of those is unrelated to `query/execute` read
    /// routing; forcing them all to thread through a new pool they don't
    /// exercise would be pure churn. Only `crates/server/src/boot.rs` needs
    /// to call this. Chainable: `AppState::new(...).with_readonly_primary(pool)`.
    pub fn with_readonly_primary(mut self, db_readonly_primary: Option<DbPool>) -> Self {
        self.db_readonly_primary = db_readonly_primary;
        self
    }

    /// Attaches `expected_schema_version` after construction, same reasoning
    /// as `with_readonly_primary` -- only `crates/server/src/boot.rs` (the
    /// one place `MIGRATOR`'s compiled version is known) needs to call this.
    pub fn with_expected_schema_version(mut self, expected_schema_version: Option<i64>) -> Self {
        self.expected_schema_version = expected_schema_version;
        self
    }

    /// Attaches a `capability.*`-configured registry in place of the inert
    /// default, same post-construction pattern and same reasoning as the two
    /// `with_*` methods above — only the boot path knows the configured
    /// threshold, and no existing `AppState::new` call site exercises the
    /// gate.
    pub fn with_capabilities(mut self, capabilities: Arc<CapabilityRegistry>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// The pepper ring every platform-generated bearer secret is hashed and
    /// verified with (API keys D-112/D-118, refresh tokens D-317, reset,
    /// email-verification, invitation and portal tokens D-500).
    ///
    /// D-120: the pepper and the retired peppers come from `self.secrets`
    /// (config-sourced, D-549 — no live rotation without a restart); the
    /// pepper id and the versioned-write flag are structural rollout state
    /// and stay on the cold config. Cheap enough to build per call (a
    /// handful of string clones). This is the one place the ring is
    /// assembled.
    pub fn pepper_ring(&self) -> PepperRing {
        let secrets = self.secrets.load();
        let previous: Vec<(u32, String)> = secrets
            .apikey_hash_previous_peppers
            .iter()
            .map(|p| (p.id, p.secret.expose().to_owned()))
            .collect();
        PepperRing::new(
            self.config.auth.apikey_hash_pepper_id,
            secrets.apikey_hash_pepper.expose(),
            &previous,
        )
    }

    /// P1.12, LSN-aware since P-read-your-writes-lsn — the pool a read
    /// should use. A Redis error or a legacy (pre-LSN) pin value fails
    /// closed to the primary, same posture the old bare-sentinel pin always
    /// had. A current LSN-carrying pin routes to the primary until the
    /// cached replica watermark shows it has replayed at least that far
    /// (`replica_caught_up_to`); once caught up — or when there was never a
    /// pin at all — routing falls through to `route_if_lag_ok`'s
    /// unconditional lag circuit breaker. When `database.readonly` isn't
    /// configured, `db_readonly` is already a clone of `db` and
    /// `replica_watermark` is never populated (the poller is never spawned),
    /// so this stays byte-identical to always using `db` for any deployment
    /// that hasn't opted in.
    pub async fn read_pool(&self, user_id: Uuid) -> &DbPool {
        // Z2-T6: no replica, no pin to read: the primary, with no store call.
        if !self.config.database.has_read_replica() {
            return &self.db;
        }
        match attome_cache::sticky_primary::check_pin(&self.redis, user_id).await {
            PinCheck::RedisError => {
                crate::metrics::record_read_routing_decision("redis_error_primary");
                &self.db
            }
            PinCheck::Legacy => {
                crate::metrics::record_read_routing_decision("legacy_primary");
                &self.db
            }
            PinCheck::Pinned(write_lsn) => {
                if self.replica_caught_up_to(&write_lsn) {
                    self.route_if_lag_ok("caught_up_replica", "circuit_breaker_primary")
                } else {
                    crate::metrics::record_read_routing_decision("pending_primary");
                    &self.db
                }
            }
            PinCheck::None => self.route_if_lag_ok("none_replica", "circuit_breaker_primary"),
        }
    }

    /// True iff the cached replica watermark (`replica_watermark`, refreshed
    /// by `replica_watermark::spawn_watermark_refresh`) has replayed at
    /// least as far as `write_lsn`. `false` — never "caught up" — whenever no
    /// watermark has been cached yet (cold start, or `database.readonly`
    /// unset): unknown must never be treated as caught up.
    fn replica_caught_up_to(&self, write_lsn: &str) -> bool {
        match self.replica_watermark.load().as_ref() {
            // A9 (BSV-F21) — a stale watermark is unknown, and unknown must
            // never read as caught up.
            Some(watermark) if !watermark.is_stale() => {
                attome_cache::sticky_primary::lsn_ge(&watermark.replay_lsn, write_lsn)
            }
            Some(_) | None => false,
        }
    }

    /// The unconditional lag circuit breaker
    /// (`database.replica_max_lag_secs`, P-ha-failover-hardening item
    /// (e)/P-read-your-writes-lsn): falls back to the primary for every
    /// caller, not just one with an active pin, whenever the cached replica
    /// lag exceeds the configured ceiling. No policy configured (`None`, the
    /// universal default today) or no watermark cached yet both route to the
    /// replica — unchanged from before this breaker existed. `replica_label`/
    /// `breaker_label` let the two call sites (`PinCheck::None` and a
    /// caught-up `PinCheck::Pinned`) record distinct
    /// `read_routing_decisions_total` outcomes even though they share this
    /// same decision table.
    fn route_if_lag_ok(&self, replica_label: &'static str, breaker_label: &'static str) -> &DbPool {
        if should_fall_back_to_primary(
            self.config.database.replica_max_lag_secs,
            self.replica_watermark.load().as_ref().map(|w| &**w),
        ) {
            crate::metrics::record_read_routing_decision(breaker_label);
            &self.db
        } else {
            crate::metrics::record_read_routing_decision(replica_label);
            &self.db_readonly
        }
    }

    /// P-api-consistency-hardening (a) — the pool `query_exec.rs::execute`
    /// (`/api/v1/query/execute`: list views, reports, custom/stored SQL
    /// queries) should use. Deliberately not a call to `read_pool`: that
    /// method can return `&self.db`, the full-privilege pool, on a pin/
    /// circuit-breaker/fail-closed branch — correct for `entity_crud.rs`
    /// (which already writes through `db` too), wrong here. Stored/custom
    /// SQL in `query_exec.rs` runs under the SELECT-only `attome_readonly`
    /// role specifically so a buggy or malicious stored query can't mutate
    /// or exfiltrate beyond `SELECT` (P1.1e), and that guarantee must hold
    /// whether or not a pin is active — so every branch below that
    /// `read_pool` would send to `&self.db` is sent to
    /// `readonly_primary_or_fallback()` (same role, primary host) instead.
    /// Mirrors `read_pool`'s exact `PinCheck`/lag-breaker decision table,
    /// down to the metric label names (prefixed `query_` so the two paths
    /// stay distinguishable in `read_routing_decisions_total`).
    ///
    /// TODO(P-cache-consistency-hardening): only checks the user-level pin.
    /// That plan's entity-keyed pin (`has_entity_pin(entity, record_id)`)
    /// doesn't exist in this codebase yet — once it does,
    /// `query_exec.rs::execute` should also consult it for single-entity-
    /// scoped stored queries (`qrow.entity_logical_name`), per
    /// `P-api-consistency-hardening`'s own §4(a) design. Not implemented
    /// here; a multi-entity/custom query only ever gets the user-level
    /// check, which is the same scoping limit that plan already names as
    /// acceptable.
    pub async fn readonly_query_pool(&self, user_id: Uuid) -> &DbPool {
        match attome_cache::sticky_primary::check_pin(&self.redis, user_id).await {
            PinCheck::RedisError => {
                crate::metrics::record_read_routing_decision("query_redis_error_primary");
                self.readonly_primary_or_fallback()
            }
            PinCheck::Legacy => {
                crate::metrics::record_read_routing_decision("query_legacy_primary");
                self.readonly_primary_or_fallback()
            }
            PinCheck::Pinned(write_lsn) => {
                if self.replica_caught_up_to(&write_lsn) {
                    self.route_query_if_lag_ok(
                        "query_caught_up_replica",
                        "query_circuit_breaker_primary",
                    )
                } else {
                    crate::metrics::record_read_routing_decision("query_pending_primary");
                    self.readonly_primary_or_fallback()
                }
            }
            PinCheck::None => {
                self.route_query_if_lag_ok("query_none_replica", "query_circuit_breaker_primary")
            }
        }
    }

    /// `db_readonly_primary` if configured, else `db_readonly` with a logged
    /// warning — never `db` (see `readonly_query_pool`'s doc comment for
    /// why). A deployment that has `database.readonly` set but is running a
    /// boot path that hasn't called `with_readonly_primary` yet degrades to
    /// today's pre-fix behavior (a possibly-stale replica read) instead of
    /// failing the request outright.
    fn readonly_primary_or_fallback(&self) -> &DbPool {
        match &self.db_readonly_primary {
            Some(pool) => pool,
            None => {
                crate::metrics::record_read_routing_decision("query_readonly_primary_missing");
                // Runs on every affected request; one warning a minute says the
                // same thing without flooding the log. The counter carries the rate.
                static LAST_WARNING_SECS: std::sync::atomic::AtomicI64 =
                    std::sync::atomic::AtomicI64::new(i64::MIN);
                if warning_due(&LAST_WARNING_SECS, unix_now_secs()) {
                    tracing::warn!(
                        "query/execute needs a fresh read (pin active or replica-lag circuit \
                         breaker tripped) but no db_readonly_primary pool is attached — \
                         falling back to db_readonly, which may serve stale data until the \
                         pin/lag window clears (logged at most once a minute; see \
                         read_routing_decisions_total{{decision=\"query_readonly_primary_missing\"}})"
                    );
                }
                &self.db_readonly
            }
        }
    }

    /// Same decision table as `route_if_lag_ok`, but the "breaker tripped"
    /// branch lands on `readonly_primary_or_fallback()` instead of
    /// `&self.db` — see `readonly_query_pool`'s doc comment for why
    /// `query_exec.rs` can never use the full-privilege pool.
    fn route_query_if_lag_ok(
        &self,
        replica_label: &'static str,
        breaker_label: &'static str,
    ) -> &DbPool {
        if should_fall_back_to_primary(
            self.config.database.replica_max_lag_secs,
            self.replica_watermark.load().as_ref().map(|w| &**w),
        ) {
            crate::metrics::record_read_routing_decision(breaker_label);
            self.readonly_primary_or_fallback()
        } else {
            crate::metrics::record_read_routing_decision(replica_label);
            &self.db_readonly
        }
    }
}

/// A9 (BSV-F21) — the lag circuit-breaker decision, split out of `AppState` so
/// it is testable without pools. Fall back to the primary when the cached
/// watermark is **stale** (a failed poll keeps the last value, so its lag is
/// unknown), or when its measured lag exceeds `max_lag_secs`. No watermark at
/// all is not a fallback here: a pinned read's fail-closed decision is
/// `replica_caught_up_to`'s job, and an unpinned read with no watermark has
/// nothing to be stale against.
fn should_fall_back_to_primary(
    max_lag_secs: Option<u64>,
    watermark: Option<&ReplicaWatermark>,
) -> bool {
    match watermark {
        Some(watermark) if watermark.is_stale() => true,
        Some(watermark) => max_lag_secs.is_some_and(|max| watermark.lag_seconds > max as f64),
        None => false,
    }
}
/// True when at least a minute has passed since the warning recorded in
/// `last`, and claims the slot for this caller. Concurrent callers race on
/// one compare-exchange, so a burst still logs once.
fn warning_due(last: &std::sync::atomic::AtomicI64, now_secs: i64) -> bool {
    use std::sync::atomic::Ordering;
    let previous = last.load(Ordering::Relaxed);
    now_secs.saturating_sub(previous) >= 60
        && last
            .compare_exchange(previous, now_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

// FromRef<AppState> for AppState is provided by Axum's blanket impl<T: Clone> FromRef<T> for T.

/// D-344 — lets `capability::Available<C>` cost one `Arc` bump instead of a
/// whole `AppState` clone on every gated request. The mirror impl for
/// `XrmState` lives in `xrm-foundation` (orphan rule: that crate owns the
/// type).
impl axum::extract::FromRef<AppState> for CapabilityStatuses {
    fn from_ref(state: &AppState) -> Self {
        CapabilityStatuses::new(Arc::clone(&state.capabilities))
    }
}

/// S3 (BSV-F15) — the future `AppState::shutdown_signal` hands out, split out
/// so its two properties (never resolves before the flip; always resolves once
/// it has flipped, whether the waiter was created before or after) are testable
/// without building a whole `AppState`. `watch` rather than `Notify` because a
/// late subscriber must see the already-flipped value instead of waiting for a
/// notification it missed.
fn shutdown_signal_from(
    tx: &tokio::sync::watch::Sender<bool>,
) -> impl std::future::Future<Output = ()> + Send + 'static {
    let mut rx = tx.subscribe();
    async move {
        let _ = rx.wait_for(|draining| *draining).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{ReplicaWatermark, should_fall_back_to_primary, shutdown_signal_from, warning_due};
    use std::sync::atomic::AtomicI64;

    #[test]
    fn the_first_warning_is_always_due() {
        assert!(warning_due(&AtomicI64::new(i64::MIN), 1_000));
    }

    #[test]
    fn a_repeat_warning_within_a_minute_is_suppressed() {
        let last = AtomicI64::new(i64::MIN);
        assert!(warning_due(&last, 1_000));
        assert!(!warning_due(&last, 1_000));
        assert!(!warning_due(&last, 1_059));
        assert!(warning_due(&last, 1_060));
        assert!(!warning_due(&last, 1_061));
    }

    /// S3 (BSV-F15) — a stream owner's signal must never resolve while the node
    /// is serving, and must resolve once the drain flips, whether the waiter
    /// was created before or after that flip.
    #[tokio::test]
    async fn shutdown_signal_resolves_when_draining_flips() {
        use std::time::Duration;

        let (tx, _rx) = tokio::sync::watch::channel(false);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), shutdown_signal_from(&tx))
                .await
                .is_err(),
            "shutdown_signal must not resolve before the drain flips"
        );

        let waiter = shutdown_signal_from(&tx);
        let flipper = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = flipper.send(true);
        });
        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("a signal created before the flip must resolve when it flips");

        tokio::time::timeout(Duration::from_millis(50), shutdown_signal_from(&tx))
            .await
            .expect("a signal created after the flip must resolve immediately");
    }

    /// A9 (BSV-F21) — a watermark whose poll is older than its freshness bound
    /// is unknown, and unknown lag must route to the primary rather than trust
    /// the stale `lag_seconds`.
    #[test]
    fn a_stale_watermark_trips_the_lag_breaker() {
        use std::time::{Duration, Instant};

        let at = |lag_seconds: f64, age: Duration| ReplicaWatermark {
            replay_lsn: "0/16B6C50".to_owned(),
            lag_seconds,
            polled_at: Instant::now() - age,
            stale_after: Duration::from_secs(3),
        };

        assert!(!should_fall_back_to_primary(
            None,
            Some(&at(0.0, Duration::ZERO))
        ));
        assert!(
            should_fall_back_to_primary(None, Some(&at(0.0, Duration::from_secs(10)))),
            "a stale watermark has unknown lag and must fall back to the primary"
        );
        assert!(should_fall_back_to_primary(
            Some(5),
            Some(&at(9.0, Duration::ZERO))
        ));
        assert!(!should_fall_back_to_primary(
            Some(5),
            Some(&at(1.0, Duration::ZERO))
        ));
        assert!(!should_fall_back_to_primary(None, None));
    }
}
