#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]
use attome::auth;
use attome::jobs::MigratorDb;

use apalis::prelude::{Monitor, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome_config::AppConfig;
use std::net::SocketAddr;

// `async_main` below is one large `async fn` whose sequential `.await?` chain
// (boot, scheduler spawns, router build) makes rustc's generated Future state
// machine hold every intermediate local live across every await point —
// unoptimized in a debug build, that alone can exceed the OS default main-
// thread stack well before any real recursion (observed: STATUS_STACK_OVERFLOW
// on Windows/MinGW's small default reserve, tipped over by one more
// provisioning call added to `attome-api`'s already-long boot chain). Running
// it on a dedicated thread with a much larger stack is the standard fix for
// this class of problem — shrinking the function is not a small change given
// its size, and every additional await point anywhere in the boot chain would
// only reopen the same margin.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    // `Box<dyn std::error::Error>` isn't `Send`, so it can't cross the
    // `thread::spawn` boundary as-is — carry the message across as a `String`
    // and re-box it back on this side.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build tokio runtime")
                .block_on(async_main())
                .map_err(|e| e.to_string())
        })
        .expect("failed to spawn main thread")
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
        .map_err(Into::into)
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    // AB7-T8: the deploy history's `start` row runs from here to ready.
    let process_started = chrono::Utc::now();
    // P-api-contract Phase 0/1: `server --print-openapi` is a one-shot mode,
    // checked before logging/config/anything else boots — printing the
    // generated OpenAPI document (`attome::openapi::document`, now every
    // mounted route across base/xrm/this crate) is pure in-process schema
    // generation, no DB/config file/listener needed. This is what lets
    // Angular's `openapi-typescript` codegen step (angular/'s `generate:api`
    // npm script) and CI's drift check run without a live authenticated
    // server, unlike fetching `/api/v1/openapi.json` over HTTP (which
    // deliberately stays behind auth, guidelines §7 / P-api-contract §4 — no
    // public-SDK consumer justifies bypass-listing it today).
    if print_openapi_flag() {
        let document = attome::openapi::document();
        println!(
            "{}",
            serde_json::to_string_pretty(&document)
                .map_err(|e| format!("failed to serialize OpenAPI document: {e}"))?
        );
        return Ok(());
    }

    // P-observability-completion: `config.validate()` (right below) is what
    // actually enforces `otlp_endpoint` is set whenever
    // `observability.enable_distributed_tracing = true` — but `init_tracing`
    // needs to run before ANY `tracing::info!`/`tracing::error!` call so
    // those aren't silently dropped on the floor by the un-initialized
    // default no-op subscriber. `AppConfig::from_file()` doesn't itself log
    // anything, so reading config before installing the subscriber (instead
    // of the previous ordering) is safe and lets `init_tracing` read
    // `config.observability` directly.
    let config = AppConfig::from_file()?;
    config.validate()?;
    // Z5-T3: the per-route policy table, from the same document the API
    // publishes; the body-limit layer reads it by matched route.
    let policy_table = attome_server::route_policy::RoutePolicyTable::from_document(
        &serde_json::to_value(&*attome::openapi::document())
            .map_err(|e| format!("failed to serialize OpenAPI document: {e}"))?,
        config.app.max_body_size_bytes,
    )
    .map_err(|e| format!("route policy table: {e}"))?;
    attome_server::route_policy::install(policy_table);
    let tracing_guard =
        attome::observability::init_tracing(&config.observability, env!("CARGO_PKG_VERSION"));
    // BCF-10 — one WARN per unknown config key (never a boot failure: an N-1
    // binary must still boot on an N config during a rollback, BCF-D4).
    attome::boot::report_ignored_config_keys(&config, false)?;
    tracing::info!(port = config.app.port, "starting attome server");

    // P-registration-gating (D-128): `server --bootstrap-admin <email>` is a
    // one-shot CLI mode, not the normal server boot — it runs schema
    // bootstrap + migrations itself (so it also works against a completely
    // empty database) and exits, never building the router/job worker/HTTP
    // listener below. This is what retires the old "self-register the first
    // admin, then set security.bootstrap_admin_email" procedure — which is now
    // the only way, that config key and its per-boot grant having been removed
    // outright. Works for a deployment that ships with
    // auth.registration_mode = "disabled"/"invite" from day one.
    if let Some(email) = bootstrap_admin_email_arg() {
        return run_bootstrap_admin(&config, &email).await;
    }

    // P-worker-process-split: the schema/migration gating, privilege-
    // separated pool checks, infrastructure clients, and full EngineSystem build
    // are shared with `bin/worker.rs` (see `attome::boot`'s module doc) so a
    // split deployment can never drift out of sync on anything security- or
    // correctness-relevant between the HTTP tier and the worker tier.
    let boot = attome::boot::init(&config).await?;
    // D-792 — the fleet console's gate (decided and logged in `boot::init`).
    #[cfg(feature = "fleet-console")]
    let fleet_console_open = boot.fleet_console_open;
    let jobs = boot.jobs;
    let system = boot.system;

    let base_state = system.state().base.clone();
    // F024: the job worker's `BulkEntityOperation` handler needs the full
    // `EngineState` (metadata registry, audit signer), not just `base_state` —
    // cloned before `system.core_routes()` below consumes `system`. Only
    // actually read below when `config.jobs.run_worker_inline` is true;
    // cheap (an `Arc`/pool-handle clone) to always take regardless.
    let attome_state = system.state().clone();
    // A second handle for the search-index drain arm, taken here because the
    // worker builders below consume `attome_state`.
    let drain_state = attome_state.clone();
    // P-license-enforcement-hardening Phase 5 (d): `auth::public_routes`
    // needs the live license handle for seat enforcement — cloned before
    // `system.core_routes()` below consumes `system`, same reasoning as
    // `attome_state` above.
    let license = system.state().modules.clone();
    let db = base_state.db.clone();
    let db_migrator = base_state.db_migrator.clone();

    // P-audit-chain-hardening item (e) — ingest circuit breaker. Deliberately
    // NOT gated by `config.jobs.run_worker_inline`: unlike the schedulers
    // below, this isn't job-queue processing — it updates
    // `base_state.audit_ingest_backlog_exceeded`, a per-node `Arc<AtomicBool>`
    // the mutation-gate middleware in THIS process reads on the request path
    // (same "not a cross-node source of truth" posture as `registry_ready`/
    // `replica_watermark`, guidelines §5). A split deployment's HTTP-serving
    // node still needs its own local copy of this running regardless of
    // where job processing lives, so it is spawned here unconditionally, not
    // folded into `spawn_chainer_lag_refresh`'s `metrics_port != 0` block
    // below either — this is a correctness/availability mechanism, not
    // observability, and must not go dark just because Prometheus scraping
    // is disabled.
    // P-audit-chain-hardening item (e) — internal poll cadence, never varied
    // per-deployment; not a config knob (unlike ingest_backlog_threshold
    // just below, which genuinely is).
    attome_api::spawn_ingest_backlog_refresh(
        base_state.clone(),
        std::time::Duration::from_secs(30),
        config.audit.ingest_backlog_threshold,
    );

    // AB5-T6: read-only mode, from the operator switch and the database-size
    // ceiling. Per node, like the backlog breaker above: the gate reads this
    // process's own flag.
    attome_api::spawn_read_only_refresh(attome_state.clone(), std::time::Duration::from_secs(15));

    // D-344 (amends D-167) — durability-capability probe. Same "correctness,
    // not observability" posture and the same per-node reasoning as the
    // ingest-backlog refresh directly above: it maintains
    // `base_state.capabilities`, which the `Available<C>` extractor in THIS
    // process reads on the request path, so an HTTP-serving node needs its
    // own copy regardless of where job processing happens.
    //
    // Note what this does NOT do: it never writes anything `/health/ready`
    // reads. D-167's node-eviction reasoning stands unchanged — a down SMTP
    // relay must not pull a healthy, DB-serving node out of rotation. This
    // refuses the individual operations that cannot durably complete
    // instead, on the handful of routes that name a capability.
    //
    // Skipped entirely when `capability.probe_enabled` is false, which
    // leaves every capability `Unknown` — the state that admits — i.e.
    // exactly the pre-D-344 behavior.
    if config.capability.probe_enabled {
        attome_api::spawn_capability_refresh(attome_state.clone());
    } else {
        tracing::info!(
            "capability.probe_enabled = false — no durability probe, and no route-level \
             capability gating (pre-D-344 behavior)",
        );
    }

    // D-195 / P-four-eyes-approval — same "correctness, not observability"
    // posture as the ingest-backlog refresh directly above: an expired
    // `approval_request` row left `pending` is a silent standing
    // approval opportunity, not just a stale gauge, so this runs
    // unconditionally rather than folded into a `metrics_port != 0` block.
    // Fixed hourly cadence — `approval.ttl_hours` defaults to 72h, so an
    // hour of slop in when expiry is noticed is immaterial.
    attome_api::spawn_approval_expiry_sweep(
        base_state.clone(),
        std::time::Duration::from_secs(3600),
    );

    // P-worker-process-split: `jobs.run_worker_inline` (default true, today's
    // behavior unchanged) gates the partition/upload-session maintenance
    // schedulers the same as it gates the `Monitor` further below — a split
    // deployment moves both to `bin/worker.rs` so the HTTP process spawns no
    // job-processing background loops at all. A duplicate scheduler tick
    // across replicas/processes is already safe (BJB-4a, D-618: the
    // `attome_jobs::schedule` ledger's row CAS lets one caller win each slot,
    // and the dedup key blocks overlap behind it) — this gate is about keeping background job-processing work out of the
    // HTTP tier's process, not about preventing a double-enqueue race.
    if config.jobs.run_worker_inline {
        attome::schedulers::spawn_worker_schedulers(&config, &base_state);
    }

    // ── Auth routes: register/login/google/logout/refresh — all public/bypass-
    // listed credential flows. Api-key account management lives in attome-security
    // now (Plan 1.6a) and is already part of `system.core_routes()` below.
    let auth_bundle = attome_server::RouteBundle::new(
        auth::public_routes(
            license,
            attome_audit::security::SecurityAuditor::from_state(system.state()),
        )
        .with_state(base_state.clone()),
    );
    // P-session-refresh-hardening (D-129): `GET /api/v1/auth/session` — NOT
    // bypass-listed, rides AuthnLayer like any other protected route. A
    // separate bundle purely for readability at this composition point; the
    // bypass list (not which bundle a route is attached to) is what actually
    // enforces the distinction (guidelines §3).
    let auth_protected_bundle = attome_server::RouteBundle::new(
        auth::protected_routes(attome_audit::security::SecurityAuditor::from_state(
            system.state(),
        ))
        .with_state(base_state.clone()),
    );
    // P-api-contract Phase 1: `GET /api/v1/openapi.json` moved out of
    // `attome-api` and up to this crate, because the assembled document now
    // spans layers only this crate can see (auth here, `attome-workflow` via
    // ModelRegistry). Its own bundle for the same readability reason as
    // `auth_protected_bundle` — it is not bypass-listed, so it rides the
    // normal AuthnLayer like every other protected route.
    let openapi_bundle =
        attome_server::RouteBundle::new(attome::openapi::routes().with_state(base_state.clone()));
    // M53 Phase 1 (Omnichannel, web chat only, D-474): the public web chat
    // widget endpoint. Bypass-listed (own manual license check), same shape
    // as `content_public.rs`/`service_public.rs` — but mounted here rather
    // than through `system.core_routes()` because it needs `attome-ai` and
    // `attome-integration` at once, neither of which `attome-api` can depend on
    // for real (see `attome::omnichannel`'s own module doc). Needs the full
    // `EngineState` (license/settings), not just `base_state` — `attome_state` was
    // cloned above before `system.core_routes()` consumed `system`.
    let omnichannel_bundle = attome_server::RouteBundle::new(
        attome::omnichannel::routes().with_state(attome_state.clone()),
    );

    // D-573/D-576 — web portal routes (`/{keyword}/api/v1/...`). An audience
    // bundle, not an ordinary one: portal users are not staff, so these routes
    // skip staff authn/authz/CSRF and authenticate with the portal's own
    // session (`attome_portal::router`). They still pass the pre-auth rate
    // limit, mutation gate and every outer layer.
    let portal_bundle =
        attome_server::RouteBundle::new(attome_portal::router::app(attome_state.clone()));

    // trd (Quantitative Trading) module: routes are registered through
    // `EngineModel`/`system.core_routes()` like every other engine (see
    // `crates/server/src/boot.rs`'s `.register(trd_engine::TrdModel)`),
    // not mounted ad hoc here. See document/TRADING-PLATFORM-PLAN.md.

    // ── Single composition point for the whole app (Plan 1.3 assembly fix;
    // compiler-enforced since D-047) ──────────────────────────────────────────
    // Every route EXCEPT liveness — XRM, auth, api-keys, readiness/version —
    // passes through the same stack, in request order (outermost first; the
    // source of truth is `attome_server::ServerBuilder::build` and
    // `attome_server::app`'s `apply_*` functions):
    //   SecurityHeaders → RequestId (sanitise, set, capture, error-body id)
    //   → Deprecation → Trace → Propagate → CORS → CatchPanic → BodyLimit
    //   → Timeout → Compression → [liveness branches off here]
    //   → AuthoringGate → MutationGate → PreAuthRateLimit → HostGate
    //   → s2s_authn → authn → CSRF → authz → RateLimit → Idempotency
    // Portal audience bundles skip s2s_authn and the staff authn…Idempotency
    // layers. The optional metrics and profiler layers below wrap all of it.
    // (MutationGate — P-audit-chain-hardening item (e) — only ever rejects a
    // mutating request while AppState::audit_ingest_backlog_exceeded is
    // true, which stays false unless spawn_ingest_backlog_refresh is
    // running; see attome_api::spawn_ingest_backlog_refresh below.)
    // `ServerBuilder::add_bundle` only accepts `RouteBundle`s — nothing merges
    // onto `app` after `.build()` returns, because `RouteBundle`'s inner
    // `Router` has no public accessor. Never construct routes here except
    // through a `RouteBundle` passed to `add_bundle`.
    //
    // `GET /health` and `/health/ready` are deliberate probe exceptions: mounted via
    // `with_liveness_routes` instead, so PreAuthRateLimit/MutationGate/s2s/
    // authn can never turn a Redis or DB blip into a fleet-wide liveness
    // failure/restart storm or mask readiness's dependency-specific 503. See `attome_server::liveness_routes` and
    // `ServerBuilder::with_liveness_routes` for the full rationale — `/health`
    // still passes through RequestId/Trace/CORS/Timeout/BodyLimit, none of
    // which depend on Redis/DB.
    let builder = attome_server::ServerBuilder::new(base_state.clone(), config.clone())
        .with_liveness_routes(attome_server::liveness_routes().with_state(base_state.clone()))
        .add_bundle(system.core_routes())
        .add_bundle(auth_bundle)
        .add_bundle(auth_protected_bundle)
        .add_bundle(openapi_bundle)
        .add_bundle(omnichannel_bundle)
        .with_web_root(web_root(&config));
    // D-792 (FLEET-CONSOLE-DESIGN.md §2.2, §3.1) — the fleet console's routes
    // are a bundle of their own, through the same middleware stack, and exist
    // only when the gate is open: otherwise `/api/v1/fleet/**` is an unknown
    // path like any other (a plain 404), not a 403 that names the feature.
    #[cfg(feature = "fleet-console")]
    let builder =
        match attome_fleet::mount(attome_fleet::Gate::from_open(fleet_console_open), || {
            attome_fleet::FleetState::new(attome_state.clone())
        })? {
            Some(router) => builder.add_bundle(attome_server::RouteBundle::new(router)),
            None => builder,
        };
    let mut app = builder
        .add_audience_bundle(portal_bundle)
        .build(|r| attome_api::apply_s2s_layer(r, base_state.clone()));
    // D-792 §7.2 — the Fleet sidebar group is contributed at serve time, only
    // with the gate open; nothing is ever stored in `sidebar`.
    #[cfg(feature = "fleet-console")]
    {
        if fleet_console_open {
            app = app.layer(axum::Extension(attome_fleet::sidebar::contributions()));
        }
    }

    // ── P-observability-bcdr Track A: `observability.metrics_port == 0` (every
    // existing config file's value today) disables all of this — no listener
    // bound, no layer applied, byte-identical behavior to before this feature.
    // The metrics HTTP layer wraps the whole app router (applied after
    // ServerBuilder::build returns, not inside it; only the optional profiler
    // layer below sits outside it) so the
    // request-duration/status histogram sees every response the server sends,
    // including early rejections (413 body-limit, 401 authn) that never reach
    // a handler — see attome_server::metrics for the rest of the design.
    // U4-T1: the built-in metrics store needs the recorder even with no
    // metrics port.
    let builtin_store = config
        .observability
        .builtin_store
        .unwrap_or(config.cache.backend == attome_config::CacheBackend::Memory);
    let metrics_server = if config.observability.metrics_port != 0 || builtin_store {
        let (metrics_layer, metrics_handle) = attome_server::build_layer_and_handle();
        app = app.layer(metrics_layer);
        if builtin_store {
            attome_server::metrics_store::spawn(
                base_state.db.clone(),
                base_state.db_migrator.clone(),
                metrics_handle.clone(),
                attome_server::metrics_store::node_name(config.app.port),
                env!("CARGO_PKG_VERSION"),
            );
            tracing::info!("metrics store: sampling every minute, kept 30 days");
            // AB10-T1: the built-in alert rules, evaluated on that store.
            attome_server::alerts::spawn(base_state.db.clone());
            // AB10-T2: and their delivery to the configured people.
            crate::alert_notify::spawn(base_state.db.clone(), config.clone());
        }

        attome_server::spawn_pool_gauge_refresh(
            base_state.clone(),
            std::time::Duration::from_secs(15),
        );
        // P-ha-failover-hardening item (e): only meaningful once a replica
        // pool actually exists — same "dark unless opted into" gate as
        // `database.readonly` itself (attome_db::create_readonly_pool falls
        // back to a clone of `db` with a loud startup warning otherwise, so
        // this check mirrors that same config flag rather than re-deriving
        // "is db_readonly actually distinct" at runtime).
        if config.database.readonly.is_some() {
            attome_server::spawn_replica_lag_refresh(
                base_state.clone(),
                std::time::Duration::from_secs(15),
            );
        }
        attome_api::spawn_chainer_lag_refresh(
            base_state.clone(),
            std::time::Duration::from_secs(15),
        );
        // P-file-upload-pipeline §8 (D-144): scan-queue backlog gauge, same
        // tier/interval as the chainer lag gauge above — unconditional like
        // it, since the upload-session pipeline is always mounted (unlike
        // the s2s telemetry gauge below, which is gated on a config flag).
        attome_api::spawn_upload_scan_backlog_refresh(
            base_state.clone(),
            std::time::Duration::from_secs(15),
        );
        // P-db-maintenance item (d): 60s, not 15s — bloat/vacuum state moves far
        // slower than pool/chainer gauges, no need to poll pg_stat_user_tables
        // that often.
        attome_api::spawn_partition_bloat_refresh(
            base_state.clone(),
            std::time::Duration::from_secs(60),
        );
        // P-job-system-hardening (b): access-log stream consumer-lag gauge —
        // only meaningful when the access log is actually being written.
        if config.s2s.access_log_enabled {
            attome_api::spawn_s2s_telemetry_lag_refresh(
                base_state.clone(),
                std::time::Duration::from_secs(15),
            );
        }

        if config.observability.metrics_port != 0 {
            let metrics_addr = format!(
                "{}:{}",
                config.app.server_host, config.observability.metrics_port
            );
            let metrics_listener = tokio::net::TcpListener::bind(&metrics_addr).await?;
            tracing::info!(addr = %metrics_addr, "metrics listening");
            Some(axum::serve(
                metrics_listener,
                attome_server::metrics_routes(metrics_handle),
            ))
        } else {
            None
        }
    } else {
        None
    };

    // ── attome-profiler: the Angular "Profiler" admin dashboard's write side.
    // `observability.profiler_enabled == false` (every existing config file's
    // value today) means no layer applied, no Redis writes — byte-identical
    // behavior, same "dark unless configured" posture as `metrics_port == 0`
    // above. Applied as its own outermost layer for the same reason
    // `metrics_layer` is: by this point the router's state has already been
    // consumed by `.with_state()` inside `EngineSystem::core_routes`, so there's
    // no `State<AppState>` left to extract — see
    // `attome_server::middleware::profiler`'s module doc. The general pool, never
    // the fail-closed coordination one (BPR-16).
    if config.observability.profiler_enabled {
        app = attome_server::apply_profiler_layer(app, base_state.redis.clone());
    }

    let addr = config.bind_addr();
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("listening on {addr}");

    // AB7-T8: the deploy history: a `start` row once ready, a `drain` row
    // from the shutdown signal to exit.
    let deploy_db = base_state.db.clone();
    let deploy_node = attome_server::metrics_store::node_name(config.app.port);
    let drain_row: std::sync::Arc<std::sync::OnceLock<uuid::Uuid>> = Default::default();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // BJB-5a: any of the four components ending (a crashed worker, a failed
    // listener) signals the others, so the process exits instead of serving
    // on with a dead job worker.
    let cascade_tx = shutdown_tx.clone();
    // S1 (BSV-F13 / BSV-D11) — how long readiness reads 503 before the
    // listeners stop accepting. The process-level deadline budget below is
    // extended by it, because the deadline now starts at SIGTERM (see
    // `term_tx`) rather than at the delayed shutdown signal.
    let drain_delay = config.shutdown_drain_delay();
    // Signalled at SIGTERM, before the drain delay, so the bounded graceful
    // shutdown deadline covers the whole post-signal budget (drain + in-flight
    // requests) instead of only the part after the delay.
    let (term_tx, term_rx) = tokio::sync::watch::channel(false);
    let draining = base_state.draining.clone();
    let drain_signal = base_state.drain_signal.clone();
    let (drain_db, drain_node, drain_row_set) =
        (deploy_db.clone(), deploy_node.clone(), drain_row.clone());
    tokio::spawn(async move {
        attome::boot::wait_for_shutdown_signal().await;
        let _ = term_tx.send(true);
        // AB7-T8: beside the drain, never in front of it.
        tokio::spawn(async move {
            if let Some(id) = attome_server::deploy_event::record_drain(
                &drain_db,
                &drain_node,
                env!("CARGO_PKG_VERSION"),
            )
            .await
            {
                let _ = drain_row_set.set(id);
            }
        });
        // S1 (BSV-F13): flip readiness to 503 and wake every
        // `AppState::shutdown_signal()` (long streams end instead of holding
        // the deadline open), then wait one LB probe interval x failure
        // threshold before closing `accept()` — otherwise the graceful
        // shutdown stops new connections in the same tick and the LB probe
        // (always a new connection) is refused rather than told not-ready.
        // `drain_delay == 0` restores the pre-S1 behaviour. `/health`
        // (liveness) is unaffected — see `AppState::draining`.
        attome::boot::begin_drain(draining, drain_signal, drain_delay, shutdown_tx).await;
    });

    let server_shutdown = shutdown_rx.clone();
    let metrics_shutdown = shutdown_rx.clone();
    let drain_shutdown = shutdown_rx.clone();
    // The deadline starts at SIGTERM, not at the (delayed) shutdown signal —
    // see `term_tx` above.
    let deadline_shutdown = term_rx;
    let worker_shutdown = shutdown_rx;
    // Never shorter than the request timeout itself, or an operator who
    // raised `app.request_timeout_secs` past the constant would have the
    // drain cut off requests the timeout layer was still willing to serve.
    // S1: plus the drain delay, so the budget is unchanged in effect — the
    // delay now elapses *inside* this window instead of in front of it.
    let shutdown_deadline = SHUTDOWN_DEADLINE.max(config.request_timeout()) + drain_delay;

    // U9-T1: every boot step is done; /health/startup now answers 200.
    base_state
        .started
        .store(true, std::sync::atomic::Ordering::Relaxed);
    tokio::spawn({
        let (db, node) = (deploy_db.clone(), deploy_node.clone());
        async move {
            attome_server::deploy_event::record_start(
                &db,
                &node,
                env!("CARGO_PKG_VERSION"),
                process_started,
            )
            .await;
        }
    });
    let server_fut = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(attome::boot::wait_for_shutdown(server_shutdown));
    // P-worker-process-split: `jobs.run_worker_inline` (default true, today's
    // behavior unchanged) gates whether this process builds/runs the apalis
    // `Monitor` at all. `false` means a split deployment's dedicated `worker`
    // binary (`crates/server/src/bin/worker.rs`) owns job processing instead
    // — this arm becomes a pure no-op that only waits on the shared shutdown
    // signal, the same shape `metrics_fut`'s `None` arm already uses below
    // when metrics are disabled, so `tokio::join!` always has four
    // same-shaped arms regardless of config.
    let worker_fut = async move {
        if config.jobs.run_worker_inline {
            // P1.4 / P-job-queue-hardening (D-165): two independently-polled
            // WorkerBuilders, one per queue, each its own concurrency budget —
            // a burst of batch work (BulkEntityOperation/ApplyStagedImport/
            // RewrapSecrets, each able to hold a worker slot for an extended
            // duration) can no longer consume the concurrency the fast,
            // latency-sensitive queue needs. Both still run inside this one
            // process/Monitor when run_worker_inline is true — that flag is
            // about process placement (P-worker-process-split), orthogonal to
            // this concurrency-budget isolation; the split-out `worker` binary
            // (`bin/worker.rs`) registers the same two builders.
            let mut jobs = jobs;
            attome::jobs::start_job_wakeup_listener(&config, &mut jobs).await;
            // AB7-T2: names unique to this process (see the worker binary).
            let fast_worker = attome_jobs::worker_name("platform-job-worker");
            let batch_worker = attome_jobs::worker_name("platform-job-batch-worker");
            let release_pool = db.clone();
            let monitor = Monitor::new()
                .register(
                    WorkerBuilder::new(&fast_worker)
                        .concurrency(config.jobs.worker_concurrency)
                        .enable_tracing()
                        .data(db.clone())
                        .data(MigratorDb(db_migrator.clone()))
                        .data(config.clone())
                        .data(attome_state.clone())
                        .backend(jobs.fast().clone())
                        .build_fn(attome::jobs::handle_platform_job),
                )
                .register(
                    WorkerBuilder::new(&batch_worker)
                        .concurrency(config.jobs.batch_worker_concurrency)
                        .enable_tracing()
                        .data(db)
                        .data(MigratorDb(db_migrator))
                        .data(config.clone())
                        .data(attome_state)
                        .backend(jobs.batch().clone())
                        .build_fn(attome::jobs::handle_platform_job),
                );
            let stopped = monitor
                .shutdown_timeout(std::time::Duration::from_secs(10))
                .run_with_signal(async move {
                    attome::boot::wait_for_shutdown(worker_shutdown).await;
                    Ok(())
                })
                .await;
            // AB7-T2: held jobs go back to the queue at once.
            attome_jobs::release_claimed_on_stop(
                &release_pool,
                &[fast_worker.as_str(), batch_worker.as_str()],
            )
            .await;
            stopped
        } else {
            attome::boot::wait_for_shutdown(worker_shutdown).await;
            Ok(())
        }
    };
    // Same shutdown-signal treatment as server_fut/worker_fut above; a no-op
    // future (just waits for the signal) when metrics_port == 0 so the join
    // below always has four same-shaped arms regardless of config.
    let metrics_fut = async move {
        match metrics_server {
            Some(metrics_server) => {
                metrics_server
                    .with_graceful_shutdown(attome::boot::wait_for_shutdown(metrics_shutdown))
                    .await
            }
            None => {
                attome::boot::wait_for_shutdown(metrics_shutdown).await;
                Ok(())
            }
        }
    };

    // The search index drain (P-search-and-retrieval §11.3). Every node runs
    // this arm; a `pg_try_advisory_xact_lock` inside each tick means exactly one
    // of them does the work and the rest skip immediately — see
    // `attome_search::scheduler`. Without it nothing is ever indexed and search is
    // a working feature over an empty table, which produces no error anywhere.
    let drain_fut = async move {
        attome_search::run_drain_loop(drain_state, attome::boot::wait_for_shutdown(drain_shutdown))
            .await;
    };

    // T4-5: the graceful shutdown is bounded. Once the signal has fired, an
    // in-flight request that never completes (a client holding a streaming
    // response open, a stuck upstream) must not keep the process alive
    // forever — the orchestrator would SIGKILL it anyway, but only after its
    // own (opaque) grace period, and with no log line saying why. The apalis
    // `Monitor` above already caps its own drain at 10 s, so this deadline
    // is really about the HTTP listeners.
    let deadline_fut = async move {
        attome::boot::wait_for_shutdown(deadline_shutdown).await;
        tokio::time::sleep(shutdown_deadline).await;
    };
    tokio::select! {
        (server_res, worker_res, metrics_res, ()) =
            async {
                tokio::join!(
                    attome::jobs::signal_shutdown_after(
                        cascade_tx.clone(),
                        std::future::IntoFuture::into_future(server_fut),
                    ),
                    attome::jobs::signal_shutdown_after(cascade_tx.clone(), worker_fut),
                    attome::jobs::signal_shutdown_after(cascade_tx.clone(), metrics_fut),
                    attome::jobs::signal_shutdown_after(cascade_tx, drain_fut),
                )
            } =>
        {
            server_res?;
            worker_res?;
            metrics_res?;
        }
        () = deadline_fut => {
            tracing::error!(
                deadline_secs = shutdown_deadline.as_secs(),
                "graceful shutdown deadline exceeded — exiting with in-flight work still pending"
            );
        }
    }

    // P-observability-completion: "flush spans during shutdown" — runs after
    // every listener has stopped accepting new work (graceful shutdown
    // already drained in-flight requests/jobs above), so this flush captures
    // whatever spans those in-flight operations produced rather than racing
    // them. A no-op when tracing was never enabled (`tracing_guard` holds no
    // provider) — see `TracingGuard::shutdown`'s doc comment for why a
    // stalled/unreachable collector must never fail process shutdown.
    // AB7-T8: failed requests during the drain are not counted yet.
    if let Some(id) = drain_row.get() {
        attome_server::deploy_event::finish_drain(&deploy_db, *id, None).await;
    }
    tracing_guard.shutdown();

    Ok(())
}

/// T4-5 — upper bound on how long `main` waits, after the shutdown signal,
/// for the HTTP listeners/worker/search drain to finish before giving up
/// and returning (which drops the runtime and ends the process). Floored at
/// `config.request_timeout()` at the use site (`app.request_timeout_secs`,
/// 30 s in `config.example.json`) so it can never cut off a request the
/// timeout layer would still allow. S1 (BSV-D11): `app.shutdown_drain_delay_secs`
/// is added to that floor at the use site, because the deadline now starts at
/// SIGTERM and the drain delay elapses inside it rather than in front of it;
/// the compose `stop_grace_period` must cover the whole sum plus a margin
/// (S2). Short enough to stay inside a typical orchestrator grace period once
/// the LB has already stopped sending traffic (`AppState::draining`).
const SHUTDOWN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// P-api-contract Phase 0: bare `--print-openapi` flag, same hand-rolled-argv
/// convention as `bootstrap_admin_email_arg` below (guidelines §0.5) — no
/// value to parse, just presence/absence.
fn print_openapi_flag() -> bool {
    std::env::args().skip(1).any(|arg| arg == "--print-openapi")
}

/// Parses `--bootstrap-admin <email>` / `--bootstrap-admin=<email>` out of the
/// process argv. Deliberately not `clap` or any other arg-parsing dependency
/// (guidelines §0.5 — three lines beat a premature abstraction) — this is the
/// one flag the binary understands outside its normal config-driven boot.
fn bootstrap_admin_email_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(email) = arg.strip_prefix("--bootstrap-admin=") {
            return Some(email.to_owned());
        }
        if arg == "--bootstrap-admin" {
            return args.next();
        }
    }
    None
}

/// P-registration-gating (D-128) — creates (or promotes) the first admin
/// account on a database where self-registration is closed, then exits.
/// Runs its own schema-bootstrap + migrations pass (same sequence `main`
/// itself runs, on the same kind of direct/non-pooled connection — P1.12)
/// so this also works as the very first command ever run against a fresh
/// database, not just as a follow-up to a normal boot.
///
/// Account lookup/creation itself is `attome_auth::accounts::bootstrap_admin`
/// (not raw SQL here) — this handler stays a thin parse -> call engine ->
/// respond shape (guidelines §0/§1): it owns argv parsing, the CLI-facing
/// messages, and granting `system.admin` once an account id exists, nothing
/// about how `user_account` rows get read or written.
///
/// A matching *active* `user_account` row is granted `system.admin`
/// in place (idempotent re-run, no new password) rather than erroring —
/// an operator re-running this command to add a second admin, or after a
/// typo'd first attempt, shouldn't have to special-case "already exists".
/// A matching *disabled* row is refused outright: bootstrap must never be
/// the tool that resurrects a disabled account (same posture as
/// `attome_auth::accounts::register`'s own disabled-email guard,
/// P-account-state-enforcement).
/// The built web app's directory: `app.web_root` when set, else `web` next
/// to the executable when it exists. `None` serves the API only.
fn web_root(config: &AppConfig) -> Option<std::path::PathBuf> {
    let root = match &config.app.web_root {
        Some(dir) => std::path::PathBuf::from(dir),
        None => std::env::current_exe().ok()?.parent()?.join("web"),
    };
    if root.join("index.html").is_file() {
        tracing::info!(root = %root.display(), "serving the web app");
        Some(root)
    } else {
        if config.app.web_root.is_some() {
            tracing::warn!(
                root = %root.display(),
                "app.web_root has no index.html; serving the API only"
            );
        }
        None
    }
}

pub(crate) async fn run_bootstrap_admin(
    config: &AppConfig,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let email = email.trim();
    if email.is_empty() {
        return Err("--bootstrap-admin requires a non-empty email argument".into());
    }

    // D-127 checksum baseline, direct pool, schema + migrations — the same
    // sequence `boot::init` and the `migrate` binary run.
    let migration_db = attome::boot::apply_schema_migrations(config).await?;

    // `--bootstrap-admin` creates an active principal through the same seat
    // gate as every other writer; D-778 makes that limit unbounded.
    let outcome = attome_api::bootstrap_admin_gated(&migration_db, email).await?;

    let user_id = match outcome {
        attome_auth::accounts::BootstrapOutcome::Disabled => {
            migration_db.close().await;
            return Err(format!(
                "'{email}' matches a DISABLED user_account row — refusing to \
                 resurrect it via bootstrap. Re-enable the account first \
                 (POST /api/v1/admin/security/users/{{id}}/enable from an existing \
                 admin session) if that's genuinely what you want, then re-run this."
            )
            .into());
        }
        attome_auth::accounts::BootstrapOutcome::AlreadyActive { user_id } => {
            println!(
                "'{email}' already has an active account (id={user_id}) — granting \
                 system.admin to it; no new password generated."
            );
            user_id
        }
        attome_auth::accounts::BootstrapOutcome::Created { user_id, password } => {
            println!("Created admin account for '{email}' (id={user_id}).");
            println!("ONE-TIME PASSWORD — shown once, never stored anywhere but its hash:");
            println!("  {password}");
            println!("Log in and change this password immediately.");
            user_id
        }
    };

    let privilege_id = attome_security::db::ensure_privilege(
        &migration_db,
        attome_security::context::ADMIN_PRIVILEGE_KEY,
        "System Admin",
        "Full administrative access to every gated route",
        attome_core::changeset::Layer::Platform,
    )
    .await?;
    attome_security::db::ensure_user_privilege_grant(&migration_db, user_id, privilege_id).await?;

    migration_db.close().await;
    println!("'{email}' now holds system.admin.");
    Ok(())
}
