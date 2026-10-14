//! P-worker-process-split — the job-worker-only counterpart to `main.rs`: no
//! HTTP listener, no router, no auth routes. Everything it needs (schema/
//! migration gating, privilege-separated pools, infrastructure clients, the
//! full `EngineSystem` build) comes from `attome::boot::init`, the exact same
//! function `main.rs` calls, so this binary can never drift out of sync with
//! the HTTP tier on anything security- or correctness-relevant.
//!
//! A deployment runs this instead of (not in addition to, ordinarily) the
//! inline worker built into `server`: set `jobs.run_worker_inline = false` in
//! the shared config so `server` never builds its own `Monitor` or spawns the
//! partition/upload-session maintenance schedulers, then run this binary as
//! its own process/container, scaled and deployed independently of the HTTP
//! tier. See `jobs.run_worker_inline`'s config doc and `document/DECISIONS.md`
//! for the reliability/blast-radius rationale.
//!
//! Same image as `server`/`migrate`/`audit_chainer` (same crate, same
//! Cargo.lock) — only the entrypoint/command differs in compose/k8s.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; cargo run --manifest-path crates/server/Cargo.toml --bin worker
//! ```
//!
//! `observability.worker_health_port` (default on, 9091 — see
//! `attome_config::ObservabilitySection`) binds this process's own
//! `/health`/`/health/ready`/`/version` listener, merging
//! `attome_server::health_routes` and `attome_server::liveness_routes` verbatim
//! (the exact same `health_ready` DB/Redis/registry check `main.rs` gates its
//! own readiness on, and the exact same always-200 liveness handler) so
//! compose/k8s gets a real readiness probe instead of the `pgrep`-only
//! liveness check this shipped with originally — see
//! `deploy/HEALTHCHECKS.md` for which probe should point at which route.
//! When `observability.metrics_port != 0` the same listener
//! also serves `/metrics` and runs `attome_server::spawn_pool_gauge_refresh`
//! (pool/redis/apalis-backlog gauges — the same function `main.rs` calls),
//! so a `worker-split` deployment gets its own per-replica Prometheus target
//! instead of only whatever `server`'s gauges happen to show.
use apalis::prelude::{Monitor, WorkerBuilder, WorkerBuilderExt, WorkerFactoryFn};
use attome::jobs::MigratorDb;
use attome_config::AppConfig;

#[tokio::main]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // P-observability-completion: same reasoning as `main.rs`'s identical
    // block — a split-deployment worker is exactly the process that needs
    // "extract context in workers" to have anything to extract *from* its
    // own exporter's perspective, so this binary gets the same
    // `init_tracing` wiring, not a second copy of the old bare-`fmt()` setup.
    let config = AppConfig::from_file()?;
    config.validate()?;
    if config.cache.backend == attome_config::CacheBackend::Memory {
        return Err("attome worker cannot run with cache.backend = \"memory\": the in-process store is private to the server process. Run the worker inline (jobs.run_worker_inline = true) or configure Redis."
            .into());
    }
    let tracing_guard =
        attome::observability::init_tracing(&config.observability, env!("CARGO_PKG_VERSION"));
    // BCF-10 — one WARN per unknown config key, never a boot failure (BCF-D4).
    attome::boot::report_ignored_config_keys(&config, false)?;
    tracing::info!("starting attome worker");

    let boot = attome::boot::init(&config).await?;
    let jobs = boot.jobs;
    let system = boot.system;

    let base_state = system.state().base.clone();
    // F024: `BulkEntityOperation`/`ApplyStagedImport`/`ScanUploadedFile`
    // handlers need the full `EngineState` (metadata registry, audit signer),
    // not just `base_state`.
    let attome_state = system.state().clone();
    let db = base_state.db.clone();
    let db_migrator = base_state.db_migrator.clone();

    // Unconditional — this binary IS the deployment's worker tier, so unlike
    // `main.rs` (which only spawns these when `jobs.run_worker_inline` is
    // true) there is no split to gate here. The same list `main.rs` uses —
    // see `attome::schedulers`' module doc (CLEANUP-REVIEW 5.17: this file
    // used to hand-copy it and missed two sweeps).
    attome::schedulers::spawn_worker_schedulers(&config, &base_state);

    // P1.4 + P-job-queue-hardening (D-165): same two independently-polled,
    // independently-concurrency-limited `WorkerBuilder`s `main.rs` registers
    // inline — see that binary's matching comment for why the split exists
    // (a burst of batch work must not starve the fast, latency-sensitive
    // queue). Kept in lockstep with `main.rs`'s registration by hand since
    // apalis's `Data<T>` extractor and per-queue `Monitor` wiring don't lend
    // themselves to a shared helper without more ceremony than the two calls
    // they'd replace.
    let mut jobs = jobs;
    attome::jobs::start_job_wakeup_listener(&config, &mut jobs).await;
    let monitor = Monitor::new()
        .register(
            WorkerBuilder::new("platform-job-worker")
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
            WorkerBuilder::new("platform-job-batch-worker")
                .concurrency(config.jobs.batch_worker_concurrency)
                .enable_tracing()
                .data(db)
                .data(MigratorDb(db_migrator))
                .data(config.clone())
                .data(attome_state)
                .backend(jobs.batch().clone())
                .build_fn(attome::jobs::handle_platform_job),
        );

    // `attome_server::health_routes`/`liveness_routes` are the exact same
    // `/health/ready`+`/version` and `/health` routers `main.rs` mounts on its
    // own app (the latter via `ServerBuilder::with_liveness_routes` there) —
    // `AppState: FromRef<AppState>` (axum's blanket identity impl) is what
    // lets them be instantiated directly against `AppState` instead of some
    // larger composed state type. This listener has no middleware at all
    // (bare `axum::serve`, no `ServerBuilder`/`apply_pre_auth_rate_limit` in
    // the mix), so merging both routers here doesn't reintroduce the
    // Redis-dependency issue `liveness_routes` exists to avoid on `main.rs`'s
    // side — it's just completeness: this listener must keep offering the
    // same three routes (`/health`, `/health/ready`, `/version`) it always
    // has.
    let mut health_router = attome_server::health_routes::<attome_server::AppState>()
        .merge(attome_server::liveness_routes::<attome_server::AppState>())
        .with_state(base_state.clone());

    // Same "dark unless configured" posture as main.rs's own metrics block:
    // `metrics_port == 0` (every existing config's value today) means none of
    // this runs — byte-identical behavior to before this was added. When
    // enabled, `/metrics` binds on its own listener (metrics_port), separate
    // from the always-on `/health*` listener (worker_health_port) below —
    // same two-listener split main.rs uses (app.port for health, metrics_port
    // for metrics), not one port serving double duty.
    let metrics_server = if config.observability.metrics_port != 0 {
        let (metrics_layer, metrics_handle) = attome_server::build_layer_and_handle();
        health_router = health_router.layer(metrics_layer);
        attome_server::spawn_pool_gauge_refresh(
            base_state.clone(),
            std::time::Duration::from_secs(15),
        );

        let metrics_addr = format!(
            "{}:{}",
            config.app.server_host, config.observability.metrics_port
        );
        let metrics_listener = tokio::net::TcpListener::bind(&metrics_addr).await?;
        tracing::info!(addr = %metrics_addr, "worker metrics listening");
        Some(axum::serve(
            metrics_listener,
            attome_server::metrics_routes(metrics_handle),
        ))
    } else {
        None
    };

    // Unlike metrics_port, this binds by default (see `default_worker_health_port`
    // on `ObservabilitySection`) — a worker readiness probe should exist out of
    // the box, not require opt-in. `0` still disables it for a deployment that
    // deliberately wants pgrep-only liveness back.
    let health_server = if config.observability.worker_health_port != 0 {
        let health_addr = format!(
            "{}:{}",
            config.app.server_host, config.observability.worker_health_port
        );
        let health_listener = tokio::net::TcpListener::bind(&health_addr).await?;
        tracing::info!(addr = %health_addr, "worker health listening");
        Some(axum::serve(health_listener, health_router))
    } else {
        None
    };

    tracing::info!("worker ready");
    // Same shutdown-signal fan-out main.rs uses across its three joined
    // futures (server/worker/metrics) — this process now has three of its
    // own (job monitor / health listener / metrics listener), so the single-
    // future `wait_for_shutdown_signal()` shortcut this used to rely on no
    // longer applies.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        attome::boot::wait_for_shutdown_signal().await;
        let _ = signal_tx.send(true);
    });
    let health_shutdown = shutdown_rx.clone();
    let metrics_shutdown = shutdown_rx.clone();
    let monitor_shutdown = shutdown_rx;

    let health_fut = async move {
        match health_server {
            Some(server) => {
                server
                    .with_graceful_shutdown(attome::boot::wait_for_shutdown(health_shutdown))
                    .await
            }
            None => {
                attome::boot::wait_for_shutdown(health_shutdown).await;
                Ok(())
            }
        }
    };
    let metrics_fut = async move {
        match metrics_server {
            Some(server) => {
                server
                    .with_graceful_shutdown(attome::boot::wait_for_shutdown(metrics_shutdown))
                    .await
            }
            None => {
                attome::boot::wait_for_shutdown(metrics_shutdown).await;
                Ok(())
            }
        }
    };
    let monitor_fut = monitor
        .shutdown_timeout(std::time::Duration::from_secs(10))
        .run_with_signal(async move {
            attome::boot::wait_for_shutdown(monitor_shutdown).await;
            Ok(())
        });

    // BJB-5b — whichever of the three ends first, for any reason, stops the
    // other two, so a dead monitor never leaves a worker answering healthy.
    let (monitor_res, health_res, metrics_res) = tokio::join!(
        attome::jobs::signal_shutdown_after(shutdown_tx.clone(), monitor_fut),
        attome::jobs::signal_shutdown_after(shutdown_tx.clone(), health_fut),
        attome::jobs::signal_shutdown_after(shutdown_tx, metrics_fut),
    );
    monitor_res?;
    health_res?;
    metrics_res?;

    // P-observability-completion: "flush spans during shutdown" — see
    // main.rs's identical call for why this runs last and never fails
    // process shutdown.
    tracing_guard.shutdown();

    Ok(())
}
