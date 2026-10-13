//! P1.13 stage 2 — the async audit-chain process (D-024).
//!
//! A standalone OS process, deliberately separate from the `server` binary:
//! it can be restarted, scaled, or paused independently, and a bug here can
//! never add latency to a request. It has no HTTP surface and no knowledge
//! of XRM entities/metadata/license — only the DB pool, the audit signer,
//! and `attome_audit::chainer`, which does the actual work (see that module's
//! doc comment for the xmin-watermark drain and Merkle-batch-signing
//! design).
//!
//! Operationally, it assumes the `server` binary has already applied
//! migrations (this process never runs `run_migrations` itself — one
//! process owns schema, per the migrations skill) — start `server` first,
//! or at least once, in every environment before this process.
//!
//! ```powershell
//! $env:APP_ENV = "debug"; cargo run --manifest-path crates/server/Cargo.toml --bin audit_chainer
//! ```
//!
//! ## This process is required in production (D-316)
//!
//! `audit.chainer_enabled` now defaults to true and
//! `validate_production_profile` refuses to boot a `production` deployment
//! without it, so this process is no longer optional: with the cutover active
//! it is the **only** writer of `audit_header`. If it is not running,
//! events are still durably captured in `audit_ingest` (nothing is lost)
//! but nothing chains them — the lag gauge climbs, `AuditChainerLagHigh` fires,
//! and once the backlog crosses `audit.ingest_backlog_threshold` the server's
//! mutation gate starts answering 503 rather than let it grow unbounded. It
//! ships in the runtime image and runs as docker-compose.yml's `audit_chainer`
//! service.
//!
//! ## The one combination this refuses to start against
//!
//! Found by actually running this against a live Postgres, back when stage 4
//! did not exist: `audit.ingest_capture_enabled = true` with
//! `audit.chainer_enabled = false` is stage 1's *purely additive* shadow mode —
//! `AuditService::write` writes the synchronous `audit_header`/`detail`/
//! `snapshot` rows **and** an ingest row. Draining those same ingest rows here
//! produces a **second** header row per event, not a duplicate-safe no-op, so
//! `main` below rejects that pair outright instead of warning about it.
//!
//! `chainer_enabled = false` with ingest capture also off is deliberately still
//! allowed, and is not the same thing: that is the documented rollback path —
//! flip the cutover off, then run this once more to drain whatever was captured
//! while it was on. New events go to the sync path only, so there is nothing to
//! double-write.

use attome_config::AppConfig;
use attome_core::AuditSigner;

/// Poll cadence and per-batch cap for the chainer loop below — never varied
/// per-deployment (dev/prod/test all ran the same values), not config knobs.
const CHAIN_POLL_INTERVAL_MS: u64 = 500;
const CHAIN_BATCH_SIZE: i64 = 500;
/// Retention-pruning tick — much coarser than the poll cadence above; a bulk
/// `DELETE` has no business running every poll. Never varied per-deployment.
const PRUNE_INTERVAL_SECS: u64 = 3600;

#[tokio::main]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let config = AppConfig::from_file()?;
    config.validate()?;
    // BCF-10 — one WARN per unknown config key, never a boot failure (BCF-D4).
    attome::boot::report_ignored_config_keys(&config, false)?;
    tracing::info!(
        poll_interval_ms = CHAIN_POLL_INTERVAL_MS,
        batch_size = CHAIN_BATCH_SIZE,
        "starting audit chainer",
    );

    // See this file's module doc ("The one combination this refuses to start
    // against"). A hard exit, not a warning: the damage is a permanently
    // duplicated audit chain, and the previous warning was easy to miss in a
    // supervised process's log stream — this binary is now started by an
    // orchestrator (docker-compose.yml's `audit_chainer` service), which
    // surfaces a non-zero exit and a restart loop where it would silently
    // ride past a `warn!`.
    if config.audit.ingest_capture_enabled && !config.audit.chainer_enabled {
        return Err(
            "refusing to start: audit.ingest_capture_enabled = true with \
             audit.chainer_enabled = false is stage 1's additive shadow mode — the synchronous \
             write path is writing its own audit_header row for every event, so draining \
             the same ingest rows here would write a SECOND header row per event. Set \
             audit.chainer_enabled = true (the default, and required under \
             app.deployment_profile = \"production\") to run the cutover path, or set \
             audit.ingest_capture_enabled = false to run this as a one-off drain before \
             disabling the cutover."
                .into(),
        );
    }

    if !config.audit.chainer_enabled {
        tracing::warn!(
            "audit.chainer_enabled is false — the synchronous write path owns new events. \
             Running as a drain-only pass over whatever audit_ingest rows were captured \
             while the cutover was on; stop this process once the lag gauge reaches zero.",
        );
    }

    let db = attome_db::create_pool(&config).await?;
    // BDB-F10 / OD-6: this process builds a pool without `boot::init`, so the
    // identity check `init` runs is not implied here. A chainer pointed at the
    // wrong database or role would otherwise report success against data it
    // does not own.
    let (expected_user, expected_dbname) = attome::boot::expected_runtime_identity(&config);
    attome_db::verify_pool_identity(&db, expected_user, expected_dbname).await?;
    tracing::info!("postgres pool connected");

    // P-audit-chain-hardening item (b) — external anchoring. `None` (the
    // default) skips this entirely: `chainer::run_batch_for_org` never
    // calls out to any store when `storage` is `None`, so a deployment that
    // hasn't opted in behaves byte-identically to before this flag existed.
    // Construction only (`create_storage_client_for` never dials the
    // endpoint, same as `attome-storage`'s own test doc explains) — a genuinely
    // unreachable/misconfigured store surfaces later as a per-batch
    // anchoring failure (logged, alertable), not a boot error, matching the
    // module's degrade-not-fail design.
    //
    // D-352: which bucket/credential this resolves to is
    // `anchor::create_anchor_store`'s call, not this bin's — the dedicated
    // append-only `audit.anchor_store` when configured (required in
    // production), the general storage bucket otherwise.
    let storage = if config.audit.external_anchoring_enabled {
        Some(attome_audit::anchor::create_anchor_store(&config).await?)
    } else {
        None
    };

    // Same construction as `EngineState::new` (attome-core/src/state.rs) —
    // duplicated rather than shared because this process never builds an
    // EngineState (no metadata registry, no license, no HTTP routes to serve).
    let signer = if config.audit.signing_enabled {
        Some(AuditSigner::from_config(
            &config.audit.signing_key_id,
            &config.audit.signing_private_key,
        )?)
    } else {
        None
    };

    let poll_interval = std::time::Duration::from_millis(CHAIN_POLL_INTERVAL_MS);
    let mut shutdown = shutdown_signal();

    // P1.13 step 6: retention pruning gets its own, much coarser cadence —
    // `None` when `ingest_retention_days == 0` (pruning disabled), since
    // `tokio::time::interval` panics on a zero period and a disabled feature
    // shouldn't need a fake duration to avoid that.
    let mut prune_ticker = (config.audit.ingest_retention_days > 0)
        .then(|| tokio::time::interval(std::time::Duration::from_secs(PRUNE_INTERVAL_SECS)));

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("shutdown signal received, exiting after current poll");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                match attome_audit::chainer::run_once(
                    &db,
                    signer.as_ref(),
                    CHAIN_BATCH_SIZE,
                    storage.as_ref(),
                )
                .await
                {
                    Ok(batches) if batches.is_empty() => {}
                    Ok(batches) => tracing::info!(count = batches.len(), "chain batches written"),
                    Err(e) => tracing::error!(error = %e, "audit chainer poll failed"),
                }

                log_lag(&db).await;
            }
            _ = tick_optional(&mut prune_ticker) => {
                // Audit plan item 2.8: only signed batches whose root is
                // anchored in `storage` are pruned, so without an anchor
                // store this deletes nothing.
                match attome_audit::chainer::prune_ingest(
                    &db,
                    storage.as_ref(),
                    config.audit.ingest_retention_days,
                )
                .await
                {
                    Ok(0) => {}
                    Ok(deleted) => tracing::info!(deleted, "audit ingest retention prune"),
                    Err(e) => tracing::error!(error = %e, "audit ingest retention prune failed"),
                }
            }
        }
    }

    Ok(())
}

/// Awaits the next tick of `ticker` if present, or never resolves if `None`
/// — lets `tokio::select!` treat a disabled ticker as a branch that simply
/// never fires, instead of needing a sentinel duration.
async fn tick_optional(ticker: &mut Option<tokio::time::Interval>) {
    match ticker {
        Some(t) => {
            t.tick().await;
        }
        None => std::future::pending::<()>().await,
    }
}

/// Makes chain lag observable (P1.13 stage 3 DoD) — logs the current
/// backlog/age per organization that has unchained `audit_ingest`
/// rows. An org fully caught up simply doesn't appear here each cycle,
/// which is the expected steady state, not a gap.
async fn log_lag(db: &attome_db::DbPool) {
    let orgs = match attome_audit::chainer::pending_organizations(db).await {
        Ok(orgs) => orgs,
        Err(e) => {
            tracing::warn!(error = %e, "audit chainer: could not list pending organizations for lag check");
            return;
        }
    };

    for org in orgs {
        match attome_audit::verify::lag(db, org).await {
            Ok((pending, Some(lag_seconds))) => {
                tracing::info!(organization_ref = %org, pending, lag_seconds, "audit chain lag");
            }
            Ok((_, None)) => {}
            Err(e) => {
                tracing::warn!(organization_ref = %org, error = %e, "audit chainer: lag check failed")
            }
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
fn shutdown_signal() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to install CTRL+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }
    })
}
