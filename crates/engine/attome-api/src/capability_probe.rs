//! D-344 (amends D-167) — the durability-capability gate's only writer.
//!
//! `attome_server::capability` owns the registry, the state machine and the
//! `Available<C>` extractor, and has zero `xrm-*` dependencies (guidelines
//! §1). This file owns the other half: what it actually *means* to probe each
//! capability. Same split, and the same reasoning, as
//! `attome_server::middleware::mutation_gate` (the flag and the gate) versus
//! `crate::metrics::spawn_ingest_backlog_refresh` (the thing that knows what
//! "backlog" means) — which is also why this lives in a `spawn_*_refresh`
//! loop of exactly that shape.
//!
//! Every probe here is the *same typed function* `/health/dependencies`
//! already calls (`attome_storage::health_check`, `attome_email::health_check`,
//! `attome_jobs::worker_last_seen_age_seconds` — the D-165/D-166
//! resource-owning-crate precedent), never a second implementation. A gate
//! that could disagree with the diagnostic endpoint about whether the object
//! store is up would be worse than no gate: the operator would be reading a
//! green endpoint while customers get 503s.
//!
//! # What this task must never do
//!
//! Touch readiness. `/health/ready` stays exactly as D-167 specifies — a live
//! `SELECT 1`, a live Redis ping, the registry pre-warm, the schema-version
//! floor, and nothing else. A down relay still must not evict a healthy,
//! DB-serving node from load-balancer rotation. This task's entire output is
//! `AppState::capabilities`, whose only readers are the `Available<C>`
//! extractor on a handful of routes and `/health/dependencies`'s reporting.

use std::time::Duration;

use attome_core::EngineState;
use attome_server::capability::{Capability, CapabilityState, ProbeOutcome};

/// Starts the probe loop. Called once from `main.rs`, unconditionally of
/// `observability.metrics_port` — like `spawn_ingest_backlog_refresh` and
/// unlike the rest of the `spawn_*_refresh` family, this drives a correctness
/// decision, not a dashboard.
///
/// A deployment with `capability.probe_enabled = false` never calls this, so
/// every capability stays `Unknown` and every gated route admits — byte
/// identical to the behavior before D-344.
pub fn spawn_capability_refresh(state: EngineState) {
    let cfg = state.base.config.capability.clone();
    state
        .base
        .capabilities
        .set_enforced(cfg.enforcement_enabled);

    let interval = Duration::from_secs(cfg.probe_interval_secs.max(1));
    let worker_stale_after = cfg.worker_stale_after_secs as f64;

    tracing::info!(
        interval_secs = cfg.probe_interval_secs,
        failure_threshold = cfg.failure_threshold,
        worker_stale_after_secs = cfg.worker_stale_after_secs,
        enforcement_enabled = cfg.enforcement_enabled,
        "capability probe started — route-level durability gating is {} \
         (/health/ready is deliberately unaffected, D-167)",
        if cfg.enforcement_enabled {
            "ENFORCING"
        } else {
            "report-only"
        },
    );

    tokio::spawn(async move {
        loop {
            probe_once(&state, worker_stale_after).await;
            tokio::time::sleep(interval).await;
        }
    });
}

/// One probe round. Split out from the loop so the transition logging and the
/// per-capability probe mapping are readable in one screen, and so a future
/// test with live infrastructure can drive a single round deterministically
/// rather than racing a timer.
async fn probe_once(state: &EngineState, worker_stale_after: f64) {
    // Concurrent, not sequential: four independent network/database round
    // trips, each already bounded by its own 2s timeout (D-167). Serially
    // this round could take 8s of the interval; together it takes the slowest
    // one.
    let (storage, email, fast, batch) = tokio::join!(
        attome_storage::health_check(&state.base.storage),
        // BEM-6/D-344: this is the enforcing gate, so it uses the bounded
        // probe rather than the unbounded default.
        attome_email::health_check_with_timeout(
            &state.base.config.email,
            attome_email::CAPABILITY_PROBE_TIMEOUT,
        ),
        attome_jobs::worker_last_seen_age_seconds(&state.base.db, false),
        attome_jobs::worker_last_seen_age_seconds(&state.base.db, true),
    );

    record(
        state,
        Capability::ObjectStorage,
        if storage.reachable {
            ProbeOutcome::Reachable
        } else {
            ProbeOutcome::Unreachable
        },
        storage.error.as_deref(),
    );

    // `enabled: false` is a deliberate deployment choice, not an outage
    // (D-029, and the same `None`-means-unknown convention D-167 established
    // for this exact struct) — it reports `Disabled`, which admits, so a
    // mail-less deployment behaves exactly as it always has.
    let email_outcome = if !email.enabled {
        ProbeOutcome::Disabled
    } else {
        match email.reachable {
            Some(true) => ProbeOutcome::Reachable,
            Some(false) => ProbeOutcome::Unreachable,
            // Enabled but never attempted — not a shape `health_check`
            // produces today. Claiming either "up" or "down" from it would be
            // a fabricated reading.
            None => ProbeOutcome::Indeterminate,
        }
    };
    record(
        state,
        Capability::Email,
        email_outcome,
        email.error.as_deref(),
    );

    record(
        state,
        Capability::FastJobs,
        worker_outcome(&fast, worker_stale_after),
        None,
    );
    record(
        state,
        Capability::BatchJobs,
        worker_outcome(&batch, worker_stale_after),
        None,
    );
}

/// Maps a queue's worker heartbeat age onto a probe outcome.
///
/// Three distinct readings that must not be collapsed:
///
/// - `Ok(Some(age))` — a worker of this queue has registered at least once.
///   Fresh enough is `Reachable`; staler than `worker_stale_after_secs` is a
///   real failure, the same signal (and the same threshold) the
///   `ApalisWorkerStale` alert already fires on.
/// - `Ok(None)` — `MAX(last_seen)` over an empty set: **no worker of this
///   queue has ever registered**. That is `Indeterminate`, not `Unreachable`.
///   A single-process deployment that has only just booted, or one that runs
///   the worker `Monitor` in a separate container that starts a moment later,
///   would otherwise reject bulk imports for its first minute on the strength
///   of a row that does not exist yet. `observability/alerts.yml` splits the
///   same case out for the same reason (see its `ApalisWorkerStale` comment
///   about no time series existing until the first heartbeat).
/// - `Err(_)` — the query itself failed, which says nothing about the worker.
fn worker_outcome(age: &Result<Option<f64>, sqlx::Error>, stale_after: f64) -> ProbeOutcome {
    match age {
        Ok(Some(seconds)) if *seconds <= stale_after => ProbeOutcome::Reachable,
        Ok(Some(_)) => ProbeOutcome::Unreachable,
        Ok(None) => ProbeOutcome::Indeterminate,
        Err(_) => ProbeOutcome::Indeterminate,
    }
}

/// Folds one outcome into the registry and logs only the *transitions* — a
/// probe loop that logged every round would emit ~2,900 lines a day per node
/// saying nothing changed, which is how a real transition gets missed.
fn record(state: &EngineState, capability: Capability, outcome: ProbeOutcome, error: Option<&str>) {
    let before = state.base.capabilities.state(capability);
    let after = state.base.capabilities.record(capability, outcome);
    if before == after {
        return;
    }

    match after {
        CapabilityState::Unavailable => tracing::error!(
            capability = capability.as_str(),
            error = error.unwrap_or("no error detail reported by the probe"),
            enforcing = state.base.capabilities.is_enforced(),
            "capability UNAVAILABLE — operations that cannot durably complete without it \
             will be refused with 503 capability_unavailable while this lasts; this node's \
             readiness and all other traffic are deliberately unaffected (D-167/D-344)",
        ),
        CapabilityState::Available => tracing::info!(
            capability = capability.as_str(),
            previous = ?before,
            "capability available",
        ),
        CapabilityState::Disabled => tracing::info!(
            capability = capability.as_str(),
            "capability disabled in configuration — not probed, and never gated",
        ),
        CapabilityState::Unknown => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole reason this helper exists rather than an inline `>` on the
    /// age: two of the four cases must NOT become `Unreachable`.
    #[test]
    fn a_fresh_heartbeat_is_reachable() {
        assert_eq!(
            worker_outcome(&Ok(Some(5.0)), 90.0),
            ProbeOutcome::Reachable
        );
        assert_eq!(
            worker_outcome(&Ok(Some(90.0)), 90.0),
            ProbeOutcome::Reachable,
            "exactly at the threshold is not yet stale"
        );
    }

    #[test]
    fn a_stale_heartbeat_is_a_real_failure() {
        assert_eq!(
            worker_outcome(&Ok(Some(90.001)), 90.0),
            ProbeOutcome::Unreachable
        );
    }

    /// A worker that has never registered is a cold start, not an outage —
    /// otherwise a fresh node rejects every bulk import until the worker
    /// container's first heartbeat lands.
    #[test]
    fn a_queue_no_worker_ever_registered_for_is_indeterminate_not_down() {
        assert_eq!(worker_outcome(&Ok(None), 90.0), ProbeOutcome::Indeterminate);
    }

    #[test]
    fn a_failed_query_says_nothing_about_the_worker() {
        assert_eq!(
            worker_outcome(&Err(sqlx::Error::RowNotFound), 90.0),
            ProbeOutcome::Indeterminate
        );
    }
}
