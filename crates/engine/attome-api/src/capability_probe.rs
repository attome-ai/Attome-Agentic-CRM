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
    // AB5-T8: the states before this round, to find what went down or came
    // back once every probe has been recorded.
    let before = Capability::ALL.map(|c| state.base.capabilities.state(c));
    probe_round(state, worker_stale_after).await;
    // AB6-T8: the breaker gauge, and an audit event per breaker change.
    let breakers = attome_outbound::registry::publish();
    for (name, from, to) in breaker_changes(&breakers) {
        audit_breaker_change(state, name, from, to).await;
    }
    let after = Capability::ALL.map(|c| state.base.capabilities.state(c));
    for (i, capability) in Capability::ALL.into_iter().enumerate() {
        if let Some(change) = period_change(before[i], after[i]) {
            record_period(&state.base.db, capability, change).await;
        }
    }
}

/// AB6-T8: the breaker states the previous round saw, by service name.
static LAST_BREAKERS: std::sync::Mutex<Vec<(&'static str, attome_outbound::BreakerState)>> =
    std::sync::Mutex::new(Vec::new());

fn state_name(state: attome_outbound::BreakerState) -> &'static str {
    match state {
        attome_outbound::BreakerState::Closed => "closed",
        attome_outbound::BreakerState::HalfOpen => "half_open",
        attome_outbound::BreakerState::Open => "open",
    }
}

/// Which services' breakers opened or closed since the last round. Half open
/// is a step on the way, not a change worth an event. A service first seen
/// open counts as opened.
fn breaker_changes(
    now: &[attome_outbound::registry::ServiceState],
) -> Vec<(&'static str, &'static str, &'static str)> {
    use attome_outbound::BreakerState::{Closed, Open};
    let mut last = LAST_BREAKERS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut changes = Vec::new();
    for s in now {
        let before = last
            .iter()
            .find(|(name, _)| *name == s.name)
            .map(|(_, state)| *state)
            .unwrap_or(Closed);
        let opened = s.state == Open && before != Open;
        let closed = s.state == Closed && before == Open;
        if opened || closed {
            changes.push((s.name, state_name(before), state_name(s.state)));
        }
        if s.state != attome_outbound::BreakerState::HalfOpen {
            match last.iter_mut().find(|(name, _)| *name == s.name) {
                Some(entry) => entry.1 = s.state,
                None => last.push((s.name, s.state)),
            }
        }
    }
    changes
}

/// AB6-T8: one Configuration audit event, attributed to the system (no
/// request, no user), when a dependency's breaker opens or closes. Best
/// effort: a failed write is logged and the probe carries on.
async fn audit_breaker_change(state: &EngineState, service: &'static str, from: &str, to: &str) {
    use attome_audit::security::{MandatoryCategory, SecurityAuditor, SecurityEvent};
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        attome_audit::AuditOperation::Update,
        uuid::Uuid::nil(),
        "outbound_service",
        None,
    )
    .named("dependency_breaker_changed")
    .attributed(attome_audit::initiator::Attribution {
        acting_user_id: uuid::Uuid::nil(),
        initiator: attome_audit::initiator::Initiator::System,
        agent_session_id: None,
        agent_action_id: None,
    })
    .comment(format!("{service} breaker {from} -> {to}"));
    let auditor = SecurityAuditor::from_state(state);
    let write = auditor.write(event);
    match tokio::time::timeout(PROBE_TIMEOUT, write).await {
        Ok(Ok(_)) => tracing::warn!(service, from, to, "outbound breaker changed"),
        Ok(Err(e)) => tracing::warn!(error = %e, service, "breaker change not audited"),
        Err(_) => tracing::warn!(service, "breaker change audit timed out"),
    }
}

/// AB5-T8: what a state change means for the degraded-period record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeriodChange {
    Open,
    Close,
}

fn period_change(before: CapabilityState, after: CapabilityState) -> Option<PeriodChange> {
    match (before, after) {
        (b, CapabilityState::Unavailable) if b != CapabilityState::Unavailable => {
            Some(PeriodChange::Open)
        }
        (CapabilityState::Unavailable, a) if a != CapabilityState::Unavailable => {
            Some(PeriodChange::Close)
        }
        _ => None,
    }
}

/// Opens or closes `capability`'s degraded period. At most one open period
/// per capability (a partial unique index), so two nodes seeing one outage
/// record it once. Bounded and best effort: a failure is logged, and the
/// probe carries on.
async fn record_period(db: &attome_db::DbPool, capability: Capability, change: PeriodChange) {
    let features: Vec<String> = capability
        .affected_features()
        .iter()
        .map(|f| (*f).to_owned())
        .collect();
    let write = async {
        match change {
            PeriodChange::Open => sqlx::query(
                "INSERT INTO degraded_period (capability, features) VALUES ($1, $2) \
                 ON CONFLICT (capability) WHERE ended_at IS NULL DO NOTHING",
            )
            .bind(capability.as_str())
            .bind(&features)
            .execute(db)
            .await
            .map(|_| ()),
            PeriodChange::Close => sqlx::query(
                "UPDATE degraded_period SET ended_at = now() \
                 WHERE capability = $1 AND ended_at IS NULL",
            )
            .bind(capability.as_str())
            .execute(db)
            .await
            .map(|_| ()),
        }
    };
    match tokio::time::timeout(PROBE_TIMEOUT, write).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(
            error = %e,
            capability = capability.as_str(),
            "degraded period not recorded"
        ),
        Err(_) => tracing::warn!(
            capability = capability.as_str(),
            "degraded period write timed out"
        ),
    }
}

/// AB5-T8: one degraded period, for the dependency report.
#[derive(Debug, Clone, serde::Serialize, sqlx::FromRow)]
pub struct DegradedPeriod {
    pub capability: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub features: Vec<String>,
    pub cause: Option<String>,
}

/// AB5-T8: the degraded periods that started in the last 90 days, newest
/// first, at most 500.
pub async fn degraded_history(db: &attome_db::DbPool) -> Result<Vec<DegradedPeriod>, sqlx::Error> {
    sqlx::query_as(
        "SELECT capability, started_at, ended_at, features, cause FROM degraded_period \
         WHERE started_at > now() - interval '90 days' \
         ORDER BY started_at DESC LIMIT 500",
    )
    .fetch_all(db)
    .await
}

async fn probe_round(state: &EngineState, worker_stale_after: f64) {
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

    // AB5-T1: the five report-and-degrade capabilities.
    let (cache, scanner, search, ai) = tokio::join!(
        tokio::time::timeout(PROBE_TIMEOUT, state.base.redis.ping()),
        probe_virus_scanner(state),
        probe_search_index(state),
        probe_ai_model(state),
    );
    record(
        state,
        Capability::Cache,
        match cache {
            Ok(true) => ProbeOutcome::Reachable,
            Ok(false) | Err(_) => ProbeOutcome::Unreachable,
        },
        None,
    );
    record(state, Capability::VirusScanner, scanner, None);
    record(state, Capability::SearchIndex, search, None);
    record(state, Capability::AiModel, ai, None);
    // No connector-wide probe exists yet; each connector reports its own
    // failures. Indeterminate keeps the capability `Unknown`, which admits.
    record(
        state,
        Capability::Connectors,
        ProbeOutcome::Indeterminate,
        None,
    );
}

/// Each AB5-T1 probe's bound, like the others' (D-167).
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// `attome_search::drain::CONSUMER`, the search drain's cursor name (a test
/// holds the two equal; this crate takes attome-search only for tests).
const SEARCH_DRAIN_CONSUMER: &str = "attome-search/index-drain";

/// The search drain counts as down once its oldest unread event is this old.
const SEARCH_LAG_DOWN_SECS: f64 = 600.0;

/// clamd answers, or scanning is switched off (`storage.clamd_address`
/// empty).
async fn probe_virus_scanner(state: &EngineState) -> ProbeOutcome {
    let address = state.base.config.storage.clamd_address.trim();
    if address.is_empty() {
        return ProbeOutcome::Disabled;
    }
    if attome_storage::clamav_health_check(address).await.reachable {
        ProbeOutcome::Reachable
    } else {
        ProbeOutcome::Unreachable
    }
}

/// The search index drain is keeping up: its change-feed cursor is less than
/// [`SEARCH_LAG_DOWN_SECS`] behind. Not registered yet says nothing.
async fn probe_search_index(state: &EngineState) -> ProbeOutcome {
    match attome_core::change_feed::consumer_health(&state.base.db).await {
        Ok(consumers) => search_outcome(&consumers),
        Err(_) => ProbeOutcome::Indeterminate,
    }
}

fn search_outcome(consumers: &[attome_core::change_feed::ConsumerHealth]) -> ProbeOutcome {
    match consumers
        .iter()
        .find(|c| c.consumer == SEARCH_DRAIN_CONSUMER)
    {
        Some(c) if c.status == "active" && c.lag_seconds < SEARCH_LAG_DOWN_SECS => {
            ProbeOutcome::Reachable
        }
        Some(_) => ProbeOutcome::Unreachable,
        None => ProbeOutcome::Indeterminate,
    }
}

/// The generation endpoint accepts a connection, or AI is switched off or
/// not configured.
async fn probe_ai_model(state: &EngineState) -> ProbeOutcome {
    let inference = &state.base.config.inference;
    let Some(target) = (inference.ai.enabled)
        .then(|| host_port(&inference.generation.base_url))
        .flatten()
    else {
        return ProbeOutcome::Disabled;
    };
    match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(target)).await {
        Ok(Ok(_)) => ProbeOutcome::Reachable,
        Ok(Err(_)) | Err(_) => ProbeOutcome::Unreachable,
    }
}

/// `host:port` of an `http(s)://host[:port]/...` URL, with the scheme's
/// default port; `None` for an empty or unusable URL.
fn host_port(url: &str) -> Option<String> {
    let url = url.trim();
    let (rest, default_port) = match url.strip_prefix("https://") {
        Some(rest) => (rest, 443),
        None => (url.strip_prefix("http://")?, 80),
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    if authority.is_empty() {
        return None;
    }
    let has_port = authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()))
        && !authority.ends_with(']');
    Some(if has_port {
        authority.to_owned()
    } else {
        format!("{authority}:{default_port}")
    })
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
/// AB6-T8: the outbound service whose breaker stands for `capability`.
fn breaker_service(capability: Capability) -> Option<&'static str> {
    match capability {
        Capability::AiModel => Some("ai_model"),
        Capability::ObjectStorage => Some("object_storage"),
        Capability::Email => Some("smtp"),
        _ => None,
    }
}

fn record(state: &EngineState, capability: Capability, outcome: ProbeOutcome, error: Option<&str>) {
    // AB6-T8: while the capability's outbound breaker is open, the probe
    // counts as failed even if this one request got through: real traffic
    // is failing.
    let breaker_open = breaker_service(capability)
        .and_then(attome_outbound::registry::state_of)
        .is_some_and(|s| s == attome_outbound::BreakerState::Open);
    let (outcome, error) = if breaker_open && outcome != ProbeOutcome::Disabled {
        (ProbeOutcome::Unreachable, Some("breaker_open"))
    } else {
        (outcome, error)
    };
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

    /// AB6-T8: an open and a close are each one change; a half-open step is
    /// none; the services map onto the capabilities they gate.
    #[test]
    fn breaker_opens_and_closes_are_changes() {
        use attome_outbound::BreakerState::{Closed, HalfOpen, Open};
        use attome_outbound::registry::ServiceState;
        let at = |state| {
            vec![ServiceState {
                name: "probe_test_service",
                state,
                count: 1,
                calls: 0,
                failures: 0,
                retries: 0,
            }]
        };
        assert!(breaker_changes(&at(Closed)).is_empty());
        assert_eq!(
            breaker_changes(&at(Open)),
            vec![("probe_test_service", "closed", "open")]
        );
        assert!(breaker_changes(&at(Open)).is_empty(), "still open");
        assert!(breaker_changes(&at(HalfOpen)).is_empty(), "a probe step");
        assert_eq!(
            breaker_changes(&at(Closed)),
            vec![("probe_test_service", "open", "closed")]
        );
        assert_eq!(breaker_service(Capability::AiModel), Some("ai_model"));
        assert_eq!(breaker_service(Capability::Email), Some("smtp"));
        assert_eq!(
            breaker_service(Capability::ObjectStorage),
            Some("object_storage")
        );
    }

    /// AB5-T8: a period opens when a capability becomes unavailable and
    /// closes when it stops being unavailable; nothing else touches it.
    #[test]
    fn periods_open_and_close_on_unavailable_edges() {
        use CapabilityState::{Available, Disabled, Unavailable, Unknown};
        assert_eq!(
            period_change(Available, Unavailable),
            Some(PeriodChange::Open)
        );
        assert_eq!(
            period_change(Unknown, Unavailable),
            Some(PeriodChange::Open)
        );
        assert_eq!(
            period_change(Unavailable, Available),
            Some(PeriodChange::Close)
        );
        assert_eq!(
            period_change(Unavailable, Disabled),
            Some(PeriodChange::Close)
        );
        assert_eq!(period_change(Unavailable, Unavailable), None);
        assert_eq!(period_change(Unknown, Available), None);
    }

    /// AB5-T1: the AI endpoint's host and port, defaulted by scheme.
    #[test]
    fn host_port_reads_the_endpoint() {
        assert_eq!(
            host_port("http://127.0.0.1:8000/v1").as_deref(),
            Some("127.0.0.1:8000")
        );
        assert_eq!(
            host_port("https://models.example/v1").as_deref(),
            Some("models.example:443")
        );
        assert_eq!(
            host_port("http://[::1]:9000/").as_deref(),
            Some("[::1]:9000")
        );
        assert_eq!(host_port("http://[::1]/").as_deref(), Some("[::1]:80"));
        assert_eq!(host_port(""), None);
        assert_eq!(host_port("ftp://x"), None);
    }

    /// AB5-T1: the search drain is down when expired or far behind, and
    /// unknown until it has registered.
    #[test]
    fn search_index_follows_the_drain_cursor() {
        let consumer = |status: &str, lag_seconds: f64| attome_core::change_feed::ConsumerHealth {
            consumer: attome_search::drain::CONSUMER.to_owned(),
            kind: "internal".to_owned(),
            status: status.to_owned(),
            lag_events: 0,
            lag_seconds,
            last_read_at: chrono::Utc::now(),
            last_event_at: None,
            max_lag_hours: 720,
        };
        assert_eq!(
            search_outcome(&[consumer("active", 5.0)]),
            ProbeOutcome::Reachable
        );
        assert_eq!(
            search_outcome(&[consumer("active", 900.0)]),
            ProbeOutcome::Unreachable
        );
        assert_eq!(
            search_outcome(&[consumer("expired", 0.0)]),
            ProbeOutcome::Unreachable
        );
        assert_eq!(search_outcome(&[]), ProbeOutcome::Indeterminate);
        assert_eq!(SEARCH_DRAIN_CONSUMER, attome_search::drain::CONSUMER);
    }

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
