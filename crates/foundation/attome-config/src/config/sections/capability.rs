//! D-344 (amends D-167) — the durability-capability gate's policy knobs.
//!
//! D-167 settled that `/health/ready` must never be flipped by object
//! storage, the job workers, SMTP, or the audit chainer: a down SMTP relay
//! must not pull an otherwise-healthy, DB-serving node out of load-balancer
//! rotation. That reasoning stands. What it left open is the other half —
//! the load balancer keeps routing file-upload, bulk-import and mail traffic
//! to a node that cannot durably complete it, and the caller gets a 2xx for
//! work that will never happen.
//!
//! This section configures the narrow fix: a per-capability probe whose only
//! consumer is a *route-level* 503 (`attome_server::capability`), never node
//! readiness.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct CapabilitySection {
    /// Whether `xrm_server::spawn_capability_refresh` should run at all.
    /// `false` leaves every capability at `unknown` forever, which the gate
    /// treats as "pass" — byte-identical to the behavior before D-344, same
    /// "nothing happens unless the poll task is spawned" posture as
    /// `audit.ingest_backlog_threshold`'s breaker.
    #[serde(default = "default_true")]
    pub probe_enabled: bool,

    /// Whether a confirmed-unavailable capability actually rejects requests
    /// on the routes that declare it, or is only reported.
    ///
    /// Defaults **on**, deliberately unlike most flags in this config tree:
    /// the finding D-344 answers is that the platform currently accepts work
    /// it cannot complete, and shipping the fix dark would not fix it. The
    /// blast radius is bounded by construction — only the handful of routes
    /// that name `attome_server::capability::Available<C>`, only after
    /// [`Self::failure_threshold`] *consecutive* failed probes, cleared by a
    /// single success. Setting this to `false` (with `probe_enabled = true`)
    /// is the intended rollout mode for an operator who wants to watch
    /// `/health/dependencies`'s `capabilities` block for a while first, and
    /// is also the kill switch if a probe ever proves flaky against a
    /// particular backend.
    #[serde(default = "default_true")]
    pub enforcement_enabled: bool,

    /// Seconds between probe rounds. 30s, not the 15s a readiness probe
    /// would use: this drives a route gate, not traffic routing, and the SMTP
    /// probe opens a real TCP+TLS connection to the relay each round — a
    /// tighter loop is a connection-rate cost paid against every deployment's
    /// mail provider for no decision-making benefit.
    #[serde(default = "default_probe_interval_secs")]
    pub probe_interval_secs: u64,

    /// Consecutive failed probes before a capability flips to
    /// `unavailable`. 2 (i.e. up to ~60s at the default interval) rather than
    /// 1: a single dropped connection to S3 or a relay is normal background
    /// noise and must not start rejecting uploads. A single success clears
    /// the counter immediately — slow to trip, fast to recover.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// How stale (`apalis.workers.last_seen`, via
    /// `attome_jobs::worker_last_seen_age_seconds`) a queue's worker heartbeat
    /// may be before that queue counts as a failed probe. 90s matches the
    /// `ApalisWorkerStale` alert rule's own expression
    /// (`observability/alerts.yml`) — 3 missed 30s `keep_alive` beats — so
    /// the gate and the alert can never disagree about what "the worker is
    /// down" means.
    #[serde(default = "default_worker_stale_after_secs")]
    pub worker_stale_after_secs: u64,
}

impl Default for CapabilitySection {
    fn default() -> Self {
        Self {
            probe_enabled: default_true(),
            enforcement_enabled: default_true(),
            probe_interval_secs: default_probe_interval_secs(),
            failure_threshold: default_failure_threshold(),
            worker_stale_after_secs: default_worker_stale_after_secs(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_probe_interval_secs() -> u64 {
    30
}

fn default_failure_threshold() -> u32 {
    2
}

fn default_worker_stale_after_secs() -> u64 {
    90
}
