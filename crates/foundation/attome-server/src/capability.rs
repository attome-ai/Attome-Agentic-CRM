//! D-344 (amends D-167) — per-capability readiness and route-level overload
//! rejection.
//!
//! # The gap this closes, and the one it deliberately does not reopen
//!
//! D-167 settled — with the user, before anything was built — that
//! `/health/ready` gates load-balancer traffic on exactly three things (a
//! live `SELECT 1`, a live Redis ping, the metadata-registry pre-warm) and
//! that object storage, the apalis workers, SMTP and the audit chainer must
//! never appear in it. A down SMTP relay must not pull an otherwise-healthy,
//! DB-serving node out of rotation, and `/health/dependencies` returns 200
//! unconditionally so it can never become a second, accidental readiness
//! gate. **None of that changes here.** This module writes to no readiness
//! signal and reads none; `attome_server::health::health_ready` is untouched.
//!
//! What D-167 left open is the other side of the same coin: the load balancer
//! keeps routing *every* kind of traffic to that healthy node, including the
//! file upload that needs the object store, the bulk import that needs a live
//! batch worker, and the mail resend that needs the relay. Those callers get
//! a 2xx for work that will never durably complete, and find out later or not
//! at all. Node eviction is the wrong instrument for that; refusing the
//! specific operation is the right one.
//!
//! So: node readiness stays global and stays narrow, and *durability* becomes
//! a per-route concern, expressed in the handler's own signature:
//!
//! ```rust,ignore
//! async fn create_upload_session(
//!     State(state): State<XrmState>,
//!     ctx: Authorized<RecordScoped<Update>>,
//!     _cap: Available<ObjectStorage>,   // 503 if the store is confirmed down
//!     ...
//! ) -> Result<Json<UploadSessionResponse>, AppError> {
//! ```
//!
//! Same shape, and the same reasoning, as [`crate::authz::Authorized<P>`]: a
//! property that used to depend on someone remembering a line inside a
//! handler body becomes an extractor that cannot be forgotten once named, and
//! that is greppable when it is missing.
//!
//! # Generic mechanism, deployment-specific probe
//!
//! This crate has zero `xrm-*` dependencies (guidelines §1) and — as with
//! [`crate::state::AppState::registry_ready`] and
//! [`crate::state::AppState::audit_ingest_backlog_exceeded`] — owns only the
//! flag and the gate. The writer is `xrm_server::spawn_capability_refresh`,
//! which reuses the exact typed health checks `/health/dependencies` already
//! calls (`attome_storage::health_check`, `attome_email::health_check`,
//! `attome_jobs::worker_last_seen_age_seconds`) so the gate and that endpoint
//! can never silently disagree about what "reachable" means.
//!
//! # Failing safe in both directions
//!
//! Rejecting traffic on a bad signal is its own outage, so the state machine
//! is asymmetric on purpose:
//!
//! - [`CapabilityState::Unknown`] — never probed (cold start, or
//!   `capability.probe_enabled = false`, or a deployment that never spawns
//!   the poller, which is every test in this workspace). **Admits.** Unknown
//!   is not "down", and a node must not reject uploads for the first 30
//!   seconds of its life.
//! - [`CapabilityState::Disabled`] — the dependency is deliberately switched
//!   off in config (`email.enabled = false`). **Admits**, same D-029 reading
//!   as the audit chainer's `{"enabled": false}`: a deliberate deployment
//!   choice is not a failure, and whatever the handler already did in that
//!   configuration keeps happening.
//! - [`CapabilityState::Unavailable`] — `failure_threshold` *consecutive*
//!   probes failed. **Rejects**, iff enforcement is on.
//! - A probe error (the query itself failed, as opposed to reporting the
//!   dependency down) leaves the last known state alone rather than guessing
//!   — same posture as `spawn_ingest_backlog_refresh`'s poll-failure arm.
//!
//! One success clears the failure counter outright: slow to trip, immediate
//! to recover.

use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};

use attome_types::AppError;
use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// A dependency whose absence makes a specific class of operation unable to
/// complete durably — as distinct from the DB/Redis/registry triple, whose
/// absence makes the *node* unable to serve at all and which therefore
/// belongs in `/health/ready` instead (D-167).
///
/// Deliberately not "every dependency": adding a variant here is a statement
/// that some route should refuse work when it is down. A dependency that only
/// needs *reporting* belongs in `/health/dependencies`'s live probe and
/// nowhere near this enum.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    /// S3/RustFS. Gates upload-session creation and finalization — both hand
    /// the caller a contract ("PUT here, then finalize") that the object
    /// store has to honour for the record's file field to ever become valid.
    ObjectStorage,
    /// The SMTP relay. Gates operations whose entire purpose is to put a
    /// message on it.
    Email,
    /// The default apalis queue's worker process. Gates nothing today on its
    /// own — it is the *other* half of an email send (`PlatformJob::SendEmail`
    /// is a fast-queue job, so a live relay with a dead worker still sends
    /// nothing) and is declared alongside [`Self::Email`] where that matters.
    FastJobs,
    /// The batch apalis queue's worker process (`PlatformJob::is_batch` —
    /// bulk entity operations, staged imports). Gates the routes that enqueue
    /// them: accepting a 50,000-row import that no worker will ever claim is
    /// exactly the "2xx for work that will never happen" this module exists
    /// to stop.
    BatchJobs,
}

impl Capability {
    /// Every capability, in declaration order. Indexing into
    /// [`CapabilityRegistry`]'s slot array is by [`Self::index`], which must
    /// stay consistent with this.
    pub const ALL: [Capability; 4] = [
        Capability::ObjectStorage,
        Capability::Email,
        Capability::FastJobs,
        Capability::BatchJobs,
    ];

    /// Stable snake_case name — the `capability` metric label, the
    /// `/health/dependencies` JSON key, and the token named in the 503 body.
    /// Never changes once shipped; an operator's alert rule and a client's
    /// error handling both key off it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::ObjectStorage => "object_storage",
            Capability::Email => "email",
            Capability::FastJobs => "fast_jobs",
            Capability::BatchJobs => "batch_jobs",
        }
    }

    const fn index(self) -> usize {
        match self {
            Capability::ObjectStorage => 0,
            Capability::Email => 1,
            Capability::FastJobs => 2,
            Capability::BatchJobs => 3,
        }
    }
}

/// What the gate currently believes about one capability. See the module doc
/// for which states admit and which reject, and why.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Unknown,
    Available,
    Unavailable,
    Disabled,
}

impl CapabilityState {
    const fn as_u8(self) -> u8 {
        match self {
            CapabilityState::Unknown => 0,
            CapabilityState::Available => 1,
            CapabilityState::Unavailable => 2,
            CapabilityState::Disabled => 3,
        }
    }

    const fn from_u8(v: u8) -> Self {
        match v {
            1 => CapabilityState::Available,
            2 => CapabilityState::Unavailable,
            3 => CapabilityState::Disabled,
            // `store` only ever writes a value produced by `as_u8`, so no
            // other discriminant is reachable; `Unknown` is the safe reading
            // regardless, since it admits.
            _ => CapabilityState::Unknown,
        }
    }
}

/// One probe round's verdict for one capability, as reported by the poller.
///
/// Deliberately not the same type as [`CapabilityState`]: a probe reports
/// what it *observed* this round, and the registry — which owns the
/// consecutive-failure threshold — decides what that means for the gate. A
/// poller that could write `Unavailable` directly would be a poller that
/// could bypass the flap protection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProbeOutcome {
    /// The dependency answered.
    Reachable,
    /// The dependency did not answer, or answered unusably (a worker
    /// heartbeat older than `worker_stale_after_secs`).
    Unreachable,
    /// The dependency is switched off in configuration — not attempted, and
    /// not a failure (D-029).
    Disabled,
    /// The probe itself could not be run (the underlying query errored). The
    /// last known state is kept rather than guessed at.
    Indeterminate,
}

#[derive(Debug)]
struct Slot {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
}

impl Slot {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(CapabilityState::Unknown.as_u8()),
            consecutive_failures: AtomicU32::new(0),
        }
    }
}

/// Per-node capability status, written by one poll task and read on the
/// request path.
///
/// Per-node, not shared: each node probes the dependencies *it* can reach and
/// gates *its own* traffic accordingly, exactly like
/// [`crate::state::AppState::replica_watermark`] and the security resolver's
/// caches. There is deliberately no cross-node consensus here — a node that
/// can still reach S3 should keep serving uploads even while its neighbour
/// cannot, and the load balancer is what distributes around it.
#[derive(Debug)]
pub struct CapabilityRegistry {
    slots: [Slot; Capability::ALL.len()],
    failure_threshold: u32,
    enforced: AtomicBool,
}

impl CapabilityRegistry {
    /// `failure_threshold` is clamped to at least 1 — a threshold of 0 would
    /// mean "trip before any probe has failed", which is not a policy anyone
    /// can have meant.
    pub fn new(failure_threshold: u32, enforced: bool) -> Self {
        Self {
            slots: [Slot::new(), Slot::new(), Slot::new(), Slot::new()],
            failure_threshold: failure_threshold.max(1),
            enforced: AtomicBool::new(enforced),
        }
    }

    /// The registry every `AppState` starts with: nothing probed, so every
    /// capability is `Unknown` and admits. Enforcement is recorded as on so
    /// that a deployment which spawns the poller starts gating without a
    /// second opt-in; it is inert until the first probe lands regardless.
    pub fn inert() -> Self {
        Self::new(2, true)
    }

    /// Whether a confirmed-`Unavailable` capability actually rejects.
    /// Read on every gated request, so it is an atomic rather than a config
    /// lookup.
    pub fn is_enforced(&self) -> bool {
        self.enforced.load(Ordering::Relaxed)
    }

    /// Sets enforcement from `capability.enforcement_enabled`. Called once at
    /// boot by the poller's spawn function; separate from `new` only so that
    /// `AppState::new`'s 20-plus test call sites do not have to thread a
    /// config value they never exercise.
    pub fn set_enforced(&self, enforced: bool) {
        self.enforced.store(enforced, Ordering::Relaxed);
    }

    /// The gate's current belief about one capability.
    pub fn state(&self, capability: Capability) -> CapabilityState {
        CapabilityState::from_u8(self.slots[capability.index()].state.load(Ordering::Relaxed))
    }

    /// Folds one probe round's verdict in, applying the consecutive-failure
    /// threshold. Returns the resulting state so the caller can log a
    /// transition without a second read.
    ///
    /// Single-writer by construction (one poll task): the load/store pairs
    /// below are not an atomic read-modify-write and do not need to be.
    pub fn record(&self, capability: Capability, outcome: ProbeOutcome) -> CapabilityState {
        let slot = &self.slots[capability.index()];
        let previous = self.state(capability);

        let next = match outcome {
            ProbeOutcome::Reachable => {
                slot.consecutive_failures.store(0, Ordering::Relaxed);
                CapabilityState::Available
            }
            ProbeOutcome::Disabled => {
                slot.consecutive_failures.store(0, Ordering::Relaxed);
                CapabilityState::Disabled
            }
            ProbeOutcome::Unreachable => {
                let failures = slot.consecutive_failures.load(Ordering::Relaxed) + 1;
                slot.consecutive_failures.store(failures, Ordering::Relaxed);
                if failures >= self.failure_threshold {
                    CapabilityState::Unavailable
                } else {
                    // Below the threshold the previous state stands. From
                    // `Unknown` that means still `Unknown` (still admitting),
                    // which is the correct reading of "one failed probe on a
                    // node that has never had a successful one" — it is not
                    // yet evidence of an outage.
                    previous
                }
            }
            // The last known state is kept deliberately: an errored probe
            // says nothing about the dependency (same arm as
            // `spawn_ingest_backlog_refresh`'s poll failure). It does not
            // reset the failure counter either — an intermittently
            // unprobeable dependency should not become permanently
            // un-trippable.
            ProbeOutcome::Indeterminate => previous,
        };

        slot.state.store(next.as_u8(), Ordering::Relaxed);
        crate::metrics::record_capability_state(capability.as_str(), next.as_u8());
        next
    }

    /// The gate itself. `Ok(())` unless this capability is confirmed
    /// unavailable *and* enforcement is on.
    pub fn ensure_available(&self, capability: Capability) -> Result<(), AppError> {
        if self.state(capability) == CapabilityState::Unavailable && self.is_enforced() {
            crate::metrics::record_capability_rejection(capability.as_str());
            tracing::warn!(
                capability = capability.as_str(),
                "rejecting a request with 503: this operation cannot durably complete while \
                 the capability is unavailable (node readiness is deliberately unaffected — \
                 see D-167/D-344)",
            );
            return Err(AppError::CapabilityUnavailable(capability.as_str()));
        }
        Ok(())
    }

    /// Every capability's current state, for `/health/dependencies`.
    pub fn snapshot(&self) -> Vec<CapabilityReport> {
        Capability::ALL
            .iter()
            .map(|c| CapabilityReport {
                capability: c.as_str(),
                state: self.state(*c),
                consecutive_failures: self.slots[c.index()]
                    .consecutive_failures
                    .load(Ordering::Relaxed),
                enforced: self.is_enforced(),
            })
            .collect()
    }
}

/// One row of [`CapabilityRegistry::snapshot`].
///
/// `state` is what the *gate* is enforcing, which is not necessarily what a
/// live probe would say this instant — `/health/dependencies` reports both,
/// and the difference (a dependency that has just come back but has not been
/// re-probed yet) is information an operator wants, not a discrepancy to hide.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    pub capability: &'static str,
    pub state: CapabilityState,
    /// How many consecutive failed probes have been seen. Non-zero with
    /// `state: "available"` means "degrading, not yet tripped".
    pub consecutive_failures: u32,
    /// Whether an `unavailable` state would actually reject
    /// (`capability.enforcement_enabled`).
    pub enforced: bool,
}

/// Cheap, cloneable handle to the registry, so the extractor costs one `Arc`
/// bump rather than a whole `AppState` clone.
///
/// `FromRef` impls: this crate provides `AppState`; `xrm-foundation` provides
/// `XrmState` (it owns that type, so the impl has to live there). Any router
/// state that can hand one of these over can mount a gated route — and one
/// that cannot fails to compile, which is the point.
#[derive(Clone, Debug)]
pub struct CapabilityStatuses(Arc<CapabilityRegistry>);

impl CapabilityStatuses {
    pub fn new(registry: Arc<CapabilityRegistry>) -> Self {
        Self(registry)
    }

    pub fn registry(&self) -> &CapabilityRegistry {
        &self.0
    }
}

// ── The extractor ───────────────────────────────────────────────────────────

/// Ties a compile-time marker type to its [`Capability`], so a handler names
/// the capability in its signature rather than passing a runtime value.
pub trait CapabilityKind {
    const CAPABILITY: Capability;
}

/// Declares that this route cannot durably complete its work without
/// capability `C`, and must return 503 rather than accept the request when
/// `C` is confirmed unavailable.
///
/// Zero-sized and carries nothing a handler body would read — bind it as
/// `_cap: Available<ObjectStorage>`. The value is the *check*, which axum has
/// already performed by the time the body runs.
///
/// Place it **after** the `Authorized<P>` extractor. Extractors run in
/// declaration order, so authorization decides first and an unauthenticated
/// caller learns nothing about the deployment's dependency state from this
/// gate. (It is not a secret — `/health/dependencies` is unauthenticated by
/// D-167 — but ordering the checks the other way round would be gratuitous.)
pub struct Available<C: CapabilityKind>(PhantomData<C>);

impl<C: CapabilityKind> std::fmt::Debug for Available<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Available")
            .field("capability", &C::CAPABILITY.as_str())
            .finish()
    }
}

/// [`Available<C>`]'s rejection: the identical `capability_unavailable`
/// response `AppError::CapabilityUnavailable` renders, plus the
/// `MutationNotApplied` response extension.
///
/// The extension tells the idempotency gate the request was refused before the
/// handler body ran, so its key can be released for a retry. Only this
/// extractor can prove that — the same `AppError` raised from handler logic may
/// follow a write, so it carries no marker and the gate treats it as an
/// unknown outcome.
#[derive(Debug)]
pub struct CapabilityRejection(AppError);

impl IntoResponse for CapabilityRejection {
    fn into_response(self) -> Response {
        let mut response = self.0.into_response();
        response
            .extensions_mut()
            .insert(crate::middleware::idempotency::MutationNotApplied);
        response
    }
}

impl<S, C> FromRequestParts<S> for Available<C>
where
    S: Send + Sync,
    C: CapabilityKind,
    CapabilityStatuses: FromRef<S>,
{
    type Rejection = CapabilityRejection;

    async fn from_request_parts(_parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        CapabilityStatuses::from_ref(state)
            .registry()
            .ensure_available(C::CAPABILITY)
            .map_err(CapabilityRejection)?;
        Ok(Self(PhantomData))
    }
}

/// Marker for [`Capability::ObjectStorage`].
#[derive(Debug)]
pub struct ObjectStorage;
impl CapabilityKind for ObjectStorage {
    const CAPABILITY: Capability = Capability::ObjectStorage;
}

/// Marker for [`Capability::Email`].
#[derive(Debug)]
pub struct Email;
impl CapabilityKind for Email {
    const CAPABILITY: Capability = Capability::Email;
}

/// Marker for [`Capability::FastJobs`].
#[derive(Debug)]
pub struct FastJobs;
impl CapabilityKind for FastJobs {
    const CAPABILITY: Capability = Capability::FastJobs;
}

/// Marker for [`Capability::BatchJobs`].
#[derive(Debug)]
pub struct BatchJobs;
impl CapabilityKind for BatchJobs {
    const CAPABILITY: Capability = Capability::BatchJobs;
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// The registry is pure in-process state with no I/O, so its whole decision
// table is unit-testable here without Postgres/Redis/an object store — same
// reasoning as `middleware/mutation_gate.rs`'s own tests. The complementary
// halves live elsewhere: `crates/server/tests/capability_gate.rs` asserts the
// intended routes actually name the extractor (a source census, like
// `route_authz.rs`), and the live-outage drill in D-344 is what proves the
// probe and the 503 agree with reality.
#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> CapabilityRegistry {
        CapabilityRegistry::new(2, true)
    }

    // ── Fail-safe defaults ──────────────────────────────────────────────────

    #[test]
    fn a_never_probed_capability_is_unknown_and_admits() {
        let r = registry();
        for c in Capability::ALL {
            assert_eq!(r.state(c), CapabilityState::Unknown);
            assert!(
                r.ensure_available(c).is_ok(),
                "{} must admit before any probe has run — a cold node must not \
                 reject work for its first probe interval",
                c.as_str()
            );
        }
    }

    #[test]
    fn a_deliberately_disabled_dependency_admits() {
        let r = registry();
        r.record(Capability::Email, ProbeOutcome::Disabled);
        assert_eq!(r.state(Capability::Email), CapabilityState::Disabled);
        assert!(r.ensure_available(Capability::Email).is_ok());
    }

    // ── Threshold / flap protection ─────────────────────────────────────────

    #[test]
    fn one_failed_probe_does_not_trip_the_gate() {
        let r = registry();
        r.record(Capability::ObjectStorage, ProbeOutcome::Reachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        assert_eq!(
            r.state(Capability::ObjectStorage),
            CapabilityState::Available,
            "a single dropped connection is background noise, not an outage"
        );
        assert!(r.ensure_available(Capability::ObjectStorage).is_ok());
    }

    #[test]
    fn consecutive_failures_reaching_the_threshold_trip_the_gate() {
        let r = registry();
        r.record(Capability::ObjectStorage, ProbeOutcome::Reachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        assert_eq!(
            r.state(Capability::ObjectStorage),
            CapabilityState::Unavailable
        );
        assert!(matches!(
            r.ensure_available(Capability::ObjectStorage),
            Err(AppError::CapabilityUnavailable("object_storage"))
        ));
    }

    #[test]
    fn a_single_success_clears_a_tripped_gate_immediately() {
        let r = registry();
        r.record(Capability::BatchJobs, ProbeOutcome::Unreachable);
        r.record(Capability::BatchJobs, ProbeOutcome::Unreachable);
        assert_eq!(r.state(Capability::BatchJobs), CapabilityState::Unavailable);

        r.record(Capability::BatchJobs, ProbeOutcome::Reachable);
        assert_eq!(
            r.state(Capability::BatchJobs),
            CapabilityState::Available,
            "slow to trip, immediate to recover"
        );
        assert!(r.ensure_available(Capability::BatchJobs).is_ok());
    }

    #[test]
    fn non_consecutive_failures_never_accumulate_into_a_trip() {
        let r = registry();
        for _ in 0..10 {
            r.record(Capability::Email, ProbeOutcome::Unreachable);
            r.record(Capability::Email, ProbeOutcome::Reachable);
        }
        assert_eq!(r.state(Capability::Email), CapabilityState::Available);
    }

    #[test]
    fn a_threshold_of_one_trips_on_the_first_failure() {
        let r = CapabilityRegistry::new(1, true);
        r.record(Capability::Email, ProbeOutcome::Unreachable);
        assert_eq!(r.state(Capability::Email), CapabilityState::Unavailable);
    }

    /// A configured threshold of 0 would mean "trip before anything failed".
    #[test]
    fn a_threshold_of_zero_is_clamped_to_one_rather_than_tripping_instantly() {
        let r = CapabilityRegistry::new(0, true);
        assert_eq!(r.state(Capability::Email), CapabilityState::Unknown);
        r.record(Capability::Email, ProbeOutcome::Unreachable);
        assert_eq!(r.state(Capability::Email), CapabilityState::Unavailable);
    }

    // ── Indeterminate probes ────────────────────────────────────────────────

    #[test]
    fn an_indeterminate_probe_keeps_the_last_known_state() {
        let r = registry();
        r.record(Capability::FastJobs, ProbeOutcome::Reachable);
        r.record(Capability::FastJobs, ProbeOutcome::Indeterminate);
        assert_eq!(r.state(Capability::FastJobs), CapabilityState::Available);

        r.record(Capability::FastJobs, ProbeOutcome::Unreachable);
        r.record(Capability::FastJobs, ProbeOutcome::Unreachable);
        r.record(Capability::FastJobs, ProbeOutcome::Indeterminate);
        assert_eq!(
            r.state(Capability::FastJobs),
            CapabilityState::Unavailable,
            "an unrunnable probe must not silently un-trip a confirmed outage"
        );
    }

    #[test]
    fn an_indeterminate_probe_does_not_reset_the_failure_counter() {
        let r = registry();
        r.record(Capability::FastJobs, ProbeOutcome::Unreachable);
        r.record(Capability::FastJobs, ProbeOutcome::Indeterminate);
        r.record(Capability::FastJobs, ProbeOutcome::Unreachable);
        assert_eq!(
            r.state(Capability::FastJobs),
            CapabilityState::Unavailable,
            "two real failures either side of an unrunnable probe are still two \
             consecutive failures"
        );
    }

    // ── Enforcement switch ──────────────────────────────────────────────────

    #[test]
    fn enforcement_off_reports_the_outage_but_admits_the_request() {
        let r = CapabilityRegistry::new(2, false);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        assert_eq!(
            r.state(Capability::ObjectStorage),
            CapabilityState::Unavailable,
            "the observe-only rollout mode still tracks state — that is its whole point"
        );
        assert!(r.ensure_available(Capability::ObjectStorage).is_ok());
    }

    #[test]
    fn set_enforced_flips_the_gate_without_disturbing_state() {
        let r = CapabilityRegistry::new(2, false);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        assert!(r.ensure_available(Capability::ObjectStorage).is_ok());
        r.set_enforced(true);
        assert!(r.ensure_available(Capability::ObjectStorage).is_err());
    }

    // ── Isolation between capabilities ──────────────────────────────────────

    /// The core of the D-167 amendment: one dependency going down must take
    /// out exactly the operations that need it, and nothing else.
    #[test]
    fn one_tripped_capability_never_affects_another() {
        let r = registry();
        for c in Capability::ALL {
            r.record(c, ProbeOutcome::Reachable);
        }
        r.record(Capability::Email, ProbeOutcome::Unreachable);
        r.record(Capability::Email, ProbeOutcome::Unreachable);

        assert!(r.ensure_available(Capability::Email).is_err());
        for c in [
            Capability::ObjectStorage,
            Capability::FastJobs,
            Capability::BatchJobs,
        ] {
            assert!(
                r.ensure_available(c).is_ok(),
                "a down relay must not gate {}",
                c.as_str()
            );
        }
    }

    // ── Reporting ───────────────────────────────────────────────────────────

    #[test]
    fn snapshot_reports_every_capability_with_its_degrading_counter() {
        let r = registry();
        r.record(Capability::ObjectStorage, ProbeOutcome::Reachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);

        let snap = r.snapshot();
        assert_eq!(snap.len(), Capability::ALL.len());

        let storage = snap
            .iter()
            .find(|row| row.capability == "object_storage")
            .expect("object_storage is reported");
        assert_eq!(storage.state, CapabilityState::Available);
        assert_eq!(
            storage.consecutive_failures, 1,
            "'degrading but not tripped' has to be visible before the trip, or the \
             endpoint is only useful after the outage already started"
        );
        assert!(storage.enforced);
    }

    #[test]
    fn capability_names_are_stable_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for c in Capability::ALL {
            assert!(seen.insert(c.as_str()), "duplicate name {}", c.as_str());
        }
        assert_eq!(Capability::ObjectStorage.as_str(), "object_storage");
        assert_eq!(Capability::Email.as_str(), "email");
        assert_eq!(Capability::FastJobs.as_str(), "fast_jobs");
        assert_eq!(Capability::BatchJobs.as_str(), "batch_jobs");
    }

    /// `ALL` and `index` are two hand-written lists that have to agree, or a
    /// probe would write into another capability's slot.
    #[test]
    fn every_capability_indexes_to_its_own_slot() {
        for (i, c) in Capability::ALL.iter().enumerate() {
            assert_eq!(c.index(), i, "{} indexes to the wrong slot", c.as_str());
        }
    }

    #[test]
    fn state_round_trips_through_its_atomic_representation() {
        for s in [
            CapabilityState::Unknown,
            CapabilityState::Available,
            CapabilityState::Unavailable,
            CapabilityState::Disabled,
        ] {
            assert_eq!(CapabilityState::from_u8(s.as_u8()), s);
        }
    }

    // ── The extractor ───────────────────────────────────────────────────────

    /// `CapabilityStatuses` is its own router state here (axum's blanket
    /// `FromRef<T> for T`), which exercises the extractor without needing a
    /// live `AppState`.
    async fn extract<C: CapabilityKind>(
        registry: CapabilityRegistry,
    ) -> Result<Available<C>, CapabilityRejection> {
        let statuses = CapabilityStatuses::new(Arc::new(registry));
        let req = axum::http::Request::builder()
            .uri("/api/v1/core_contact/x/files/y/upload-session")
            .body(())
            .unwrap();
        let (mut parts, _) = req.into_parts();
        Available::<C>::from_request_parts(&mut parts, &statuses).await
    }

    #[tokio::test]
    async fn extractor_admits_an_available_capability() {
        let r = registry();
        r.record(Capability::ObjectStorage, ProbeOutcome::Reachable);
        let got = extract::<ObjectStorage>(r).await;
        assert!(got.is_ok(), "{got:?}");
    }

    #[tokio::test]
    async fn extractor_rejects_a_tripped_capability_with_its_own_error() {
        let r = registry();
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        let got = extract::<ObjectStorage>(r).await;
        assert!(matches!(
            got,
            Err(CapabilityRejection(AppError::CapabilityUnavailable(
                "object_storage"
            )))
        ));
    }

    /// P1.1. The rejection renders the ordinary `capability_unavailable` 503
    /// and carries the `MutationNotApplied` marker, which is what lets the
    /// idempotency gate release the key — this extractor runs before the
    /// handler body, so nothing can have been written.
    #[tokio::test]
    async fn extractor_rejection_carries_the_not_applied_marker() {
        let r = registry();
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        r.record(Capability::ObjectStorage, ProbeOutcome::Unreachable);
        let rejection = extract::<ObjectStorage>(r)
            .await
            .expect_err("a tripped capability must reject");
        let response = rejection.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(
            response
                .extensions()
                .get::<crate::middleware::idempotency::MutationNotApplied>()
                .is_some()
        );
    }

    #[tokio::test]
    async fn extractor_gates_on_its_own_capability_only() {
        let r = registry();
        r.record(Capability::BatchJobs, ProbeOutcome::Unreachable);
        r.record(Capability::BatchJobs, ProbeOutcome::Unreachable);
        assert!(
            extract::<ObjectStorage>(r).await.is_ok(),
            "a dead batch worker must not gate an upload"
        );
    }
}
