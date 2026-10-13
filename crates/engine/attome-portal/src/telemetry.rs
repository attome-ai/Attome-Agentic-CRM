//! Portal metrics (web portal plan §5 "Visibility", Phase 13 step 5).
//!
//! Every counter goes through the process-wide `metrics` recorder that
//! `attome_server` installs (the Prometheus exporter), like the staff
//! middleware's. Label values are fixed `&'static str`s: no portal id, keyword,
//! user id or address ever becomes a label (unbounded cardinality, and PII).
//!
//! - `security_rejection_total{reason}` — the platform's existing rejection
//!   counter (`attome_server::middleware::csrf`), with the portal reasons below.
//!   `portal_host` is counted by `attome_server::middleware::host_gate` for the
//!   portal audience, since that layer runs before this crate sees a request.
//! - `portal_auth_total{outcome}` — portal password logins.
//! - `portal_plan_match_nothing_total` — a grant condition that no longer
//!   renders against current metadata (G-6 drift), so it matches nothing.
//! - `portal_cache_bypass_total{reason}` and
//!   `portal_cache_invalidation_failed_total` — the G-9 cache ([`crate::cache`]);
//!   its hit rate is `hot_cache_lookups_total{cache="portal_entry"|"portal_plan"}`.

/// A cookie-carrying request from an origin outside the portal hosts (G-10).
pub(crate) const REJECT_ORIGIN: &str = "portal_origin";
/// A portal, account or record budget refused the request, or its Redis
/// counter was unreachable (fails closed, R10).
pub(crate) const REJECT_BUDGET: &str = "portal_budget";
/// The client address is outside the portal's CIDR allowlist (G-13).
pub(crate) const REJECT_CIDR: &str = "portal_cidr";
/// A signed session whose credential epoch, refresh family or account status
/// no longer admits it (revocation, R4).
pub(crate) const REJECT_EPOCH: &str = "portal_epoch";

pub(crate) const AUTH_SUCCESS: &str = "success";
pub(crate) const AUTH_BAD_CREDENTIALS: &str = "bad_credentials";
pub(crate) const AUTH_LOCKED: &str = "locked";
pub(crate) const AUTH_MFA_REQUIRED: &str = "mfa_required";

pub(crate) fn rejected(reason: &'static str) {
    metrics::counter!("security_rejection_total", "reason" => reason).increment(1);
}

pub(crate) fn auth_outcome(outcome: &'static str) {
    metrics::counter!("portal_auth_total", "outcome" => outcome).increment(1);
}

pub(crate) fn plan_match_nothing() {
    metrics::counter!("portal_plan_match_nothing_total").increment(1);
}

/// G-9: the access version could not be read (Redis error or timeout), so
/// this request bypassed the portal cache and read PostgreSQL.
pub(crate) const CACHE_BYPASS_REDIS: &str = "redis_error";
/// G-9: the access version key was absent (cold, expired or evicted); a
/// fresh version was started and this request read PostgreSQL.
pub(crate) const CACHE_BYPASS_ABSENT: &str = "version_absent";

/// `portal_cache_bypass_total{reason}`: requests served from PostgreSQL
/// because the cache's version could not be established.
pub(crate) fn cache_bypass(reason: &'static str) {
    metrics::counter!("portal_cache_bypass_total", "reason" => reason).increment(1);
}

/// `portal_cache_invalidation_failed_total`: a portal-admin write committed
/// but its access-version bump did not reach Redis, so other nodes may serve
/// the previous grants until their entries expire (at most the cache TTL).
pub(crate) fn cache_invalidation_failed() {
    metrics::counter!("portal_cache_invalidation_failed_total").increment(1);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use metrics::{
        Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };

    use super::*;

    /// Counts increments per `name{label=value,…}`.
    #[derive(Default, Clone)]
    struct Capture(Arc<Mutex<BTreeMap<String, Arc<Cell>>>>);

    #[derive(Default)]
    struct Cell(AtomicU64);

    impl CounterFn for Cell {
        fn increment(&self, value: u64) {
            self.0.fetch_add(value, Ordering::Relaxed);
        }
        fn absolute(&self, value: u64) {
            self.0.store(value, Ordering::Relaxed);
        }
    }

    impl Capture {
        fn get(&self, series: &str) -> u64 {
            self.0
                .lock()
                .unwrap()
                .get(series)
                .map_or(0, |c| c.0.load(Ordering::Relaxed))
        }
    }

    impl Recorder for Capture {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let series = format!("{}{{{}}}", key.name(), labels.join(","));
            let cell = self.0.lock().unwrap().entry(series).or_default().clone();
            Counter::from_arc(cell)
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }

    #[test]
    fn portal_counters_use_the_plan_names_and_labels() {
        let capture = Capture::default();
        metrics::with_local_recorder(&capture, || {
            for reason in [REJECT_ORIGIN, REJECT_BUDGET, REJECT_CIDR, REJECT_EPOCH] {
                rejected(reason);
            }
            rejected(REJECT_BUDGET);
            for outcome in [
                AUTH_SUCCESS,
                AUTH_BAD_CREDENTIALS,
                AUTH_LOCKED,
                AUTH_MFA_REQUIRED,
            ] {
                auth_outcome(outcome);
            }
            plan_match_nothing();
            cache_bypass(CACHE_BYPASS_REDIS);
            cache_bypass(CACHE_BYPASS_ABSENT);
            cache_invalidation_failed();
        });
        assert_eq!(
            capture.get("portal_cache_bypass_total{reason=redis_error}"),
            1
        );
        assert_eq!(
            capture.get("portal_cache_bypass_total{reason=version_absent}"),
            1
        );
        assert_eq!(capture.get("portal_cache_invalidation_failed_total{}"), 1);
        assert_eq!(
            capture.get("security_rejection_total{reason=portal_origin}"),
            1
        );
        assert_eq!(
            capture.get("security_rejection_total{reason=portal_budget}"),
            2
        );
        assert_eq!(
            capture.get("security_rejection_total{reason=portal_cidr}"),
            1
        );
        assert_eq!(
            capture.get("security_rejection_total{reason=portal_epoch}"),
            1
        );
        for outcome in ["success", "bad_credentials", "locked", "mfa_required"] {
            assert_eq!(
                capture.get(&format!("portal_auth_total{{outcome={outcome}}}")),
                1
            );
        }
        assert_eq!(capture.get("portal_plan_match_nothing_total{}"), 1);
    }
}
