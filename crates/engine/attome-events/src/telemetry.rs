//! Event-bus metrics (M62 plan §4.3, phase E1).
//!
//! Every series goes through the process-wide `metrics` recorder that
//! `attome_server` installs (the Prometheus exporter).
//!
//! **Cardinality bound.** §4.3 sketched a `{subscription}` label. A
//! subscription id is unbounded (admins create them at will) and its name is
//! admin free text, so neither becomes a label. Series are keyed by the
//! subscription's `kind` (a closed set: the table's CHECK plus
//! [`KIND_UNKNOWN`]) and by closed outcome/reason enums. The per-subscription
//! breakdown (lag and success rate per row) is the E3 admin page's, read from
//! PostgreSQL; the metrics answer "is any subscription of this kind behind or
//! failing", which is what an alert needs.
//!
//! - `events_dispatched_total{kind}` — deliveries a dispatch tick created.
//! - `events_dispatch_failures_total{kind}` — one subscription's tick failed
//!   (its cursor did not advance; retried next tick).
//! - `events_deliveries_total{kind,outcome}` — one per delivery attempt that
//!   reached an outcome: `delivered`, `failed` (apalis retries it) or
//!   `dead_letter`.
//! - `events_dead_lettered_total{kind,reason}` — why a delivery was
//!   dead-lettered (closed reasons, below).
//! - `events_delivery_seconds{kind}` — delivery row created → delivered,
//!   retries included (the S6 latency, histogram).
//! - `events_delivery_attempt_seconds{kind}` — one outbound HTTP attempt.
//! - Gauges, refreshed at the end of every webhook dispatch tick
//!   ([`refresh_gauges`]): `events_subscription_lag_max{kind}` (the largest
//!   number of unread feed rows behind any active subscription of that kind,
//!   saturating at [`LAG_CAP`]), `events_dead_letters{kind}` and
//!   `events_deliveries_retrying{kind}` (delivery rows currently in
//!   `dead_letter` / `failed`). A gauge is set by whichever node ran the tick;
//!   read it with `max by (kind)` across instances.

use attome_db::DbPool;
use attome_types::AppError;

/// Label for a delivery whose subscription row is gone.
pub const KIND_UNKNOWN: &str = "unknown";

/// Every `kind` label this crate emits a gauge for. `job`/`workflow`/
/// `internal` pass the CHECK but are refused by the admin API, so they never
/// have rows; a stray one reads as [`KIND_UNKNOWN`].
pub const GAUGE_KINDS: [&str; 3] = ["webhook", "audit", "connector"];

/// Unread rows counted per subscription before the lag gauge saturates. The
/// count is a bounded scan, so the gauge costs at most this many index rows
/// per subscription per tick.
pub const LAG_CAP: i64 = 10_000;

/// Maps a stored subscription kind onto the closed label set.
pub fn kind_label(kind: &str) -> &'static str {
    GAUGE_KINDS
        .into_iter()
        .find(|k| *k == kind)
        .unwrap_or(KIND_UNKNOWN)
}

pub const OUTCOME_DELIVERED: &str = "delivered";
pub const OUTCOME_FAILED: &str = "failed";
pub const OUTCOME_DEAD_LETTER: &str = "dead_letter";

/// Why a delivery was dead-lettered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadLetterReason {
    SubscriptionGone,
    SubscriptionInactive,
    NoTarget,
    AttemptsExhausted,
    BadUrl,
    SsrfRejected,
}

impl DeadLetterReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SubscriptionGone => "subscription_gone",
            Self::SubscriptionInactive => "subscription_inactive",
            Self::NoTarget => "no_target",
            Self::AttemptsExhausted => "attempts_exhausted",
            Self::BadUrl => "bad_url",
            Self::SsrfRejected => "ssrf_rejected",
        }
    }
}

pub fn dispatched(kind: &'static str, deliveries: u64) {
    if deliveries > 0 {
        metrics::counter!("events_dispatched_total", "kind" => kind).increment(deliveries);
    }
}

pub fn dispatch_failed(kind: &'static str) {
    metrics::counter!("events_dispatch_failures_total", "kind" => kind).increment(1);
}

pub fn delivery_outcome(kind: &'static str, outcome: &'static str) {
    metrics::counter!("events_deliveries_total", "kind" => kind, "outcome" => outcome).increment(1);
}

/// M13-T3: a subscription turned off because its endpoint kept failing.
pub fn auto_paused() {
    metrics::counter!("events_subscriptions_auto_paused_total").increment(1);
}

pub fn dead_lettered(kind: &'static str, reason: DeadLetterReason) {
    delivery_outcome(kind, OUTCOME_DEAD_LETTER);
    metrics::counter!(
        "events_dead_lettered_total",
        "kind" => kind,
        "reason" => reason.as_str(),
    )
    .increment(1);
}

pub fn delivered(kind: &'static str, end_to_end_seconds: f64) {
    delivery_outcome(kind, OUTCOME_DELIVERED);
    metrics::histogram!("events_delivery_seconds", "kind" => kind).record(end_to_end_seconds);
}

pub fn attempt(kind: &'static str, seconds: f64) {
    metrics::histogram!("events_delivery_attempt_seconds", "kind" => kind).record(seconds);
}

/// One read of the backlog gauges, per kind label.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GaugeSnapshot {
    /// `(kind, max unread rows behind any active subscription of that kind)`.
    pub lag_max: Vec<(&'static str, i64)>,
    /// `(kind, delivery rows in dead_letter)`.
    pub dead_letters: Vec<(&'static str, i64)>,
    /// `(kind, delivery rows in failed, i.e. waiting for an apalis retry)`.
    pub retrying: Vec<(&'static str, i64)>,
}

impl GaugeSnapshot {
    fn value(list: &[(&'static str, i64)], kind: &str) -> i64 {
        list.iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, v)| *v)
            .sum()
    }

    pub fn lag_max_for(&self, kind: &str) -> i64 {
        self.lag_max
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, v)| *v)
            .max()
            .unwrap_or(0)
    }

    pub fn dead_letters_for(&self, kind: &str) -> i64 {
        Self::value(&self.dead_letters, kind)
    }

    pub fn retrying_for(&self, kind: &str) -> i64 {
        Self::value(&self.retrying, kind)
    }
}

/// Reads the gauge values. Three bounded queries: the backlog uses the
/// partial `core_event_delivery_status_idx`; each lag count stops at
/// [`LAG_CAP`] rows.
pub async fn read_gauges(db: &DbPool) -> Result<GaugeSnapshot, AppError> {
    let backlog: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT s.kind, d.status, COUNT(*)::bigint \
           FROM event_delivery d \
           JOIN event_subscription s ON s.id = d.subscription_ref \
          WHERE d.status IN ('failed', 'dead_letter') \
          GROUP BY s.kind, d.status",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    // Webhook subscriptions read the entity change feed (`dispatch`); the
    // predicate mirrors `change_feed::read_batch`, so "behind" means exactly
    // the rows the next ticks would read.
    let webhook_lag: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(l.lag), 0)::bigint \
           FROM event_subscription s \
           LEFT JOIN change_consumer_cursor c ON c.consumer = 'events:' || s.id::text \
           CROSS JOIN LATERAL ( \
               SELECT COUNT(*) AS lag FROM ( \
                   SELECT 1 FROM entity_change_event e \
                    WHERE e.commit_xid > COALESCE(c.last_commit_xid, '0'::xid8) \
                      AND e.commit_xid < pg_snapshot_xmin(pg_current_snapshot()) \
                    LIMIT $1) x) l \
          WHERE s.is_deleted = FALSE AND s.is_active = TRUE AND s.kind = 'webhook'",
    )
    .bind(LAG_CAP)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    // Audit subscriptions read `audit_header` by id (`audit_dispatch`).
    // The `created_at` floor lets the partitioned table prune; a UUIDv7 id
    // after the cursor is never much older than the cursor's own timestamp.
    let audit_lag: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(l.lag), 0)::bigint \
           FROM event_subscription s \
           LEFT JOIN change_consumer_cursor c \
                  ON c.consumer = 'audit-events:' || s.id::text \
           CROSS JOIN LATERAL ( \
               SELECT COUNT(*) AS lag FROM ( \
                   SELECT 1 FROM audit_header h \
                    WHERE h.is_active = TRUE \
                      AND (c.last_id IS NULL OR h.id > c.last_id) \
                      AND (c.last_created_at IS NULL \
                           OR h.created_at >= c.last_created_at - INTERVAL '1 minute') \
                    LIMIT $1) x) l \
          WHERE s.is_deleted = FALSE AND s.is_active = TRUE AND s.kind = 'audit'",
    )
    .bind(LAG_CAP)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    let mut snapshot = GaugeSnapshot {
        lag_max: vec![("webhook", webhook_lag), ("audit", audit_lag)],
        ..GaugeSnapshot::default()
    };
    for (kind, status, count) in backlog {
        let kind = kind_label(&kind);
        match status.as_str() {
            "dead_letter" => snapshot.dead_letters.push((kind, count)),
            _ => snapshot.retrying.push((kind, count)),
        }
    }
    Ok(snapshot)
}

/// Sets every gauge for every kind label, zero included, so an alert on a
/// kind whose backlog drained clears rather than holding its last value.
pub fn publish(snapshot: &GaugeSnapshot) {
    for kind in GAUGE_KINDS {
        metrics::gauge!("events_subscription_lag_max", "kind" => kind)
            .set(snapshot.lag_max_for(kind) as f64);
        metrics::gauge!("events_dead_letters", "kind" => kind)
            .set(snapshot.dead_letters_for(kind) as f64);
        metrics::gauge!("events_deliveries_retrying", "kind" => kind)
            .set(snapshot.retrying_for(kind) as f64);
    }
}

/// Reads and publishes the gauges. A failed read is logged and leaves the
/// previous values: the gauges are observational, and the tick's own work
/// must not fail because of them.
pub async fn refresh_gauges(db: &DbPool) {
    match read_gauges(db).await {
        Ok(snapshot) => publish(&snapshot),
        Err(error) => {
            tracing::warn!(%error, "events telemetry: gauge refresh failed; previous values kept");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    use metrics::{
        Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata,
        Recorder, SharedString, Unit,
    };

    use super::*;

    /// Per `name{label=value,…}`: counter total, histogram sample count, or
    /// the last gauge value (as whole units).
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

    impl HistogramFn for Cell {
        fn record(&self, _value: f64) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl GaugeFn for Cell {
        fn increment(&self, _value: f64) {}
        fn decrement(&self, _value: f64) {}
        fn set(&self, value: f64) {
            self.0.store(value as u64, Ordering::Relaxed);
        }
    }

    impl Capture {
        fn cell(&self, key: &Key) -> Arc<Cell> {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let series = format!("{}{{{}}}", key.name(), labels.join(","));
            self.0.lock().unwrap().entry(series).or_default().clone()
        }
        fn get(&self, series: &str) -> Option<u64> {
            self.0
                .lock()
                .unwrap()
                .get(series)
                .map(|c| c.0.load(Ordering::Relaxed))
        }
    }

    impl Recorder for Capture {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            Counter::from_arc(self.cell(key))
        }
        fn register_gauge(&self, key: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::from_arc(self.cell(key))
        }
        fn register_histogram(&self, key: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::from_arc(self.cell(key))
        }
    }

    #[test]
    fn event_bus_metrics_use_the_plan_names_and_closed_labels() {
        let capture = Capture::default();
        metrics::with_local_recorder(&capture, || {
            dispatched("webhook", 3);
            dispatched("audit", 0);
            dispatch_failed("webhook");
            attempt("webhook", 0.2);
            delivered("webhook", 4.0);
            delivery_outcome("webhook", OUTCOME_FAILED);
            dead_lettered(KIND_UNKNOWN, DeadLetterReason::SubscriptionGone);
            dead_lettered("audit", DeadLetterReason::AttemptsExhausted);
        });

        assert_eq!(
            capture.get("events_dispatched_total{kind=webhook}"),
            Some(3)
        );
        assert_eq!(
            capture.get("events_dispatched_total{kind=audit}"),
            None,
            "a zero-delivery tick records no series"
        );
        assert_eq!(
            capture.get("events_dispatch_failures_total{kind=webhook}"),
            Some(1)
        );
        assert_eq!(
            capture.get("events_delivery_attempt_seconds{kind=webhook}"),
            Some(1)
        );
        assert_eq!(
            capture.get("events_delivery_seconds{kind=webhook}"),
            Some(1)
        );
        assert_eq!(
            capture.get("events_deliveries_total{kind=webhook,outcome=delivered}"),
            Some(1)
        );
        assert_eq!(
            capture.get("events_deliveries_total{kind=webhook,outcome=failed}"),
            Some(1)
        );
        assert_eq!(
            capture.get("events_deliveries_total{kind=unknown,outcome=dead_letter}"),
            Some(1)
        );
        assert_eq!(
            capture.get("events_dead_lettered_total{kind=audit,reason=attempts_exhausted}"),
            Some(1)
        );
    }

    #[test]
    fn publish_sets_every_kind_including_zero() {
        let capture = Capture::default();
        let snapshot = GaugeSnapshot {
            lag_max: vec![("webhook", 42), ("audit", 0)],
            dead_letters: vec![("webhook", 2), ("webhook", 1)],
            retrying: vec![("audit", 5)],
        };
        metrics::with_local_recorder(&capture, || publish(&snapshot));

        assert_eq!(
            capture.get("events_subscription_lag_max{kind=webhook}"),
            Some(42)
        );
        assert_eq!(capture.get("events_dead_letters{kind=webhook}"), Some(3));
        assert_eq!(
            capture.get("events_deliveries_retrying{kind=audit}"),
            Some(5)
        );
        for kind in GAUGE_KINDS {
            for name in [
                "events_subscription_lag_max",
                "events_dead_letters",
                "events_deliveries_retrying",
            ] {
                assert!(
                    capture.get(&format!("{name}{{kind={kind}}}")).is_some(),
                    "{name} not set for {kind}"
                );
            }
        }
    }

    #[test]
    fn kind_labels_are_closed() {
        assert_eq!(kind_label("webhook"), "webhook");
        assert_eq!(kind_label("audit"), "audit");
        assert_eq!(kind_label("connector"), "connector");
        assert_eq!(kind_label("job"), KIND_UNKNOWN);
        assert_eq!(kind_label("anything an admin typed"), KIND_UNKNOWN);
        let reasons = [
            DeadLetterReason::SubscriptionGone,
            DeadLetterReason::SubscriptionInactive,
            DeadLetterReason::NoTarget,
            DeadLetterReason::AttemptsExhausted,
            DeadLetterReason::BadUrl,
            DeadLetterReason::SsrfRejected,
        ];
        let mut seen: Vec<&str> = reasons.iter().map(|r| r.as_str()).collect();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), reasons.len());
    }
}
