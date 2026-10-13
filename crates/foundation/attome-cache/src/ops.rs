//! `base_cache_redis_ops_total{primitive,outcome}` — the crate's failure
//! counter (BCA-21, plan §5 "Visibility").
//!
//! Before this module the only signals this crate emitted were
//! `hot_cache_lookups_total` and `redis_subscriber_clients_created_total`;
//! a Redis call that errored or timed out was visible only in whatever the
//! caller did with the `AppError`, which for a fail-closed control means a
//! 429/503 an operator cannot attribute to the store (BCA-F4).
//!
//! closed Rust enum with no path from a key, user id, or stream name into a
//! label value: 7 primitives × 3 outcomes = 21 series, ever. A per-key label
//! would take the scrape endpoint down, which is why the plan states the
//! ceiling explicitly.
//!
//! An `ok` outcome is recorded too, so an operator can see the *rate* of
//! failures against traffic rather than a bare counter (a lone error counter
//! cannot answer "is this 1 in 10 or 1 in 10 million?").

use tokio::time::error::Elapsed;

/// Which primitive made the call. Stable metric label values — never rename
/// one without a dashboard/alert migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Primitive {
    RateLimit,
    RwPin,
    TokenWindow,
    Stream,
    Coalesce,
    Persistence,
    Ping,
}

impl Primitive {
    /// Every variant, so a test can prove the label set is exactly this size.
    #[cfg(test)]
    pub(crate) const ALL: [Primitive; 7] = [
        Primitive::RateLimit,
        Primitive::RwPin,
        Primitive::TokenWindow,
        Primitive::Stream,
        Primitive::Coalesce,
        Primitive::Persistence,
        Primitive::Ping,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Primitive::RateLimit => "rate_limit",
            Primitive::RwPin => "rw_pin",
            Primitive::TokenWindow => "token_window",
            Primitive::Stream => "stream",
            Primitive::Coalesce => "coalesce",
            Primitive::Persistence => "persistence",
            Primitive::Ping => "ping",
        }
    }
}

/// How the call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Ok,
    /// Redis answered with an error the caller treats as a failure (wrong
    /// type, auth, ...). An error reply the caller interprets as a normal
    /// answer — BUSYGROUP, a missing group on XPENDING — is `Ok`.
    Error,
    /// The crate's own bound in `crate::timeouts` elapsed first.
    Timeout,
}

impl Outcome {
    #[cfg(test)]
    pub(crate) const ALL: [Outcome; 3] = [Outcome::Ok, Outcome::Error, Outcome::Timeout];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Error => "error",
            Outcome::Timeout => "timeout",
        }
    }
}

/// Records exactly one call outcome.
pub(crate) fn record(primitive: Primitive, outcome: Outcome) {
    metrics::counter!(
        "base_cache_redis_ops_total",
        "primitive" => primitive.label(),
        "outcome" => outcome.label(),
    )
    .increment(1);
}

/// Classifies one bounded call and records it. Call sites keep their existing
/// `tokio::time::timeout` shape and hand the untouched result here, so the
/// counter cannot disagree with the error the caller returns.
pub(crate) fn record_op<T, E>(primitive: Primitive, result: &Result<Result<T, E>, Elapsed>) {
    let outcome = match result {
        Ok(Ok(_)) => Outcome::Ok,
        Ok(Err(_)) => Outcome::Error,
        Err(_) => Outcome::Timeout,
    };
    record(primitive, outcome);
}

#[cfg(test)]
mod tests {
    use super::*;
    use fred::interfaces::ClientLike;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    // ── A minimal metrics::Recorder that keeps the label set ────────────────
    //
    // `metrics-util`'s debugging recorder is the usual tool; this crate's
    // Cargo.toml is outside the write surface, so this is the same idea
    // written out, keyed by name plus sorted labels (the name alone cannot
    // distinguish `outcome=ok` from `outcome=timeout`, which is the whole
    // point of this counter).

    fn composite(name: &str, labels: &[(&str, &str)]) -> String {
        let mut parts: Vec<String> = labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        parts.sort();
        format!("{name}{{{}}}", parts.join(","))
    }

    #[derive(Clone, Default)]
    struct TestRecorder {
        counters: Arc<Mutex<HashMap<String, u64>>>,
    }

    impl TestRecorder {
        fn install() -> Self {
            static RECORDER: OnceLock<TestRecorder> = OnceLock::new();
            let recorder = RECORDER.get_or_init(TestRecorder::default).clone();
            let _ = metrics::set_global_recorder(recorder.clone());
            recorder
        }

        fn counter(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
            self.counters
                .lock()
                .expect("test recorder lock")
                .get(&composite(name, labels))
                .copied()
                .unwrap_or(0)
        }
    }

    impl metrics::Recorder for TestRecorder {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            let mut parts: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            parts.sort();
            let composite = format!("{}{{{}}}", key.name(), parts.join(","));
            metrics::Counter::from_arc(Arc::new(TestCounter {
                name: composite,
                counters: self.counters.clone(),
            }))
        }

        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    struct TestCounter {
        name: String,
        counters: Arc<Mutex<HashMap<String, u64>>>,
    }

    impl metrics::CounterFn for TestCounter {
        fn increment(&self, value: u64) {
            let mut counters = self.counters.lock().expect("test recorder lock");
            *counters.entry(self.name.clone()).or_insert(0) += value;
        }

        fn absolute(&self, value: u64) {
            self.counters
                .lock()
                .expect("test recorder lock")
                .insert(self.name.clone(), value);
        }
    }

    /// A store that accepts the TCP connection and then answers nothing: any
    /// command it receives can only run out the client's own bound, which is
    /// exactly the timeout path this counter exists for. No live Redis needed.
    async fn stalling_pool() -> (crate::redis_pool::RedisPool, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a stalling listener");
        let addr = listener.local_addr().expect("listener address");
        let acceptor = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let config = fred::prelude::RedisConfig::from_url(&format!("redis://{addr}"))
            .expect("stalling redis config");
        let pool =
            crate::redis_pool::RedisPool::new(config, None, None, None, 1).expect("stalling pool");
        pool.connect();
        (pool, acceptor)
    }

    /// The acceptance case: a forced timeout records `outcome="timeout"`, and
    /// it does so inside the crate's own bound rather than the operator's
    /// `cache.timeout` (2000 ms default).
    #[tokio::test]
    async fn redis_ops_total_records_a_timeout_when_the_store_stalls() {
        let recorder = TestRecorder::install();
        let (pool, acceptor) = stalling_pool().await;
        let labels = [("outcome", "timeout"), ("primitive", "rate_limit")];
        let before = recorder.counter("base_cache_redis_ops_total", &labels);

        let started = std::time::Instant::now();
        let result = crate::rate_limit::check(&pool, "test:ops-timeout", 10).await;
        let elapsed = started.elapsed();
        acceptor.abort();

        assert!(
            result.is_err(),
            "a stalled store must fail closed, not admit: {result:?}"
        );
        assert_eq!(
            recorder.counter("base_cache_redis_ops_total", &labels),
            before + 1,
            "the timeout outcome must be recorded exactly once"
        );
        assert!(
            elapsed < crate::timeouts::REQUEST_PATH + Duration::from_millis(400),
            "the call must stay inside the crate's own request-path bound, took {elapsed:?}"
        );
    }

    /// The taxonomy is closed: 7 primitives x 3 outcomes is the hard ceiling,
    /// and every one of those 21 series is reachable (a variant that no call
    /// site uses would be dead weight in the label set).
    /// Serializes the tests that write the `ping` series on the shared recorder.
    static PING_SERIES: Mutex<()> = Mutex::new(());

    #[test]
    fn redis_ops_total_has_a_bounded_label_taxonomy() {
        let _serial = PING_SERIES.lock().unwrap_or_else(|p| p.into_inner());
        let recorder = TestRecorder::install();
        let mut reachable = 0;
        for primitive in Primitive::ALL {
            for outcome in Outcome::ALL {
                record(primitive, outcome);
                assert!(
                    recorder.counter(
                        "base_cache_redis_ops_total",
                        &[
                            ("primitive", primitive.label()),
                            ("outcome", outcome.label()),
                        ]
                    ) > 0,
                    "{} / {} must be a real series",
                    primitive.label(),
                    outcome.label()
                );
                reachable += 1;
            }
        }
        assert_eq!(reachable, 21, "7 primitives x 3 outcomes");
    }

    /// `record_op` maps each of the three result shapes to its own outcome —
    /// the classification every call site depends on.
    #[test]
    fn redis_ops_total_classifies_each_result_shape() {
        let _serial = PING_SERIES.lock().unwrap_or_else(|p| p.into_inner());
        let recorder = TestRecorder::install();
        let ok_labels = [("primitive", "ping"), ("outcome", "ok")];
        let err_labels = [("primitive", "ping"), ("outcome", "error")];
        let ok_before = recorder.counter("base_cache_redis_ops_total", &ok_labels);
        let err_before = recorder.counter("base_cache_redis_ops_total", &err_labels);
        let ok: Result<Result<u8, ()>, Elapsed> = Ok(Ok(1));
        let err: Result<Result<u8, ()>, Elapsed> = Ok(Err(()));
        record_op(Primitive::Ping, &ok);
        record_op(Primitive::Ping, &err);
        assert_eq!(
            recorder.counter("base_cache_redis_ops_total", &ok_labels),
            ok_before + 1
        );
        assert_eq!(
            recorder.counter("base_cache_redis_ops_total", &err_labels),
            err_before + 1
        );
    }
}
