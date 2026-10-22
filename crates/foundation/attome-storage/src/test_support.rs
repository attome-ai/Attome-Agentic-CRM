//! Shared test-only fixtures for this crate's unit tests.
//!
//! `create_storage_client` takes a whole `AppConfig` even though it only ever
//! reads `.storage` — so [`test_config`] builds every other section with the
//! same throwaway values `attome-config`'s own `minimal_valid_config` test
//! fixture uses (proven to deserialize), just to satisfy the type. Tests that
//! only need a client for one bucket use [`target`] instead.

use attome_config::{AppConfig, S3Target};

pub(crate) fn test_config(bucket: &str, endpoint: &str) -> AppConfig {
    test_config_with_public_endpoint(bucket, endpoint, "")
}

pub(crate) fn test_config_with_public_endpoint(
    bucket: &str,
    endpoint: &str,
    public_endpoint: &str,
) -> AppConfig {
    test_config_with_storage(serde_json::json!({
        "s3_endpoint": endpoint, "s3_public_endpoint": public_endpoint,
        "s3_region": "us-east-1",
        "s3_access_key": "test-access-key", "s3_secret_key": "test-secret-key",
        "s3_bucket": bucket
    }))
}

/// Z6-T1: the same throwaway configuration with `storage` set to `storage`.
pub(crate) fn test_config_with_storage(storage: serde_json::Value) -> AppConfig {
    let json = format!(
        r#"{{
            "app": {{
                "port": 0, "frontend_host": "localhost", "frontend_port": 4200,
                "log_level": "error", "threads": 1, "max_connection_num": 64,
                "max_connection_num_per_ip": 16, "idle_connection_timeout": 30,
                "keepalive_requests": 100, "static_files_cache_time": 0,
                "server_header_field": "test"
            }},
            "database": {{
                "host": "localhost", "port": 5555, "dbname": "test", "user": "test",
                "password": "test", "schema": "test", "connection_number": 1,
                "timeout": 5.0
            }},
            "cache": {{
                "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60
            }},
            "storage": {storage},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test",
                "apikey_hash_pepper": "test-only-throwaway-pepper-32-bytes-min"
            }},
            "rate_limit": {{ "anonymous_rpm": 100, "authenticated_rpm": 1000 }},
            "observability": {{
                "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
                "enable_distributed_tracing": false
            }},
            "email": {{
                "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
                "smtp_password": "", "smtp_from_address": "a@b.c",
                "smtp_from_name": "t", "smtp_use_tls": false,
                "queue_poll_seconds": 5, "max_retries": 1, "batch_size": 5
            }},
            "google_ai": {{
                "api_key": "test", "base_url": "http://localhost",
                "default_model": "test", "timeout_seconds": 5
            }}
        }}"#
    );
    serde_json::from_str(&json).expect("test config must deserialize")
}

/// An [`S3Target`] with throwaway credentials, for tests that build a client
/// directly with `create_storage_client_for`.
pub(crate) fn target<'a>(
    bucket: &'a str,
    endpoint: &'a str,
    public_endpoint: &'a str,
    verify_ssl: bool,
) -> S3Target<'a> {
    S3Target {
        endpoint,
        public_endpoint,
        region: "us-east-1",
        bucket,
        access_key: "test-access-key",
        secret_key: "test-secret-key",
        verify_ssl,
    }
}

// ── Metrics recorder for the BST-10 unit tests ─────────────────────────────

/// A minimal [`metrics::Recorder`] that keeps the last value of every gauge
/// and the running total of every counter.
///
/// `metrics-util`'s debugging recorder is the usual tool for this, but this
/// crate's `Cargo.toml` is outside the write surface, so this is the same
/// idea written out: install once per test binary, then compare a snapshot
/// taken before an operation with one taken after it (`cargo test` runs a
/// binary's tests in parallel, so absolute totals are not stable).
#[derive(Clone, Default)]
pub(crate) struct TestRecorder {
    counters: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    gauges: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, f64>>>,
}

impl TestRecorder {
    /// Installs (once per process) and returns the process-wide recorder.
    /// Later calls return the same one — `set_global_recorder` reports
    /// `AlreadySet` and that is fine.
    pub(crate) fn install() -> Self {
        static RECORDER: std::sync::OnceLock<TestRecorder> = std::sync::OnceLock::new();
        let recorder = RECORDER.get_or_init(TestRecorder::default).clone();
        let _ = metrics::set_global_recorder(recorder.clone());
        recorder
    }

    /// Running total for `name` (0 when the counter was never incremented).
    pub(crate) fn counter(&self, name: &str) -> u64 {
        self.counters
            .lock()
            .expect("test recorder lock")
            .get(name)
            .copied()
            .unwrap_or(0)
    }

    /// Last recorded value for `name`, or `None` when never set.
    pub(crate) fn gauge(&self, name: &str) -> Option<f64> {
        self.gauges
            .lock()
            .expect("test recorder lock")
            .get(name)
            .copied()
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

    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        metrics::Counter::from_arc(std::sync::Arc::new(TestCounter {
            name: key.name().to_string(),
            counters: self.counters.clone(),
        }))
    }

    fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::from_arc(std::sync::Arc::new(TestGauge {
            name: key.name().to_string(),
            gauges: self.gauges.clone(),
        }))
    }

    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        // No test here observes a histogram; the default no-op handle keeps
        // this recorder honest about that instead of pretending to store one.
        metrics::Histogram::noop()
    }
}

struct TestCounter {
    name: String,
    counters: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
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

struct TestGauge {
    name: String,
    gauges: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, f64>>>,
}

impl TestGauge {
    fn add(&self, delta: f64) {
        let mut gauges = self.gauges.lock().expect("test recorder lock");
        *gauges.entry(self.name.clone()).or_insert(0.0) += delta;
    }
}

impl metrics::GaugeFn for TestGauge {
    fn increment(&self, value: f64) {
        self.add(value);
    }

    fn decrement(&self, value: f64) {
        self.add(-value);
    }

    fn set(&self, value: f64) {
        self.gauges
            .lock()
            .expect("test recorder lock")
            .insert(self.name.clone(), value);
    }
}
