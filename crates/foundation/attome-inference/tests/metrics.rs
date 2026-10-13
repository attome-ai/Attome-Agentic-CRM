//! **BIN-FX2.** A recording `metrics::Recorder` sees exactly one latency sample
//! and one outcome count per call, with the right labels, for every Phase B
//! scenario — including an embedding whose two retries are still one call.
//!
//! One `#[tokio::test]` on purpose: the recorder is process-global, and the
//! scenarios compare totals before and after each call, which parallel tests
//! in the same binary would disturb.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use attome_config::{InferenceEndpoint, InferenceSection};
use attome_inference::telemetry::{CLASSES, ENDPOINTS, OUTCOMES, REQUEST_SECONDS, REQUESTS_TOTAL};
use attome_inference::testing::{FakeModelServer, Reply, http, json};
use attome_inference::{
    ChatMessage, EmbedKind, EmbeddingClient, GenerationClient, GenerationRequest,
};

type Store = Arc<Mutex<HashMap<String, u64>>>;

/// Counts counter increments and histogram samples per full key
/// (`name{label=value,...}`, labels sorted).
#[derive(Clone, Default)]
struct Recorder {
    counts: Store,
}

fn key_of(key: &metrics::Key) -> String {
    let mut labels: Vec<String> = key
        .labels()
        .map(|l| format!("{}={}", l.key(), l.value()))
        .collect();
    labels.sort();
    format!("{}{{{}}}", key.name(), labels.join(","))
}

struct Handle {
    key: String,
    counts: Store,
}

impl Handle {
    fn add(&self, n: u64) {
        if let Ok(mut counts) = self.counts.lock() {
            *counts.entry(self.key.clone()).or_default() += n;
        }
    }
}

impl metrics::CounterFn for Handle {
    fn increment(&self, value: u64) {
        self.add(value);
    }
    fn absolute(&self, _: u64) {}
}

impl metrics::HistogramFn for Handle {
    fn record(&self, _: f64) {
        self.add(1);
    }
}

impl metrics::Recorder for Recorder {
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
        metrics::Counter::from_arc(Arc::new(Handle {
            key: key_of(key),
            counts: self.counts.clone(),
        }))
    }
    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        key: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::from_arc(Arc::new(Handle {
            key: key_of(key),
            counts: self.counts.clone(),
        }))
    }
}

fn recorder() -> Recorder {
    static RECORDER: OnceLock<Recorder> = OnceLock::new();
    let recorder = RECORDER.get_or_init(Recorder::default).clone();
    let _ = metrics::set_global_recorder(recorder.clone());
    recorder
}

impl Recorder {
    fn snapshot(&self) -> HashMap<String, u64> {
        self.counts.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

/// What one call must have added: its counter series and its histogram series,
/// once each, and nothing else.
fn assert_one_call(
    before: &HashMap<String, u64>,
    after: &HashMap<String, u64>,
    scenario: &str,
    endpoint: &str,
    outcome: &str,
    class: &str,
) {
    assert!(
        ENDPOINTS.contains(&endpoint) && OUTCOMES.contains(&outcome) && CLASSES.contains(&class)
    );
    let counter =
        format!("{REQUESTS_TOTAL}{{class={class},endpoint={endpoint},outcome={outcome}}}");
    let histogram = format!("{REQUEST_SECONDS}{{endpoint={endpoint},outcome={outcome}}}");
    let mut delta: HashMap<&str, u64> = HashMap::new();
    for (key, value) in after {
        let added = value - before.get(key).copied().unwrap_or(0);
        if added > 0 {
            delta.insert(key.as_str(), added);
        }
    }
    let expected: HashMap<&str, u64> =
        HashMap::from([(counter.as_str(), 1), (histogram.as_str(), 1)]);
    assert_eq!(delta, expected, "scenario `{scenario}`");
}

fn section(server: &FakeModelServer, timeout_secs: u64) -> InferenceSection {
    let base = server.base_url();
    InferenceSection {
        generation: InferenceEndpoint {
            base_url: base.clone(),
            model: "test-model".into(),
            request_timeout_secs: timeout_secs,
            ..InferenceEndpoint::default()
        },
        embedding: InferenceEndpoint {
            base_url: base,
            model: "bge-m3".into(),
            request_timeout_secs: timeout_secs,
            ..InferenceEndpoint::default()
        },
        ..InferenceSection::default()
    }
}

const EMBED_OK: &str =
    "{\"data\":[{\"index\":0,\"embedding\":[0.5,0.25]}],\"usage\":{\"prompt_tokens\":4}}";
const CHAT_OK: &str = "{\"choices\":[{\"message\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}],\
    \"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}";

fn request() -> GenerationRequest {
    GenerationRequest::new(vec![ChatMessage::user("hello")])
}

async fn embed_scenario(
    rec: &Recorder,
    name: &str,
    replies: Vec<Reply>,
    timeout: u64,
    outcome: &str,
    class: &str,
) {
    let server = FakeModelServer::start(replies).await;
    let client = EmbeddingClient::new(&section(&server, timeout)).expect("embedding client");
    let before = rec.snapshot();
    let _ = client.embed(&["hi"], EmbedKind::Query).await;
    assert_one_call(&before, &rec.snapshot(), name, "embedding", outcome, class);
}

async fn generate_scenario(
    rec: &Recorder,
    name: &str,
    replies: Vec<Reply>,
    outcome: &str,
    class: &str,
) {
    let server = FakeModelServer::start(replies).await;
    let client = GenerationClient::new(&section(&server, 5)).expect("generation client");
    let before = rec.snapshot();
    let _ = client.generate(request()).await;
    assert_one_call(&before, &rec.snapshot(), name, "generation", outcome, class);
}

#[tokio::test]
async fn every_call_records_one_sample_with_its_outcome() {
    let rec = recorder();

    embed_scenario(
        &rec,
        "embedding success",
        vec![json(EMBED_OK)],
        5,
        "ok",
        "none",
    )
    .await;
    embed_scenario(
        &rec,
        "two retries then success is one call",
        vec![
            http(503, "Service Unavailable", &[], "no"),
            http(503, "Service Unavailable", &[], "no"),
            json(EMBED_OK),
        ],
        5,
        "ok",
        "none",
    )
    .await;
    embed_scenario(
        &rec,
        "401",
        vec![http(401, "Unauthorized", &[], "")],
        5,
        "upstream",
        "unauthorized",
    )
    .await;
    embed_scenario(
        &rec,
        "403",
        vec![http(403, "Forbidden", &[], "")],
        5,
        "upstream",
        "forbidden",
    )
    .await;
    embed_scenario(
        &rec,
        "429 past the deadline",
        vec![http(429, "Too Many Requests", &[("Retry-After", "60")], "")],
        1,
        "upstream",
        "rate_limited",
    )
    .await;
    embed_scenario(
        &rec,
        "400",
        vec![http(400, "Bad Request", &[], "")],
        5,
        "upstream",
        "client_error",
    )
    .await;
    embed_scenario(
        &rec,
        "500",
        vec![http(500, "Internal Server Error", &[], "")],
        5,
        "upstream",
        "server_error",
    )
    .await;
    embed_scenario(&rec, "stall", vec![Reply::Stall], 1, "timeout", "none").await;
    embed_scenario(
        &rec,
        "garbage body",
        vec![json("this is not json")],
        5,
        "bad_response",
        "none",
    )
    .await;

    // A refused connection: a port with nothing behind it.
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        let base = format!("http://{addr}/v1");
        let section = InferenceSection {
            embedding: InferenceEndpoint {
                base_url: base,
                model: "bge-m3".into(),
                // Windows spends ~2 s refusing a loopback connect; the
                // deadline must outlast the first attempt.
                request_timeout_secs: 5,
                ..InferenceEndpoint::default()
            },
            ..InferenceSection::default()
        };
        let client = EmbeddingClient::new(&section).expect("embedding client");
        let before = rec.snapshot();
        let _ = client.embed(&["hi"], EmbedKind::Query).await;
        assert_one_call(
            &before,
            &rec.snapshot(),
            "refused",
            "embedding",
            "transport",
            "none",
        );
    }

    generate_scenario(
        &rec,
        "generation success",
        vec![json(CHAT_OK)],
        "ok",
        "none",
    )
    .await;
    generate_scenario(
        &rec,
        "generation 503 is not retried",
        vec![http(503, "Service Unavailable", &[], "")],
        "upstream",
        "server_error",
    )
    .await;

    // A stream cancelled before its headers.
    {
        let server = FakeModelServer::start(vec![Reply::Stall]).await;
        let client = GenerationClient::new(&section(&server, 5)).expect("generation client");
        let before = rec.snapshot();
        let _ = client.generate_stream(request(), |_| {}, async {}).await;
        assert_one_call(
            &before,
            &rec.snapshot(),
            "cancel",
            "generation",
            "cancelled",
            "none",
        );
    }

    // The listing call is the third endpoint.
    {
        let server = FakeModelServer::start(vec![json("{\"data\":[{\"id\":\"m\"}]}")]).await;
        let http_client = attome_inference::DialClient::unchecked(
            reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("client"),
        );
        let before = rec.snapshot();
        let _ = attome_inference::list_models(&http_client, &server.base_url(), Default::default())
            .await;
        assert_one_call(&before, &rec.snapshot(), "listing", "models", "ok", "none");
    }

    // An empty embedding batch dials nothing and records nothing.
    {
        let server = FakeModelServer::start(vec![json(EMBED_OK)]).await;
        let client = EmbeddingClient::new(&section(&server, 5)).expect("embedding client");
        let before = rec.snapshot();
        let _ = client.embed(&[], EmbedKind::Query).await;
        assert_eq!(before, rec.snapshot(), "an empty batch is not a call");
        assert_eq!(server.accept_count(), 0);
    }
}
