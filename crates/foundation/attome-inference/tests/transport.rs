//! Socket-level tests: a real `TcpListener`, the real clients, real timeouts.
//!
//! Every assertion here is about bytes on a wire rather than a function's
//! return value — the plan's Phase B/C acceptance (BIN-B2, BIN-C1, BIN-C2,
//! BIN-E2) and the socket half of BIN-A2's tool-call cap. The server is the
//! shared `attome_inference::testing::FakeModelServer` (BIN-B1), the same one
//! every consumer's tests can use.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::net::SocketAddr;
use std::time::Duration;

use attome_config::{InferenceEndpoint, InferenceSection};
use attome_inference::generate::{GenerationClient, GenerationRequest};
use attome_inference::testing::{FakeModelServer, Reply, http, json, sse_event, sse_head};
use attome_inference::{ChatMessage, EmbedKind, EmbeddingClient, InferenceError, UpstreamClass};

/// Q21-T1: a client for the fake model server, which listens on loopback.
fn loopback_client() -> attome_outbound::http::Outbound {
    let purpose = attome_outbound::http::Purpose::public("test").with_private_hosts(["127.0.0.1"]);
    attome_outbound::http::client(purpose, |b| b.timeout(Duration::from_secs(5)))
        .expect("a loopback client")
}

/// attome-server B5: a checked client's precheck runs before the listing and
/// before a caller-built generation client is usable; a refused loopback
/// literal never reaches the socket.
#[tokio::test]
async fn a_checked_dial_client_refuses_a_loopback_literal_before_dialing() {
    let server = FakeModelServer::start(vec![json("{\"data\":[]}")]).await;
    let refuse_loopback = |url: &reqwest::Url| {
        !url.host_str()
            .and_then(|host| host.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
    };
    let http = attome_inference::DialClient::checked(loopback_client(), refuse_loopback);

    let listing = attome_inference::list_models(
        &http,
        &server.base_url(),
        attome_inference::ModelListAuth::default(),
    )
    .await;
    assert!(
        matches!(listing, Err(InferenceError::Transport { .. })),
        "{listing:?}"
    );

    let endpoint = InferenceEndpoint {
        base_url: server.base_url(),
        model: "m".into(),
        ..InferenceEndpoint::default()
    };
    let generation = GenerationClient::for_endpoint(endpoint, 16, http);
    assert!(matches!(generation, Err(InferenceError::Transport { .. })));
    assert_eq!(server.accept_count(), 0, "nothing may be dialled");
}

/// **BIN-FX4/BIN-D3.** The listing call is the transport's now, over a client
/// the caller built — the same masking and the same capped read as any other
/// call.
#[tokio::test]
async fn a_model_listing_arrives_over_a_socket() {
    let body = "{\"data\":[{\"id\":\"m1\",\"name\":\"Model One\"}]}";
    let server = FakeModelServer::start(vec![json(body)]).await;
    let http = attome_inference::DialClient::unchecked(loopback_client());
    let listings = attome_inference::list_models(
        &http,
        &server.base_url(),
        attome_inference::ModelListAuth::default(),
    )
    .await
    .expect("a model listing");
    assert_eq!(listings.len(), 1);
    assert_eq!(listings[0].id, "m1");
    assert_eq!(listings[0].display_name.as_deref(), Some("Model One"));
    assert!(server.last_request().contains("GET /v1/models"));
}

/// A listing call is classified and refused exactly like every other call.
#[tokio::test]
async fn a_failed_model_listing_is_classified() {
    let server = FakeModelServer::start(vec![http(401, "Unauthorized", &[], "no")]).await;
    let http = attome_inference::DialClient::unchecked(loopback_client());
    let error = attome_inference::list_models(
        &http,
        &server.base_url(),
        attome_inference::ModelListAuth::default(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            error,
            InferenceError::Upstream {
                class: UpstreamClass::Unauthorized,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 1);
}

/// A section whose generation and embedding endpoints both point at `server`.
fn section(server: &FakeModelServer, timeout_secs: u64) -> InferenceSection {
    section_for(server.addr(), timeout_secs)
}

const EMBED_OK: &str =
    "{\"data\":[{\"index\":0,\"embedding\":[0.5,0.25,0.125]}],\"usage\":{\"prompt_tokens\":4}}";

/// The same, for an address with no server behind it.
fn section_for(addr: SocketAddr, timeout_secs: u64) -> InferenceSection {
    let base = format!("http://{addr}/v1");
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

fn embedding_client(server: &FakeModelServer, timeout_secs: u64) -> EmbeddingClient {
    EmbeddingClient::new(&section(server, timeout_secs)).expect("a loopback embedding client")
}

fn generation_client(server: &FakeModelServer, timeout_secs: u64) -> GenerationClient {
    GenerationClient::new(&section(server, timeout_secs)).expect("a loopback generation client")
}

fn stream_request() -> GenerationRequest {
    GenerationRequest::new(vec![ChatMessage::user("hello")])
}

/// The baseline BIN-B2 characterises: a real socket, a real scripted answer,
/// deltas as they arrive, and the assembled result a non-streaming call would
/// have returned.
#[tokio::test]
async fn a_streamed_answer_arrives_over_a_socket() {
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n\
        data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
        data: [DONE]\n\n";
    let server = FakeModelServer::start(vec![json(body)]).await;
    let client = generation_client(&server, 5);
    let mut deltas: Vec<String> = Vec::new();
    let result = client
        .generate_stream(
            stream_request(),
            |delta| deltas.push(delta.to_owned()),
            std::future::pending::<()>(),
        )
        .await
        .expect("a streamed answer");
    assert_eq!(result.text, "hi");
    assert_eq!(deltas, vec!["hi".to_owned()]);
    assert_eq!(server.request_count(), 1);
    assert!(server.last_request().contains("\"stream\":true"));
}

/// The embedding half of the same baseline, including the wire body.
#[tokio::test]
async fn an_embedding_arrives_over_a_socket() {
    let server = FakeModelServer::start(vec![json(EMBED_OK)]).await;
    let client = embedding_client(&server, 5);
    let (vectors, usage) = client
        .embed(&["hello"], EmbedKind::Document)
        .await
        .expect("an embedding answer");
    assert_eq!(vectors, vec![vec![0.5, 0.25, 0.125]]);
    assert_eq!(usage.prompt_tokens, 4);
    assert_eq!(server.request_count(), 1);
    assert!(server.last_request().contains("/v1/embeddings"));
}

/// **BIN-E2 / D-645.** Two transient failures and then success: exactly three
/// requests, and the answer is the third one's.
#[tokio::test]
async fn an_embedding_retries_two_transient_failures_then_succeeds() {
    let server = FakeModelServer::start(vec![
        http(503, "Service Unavailable", &[], "no"),
        http(503, "Service Unavailable", &[], "no"),
        json(EMBED_OK),
    ])
    .await;
    let client = embedding_client(&server, 5);
    let (vectors, _) = client
        .embed(&["hello"], EmbedKind::Document)
        .await
        .expect("the third attempt succeeds");
    assert_eq!(vectors.len(), 1);
    assert_eq!(
        server.request_count(),
        3,
        "the original plus D-645's two retries, and no more"
    );
}

/// The retry budget is finite: the fourth attempt is never made.
#[tokio::test]
async fn an_embedding_gives_up_after_exactly_three_attempts() {
    let server = FakeModelServer::start(vec![http(503, "Service Unavailable", &[], "no")]).await;
    let client = embedding_client(&server, 5);
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    assert!(
        matches!(
            error,
            InferenceError::Upstream {
                class: UpstreamClass::ServerError { retryable: true },
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 3);
}

/// A rejected request is not a transient one, however much it looks like it.
#[tokio::test]
async fn a_client_error_is_not_retried() {
    let server = FakeModelServer::start(vec![http(400, "Bad Request", &[], "bad")]).await;
    let client = embedding_client(&server, 5);
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    assert!(
        matches!(
            error,
            InferenceError::Upstream {
                class: UpstreamClass::ClientError,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 1);
}

/// A 5xx that is not a restart carries no retry: a 500 from a broken handler
/// would fail identically on the replay.
#[tokio::test]
async fn a_plain_server_error_is_not_retried() {
    let server =
        FakeModelServer::start(vec![http(500, "Internal Server Error", &[], "boom")]).await;
    let client = embedding_client(&server, 5);
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    assert!(
        matches!(
            error,
            InferenceError::Upstream {
                class: UpstreamClass::ServerError { retryable: false },
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 1);
}

/// **BIN-E1/BIN-E2.** The server's own hint is honoured, but a wait that would
/// cross the deadline is not attempted at all — so this fails immediately with
/// the class intact rather than sleeping the 60 seconds it asked for.
#[tokio::test]
async fn a_retry_after_beyond_the_deadline_fails_immediately() {
    let server = FakeModelServer::start(vec![http(
        429,
        "Too Many Requests",
        &[("Retry-After", "60")],
        "slow down",
    )])
    .await;
    let client = embedding_client(&server, 1);
    let started = std::time::Instant::now();
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    assert_eq!(
        server.request_count(),
        1,
        "a wait beyond the whole-request bound must not be attempted"
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    match error {
        InferenceError::Upstream {
            class: UpstreamClass::RateLimited { retry_after },
            ..
        } => assert_eq!(retry_after, Some(Duration::from_secs(60))),
        other => panic!("expected a rate-limit class, got {other:?}"),
    }
}

/// **D-553/D-645.** Generation is never replayed at the transport: a retry can
/// mint new tool-call ids and double-spend one grant.
#[tokio::test]
async fn generation_is_never_retried_at_the_transport() {
    let server = FakeModelServer::start(vec![http(503, "Service Unavailable", &[], "no")]).await;
    let client = generation_client(&server, 5);
    let error = client.generate(stream_request()).await.unwrap_err();
    assert!(
        matches!(error, InferenceError::Upstream { .. }),
        "{error:?}"
    );
    assert_eq!(
        server.request_count(),
        1,
        "generation must never be retried at the transport"
    );
}

/// **BIN-C1.** A redirect is refused, and the host it points at is never
/// dialled: the second listener sees zero connections. This is the socket-half
/// of `S4` — a prompt cannot be moved by a 307.
#[tokio::test]
async fn a_redirect_is_refused_and_the_target_is_never_dialled() {
    let target = FakeModelServer::start(vec![json(EMBED_OK)]).await;
    let location = format!("{}/embeddings", target.base_url());
    let source = FakeModelServer::start(vec![http(
        307,
        "Temporary Redirect",
        &[("Location", location.as_str())],
        "",
    )])
    .await;
    let client = embedding_client(&source, 5);
    let error = client
        .embed(&["secret"], EmbedKind::Query)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, InferenceError::BadResponse { reason, .. } if *reason == "redirect refused"),
        "{error:?}"
    );
    assert_eq!(source.request_count(), 1, "a redirect must not be followed");
    assert_eq!(
        target.accept_count(),
        0,
        "the redirect target must receive nothing at all"
    );
}

/// **BIN-C2.** A body larger than the cap is refused before it is buffered.
#[tokio::test]
async fn an_over_cap_body_is_refused() {
    let declared = attome_inference::MAX_BODY_BYTES + 1;
    let raw = format!(
        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {declared}\r\n\r\n{}",
        "x".repeat(64)
    );
    let server = FakeModelServer::start(vec![Reply::Raw(raw)]).await;
    let client = embedding_client(&server, 5);
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    assert!(
        matches!(&error, InferenceError::BadResponse { reason, .. } if reason.contains("size cap")),
        "{error:?}"
    );
}

/// **BIN-C3.** A server that accepts the connection and then says nothing is a
/// timeout, not a hang.
#[tokio::test]
async fn a_stalled_server_times_out() {
    let server = FakeModelServer::start(vec![Reply::Stall]).await;
    let client = embedding_client(&server, 1);
    let started = std::time::Instant::now();
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    assert!(
        matches!(error, InferenceError::Timeout("embedding")),
        "{error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// **D-645.** Every attempt shares one deadline: a retry after a slow 503 gets
/// only what is left of it, not a fresh request timeout of its own.
#[tokio::test]
async fn a_retry_cannot_outlive_the_request_deadline() {
    let Reply::Raw(unavailable) = http(503, "Service Unavailable", &[], "no") else {
        unreachable!("http() builds a raw reply");
    };
    let server = FakeModelServer::start(vec![
        Reply::Delayed(Duration::from_millis(1500), unavailable),
        Reply::Stall,
    ])
    .await;
    let client = embedding_client(&server, 2);
    let started = std::time::Instant::now();
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    let elapsed = started.elapsed();
    // The cut-off retry reports the 503 that caused it.
    assert!(
        matches!(
            error,
            InferenceError::Upstream {
                class: UpstreamClass::ServerError { retryable: true },
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(
        server.request_count(),
        2,
        "the retry was sent, then cut off"
    );
    // Without the shared deadline this is ~1.5 s + backoff + a fresh 2 s.
    assert!(
        elapsed < Duration::from_millis(2800),
        "took {elapsed:?} against a 2 s bound"
    );
}

/// A closed port is a transport failure, and it is one of the outcomes D-645
/// permits a replay for.
#[tokio::test]
async fn an_unreachable_server_is_a_transport_failure() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    drop(listener);
    let client = EmbeddingClient::new(&section_for(addr, 5)).expect("a loopback client");
    let error = client.embed(&["hi"], EmbedKind::Query).await.unwrap_err();
    assert!(
        matches!(error, InferenceError::Transport { .. }),
        "{error:?}"
    );
}

/// **BIN-B2, cancellation.** A Stop before the headers resolves as `Cancelled`
/// immediately, and the request is dropped rather than awaited.
#[tokio::test]
async fn a_cancel_before_headers_returns_cancelled() {
    let server = FakeModelServer::start(vec![Reply::Stall]).await;
    let client = generation_client(&server, 5);
    let started = std::time::Instant::now();
    let error = client
        .generate_stream(stream_request(), |_| {}, async {})
        .await
        .unwrap_err();
    assert!(
        matches!(error, InferenceError::Cancelled("generation")),
        "{error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

/// **BIN-A2 at the socket.** The `usize::MAX` unit test proves the arithmetic;
/// this proves a real server's `index` cannot grow the assembler.
#[tokio::test]
async fn a_streamed_tool_call_index_beyond_the_cap_is_refused() {
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":\
        [{\"index\":5000,\"id\":\"c\",\"function\":{\"name\":\"n\",\"arguments\":\"{}\"}}]}}]}\n\n\
        data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
        data: [DONE]\n\n";
    let server = FakeModelServer::start(vec![json(body)]).await;
    let client = generation_client(&server, 5);
    let error = client
        .generate_stream(stream_request(), |_| {}, std::future::pending::<()>())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, InferenceError::BadResponse { reason, .. } if reason.contains("tool-call index")),
        "{error:?}"
    );
}

/// **A-83 over the wire.** A stream that ends before the model said why is an
/// error, not a short answer.
#[tokio::test]
async fn a_stream_without_a_finish_reason_is_an_error() {
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n";
    let server = FakeModelServer::start(vec![json(body)]).await;
    let client = generation_client(&server, 5);
    let error = client
        .generate_stream(stream_request(), |_| {}, std::future::pending::<()>())
        .await
        .unwrap_err();
    assert!(
        matches!(&error, InferenceError::BadResponse { reason, .. } if reason.contains("before the model finished")),
        "{error:?}"
    );
}

/// **BIN-B2, cancellation mid-stream.** A Stop after the first delta resolves
/// as `Cancelled` within 100 ms, and the server sees the connection close —
/// the generation is abandoned on the wire, not just ignored locally.
#[tokio::test]
async fn a_cancel_mid_stream_returns_cancelled_and_closes_the_connection() {
    let first = sse_event("{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}");
    let server = FakeModelServer::start(vec![Reply::Chunks {
        pieces: vec![(Duration::ZERO, sse_head()), (Duration::ZERO, first)],
        hold: true,
    }])
    .await;
    let client = generation_client(&server, 5);
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel::<std::time::Instant>();
    let mut seen_tx = Some(seen_tx);
    let error = client
        .generate_stream(
            stream_request(),
            move |_| {
                if let Some(tx) = seen_tx.take() {
                    let _ = tx.send(std::time::Instant::now());
                }
            },
            async move {
                let _ = seen_rx.await;
            },
        )
        .await
        .unwrap_err();
    let cancelled_at = std::time::Instant::now();
    assert!(
        matches!(error, InferenceError::Cancelled("generation")),
        "{error:?}"
    );
    let deadline = cancelled_at + Duration::from_secs(2);
    while server.peer_close_count() == 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server.peer_close_count(),
        1,
        "the server saw the close within 2 s"
    );
}

/// The cancel itself is prompt: a stream the server never finishes is left
/// within 100 ms of the Stop, not at the idle bound.
#[tokio::test]
async fn a_cancel_mid_stream_is_prompt() {
    let first = sse_event("{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"partial\"}}]}");
    let server = FakeModelServer::start(vec![Reply::Chunks {
        pieces: vec![(Duration::ZERO, sse_head()), (Duration::ZERO, first)],
        hold: true,
    }])
    .await;
    let client = generation_client(&server, 5);
    let stop_at = std::sync::Arc::new(std::sync::Mutex::new(None::<std::time::Instant>));
    let stop_at_cancel = stop_at.clone();
    let error = client
        .generate_stream(stream_request(), |_| {}, async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            if let Ok(mut at) = stop_at_cancel.lock() {
                *at = Some(std::time::Instant::now());
            }
        })
        .await
        .unwrap_err();
    let returned = std::time::Instant::now();
    assert!(matches!(error, InferenceError::Cancelled(_)), "{error:?}");
    let stopped = stop_at
        .lock()
        .ok()
        .and_then(|at| *at)
        .expect("the stop fired");
    assert!(
        returned.duration_since(stopped) < Duration::from_millis(100),
        "cancel took {:?}",
        returned.duration_since(stopped)
    );
}

/// A server that closes half-way through an answer produced no answer: the
/// stream ends before a `finish_reason`, which is an error, never a short text.
#[tokio::test]
async fn a_server_closing_mid_stream_is_an_error() {
    let first = sse_event("{\"choices\":[{\"index\":0,\"delta\":{\"content\":\"half an ans\"}}]}");
    let server = FakeModelServer::start(vec![Reply::Chunks {
        pieces: vec![(Duration::ZERO, sse_head()), (Duration::ZERO, first)],
        hold: false,
    }])
    .await;
    let client = generation_client(&server, 5);
    let error = client
        .generate_stream(stream_request(), |_| {}, std::future::pending::<()>())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            InferenceError::BadResponse { .. } | InferenceError::Transport { .. }
        ),
        "{error:?}"
    );
}
