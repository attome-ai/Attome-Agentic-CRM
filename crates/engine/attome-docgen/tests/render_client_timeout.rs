//! Regression proof for guidelines §10's "a hung external call must fail
//! closed, never block indefinitely" applied to
//! `attome_docgen::render_client::render_pdf` (M57 Phase 1, D-463): a render
//! sidecar that accepts the connection but never responds must make the
//! call fail with an error inside the configured timeout, not hang forever
//! or block the calling worker.
//!
//! No real render sidecar or Docker Chrome pair needed — a bare TCP
//! listener that never writes a response is enough to exercise the actual
//! failure mode this module exists to bound.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

fn test_config(
    render_service_url: String,
    request_timeout_secs: u64,
) -> attome_config::DocgenSection {
    attome_config::DocgenSection {
        render_service_url,
        request_timeout_secs,
        max_response_bytes: 25_000_000,
        max_html_bytes: 5_000_000,
    }
}

#[tokio::test]
async fn a_sidecar_that_never_responds_fails_within_the_configured_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a local test listener");
    let addr = listener.local_addr().unwrap();

    // Accepts the connection and reads the request so the client's write
    // side doesn't error out, then simply never writes a response —
    // simulating a wedged/overloaded render sidecar.
    let accept_task = tokio::spawn(async move {
        if let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            // Best-effort drain of the request; ignore errors/EOF.
            let _ = socket.read(&mut buf).await;
            // Hold the connection open without responding until the test's
            // own timeout races us out — the client-side timeout below is
            // what this test is actually proving.
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    let config = test_config(format!("http://{addr}"), 1);
    let started = Instant::now();
    let result =
        attome_docgen::render_client::render_pdf(&config, "<html></html>", "A4", None).await;
    let elapsed = started.elapsed();

    accept_task.abort();

    assert!(
        result.is_err(),
        "a render against a sidecar that never responds must fail, not succeed"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "render_pdf must fail close to the configured 1s timeout, not hang \
         indefinitely — took {elapsed:?}"
    );
}
