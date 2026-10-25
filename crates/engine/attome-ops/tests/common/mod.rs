//! Shared helpers for the ops engine's tests (AB4-T1).
#![allow(dead_code, reason = "each test binary uses a different subset")]
#![allow(
    clippy::expect_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::net::SocketAddr;

/// Serves `router` on a free local port in a spawned task and answers the
/// address: a stand-in for a Patroni node or any HTTP dependency.
pub async fn fake_http(router: axum::Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a local port");
    let addr = listener.local_addr().expect("the bound address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    addr
}
