//! AB4-T1: the shared fake HTTP server answers what its router says.
#![allow(
    clippy::expect_used,
    reason = "test: a failed step should panic with its message"
)]

mod common;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn ops_fake_http_serves_the_router() {
    let router = axum::Router::new().route("/cluster", axum::routing::get(|| async { "leader" }));
    let addr = common::fake_http(router).await;
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    stream
        .write_all(b"GET /cluster HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.expect("read");
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("leader"), "{answer}");
}
