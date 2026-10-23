//! AB6-T4: object store calls go through `attome_outbound`. A stub S3 answers
//! the first GET with 503 and the second with the object; the store's own
//! retries are off, so the one retry is the outbound layer's.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use attome_config::S3Target;
use object_store::ObjectStoreExt;
use object_store::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A stub S3: the first `fail` requests get 503, the rest the object.
async fn stub_s3(fail: usize, seen: Arc<AtomicUsize>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 2048];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let n = seen.fetch_add(1, Ordering::SeqCst);
                let response = if n < fail {
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                } else {
                    let body = "hello";
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"e1\"\r\n\
                         Last-Modified: Thu, 22 Oct 2026 10:00:00 GMT\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn storage_get_retries_once_on_503() {
    let seen = Arc::new(AtomicUsize::new(0));
    let addr = stub_s3(1, seen.clone()).await;
    let endpoint = format!("http://{addr}");
    let client = attome_storage::create_storage_client_for(
        S3Target {
            endpoint: &endpoint,
            public_endpoint: "",
            region: "us-east-1",
            bucket: "outbound-test",
            access_key: "test-access-key",
            secret_key: "test-secret-key",
            verify_ssl: false,
        },
        "test",
    )
    .await
    .expect("client");

    let body = client
        .store()
        .get(&Path::from("k.txt"))
        .await
        .expect("the retry gets the object")
        .bytes()
        .await
        .expect("body");
    assert_eq!(&body[..], b"hello");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        2,
        "one 503, then one retry by the outbound layer, and no retries of the store's own"
    );
}
