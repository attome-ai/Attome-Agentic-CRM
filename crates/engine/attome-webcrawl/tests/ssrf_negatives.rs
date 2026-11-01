//! K6-T13: every way a website source could point the crawler at a private
//! address is refused: a sitemap on the cloud metadata address, a linked
//! document on a private network, and a redirect from the source's own
//! allowed intranet host to localhost. No database: these are the fetch
//! contract's own checks (`attome_webcrawl::safety`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_webcrawl::safety::{self, SourceAccess};
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const AGENT: &str = "attome-test";

/// One HTTP server on loopback that redirects every request to `location`.
async fn redirector(location: String) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let reply = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = socket.write_all(reply.as_bytes()).await;
        }
    });
    port
}

#[tokio::test]
async fn every_private_target_refused() {
    let none = SourceAccess::default();

    // A sitemap on the cloud metadata address.
    let sitemap = Url::parse("http://169.254.169.254/latest/meta-data/sitemap.xml").unwrap();
    let checked = safety::validate_url(&sitemap).await;
    assert!(checked.is_err(), "metadata sitemap: {checked:?}");
    let client = safety::build_client_for(2, &none).expect("client");
    let fetched = safety::fetch_bytes(&client, &sitemap, 1024, AGENT, None, None, &none).await;
    assert!(
        fetched.is_err(),
        "metadata sitemap fetched: {:?}",
        fetched.map(|_| ())
    );

    // A linked document on a private network.
    let document = Url::parse("http://10.0.0.1/annual-report.pdf").unwrap();
    let fetched = safety::fetch_bytes(&client, &document, 1024, AGENT, None, None, &none).await;
    assert!(
        fetched.is_err(),
        "private document fetched: {:?}",
        fetched.map(|_| ())
    );

    // A redirect from the source's own allowed intranet host to localhost:
    // the first hop is allowed, the redirect is not.
    let port = redirector("http://localhost:9/secret".to_owned()).await;
    let intranet = SourceAccess {
        allow_host: Some("127.0.0.1".to_owned()),
        ..SourceAccess::default()
    };
    let client = safety::build_client_for(2, &intranet).expect("client");
    let start = Url::parse(&format!("http://127.0.0.1:{port}/wiki")).unwrap();
    let fetched = safety::fetch_bytes(&client, &start, 1024, AGENT, None, None, &intranet).await;
    assert!(
        fetched.is_err(),
        "redirect to localhost followed: {:?}",
        fetched.map(|_| ())
    );
    let localhost = Url::parse("http://localhost:9/secret").unwrap();
    assert!(
        safety::validate_url_for(&localhost, &intranet)
            .await
            .is_err(),
        "localhost is not the allowed host"
    );
}
