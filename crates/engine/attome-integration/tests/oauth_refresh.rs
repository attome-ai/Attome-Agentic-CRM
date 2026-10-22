//! Z1-T11 against a real database and a local token endpoint: a refresh
//! stores the new tokens encrypted and a token about to expire is renewed;
//! a failed refresh records a masked reason and leaves the old token.
//!
//! The stub runs on loopback, which the production endpoint's address guard
//! refuses by design, so these tests post through a plain client
//! implementing the same [`TokenEndpoint`].
//!
//! ```powershell
//! $env:DATABASE_URL = "postgres://postgres:<pw>@localhost:5556/attomedb_test"
//! cargo test -p attome-integration --test oauth_refresh
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_integration::connection::Connection;
use attome_integration::credential::Credential;
use attome_integration::oauth::{
    TokenEndpoint, TokenFuture, access_token, parse_token_response, refresh,
};
use attome_integration::system::IntegrationSystem;
use attome_testkit::skip_if_no_db;
use axum::{Form, Router, http::StatusCode, response::IntoResponse, routing::post};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

async fn test_db() -> Option<DbPool> {
    let url = attome_testkit::migrated_db_url()?;
    Some(
        PgPoolOptions::new()
            .max_connections(3)
            .connect(&url)
            .await
            .expect("failed to connect to DATABASE_URL"),
    )
}

fn ring() -> KeyRing {
    KeyRing::single("cc".repeat(32))
}

/// A token endpoint on loopback. Each call answers the next access token
/// (`at-1`, `at-2`, …) and a rotated refresh token, or `401 invalid_client`
/// once `fail` is set.
#[derive(Clone, Default)]
struct Stub {
    calls: Arc<AtomicUsize>,
    fail: Arc<std::sync::atomic::AtomicBool>,
    last_grant: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

async fn start_stub(stub: Stub) -> String {
    let app = Router::new().route(
        "/token",
        post({
            let stub = stub.clone();
            move |Form(form): Form<Vec<(String, String)>>| {
                let stub = stub.clone();
                async move {
                    *stub.last_grant.lock().unwrap() = form;
                    if stub.fail.load(Ordering::SeqCst) {
                        return (
                            StatusCode::UNAUTHORIZED,
                            r#"{"error":"invalid_client","error_description":"secret s3cr3t wrong"}"#,
                        )
                            .into_response();
                    }
                    let n = stub.calls.fetch_add(1, Ordering::SeqCst) + 1;
                    (
                        StatusCode::OK,
                        format!(
                            r#"{{"access_token":"at-{n}","refresh_token":"rt-{n}","expires_in":3600}}"#
                        ),
                    )
                        .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}/token")
}

/// The same request the guarded endpoint sends, through a plain client.
struct PlainEndpoint(reqwest::Client);

impl TokenEndpoint for PlainEndpoint {
    fn request<'a>(
        &'a self,
        token_url: &'a str,
        form: Vec<(&'static str, String)>,
    ) -> TokenFuture<'a> {
        Box::pin(async move {
            let response = self.0.post(token_url).form(&form).send().await.unwrap();
            let status = response.status().as_u16();
            let body = response.bytes().await.unwrap();
            parse_token_response(status, &body)
        })
    }
}

fn connection(auth_type: &str, token_url: &str) -> (Connection, Option<String>) {
    let config = Some(format!(r#"{{"token_url":"{token_url}","scope":"api"}}"#));
    let system = IntegrationSystem {
        id: Uuid::now_v7(),
        name: format!("oauth-test-{}", Uuid::now_v7().simple()),
        kind: "rest".into(),
        base_url: "https://erp.example.com".into(),
        auth_type: auth_type.into(),
        credential_ref: None,
        rate_limit: None,
        status: "active".into(),
        health_last_ok_at: None,
        health_last_error: None,
        service_principal_ref: Uuid::nil().to_string(),
        config: config.clone(),
        row_version: 1,
    };
    (Connection::of(&system), config)
}

fn token_value(token: &Credential) -> String {
    token.with_value(str::to_owned)
}

#[tokio::test]
async fn refresh_before_expiry_updates_token() {
    let db = skip_if_no_db!(test_db().await);
    let stub = Stub::default();
    let url = start_stub(stub.clone()).await;
    let endpoint = PlainEndpoint(reqwest::Client::new());
    let (conn, config) = connection("oauth2_refresh_token", &url);
    let secret = Credential::for_test(
        r#"{"client_id":"cid","client_secret":"csecret","refresh_token":"rt-0"}"#,
    );

    // First use: no token yet, so one is fetched with the first refresh
    // token and stored encrypted.
    let token = access_token(&db, &ring(), &conn, config.as_deref(), &secret, &endpoint)
        .await
        .expect("first token");
    assert_eq!(token_value(&token), "at-1");
    let grant = stub.last_grant.lock().unwrap().clone();
    assert!(grant.contains(&("grant_type".into(), "refresh_token".into())));
    assert!(grant.contains(&("refresh_token".into(), "rt-0".into())));
    let (access, refresh_enc): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT access_token_encrypted, refresh_token_encrypted \
           FROM integration_oauth_token WHERE system_id = $1",
    )
    .bind(conn.id)
    .fetch_one(&db)
    .await
    .unwrap();
    let (access, refresh_enc) = (access.unwrap(), refresh_enc.unwrap());
    assert!(
        !access.contains("at-1") && !refresh_enc.contains("rt-1"),
        "stored encrypted"
    );

    // Still fresh: answered from the database, no call.
    let again = access_token(&db, &ring(), &conn, config.as_deref(), &secret, &endpoint)
        .await
        .unwrap();
    assert_eq!(token_value(&again), "at-1");
    assert_eq!(stub.calls.load(Ordering::SeqCst), 1);

    // About to expire (under a minute left): renewed, with the rotated
    // refresh token the provider sent last time.
    sqlx::query(
        "UPDATE integration_oauth_token SET expires_at = now() + interval '30 seconds' \
          WHERE system_id = $1",
    )
    .bind(conn.id)
    .execute(&db)
    .await
    .unwrap();
    let renewed = access_token(&db, &ring(), &conn, config.as_deref(), &secret, &endpoint)
        .await
        .unwrap();
    assert_eq!(token_value(&renewed), "at-2");
    let grant = stub.last_grant.lock().unwrap().clone();
    assert!(grant.contains(&("refresh_token".into(), "rt-1".into())));
    let (expires_ok, error): (bool, Option<String>) = sqlx::query_as(
        "SELECT expires_at > now() + interval '50 minutes', last_refresh_error \
           FROM integration_oauth_token WHERE system_id = $1",
    )
    .bind(conn.id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(expires_ok);
    assert_eq!(error, None);

    // Client credentials: no refresh token needed.
    let (cc, cc_config) = connection("oauth2_client_credentials", &url);
    let cc_secret = Credential::for_test(r#"{"client_id":"cid","client_secret":"csecret"}"#);
    let token = refresh(
        &db,
        &ring(),
        &cc,
        cc_config.as_deref(),
        &cc_secret,
        &endpoint,
    )
    .await
    .unwrap();
    assert_eq!(token_value(&token), "at-3");
    let grant = stub.last_grant.lock().unwrap().clone();
    assert!(grant.contains(&("grant_type".into(), "client_credentials".into())));
    assert!(grant.contains(&("scope".into(), "api".into())));
}

#[tokio::test]
async fn refresh_failure_records_error() {
    let db = skip_if_no_db!(test_db().await);
    let stub = Stub::default();
    let url = start_stub(stub.clone()).await;
    let endpoint = PlainEndpoint(reqwest::Client::new());
    let (conn, config) = connection("oauth2_client_credentials", &url);
    let secret = Credential::for_test(r#"{"client_id":"cid","client_secret":"csecret"}"#);
    let first = refresh(&db, &ring(), &conn, config.as_deref(), &secret, &endpoint)
        .await
        .unwrap();
    assert_eq!(token_value(&first), "at-1");

    stub.fail.store(true, Ordering::SeqCst);
    let err = refresh(&db, &ring(), &conn, config.as_deref(), &secret, &endpoint)
        .await
        .unwrap_err();
    assert!(!err.to_string().contains("s3cr3t"), "{err}");

    let (error, claim_cleared, access): (Option<String>, bool, Option<String>) = sqlx::query_as(
        "SELECT last_refresh_error, refresh_claimed_until IS NULL, access_token_encrypted \
           FROM integration_oauth_token WHERE system_id = $1",
    )
    .bind(conn.id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        error.as_deref(),
        Some("token endpoint answered 401 (invalid_client)")
    );
    assert!(
        claim_cleared,
        "a failed refresh frees the claim for the next try"
    );
    assert!(access.is_some(), "the old token is kept");

    // A live claim from another node: this node does not call the provider.
    stub.fail.store(false, Ordering::SeqCst);
    sqlx::query(
        "UPDATE integration_oauth_token \
            SET refresh_claimed_until = now() + interval '1 second', \
                expires_at = now() - interval '1 second' \
          WHERE system_id = $1",
    )
    .bind(conn.id)
    .execute(&db)
    .await
    .unwrap();
    let before = stub.calls.load(Ordering::SeqCst);
    let waited = refresh(&db, &ring(), &conn, config.as_deref(), &secret, &endpoint).await;
    assert!(
        waited.is_err(),
        "the other node's claim lapsed without a token"
    );
    assert_eq!(stub.calls.load(Ordering::SeqCst), before);
}
