//! Integration test for P-datastore-tls: Postgres `sslmode=verify-full`
//! actually works against a real TLS-enabled server, and a wrong CA is a
//! boot-time connection refusal (fail-closed, D-038), not a silent
//! plaintext/unverified fallback.
//!
//! Requires a TLS-enabled Postgres reachable at `PG_TLS_TEST_HOST`/`_PORT`
//! (defaults 127.0.0.1:5557) with `PG_TLS_TEST_PASSWORD`, plus
//! `PG_TLS_TEST_CA_PATH` (the real CA that signed the server cert) and
//! `PG_TLS_TEST_WRONG_CA_PATH` (an unrelated CA, for the negative case).
//!
//! **This test does not need to be run by hand — and does not need openssl.**
//! `scripts/test-attome-db-tls.ps1` (attome-db plan 2.3) builds the whole PKI with
//! .NET, starts a uniquely named throwaway `pgvector/pgvector:pg18` on :5557
//! with `ssl=on`, exports the four `PG_TLS_TEST_*` variables below, runs this
//! target with `--ignored`, and always removes the container and its scratch
//! directory afterwards; it never touches `docker compose`:
//!
//! ```powershell
//! pwsh scripts/test-attome-db-tls.ps1
//! ```
//!
//! The manual recipe below is the fallback for a host where that script cannot
//! run. sqlx uses rustls, so the server certificate needs an `IP:127.0.0.1`
//! subjectAltName and the `serverAuth` usage, signed by a real CA
//! (`CA:TRUE`):
//!
//! ```powershell
//! $env:PG_TLS_TEST_CA_PATH = "C:\path\to\ca.crt"
//! $env:PG_TLS_TEST_WRONG_CA_PATH = "C:\path\to\wrong-ca.crt"
//! $env:PG_TLS_TEST_PASSWORD = "..."
//! cargo test -p attome-db --test tls -- --ignored
//! ```

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_config::AppConfig;

fn env_or_panic(key: &str) -> String {
    std::env::var(key)
        .unwrap_or_else(|_| panic!("set {key} to run the P-datastore-tls integration test"))
}

fn test_config(ssl_mode: &str, ssl_root_cert: Option<String>) -> AppConfig {
    let host = std::env::var("PG_TLS_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = std::env::var("PG_TLS_TEST_PORT")
        .unwrap_or_else(|_| "5557".into())
        .parse()
        .expect("PG_TLS_TEST_PORT must be a valid port number");
    let password = env_or_panic("PG_TLS_TEST_PASSWORD");

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
                "host": "{host}", "port": {port}, "dbname": "attomedb_tls",
                "user": "postgres", "password": "{password}", "schema": "public",
                "connection_number": 2, "timeout": 5.0,
                "ssl_mode": "{ssl_mode}"
                {ssl_root_cert_field}
            }},
            "cache": {{
                "host": "localhost", "port": 6379, "password": "", "db": 0,
                "connection_pool_size": 1, "timeout": 500, "l1_cache_size_mb": 1,
                "l1_cache_ttl_seconds": 60
            }},
            "storage": {{
                "s3_endpoint": "http://localhost:9000", "s3_region": "us-east-1",
                "s3_access_key": "test", "s3_secret_key": "test", "s3_bucket": "test"
            }},
            "auth": {{
                "jwt_secret": "test-only-throwaway-secret-32-bytes-min", "jwt_issuer": "test"
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
        }}"#,
        ssl_root_cert_field = match &ssl_root_cert {
            Some(path) => format!(r#", "ssl_root_cert": "{}""#, path.replace('\\', "\\\\")),
            None => String::new(),
        }
    );
    serde_json::from_str(&json).expect("test config must deserialize")
}

#[tokio::test]
#[ignore = "requires a TLS-enabled Postgres server; see this file's header for setup"]
async fn verify_full_with_the_real_ca_connects_and_is_actually_encrypted() {
    let ca_path = env_or_panic("PG_TLS_TEST_CA_PATH");
    let config = test_config("verify-full", Some(ca_path));

    let pool = attome_db::create_pool(&config)
        .await
        .expect("verify-full with the real CA must connect");

    let (ssl, version): (bool, Option<String>) =
        sqlx::query_as("SELECT ssl, version FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
            .fetch_one(&pool)
            .await
            .expect("pg_stat_ssl query must succeed");

    assert!(
        ssl,
        "connection must actually be TLS-encrypted, not just requested"
    );
    assert!(version.is_some(), "a real TLS version must be reported");
}

#[tokio::test]
#[ignore = "requires a TLS-enabled Postgres server; see this file's header for setup"]
async fn verify_full_with_the_wrong_ca_is_a_connection_refusal() {
    let wrong_ca_path = env_or_panic("PG_TLS_TEST_WRONG_CA_PATH");
    let config = test_config("verify-full", Some(wrong_ca_path));

    let err = match attome_db::create_pool(&config).await {
        Ok(_) => panic!(
            "a CA that didn't sign the server's cert must refuse the connection, not silently \
             succeed or fall back to plaintext"
        ),
        Err(err) => err,
    };
    // The refusal must be the certificate check itself, not an unrelated
    // failure (a wrong password, an unreachable host) that would let this test
    // pass without proving anything about verify-full. sqlx 0.8 with rustls
    // surfaces a failed handshake as `Error::Tls`, or as `Error::Io` wrapping
    // rustls' "invalid peer certificate: UnknownIssuer".
    let is_certificate_refusal = match &err {
        sqlx::Error::Tls(_) => true,
        sqlx::Error::Io(io) => {
            let msg = io.to_string().to_ascii_lowercase();
            msg.contains("certificate") || msg.contains("unknownissuer")
        }
        _ => false,
    };
    assert!(
        is_certificate_refusal,
        "the connection must be refused by certificate verification, got: {err:?}"
    );
}
