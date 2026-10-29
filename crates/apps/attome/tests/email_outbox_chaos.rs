//! AB9-T6 (outbox half): the `SendEmail` worker killed after five sends
//! resumes without sending any message twice. A killed apalis worker leaves
//! its unfinished jobs to be delivered again, including the one whose send
//! it had already recorded; `run_send_email_job` sends only while the
//! message's `email_delivery` row is still `queued`, so a redelivered job
//! for a settled row sends nothing.
//!
//! Not provable here, and stated: a worker killed between the relay's
//! acceptance and the `sent` write leaves the row `queued`, and its
//! redelivery sends again (at least once, never lost). Only a provider-side
//! idempotency key could close that window.
//!
//! The sink is a local SMTP listener that records each accepted message's
//! recipient; nothing leaves the machine.
//!
//! ```powershell
//! cargo test -p attome --test email_outbox_chaos
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use attome_config::{AppConfig, EmailSection};
use attome_email::delivery::{self, EmailDeliveryKind};
use attome_testkit::skip_if_no_db;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use uuid::Uuid;

const MESSAGES: usize = 20;
const KILLED_AFTER: usize = 5;

fn test_config(port: u16) -> AppConfig {
    let json = r#"{
        "app": {
            "port": 0, "server_host": "127.0.0.1", "frontend_host": "localhost",
            "frontend_port": 4200, "log_level": "error", "threads": 1,
            "max_body_size_bytes": 1024, "request_timeout_secs": 5,
            "enable_session": true, "max_connection_num": 64,
            "max_connection_num_per_ip": 16, "use_gzip": false,
            "enable_compression": false, "gzip_level": 1, "br_level": 1,
            "idle_connection_timeout": 30, "keepalive_requests": 100,
            "static_files_cache_time": 0, "server_header_field": "attome-test"
        },
        "database": {
            "host": "localhost", "port": 5555, "dbname": "unused_overridden_by_env",
            "user": "unused", "password": "unused", "schema": "attome_dev",
            "connection_number": 5, "timeout": 5.0
        },
        "cache": {
            "host": "localhost", "port": 6379, "password": "",
            "db": 0, "connection_pool_size": 4, "timeout": 2000,
            "l1_cache_size_mb": 8, "l1_cache_ttl_seconds": 60,
            "metadata_registry_enabled": false
        },
        "storage": {
            "s3_endpoint": "http://localhost:9000", "s3_public_endpoint": "",
            "s3_region": "us-east-1", "s3_access_key": "test", "s3_secret_key": "test",
            "s3_bucket": "attome-test", "s3_use_path_style": true, "s3_verify_ssl": false
        },
        "auth": {
            "jwt_secret": "test-only-throwaway-secret-do-not-use-in-prod",
            "jwt_issuer": "attome-test", "jwt_expiry_hours": 1,
            "oauth_google_client_id": "", "oauth_google_client_secret": ""
        },
        "rate_limit": { "anonymous_rpm": 1000, "authenticated_rpm": 1000, "per_endpoint_limits": {} },
        "observability": {
            "metrics_port": 0, "log_sampling_rate": 1.0, "trace_sampling_rate": 1.0,
            "enable_distributed_tracing": false
        },
        "email": {
            "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
            "smtp_password": "", "smtp_from_address": "test@test.local",
            "smtp_from_name": "test", "smtp_use_tls": false,
            "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1
        },
        "google_ai": {
            "api_key": "", "base_url": "https://example.invalid",
            "default_model": "none", "timeout_seconds": 1
        },
        "llm_api": {},
        "external_api": {},
        "s2s": { "enabled": false },
        "security": { "bootstrap_admin_email": null }
    }"#;
    let mut config: AppConfig = attome_testkit::with_test_database(
        serde_json::from_str(json).expect("test_config JSON must deserialize into AppConfig"),
        true,
    );
    config.email = EmailSection {
        enabled: true,
        smtp_host: "127.0.0.1".to_string(),
        smtp_port: port,
        smtp_user: String::new(),
        smtp_password: String::new().into(),
        smtp_from_address: "noreply@example.invalid".to_string(),
        smtp_from_name: "Attome".to_string(),
        smtp_use_tls: None,
        tls_mode: Some("none".to_string()),
        test_mode_catch_all: None,
        providers: Default::default(),
        rate_limits: Default::default(),
        feedback: Default::default(),
        domain_check: Default::default(),
    };
    config
}

/// A fake relay: accepts every connection and message, recording the
/// recipient of each message it accepted.
async fn spawn_sink() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the SMTP sink");
    let port = listener.local_addr().expect("sink local addr").port();
    let accepted = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&accepted);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            tokio::spawn(async move {
                let (read_half, mut write_half) = stream.into_split();
                let _ = write_half.write_all(b"220 sink ESMTP\r\n").await;
                let mut lines = BufReader::new(read_half).lines();
                let mut in_data = false;
                let mut recipients: Vec<String> = Vec::new();
                while let Ok(Some(line)) = lines.next_line().await {
                    if in_data {
                        if line.trim_end() == "." {
                            in_data = false;
                            seen.lock().unwrap().append(&mut recipients);
                            let _ = write_half.write_all(b"250 OK queued\r\n").await;
                        }
                        continue;
                    }
                    let upper = line.to_ascii_uppercase();
                    let reply: &[u8] = if upper.starts_with("QUIT") {
                        let _ = write_half.write_all(b"221 bye\r\n").await;
                        break;
                    } else if upper.starts_with("RCPT TO:") {
                        let address = line[8..].trim().trim_matches(|c| c == '<' || c == '>');
                        recipients.push(address.to_ascii_lowercase());
                        b"250 OK\r\n"
                    } else if upper.starts_with("DATA") {
                        in_data = true;
                        b"354 end with <CRLF>.<CRLF>\r\n"
                    } else {
                        b"250 OK\r\n"
                    };
                    let _ = write_half.write_all(reply).await;
                }
            });
        }
    });
    (port, accepted)
}

/// A queued ledger row and its message, as a producer writes them.
async fn queued(db: &attome_db::DbPool, tag: &str, n: usize) -> (Uuid, attome_email::EmailMessage) {
    let id = Uuid::now_v7();
    let recipient = format!("outbox-chaos-{tag}-{n}@example.invalid");
    let mut tx = attome_db::tx::begin(db).await.expect("begin");
    delivery::record_queued_in_tx(
        &mut tx,
        id,
        EmailDeliveryKind::Generic,
        &recipient,
        "Hello",
        None,
        None,
        None,
    )
    .await
    .expect("record the queued row");
    tx.commit().await.expect("commit");
    let message = attome_email::EmailMessage {
        to: recipient,
        subject: format!("Hello {n}"),
        text_body: "body".to_string(),
        html_body: None,
        delivery_id: Some(id),
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
        stream: Default::default(),
        list_unsubscribe: None,
    };
    (id, message)
}

/// One delivery of a job, as the apalis worker runs it.
async fn deliver(config: &AppConfig, db: &attome_db::DbPool, message: attome_email::EmailMessage) {
    let task_id = format!("email-outbox-chaos-{}", Uuid::now_v7());
    tokio::time::timeout(
        Duration::from_secs(60),
        attome::jobs::run_send_email_job(db, config, message, 0, &task_id),
    )
    .await
    .expect("the arm finishes well inside the send deadline")
    .expect("an accepted message ends the job Ok");
}

#[tokio::test]
async fn email_outbox_resumes_without_duplicates() {
    let db = skip_if_no_db!(attome_testkit::migrated_pool(5).await);
    let (port, accepted) = spawn_sink().await;
    let config = test_config(port);
    let tag = Uuid::now_v7().simple().to_string()[20..].to_owned();
    let mut jobs = Vec::new();
    for n in 0..MESSAGES {
        jobs.push(queued(&db, &tag, n).await);
    }

    // The first worker sends five and is killed before the queue saw the
    // fifth job finish: jobs five to twenty are delivered again.
    for (_, message) in jobs.iter().take(KILLED_AFTER) {
        deliver(&config, &db, message.clone()).await;
    }
    assert_eq!(accepted.lock().unwrap().len(), KILLED_AFTER);

    // The restarted worker gets every unfinished job; at-least-once
    // delivery may hand it the finished ones too, so it gets all twenty.
    for (_, message) in &jobs {
        deliver(&config, &db, message.clone()).await;
    }

    let mut got = accepted.lock().unwrap().clone();
    assert_eq!(got.len(), MESSAGES, "each message sent once: {got:?}");
    got.sort();
    got.dedup();
    assert_eq!(got.len(), MESSAGES, "twenty distinct messages");
    for (id, message) in &jobs {
        let row = delivery::get_by_id(&db, *id)
            .await
            .expect("read the ledger row")
            .expect("the ledger row exists");
        assert_eq!(row.status, "sent", "{}", message.to);
    }
}
