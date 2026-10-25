//! BEM-9 (attome-email plan, Phase P3) — the `SendEmail` job arm against the
//! delivery ledger: every relay outcome leaves `email_delivery`
//! in the state §4.2's disposition table names, and only a transient outcome
//! asks apalis for a retry. Drives `attome::jobs::run_send_email_job` directly
//! (no apalis worker) against a scripted SMTP peer, the same raw-listener
//! shape as `attome-email/tests/smtp_classification.rs`.
//!
//! Not here: the post-DATA stall → `unknown` row. `send`'s deadline is a
//! fixed 120 s, so that case is covered by `attome-email`'s own sender unit test
//! (short deadline) plus the disposition-table unit test in `jobs.rs`.
//!
//! Requires a throwaway test database with the workspace migrations applied.
//!
//! ```powershell
//! cargo test -p server --test email_job_ledger -- --test-threads=1
//! ```

#![recursion_limit = "512"]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::time::Duration;

use attome_config::{AppConfig, EmailSection};
use attome_email::delivery::{self, EmailDeliveryKind};
use attome_testkit::skip_if_no_db;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use uuid::Uuid;

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
    };
    config
}

/// One scripted reply per matched command; `=.` answers the DATA terminator.
type Step = (&'static str, &'static str);

async fn spawn_peer(steps: Vec<Step>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the scripted SMTP peer");
    let port = listener.local_addr().expect("peer local addr").port();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read_half, mut write_half) = stream.into_split();
        let _ = write_half.write_all(b"220 scripted ESMTP\r\n").await;
        let mut lines = BufReader::new(read_half).lines();
        let mut in_data = false;
        while let Ok(Some(line)) = lines.next_line().await {
            if line.starts_with("QUIT") {
                let _ = write_half.write_all(b"221 bye\r\n").await;
                break;
            }
            if in_data {
                if line.trim_end() == "." {
                    in_data = false;
                    let reply = steps
                        .iter()
                        .find(|(needle, _)| *needle == "=.")
                        .map_or("250 OK\r\n", |(_, reply)| *reply);
                    let _ = write_half.write_all(reply.as_bytes()).await;
                }
                continue;
            }
            let reply = steps
                .iter()
                .find(|(needle, _)| *needle != "=." && line.contains(needle))
                .map_or("250 OK\r\n", |(_, reply)| *reply);
            let _ = write_half.write_all(reply.as_bytes()).await;
            if line.starts_with("DATA") && reply.starts_with("354") {
                in_data = true;
            }
        }
    });
    port
}

const DATA: Step = ("DATA", "354 end with <CRLF>.<CRLF>\r\n");

async fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let port = listener.local_addr().expect("probe local addr").port();
    drop(listener);
    port
}

async fn test_pool() -> Option<attome_db::DbPool> {
    attome_testkit::migrated_pool(5).await
}

/// A queued ledger row and the message that carries its id.
async fn queued(db: &attome_db::DbPool) -> (Uuid, attome_email::EmailMessage) {
    let id = Uuid::now_v7();
    let recipient = attome_testkit::unique_email("email-job-ledger");
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
        subject: "Hello".to_string(),
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
    };
    (id, message)
}

async fn row(db: &attome_db::DbPool, id: Uuid) -> delivery::EmailDeliveryRow {
    delivery::get_by_id(db, id)
        .await
        .expect("read the ledger row")
        .expect("the ledger row exists")
}

/// A task id no `apalis.jobs` row has: `is_final_attempt` reads no budget,
/// so a transient outcome is always a retry.
fn no_task() -> String {
    format!("email-job-ledger-{}", Uuid::now_v7())
}

async fn run(
    config: &AppConfig,
    db: &attome_db::DbPool,
    message: attome_email::EmailMessage,
    attempt: usize,
    task_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tokio::time::timeout(
        Duration::from_secs(60),
        attome::jobs::run_send_email_job(db, config, message, attempt, task_id),
    )
    .await
    .expect("the arm finishes well inside the send deadline")
}

#[tokio::test]
async fn an_accepted_message_moves_queued_to_sent() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config(spawn_peer(vec![DATA]).await);
    let (id, message) = queued(&db).await;

    run(&config, &db, message, 0, &no_task())
        .await
        .expect("a sent message ends the job Ok");
    let row = row(&db, id).await;
    assert_eq!(row.status, "sent");
    assert!(row.sent_at.is_some());
}

#[tokio::test]
async fn two_transient_failures_then_a_send_end_sent_with_the_attempts_counted() {
    let db = skip_if_no_db!(test_pool().await);
    let (id, message) = queued(&db).await;
    let task = no_task();
    let refused = test_config(dead_port().await);

    for attempt in 0..2 {
        let outcome = run(&refused, &db, message.clone(), attempt, &task).await;
        assert!(outcome.is_err(), "a transient failure asks apalis to retry");
        let row = row(&db, id).await;
        assert_eq!(
            row.status, "queued",
            "a retryable outcome leaves the row open"
        );
        assert_eq!(row.attempts, i32::try_from(attempt + 1).expect("small"));
    }

    let accepted = test_config(spawn_peer(vec![DATA]).await);
    run(&accepted, &db, message, 2, &task)
        .await
        .expect("the third attempt sends");
    assert_eq!(row(&db, id).await.status, "sent");
}

#[tokio::test]
async fn a_5_7_1_rejection_moves_queued_to_failed_without_suppressing() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config(
        spawn_peer(vec![(
            "MAIL FROM",
            "550 5.7.1 Sender address rejected: not authorised\r\n",
        )])
        .await,
    );
    let (id, message) = queued(&db).await;
    let recipient = message.to.clone();

    run(&config, &db, message, 0, &no_task())
        .await
        .expect("a terminal outcome ends the job Ok, never a retry");
    let row = row(&db, id).await;
    assert_eq!(row.status, "failed");
    assert!(
        !attome_email::suppression::is_suppressed(&db, &recipient)
            .await
            .expect("suppression lookup"),
        "5.7.1 is the relay's policy, not the recipient's (D-661)"
    );
}

#[tokio::test]
async fn a_5_1_1_rejection_moves_queued_to_suppressed() {
    let db = skip_if_no_db!(test_pool().await);
    let config = test_config(
        spawn_peer(vec![(
            "RCPT TO",
            "550 5.1.1 <recipient> User unknown in local recipient table\r\n",
        )])
        .await,
    );
    let (id, message) = queued(&db).await;
    let recipient = message.to.clone();

    run(&config, &db, message, 0, &no_task())
        .await
        .expect("a terminal outcome ends the job Ok");
    assert_eq!(row(&db, id).await.status, "suppressed");
    assert!(
        attome_email::suppression::is_suppressed(&db, &recipient)
            .await
            .expect("suppression lookup")
    );
}

#[tokio::test]
async fn a_config_error_moves_queued_to_failed_with_no_retry() {
    let db = skip_if_no_db!(test_pool().await);
    let mut config = test_config(dead_port().await);
    // Credentials over a plaintext link to a non-loopback relay are refused
    // before any dial (BEM-D4): a configuration error no retry can fix.
    config.email.smtp_host = "relay.example.invalid".to_string();
    config.email.smtp_user = "smtp-user".to_string();
    config.email.smtp_password = "hunter2".into();
    let (id, message) = queued(&db).await;

    run(&config, &db, message, 0, &no_task())
        .await
        .expect("a configuration error ends the job Ok, never a retry");
    assert_eq!(row(&db, id).await.status, "failed");
}

/// BEM-17: the last attempt of a transient failure closes the row as
/// `failed` instead of leaving it `queued` behind a dead-lettered job. Pins
/// `is_final_attempt`'s reading of the apalis row's own budget.
#[tokio::test]
async fn the_last_transient_attempt_moves_queued_to_failed() {
    let db = skip_if_no_db!(test_pool().await);
    let (task,): (String,) = sqlx::query_as(
        "SELECT id FROM apalis.push_job(job_type => 'email-job-ledger-test', \
             job => '{}'::json, max_attempts => 2)",
    )
    .fetch_one(&db)
    .await
    .expect("a two-attempt apalis row");
    let config = test_config(dead_port().await);
    let (id, message) = queued(&db).await;

    let first = run(&config, &db, message.clone(), 1, &task).await;
    assert!(first.is_err(), "attempt 1 of 2 still retries");
    assert_eq!(row(&db, id).await.status, "queued");

    run(&config, &db, message, 2, &task)
        .await
        .expect("the final attempt settles the row and ends Ok");
    assert_eq!(row(&db, id).await.status, "failed");

    sqlx::query("DELETE FROM apalis.jobs WHERE id = $1")
        .bind(&task)
        .execute(&db)
        .await
        .expect("remove the test's apalis row");
}
