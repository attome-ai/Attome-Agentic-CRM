//! BEM-0.1 / BEM-2 (attome-email plan §6) — classification and the D-661
//! suppression rule, exercised against a **scripted SMTP peer** (a raw
//! `tokio::net::TcpListener` playing one reply script per test, the same shape
//! attome-storage's `fake_s3`/`fake_clamd` and xrm-s2s's rate-limit peer
//! already use).
//!
//! DB-backed on purpose: `send()` checks `email_suppression`
//! before it ever builds a transport, and these tests assert on the
//! suppression *side effect* (F2 / D-661) as much as on the returned class.
//!
//! Runs against attome-testkit's migrated throwaway database
//! (`attome_testkit::migrated_pool`): set `DATABASE_URL` to a PostgreSQL
//! server; without it each test prints SKIP.
//!
//! Run: DATABASE_URL=postgres://... cargo test -p attome-email --test smtp_classification -- --test-threads=1

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]
#![allow(
    clippy::disallowed_methods,
    reason = "integration test sets up or inspects state in a raw pool transaction; production code uses attome_db::tx::begin"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use attome_config::EmailSection;
use attome_email::SendError;
use attome_testkit::skip_if_no_db;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// One scripted reply. `needle` matches the received line by substring, unless
/// it starts with `=` — then it must equal the line exactly (the DATA
/// terminator is the only line a substring match cannot safely name).
///
/// `reply: None` means "say nothing more": the peer holds the connection open
/// in silence, which is how a stalled session is scripted.
type Step = (&'static str, Option<&'static str>);

/// A running scripted peer. `seen` is every line the peer received, so a test
/// can assert on what the client *sent*.
struct Peer {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Peer {
    fn commands(&self) -> Vec<String> {
        self.seen.lock().expect("peer command log").clone()
    }

    fn sent_any(&self, needle: &str) -> bool {
        self.commands().iter().any(|line| line.contains(needle))
    }
}

/// Binds a peer on an ephemeral loopback port and scripts it. The returned
/// `Peer` is live immediately: the listener has already been bound, so the
/// port is connectable before the accept happens.
async fn spawn_peer(greeting: &'static str, steps: Vec<Step>) -> Peer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the scripted SMTP peer");
    let port = listener.local_addr().expect("peer local addr").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);

    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read_half, mut write_half) = stream.into_split();
        if !greeting.is_empty() {
            let _ = write_half.write_all(greeting.as_bytes()).await;
        }
        let mut lines = BufReader::new(read_half).lines();
        let mut in_data = false;
        while let Ok(Some(line)) = lines.next_line().await {
            log.lock().expect("peer command log").push(line.clone());
            if line.starts_with("QUIT") {
                let _ = write_half.write_all(b"221 bye\r\n").await;
                break;
            }
            if in_data {
                // The message body is opaque to SMTP: one answer, after the
                // CRLF.CRLF terminator, never one per body line.
                if line.trim_end() == "." {
                    in_data = false;
                    let reply = steps
                        .iter()
                        .find(|(needle, _)| needle.starts_with("=."))
                        .and_then(|(_, reply)| *reply);
                    if let Some(reply) = reply {
                        let _ = write_half.write_all(reply.as_bytes()).await;
                    }
                }
                continue;
            }
            let matched = steps
                .iter()
                .find(|(needle, _)| match needle.strip_prefix('=') {
                    Some(exact) => line.trim_end() == exact,
                    None => line.contains(needle),
                });
            match matched {
                Some((_, Some(reply))) => {
                    let _ = write_half.write_all(reply.as_bytes()).await;
                    if line.contains("DATA") {
                        in_data = true;
                    }
                }
                // Scripted silence: hold the socket open and say nothing.
                Some((_, None)) => tokio::time::sleep(Duration::from_secs(5)).await,
                None => {
                    let _ = write_half.write_all(b"250 OK\r\n").await;
                }
            }
        }
    });

    Peer { port, seen }
}

/// A port nothing is listening on: bind, learn the port, drop the listener.
/// Every later connect to it is refused, deterministically and instantly.
async fn dead_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe listener");
    let port = listener.local_addr().expect("probe local addr").port();
    drop(listener);
    port
}

fn cfg_for(port: u16, user: &str) -> EmailSection {
    EmailSection {
        enabled: true,
        smtp_host: "127.0.0.1".to_string(),
        smtp_port: port,
        smtp_user: user.to_string(),
        smtp_password: if user.is_empty() { "" } else { "hunter2" }.into(),
        smtp_from_address: "noreply@example.invalid".to_string(),
        smtp_from_name: "Attome".to_string(),
        // The scripted peer speaks plaintext; the host is loopback, which is
        // the one case BEM-D4 permits credentials over an unencrypted link.
        smtp_use_tls: None,
        tls_mode: Some("none".to_string()),
        test_mode_catch_all: None,
        providers: Default::default(),
        rate_limits: Default::default(),
        feedback: Default::default(),
        domain_check: Default::default(),
    }
}

fn message_to(recipient: &str) -> attome_email::EmailMessage {
    attome_email::EmailMessage {
        to: recipient.to_string(),
        subject: "Hello".to_string(),
        text_body: "body".to_string(),
        html_body: None,
        delivery_id: None,
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
        stream: Default::default(),
        list_unsubscribe: None,
        list_unsubscribe: None,
    }
}

async fn test_pool() -> Option<PgPool> {
    attome_testkit::migrated_pool(5).await
}

/// A live peer is only reachable through a unique address, so the assertions
/// below read the exact recipient rather than a shared fixture.
fn unique_recipient() -> String {
    attome_testkit::unique_email("smtp-classification")
}

/// F1 — a relay that refuses the connection is a *transient* failure: the
/// ledger attempt is retried with backoff and the row is never closed out as
/// terminal on the strength of an unreachable relay.
#[tokio::test]
async fn a_refused_connection_is_transient() {
    let pool = skip_if_no_db!(test_pool().await);
    let cfg = cfg_for(dead_port().await, "");
    let recipient = unique_recipient();

    let result = attome_email::send(&cfg, &pool, message_to(&recipient)).await;

    assert!(
        matches!(result, Err(SendError::Transient { .. })),
        "a refused connection must be Transient (retryable), got {result:?}"
    );
    assert!(
        !attome_email::suppression::is_suppressed(&pool, &recipient)
            .await
            .unwrap()
    );
}

/// F2 / D-661 — a `535` is the relay rejecting *our own credentials*. It must
/// never suppress the recipient: one mistyped SMTP password would otherwise
/// blacklist every address that deployment ever mails.
#[tokio::test]
async fn a_535_at_auth_does_not_suppress_the_recipient() {
    let pool = skip_if_no_db!(test_pool().await);
    let peer = spawn_peer(
        "220 scripted ESMTP\r\n",
        vec![
            (
                "EHLO",
                Some("250-scripted\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n"),
            ),
            (
                "AUTH",
                Some("535 5.7.8 Authentication credentials invalid\r\n"),
            ),
        ],
    )
    .await;
    let cfg = cfg_for(peer.port, "smtp-user");
    let recipient = unique_recipient();

    let result = attome_email::send(&cfg, &pool, message_to(&recipient)).await;

    assert!(
        peer.sent_any("AUTH"),
        "the scripted peer must have been asked to authenticate"
    );
    match result {
        Err(SendError::Permanent {
            ref code,
            recipient_attributable,
            ..
        }) => {
            assert_eq!(code, "535");
            assert!(
                !recipient_attributable,
                "535 is the deployment's credential problem, not the recipient's (D-661)"
            );
        }
        other => panic!("expected a permanent relay rejection, got {other:?}"),
    }
    assert!(
        !attome_email::suppression::is_suppressed(&pool, &recipient)
            .await
            .unwrap()
    );
}

/// F2 / D-661 — `550 5.7.1` at `MAIL FROM` is the relay refusing our sender,
/// not the recipient. Same rule as the 535 above.
#[tokio::test]
async fn a_550_5_7_1_at_mail_from_does_not_suppress_the_recipient() {
    let pool = skip_if_no_db!(test_pool().await);
    let peer = spawn_peer(
        "220 scripted ESMTP\r\n",
        vec![
            ("EHLO", Some("250 scripted\r\n")),
            (
                "MAIL FROM",
                Some("550 5.7.1 Sender address rejected: not authorised\r\n"),
            ),
        ],
    )
    .await;
    let cfg = cfg_for(peer.port, "");
    let recipient = unique_recipient();

    let result = attome_email::send(&cfg, &pool, message_to(&recipient)).await;

    match result {
        Err(SendError::Permanent {
            recipient_attributable,
            ..
        }) => assert!(
            !recipient_attributable,
            "550 5.7.1 is a relay/sender-policy rejection (D-661)"
        ),
        other => panic!("expected a permanent rejection, got {other:?}"),
    }
    assert!(
        !attome_email::suppression::is_suppressed(&pool, &recipient)
            .await
            .unwrap()
    );
}

/// P1 acceptance — `552 5.3.4` (message too big) and a bare `554` are relay
/// verdicts, never recipient ones, even though both are 5xx.
#[tokio::test]
async fn a_552_and_a_554_do_not_suppress_the_recipient() {
    let pool = skip_if_no_db!(test_pool().await);
    for reply in [
        "552 5.3.4 Message size exceeds fixed maximum\r\n",
        "554 Message rejected\r\n",
    ] {
        let peer = spawn_peer(
            "220 scripted ESMTP\r\n",
            vec![
                ("EHLO", Some("250 scripted\r\n")),
                ("MAIL FROM", Some("250 OK\r\n")),
                ("RCPT TO", Some("250 OK\r\n")),
                ("DATA", Some("354 end with <CRLF>.<CRLF>\r\n")),
                ("=.", Some(reply)),
            ],
        )
        .await;
        let cfg = cfg_for(peer.port, "");
        let recipient = unique_recipient();

        let result = attome_email::send(&cfg, &pool, message_to(&recipient)).await;
        match result {
            Err(SendError::Permanent {
                recipient_attributable,
                ..
            }) => assert!(!recipient_attributable, "{reply:?} must not suppress"),
            other => panic!("expected a permanent rejection for {reply:?}, got {other:?}"),
        }
        assert!(
            !attome_email::suppression::is_suppressed(&pool, &recipient)
                .await
                .unwrap(),
            "{reply:?} must leave the address mailable"
        );
    }
}

/// The guard: `550 5.1.1` at `RCPT TO` *is* recipient-attributable, and is the
/// one case that must keep suppressing. Green before BEM-2 and after it.
#[tokio::test]
async fn a_550_5_1_1_at_rcpt_suppresses_the_recipient() {
    let pool = skip_if_no_db!(test_pool().await);
    let peer = spawn_peer(
        "220 scripted ESMTP\r\n",
        vec![
            ("EHLO", Some("250 scripted\r\n")),
            ("MAIL FROM", Some("250 OK\r\n")),
            (
                "RCPT TO",
                Some("550 5.1.1 <recipient> User unknown in local recipient table\r\n"),
            ),
        ],
    )
    .await;
    let cfg = cfg_for(peer.port, "");
    let recipient = unique_recipient();

    let result = attome_email::send(&cfg, &pool, message_to(&recipient)).await;

    match result {
        Err(SendError::Permanent {
            recipient_attributable,
            ..
        }) => assert!(
            recipient_attributable,
            "550 5.1.1 is recipient-attributable (D-661)"
        ),
        other => panic!("expected a permanent recipient rejection, got {other:?}"),
    }
    assert!(
        attome_email::suppression::is_suppressed(&pool, &recipient)
            .await
            .unwrap(),
        "550 5.1.1 is recipient-attributable — the address must be suppressed"
    );
}
