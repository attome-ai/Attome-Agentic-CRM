//! P-health-readiness — read-only SMTP reachability check, consumed by
//! xrm-server's /health/dependencies diagnostic endpoint (never
//! /health/ready — a down relay must not pull an otherwise-healthy,
//! DB-serving node out of load-balancer rotation).

use std::time::{Duration, Instant};

use attome_config::EmailSection;
use lettre::transport::smtp::Error as SmtpError;
use serde::Serialize;

use crate::sender::{self, build_transport, build_transport_anonymous};

// See `attome_storage::health`'s identical constant for why this is 2s, not
// 5s: it must lose the race against `attome_server::app`'s global
// `TimeoutLayer` (request_timeout_secs), not tie with it.
const PUBLIC_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// BEM-D5/BEM-7 — the capability probe runs on the D-344 gate's own schedule
/// (never on a request path, so never bound by `TimeoutLayer`) and may spend
/// far longer than the public probe: a cold TLS + EHLO handshake to a real
/// relay has been measured well past 2 s. BEM-16 replaces the default with
/// the measured p95 × 2, floor 10 s.
pub const CAPABILITY_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
pub struct EmailHealth {
    pub enabled: bool,
    /// `None` when `enabled` is false — never attempted, not a failure (same
    /// "`None` means unknown, not down" convention
    /// `attome_jobs::worker_last_seen_age_seconds` already established).
    pub reachable: Option<bool>,
    pub latency_ms: Option<f64>,
    /// A **category only** (F6/BEM-6): one of `timeout`, `connect`, `tls`,
    /// `auth`, `rejected`, `other`. The old shape returned lettre's
    /// `Display` text — the relay's raw reply, which names the configured
    /// host — on an unauthenticated route (F6). Never a host, never a reply
    /// body.
    pub error: Option<String>,
    /// The raw text, for the server-side `warn!` only. `#[serde(skip)]` is
    /// what keeps it out of the public body; a caller can read it (preflight
    /// prints it), a JSON body cannot.
    #[serde(skip)]
    pub detail: Option<String>,
}

/// Builds the failure shape shared by every branch below, so the category and
/// the detail-log pair can never drift apart.
fn failed(category: &str, detail: String, latency_ms: Option<f64>) -> EmailHealth {
    tracing::warn!(
        category = category,
        detail = %detail,
        "email health probe failed; the public body carries the category only"
    );
    EmailHealth {
        enabled: true,
        reachable: Some(false),
        latency_ms,
        error: Some(category.to_string()),
        detail: Some(detail),
    }
}

/// The category vocabulary documented on `EmailHealth::error` (plan §5).
fn category(err: &SmtpError) -> &'static str {
    if err.is_timeout() {
        "timeout"
    } else if err.is_tls() || sender::is_tls_handshake_failure(err) {
        "tls"
    } else if err.is_client() {
        // lettre's own client-refusal class: "No compatible authentication
        // mechanism was found" is the one this path actually produces.
        "auth"
    } else if err.is_permanent() {
        // A relay-side authentication rejection is the operator's credential
        // problem, not a generic rejection — preflight turns it into the same
        // `auth` category the mechanism failure gets.
        match err.status().map(|c| c.to_string()).as_deref() {
            Some("530" | "534" | "535" | "538") => "auth",
            _ => "rejected",
        }
    } else if err.is_transient() {
        "rejected"
    } else if err.is_transport_shutdown() {
        "other"
    } else {
        // Refused, reset, truncated or unparseable — the socket never got as
        // far as a verdict from the relay.
        "connect"
    }
}

/// The anonymous probe every existing caller already uses: connect + TLS +
/// EHLO + NOOP, **never AUTH** (BEM-6/BEM-D3). A scanner hitting
/// /health/dependencies can no longer lock the shared service account out; a
/// credential that has been revoked or rotated still surfaces through
/// `health_check_authenticated` (preflight) and the `config` outcome counter.
///
/// The 2 s budget is the public probe's — see PUBLIC_PROBE_TIMEOUT.
pub async fn health_check(cfg: &EmailSection) -> EmailHealth {
    health_check_with_timeout(cfg, PUBLIC_PROBE_TIMEOUT).await
}

/// BEM-7 — the same anonymous probe with a caller-chosen budget, for the
/// D-344 capability gate (`CAPABILITY_PROBE_TIMEOUT`) which is not bound by
/// `TimeoutLayer`.
pub async fn health_check_with_timeout(cfg: &EmailSection, timeout: Duration) -> EmailHealth {
    probe(cfg, timeout, false).await
}

/// The AUTH-verifying probe: preflight's, and only preflight's (BEM-D3). Every
/// other caller wants `health_check`.
///
/// Not used by this crate's own callers yet — `crates/server/src/bin/
/// preflight.rs` and `xrm-server/src/capability_probe.rs` still call
/// `health_check`; switching them is part of BEM-6's caller wiring and is
/// recorded as owed in the plan (both files live outside attome-email).
pub async fn health_check_authenticated(cfg: &EmailSection, timeout: Duration) -> EmailHealth {
    probe(cfg, timeout, true).await
}

async fn probe(cfg: &EmailSection, timeout: Duration, with_credentials: bool) -> EmailHealth {
    if !cfg.enabled {
        return EmailHealth {
            enabled: false,
            reachable: None,
            latency_ms: None,
            error: None,
            detail: None,
        };
    }

    // Z8-T1: only an SMTP relay is probed. An HTTPS provider has no
    // credential-free probe, so it reports enabled and unprobed.
    let provider = crate::provider::provider_name(cfg, &cfg.smtp_from_address);
    if !provider.eq_ignore_ascii_case(crate::provider::SMTP) {
        return EmailHealth {
            enabled: true,
            reachable: None,
            latency_ms: None,
            error: None,
            detail: Some(format!("provider {provider}: not probed")),
        };
    }

    let transport = if with_credentials {
        build_transport(cfg)
    } else {
        build_transport_anonymous(cfg)
    };
    let transport = match transport {
        Ok(t) => t,
        Err(e) => return failed("connect", e.to_string(), None),
    };

    let start = Instant::now();
    match tokio::time::timeout(timeout, transport.test_connection()).await {
        Ok(Ok(reachable)) => EmailHealth {
            enabled: true,
            reachable: Some(reachable),
            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            error: None,
            detail: None,
        },
        Ok(Err(e)) => {
            let latency_ms = Some(start.elapsed().as_secs_f64() * 1000.0);
            let category = category(&e);
            failed(category, e.to_string(), latency_ms)
        }
        Err(_) => failed(
            "timeout",
            format!("timed out after {}s", timeout.as_secs_f64()),
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    /// BEM-0.2 — a scripted SMTP peer that records every command it receives.
    struct Peer {
        port: u16,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl Peer {
        fn sent_any(&self, needle: &str) -> bool {
            self.seen
                .lock()
                .expect("peer command log")
                .iter()
                .any(|line| line.contains(needle))
        }

        fn commands(&self) -> Vec<String> {
            self.seen.lock().expect("peer command log").clone()
        }
    }

    /// `ehlo_reply` lets a test script a rejected handshake; `stall` makes
    /// the peer greet and then say nothing at all.
    async fn spawn_peer(ehlo_reply: &'static str, stall_after_greeting: bool) -> Peer {
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
            if stall_after_greeting {
                // Say nothing at all — not even a banner. The probe's own
                // timeout is the only thing that can end this, and five
                // seconds outlasts every budget these tests set.
                tokio::time::sleep(Duration::from_secs(5)).await;
                return;
            }
            let _ = write_half.write_all(b"220 scripted ESMTP\r\n").await;
            let mut lines = BufReader::new(read_half).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log.lock().expect("peer command log").push(line.clone());
                if line.starts_with("QUIT") {
                    let _ = write_half.write_all(b"221 bye\r\n").await;
                    break;
                }
                if line.starts_with("EHLO") {
                    let _ = write_half.write_all(ehlo_reply.as_bytes()).await;
                } else {
                    let _ = write_half.write_all(b"250 OK\r\n").await;
                }
            }
        });

        Peer { port, seen }
    }

    fn cfg_for(port: u16) -> EmailSection {
        EmailSection {
            enabled: true,
            smtp_host: "127.0.0.1".to_string(),
            smtp_port: port,
            smtp_user: "smtp-user".to_string(),
            smtp_password: "hunter2".into(),
            smtp_from_address: "noreply@example.invalid".to_string(),
            smtp_from_name: "Attome".to_string(),
            smtp_use_tls: None,
            // The scripted peer speaks plaintext on loopback.
            tls_mode: Some("none".to_string()),
            test_mode_catch_all: None,
            providers: Default::default(),
            rate_limits: Default::default(),
        }
    }

    /// F6 / BEM-D3 — the anonymous `/health/dependencies` probe must never
    /// `AUTH`: it is reachable without a credential, so a scanner could
    /// otherwise lock the shared service account out. A revoked credential
    /// still surfaces through preflight's authenticated probe.
    #[tokio::test]
    async fn the_public_probe_sends_no_auth_command_and_leaks_no_host() {
        let peer = spawn_peer("250-scripted\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n", false).await;
        let health = health_check(&cfg_for(peer.port)).await;

        assert_eq!(health.reachable, Some(true), "the probe reaches the peer");
        assert!(
            !peer.sent_any("AUTH"),
            "the anonymous probe must never send AUTH (BEM-D3): sent {:?}",
            peer.commands()
        );
        assert!(
            !peer.sent_any("smtp-user"),
            "the anonymous probe must never put the service account on the wire"
        );
        assert!(
            health.error.is_none(),
            "a reachable relay is not an error, got {:?}",
            health.error
        );
    }

    /// BEM-6 — the AUTH-verifying variant exists for preflight and does send
    /// `AUTH` (this peer accepts it, so the probe reaches its NOOP).
    #[tokio::test]
    async fn the_authenticated_probe_authenticates() {
        let peer = spawn_peer("250-scripted\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n", false).await;
        let health = health_check_authenticated(&cfg_for(peer.port), PUBLIC_PROBE_TIMEOUT).await;

        assert!(
            peer.sent_any("AUTH"),
            "the authenticated probe is the one that authenticates: sent {:?}",
            peer.commands()
        );
        assert_eq!(health.reachable, Some(true));
        assert!(health.error.is_none());
    }

    /// BEM-6 — a relay that refuses the credentials is the `auth` category,
    /// which is what preflight acts on. A revoked or rotated password reaches
    /// the operator here and nowhere else.
    #[tokio::test]
    async fn a_rejected_credential_is_the_auth_category() {
        let mut cfg = cfg_for(0);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind peer");
        cfg.smtp_port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (read_half, mut write_half) = stream.into_split();
            let _ = write_half.write_all(b"220 scripted ESMTP\r\n").await;
            let mut lines = BufReader::new(read_half).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.starts_with("EHLO") {
                    let _ = write_half
                        .write_all(b"250-scripted\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n")
                        .await;
                } else if line.starts_with("AUTH") {
                    let _ = write_half
                        .write_all(b"535 5.7.8 Authentication credentials invalid\r\n")
                        .await;
                } else {
                    let _ = write_half.write_all(b"250 OK\r\n").await;
                }
            }
        });

        let health = health_check_authenticated(&cfg, PUBLIC_PROBE_TIMEOUT).await;

        assert_eq!(health.reachable, Some(false));
        assert_eq!(
            health.error.as_deref(),
            Some("auth"),
            "a 535 must be the auth category: {:?}",
            health.detail
        );
        assert!(
            !health.error.as_deref().unwrap().contains("hunter2"),
            "the body must never carry the credential"
        );
    }

    /// F6 — a rejected handshake is reported as a category, and the relay's own
    /// text (which names the host) stays in `detail`, out of the body.
    #[tokio::test]
    async fn a_rejected_handshake_reports_a_category_and_keeps_the_text_out_of_the_body() {
        let peer = spawn_peer(
            "554 5.7.1 <127.0.0.1> blocked by policy for 127.0.0.1\r\n",
            false,
        )
        .await;
        let health = health_check(&cfg_for(peer.port)).await;

        assert_eq!(health.reachable, Some(false));
        assert_eq!(
            health.error.as_deref(),
            Some("rejected"),
            "the body carries the category, not the reply"
        );
        assert!(
            !health.error.as_deref().unwrap().contains("127.0.0.1"),
            "no host may reach the public body"
        );
        assert!(
            health
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("blocked by policy")),
            "the raw text is kept for the server-side log: {:?}",
            health.detail
        );
    }

    /// BEM-7 — a peer that accepts the connection and then stalls is the public
    /// probe's `timeout`, inside its own 2 s budget rather than the global
    /// `TimeoutLayer`'s.
    #[tokio::test]
    async fn a_stalled_peer_is_a_timeout_category() {
        let peer = spawn_peer("", true).await;
        let start = Instant::now();
        let health =
            health_check_with_timeout(&cfg_for(peer.port), Duration::from_millis(250)).await;

        assert_eq!(health.error.as_deref(), Some("timeout"));
        assert_eq!(health.reachable, Some(false));
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "the probe's own budget must bound it, took {:?}",
            start.elapsed()
        );
    }

    /// Disabled email is never probed — not a failure.
    #[tokio::test]
    async fn disabled_email_is_not_probed() {
        let mut cfg = cfg_for(1);
        cfg.enabled = false;
        let health = health_check(&cfg).await;
        assert!(!health.enabled);
        assert_eq!(health.reachable, None);
        assert!(health.error.is_none());
    }
}
