use std::error::Error as _;
use std::net::IpAddr;
use std::time::Duration;

use attome_config::EmailSection;
use attome_types::text::normalize_email;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{MultiPart, SinglePart},
    transport::smtp::Error as SmtpError,
    transport::smtp::authentication::Credentials,
};
use tracing::Instrument as _;

use crate::error::SendError;
use crate::message::EmailMessage;
use crate::suppression::{self, SuppressionReason};

// lettre applies `info.timeout` to the **TCP connect only**
// (`client/async_net.rs:171-181` of lettre 0.11.23); it is not a per-command
// read timeout. It exists so an unreachable relay releases the shared
// job-worker slot instead of occupying it indefinitely — guidelines §10 wants
// an explicit timeout on every external call.
const SMTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The whole-send deadline (BEM-7, plan §5). Sits outside lettre, so a peer
/// that accepts the connection and then goes silent — including one that
/// stalls *after* `DATA` — cannot pin a worker forever. Its expiry is the one
/// route to `SendError::Unknown`: lettre cannot expose which SMTP stage was
/// reached (BEM-0.3), so a stall we had to cut off is never retried.
const SEND_DEADLINE: Duration = Duration::from_secs(120);

/// `email.tls_mode` values `attome-config` accepts
/// (`sections/observability.rs`).
const TLS_MODE_IMPLICIT: &str = "implicit";
const TLS_MODE_STARTTLS: &str = "starttls";
const TLS_MODE_NONE: &str = "none";

/// True for a host that can only be this machine: `localhost`, `127.0.0.0/8`,
/// `::1`. BEM-D4 refuses to put credentials on an unencrypted link unless the
/// peer is here (a dev SMTP sink), because no legitimate remote
/// plaintext-AUTH case exists.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim().trim_start_matches('[').trim_end_matches(']');
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Builds the configured SMTP transport — shared by `send()` and
/// `crate::health::health_check` so the relay-selection logic (TLS mode,
/// port, credentials, timeout) exists in exactly one place.
///
/// `with_credentials` is **false** only for the anonymous health probe
/// (BEM-6/BEM-D3): the unauthenticated `/health/dependencies` route must
/// never send `AUTH`, or a scanner can lock the shared service account out.
pub(crate) fn build_transport(
    cfg: &EmailSection,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, SendError> {
    transport_for(cfg, true)
}

/// The credential-less variant the public probe uses (BEM-6).
pub(crate) fn build_transport_anonymous(
    cfg: &EmailSection,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, SendError> {
    transport_for(cfg, false)
}

fn transport_for(
    cfg: &EmailSection,
    with_credentials: bool,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, SendError> {
    let mode = cfg.effective_tls_mode();
    let mut transport_builder = match mode {
        // Implicit TLS / SMTPS (the historical `smtp_use_tls = true`, and the
        // default). `relay` validates the certificate against the host name.
        TLS_MODE_IMPLICIT => {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host).map_err(|e| {
                SendError::Config {
                    message: format!("implicit TLS for {}: {e}", cfg.smtp_host),
                }
            })?
        }
        // STARTTLS, required: lettre aborts the session if the relay does not
        // offer the upgrade, so a downgrade attempt cannot leak credentials.
        TLS_MODE_STARTTLS => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)
            .map_err(|e| SendError::Config {
            message: format!("STARTTLS for {}: {e}", cfg.smtp_host),
        })?,
        // Plaintext, for a loopback dev sink only. `attome-config`'s `validate()`
        // already refuses this outside `APP_ENV=debug`; re-checked here so a
        // caller holding a hand-built `EmailSection` cannot bypass it.
        TLS_MODE_NONE => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host),
        other => {
            return Err(SendError::Config {
                message: format!(
                    "email.tls_mode must be one of {TLS_MODE_IMPLICIT:?}, {TLS_MODE_STARTTLS:?}, \
                     {TLS_MODE_NONE:?} — got {other:?}"
                ),
            });
        }
    }
    .port(cfg.smtp_port)
    .timeout(Some(SMTP_CONNECT_TIMEOUT));

    if !cfg.smtp_user.is_empty() && with_credentials {
        // BEM-5/BEM-D4: refuse before the connect. `auth()` in lettre has no
        // encryption check, so with `builder_dangerous` a relay that
        // advertises AUTH before TLS would receive the password in clear.
        if mode == TLS_MODE_NONE && !is_loopback_host(&cfg.smtp_host) {
            return Err(SendError::Config {
                message: format!(
                    "refusing to send SMTP credentials over an unencrypted connection to {} \
                     (email.tls_mode = \"none\") — every remote relay needs \"implicit\" or \
                     \"starttls\"; only a loopback dev sink may be plaintext",
                    cfg.smtp_host
                ),
            });
        }
        transport_builder = transport_builder.credentials(Credentials::new(
            cfg.smtp_user.clone(),
            cfg.smtp_password.expose().to_owned(),
        ));
    }

    Ok(transport_builder.build())
}

/// Builds (and validates) the RFC 5322 message before any I/O — cheap/local
/// checks fail before a DB round trip, and it keeps the "malformed address"
/// cases pure unit tests with no database dependency.
fn build_email(cfg: &EmailSection, msg: &EmailMessage) -> Result<Message, SendError> {
    let from = msg
        .from_override
        .clone()
        .unwrap_or_else(|| format!("{} <{}>", cfg.smtp_from_name, cfg.smtp_from_address));
    let mut builder =
        Message::builder()
            .from(from.parse().map_err(|e: lettre::address::AddressError| {
                SendError::InvalidAddress(e.to_string())
            })?)
            .to(msg.to.parse().map_err(|e: lettre::address::AddressError| {
                SendError::InvalidAddress(e.to_string())
            })?)
            .subject(msg.subject.clone())
            // M52 Phase 1 (threading): set on every send whose producer knows
            // its own Message-ID, `None` (a no-op builder call) for every
            // other producer — see `EmailMessage::message_id`'s doc comment.
            .message_id(msg.message_id.clone());
    if let Some(in_reply_to) = &msg.in_reply_to {
        builder = builder.in_reply_to(in_reply_to.clone());
    }
    if let Some(references) = &msg.references {
        builder = builder.references(references.clone());
    }

    let text_body = msg.text_body.clone();
    let email = match &msg.html_body {
        Some(html) => builder.multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::plain(text_body))
                .singlepart(SinglePart::html(html.clone())),
        ),
        None => builder.body(text_body),
    }
    .map_err(|e| SendError::InvalidAddress(e.to_string()))?;
    Ok(email)
}

/// The first RFC 3463 `class.subject.detail` token in a reply's text, if any.
/// lettre's `Code` carries the three-digit reply only; the enhanced status
/// lives solely in the reply text (plan §2.2).
fn enhanced_status(reply_text: &str) -> Option<&str> {
    fn all_digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }
    reply_text.split_whitespace().find(|token| {
        let token = token.trim_end_matches(['.', ',', ';', ':', ')']);
        let mut parts = token.split('.');
        let (Some(class), Some(subject), Some(detail), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        class.len() == 1 && all_digits(class) && all_digits(subject) && all_digits(detail)
    })
}

/// D-661 (amends D-166) — is this permanent rejection the *recipient's* fault?
///
/// Yes for an enhanced `5.1.x` (addressing status) or `5.2.1`/`5.2.2`
/// (mailbox disabled / full), and for a bare `550`/`551`/`553` carrying no
/// enhanced status at all. No for everything else — in particular `5.7.x`
/// (sender policy), `5.3.x`, `530/534/535/538` (authentication),
/// `552` and `554` — because those indict the relay's configuration or the
/// deployment's credentials, not the mailbox.
fn is_recipient_attributable(code: &str, reply_text: Option<&str>) -> bool {
    if let Some(enhanced) = reply_text.and_then(enhanced_status) {
        let mut parts = enhanced.split('.');
        // class.subject.detail — the class must be `5` (a permanent failure);
        // a `4.x.x` status inside a 5xx reply is a malformed or relay-mangled
        // answer, and the safe reading of it is "not the recipient's fault".
        let class = parts.next().unwrap_or_default();
        let subject = parts.next().unwrap_or_default();
        let detail = parts.next().unwrap_or_default();
        if class != "5" {
            return false;
        }
        return match subject {
            // 5.1.x — addressing status: the destination address itself.
            "1" => true,
            // 5.2.1 mailbox disabled / 5.2.2 mailbox full are the recipient's.
            // 5.2.3 (message too long) and 5.2.4 (list expansion) are not.
            "2" => matches!(detail, "1" | "2"),
            _ => false,
        };
    }
    matches!(code, "550" | "551" | "553")
}

/// The innermost `io::Error` kind in an SMTP error's source chain, if any.
/// lettre exposes no `is_connection()`/`is_network()` (plan §2.2), so this is
/// the only way to tell a refused connection (retryable) from a failed TLS
/// handshake (configuration) — under `tokio1-rustls` the latter is
/// `Kind::Connection` carrying an `io::Error` of kind `InvalidData`, and
/// `is_tls()` never fires for it.
fn io_error_kind(err: &SmtpError) -> Option<std::io::ErrorKind> {
    let mut source = err.source();
    while let Some(cause) = source {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            return Some(io_err.kind());
        }
        source = cause.source();
    }
    None
}

/// True when lettre's `Kind::Connection` actually wraps a TLS handshake
/// failure — under `tokio1-rustls` a failed handshake is not `Kind::Tls` but
/// a `Connection` error whose source is an `io::Error` of kind
/// `InvalidData` (plan §2.2). Shared with `crate::health`'s category
/// vocabulary so the two never disagree about what "tls" means.
pub(crate) fn is_tls_handshake_failure(err: &SmtpError) -> bool {
    io_error_kind(err) == Some(std::io::ErrorKind::InvalidData)
}

/// The relay's own reply text: lettre stores it as the error's String source,
/// and it is where the RFC 3463 enhanced status lives (plan §2.2).
///
/// Read through `source().to_string()`, not a downcast: `String` does not
/// implement `std::error::Error`, so lettre reaches it through std's
/// `From<String> for Box<dyn Error + Send + Sync>` — a **private** wrapper
/// whose `downcast_ref::<String>()` can never match, while its `Display`
/// delegates to the string verbatim. This is the one place the plan's
/// "never parse the Display text" rule bends, and only because the enhanced
/// status is not exposed any other way; the parse below reads the *reply*
/// (never lettre's own `"permanent error (550): "` prefix, which this does
/// not include) and only for the class/subject/detail shape.
fn reply_text(err: &SmtpError) -> Option<String> {
    err.source().map(|cause| cause.to_string())
}

/// The one place the send-outcome rule lives (plan §4.2). Every branch is a
/// lettre predicate, an `io::ErrorKind`, or the D-661 enhanced-status parse —
/// never a substring of lettre's `Display` text.
pub(crate) fn classify(err: &SmtpError) -> SendError {
    if err.is_permanent() {
        let code = err.status().map(|c| c.to_string()).unwrap_or_default();
        let recipient_attributable = is_recipient_attributable(&code, reply_text(err).as_deref());
        return SendError::Permanent {
            code,
            message: err.to_string(),
            recipient_attributable,
        };
    }
    if err.is_transient() {
        return SendError::Transient {
            message: err.to_string(),
        };
    }
    // A TLS handshake failure: configuration, not a transient network blip.
    if err.is_tls() || io_error_kind(err) == Some(std::io::ErrorKind::InvalidData) {
        return SendError::Config {
            message: err.to_string(),
        };
    }
    // No compatible AUTH mechanism, STARTTLS absent when required, an
    // unsupported message shape — no retry changes any of them.
    if err.is_client() {
        return SendError::Config {
            message: err.to_string(),
        };
    }
    // lettre applies its own timeout to the TCP connect alone (BEM-0.3), so a
    // lettre-level timeout is unambiguously pre-`DATA`: retryable.
    if err.is_timeout() {
        return SendError::Transient {
            message: err.to_string(),
        };
    }
    // A malformed/truncated reply — including the peer closing mid-session,
    // which surfaces as `error::response("incomplete response")`. Same
    // stage-blind trade-off as the io arm below.
    if err.is_response() {
        return SendError::Transient {
            message: err.to_string(),
        };
    }
    // Anything else that carried an OS-level cause: refused, reset, aborted,
    // broken pipe, unexpected EOF, DNS failure. lettre cannot say which stage
    // a reset or EOF hit (BEM-0.3), so one after the final `.` may follow an
    // accepted message; plan §4.2 retries these anyway, accepting that rare
    // duplicate over dropping every mid-session disconnect.
    if io_error_kind(err).is_some() {
        return SendError::Transient {
            message: err.to_string(),
        };
    }
    SendError::Internal(err.to_string())
}

/// One SMTP session: build the transport, send, classify. No database access
/// and no side effects — that split is what lets the classification rules be
/// unit-tested against a scripted peer (BEM-1, P1 acceptance).
pub(crate) async fn deliver(cfg: &EmailSection, email: Message) -> Result<(), SendError> {
    let transport = build_transport(cfg)?;
    match transport.send(email).await {
        Ok(_) => Ok(()),
        Err(e) => Err(classify(&e)),
    }
}

/// Applies the outcome of one attempt: the whole-send deadline, the
/// suppression write for the one class that earns it, and nothing else.
///
/// Bookkeeping here is advisory, never authoritative over the send outcome
/// (D-166): a failed suppression write is `warn!`ed and downgraded, so the
/// job records a real failure instead of a false suppression (BEM-3).
async fn settle_outcome(
    cfg: &EmailSection,
    db: &attome_db::DbPool,
    recipient: &str,
    email: Message,
    delivery_id: Option<uuid::Uuid>,
    deadline: Duration,
) -> Result<(), SendError> {
    let attempt = tokio::time::timeout(deadline, deliver(cfg, email)).await;
    let err = match attempt {
        Ok(Ok(())) => return Ok(()),
        Ok(Err(e)) => e,
        // The SMTP stage at cut-off is not observable (BEM-0.3). Safe side:
        // no retry, operator-visible.
        Err(_elapsed) => {
            return Err(SendError::Unknown {
                message: format!(
                    "no SMTP outcome within {}s — the relay accepted the connection but the \
                     session did not complete; not retried, because a duplicate delivery is \
                     worse than a gap",
                    deadline.as_secs()
                ),
            });
        }
    };

    if let SendError::Permanent {
        code,
        message,
        recipient_attributable: true,
    } = &err
        && let Err(write_err) = suppression::suppress(
            db,
            recipient,
            SuppressionReason::HardBounce,
            Some(message),
            None,
        )
        .await
    {
        // BEM-3/F4: the old code swallowed this and the ledger still read
        // suppressed — an address nobody could mail and nobody could find.
        tracing::warn!(
            delivery_id = ?delivery_id,
            error = %write_err,
            "email: the recipient-attributable rejection could not be written to \
             email_suppression — the send stays failed and the address \
             stays mailable; the ledger must not claim it was suppressed"
        );
        return Err(SendError::Permanent {
            code: code.clone(),
            message: message.clone(),
            recipient_attributable: false,
        });
    }
    Err(err)
}

/// Sends one email via the configured SMTP relay. Returns
/// `SendError::Disabled` if `email.enabled` is false — callers on the
/// request path (reset-request) check this themselves first to avoid doing
/// token-generation work for a deployment with no email channel at all; this
/// check is a defense-in-depth backstop for the job-handler call site, not
/// the primary gate.
///
/// Checks `email_suppression` before any network attempt
/// (P-email-hardening) — the one call path every email producer shares (the three
/// `PlatformJob::SendEmail` job producers and `xrm_notification::dispatch`'s
/// own direct, non-apalis send). Only a *recipient-attributable* permanent
/// rejection suppresses (BEM-2/D-661); a transient one does not.
pub async fn send(
    cfg: &EmailSection,
    db: &attome_db::DbPool,
    msg: EmailMessage,
) -> Result<(), SendError> {
    let span = tracing::info_span!(
        "email_send",
        delivery_id = ?msg.delivery_id,
        communication_id = ?msg.communication_id
    );
    let result = send_in_span(cfg, db, msg).instrument(span).await;
    // BEM-10 — every outcome, including the ones that never reached the relay
    // (disabled, suppressed, malformed), so the ratio alerts see the whole mix.
    metrics::counter!("email_send_total", "outcome" => outcome_label(&result)).increment(1);
    result
}

/// The bounded `outcome` label (plan §5): never a recipient, never free text.
pub(crate) fn outcome_label(result: &Result<(), SendError>) -> &'static str {
    match result {
        Ok(()) => "sent",
        Err(e) => e.label(),
    }
}

async fn send_in_span(
    cfg: &EmailSection,
    db: &attome_db::DbPool,
    msg: EmailMessage,
) -> Result<(), SendError> {
    if !cfg.enabled {
        return Err(SendError::Disabled);
    }

    let email = build_email(cfg, &msg)?;

    let recipient = normalize_email(&msg.to);
    if suppression::is_suppressed(db, &recipient)
        .await
        .map_err(|e| SendError::Internal(e.to_string()))?
    {
        tracing::debug!("email: recipient is suppressed; no SMTP attempt made");
        return Err(SendError::Suppressed);
    }

    let started = std::time::Instant::now();
    let result = settle_outcome(cfg, db, &recipient, email, msg.delivery_id, SEND_DEADLINE).await;
    metrics::histogram!("email_send_duration_seconds").record(started.elapsed().as_secs_f64());

    match &result {
        Ok(()) => tracing::info!("email: accepted by the relay"),
        Err(e) => tracing::warn!(
            outcome = e.label(),
            error = %e.redacted_message(),
            "email: send failed"
        ),
    }
    result
}

#[cfg(test)]
mod tests {
    use attome_config::EmailSection;
    use sqlx::postgres::PgPoolOptions;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;

    fn test_cfg() -> EmailSection {
        EmailSection {
            enabled: true,
            smtp_host: "localhost".to_string(),
            smtp_port: 1025,
            smtp_user: String::new(),
            smtp_password: String::new().into(),
            smtp_from_address: "noreply@example.com".to_string(),
            smtp_from_name: "Attome".to_string(),
            smtp_use_tls: None,
            tls_mode: None,
        }
    }

    fn test_message() -> EmailMessage {
        EmailMessage {
            to: "user@example.com".to_string(),
            subject: "Hello".to_string(),
            text_body: "body".to_string(),
            html_body: None,
            delivery_id: None,
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
        }
    }

    /// `PgPoolOptions::connect_lazy` never actually opens a connection until
    /// a query runs — used only by the tests that never reach the suppression
    /// lookup.
    fn unreachable_pool() -> attome_db::DbPool {
        PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/unused")
            .expect("build lazy pool")
    }

    /// The scripted peers below speak plaintext on loopback, so the transport
    /// mode is pinned to `none` explicitly — a test that wants the implicit-TLS
    /// path opts back in (see the plaintext-peer TLS test).
    fn cfg_at(port: u16) -> EmailSection {
        EmailSection {
            smtp_port: port,
            tls_mode: Some("none".to_string()),
            ..test_cfg()
        }
    }

    /// A peer scripted the same way `tests/smtp_classification.rs` scripts
    /// one, but reachable from an in-crate unit test (no database needed).
    async fn spawn_peer(steps: Vec<(&'static str, Option<&'static str>)>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind scripted peer");
        let port = listener.local_addr().expect("peer addr").port();
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
                    // The message body is opaque to SMTP: the relay answers
                    // exactly once, after the CRLF.CRLF terminator. Replying
                    // per body line would hand the client a spurious 250
                    // before it ever reads the real verdict.
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
                        // Sentinel: close the TCP stream right here, which is
                        // what a relay that dies mid-session does from the
                        // client's side (EOF, no reply).
                        if *reply == "!close" {
                            break;
                        }
                        let _ = write_half.write_all(reply.as_bytes()).await;
                        if line.contains("DATA") {
                            in_data = true;
                        }
                    }
                    // Scripted silence: hold the socket open and say nothing.
                    // Five seconds is longer than every deadline these tests
                    // set, and short enough that a mistake cannot look like a
                    // hang.
                    Some((_, None)) => tokio::time::sleep(Duration::from_secs(5)).await,
                    None => {
                        let _ = write_half.write_all(b"250 OK\r\n").await;
                    }
                }
            }
        });
        port
    }

    async fn dead_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        port
    }

    // ── The D-661 rule itself ─────────────────────────────────────────────

    #[test]
    fn the_enhanced_status_rule_matches_d661() {
        // Recipient-attributable.
        assert!(is_recipient_attributable("550", Some("5.1.1 user unknown")));
        assert!(is_recipient_attributable(
            "550",
            Some("5.1.0 other address status")
        ));
        assert!(is_recipient_attributable(
            "551",
            Some("5.2.1 mailbox disabled")
        ));
        assert!(is_recipient_attributable("552", Some("5.2.2 mailbox full")));
        // Bare 550/551/553 with no enhanced status.
        assert!(is_recipient_attributable("550", None));
        assert!(is_recipient_attributable("550", Some("User unknown")));
        assert!(is_recipient_attributable("551", Some("not our user")));
        assert!(is_recipient_attributable("553", Some("bad mailbox name")));

        // Relay/config-attributable — the F2 regressions.
        assert!(!is_recipient_attributable(
            "535",
            Some("5.7.8 authentication credentials invalid")
        ));
        assert!(!is_recipient_attributable("535", None));
        assert!(!is_recipient_attributable(
            "550",
            Some("5.7.1 sender address rejected")
        ));
        assert!(!is_recipient_attributable(
            "552",
            Some("5.3.4 message too big")
        ));
        assert!(!is_recipient_attributable("552", None));
        assert!(!is_recipient_attributable(
            "554",
            Some("5.7.1 no relay access")
        ));
        assert!(!is_recipient_attributable("554", None));
        assert!(!is_recipient_attributable(
            "530",
            Some("5.7.0 authentication required")
        ));
        assert!(!is_recipient_attributable(
            "550",
            Some("5.2.3 message too long")
        ));
        // Only a 5-class enhanced status counts.
        assert!(!is_recipient_attributable("550", Some("4.1.1 later")));
    }

    #[test]
    fn an_enhanced_status_must_be_a_whole_class_subject_detail_token() {
        assert_eq!(enhanced_status("5.1.1 user unknown"), Some("5.1.1"));
        assert_eq!(enhanced_status("550 5.7.8 nope"), Some("5.7.8"));
        assert_eq!(enhanced_status("5.1.1,"), Some("5.1.1,"));
        assert_eq!(enhanced_status("no code here"), None);
        assert_eq!(enhanced_status("5.1"), None);
        assert_eq!(enhanced_status("5.1.1.2"), None);
        assert_eq!(enhanced_status(""), None);
    }

    #[test]
    fn only_a_loopback_host_may_carry_credentials_over_plaintext() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.6.6.6"));
        assert!(is_loopback_host("::1"));
        assert!(is_loopback_host("[::1]"));
        assert!(!is_loopback_host("smtp.example.com"));
        assert!(!is_loopback_host("10.0.0.5"));
        assert!(!is_loopback_host("172.17.0.2"));
    }

    /// P1 acceptance — a peer that accepts the connection and then closes is
    /// a retryable failure, not an `Internal` one.
    #[tokio::test]
    async fn a_peer_that_closes_mid_session_is_transient() {
        let port = spawn_peer(vec![("EHLO", Some("!close"))]).await;
        let email = build_email(&cfg_at(port), &test_message()).expect("build message");
        // `deliver` is the un-deadlined core; `send` wraps it. Bound it here so
        // a regression fails fast instead of hanging the suite.
        let result = tokio::time::timeout(Duration::from_secs(10), deliver(&cfg_at(port), email))
            .await
            .expect("deliver must not hang when the peer closes");
        assert!(
            matches!(result, Err(SendError::Transient { .. })),
            "a peer cut off mid-session must be retryable, got {result:?}"
        );
    }

    /// P1 acceptance — implicit TLS against a plaintext listener is a
    /// configuration error: no retry can fix it, and it must not suppress.
    #[tokio::test]
    async fn implicit_tls_against_a_plaintext_peer_is_config() {
        let port = spawn_peer(vec![("EHLO", Some("250 scripted\r\n"))]).await;
        let mut cfg = cfg_at(port);
        cfg.tls_mode = Some("implicit".to_string());
        let email = build_email(&cfg, &test_message()).expect("build message");
        let result = deliver(&cfg, email).await;
        assert!(
            matches!(result, Err(SendError::Config { .. })),
            "a failed TLS handshake is configuration, got {result:?}"
        );
    }

    /// P1 acceptance — credentials requested but no AUTH advertised.
    #[tokio::test]
    async fn no_auth_advertised_is_config() {
        let port = spawn_peer(vec![("EHLO", Some("250 scripted\r\n"))]).await;
        let mut cfg = cfg_at(port);
        cfg.smtp_user = "smtp-user".to_string();
        cfg.smtp_password = "hunter2".into();
        let email = build_email(&cfg, &test_message()).expect("build message");
        let result = deliver(&cfg, email).await;
        assert!(
            matches!(result, Err(SendError::Config { .. })),
            "a relay advertising no compatible AUTH is configuration, got {result:?}"
        );
    }

    /// P1 acceptance — `552 5.3.4` and a bare `554` after `DATA` are relay
    /// verdicts, never recipient ones.
    #[tokio::test]
    async fn a_552_and_a_554_after_data_are_not_recipient_attributable() {
        for reply in [
            "552 5.3.4 Message size exceeds fixed maximum\r\n",
            "554 Message rejected\r\n",
        ] {
            let port = spawn_peer(vec![
                ("EHLO", Some("250 scripted\r\n")),
                ("MAIL FROM", Some("250 OK\r\n")),
                ("RCPT TO", Some("250 OK\r\n")),
                ("DATA", Some("354 end with <CRLF>.<CRLF>\r\n")),
                ("=.", Some(reply)),
            ])
            .await;
            let cfg = cfg_at(port);
            let email = build_email(&cfg, &test_message()).expect("build message");
            let result = deliver(&cfg, email).await;
            match result {
                Err(SendError::Permanent {
                    recipient_attributable,
                    ..
                }) => assert!(
                    !recipient_attributable,
                    "{reply:?} must never suppress the recipient"
                ),
                other => panic!("expected a permanent rejection, got {other:?}"),
            }
        }
    }

    /// F1 — a refused connection is transient.
    #[tokio::test]
    async fn a_refused_connection_classifies_as_transient() {
        let cfg = cfg_at(dead_port().await);
        let email = build_email(&cfg, &test_message()).expect("build message");
        let result = deliver(&cfg, email).await;
        assert!(
            matches!(result, Err(SendError::Transient { .. })),
            "got {result:?}"
        );
    }

    /// BEM-5 acceptance — credentials on `tls_mode = none` against a remote
    /// host are refused **before any connection is attempted**, so the
    /// password never reaches the network. The host here resolves nowhere, so
    /// a connect attempt would hang or fail; a `Config` verdict proves the
    /// guard fired first.
    #[tokio::test]
    async fn plaintext_credentials_to_a_remote_host_are_refused_before_connect() {
        let mut cfg = test_cfg();
        cfg.smtp_host = "smtp.example.invalid".to_string();
        cfg.smtp_user = "smtp-user".to_string();
        cfg.smtp_password = "hunter2".into();
        cfg.tls_mode = Some("none".to_string());

        let err = build_transport(&cfg).expect_err("must be refused");
        match err {
            SendError::Config { message } => {
                assert!(message.contains("unencrypted"), "{message}");
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    /// BEM-5 — a loopback host is the one legitimate plaintext-credential case
    /// (a dev SMTP sink).
    #[test]
    fn plaintext_credentials_to_loopback_are_allowed() {
        let mut cfg = test_cfg();
        cfg.smtp_user = "smtp-user".to_string();
        cfg.smtp_password = "hunter2".into();
        cfg.tls_mode = Some("none".to_string());
        assert!(build_transport(&cfg).is_ok());
    }

    #[test]
    fn an_unknown_tls_mode_is_a_configuration_error() {
        let mut cfg = test_cfg();
        cfg.tls_mode = Some("opportunistic".to_string());
        assert!(matches!(
            build_transport(&cfg),
            Err(SendError::Config { .. })
        ));
    }

    /// The deprecated bool still maps for one release (plan §4.3).
    #[test]
    fn the_deprecated_smtp_use_tls_bool_still_selects_a_mode() {
        let mut cfg = test_cfg();
        cfg.smtp_use_tls = Some(true);
        assert_eq!(cfg.effective_tls_mode(), "implicit");
        cfg.smtp_use_tls = Some(false);
        assert_eq!(cfg.effective_tls_mode(), "none");
        cfg.smtp_use_tls = None;
        assert_eq!(cfg.effective_tls_mode(), "implicit");
        cfg.smtp_use_tls = Some(false);
        cfg.tls_mode = Some("starttls".to_string());
        assert_eq!(
            cfg.effective_tls_mode(),
            "starttls",
            "tls_mode wins over the deprecated bool"
        );
    }

    /// BEM-17 / BEM-0.3 — a peer that stalls *after* `DATA` produces
    /// `Unknown`, and never a suppression. The deadline is short here so the
    /// test does not wait the production 120 s.
    #[tokio::test]
    async fn a_stall_after_data_is_unknown_and_suppresses_nothing() {
        let port = spawn_peer(vec![
            ("EHLO", Some("250 scripted\r\n")),
            ("MAIL FROM", Some("250 OK\r\n")),
            ("RCPT TO", Some("250 OK\r\n")),
            ("DATA", Some("354 go\r\n")),
            ("=.", None),
        ])
        .await;
        let cfg = cfg_at(port);
        let email = build_email(&cfg, &test_message()).expect("build message");
        let recipient = "user@example.invalid";

        let result = settle_outcome(
            &cfg,
            &unreachable_pool(),
            recipient,
            email,
            None,
            Duration::from_millis(300),
        )
        .await;

        assert!(
            matches!(result, Err(SendError::Unknown { .. })),
            "a stalled post-DATA session must be Unknown, got {result:?}"
        );
    }

    /// BEM-3/F4 — the suppression write is advisory. When it fails, the send
    /// outcome must survive as a permanent rejection that no longer claims the
    /// recipient was suppressed, so the job records \`failed\`, not \`suppressed\`.
    /// The pool points at a dead port: the INSERT cannot connect, while the
    /// classification and the scripted peer are untouched.
    #[tokio::test]
    async fn a_failed_suppression_write_does_not_claim_a_suppression() {
        let port = spawn_peer(vec![
            ("EHLO", Some("250 scripted\r\n")),
            ("MAIL FROM", Some("250 OK\r\n")),
            (
                "RCPT TO",
                Some("550 5.1.1 user unknown in local recipient table\r\n"),
            ),
        ])
        .await;
        let cfg = cfg_at(port);
        let email = build_email(&cfg, &test_message()).expect("build message");

        let result = settle_outcome(
            &cfg,
            &unreachable_pool(),
            "user@example.invalid",
            email,
            None,
            Duration::from_secs(10),
        )
        .await;

        match result {
            Err(SendError::Permanent {
                ref code,
                recipient_attributable,
                ..
            }) => {
                assert_eq!(code, "550");
                assert!(
                    !recipient_attributable,
                    "the ledger must not claim a suppression that was never written (BEM-3)"
                );
            }
            other => panic!("expected the downgraded permanent rejection, got {other:?}"),
        }
    }

    /// Counters keyed `name{label=value,…}`, for `metrics::with_local_recorder`.
    #[derive(Clone, Default)]
    struct CountingRecorder(
        std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    );

    struct CountingHandle {
        key: String,
        counts: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    }

    impl metrics::CounterFn for CountingHandle {
        fn increment(&self, value: u64) {
            *self
                .counts
                .lock()
                .expect("recorder lock")
                .entry(self.key.clone())
                .or_insert(0) += value;
        }
        fn absolute(&self, value: u64) {
            self.counts
                .lock()
                .expect("recorder lock")
                .insert(self.key.clone(), value);
        }
    }

    impl metrics::Recorder for CountingRecorder {
        fn describe_counter(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_gauge(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn describe_histogram(
            &self,
            _: metrics::KeyName,
            _: Option<metrics::Unit>,
            _: metrics::SharedString,
        ) {
        }
        fn register_counter(
            &self,
            key: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            metrics::Counter::from_arc(std::sync::Arc::new(CountingHandle {
                key: format!("{}{{{}}}", key.name(), labels.join(",")),
                counts: self.0.clone(),
            }))
        }
        fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
            metrics::Gauge::noop()
        }
        fn register_histogram(
            &self,
            _: &metrics::Key,
            _: &metrics::Metadata<'_>,
        ) -> metrics::Histogram {
            metrics::Histogram::noop()
        }
    }

    /// BEM-10 — the label vocabulary is closed: one value per class, never a
    /// recipient or reply text.
    #[test]
    fn every_send_outcome_has_a_fixed_label() {
        let permanent = |recipient_attributable| SendError::Permanent {
            code: "550".into(),
            message: "5.1.1 a@b".into(),
            recipient_attributable,
        };
        let cases = [
            (Ok(()), "sent"),
            (Err(SendError::Disabled), "disabled"),
            (Err(SendError::InvalidAddress("x@".into())), "config"),
            (Err(SendError::Suppressed), "suppressed"),
            (Err(permanent(true)), "permanent_recipient"),
            (Err(permanent(false)), "permanent_relay"),
            (
                Err(SendError::Transient {
                    message: "451".into(),
                }),
                "transient",
            ),
            (
                Err(SendError::Config {
                    message: "tls".into(),
                }),
                "config",
            ),
            (
                Err(SendError::Unknown {
                    message: "stall".into(),
                }),
                "unknown",
            ),
            (Err(SendError::Internal("db".into())), "internal"),
        ];
        for (result, label) in cases {
            assert_eq!(outcome_label(&result), label, "{result:?}");
        }
    }

    /// BEM-10 — `send` counts outcomes that never reach the relay too.
    #[test]
    fn send_counts_a_disabled_outcome() {
        let recorder = CountingRecorder::default();
        let mut cfg = test_cfg();
        cfg.enabled = false;
        metrics::with_local_recorder(&recorder, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async {
                    let result = send(&cfg, &unreachable_pool(), test_message()).await;
                    assert!(matches!(result, Err(SendError::Disabled)));
                });
        });
        let counts = recorder.0.lock().expect("recorder lock");
        assert_eq!(
            counts.get("email_send_total{outcome=disabled}"),
            Some(&1),
            "{counts:?}"
        );
    }

    #[tokio::test]
    async fn disabled_email_returns_feature_unavailable_without_touching_the_network() {
        let mut cfg = test_cfg();
        cfg.enabled = false;
        // A host that cannot resolve — if this ever got past the enabled gate,
        // the test would hang on a connection attempt instead of returning.
        cfg.smtp_host = "this-host-does-not-resolve.invalid".to_string();

        let result = send(&cfg, &unreachable_pool(), test_message()).await;
        assert!(matches!(result, Err(SendError::Disabled)));
    }

    #[tokio::test]
    async fn a_malformed_from_address_is_rejected_before_any_network_attempt() {
        let mut cfg = test_cfg();
        cfg.smtp_from_address = "not-an-email-address".to_string();
        cfg.smtp_host = "this-host-does-not-resolve.invalid".to_string();

        let result = send(&cfg, &unreachable_pool(), test_message()).await;
        assert!(matches!(result, Err(SendError::InvalidAddress(_))));
    }

    #[tokio::test]
    async fn a_malformed_recipient_address_is_rejected_before_any_network_attempt() {
        let mut cfg = test_cfg();
        cfg.smtp_host = "this-host-does-not-resolve.invalid".to_string();
        let mut msg = test_message();
        msg.to = "not-an-email-address".to_string();

        let result = send(&cfg, &unreachable_pool(), msg).await;
        assert!(matches!(result, Err(SendError::InvalidAddress(_))));
    }
}
