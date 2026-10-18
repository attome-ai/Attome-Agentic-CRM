//! An in-process SMTP inbox for tests (roadmap Z15-T6), behind the
//! `test-support` feature: a loopback SMTP server that accepts every message
//! and keeps it, so a test sends mail through the real [`crate::send`] path
//! and reads back what arrived, with no relay and no container.
//!
//! It speaks just enough plaintext SMTP for `lettre` (`EHLO`, `MAIL FROM`,
//! `RCPT TO`, `DATA`, `RSET`, `NOOP`, `QUIT`); point an `EmailSection` at it
//! with [`FakeInbox::config`] (`tls_mode = "none"`, loopback, no
//! credentials). Every connection is served, so a test may send many.
//!
//! ```ignore
//! let inbox = FakeInbox::start().await;
//! attome_email::send(&inbox.config(), &pool, message).await?;
//! let mail = inbox.messages_to("someone@example.invalid");
//! assert_eq!(mail[0].subject, "Hello");
//! ```

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use attome_config::EmailSection;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// One message the inbox received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailSummary {
    /// The envelope sender (`MAIL FROM`).
    pub from: String,
    /// The envelope recipients (`RCPT TO`), lowercased.
    pub to: Vec<String>,
    /// The `Subject` header as sent (an encoded word stays encoded).
    pub subject: String,
    /// The text after the headers, as sent (transfer encoding not undone).
    pub body: String,
    /// The whole message: headers and body.
    pub raw: String,
}

/// The fake SMTP server. The listener lives until the test's runtime shuts
/// down.
pub struct FakeInbox {
    addr: SocketAddr,
    messages: Arc<Mutex<Vec<MailSummary>>>,
}

impl std::fmt::Debug for FakeInbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeInbox")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

/// `<a@b>` or `a@b` after a `MAIL FROM:` / `RCPT TO:` verb.
fn address(argument: &str) -> String {
    let rest = argument.split_once(':').map_or(argument, |(_, rest)| rest);
    let rest = rest.trim();
    let inner = rest
        .strip_prefix('<')
        .and_then(|r| r.split_once('>').map(|(a, _)| a))
        .unwrap_or_else(|| rest.split_whitespace().next().unwrap_or_default());
    inner.trim().to_owned()
}

/// Splits a received message into its subject and body.
fn summarise(from: String, to: Vec<String>, raw: String) -> MailSummary {
    let (headers, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .unwrap_or((raw.as_str(), ""));
    let mut subject = String::new();
    let mut in_subject = false;
    for line in headers.lines() {
        if in_subject && line.starts_with([' ', '\t']) {
            // RFC 5322 2.2.3: unfolding removes the line break, not the space.
            subject.push(' ');
            subject.push_str(line.trim_start());
            continue;
        }
        in_subject = false;
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("subject")
        {
            subject = value.trim().to_owned();
            in_subject = true;
        }
    }
    MailSummary {
        from,
        to,
        subject,
        body: body.to_owned(),
        raw,
    }
}

async fn serve(stream: TcpStream, messages: Arc<Mutex<Vec<MailSummary>>>) {
    let (read_half, mut write_half) = stream.into_split();
    if write_half
        .write_all(b"220 attome fake inbox ESMTP\r\n")
        .await
        .is_err()
    {
        return;
    }
    let mut lines = BufReader::new(read_half).lines();
    let mut from = String::new();
    let mut to: Vec<String> = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        let verb = line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        let reply: &[u8] = match verb.as_str() {
            "EHLO" | "HELO" => b"250 fake-inbox\r\n",
            "MAIL" => {
                from = address(&line);
                to.clear();
                b"250 OK\r\n"
            }
            "RCPT" => {
                to.push(address(&line).to_ascii_lowercase());
                b"250 OK\r\n"
            }
            "DATA" => {
                if write_half
                    .write_all(b"354 end with <CRLF>.<CRLF>\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let mut raw = String::new();
                while let Ok(Some(data)) = lines.next_line().await {
                    if data == "." {
                        break;
                    }
                    // RFC 5321 4.5.2: a leading dot was doubled by the sender.
                    let data = data
                        .strip_prefix('.')
                        .filter(|rest| rest.starts_with('.'))
                        .unwrap_or(&data);
                    raw.push_str(data);
                    raw.push_str("\r\n");
                }
                let summary = summarise(std::mem::take(&mut from), std::mem::take(&mut to), raw);
                if let Ok(mut all) = messages.lock() {
                    all.push(summary);
                }
                b"250 OK queued\r\n"
            }
            "RSET" => {
                from.clear();
                to.clear();
                b"250 OK\r\n"
            }
            "NOOP" => b"250 OK\r\n",
            "QUIT" => {
                let _ = write_half.write_all(b"221 bye\r\n").await;
                return;
            }
            _ => b"502 command not implemented\r\n",
        };
        if write_half.write_all(reply).await.is_err() {
            return;
        }
    }
}

impl FakeInbox {
    /// Binds `127.0.0.1:0` and accepts every message sent to it.
    pub async fn start() -> Self {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => panic!("bind a loopback port: {error}"),
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => panic!("read the loopback address: {error}"),
        };
        let messages = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&messages);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, Arc::clone(&kept)));
            }
        });
        Self { addr, messages }
    }

    /// The inbox's address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// An enabled email section that sends here: loopback, plaintext, no
    /// credentials, from `noreply@example.invalid`.
    pub fn config(&self) -> EmailSection {
        EmailSection {
            enabled: true,
            smtp_host: self.addr.ip().to_string(),
            smtp_port: self.addr.port(),
            smtp_user: String::new(),
            smtp_password: "".into(),
            smtp_from_address: "noreply@example.invalid".to_owned(),
            smtp_from_name: "Attome".to_owned(),
            smtp_use_tls: None,
            tls_mode: Some("none".to_owned()),
            test_mode_catch_all: None,
            providers: Default::default(),
        }
    }

    /// Every message received, oldest first.
    pub fn messages(&self) -> Vec<MailSummary> {
        self.messages
            .lock()
            .map(|all| all.clone())
            .unwrap_or_default()
    }

    /// The messages whose envelope names `addr` as a recipient (any case).
    pub fn messages_to(&self, addr: &str) -> Vec<MailSummary> {
        let addr = addr.to_ascii_lowercase();
        self.messages()
            .into_iter()
            .filter(|m| m.to.contains(&addr))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_address_reads_with_or_without_brackets() {
        assert_eq!(address("MAIL FROM:<a@b.test> SIZE=10"), "a@b.test");
        assert_eq!(address("RCPT TO: c@d.test"), "c@d.test");
    }

    #[test]
    fn a_folded_subject_is_joined() {
        let raw =
            "From: a@b\r\nSubject: Hello\r\n there\r\nTo: c@d\r\n\r\nBody line\r\n".to_owned();
        let summary = summarise("a@b".into(), vec!["c@d".into()], raw);
        assert_eq!(summary.subject, "Hello there");
        assert_eq!(summary.body, "Body line\r\n");
    }
}
