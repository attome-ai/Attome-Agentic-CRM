//! J2-T1: an IMAP mailbox (`async-imap` over rustls, MIME parsed with
//! `mail-parser`, both pure Rust).
//!
//! Each pull logs in, selects the folder and fetches the next UIDs after the
//! cursor (`imap:{uidvalidity}:{last_uid}`), at most
//! [`super::MAX_PER_PULL`] of them, peeking so nothing is marked read. When
//! the folder's UIDVALIDITY changed, UIDs mean something else now: the pull
//! starts again from the newest messages, and routing (J2-T2) recognises the
//! ones it already has by `Message-ID`. Polling every minute is the caller's
//! schedule; IDLE needs a held connection per mailbox and is left to the
//! scheduler that owns such connections.

use std::sync::Arc;
use std::time::Duration;

use attome_types::AppError;
use futures_util::StreamExt;
use mail_parser::{MessageParser, MimeHeaders};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::{
    MAX_PER_PULL, MailAddress, MailAttachment, MailMessage, bare_id, reference_ids, required,
};
use crate::system::IntegrationSystem;

const TIMEOUT: Duration = Duration::from_secs(120);
/// Messages read on the first pull, or after UIDVALIDITY changed.
const FIRST_PULL: u32 = 50;

/// `imap:{uidvalidity}:{last_uid}`. Pure.
pub fn parse_cursor(cursor: Option<&str>) -> Option<(u32, u32)> {
    let rest = cursor?.strip_prefix("imap:")?;
    let (validity, last) = rest.split_once(':')?;
    Some((validity.parse().ok()?, last.parse().ok()?))
}

pub fn format_cursor(validity: u32, last: u32) -> String {
    format!("imap:{validity}:{last}")
}

/// The first UID to read: after the cursor when the folder is the same
/// (UIDVALIDITY), else the newest [`FIRST_PULL`]. Pure.
pub fn start_uid(cursor: Option<(u32, u32)>, validity: u32, uid_next: Option<u32>) -> u32 {
    match cursor {
        Some((v, last)) if v == validity => last.saturating_add(1),
        _ => uid_next.map_or(1, |next| next.saturating_sub(FIRST_PULL).max(1)),
    }
}

/// The UID the cursor reaches after reading `start..=end`: every UID below
/// `uid_next` in that range has been looked at, found or not, so a gap of
/// deleted messages never stalls the sync. Pure.
pub fn reached(start: u32, end: u32, uid_next: Option<u32>, highest_seen: Option<u32>) -> u32 {
    let covered = match uid_next {
        Some(next) => end.min(next.saturating_sub(1)),
        None => highest_seen.unwrap_or(start.saturating_sub(1)),
    };
    covered
        .max(highest_seen.unwrap_or(0))
        .max(start.saturating_sub(1))
}

/// One raw message, parsed. Pure.
pub fn parse_message(uid: u32, raw: &[u8]) -> Option<MailMessage> {
    let message = MessageParser::default().parse(raw)?;
    let addr = |a: &mail_parser::Addr| {
        Some(MailAddress {
            name: a.name().map(str::to_owned).filter(|n| !n.is_empty()),
            address: a.address()?.trim().to_owned(),
        })
    };
    let list = |a: Option<&mail_parser::Address>| -> Vec<MailAddress> {
        a.map(|a| a.iter().filter_map(addr).collect())
            .unwrap_or_default()
    };
    let raw_header = |name: &str| {
        message
            .header_raw(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
    };
    let attachments = message
        .attachments()
        .enumerate()
        .map(|(i, part)| MailAttachment {
            name: part.attachment_name().map(str::to_owned),
            content_type: part.content_type().map(|c| match c.subtype() {
                Some(sub) => format!("{}/{}", c.ctype(), sub),
                None => c.ctype().to_owned(),
            }),
            size: part.contents().len() as u64,
            reference: format!("imap:{uid}/{i}"),
        })
        .collect();
    Some(MailMessage {
        provider: "imap",
        id: uid.to_string(),
        message_id: message.message_id().and_then(bare_id),
        in_reply_to: raw_header("In-Reply-To").as_deref().and_then(bare_id),
        references: raw_header("References")
            .as_deref()
            .map(reference_ids)
            .unwrap_or_default(),
        thread_hint: None,
        from: list(message.from()).into_iter().next(),
        to: list(message.to()),
        cc: list(message.cc()),
        subject: message.subject().map(str::to_owned),
        date: message.date().map(|d| d.to_rfc3339()),
        text: message.body_text(0).map(|t| t.into_owned()),
        html: message.body_html(0).map(|t| t.into_owned()),
        auto_submitted: raw_header("Auto-Submitted"),
        precedence: raw_header("Precedence"),
        list_id: raw_header("List-Id"),
        attachments,
    })
}

fn connector() -> Result<TlsConnector, AppError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(AppError::internal)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

pub(super) async fn pull(
    system: &IntegrationSystem,
    cfg: &Value,
    password: &str,
    cursor: Option<&str>,
) -> Result<(Vec<MailMessage>, Option<String>), AppError> {
    let host = required(cfg, system, "host")?.to_owned();
    let user = required(cfg, system, "username")?.to_owned();
    let port = cfg
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .unwrap_or(993);
    let folder = cfg
        .get("folder")
        .and_then(Value::as_str)
        .filter(|f| !f.is_empty())
        .unwrap_or("INBOX")
        .to_owned();
    let cursor = parse_cursor(cursor);
    let read = async move {
        let server = ServerName::try_from(host.clone())
            .map_err(|_| AppError::Validation("host: not a server name".into()))?;
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(AppError::internal)?;
        let tls = connector()?
            .connect(server, tcp)
            .await
            .map_err(AppError::internal)?;
        let client = async_imap::Client::new(tls);
        let mut session = client.login(&user, password).await.map_err(|(e, _)| {
            AppError::Validation(format!("the IMAP server refused the login: {e}"))
        })?;
        let mailbox = session.select(&folder).await.map_err(AppError::internal)?;
        let validity = mailbox.uid_validity.unwrap_or(0);
        let start = start_uid(cursor, validity, mailbox.uid_next);
        let end = start.saturating_add(u32::try_from(MAX_PER_PULL).unwrap_or(100) - 1);
        let mut out = Vec::new();
        let mut highest: Option<u32> = None;
        if mailbox.uid_next.is_none_or(|next| start < next) {
            let mut fetches = session
                .uid_fetch(format!("{start}:{end}"), "(UID BODY.PEEK[])")
                .await
                .map_err(AppError::internal)?;
            while let Some(fetch) = fetches.next().await {
                let fetch = fetch.map_err(AppError::internal)?;
                let Some(uid) = fetch.uid else {
                    continue;
                };
                // `n:m` past the end still answers the last message.
                if uid < start || uid > end {
                    continue;
                }
                highest = Some(highest.map_or(uid, |h| h.max(uid)));
                if let Some(message) = fetch.body().and_then(|raw| parse_message(uid, raw)) {
                    out.push(message);
                }
            }
        }
        let last = reached(start, end, mailbox.uid_next, highest);
        // The messages are read; a failed goodbye changes nothing.
        let _ = session.logout().await;
        Ok::<_, AppError>((out, Some(format_cursor(validity, last))))
    };
    tokio::time::timeout(TIMEOUT, read)
        .await
        .map_err(|_| AppError::Validation("the IMAP server did not answer in time".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &[u8] = b"From: =?UTF-8?B?2LPYp9ix2Kk=?= <sara@client.sa>\r\n\
To: sales@us.sa, \"Ops Team\" <ops@us.sa>\r\n\
Subject: =?UTF-8?B?2LfZhNioINi52LHYtiDYs9i52LE=?=\r\n\
Message-ID: <m2@client.sa>\r\n\
In-Reply-To: <m1@us.sa>\r\n\
References: <m0@us.sa> <m1@us.sa>\r\n\
Date: Sun, 19 Oct 2025 11:00:00 +0300\r\n\
Auto-Submitted: auto-replied\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
\r\n\
--b1\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
2YbYrdiq2KfYrCDYudix2LbZi9in\r\n\
--b1\r\n\
Content-Type: application/pdf; name=\"RFQ.pdf\"\r\n\
Content-Disposition: attachment; filename=\"RFQ.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--b1--\r\n";

    #[test]
    fn mailbox_imap_parses_mime() {
        let m = parse_message(42, RAW).unwrap();
        assert_eq!((m.provider, m.id.as_str()), ("imap", "42"));
        assert_eq!(
            m.from.as_ref().map(|f| f.address.as_str()),
            Some("sara@client.sa")
        );
        assert_eq!(
            m.from.as_ref().and_then(|f| f.name.as_deref()),
            Some("سارة")
        );
        assert_eq!(m.subject.as_deref(), Some("طلب عرض سعر"));
        assert_eq!(m.text.as_deref().map(str::trim), Some("نحتاج عرضًا"));
        assert_eq!(m.to.len(), 2);
        assert_eq!(m.message_id.as_deref(), Some("m2@client.sa"));
        assert_eq!(m.in_reply_to.as_deref(), Some("m1@us.sa"));
        assert_eq!(m.references, vec!["m0@us.sa", "m1@us.sa"]);
        assert_eq!(m.auto_submitted.as_deref(), Some("auto-replied"));
        assert_eq!(m.date.as_deref(), Some("2025-10-19T11:00:00+03:00"));
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].name.as_deref(), Some("RFQ.pdf"));
        assert_eq!(
            m.attachments[0].content_type.as_deref(),
            Some("application/pdf")
        );
        assert_eq!(m.attachments[0].reference, "imap:42/0");
    }

    #[test]
    fn mailbox_imap_cursor_reads_each_message_once() {
        assert_eq!(parse_cursor(Some("imap:7:120")), Some((7, 120)));
        assert_eq!(parse_cursor(Some("graph:x")), None);
        assert_eq!(format_cursor(7, 120), "imap:7:120");
        // The same folder: after the last UID read.
        assert_eq!(start_uid(Some((7, 120)), 7, Some(130)), 121);
        // UIDVALIDITY changed, or the first pull: the newest 50.
        assert_eq!(start_uid(Some((6, 120)), 7, Some(130)), 80);
        assert_eq!(start_uid(None, 7, Some(20)), 1);
        assert_eq!(start_uid(None, 7, None), 1);
        // Read 121..=220 with UIDNEXT 130: the cursor reaches 129, found or not.
        assert_eq!(reached(121, 220, Some(130), Some(125)), 129);
        // A gap of deleted messages still moves the cursor on.
        assert_eq!(reached(121, 220, Some(500), None), 220);
        // Nothing new: the cursor stays.
        assert_eq!(reached(121, 220, Some(121), None), 120);
        assert_eq!(reached(121, 220, None, Some(150)), 150);
    }
}
