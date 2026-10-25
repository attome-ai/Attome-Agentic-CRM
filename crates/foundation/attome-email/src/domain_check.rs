//! Z8-T4: sending-domain checks. For a domain this deployment sends from,
//! the SPF, DKIM and DMARC records it needs, read from DNS and judged
//! `ok`, `missing`, `wrong`, `not_configured` (no DKIM selector named) or
//! `unknown` (DNS did not answer), each with the record to add.
//!
//! - SPF: one `v=spf1` TXT record on the domain, carrying
//!   `include:<spf_include>` when the domain names one.
//! - DKIM: `<selector>._domainkey.<domain>` holds a key (`v=DKIM1` or
//!   `p=`); an empty `p=` is a revoked key, so wrong.
//! - DMARC: one `v=DMARC1` record on `_dmarc.<domain>` with a policy.
//!
//! DNS is read by [`DnsTxtResolver`], a small pure-Rust TXT client over UDP
//! (TCP when the answer is truncated) against `email.domain_check.resolver`,
//! three seconds a question; no resolver crate ships (see
//! `attome_marketing::address_check`). Tests use their own [`TxtResolver`].
//!
//! This deployment's SMTP sending does not sign with DKIM itself, so no key
//! is generated here: the selector is the sending provider's (SES,
//! SendGrid, the mail host), and the check confirms its record is
//! published.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// How long one DNS question may take.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// TXT, in DNS.
const TYPE_TXT: u16 = 16;

/// What DNS answered for a name's TXT records.
pub type TxtAnswer = Result<Vec<String>, String>;

/// Reads a name's TXT records.
pub trait TxtResolver: Send + Sync {
    fn txt<'a>(&'a self, name: &'a str) -> Pin<Box<dyn Future<Output = TxtAnswer> + Send + 'a>>;
}

/// The records one domain needs, as `email.domain_check.domains` names them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainSettings {
    /// The provider's SPF include (`amazonses.com`, `sendgrid.net`).
    pub spf_include: Option<String>,
    /// The provider's DKIM selector.
    pub dkim_selector: Option<String>,
}

/// One record's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordCheck {
    /// `spf`, `dkim` or `dmarc`.
    pub kind: &'static str,
    /// The DNS name the record lives at.
    pub name: String,
    /// `ok`, `missing`, `wrong`, `not_configured` or `unknown`.
    pub status: &'static str,
    /// What DNS holds there now.
    pub found: Vec<String>,
    /// The record to publish (TXT).
    pub expected: String,
    pub detail: Option<String>,
}

/// A domain's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DomainCheck {
    pub domain: String,
    pub records: Vec<RecordCheck>,
    /// Every record is `ok`, or `not_configured`.
    pub ok: bool,
}

/// Whether `domain` is a host name a check can ask DNS about. Pure.
pub fn domain_ok(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    !domain.is_empty()
        && domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn starts_with_tag(record: &str, tag: &str) -> bool {
    record
        .trim_start()
        .get(..tag.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(tag))
}

/// The SPF verdict from the domain's TXT records. Pure.
pub fn judge_spf(domain: &str, settings: &DomainSettings, txt: &TxtAnswer) -> RecordCheck {
    let expected = match settings.spf_include.as_deref() {
        Some(include) => format!("v=spf1 include:{include} ~all"),
        None => "v=spf1 mx ~all".to_owned(),
    };
    let mut check = RecordCheck {
        kind: "spf",
        name: domain.to_owned(),
        status: "ok",
        found: Vec::new(),
        expected,
        detail: None,
    };
    let records = match txt {
        Ok(records) => records,
        Err(error) => {
            check.status = "unknown";
            check.detail = Some(error.clone());
            return check;
        }
    };
    check.found = records
        .iter()
        .filter(|r| starts_with_tag(r, "v=spf1"))
        .cloned()
        .collect();
    match check.found.as_slice() {
        [] => check.status = "missing",
        [one] => {
            if let Some(include) = settings.spf_include.as_deref() {
                let wanted = format!("include:{}", include.to_ascii_lowercase());
                if !one
                    .to_ascii_lowercase()
                    .split_whitespace()
                    .any(|term| term.trim_start_matches(['+', '~', '?']) == wanted)
                {
                    check.status = "wrong";
                    check.detail = Some(format!("the SPF record does not include {include}"));
                }
            }
        }
        _ => {
            check.status = "wrong";
            check.detail = Some("more than one SPF record: receivers then fail SPF".into());
        }
    }
    check
}

/// The DKIM verdict. Pure.
pub fn judge_dkim(domain: &str, settings: &DomainSettings, txt: Option<&TxtAnswer>) -> RecordCheck {
    let Some(selector) = settings.dkim_selector.as_deref() else {
        return RecordCheck {
            kind: "dkim",
            name: format!("<selector>._domainkey.{domain}"),
            status: "not_configured",
            found: Vec::new(),
            expected: "the DKIM record your sending provider gives you".into(),
            detail: Some("name the provider's DKIM selector to check it".into()),
        };
    };
    let mut check = RecordCheck {
        kind: "dkim",
        name: format!("{selector}._domainkey.{domain}"),
        status: "ok",
        found: Vec::new(),
        expected: "v=DKIM1; k=rsa; p=<the provider's public key>".into(),
        detail: None,
    };
    let records = match txt {
        Some(Ok(records)) => records,
        Some(Err(error)) => {
            check.status = "unknown";
            check.detail = Some(error.clone());
            return check;
        }
        None => {
            check.status = "unknown";
            return check;
        }
    };
    check.found = records
        .iter()
        .filter(|r| starts_with_tag(r, "v=DKIM1") || r.contains("p="))
        .cloned()
        .collect();
    match check.found.first() {
        None => check.status = "missing",
        Some(record) => {
            let key = record
                .split(';')
                .map(str::trim)
                .find_map(|tag| tag.strip_prefix("p="))
                .map(str::trim);
            if key.is_none_or(str::is_empty) {
                check.status = "wrong";
                check.detail = Some("the DKIM record has no public key (p= is empty)".into());
            }
        }
    }
    check
}

/// The DMARC verdict. Pure.
pub fn judge_dmarc(domain: &str, txt: &TxtAnswer) -> RecordCheck {
    let mut check = RecordCheck {
        kind: "dmarc",
        name: format!("_dmarc.{domain}"),
        status: "ok",
        found: Vec::new(),
        expected: format!("v=DMARC1; p=none; rua=mailto:dmarc@{domain}"),
        detail: None,
    };
    let records = match txt {
        Ok(records) => records,
        Err(error) => {
            check.status = "unknown";
            check.detail = Some(error.clone());
            return check;
        }
    };
    check.found = records
        .iter()
        .filter(|r| starts_with_tag(r, "v=DMARC1"))
        .cloned()
        .collect();
    match check.found.as_slice() {
        [] => check.status = "missing",
        [one] => {
            let has_policy = one
                .split(';')
                .map(str::trim)
                .any(|tag| tag.to_ascii_lowercase().starts_with("p="));
            if !has_policy {
                check.status = "wrong";
                check.detail = Some("the DMARC record has no policy (p=)".into());
            }
        }
        _ => {
            check.status = "wrong";
            check.detail = Some("more than one DMARC record: receivers then ignore it".into());
        }
    }
    check
}

/// Checks a domain's three records through `resolver`.
pub async fn check_domain(
    resolver: &dyn TxtResolver,
    domain: &str,
    settings: &DomainSettings,
) -> DomainCheck {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    let spf = resolver.txt(&domain).await;
    let dmarc = resolver.txt(&format!("_dmarc.{domain}")).await;
    let dkim = match settings.dkim_selector.as_deref() {
        Some(selector) => Some(
            resolver
                .txt(&format!("{selector}._domainkey.{domain}"))
                .await,
        ),
        None => None,
    };
    let records = vec![
        judge_spf(&domain, settings, &spf),
        judge_dkim(&domain, settings, dkim.as_ref()),
        judge_dmarc(&domain, &dmarc),
    ];
    let ok = records
        .iter()
        .all(|r| r.status == "ok" || r.status == "not_configured");
    DomainCheck {
        domain,
        records,
        ok,
    }
}

/// A TXT question for `name`, with message id `id`. Pure.
pub fn encode_query(id: u16, name: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(name.len() + 18);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // recursion desired
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // one question
    for label in name.trim_end_matches('.').split('.') {
        let len = u8::try_from(label.len())
            .ok()
            .filter(|l| (1..=63).contains(l))
            .ok_or_else(|| format!("{name} is not a DNS name"))?;
        out.push(len);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&[0, 1]); // IN
    Ok(out)
}

/// What a DNS answer carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The TXT records (an empty list for a name with none).
    Records(Vec<String>),
    /// The answer did not fit; ask again over TCP.
    Truncated,
}

fn read_u16(buf: &[u8], at: usize) -> Result<u16, String> {
    buf.get(at..at + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or_else(|| "a short DNS answer".to_owned())
}

/// The offset just past the (possibly compressed) name at `at`. Pure.
fn skip_name(buf: &[u8], mut at: usize) -> Result<usize, String> {
    loop {
        let len = *buf.get(at).ok_or("a short DNS answer")?;
        match len {
            0 => return Ok(at + 1),
            l if l & 0xC0 == 0xC0 => return Ok(at + 2),
            l => at += 1 + usize::from(l),
        }
    }
}

/// Reads the TXT records of a DNS answer to question `id`. Pure.
pub fn decode_answer(id: u16, buf: &[u8]) -> Result<Answer, String> {
    if read_u16(buf, 0)? != id {
        return Err("a DNS answer to another question".into());
    }
    let flags = read_u16(buf, 2)?;
    if flags & 0x8000 == 0 {
        return Err("not a DNS answer".into());
    }
    if flags & 0x0200 != 0 {
        return Ok(Answer::Truncated);
    }
    match flags & 0x000F {
        0 => {}
        3 => return Ok(Answer::Records(Vec::new())),
        code => return Err(format!("DNS answered with error {code}")),
    }
    let questions = read_u16(buf, 4)?;
    let answers = read_u16(buf, 6)?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(buf, at)? + 4;
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        at = skip_name(buf, at)?;
        let kind = read_u16(buf, at)?;
        let length = usize::from(read_u16(buf, at + 8)?);
        let start = at + 10;
        let data = buf.get(start..start + length).ok_or("a short DNS answer")?;
        if kind == TYPE_TXT {
            let mut text = Vec::new();
            let mut i = 0;
            while i < data.len() {
                let n = usize::from(data[i]);
                text.extend_from_slice(data.get(i + 1..i + 1 + n).ok_or("a short TXT record")?);
                i += 1 + n;
            }
            records.push(String::from_utf8_lossy(&text).into_owned());
        }
        at = start + length;
    }
    Ok(Answer::Records(records))
}

/// TXT over UDP, then TCP when truncated, against one resolver.
#[derive(Debug, Clone)]
pub struct DnsTxtResolver {
    pub server: SocketAddr,
}

impl DnsTxtResolver {
    /// The resolver at `address` (`1.1.1.1:53`; port 53 when absent).
    pub fn new(address: &str) -> Result<Self, String> {
        let address = address.trim();
        let with_port = if address.parse::<SocketAddr>().is_ok() {
            address.to_owned()
        } else {
            format!("{address}:53")
        };
        with_port
            .parse()
            .map(|server| Self { server })
            .map_err(|_| {
                format!("{address} is not a resolver address (an IP, with an optional port)")
            })
    }

    async fn ask(&self, name: &str) -> TxtAnswer {
        let id: u16 = rand_id();
        let query = encode_query(id, name)?;
        let bind = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind)
            .await
            .map_err(|e| e.to_string())?;
        socket
            .send_to(&query, self.server)
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(DNS_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| "DNS did not answer within three seconds".to_owned())?
            .map_err(|e| e.to_string())?;
        match decode_answer(id, &buf[..n])? {
            Answer::Records(records) => Ok(records),
            Answer::Truncated => self.ask_tcp(id, &query).await,
        }
    }

    async fn ask_tcp(&self, id: u16, query: &[u8]) -> TxtAnswer {
        let exchange = async {
            let mut stream = tokio::net::TcpStream::connect(self.server)
                .await
                .map_err(|e| e.to_string())?;
            let len = u16::try_from(query.len()).map_err(|e| e.to_string())?;
            stream
                .write_all(&len.to_be_bytes())
                .await
                .map_err(|e| e.to_string())?;
            stream.write_all(query).await.map_err(|e| e.to_string())?;
            let mut len = [0u8; 2];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
            stream
                .read_exact(&mut buf)
                .await
                .map_err(|e| e.to_string())?;
            match decode_answer(id, &buf)? {
                Answer::Records(records) => Ok(records),
                Answer::Truncated => Err("DNS truncated the answer over TCP".to_owned()),
            }
        };
        tokio::time::timeout(DNS_TIMEOUT, exchange)
            .await
            .map_err(|_| "DNS did not answer within three seconds".to_owned())?
    }
}

/// A message id that differs per question (a spoofed answer must guess it).
fn rand_id() -> u16 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let mut bytes = [0u8; 2];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_ok() {
        u16::from_be_bytes(bytes)
    } else {
        (nanos & 0xFFFF) as u16
    }
}

impl TxtResolver for DnsTxtResolver {
    fn txt<'a>(&'a self, name: &'a str) -> Pin<Box<dyn Future<Output = TxtAnswer> + Send + 'a>> {
        Box::pin(self.ask(name))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    struct FakeResolver(HashMap<String, TxtAnswer>);

    impl TxtResolver for FakeResolver {
        fn txt<'a>(
            &'a self,
            name: &'a str,
        ) -> Pin<Box<dyn Future<Output = TxtAnswer> + Send + 'a>> {
            let answer = self.0.get(name).cloned().unwrap_or(Ok(Vec::new()));
            Box::pin(async move { answer })
        }
    }

    fn settings() -> DomainSettings {
        DomainSettings {
            spf_include: Some("amazonses.com".into()),
            dkim_selector: Some("s1".into()),
        }
    }

    #[tokio::test]
    async fn a_domain_with_all_three_records_is_ok() {
        let resolver = FakeResolver(HashMap::from([
            (
                "example.com".into(),
                Ok(vec![
                    "google-site-verification=x".into(),
                    "v=spf1 include:amazonses.com ~all".into(),
                ]),
            ),
            (
                "s1._domainkey.example.com".into(),
                Ok(vec!["v=DKIM1; k=rsa; p=MIIBIjAN".into()]),
            ),
            (
                "_dmarc.example.com".into(),
                Ok(vec!["v=DMARC1; p=quarantine".into()]),
            ),
        ]));
        let check = check_domain(&resolver, "Example.com.", &settings()).await;
        assert_eq!(check.domain, "example.com");
        assert!(check.ok, "{check:?}");
        assert!(check.records.iter().all(|r| r.status == "ok"));
    }

    #[tokio::test]
    async fn missing_and_wrong_records_say_what_to_add() {
        let resolver = FakeResolver(HashMap::from([
            (
                "example.com".into(),
                Ok(vec!["v=spf1 include:sendgrid.net ~all".into()]),
            ),
            (
                "s1._domainkey.example.com".into(),
                Ok(vec!["v=DKIM1; p=".into()]),
            ),
        ]));
        let check = check_domain(&resolver, "example.com", &settings()).await;
        assert!(!check.ok);
        let status: Vec<_> = check.records.iter().map(|r| (r.kind, r.status)).collect();
        assert_eq!(
            status,
            [("spf", "wrong"), ("dkim", "wrong"), ("dmarc", "missing")]
        );
        assert_eq!(
            check.records[0].expected,
            "v=spf1 include:amazonses.com ~all"
        );
        assert_eq!(
            check.records[2].expected,
            "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        );
    }

    #[test]
    fn two_spf_records_are_wrong_and_dns_failure_is_unknown() {
        let two = Ok(vec!["v=spf1 mx ~all".into(), "v=spf1 a ~all".into()]);
        assert_eq!(
            judge_spf("e.com", &DomainSettings::default(), &two).status,
            "wrong"
        );
        let down: TxtAnswer = Err("DNS did not answer within three seconds".into());
        assert_eq!(judge_dmarc("e.com", &down).status, "unknown");
        let unnamed = judge_dkim("e.com", &DomainSettings::default(), None);
        assert_eq!(unnamed.status, "not_configured");
    }

    #[test]
    fn domain_names_are_checked() {
        assert!(domain_ok("mail.example.com"));
        assert!(domain_ok("example.sa."));
        assert!(!domain_ok("localhost"));
        assert!(!domain_ok("-bad.example.com"));
        assert!(!domain_ok("ex ample.com"));
        assert!(!domain_ok(&format!("{}.com", "a".repeat(64))));
    }

    /// A TXT answer for `example.com` built by hand, with a compressed name
    /// and a record split over two character strings.
    fn answer(id: u16, flags: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
        out.extend_from_slice(b"\x07example\x03com\x00\x00\x10\x00\x01");
        out.extend_from_slice(&[0xC0, 12]);
        out.extend_from_slice(&[0, 16, 0, 1, 0, 0, 1, 0]);
        let data: &[u8] = b"\x07v=spf1 \x08mx ~all.";
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn dns_answers_are_read() {
        let query = encode_query(0x1234, "example.com").unwrap();
        assert_eq!(&query[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x10\x00\x01");
        assert_eq!(
            decode_answer(0x1234, &answer(0x1234, 0x8180)).unwrap(),
            Answer::Records(vec!["v=spf1 mx ~all.".into()])
        );
        assert_eq!(
            decode_answer(0x1234, &answer(0x1234, 0x8380)).unwrap(),
            Answer::Truncated
        );
        assert_eq!(
            decode_answer(0x1234, &answer(0x1234, 0x8183)).unwrap(),
            Answer::Records(Vec::new())
        );
        assert!(decode_answer(0x9999, &answer(0x1234, 0x8180)).is_err());
        assert!(decode_answer(0x1234, &answer(0x1234, 0x8180)[..20]).is_err());
        assert!(encode_query(1, "bad..name").is_err());
        assert_eq!(
            DnsTxtResolver::new("1.1.1.1").unwrap().server,
            "1.1.1.1:53".parse::<SocketAddr>().unwrap()
        );
        assert!(DnsTxtResolver::new("dns.example").is_err());
    }
}
