//! E6-T7: DMARC aggregate reports (RFC 7489 appendix C) — parsed from raw
//! XML, `.gz` or `.zip`, stored once per reporter and report id, and
//! summarised per sending source.
//!
//! **Parsing** reads at most [`MAX_XML_BYTES`] of XML after decompression
//! and refuses any document type declaration, so no entity — internal or
//! external — is ever defined or expanded. Element names are read without
//! their namespace prefix, so both the bare schema and the
//! `urn:ietf:params:xml:ns:dmarc-2.0` one parse.
//!
//! **Storage** is `marketing_dmarc_report` and `marketing_dmarc_record`
//! (migration 0164) in one transaction; a report seen before (the same
//! `reporter_org` and `report_id`) is skipped, so ingesting a mailbox twice
//! stores nothing new.
//!
//! **Not here yet:** reading the reports from a mailbox. The J2-T1 readers
//! list attachments without fetching them, so the 30-minute poll waits for
//! an attachment fetch there; reports arrive through [`ingest`] (the upload
//! route, E6-T11) until then.

use std::io::Read;

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use quick_xml::events::Event;
use serde::Serialize;
use uuid::Uuid;

/// The most XML read from one report, after decompression.
pub const MAX_XML_BYTES: u64 = 20 * 1024 * 1024;

/// One row of a report: a sending source and how its mail fared.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DmarcRecord {
    pub source_ip: String,
    pub count: i64,
    pub disposition: String,
    /// The policy-evaluated DKIM result (`pass`/`fail`).
    pub dkim: String,
    /// The policy-evaluated SPF result (`pass`/`fail`).
    pub spf: String,
    pub header_from: String,
}

/// One aggregate report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DmarcReport {
    pub reporter_org: String,
    pub report_id: String,
    pub domain: String,
    /// The published policy (`none`, `quarantine`, `reject`).
    pub policy: String,
    pub date_begin: i64,
    pub date_end: i64,
    pub records: Vec<DmarcRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DmarcError {
    #[error("the report is larger than 20 MB")]
    TooLarge,
    #[error("the report declares a document type, which is not accepted")]
    DocType,
    #[error("the archive holds no XML report")]
    EmptyArchive,
    #[error("the report is not readable XML: {0}")]
    Xml(String),
    #[error("the report has no {0}")]
    Missing(&'static str),
}

impl From<DmarcError> for AppError {
    fn from(e: DmarcError) -> Self {
        AppError::Validation(e.to_string())
    }
}

/// Reads at most [`MAX_XML_BYTES`] (one byte more means too large).
fn bounded(reader: impl Read) -> Result<Vec<u8>, DmarcError> {
    let mut out = Vec::new();
    reader
        .take(MAX_XML_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| DmarcError::Xml(e.to_string()))?;
    if out.len() as u64 > MAX_XML_BYTES {
        return Err(DmarcError::TooLarge);
    }
    Ok(out)
}

fn u16_at(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..at + 2)
        .map(|s| usize::from(u16::from_le_bytes([s[0], s[1]])))
}

fn u32_at(b: &[u8], at: usize) -> Option<usize> {
    b.get(at..at + 4)
        .and_then(|s| usize::try_from(u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok())
}

/// The first `.xml` member of a ZIP archive, inflated. Stored and deflated
/// members only. Pure.
fn zip_xml(archive: &[u8]) -> Result<Vec<u8>, DmarcError> {
    let floor = archive.len().saturating_sub(22 + 65_535);
    let eocd = (floor..=archive.len().saturating_sub(22))
        .rev()
        .find(|&i| archive.get(i..i + 4) == Some(b"PK\x05\x06"))
        .ok_or(DmarcError::EmptyArchive)?;
    let entries = u16_at(archive, eocd + 10).ok_or(DmarcError::EmptyArchive)?;
    let mut at = u32_at(archive, eocd + 16).ok_or(DmarcError::EmptyArchive)?;
    for _ in 0..entries {
        if archive.get(at..at + 4) != Some(b"PK\x01\x02") {
            break;
        }
        let field = |offset| u16_at(archive, at + offset).ok_or(DmarcError::EmptyArchive);
        let method = field(10)?;
        let compressed = u32_at(archive, at + 20).ok_or(DmarcError::EmptyArchive)?;
        let name_len = field(28)?;
        let extra_len = field(30)?;
        let comment_len = field(32)?;
        let local = u32_at(archive, at + 42).ok_or(DmarcError::EmptyArchive)?;
        let name = archive
            .get(at + 46..at + 46 + name_len)
            .ok_or(DmarcError::EmptyArchive)?;
        if name.to_ascii_lowercase().ends_with(b".xml")
            && archive.get(local..local + 4) == Some(b"PK\x03\x04")
        {
            let data_at = local
                + 30
                + u16_at(archive, local + 26).ok_or(DmarcError::EmptyArchive)?
                + u16_at(archive, local + 28).ok_or(DmarcError::EmptyArchive)?;
            let data = data_at
                .checked_add(compressed)
                .and_then(|end| archive.get(data_at..end))
                .ok_or(DmarcError::EmptyArchive)?;
            return match method {
                0 => bounded(data),
                8 => bounded(flate2::read::DeflateDecoder::new(data)),
                _ => Err(DmarcError::EmptyArchive),
            };
        }
        at += 46 + name_len + extra_len + comment_len;
    }
    Err(DmarcError::EmptyArchive)
}

/// The XML inside `bytes`: gzip and ZIP are recognised by their magic.
fn xml_of(bytes: &[u8]) -> Result<Vec<u8>, DmarcError> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        bounded(flate2::read::GzDecoder::new(bytes))
    } else if bytes.starts_with(b"PK\x03\x04") {
        zip_xml(bytes)
    } else {
        bounded(bytes)
    }
}

/// Parses one aggregate report from XML, `.gz` or `.zip` bytes. Pure.
pub fn parse_report(bytes: &[u8]) -> Result<DmarcReport, DmarcError> {
    let xml = xml_of(bytes)?;
    let mut reader = quick_xml::Reader::from_reader(xml.as_slice());
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();
    let mut report = DmarcReport::default();
    let mut record = DmarcRecord::default();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::DocType(_)) => return Err(DmarcError::DocType),
            Ok(Event::Start(e)) => {
                path.push(String::from_utf8_lossy(e.local_name().as_ref()).into_owned());
                if path.last().is_some_and(|n| n == "record") {
                    record = DmarcRecord::default();
                }
            }
            Ok(Event::End(_)) => {
                if path.last().is_some_and(|n| n == "record") {
                    report.records.push(std::mem::take(&mut record));
                }
                path.pop();
            }
            Ok(Event::Text(t)) => {
                let text = t
                    .decode()
                    .map_err(|e| DmarcError::Xml(e.to_string()))?
                    .trim()
                    .to_owned();
                if text.is_empty() {
                    buf.clear();
                    continue;
                }
                let at: Vec<&str> = path.iter().map(String::as_str).collect();
                match at.as_slice() {
                    [.., "report_metadata", "org_name"] => report.reporter_org = text,
                    [.., "report_metadata", "report_id"] => report.report_id = text,
                    [.., "date_range", "begin"] => report.date_begin = text.parse().unwrap_or(0),
                    [.., "date_range", "end"] => report.date_end = text.parse().unwrap_or(0),
                    [.., "policy_published", "domain"] => report.domain = text,
                    [.., "policy_published", "p"] => report.policy = text,
                    [.., "row", "source_ip"] => record.source_ip = text,
                    [.., "row", "count"] => record.count = text.parse().unwrap_or(0),
                    [.., "policy_evaluated", "disposition"] => record.disposition = text,
                    [.., "policy_evaluated", "dkim"] => record.dkim = text,
                    [.., "policy_evaluated", "spf"] => record.spf = text,
                    [.., "identifiers", "header_from"] => record.header_from = text,
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(DmarcError::Xml(e.to_string())),
            _ => {}
        }
        buf.clear();
    }
    if report.reporter_org.is_empty() {
        return Err(DmarcError::Missing("org_name"));
    }
    if report.report_id.is_empty() {
        return Err(DmarcError::Missing("report_id"));
    }
    if report.domain.is_empty() {
        return Err(DmarcError::Missing("policy domain"));
    }
    Ok(report)
}

fn at(seconds: i64) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(seconds, 0)
}

/// Stores a report and its rows in one transaction. `false` when the same
/// reporter's report id is already stored. With `audit` (the audit service
/// and the person uploading), a stored report writes its Configuration
/// event in the same transaction.
pub async fn store_report(
    db: &DbPool,
    report: &DmarcReport,
    audit: Option<(&attome_audit::AuditService<'_>, Uuid)>,
) -> Result<bool, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO marketing_dmarc_report \
           (reporter_org, report_id, domain, policy, date_begin, date_end) \
         VALUES ($1, $2, lower($3), $4, $5, $6) \
         ON CONFLICT (reporter_org, report_id) DO NOTHING RETURNING id",
    )
    .bind(&report.reporter_org)
    .bind(&report.report_id)
    .bind(&report.domain)
    .bind(&report.policy)
    .bind(at(report.date_begin))
    .bind(at(report.date_end))
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(id) = id else {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(false);
    };
    let column = |f: fn(&DmarcRecord) -> String| report.records.iter().map(f).collect::<Vec<_>>();
    let counts: Vec<i64> = report.records.iter().map(|r| r.count).collect();
    sqlx::query(
        "INSERT INTO marketing_dmarc_record \
           (report_ref, source_ip, message_count, disposition, dkim, spf, header_from) \
         SELECT $1, r.ip, r.n, r.disposition, r.dkim, r.spf, r.header_from \
           FROM unnest($2::text[], $3::bigint[], $4::text[], $5::text[], $6::text[], $7::text[]) \
                AS r(ip, n, disposition, dkim, spf, header_from)",
    )
    .bind(id)
    .bind(column(|r| r.source_ip.clone()))
    .bind(&counts)
    .bind(column(|r| r.disposition.clone()))
    .bind(column(|r| r.dkim.to_ascii_lowercase()))
    .bind(column(|r| r.spf.to_ascii_lowercase()))
    .bind(column(|r| r.header_from.to_ascii_lowercase()))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if let Some((service, actor)) = audit {
        attome_audit::security::write_security_event(
            &mut tx,
            service,
            attome_audit::security::SecurityEvent::new(
                attome_audit::security::MandatoryCategory::Configuration,
                attome_audit::AuditOperation::Create,
                actor,
                "marketing_dmarc_report",
                Some(id),
            )
            .named("dmarc.upload")
            .comment(format!(
                "DMARC report {} from {} for {}",
                report.report_id, report.reporter_org, report.domain
            )),
        )
        .await?;
    }
    tx.commit().await.map_err(AppError::internal)?;
    Ok(true)
}

/// Parses and stores one report file. `false` for a report already stored.
pub async fn ingest(db: &DbPool, bytes: &[u8]) -> Result<bool, AppError> {
    let report = parse_report(bytes)?;
    store_report(db, &report, None).await
}

/// How one source sent as the domain over the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SourceSummary {
    pub source_ip: String,
    pub messages: i64,
    pub spf_pass: i64,
    pub dkim_pass: i64,
    /// Messages that failed both SPF and DKIM.
    pub both_fail: i64,
}

/// Per source, the messages reported for `domain` in the last `days`, with
/// SPF and DKIM passes, and the sources that failed both for every message
/// (sending as the domain without authorisation), most messages first.
pub async fn summarise(
    db: &DbPool,
    domain: &str,
    days: i32,
) -> Result<(Vec<SourceSummary>, Vec<String>), AppError> {
    let rows: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT r.source_ip, \
                COALESCE(SUM(r.message_count), 0)::bigint, \
                COALESCE(SUM(r.message_count) FILTER (WHERE r.spf = 'pass'), 0)::bigint, \
                COALESCE(SUM(r.message_count) FILTER (WHERE r.dkim = 'pass'), 0)::bigint, \
                COALESCE(SUM(r.message_count) FILTER (WHERE r.spf <> 'pass' AND r.dkim <> 'pass'), 0)::bigint \
           FROM marketing_dmarc_record r \
           JOIN marketing_dmarc_report p ON p.id = r.report_ref \
          WHERE p.domain = lower($1) AND p.date_end >= now() - make_interval(days => $2) \
          GROUP BY r.source_ip \
          ORDER BY 2 DESC, 1",
    )
    .bind(domain)
    .bind(days)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let sources: Vec<SourceSummary> = rows
        .into_iter()
        .map(
            |(source_ip, messages, spf_pass, dkim_pass, both_fail)| SourceSummary {
                source_ip,
                messages,
                spf_pass,
                dkim_pass,
                both_fail,
            },
        )
        .collect();
    let unauthorised = unauthorised(&sources);
    Ok((sources, unauthorised))
}

/// The sources whose every message failed both checks. Pure.
pub fn unauthorised(sources: &[SourceSummary]) -> Vec<String> {
    sources
        .iter()
        .filter(|s| s.messages > 0 && s.both_fail == s.messages)
        .map(|s| s.source_ip.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE: &[u8] = include_bytes!("../tests/fixtures/dmarc/google_sample.xml");
    const MICROSOFT: &[u8] = include_bytes!("../tests/fixtures/dmarc/microsoft_sample.xml.gz");

    #[test]
    fn parse_plain_xml_fixture() {
        let report = parse_report(GOOGLE).unwrap();
        assert_eq!(report.reporter_org, "google.com");
        assert_eq!(report.report_id, "17391234567890123456");
        assert_eq!(report.domain, "example.com");
        assert_eq!(report.policy, "none");
        assert_eq!(report.records.len(), 3);
        assert_eq!(report.records[2].source_ip, "192.0.2.99");
        assert_eq!(
            (
                report.records[2].dkim.as_str(),
                report.records[2].spf.as_str()
            ),
            ("fail", "fail")
        );
        let summary: Vec<SourceSummary> = report
            .records
            .iter()
            .map(|r| SourceSummary {
                source_ip: r.source_ip.clone(),
                messages: r.count,
                spf_pass: if r.spf == "pass" { r.count } else { 0 },
                dkim_pass: if r.dkim == "pass" { r.count } else { 0 },
                both_fail: if r.spf != "pass" && r.dkim != "pass" {
                    r.count
                } else {
                    0
                },
            })
            .collect();
        assert_eq!(unauthorised(&summary), vec!["192.0.2.99"]);
    }

    #[test]
    fn parse_gzip_fixture() {
        let report = parse_report(MICROSOFT).unwrap();
        assert_eq!(report.reporter_org, "Enterprise Outlook");
        assert_eq!(report.policy, "quarantine");
        assert_eq!(report.records.len(), 2);
        assert_eq!(report.records[1].disposition, "quarantine");
    }

    #[test]
    fn rejects_oversize_input() {
        let mut big = b"<feedback>".to_vec();
        big.resize(usize::try_from(MAX_XML_BYTES).unwrap() + 10, b' ');
        assert_eq!(parse_report(&big), Err(DmarcError::TooLarge));
    }

    #[test]
    fn rejects_external_entities() {
        let xml = br#"<?xml version="1.0"?>
<!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<feedback><report_metadata><org_name>&xxe;</org_name></report_metadata></feedback>"#;
        assert_eq!(parse_report(xml), Err(DmarcError::DocType));
    }
}
