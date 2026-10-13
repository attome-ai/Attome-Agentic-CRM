//! Audit hash version 2 — the canonical event encoding (D-539, audit 10/10
//! plan items 2.2 and 2.3).
//!
//! This module is the **only** implementation of `CANONICAL_EVENT_V2` in the
//! platform. Both writers (`AuditService`'s synchronous path and the chainer)
//! and the verifier (`crate::verify`) call it, so the bytes a writer digests
//! and the bytes a verifier recomputes from stored rows cannot drift apart.
//! `tests/vectors/hash_v2.json` publishes its output for an independent
//! implementation, and `tests/hash_v2_tamper.rs::test_vector_matches` pins it.
//!
//! ## What the digest covers
//!
//! The stored header columns listed in D-539 (fields 1–29), the stored detail
//! rows (field 40), the stored snapshot row (field 41) and the attachment
//! references (field 42). Values are the **stored** form: after D-107
//! encryption, after sensitive-value masking, and with the database
//! transaction clock as `changed_on`. Actor display fields, row ids and chain
//! metadata are excluded on purpose (D-539 ruling 3, "Excluded").
//!
//! ## Framing, as implemented
//!
//! Every field — scalar or composite — is `u16 field_no`, then a presence tag
//! `u8` (`0x00` SQL NULL / absent, `0x01` present), then, when present,
//! `LP(value)`. For the composite fields that means:
//!
//! - field 40 (details): present, value = `u32 count` then `LP(row bytes)` per
//!   row, rows ordered by `field_name` bytes;
//! - field 41 (snapshot): `0x00` with no snapshot row, else `0x01` then
//!   `LP(row bytes)`;
//! - field 42 (attachments): present, value = `u32 count` then `LP(row bytes)`
//!   per attachment, ordered by `document_ref` then `content_sha256` bytes.
//!
//! D-539's text states the snapshot framing exactly and the list framing as
//! "`u32 count`, then each row as `LP(row bytes)`"; wrapping that list in the
//! same presence tag and length prefix as every other field keeps one field
//! syntax for the whole stream. The D-539 implementation record says so.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::initiator::Attribution;
use crate::model::AuditEvent;

/// The original hash formula (`service::compute_hash_raw`). Every row written
/// before hash v2 carries it, and it verifies forever (I9).
pub const HASH_VERSION_V1: i16 = 1;
/// The complete-event digest of D-539.
pub const HASH_VERSION_V2: i16 = 2;

const EVENT_MAGIC: &[u8] = b"ATTOME-AUDIT-EVENT";
const CHAIN_DOMAIN: &[u8] = b"ATTOME-AUDIT-CHAIN";

/// The value `audit_snapshot.trigger` is written with today (see
/// `AuditService::write_snapshot`).
pub(crate) const SNAPSHOT_TRIGGER_ON_WRITE: i32 = 0;

/// An event that cannot be encoded. Always a hard failure: a writer refuses
/// the write, a verifier reports the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// Two detail rows of one header share a `field_name`.
    DuplicateDetailField(Option<String>),
    /// More than one `audit_snapshot` row names the header.
    MultipleSnapshots(usize),
    /// A field number was emitted out of ascending order (an implementation
    /// defect, never data-dependent).
    FieldOrder { previous: u16, next: u16 },
    /// An attachment `content_sha256` is not 64 hex characters.
    InvalidDigestHex(String),
    /// A value longer than `u32::MAX` bytes.
    TooLong,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicateDetailField(name) => {
                write!(f, "two detail rows share field_name {name:?}")
            }
            Self::MultipleSnapshots(n) => write!(f, "{n} snapshot rows name one header"),
            Self::FieldOrder { previous, next } => {
                write!(f, "field {next} emitted after field {previous}")
            }
            Self::InvalidDigestHex(v) => write!(f, "{v:?} is not a 64-char hex SHA-256 digest"),
            Self::TooLong => f.write_str("a value exceeds u32::MAX bytes"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Header fields 1–29, typed as their `audit_header` columns.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct CanonicalHeader {
    pub organization_ref: Option<Uuid>,
    pub category: Option<i32>,
    pub operation: Option<i32>,
    pub source: Option<i32>,
    pub entity_name: Option<String>,
    pub record_id: Option<Uuid>,
    pub version_before: Option<i64>,
    pub version_after: Option<i64>,
    pub user_id: Option<Uuid>,
    pub initiator: Option<i16>,
    pub agent_session_id: Option<Uuid>,
    pub agent_action_id: Option<String>,
    pub changed_on: Option<DateTime<Utc>>,
    pub correlation_id: Option<Uuid>,
    pub batch_id: Option<Uuid>,
    pub event_name: Option<String>,
    pub event_comment: Option<String>,
    pub ip_address: Option<String>,
    pub browser: Option<String>,
    pub device_type: Option<i32>,
    pub request_id: Option<String>,
    pub session_id: Option<Uuid>,
    pub ai_model_id: Option<String>,
    pub approval_request_ref: Option<Uuid>,
    pub outcome: Option<i16>,
    pub requested_count: Option<i32>,
    pub affected_count: Option<i32>,
    pub failed_count: Option<i32>,
    pub occurrence_count: Option<i32>,
}

/// One `audit_detail` row (field 40).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct CanonicalDetail {
    pub field_name: Option<String>,
    pub display_name: Option<String>,
    pub data_type: Option<i32>,
    pub value_mode: Option<i16>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub old_display_value: Option<String>,
    pub new_display_value: Option<String>,
    pub old_lookup_entity: Option<String>,
    pub old_lookup_name: Option<String>,
    pub new_lookup_entity: Option<String>,
    pub new_lookup_name: Option<String>,
    pub is_sensitive: Option<bool>,
}

/// The `audit_snapshot` row (field 41). `snapshot_json` is the stored
/// `jsonb` value; [`snapshot_canonical_text`] turns it into field 3's bytes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CanonicalSnapshot {
    pub version: Option<i64>,
    pub trigger: Option<i32>,
    pub snapshot_json: Option<serde_json::Value>,
}

/// One attachment reference (field 42). No table stores these until Phase 7
/// (`audit_attachment`), so every event written today encodes zero.
/// `content_sha256` is hex here and encoded as its raw 32 bytes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CanonicalAttachment {
    pub document_ref: Option<Uuid>,
    pub content_sha256: Option<String>,
    pub filename: Option<String>,
    pub attached_by: Option<Uuid>,
    pub attached_on: Option<DateTime<Utc>>,
}

/// Everything `CANONICAL_EVENT_V2` covers for one header.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CanonicalEvent {
    pub header: CanonicalHeader,
    pub details: Vec<CanonicalDetail>,
    /// Stored snapshot rows naming this header. More than one is an encoding
    /// error (a verifier reports it; a writer never produces it).
    pub snapshots: Vec<CanonicalSnapshot>,
    pub attachments: Vec<CanonicalAttachment>,
}

impl CanonicalEvent {
    /// The event exactly as a writer will store it. `event` must already be
    /// in its stored form: encrypted (D-107), masked, and carrying the
    /// database clock in `changed_on`.
    pub fn from_event(
        event: &AuditEvent,
        attribution: &Attribution,
        extras: &crate::model::EventExtras,
    ) -> Self {
        let header = CanonicalHeader {
            organization_ref: Some(event.organization_ref),
            category: Some(event.category as i32),
            operation: Some(event.operation as i32),
            source: Some(event.source as i32),
            entity_name: event.entity_name.clone(),
            record_id: event.record_id,
            version_before: event.version_before,
            version_after: event.version_after,
            user_id: Some(event.user_context.user_id),
            initiator: Some(attribution.initiator.as_i16()),
            agent_session_id: attribution.agent_session_id,
            agent_action_id: attribution.agent_action_id.clone(),
            changed_on: Some(event.changed_on),
            correlation_id: event.correlation_id,
            batch_id: event.batch_id,
            event_name: event.event_name.clone(),
            event_comment: event.event_comment.clone(),
            ip_address: event.request_context.ip_address.clone(),
            browser: event.request_context.browser.clone(),
            device_type: event.request_context.device_type,
            // D-541 rule 3 (fields 25-29): set by the security writer and,
            // later, bulk parent events.
            outcome: extras.outcome_i16(),
            requested_count: extras.requested_count,
            affected_count: extras.affected_count,
            failed_count: extras.failed_count,
            occurrence_count: extras.occurrence_count,
            // C19 (fields 23-24): set on AI actions by the mandatory writer.
            ai_model_id: extras.ai_model_id.clone(),
            approval_request_ref: extras.approval_request_ref,
            // Fields 21-22 (request and session id) are reserved by D-539
            // ruling 7 and populated by Phase 4; no writer sets them yet.
            ..CanonicalHeader::default()
        };

        let details = event
            .changed_fields
            .iter()
            .map(|f| CanonicalDetail {
                field_name: Some(f.field_name.clone()),
                display_name: f.display_name.clone(),
                data_type: f.data_type,
                value_mode: Some(
                    crate::value_mode::classify(
                        event.entity_name.as_deref(),
                        &f.field_name,
                        f.is_sensitive,
                    )
                    .as_i16(),
                ),
                old_value: f.old_value.clone(),
                new_value: f.new_value.clone(),
                old_display_value: f.old_display_value.clone(),
                new_display_value: f.new_display_value.clone(),
                old_lookup_entity: f.old_lookup_entity.clone(),
                old_lookup_name: f.old_lookup_name.clone(),
                new_lookup_entity: f.new_lookup_entity.clone(),
                new_lookup_name: f.new_lookup_name.clone(),
                is_sensitive: Some(f.is_sensitive),
            })
            .collect();

        let snapshots = event
            .snapshot_json
            .as_ref()
            .map(|json| CanonicalSnapshot {
                version: event.version_after,
                trigger: Some(SNAPSHOT_TRIGGER_ON_WRITE),
                snapshot_json: Some(json.clone()),
            })
            .into_iter()
            .collect();

        Self {
            header,
            details,
            snapshots,
            attachments: Vec::new(),
        }
    }
}

// ── primitives ──────────────────────────────────────────────────────────────

struct FieldWriter {
    buf: Vec<u8>,
    last: Option<u16>,
}

impl FieldWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            last: None,
        }
    }

    fn tag(&mut self, no: u16) -> Result<(), EncodeError> {
        if let Some(previous) = self.last
            && no <= previous
        {
            return Err(EncodeError::FieldOrder { previous, next: no });
        }
        self.last = Some(no);
        self.buf.extend_from_slice(&no.to_be_bytes());
        Ok(())
    }

    fn opt(&mut self, no: u16, value: Option<&[u8]>) -> Result<(), EncodeError> {
        self.tag(no)?;
        match value {
            None => self.buf.push(0x00),
            Some(bytes) => {
                self.buf.push(0x01);
                push_lp(&mut self.buf, bytes)?;
            }
        }
        Ok(())
    }

    fn text(&mut self, no: u16, v: &Option<String>) -> Result<(), EncodeError> {
        self.opt(no, v.as_deref().map(str::as_bytes))
    }

    fn uuid(&mut self, no: u16, v: &Option<Uuid>) -> Result<(), EncodeError> {
        self.opt(no, v.as_ref().map(|u| u.as_bytes().as_slice()))
    }

    fn i16(&mut self, no: u16, v: Option<i16>) -> Result<(), EncodeError> {
        self.opt(no, v.map(i16::to_be_bytes).as_ref().map(|b| b.as_slice()))
    }

    fn i32(&mut self, no: u16, v: Option<i32>) -> Result<(), EncodeError> {
        self.opt(no, v.map(i32::to_be_bytes).as_ref().map(|b| b.as_slice()))
    }

    fn i64(&mut self, no: u16, v: Option<i64>) -> Result<(), EncodeError> {
        self.opt(no, v.map(i64::to_be_bytes).as_ref().map(|b| b.as_slice()))
    }

    fn bool(&mut self, no: u16, v: Option<bool>) -> Result<(), EncodeError> {
        self.opt(no, v.map(|b| [u8::from(b)]).as_ref().map(|b| b.as_slice()))
    }

    fn timestamptz(&mut self, no: u16, v: Option<DateTime<Utc>>) -> Result<(), EncodeError> {
        self.i64(no, v.map(|t| t.timestamp_micros()))
    }

    fn rows(&mut self, no: u16, rows: &[Vec<u8>]) -> Result<(), EncodeError> {
        let count = u32::try_from(rows.len()).map_err(|_| EncodeError::TooLong)?;
        let mut value = count.to_be_bytes().to_vec();
        for row in rows {
            push_lp(&mut value, row)?;
        }
        self.opt(no, Some(&value))
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

fn push_lp(buf: &mut Vec<u8>, bytes: &[u8]) -> Result<(), EncodeError> {
    let len = u32::try_from(bytes.len()).map_err(|_| EncodeError::TooLong)?;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    ::hex::encode(bytes)
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], EncodeError> {
    let invalid = || EncodeError::InvalidDigestHex(s.to_owned());
    if s.len() != 64 || !s.is_ascii() {
        return Err(invalid());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(out)
}

// ── encoding ────────────────────────────────────────────────────────────────

/// `CANONICAL_EVENT_V2` with the magic version `2`. See [`encode_with_magic`].
pub fn encode_v2(event: &CanonicalEvent) -> Result<Vec<u8>, EncodeError> {
    encode_with_magic(event, HASH_VERSION_V2 as u16)
}

/// The canonical byte stream with an explicit magic version. Hash v2 uses
/// `2`. D-539 ruling 6's v1 cutover checkpoint (plan item 2.6) encodes stored
/// v1 events with the same field layout and the magic version written as `1`.
pub fn encode_with_magic(
    event: &CanonicalEvent,
    magic_version: u16,
) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    push_lp(&mut out, EVENT_MAGIC)?;
    out.extend_from_slice(&magic_version.to_be_bytes());

    let h = &event.header;
    let mut w = FieldWriter::new();
    w.uuid(1, &h.organization_ref)?;
    w.i32(2, h.category)?;
    w.i32(3, h.operation)?;
    w.i32(4, h.source)?;
    w.text(5, &h.entity_name)?;
    w.uuid(6, &h.record_id)?;
    w.i64(7, h.version_before)?;
    w.i64(8, h.version_after)?;
    w.uuid(9, &h.user_id)?;
    w.i16(10, h.initiator)?;
    w.uuid(11, &h.agent_session_id)?;
    w.text(12, &h.agent_action_id)?;
    w.timestamptz(13, h.changed_on)?;
    w.uuid(14, &h.correlation_id)?;
    w.uuid(15, &h.batch_id)?;
    w.text(16, &h.event_name)?;
    w.text(17, &h.event_comment)?;
    w.text(18, &h.ip_address)?;
    w.text(19, &h.browser)?;
    w.i32(20, h.device_type)?;
    w.text(21, &h.request_id)?;
    w.uuid(22, &h.session_id)?;
    w.text(23, &h.ai_model_id)?;
    w.uuid(24, &h.approval_request_ref)?;
    w.i16(25, h.outcome)?;
    w.i32(26, h.requested_count)?;
    w.i32(27, h.affected_count)?;
    w.i32(28, h.failed_count)?;
    w.i32(29, h.occurrence_count)?;

    w.rows(40, &encode_details(&event.details)?)?;

    match event.snapshots.as_slice() {
        [] => w.opt(41, None)?,
        [snapshot] => w.opt(41, Some(&encode_snapshot(snapshot)?))?,
        many => return Err(EncodeError::MultipleSnapshots(many.len())),
    }

    w.rows(42, &encode_attachments(&event.attachments)?)?;

    out.extend_from_slice(&w.finish());
    Ok(out)
}

fn encode_details(details: &[CanonicalDetail]) -> Result<Vec<Vec<u8>>, EncodeError> {
    let mut sorted: Vec<&CanonicalDetail> = details.iter().collect();
    sorted.sort_by(|a, b| {
        a.field_name
            .as_deref()
            .map(str::as_bytes)
            .cmp(&b.field_name.as_deref().map(str::as_bytes))
    });
    if let Some(pair) = sorted
        .windows(2)
        .find(|p| p[0].field_name == p[1].field_name)
    {
        return Err(EncodeError::DuplicateDetailField(
            pair[0].field_name.clone(),
        ));
    }

    sorted
        .into_iter()
        .map(|d| {
            let mut w = FieldWriter::new();
            w.text(1, &d.field_name)?;
            w.text(2, &d.display_name)?;
            w.i32(3, d.data_type)?;
            w.i16(4, d.value_mode)?;
            w.text(5, &d.old_value)?;
            w.text(6, &d.new_value)?;
            w.text(7, &d.old_display_value)?;
            w.text(8, &d.new_display_value)?;
            w.text(9, &d.old_lookup_entity)?;
            w.text(10, &d.old_lookup_name)?;
            w.text(11, &d.new_lookup_entity)?;
            w.text(12, &d.new_lookup_name)?;
            w.bool(13, d.is_sensitive)?;
            Ok(w.finish())
        })
        .collect()
}

fn encode_snapshot(s: &CanonicalSnapshot) -> Result<Vec<u8>, EncodeError> {
    let mut w = FieldWriter::new();
    w.i64(1, s.version)?;
    w.i32(2, s.trigger)?;
    w.text(3, &s.snapshot_json.as_ref().map(snapshot_canonical_text))?;
    Ok(w.finish())
}

fn encode_attachments(attachments: &[CanonicalAttachment]) -> Result<Vec<Vec<u8>>, EncodeError> {
    let mut decoded = attachments
        .iter()
        .map(|a| {
            let sha = a.content_sha256.as_deref().map(decode_hex_32).transpose()?;
            Ok((a, sha))
        })
        .collect::<Result<Vec<_>, EncodeError>>()?;
    decoded.sort_by(|(a, a_sha), (b, b_sha)| {
        a.document_ref
            .as_ref()
            .map(|u| *u.as_bytes())
            .cmp(&b.document_ref.as_ref().map(|u| *u.as_bytes()))
            .then_with(|| a_sha.cmp(b_sha))
    });

    decoded
        .into_iter()
        .map(|(a, sha)| {
            let mut w = FieldWriter::new();
            w.uuid(1, &a.document_ref)?;
            w.opt(2, sha.as_ref().map(|s| s.as_slice()))?;
            w.text(3, &a.filename)?;
            w.uuid(4, &a.attached_by)?;
            w.timestamptz(5, a.attached_on)?;
            Ok(w.finish())
        })
        .collect()
}

/// SHA-256 over the canonical bytes, as 32 raw bytes.
pub fn digest_bytes(canonical: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical).into()
}

/// `content_digest` for a v2 event: SHA-256 over `CANONICAL_EVENT_V2`, as the
/// 64 lowercase hex characters `audit_header.content_digest` stores.
pub fn content_digest_v2(event: &CanonicalEvent) -> Result<String, EncodeError> {
    Ok(hex(&digest_bytes(&encode_v2(event)?)))
}

/// `event_hash` for a v2 row: `SHA-256("ATTOME-AUDIT-CHAIN" || 0x00 || u16(2)
/// || LP(prev_hash) || content_digest)`. `prev_hash` is the previous row's
/// stored `event_hash` verbatim (a v1 or v2 hash), empty for genesis.
pub fn event_hash_v2(prev_hash: &str, content_digest_hex: &str) -> Result<String, EncodeError> {
    let digest = decode_hex_32(content_digest_hex)?;
    let mut h = Sha256::new();
    h.update(CHAIN_DOMAIN);
    h.update([0x00]);
    h.update((HASH_VERSION_V2 as u16).to_be_bytes());
    let len = u32::try_from(prev_hash.len()).map_err(|_| EncodeError::TooLong)?;
    h.update(len.to_be_bytes());
    h.update(prev_hash.as_bytes());
    h.update(digest);
    Ok(hex(&h.finalize()))
}

/// The v1 formula, re-exported for the published test vector's v1→v2 link
/// case and for independent implementations. Unchanged forever (I9).
pub fn event_hash_v1(
    prev_hash: &str,
    operation: i32,
    entity_name: Option<&str>,
    record_id: Option<Uuid>,
    user_id: Uuid,
    changed_on_millis: i64,
) -> String {
    crate::service::compute_hash_raw(
        prev_hash,
        operation,
        entity_name,
        record_id,
        user_id,
        changed_on_millis,
    )
}

// ── stored rows ─────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct StoredHeader {
    id: Uuid,
    #[sqlx(flatten)]
    header: CanonicalHeader,
}

#[derive(sqlx::FromRow)]
struct StoredDetail {
    audit_ref: Option<Uuid>,
    #[sqlx(flatten)]
    detail: CanonicalDetail,
}

#[derive(sqlx::FromRow)]
struct StoredSnapshot {
    audit_ref: Option<Uuid>,
    version: Option<i64>,
    trigger: Option<i32>,
    snapshot_json: Option<serde_json::Value>,
}

/// Loads the canonical v2 input of each header in `header_ids` from the
/// **stored** `audit_header`, `audit_detail` and `audit_snapshot`
/// rows — never from `audit_ingest` (D-539 ruling 4). A header id that
/// does not exist is absent from the map. Three statements regardless of how
/// many ids are passed; callers chunk large walks.
///
/// Detail and snapshot rows are matched by `audit_ref` alone, not by
/// `organization_ref`: a row moved to another header or another organization
/// must drop out of its original header's digest and into the other one's,
/// which is what makes moving it detectable.
pub(crate) async fn load_stored_events(
    conn: &mut sqlx::PgConnection,
    header_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, CanonicalEvent>, sqlx::Error> {
    let mut events = std::collections::HashMap::with_capacity(header_ids.len());
    if header_ids.is_empty() {
        return Ok(events);
    }

    let headers: Vec<StoredHeader> = sqlx::query_as(
        "SELECT id, organization_ref, category, operation, source, entity_name, record_id,
                version_before, version_after, user_id, initiator, agent_session_id,
                agent_action_id, changed_on, correlation_id, batch_id, event_name,
                event_comment, ip_address, browser, device_type, request_id, session_id,
                ai_model_id, approval_request_ref, outcome, requested_count, affected_count,
                failed_count, occurrence_count
         FROM audit_header
         WHERE id = ANY($1)",
    )
    .bind(header_ids)
    .fetch_all(&mut *conn)
    .await?;
    for row in headers {
        events.insert(
            row.id,
            CanonicalEvent {
                header: row.header,
                ..CanonicalEvent::default()
            },
        );
    }

    let details: Vec<StoredDetail> = sqlx::query_as(
        "SELECT audit_ref, field_name, display_name, data_type, value_mode, old_value, new_value,
                old_display_value, new_display_value, old_lookup_entity, old_lookup_name,
                new_lookup_entity, new_lookup_name, is_sensitive
         FROM audit_detail
         WHERE audit_ref = ANY($1)",
    )
    .bind(header_ids)
    .fetch_all(&mut *conn)
    .await?;
    for row in details {
        if let Some(event) = row.audit_ref.and_then(|r| events.get_mut(&r)) {
            event.details.push(row.detail);
        }
    }

    let snapshots: Vec<StoredSnapshot> = sqlx::query_as(
        "SELECT audit_ref, version, trigger, snapshot_json
         FROM audit_snapshot
         WHERE audit_ref = ANY($1)",
    )
    .bind(header_ids)
    .fetch_all(&mut *conn)
    .await?;
    for row in snapshots {
        if let Some(event) = row.audit_ref.and_then(|r| events.get_mut(&r)) {
            event.snapshots.push(CanonicalSnapshot {
                version: row.version,
                trigger: row.trigger,
                snapshot_json: row.snapshot_json,
            });
        }
    }

    Ok(events)
}

// ── snapshot canonical text (D-539 field 41.3) ──────────────────────────────

/// Field 41.3's text: a stored JSON string (the encrypted case) is its UTF-8
/// content; any other stored value is its RFC 8785 (JCS) serialization.
pub fn snapshot_canonical_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        other => {
            let mut out = String::new();
            write_jcs(other, &mut out);
            out
        }
    }
}

/// RFC 8785 JSON Canonicalization Scheme. Object members sorted by the UTF-16
/// code units of their names, no insignificant whitespace, strings escaped as
/// JSON requires (only `"`, `\` and control characters, with the short forms
/// and lowercase `\u00xx`, which is exactly `serde_json`'s escaping), and
/// numbers in ECMAScript `Number.prototype.toString` form of their IEEE-754
/// double.
fn write_jcs(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&es_number(n.as_f64().unwrap_or(f64::NAN))),
        Value::String(s) => out.push_str(&serde_json::Value::String(s.clone()).to_string()),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (key, item)) in members.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::Value::String(key.clone()).to_string());
                out.push(':');
                write_jcs(item, out);
            }
            out.push('}');
        }
    }
}

/// ECMAScript `Number::toString` for a finite double (ECMA-262 §6.1.6.1.20),
/// built from Rust's shortest round-trip digits. JSON has no NaN or infinity;
/// they print as `null`, which cannot arise from a stored `jsonb` value.
fn es_number(x: f64) -> String {
    if !x.is_finite() {
        return "null".to_owned();
    }
    if x == 0.0 {
        return "0".to_owned();
    }
    let sign = if x < 0.0 { "-" } else { "" };
    // `{:e}` prints the shortest digits that round-trip, as `d[.ddd]e[-]n`.
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let k = digits.len() as i32;
    let n = exp.parse::<i32>().unwrap_or(0) + 1;

    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let exp_sign = if e < 0 { '-' } else { '+' };
        if k == 1 {
            format!("{digits}e{exp_sign}{}", e.abs())
        } else {
            format!("{}.{}e{exp_sign}{}", &digits[..1], &digits[1..], e.abs())
        }
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn es_number_matches_ecmascript() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-1.5, "-1.5"),
            (0.1, "0.1"),
            (100.0, "100"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (123456789012345680000.0, "123456789012345680000"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1.2345e-7, "1.2345e-7"),
            (4.5e300, "4.5e+300"),
            (9007199254740993.0, "9007199254740992"),
            (0.000001234, "0.000001234"),
            (333_333_333.333_333_3, "333333333.3333333"),
        ];
        for (x, expected) in cases {
            assert_eq!(es_number(*x), *expected, "for {x:e}");
        }
    }

    #[test]
    fn jcs_sorts_members_and_drops_whitespace() {
        let v = json!({"b": [1, 2.50, "x"], "a": {"z": null, "é": true, "\u{1F600}": false}});
        assert_eq!(
            snapshot_canonical_text(&v),
            "{\"a\":{\"z\":null,\"é\":true,\"\u{1F600}\":false},\"b\":[1,2.5,\"x\"]}"
        );
    }

    #[test]
    fn a_json_string_snapshot_is_its_content() {
        assert_eq!(snapshot_canonical_text(&json!("abc==")), "abc==");
    }

    #[test]
    fn duplicate_detail_fields_are_refused() {
        let detail = CanonicalDetail {
            field_name: Some("name".into()),
            ..Default::default()
        };
        let event = CanonicalEvent {
            details: vec![detail.clone(), detail],
            ..Default::default()
        };
        assert_eq!(
            encode_v2(&event),
            Err(EncodeError::DuplicateDetailField(Some("name".into())))
        );
    }

    #[test]
    fn two_snapshots_are_refused() {
        let event = CanonicalEvent {
            snapshots: vec![CanonicalSnapshot::default(), CanonicalSnapshot::default()],
            ..Default::default()
        };
        assert_eq!(encode_v2(&event), Err(EncodeError::MultipleSnapshots(2)));
    }

    #[test]
    fn empty_string_differs_from_null() {
        let null = CanonicalEvent::default();
        let empty = CanonicalEvent {
            header: CanonicalHeader {
                event_comment: Some(String::new()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_ne!(encode_v2(&null).unwrap(), encode_v2(&empty).unwrap());
    }

    #[test]
    fn an_attachment_changes_the_digest() {
        let none = CanonicalEvent::default();
        let one = CanonicalEvent {
            attachments: vec![CanonicalAttachment {
                document_ref: Some(Uuid::nil()),
                content_sha256: Some("00".repeat(32)),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_ne!(
            content_digest_v2(&none).unwrap(),
            content_digest_v2(&one).unwrap()
        );
    }

    #[test]
    fn event_hash_rejects_a_malformed_digest() {
        assert!(event_hash_v2("", "zz").is_err());
    }
}
