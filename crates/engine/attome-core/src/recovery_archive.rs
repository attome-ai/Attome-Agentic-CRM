//! Solution 7 Phase 2 (D-788 rule 9; `SOLUTION-7-PHASE-2-DESIGN.md` §8) — the
//! 30-day recovery archive (`recovery_archive`, migration 0527).
//!
//! Before a value is nulled by an in-place type conversion, or a column is
//! dropped by a field delete, the executor copies `(record id, field, value)`
//! here **in the same transaction** that nulls or drops it
//! ([`insert_batch`]). The value is the column's `to_jsonb(...)` form as JSON
//! text (so its type survives: numbers, booleans, a multi-choice array),
//! encrypted in the application with `attome_auth::envelope::encrypt_bytes`
//! under `metadata.recovery_archive_key_encryption_key` — its own ring, its
//! own trust domain (D-069). No ring configured means [`ring`] is `None`, and
//! every caller that would archive a value refuses with
//! [`ARCHIVE_KEY_MISSING`] (fail closed: nothing is dropped or nulled without
//! its archive).
//!
//! Values are never logged, never in a plan or ledger, never in an audit
//! payload: those carry counts and ids only.
//!
//! **Sealed payload (security review L4, M1).** The plaintext is
//! `{"v": <value>, "s": <was the field sensitive>}` and the envelope's
//! additional authenticated data is [`aad`] — the row's `(attribute_id,
//! record_id)` — so a ciphertext copied onto another row (someone with
//! database write access) does not open, and the sensitivity flag cannot be
//! flipped without the key. A row sealed before this format (no AAD, bare
//! value) does not open either: it is refused with
//! [`ARCHIVE_VALUE_UNREADABLE`] (fail closed; pre-production, D-790).
//!
//! [`purge_expired`] is the hourly job body (`EngineJob::PruneRecoveryArchive`):
//! bounded batches, each its own transaction, skipping rows whose record is
//! under an active legal hold, and nothing at all while the deployment-wide
//! `retention.legal_hold` flag is on. [`erase_record`] is the DSR-erasure arm.

use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

/// The envelope's `field_name` (error messages only; never key material).
pub const ENVELOPE_FIELD: &str = "recovery_archive";

/// Stable refusal: an operation needs the archive and no key ring is
/// configured (design §5.2 / §8.2).
pub const ARCHIVE_KEY_MISSING: &str = "archive_key_missing: this change would archive record values, but \
     metadata.recovery_archive_key_encryption_key is not configured; nothing was changed";

/// Stable refusal: the row's ciphertext does not open under its own
/// `(attribute_id, record_id)` (moved between rows, or sealed before the
/// bound format).
pub const ARCHIVE_VALUE_UNREADABLE: &str = "archive_value_unreadable: this archived value does not \
     open for its own row (it was moved between rows or sealed in an older format); nothing was read";

/// Rows per purge batch.
pub const PURGE_BATCH: i64 = 5_000;

/// Why a value was archived (the table's CHECK).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveReason {
    FieldDeleted,
    ConversionNulled,
}

impl ArchiveReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FieldDeleted => "field_deleted",
            Self::ConversionNulled => "conversion_nulled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [Self::FieldDeleted, Self::ConversionNulled]
            .into_iter()
            .find(|r| r.as_str() == value)
    }
}

/// Which field of which entity an archive event is about, and the change
/// that caused it.
#[derive(Debug, Clone)]
pub struct ArchiveEvent<'a> {
    pub reason: ArchiveReason,
    pub entity: &'a str,
    pub field: &'a str,
    pub attribute_id: Uuid,
    /// The source type (what the value was).
    pub field_type: &'a str,
    /// The field was `is_sensitive` when archived (security review M1): a
    /// read of the value then needs the field-security grant, as a read of
    /// the field itself does (D-111).
    pub sensitive: bool,
    /// `(changeset id, op seq)` when the change was recorded or applied
    /// from a changeset; `None` for an admin-route change outside one.
    pub op: Option<(Uuid, i32)>,
    /// The batched run this event belongs to (resume-safe inserts).
    pub run_ref: Option<Uuid>,
}

/// The configured ring, or `None` (fail closed at the caller).
pub fn ring(config: &attome_config::AppConfig) -> Option<&KeyRing> {
    let ring = &config.metadata.recovery_archive_key_encryption_key;
    (!ring.is_empty()).then_some(ring)
}

/// The additional authenticated data binding a sealed value to its row.
pub fn aad(attribute_id: Uuid, record_id: Uuid) -> Vec<u8> {
    format!("{ENVELOPE_FIELD}/v2:{attribute_id}:{record_id}").into_bytes()
}

/// Encrypts one value (its JSON text) with its sensitivity, bound to its row.
fn seal(
    ring: &KeyRing,
    attribute_id: Uuid,
    record_id: Uuid,
    value: &Value,
    sensitive: bool,
) -> Result<Vec<u8>, AppError> {
    let payload = serde_json::json!({ "v": value, "s": sensitive });
    let text = serde_json::to_vec(&payload).map_err(AppError::internal)?;
    attome_auth::envelope::encrypt_bytes_with_aad(
        ENVELOPE_FIELD,
        ring,
        &text,
        &aad(attribute_id, record_id),
    )
}

/// One archived value, opened.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenedValue {
    pub value: Value,
    /// The field was sensitive when the value was archived.
    pub sensitive: bool,
}

/// Decrypts one archived value of `row` back to JSON. A ciphertext that does
/// not open for this row's `(attribute_id, record_id)` is refused with
/// [`ARCHIVE_VALUE_UNREADABLE`] (logged at error: tampering or an old row).
pub fn open(ring: &KeyRing, row: &ArchiveRow, value_enc: &[u8]) -> Result<OpenedValue, AppError> {
    open_parts(ring, row.id, row.attribute_id, row.record_id, value_enc)
}

fn open_parts(
    ring: &KeyRing,
    archive_id: Uuid,
    attribute_id: Uuid,
    record_id: Uuid,
    value_enc: &[u8],
) -> Result<OpenedValue, AppError> {
    let unreadable = |why: &str| {
        tracing::error!(%archive_id, %attribute_id, %record_id, why,
            "recovery archive: a value does not open for its own row (moved, tampered or old format)");
        AppError::Conflict(ARCHIVE_VALUE_UNREADABLE)
    };
    let bytes = attome_auth::envelope::decrypt_bytes_with_aad(
        ENVELOPE_FIELD,
        ring,
        value_enc,
        &aad(attribute_id, record_id),
    )
    .map_err(|_| unreadable("decrypt"))?;
    let payload: Value = serde_json::from_slice(&bytes).map_err(|_| unreadable("payload"))?;
    let (Some(value), Some(sensitive)) =
        (payload.get("v"), payload.get("s").and_then(Value::as_bool))
    else {
        return Err(unreadable("payload shape"));
    };
    Ok(OpenedValue {
        value: value.clone(),
        sensitive,
    })
}

/// Whether the row is past its 30 days (security review L5): an expired row
/// the purge has not reached yet, or one a legal hold keeps, is never read
/// or restored.
pub fn is_expired(row: &ArchiveRow, now: DateTime<Utc>) -> bool {
    row.expires_at <= now
}

/// Archives `(record id, value)` pairs of one event, in the caller's
/// transaction. Encrypted before the insert; one bound statement per batch
/// (`unnest`). With a `run_ref`, a row already archived for the same record
/// by the same run is replaced (a resumed batch, or the final catch-up of a
/// record written after its first archive), otherwise ignored on the event
/// key. Returns the rows written.
pub async fn insert_batch(
    conn: &mut PgConnection,
    ring: &KeyRing,
    event: &ArchiveEvent<'_>,
    values: &[(Uuid, Value)],
) -> Result<u64, AppError> {
    if values.is_empty() {
        return Ok(0);
    }
    let mut ids = Vec::with_capacity(values.len());
    let mut sealed = Vec::with_capacity(values.len());
    for (id, value) in values {
        ids.push(*id);
        sealed.push(seal(ring, event.attribute_id, *id, value, event.sensitive)?);
    }
    let (changeset_id, op_seq) = match event.op {
        Some((id, seq)) => (Some(id), Some(seq)),
        None => (None, None),
    };
    let conflict = if event.run_ref.is_some() {
        "ON CONFLICT (run_ref, record_id) WHERE run_ref IS NOT NULL \
         DO UPDATE SET value_enc = EXCLUDED.value_enc, archived_at = now(), \
                       expires_at = now() + interval '30 days'"
    } else {
        "ON CONFLICT ON CONSTRAINT uq_core_recovery_archive_event DO NOTHING"
    };
    let sql = format!(
        "INSERT INTO recovery_archive \
             (reason, entity_logicalname, field_logicalname, attribute_id, record_id, \
              field_type, value_enc, changeset_id, op_seq, run_ref) \
         SELECT $1, $2, $3, $4, r.record_id, $5, r.value_enc, $6, $7, $8 \
         FROM unnest($9::uuid[], $10::bytea[]) AS r(record_id, value_enc) \
         {conflict}"
    );
    let done = sqlx::query(&sql)
        .bind(event.reason.as_str())
        .bind(event.entity)
        .bind(event.field)
        .bind(event.attribute_id)
        .bind(event.field_type)
        .bind(changeset_id)
        .bind(op_seq)
        .bind(event.run_ref)
        .bind(&ids)
        .bind(&sealed)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(done.rows_affected())
}

/// One archive row without its value (list responses).
#[derive(Debug, Clone, Serialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct ArchiveRow {
    pub id: Uuid,
    pub reason: String,
    pub entity_logicalname: String,
    pub field_logicalname: String,
    pub attribute_id: Uuid,
    pub record_id: Uuid,
    pub field_type: String,
    pub changeset_id: Option<Uuid>,
    pub op_seq: Option<i32>,
    pub run_ref: Option<Uuid>,
    pub report_item_ref: Option<Uuid>,
    pub archived_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub restored_at: Option<DateTime<Utc>>,
    pub restored_by: Option<Uuid>,
}

/// The enumerated columns of [`ArchiveRow`].
pub const ARCHIVE_ROW_COLUMNS: &str = "id, reason, entity_logicalname, field_logicalname, \
     attribute_id, record_id, field_type, changeset_id, op_seq, run_ref, report_item_ref, \
     archived_at, expires_at, restored_at, restored_by";

/// One row with its encrypted value (restore and the one-record read).
pub async fn get_with_value(
    conn: &mut PgConnection,
    id: Uuid,
) -> Result<Option<(ArchiveRow, Vec<u8>)>, AppError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        #[sqlx(flatten)]
        row: ArchiveRow,
        value_enc: Vec<u8>,
    }
    let sql =
        format!("SELECT {ARCHIVE_ROW_COLUMNS}, value_enc FROM recovery_archive WHERE id = $1");
    let row: Option<Row> = sqlx::query_as(&sql)
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(row.map(|r| (r.row, r.value_enc)))
}

/// Marks one row restored (idempotent: an already restored row is left).
pub async fn mark_restored(
    conn: &mut PgConnection,
    id: Uuid,
    actor: Uuid,
) -> Result<bool, AppError> {
    let done = sqlx::query(
        "UPDATE recovery_archive SET restored_at = now(), restored_by = $2 \
         WHERE id = $1 AND restored_at IS NULL",
    )
    .bind(id)
    .bind(actor)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected() == 1)
}

/// DSR erasure (design §8.2): erasing a data subject's record deletes its
/// archived values too. In the erasure's own transaction. Called by the
/// direct erasure, the DSR erasure (every record of the request) and the
/// retention purge (security review L6): a destroyed record's values do not
/// live on in the archive.
///
/// Security review L6: the table is locked `SHARE ROW EXCLUSIVE` first. That
/// conflicts with every archive insert (`ROW EXCLUSIVE`), so a batch that is
/// copying this record's value right now commits before the delete runs (the
/// delete, a later statement, then sees its row), and no batch inserts while
/// the erasure is open.
pub async fn erase_record(
    conn: &mut PgConnection,
    entity: &str,
    record_id: Uuid,
) -> Result<u64, AppError> {
    sqlx::query("LOCK TABLE recovery_archive IN SHARE ROW EXCLUSIVE MODE")
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let done = sqlx::query(
        "DELETE FROM recovery_archive WHERE entity_logicalname = $1 AND record_id = $2",
    )
    .bind(entity)
    .bind(record_id)
    .execute(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    Ok(done.rows_affected())
}

/// The hourly purge (design §8.4): deletes expired rows in batches of
/// [`PURGE_BATCH`], each its own transaction, until a batch deletes fewer.
/// A row whose record is under an active legal hold (a hold naming the
/// record, or a whole-entity hold) is kept; `deployment_hold` (the
/// `retention.legal_hold` flag) suspends the purge entirely. Returns the rows
/// deleted.
pub async fn purge_expired(db: &DbPool, deployment_hold: bool) -> Result<u64, AppError> {
    if deployment_hold {
        tracing::info!("recovery archive purge skipped: retention.legal_hold is on");
        return Ok(0);
    }
    let mut total: u64 = 0;
    loop {
        let done = sqlx::query(
            "DELETE FROM recovery_archive WHERE id IN ( \
                 SELECT a.id FROM recovery_archive a \
                 WHERE a.expires_at < now() \
                   AND NOT EXISTS ( \
                       SELECT 1 FROM legal_hold h \
                       WHERE h.entity_logicalname = a.entity_logicalname \
                         AND (h.record_id = a.record_id OR h.record_id IS NULL) \
                         AND h.released_at IS NULL AND h.is_deleted = false) \
                 ORDER BY a.expires_at LIMIT $1)",
        )
        .bind(PURGE_BATCH)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        let n = done.rows_affected();
        total += n;
        if n < u64::try_from(PURGE_BATCH).unwrap_or(u64::MAX) {
            break;
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_ring() -> KeyRing {
        KeyRing::single("ab".repeat(32))
    }

    #[test]
    fn a_sealed_value_opens_to_the_same_json() {
        let ring = test_ring();
        let (attr, rec) = (Uuid::now_v7(), Uuid::now_v7());
        for value in [json!("text"), json!(12.5), json!(true), json!(["a", "b"])] {
            let sealed = seal(&ring, attr, rec, &value, false).expect("seal");
            assert!(
                !sealed.windows(4).any(|w| w == b"text"),
                "value is not in clear"
            );
            let opened = open_parts(&ring, Uuid::nil(), attr, rec, &sealed).expect("open");
            assert_eq!(opened.value, value);
            assert!(!opened.sensitive);
        }
    }

    #[test]
    fn a_value_moved_to_another_row_does_not_open() {
        let ring = test_ring();
        let (attr, rec) = (Uuid::now_v7(), Uuid::now_v7());
        let sealed = seal(&ring, attr, rec, &json!("secret"), true).expect("seal");
        let opened = open_parts(&ring, Uuid::nil(), attr, rec, &sealed).expect("open");
        assert!(opened.sensitive, "the sensitivity flag round-trips");
        for (a, r) in [(attr, Uuid::now_v7()), (Uuid::now_v7(), rec)] {
            assert!(matches!(
                open_parts(&ring, Uuid::nil(), a, r, &sealed),
                Err(AppError::Conflict(ARCHIVE_VALUE_UNREADABLE))
            ));
        }
    }

    #[test]
    fn an_unbound_old_format_value_is_refused() {
        let ring = test_ring();
        let old =
            attome_auth::envelope::encrypt_bytes(ENVELOPE_FIELD, &ring, br#""old""#).expect("seal");
        assert!(matches!(
            open_parts(&ring, Uuid::nil(), Uuid::now_v7(), Uuid::now_v7(), &old),
            Err(AppError::Conflict(ARCHIVE_VALUE_UNREADABLE))
        ));
    }

    #[test]
    fn expiry_is_checked_against_now() {
        let now = Utc::now();
        let mut row = ArchiveRow {
            id: Uuid::now_v7(),
            reason: "field_deleted".into(),
            entity_logicalname: "e".into(),
            field_logicalname: "f".into(),
            attribute_id: Uuid::now_v7(),
            record_id: Uuid::now_v7(),
            field_type: "text".into(),
            changeset_id: None,
            op_seq: None,
            run_ref: None,
            report_item_ref: None,
            archived_at: now,
            expires_at: now + chrono::Duration::days(30),
            restored_at: None,
            restored_by: None,
        };
        assert!(!is_expired(&row, now));
        row.expires_at = now - chrono::Duration::seconds(1);
        assert!(is_expired(&row, now));
    }

    #[test]
    fn reasons_round_trip() {
        for r in [ArchiveReason::FieldDeleted, ArchiveReason::ConversionNulled] {
            assert_eq!(ArchiveReason::parse(r.as_str()), Some(r));
        }
    }
}
