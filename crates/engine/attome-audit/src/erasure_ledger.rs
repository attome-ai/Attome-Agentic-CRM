//! The erasure ledger (roadmap R2-T1): one object per erased or purged
//! record in object storage, outside the database a backup restores, so a
//! restored database cannot bring an erased subject back.
//!
//! An erasure commits in the database first, then [`record`] writes its
//! entry; a failed write is logged as an error (the erasure itself stands).
//! At boot, before the server serves, the ledger is replayed against the
//! database (`attome_compliance::erasure_replay`), so after `attome restore`
//! every erasure since the backup is applied again.
//!
//! The object key carries everything replay needs, so a boot lists the
//! ledger without reading each entry: `erasure-ledger/{kind}/{entity}/{record_id}`.

use attome_storage::StorageClient;
use attome_types::AppError;
use uuid::Uuid;

/// Where entries live in the bucket.
pub const LEDGER_PREFIX: &str = "erasure-ledger";

/// Why a record's data was destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureKind {
    /// A data-subject or administrator erasure: the audit key and the
    /// record's copies are destroyed.
    Erasure,
    /// A retention purge: the same, and the record's sensitive fields are
    /// scrubbed.
    Purge,
}

impl ErasureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Erasure => "erasure",
            Self::Purge => "purge",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "erasure" => Some(Self::Erasure),
            "purge" => Some(Self::Purge),
            _ => None,
        }
    }
}

/// One ledger entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    pub kind: ErasureKind,
    pub entity: String,
    pub record_id: Uuid,
}

impl LedgerEntry {
    /// The entry's object key.
    pub fn key(&self) -> String {
        format!(
            "{LEDGER_PREFIX}/{}/{}/{}",
            self.kind.as_str(),
            self.entity,
            self.record_id
        )
    }

    /// The entry an object key names, or `None` for anything else.
    pub fn from_key(key: &str) -> Option<Self> {
        let mut parts = key.split('/');
        if parts.next()? != LEDGER_PREFIX {
            return None;
        }
        let kind = ErasureKind::parse(parts.next()?)?;
        let entity = parts.next()?;
        let record_id = Uuid::parse_str(parts.next()?).ok()?;
        if parts.next().is_some() || entity.is_empty() {
            return None;
        }
        Some(Self {
            kind,
            entity: entity.to_owned(),
            record_id,
        })
    }
}

/// Writes `entry` to the ledger. Call after the erasure commits.
pub async fn record(storage: &StorageClient, entry: &LedgerEntry) -> Result<(), AppError> {
    let body = serde_json::json!({
        "kind": entry.kind.as_str(),
        "entity": entry.entity,
        "record_id": entry.record_id,
        "recorded_at": chrono::Utc::now(),
    });
    attome_storage::mirror::write_object(storage, &entry.key(), body.to_string().into_bytes())
        .await
        .map_err(AppError::internal)
}

/// [`record`], logging a failure instead of returning it: the erasure has
/// already committed, so the caller's answer stands either way.
pub async fn record_or_log(storage: &StorageClient, entry: &LedgerEntry) {
    if let Err(error) = record(storage, entry).await {
        tracing::error!(
            %error,
            entity = %entry.entity,
            record_id = %entry.record_id,
            "erasure ledger: the entry was not written; a restore from an older backup \
             would not erase this record again"
        );
    }
}

/// Every entry in the ledger.
pub async fn read_all(storage: &StorageClient) -> Result<Vec<LedgerEntry>, AppError> {
    let objects = attome_storage::mirror::list_prefix(storage, LEDGER_PREFIX)
        .await
        .map_err(AppError::internal)?;
    Ok(objects
        .iter()
        .filter_map(|o| LedgerEntry::from_key(&o.key))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erasure_ledger_keys_round_trip() {
        let entry = LedgerEntry {
            kind: ErasureKind::Purge,
            entity: "contact".into(),
            record_id: Uuid::now_v7(),
        };
        let key = entry.key();
        assert!(key.starts_with("erasure-ledger/purge/contact/"));
        assert_eq!(LedgerEntry::from_key(&key), Some(entry));
        for bad in [
            "erasure-ledger/erasure/contact",
            "erasure-ledger/other/contact/0190a0a0-0000-7000-8000-000000000001",
            "erasure-ledger/erasure/contact/not-a-uuid",
            "erasure-ledger/erasure//0190a0a0-0000-7000-8000-000000000001",
            "branding/x/logo",
            "erasure-ledger/erasure/contact/0190a0a0-0000-7000-8000-000000000001/extra",
        ] {
            assert_eq!(LedgerEntry::from_key(bad), None, "{bad}");
        }
    }
}
