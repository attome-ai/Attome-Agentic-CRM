//! The v1 cutover checkpoint (D-539 ruling 6, audit 10/10 plan item 2.6).
//!
//! Hash version 1 covers only an event's identity (`compute_hash_raw`), so an
//! edit to a v1 row's detail values, snapshot, remark or request context is
//! invisible to the v1 hash forever. Hash v2 closes that for every event
//! written after the cutover. This module closes it for the history written
//! before: once no writer produces v1 rows any more, it freezes the stored v1
//! content in a signed, externally anchored checkpoint, and verification
//! recomputes it, so a post-cutover edit of pre-cutover content is detected.
//!
//! ## What the checkpoint holds
//!
//! For one organization: the last v1 header id and its `event_hash`, and for
//! each `audit_header` partition holding v1 rows a `v1_partition_digest` —
//! SHA-256 over the concatenation, in header `id` order, of each v1 header's
//! `LP(CANONICAL_EVENT_V2 bytes)`, encoded over its stored header, detail and
//! snapshot rows with the magic version written as `1` and field 13 the stored
//! `changed_on` (`canonical::encode_with_magic(event, 1)`). Row counts ride
//! along so a report can say what changed.
//!
//! ## Signing, storage, trust
//!
//! The record is serialized once to JSON text and that exact text is what is
//! hashed and signed (`AuditSigner::sign(SIGNING_DOMAIN, sha256(record))`), so
//! no re-serialization can change what a verifier checks. The signed object is
//! written to `audit_v1_checkpoint` (migration 0475) and, when anchoring is
//! configured, with `PutMode::Create` to `audit-chain-anchors/{org}/v1-cutover.json`
//! in the D-352 anchor store. That reuses the signing-key registry and the
//! anchor store: no new trust root. Verification prefers the anchored copy and
//! reports a database copy that disagrees with it.
//!
//! ## When it runs
//!
//! v2 activates at deploy (G1-3 a); this runs afterwards as a durable job
//! (`EngineJob::AuditV1CutoverCheckpoint`), once per organization, and only
//! when the v1 set is closed:
//!
//! - no pre-v2 ingest payload (no `hash_version` key) is still waiting to be
//!   chained — the chainer writes those as v1 rows (D-539 implementation
//!   record, "Pre-v2 ingest payloads");
//! - no pre-v2 payload was captured, and no v1 header was stamped, within a
//!   quiet period, so an old-binary node still draining during a rolling
//!   upgrade has had time to stop.
//!
//! Otherwise the job defers and the next scheduler tick retries. After the
//! checkpoint exists, a v1 row with an id above its last v1 header is a
//! verification error: nothing may extend the v1 history once it is frozen.
//!
//! Idempotent and retry-safe: the row insert is `ON CONFLICT DO NOTHING` under
//! a per-organization advisory lock, the anchor write is `PutMode::Create`
//! with byte comparison on conflict, and a run that finds the row already
//! present only (re)anchors it.

use std::collections::BTreeMap;

use attome_db::DbPool;
use attome_storage::StorageClient;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use object_store::{ObjectStoreExt, PutMode, PutOptions, path::Path};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use attome_core::AuditSigner;

use crate::canonical;

/// `format` value of every checkpoint record this implementation writes.
pub const V1_CHECKPOINT_FORMAT: &str = "attome-audit-v1-cutover/1";

/// First argument of the checkpoint signature. A chain row signs
/// `prev_hash|event_hash`, where `prev_hash` is a hex digest or empty, so this
/// non-hex domain cannot be confused with a row or batch signature.
pub const SIGNING_DOMAIN: &str = "attome-audit-v1-cutover";

/// Header rows loaded per `canonical::load_stored_events` call.
const LOAD_CHUNK: i64 = 500;

/// Quiet period the scheduled job waits after the newest pre-v2 capture
/// before freezing the v1 set. Tests pass zero.
pub const DEFAULT_QUIET_PERIOD: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// One partition's frozen v1 content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1PartitionDigest {
    /// `audit_header` partition name (`tableoid::regclass`).
    pub partition: String,
    pub header_count: u64,
    pub detail_count: u64,
    pub snapshot_count: u64,
    /// SHA-256 hex over `LP(encode_with_magic(event, 1))` per v1 header, in id order.
    pub v1_partition_digest: String,
}

/// The checkpoint record, signed as its serialized JSON text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1CheckpointRecord {
    pub format: String,
    pub organization_ref: Uuid,
    pub last_v1_header_id: Uuid,
    pub last_v1_event_hash: String,
    pub v1_header_count: u64,
    pub partitions: Vec<V1PartitionDigest>,
    /// Application clock at creation — diagnostic only, never compared.
    pub created_at: DateTime<Utc>,
}

/// The stored and anchored object: the record text plus its hash and signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct SignedV1Checkpoint {
    /// `V1CheckpointRecord` serialized to JSON, verbatim.
    pub record: String,
    /// SHA-256 hex over `record`'s UTF-8 bytes.
    pub record_sha256: String,
    pub signing_key_id: Option<String>,
    /// `AuditSigner::sign(SIGNING_DOMAIN, record_sha256)`; `None` only where
    /// audit signing was never configured.
    pub signature: Option<String>,
}

/// What one `create_v1_cutover_checkpoint` call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// The checkpoint was written by this call.
    Created { v1_headers: u64, partitions: usize },
    /// A checkpoint already existed; it was (re)anchored if a store is given.
    AlreadyExists,
    /// The organization has no v1 rows: nothing to freeze.
    NoV1History,
    /// The v1 set is not closed yet; the next run retries.
    Deferred(String),
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn checkpoint_path(org: Uuid) -> Result<Path, AppError> {
    Path::parse(format!("audit-chain-anchors/{org}/v1-cutover.json")).map_err(AppError::internal)
}

#[derive(sqlx::FromRow)]
struct LastV1 {
    id: Uuid,
    event_hash: String,
    changed_on: Option<DateTime<Utc>>,
}

async fn last_v1_header(db: &DbPool, org: Uuid) -> Result<Option<LastV1>, AppError> {
    sqlx::query_as(
        "SELECT id, event_hash, changed_on FROM audit_header
         WHERE organization_ref = $1 AND hash_version = 1
         ORDER BY id DESC LIMIT 1",
    )
    .bind(org)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// The per-partition v1 digests for `org`, over every v1 header with
/// `id <= through`. Streams the headers in id order, `LOAD_CHUNK` at a time.
pub(crate) async fn compute_v1_partition_digests(
    db: &DbPool,
    org: Uuid,
    through: Uuid,
) -> Result<Vec<V1PartitionDigest>, AppError> {
    struct Acc {
        hasher: Sha256,
        headers: u64,
        details: u64,
        snapshots: u64,
    }

    let mut partitions: BTreeMap<String, Acc> = BTreeMap::new();
    let mut after = Uuid::nil();
    let mut conn = db.acquire().await.map_err(AppError::internal)?;

    loop {
        let page: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, tableoid::regclass::text FROM audit_header
             WHERE organization_ref = $1 AND hash_version = 1 AND id > $2 AND id <= $3
             ORDER BY id
             LIMIT $4",
        )
        .bind(org)
        .bind(after)
        .bind(through)
        .bind(LOAD_CHUNK)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = page.last() else {
            break;
        };
        after = last.0;

        let ids: Vec<Uuid> = page.iter().map(|(id, _)| *id).collect();
        let stored = canonical::load_stored_events(&mut conn, &ids)
            .await
            .map_err(AppError::internal)?;

        for (id, partition) in &page {
            let event = stored.get(id).ok_or_else(|| {
                AppError::internal(format!(
                    "v1 header {id} disappeared while it was being read"
                ))
            })?;
            let bytes = canonical::encode_with_magic(event, canonical::HASH_VERSION_V1 as u16)
                .map_err(|e| {
                    AppError::internal(format!(
                        "v1 header {id}: stored rows cannot be canonically encoded ({e})"
                    ))
                })?;
            let len = u32::try_from(bytes.len())
                .map_err(|_| AppError::internal(format!("v1 header {id}: encoding too long")))?;
            let acc = partitions.entry(partition.clone()).or_insert_with(|| Acc {
                hasher: Sha256::new(),
                headers: 0,
                details: 0,
                snapshots: 0,
            });
            acc.hasher.update(len.to_be_bytes());
            acc.hasher.update(&bytes);
            acc.headers += 1;
            acc.details += event.details.len() as u64;
            acc.snapshots += event.snapshots.len() as u64;
        }
    }

    Ok(partitions
        .into_iter()
        .map(|(partition, acc)| {
            let digest = hex::encode(acc.hasher.finalize());
            V1PartitionDigest {
                partition,
                header_count: acc.headers,
                detail_count: acc.details,
                snapshot_count: acc.snapshots,
                v1_partition_digest: digest,
            }
        })
        .collect())
}

/// Why the v1 set of `org` is not closed yet, if it is not.
async fn cutover_blocker(
    db: &DbPool,
    org: Uuid,
    last_v1: &LastV1,
    quiet_period: std::time::Duration,
) -> Result<Option<String>, AppError> {
    let quiet = chrono::Duration::from_std(quiet_period).map_err(AppError::internal)?;

    // Pre-v2 payloads not yet chained. `last_ingest_id` of the newest batch is
    // the chainer's checkpoint; everything after it is pending.
    let pending_legacy: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM audit_ingest i
             WHERE i.organization_ref = $1
               AND i.payload->>'hash_version' IS NULL
               AND i.id > COALESCE(
                   (SELECT b.last_ingest_id FROM audit_chain_batch b
                    WHERE b.organization_ref = $1 ORDER BY b.id DESC LIMIT 1),
                   '00000000-0000-0000-0000-000000000000'::uuid)
         )",
    )
    .bind(org)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if pending_legacy {
        return Ok(Some(
            "pre-v2 ingest payloads are still waiting to be chained (they become v1 rows)".into(),
        ));
    }

    if quiet.is_zero() {
        return Ok(None);
    }

    let newest_legacy_capture: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(created_at) FROM audit_ingest
         WHERE organization_ref = $1 AND payload->>'hash_version' IS NULL",
    )
    .bind(org)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT now()")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    let newest = newest_legacy_capture
        .into_iter()
        .chain(last_v1.changed_on)
        .max();
    if let Some(newest) = newest
        && newest > now - quiet
    {
        return Ok(Some(format!(
            "a pre-v2 event was captured at {newest}, inside the {}s quiet period",
            quiet.num_seconds()
        )));
    }
    Ok(None)
}

/// Computes, signs, stores and (with `store`) anchors the v1 cutover
/// checkpoint of `org`. See the module doc for when it defers.
pub async fn create_v1_cutover_checkpoint(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    store: Option<&StorageClient>,
    org: Uuid,
    quiet_period: std::time::Duration,
) -> Result<CheckpointOutcome, AppError> {
    if let Some(existing) = load_stored_checkpoint(db, org).await? {
        if let Some(store) = store {
            anchor_checkpoint(store, org, &existing).await?;
        }
        return Ok(CheckpointOutcome::AlreadyExists);
    }

    let Some(last_v1) = last_v1_header(db, org).await? else {
        return Ok(CheckpointOutcome::NoV1History);
    };
    if let Some(reason) = cutover_blocker(db, org, &last_v1, quiet_period).await? {
        return Ok(CheckpointOutcome::Deferred(reason));
    }

    // Computed outside any transaction: the v1 set is closed (checked above),
    // and the walk is bounded by `last_v1.id`, so nothing it reads can change
    // underneath it except by tampering — which is what it freezes.
    let partitions = compute_v1_partition_digests(db, org, last_v1.id).await?;
    let v1_header_count = partitions.iter().map(|p| p.header_count).sum();
    let record = V1CheckpointRecord {
        format: V1_CHECKPOINT_FORMAT.to_owned(),
        organization_ref: org,
        last_v1_header_id: last_v1.id,
        last_v1_event_hash: last_v1.event_hash.clone(),
        v1_header_count,
        partitions,
        created_at: Utc::now(),
    };
    let record_text = serde_json::to_string(&record).map_err(AppError::internal)?;
    let record_sha256 = sha256_hex(record_text.as_bytes());
    let signed = SignedV1Checkpoint {
        signature: signer.map(|s| s.sign(SIGNING_DOMAIN, &record_sha256)),
        signing_key_id: signer.map(|s| s.key_id.clone()),
        record: record_text,
        record_sha256,
    };

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-audit/v1-checkpoint:{org}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(CheckpointOutcome::Deferred(
            "another run holds this organization's checkpoint lock".into(),
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO audit_v1_checkpoint
             (organization_ref, last_v1_header_id, record, record_sha256, signing_key_id, signature)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (organization_ref) DO NOTHING",
    )
    .bind(org)
    .bind(last_v1.id)
    .bind(&signed.record)
    .bind(&signed.record_sha256)
    .bind(signed.signing_key_id.as_deref())
    .bind(signed.signature.as_deref())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    tx.commit().await.map_err(AppError::internal)?;

    if inserted == 0 {
        // A concurrent run won between the existence check and the insert.
        if let (Some(store), Some(existing)) = (store, load_stored_checkpoint(db, org).await?) {
            anchor_checkpoint(store, org, &existing).await?;
        }
        return Ok(CheckpointOutcome::AlreadyExists);
    }

    tracing::info!(
        organization_ref = %org,
        last_v1_header_id = %last_v1.id,
        v1_headers = v1_header_count,
        partitions = record.partitions.len(),
        signed = signed.signature.is_some(),
        "audit v1 cutover checkpoint written",
    );

    if let Some(store) = store {
        anchor_checkpoint(store, org, &signed).await?;
    }
    Ok(CheckpointOutcome::Created {
        v1_headers: v1_header_count,
        partitions: record.partitions.len(),
    })
}

/// Runs [`create_v1_cutover_checkpoint`] for every organization that holds v1
/// rows and has no checkpoint yet, plus (with `store`) every organization whose
/// checkpoint exists, so a failed anchor write is retried. One organization's
/// failure does not stop the others; it is returned in its slot.
pub async fn run_v1_cutover_checkpoints(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    store: Option<&StorageClient>,
    quiet_period: std::time::Duration,
) -> Result<Vec<(Uuid, Result<CheckpointOutcome, AppError>)>, AppError> {
    let mut orgs: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT organization_ref FROM audit_header
         WHERE hash_version = 1 AND organization_ref IS NOT NULL
           AND organization_ref NOT IN (SELECT organization_ref FROM audit_v1_checkpoint)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if store.is_some() {
        let checkpointed: Vec<Uuid> =
            sqlx::query_scalar("SELECT organization_ref FROM audit_v1_checkpoint")
                .fetch_all(db)
                .await
                .map_err(AppError::internal)?;
        orgs.extend(checkpointed);
    }
    orgs.sort();
    orgs.dedup();

    let mut results = Vec::with_capacity(orgs.len());
    for org in orgs {
        let outcome = create_v1_cutover_checkpoint(db, signer, store, org, quiet_period).await;
        if let Err(e) = &outcome {
            tracing::error!(organization_ref = %org, error = %e, "audit v1 cutover checkpoint failed");
        }
        results.push((org, outcome));
    }
    Ok(results)
}

async fn load_stored_checkpoint(
    db: &DbPool,
    org: Uuid,
) -> Result<Option<SignedV1Checkpoint>, AppError> {
    sqlx::query_as(
        "SELECT record, record_sha256, signing_key_id, signature
         FROM audit_v1_checkpoint WHERE organization_ref = $1",
    )
    .bind(org)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Writes `signed` to the anchor store with `PutMode::Create`. An existing
/// object with identical bytes is success; different bytes are an error.
pub async fn anchor_checkpoint(
    store: &StorageClient,
    org: Uuid,
    signed: &SignedV1Checkpoint,
) -> Result<(), AppError> {
    let path = checkpoint_path(org)?;
    let bytes = serde_json::to_vec(signed).map_err(AppError::internal)?;
    let opts = PutOptions {
        mode: PutMode::Create,
        ..Default::default()
    };
    match store.store().put_opts(&path, bytes.into(), opts).await {
        Ok(_) => Ok(()),
        Err(object_store::Error::AlreadyExists { .. }) => {
            match fetch_anchored_checkpoint(store, org).await? {
                Some(existing) if existing == *signed => Ok(()),
                Some(_) => Err(AppError::internal(format!(
                    "conflicting v1 cutover checkpoint anchor for organization {org}: the anchored \
                 object differs from the database copy"
                ))),
                None => Err(AppError::internal(
                    "v1 cutover checkpoint create reported AlreadyExists but the object could not be read",
                )),
            }
        }
        Err(e) => Err(AppError::internal(e)),
    }
}

/// The anchored checkpoint of `org`, if one was written.
pub async fn fetch_anchored_checkpoint(
    store: &StorageClient,
    org: Uuid,
) -> Result<Option<SignedV1Checkpoint>, AppError> {
    let path = checkpoint_path(org)?;
    match store.store().get(&path).await {
        Ok(result) => {
            let bytes = result.bytes().await.map_err(AppError::internal)?;
            Ok(Some(
                serde_json::from_slice(&bytes).map_err(AppError::internal)?,
            ))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(AppError::internal(e)),
    }
}

// ── verification ────────────────────────────────────────────────────────────

/// How the v1 history of an organization is protected, as verification found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum V1ContentProtection {
    /// No v1 rows and no checkpoint: nothing to protect.
    #[default]
    NoV1History,
    /// v1 rows exist and no checkpoint does: their content is unprotected.
    NotCheckpointed,
    /// Checked against the externally anchored checkpoint.
    CheckpointedAnchored,
    /// An anchor store is configured but holds no checkpoint object; checked
    /// against the database copy (the job retries the anchor write).
    CheckpointedAnchorMissing,
    /// The anchor store could not be read; checked against the database copy.
    /// The external half of the check is unknown, not passed (C21).
    CheckpointedAnchorUnknown,
    /// No anchor store configured (development); checked against the signed
    /// database copy only.
    CheckpointedDatabaseOnly,
}

impl V1ContentProtection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoV1History => "no_v1_history",
            Self::NotCheckpointed => "not_checkpointed",
            Self::CheckpointedAnchored => "checkpointed_anchored",
            Self::CheckpointedAnchorMissing => "checkpointed_anchor_missing",
            Self::CheckpointedAnchorUnknown => "checkpointed_anchor_unknown",
            Self::CheckpointedDatabaseOnly => "checkpointed_database_only",
        }
    }
}

/// Outcome of [`verify_v1_checkpoint`], folded into `VerificationReport`.
#[derive(Debug, Default)]
pub(crate) struct V1CheckpointCheck {
    pub protection: V1ContentProtection,
    /// Checkpointed partitions no longer present (dropped under retention and
    /// bridged by their epoch seal, D-280).
    pub partitions_dropped: usize,
    pub errors: Vec<String>,
}

/// D-539 ruling 6 — verifies `org`'s v1 history against its checkpoint.
/// `v1_rows_exist` decides between `NoV1History` and `NotCheckpointed` when no
/// checkpoint exists. The signature over `(SIGNING_DOMAIN, record_sha256)` is
/// resolved through the signing-key registry exactly as row and batch
/// signatures are.
pub(crate) async fn verify_v1_checkpoint(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    store: Option<&StorageClient>,
    signing_configured: bool,
    org: Uuid,
    v1_rows_exist: bool,
) -> Result<V1CheckpointCheck, AppError> {
    let mut check = V1CheckpointCheck::default();
    let db_copy = load_stored_checkpoint(db, org).await?;

    let (signed, protection) = match store {
        Some(store) => match fetch_anchored_checkpoint(store, org).await {
            Ok(Some(anchored)) => {
                if let Some(db_copy) = &db_copy
                    && *db_copy != anchored
                {
                    check.errors.push(format!(
                        "v1 cutover checkpoint: the database copy in audit_v1_checkpoint differs \
                         from the externally anchored object for organization {org} — the anchored \
                         copy is used"
                    ));
                }
                (Some(anchored), V1ContentProtection::CheckpointedAnchored)
            }
            Ok(None) => (db_copy, V1ContentProtection::CheckpointedAnchorMissing),
            Err(e) => {
                tracing::warn!(
                    organization_ref = %org,
                    error = %e,
                    "audit verification: v1 cutover checkpoint anchor unreadable — external check unknown",
                );
                (db_copy, V1ContentProtection::CheckpointedAnchorUnknown)
            }
        },
        None => (db_copy, V1ContentProtection::CheckpointedDatabaseOnly),
    };

    let Some(signed) = signed else {
        check.protection = if v1_rows_exist {
            V1ContentProtection::NotCheckpointed
        } else {
            V1ContentProtection::NoV1History
        };
        return Ok(check);
    };
    check.protection = protection;

    if sha256_hex(signed.record.as_bytes()) != signed.record_sha256 {
        check.errors.push(
            "v1 cutover checkpoint: record_sha256 does not match the record text — the checkpoint \
             was altered"
                .to_owned(),
        );
        return Ok(check);
    }
    match &signed.signature {
        Some(sig) => {
            if !crate::verify::signature_verifies(
                db,
                signer,
                signed.signing_key_id.as_deref(),
                SIGNING_DOMAIN,
                &signed.record_sha256,
                sig,
            )
            .await?
            {
                check.errors.push(
                    "v1 cutover checkpoint: signature does not verify against its record_sha256"
                        .to_owned(),
                );
                return Ok(check);
            }
        }
        None if signing_configured => {
            check.errors.push(
                "v1 cutover checkpoint: unsigned while audit signing is configured — the signature \
                 was stripped or the checkpoint was forged"
                    .to_owned(),
            );
            return Ok(check);
        }
        None => {}
    }

    let record: V1CheckpointRecord = match serde_json::from_str(&signed.record) {
        Ok(r) => r,
        Err(e) => {
            check.errors.push(format!(
                "v1 cutover checkpoint: record does not parse ({e})"
            ));
            return Ok(check);
        }
    };
    if record.format != V1_CHECKPOINT_FORMAT || record.organization_ref != org {
        check.errors.push(format!(
            "v1 cutover checkpoint: unknown format {:?} or wrong organization {}",
            record.format, record.organization_ref
        ));
        return Ok(check);
    }

    // Nothing may extend the v1 history once it is frozen.
    let late_v1: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM audit_header
         WHERE organization_ref = $1 AND hash_version = 1 AND id > $2
         ORDER BY id LIMIT 100",
    )
    .bind(org)
    .bind(record.last_v1_header_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    for id in late_v1 {
        check.errors.push(format!(
            "header {id}: a hash_version 1 row after the v1 cutover checkpoint's last v1 header \
             {} — no writer produces v1 rows after the cutover",
            record.last_v1_header_id
        ));
    }

    let last_hash: Option<String> =
        sqlx::query_scalar("SELECT event_hash FROM audit_header WHERE id = $1")
            .bind(record.last_v1_header_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    if let Some(hash) = last_hash
        && hash != record.last_v1_event_hash
    {
        check.errors.push(format!(
            "header {}: event_hash differs from the v1 cutover checkpoint's last v1 event hash",
            record.last_v1_header_id
        ));
    }

    let recomputed = compute_v1_partition_digests(db, org, record.last_v1_header_id).await?;
    let mut recomputed: BTreeMap<String, V1PartitionDigest> = recomputed
        .into_iter()
        .map(|p| (p.partition.clone(), p))
        .collect();

    for frozen in &record.partitions {
        match recomputed.remove(&frozen.partition) {
            Some(now) if now == *frozen => {}
            Some(now) => check.errors.push(format!(
                "partition {}: v1 content changed after the cutover checkpoint (checkpoint \
                 {} headers/{} details/{} snapshots digest {}, now {} headers/{} details/{} \
                 snapshots digest {}) — pre-cutover detail, snapshot or header content was edited",
                frozen.partition,
                frozen.header_count,
                frozen.detail_count,
                frozen.snapshot_count,
                frozen.v1_partition_digest,
                now.header_count,
                now.detail_count,
                now.snapshot_count,
                now.v1_partition_digest
            )),
            None => {
                let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
                    .bind(&frozen.partition)
                    .fetch_one(db)
                    .await
                    .map_err(AppError::internal)?;
                if exists {
                    check.errors.push(format!(
                        "partition {}: holds none of the {} v1 headers the cutover checkpoint froze \
                         — pre-cutover rows were deleted or moved",
                        frozen.partition, frozen.header_count
                    ));
                } else {
                    check.partitions_dropped += 1;
                }
            }
        }
    }
    for (partition, extra) in recomputed {
        check.errors.push(format!(
            "partition {partition}: {} v1 headers the cutover checkpoint does not know — v1 rows \
             were added to pre-cutover history",
            extra.header_count
        ));
    }

    Ok(check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_path_is_per_organization() {
        let org = Uuid::now_v7();
        let path = checkpoint_path(org).unwrap();
        assert_eq!(
            path.as_ref(),
            format!("audit-chain-anchors/{org}/v1-cutover.json")
        );
    }

    #[test]
    fn protection_states_have_stable_names() {
        assert_eq!(
            V1ContentProtection::NotCheckpointed.as_str(),
            "not_checkpointed"
        );
        assert_eq!(
            V1ContentProtection::CheckpointedAnchored.as_str(),
            "checkpointed_anchored"
        );
    }

    #[test]
    fn signing_domain_is_not_hex() {
        assert!(!SIGNING_DOMAIN.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
