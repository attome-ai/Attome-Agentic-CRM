//! P1.13 stage 3 — chain verification. Closes the "verification is out of
//! scope" follow-up left open since P1.5b, extended to also cover the
//! chainer's batches (stage 2).
//!
//! Three independent checks, all against `organization_ref` (D-002 — the
//! chain is partitioned per org, same as everywhere else in this crate):
//!
//! 1. **Row-level hash-link continuity + signature** — walks every
//!    `audit_header` row for the org in `id` order (sync-path and
//!    chainer-path rows share one physical table and one chain, so this
//!    single walk covers both, including the boundary where one hands off to
//!    the other) and recomputes each row's `event_hash` with the formula its
//!    `hash_version` names (D-539): version 1 is `compute_hash_raw` over the
//!    stored identity columns; version 2 is `crate::canonical`'s digest over
//!    the stored header, detail and snapshot rows (never `audit_ingest`);
//!    any other version fails. A v1→v2 chain links by the stored hash string,
//!    so mixed history verifies. It checks the recomputed hash against the
//!    stored value and against the previous row's `event_hash`. A single tampered historical
//!    row breaks the chain from that point forward, by design. Sync-path rows
//!    (`chainer_enabled = false` — the development-only mode since D-316, and
//!    any history written before a deployment cut over) additionally carry
//!    a per-row `signature`; this walk also verifies it against
//!    `signing_key_id` the same way the batch check below does, resolving
//!    the verifying key from `audit_signing_key`. Without this, a
//!    writer with direct DB access could rewrite a header row and recompute
//!    `event_hash`/`prev_hash` to keep the hash chain internally consistent —
//!    the signature check is what makes that tamper detectable on the
//!    default (non-batched) code path. **A missing signature is not a free
//!    pass**: once `audit_signing_key` has any row — i.e. this
//!    deployment has ever booted with `audit.signing` configured
//!    (`upsert_signing_key` at boot) — a sync-path row with `signature IS
//!    NULL` is reported as an error, and so is a batch with `signature IS
//!    NULL`. Before this rule (platform review 2026-08-24, B8) a writer with
//!    direct DB access could defeat the row check above by simply
//!    *stripping* the signature along with the rewrite — `verify_row_
//!    signature` skipped unsigned rows, so a stripped row verified clean.
//!    Chainer-path rows (`chain_batch_ref IS NOT NULL`) are exempt from the
//!    row-level rule, because they are written unsigned by design and their
//!    batch carries the signature instead. The one honest cost: history
//!    written before signing was first configured is now reported too — it
//!    genuinely is unverifiable, and an operator who enables signing on a
//!    deployment with unsigned history should expect (and review) exactly
//!    those rows, dated before the first `audit_signing_key.created_at`.
//! 2. **Batch-level Merkle/signature integrity** — for each
//!    `audit_chain_batch`, recomputes the Merkle root from its member
//!    header rows' (already-verified) event hashes, checks it against the
//!    stored root, checks `prev_batch_hash` against the previous batch's
//!    root, and verifies the signature. P-key-rotation-and-jwt (d):
//!    resolved from the batch's own stored `signing_key_id` via
//!    `audit_signing_key` (so a signature made under a since-rotated
//!    key still verifies), falling back to the live signer's self-check only
//!    when the registry has no row for that key_id (pre-migration history).
//! 3. **Ingest completeness** — every `audit_ingest` row up to the last
//!    batch's `last_ingest_id` is claimed by exactly one batch (no gaps
//!    between batches, no double-counting); rows after that are reported as
//!    pending (lag), not an error. Ranges at or below the pruned-ingest
//!    watermark (plan item 2.8) are not counted, because their rows were
//!    deleted after the covering batches were signed and anchored.
//!
//! After the three, the v1 cutover checkpoint (D-539 ruling 6, plan item 2.6,
//! `crate::checkpoint`) is recomputed and compared, which is what protects the
//! content of pre-v2 (hash version 1) rows.
//!
//! Between 1 and 2, `verify_batch_refs` (D-516 ruling 4) checks that every
//! `chain_batch_ref` names a batch of the header's organization. Check 1's
//! exemption for chainer-path rows rests on that batch existing; check 2 only
//! walks batches that do. A missing batch is accepted only under D-280, when
//! an anchored epoch seal names it and the headers still referencing it
//! recompute to the sealed Merkle root.

use attome_db::DbPool;
use attome_storage::StorageClient;
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use uuid::Uuid;

use attome_core::AuditSigner;
use attome_core::audit_signing;

use crate::anchor;
use crate::canonical;
use crate::chainer::{hex_decode_32, merkle_root};
use crate::checkpoint;
use crate::service::compute_hash_raw;

#[derive(Debug, Default)]
pub struct VerificationReport {
    pub organization_ref: Uuid,
    pub headers_checked: usize,
    pub batches_checked: usize,
    pub pending_ingest: i64,
    /// Age of the oldest not-yet-chained `audit_ingest` row, in seconds.
    /// `None` when there is nothing pending.
    pub lag_seconds: Option<i64>,
    /// C14 / D-539 ruling 5 — rows whose `changed_on` is the **application
    /// clock** (hash version 1). Reported, never described as trusted time.
    pub v1_headers: usize,
    /// Rows whose `changed_on` is the database transaction clock at capture
    /// (hash version 2).
    pub v2_headers: usize,
    /// Chainer batches holding v2 rows whose anchor bound was read and
    /// compared (only with an anchor store; see `verify_chain_with_anchors`).
    pub anchor_time_checked_batches: usize,
    /// Batches holding v2 rows whose anchor bound is missing or unreadable:
    /// the time check for them is *unknown*, not passed (C21). Always empty
    /// without an anchor store, where the check does not run at all.
    pub anchor_time_unknown_batches: Vec<Uuid>,
    /// D-539 ruling 6 / plan item 2.6 — how the v1 history's content is
    /// protected: by a cutover checkpoint that was recomputed and compared
    /// (anchored, database-only, anchor missing or unreadable), or not at all.
    pub v1_content_protection: checkpoint::V1ContentProtection,
    /// Checkpointed partitions that no longer exist (dropped under retention;
    /// continuity across them rests on their epoch seal, D-280).
    pub v1_checkpoint_partitions_dropped: usize,
    /// Plan item 2.8 — the highest `last_ingest_id` whose batches' ingest rows
    /// were pruned (`audit_ingest_prune`). Ingest-range counts stop there.
    pub ingest_pruned_through: Option<Uuid>,
    /// Batches at or below `ingest_pruned_through`.
    pub ingest_pruned_batches: usize,
    pub errors: Vec<String>,
}

impl VerificationReport {
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Runs all three checks for one organization's chain. Equivalent to
/// `verify_chain_with_anchors(db, signer, None, org)` — see that function's
/// doc for what passing a `store` additionally buys.
pub async fn verify_chain(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    org: Uuid,
) -> Result<VerificationReport, AppError> {
    verify_chain_with_anchors(db, signer, None, org).await
}

/// Same three checks as `verify_chain`, plus one thing `verify_batches`
/// alone cannot do without `store`: bridge an epoch boundary where the
/// oldest remaining `audit_chain_batch` row for `org` is not this
/// chain's true genesis — its `prev_batch_hash` is non-empty, but the batch
/// it should chain to no longer exists in this database (P-audit-chain-
/// hardening item (c), D-280 — e.g. an old partition was dropped once its
/// epoch was sealed). Without `store`, that situation is reported as an
/// ordinary `prev_batch_hash` mismatch, which is the honest answer when no
/// external anchor is configured to prove continuity. With `store`, the
/// oldest remaining batch's own `epoch_period` is looked up directly
/// (`anchor::fetch_epoch_seal` — no calendar arithmetic needed; see that
/// function's doc for why the seal is filed under the new epoch rather than
/// the old one) — if the anchored root matches this batch's
/// `prev_batch_hash`, continuity across the boundary is proven without
/// needing the dropped epoch's raw rows to still exist, which is the entire
/// point of sealing an epoch.
pub async fn verify_chain_with_anchors(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    store: Option<&StorageClient>,
    org: Uuid,
) -> Result<VerificationReport, AppError> {
    let mut report = VerificationReport {
        organization_ref: org,
        ..Default::default()
    };

    // Read once per pass, not per row: the answer cannot change underneath
    // a verification run in any way that matters (keys are only ever added
    // at boot, never deleted), and it gates every row and batch below.
    let signing_configured = signing_configured(db).await?;

    verify_row_chain(db, signer, signing_configured, org, &mut report).await?;
    verify_batch_refs(db, store, org, &mut report).await?;
    // verify_batches also checks ingest-range completeness (no gaps/overlaps
    // between batches) — it already has the batch list loaded, and needs it
    // to compare consecutive batches, so that check lives there rather than
    // as a separate pass over the same rows.
    verify_batches(db, signer, signing_configured, store, org, &mut report).await?;
    if let Some(store) = store {
        verify_anchor_time_bounds(db, store, org, &mut report).await?;
    }

    // D-539 ruling 6 — the v1 cutover checkpoint. `v1_headers` was counted by
    // the row walk above.
    let v1_check = checkpoint::verify_v1_checkpoint(
        db,
        signer,
        store,
        signing_configured,
        org,
        report.v1_headers > 0,
    )
    .await?;
    report.v1_content_protection = v1_check.protection;
    report.v1_checkpoint_partitions_dropped = v1_check.partitions_dropped;
    report.errors.extend(v1_check.errors);

    let (pending, lag) = lag(db, org).await?;
    report.pending_ingest = pending;
    report.lag_seconds = lag;

    Ok(report)
}

/// Cheap standalone lag check (pending count + oldest-pending age), useful
/// for a monitoring loop that doesn't want to pay for a full verification
/// pass every poll.
pub async fn lag(db: &DbPool, org: Uuid) -> Result<(i64, Option<i64>), AppError> {
    let last_ingest_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT last_ingest_id FROM audit_chain_batch
         WHERE organization_ref = $1 ORDER BY id DESC LIMIT 1",
    )
    .bind(org)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let cutoff = last_ingest_id.unwrap_or(Uuid::nil());

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_ingest WHERE organization_ref = $1 AND id > $2",
    )
    .bind(org)
    .bind(cutoff)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    let oldest_pending: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MIN(created_at) FROM audit_ingest WHERE organization_ref = $1 AND id > $2",
    )
    .bind(org)
    .bind(cutoff)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    let lag_seconds = oldest_pending.map(|t| (Utc::now() - t).num_seconds());
    Ok((pending, lag_seconds))
}

/// P-audit-chain-hardening item (b) — the standalone verification path the
/// plan's goal (§3(b)) calls for: cross-checks every batch's
/// `audit_chain_batch.merkle_root` (this deployment's own Postgres)
/// against its externally anchored copy (`anchor::fetch_anchored_root`),
/// independent of `verify_chain`'s in-database checks above. A mismatch
/// here is the strongest possible signal this whole plan exists to
/// produce: it means the database's own copy of a root disagrees with a
/// copy that was never inside this deployment's blast radius at all.
#[derive(Debug, Default)]
pub struct AnchorVerificationReport {
    pub organization_ref: Uuid,
    pub batches_checked: usize,
    /// Batches with no external anchor on record — not itself evidence of
    /// tampering (may simply predate `external_anchoring_enabled`, or that
    /// batch's own anchoring attempt failed — anchoring is best-effort by
    /// design, see `anchor`'s module doc). Reported for visibility, not
    /// folded into `mismatches`.
    pub unanchored: Vec<Uuid>,
    /// A batch whose anchored root disagrees with what's stored in
    /// `audit_chain_batch` — this is real tamper evidence, not a soft
    /// finding.
    pub mismatches: Vec<String>,
}

impl AnchorVerificationReport {
    pub fn is_ok(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// See [`AnchorVerificationReport`]. Fetches one anchor per batch
/// sequentially rather than concurrently — this is an operator-triggered
/// drill/audit path (`verify_audit_chain` bin), not a request-path or
/// per-poll operation, so bounded concurrency (guidelines §14) isn't worth
/// the added complexity here; a deployment with enough batches for this to
/// matter can shard by organization across multiple invocations.
pub async fn verify_anchors(
    db: &DbPool,
    store: &StorageClient,
    org: Uuid,
) -> Result<AnchorVerificationReport, AppError> {
    let batches: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, merkle_root FROM audit_chain_batch
         WHERE organization_ref = $1
         ORDER BY id",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut report = AnchorVerificationReport {
        organization_ref: org,
        batches_checked: batches.len(),
        ..Default::default()
    };

    for (batch_id, stored_root) in batches {
        match anchor::fetch_anchored_root(store, org, batch_id).await? {
            Some(anchored_root) if anchored_root != stored_root => {
                report.mismatches.push(format!(
                    "batch {batch_id}: audit_chain_batch.merkle_root {stored_root} \
                     does not match externally anchored root {anchored_root}"
                ));
            }
            Some(_) => {}
            None => report.unanchored.push(batch_id),
        }
    }

    Ok(report)
}

#[derive(sqlx::FromRow)]
struct HeaderRow {
    id: Uuid,
    operation: Option<i32>,
    entity_name: Option<String>,
    record_id: Option<Uuid>,
    user_id: Option<Uuid>,
    changed_on: Option<DateTime<Utc>>,
    prev_hash: Option<String>,
    event_hash: String,
    signature: Option<String>,
    signing_key_id: Option<String>,
    /// `Some` for a chainer-path row (`append_in_batch`), whose batch
    /// carries the signature; `None` for a sync-path row, which must carry
    /// its own once signing is configured.
    chain_batch_ref: Option<Uuid>,
    /// D-539 ruling 1: which formula `event_hash` was computed with.
    hash_version: i16,
    /// Diagnostic only (v2): verification always recomputes the digest.
    content_digest: Option<String>,
}

/// "Has this deployment ever configured audit signing?" — true once
/// `audit_signing_key` holds any row. Rows are written by
/// `upsert_signing_key` at boot for the configured signer and are never
/// deleted (a rotated-out key is marked `retired_at`, so it still counts:
/// signing was configured when it was live, and every row written under it
/// must be signed). This is the gate for the NULL-signature rule in
/// `verify_row_signature` and `verify_batches`.
async fn signing_configured(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM audit_signing_key)")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Row-level counterpart to `verify_batch_signature` below. Only sync-path
/// rows (`chainer_enabled = false` — dev-only since D-316, plus pre-cutover
/// history, `AuditService::write_header` via
/// `write_in_tx`) carry a per-row `signature` — chainer-path rows
/// (`append_in_batch`, `chain_batch_ref IS NOT NULL`) are written with
/// `signature = NULL` because their batch's Merkle root gets the signature
/// instead, so a `None` on one of those is never an error. A `None` on a
/// **sync-path** row is an error whenever `signing_configured` (see that
/// function): with signing configured every sync-path write signs, so an
/// unsigned sync-path row is either a stripped signature — the trivial
/// bypass of the check below, since an attacker who rewrites a row can
/// also NULL its signature — or pre-signing history, which is unverifiable
/// and must be surfaced rather than silently accepted. With signing never
/// configured, unsigned rows are the only kind there are, and the row is
/// skipped as before. Before the signature check itself existed,
/// `verify_row_chain` only recomputed `event_hash`/`prev_hash` continuity
/// — a writer with direct DB access could rewrite a header row's business
/// columns, recompute `event_hash`/`prev_hash` to keep the chain internally
/// consistent, and `verify_chain` would report clean, because the stored
/// `signature` was never checked against anything on the sync path.
async fn verify_row_signature(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    signing_configured: bool,
    row: &HeaderRow,
    prev_hash: &str,
    report: &mut VerificationReport,
) -> Result<(), AppError> {
    let Some(sig) = &row.signature else {
        if signing_configured && row.chain_batch_ref.is_none() {
            report.errors.push(format!(
                "header {}: no signature on a sync-path row while audit signing is configured \
                 (audit_signing_key is non-empty) — either the signature was stripped, or \
                 the row predates signing and is unverifiable",
                row.id
            ));
        }
        return Ok(());
    };

    match verify_signature(
        db,
        signer,
        row.signing_key_id.as_deref(),
        prev_hash,
        &row.event_hash,
        sig,
    )
    .await?
    {
        SignatureCheck::Ok => {}
        SignatureCheck::Invalid => {
            report.errors.push(format!(
                "header {}: signature does not verify against prev_hash||event_hash",
                row.id
            ));
        }
        SignatureCheck::Unverifiable => {
            report.errors.push(format!(
                "header {}: has a signature but neither the registry nor a live signer can verify it",
                row.id
            ));
        }
    }

    Ok(())
}

async fn verify_row_chain(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    signing_configured: bool,
    org: Uuid,
    report: &mut VerificationReport,
) -> Result<(), AppError> {
    let rows: Vec<HeaderRow> = sqlx::query_as(
        "SELECT id, operation, entity_name, record_id, user_id, changed_on, prev_hash, event_hash,
                signature, signing_key_id, chain_batch_ref, hash_version, content_digest
         FROM audit_header
         WHERE organization_ref = $1
         ORDER BY id",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    if attachment_table_exists(db).await? {
        report.errors.push(
            "audit_attachment exists, but this verifier predates attachment references \
             (audit plan Phase 7) and encodes every v2 event with zero attachments — v2 \
             digests cannot be trusted until the verifier reads that table"
                .to_owned(),
        );
    }

    let mut expected_prev = String::new();
    let mut conn = db.acquire().await.map_err(AppError::internal)?;

    for chunk in rows.chunks(V2_LOAD_CHUNK) {
        // D-539 ruling 4: v2 content comes from the stored header, detail and
        // snapshot rows, loaded in three statements per chunk.
        let v2_ids: Vec<Uuid> = chunk
            .iter()
            .filter(|r| r.hash_version == canonical::HASH_VERSION_V2)
            .map(|r| r.id)
            .collect();
        let stored = canonical::load_stored_events(&mut conn, &v2_ids)
            .await
            .map_err(AppError::internal)?;

        for row in chunk {
            let stored_prev = row.prev_hash.clone().unwrap_or_default();
            if stored_prev != expected_prev {
                report.errors.push(format!(
                    "header {}: prev_hash mismatch (stored {stored_prev:?}, expected {expected_prev:?})",
                    row.id
                ));
            }

            verify_row_signature(db, signer, signing_configured, row, &stored_prev, report).await?;

            match row.hash_version {
                canonical::HASH_VERSION_V1 => report.v1_headers += 1,
                canonical::HASH_VERSION_V2 => report.v2_headers += 1,
                _ => {}
            }

            match recompute_row_hash(row, &expected_prev, stored.get(&row.id)) {
                Ok(recomputed) => {
                    if let Some(digest) = &recomputed.content_digest
                        && row.content_digest.as_deref() != Some(digest.as_str())
                    {
                        report.errors.push(format!(
                            "header {}: content_digest mismatch — the stored header, detail or \
                             snapshot content changed (stored {:?}, recomputed {digest})",
                            row.id, row.content_digest
                        ));
                    }
                    if recomputed.event_hash != row.event_hash {
                        report.errors.push(format!(
                            "header {}: event_hash mismatch — tamper detected \
                             (stored {}, recomputed {})",
                            row.id, row.event_hash, recomputed.event_hash
                        ));
                    }
                }
                Err(reason) => report.errors.push(format!("header {}: {reason}", row.id)),
            }

            expected_prev = row.event_hash.clone();
        }
    }

    report.headers_checked = rows.len();
    Ok(())
}

/// Rows per `canonical::load_stored_events` call — bounds both the `= ANY($1)`
/// array and the detail/snapshot rows held in memory at once.
pub(crate) const V2_LOAD_CHUNK: usize = 500;

struct RecomputedHash {
    event_hash: String,
    /// `Some` for a v2 row.
    content_digest: Option<String>,
}

/// D-539 ruling 1 — dispatch on `hash_version`. `1` is `compute_hash_raw`
/// over the stored identity columns, forever; `2` is the canonical-event
/// digest over `stored` (the row's stored header, detail and snapshot rows);
/// any other value is a failure, never a skip. `Err` carries the report text.
fn recompute_row_hash(
    row: &HeaderRow,
    prev_hash: &str,
    stored: Option<&canonical::CanonicalEvent>,
) -> Result<RecomputedHash, String> {
    match row.hash_version {
        canonical::HASH_VERSION_V1 => {
            let (Some(operation), Some(user_id), Some(changed_on)) =
                (row.operation, row.user_id, row.changed_on)
            else {
                return Err("missing operation/user_id/changed_on — cannot recompute hash".into());
            };
            Ok(RecomputedHash {
                event_hash: compute_hash_raw(
                    prev_hash,
                    operation,
                    row.entity_name.as_deref(),
                    row.record_id,
                    user_id,
                    changed_on.timestamp_millis(),
                ),
                content_digest: None,
            })
        }
        canonical::HASH_VERSION_V2 => {
            let stored =
                stored.ok_or("hash_version 2 row disappeared while it was being verified")?;
            let digest = canonical::content_digest_v2(stored).map_err(|e| {
                format!("stored rows cannot be canonically encoded ({e}) — tamper detected")
            })?;
            let event_hash = canonical::event_hash_v2(prev_hash, &digest)
                .map_err(|e| format!("cannot compute the v2 event hash: {e}"))?;
            Ok(RecomputedHash {
                event_hash,
                content_digest: Some(digest),
            })
        }
        other => Err(format!(
            "unknown hash_version {other} — this verifier knows versions 1 and 2, and an \
             unknown version is a verification failure, never a skip (D-539 ruling 1)"
        )),
    }
}

/// Phase 7 creates `audit_attachment`. Until then every v2 event encodes
/// zero attachment references; if the table appears before this verifier
/// learns to read it, verification fails closed instead of ignoring it.
async fn attachment_table_exists(db: &DbPool) -> Result<bool, AppError> {
    sqlx::query_scalar("SELECT to_regclass('audit_attachment') IS NOT NULL")
        .fetch_one(db)
        .await
        .map_err(AppError::internal)
}

/// Recomputes one header's `event_hash` from its stored rows and its own
/// stored `prev_hash`, with the formula its `hash_version` names. `Ok(None)`
/// when no such header exists; `Err` when the row cannot be recomputed at all
/// (an unknown version, or stored rows that do not encode). The formula is
/// public by design (D-539 publishes a test vector), so this is exactly what a
/// DB-level writer can compute too — tamper tests use it to prove that a
/// consistently rewritten row is still caught by a signature, a batch Merkle
/// root or an anchor, never by the hash alone.
pub async fn recompute_stored_event_hash(
    db: &DbPool,
    header_id: Uuid,
) -> Result<Option<String>, AppError> {
    let row: Option<HeaderRow> = sqlx::query_as(
        "SELECT id, operation, entity_name, record_id, user_id, changed_on, prev_hash, event_hash,
                signature, signing_key_id, chain_batch_ref, hash_version, content_digest
         FROM audit_header
         WHERE id = $1",
    )
    .bind(header_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let stored = load_one_stored_event(db, &row).await?;
    recompute_row_hash(
        &row,
        row.prev_hash.as_deref().unwrap_or_default(),
        stored.as_ref(),
    )
    .map(|r| Some(r.event_hash))
    .map_err(|reason| AppError::internal(format!("header {header_id}: {reason}")))
}

async fn load_one_stored_event(
    db: &DbPool,
    row: &HeaderRow,
) -> Result<Option<canonical::CanonicalEvent>, AppError> {
    if row.hash_version != canonical::HASH_VERSION_V2 {
        return Ok(None);
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    Ok(canonical::load_stored_events(&mut conn, &[row.id])
        .await
        .map_err(AppError::internal)?
        .remove(&row.id))
}

/// C14 / D-539 ruling 5 — the anchor upper bound. For every chainer batch
/// holding v2 rows, reads the anchor object's storage-assigned `Last-Modified`
/// live from the anchor store and reports each v2 event whose `changed_on` is
/// later than that bound plus one second (HTTP-date granularity). A batch
/// whose anchor is missing or unreadable is recorded as *unknown*, never as a
/// pass (C21). v1 rows are not checked: their time is the application clock
/// and is reported as such (`VerificationReport::v1_headers`).
async fn verify_anchor_time_bounds(
    db: &DbPool,
    store: &StorageClient,
    org: Uuid,
    report: &mut VerificationReport,
) -> Result<(), AppError> {
    let batches: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT chain_batch_ref, MAX(changed_on)
         FROM audit_header
         WHERE organization_ref = $1
           AND hash_version = 2
           AND chain_batch_ref IS NOT NULL
           AND changed_on IS NOT NULL
         GROUP BY chain_batch_ref
         ORDER BY chain_batch_ref",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for (batch_id, latest) in batches {
        let bound = match anchor::fetch_anchor_bound(store, org, batch_id).await {
            Ok(Some(bound)) => bound,
            Ok(None) => {
                report.anchor_time_unknown_batches.push(batch_id);
                continue;
            }
            Err(e) => {
                tracing::warn!(
                    organization_ref = %org,
                    batch_id = %batch_id,
                    error = %e,
                    "audit verification: anchor bound unreadable — time check reported unknown",
                );
                report.anchor_time_unknown_batches.push(batch_id);
                continue;
            }
        };
        report.anchor_time_checked_batches += 1;

        let limit = bound + chrono::Duration::seconds(1);
        if latest <= limit {
            continue;
        }
        let late: Vec<(Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT id, changed_on FROM audit_header
             WHERE organization_ref = $1 AND chain_batch_ref = $2
               AND hash_version = 2 AND changed_on > $3
             ORDER BY id",
        )
        .bind(org)
        .bind(batch_id)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        for (header_id, changed_on) in late {
            report.errors.push(format!(
                "header {header_id}: v2 event time {changed_on} is later than its batch \
                 {batch_id}'s anchor bound {bound} (anchor object Last-Modified, +1s tolerance) \
                 — an event cannot postdate the anchor that covers it"
            ));
        }
    }
    Ok(())
}

/// D-516 ruling 4 — every `chain_batch_ref` must name a batch of the same
/// organization. `verify_row_signature` exempts chainer-path rows from the
/// per-row signature rule because their batch carries the signature, and
/// `verify_batches` only walks batches that exist, so before this check a
/// forged header only had to carry *any* `chain_batch_ref` — even a random
/// one — to escape both.
///
/// The one legitimate missing batch is D-280's: a sealed epoch whose
/// `audit_chain_batch` row was dropped (`tests/epoch_boundary.rs`). That
/// is accepted only when an externally anchored epoch seal names the missing
/// batch **and** the Merkle root recomputed over the headers still carrying
/// that reference equals the sealed root — the same trust root
/// `bridge_epoch_boundary` uses for `prev_batch_hash`. Without a `store`, or
/// with no seal naming the batch, a dangling reference is an error.
async fn verify_batch_refs(
    db: &DbPool,
    store: Option<&StorageClient>,
    org: Uuid,
    report: &mut VerificationReport,
) -> Result<(), AppError> {
    let dangling: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT h.chain_batch_ref
         FROM audit_header h
         WHERE h.organization_ref = $1
           AND h.chain_batch_ref IS NOT NULL
           AND NOT EXISTS (
               SELECT 1 FROM audit_chain_batch b
               WHERE b.id = h.chain_batch_ref AND b.organization_ref = $1
           )
         ORDER BY h.chain_batch_ref",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    if dangling.is_empty() {
        return Ok(());
    }

    let sealed = sealed_batch_roots(db, store, org).await?;

    for batch_ref in dangling {
        let Some(sealed_root) = sealed.get(&batch_ref) else {
            report.errors.push(format!(
                "chain_batch_ref {batch_ref}: names no audit_chain_batch row of this \
                 organization and no anchored epoch seal accounts for it — a forged or \
                 dangling batch reference (a header is exempt from the per-row signature \
                 rule only because its batch signs it)"
            ));
            continue;
        };

        let member_hashes: Vec<String> = sqlx::query_scalar(
            "SELECT event_hash FROM audit_header
             WHERE organization_ref = $1 AND chain_batch_ref = $2
             ORDER BY id",
        )
        .bind(org)
        .bind(batch_ref)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;

        let leaves: Result<Vec<[u8; 32]>, AppError> =
            member_hashes.iter().map(|h| hex_decode_32(h)).collect();
        match leaves {
            Ok(leaves) => {
                let recomputed_root = merkle_root(&leaves);
                if recomputed_root != *sealed_root {
                    report.errors.push(format!(
                        "chain_batch_ref {batch_ref}: its batch row is gone and the Merkle root \
                         over the headers still referencing it ({recomputed_root}) does not match \
                         the anchored epoch seal ({sealed_root}) — a header was added to, removed \
                         from, or altered in a sealed epoch"
                    ));
                }
            }
            Err(e) => report.errors.push(format!(
                "chain_batch_ref {batch_ref}: could not decode a member event_hash: {e}"
            )),
        }
    }

    Ok(())
}

/// Batch id → sealed Merkle root for every epoch seal reachable from the
/// batches still present. Each remaining batch's `epoch_period` is the key
/// its preceding epoch's seal is filed under (`anchor::fetch_epoch_seal`),
/// and that seal names the preceding epoch's last batch. Empty when no
/// `store` is configured. Called only when a dangling reference exists, so
/// the common path makes no storage request.
async fn sealed_batch_roots(
    db: &DbPool,
    store: Option<&StorageClient>,
    org: Uuid,
) -> Result<std::collections::HashMap<Uuid, String>, AppError> {
    let mut roots = std::collections::HashMap::new();
    let Some(store) = store else {
        return Ok(roots);
    };

    let periods: Vec<NaiveDate> = sqlx::query_scalar(
        "SELECT DISTINCT epoch_period FROM audit_chain_batch
         WHERE organization_ref = $1
         ORDER BY epoch_period",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    for period in periods {
        if let Some((batch_id, merkle_root)) = anchor::fetch_epoch_seal(store, org, period).await? {
            roots.insert(batch_id, merkle_root);
        }
    }

    Ok(roots)
}

// ── D-442 / M58 Phase 1 — bounded single-row check ──────────────────────────

/// Result of [`verify_header_row`] — the bounded, single-row counterpart to
/// [`verify_row_chain`]'s full per-organization walk. Used by M58's
/// `GET /api/v1/signoff/{decision_id}/verify` (`attome-server::signoff`), which
/// needs a cheap check on one specific `audit_header` row rather than
/// paying for a full-chain walk on every call.
///
/// Reuses exactly the same primitives `verify_row_chain`/`verify_row_signature`
/// use (`recompute_row_hash`, `verify_signature`) — no new comparison logic.
/// What this does NOT prove, unlike the full walk: that this row's stored
/// `prev_hash` itself continues correctly from the true previous row (that
/// needs `verify_chain`). What it DOES prove: the row has not been altered in
/// place since it was written — for a hash-version-2 row its whole canonical
/// event (header, detail and snapshot rows, D-539); for a version-1 row only
/// `operation`/`entity_name`/`record_id`/`user_id`/`changed_on` — and, when
/// signed, that the signature still verifies.
#[derive(Debug)]
pub struct RowVerification {
    pub header_id: Uuid,
    /// The row's stored `hash_version` (D-539): what `hash_ok` covers.
    pub hash_version: i16,
    pub hash_ok: bool,
    /// `None` when the row carries no signature to check at all — either
    /// this deployment has never configured audit signing, or this is a
    /// chainer-path row (`chain_batch_ref IS NOT NULL`) whose *batch* is
    /// signed instead (see `verify_row_signature`'s doc comment) — neither
    /// case is itself an error. `Some(false)` for an unsigned chainer-path
    /// row whose `chain_batch_ref` names no batch of its organization
    /// (D-516 ruling 4): nothing verifiable covers it. Also `Some(false)` for
    /// an unsigned row with no batch reference once this deployment has
    /// configured audit signing — the same rule `verify_row_signature` applies
    /// on the full walk (audit 10/10 plan item 1.7).
    pub signature_ok: Option<bool>,
}

impl RowVerification {
    pub fn is_ok(&self) -> bool {
        self.hash_ok && self.signature_ok != Some(false)
    }
}

/// Looks up one `audit_header` row by id and runs the same two checks
/// [`verify_row_chain`] runs on every row of a full walk — `Ok(None)` when no
/// such row exists (e.g. the event is still sitting unchained in
/// `audit_ingest` under `audit.chainer_enabled`, or the id is simply
/// wrong).
pub async fn verify_header_row(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    header_id: Uuid,
) -> Result<Option<RowVerification>, AppError> {
    let row: Option<HeaderRow> = sqlx::query_as(
        "SELECT id, operation, entity_name, record_id, user_id, changed_on, prev_hash, event_hash,
                signature, signing_key_id, chain_batch_ref, hash_version, content_digest
         FROM audit_header
         WHERE id = $1",
    )
    .bind(header_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let Some(row) = row else {
        return Ok(None);
    };

    let prev_hash = row.prev_hash.clone().unwrap_or_default();

    // D-539 ruling 1: the same dispatch the full walk uses. A v2 row is
    // recomputed from its stored header, detail and snapshot rows, so this
    // single-row check now covers the event's content, not just its identity.
    // An unknown version or unencodable stored rows is a failed hash check.
    let stored = load_one_stored_event(db, &row).await?;
    let hash_ok = recompute_row_hash(&row, &prev_hash, stored.as_ref())
        .is_ok_and(|recomputed| recomputed.event_hash == row.event_hash);

    let signature_ok = match (&row.signature, row.chain_batch_ref) {
        (Some(sig), _) => Some(matches!(
            verify_signature(
                db,
                signer,
                row.signing_key_id.as_deref(),
                &prev_hash,
                &row.event_hash,
                sig,
            )
            .await?,
            SignatureCheck::Ok
        )),
        // D-516 ruling 4: a chainer-path row is exempt from carrying its own
        // signature only because its batch signs it. With no batch of the
        // header's organization to do that, nothing verifiable covers the
        // row. This check has no anchor store, so D-280's sealed-and-dropped
        // batch — provable only by `verify_chain_with_anchors` — also reports
        // `Some(false)` here, which is the honest answer without the seal.
        (None, Some(batch_ref)) => {
            let batch_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                     SELECT 1
                     FROM audit_chain_batch b
                     JOIN audit_header h ON h.organization_ref = b.organization_ref
                     WHERE b.id = $1 AND h.id = $2
                 )",
            )
            .bind(batch_ref)
            .bind(header_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
            if batch_exists { None } else { Some(false) }
        }
        // Item 1.7: the NULL-signature rule `verify_row_signature` applies on
        // the full walk. Once signing has been configured, a sync-path row
        // must carry its own signature; an unsigned one is a stripped
        // signature or unverifiable history, never a pass.
        (None, None) => {
            if signing_configured(db).await? {
                Some(false)
            } else {
                None
            }
        }
    };

    Ok(Some(RowVerification {
        header_id,
        hash_version: row.hash_version,
        hash_ok,
        signature_ok,
    }))
}

#[derive(sqlx::FromRow)]
struct BatchRow {
    id: Uuid,
    first_ingest_id: Uuid,
    last_ingest_id: Uuid,
    event_count: i32,
    prev_batch_hash: String,
    merkle_root: String,
    signature: Option<String>,
    signing_key_id: Option<String>,
    epoch_period: NaiveDate,
}

/// Bridges a non-genesis first batch (see `verify_batches`) via the anchor
/// filed under its own `epoch_period` — that anchor, if it exists, names
/// whatever batch actually preceded this one (`anchor::fetch_epoch_seal`
/// doc comment), so no calendar arithmetic is needed here either.
/// `Ok(None)` when there's nothing to bridge with — no `store` configured,
/// or no epoch was ever sealed at this boundary — the caller distinguishes
/// those from an actual mismatch.
async fn bridge_epoch_boundary(
    store: Option<&StorageClient>,
    org: Uuid,
    oldest_batch: &BatchRow,
) -> Result<Option<String>, AppError> {
    let Some(store) = store else {
        return Ok(None);
    };
    let sealed = anchor::fetch_epoch_seal(store, org, oldest_batch.epoch_period).await?;
    Ok(sealed.map(|(_, merkle_root)| merkle_root))
}

async fn verify_batches(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    signing_configured: bool,
    store: Option<&StorageClient>,
    org: Uuid,
    report: &mut VerificationReport,
) -> Result<(), AppError> {
    let batches: Vec<BatchRow> = sqlx::query_as(
        "SELECT id, first_ingest_id, last_ingest_id, event_count, prev_batch_hash,
                merkle_root, signature, signing_key_id, epoch_period
         FROM audit_chain_batch
         WHERE organization_ref = $1
         ORDER BY id",
    )
    .bind(org)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut expected_prev_batch_hash = String::new();

    for (i, batch) in batches.iter().enumerate() {
        if batch.prev_batch_hash != expected_prev_batch_hash {
            if i == 0 {
                // Not genesis: either real tamper/gap evidence, or this is
                // the first batch of an epoch whose preceding epoch was
                // sealed and dropped (D-280) — try to bridge it via the
                // sealed anchor before treating it as an error.
                match bridge_epoch_boundary(store, org, batch).await? {
                    Some(sealed_root) if sealed_root == batch.prev_batch_hash => {
                        // Proven via the externally anchored epoch seal:
                        // this remaining data's genesis chains cleanly to a
                        // sealed epoch this deployment no longer needs the
                        // raw rows of. Not an error.
                    }
                    Some(mismatched_root) => {
                        report.errors.push(format!(
                            "batch {}: prev_batch_hash {} does not match the sealed anchor for \
                             the preceding epoch ({mismatched_root}) — tamper evidence, not a \
                             missing-history gap",
                            batch.id, batch.prev_batch_hash
                        ));
                    }
                    None => {
                        report.errors.push(format!(
                            "batch {}: prev_batch_hash mismatch (stored {:?}, expected {:?}) and \
                             no sealed epoch anchor found to bridge it — either tamper evidence \
                             or an older partition was dropped without ever being sealed/anchored",
                            batch.id, batch.prev_batch_hash, expected_prev_batch_hash
                        ));
                    }
                }
            } else {
                report.errors.push(format!(
                    "batch {}: prev_batch_hash mismatch (stored {:?}, expected {:?})",
                    batch.id, batch.prev_batch_hash, expected_prev_batch_hash
                ));
            }
        }

        let member_hashes: Vec<String> = sqlx::query_scalar(
            "SELECT event_hash FROM audit_header WHERE chain_batch_ref = $1 ORDER BY id",
        )
        .bind(batch.id)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;

        if member_hashes.len() as i32 != batch.event_count {
            report.errors.push(format!(
                "batch {}: event_count {} does not match {} member header rows found",
                batch.id,
                batch.event_count,
                member_hashes.len()
            ));
        }

        if member_hashes.is_empty() {
            report
                .errors
                .push(format!("batch {}: no member header rows found", batch.id));
        } else {
            let leaves: Result<Vec<[u8; 32]>, AppError> =
                member_hashes.iter().map(|h| hex_decode_32(h)).collect();
            match leaves {
                Ok(leaves) => {
                    let recomputed_root = merkle_root(&leaves);
                    if recomputed_root != batch.merkle_root {
                        report.errors.push(format!(
                            "batch {}: merkle_root mismatch (stored {}, recomputed {recomputed_root})",
                            batch.id, batch.merkle_root
                        ));
                    }
                }
                Err(e) => report.errors.push(format!(
                    "batch {}: could not decode a member event_hash: {e}",
                    batch.id
                )),
            }
        }

        if let Some(sig) = &batch.signature {
            verify_batch_signature(db, signer, batch, sig, report).await?;
        } else if signing_configured {
            // Same rule as `verify_row_signature`: with signing configured
            // the chainer signs every batch (`sign_batch`), so an unsigned
            // batch is a stripped signature or unverifiable pre-signing
            // history — never a clean pass.
            report.errors.push(format!(
                "batch {}: no signature while audit signing is configured \
                 (audit_signing_key is non-empty) — either the signature was stripped, or \
                 the batch predates signing and is unverifiable",
                batch.id
            ));
        } // else: signing has never been configured here — unsigned is the only kind there is.

        expected_prev_batch_hash = batch.merkle_root.clone();
    }

    report.batches_checked = batches.len();
    verify_ingest_ranges(db, store, org, &batches, report).await
}

/// `verify_signature` as a plain yes/no, for callers outside this module that
/// sign their own `(a, b)` pair (the v1 cutover checkpoint). A signature
/// neither the registry nor a live signer can check is not a pass.
pub(crate) async fn signature_verifies(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    signing_key_id: Option<&str>,
    a: &str,
    b: &str,
    sig: &str,
) -> Result<bool, AppError> {
    Ok(matches!(
        verify_signature(db, signer, signing_key_id, a, b, sig).await?,
        SignatureCheck::Ok
    ))
}

/// Outcome of resolving+checking a signature against the signing-key
/// registry (shared by the per-row and per-batch checks below).
enum SignatureCheck {
    Ok,
    Invalid,
    /// Signature present but neither the registry nor a live signer could
    /// check it (key_id not registered and no live signer configured).
    Unverifiable,
}

/// P-key-rotation-and-jwt (d) — resolves the verifying key from the
/// signature's own stored `signing_key_id` via `audit_signing_key`
/// first; only falls back to `signer`'s self-check when the registry has no
/// row for that key_id (signed before this registry existed). This is what
/// makes a signature made under a since-rotated-out key still verify: the
/// registry row for a retired key is never deleted, only marked
/// `retired_at`. Shared by the batch-level check (`prev_batch_hash`,
/// `merkle_root`) and the row-level check (`prev_hash`, `event_hash`) —
/// both sign `(a, b)` the same way via `sign_pair`/`AuditSigner::sign`.
async fn verify_signature(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    signing_key_id: Option<&str>,
    a: &str,
    b: &str,
    sig: &str,
) -> Result<SignatureCheck, AppError> {
    let registered_key = match signing_key_id {
        Some(key_id) => audit_signing::lookup_signing_public_key(db, key_id).await?,
        None => None,
    };

    Ok(match (registered_key, signer) {
        (Some(public_key), _) => {
            if audit_signing::verify_with_key(a, b, sig, &public_key) {
                SignatureCheck::Ok
            } else {
                SignatureCheck::Invalid
            }
        }
        (None, Some(signer)) => {
            if signer.verify(a, b, sig) {
                SignatureCheck::Ok
            } else {
                SignatureCheck::Invalid
            }
        }
        (None, None) => SignatureCheck::Unverifiable,
    })
}

async fn verify_batch_signature(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    batch: &BatchRow,
    sig: &str,
    report: &mut VerificationReport,
) -> Result<(), AppError> {
    match verify_signature(
        db,
        signer,
        batch.signing_key_id.as_deref(),
        &batch.prev_batch_hash,
        &batch.merkle_root,
        sig,
    )
    .await?
    {
        SignatureCheck::Ok => {}
        SignatureCheck::Invalid => {
            report.errors.push(format!(
                "batch {}: signature does not verify against prev_batch_hash||merkle_root",
                batch.id
            ));
        }
        SignatureCheck::Unverifiable => {
            report.errors.push(format!(
                "batch {}: has a signature but neither the registry nor a live signer can verify it",
                batch.id
            ));
        }
    }
    Ok(())
}

/// No gaps between consecutive batches' ingest ranges, and each batch's own
/// range contains exactly `event_count` ingest rows (catches double-counted
/// or missing ingest rows without relying on the header-row count alone).
///
/// Plan item 2.8: the ingest rows of batches at or below the pruned watermark
/// (`audit_ingest_prune`) were deleted by `chainer::prune_ingest`, so
/// their range count is not checked. Neither hash version reads ingest: the
/// header rows, Merkle roots and signatures checked above carry the proof.
/// The watermark is checked instead: it must be the `last_ingest_id` of one
/// of this organization's batches, and — with an anchor store — every batch it
/// covers must be anchored with a matching root (the batches' signatures are
/// already required by `verify_batches` once signing is configured). The gap
/// check between consecutive batches still runs below the watermark: pruning
/// deletes only rows inside batch ranges, so an orphaned row between two
/// ranges survives it.
async fn verify_ingest_ranges(
    db: &DbPool,
    store: Option<&StorageClient>,
    org: Uuid,
    batches: &[BatchRow],
    report: &mut VerificationReport,
) -> Result<(), AppError> {
    let pruned_through: Option<Uuid> = sqlx::query_scalar(
        "SELECT through_ingest_id FROM audit_ingest_prune
         WHERE organization_ref = $1
         ORDER BY through_ingest_id DESC
         LIMIT 1",
    )
    .bind(org)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    report.ingest_pruned_through = pruned_through;

    if let Some(watermark) = pruned_through
        && !batches.iter().any(|b| b.last_ingest_id == watermark)
    {
        report.errors.push(format!(
            "audit_ingest_prune: pruned watermark {watermark} is not the last_ingest_id of \
             any chain batch of this organization — a forged or stale watermark"
        ));
    }

    let mut prev_last_ingest_id: Option<Uuid> = None;

    for batch in batches {
        let pruned = pruned_through.is_some_and(|w| batch.last_ingest_id <= w);
        if pruned {
            report.ingest_pruned_batches += 1;
            if let Some(store) = store {
                match anchor::fetch_anchored_root(store, org, batch.id).await {
                    Ok(Some(root)) if root == batch.merkle_root => {}
                    Ok(Some(root)) => report.errors.push(format!(
                        "batch {}: ingest range pruned, and its anchored root {root} does not \
                         match merkle_root {}",
                        batch.id, batch.merkle_root
                    )),
                    Ok(None) => report.errors.push(format!(
                        "batch {}: ingest range pruned but the batch has no external anchor — \
                         pruning is allowed only for signed and anchored batches",
                        batch.id
                    )),
                    Err(e) => {
                        tracing::warn!(
                            organization_ref = %org,
                            batch_id = %batch.id,
                            error = %e,
                            "audit verification: anchor of a pruned batch unreadable — reported unknown",
                        );
                        if !report.anchor_time_unknown_batches.contains(&batch.id) {
                            report.anchor_time_unknown_batches.push(batch.id);
                        }
                    }
                }
            }
        } else {
            let range_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_ingest
                 WHERE organization_ref = $1 AND id >= $2 AND id <= $3",
            )
            .bind(org)
            .bind(batch.first_ingest_id)
            .bind(batch.last_ingest_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;

            if range_count as i32 != batch.event_count {
                report.errors.push(format!(
                    "batch {}: ingest range [{}, {}] contains {range_count} rows, expected {}",
                    batch.id, batch.first_ingest_id, batch.last_ingest_id, batch.event_count
                ));
            }
        }

        if let Some(prev_last) = prev_last_ingest_id {
            let gap_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_ingest
                 WHERE organization_ref = $1 AND id > $2 AND id < $3",
            )
            .bind(org)
            .bind(prev_last)
            .bind(batch.first_ingest_id)
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;

            if gap_count > 0 {
                report.errors.push(format!(
                    "{gap_count} orphaned ingest row(s) between batch's last_ingest_id {prev_last} \
                     and the next batch's first_ingest_id {}",
                    batch.first_ingest_id
                ));
            }
        }

        prev_last_ingest_id = Some(batch.last_ingest_id);
    }

    Ok(())
}
