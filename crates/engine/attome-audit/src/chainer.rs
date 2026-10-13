//! P1.13 stage 2 — the async chain-append process.
//!
//! Drains `audit_ingest` (P1.13 stage 1) into `audit_header`/
//! `detail`/`snapshot` with hash-linking identical to the synchronous
//! `AuditService::write` path (P1.5), but signs one Merkle root per batch
//! instead of one signature per row, and only holds the per-organization
//! advisory lock for the duration of one batch's transaction — never across
//! a whole poll cycle, and never blocking (`pg_try_advisory_xact_lock`, same
//! as everywhere else in this codebase). This is what actually removes the
//! chain-append lock as the platform's throughput ceiling (D-024); stage 1's
//! `audit_ingest` write is lock-free and runs in parallel with every
//! other request.
//!
//! Packaged as its own OS process, not a request-path task: the entrypoint
//! is `attome-website/crates/server/src/bin/audit_chainer.rs`, a thin loop
//! that calls `run_once` on a poll interval. This module has no knowledge of
//! how it is invoked and is independently testable.
//!
//! ## The commit-visibility race, and why this drains a *prefix*, not a filter
//!
//! Two `audit_ingest` rows inserted on different pooled connections can
//! commit out of `id` order (the classic transactional-outbox race): a
//! higher-`id` (uuidv7, so normally "later") row's transaction can commit
//! before a lower-`id` row's, if the lower-`id` transaction is still
//! in-flight. A naive `WHERE id > last_seen ORDER BY id` drain is unsafe
//! against this — it can walk past the still-in-flight row and never come
//! back for it, silently losing that event forever, since a future poll's
//! `WHERE id > checkpoint` bound would already exclude it.
//!
//! This is closed with an **xmin-snapshot watermark**: for a candidate row,
//! `xact_id < pg_snapshot_xmin(pg_current_snapshot())` (see `is_resolved`;
//! evaluated *before* selecting rows, so it is always at least as
//! conservative as the row select) guarantees that row's own inserting
//! transaction has already resolved (committed or aborted) — no live
//! transaction can still be holding a lower xid open. Critically, the code
//! below only ever advances the checkpoint across a **contiguous prefix** of
//! candidate rows in `id` order, stopping at the first row that fails the
//! watermark check, rather than filtering row-by-row and skipping past a
//! not-yet-resolved one. Skipping instead of stopping would create exactly
//! the silent-loss hole this mechanism exists to prevent, since the
//! checkpoint (`audit_chain_batch.last_ingest_id`) can never move
//! backwards to pick up a skipped row later.
//!
//! Wraparound: until migrations/0471 this compared `xmin::text::bigint` —
//! the *raw* 32-bit transaction id with no epoch information — against the
//! 64-bit, epoch-extended snapshot xmin, so after the first xid wraparound
//! every row compared as resolved and a late-committing row could be walked
//! past. `audit_ingest.xact_id` now records the inserting transaction's
//! 64-bit id, so both sides carry the epoch (audit 10/10 plan Phase 1.5).
//! This remains D-024's "cheaper interim," not its target architecture —
//! logical replication (CDC) removes the race structurally and is the
//! documented follow-up once P1.8d's load numbers justify the extra
//! infrastructure.
//!
//! **Validation status (D-028/D-029, 2026-07-09):** this query and the whole
//! drain/batch/verify pipeline have been run against a live PostgreSQL 18
//! instance and behave correctly for sequential/low-concurrency writes,
//! including a deliberately tampered row being caught by verification. What
//! has **not** been tested: the specific out-of-order-commit race this
//! prefix-stop logic exists to handle (two genuinely concurrent transactions
//! on separate connections, racing so a higher-`id` row commits before a
//! lower-`id` one) has never actually been reproduced and observed being
//! handled correctly — only reasoned about. Two `audit_chainer` processes
//! have never been run against the same database simultaneously to confirm
//! the advisory lock actually prevents double-processing. Killing the
//! chainer mid-batch and confirming clean restart (§6 of the plan doc) has
//! not been done either. Treat those three as open, not implied-covered by
//! the validation that *has* happened.

use attome_db::DbPool;
use attome_storage::StorageClient;
use attome_types::AppError;
use chrono::{Datelike, NaiveDate, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Postgres;
use uuid::Uuid;

use attome_core::AuditSigner;

use crate::anchor;
use crate::service::{AuditService, IngestEnvelope};

/// Summary of one committed batch, for the bin entrypoint to log.
#[derive(Debug)]
pub struct ChainBatchSummary {
    pub organization_ref: Uuid,
    pub batch_id: Uuid,
    pub event_count: usize,
    pub first_ingest_id: Uuid,
    pub last_ingest_id: Uuid,
}

/// Drains at most one batch (up to `batch_size` events) per distinct
/// organization currently holding `audit_ingest` rows. An organization
/// with nothing pending, or whose only pending rows are still inside an
/// in-flight transaction per the xmin watermark, is simply absent from the
/// returned list — not an error.
///
/// One organization's batch failing (a malformed payload, a transient DB
/// error) does not abort the others: each `run_batch_for_org` call is
/// independent (D-002 partitions the chain per org, so there is no shared
/// state to corrupt across them), and letting one bad org block every other
/// org's draining would be strictly worse than just retrying that one org
/// next poll. The failure is logged and the poll continues; found by
/// actually running this against a live Postgres (a malformed ingest row
/// from unrelated test data starved every other org's batch until this was
/// fixed).
pub async fn run_once(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    batch_size: i64,
    storage: Option<&StorageClient>,
) -> Result<Vec<ChainBatchSummary>, AppError> {
    let orgs = pending_organizations(db).await?;
    let mut summaries = Vec::with_capacity(orgs.len());

    for org in orgs {
        match run_batch_for_org(db, signer, org, batch_size, storage).await {
            Ok(Some(summary)) => summaries.push(summary),
            Ok(None) => {}
            Err(e) => tracing::error!(
                organization_ref = %org,
                error = %e,
                "audit chainer: batch failed for this organization, continuing with others",
            ),
        }
    }

    Ok(summaries)
}

/// D-002 single-tenant means this is realistically one row, but the sync
/// path (P1.5) already partitions the chain per `organization_ref`, so the
/// chainer mirrors that instead of assuming a single global org. `pub` (not
/// `pub(crate)`) since the `audit_chainer` bin also uses it to know which
/// organizations to lag-check each poll — see `crate::verify::lag`.
pub async fn pending_organizations(db: &DbPool) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT DISTINCT organization_ref FROM audit_ingest ORDER BY organization_ref",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// P-health-readiness — the same max-lag/sum-pending aggregation
/// `attome-server`'s `spawn_chainer_lag_refresh` gauge-refresh loop already
/// computes, lifted here so the Prometheus gauge and the new
/// `/health/dependencies` diagnostic endpoint can never silently diverge in
/// how "lag" is defined. D-002 single-tenant: worst (max) lag across
/// organizations is what "is the chainer behind" actually cares about, not
/// a per-org breakdown.
pub struct ChainerAggregate {
    pub organizations_pending: usize,
    pub total_pending_ingest: i64,
    pub max_lag_seconds: i64,
}

impl std::fmt::Debug for ChainerAggregate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainerAggregate").finish_non_exhaustive()
    }
}

pub async fn aggregate_lag(db: &DbPool) -> Result<ChainerAggregate, AppError> {
    let orgs = pending_organizations(db).await?;
    let mut total_pending_ingest = 0i64;
    let mut max_lag_seconds = 0i64;
    for org in &orgs {
        let (pending, lag_seconds) = crate::verify::lag(db, *org).await?;
        total_pending_ingest += pending;
        max_lag_seconds = max_lag_seconds.max(lag_seconds.unwrap_or(0));
    }
    Ok(ChainerAggregate {
        organizations_pending: orgs.len(),
        total_pending_ingest,
        max_lag_seconds,
    })
}

async fn run_batch_for_org(
    db: &DbPool,
    signer: Option<&AuditSigner>,
    org: Uuid,
    batch_size: i64,
    storage: Option<&StorageClient>,
) -> Result<Option<ChainBatchSummary>, AppError> {
    let mut tx = attome_db::tx::begin(db).await?;

    // Non-blocking, same primitive as the sync path's append lock (guidelines
    // §2) — a different namespace ("chain:" not "append:") so this never
    // contends with the still-live synchronous writers during the overlap
    // window (D-024). If another chainer instance is already mid-batch for
    // this org, skip this poll cycle for it rather than waiting.
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-audit/chain:{org}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(None);
    }

    let checkpoint = last_batch(&mut tx, org).await?;
    let last_ingest_id = checkpoint
        .as_ref()
        .map(|b| b.last_ingest_id)
        .unwrap_or(Uuid::nil());
    let prev_batch_hash = checkpoint
        .as_ref()
        .map(|b| b.merkle_root.clone())
        .unwrap_or_default();
    let mut prev_hash = AuditService::fetch_last_hash(&mut tx, org).await?;

    // Both sides are 64-bit, epoch-extended transaction ids (migrations/0471)
    // — see the module doc and `is_resolved`.
    let watermark: i64 =
        sqlx::query_scalar("SELECT pg_snapshot_xmin(pg_current_snapshot())::text::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;

    let candidates: Vec<(Uuid, Value, Option<i64>)> = sqlx::query_as(
        "SELECT id, payload, xact_id::text::bigint AS xact
         FROM audit_ingest
         WHERE organization_ref = $1 AND id > $2
         ORDER BY id
         LIMIT $3",
    )
    .bind(org)
    .bind(last_ingest_id)
    .bind(batch_size)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    // Contiguous prefix only (see module doc) — stop at the first row whose
    // inserting transaction isn't yet guaranteed resolved, never skip it.
    let prefix: Vec<(Uuid, Value)> = candidates
        .into_iter()
        .take_while(|(_, _, xact)| is_resolved(*xact, watermark))
        .map(|(id, payload, _)| (id, payload))
        .collect();

    if prefix.is_empty() {
        return Ok(None);
    }

    // P-audit-chain-hardening item (c), D-280 — epoch-boundary detection.
    // If the checkpoint batch belongs to an earlier calendar month than the
    // batch this run is about to write, it was — only knowable now, in
    // hindsight — the last batch of its epoch (there is no way to predict
    // in advance whether an org will ever produce another batch in a later
    // month). Never an UPDATE to that existing row (migration 0072 revokes
    // UPDATE on this table from the runtime role, and D-280's own design
    // puts the epoch boundary in the anchor record, not an in-database
    // flag) — `sealed_epoch` is carried forward and anchored, after commit,
    // to a well-known epoch-keyed path (`anchor::anchor_epoch_seal`),
    // alongside but distinct from that batch's own per-batch anchor (which
    // it already received when IT was written, one run_batch_for_org call
    // ago).
    let this_batch_epoch = current_epoch_period();
    let sealed_epoch = checkpoint.as_ref().and_then(|last| {
        (last.epoch_period < this_batch_epoch)
            .then(|| (last.id, last.epoch_period, last.merkle_root.clone()))
    });

    let batch_id = Uuid::now_v7();
    let first_ingest_id = prefix[0].0;
    let mut last_ingest_id = first_ingest_id;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(prefix.len());
    let mut v2_digests: Vec<(Uuid, String)> = Vec::new();

    for (ingest_id, payload) in &prefix {
        let envelope: IngestEnvelope =
            serde_json::from_value(payload.clone()).map_err(AppError::internal)?;

        let (header_id, event_hash, content_digest) =
            AuditService::append_in_batch(&mut tx, &envelope, &prev_hash, batch_id).await?;
        if let Some(digest) = content_digest {
            v2_digests.push((header_id, digest));
        }

        leaves.push(hex_decode_32(&event_hash)?);
        prev_hash = event_hash;
        last_ingest_id = *ingest_id;
    }

    // D-539 ruling 4: the digest each v2 event carried from its mutation's
    // transaction must reproduce from the rows this batch just wrote, or the
    // whole batch rolls back (and is retried, and fails loudly, next poll).
    AuditService::check_stored_digests(&mut tx, &v2_digests).await?;

    let event_count = prefix.len();
    let root = merkle_root(&leaves);
    let (signature, signing_key_id) = AuditService::sign_batch(signer, &prev_batch_hash, &root);

    sqlx::query(
        "INSERT INTO audit_chain_batch
             (id, organization_ref, first_ingest_id, last_ingest_id, event_count,
              prev_batch_hash, merkle_root, signing_key_id, signature, epoch_period)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(batch_id)
    .bind(org)
    .bind(first_ingest_id)
    .bind(last_ingest_id)
    .bind(event_count as i32)
    .bind(&prev_batch_hash)
    .bind(&root)
    .bind(signing_key_id.as_deref())
    .bind(signature.as_deref())
    .bind(this_batch_epoch)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;

    tracing::info!(
        organization_ref = %org,
        batch_id         = %batch_id,
        event_count,
        "audit chain batch written",
    );
    // P-observability-bcdr Track A — throughput counter; the complementary
    // "how far behind" gauge is pull-style, refreshed by attome-server's
    // spawn_chainer_lag_refresh via verify::lag, not pushed from here.
    metrics::counter!("audit_chain_batch_events_total").increment(event_count as u64);

    // P-audit-chain-hardening item (b) — external anchoring, deliberately
    // AFTER the commit above and deliberately best-effort: an anchoring
    // failure must never roll back or block a batch the chain itself
    // already considers durable (D-027 degrade-not-fail). `storage` is
    // `None` whenever `audit.external_anchoring_enabled` is false (the
    // default) — see the `audit_chainer` bin's call site — so a deployment
    // that hasn't opted in pays nothing extra here.
    if let Some(store) = storage {
        if let Err(e) = anchor::anchor_root(store, org, batch_id, &root).await {
            tracing::error!(
                organization_ref = %org,
                batch_id = %batch_id,
                error = %e,
                "audit chain external anchoring failed — this batch's Merkle root is still \
                 durably chained in audit_chain_batch, but is NOT yet independently \
                 verifiable outside this deployment until a future anchoring attempt succeeds",
            );
            metrics::counter!("audit_chain_anchor_failures_total").increment(1);
        }

        // P-audit-chain-hardening item (c), D-280 — seal the epoch this
        // batch's checkpoint just closed, if any (see the detection above).
        // Best-effort/degrade-not-fail, same posture as the per-batch
        // anchor immediately above: an epoch seal that fails here is caught
        // later by an operator running the anchor cross-check
        // (`verify::verify_anchors` doesn't look at epoch seals today, but
        // the same `--reanchor`-style recovery shape applies) — it must
        // never roll back or block a batch this org's chain already
        // considers durable.
        if let Some((sealed_batch_id, sealed_epoch, sealed_merkle_root)) = &sealed_epoch
            && let Err(e) = anchor::anchor_epoch_seal(
                store,
                org,
                *sealed_epoch,
                this_batch_epoch,
                *sealed_batch_id,
                sealed_merkle_root,
            )
            .await
        {
            tracing::error!(
                organization_ref = %org,
                epoch_period = %sealed_epoch,
                sealed_batch_id = %sealed_batch_id,
                error = %e,
                "audit chain epoch-seal anchoring failed — this epoch is not yet safe to \
                 assume droppable (P-db-maintenance item (c)) until a future sealing \
                 attempt succeeds",
            );
            metrics::counter!("audit_chain_epoch_seal_anchor_failures_total").increment(1);
        }
    }

    Ok(Some(ChainBatchSummary {
        organization_ref: org,
        batch_id,
        event_count,
        first_ingest_id,
        last_ingest_id,
    }))
}

/// Most batches one `prune_ingest` run considers per organization. Bounds the
/// anchor reads outside the transaction and the ranges deleted inside it; a
/// backlog drains over successive runs.
const PRUNE_MAX_BATCHES_PER_RUN: i64 = 500;

#[derive(sqlx::FromRow)]
struct PruneCandidate {
    id: Uuid,
    first_ingest_id: Uuid,
    last_ingest_id: Uuid,
    event_count: i32,
    merkle_root: String,
    signature: Option<String>,
}

/// P1.13 step 6, rewritten for audit 10/10 plan item 2.8 — deletes
/// `audit_ingest` rows that are provably redundant, **without breaking
/// verification**, and returns how many were deleted across every
/// organization. `retention_days = 0` disables pruning entirely (returns
/// `Ok(0)` without issuing a query) — an explicit opt-in, not a default-on
/// delete of audit data.
///
/// A batch's ingest range is pruned only when, walking the organization's
/// batches in id order from the current watermark and stopping at the first
/// batch that fails any rule:
///
/// 1. the batch is **sealed**: it carries its signature (an unsigned batch is
///    never pruned, so a deployment without audit signing never prunes);
/// 2. the batch is **anchored**: `store` holds its anchor object and the
///    anchored root equals the stored `merkle_root` (no `store` — anchoring
///    disabled — means nothing is pruned);
/// 3. every ingest row in its range is older than `retention_days`;
/// 4. its range holds **no more** rows than `event_count`. More rows means an
///    unchained row sits inside a claimed range (the out-of-order-commit race
///    the chainer's prefix rule guards against), which is evidence and is kept.
///    Fewer rows is accepted: rows can only be missing because something
///    already deleted them (a pre-2.8 age-based prune), and the rule above is
///    what makes that safe to adopt.
///
/// The prefix is deleted range by range — never rows between ranges, so an
/// orphaned row stays visible to the gap check — and the new watermark (the
/// last pruned batch and its `last_ingest_id`) is appended to
/// `audit_ingest_prune` in the same transaction. Verification
/// (`verify::verify_ingest_ranges`) stops counting ingest rows at that
/// watermark and checks the watermark against the anchored batches instead.
///
/// Concurrency: anchors are read before the transaction (no external I/O
/// inside it; batches are append-only, so what was read stays true). The
/// transaction takes `attome-audit/prune:{org}` with `pg_try_advisory_xact_lock`
/// and re-reads the watermark; a concurrent run makes this one skip the
/// organization, and a retry after a crash re-derives everything, so the
/// operation is retry-safe with no idempotency key. It never races the chainer
/// in a way that matters: a batch commit only extends the drained range.
pub async fn prune_ingest(
    db: &DbPool,
    store: Option<&StorageClient>,
    retention_days: u32,
) -> Result<u64, AppError> {
    if retention_days == 0 {
        return Ok(0);
    }
    let Some(store) = store else {
        tracing::debug!(
            "audit ingest prune skipped: no anchor store (audit.external_anchoring_enabled is \
             false), and only signed, anchored batches are pruned (audit plan item 2.8)"
        );
        return Ok(0);
    };

    let orgs: Vec<Uuid> = sqlx::query_scalar(
        "SELECT DISTINCT organization_ref FROM audit_chain_batch ORDER BY organization_ref",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    let mut deleted = 0u64;
    for org in orgs {
        match prune_ingest_for_org(db, store, org, retention_days).await {
            Ok(n) => deleted += n,
            Err(e) => tracing::error!(
                organization_ref = %org,
                error = %e,
                "audit ingest prune failed for this organization, continuing with others",
            ),
        }
    }
    Ok(deleted)
}

async fn pruned_watermark<'e, E>(executor: E, org: Uuid) -> Result<Uuid, AppError>
where
    E: sqlx::Executor<'e, Database = Postgres>,
{
    let watermark: Option<Uuid> = sqlx::query_scalar(
        "SELECT through_ingest_id FROM audit_ingest_prune
         WHERE organization_ref = $1
         ORDER BY through_ingest_id DESC
         LIMIT 1",
    )
    .bind(org)
    .fetch_optional(executor)
    .await
    .map_err(AppError::internal)?;
    Ok(watermark.unwrap_or(Uuid::nil()))
}

async fn prune_ingest_for_org(
    db: &DbPool,
    store: &StorageClient,
    org: Uuid,
    retention_days: u32,
) -> Result<u64, AppError> {
    let watermark = pruned_watermark(db, org).await?;
    let candidates: Vec<PruneCandidate> = sqlx::query_as(
        "SELECT id, first_ingest_id, last_ingest_id, event_count, merkle_root, signature
         FROM audit_chain_batch
         WHERE organization_ref = $1 AND last_ingest_id > $2
         ORDER BY id
         LIMIT $3",
    )
    .bind(org)
    .bind(watermark)
    .bind(PRUNE_MAX_BATCHES_PER_RUN)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;

    // Rules 1 and 2, outside the transaction.
    let mut sealed_and_anchored: Vec<&PruneCandidate> = Vec::new();
    for batch in &candidates {
        if batch.signature.is_none() {
            break;
        }
        match anchor::fetch_anchored_root(store, org, batch.id).await? {
            Some(root) if root == batch.merkle_root => sealed_and_anchored.push(batch),
            Some(root) => {
                tracing::error!(
                    organization_ref = %org,
                    batch_id = %batch.id,
                    anchored_root = %root,
                    merkle_root = %batch.merkle_root,
                    "audit ingest prune: anchored root disagrees with the batch — not pruning",
                );
                break;
            }
            None => break,
        }
    }
    if sealed_and_anchored.is_empty() {
        return Ok(0);
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-audit/prune:{org}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked || pruned_watermark(&mut *tx, org).await? != watermark {
        return Ok(0);
    }

    // Rules 3 and 4, inside the transaction.
    let mut firsts: Vec<Uuid> = Vec::new();
    let mut lasts: Vec<Uuid> = Vec::new();
    let mut through: Option<&PruneCandidate> = None;
    for batch in sealed_and_anchored {
        let (rows, aged): (i64, bool) = sqlx::query_as(
            "SELECT COUNT(*),
                    COALESCE(bool_and(created_at < NOW() - make_interval(days => $4)), true)
             FROM audit_ingest
             WHERE organization_ref = $1 AND id >= $2 AND id <= $3",
        )
        .bind(org)
        .bind(batch.first_ingest_id)
        .bind(batch.last_ingest_id)
        .bind(retention_days as i32)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if !aged {
            break;
        }
        if rows > i64::from(batch.event_count) {
            tracing::error!(
                organization_ref = %org,
                batch_id = %batch.id,
                rows,
                event_count = batch.event_count,
                "audit ingest prune: the batch's ingest range holds rows it did not chain — \
                 keeping them as evidence and not pruning past this batch",
            );
            break;
        }
        firsts.push(batch.first_ingest_id);
        lasts.push(batch.last_ingest_id);
        through = Some(batch);
    }
    let Some(through) = through else {
        return Ok(0);
    };

    let deleted = sqlx::query(
        "DELETE FROM audit_ingest ing
         USING unnest($2::uuid[], $3::uuid[]) AS r(first_id, last_id)
         WHERE ing.organization_ref = $1
           AND ing.id >= r.first_id AND ing.id <= r.last_id",
    )
    .bind(org)
    .bind(&firsts)
    .bind(&lasts)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();

    sqlx::query(
        "INSERT INTO audit_ingest_prune
             (organization_ref, through_batch_id, through_ingest_id, rows_deleted)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(org)
    .bind(through.id)
    .bind(through.last_ingest_id)
    .bind(i64::try_from(deleted).unwrap_or(i64::MAX))
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;
    tracing::info!(
        organization_ref = %org,
        through_batch_id = %through.id,
        batches = lasts.len(),
        deleted,
        "audit ingest pruned through a signed, anchored batch",
    );
    Ok(deleted)
}

/// The most recent batch for `org`, if one exists yet. `epoch_period` is
/// what lets `run_batch_for_org` detect an epoch boundary crossing
/// (P-audit-chain-hardening item (c), D-280) purely by comparing this
/// checkpoint's month against the new batch's month — no separate query.
#[derive(sqlx::FromRow)]
struct LastBatch {
    merkle_root: String,
    last_ingest_id: Uuid,
    id: Uuid,
    epoch_period: NaiveDate,
}

async fn last_batch(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    org: Uuid,
) -> Result<Option<LastBatch>, AppError> {
    let row: Option<LastBatch> = sqlx::query_as(
        "SELECT merkle_root, last_ingest_id, id, epoch_period
         FROM audit_chain_batch
         WHERE organization_ref = $1
         ORDER BY id DESC
         LIMIT 1",
    )
    .bind(org)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    Ok(row)
}

/// The calendar-month epoch a batch produced "now" belongs to (D-280: the
/// epoch period is the first day of the month).
#[expect(
    clippy::expect_used,
    reason = "the current year and month always form a valid date"
)]
fn current_epoch_period() -> NaiveDate {
    let now = Utc::now();
    NaiveDate::from_ymd_opt(now.year(), now.month(), 1)
        .expect("Utc::now()'s own year/month is always a valid calendar date")
}

/// Standard binary Merkle tree over SHA-256 leaves (duplicate the last node
/// when a level has an odd count — the common Bitcoin-style construction).
/// A signed root proves membership of every leaf in this specific batch.
/// `pub(crate)` so `crate::verify` (P1.13 stage 3) recomputes it the same way.
pub(crate) fn merkle_root(leaves: &[[u8; 32]]) -> String {
    debug_assert!(!leaves.is_empty());

    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update(pair[0]);
            h.update(pair.get(1).unwrap_or(&pair[0]));
            next.push(h.finalize().into());
        }
        level = next;
    }

    hex_encode_32(&level[0])
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// Decodes a 64-hex-char SHA-256 digest (as produced by `compute_hash`) back
/// into raw bytes for Merkle-tree hashing. `pub(crate)` for `crate::verify`.
pub(crate) fn hex_decode_32(s: &str) -> Result<[u8; 32], AppError> {
    if s.len() != 64 {
        return Err(AppError::internal(
            "audit chain event_hash is not a 64-char hex SHA-256 digest",
        ));
    }
    let mut out = [0u8; 32];
    for (i, chunk) in out.iter_mut().enumerate() {
        *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(AppError::internal)?;
    }
    Ok(out)
}

/// Whether an ingest row's inserting transaction is guaranteed resolved
/// (committed or aborted), given `watermark` =
/// `pg_snapshot_xmin(pg_current_snapshot())`. Both values are 64-bit,
/// epoch-extended transaction ids, so the comparison stays correct across
/// xid wraparound; the pre-0471 `xmin::text::bigint` was the raw 32-bit xid.
/// The cast to `bigint` only overflows past 2^31 xid epochs.
///
/// `None` is a row written before migrations/0471 added `xact_id`. It is
/// resolved by construction: that migration's `ADD COLUMN` took ACCESS
/// EXCLUSIVE, which waited for every transaction still inserting into the
/// table to finish.
fn is_resolved(xact: Option<i64>, watermark: i64) -> bool {
    xact.is_none_or(|x| x < watermark)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legacy_row_without_a_transaction_id_is_resolved() {
        assert!(is_resolved(None, 0));
        assert!(is_resolved(None, i64::MAX));
    }

    #[test]
    fn only_a_transaction_below_the_watermark_is_resolved() {
        assert!(is_resolved(Some(99), 100));
        assert!(!is_resolved(Some(100), 100));
        assert!(!is_resolved(Some(101), 100));
    }

    /// Audit 10/10 plan Phase 1.5: one xid wraparound later, a transaction
    /// that is still in flight must not compare as resolved.
    #[test]
    fn the_comparison_survives_an_xid_epoch_boundary() {
        const EPOCH: i64 = 1 << 32;
        let watermark = EPOCH + 5;
        let in_flight = EPOCH + 10;

        assert!(!is_resolved(Some(in_flight), watermark));
        assert!(is_resolved(Some(EPOCH - 1), watermark));

        // The defect this replaces: the raw 32-bit xmin of that same in-flight
        // transaction (10) compared against the epoch-extended watermark.
        let raw_32_bit_xmin = in_flight & 0xFFFF_FFFF;
        assert!(
            raw_32_bit_xmin < watermark,
            "the pre-0471 comparison would have treated an in-flight row as resolved"
        );
    }

    /// D-280: epoch_period is always the first of a calendar month, never
    /// today's actual date — this is what makes two batches produced on
    /// different days of the same month compare as the same epoch.
    #[test]
    fn current_epoch_period_is_the_first_of_the_current_month() {
        let period = current_epoch_period();
        assert_eq!(period.day(), 1);
        let now = Utc::now();
        assert_eq!(period.year(), now.year());
        assert_eq!(period.month(), now.month());
    }
}
