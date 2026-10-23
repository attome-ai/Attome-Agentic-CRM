//! P-retention-archive-completion §3b/§3c/§3e — the propose sweep and the
//! execute step for an already-approved `audit_retention_action` row. Called
//! from `crates/server/src/jobs.rs`'s `EngineJob::ProposeRetentionActions`/
//! `EngineJob::ExecuteRetentionAction` handlers — the admin surface
//! (`retention_admin.rs`) only ever reads/approves/rejects rows, it never
//! runs the actual work inline (guidelines §10).
//!
//! Partition archive/drop (§3b.3): detach -> masked export to object store
//! -> verify row count + checksum -> drop. Entity purge (§3c):
//! `attome_audit::destroy_key` (D-107) then `attome_metadata::purge::scrub_record` —
//! never a hard `DELETE`.
//!
//! **Memory-scaling fix (P-retention-archive-completion follow-up,
//! 2026-07-31)**: the partition-archive export used to buffer the entire
//! exported partition into one `Vec<String>`/`Bytes` before a single `PUT`,
//! and re-verification downloaded the whole object into one buffer again.
//! Both are now streamed — see `stream_masked_export_to_store` and
//! `verify_uploaded_checksum` below — so peak memory no longer scales with
//! partition size. The pure streaming/hashing/abort-on-failure logic is
//! covered by this module's own unit tests (`object_store::memory::InMemory`,
//! no live infra needed). What is **not** verified, because this environment
//! has no Rust toolchain, no live Postgres, and no live object store to run
//! against:
//!
//! - TODO(needs live Postgres + object store to actually run): an end-to-end
//!   integration test of `execute_partition_archive` itself against a real
//!   partitioned table now exists —
//!   `crates/engine/attome-api/tests/retention.rs`'s
//!   `execute_partition_archive_streams_verifies_and_drops_a_real_partition`
//!   (unmasked path, `s2s_access_log`) and
//!   `execute_partition_archive_masks_is_sensitive_columns_in_the_live_archived_object`
//!   (masked path, `audit_detail`) — but neither has ever been run
//!   in this sandbox (no Rust toolchain, no live Postgres, no live object
//!   store), so "code exists" is not "proven to pass."
//! - TODO(needs live infra): an actual multi-GB partition run to confirm
//!   real-world bounded memory (the unit tests below prove the code path
//!   never materializes an all-rows buffer, but not real RSS behavior under
//!   load).
//! - TODO(needs live infra): a failure-during-upload/retry test against the
//!   real `execute_action` job path (a store double proves `abort()` is
//!   called in isolation below; the full retry-after-crash round trip through
//!   `EngineJob::ExecuteRetentionAction` is untested).
//! - TODO(needs live Postgres): confirming `sqlx::query_scalar(&sql).fetch(db)`
//!   actually streams from the wire rather than buffering server-side in the
//!   driver — believed correct per sqlx's design, unverified here.
//!
//! **Out of scope for this change**: the deferred retention admin UI
//! (Angular) — unrelated surface, tracked separately.

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::{EngineState, partition_maintenance, quote_ident};
use attome_db::DbPool;
use attome_types::AppError;
use chrono::Utc;
use futures_util::TryStreamExt;
use object_store::{ObjectStore, ObjectStoreExt, buffered::BufWriter, path::Path as ObjectPath};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// The four tables `migrations/0026_audit_partitioning.sql` partitions.
/// Duplicated from `crates/server/src/jobs.rs`'s own `PARTITIONED_TABLES`
/// rather than shared — attome-api cannot depend on crates/server
/// (guidelines §1), the same layering reason
/// `attome_core::partition_maintenance`'s `valid_identifier` duplicates
/// `attome_metadata::provision::valid_identifier` instead of importing it.
const PARTITIONED_TABLES: &[&str] = &[
    "audit_header",
    "audit_detail",
    "audit_snapshot",
    "s2s_access_log",
];

fn parent_table_for_partition(partition_name: &str) -> Option<&'static str> {
    PARTITIONED_TABLES
        .iter()
        .copied()
        .find(|t| partition_name.starts_with(&format!("{t}_")))
}

// ── Propose ──────────────────────────────────────────────────────────────

/// P-retention-archive-completion §3b/§3c step 1 — the daily proposal sweep,
/// called by `EngineJob::ProposeRetentionActions`'s job handler (and the
/// admin `POST .../retention/propose` on-demand trigger). Re-reads current
/// config on every run rather than trusting an enqueue-time snapshot (same
/// convention as `EnsureAuditPartitions`), so a retention-window change
/// takes effect on the very next run with no re-enqueue needed. A `None`
/// window (today's default) skips that table's/entity purge's sweep
/// entirely — "keep forever" means exactly that, not "propose with an
/// arbitrary fallback". Returns how many `audit_retention_action` rows were
/// newly proposed across every table/entity.
pub async fn propose_retention_actions(state: &EngineState) -> Result<u32, AppError> {
    let db = &state.base.db;
    let retention = &state.base.config.retention;
    let mut proposed = 0u32;

    if let Some(days) = retention.audit_days {
        for table in ["audit_header", "audit_detail", "audit_snapshot"] {
            proposed +=
                partition_maintenance::propose_partition_archive_actions(db, table, days).await?;
        }
    }
    if let Some(days) = retention.s2s_access_log_days {
        proposed +=
            partition_maintenance::propose_partition_archive_actions(db, "s2s_access_log", days)
                .await?;
    }
    // A18-T5: an entity's own bin retention wins over the deployment's.
    proposed += attome_metadata::purge::propose_purge_actions_by_entity(
        db,
        retention.entity_purge_grace_days,
        &retention.disposition_action,
    )
    .await?;
    // R3-T1: live records past their retention rule's period.
    proposed += crate::retention_rules::propose_rule_actions(state).await?;

    Ok(proposed)
}

/// M35 (AI Memory, D-451) — the memory retention sweep. Called from
/// `crates/server/src/jobs.rs`'s `EngineJob::PruneExpiredMemories`
/// handler, on its own scheduler (`spawn_memory_retention_scheduler`), NOT
/// folded into `propose_retention_actions`/`execute_action` above — see
/// `attome_core::jobs::EngineJob::PruneExpiredMemories`'s doc comment for why that
/// ledger's per-target dedup index is structurally the wrong shape for a
/// recurring, age-based bulk sweep with no single fixed target.
///
/// Re-reads `ai.memory_retention_days` on every run rather than trusting an
/// enqueue-time snapshot (same convention as `propose_retention_actions`
/// itself), so a change to the setting takes effect on the very next tick.
/// The setting always has an effective value (a `Deployment`-scope default of
/// 365 days, `attome_core::setting_catalog::ai_settings`), so unlike the
/// `Option<u32>` `retention.*_days` config fields above, this sweep never
/// skips — "keep memory forever" requires setting a very large window
/// explicitly, not leaving this one unset.
#[expect(
    clippy::expect_used,
    reason = "each expect() here guards an invariant its message states"
)]
pub async fn prune_expired_memories(state: &EngineState) -> Result<u64, AppError> {
    let descriptor = attome_core::setting_descriptor::registry()
        .get("ai.memory_retention_days")
        .expect("ai.memory_retention_days must be registered in the setting catalogue");
    let (value, _source) = state.settings.load().resolve(descriptor, None, None);
    let retention_days = value.as_i64().unwrap_or(365);

    attome_search::purge_expired(&state.base.db, retention_days).await
}

// ── Execute ──────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct ActionRow {
    action_type: String,
    target: String,
    status: String,
    approved_by: Option<Uuid>,
}

/// Executes `action_id` — the single entry point
/// `EngineJob::ExecuteRetentionAction`'s job handler calls. Idempotent
/// against a re-delivered job: re-reads the row's current `status` rather
/// than trusting the enqueue-time snapshot (same convention as
/// `EnsureAuditPartitions`/`BuildAttributeIndex`), so a retry after a crash
/// mid-execution safely no-ops if a previous attempt already reached
/// `completed`/`failed`/`rejected`.
///
/// Refuses (returns `Err`, which apalis treats as a normal bounded-retry job
/// failure — recoverable via `jobs_admin`'s dead-letter replay once the
/// blocker clears) if `retention.legal_hold`/`retention.dry_run` changed
/// between approval and execution — the approve endpoint already checks
/// both, but config can change in between (§3a/§3e).
pub async fn execute_action(state: &EngineState, action_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;

    let action: Option<ActionRow> = sqlx::query_as(
        "SELECT action_type, target, status, approved_by FROM audit_retention_action \
          WHERE id = $1 AND is_deleted = false",
    )
    .bind(action_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let Some(action) = action else {
        tracing::warn!(action_id = %action_id, "retention execute: action row not found, nothing to do");
        return Ok(());
    };

    if action.status != "approved" {
        tracing::info!(
            action_id = %action_id,
            status = %action.status,
            "retention execute: action is not in 'approved' state, skipping (already executed/rejected, or a re-delivered job)"
        );
        return Ok(());
    }

    if state.base.config.retention.legal_hold {
        return Err(AppError::internal(
            "retention.legal_hold is set — refusing to execute an already-approved retention action",
        ));
    }
    if state.base.config.retention.dry_run {
        return Err(AppError::internal(
            "retention.dry_run is true — refusing to execute an already-approved retention action",
        ));
    }

    mark_executing(db, action_id).await?;

    let result = match action.action_type.as_str() {
        "partition_archive" => execute_partition_archive(state, &action.target).await,
        "entity_purge" => execute_entity_purge(state, &action.target, action.approved_by).await,
        "archive" => {
            crate::archive::execute_entity_archive(
                state,
                &action.target,
                action_id,
                action.approved_by,
            )
            .await
        }
        // R3-T1: a reviewed record is kept; a purge or archive first deletes
        // the live record as the approver, then runs the bin disposition.
        "rule_review" => Ok(Some("reviewed: kept".to_owned())),
        "rule_purge" => match crate::retention_rules::delete_for_disposition(
            state,
            &action.target,
            action_id,
            action.approved_by,
        )
        .await
        {
            Ok(()) => execute_entity_purge(state, &action.target, action.approved_by).await,
            Err(e) => Err(e),
        },
        "rule_archive" => match crate::retention_rules::delete_for_disposition(
            state,
            &action.target,
            action_id,
            action.approved_by,
        )
        .await
        {
            Ok(()) => {
                crate::archive::execute_entity_archive(
                    state,
                    &action.target,
                    action_id,
                    action.approved_by,
                )
                .await
            }
            Err(e) => Err(e),
        },
        other => Err(AppError::internal(format!(
            "retention execute: unknown action_type {other:?} for action {action_id}"
        ))),
    };

    match result {
        Ok(evidence_ref) => {
            mark_completed(db, action_id, evidence_ref.as_deref()).await?;
            Ok(())
        }
        Err(e) => {
            mark_failed(db, action_id, &e.to_string()).await?;
            Err(e)
        }
    }
}

async fn mark_executing(db: &DbPool, action_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE audit_retention_action \
            SET status = 'executing', updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(action_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn mark_completed(
    db: &DbPool,
    action_id: Uuid,
    evidence_ref: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE audit_retention_action \
            SET status = 'completed', executed_at = NOW(), evidence_ref = $2, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(action_id)
    .bind(evidence_ref)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn mark_failed(db: &DbPool, action_id: Uuid, reason: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE audit_retention_action \
            SET status = 'failed', failure_reason = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(action_id)
    .bind(reason)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

// ── Partition archive/drop ──────────────────────────────────────────────

/// `partition_name` is just a table-name string — despite the parameter
/// name (kept for the partition-archive call site below), this works for
/// any table, which is exactly why `dsr_admin.rs` reuses it unchanged for
/// entity tables (P-data-protection-governance §4).
pub async fn export_columns(db: &DbPool, partition_name: &str) -> Result<Vec<String>, AppError> {
    let cols: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
          WHERE table_schema = current_schema() AND table_name = $1 \
          ORDER BY ordinal_position",
    )
    .bind(partition_name)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if cols.is_empty() {
        return Err(AppError::internal(format!(
            "retention execute: no columns found for detached partition {partition_name}"
        )));
    }
    Ok(cols)
}

/// The exact masking expression `scripts/observability/export-audit-ledger.sh`
/// applies to `audit_detail`'s value columns (its own lines 108-116) —
/// copied verbatim so the two implementations can't silently drift (plan
/// §4/§5 step 4's shared-template requirement). Applied only when the
/// exported partition actually carries both `is_sensitive` and the given
/// column — i.e. only `audit_detail`'s shape; every other partitioned
/// table's columns pass through unmasked, matching the shell script's own
/// scope (it never exports `audit_snapshot` at all today).
pub const MASKED_DETAIL_COLUMNS: &[&str] = &[
    "old_value",
    "new_value",
    "old_display_value",
    "new_display_value",
    "old_lookup_name",
    "new_lookup_name",
];

pub fn masked_select_expr(columns: &[String]) -> String {
    let has_is_sensitive = columns.iter().any(|c| c == "is_sensitive");
    columns
        .iter()
        .map(|c| {
            let ident = quote_ident(c);
            if has_is_sensitive && MASKED_DETAIL_COLUMNS.contains(&c.as_str()) {
                format!("CASE WHEN is_sensitive THEN '***MASKED***' ELSE {ident} END AS {ident}")
            } else {
                ident
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Streams already-masked NDJSON-line rows into `store` at `path` via
/// `object_store`'s adaptive `BufWriter` — a single `put` under its buffer
/// capacity, transparent multipart above it, so this one call covers both
/// "stream to object storage" and "use multipart where appropriate" without
/// hand-rolling a size threshold. The SHA-256 checksum is computed
/// incrementally alongside each write, never by hashing one fully-buffered
/// blob. Peak memory is one line at a time plus `BufWriter`'s own bounded
/// internal buffer — it does not scale with partition size.
///
/// On any row-stream error or write error, the in-flight multipart upload is
/// aborted (best-effort — the abort error itself is only logged, the
/// original error is what the caller sees) so a failed export never leaves
/// orphaned, billed multipart parts sitting in the bucket. The caller is
/// still responsible for the existing "leave the partition detached, don't
/// drop it" behavior on any `Err` from this function.
///
/// Generic over the row source so it can be unit-tested with a synthetic
/// stream (`object_store::memory::InMemory`, no live Postgres) as well as
/// driven by `sqlx::query_scalar(..).fetch(db)` in production.
pub async fn stream_masked_export_to_store<S>(
    rows: S,
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
) -> Result<(i64, String), AppError>
where
    S: futures_util::Stream<Item = Result<String, sqlx::Error>>,
{
    let mut rows = std::pin::pin!(rows);
    let mut writer = BufWriter::new(store, path);
    let mut hasher = Sha256::new();
    let mut row_count: i64 = 0;

    loop {
        match rows.try_next().await {
            Ok(Some(line)) => {
                let mut chunk = line.into_bytes();
                chunk.push(b'\n');
                hasher.update(&chunk);
                if let Err(e) = writer.put(bytes::Bytes::from(chunk)).await {
                    if let Err(abort_err) = writer.abort().await {
                        tracing::warn!(error = %abort_err, "retention execute: failed to abort in-flight multipart upload after a write error (may leave orphaned parts)");
                    }
                    return Err(AppError::internal(e));
                }
                row_count += 1;
            }
            Ok(None) => break,
            Err(e) => {
                if let Err(abort_err) = writer.abort().await {
                    tracing::warn!(error = %abort_err, "retention execute: failed to abort in-flight multipart upload after a row-stream error (may leave orphaned parts)");
                }
                return Err(AppError::internal(e));
            }
        }
    }

    writer.shutdown().await.map_err(|e| {
        AppError::internal(format!(
            "retention execute: failed to complete multipart upload: {e}"
        ))
    })?;

    Ok((row_count, hex::encode(hasher.finalize())))
}

/// Re-downloads `path` and hashes it incrementally (never collecting the
/// whole object into one buffer) to confirm the bytes that actually landed
/// match `expected_checksum` — catches silent upload truncation/corruption
/// that trusting the store's own PUT response would miss. This re-fetch is a
/// deliberate, real bandwidth cost (an independent check, not a
/// store-reported metadata trust), not something this streaming rewrite
/// eliminates — only the memory footprint of doing it is bounded now.
pub async fn verify_uploaded_checksum(
    store: &dyn ObjectStore,
    path: &ObjectPath,
    expected_checksum: &str,
) -> Result<bool, AppError> {
    let get_result = store.get(path).await.map_err(AppError::internal)?;
    let mut stream = get_result.into_stream();
    let mut hasher = Sha256::new();
    while let Some(chunk) = stream.try_next().await.map_err(AppError::internal)? {
        hasher.update(&chunk);
    }
    Ok(hex::encode(hasher.finalize()) == expected_checksum)
}

/// §3b.3: detach -> export (masked, NDJSON, streamed) -> upload -> verify row
/// count + re-fetched checksum -> drop. Any failure after detach leaves the
/// partition detached-but-undropped for manual inspection (§3b.4/§8 "fail
/// safe, not fail silent") — this function never drops on a failed check.
/// Returns the evidence-report string stored in
/// `audit_retention_action.evidence_ref`.
async fn execute_partition_archive(
    state: &EngineState,
    partition_name: &str,
) -> Result<Option<String>, AppError> {
    let db = &state.base.db;
    let table = parent_table_for_partition(partition_name).ok_or_else(|| {
        AppError::internal(format!(
            "retention execute: {partition_name} does not match any known partitioned table"
        ))
    })?;

    // P-data-protection-governance §4: the four partitioned tables above are
    // infrastructure tables outside the per-attribute classification engine
    // (`attribute_info` only classifies provisioned entity tables),
    // so this uses `SensitiveSpecialCategory` as a deliberate worst-case
    // default rather than a precise per-column classification —
    // `audit_detail`/`snapshot` carry arbitrary field values
    // (`masked_select_expr` below already redacts `is_sensitive` columns,
    // but a "personal"-classified field never flagged `is_sensitive` would
    // still be plaintext here) and `s2s_access_log` carries IP
    // addresses (personal data under GDPR). No admin-override path exists at
    // this call site today — this action is already `system.admin` +
    // four-eyes-approval gated (`retention_admin.rs`), and a genuine
    // cross-region archive need is an architecture conversation, not a
    // per-request override. A no-op when `deployment.data_region` is unset
    // (no residency claim configured — "ships dark", same posture as every
    // other new config surface this session).
    if let Some(deployment_region) = state.base.config.deployment.data_region.as_deref() {
        let decision = attome_core::assert_transfer_allowed(
            attome_core::DataClassification::SensitiveSpecialCategory,
            &state.base.config.storage.s3_region,
            deployment_region,
            false,
        );
        if decision == attome_core::TransferDecision::Blocked {
            return Err(AppError::Conflict(
                "retention execute: archive destination region does not match the deployment's \
                 declared data_region — refusing a cross-border transfer (P-data-protection-governance)",
            ));
        }
    }

    partition_maintenance::detach_partition(db, table, partition_name).await?;

    let source_row_count = partition_maintenance::count_partition_rows(db, partition_name).await?;

    let columns = export_columns(db, partition_name).await?;
    let select_expr = masked_select_expr(&columns);
    let sql = format!(
        "SELECT row_to_json(t)::text FROM (SELECT {select_expr} FROM {partition_ident} ORDER BY id) t",
        partition_ident = quote_ident(partition_name)
    );

    let object_key = format!("retention-archives/{partition_name}.ndjson");
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid archive object key: {e}")))?;

    // No transaction/DB lock is held across this call (guidelines §2/§10) —
    // the partition is already detached (no live query path to it) by this
    // point, so there is nothing for a slow streamed export+upload to block.
    let rows = sqlx::query_scalar::<_, String>(&sql).fetch(db);
    let (exported_row_count, checksum) =
        stream_masked_export_to_store(rows, state.base.storage.store_arc(), path.clone()).await?;

    if exported_row_count != source_row_count {
        return Err(AppError::internal(format!(
            "retention execute: exported {exported_row_count} rows but the detached partition has {source_row_count} — leaving it detached, not dropping"
        )));
    }

    // Re-verify against the object store itself (not just the running hash
    // that produced the upload) before dropping anything — catches a silent
    // upload truncation/corruption, exactly the failure mode §3b.4/§8's
    // "never drop on a failed check" rule exists for.
    if !verify_uploaded_checksum(state.base.storage.store(), &path, &checksum).await? {
        return Err(AppError::internal(format!(
            "retention execute: archive checksum mismatch after upload for {object_key} — leaving partition detached, not dropping"
        )));
    }

    partition_maintenance::drop_detached_partition(db, partition_name).await?;

    tracing::info!(
        partition = %partition_name,
        rows = source_row_count,
        object_key = %object_key,
        checksum = %checksum,
        "retention execute: partition archived and dropped"
    );

    Ok(Some(format!(
        "{object_key} (sha256={checksum}, rows={source_row_count})"
    )))
}

// ── Entity purge ─────────────────────────────────────────────────────────

/// §3c: crypto-shred (`attome_audit::destroy_key`, D-107, unchanged) then
/// field-scrub (`attome_metadata::purge::scrub_record`) — never a hard `DELETE`.
/// `approved_by` (the admin who approved this action) is the actor recorded
/// against both the scrub's `modified_by` and the audit event this writes —
/// there is no interactive `SecurityContext` on a background job, and the
/// approver is the one human decision this action traces back to.
/// Shared by `execute_entity_purge` and `attome_compliance::archive::execute_entity_archive`
/// — both `audit_retention_action` targets use the identical
/// `"{logicalname}:{record_id}"` shape `propose_purge_actions_for_entity`
/// writes (attome-metadata's `purge.rs`), regardless of which disposition
/// (`entity_purge` vs `archive`) the sweep proposed for that record.
pub(crate) fn parse_entity_target(target: &str) -> Result<(&str, Uuid), AppError> {
    let (entity_logicalname, record_id_str) = target.split_once(':').ok_or_else(|| {
        AppError::internal(format!(
            "retention execute: malformed target {target:?}, expected \"logicalname:record_id\""
        ))
    })?;
    let record_id = Uuid::parse_str(record_id_str).map_err(|e| {
        AppError::internal(format!(
            "retention execute: invalid record id in target {target:?}: {e}"
        ))
    })?;
    Ok((entity_logicalname, record_id))
}

async fn execute_entity_purge(
    state: &EngineState,
    target: &str,
    approved_by: Option<Uuid>,
) -> Result<Option<String>, AppError> {
    let (entity_logicalname, record_id) = parse_entity_target(target)?;
    // Defensive default only — every row reaching `execute_action` was set
    // by the approve endpoint, which always records `approved_by`. Not an
    // `unwrap()` (guidelines §6) in case an older/hand-inserted row lacks it.
    let actor = approved_by.unwrap_or(Uuid::nil());
    let (key_destroyed, scrubbed) = purge_record(
        state,
        entity_logicalname,
        record_id,
        actor,
        "retention_purge",
    )
    .await?;
    Ok(Some(format!(
        "key_destroyed={key_destroyed}, scrubbed={scrubbed}"
    )))
}

/// Crypto-shreds and scrubs one record as `actor`, writing `event_name` as
/// its Security/Erasure audit event; whether the key was destroyed and the
/// record scrubbed. K7-T1's approved dispositions purge through it too.
pub(crate) async fn purge_record(
    state: &EngineState,
    entity_logicalname: &str,
    record_id: Uuid,
    actor: Uuid,
    event_name: &str,
) -> Result<(bool, bool), AppError> {
    let registry = state.entities.load();
    let meta = registry.get(entity_logicalname).ok_or_else(|| {
        AppError::internal(format!(
            "retention execute: entity {entity_logicalname} is no longer registered"
        ))
    })?;
    let attrs = meta.attrs.clone();
    drop(registry);

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-compliance/retention-purge:{record_id}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::internal(format!(
            "retention execute: another operation already holds the purge lock for {record_id}"
        )));
    }

    let key_destroyed =
        attome_audit::destroy_key(&mut tx, entity_logicalname, record_id, actor).await?;
    let scrubbed =
        attome_metadata::purge::scrub_record(&mut tx, entity_logicalname, &attrs, record_id, actor)
            .await?;
    // A18-T5: the bin entry is closed as purged, so it is no longer offered
    // for restore.
    sqlx::query(
        "UPDATE deletion SET purged_at = NOW()          WHERE entity = $1 AND record_id = $2 AND restored_at IS NULL AND purged_at IS NULL",
    )
    .bind(entity_logicalname)
    .bind(record_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // D-788 rule 9 / security review L6: a purged record's values in the
    // 30-day recovery archive go with it, in the same transaction.
    let archived_erased =
        attome_core::recovery_archive::erase_record(&mut tx, entity_logicalname, record_id).await?;
    if archived_erased > 0 {
        tracing::info!(%record_id, archived_erased, "retention purge: recovery-archive values deleted");
    }
    // Solution 7 Phase 2 design §9.3: the record's sealed release-report
    // conflict values and its baseline rows go too, in the same transaction.
    let report_erased =
        attome_core::release_report::erase_record(&mut tx, entity_logicalname, record_id).await?;
    if report_erased > 0 {
        tracing::info!(%record_id, report_erased, "retention purge: release-report conflict items deleted");
    }

    let (user_ctx, organization_ref) = attome_audit::fetch_audit_ctx(state, actor).await;
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());

    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::Security,
        entity_name: Some(entity_logicalname.to_string()),
        record_id: Some(record_id),
        operation: AuditOperation::Erasure,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event_name.to_string()),
        event_comment: Some(format!(
            "P-retention-archive-completion: retention purge for {entity_logicalname}/{record_id} \
             (key_destroyed={key_destroyed}, scrubbed={scrubbed})"
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };
    audit_service.write_in_tx(&mut tx, event).await?;

    tx.commit().await.map_err(AppError::internal)?;
    // R2-T1: outside the database, so a restore cannot bring it back.
    attome_audit::erasure_ledger::record_or_log(
        &state.base.storage,
        &attome_audit::erasure_ledger::LedgerEntry {
            kind: attome_audit::erasure_ledger::ErasureKind::Purge,
            entity: entity_logicalname.to_owned(),
            record_id,
        },
    )
    .await;

    Ok((key_destroyed, scrubbed))
}

// ── Tests ─────────────────────────────────────────────────────────────────
//
// `parent_table_for_partition` and `masked_select_expr` are pure functions —
// exercised directly with no database required. `stream_masked_export_to_store`
// and `verify_uploaded_checksum` take an `Arc<dyn ObjectStore>`/`&dyn
// ObjectStore` directly rather than a `StorageClient` (whose only constructor
// builds a concrete `AmazonS3`), so they're exercised below against
// `object_store::memory::InMemory` — real streaming/hashing/error-path
// behavior, no live network. This `object_store` 0.14 API surface
// (`buffered::BufWriter`, `GetResult::into_stream`, `MultipartUpload::abort`)
// was written from documentation, not verified by `cargo check` in this
// sandbox (no Rust toolchain available) — same disclosed status as
// `attome_audit::anchor`'s `put_opts`/`PutOptions` usage.
//
// Still NOT covered here, and needing live infrastructure this sandbox
// doesn't have — see this file's top doc comment for the full TODO list:
// `propose_retention_actions`/`execute_action`/`execute_partition_archive`
// themselves against a real Postgres partitioned table (an integration test
// for this now exists — `crates/engine/attome-api/tests/retention.rs`'s two
// `execute_partition_archive_*` tests — but has never actually been run
// here), a real multi-GB partition run, and a genuine mid-upload network
// failure against a real S3-compatible backend (`InMemory` doesn't model
// orphaned multipart parts the way a real bucket does, so the "abort avoids
// being billed for orphaned
// parts" property specifically is not provable against it).
#[cfg(test)]
mod tests {
    use super::{
        masked_select_expr, parent_table_for_partition, stream_masked_export_to_store,
        verify_uploaded_checksum,
    };
    use object_store::{ObjectStore, ObjectStoreExt, memory::InMemory, path::Path as ObjectPath};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    #[tokio::test]
    async fn streams_every_row_and_returns_a_checksum_matching_the_uploaded_object() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let path = ObjectPath::parse("retention-archives/test_p2026_01.ndjson").unwrap();
        let rows = futures_util::stream::iter(vec![
            Ok::<_, sqlx::Error>(r#"{"id":1}"#.to_string()),
            Ok::<_, sqlx::Error>(r#"{"id":2}"#.to_string()),
            Ok::<_, sqlx::Error>(r#"{"id":3}"#.to_string()),
        ]);

        let (row_count, checksum) =
            stream_masked_export_to_store(rows, store.clone(), path.clone())
                .await
                .expect("streaming export must succeed against a working store");

        assert_eq!(row_count, 3);

        let uploaded = store.as_ref().get(&path).await.expect("object must exist");
        let bytes = uploaded.bytes().await.expect("read uploaded bytes");
        assert_eq!(
            bytes.as_ref(),
            b"{\"id\":1}\n{\"id\":2}\n{\"id\":3}\n",
            "uploaded object must be one NDJSON line per row, in stream order"
        );
        assert_eq!(
            checksum,
            hex::encode(Sha256::digest(bytes.as_ref())),
            "returned checksum must match the actual uploaded bytes, not just the running hash's own bookkeeping"
        );
    }

    #[tokio::test]
    async fn a_zero_row_partition_uploads_an_empty_object_rather_than_erroring() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let path = ObjectPath::parse("retention-archives/test_p2026_02.ndjson").unwrap();
        let rows = futures_util::stream::iter(Vec::<Result<String, sqlx::Error>>::new());

        let (row_count, checksum) =
            stream_masked_export_to_store(rows, store.clone(), path.clone())
                .await
                .expect("an empty partition is a valid, if unusual, export");

        assert_eq!(row_count, 0);
        assert_eq!(checksum, hex::encode(Sha256::digest(b"")));
    }

    /// A row-stream failure partway through must abort the upload and
    /// propagate the error — never silently complete a truncated archive.
    /// `InMemory` never sees a committed object in this path because the
    /// buffered writer stays under `BufWriter`'s own capacity for these few
    /// bytes, so nothing is sent to the store before the abort; this asserts
    /// the outward-visible half of that guarantee (no object at `path`), not
    /// the multipart-specific plumbing (see this module's top doc comment
    /// for what still needs a real backend).
    #[tokio::test]
    async fn a_row_stream_error_aborts_the_upload_and_leaves_no_object_behind() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let path = ObjectPath::parse("retention-archives/test_p2026_03.ndjson").unwrap();
        let rows = futures_util::stream::iter(vec![
            Ok(r#"{"id":1}"#.to_string()),
            Err(sqlx::Error::RowNotFound),
        ]);

        let result = stream_masked_export_to_store(rows, store.clone(), path.clone()).await;
        assert!(
            result.is_err(),
            "a row-stream error must fail the export, not silently truncate it"
        );

        let get_err = store
            .as_ref()
            .get(&path)
            .await
            .expect_err("a failed export must never leave a visible (partial) object");
        assert!(matches!(get_err, object_store::Error::NotFound { .. }));
    }

    #[tokio::test]
    async fn verify_uploaded_checksum_confirms_matching_bytes() {
        let store = InMemory::new();
        let path = ObjectPath::parse("retention-archives/test_verify_ok.ndjson").unwrap();
        let body = b"{\"id\":1}\n{\"id\":2}\n".to_vec();
        store
            .put(&path, body.clone().into())
            .await
            .expect("seed the object directly");
        let checksum = hex::encode(Sha256::digest(&body));

        let matches = verify_uploaded_checksum(&store, &path, &checksum)
            .await
            .expect("verification against a reachable store must succeed");
        assert!(matches, "identical bytes must produce a matching checksum");
    }

    /// The exact regression this fix must never introduce: a checksum
    /// mismatch (simulating silent upload corruption) must be detected, not
    /// waved through — `execute_partition_archive`'s caller relies on this to
    /// decide whether it is safe to drop the detached partition (§3b.4/§8,
    /// and the "prevent drop before verification succeeds" review item).
    #[tokio::test]
    async fn verify_uploaded_checksum_detects_a_mismatch() {
        let store = InMemory::new();
        let path = ObjectPath::parse("retention-archives/test_verify_mismatch.ndjson").unwrap();
        store
            .put(&path, b"corrupted-bytes".to_vec().into())
            .await
            .expect("seed the object directly");
        let expected_checksum_of_something_else = hex::encode(Sha256::digest(b"original-bytes"));

        let matches = verify_uploaded_checksum(&store, &path, &expected_checksum_of_something_else)
            .await
            .expect("verification against a reachable store must succeed even on mismatch");
        assert!(
            !matches,
            "a checksum mismatch must be reported, never silently accepted"
        );
    }

    #[test]
    fn identifies_the_parent_of_a_normal_monthly_partition() {
        assert_eq!(
            parent_table_for_partition("audit_detail_p2026_01"),
            Some("audit_detail")
        );
        assert_eq!(
            parent_table_for_partition("s2s_access_log_p2026_01"),
            Some("s2s_access_log")
        );
    }

    #[test]
    fn identifies_the_parent_of_the_historical_pre_partition_bucket() {
        assert_eq!(
            parent_table_for_partition("audit_header_pre_partition"),
            Some("audit_header")
        );
    }

    #[test]
    fn an_unrecognized_partition_name_has_no_parent() {
        assert_eq!(
            parent_table_for_partition("some_other_table_p2026_01"),
            None
        );
    }

    #[test]
    fn masks_the_detail_shaped_value_columns_only_when_is_sensitive_is_present() {
        let columns: Vec<String> = ["id", "created_at", "old_value", "new_value", "is_sensitive"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let expr = masked_select_expr(&columns);
        assert!(expr.contains("CASE WHEN is_sensitive THEN '***MASKED***' ELSE \"old_value\" END"));
        assert!(expr.contains("CASE WHEN is_sensitive THEN '***MASKED***' ELSE \"new_value\" END"));
        assert!(expr.contains("\"id\""));
        assert!(expr.contains("\"created_at\""));
    }

    #[test]
    fn never_masks_when_the_partition_has_no_is_sensitive_column() {
        // audit_header/audit_snapshot/s2s_access_log shape:
        // no `is_sensitive` column, so even a same-named value column (there
        // isn't one today, but this pins the guard) must never be masked.
        let columns: Vec<String> = ["id", "created_at", "old_value"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let expr = masked_select_expr(&columns);
        assert!(!expr.contains("MASKED"));
        assert!(expr.contains("\"old_value\""));
    }

    /// Plan §4/§5 step 4's shared-template requirement: the masking CASE
    /// fragment `masked_select_expr` generates must not silently drift from
    /// `scripts/observability/export-audit-ledger.sh`'s own masking SQL for
    /// `audit_detail`. This reads that script directly and asserts its
    /// masking pattern for `old_value` still appears with the identical
    /// `'***MASKED***'` literal and `CASE WHEN is_sensitive THEN ... ELSE
    /// ... END` shape this module generates — a byte-level parity test on
    /// the one thing that actually matters (the masking guarantee), not on
    /// the surrounding SQL dialect (COPY-via-psql vs. this module's
    /// SELECT-via-sqlx, which necessarily differ — see this module's top
    /// doc comment).
    #[test]
    fn masking_literal_matches_the_shell_export_scripts_own_masking_sql() {
        let script = include_str!("../../../../scripts/observability/export-audit-ledger.sh");
        assert!(
            script.contains("CASE WHEN is_sensitive THEN '***MASKED***' ELSE old_value END"),
            "export-audit-ledger.sh's masking fragment for old_value changed shape — \
             update masked_select_expr (and this test) in the same change"
        );

        let columns: Vec<String> = ["old_value", "is_sensitive"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let expr = masked_select_expr(&columns);
        assert!(expr.contains("CASE WHEN is_sensitive THEN '***MASKED***' ELSE \"old_value\" END"));
    }
}
