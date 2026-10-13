use attome_config::KeyRing;
use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, SubsecRound, Utc};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Postgres;
use uuid::Uuid;

use attome_core::AuditSigner;

use crate::initiator::Attribution;
use crate::model::{AuditEvent, EventExtras};

/// Writes audit events to the XRM audit entities via the generic entity insert.
///
/// Call `write()` (standalone) or `write_in_tx()` (sharing the caller's
/// transaction) after every successful entity mutation. Per guidelines §10,
/// fire-and-forget spawns are forbidden for durable work — apalis (Plan 1.4)
/// is now available for that (`state.jobs`), but audit writes aren't queued
/// through it: the append still runs synchronously, with its cost kept low
/// by resolving audit-detail metadata once per write instead of once per
/// field (P1.5d). `entity_crud.rs`'s handlers use `write_in_tx` so the audit
/// chain append shares one transaction with the mutation it records — a
/// failed append rolls the mutation back too, instead of leaving a ghost
/// edit with no audit trail.
pub struct AuditService<'a> {
    db: &'a DbPool,
    signer: Option<&'a AuditSigner>,
    /// P1.13 stage 1 (`audit.ingest_capture_enabled`): additionally write a
    /// durable `audit_ingest` row alongside the chain append below.
    /// Purely additive — does not (yet) replace the synchronous chain write.
    /// Ignored (treated as always-on) when `chainer_enabled` is true — see
    /// that field's doc.
    ingest_capture_enabled: bool,
    /// P1.13 stage 4 (`audit.chainer_enabled`) — the cutover. When true,
    /// `write()` no longer acquires the append lock or writes
    /// `audit_header`/`detail`/`snapshot` at all: it only durably
    /// captures the event into `audit_ingest` (unconditionally,
    /// regardless of `ingest_capture_enabled`, since ingest is now the sole
    /// durability mechanism — there would be nowhere else for the event to
    /// go). The chainer process becomes solely responsible for producing
    /// `audit_header` rows.
    ///
    /// **This builder field defaults to false; `audit.chainer_enabled` — the
    /// config that actually decides a deployment's path — defaults to true
    /// (D-316) and is required under `deployment_profile = "production"`.**
    /// The two are not in conflict and the builder default must not be
    /// "fixed" to match: every call site in `crates/xrm`/`crates/server`
    /// threads the config value through `with_chainer_enabled`, so the
    /// builder default is only ever seen by a caller constructing
    /// `AuditService` with no config at all (the test suites, which pick a
    /// path explicitly and would be silently switched by a change here).
    chainer_enabled: bool,
    /// D-107 (`audit.erasure_enabled` + `audit.erasure_key_encryption_key`,
    /// parsed once at boot onto `EngineState.audit_erasure_key`) — when set,
    /// `write_in_tx` encrypts `changed_fields`/`snapshot_json` in place
    /// before ANY persistence (see `crate::erasure`'s doc comment for why
    /// this happens once, up front, rather than per storage location).
    /// `None` (the default) is today's plaintext behavior, unchanged.
    /// P-key-rotation-and-jwt (a): a `KeyRing`, not a bare `[u8; 32]` — the
    /// key wrapping each record's DEK can now rotate.
    erasure_key: Option<KeyRing>,
}

impl std::fmt::Debug for AuditService<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditService").finish_non_exhaustive()
    }
}

impl<'a> AuditService<'a> {
    pub fn new(db: &'a DbPool, signer: Option<&'a AuditSigner>) -> Self {
        Self {
            db,
            signer,
            ingest_capture_enabled: false,
            chainer_enabled: false,
            erasure_key: None,
        }
    }

    /// P1.13 stage 1: opts this instance into also writing a durable
    /// `audit_ingest` row per event (see `ingest_capture_enabled` doc).
    pub fn with_ingest_capture(mut self, enabled: bool) -> Self {
        self.ingest_capture_enabled = enabled;
        self
    }

    /// P1.13 stage 4: opts this instance into the chainer cutover — `write()`
    /// stops producing `audit_header` rows itself (see `chainer_enabled`
    /// doc).
    pub fn with_chainer_enabled(mut self, enabled: bool) -> Self {
        self.chainer_enabled = enabled;
        self
    }

    /// D-107: opts this instance into crypto-shredding — pass
    /// `state.audit_erasure_key` (see `erasure_key` field doc).
    pub fn with_erasure_key(mut self, key: Option<KeyRing>) -> Self {
        self.erasure_key = key;
        self
    }

    /// Writes one audit header + N detail rows + optional snapshot, inside
    /// the caller's own transaction — the combined fix for P1.5(a)
    /// chain-fork and P1.5(d) atomicity/N+1, plus the atomicity the
    /// `entity_crud.rs` handlers need: call this with the same `tx` the
    /// entity mutation ran in, and commit once, so a failed audit append
    /// rolls the mutation back too instead of leaving a ghost edit. Returns
    /// the `id` of the created `audit_header` record.
    ///
    /// P1.13 stage 4: when `chainer_enabled` is set, none of the header/
    /// detail/snapshot writes happen — this durably captures the event into
    /// `audit_ingest` and returns *that* row's id instead (every call
    /// site today discards the returned id, so this substitution is
    /// transparent to callers). The chainer process is solely responsible
    /// for turning ingest rows into header rows once this path is active.
    pub async fn write_in_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        event: AuditEvent,
    ) -> Result<Uuid, AppError> {
        // No caller of the plain (non-`_attributed`) entry point passes an
        // `Initiator` today, so default to `Attribution::user`, whose
        // `initiator`/`agent_session_id`/`agent_action_id` (0/NULL/NULL)
        // are exactly the values the database column DEFAULTs already
        // produced before those columns were threaded into this insert —
        // see `write_header`'s doc. Existing rows and existing tests are
        // therefore unaffected.
        let attribution = Attribution::user(event.user_context.user_id);
        self.write_in_tx_attributed(tx, event, attribution).await
    }

    /// Same as `write_in_tx`, but lets the caller supply the
    /// [`Attribution`] (who/what actually drove the write) instead of the
    /// `Attribution::user(event.user_context.user_id)` default `write_in_tx`
    /// applies. Needed by any caller attributing a write to
    /// `Initiator::Agent` or `Initiator::System` — e.g. `trd-engine`'s
    /// `record_transition`/`record_guardrail_decision`
    /// (document/TRADING-PLATFORM-PLAN.md §6 rule 5) attributing a LIVE
    /// strategy's autonomous order-pipeline actions to `System` rather than
    /// misattributing them to whichever user's id happens to be on
    /// `event.user_context`.
    pub async fn write_in_tx_attributed(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        event: AuditEvent,
        attribution: Attribution,
    ) -> Result<Uuid, AppError> {
        self.write_in_tx_with_extras(tx, event, attribution, EventExtras::default())
            .await
    }

    /// Same as `write_in_tx_attributed`, plus the D-541 rule 3 outcome and
    /// count columns (hash v2 fields 25-29). The security writer
    /// (`crate::security`) and bulk parent events use it.
    pub async fn write_in_tx_with_extras(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        mut event: AuditEvent,
        attribution: Attribution,
        extras: EventExtras,
    ) -> Result<Uuid, AppError> {
        // Plan 4.1: fill correlation_id/IP/browser/device_type from the
        // ambient per-request context where the caller left them at their
        // all-None default (never overwrites a caller-supplied value) —
        // before encryption/digest below, so an HTTP-originated event's hash
        // covers its own request id and client context (D-539 ruling 4).
        crate::request_ctx::backfill(&mut event);

        // D-107: encrypt in place, once, before this event reaches ANY
        // storage — audit_ingest (below, or via the chainer's later
        // drain of this same ingest row) and the synchronous header/detail/
        // snapshot path both just persist whatever's already in `event`
        // after this point, with no crypto-awareness of their own. See
        // `crate::erasure`'s doc comment for why this has to happen exactly
        // once, here, rather than at each storage site.
        if let Some(master_key) = &self.erasure_key {
            crate::erasure::encrypt_event_in_place(tx, master_key, &mut event).await?;
        }

        // D-539 ruling 4: the digest covers the event as it will be stored,
        // so the stored form is fixed here, once, before any storage: the
        // value_mode capture decision (after encryption, exactly as
        // `write_details` has always stored them) and the database clock as
        // the event time.
        mask_event_in_place(&mut event, self.erasure_key.is_some());

        if self.chainer_enabled {
            // D-539 ruling 5: the ingest row's own transaction clock, which is
            // exactly the `created_at` its `DEFAULT NOW()` stamps below.
            let db_now: DateTime<Utc> = sqlx::query_scalar("SELECT transaction_timestamp()")
                .fetch_one(&mut **tx)
                .await
                .map_err(AppError::internal)?;
            let content_digest = stamp_and_digest(&mut event, &attribution, &extras, db_now)?;

            // The digest is computed here, inside the mutation's transaction,
            // and travels in the payload with the attribution it covers
            // (initiator and agent ids are hashed fields, so the chainer must
            // write exactly the attribution this call was given — which also
            // closes the pre-v2 gap where a chainer-drained row lost it).
            let ingest_id =
                Self::write_ingest(tx, &event, Some((&attribution, &content_digest)), &extras)
                    .await?;

            tracing::debug!(
                ingest_id = %ingest_id,
                entity    = ?event.entity_name,
                operation = ?event.operation,
                "audit event captured (chainer cutover active)",
            );

            return Ok(ingest_id);
        }

        let db_now = Self::acquire_chain_lock(tx, event.organization_ref).await?;
        let content_digest = stamp_and_digest(&mut event, &attribution, &extras, db_now)?;

        let prev_hash = Self::fetch_last_hash(tx, event.organization_ref).await?;
        let event_hash = crate::canonical::event_hash_v2(&prev_hash, &content_digest)
            .map_err(AppError::internal)?;
        let (signature, signing_key_id) = self.sign(&prev_hash, &event_hash);

        let header_id = Self::write_header(
            tx,
            &event,
            &prev_hash,
            &event_hash,
            signature.as_deref(),
            signing_key_id.as_deref(),
            None,
            &attribution,
            Some(&content_digest),
            &extras,
        )
        .await?;
        Self::write_details(tx, header_id, &event).await?;

        if let Some(snapshot) = &event.snapshot_json {
            Self::write_snapshot(tx, header_id, &event, snapshot).await?;
        }

        Self::check_stored_digests(tx, &[(header_id, content_digest.clone())]).await?;

        if self.ingest_capture_enabled {
            Self::write_ingest(tx, &event, Some((&attribution, &content_digest)), &extras).await?;
        }

        tracing::debug!(
            header_id = %header_id,
            entity    = ?event.entity_name,
            operation = ?event.operation,
            "audit event written",
        );

        Ok(header_id)
    }

    /// Standalone form of `write_in_tx`: opens and commits its own
    /// transaction. Use this only when there's no caller transaction to
    /// share (e.g. the test suite); `entity_crud.rs`'s handlers use
    /// `write_in_tx` against their own `tx` instead, so the audit append is
    /// atomic with the mutation it records.
    pub async fn write(&self, event: AuditEvent) -> Result<Uuid, AppError> {
        let mut tx = attome_db::tx::begin(self.db).await?;
        let id = self.write_in_tx(&mut tx, event).await?;
        tx.commit().await.map_err(AppError::internal)?;
        Ok(id)
    }

    /// Standalone form of `write_in_tx_attributed`: opens and commits its
    /// own transaction. See `write_in_tx_attributed`'s doc.
    pub async fn write_attributed(
        &self,
        event: AuditEvent,
        attribution: Attribution,
    ) -> Result<Uuid, AppError> {
        let mut tx = attome_db::tx::begin(self.db).await?;
        let id = self
            .write_in_tx_attributed(&mut tx, event, attribution)
            .await?;
        tx.commit().await.map_err(AppError::internal)?;
        Ok(id)
    }

    // ── internal ──────────────────────────────────────────────────────────────

    fn sign(&self, prev_hash: &str, event_hash: &str) -> (Option<String>, Option<String>) {
        sign_pair(self.signer, prev_hash, event_hash)
    }

    /// Acquires `pg_try_advisory_xact_lock(ADVISORY_LOCK_NAMESPACE,
    /// hashtext("attome-audit/append:{org}"))` with exactly one non-blocking
    /// attempt — no retry loop.
    ///
    /// This runs *inside* the caller's own transaction (see `write_in_tx`'s
    /// doc: it shares the entity-mutation transaction so a failed append
    /// rolls the mutation back too), which is precisely why a retry loop is
    /// wrong here: a sleep between attempts would sit inside that open
    /// transaction, holding its pooled connection idle-in-transaction for
    /// the whole retry budget on every contended call (T2-14 /
    /// TECHNICAL-DUE-DILIGENCE-2026-08-24 finding 3.5 — guidelines §2 "never
    /// hold a database transaction ... across external I/O" and §10 "never
    /// block a Tokio runtime thread with ... sleeps" cover exactly this
    /// shape). A miss returns `Conflict` immediately instead, so the caller's
    /// transaction closes right away; retrying, if desired, belongs to the
    /// caller, outside any open transaction.
    ///
    /// The lock auto-releases on this transaction's commit/rollback.
    ///
    /// Returns the transaction clock (`transaction_timestamp()`), read in the
    /// same round trip, which is the v2 event time (D-539 ruling 5).
    async fn acquire_chain_lock(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        organization_ref: Uuid,
    ) -> Result<DateTime<Utc>, AppError> {
        let key = format!("attome-audit/append:{organization_ref}");

        let (locked, db_now): (bool, DateTime<Utc>) = sqlx::query_as(
            "SELECT pg_try_advisory_xact_lock($1, hashtext($2)), transaction_timestamp()",
        )
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(&key)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        if locked {
            return Ok(db_now);
        }

        Err(AppError::Conflict(
            "audit chain append lock is held by a concurrent writer for this organization",
        ))
    }

    // Must run after acquire_chain_lock, in the same transaction, so the
    // read and the header insert below are atomic together — reading the
    // tail without the lock (or without sharing the lock's transaction) is
    // exactly the P1.5a fork bug.
    //
    // Orders by `id DESC`, NOT `created_at DESC` (P1.8 finding, 2026-07-07):
    // `audit_header.created_at` defaults to SQL `NOW()`, which freezes at
    // *transaction start*, not statement execution. Under the P1.8 concurrent-
    // writer stress test, transactions begun within the same millisecond got
    // `created_at` values that did not match the true commit order the
    // advisory lock enforces, so this lookup picked a stale row and forked
    // the chain even though the lock itself serialized correctly. `id` is a
    // `uuidv7()` PK whose timestamp component is generated when the INSERT
    // actually executes (i.e. after this function's caller has already
    // acquired the lock and is about to write), so it is monotonic with
    // respect to real commit order in a way `created_at` is not.
    pub(crate) async fn fetch_last_hash(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        org: Uuid,
    ) -> Result<String, AppError> {
        let hash: Option<String> = sqlx::query_scalar(
            "SELECT event_hash FROM audit_header
             WHERE organization_ref = $1
             ORDER BY id DESC
             LIMIT 1",
        )
        .bind(org)
        .fetch_optional(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        Ok(hash.unwrap_or_default())
    }

    /// `chain_batch_ref` is `None` for the synchronous path (P1.5) and
    /// `Some(batch_id)` when the async chainer (P1.13 stage 2) writes this
    /// row as part of a Merkle-signed batch instead of signing it per-row.
    ///
    /// `attribution` (added alongside `Initiator::System`,
    /// document/TRADING-PLATFORM-PLAN.md §6 rule 5): before this, `Initiator`
    /// had zero usages outside `attome-audit` itself and this insert never set
    /// `initiator`/`agent_session_id`/`agent_action_id` at all — those three
    /// columns (migration 0121) only ever took their SQL DEFAULTs
    /// (0/NULL/NULL). `write_in_tx`/`write`'s default
    /// `Attribution::user(event.user_context.user_id)` reproduces exactly
    /// that, so this is additive: no existing row's values change.
    // `attribution` (added for trd System-attributed rows, see this fn's
    // doc comment) pushed the arity past clippy's default threshold; every
    // parameter here is a distinct, already-computed piece of one insert
    // (hash-chain fields, signing metadata, attribution) with no natural
    // sub-grouping used anywhere else — bundling them into a one-off struct
    // would move the arity problem, not solve it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn write_header(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        event: &AuditEvent,
        prev_hash: &str,
        event_hash: &str,
        signature: Option<&str>,
        signing_key_id: Option<&str>,
        chain_batch_ref: Option<Uuid>,
        attribution: &Attribution,
        content_digest: Option<&str>,
        extras: &EventExtras,
    ) -> Result<Uuid, AppError> {
        // D-539 ruling 1: a row with a content digest is hash version 2; a
        // row without one (a pre-v2 ingest payload drained by the chainer)
        // stays version 1 and keeps `compute_hash_raw`.
        let hash_version = if content_digest.is_some() {
            crate::canonical::HASH_VERSION_V2
        } else {
            crate::canonical::HASH_VERSION_V1
        };
        let data = json!({
            "hash_version":      hash_version,
            "content_digest":    content_digest,
            "organization_ref":  event.organization_ref.to_string(),
            "is_active":         true,
            "category":          event.category as i32,
            "entity_name":       event.entity_name,
            "record_id":         event.record_id.map(|u| u.to_string()),
            "operation":         event.operation as i32,
            "version_before":    event.version_before,
            "version_after":     event.version_after,
            "user_id":           event.user_context.user_id.to_string(),
            "user_name":         event.user_context.user_name,
            "user_display_name": event.user_context.user_display_name,
            "user_email":        event.user_context.user_email,
            "user_job_ref":      event.user_context.user_job_ref.map(|u| u.to_string()),
            "user_job_name":     event.user_context.user_job_name,
            "changed_on":        normalize_changed_on(event.changed_on).to_rfc3339(),
            "source":            event.source as i32,
            "ip_address":        event.request_context.ip_address,
            "browser":           event.request_context.browser,
            "device_type":       event.request_context.device_type,
            "correlation_id":    event.correlation_id.map(|u| u.to_string()),
            "batch_id":          event.batch_id.map(|u| u.to_string()),
            "event_name":        event.event_name,
            "event_comment":     event.event_comment,
            "prev_hash":         prev_hash,
            "event_hash":        event_hash,
            "signing_key_id":    signing_key_id,
            "signature":         signature,
            "chain_batch_ref":   chain_batch_ref.map(|u| u.to_string()),
            "initiator":         attribution.initiator.as_i16(),
            "agent_session_id":  attribution.agent_session_id.map(|u| u.to_string()),
            "agent_action_id":   attribution.agent_action_id.clone(),
            "outcome":           extras.outcome_i16(),
            "requested_count":   extras.requested_count,
            "affected_count":    extras.affected_count,
            "failed_count":      extras.failed_count,
            "occurrence_count":  extras.occurrence_count,
            "ai_model_id":       extras.ai_model_id.clone(),
            "approval_request_ref": extras.approval_request_ref.map(|u| u.to_string()),
        });

        attome_core::crud::append_only_insert(&mut *tx, "audit_header", &data).await
    }

    /// Batches every changed field into one multi-row INSERT instead of one
    /// `crud::append_only_insert` call per field — the N+1 half of P1.5d.
    /// Metadata for `audit_detail` is now resolved once (inside
    /// `append_only_insert_many`) regardless of field count.
    pub(crate) async fn write_details(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        header_id: Uuid,
        event: &AuditEvent,
    ) -> Result<(), AppError> {
        if event.changed_fields.is_empty() {
            return Ok(());
        }

        let rows: Vec<serde_json::Value> = event
            .changed_fields
            .iter()
            .map(|field| {
                let mode = crate::value_mode::classify(
                    event.entity_name.as_deref(),
                    &field.field_name,
                    field.is_sensitive,
                );
                json!({
                    "organization_ref":   event.organization_ref.to_string(),
                    "is_active":          true,
                    "audit_ref":          header_id.to_string(),
                    "field_name":         field.field_name,
                    "display_name":       field.display_name,
                    "data_type":          field.data_type,
                    "value_mode":         mode.as_i16(),
                    // `mask_event_in_place` already decided the final stored
                    // form (ciphertext, plaintext, "********", or None for
                    // NotCaptured) before this event ever reaches storage —
                    // no further masking here.
                    "old_value":          field.old_value,
                    "new_value":          field.new_value,
                    "old_display_value":  field.old_display_value,
                    "new_display_value":  field.new_display_value,
                    "old_lookup_entity":  field.old_lookup_entity,
                    "old_lookup_name":    field.old_lookup_name,
                    "new_lookup_entity":  field.new_lookup_entity,
                    "new_lookup_name":    field.new_lookup_name,
                    "is_sensitive":       field.is_sensitive,
                })
            })
            .collect();

        attome_core::crud::append_only_insert_many(&mut *tx, "audit_detail", &rows).await
    }

    /// Not routed through `attome_core::crud::append_only_insert` — the
    /// generic metadata-driven path every other audit write in this file uses —
    /// because `snapshot_json` is physically `jsonb`
    /// (`migrations/0011_audit_jsonb.sql`), but the metadata-driven cast
    /// vocabulary (`entity_mutation.rs`/`attome-metadata::crud`'s `sql_cast`,
    /// keyed by `field_type_int`) has no scalar-jsonb slot: the only
    /// `field_type` that ever casts `::jsonb` is a multi-valued `file`
    /// field (D-362), and mislabeling this column as `file` just to borrow
    /// that cast would make the generic reader (and any admin UI built on
    /// it) treat a JSON snapshot as a downloadable attachment, which it
    /// isn't. The declared metadata (`seed.rs`: `field_type: "text"`)
    /// correctly describes what this column *is* to every other reader;
    /// this insert — the column's only writer — is the one place that needs
    /// to know its *physical* type, so it says so explicitly rather than
    /// asking the generic engine to infer it.
    ///
    /// Found live (2026-08-15, D-364's Documents feature): this path had
    /// apparently never been exercised against a real Postgres before —
    /// `hard_delete_record` is `write_snapshot`'s only caller with
    /// `snapshot_json` populated (every other audit event passes `None`),
    /// and every hard-delete failed with "column snapshot_json is of type
    /// jsonb but expression is of type text", rolling the whole delete back
    /// (verified: the failure left no partial-delete state — the row, the
    /// change-feed emit, and the rest of the audit write all rolled back
    /// together, since this all runs in the caller's transaction).
    pub(crate) async fn write_snapshot(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        header_id: Uuid,
        event: &AuditEvent,
        snapshot: &serde_json::Value,
    ) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO audit_snapshot \
                (organization_ref, audit_ref, entity_name, record_id, version, snapshot_json, trigger) \
             VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)",
        )
        .bind(event.organization_ref)
        .bind(header_id)
        .bind(event.entity_name.as_deref())
        .bind(event.record_id)
        .bind(event.version_after)
        .bind(snapshot.to_string())
        .bind(crate::canonical::SNAPSHOT_TRIGGER_ON_WRITE) // 0 = OnCreate/OnUpdate — hashed as snapshot field 2
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        Ok(())
    }

    /// Durable capture for the async chainer (P1.13 stages 1+4). Not a
    /// registered XRM entity — `audit_ingest` is internal plumbing, so
    /// this is a plain parameterized insert rather than `attome_metadata::crud`.
    /// Returns the new row's id (used as `write()`'s return value in stage
    /// 4's cutover mode, where there is no header id to return instead).
    ///
    /// `v2` carries the attribution and the content digest computed in this
    /// transaction (D-539 ruling 4). The payload is the serialized
    /// `AuditEvent` with `hash_version`, `content_digest` and `attribution`
    /// added as top-level keys ([`IngestEnvelope`]), so every existing reader
    /// of the payload's event fields is unaffected.
    async fn write_ingest(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        event: &AuditEvent,
        v2: Option<(&Attribution, &str)>,
        extras: &EventExtras,
    ) -> Result<Uuid, AppError> {
        let envelope = IngestEnvelope {
            event: event.clone(),
            extras: extras.clone(),
            hash_version: v2.map(|_| crate::canonical::HASH_VERSION_V2),
            content_digest: v2.map(|(_, digest)| digest.to_owned()),
            attribution: v2.map(|(attribution, _)| attribution.clone()),
        };
        let payload = serde_json::to_value(&envelope).map_err(AppError::internal)?;

        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO audit_ingest (organization_ref, payload) VALUES ($1, $2) RETURNING id",
        )
        .bind(event.organization_ref)
        .bind(payload)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        Ok(id)
    }

    /// Batch-mode chain append (P1.13 stage 2, used by `crate::chainer`).
    /// Like the header/detail/snapshot writes inside `write()` above, but:
    /// the caller (the chainer) supplies `prev_hash` and already holds
    /// whatever lock/transaction discipline it needs for the whole batch,
    /// and the row is written unsigned — the batch's Merkle root gets one
    /// signature instead (`sign_batch`), not each row.
    ///
    /// A v2 payload (`content_digest` present) is written as hash version 2
    /// with the attribution and digest the mutation's transaction computed;
    /// the caller must then [`check_stored_digests`](Self::check_stored_digests)
    /// before committing. A payload captured before v2 (no digest, so no
    /// attribution and an application-clock `changed_on`) is written exactly
    /// as it always was: hash version 1, attributed to the plain user.
    /// Returns `(header_id, event_hash, content_digest)`.
    pub(crate) async fn append_in_batch(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        envelope: &IngestEnvelope,
        prev_hash: &str,
        chain_batch_ref: Uuid,
    ) -> Result<(Uuid, String, Option<String>), AppError> {
        let event = &envelope.event;

        let (event_hash, attribution, content_digest) =
            match (envelope.hash_version, &envelope.content_digest) {
                (Some(crate::canonical::HASH_VERSION_V2), Some(digest)) => (
                    crate::canonical::event_hash_v2(prev_hash, digest)
                        .map_err(AppError::internal)?,
                    envelope
                        .attribution
                        .clone()
                        .unwrap_or_else(|| Attribution::user(event.user_context.user_id)),
                    Some(digest.clone()),
                ),
                (None, None) => (
                    compute_hash(prev_hash, event),
                    Attribution::user(event.user_context.user_id),
                    None,
                ),
                (version, _) => {
                    return Err(AppError::internal(format!(
                        "audit ingest payload has hash_version {version:?} with content_digest \
                     present = {} — not a payload this chainer writes",
                        envelope.content_digest.is_some()
                    )));
                }
            };

        let header_id = Self::write_header(
            tx,
            event,
            prev_hash,
            &event_hash,
            None,
            None,
            Some(chain_batch_ref),
            &attribution,
            content_digest.as_deref(),
            &envelope.extras,
        )
        .await?;
        Self::write_details(tx, header_id, event).await?;

        if let Some(snapshot) = &event.snapshot_json {
            Self::write_snapshot(tx, header_id, event, snapshot).await?;
        }

        Ok((header_id, event_hash, content_digest))
    }

    /// D-539 ruling 4: recomputes each header's content digest from the rows
    /// just written (inside the same transaction, so it reads its own writes)
    /// and fails when any differs from the digest the event was hashed with.
    /// A failure rolls the whole write — or the whole chainer batch — back,
    /// so a row whose stored form does not reproduce its digest is never
    /// committed.
    pub(crate) async fn check_stored_digests(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        expected: &[(Uuid, String)],
    ) -> Result<(), AppError> {
        for chunk in expected.chunks(crate::verify::V2_LOAD_CHUNK) {
            let ids: Vec<Uuid> = chunk.iter().map(|(id, _)| *id).collect();
            let stored = crate::canonical::load_stored_events(tx, &ids)
                .await
                .map_err(AppError::internal)?;
            for (id, digest) in chunk {
                let recomputed = stored
                    .get(id)
                    .map(crate::canonical::content_digest_v2)
                    .transpose()
                    .map_err(AppError::internal)?;
                if recomputed.as_deref() != Some(digest.as_str()) {
                    return Err(AppError::internal(format!(
                        "audit header {id}: stored rows digest to {recomputed:?}, but the event \
                         was hashed with content_digest {digest} — refusing to commit it"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Signs a batch's Merkle root the same way `sign` signs a per-row hash —
    /// `(prev_batch_hash || merkle_root)`, chaining batches together the same
    /// way `prev_hash || event_hash` chains rows.
    pub(crate) fn sign_batch(
        signer: Option<&AuditSigner>,
        prev_batch_hash: &str,
        merkle_root: &str,
    ) -> (Option<String>, Option<String>) {
        sign_pair(signer, prev_batch_hash, merkle_root)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// The `audit_ingest.payload` shape. `event`'s fields stay top-level (so
/// `signoff::decision_chain_evidence`'s `payload->>'record_id'` lookup and
/// every pre-v2 payload keep working); the three v2 keys are absent on a
/// payload captured before hash v2, which the chainer writes as version 1.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct IngestEnvelope {
    #[serde(flatten)]
    pub event: AuditEvent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_version: Option<i16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
    /// D-541 rule 3 columns; absent (all NULL) on every payload that sets none.
    #[serde(default, skip_serializing_if = "EventExtras::is_empty")]
    pub extras: EventExtras,
}

/// D-540 rulings 3/G2-1 (plan 5.3): applies the `value_mode` capture decision
/// to the event in place, so the ingest payload, the digest and the stored
/// detail rows all carry the same, final stored form. `write_details` reads
/// `field.old_value` etc. as already-final; this is the one place that
/// decides them.
///
/// `encrypted` is whether `encrypt_event_in_place` already turned this
/// event's values into ciphertext (`self.erasure_key.is_some()`). A
/// `NotCaptured` (credential) field is stripped either way — the fact that it
/// changed is evidence enough, the value never is. A `Restricted`
/// (`is_sensitive`) field keeps its ciphertext when one exists; with no key
/// configured there is no ciphertext to protect the plaintext, so it falls
/// back to the pre-encryption `"********"` placeholder (D-540: "with no key,
/// Restricted values keep write-time masking"). An ordinary field is never
/// touched here — its `Encrypted` mode ciphertext (or plaintext, with no key)
/// is exactly what should be stored.
fn mask_event_in_place(event: &mut AuditEvent, encrypted: bool) {
    let entity_name = event.entity_name.clone();
    for field in &mut event.changed_fields {
        match crate::value_mode::classify(
            entity_name.as_deref(),
            &field.field_name,
            field.is_sensitive,
        ) {
            crate::value_mode::ValueMode::NotCaptured => {
                field.old_value = None;
                field.new_value = None;
                field.old_display_value = None;
                field.new_display_value = None;
                field.old_lookup_entity = None;
                field.old_lookup_name = None;
                field.new_lookup_entity = None;
                field.new_lookup_name = None;
            }
            crate::value_mode::ValueMode::Restricted if !encrypted => {
                field.old_value = mask_sensitive(&field.old_value, true);
                field.new_value = mask_sensitive(&field.new_value, true);
                field.old_display_value = mask_sensitive(&field.old_display_value, true);
                field.new_display_value = mask_sensitive(&field.new_display_value, true);
            }
            crate::value_mode::ValueMode::Restricted | crate::value_mode::ValueMode::Encrypted => {}
        }
    }
}

/// D-539 ruling 5: replaces the application's `changed_on` with the database
/// transaction clock (the application value is kept only in this debug log),
/// then computes the v2 content digest over the event as it will be stored.
/// An event that cannot be encoded (two detail rows with one `field_name`) is
/// refused here, before anything is written.
fn stamp_and_digest(
    event: &mut AuditEvent,
    attribution: &Attribution,
    extras: &EventExtras,
    db_now: DateTime<Utc>,
) -> Result<String, AppError> {
    if event.changed_on != db_now {
        tracing::debug!(
            application_changed_on = %event.changed_on,
            database_changed_on = %db_now,
            "audit v2 event time taken from the database transaction clock",
        );
    }
    event.changed_on = db_now;
    crate::canonical::content_digest_v2(&crate::canonical::CanonicalEvent::from_event(
        event,
        attribution,
        extras,
    ))
    .map_err(|e| AppError::internal(format!("audit event cannot be canonically encoded: {e}")))
}

fn sign_pair(signer: Option<&AuditSigner>, a: &str, b: &str) -> (Option<String>, Option<String>) {
    match signer {
        Some(signer) => (Some(signer.sign(a, b)), Some(signer.key_id.clone())),
        None => (None, None),
    }
}

fn mask_sensitive(value: &Option<String>, is_sensitive: bool) -> Option<String> {
    if is_sensitive {
        value.as_ref().map(|_| "********".to_owned())
    } else {
        value.clone()
    }
}

/// **Hash version 1** (D-539): SHA-256( prev_hash | operation | entity_name |
/// record_id | user_id | timestamp_ms ). It covers only that identity, not the
/// event's content, which is why every writer now produces version 2
/// (`crate::canonical`). It remains the formula for pre-v2 rows forever (I9),
/// including pre-v2 ingest payloads the chainer drains after an upgrade.
pub(crate) fn compute_hash(prev_hash: &str, event: &AuditEvent) -> String {
    compute_hash_raw(
        prev_hash,
        event.operation as i32,
        event.entity_name.as_deref(),
        event.record_id,
        event.user_context.user_id,
        normalize_changed_on(event.changed_on).timestamp_millis(),
    )
}

/// `audit_header.changed_on` is a `timestamptz` (Postgres native
/// microsecond precision) written via `to_rfc3339()`, which preserves
/// whatever precision the in-memory `DateTime<Utc>` happens to carry —
/// typically nanoseconds, straight from `Utc::now()`. Postgres *rounds*
/// (not truncates) any finer input down to microseconds on storage, so a
/// value whose sub-microsecond remainder is large enough can come back out
/// with a different millisecond component than the one it went in with
/// (found by P1.13's leftover-validation testing: a 4000-row batch produced
/// two rows whose recomputed `event_hash` didn't match their own stored
/// value, purely from this rounding — a false-positive tamper report on
/// untampered rows). Truncating to microsecond precision here, at both the
/// hash-input site (`compute_hash`) and the storage site (`write_header`'s
/// `changed_on` field) before either ever sees the value, makes the two
/// agree unconditionally: the value that gets hashed is bit-identical to
/// the value that gets stored (and therefore to whatever verification later
/// reads back), so there is nothing left for Postgres's rounding to change.
fn normalize_changed_on(dt: DateTime<Utc>) -> DateTime<Utc> {
    dt.trunc_subsecs(6)
}

/// The primitive fields `compute_hash` extracts from `AuditEvent` — split out
/// so `crate::verify` can recompute the same hash straight from stored
/// `audit_header` columns (P1.13 stage 3), without reconstructing a
/// synthetic `AuditEvent`, and without duplicating the hash formula.
pub(crate) fn compute_hash_raw(
    prev_hash: &str,
    operation: i32,
    entity_name: Option<&str>,
    record_id: Option<Uuid>,
    user_id: Uuid,
    changed_on_millis: i64,
) -> String {
    let mut h = Sha256::new();
    h.update(prev_hash.as_bytes());
    h.update(operation.to_le_bytes());
    if let Some(name) = entity_name {
        h.update(name.as_bytes());
    }
    if let Some(record) = record_id {
        h.update(record.as_bytes());
    }
    h.update(user_id.as_bytes());
    h.update(changed_on_millis.to_le_bytes());

    hex::encode(h.finalize())
}
