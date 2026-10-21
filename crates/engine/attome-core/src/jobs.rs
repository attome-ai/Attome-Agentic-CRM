//! The engine's jobs: one enum of every kind the engines enqueue, routed and
//! stored by attome-jobs (V2-D481). A kind's queue, priority lane and attempt
//! budget are declared here, exhaustively, so a new kind cannot inherit them
//! by omission.

use attome_jobs::JobPriority;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RewrapDomain {
    Mfa,
    S2s,
    Erasure,
}

impl RewrapDomain {
    pub const ALL: [Self; 3] = [Self::Mfa, Self::S2s, Self::Erasure];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mfa => "mfa",
            Self::S2s => "s2s",
            Self::Erasure => "erasure",
        }
    }
}

impl fmt::Display for RewrapDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for RewrapDomain {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "mfa" => Ok(Self::Mfa),
            "s2s" => Ok(Self::S2s),
            "erasure" => Ok(Self::Erasure),
            _ => Err("domain must be one of: mfa, s2s, erasure"),
        }
    }
}

/// The platform's single async job contract (P1.4). Pure data only — no
/// xrm-* types — because its producers span both layers (e.g.
/// `attome-server`'s bulk/staged-import endpoints, `attome-auth`'s rewrap
/// trigger) and `base-*` may never depend on `xrm-*` (guidelines §1).
/// Handlers that perform the actual work are registered centrally in the
/// `server` binary's worker `Monitor`, the one place both layers are visible.
/// (P-job-system-hardening (b) took the two highest-frequency producers —
/// `attome-server`'s auth middleware and attome-s2s's HMAC middleware — off this
/// queue entirely: see `attome_server::apikey_touch`/`attome_s2s::telemetry`.)
///
/// All variants share one `apalis.jobs` table and one enum (never a
/// table/worker per job kind — still the documented "rejected alternative",
/// guidelines §0.5), but route across two `job_type` namespaces/workers
/// (P-job-queue-hardening, D-165): [`Self::is_batch`] sends the handful of
/// open-ended, record-count-proportional variants to their own worker so
/// they can never starve the fast, latency-sensitive ones sharing the
/// default queue's concurrency budget.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EngineJob {
    /// Send one email via SMTP (P-account-lifecycle) — reset/verification
    /// links, generic notifications. Always enqueued, never sent on the
    /// request path (guidelines §10 — a slow SMTP host must never slow a
    /// login/register/reset-request call).
    ///
    /// Boxed (M52 Phase 1, D-465): `EmailMessage` grew four more `Option`
    /// fields for outbound-communication threading
    /// (`message_id`/`in_reply_to`/`references`/`communication_id`), which
    /// pushed `EngineJob`'s largest variant past clippy's
    /// `large_enum_variant` threshold — every other variant is a handful of
    /// scalars, so the fix belongs on this one payload, not a blanket size
    /// budget increase. `Box<T>` is `Serialize`/`Deserialize`-transparent
    /// (serde's blanket impl), so this is a pure in-memory layout change —
    /// the JSON on the wire (and in any already-queued row) is byte-for-byte
    /// unchanged, no `JobEnvelope` envelope bump needed.
    SendEmail(Box<attome_email::EmailMessage>),
    /// P-db-maintenance item (c) — create-ahead maintenance for the
    /// RANGE-partitioned audit family + `s2s_access_log`
    /// (migrations/0026_audit_partitioning.sql). No payload: the handler
    /// re-derives "now" and the fixed table list itself, so a delayed retry
    /// after a crash just re-checks the same idempotent create-ahead work
    /// rather than replaying a stale enqueue-time snapshot.
    EnsureAuditPartitions,
    /// Drops fully expired notification-recipient partitions when the
    /// deployment has opted into notification retention. The handler reads
    /// current config so retention changes take effect on the next run.
    PruneNotificationRecipientPartitions,
    /// Materializes an organization/global notification into explicit
    /// per-user inbox rows.  The `crates/server` job handler maps this pure payload
    /// onto attome-notification, where the XRM tables are visible.
    FanOutNotification { dispatch_id: Uuid },
    /// Catches up a newly-created user on currently active organization/global
    /// in-app notifications.  The insert is idempotent in attome-notification,
    /// so a retry is safe.
    BackfillRecipientForNewUser { user_id: Uuid },
    /// Builds or removes the btree supporting a sortable/filterable entity
    /// attribute. The payload is a metadata pointer, not a desired-state
    /// snapshot: the worker re-reads current intent before issuing DDL.
    BuildAttributeIndex {
        entity_logicalname: String,
        field_logicalname: String,
    },
    /// Solution 7 Phase 2 (D-787 rule 7, D-791 rule 7) — builds the unique
    /// `uxbk_<e40>_<h8>` index that enforces an entity's declared business
    /// key (and drops the index of a key it replaced), above the size gate.
    /// Same bare-pointer shape as `BuildAttributeIndex`: the worker re-reads
    /// the entity's current `business_key` before issuing DDL, so a key
    /// changed again while this was queued builds the newest one. Enqueued
    /// dedup-keyed `business-key-index:<entity>`
    /// (`attome_metadata::provision::business_key::ensure_business_key_index`).
    BuildBusinessKeyIndex { entity_logicalname: String },
    /// F024 (P2.2) — chunked bulk create/update/delete against a provisioned
    /// entity table. `records` is pure JSON (attome-jobs cannot depend on
    /// xrm-*'s `AttrInfo`/validation types) — `crates/server`'s job handler maps
    /// this onto `attome_server::bulk::process` where those types are visible.
    /// `bulk_op_id` names the `automation_bulk_operation` row the handler updates
    /// as it goes, so a client polling `GET .../bulk/{id}` sees real
    /// progress, not just a final result.
    BulkEntityOperation(BulkEntityOperationPayload),
    /// F024 follow-up: applies an admin-approved staged import. Enqueued by
    /// `POST .../staged-import/{id}/approve` instead of running the apply
    /// loop on the request thread — an approval can cover as many records as
    /// the original staged import, so it gets the same durability/async
    /// treatment as `BulkEntityOperation` rather than a synchronous handler
    /// with no size bound. `import_id` names the `automation_staged_import` row.
    ApplyStagedImport(ApplyStagedImportPayload),
    /// P-key-rotation-and-jwt (b) — background convergence after a
    /// `KeyRing` rotation: rewrites every row in `domain`'s table that isn't
    /// already under the ring's active key. `RewrapDomain` lives here as pure
    /// job-contract data, independent of the `xrm-*`/`attome-auth` types that
    /// own each domain's actual table/crypto. Never fire-and-forget
    /// (guidelines §10) — enqueued by
    /// the admin rewrap-trigger endpoint (`system.admin`-gated,
    /// advisory-locked `"attome-auth/rewrap:{domain}"`), not run on the
    /// request thread, since a large table's full rewrap can take a while.
    RewrapSecrets { domain: RewrapDomain },
    /// P-file-upload-pipeline — async malware/content-disarm scan +
    /// sniffed-type/checksum verification for a finalized upload session.
    /// Enqueued by `POST .../upload-session/{id}/finalize` in the same
    /// commit as that session's `pending -> uploaded` transition
    /// (guidelines §9). The handler (`attome_document::files_scan::process`)
    /// claims the session, fetches+hashes+sniffs the quarantined bytes, and
    /// either promotes it to `clean` or rejects it — never on the request
    /// thread (guidelines §10).
    ScanUploadedFile { session_id: Uuid },
    /// K1-T4 — extracts a clean upload's text (plain text, DOCX, PDF) into
    /// `document_text` for global search and re-announces the documents that
    /// name the file (`attome_document::text_extract::process`). Enqueued in
    /// the scan's clean transaction. Pure pointer; idempotent.
    DocumentTextExtract { session_id: Uuid },
    /// P-file-upload-pipeline — periodic sweep that expires abandoned upload
    /// sessions (presigned but never uploaded, uploaded but never
    /// finalized) past `attome_document::files::UPLOAD_SESSION_TTL_SECS` and
    /// deletes their quarantine object. Bare unit variant, same shape as
    /// `EnsureAuditPartitions`: the handler re-derives "now" rather than
    /// replaying an enqueue-time snapshot, and never touches a `legal_hold`
    /// session or one with an unexpired `retention_expires_at`.
    PruneExpiredUploadSessions,
    /// P-job-queue-hardening (D-165) — periodic sweep that deletes
    /// `apalis.jobs` rows in a terminal state (`Done`/`Killed`) older than
    /// `jobs.history_retention_days`. Bare unit variant, same
    /// re-derive-current-config-not-enqueue-time-snapshot shape as
    /// `EnsureAuditPartitions`/`PruneExpiredUploadSessions`. Exists so the
    /// dead-letter admin list (`GET .../admin/jobs/dead-letter`) stays a
    /// bounded, meaningful history instead of an ever-growing table — apalis
    /// itself never vacuums a finished job on its own.
    PruneApalisJobHistory,
    /// P-stored-query-containment addendum §11(c) — background convergence
    /// for `sql_query_version`'s cached `cost_estimate`, which
    /// `query/execute` never otherwise revalidates after publish (phase 2
    /// skips per-request `EXPLAIN` by default). Bare unit variant, same
    /// re-derive-current-state shape as `EnsureAuditPartitions`/
    /// `PruneExpiredUploadSessions`/`PruneApalisJobHistory`: the handler
    /// (`attome_records::query_admin::revalidate_all`) re-reads every currently
    /// active `sql_query` row and re-runs the publish-time lint on the
    /// readonly pool, rather than replaying an enqueue-time snapshot of
    /// which queries existed.
    RevalidateQueryPlans,
    /// AA4-T5: daily, queues a `BuildAttributeIndex` for every filterable
    /// text attribute whose table has grown past
    /// `query.trigram_index_min_rows` without a trigram index; the build
    /// adds it.
    TrigramIndexSweep,
    /// P-retention-archive-completion §3b/§3c — daily proposal sweep:
    /// identifies partitions of `audit_header`/`audit_detail`/
    /// `audit_snapshot`/`s2s_access_log` older than
    /// `retention.{audit,s2s_access_log}_days`, and soft-deleted entity
    /// records older than `retention.entity_purge_grace_days`, writing one
    /// `audit_retention_action` row per eligible target
    /// (`status = 'proposed'`). Bare unit variant, same
    /// re-derive-current-config-not-enqueue-time-snapshot shape as
    /// `EnsureAuditPartitions` — never executes anything destructive itself
    /// (propose and execute are always separate steps, §3e).
    ProposeRetentionActions,
    /// P-retention-archive-completion §3b/§3c/§3e — executes exactly one
    /// already-`approved` `audit_retention_action` row: partition
    /// detach/archive/verify/drop, or entity crypto-shred + field-scrub.
    /// Enqueued only by the admin approve endpoint, never on a timer —
    /// mirrors `ApplyStagedImport`'s "approval enqueues its own execution"
    /// shape. Refused by the handler if `retention.dry_run` is still true or
    /// `retention.legal_hold` is set, even though the row is already
    /// approved (config can change between approve and execute).
    ExecuteRetentionAction { action_id: Uuid },
    /// P-idempotency-hardening §4.4/§5 step 11 — periodic sweep that
    /// soft-deletes `idempotency_record` rows (the durable-tier
    /// counterpart to the Redis gate's TTL) older than
    /// `idempotency.durable_retention_hours`. Bare unit variant, same
    /// re-derive-current-config-not-enqueue-time-snapshot shape as
    /// `EnsureAuditPartitions`/`PruneApalisJobHistory`.
    PruneIdempotencyRecords,
    /// attome-auth plan BAU-13a/13b — periodic sweep that deletes dead refresh
    /// lineages and expired reset, verification and invitation tokens past
    /// their retention (`attome_auth::refresh::prune_dead_families`, each
    /// module's `prune_expired`), in bounded batches. Bare unit variant: the
    /// handler re-reads the current retention on every run.
    PruneAuthTokens,
    /// P-online-schema-change Step 3 — runs one `schema_change_operation`
    /// plan: chunked NULL-backfill (when the plan sets a column required),
    /// then the terminal `evolve_attribute_schema` ALTER. A bare `plan_id`
    /// pointer, matching `BuildAttributeIndex`'s "never a stale
    /// desired-state snapshot" shape — but unlike that job, the handler does
    /// NOT re-read mutable intent from `attribute_info` before running:
    /// the ledger row is the frozen intent, committed atomically (same
    /// transaction) with the metadata write that created it, so re-deriving
    /// it would just read back what that transaction already wrote. See
    /// `attome_metadata::provision::apply_schema_change_plan`'s doc comment.
    ApplySchemaChangePlan { plan_id: Uuid },
    /// P-environment-promotion §5 step 12 — applies one
    /// `metadata_bundle_plan` row: walks the plan's entries in
    /// dependency order, one short transaction per object, advancing the
    /// ledger's `cursor` after each so a crash-and-resume continues rather
    /// than restarts, and fires a single metadata-change doorbell at the
    /// end. Same bare-`plan_id`-pointer shape as `ApplySchemaChangePlan`:
    /// the ledger row is the frozen intent (bundle + plan JSON, both
    /// hashes), claimed by row-CAS with a stale-claim timeout
    /// (`attome_server::bundle::ledger::claim`), so the handler re-reads it
    /// rather than trusting anything carried in the queue payload. Enqueued
    /// dedup-keyed on the plan id (`attome_server::bundle::ledger::enqueue_apply`)
    /// once the plan is `queued` — directly on the development profile, or by
    /// `approval_admin::execute_approved` for an approved
    /// `metadata.bundle_apply` request in production.
    ApplyMetadataBundle { plan_id: Uuid },
    /// Solution 7 Phase 1 (D-785, design §5.3) — applies
    /// `changeset_apply` rows strictly in the order given, each a
    /// claimed, cursor-resumable run through the metadata reconcile
    /// primitives (`attome_server::changeset::apply::run_apply_job`); a failure
    /// stops the run and the later rows stay `queued`. Same bare-pointer
    /// shape as `ApplyMetadataBundle`: the ledger rows are the frozen intent
    /// (document, checksum, plan), re-read and re-checked when claimed.
    /// Enqueued dedup-keyed on the ids (`changeset::ledger::enqueue_apply`)
    /// by the apply route or an approved `metadata.changeset_apply`.
    ApplyChangesets { apply_ids: Vec<Uuid> },
    /// Solution 7 Phase 2 (D-788; SOLUTION-7-PHASE-2-DESIGN.md §6) — runs one
    /// `data_step_run` row: the batched half of a structure change
    /// above the size gate (a large in-place type change's shadow-column
    /// backfill and swap, a large field delete's archive copy and drop).
    /// Bare pointer: the run row is the frozen intent (kind, spec, cursor),
    /// claimed by row CAS with a stale-claim takeover and resumed from its
    /// cursor (`attome_server::field_changes::run_field_run`).
    RunDataStep { run_id: Uuid },
    /// Solution 7 Phase 2 (D-788 rule 9, design §8.4) — hourly purge of
    /// `recovery_archive` rows past `expires_at`, in bounded
    /// batches, skipping rows whose record is under a legal hold. Bare unit
    /// variant, the `PruneIdempotencyRecords` shape.
    PruneRecoveryArchive,
    /// D-188 (metadata-dependency reactive-lint containment) — background
    /// convergence for `field_security_profile_field`'s
    /// `entity_logicalname`/`field_logicalname` string references, the one
    /// other logicalname-reference consumer (alongside `sql_query`)
    /// that had no revalidation path. Bare unit variant, same
    /// re-derive-current-state shape as `RevalidateQueryPlans`: the handler
    /// (`attome_security::revalidation::revalidate_field_security_profiles`)
    /// re-reads every active profile-field row and logs (never mutates) the
    /// ones whose entity/field is no longer active.
    RevalidateFieldSecurityProfiles,
    /// P-workflow-engine (P2.9) §4.4 — drives one `workflow_instance`
    /// in-memory through as many nodes as are ready to run, back to back,
    /// until it hits a checkpoint (a wait-capable node, or a terminal
    /// state). Pure pointer, not a desired-state snapshot: the handler
    /// re-reads the instance's current `node_data`/`node_run` rows from
    /// Postgres, same "never replay a stale enqueue-time payload" shape as
    /// `BuildAttributeIndex`/`ApplySchemaChangePlan`. Enqueued whenever an
    /// instance starts, and whenever a wait resumes (event match, SLA
    /// sweep, manual/signal call).
    WorkflowExecute { instance_id: Uuid },
    /// P-workflow-engine §4.3/§5 step 7 — periodic sweep of
    /// `workflow_trigger_index` for `role='wait' AND
    /// match_type='schedule' AND resume_at < now()`; enqueues
    /// `WorkflowExecute` for each match. Bare unit variant, same
    /// re-derive-current-state shape as `EnsureAuditPartitions`.
    WorkflowSlaSweep,
    /// P-workflow-engine §5 step 6 follow-up (D-267 addendum) — drains
    /// `entity_change_event`'s durable outbox (written by
    /// `entity_mutation::create_one`/`update_one` in the same transaction as
    /// every entity write) and starts a new workflow instance for each
    /// matching published entry trigger. Bare unit variant, same
    /// re-derive-current-state shape as `WorkflowSlaSweep`.
    WorkflowEntityTriggerDispatch,
    /// P-web-crawling (D-365) — walks one `webcrawl_target` same-origin,
    /// up to `webcrawl.max_pages`/`webcrawl.max_depth`, through the
    /// SSRF-hardened fetcher (`attome_webcrawl::safety`), persisting each
    /// discovered page as it goes. Pure pointer, not a desired-state
    /// snapshot — same "handler re-reads current state" shape as
    /// `WorkflowExecute`/`ApplySchemaChangePlan`. Enqueued (in the same
    /// transaction as the target row insert, via `enqueue_in_tx`) by
    /// `POST /api/v1/webcrawl/targets` and `.../recrawl`, both
    /// `Authorized<Admin>`-gated.
    CrawlWebsite { target_id: Uuid },
    /// D7-T3: adds an owner's default team to their open deals that miss a
    /// member, in batches. Enqueued by `POST /api/v1/sales/default-team/apply`.
    SalesDefaultTeamApply { owner_id: Uuid },
    /// D6-T6: moves a large deal's schedule rows by whole months, after the
    /// user agreed to it.
    SalesScheduleShift { opportunity_id: Uuid, months: i32 },
    /// D21-T5: applies a call list's outcome rules for one saved attempt,
    /// after the attempt committed.
    SalesCallOutcomeRules { attempt_id: Uuid },
    /// AI4-T6: one follow-up rule's scan, queued by hand.
    AiFollowupRuleRun { rule_id: Uuid },
    /// F10-T5: computes (or resumes) one commission calculation run,
    /// enqueued by `POST /api/v1/commission/periods/{id}/runs`. Pure
    /// pointer; the run's `cursor` makes a retry resume.
    CommissionRun { run_id: Uuid },
    /// F10-T9: recomputes an open period into recalculation previews,
    /// leaving statements alone.
    CommissionRecalcPreview { period_id: Uuid },
    /// F4-T6: runs the registered after-issue hooks (e-invoicing, the
    /// document, sending) for one invoice, enqueued in the issuing
    /// transaction. Pure pointer; each hook is idempotent.
    BillingAfterIssue { invoice_id: Uuid },
    /// F5-T10: refunds one pending refund through its gateway.
    BillingExecuteRefund { refund_id: Uuid },
    /// TECHNICAL-DUE-DILIGENCE-2026-08-24 finding 3.2 (T2-2) — the async half
    /// of `attome_server::entity_mutation::apply_dependents_on_delete`'s
    /// `OnTargetDelete::CascadeDeactivate` handling. A dependent group at or
    /// below `entity_mutation::CASCADE_INLINE_ROW_LIMIT` finishes inline,
    /// inside the deleting request's own transaction, exactly as before this
    /// job existed; above it, `apply_dependents_on_delete` enqueues this job
    /// (dedup-keyed on the parent/dependent-group triple, in the same
    /// transaction as the parent's own deactivation) instead of blocking the
    /// request on an unbounded `UPDATE ... RETURNING`. Pure pointer, not a
    /// desired-state snapshot — same "handler re-reads current state" shape
    /// as `BuildAttributeIndex`/`WorkflowExecute`: the worker
    /// (`attome_server::entity_mutation::run_cascade_deactivate_job`) re-checks
    /// `is_active = TRUE` on every bounded batch, so a dependent reactivated
    /// or independently deleted between enqueue and run is handled correctly
    /// either way, and a crash-and-retry only ever repeats work on rows the
    /// previous attempt hadn't reached yet.
    CascadeDeactivateDependents {
        target_entity: String,
        target_record_id: Uuid,
        dependent_entity: String,
        dependent_field: String,
        deactivated_by: Uuid,
    },
    /// M27 Phase 1 (KPI & Metrics, D-407) — periodic sweep: evaluates every
    /// active `source_kind = "query"` `dashboard_metric_definition` for its
    /// current period and writes an `metric_snapshot` row, idempotent
    /// per `(metric, period)`. Bare unit variant, same
    /// re-derive-current-state shape as `EnsureAuditPartitions`/
    /// `WorkflowSlaSweep` — the handler
    /// (`attome_metric::metric::run_scheduled_snapshot_sweep`) re-reads
    /// every active metric rather than replaying an enqueue-time snapshot
    /// of which metrics existed. `manual`-sourced metrics are never swept —
    /// they're only written via an explicit `/api/v1/metrics/{id}/compute`
    /// call.
    ComputeMetricSnapshots,
    /// M62 Phase 1 (Event Bus, D-403/D-409) — scheduled tick: for every
    /// active `event_subscription`, reads its outbox cursor
    /// (`attome_core::change_feed`, keyed `"events:{subscription id}"`),
    /// applies the subscription's filter, and inserts one
    /// `event_delivery` row per newly-matched event (`ON CONFLICT
    /// (subscription_ref, event_id) DO NOTHING` — the row itself is the
    /// idempotency key, see migration `0144`'s header), enqueueing
    /// `EventsDeliverWebhook` for each new row. Bare unit variant, same
    /// re-derive-current-state shape as `WorkflowEntityTriggerDispatch`.
    EventsDispatchTick,
    /// M62 Phase 1 — delivers one already-created `event_delivery`
    /// row: signs the payload (HMAC-SHA256, `attome_events::crypto`, same
    /// canonical-signing discipline as `attome-s2s`), re-validates the target
    /// through `attome_server::ssrf_guard` (DNS can change since the
    /// subscription was saved), sends it, and records the outcome. Pure
    /// pointer — the handler loads the subscription's current target/secret/
    /// retry policy fresh on every attempt, so an admin editing the
    /// subscription mid-retry takes effect on the next attempt. Deduplicated
    /// on this variant's own `delivery_id` (apalis `push_job_dedup`), which
    /// is unique per (subscription, event) by construction.
    EventsDeliverWebhook { delivery_id: Uuid },
    /// M12 (data management) — runs one `data_export` row: builds the
    /// permission-filtered result set (row + field security, the same
    /// enforcement `query_exec.rs` applies), serializes it in the requested
    /// format, and uploads it via `attome-storage`. Enqueued by
    /// `POST /api/v1/{entity}/export` in the same transaction as the ledger
    /// row (`enqueue_in_tx`), mirroring `BulkEntityOperation`'s shape.
    DataExport(DataExportPayload),
    /// M12 — runs one `data_profile` row: null %, distinct counts,
    /// min/max, and pattern samples per field. Enqueued by
    /// `POST /admin/data/profile`.
    DataProfile(DataProfilePayload),
    /// M12 — applies one fixed built-in transform to one field over a
    /// dry-run-confirmed record set, durable and resumable via
    /// `bulk_transform_operation_item`'s per-record ledger. Enqueued by
    /// `POST /api/v1/{entity}/bulk-transform` once approved (D-195 four-eyes
    /// above the row-count threshold) or immediately below it.
    DataBulkTransform(DataBulkTransformPayload),
    /// M34 (AI Governance, D-435) — the nightly quality-monitor sweep: scans
    /// `ai_suggestion_outcome` for accept/edit/reject drift per (action,
    /// model, prompt_version) versus the prior period and raises an in-app
    /// alert on a significant drop. Bare unit variant, same re-derive-
    /// current-state shape as `ComputeMetricSnapshots`/`EnsureAuditPartitions`
    /// — the handler (`attome_ai::quality_monitor::run`) re-reads the whole
    /// outcome table's current window rather than replaying an enqueue-time
    /// snapshot.
    AiQualityMonitor,
    /// C4 (chat confirm round-trip, row A-40) — reclaims `ai_tool_call`
    /// confirm leases whose holder died, returning those proposals to
    /// `proposed`, and expires proposals nobody confirmed in time. Bare unit
    /// variant, same re-derive-current-state shape as `AiQualityMonitor`:
    /// the handler (`attome_ai::tool_call::sweep`) reads the table as it is now.
    AiToolCallSweep,
    /// A18-T4: reports people who deleted many records in a short time to
    /// the administrators. Bare unit variant; the handler reads the deletion
    /// ledger as it is now.
    BinDeleteAlertSweep,
    /// B4-T3: removes tag links whose expiry has passed. Bare unit variant.
    TagExpirySweep,
    /// W1-T4: the nightly contract key-date run (notice deadlines, renewal
    /// tasks, obligation reminders and escalations, recurring obligations).
    /// Bare unit variant; the handler reads the tables as they are now.
    ContractKeyDates,
    /// W1-T3: proposes accounts for contracts that name their counterparty
    /// only as text. Enqueued on demand by an administrator; bare unit
    /// variant.
    ContractCounterpartyMatch,
    /// V2-T2: creates the next task for every completed recurring task.
    /// Bare unit variant.
    RecurringTaskRoll,
    /// W1-T13: drafts contracts from accepted quotes, confirmed orders and
    /// contract intake requests, off the change feed. Bare unit variant.
    ContractLinkSweep,
    /// F3-T11: hands committed subscription events to revenue and churn,
    /// off the change feed. Bare unit variant.
    BillingHandoffSweep,
    /// F3-T9: renews subscriptions or opens renewal opportunities, and
    /// reminds, converts or ends trials. Bare unit variant.
    BillingRenewalSweep,
    /// F3-T8: plans subscription charges (recurring, setup and usage) up to
    /// the horizon. Bare unit variant.
    BillingGenerateCharges,
    /// D18-T1: scores every record of every enabled points model. Bare
    /// unit variant.
    PointsScoring,
    /// D19-T1: scores the risk of every open deal. Bare unit variant.
    DealRiskEvaluation,
    /// D11-T2: recomputes every open forecast period's cells and takes the
    /// weekly snapshot. Bare unit variant.
    ForecastRecompute,
    /// F3-T10: stores today's recurring-revenue snapshot. Bare unit variant.
    MrrSnapshot,
    /// K6-T3: queues a crawl for every website source due on its schedule.
    /// Bare unit variant.
    WebcrawlRecrawlDue,
    /// M10-T1: claims due timers and queues a `TimerFire` for each. Bare
    /// unit variant.
    TimerSweep,
    /// M10-T1: runs one fired timer's action. Pure pointer; the handler
    /// reads the timer row.
    TimerFire { timer_id: Uuid },
    /// M12-T2: runs one report schedule's occurrence, which the Z7 ledger
    /// (`report-schedule:{id}`) claimed once. Pure pointer; the handler reads
    /// the schedule row.
    ReportScheduleFire { schedule_id: Uuid },
    /// A3-T5: rewrites a published business rule's clean-up queue from a
    /// full scan of its entity's stored records. Pure pointer.
    ValidationCleanupScan { rule_id: Uuid },
    /// The nightly marketing pass: loyalty earning and expiry (E30-T1),
    /// referral rewards (E31-T1), target account scores (E20-T1) and bounce
    /// and complaint effects (E6-T5). Bare unit variant.
    MarketingNightly,
    /// E7-T4: refreshes the scheduled marketing lists that are due. Bare
    /// unit variant.
    SegmentRefreshDue,
    /// The five-minute marketing pass: overdue hand-offs (E9-T7) and nurture
    /// track moves (E9-T4). Bare unit variant.
    MarketingSweep,
    /// Q10-T6: removes role grants past their end date. Bare unit variant.
    RoleGrantExpiry,
    /// D7-T3: gives new deals their owner's default team, off the change
    /// feed. Bare unit variant.
    SalesDefaultTeamSweep,
    /// F10-T3: writes commission credits for won deals, off the change
    /// feed. Bare unit variant.
    CommissionCreditSweep,
    /// F4-T9: turns pending invoice requests into draft invoices. Bare unit
    /// variant.
    BillingRequestSweep,
    /// F4-T9: copies each due invoice schedule's template into a draft.
    /// Bare unit variant.
    BillingScheduleRun,
    /// F4-T10: marks issued invoices past due with something open as
    /// overdue. Bare unit variant.
    BillingOverdueSweep,
    /// F5-T9: charges due invoices to saved methods. Bare unit variant.
    BillingChargeDue,
    /// F5-T11: reconciles yesterday's gateway payouts. Bare unit variant.
    BillingReconcile,
    /// AG2-T3: sends e-invoices ZATCA could not take yet. Bare unit variant.
    BillingEinvoiceSweep,
    /// F5-T7: applies stored payment gateway events. Bare unit variant.
    BillingGatewayEventApply,
    /// D6-T8: removes line snapshots older than a day. Bare unit variant.
    SalesSnapshotPrune,
    /// C2-T1: tells followers about changes to records they follow, off
    /// the change feed. Bare unit variant.
    NotificationFollowSweep,
    /// D25-T3: win/loss reviews for big closes, off the change feed. Bare
    /// unit variant.
    SalesDealCloseSweep,
    /// D7-T6: tells managers about disabled users' open deals. Bare unit
    /// variant.
    SalesLeaverSweep,
    /// AI4-T5: runs every active follow-up rule's stall detector. Bare unit
    /// variant.
    AiFollowupScan,
    /// AI4-T5: one follow-up item, run by the follow-up agent for the
    /// record's owner. Bare id pointer; the ledger row is the state.
    AiFollowupItem { item_id: Uuid },
    /// Y2-T8: the daily table-health sample. Bare unit variant.
    TableHealthSample,
    /// Q16-T2: the weekly audit chain verification. Bare unit variant.
    AuditChainVerify,
    /// K2-T2: the weekly rescan of files promoted in the last 30 days, with
    /// the scanner's current signatures. Bare unit variant.
    UploadRescanSweep,
    /// AA13-T9: writes the latest finished month's SLO report when it is
    /// missing. Bare unit variant.
    SloMonthlyReport,
    /// AA13-T9: tells the administrators when an SLO class burns its error
    /// budget fast, once per class per hour. Bare unit variant.
    SloBurnCheck,
    /// AA14-T8: compares each SLO class's p95 in the week after the last
    /// upgrade with the week before and alerts on a clear regression. Daily.
    /// Bare unit variant.
    PerfRegressionCheck,
    /// AA9-T7: tells the administrators about each limit near its value,
    /// once per limit per day. Daily. Bare unit variant.
    LimitWarningCheck,
    /// D25-T4: competitor mentions in new emails and notes, off the change
    /// feed. Bare unit variant.
    SalesMentionScan,
    /// M03 (Security & Identity) gap 1 / D-434 — periodic sweep: flips every
    /// `access_review` campaign still `active` past its `due_date`
    /// to `completed`, whatever state its items are in. Bare unit variant,
    /// same re-derive-current-state shape as `EnsureAuditPartitions`/
    /// `WorkflowSlaSweep` — the handler
    /// (`attome_security::admin::sweep_due_campaigns`) re-reads every campaign
    /// currently due rather than replaying an enqueue-time snapshot of which
    /// campaigns existed.
    AccessReviewCampaignSweep,
    /// M17 (data migration, D-433) — reverts one `migration_run`: for
    /// each `migration_run_item` row still `pending`, re-applies the
    /// inverse mutation (soft-delete for a tracked `create`, restore of
    /// `prior_data` for a tracked `update`) through the same
    /// `entity_mutation::update_one`/`delete_one` optimistic-concurrency
    /// check every other write uses — a record whose current `row_version`
    /// no longer matches what this run last set it to is refused, not
    /// forced, and reported per-item. Enqueued by `POST
    /// .../migration-projects/{project_id}/runs/{run_id}/rollback`
    /// (`system.admin`-gated), same "durable job, not a request-thread loop"
    /// shape as `ApplyStagedImport`.
    RollbackMigrationRun { run_id: Uuid, user_id: Uuid },
    /// D-432 / M13 (Master Data Management, scoped to dedup + survivorship
    /// only) — periodic tick: drains the entity-change outbox cursor keyed
    /// `"mdm/match-sweep"` (`attome_core::change_feed`, bounded batch),
    /// evaluates every active `match_rule` against each changed
    /// record's peers, and writes `duplicate_candidate` rows for
    /// pairs clearing the rule's `threshold`. Bare unit variant, same
    /// re-derive-current-state shape as `WorkflowEntityTriggerDispatch`/
    /// `EventsDispatchTick` — the handler
    /// (`attome_server::duplicates_match::run_match_sweep`) re-reads current
    /// match rules on every tick rather than replaying an enqueue-time
    /// snapshot of which rules existed.
    DataMatchSweep,
    /// A15-T6: one page of a full scan of a match rule's entity: the next
    /// 500 live rows after `after_id` get their match keys written and are
    /// each scored against their peers; the handler enqueues the page after,
    /// so a scan resumes from its last page after a restart. Enqueued
    /// dedup-keyed `match-scan:<rule>:<after_id or start>`
    /// (`attome_api::duplicates_match::run_match_scan`).
    DataMatchScan {
        rule_id: Uuid,
        after_id: Option<Uuid>,
    },
    /// M61 Phase 1 (API Management, D-438) — nightly rollup: drains the Redis
    /// write-coalescing buffer `attome_server::api_usage` populates on every
    /// authenticated request (one `HINCRBY` per (day, method, route,
    /// identity)) into `api_usage`. Bare unit variant, same
    /// re-derive-current-state shape as `DataMatchSweep`/
    /// `EnsureAuditPartitions` — the handler
    /// (`attome_server::api_usage::flush`) always drains whatever is currently
    /// buffered rather than replaying an enqueue-time snapshot.
    ApiUsageRollup,
    /// M56 Content Management Phase 1 (D-436, migration `0230`) — periodic
    /// sweep: publishes a `draft` page whose `publish_at` has passed, and
    /// reverts a `published` page whose `unpublish_at` has passed, back to
    /// `draft`. Bare unit variant, same re-derive-current-state shape as
    /// `AccessReviewCampaignSweep`/`WorkflowSlaSweep` — the handler
    /// (`attome_content::scheduling::sweep_scheduled_transitions`) re-scans the
    /// two indexed predicates on every tick rather than replaying an
    /// enqueue-time snapshot of which pages were due.
    ContentScheduledPublishSweep,
    /// M14 Phase 1 (Data Quality, D-468) — periodic sweep: computes a
    /// completeness score (`is_required` field metadata + null counts, M12's
    /// technique) and a uniqueness score (M13's `duplicate_candidate`
    /// open-candidate count) per active entity, upserting
    /// `quality_score`/`quality_issue` and raising an M51
    /// in-app alert when a dimension score crosses a fixed threshold. Bare
    /// unit variant, same re-derive-current-state shape as `DataMatchSweep`/
    /// `ContentScheduledPublishSweep` — the handler
    /// (`attome_server::quality_score::run_sweep`) re-reads every entity's
    /// current null/duplicate counts on every tick rather than replaying an
    /// enqueue-time snapshot.
    DataQualityScoreSweep,
    /// M25 Phase 1 (Report, D-440) — runs one `report_run` row: resolves
    /// `requested_by`'s `SecurityContext` fresh from Postgres
    /// (`attome_security::resolve_uncached` — never the enqueuing caller's
    /// context and never a superuser one, D-440's whole point), executes the
    /// report's `query_ref` stored query through the same
    /// `query_exec::execute_stored_query` every other caller uses, renders
    /// csv/xlsx, and uploads via attome-storage. Bare `run_id` — the worker
    /// re-reads the run/report rows fresh rather than replaying an
    /// enqueue-time snapshot, same discipline `DataExport` follows.
    ReportRun { run_id: Uuid },
    /// M25 Phase 1 (Report, D-440) — periodic sweep: finds
    /// `report_schedule` rows whose `next_run_at` has passed, claims
    /// each with a guarded row_version UPDATE (so two replicas can't both
    /// fire the same occurrence), creates its `report_run` row with
    /// `requested_by = run_as`, and enqueues `ReportRun` for it. Bare unit
    /// variant, same re-derive-current-state shape as
    /// `WorkflowSlaSweep`/`ContentScheduledPublishSweep`.
    ReportScheduleSweep,
    /// AH8 (V2-D693): runs `ai_deferred_action` rows whose undo window ended,
    /// re-checking each first; ends rows interrupted mid-run as failed so
    /// none runs twice. Bare unit variant, same re-derive-current-state
    /// shape as `ReportScheduleSweep`: the rows are the queue.
    AiDeferredActionSweep,
    /// AH8-T8: daily; one in-app summary per person of the actions their
    /// agents ran on their own at `automatic`, then prunes summarized rows.
    AiAutonomySummary,
    /// M23 Records Management (D-456) — runs one `audit_legal_matter`'s
    /// "collect": scans its `scope_entity` under `scope_filter` in bounded
    /// batches, places a hold (`legal_hold`, tagged
    /// `matter_reference`) on every hit not already held for this matter,
    /// then writes one unmasked NDJSON collection package to `attome-storage`.
    /// Enqueued by `POST .../legal/matters/{id}/collect` in the same
    /// transaction as the `open|collected -> collecting` transition
    /// (`attome_compliance::legal_matter_admin::collect`), dedup-keyed on the
    /// matter id. Pure pointer, not a desired-state snapshot: the handler
    /// (`attome_compliance::legal_matter_admin::run_collect_job`) re-reads the
    /// matter's current `scope_entity`/`scope_filter` rather than trusting
    /// anything carried in the queue payload.
    LegalMatterCollect { matter_id: Uuid, collected_by: Uuid },
    /// M23 Records Management (D-456) — releases every active hold tagged
    /// with one legal matter's `reference`, in bounded batches. Enqueued by
    /// `POST .../legal/matters/{id}/release`, same
    /// `collected -> releasing`-in-the-same-transaction shape as
    /// `LegalMatterCollect` above.
    LegalMatterRelease { matter_id: Uuid, released_by: Uuid },
    /// Retired (D-778): the licence-expiry notifier it ran is deleted and
    /// nothing schedules it. The variant stays so a row queued by an older
    /// build still deserializes; `crates/server/src/jobs.rs` completes it as
    /// a no-op. Remove once no deployment can hold such a queued row.
    LicenseExpiryCheck,
    /// Audit plan 3.5 (D-541 rule 6) — periodic sweep: for every closed
    /// 5-minute failed-login window still held in coordination Redis, writes
    /// one summary `FailedLogin` event per coalescing key that failed more
    /// than once, then deletes its counter. Bare unit variant: the handler
    /// re-reads Redis on every tick, and a retried tick is idempotent (the
    /// summary write checks for an existing one under an advisory lock).
    FailedLoginSweep,
    /// M11 Search gap list — rebuilds `search_suggestion` from
    /// registered entities' display names and active `saved_search`
    /// records. Bare unit variant, same re-derive-current-state shape as
    /// `ContentScheduledPublishSweep` — the handler
    /// (`attome_search::refresh_suggestions`) deletes and rebuilds the whole
    /// (bounded) table on every tick rather than replaying an enqueue-time
    /// snapshot.
    SearchSuggestionRefresh,
    /// M11 Search gap list — the bounded, scheduled saved-search
    /// alert-on-new-results sweep. Bare unit variant; the handler
    /// (`attome_search::sweep_alerts`) re-derives current state (each alert-
    /// enabled saved search's current result count) on every tick, same
    /// shape as `DataMatchSweep`/`ApiUsageRollup`.
    SearchSavedSearchAlertSweep,
    /// M37 Knowledge Management Phase 2 (D-452) — nightly rollup: folds
    /// unrolled-up rows from `content_page_view`/`content_page_vote`
    /// and `attome-search`'s `knowledge_chunk_retrieval` into
    /// `content_page_stats`. Bare unit variant, same re-derive-
    /// current-state shape as `ApiUsageRollup` — the handler
    /// (`attome_content::analytics::rollup_page_stats`, composed with
    /// `attome_search::telemetry::retrieval_counts_by_source` in
    /// `crates/server/src/jobs.rs`) always drains whatever is currently
    /// unrolled-up rather than replaying an enqueue-time snapshot.
    ContentPageStatsRollup,
    /// M37 Knowledge Management Phase 2 (D-452) — daily sweep: notifies
    /// (M51, in-app) the owner (`updated_by`) of every live page whose
    /// `review_by` has passed. Bare unit variant, same re-derive-
    /// current-state shape as `ContentScheduledPublishSweep` — the handler
    /// (`attome_content::analytics::sweep_review_reminders`) re-scans
    /// `idx_xrm_content_page_review_by` on every tick; there is no
    /// enqueue-time snapshot and no "already reminded" flag, so an owner who
    /// ignores the reminder is nagged again on the next tick rather than
    /// only once.
    ContentReviewReminderSweep,
    /// M35 (AI Memory, D-451) — periodic sweep: deletes `memory`
    /// rows older than the `ai.memory_retention_days` setting
    /// (`attome-core::setting_catalog`). Bare unit variant, same
    /// re-derive-current-config-not-enqueue-time-snapshot shape as
    /// `PruneExpiredUploadSessions`/`PruneIdempotencyRecords` — the handler
    /// (`attome_compliance::retention::prune_expired_memories`) always re-reads
    /// the current setting value rather than replaying an enqueue-time
    /// snapshot of the retention window.
    ///
    /// M18 Data Catalog Phase 1 (D-466) — periodic, self-converging backfill
    /// of `metadata_reference` for queries/workflows published
    /// BEFORE this release's live lineage writers existed. Bare unit
    /// variant, same re-derive-current-state shape as `DataMatchSweep` —
    /// the handler (`attome_records::query_admin::backfill_catalog_lineage` +
    /// `attome_workflow::catalog_backfill::backfill_catalog_lineage`) reads its
    /// own resumable cursor (`metadata_reference_backfill_progress`,
    /// migration `0357`) fresh on every tick and processes one bounded batch
    /// per kind, rather than needing a one-shot admin trigger: once both
    /// kinds' cursors report `completed`, every later tick is a cheap no-op.
    CatalogLineageBackfill,
    /// M18 Data Catalog Phase 1 (D-466) — the dashboard-widget half of
    /// `metadata_reference` maintenance, driven off the
    /// entity-change-feed outbox rather than a bespoke save hook (dashboards
    /// are generic-CRUD entities — migration `0356`'s header). Bare unit
    /// variant, same non-destructive-cursor outbox-consumer shape as
    /// `DataMatchSweep` — the handler
    /// (`attome_server::catalog_admin::run_dashboard_lineage_sweep`) drains one
    /// bounded batch of `dashboard_widget` create/update events per
    /// tick and copies each widget's `query_id`'s already-recorded query
    /// lineage under `from_kind = "dashboard"`.
    CatalogDashboardLineageSweep,
    /// M18 Data Catalog Phase 1 (D-466) — nightly per-entity usage snapshot
    /// (record count, last write, 30-day search impressions) into
    /// `catalog_usage_rollup` (migration `0358`), read by
    /// `GET /api/v1/catalog/entities/{name}`. Bare unit variant, same
    /// re-derive-current-state shape as `ApiUsageRollup`/
    /// `ContentPageStatsRollup` — the handler
    /// (`attome_server::catalog_admin::run_usage_rollup`) always recomputes
    /// every registered entity's snapshot rather than replaying an
    /// enqueue-time snapshot.
    CatalogUsageRollup,
    /// A3-T8: nightly; rewrites each entity's validity score (the share of
    /// its live records passing every active business rule) in
    /// `validation_score` from a full scan. Pure trigger.
    ValidationScoreSweep,
    /// Deliberately **not** routed through `attome_compliance::retention`'s
    /// propose/approve/execute ledger (`audit_retention_action`) the way
    /// partition-archive/entity-purge are: that ledger's dedup index
    /// (`(action_type, target) WHERE status <> 'rejected'`, migration
    /// `0067`) exists to make a ONE-TIME action per specific target
    /// idempotent across daily re-proposals — a partition gets archived
    /// once, a record gets purged once. Memory retention is the opposite
    /// shape: an ongoing, recurring, age-based bulk sweep with no single
    /// fixed target. Forcing it through that ledger under a symbolic target
    /// (e.g. `"memory"`) would let the FIRST sweep complete and then
    /// permanently block every later one, since a `completed` row still
    /// satisfies `status <> 'rejected'` — a genuine correctness bug, not a
    /// style preference. See `document/decisions/security/D-451.md`.
    PruneExpiredMemories,
    /// M41 Phase 1 (Process Intelligence, D-462) — periodic tick: for every
    /// active `process_case_def`, reads new source rows past its own
    /// persisted `(cursor_last_ts, cursor_last_id)` cursor (from
    /// `workflow_node_run` or `audit_header`/`_detail`,
    /// depending on the case def's `source`), writes them idempotently into
    /// `process_event`, and recomputes that case def's DFG/variant/
    /// cycle-time snapshot when new events landed. Bare unit variant, same
    /// re-derive-current-state shape as `WorkflowEntityTriggerDispatch`/
    /// `DataMatchSweep` — the handler
    /// (`attome_process::extraction::run_sweep`) re-reads every active case def
    /// on every tick rather than replaying an enqueue-time snapshot of which
    /// case defs existed. Never fire-and-forget (guidelines §10): each case
    /// def's batch is durable, cursor-resumable, and bounded
    /// (`extraction::BATCH_LIMIT`), and per-source-row idempotent via
    /// `process_event`'s unique index, so a retry after a crash never
    /// double-counts.
    ProcessExtractionSweep,
    /// M84 Phase 1 (Queue Management, D-464) — periodic sweep: for every
    /// active `service_work_queue`, alerts `escalation_recipient` (falling back
    /// to `lead_ref`) when the queue is overflowing capacity (an unassigned
    /// item exists and every active member is at/over `capacity`), and again
    /// when it has items that have sat unassigned past
    /// `escalate_after_minutes`. Bare unit variant, same re-derive-
    /// current-state shape as `AccessReviewCampaignSweep`/
    /// `ContentReviewReminderSweep` — the handler
    /// (`attome_service::queue::run_escalation_sweep`) re-scans every active
    /// queue's current backlog on every tick rather than replaying an
    /// enqueue-time snapshot, and re-nags every tick the condition still
    /// holds (no persistent "already alerted" marker — see that function's
    /// own doc comment for why that's deliberate, not a gap).
    WorkQueueEscalationSweep,
    /// M73 (SLA Management, D-422) — REVIEW-2026-09-02 finding #1: this
    /// wiring was the missing half. Runs, in order, `attome_service::clock::
    /// sweep_auto_pause` (reconciles each ticket's clock against its current
    /// `status` before anything else reads clock state), `attome_service::sla::
    /// sweep_warnings`, `attome_service::sla::sweep_breaches`, and
    /// `attome_service::sla::sweep_escalations` — all four existed and were
    /// tested since D-422 but had no caller outside their own test files, so
    /// no SLA breach, warning, or escalation ever fired in a deployment.
    /// Bare unit variant, same re-derive-current-state shape as
    /// `WorkQueueEscalationSweep` immediately above — each sweep re-scans
    /// its own due/breached candidate set on every tick rather than
    /// replaying an enqueue-time snapshot.
    TicketSlaSweep,
    /// M72 (Resource Management) — see `attome_project::utilization`'s module
    /// doc, which named this exact variant as its own missing follow-up:
    /// `sweep_utilization_alerts` existed and was tested with zero callers
    /// in `crates/server`. Bare unit variant, same shape as
    /// `TicketSlaSweep`/`WorkQueueEscalationSweep` above — re-derives every
    /// active team's trailing utilization on every tick.
    ResourceUtilizationSweep,
    /// M57 Phase 1 (Document Generation, D-463) — renders one document from
    /// an active `docgen_template` against a record, under
    /// `requested_by`'s `SecurityContext` resolved fresh from Postgres
    /// (never the enqueuing caller's cached context and never a superuser
    /// one — same discipline as `ReportRun`/D-440). Pure pointer, not a
    /// desired-state snapshot: the handler (`attome_docgen::render::process`)
    /// re-reads the `docgen_render` ledger row, the template, and the
    /// record fresh rather than replaying an enqueue-time payload. Builds
    /// the merge context through the same field/record security every other
    /// read path uses, screens the merged HTML for embedded external URLs
    /// (SSRF-shaped guard), calls the isolated render sidecar under an
    /// explicit timeout and response-size cap, uploads the result via
    /// attome-storage, and — if the template names `attach_to_field` — attaches
    /// it as a new M55 file version via `attome_server::entity_crud::
    /// update_record_for`. Never `is_batch`: one record per render, same
    /// shape as `ReportRun`.
    DocgenRender { render_id: Uuid },
    /// F3-T8: one billing run (`billing_run`): its due charges requested
    /// from invoicing group by group, resumable. Pure pointer.
    BillingExecuteRun { run_id: Uuid },
    /// G11-T1 — brings one content page's knowledge item in line with the
    /// page (`attome_content::article::sync`): projects a published article
    /// into `knowledge_data_item`, or sets its item back to draft once it is
    /// unpublished, deleted or no longer an article. Pure pointer: the
    /// handler re-reads the page and writes through the entity engine as the
    /// page's knowledge author. Idempotent; one record, so never `is_batch`.
    ContentArticleIndex { page_id: Uuid },
    /// N22-T2 — transcribes a recording (`attome_document`) through the
    /// speech endpoint into `recording_transcript` and `document_text`
    /// (`attome_document::transcribe::process`). Pure pointer; idempotent.
    TranscribeRecording { document_id: Uuid },
    /// M36 Phase 1 (Predictive Intelligence, D-473) — trains one
    /// `prediction_model`: extracts a labeled feature set from ticket/SLA
    /// history (bounded sample size), fits the model (`spawn_blocking` —
    /// guidelines §10, the fit itself is CPU-bound), evaluates it on a
    /// holdout split against a naive baseline, and writes the verdict
    /// (`active` only if it beat baseline, else `failed_holdout`) plus the
    /// holdout report into `metrics`. Pure pointer, not a desired-state
    /// snapshot — the handler (`attome_predict::train::run`) re-reads the
    /// model's current `target`/`entity`/`features` fresh rather than
    /// replaying an enqueue-time payload, so an admin edit between enqueue
    /// and run takes effect. Enqueued in the same transaction as the model
    /// row insert (`POST /api/v1/admin/predict/models`) and dedup-keyed on
    /// the model id by the manual retrain endpoint
    /// (`POST .../models/{id}/train`).
    PredictTrainModel { model_id: Uuid },
    /// M36 Phase 1 — periodic sweep: scores every relevant live record
    /// (Phase 1: open tickets) against every `active` `prediction_model`
    /// whose entity matches, writing one `prediction` row per (model,
    /// record) and dual-writing the proposal half into M97's
    /// `outcome` ledger (`kind = 'prediction'`, direct bound SQL —
    /// see `attome_predict::score`'s doc comment for why this crate writes that
    /// table directly rather than depending on `attome-ai`). Bare unit
    /// variant, same re-derive-current-state shape as
    /// `EnsureAuditPartitions`/`WorkflowSlaSweep` — the handler
    /// (`attome_predict::score::run_scoring_sweep`) re-reads every currently
    /// active model and currently open ticket on every tick rather than
    /// replaying an enqueue-time snapshot.
    PredictScoringSweep,
    /// M36 Phase 1 — periodic sweep: for every `prediction` whose
    /// `horizon_at` has passed and whose `outcome_ref` is still unset,
    /// determines the actual outcome (did the ticket really breach its SLA)
    /// and writes ONE complete `outcome` row (`expected_value`,
    /// `actual_value`, `effectiveness`, and `measured_at` all in the same
    /// direct bound-SQL `INSERT` — see `0421_xrm_prediction.sql`'s
    /// `outcome_ref` doc comment for why this is a single write rather than
    /// a two-phase propose/measure dual-write like `attome_ai::outcome::
    /// record_proposed`/`record_measured`). Bare unit variant, same
    /// re-derive-current-state shape as `PredictScoringSweep` — the handler
    /// (`attome_predict::score::fill_outcomes`, in the same file as the scoring
    /// sweep above, not a separate `outcome_fill` module) re-scans the
    /// pending-horizon
    /// index on every tick rather than replaying an enqueue-time snapshot.
    PredictOutcomeFillSweep,
    /// M01 §7 C-04 — periodic sweep that deletes `entity_change_event`
    /// rows every registered consumer cursor has passed and that are older
    /// than `change_feed.retention_days`
    /// (`attome_core::change_feed::prune`, D-358's outbox — it had shipped
    /// with no caller at all, so the table grew unboundedly). Bare unit
    /// variant, same re-derive-current-config-not-enqueue-time-snapshot shape
    /// as `EnsureAuditPartitions`/`PruneApalisJobHistory`/
    /// `PruneIdempotencyRecords`: the handler
    /// (`server::jobs::prune_change_feed`) re-reads the retention floor and
    /// every registered cursor's current position on every tick, and
    /// `prune` itself runs in bounded, individually advisory-locked batches
    /// rather than one unbounded `DELETE` (see that function's doc comment)
    /// — the first run after this job ships can find years of unpruned
    /// history.
    PruneChangeFeed,
    /// Audit 10/10 plan item 2.6 (D-539 ruling 6) — computes, signs, stores
    /// and anchors the v1 cutover checkpoint for every organization that holds
    /// hash-version-1 audit rows and has none yet, and re-anchors an existing
    /// checkpoint whose anchor write failed. Bare unit variant, same
    /// re-derive-current-state shape as `EnsureAuditPartitions`: the handler
    /// (`attome_audit::checkpoint::run_v1_cutover_checkpoints`) defers an
    /// organization whose v1 set is not closed yet (pre-v2 ingest payloads
    /// still pending, or captured inside the quiet period) and is a no-op once
    /// every checkpoint exists, so the periodic tick is safe to repeat forever.
    AuditV1CutoverCheckpoint,

    /// attome-approval BAP-11b — carries out an approval request a policy
    /// step timeout auto-approved. Enqueued in the timeout's own transaction
    /// with the dedup key `approval-execute:{request_id}`. The handler runs the
    /// action only under its own D-518 execution claim, so a duplicate
    /// delivery, a manual `retry-execution` or a dead worker's leftover claim
    /// never dispatches it twice.
    ExecuteApprovedRequest { request_id: Uuid },

    /// D-792 (FLEET-CONSOLE-DESIGN.md §6.3) — the fleet console's periodic
    /// sync: probes every registered customer deployment, records the
    /// observation, notifies the developer once per new release report with
    /// open items (and on readiness changes), and re-arms the steps of the
    /// active rollout's waiting targets. Scheduled only inside the fleet
    /// console's gated boot path; a binary built without the
    /// `fleet-console` feature has no handler for it and fails the attempt.
    FleetPoll,

    /// D-792 (design §6.4) — drives one rollout target (`fleet_target`
    /// row) one step forward: plan it on the customer, or follow its apply
    /// through the customer's approval and ledger, then re-evaluates its
    /// wave. Enqueued dedup-keyed `fleet-rollout-step:<target_id>`; the
    /// handler re-reads the target row, so a duplicate or stale delivery
    /// does nothing.
    FleetRolloutStep { target_id: Uuid },

    /// Z7-T1 — a job of a type registered at run time in [`JOB_TYPES`]
    /// (`{name, version, payload}`), so an engine adds a job without a new
    /// variant here. Its queue, lane and attempts come from the registered
    /// [`attome_jobs::JobType`]; a name this worker has no handler for fails
    /// with `unknown_job_type` and ends in the dead letters.
    Registered(attome_jobs::RegisteredJob),
}

/// Z7-T1 — the job types registered at run time, each with its handler.
/// Filled by code at start-up on every node (server and worker alike); the
/// worker runs [`EngineJob::Registered`] through it.
pub static JOB_TYPES: attome_jobs::JobRegistry<crate::EngineState> =
    attome_jobs::JobRegistry::new();

/// The registered declaration of a [`EngineJob::Registered`] job, if its
/// type is registered on this node.
fn registered_type(job: &EngineJob) -> Option<attome_jobs::JobType> {
    match job {
        EngineJob::Registered(job) => JOB_TYPES.job_type(&job.name),
        _ => None,
    }
}

impl EngineJob {
    /// Routes this job onto the batch queue (`job_type = "attome_job_batch"`)
    /// instead of the default fast one — true only for variants that loop
    /// over an open-ended, record-count-proportional amount of work.
    /// Centralized here (rather than trusted per call site) so every
    /// `enqueue`/`enqueue_in_tx` caller gets correct routing automatically;
    /// see this module's top doc comment and D-165.
    ///
    /// BJB-1 (J6): both arms are spelled out — an exhaustive `match`, no
    /// wildcard — so a new variant cannot inherit a queue by omission. The
    /// previous `matches!` form compiled for a new variant without anyone
    /// deciding which queue it belongs on, and a batch-shaped variant that
    /// stayed on the fast queue starves every latency-sensitive job behind it.
    pub const fn is_batch(&self) -> bool {
        match self {
            // Record-count-proportional, open-ended work: one row can hold a
            // worker slot for an unbounded time.
            Self::BulkEntityOperation(_)
            | Self::ApplyStagedImport(_)
            | Self::RewrapSecrets { .. }
            | Self::ApplySchemaChangePlan { .. }
            | Self::ApplyMetadataBundle { .. }
            | Self::ApplyChangesets { .. }
            | Self::RunDataStep { .. }
            | Self::CrawlWebsite { .. }
            | Self::SalesDefaultTeamApply { .. }
            | Self::SalesScheduleShift { .. }
            | Self::SalesCallOutcomeRules { .. }
            | Self::AiFollowupRuleRun { .. }
            | Self::CommissionRun { .. }
            | Self::CommissionRecalcPreview { .. }
            | Self::CascadeDeactivateDependents { .. }
            | Self::DataExport(_)
            | Self::DataProfile(_)
            | Self::DataBulkTransform(_)
            | Self::RollbackMigrationRun { .. }
            | Self::ReportRun { .. }
            | Self::LegalMatterCollect { .. }
            | Self::LegalMatterRelease { .. }
            | Self::DataMatchScan { .. } => true,

            // Everything else: bounded work, latency-sensitive, or cheap.
            Self::SendEmail(_)
            | Self::EnsureAuditPartitions
            | Self::PruneNotificationRecipientPartitions
            | Self::FanOutNotification { .. }
            | Self::BackfillRecipientForNewUser { .. }
            | Self::BuildAttributeIndex { .. }
            | Self::BuildBusinessKeyIndex { .. }
            | Self::ScanUploadedFile { .. }
            | Self::DocumentTextExtract { .. }
            | Self::PruneExpiredUploadSessions
            | Self::PruneApalisJobHistory
            | Self::RevalidateQueryPlans
            | Self::TrigramIndexSweep
            | Self::ProposeRetentionActions
            | Self::ExecuteRetentionAction { .. }
            | Self::PruneIdempotencyRecords
            | Self::PruneAuthTokens
            | Self::PruneRecoveryArchive
            | Self::RevalidateFieldSecurityProfiles
            | Self::WorkflowExecute { .. }
            | Self::TimerFire { .. }
            | Self::ReportScheduleFire { .. }
            | Self::ValidationCleanupScan { .. }
            | Self::WorkflowSlaSweep
            | Self::WorkflowEntityTriggerDispatch
            | Self::ComputeMetricSnapshots
            | Self::EventsDispatchTick
            | Self::EventsDeliverWebhook { .. }
            | Self::AiQualityMonitor
            | Self::AiToolCallSweep
            | Self::BinDeleteAlertSweep
            | Self::TagExpirySweep
            | Self::ContractKeyDates
            | Self::ContractCounterpartyMatch
            | Self::RecurringTaskRoll
            | Self::ContractLinkSweep
            | Self::BillingRenewalSweep
            | Self::BillingGenerateCharges
            | Self::BillingHandoffSweep
            | Self::PointsScoring
            | Self::DealRiskEvaluation
            | Self::ForecastRecompute
            | Self::MrrSnapshot
            | Self::WebcrawlRecrawlDue
            | Self::TimerSweep
            | Self::MarketingNightly
            | Self::SegmentRefreshDue
            | Self::MarketingSweep
            | Self::RoleGrantExpiry
            | Self::SalesDefaultTeamSweep
            | Self::CommissionCreditSweep
            | Self::BillingRequestSweep
            | Self::BillingScheduleRun
            | Self::BillingOverdueSweep
            | Self::BillingChargeDue
            | Self::BillingReconcile
            | Self::BillingEinvoiceSweep
            | Self::BillingGatewayEventApply
            | Self::SalesSnapshotPrune
            | Self::NotificationFollowSweep
            | Self::SalesDealCloseSweep
            | Self::SalesLeaverSweep
            | Self::AiFollowupScan
            | Self::AiFollowupItem { .. }
            | Self::TableHealthSample
            | Self::AuditChainVerify
            | Self::UploadRescanSweep
            | Self::SloMonthlyReport
            | Self::SloBurnCheck
            | Self::PerfRegressionCheck
            | Self::LimitWarningCheck
            | Self::SalesMentionScan
            | Self::AccessReviewCampaignSweep
            | Self::DataMatchSweep
            | Self::ApiUsageRollup
            | Self::ContentScheduledPublishSweep
            | Self::DataQualityScoreSweep
            | Self::ReportScheduleSweep
            | Self::AiDeferredActionSweep
            | Self::AiAutonomySummary
            | Self::LicenseExpiryCheck
            | Self::FailedLoginSweep
            | Self::SearchSuggestionRefresh
            | Self::SearchSavedSearchAlertSweep
            | Self::ContentPageStatsRollup
            | Self::ContentReviewReminderSweep
            | Self::CatalogLineageBackfill
            | Self::CatalogDashboardLineageSweep
            | Self::CatalogUsageRollup
            | Self::ValidationScoreSweep
            | Self::PruneExpiredMemories
            | Self::ProcessExtractionSweep
            | Self::WorkQueueEscalationSweep
            | Self::TicketSlaSweep
            | Self::ResourceUtilizationSweep
            | Self::DocgenRender { .. }
            | Self::BillingExecuteRun { .. }
            | Self::ContentArticleIndex { .. }
            | Self::TranscribeRecording { .. }
            | Self::PredictTrainModel { .. }
            | Self::PredictScoringSweep
            | Self::PredictOutcomeFillSweep
            | Self::PruneChangeFeed
            | Self::AuditV1CutoverCheckpoint
            | Self::ExecuteApprovedRequest { .. }
            | Self::FleetPoll
            | Self::BillingAfterIssue { .. }
            | Self::BillingExecuteRefund { .. }
            | Self::FleetRolloutStep { .. } => false,
            // Decided by its registered type in the `Job` impl below.
            Self::Registered(_) => false,
        }
    }
}

impl EngineJob {
    /// The externally-tagged JSON tag serde already uses for this variant —
    /// duplicated here as a plain string (not derived from serde) so
    /// `JobEnvelope`'s envelope can carry it as a value and check it
    /// against a known list *before* attempting the full payload decode (see
    /// that type's doc comment). Exhaustive, no wildcard arm, so a new
    /// variant forces this to be updated in the same change as every other
    /// per-variant method below.
    pub fn variant_name(&self) -> &'static str {
        match self {
            EngineJob::SendEmail(_) => "SendEmail",
            EngineJob::EnsureAuditPartitions => "EnsureAuditPartitions",
            EngineJob::PruneNotificationRecipientPartitions => {
                "PruneNotificationRecipientPartitions"
            }
            EngineJob::FanOutNotification { .. } => "FanOutNotification",
            EngineJob::BackfillRecipientForNewUser { .. } => "BackfillRecipientForNewUser",
            EngineJob::BuildAttributeIndex { .. } => "BuildAttributeIndex",
            EngineJob::BuildBusinessKeyIndex { .. } => "BuildBusinessKeyIndex",
            EngineJob::BulkEntityOperation(_) => "BulkEntityOperation",
            EngineJob::ApplyStagedImport(_) => "ApplyStagedImport",
            EngineJob::RewrapSecrets { .. } => "RewrapSecrets",
            EngineJob::ScanUploadedFile { .. } => "ScanUploadedFile",
            EngineJob::DocumentTextExtract { .. } => "DocumentTextExtract",
            EngineJob::PruneExpiredUploadSessions => "PruneExpiredUploadSessions",
            EngineJob::PruneApalisJobHistory => "PruneApalisJobHistory",
            EngineJob::RevalidateQueryPlans => "RevalidateQueryPlans",
            EngineJob::TrigramIndexSweep => "TrigramIndexSweep",
            EngineJob::ProposeRetentionActions => "ProposeRetentionActions",
            EngineJob::ExecuteRetentionAction { .. } => "ExecuteRetentionAction",
            EngineJob::PruneIdempotencyRecords => "PruneIdempotencyRecords",
            EngineJob::PruneAuthTokens => "PruneAuthTokens",
            EngineJob::ApplySchemaChangePlan { .. } => "ApplySchemaChangePlan",
            EngineJob::ApplyMetadataBundle { .. } => "ApplyMetadataBundle",
            EngineJob::ApplyChangesets { .. } => "ApplyChangesets",
            EngineJob::RunDataStep { .. } => "RunDataStep",
            EngineJob::PruneRecoveryArchive => "PruneRecoveryArchive",
            EngineJob::RevalidateFieldSecurityProfiles => "RevalidateFieldSecurityProfiles",
            EngineJob::WorkflowExecute { .. } => "WorkflowExecute",
            EngineJob::WorkflowSlaSweep => "WorkflowSlaSweep",
            EngineJob::WorkflowEntityTriggerDispatch => "WorkflowEntityTriggerDispatch",
            EngineJob::CrawlWebsite { .. } => "CrawlWebsite",
            EngineJob::SalesDefaultTeamApply { .. } => "SalesDefaultTeamApply",
            EngineJob::SalesScheduleShift { .. } => "SalesScheduleShift",
            EngineJob::SalesCallOutcomeRules { .. } => "SalesCallOutcomeRules",
            EngineJob::AiFollowupRuleRun { .. } => "AiFollowupRuleRun",
            EngineJob::CommissionRun { .. } => "CommissionRun",
            EngineJob::CommissionRecalcPreview { .. } => "CommissionRecalcPreview",
            EngineJob::BillingAfterIssue { .. } => "BillingAfterIssue",
            EngineJob::BillingExecuteRefund { .. } => "BillingExecuteRefund",
            EngineJob::CascadeDeactivateDependents { .. } => "CascadeDeactivateDependents",
            EngineJob::ComputeMetricSnapshots => "ComputeMetricSnapshots",
            EngineJob::EventsDispatchTick => "EventsDispatchTick",
            EngineJob::EventsDeliverWebhook { .. } => "EventsDeliverWebhook",
            EngineJob::DataExport(_) => "DataExport",
            EngineJob::DataProfile(_) => "DataProfile",
            EngineJob::DataBulkTransform(_) => "DataBulkTransform",
            EngineJob::AiQualityMonitor => "AiQualityMonitor",
            EngineJob::AiToolCallSweep => "AiToolCallSweep",
            EngineJob::BinDeleteAlertSweep => "BinDeleteAlertSweep",
            EngineJob::TagExpirySweep => "TagExpirySweep",
            EngineJob::ContractKeyDates => "ContractKeyDates",
            EngineJob::ContractCounterpartyMatch => "ContractCounterpartyMatch",
            EngineJob::RecurringTaskRoll => "RecurringTaskRoll",
            EngineJob::ContractLinkSweep => "ContractLinkSweep",
            EngineJob::BillingHandoffSweep => "BillingHandoffSweep",
            EngineJob::BillingRenewalSweep => "BillingRenewalSweep",
            EngineJob::BillingGenerateCharges => "BillingGenerateCharges",
            EngineJob::PointsScoring => "PointsScoring",
            EngineJob::DealRiskEvaluation => "DealRiskEvaluation",
            EngineJob::ForecastRecompute => "ForecastRecompute",
            EngineJob::MrrSnapshot => "MrrSnapshot",
            EngineJob::WebcrawlRecrawlDue => "WebcrawlRecrawlDue",
            EngineJob::TimerSweep => "TimerSweep",
            EngineJob::TimerFire { .. } => "TimerFire",
            EngineJob::ReportScheduleFire { .. } => "ReportScheduleFire",
            EngineJob::ValidationCleanupScan { .. } => "ValidationCleanupScan",
            EngineJob::MarketingNightly => "MarketingNightly",
            EngineJob::SegmentRefreshDue => "SegmentRefreshDue",
            EngineJob::MarketingSweep => "MarketingSweep",
            EngineJob::RoleGrantExpiry => "RoleGrantExpiry",
            EngineJob::SalesDefaultTeamSweep => "SalesDefaultTeamSweep",
            EngineJob::CommissionCreditSweep => "CommissionCreditSweep",
            EngineJob::BillingRequestSweep => "BillingRequestSweep",
            EngineJob::BillingScheduleRun => "BillingScheduleRun",
            EngineJob::BillingOverdueSweep => "BillingOverdueSweep",
            EngineJob::BillingChargeDue => "BillingChargeDue",
            EngineJob::BillingReconcile => "BillingReconcile",
            EngineJob::BillingEinvoiceSweep => "BillingEinvoiceSweep",
            EngineJob::BillingGatewayEventApply => "BillingGatewayEventApply",
            EngineJob::SalesSnapshotPrune => "SalesSnapshotPrune",
            EngineJob::NotificationFollowSweep => "NotificationFollowSweep",
            EngineJob::SalesDealCloseSweep => "SalesDealCloseSweep",
            EngineJob::SalesLeaverSweep => "SalesLeaverSweep",
            EngineJob::AiFollowupScan => "AiFollowupScan",
            EngineJob::AiFollowupItem { .. } => "AiFollowupItem",
            EngineJob::TableHealthSample => "TableHealthSample",
            EngineJob::AuditChainVerify => "AuditChainVerify",
            EngineJob::UploadRescanSweep => "UploadRescanSweep",
            EngineJob::SloMonthlyReport => "SloMonthlyReport",
            EngineJob::SloBurnCheck => "SloBurnCheck",
            EngineJob::PerfRegressionCheck => "PerfRegressionCheck",
            EngineJob::LimitWarningCheck => "LimitWarningCheck",
            EngineJob::SalesMentionScan => "SalesMentionScan",
            EngineJob::AccessReviewCampaignSweep => "AccessReviewCampaignSweep",
            EngineJob::RollbackMigrationRun { .. } => "RollbackMigrationRun",
            EngineJob::DataMatchSweep => "DataMatchSweep",
            EngineJob::DataMatchScan { .. } => "DataMatchScan",
            EngineJob::ApiUsageRollup => "ApiUsageRollup",
            EngineJob::ContentScheduledPublishSweep => "ContentScheduledPublishSweep",
            EngineJob::DataQualityScoreSweep => "DataQualityScoreSweep",
            EngineJob::ReportRun { .. } => "ReportRun",
            EngineJob::ReportScheduleSweep => "ReportScheduleSweep",
            EngineJob::AiDeferredActionSweep => "AiDeferredActionSweep",
            EngineJob::AiAutonomySummary => "AiAutonomySummary",
            EngineJob::LegalMatterCollect { .. } => "LegalMatterCollect",
            EngineJob::LegalMatterRelease { .. } => "LegalMatterRelease",
            EngineJob::LicenseExpiryCheck => "LicenseExpiryCheck",
            EngineJob::FailedLoginSweep => "FailedLoginSweep",
            EngineJob::SearchSuggestionRefresh => "SearchSuggestionRefresh",
            EngineJob::SearchSavedSearchAlertSweep => "SearchSavedSearchAlertSweep",
            EngineJob::ContentPageStatsRollup => "ContentPageStatsRollup",
            EngineJob::ContentReviewReminderSweep => "ContentReviewReminderSweep",
            EngineJob::PruneExpiredMemories => "PruneExpiredMemories",
            EngineJob::ProcessExtractionSweep => "ProcessExtractionSweep",
            EngineJob::WorkQueueEscalationSweep => "WorkQueueEscalationSweep",
            EngineJob::TicketSlaSweep => "TicketSlaSweep",
            EngineJob::ResourceUtilizationSweep => "ResourceUtilizationSweep",
            EngineJob::CatalogLineageBackfill => "CatalogLineageBackfill",
            EngineJob::CatalogDashboardLineageSweep => "CatalogDashboardLineageSweep",
            EngineJob::CatalogUsageRollup => "CatalogUsageRollup",
            EngineJob::ValidationScoreSweep => "ValidationScoreSweep",
            EngineJob::DocgenRender { .. } => "DocgenRender",
            EngineJob::BillingExecuteRun { .. } => "BillingExecuteRun",
            EngineJob::ContentArticleIndex { .. } => "ContentArticleIndex",
            EngineJob::TranscribeRecording { .. } => "TranscribeRecording",
            EngineJob::PredictTrainModel { .. } => "PredictTrainModel",
            EngineJob::PredictScoringSweep => "PredictScoringSweep",
            EngineJob::PredictOutcomeFillSweep => "PredictOutcomeFillSweep",
            EngineJob::PruneChangeFeed => "PruneChangeFeed",
            EngineJob::AuditV1CutoverCheckpoint => "AuditV1CutoverCheckpoint",
            EngineJob::ExecuteApprovedRequest { .. } => "ExecuteApprovedRequest",
            EngineJob::FleetPoll => "FleetPoll",
            EngineJob::FleetRolloutStep { .. } => "FleetRolloutStep",
            EngineJob::Registered(_) => "Registered",
        }
    }
}

impl EngineJob {
    /// M08 checklist item 1 (priority lanes) — which [`JobPriority`] lane
    /// this variant enqueues into. Exhaustive, no wildcard arm, same
    /// discipline as [`Self::variant_name`]: a new variant forces a
    /// deliberate classification here rather than silently inheriting
    /// `Normal`.
    ///
    /// Classification: `High` when a human is waiting on the outcome or
    /// another system has a delivery SLA; `Low` for periodic maintenance/
    /// sweep work nobody observes directly; `Normal` (apalis's own default)
    /// for background work that is neither.
    pub const fn priority(&self) -> JobPriority {
        match self {
            // High — a human or an external SLA is waiting on this outcome.
            Self::SendEmail(_)
            | Self::ScanUploadedFile { .. }
            | Self::DocumentTextExtract { .. }
            | Self::WorkflowExecute { .. }
            | Self::TimerFire { .. }
            | Self::ReportScheduleFire { .. }
            | Self::ValidationCleanupScan { .. }
            | Self::FanOutNotification { .. }
            | Self::BackfillRecipientForNewUser { .. }
            | Self::EventsDeliverWebhook { .. }
            | Self::ExecuteRetentionAction { .. }
            | Self::ExecuteApprovedRequest { .. }
            | Self::RollbackMigrationRun { .. }
            | Self::CascadeDeactivateDependents { .. }
            | Self::ApplyStagedImport(_)
            | Self::BulkEntityOperation(_)
            | Self::DataExport(_)
            | Self::DataProfile(_)
            | Self::DataBulkTransform(_)
            | Self::ApplySchemaChangePlan { .. }
            | Self::ApplyMetadataBundle { .. }
            | Self::ApplyChangesets { .. }
            | Self::RunDataStep { .. }
            | Self::ReportRun { .. }
            | Self::LegalMatterCollect { .. }
            | Self::LegalMatterRelease { .. }
            | Self::DocgenRender { .. }
            | Self::BillingExecuteRun { .. }
            | Self::ContentArticleIndex { .. }
            | Self::TranscribeRecording { .. }
            | Self::PredictTrainModel { .. } => JobPriority::High,

            // Low — periodic maintenance/sweep work with no observer.
            Self::EnsureAuditPartitions
            | Self::PruneNotificationRecipientPartitions
            | Self::PruneExpiredUploadSessions
            | Self::PruneApalisJobHistory
            | Self::RevalidateQueryPlans
            | Self::TrigramIndexSweep
            | Self::ProposeRetentionActions
            | Self::PruneIdempotencyRecords
            | Self::PruneAuthTokens
            | Self::PruneRecoveryArchive
            | Self::RevalidateFieldSecurityProfiles
            | Self::WorkflowSlaSweep
            | Self::WorkflowEntityTriggerDispatch
            | Self::ComputeMetricSnapshots
            | Self::EventsDispatchTick
            | Self::AiQualityMonitor
            | Self::AiToolCallSweep
            | Self::BinDeleteAlertSweep
            | Self::TagExpirySweep
            | Self::ContractKeyDates
            | Self::ContractCounterpartyMatch
            | Self::RecurringTaskRoll
            | Self::ContractLinkSweep
            | Self::BillingRenewalSweep
            | Self::BillingGenerateCharges
            | Self::BillingHandoffSweep
            | Self::PointsScoring
            | Self::DealRiskEvaluation
            | Self::ForecastRecompute
            | Self::MrrSnapshot
            | Self::WebcrawlRecrawlDue
            | Self::TimerSweep
            | Self::MarketingNightly
            | Self::SegmentRefreshDue
            | Self::MarketingSweep
            | Self::RoleGrantExpiry
            | Self::SalesDefaultTeamSweep
            | Self::CommissionCreditSweep
            | Self::BillingRequestSweep
            | Self::BillingScheduleRun
            | Self::BillingOverdueSweep
            | Self::BillingChargeDue
            | Self::BillingReconcile
            | Self::BillingEinvoiceSweep
            | Self::SalesSnapshotPrune
            | Self::NotificationFollowSweep
            | Self::SalesDealCloseSweep
            | Self::SalesLeaverSweep
            | Self::AiFollowupScan
            | Self::AiFollowupItem { .. }
            | Self::TableHealthSample
            | Self::AuditChainVerify
            | Self::UploadRescanSweep
            | Self::SloMonthlyReport
            | Self::SloBurnCheck
            | Self::PerfRegressionCheck
            | Self::LimitWarningCheck
            | Self::SalesMentionScan
            | Self::AccessReviewCampaignSweep
            | Self::DataMatchSweep
            | Self::DataMatchScan { .. }
            | Self::ApiUsageRollup
            | Self::ContentScheduledPublishSweep
            | Self::DataQualityScoreSweep
            | Self::ReportScheduleSweep
            | Self::AiDeferredActionSweep
            | Self::AiAutonomySummary
            | Self::LicenseExpiryCheck
            | Self::FailedLoginSweep
            | Self::SearchSuggestionRefresh
            | Self::SearchSavedSearchAlertSweep
            | Self::ContentPageStatsRollup
            | Self::ContentReviewReminderSweep
            | Self::PruneExpiredMemories
            | Self::ProcessExtractionSweep
            | Self::WorkQueueEscalationSweep
            | Self::TicketSlaSweep
            | Self::ResourceUtilizationSweep
            | Self::CatalogLineageBackfill
            | Self::CatalogDashboardLineageSweep
            | Self::CatalogUsageRollup
            | Self::ValidationScoreSweep
            | Self::PredictScoringSweep
            | Self::PredictOutcomeFillSweep
            | Self::PruneChangeFeed
            | Self::AuditV1CutoverCheckpoint
            | Self::BuildAttributeIndex { .. }
            | Self::BuildBusinessKeyIndex { .. }
            | Self::FleetPoll => JobPriority::Low,

            // Normal — background work that is neither urgent nor idle
            // maintenance.
            Self::RewrapSecrets { .. }
            | Self::CrawlWebsite { .. }
            | Self::SalesDefaultTeamApply { .. }
            | Self::SalesScheduleShift { .. }
            | Self::SalesCallOutcomeRules { .. }
            | Self::AiFollowupRuleRun { .. }
            | Self::CommissionRun { .. }
            | Self::CommissionRecalcPreview { .. }
            | Self::BillingAfterIssue { .. }
            | Self::BillingExecuteRefund { .. }
            | Self::BillingGatewayEventApply
            | Self::FleetRolloutStep { .. } => JobPriority::Normal,
            // Decided by its registered type in the `Job` impl below.
            Self::Registered(_) => JobPriority::Normal,
        }
    }
}

impl EngineJob {
    /// BJB-2 (J3) — the retry budget this kind is allowed, declared once here
    /// and bound on **every** enqueue path
    /// (`attome_jobs::enqueue`/`enqueue_in_tx`/`enqueue_dedup`/
    /// `enqueue_in_tx_dedup`). Before BJB-2 the budget was an accident of the
    /// enqueue function — 5 (apalis-sql `SqlContext::new`'s default) through
    /// `enqueue`, 25 (`apalis.push_job`'s SQL parameter default) through the
    /// other three — so the same kind could be retried 5 or 25 times depending
    /// on which producer enqueued it (BJB-F3).
    ///
    /// The classification (BJB-D2, owner-delegated default; revisit with 30
    /// days of dead-letter data):
    ///
    /// - **5** — destructive or one-shot: replaying a partially-applied run is
    ///   worse than dead-lettering it for an operator.
    /// - **3** — periodic sweeps: a lost attempt is not lost work, because the
    ///   next scheduled slot re-runs the same re-derive-current-state job. The
    ///   set is exactly the kinds a `spawn_*_scheduler` in
    ///   `crates/server/src/jobs.rs` enqueues — an objective criterion, not a
    ///   judgement per kind; a kind that becomes scheduled should move here
    ///   when it does.
    /// - **8** — `SendEmail` (a reset/verification link is worth retrying for
    ///   roughly 40 minutes but not for hours) and `EventsDeliverWebhook`
    ///   (delivery has its own ledger policy; 8 is this queue's ceiling for
    ///   it).
    /// - **10** — everything else, including the four kinds whose real budget
    ///   was previously 5 by accident (`WorkflowExecute`,
    ///   `FanOutNotification`, `BackfillRecipientForNewUser`).
    ///
    /// Exhaustive, no wildcard arm — a new variant must be classified here in
    /// the same change that adds it (success criterion 2).
    pub const fn max_attempts(&self) -> i32 {
        match self {
            // Destructive / one-shot: never replay automatically past a
            // handful of transient-failure attempts.
            Self::ExecuteRetentionAction { .. }
            | Self::RewrapSecrets { .. }
            | Self::ApplyMetadataBundle { .. }
            | Self::ApplyChangesets { .. }
            | Self::RunDataStep { .. }
            | Self::ApplySchemaChangePlan { .. }
            | Self::LegalMatterCollect { .. }
            | Self::LegalMatterRelease { .. }
            | Self::RollbackMigrationRun { .. }
            // BAP-11b: an executor error releases the claim so the next
            // attempt may claim again; five bounds that.
            | Self::ExecuteApprovedRequest { .. }
            // D-792: one remote plan call per target; the next FleetPoll
            // re-arms a target still waiting, so a short budget suffices.
            | Self::FleetRolloutStep { .. } => 5,

            // Periodic sweeps — the kinds the schedulers in
            // `crates/server/src/jobs.rs` enqueue. The next slot is the retry.
            Self::EnsureAuditPartitions
            | Self::PruneNotificationRecipientPartitions
            | Self::PruneExpiredUploadSessions
            | Self::PruneApalisJobHistory
            | Self::RevalidateQueryPlans
            | Self::TrigramIndexSweep
            | Self::ProposeRetentionActions
            | Self::PruneIdempotencyRecords
            | Self::PruneAuthTokens
            | Self::PruneRecoveryArchive
            | Self::RevalidateFieldSecurityProfiles
            | Self::WorkflowSlaSweep
            | Self::WorkflowEntityTriggerDispatch
            | Self::ComputeMetricSnapshots
            | Self::EventsDispatchTick
            | Self::AiQualityMonitor
            | Self::AiToolCallSweep
            | Self::BinDeleteAlertSweep
            | Self::TagExpirySweep
            | Self::ContractKeyDates
            | Self::ContractCounterpartyMatch
            | Self::RecurringTaskRoll
            | Self::ContractLinkSweep
            | Self::BillingRenewalSweep
            | Self::BillingGenerateCharges
            | Self::BillingHandoffSweep
            | Self::PointsScoring
            | Self::DealRiskEvaluation
            | Self::ForecastRecompute
            | Self::MrrSnapshot
            | Self::WebcrawlRecrawlDue
            | Self::TimerSweep
            | Self::MarketingNightly
            | Self::SegmentRefreshDue
            | Self::MarketingSweep
            | Self::RoleGrantExpiry
            | Self::SalesDefaultTeamSweep
            | Self::CommissionCreditSweep
            | Self::BillingRequestSweep
            | Self::BillingScheduleRun
            | Self::BillingOverdueSweep
            | Self::BillingChargeDue
            | Self::BillingReconcile
            | Self::BillingEinvoiceSweep
            | Self::BillingGatewayEventApply
            | Self::SalesSnapshotPrune
            | Self::NotificationFollowSweep
            | Self::SalesDealCloseSweep
            | Self::SalesLeaverSweep
            | Self::AiFollowupScan
            | Self::AiFollowupItem { .. }
            | Self::TableHealthSample
            | Self::AuditChainVerify
            | Self::UploadRescanSweep
            | Self::SloMonthlyReport
            | Self::SloBurnCheck
            | Self::PerfRegressionCheck
            | Self::LimitWarningCheck
            | Self::SalesMentionScan
            | Self::AccessReviewCampaignSweep
            | Self::DataMatchSweep
            | Self::ApiUsageRollup
            | Self::ContentScheduledPublishSweep
            | Self::DataQualityScoreSweep
            | Self::ReportScheduleSweep
            | Self::AiDeferredActionSweep
            | Self::AiAutonomySummary
            | Self::LicenseExpiryCheck
            | Self::FailedLoginSweep
            | Self::SearchSuggestionRefresh
            | Self::SearchSavedSearchAlertSweep
            | Self::ContentPageStatsRollup
            | Self::ContentReviewReminderSweep
            | Self::PruneExpiredMemories
            | Self::ProcessExtractionSweep
            | Self::WorkQueueEscalationSweep
            | Self::TicketSlaSweep
            | Self::ResourceUtilizationSweep
            | Self::CatalogLineageBackfill
            | Self::CatalogDashboardLineageSweep
            | Self::CatalogUsageRollup
            | Self::ValidationScoreSweep
            | Self::PredictScoringSweep
            | Self::PredictOutcomeFillSweep
            | Self::PruneChangeFeed
            | Self::AuditV1CutoverCheckpoint
            | Self::FleetPoll => 3,

            // 8 — bounded but human-visible delivery.
            Self::SendEmail(_) | Self::EventsDeliverWebhook { .. } => 8,

            // 10 — everything else.
            Self::FanOutNotification { .. }
            | Self::BackfillRecipientForNewUser { .. }
            | Self::BuildAttributeIndex { .. }
            | Self::BuildBusinessKeyIndex { .. }
            | Self::DataMatchScan { .. }
            | Self::BulkEntityOperation(_)
            | Self::ApplyStagedImport(_)
            | Self::ScanUploadedFile { .. }
            | Self::DocumentTextExtract { .. }
            | Self::WorkflowExecute { .. }
            | Self::TimerFire { .. }
            | Self::ReportScheduleFire { .. }
            | Self::ValidationCleanupScan { .. }
            | Self::CrawlWebsite { .. }
            | Self::SalesDefaultTeamApply { .. }
            | Self::SalesScheduleShift { .. }
            | Self::SalesCallOutcomeRules { .. }
            | Self::AiFollowupRuleRun { .. }
            | Self::CommissionRun { .. }
            | Self::CommissionRecalcPreview { .. }
            | Self::BillingAfterIssue { .. }
            | Self::BillingExecuteRefund { .. }
            | Self::CascadeDeactivateDependents { .. }
            | Self::DataExport(_)
            | Self::DataProfile(_)
            | Self::DataBulkTransform(_)
            | Self::ReportRun { .. }
            | Self::DocgenRender { .. }
            | Self::BillingExecuteRun { .. }
            | Self::ContentArticleIndex { .. }
            | Self::TranscribeRecording { .. }
            | Self::PredictTrainModel { .. } => 10,
            // Decided by its registered type in the `Job` impl below; 5 when
            // the type is not registered on the producing node.
            Self::Registered(_) => 5,
        }
    }
}

/// See `EngineJob::BulkEntityOperation`'s doc comment for why this is pure
/// JSON rather than typed `xrm-*` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkEntityOperationPayload {
    pub bulk_op_id: Uuid,
    pub entity_logicalname: String,
    /// `"create"`, `"update"`, or `"delete"` — mirrors
    /// `automation_bulk_operation.operation`'s own CHECK constraint; validated at
    /// enqueue time and revalidated by the worker before each item.
    pub operation: String,
    /// One JSON mutation envelope per record: `{ id?, expected_row_version?,
    /// data }`. Update/delete require both `id` and `expected_row_version`;
    /// create requires neither. The xrm worker validates the envelope again
    /// before mutating the entity table.
    pub records: Vec<serde_json::Value>,
    pub user_id: Uuid,
}

/// See `EngineJob::ApplyStagedImport`'s doc comment. `records` mirrors
/// `BulkEntityOperationPayload::records` (the approved staged import's own
/// raw records, re-read from `automation_staged_import.raw_records` at approval
/// time so the payload reflects what was actually reviewed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyStagedImportPayload {
    pub import_id: Uuid,
    pub entity_logicalname: String,
    pub operation: String,
    pub records: Vec<serde_json::Value>,
    pub user_id: Uuid,
}

/// M12 (data management) — a permission-filtered record export. Pure JSON,
/// same reasoning as `BulkEntityOperationPayload`: `attome-jobs` cannot depend
/// on `attome-core`'s `Filter` type, so `filters` carries its wire shape
/// as opaque `Value`s and the xrm worker (`attome_server::data_export::process`)
/// decodes them. `columns` is the caller's requested projection *before*
/// field-security filtering — the worker re-derives the caller's actual
/// grants from `user_id` at process time rather than trusting a
/// enqueue-time snapshot of which columns were visible, the same
/// re-authorize-in-the-worker discipline `bulk::process` already follows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataExportPayload {
    pub export_id: Uuid,
    pub entity_logicalname: String,
    /// `"csv"`, `"xlsx"`, or `"json"` — mirrors `data_export.format`'s
    /// CHECK constraint; validated again by the worker.
    pub format: String,
    pub columns: Vec<String>,
    pub filters: Vec<serde_json::Value>,
    pub user_id: Uuid,
}

/// M12 — `POST /admin/data/profile` background job: null %, distinct counts,
/// min/max, and pattern samples per field, written to
/// `data_profile`. Bare pointer, not a desired-state snapshot — same
/// re-derive-current-metadata shape as `BuildAttributeIndex`: the worker
/// re-reads the entity's live attributes rather than trusting an
/// enqueue-time list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataProfilePayload {
    pub profile_id: Uuid,
    pub entity_logicalname: String,
    pub user_id: Uuid,
}

/// M12 — applies one fixed built-in transform (`trim`/`upper`/`lower`/
/// `set_to_value`) to one field across a bounded, dry-run-confirmed set of
/// records. `record_ids` is the frozen candidate set captured at enqueue
/// time (mirrors `ApplySchemaChangePlan`'s "the ledger row is the frozen
/// intent" convention) — the worker's own item ledger
/// (`bulk_transform_operation_item`) makes re-processing idempotent on
/// retry, same as `BulkEntityOperationPayload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataBulkTransformPayload {
    pub operation_id: Uuid,
    pub entity_logicalname: String,
    pub field_logicalname: String,
    /// `"trim"`, `"upper"`, `"lower"`, or `"set_to_value"`.
    pub transform: String,
    /// Only meaningful for `"set_to_value"`.
    pub value: Option<String>,
    pub record_ids: Vec<Uuid>,
    pub user_id: Uuid,
}

/// `EngineJob` is stored as JSONB in `apalis.jobs.job` (`PostgresStorage`) —
/// a variant that fails to round-trip through serde would corrupt the queue
/// (a job enqueued today, unreadable by tomorrow's binary, or vice versa on a
/// rolling deploy). These tests pin the shape of every variant so a
/// `#[derive]`-affecting change (a field rename, a newtype vs. struct variant
/// swap) is caught here instead of in production `apalis.jobs`.
impl attome_jobs::Job for EngineJob {
    fn kind(&self) -> &'static str {
        self.variant_name()
    }

    fn is_batch(&self) -> bool {
        registered_type(self).map_or_else(
            || EngineJob::is_batch(self),
            |job_type| job_type.lane == attome_jobs::Lane::Batch,
        )
    }

    fn priority(&self) -> JobPriority {
        registered_type(self)
            .map_or_else(|| EngineJob::priority(self), |job_type| job_type.priority)
    }

    fn max_attempts(&self) -> i32 {
        registered_type(self).map_or_else(
            || EngineJob::max_attempts(self),
            |job_type| job_type.max_attempts,
        )
    }

    /// Z7-T3: a clean-up scan reads a rule's whole entity table (A3-T5); a
    /// burst of publishes runs at most two at a time.
    fn concurrency_caps() -> &'static [(&'static str, i32)] {
        &[("ValidationCleanupScan", 2)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_round_trips(job: EngineJob) {
        let json = serde_json::to_string(&job).expect("serialize EngineJob");
        let back: EngineJob =
            serde_json::from_str(&json).expect("deserialize EngineJob from its own JSON");
        // EngineJob has no PartialEq (its SendEmail payload doesn't derive it
        // either) — re-serializing the round-tripped value and comparing bytes
        // is an equivalent, dependency-free equality check.
        let json_again = serde_json::to_string(&back).expect("re-serialize round-tripped job");
        assert_eq!(json, json_again, "round trip must be lossless: {json}");
    }

    #[test]
    fn send_email_round_trips() {
        assert_round_trips(EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: "user@example.invalid".to_string(),
            subject: "Verify your email".to_string(),
            text_body: "click the link".to_string(),
            html_body: Some("<p>click the link</p>".to_string()),
            delivery_id: Some(Uuid::now_v7()),
            from_override: Some("Notifications <notify@example.invalid>".to_string()),
            message_id: Some("<msg-1@example.invalid>".to_string()),
            in_reply_to: None,
            references: None,
            communication_id: Some(Uuid::now_v7()),
            attachments: Vec::new(),
        })));
    }

    #[test]
    fn send_email_round_trips_without_an_html_body_or_delivery_id() {
        assert_round_trips(EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: "user@example.invalid".to_string(),
            subject: "Verify your email".to_string(),
            text_body: "click the link".to_string(),
            html_body: None,
            delivery_id: None,
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
        })));
    }

    /// P-email-hardening: a job enqueued by a binary older than
    /// `delivery_id`'s introduction must still deserialize (as `None`) —
    /// `#[serde(default)]` on the field, no `JobEnvelope` version
    /// bump needed.
    #[test]
    fn send_email_accepts_the_legacy_pre_delivery_id_json_shape() {
        let legacy = serde_json::json!({
            "SendEmail": {
                "to": "user@example.invalid",
                "subject": "Verify your email",
                "text_body": "click the link",
                "html_body": null
            }
        });
        let decoded: EngineJob = serde_json::from_value(legacy).unwrap();
        // `msg` is `Box<EmailMessage>` (this crate's own `large_enum_variant`
        // fix, see `EngineJob::SendEmail`'s doc comment) — box patterns
        // aren't stable Rust, so the field check is a match guard against the
        // deref'd payload rather than a nested struct pattern.
        assert!(matches!(
            decoded,
            EngineJob::SendEmail(ref msg) if msg.delivery_id.is_none()
        ));
    }

    #[test]
    fn ensure_audit_partitions_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::EnsureAuditPartitions);
        assert_round_trips(EngineJob::PruneNotificationRecipientPartitions);
        assert_round_trips(EngineJob::FanOutNotification {
            dispatch_id: Uuid::now_v7(),
        });
        assert_round_trips(EngineJob::BackfillRecipientForNewUser {
            user_id: Uuid::now_v7(),
        });
        assert_round_trips(EngineJob::BuildAttributeIndex {
            entity_logicalname: "contact".to_string(),
            field_logicalname: "last_name".to_string(),
        });
        assert_round_trips(EngineJob::BuildBusinessKeyIndex {
            entity_logicalname: "country".to_string(),
        });
    }

    #[test]
    fn bulk_entity_operation_round_trips() {
        assert_round_trips(EngineJob::BulkEntityOperation(BulkEntityOperationPayload {
            bulk_op_id: Uuid::now_v7(),
            entity_logicalname: "contact".to_string(),
            operation: "update".to_string(),
            records: vec![
                serde_json::json!({"id": Uuid::now_v7().to_string(), "expected_row_version": 0, "data": {"name": "a"}}),
                serde_json::json!({"id": Uuid::now_v7().to_string(), "expected_row_version": 0, "data": {"name": "b"}}),
            ],
            user_id: Uuid::now_v7(),
        }));
    }

    #[test]
    fn apply_staged_import_round_trips() {
        assert_round_trips(EngineJob::ApplyStagedImport(ApplyStagedImportPayload {
            import_id: Uuid::now_v7(),
            entity_logicalname: "contact".to_string(),
            operation: "update".to_string(),
            records: vec![
                serde_json::json!({"id": Uuid::now_v7().to_string(), "expected_row_version": 0, "data": {"name": "a"}}),
            ],
            user_id: Uuid::now_v7(),
        }));
    }

    #[test]
    fn rewrap_secrets_round_trips_for_every_domain() {
        for domain in RewrapDomain::ALL {
            assert_round_trips(EngineJob::RewrapSecrets { domain });
        }
    }

    #[test]
    fn document_text_extract_round_trips() {
        assert_round_trips(EngineJob::DocumentTextExtract {
            session_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn transcribe_recording_round_trips() {
        assert_round_trips(EngineJob::TranscribeRecording {
            document_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn content_article_index_round_trips() {
        assert_round_trips(EngineJob::ContentArticleIndex {
            page_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn scan_uploaded_file_round_trips() {
        assert_round_trips(EngineJob::ScanUploadedFile {
            session_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn prune_expired_upload_sessions_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PruneExpiredUploadSessions);
    }

    #[test]
    fn process_extraction_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ProcessExtractionSweep);
        assert!(!EngineJob::ProcessExtractionSweep.is_batch());
        assert_eq!(
            EngineJob::ProcessExtractionSweep.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn prune_expired_memories_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PruneExpiredMemories);
        assert!(!EngineJob::PruneExpiredMemories.is_batch());
        assert_eq!(EngineJob::PruneExpiredMemories.priority(), JobPriority::Low);
    }

    #[test]
    fn compute_metric_snapshots_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ComputeMetricSnapshots);
    }

    #[test]
    fn ai_quality_monitor_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::AiQualityMonitor);
        assert_round_trips(EngineJob::AiToolCallSweep);
        assert_round_trips(EngineJob::BinDeleteAlertSweep);
        assert_round_trips(EngineJob::TagExpirySweep);
        assert_round_trips(EngineJob::ContractKeyDates);
        assert_round_trips(EngineJob::ContractCounterpartyMatch);
        assert_round_trips(EngineJob::RecurringTaskRoll);
        assert_round_trips(EngineJob::ContractLinkSweep);
        assert_round_trips(EngineJob::BillingHandoffSweep);
        assert_round_trips(EngineJob::BillingRenewalSweep);
        assert_round_trips(EngineJob::BillingGenerateCharges);
        assert_round_trips(EngineJob::BillingExecuteRun {
            run_id: Uuid::nil(),
        });
        assert_round_trips(EngineJob::PointsScoring);
        assert_round_trips(EngineJob::DealRiskEvaluation);
        assert_round_trips(EngineJob::ForecastRecompute);
        assert_round_trips(EngineJob::MrrSnapshot);
        assert_round_trips(EngineJob::WebcrawlRecrawlDue);
        assert_round_trips(EngineJob::TimerSweep);
        assert_round_trips(EngineJob::MarketingNightly);
        assert_round_trips(EngineJob::SegmentRefreshDue);
        assert_round_trips(EngineJob::MarketingSweep);
        assert_round_trips(EngineJob::RoleGrantExpiry);
        assert_round_trips(EngineJob::SalesDefaultTeamSweep);
        assert_round_trips(EngineJob::CommissionCreditSweep);
        assert_round_trips(EngineJob::BillingRequestSweep);
        assert_round_trips(EngineJob::BillingScheduleRun);
        assert_round_trips(EngineJob::BillingOverdueSweep);
        assert_round_trips(EngineJob::BillingChargeDue);
        assert_round_trips(EngineJob::BillingReconcile);
        assert_round_trips(EngineJob::BillingEinvoiceSweep);
        assert_round_trips(EngineJob::BillingGatewayEventApply);
        assert_round_trips(EngineJob::SalesSnapshotPrune);
        assert_round_trips(EngineJob::NotificationFollowSweep);
        assert_round_trips(EngineJob::SalesDealCloseSweep);
        assert_round_trips(EngineJob::AiFollowupScan);
        assert_round_trips(EngineJob::SalesLeaverSweep);
        assert_round_trips(EngineJob::AiFollowupItem {
            item_id: Uuid::nil(),
        });
        assert_round_trips(EngineJob::TableHealthSample);
        assert_round_trips(EngineJob::AuditChainVerify);
        assert_round_trips(EngineJob::UploadRescanSweep);
        assert_round_trips(EngineJob::SloMonthlyReport);
        assert_round_trips(EngineJob::SloBurnCheck);
        assert_round_trips(EngineJob::PerfRegressionCheck);
        assert_round_trips(EngineJob::LimitWarningCheck);
        assert_round_trips(EngineJob::SalesMentionScan);
        assert_round_trips(EngineJob::SalesDefaultTeamApply {
            owner_id: Uuid::now_v7(),
        });
        assert_round_trips(EngineJob::AiFollowupRuleRun {
            rule_id: Uuid::now_v7(),
        });
        assert_round_trips(EngineJob::SalesCallOutcomeRules {
            attempt_id: Uuid::now_v7(),
        });
        assert_round_trips(EngineJob::SalesScheduleShift {
            opportunity_id: Uuid::now_v7(),
            months: -2,
        });
        assert_round_trips(EngineJob::TimerFire {
            timer_id: Uuid::now_v7(),
        });
        assert_round_trips(EngineJob::ReportScheduleFire {
            schedule_id: Uuid::now_v7(),
        });
        assert_round_trips(EngineJob::ValidationCleanupScan {
            rule_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn prune_apalis_job_history_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PruneApalisJobHistory);
    }

    #[test]
    fn revalidate_query_plans_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::RevalidateQueryPlans);
    }

    #[test]
    fn trigram_index_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::TrigramIndexSweep);
        assert!(!EngineJob::TrigramIndexSweep.is_batch());
    }

    #[test]
    fn propose_retention_actions_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ProposeRetentionActions);
    }

    #[test]
    fn execute_retention_action_round_trips() {
        assert_round_trips(EngineJob::ExecuteRetentionAction {
            action_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn prune_idempotency_records_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PruneIdempotencyRecords);
    }

    #[test]
    fn prune_auth_tokens_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PruneAuthTokens);
        assert_round_trips(EngineJob::PruneRecoveryArchive);
        assert_round_trips(EngineJob::RunDataStep {
            run_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn apply_schema_change_plan_round_trips() {
        assert_round_trips(EngineJob::ApplySchemaChangePlan {
            plan_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn apply_metadata_bundle_round_trips() {
        assert_round_trips(EngineJob::ApplyMetadataBundle {
            plan_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn apply_changesets_round_trips_and_is_batch() {
        let job = EngineJob::ApplyChangesets {
            apply_ids: vec![Uuid::now_v7(), Uuid::now_v7()],
        };
        assert!(job.is_batch());
        assert_eq!(job.max_attempts(), 5);
        assert_eq!(job.variant_name(), "ApplyChangesets");
        assert_round_trips(job);
    }

    #[test]
    fn revalidate_field_security_profiles_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::RevalidateFieldSecurityProfiles);
    }

    #[test]
    fn audit_v1_cutover_checkpoint_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::AuditV1CutoverCheckpoint);
        assert!(!EngineJob::AuditV1CutoverCheckpoint.is_batch());
        assert_eq!(
            EngineJob::AuditV1CutoverCheckpoint.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn fleet_console_jobs_round_trip_and_stay_on_the_fast_queue() {
        assert_round_trips(EngineJob::FleetPoll);
        assert_round_trips(EngineJob::FleetRolloutStep {
            target_id: Uuid::now_v7(),
        });
        assert!(!EngineJob::FleetPoll.is_batch());
        assert_eq!(EngineJob::FleetPoll.priority(), JobPriority::Low);
        assert_eq!(EngineJob::FleetPoll.max_attempts(), 3);
        let step = EngineJob::FleetRolloutStep {
            target_id: Uuid::nil(),
        };
        assert!(!step.is_batch());
        assert_eq!(step.priority(), JobPriority::Normal);
        assert_eq!(step.max_attempts(), 5);
    }

    #[test]
    fn prune_change_feed_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PruneChangeFeed);
        assert!(!EngineJob::PruneChangeFeed.is_batch());
        assert_eq!(EngineJob::PruneChangeFeed.priority(), JobPriority::Low);
    }

    #[test]
    fn is_batch_is_true_only_for_the_open_ended_record_count_proportional_variants() {
        assert!(
            EngineJob::BulkEntityOperation(BulkEntityOperationPayload {
                bulk_op_id: Uuid::now_v7(),
                entity_logicalname: "contact".to_string(),
                operation: "update".to_string(),
                records: vec![],
                user_id: Uuid::now_v7(),
            })
            .is_batch()
        );
        assert!(
            EngineJob::ApplyStagedImport(ApplyStagedImportPayload {
                import_id: Uuid::now_v7(),
                entity_logicalname: "contact".to_string(),
                operation: "update".to_string(),
                records: vec![],
                user_id: Uuid::now_v7(),
            })
            .is_batch()
        );
        assert!(
            EngineJob::RewrapSecrets {
                domain: RewrapDomain::Mfa
            }
            .is_batch()
        );
        assert!(
            EngineJob::ApplySchemaChangePlan {
                plan_id: Uuid::now_v7()
            }
            .is_batch()
        );
        assert!(
            EngineJob::ApplyMetadataBundle {
                plan_id: Uuid::now_v7()
            }
            .is_batch()
        );
        assert!(
            EngineJob::CrawlWebsite {
                target_id: Uuid::now_v7()
            }
            .is_batch()
        );

        // BJB-1 — the remaining 11 of the 17 batch variants (the six above
        // plus these are the whole true set).
        assert!(
            EngineJob::CascadeDeactivateDependents {
                target_entity: "account".to_string(),
                target_record_id: Uuid::now_v7(),
                dependent_entity: "contact".to_string(),
                dependent_field: "parent_account".to_string(),
                deactivated_by: Uuid::now_v7(),
            }
            .is_batch()
        );
        assert!(
            EngineJob::DataExport(DataExportPayload {
                export_id: Uuid::now_v7(),
                entity_logicalname: "contact".to_string(),
                format: "csv".to_string(),
                columns: vec![],
                filters: vec![],
                user_id: Uuid::now_v7(),
            })
            .is_batch()
        );
        assert!(
            EngineJob::DataProfile(DataProfilePayload {
                profile_id: Uuid::now_v7(),
                entity_logicalname: "contact".to_string(),
                user_id: Uuid::now_v7(),
            })
            .is_batch()
        );
        assert!(
            EngineJob::DataBulkTransform(DataBulkTransformPayload {
                operation_id: Uuid::now_v7(),
                entity_logicalname: "contact".to_string(),
                field_logicalname: "name".to_string(),
                transform: "trim".to_string(),
                value: None,
                record_ids: vec![],
                user_id: Uuid::now_v7(),
            })
            .is_batch()
        );
        assert!(
            EngineJob::RollbackMigrationRun {
                run_id: Uuid::now_v7(),
                user_id: Uuid::now_v7(),
            }
            .is_batch()
        );
        assert!(
            EngineJob::ReportRun {
                run_id: Uuid::now_v7()
            }
            .is_batch()
        );
        assert!(
            EngineJob::LegalMatterCollect {
                matter_id: Uuid::now_v7(),
                collected_by: Uuid::now_v7(),
            }
            .is_batch()
        );
        assert!(
            EngineJob::LegalMatterRelease {
                matter_id: Uuid::now_v7(),
                released_by: Uuid::now_v7(),
            }
            .is_batch()
        );

        assert!(!EngineJob::EnsureAuditPartitions.is_batch());
        assert!(!EngineJob::PruneExpiredUploadSessions.is_batch());
        assert!(!EngineJob::PruneApalisJobHistory.is_batch());
        assert!(!EngineJob::RevalidateQueryPlans.is_batch());
        assert!(!EngineJob::ProposeRetentionActions.is_batch());
        assert!(
            !EngineJob::ExecuteRetentionAction {
                action_id: Uuid::now_v7()
            }
            .is_batch()
        );
        assert!(!EngineJob::PruneIdempotencyRecords.is_batch());
        assert!(!EngineJob::PruneAuthTokens.is_batch());
        assert!(!EngineJob::RevalidateFieldSecurityProfiles.is_batch());
        assert!(
            !EngineJob::ScanUploadedFile {
                session_id: Uuid::now_v7()
            }
            .is_batch()
        );
        assert!(
            !EngineJob::WorkflowExecute {
                instance_id: Uuid::now_v7()
            }
            .is_batch()
        );
        assert!(!EngineJob::WorkflowSlaSweep.is_batch());
        assert!(!EngineJob::WorkflowEntityTriggerDispatch.is_batch());
    }

    #[test]
    fn workflow_execute_round_trips() {
        assert_round_trips(EngineJob::WorkflowExecute {
            instance_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn workflow_sla_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::WorkflowSlaSweep);
    }

    #[test]
    fn workflow_entity_trigger_dispatch_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::WorkflowEntityTriggerDispatch);
    }

    #[test]
    fn billing_execute_refund_round_trips() {
        assert_round_trips(EngineJob::BillingExecuteRefund {
            refund_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn commission_recalc_preview_round_trips() {
        assert_round_trips(EngineJob::CommissionRecalcPreview {
            period_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn billing_after_issue_round_trips() {
        let job = EngineJob::BillingAfterIssue {
            invoice_id: Uuid::now_v7(),
        };
        assert!(!job.is_batch());
        assert_round_trips(job);
    }

    #[test]
    fn commission_run_round_trips() {
        assert_round_trips(EngineJob::CommissionRun {
            run_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn crawl_website_round_trips() {
        assert_round_trips(EngineJob::CrawlWebsite {
            target_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn events_dispatch_tick_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::EventsDispatchTick);
    }

    #[test]
    fn events_deliver_webhook_round_trips() {
        assert_round_trips(EngineJob::EventsDeliverWebhook {
            delivery_id: Uuid::now_v7(),
        });
    }

    #[test]
    fn rewrap_domain_rejects_unknown_values() {
        assert_eq!("mfa".parse(), Ok(RewrapDomain::Mfa));
        assert!("unknown".parse::<RewrapDomain>().is_err());
        assert!(serde_json::from_str::<RewrapDomain>(r#""unknown""#).is_err());
    }

    #[test]
    fn rewrap_domain_preserves_the_existing_queue_json_shape() {
        let json = serde_json::to_value(EngineJob::RewrapSecrets {
            domain: RewrapDomain::Mfa,
        })
        .unwrap();
        assert_eq!(json["RewrapSecrets"]["domain"], "mfa");

        let old_payload = serde_json::json!({"RewrapSecrets": {"domain": "s2s"}});
        let decoded: EngineJob = serde_json::from_value(old_payload).unwrap();
        assert!(matches!(
            decoded,
            EngineJob::RewrapSecrets {
                domain: RewrapDomain::S2s
            }
        ));
    }

    #[test]
    fn max_attempts_declares_a_budget_per_kind() {
        // BJB-2 / BJB-D2 — one budget per kind, chosen rather than inherited
        // from whichever enqueue path ran. Representative kinds from every
        // tier; the exhaustive `match` that makes this compile is the real
        // guard for a new variant.
        assert_eq!(EngineJob::EnsureAuditPartitions.max_attempts(), 3);
        assert_eq!(EngineJob::PruneApalisJobHistory.max_attempts(), 3);
        assert_eq!(EngineJob::PruneChangeFeed.max_attempts(), 3);
        assert_eq!(
            EngineJob::ExecuteRetentionAction {
                action_id: Uuid::now_v7()
            }
            .max_attempts(),
            5
        );
        assert_eq!(
            EngineJob::RewrapSecrets {
                domain: RewrapDomain::Mfa
            }
            .max_attempts(),
            5
        );
        assert_eq!(
            EngineJob::EventsDeliverWebhook {
                delivery_id: Uuid::now_v7()
            }
            .max_attempts(),
            8
        );
        assert_eq!(
            EngineJob::WorkflowExecute {
                instance_id: Uuid::now_v7()
            }
            .max_attempts(),
            10
        );
        assert_eq!(
            EngineJob::FanOutNotification {
                dispatch_id: Uuid::now_v7()
            }
            .max_attempts(),
            10
        );
        assert_eq!(
            EngineJob::BulkEntityOperation(BulkEntityOperationPayload {
                bulk_op_id: Uuid::now_v7(),
                entity_logicalname: "contact".to_string(),
                operation: "update".to_string(),
                records: vec![],
                user_id: Uuid::now_v7(),
            })
            .max_attempts(),
            10
        );
    }

    #[test]
    fn each_variant_serializes_to_a_distinct_externally_tagged_json_shape() {
        // apalis's job_type column disambiguates the queue, but the JSON
        // payload itself is also matched back onto the enum by serde's
        // default externally-tagged representation — pin that every variant
        // carries its own tag so two variants can never collide/parse as
        // each other.
        let scan_uploaded_file = serde_json::to_value(EngineJob::ScanUploadedFile {
            session_id: Uuid::now_v7(),
        })
        .unwrap();
        assert!(scan_uploaded_file.get("ScanUploadedFile").is_some());

        let ensure_partitions = serde_json::to_value(EngineJob::EnsureAuditPartitions).unwrap();
        assert_eq!(
            ensure_partitions,
            serde_json::json!("EnsureAuditPartitions")
        );
    }

    #[test]
    fn data_export_round_trips() {
        assert_round_trips(EngineJob::DataExport(DataExportPayload {
            export_id: Uuid::now_v7(),
            entity_logicalname: "contact".to_string(),
            format: "csv".to_string(),
            columns: vec!["firstname".to_string(), "lastname".to_string()],
            filters: vec![serde_json::json!({"field": "status", "op": "eq", "value": "active"})],
            user_id: Uuid::now_v7(),
        }));
    }

    #[test]
    fn data_profile_round_trips() {
        assert_round_trips(EngineJob::DataProfile(DataProfilePayload {
            profile_id: Uuid::now_v7(),
            entity_logicalname: "contact".to_string(),
            user_id: Uuid::now_v7(),
        }));
    }

    #[test]
    fn access_review_campaign_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::AccessReviewCampaignSweep);
        assert!(!EngineJob::AccessReviewCampaignSweep.is_batch());
    }

    #[test]
    fn data_match_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::DataMatchSweep);
        // A15-T6
        assert_round_trips(EngineJob::DataMatchScan {
            rule_id: Uuid::now_v7(),
            after_id: Some(Uuid::now_v7()),
        });
        assert!(
            EngineJob::DataMatchScan {
                rule_id: Uuid::now_v7(),
                after_id: None
            }
            .is_batch()
        );
        assert!(!EngineJob::DataMatchSweep.is_batch());
    }

    #[test]
    fn api_usage_rollup_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ApiUsageRollup);
        assert!(!EngineJob::ApiUsageRollup.is_batch());
    }

    #[test]
    fn content_scheduled_publish_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ContentScheduledPublishSweep);
        assert!(!EngineJob::ContentScheduledPublishSweep.is_batch());
    }

    #[test]
    fn data_quality_score_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::DataQualityScoreSweep);
        assert!(!EngineJob::DataQualityScoreSweep.is_batch());
    }

    #[test]
    fn predict_train_model_round_trips() {
        assert_round_trips(EngineJob::PredictTrainModel {
            model_id: Uuid::now_v7(),
        });
        assert!(
            !EngineJob::PredictTrainModel {
                model_id: Uuid::now_v7()
            }
            .is_batch()
        );
        assert_eq!(
            EngineJob::PredictTrainModel {
                model_id: Uuid::now_v7()
            }
            .priority(),
            JobPriority::High
        );
    }

    #[test]
    fn predict_scoring_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PredictScoringSweep);
        assert!(!EngineJob::PredictScoringSweep.is_batch());
        assert_eq!(EngineJob::PredictScoringSweep.priority(), JobPriority::Low);
    }

    #[test]
    fn predict_outcome_fill_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::PredictOutcomeFillSweep);
        assert!(!EngineJob::PredictOutcomeFillSweep.is_batch());
        assert_eq!(
            EngineJob::PredictOutcomeFillSweep.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn report_run_round_trips() {
        assert_round_trips(EngineJob::ReportRun {
            run_id: Uuid::now_v7(),
        });
        assert!(
            EngineJob::ReportRun {
                run_id: Uuid::now_v7()
            }
            .is_batch()
        );
    }

    #[test]
    fn report_schedule_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ReportScheduleSweep);
        assert_round_trips(EngineJob::AiDeferredActionSweep);
        assert_round_trips(EngineJob::AiAutonomySummary);
        assert!(!EngineJob::AiDeferredActionSweep.is_batch());
        assert!(!EngineJob::ReportScheduleSweep.is_batch());
    }

    #[test]
    fn legal_matter_collect_round_trips_and_is_batch() {
        let job = EngineJob::LegalMatterCollect {
            matter_id: Uuid::now_v7(),
            collected_by: Uuid::now_v7(),
        };
        assert!(job.is_batch());
        assert_round_trips(job);
    }

    #[test]
    fn legal_matter_release_round_trips_and_is_batch() {
        let job = EngineJob::LegalMatterRelease {
            matter_id: Uuid::now_v7(),
            released_by: Uuid::now_v7(),
        };
        assert!(job.is_batch());
        assert_round_trips(job);
    }

    #[test]
    fn failed_login_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::FailedLoginSweep);
        assert!(!EngineJob::FailedLoginSweep.is_batch());
    }

    #[test]
    fn license_expiry_check_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::LicenseExpiryCheck);
        assert!(!EngineJob::LicenseExpiryCheck.is_batch());
    }

    #[test]
    fn search_suggestion_refresh_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::SearchSuggestionRefresh);
        assert!(!EngineJob::SearchSuggestionRefresh.is_batch());
        assert_eq!(
            EngineJob::SearchSuggestionRefresh.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn search_saved_search_alert_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::SearchSavedSearchAlertSweep);
        assert!(!EngineJob::SearchSavedSearchAlertSweep.is_batch());
        assert_eq!(
            EngineJob::SearchSavedSearchAlertSweep.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn content_page_stats_rollup_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ContentPageStatsRollup);
        assert!(!EngineJob::ContentPageStatsRollup.is_batch());
        assert_eq!(
            EngineJob::ContentPageStatsRollup.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn catalog_lineage_backfill_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::CatalogLineageBackfill);
        assert!(!EngineJob::CatalogLineageBackfill.is_batch());
        assert_eq!(
            EngineJob::CatalogLineageBackfill.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn catalog_dashboard_lineage_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::CatalogDashboardLineageSweep);
        assert!(!EngineJob::CatalogDashboardLineageSweep.is_batch());
        assert_eq!(
            EngineJob::CatalogDashboardLineageSweep.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn catalog_usage_rollup_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::CatalogUsageRollup);
        assert_round_trips(EngineJob::ValidationScoreSweep);
        assert_eq!(EngineJob::ValidationScoreSweep.priority(), JobPriority::Low);
        assert!(!EngineJob::CatalogUsageRollup.is_batch());
        assert_eq!(EngineJob::CatalogUsageRollup.priority(), JobPriority::Low);
    }

    #[test]
    fn content_review_reminder_sweep_round_trips_as_a_bare_unit_variant() {
        assert_round_trips(EngineJob::ContentReviewReminderSweep);
        assert!(!EngineJob::ContentReviewReminderSweep.is_batch());
        assert_eq!(
            EngineJob::ContentReviewReminderSweep.priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn data_bulk_transform_round_trips() {
        assert_round_trips(EngineJob::DataBulkTransform(DataBulkTransformPayload {
            operation_id: Uuid::now_v7(),
            entity_logicalname: "contact".to_string(),
            field_logicalname: "firstname".to_string(),
            transform: "trim".to_string(),
            value: None,
            record_ids: vec![Uuid::now_v7(), Uuid::now_v7()],
            user_id: Uuid::now_v7(),
        }));
    }

    #[test]
    fn job_priority_orders_low_below_normal_below_high() {
        assert!(JobPriority::Low < JobPriority::Normal);
        assert!(JobPriority::Normal < JobPriority::High);
    }

    #[test]
    fn job_priority_normal_is_apalis_own_zero_default() {
        // Introducing JobPriority must not move any job that stays
        // classified Normal — apalis-sql 0.7.4's own SqlContext/push_job
        // default is 0.
        assert_eq!(JobPriority::Normal.apalis_priority(), 0);
        assert!(JobPriority::Low.apalis_priority() < 0);
        assert!(JobPriority::High.apalis_priority() > 0);
    }

    #[test]
    fn job_priority_labels_are_distinct_and_cover_all_variants() {
        let mut seen = std::collections::HashSet::new();
        for p in JobPriority::ALL {
            assert!(seen.insert(p.label()), "duplicate label {}", p.label());
        }
    }

    #[test]
    fn user_facing_and_sla_bound_variants_are_high_priority() {
        assert_eq!(
            EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
                to: "user@example.invalid".to_string(),
                subject: "s".to_string(),
                text_body: "b".to_string(),
                html_body: None,
                delivery_id: None,
                from_override: None,
                message_id: None,
                in_reply_to: None,
                references: None,
                communication_id: None,
                attachments: Vec::new(),
            }))
            .priority(),
            JobPriority::High
        );
        assert_eq!(
            EngineJob::ScanUploadedFile {
                session_id: Uuid::now_v7()
            }
            .priority(),
            JobPriority::High
        );
        assert_eq!(
            EngineJob::EventsDeliverWebhook {
                delivery_id: Uuid::now_v7()
            }
            .priority(),
            JobPriority::High
        );
    }

    #[test]
    fn periodic_sweeps_with_no_observer_are_low_priority() {
        assert_eq!(
            EngineJob::EnsureAuditPartitions.priority(),
            JobPriority::Low
        );
        assert_eq!(EngineJob::WorkflowSlaSweep.priority(), JobPriority::Low);
        assert_eq!(
            EngineJob::PruneApalisJobHistory.priority(),
            JobPriority::Low
        );
        assert_eq!(
            EngineJob::BuildAttributeIndex {
                entity_logicalname: "contact".to_string(),
                field_logicalname: "last_name".to_string(),
            }
            .priority(),
            JobPriority::Low
        );
    }

    #[test]
    fn rollback_migration_run_round_trips_and_is_batch() {
        let job = EngineJob::RollbackMigrationRun {
            run_id: Uuid::now_v7(),
            user_id: Uuid::now_v7(),
        };
        assert!(job.is_batch());
        assert_round_trips(job);
    }
}
