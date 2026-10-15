//! Audit-chain policy (`AuditSection`), the notification-inbox retention
//! knob, and P-retention-archive-completion's partition archive/drop +
//! entity-purge + legal-hold policy (`RetentionSection`).

use serde::Deserialize;

use crate::Secret;

use crate::config::helpers::default_true;
use crate::config::sections::storage::S3Target;
use crate::keyring::KeyRing;

// ── Anchor store (D-352, TODO-004 / H-1) ───────────────────────────────────────

/// The dedicated, WORM-provisioned bucket external audit anchors are written
/// to, and the **append-only** credential they are written with — D-352,
/// closing the gap `xrm_audit::anchor`'s module doc has named since D-174.
///
/// **Why this is a second bucket and not `storage`.** D-174 anchored to the
/// deployment's general object store, reusing `storage`'s client and
/// credential. That cannot be made immutable: the same credential must keep
/// `DeleteObject` for the upload paths that genuinely delete objects
/// (`xrm_document::files::…`, `files_scan`'s quarantine cleanup and rejected-scan
/// purge), and Object Lock retention on that bucket would break every one of
/// them. An anchor whose own writer can delete it is not an independent
/// record of anything — a party who compromised the deployment holds that
/// credential. So the anchor bucket is separate, its producer credential
/// carries `PutObject`/`GetObject`/`ListBucket` and nothing else, and
/// delete/retention authority lives with an operator identity that is never
/// stored on the deployment host. See `deploy/audit-anchor/README.md`.
///
/// **What this struct can and cannot enforce.** Object Lock is provisioned on
/// the bucket, out-of-band, before the deployment ever starts — application
/// code cannot turn it on, and nothing here pretends otherwise. The two
/// `object_lock_*` fields are an operator *declaration* of what was
/// provisioned, and `validate_production_profile` refuses to boot a production
/// deployment that has anchoring on without them. A declaration is not proof,
/// which is why it is deliberately not the only control: `preflight` probes
/// the credential's append-only-ness live, and
/// `scripts/audit/anchor-immutability-drill.sh` proves the retention half
/// against the real bucket. The boot check's job is to make "we forgot to
/// provision it" a loud failure rather than a silent one.
#[derive(Clone, Deserialize)]
pub struct AnchorStoreSection {
    /// S3-compatible endpoint holding the anchor bucket. May be the same
    /// endpoint as `storage.s3_endpoint` (one RustFS/MinIO deployment, two
    /// buckets) or a wholly separate one — a different account, region, or
    /// provider is strictly better, since it widens the blast-radius gap this
    /// whole mechanism exists to create. Empty selects AWS S3 proper (the
    /// same convention `storage.s3_endpoint` uses).
    #[serde(default)]
    pub s3_endpoint: String,
    #[serde(default)]
    pub s3_region: String,
    /// Must differ from `storage.s3_bucket` — `validate()` rejects the same
    /// bucket for both, since the whole point is that this one is WORM and
    /// that one cannot be.
    #[serde(default)]
    pub s3_bucket: String,
    /// The **producer** identity: `PutObject`/`GetObject`/`ListBucket` only.
    /// No `DeleteObject`, no `DeleteObjectVersion`, no
    /// `PutBucketVersioning`/`PutBucketPolicy`/`PutLifecycleConfiguration`, no
    /// `s3:BypassGovernanceRetention`, no `PutObjectRetention` (which would
    /// let a compromised app shorten its own retention).
    #[serde(default)]
    pub s3_access_key: String,
    #[serde(default)]
    pub s3_secret_key: Secret,
    #[serde(default = "default_true")]
    pub s3_verify_ssl: bool,
    /// What the operator provisioned on the bucket, out-of-band:
    /// `"compliance"`, `"governance"`, or `"none"`. Mirrors
    /// `deploy/backup/README.md`'s fallback ladder, and means the same things:
    /// compliance mode cannot be bypassed even by the bucket owner's root
    /// credentials; governance mode can, by a distinct identity holding
    /// `s3:BypassGovernanceRetention`. `"none"` is honest about having no
    /// bucket-side backstop at all and is refused in production.
    #[serde(default)]
    pub object_lock_mode: String,
    /// The default retention period, in days, configured on the bucket. Must
    /// be at least as long as the deployment's audit-retention obligation —
    /// an anchor that expires before the events it attests to is worse than
    /// useless, because the chain then looks anchored right up until the
    /// moment someone needs it. Zero is refused in production.
    #[serde(default)]
    pub object_lock_retention_days: u32,
}

impl AnchorStoreSection {
    pub fn s3_target(&self) -> S3Target<'_> {
        S3Target {
            endpoint: &self.s3_endpoint,
            // The anchor bucket never presigns browser-facing URLs; anchors
            // are written and read server-side only.
            public_endpoint: "",
            region: &self.s3_region,
            bucket: &self.s3_bucket,
            access_key: &self.s3_access_key,
            secret_key: self.s3_secret_key.expose(),
            verify_ssl: self.s3_verify_ssl,
        }
    }

    /// The three rungs `object_lock_mode` accepts, in the same order and with
    /// the same meanings as `deploy/backup/README.md`'s ladder.
    pub const VALID_OBJECT_LOCK_MODES: &'static [&'static str] =
        &["compliance", "governance", "none"];

    /// True when the declared mode is one the bucket can actually refuse a
    /// purge under. `"none"` is not — see the field's doc.
    pub fn declares_worm(&self) -> bool {
        matches!(self.object_lock_mode.as_str(), "compliance" | "governance")
    }
}

/// Hand-rolled: `s3_access_key`/`s3_secret_key` are live object-storage
/// credentials, same custody class as `StorageSection`'s — the derived `Debug`
/// would print both raw.
impl std::fmt::Debug for AnchorStoreSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnchorStoreSection")
            .field("s3_endpoint", &self.s3_endpoint)
            .field("s3_region", &self.s3_region)
            .field("s3_bucket", &self.s3_bucket)
            .field("s3_access_key", &"[REDACTED]")
            .field("s3_secret_key", &"[REDACTED]")
            .field("s3_verify_ssl", &self.s3_verify_ssl)
            .field("object_lock_mode", &self.object_lock_mode)
            .field(
                "object_lock_retention_days",
                &self.object_lock_retention_days,
            )
            .finish()
    }
}

// ── Audit section (P1.5b) ──────────────────────────────────────────────────────

#[derive(Clone, Deserialize)]
pub struct AuditSection {
    /// Sign every audit chain event's (prev_hash||event_hash) with a
    /// dedicated Ed25519 keypair (D-016 — unrelated to the license
    /// verifier's verify-only key in xrm-license, D-142). When false,
    /// `signature`/`signing_key_id` are left NULL; hash-chaining alone
    /// still applies.
    #[serde(default)]
    pub signing_enabled: bool,

    /// Identifies which keypair produced a signature — stays alongside every
    /// signature it makes so old signatures remain attributable after a key
    /// rotation. Any operator-chosen label, e.g. "audit-key-1".
    #[serde(default)]
    pub signing_key_id: String,

    /// 64-hex-char Ed25519 signing seed. Required when signing_enabled = true.
    /// Generate with: openssl rand -hex 32
    #[serde(default)]
    pub signing_private_key: Secret,

    /// P1.13 stage 1: additionally durably capture every audit event into
    /// `xrm_audit_ingest` (same transaction as the existing header/detail/
    /// snapshot writes) so a future async chainer has something to drain.
    /// Purely additive today — the synchronous chain append in
    /// `AuditService::write` still runs unconditionally either way; this
    /// flag does not yet turn it off. Default false until the chainer
    /// (a later P1.13 stage) exists to consume the table.
    #[serde(default)]
    pub ingest_capture_enabled: bool,

    /// P1.13 stage 4 — the cutover, and since D-316 the **default**. When
    /// true, `write()` only durably captures the event into
    /// `xrm_audit_ingest` (no lock, no chain read) and the `audit_chainer`
    /// process becomes solely responsible for producing header rows —
    /// requires `audit_chainer` to actually be running, or events accumulate
    /// in `xrm_audit_ingest` unchained (the lag gauge, the
    /// `AuditChainerLagHigh` alert, and finally `ingest_backlog_threshold`'s
    /// mutation gate are what make that visible rather than silent).
    ///
    /// False keeps the pre-P1.13 synchronous path: `AuditService::write`
    /// acquires the per-organization append lock and writes
    /// `xrm_audit_header`/`detail`/`snapshot` inline, inside the caller's
    /// business transaction. That path serializes **every** mutation in the
    /// deployment on one lock (D-002: one organization, one chain), which
    /// the 2026-08-10 engineering review reproduced as ordinary concurrent
    /// saves failing with `Conflict` after the 200 × 5 ms retry budget
    /// (F-001), each retry sleeping with an open transaction holding a
    /// pooled connection (F-010). It is therefore supported only for
    /// single-writer development — `validate_production_profile` refuses to
    /// boot a `production` deployment with it false (D-316).
    ///
    /// To roll back a deployment to the sync path: flip this to false, and
    /// run `audit_chainer` once more afterwards to drain whatever was
    /// captured while it was on (the chainer deliberately still starts with
    /// this false, exactly so that drain step is possible — see its module
    /// doc).
    #[serde(default = "default_chainer_enabled")]
    pub chainer_enabled: bool,

    /// P1.13 step 6 — how many days a `xrm_audit_ingest` row is kept after
    /// its batch has already been drained into `xrm_audit_header` (i.e. it
    /// is provably redundant, kept only for a debugging/replay window).
    /// `0` disables pruning entirely — an explicit opt-in, never a
    /// default-on delete of audit data.
    ///
    /// Audit 10/10 plan item 2.8: only ingest ranges whose chain batches are
    /// signed and externally anchored are pruned, and the pruned watermark is
    /// recorded so verification still passes. With
    /// `external_anchoring_enabled = false` nothing is pruned, whatever this
    /// is set to (`xrm_audit::chainer::prune_ingest`).
    #[serde(default)]
    pub ingest_retention_days: u32,

    /// P-db-maintenance item (c) — how many months of partitions the
    /// create-ahead job keeps provisioned beyond the current one, for the
    /// audit family + `xrm_s2s_access_log` (migrations/0026). `2` matches
    /// the plan's stated default; raise it for a deployment whose
    /// maintenance window runs less often than this job's own poll interval.
    #[serde(default = "default_partition_create_ahead_months")]
    pub partition_create_ahead_months: u32,

    /// D-107 (P-data-lifecycle item (d)'s erasure ruling) — crypto-shredding.
    /// When active, every audit write for a record with an `id`
    /// fetches-or-creates that record's data-encryption key
    /// (`xrm_audit_erasure_key`, migration 0039) and encrypts its field values
    /// in place before any storage — see `xrm_audit::erasure`.
    ///
    /// D-540 (G2-2 a): optional. Omitted means "on wherever a key is
    /// configured" — active exactly when `erasure_key_encryption_key` is
    /// non-empty ([`AuditSection::erasure_active`]). An explicit `false` keeps
    /// it off and stays allowed outside production; an explicit `true` without
    /// a key is a boot error. `validate_production_profile` refuses a
    /// `production` deployment unless it is active with a real key (D-540
    /// ruling 1, audit plan item 2.7).
    #[serde(default)]
    pub erasure_enabled: Option<bool>,

    /// D-107 — AES-256-GCM master key(s) (64 hex chars each) wrapping every
    /// record's data-encryption key in `xrm_audit_erasure_key.wrapped_dek`. A
    /// *dedicated* key, same reasoning as `auth.mfa_encryption_key` not
    /// reusing `s2s.key_encryption_key`: audit-erasure keys are their own
    /// trust domain. Only required (`check_secret`-validated) when
    /// `erasure_enabled = true`. Generate with: openssl rand -hex 32.
    /// P-key-rotation-and-jwt (a): a `KeyRing` — see that type's doc.
    #[serde(default)]
    pub erasure_key_encryption_key: KeyRing,

    /// P-audit-chain-hardening item (b) — anchors each sealed batch's
    /// Merkle root to the deployment's own configured object store
    /// (`attome_storage`, e.g. RustFS), outside this database's own blast
    /// radius, so a compromise of the DB+app config together can no longer
    /// silently rewrite history undetected. Default false: ships dark, same
    /// posture as every other flag in this section. Best-effort — an
    /// anchoring failure is logged/alertable but never blocks the chainer's
    /// own batch commit (`xrm_audit::chainer`'s degrade-not-fail design,
    /// D-027). See `xrm_audit::anchor`.
    #[serde(default)]
    pub external_anchoring_enabled: bool,

    /// D-352 (TODO-004 / review finding H-1) — the dedicated WORM bucket and
    /// append-only credential anchors are written with. See
    /// [`AnchorStoreSection`] for why this is not `storage`.
    ///
    /// `None` (the default) keeps D-174's original behavior: anchors go to
    /// this deployment's general `storage` bucket with the app's own
    /// credential, which is tamper-*evident* (nothing overwrites an anchor
    /// through this application, `PutMode::Create`) but not tamper-*proof*
    /// (that credential can delete through the storage backend directly).
    /// That remains fine for development. `validate_production_profile`
    /// refuses it in production whenever `external_anchoring_enabled` is
    /// true — a production deployment claiming external anchoring while the
    /// anchor's own writer can delete it is the finding this closes.
    #[serde(default)]
    pub anchor_store: Option<AnchorStoreSection>,

    /// P-audit-chain-hardening item (e) — ingest circuit breaker. How many
    /// undrained `xrm_audit_ingest` rows (summed across organizations,
    /// `xrm_audit::chainer::aggregate_lag`'s `total_pending_ingest`) trip
    /// the mutating-request gate (`AppState::audit_ingest_backlog_exceeded`).
    /// 100_000 matches the originating review's own number — a starting
    /// point, not a measured one; tune per deployment. Reads are never
    /// affected, only `POST`/`PUT`/`PATCH`/`DELETE`.
    #[serde(default = "default_ingest_backlog_threshold")]
    pub ingest_backlog_threshold: i64,
}

/// Hand-rolled: `signing_private_key` is raw Ed25519 seed material — the
/// derived `Debug` would print it raw. `erasure_key_encryption_key` is a
/// `KeyRing`, already redacted by that type's own `Debug` impl, so it's
/// listed plainly here.
impl std::fmt::Debug for AuditSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSection")
            .field("signing_enabled", &self.signing_enabled)
            .field("signing_key_id", &self.signing_key_id)
            .field("signing_private_key", &"[REDACTED]")
            .field("ingest_capture_enabled", &self.ingest_capture_enabled)
            .field("chainer_enabled", &self.chainer_enabled)
            .field("ingest_retention_days", &self.ingest_retention_days)
            .field(
                "partition_create_ahead_months",
                &self.partition_create_ahead_months,
            )
            .field("erasure_enabled", &self.erasure_enabled)
            .field(
                "erasure_key_encryption_key",
                &self.erasure_key_encryption_key,
            )
            .field(
                "external_anchoring_enabled",
                &self.external_anchoring_enabled,
            )
            .field("anchor_store", &self.anchor_store)
            .field("ingest_backlog_threshold", &self.ingest_backlog_threshold)
            .finish()
    }
}

// A bare `#[derive(Default)]` would silently zero every `default = "fn"`
// field below whenever a config omits this whole `audit` section — see
// `S2SSection`'s identical note above.
impl Default for AuditSection {
    fn default() -> Self {
        Self {
            signing_enabled: false,
            signing_key_id: String::new(),
            signing_private_key: Secret::default(),
            ingest_capture_enabled: false,
            chainer_enabled: default_chainer_enabled(),
            ingest_retention_days: 0,
            partition_create_ahead_months: default_partition_create_ahead_months(),
            erasure_enabled: None,
            erasure_key_encryption_key: KeyRing::default(),
            external_anchoring_enabled: false,
            anchor_store: None,
            ingest_backlog_threshold: default_ingest_backlog_threshold(),
        }
    }
}

impl AuditSection {
    /// D-540 (G2-2 a) — whether audit values are encrypted at rest: the
    /// explicit `erasure_enabled` when set, otherwise "a key is configured".
    pub fn erasure_active(&self) -> bool {
        self.erasure_enabled
            .unwrap_or_else(|| !self.erasure_key_encryption_key.is_empty())
    }
}

/// The development-only `audit.erasure_key_encryption_key` that
/// `config.example.json` ships (D-540 G2-2 a), so a development deployment
/// exercises the same encrypted read path as production. It is public, so it
/// protects nothing: `validate_production_profile` refuses it anywhere in a
/// `production` deployment's ring.
pub const DEVELOPMENT_ERASURE_KEY: &str =
    "dec0de00dec0de00dec0de00dec0de00dec0de00dec0de00dec0de00dec0de00";

/// D-316 — true, not false. An omitted `audit.chainer_enabled` now means the
/// async path, so the serialized sync append is something a deployment opts
/// *into* (single-writer dev) rather than something it inherits by silence.
/// See the field's own doc for the F-001/F-010 evidence behind the flip.
fn default_chainer_enabled() -> bool {
    true
}
fn default_partition_create_ahead_months() -> u32 {
    2
}
fn default_ingest_backlog_threshold() -> i64 {
    100_000
}

/// Notification recipient retention is deliberately opt-in. A zero value
/// disables pruning, matching the audit retention convention while avoiding
/// an unexpected destructive default for existing deployments.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct NotificationSection {
    /// How many days recipient rows remain before old partitions are removed.
    /// `0` disables pruning.
    #[serde(default)]
    pub recipient_retention_days: u32,

    /// M51 Phase 1 — the "From" header notification-engine email should
    /// appear to come from (e.g. `"Notifications <notifications@example.com>"`),
    /// distinct from the account-lifecycle "From" in `email.smtp_from_name`/
    /// `smtp_from_address`. `None` (default) falls back to that same
    /// deployment-wide address -- this section reuses `config.email`'s SMTP
    /// transport (host/port/credentials/`enabled`) unconditionally; it never
    /// grows its own SMTP block.
    #[serde(default)]
    pub email_from: Option<String>,
}

// ── Retention section (P-retention-archive-completion) ──────────────────────────

/// P-retention-archive-completion §3a — policy-driven partition archive/drop,
/// entity-record purge, and legal hold. Config-driven per D-002's
/// single-deployment-per-customer model: every field below is one
/// deployment's own `config.json`, never a cross-customer policy table.
///
/// Every window defaults to `None` ("keep forever") and `dry_run` defaults
/// `true`, so a fresh deployment with no `retention` block behaves exactly as
/// today — zero automatic archive/drop/purge behavior until an operator
/// explicitly configures a window **and** flips `dry_run` off **and**
/// approves a specific proposed action (§3a/§3d/§3e; two independent gates,
/// neither sufficient alone).
#[derive(Debug, Clone, Deserialize)]
pub struct RetentionSection {
    /// Age (in days) past which a `xrm_audit_header`/`xrm_audit_detail`/
    /// `xrm_audit_snapshot` partition becomes archive/drop-eligible.
    /// `None` (default) = keep forever, today's behavior.
    #[serde(default)]
    pub audit_days: Option<u32>,

    /// Age (in days) past which a `xrm_s2s_access_log` partition becomes
    /// archive/drop-eligible. `None` (default) = keep forever.
    #[serde(default)]
    pub s2s_access_log_days: Option<u32>,

    /// How long (in days) a provisioned entity record may sit
    /// `is_active = false` before it becomes purge-eligible (crypto-shred +
    /// field-scrub, never a hard `DELETE` — see `xrm_entity::purge`).
    /// `None` (default) disables entity purge entirely.
    #[serde(default)]
    pub entity_purge_grace_days: Option<u32>,

    /// Deployment-wide kill switch (D-002: a litigation hold on a
    /// self-hosted, one-customer-per-deployment platform is realistically an
    /// all-or-nothing freeze for that deployment, not a per-record flag).
    /// While `true`, no archive/drop/purge action may execute regardless of
    /// how far past its window a partition or record is — proposals still
    /// compute, for visibility, but approve/execute are refused outright.
    #[serde(default)]
    pub legal_hold: bool,

    /// Safety default. While `true` (the default), the propose step always
    /// runs and always writes `xrm_audit_retention_action` rows so an operator can
    /// see exactly what a live run *would* do, but approve/execute are
    /// refused outright with a message naming this flag. Must be explicitly
    /// flipped to `false` before any partition can be dropped or any record
    /// purged.
    #[serde(default = "default_retention_dry_run")]
    pub dry_run: bool,

    /// How often the daily proposal sweep re-checks (enqueues
    /// `PlatformJob::ProposeRetentionActions`), in seconds. Idempotent
    /// either way — a shorter interval only means more no-op re-checks once
    /// caught up, never duplicate proposals (migration 0067's partial unique
    /// index makes the insert idempotent).
    #[serde(default = "default_retention_propose_interval_secs")]
    pub propose_interval_secs: u64,

    /// M23 Records Management (D-456) — which disposition outcome the daily
    /// sweep proposes for a record past `entity_purge_grace_days`:
    /// `"purge"` (default — today's behavior, crypto-shred + field-scrub, no
    /// evidence kept) or `"archive"` (export to `attome-storage` first,
    /// evidence kept in `xrm_core_archive_record`, then the same
    /// field-scrub — see `xrm_compliance::archive::execute_entity_archive`).
    /// Deployment-wide, same D-002 single-deployment-per-customer convention
    /// as every other field in this section — not a per-record or
    /// per-entity policy table. An unrecognized value falls back to
    /// `"purge"` with a warning rather than failing the sweep (see
    /// `xrm_entity::purge::propose_purge_actions`), the same fail-safe
    /// posture `dry_run`'s default takes.
    #[serde(default = "default_retention_disposition_action")]
    pub disposition_action: String,
}

impl Default for RetentionSection {
    fn default() -> Self {
        Self {
            audit_days: None,
            s2s_access_log_days: None,
            entity_purge_grace_days: None,
            legal_hold: false,
            dry_run: default_retention_dry_run(),
            propose_interval_secs: default_retention_propose_interval_secs(),
            disposition_action: default_retention_disposition_action(),
        }
    }
}

fn default_retention_disposition_action() -> String {
    "purge".to_string()
}

fn default_retention_dry_run() -> bool {
    true
}
fn default_retention_propose_interval_secs() -> u64 {
    86400
}
