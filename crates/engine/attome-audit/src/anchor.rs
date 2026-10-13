//! P-audit-chain-hardening item (b) — external anchoring.
//!
//! Closes the gap named in that plan's problem statement: even fully
//! signed, the chain's ultimate root of trust (`audit_chain_batch`'s
//! Merkle roots) lives entirely inside the same database instance the chain
//! protects — nothing about a deployment's own state can prove to an
//! outside party that history wasn't altered by someone who compromised the
//! deployment itself (DB and/or app config together, D-016's threat model
//! for why this is a distinct concern from signing alone).
//!
//! Reuses this deployment's own already-configured object store
//! (`attome_storage`, e.g. RustFS per the docker-compose topology every
//! deployment already runs) rather than adding a new infrastructure
//! dependency, a public blockchain, or a cloud-vendor-specific service — the
//! plan's §4(b) explicitly rejected those for an air-gapped/on-premise,
//! per-customer-isolated deployment model (D-001/D-002).
//!
//! Best-effort by design: anchoring failure must never block the chainer's
//! own batch commit (`chainer::run_batch_for_org` calls this only *after*
//! `tx.commit()` succeeds, logging and moving on if it fails) — an
//! anchoring outage degrades the *external* guarantee, not the *internal*
//! one, per the platform's existing degrade-vs-fail-closed split (D-027) for
//! coordination concerns that aren't themselves a security control on the
//! request path.
//!
//! ## Where the immutability actually comes from (D-352)
//!
//! Three controls, none of which is sufficient alone, and only the first of
//! which is code in this file:
//!
//! 1. **`PutMode::Create`** (here). Fails if the key already exists, so
//!    *this application* never silently overwrites an anchor — `batch_id`
//!    (uuidv7) is unique per batch, so the key is unique by construction.
//!    This is an application-level guard and nothing more: it does not
//!    constrain anyone talking to the bucket directly, including a party who
//!    has compromised the very deployment the anchor is meant to be
//!    independent of.
//! 2. **An append-only producer credential** — `audit.anchor_store`'s
//!    `s3_access_key`, holding `PutObject`/`GetObject`/`ListBucket` and no
//!    `DeleteObject`, `DeleteObjectVersion`, `PutObjectRetention`, or
//!    `s3:BypassGovernanceRetention`. This is why anchors have their own
//!    bucket rather than sharing `storage`'s: that credential must keep
//!    `DeleteObject` for quarantine cleanup and record erasure, so its bucket
//!    can never be WORM. [`AnchorStoreSection`](attome_config::AnchorStoreSection)
//!    carries the reasoning in full.
//! 3. **Object Lock retention on the bucket** — provisioned out-of-band,
//!    before this process ever starts, with delete/retention authority held
//!    by an operator identity that is never stored on the deployment host.
//!
//! Application code cannot enable (2) or (3); it can only refuse to run while
//! claiming a guarantee it does not have. So
//! `AppConfig::validate_production_profile` fails boot when
//! `external_anchoring_enabled` is true in production without an
//! `anchor_store` declaring a real retention mode, `crates/server`'s
//! `preflight` binary probes the credential's append-only-ness live, and
//! `scripts/audit/anchor-immutability-drill.sh` proves the retention half
//! against the real bucket. See `deploy/audit-anchor/README.md`.
//!
//! What a declaration cannot do is prove itself — an operator can write
//! `"compliance"` into a config file over a bucket with no Object Lock at
//! all. The drill is the evidence; the boot check only makes the *omission*
//! loud rather than silent.
//!
//! ### One thing Object Lock genuinely does not give you
//!
//! It does not make an overwrite *fail*. A `PUT` to an existing key on a
//! versioned bucket succeeds and creates a new version; what retention
//! guarantees is that the **prior** version survives and cannot be purged
//! before its retention date. So the honest claim is "the originally
//! anchored bytes remain recoverable", not "a second write is rejected" —
//! the rejection half is (1) above, and it only binds this application.
//! `scripts/audit/anchor-immutability-drill.sh` asserts the recoverable-prior-
//! version property, not a failed overwrite, for exactly this reason.
//!
//! ## Verification status
//!
//! The `object_store` API surface used here (`put_opts`/`PutMode`/
//! `PutOptions`/`GetResult::bytes`) is compiler-verified: the workspace
//! builds and passes `clippy --all-targets -- -D warnings`, which is a
//! stronger check than the `cargo check` the note that used to sit here
//! asked for (TODO-029, 2026-08-12). A wrong method or signature against
//! this crate version could not compile.
//!
//! Still NOT covered by any test, and the distinction matters: compiling
//! proves the calls are well-typed, not that they behave. An actual put/get
//! cycle against a live store, and a `PutMode::Create` conflict on a
//! re-anchor attempt, both still need one — that is the drill D-352 defines,
//! not something a type check can stand in for. This crate's tests cover
//! path construction and record round-trip shape only.

use attome_config::AppConfig;
use attome_db::DbPool;
use attome_storage::{StorageClient, StorageError};
use attome_types::AppError;
use chrono::{DateTime, NaiveDate, Utc};
use object_store::{ObjectStoreExt, PutMode, PutOptions, path::Path};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Reserved key the append-only-credential probe targets. Nothing ever
/// anchors here — `anchor_path`/`epoch_seal_path` are both
/// `audit-chain-anchors/{uuid}/…`, and `_probe` is not a valid `Uuid`, so
/// this key can never collide with a real anchor.
///
/// It is deliberately a key that does **not exist**: `preflight` proves the
/// producer credential is append-only by attempting a `DELETE` against it and
/// requiring the store to refuse. A correctly locked-down credential gets
/// `AccessDenied` and nothing is written, read, or removed — the probe is a
/// no-op against a correct deployment. Only a *misconfigured* one (a
/// credential that really can delete) sees any effect, and on a versioned
/// bucket that effect is a single delete marker over a key that never had an
/// object under it. That is the trade this probe makes, and it is worth it:
/// the alternative is shipping a production deployment whose anchor
/// credential's permissions were never tested at all.
pub const ANCHOR_APPEND_ONLY_PROBE_KEY: &str = "audit-chain-anchors/_probe/append-only-probe.json";

/// Outcome of [`probe_append_only`]. Deliberately three-valued: "the
/// credential is locked down" and "the probe could not tell" are different
/// facts and must not be reported the same way.
#[derive(Debug)]
pub enum AppendOnlyProbe {
    /// The only good outcome — the store refused the delete.
    Denied,
    /// The credential may delete from the anchor bucket. Every anchor it
    /// writes is erasable by whoever holds it, which is the whole finding.
    Permitted,
    /// Neither proven nor disproven; carries the store's own message.
    Inconclusive(String),
}

/// Proves the anchor producer credential is genuinely append-only by asking
/// it to do the one thing it must not be able to do: delete.
///
/// Targets [`ANCHOR_APPEND_ONLY_PROBE_KEY`] — a key no anchor can occupy and
/// that never holds an object — so a correctly configured deployment gets
/// `AccessDenied` and nothing at all happens. See that constant's doc for the
/// artifact a *misconfigured* deployment leaves behind, and why that trade is
/// worth making.
///
/// This proves the identity-side control only. Object Lock retention — the
/// bucket-side backstop that still holds when the credential's restrictions
/// are what got bypassed — cannot be probed from here;
/// `scripts/audit/anchor-immutability-drill.sh` covers that half.
pub async fn probe_append_only(store: &StorageClient) -> AppendOnlyProbe {
    let path = match Path::parse(ANCHOR_APPEND_ONLY_PROBE_KEY) {
        Ok(p) => p,
        Err(e) => return AppendOnlyProbe::Inconclusive(e.to_string()),
    };

    match store.store().delete(&path).await {
        Err(object_store::Error::PermissionDenied { .. })
        | Err(object_store::Error::Unauthenticated { .. }) => AppendOnlyProbe::Denied,
        Ok(()) => AppendOnlyProbe::Permitted,
        // S3 answers `DeleteObject` on a missing key with 204 when the caller
        // is permitted, so a `NotFound` here still means the request was
        // authorized — the backend just reported the absence instead. Same
        // verdict as `Ok`: authorization is what is being measured, not
        // whether an object happened to be there.
        Err(object_store::Error::NotFound { .. }) => AppendOnlyProbe::Permitted,
        Err(e) => AppendOnlyProbe::Inconclusive(e.to_string()),
    }
}

/// Builds the [`StorageClient`] anchors are written through, resolving which
/// bucket and credential that means (D-352).
///
/// `audit.anchor_store` set — the production-required shape — gives the
/// dedicated WORM bucket and its append-only producer credential.
/// `audit.anchor_store` absent falls back to this deployment's general
/// `storage` bucket and the application's own credential, which is D-174's
/// original behavior: tamper-evident through this application, not
/// tamper-proof against anyone holding that credential.
///
/// The fallback is reachable only outside production —
/// `validate_production_profile` refuses `external_anchoring_enabled = true`
/// with no `anchor_store` — so it exists to keep `cargo run` and the test
/// suites working against a single dev RustFS bucket, not as a supported
/// deployment posture. It logs at `warn` so it can never be the quiet default
/// somebody later mistakes for the real thing.
pub async fn create_anchor_store(config: &AppConfig) -> Result<StorageClient, StorageError> {
    match &config.audit.anchor_store {
        Some(anchor) => {
            attome_storage::create_storage_client_for(anchor.s3_target(), "audit-anchor").await
        }
        None => {
            tracing::warn!(
                bucket = %config.storage.s3_bucket,
                "audit.external_anchoring_enabled is on with no audit.anchor_store — anchors \
                 will be written to the general storage bucket with this application's own \
                 credential, which holds DeleteObject. Anchors are therefore deletable by \
                 anyone holding it, including a party who has compromised this deployment. \
                 This is refused under app.deployment_profile = \"production\"; see \
                 deploy/audit-anchor/README.md"
            );
            attome_storage::create_storage_client(config).await
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AnchorRecord {
    organization_ref: Uuid,
    batch_id: Uuid,
    merkle_root: String,
    /// Application clock at write time — diagnostic only. The trusted upper
    /// bound on the batch's event times is the object's storage-assigned
    /// `Last-Modified` ([`fetch_anchor_bound`]), never this field (D-539).
    anchored_at: DateTime<Utc>,
}

/// P-audit-chain-hardening item (c), D-280 — the anchor record for an
/// epoch's seal, keyed by `(org, boundary_epoch_period)` rather than
/// `batch_id` (see [`epoch_seal_path`]). `boundary_epoch_period` is the NEW
/// epoch whose first batch is what triggered detecting the seal — chosen as
/// the lookup key (rather than `sealed_epoch_period`, the OLD epoch that
/// closed) specifically so a verifier bridging a dropped partition never
/// needs to compute anything: the oldest batch it can still see already
/// carries its own `epoch_period`, which IS `boundary_epoch_period` here,
/// no calendar arithmetic required on the read path. `sealed_epoch_period`
/// is carried for operator/audit legibility (which epoch this seal actually
/// closed), not used as a lookup key by anything.
#[derive(Debug, Serialize, Deserialize)]
struct EpochSealRecord {
    organization_ref: Uuid,
    sealed_epoch_period: NaiveDate,
    boundary_epoch_period: NaiveDate,
    batch_id: Uuid,
    merkle_root: String,
    anchored_at: DateTime<Utc>,
}

/// One anchor per `(org, batch_id)` — `batch_id` is a uuidv7
/// (`chainer::run_batch_for_org`'s `Uuid::now_v7()`), so this key is unique
/// per batch by construction; no other component of the path needs to
/// disambiguate collisions.
fn anchor_path(org: Uuid, batch_id: Uuid) -> Result<Path, AppError> {
    Path::parse(format!("audit-chain-anchors/{org}/{batch_id}.json")).map_err(AppError::internal)
}

/// Anchors `merkle_root` for `(org, batch_id)` to the deployment's own
/// configured object store. Idempotent: a `PutMode::Create` conflict (this
/// exact batch was already anchored — e.g. a retried call after a
/// network blip that actually succeeded) is treated as success, not an
/// error, since the desired end state ("this batch's root is anchored") is
/// already true either way.
pub async fn anchor_root(
    store: &StorageClient,
    org: Uuid,
    batch_id: Uuid,
    merkle_root: &str,
) -> Result<(), AppError> {
    let path = anchor_path(org, batch_id)?;
    let record = AnchorRecord {
        organization_ref: org,
        batch_id,
        merkle_root: merkle_root.to_owned(),
        anchored_at: Utc::now(),
    };
    let bytes = serde_json::to_vec(&record).map_err(AppError::internal)?;

    let opts = PutOptions {
        mode: PutMode::Create,
        ..Default::default()
    };
    match store.store().put_opts(&path, bytes.into(), opts).await {
        Ok(_) => Ok(()),
        Err(object_store::Error::AlreadyExists { .. }) => {
            match fetch_anchored_root(store, org, batch_id).await? {
                Some(existing) if existing == merkle_root => Ok(()),
                Some(existing) => Err(AppError::internal(format!(
                    "conflicting audit anchor for organization {org}, batch {batch_id}: \
                     existing root {existing}, attempted root {merkle_root}"
                ))),
                None => Err(AppError::internal(
                    "audit anchor create reported AlreadyExists but the object could not be read",
                )),
            }
        }
        Err(e) => Err(AppError::internal(e)),
    }
}

/// Recovery from a failed anchoring attempt (P-audit-chain-hardening item
/// (b), external feedback item 18: "document recovery from a failed
/// anchoring attempt"). `chainer::run_batch_for_org` only ever anchors a
/// batch once, immediately after its commit, best-effort — if that one
/// attempt fails (the object store was briefly unreachable, a credential
/// rotated, etc.) nothing retries it automatically, since anchoring must
/// never block or be retried inline against the chainer's own progress
/// (D-027 degrade-not-fail, see this module's top doc). This is the
/// operator-triggered backfill for exactly that gap: re-reads the batch's
/// already-durable `merkle_root` from `audit_chain_batch` (never
/// recomputed — the in-database chain is the source of truth for what the
/// root *is*; anchoring only ever copies it outward) and re-calls
/// [`anchor_root`], which is itself idempotent, so calling this for a batch
/// that actually anchored successfully the first time is always safe.
///
/// Typical flow: run `verify_audit_chain`'s anchor cross-check
/// (`verify::verify_anchors`), take its `unanchored` batch ids for an
/// organization, and call this once per id — see
/// `crates/server/src/bin/verify_audit_chain.rs`'s `--reanchor` flag for the
/// operator-facing wrapper around exactly this loop.
pub async fn reanchor_batch(
    db: &DbPool,
    store: &StorageClient,
    org: Uuid,
    batch_id: Uuid,
) -> Result<(), AppError> {
    let merkle_root: Option<String> = sqlx::query_scalar(
        "SELECT merkle_root FROM audit_chain_batch
         WHERE id = $1 AND organization_ref = $2",
    )
    .bind(batch_id)
    .bind(org)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    let merkle_root = merkle_root.ok_or_else(|| {
        AppError::Validation(format!(
            "no audit_chain_batch row for organization {org}, batch {batch_id} — \
             cannot reanchor a batch that was never chained"
        ))
    })?;

    anchor_root(store, org, batch_id, &merkle_root).await
}

/// Well-known path keyed by `(org, boundary_epoch_period)` alone —
/// deliberately NOT `batch_id`, unlike [`anchor_path`]. P-audit-chain-
/// hardening item (c), D-280: once an old partition is dropped, a verifier
/// has no way to learn the batch_id of whatever batch used to close the
/// preceding epoch — that row is gone. What a verifier DOES still have is
/// the oldest *remaining* batch's own `epoch_period` column — and that IS
/// `boundary_epoch_period` (see [`EpochSealRecord`]'s doc comment for why
/// the seal is keyed by the new epoch rather than the old one), so no
/// calendar arithmetic is needed to find it, only a direct lookup.
fn epoch_seal_path(org: Uuid, boundary_epoch_period: NaiveDate) -> Result<Path, AppError> {
    Path::parse(format!(
        "audit-chain-anchors/{org}/epoch-boundary/{boundary_epoch_period}.json"
    ))
    .map_err(AppError::internal)
}

/// Anchors `(batch_id, merkle_root)` as the seal that closed
/// `sealed_epoch_period`, filed under `boundary_epoch_period` (the new
/// epoch whose first batch triggered detecting the seal — see
/// [`EpochSealRecord`] for why the key is the new epoch, not the old one).
///
/// Called by `chainer::run_batch_for_org` only when it detects — after the
/// fact — that the previous batch it just chained belongs to an earlier
/// calendar month than the batch it is about to write: that previous batch
/// was the last one of its epoch. This can only ever be known in hindsight
/// (there is no way to predict in advance whether an organization will ever
/// produce another batch in a later month), so sealing is always one batch
/// behind the epoch boundary itself, never proactive.
///
/// Idempotent the same way [`anchor_root`] is: a `PutMode::Create` conflict
/// (this epoch was already sealed — e.g. a retried call after a network
/// blip that actually succeeded) is treated as success, not an error.
pub async fn anchor_epoch_seal(
    store: &StorageClient,
    org: Uuid,
    sealed_epoch_period: NaiveDate,
    boundary_epoch_period: NaiveDate,
    batch_id: Uuid,
    merkle_root: &str,
) -> Result<(), AppError> {
    let path = epoch_seal_path(org, boundary_epoch_period)?;
    let record = EpochSealRecord {
        organization_ref: org,
        sealed_epoch_period,
        boundary_epoch_period,
        batch_id,
        merkle_root: merkle_root.to_owned(),
        anchored_at: Utc::now(),
    };
    let bytes = serde_json::to_vec(&record).map_err(AppError::internal)?;

    let opts = PutOptions {
        mode: PutMode::Create,
        ..Default::default()
    };
    match store.store().put_opts(&path, bytes.into(), opts).await {
        Ok(_) => Ok(()),
        Err(object_store::Error::AlreadyExists { .. }) => {
            match fetch_epoch_seal(store, org, boundary_epoch_period).await? {
                Some((existing_batch, existing_root))
                    if existing_batch == batch_id && existing_root == merkle_root =>
                {
                    Ok(())
                }
                Some((existing_batch, existing_root)) => Err(AppError::internal(format!(
                    "conflicting audit epoch seal at boundary {boundary_epoch_period}: \
                     existing batch/root {existing_batch}/{existing_root}, attempted \
                     {batch_id}/{merkle_root}"
                ))),
                None => Err(AppError::internal(
                    "audit epoch-seal create reported AlreadyExists but the object could not be read",
                )),
            }
        }
        Err(e) => Err(AppError::internal(e)),
    }
}

/// Fetches the sealed `(batch_id, merkle_root)` filed under
/// `boundary_epoch_period` — pass the oldest-remaining batch's own
/// `epoch_period` directly, no arithmetic needed (see [`EpochSealRecord`]).
/// `Ok(None)` covers both "this epoch hasn't closed yet" (it's still the
/// live/current epoch, or the organization never produced a later batch)
/// and "it closed before external anchoring was enabled" — same
/// non-distinguishing convention as `fetch_anchored_root`, for the same
/// reason: neither is a verification failure on its own.
/// `verify::verify_batches` is the caller that turns a `None` here into an
/// actual reported error, when appropriate.
pub async fn fetch_epoch_seal(
    store: &StorageClient,
    org: Uuid,
    boundary_epoch_period: NaiveDate,
) -> Result<Option<(Uuid, String)>, AppError> {
    let path = epoch_seal_path(org, boundary_epoch_period)?;
    match store.store().get(&path).await {
        Ok(result) => {
            let bytes = result.bytes().await.map_err(AppError::internal)?;
            let record: EpochSealRecord =
                serde_json::from_slice(&bytes).map_err(AppError::internal)?;
            if record.organization_ref != org
                || record.boundary_epoch_period != boundary_epoch_period
            {
                return Err(AppError::internal(
                    "audit epoch-seal record identity does not match its object-store key",
                ));
            }
            Ok(Some((record.batch_id, record.merkle_root)))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(AppError::internal(e)),
    }
}

/// C14 / D-539 ruling 5 — the batch's **anchor bound**: the storage-assigned
/// `Last-Modified` time of its anchor object, read live with a `HEAD`. Every
/// event in the batch existed before the store accepted the anchor, so a v2
/// event time later than this (plus one second of HTTP-date granularity) is
/// reported by `verify::verify_chain_with_anchors`. Deliberately not copied
/// into the database, where it would be as untrusted as the rows it bounds.
/// The `anchored_at` field inside the anchor JSON is the application clock:
/// diagnostic only, never compared. `Ok(None)` when the batch was never
/// anchored.
pub async fn fetch_anchor_bound(
    store: &StorageClient,
    org: Uuid,
    batch_id: Uuid,
) -> Result<Option<DateTime<Utc>>, AppError> {
    let path = anchor_path(org, batch_id)?;
    match store.store().head(&path).await {
        Ok(meta) => Ok(Some(meta.last_modified)),
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(AppError::internal(e)),
    }
}

/// Fetches the externally anchored root for `(org, batch_id)`, if one was
/// ever written — the standalone verification path the plan's goal (§3(b))
/// calls for: an external auditor (or this platform's own periodic
/// self-check) can confirm a batch's `audit_chain_batch.merkle_root`
/// against this copy without trusting anything else read from this
/// deployment's own Postgres. `Ok(None)` for a batch that predates
/// `external_anchoring_enabled` being turned on, or one anchoring itself
/// failed for (best-effort, per the module doc) — not distinguished from
/// each other, since neither is a verification failure on its own; a
/// caller wanting mandatory anchoring compares this against
/// `audit_chain_batch.merkle_root` and treats `None` as its own
/// finding.
pub async fn fetch_anchored_root(
    store: &StorageClient,
    org: Uuid,
    batch_id: Uuid,
) -> Result<Option<String>, AppError> {
    let path = anchor_path(org, batch_id)?;
    match store.store().get(&path).await {
        Ok(result) => {
            let bytes = result.bytes().await.map_err(AppError::internal)?;
            let record: AnchorRecord =
                serde_json::from_slice(&bytes).map_err(AppError::internal)?;
            if record.organization_ref != org || record.batch_id != batch_id {
                return Err(AppError::internal(
                    "audit anchor record identity does not match its object-store key",
                ));
            }
            Ok(Some(record.merkle_root))
        }
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(e) => Err(AppError::internal(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_path_is_scoped_by_organization_and_batch() {
        let org = Uuid::now_v7();
        let batch_a = Uuid::now_v7();
        let batch_b = Uuid::now_v7();

        let path_a = anchor_path(org, batch_a).unwrap();
        let path_b = anchor_path(org, batch_b).unwrap();

        assert_ne!(path_a, path_b, "distinct batches must never share a key");
        assert!(path_a.as_ref().starts_with("audit-chain-anchors/"));
        assert!(path_a.as_ref().contains(&org.to_string()));
        assert!(path_a.as_ref().contains(&batch_a.to_string()));
    }

    #[test]
    fn anchor_record_round_trips_through_json() {
        let record = AnchorRecord {
            organization_ref: Uuid::now_v7(),
            batch_id: Uuid::now_v7(),
            merkle_root: "a".repeat(64),
            anchored_at: Utc::now(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let decoded: AnchorRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.merkle_root, record.merkle_root);
        assert_eq!(decoded.batch_id, record.batch_id);
        assert_eq!(decoded.organization_ref, record.organization_ref);
    }

    #[test]
    fn epoch_seal_path_is_keyed_by_period_not_batch_id() {
        let org = Uuid::now_v7();
        let period_a = NaiveDate::from_ymd_opt(2026, 7, 1).unwrap();
        let period_b = NaiveDate::from_ymd_opt(2026, 8, 1).unwrap();

        let path_a = epoch_seal_path(org, period_a).unwrap();
        let path_b = epoch_seal_path(org, period_b).unwrap();

        assert_ne!(
            path_a, path_b,
            "distinct epochs must never share a key, even for the same org"
        );
        assert!(path_a.as_ref().starts_with("audit-chain-anchors/"));
        assert!(path_a.as_ref().contains(&org.to_string()));
        assert!(path_a.as_ref().contains("2026-07-01"));
        // Deliberately NOT scoped by batch_id — see this function's doc
        // comment for why: a verifier bridging a dropped partition only
        // ever has the epoch period to look up with, never the sealing
        // batch's id.
        assert!(path_a.as_ref().contains("/epoch-boundary/"));
    }

    #[test]
    fn epoch_seal_record_round_trips_through_json() {
        let record = EpochSealRecord {
            organization_ref: Uuid::now_v7(),
            sealed_epoch_period: NaiveDate::from_ymd_opt(2026, 6, 1).unwrap(),
            boundary_epoch_period: NaiveDate::from_ymd_opt(2026, 8, 1).unwrap(),
            batch_id: Uuid::now_v7(),
            merkle_root: "b".repeat(64),
            anchored_at: Utc::now(),
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let decoded: EpochSealRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.merkle_root, record.merkle_root);
        assert_eq!(decoded.batch_id, record.batch_id);
        assert_eq!(decoded.organization_ref, record.organization_ref);
        assert_eq!(decoded.sealed_epoch_period, record.sealed_epoch_period);
        assert_eq!(decoded.boundary_epoch_period, record.boundary_epoch_period);
    }

    // NOT covered here — needs a live object store (RustFS/S3), unavailable
    // in this environment:
    //   - anchor_root then fetch_anchored_root round-trips the real merkle
    //     root through an actual put/get cycle.
    //   - a second anchor_root call for the same (org, batch_id) is a no-op
    //     (PutMode::Create conflict swallowed) rather than an error.
    //   - fetch_anchored_root returns Ok(None), not an error, for a
    //     (org, batch_id) that was never anchored.
    //   - reanchor_batch: needs BOTH a live object store AND a live Postgres
    //     with a real audit_chain_batch row (TODO, external feedback
    //     item 18) — (1) reanchoring a batch whose first attempt never wrote
    //     anything succeeds and fetch_anchored_root then returns the right
    //     root, (2) reanchoring an already-anchored batch is a no-op (via
    //     anchor_root's own idempotency), (3) reanchoring an id with no
    //     audit_chain_batch row returns AppError::Validation, not a
    //     panic or a silent no-op.
    //   - anchor_epoch_seal then fetch_epoch_seal round-trips through an
    //     actual put/get cycle the same way (org, batch_id) anchoring does
    //     above (P-audit-chain-hardening item (c), D-280) — same gap, same
    //     reason.
    //   - probe_append_only returns Denied against a genuinely locked-down
    //     producer credential (D-352). Untested in BOTH directions and the
    //     riskier half is which `object_store::Error` variant a real
    //     MinIO/RustFS/AWS `AccessDenied` actually maps to: this asserts
    //     `PermissionDenied`/`Unauthenticated` from the crate's error
    //     taxonomy, not from observation. A wrong guess lands in
    //     `Inconclusive`, which preflight fails — so the failure mode is an
    //     unhelpful verdict, never a falsely reassuring one.
    // See this crate's `chainer` integration tests
    // (`tests/chainer_end_to_end.rs` and siblings) for the pattern a live
    // version of these would follow once a test RustFS/MinIO endpoint is
    // available in CI. The bucket-side half of D-352 (retention actually
    // refusing a purge) is not a Rust test at all — it needs a real WORM
    // bucket, and lives in scripts/audit/anchor-immutability-drill.sh.
}
