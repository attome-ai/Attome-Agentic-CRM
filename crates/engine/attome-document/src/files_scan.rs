//! P-file-upload-pipeline — the async scan job (`EngineJob::ScanUploadedFile`)
//! and the orphan-sweep job (`EngineJob::PruneExpiredUploadSessions`).
//!
//! Never runs on the request thread (guidelines §9/§10): `files.rs`'s
//! `finalize_upload_session` only enqueues this; everything here — the S3
//! GET, the ClamAV round trip — happens in the background worker.
use std::time::Duration;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::EngineState;
use attome_types::AppError;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures_util::{Stream, TryStreamExt};
use object_store::{GetOptions, ObjectStoreExt, path::Path as ObjectPath};
use sha2::{Digest, Sha256};
use sqlx::Postgres;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::files::FileOwner;

/// Same reclaim window as `automation_bulk_operation_item.claimed_at`
/// (`bulk.rs::STALE_CLAIM_AFTER_SECS`) — a crashed worker's claim is
/// reclaimable rather than wedging the session forever.
const STALE_CLAIM_AFTER_SECS: i64 = 120;

/// How long a session may sit `uploaded`/`scanning` before the sweep calls it
/// a failed scan (UP-1.2). The plan's 24 h: long enough that a real backlog or
/// a scanner outage can be fixed, short enough that no session sits in a
/// non-terminal state indefinitely (U3).
pub(crate) const SCAN_DEADLINE_SECS: i64 = 24 * 60 * 60;

/// Rows one sweep pass claims per run — bounded so a sweep can neither scan an
/// unbounded set nor hold a long transaction, and so the next run (every
/// 900 s) picks up where this one stopped (UP-1, UP-F8).
const SWEEP_BATCH_LIMIT: i64 = 500;

/// Bounds the clamd INSTREAM round trip (connect + stream + response) — a
/// hung scanner must fail the job (retryable) rather than block the worker
/// indefinitely (guidelines §10).
const CLAMD_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounds each streamed S3 GET (the hash+sniff pass and, separately, the
/// re-fetch that feeds clamd) — same guidelines §10 concern, now covering
/// the download itself rather than only the in-memory `bytes()` call the
/// old code awaited with no timeout at all.
const OBJECT_STREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// Bounds how much of the object's leading bytes are buffered for
/// magic-byte content-type sniffing (`infer::get`) — far more than any
/// allowlisted format's signature needs, but nowhere near the full object.
/// This is the fix for the reported defect: the scan job used to hold the
/// entire object (`GetResult::bytes()`) in memory just to sniff+hash it;
/// at concurrency 3 x a 25 MB upload that was ~75 MB baseline before
/// ClamAV even started. Now only this bounded prefix plus per-chunk
/// transient buffers are ever resident.
const SNIFF_BUFFER_LEN: usize = 64 * 1024;

/// Sub-chunk size written to clamd's INSTREAM socket — independent of
/// whatever chunk sizes the underlying S3 stream happens to hand back.
const INSTREAM_CHUNK_SIZE: usize = 16 * 1024;

struct ClaimedSession {
    entity_logicalname: String,
    record_id: Uuid,
    field_logicalname: String,
    /// The session's one owner, staff or portal user (D-774).
    owner: FileOwner,
    quarantine_key: String,
    declared_filename: String,
    declared_content_type: String,
    declared_checksum_sha256: Option<String>,
}

/// Claims one `uploaded`/stale-`scanning` session for scanning, transitioning
/// it to `scanning`. Returns `None` when there is nothing (more) to do —
/// already claimed by a live attempt, already terminal, or the row is gone —
/// which is not an error: the caller should simply return `Ok(())`.
type ClaimRowTuple = (
    String,
    Uuid,
    String,
    Option<Uuid>,
    Option<Uuid>,
    String,
    String,
    String,
    Option<String>,
    String,
    Option<DateTime<Utc>>,
);

async fn claim(state: &EngineState, session_id: Uuid) -> Result<Option<ClaimedSession>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<ClaimRowTuple> = sqlx::query_as(
        "SELECT entity_logicalname, record_id, field_logicalname, owner_user_ref,
                owner_portal_user_ref, quarantine_key, declared_filename, declared_content_type,
                declared_checksum_sha256, status, claimed_at
         FROM upload_session
         WHERE id = $1 AND is_deleted = false
         FOR UPDATE",
    )
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let Some((
        entity_logicalname,
        record_id,
        field_logicalname,
        owner_user_ref,
        owner_portal_user_ref,
        quarantine_key,
        declared_filename,
        declared_content_type,
        declared_checksum_sha256,
        status,
        claimed_at,
    )) = row
    else {
        return Ok(None);
    };

    let stale = claimed_at
        .is_some_and(|c| Utc::now() - c > chrono::Duration::seconds(STALE_CLAIM_AFTER_SECS));
    let claimable = match status.as_str() {
        "uploaded" => true,
        "scanning" => stale,
        _ => false, // pending, clean, rejected, expired
    };
    if !claimable {
        return Ok(None);
    }
    // Before the claim commits, so a malformed row (both or neither owner,
    // which the validated CHECK rules out) is never left stuck in `scanning`.
    let owner = FileOwner::from_columns(owner_user_ref, owner_portal_user_ref)?;

    let updated = sqlx::query(
        "UPDATE upload_session
            SET status = 'scanning', claimed_at = NOW(), updated_at = NOW(),
                row_version = row_version + 1
          WHERE id = $1",
    )
    .bind(session_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::internal("upload session claim affected no rows"));
    }
    attome_db::tx::commit(tx).await?;

    Ok(Some(ClaimedSession {
        entity_logicalname,
        record_id,
        field_logicalname,
        owner,
        quarantine_key,
        declared_filename,
        declared_content_type,
        declared_checksum_sha256,
    }))
}

enum ScanOutcome {
    Clean {
        actual_content_type: String,
        actual_checksum_sha256: String,
    },
    /// `client_reason` is what the session's own `reject_reason` column (and
    /// therefore the owner-visible status-poll endpoint) shows — kept
    /// generic for the malware case; `audit_detail` carries anything more
    /// specific (e.g. the signature name) into the audit event only.
    Rejected {
        client_reason: &'static str,
        audit_detail: String,
        keep_quarantine_object: bool,
    },
    /// K2-T1: the scanner found malware. Rejected like any other refusal,
    /// with the object kept under the quarantine prefix as evidence and
    /// never promoted, and the uploader and administrators are told.
    Infected { signature: String },
}

/// Rejection used both when `GetResult::meta.size` already reports an
/// over-ceiling object (cheap, no bytes read) and when the running total
/// crosses the ceiling mid-stream (defense in depth against a store that
/// misreports its own metadata) — same client-visible/audit wording either
/// way, the caller just picks which check fired.
fn too_large_outcome(max_bytes: u64) -> ScanOutcome {
    ScanOutcome::Rejected {
        client_reason: "uploaded object exceeds the configured size limit",
        audit_detail: format!("object exceeds storage.max_upload_size_bytes ({max_bytes} bytes)"),
        keep_quarantine_object: false,
    }
}

/// Claims the two cheap, clamd-independent checks first (checksum, sniffed
/// content-type) exactly as the pre-streaming version did — a mismatch on
/// either rejects without ever opening a connection to clamd, which is what
/// `scan_job_rejects_a_checksum_mismatch_without_promoting` in
/// `tests/file_upload_pipeline.rs` exercises without a reachable scanner.
/// Only a candidate that passes both is re-fetched and streamed into clamd.
async fn run_scan(
    state: &EngineState,
    claimed: &ClaimedSession,
    quarantine_path: &ObjectPath,
    first_stream: impl Stream<Item = object_store::Result<Bytes>> + Unpin,
    // BST-7: the ETag of the bytes `process` just read. Every later read of
    // this object — the re-fetch below and the promote — must match it.
    source_etag: &str,
) -> Result<ScanOutcome, AppError> {
    let storage_cfg = &state.base.config.storage;
    let max_bytes = storage_cfg.max_upload_size_bytes;

    let hashed = hash_and_sniff(max_bytes, first_stream).await?;
    let (computed_checksum, sniff_prefix) = match hashed {
        HashedPrefix::TooLarge => return Ok(too_large_outcome(max_bytes)),
        HashedPrefix::Done {
            computed_checksum,
            sniff_prefix,
        } => (computed_checksum, sniff_prefix),
    };

    if let Some(declared) = &claimed.declared_checksum_sha256
        && !declared.eq_ignore_ascii_case(&computed_checksum)
    {
        return Ok(ScanOutcome::Rejected {
            client_reason: "declared checksum does not match uploaded bytes",
            audit_detail: "checksum mismatch".to_string(),
            keep_quarantine_object: false,
        });
    }

    // Sniff actual magic bytes from the buffered leading prefix when available.
    let sniffed = infer::get(&sniff_prefix).map(|t| t.mime_type().to_string());

    let is_image = crate::files::is_image_field(
        state,
        &claimed.entity_logicalname,
        &claimed.field_logicalname,
    );

    // U9: an `image` field promotes only real images. Finalize sniffed the
    // bytes too, but the presigned PUT stays valid for the session TTL, so
    // these — the bytes about to be promoted — are the ones that count.
    if is_image
        && !sniffed
            .as_deref()
            .is_some_and(crate::files::is_allowed_image_type)
    {
        return Ok(ScanOutcome::Rejected {
            client_reason: "uploaded object is not an allowed image type",
            audit_detail: format!(
                "image field received a non-image upload (sniffed: {})",
                sniffed.as_deref().unwrap_or("unknown")
            ),
            keep_quarantine_object: false,
        });
    }

    // BST-13/D-617: a generic `file` field is held to the same standard, with
    // the platform allowlist as the policy. The declared type was checked at
    // session create, but these — the bytes about to be promoted — are the
    // ones that would reach a record, so they must be an allowlisted type
    // themselves. `text/plain`/`text/csv` carry no magic signature for
    // `infer` to find, so they are the only declared types a no-sniff result
    // is acceptable for; everything else must be identifiable from its own
    // bytes. The forced `attachment` disposition (BST-6) is the second,
    // independent control for exactly those two cases.
    if !is_image {
        let declared = crate::files::content_type_essence(&claimed.declared_content_type);
        if !crate::files::is_allowed_content_type(&declared) {
            return Ok(ScanOutcome::Rejected {
                client_reason: "uploaded object is not an allowed file type",
                audit_detail: format!("declared content type is not allowed: {declared}"),
                keep_quarantine_object: false,
            });
        }
        let sniff_free = crate::files::SNIFF_FREE_CONTENT_TYPES.contains(&declared.as_str());
        match sniffed.as_deref() {
            Some(sniffed_type) if !crate::files::is_allowed_content_type(sniffed_type) => {
                return Ok(ScanOutcome::Rejected {
                    client_reason: "uploaded object is not an allowed file type",
                    audit_detail: format!(
                        "sniffed content type is not allowed: {sniffed_type} (declared {declared})"
                    ),
                    keep_quarantine_object: false,
                });
            }
            Some(sniffed_type) if !sniff_free && sniffed_type != declared => {
                return Ok(ScanOutcome::Rejected {
                    client_reason: "uploaded object does not match its declared file type",
                    audit_detail: format!("declared {declared} but the bytes are {sniffed_type}"),
                    keep_quarantine_object: false,
                });
            }
            None if !sniff_free => {
                return Ok(ScanOutcome::Rejected {
                    client_reason: "uploaded object's file type could not be verified",
                    audit_detail: format!("no magic-byte signature found for declared {declared}"),
                    keep_quarantine_object: false,
                });
            }
            _ => {}
        }
    }

    let clamd_address = storage_cfg.clamd_address.trim();
    if clamd_address.is_empty() {
        // Fail closed (§8's documented risk): no silent skip. The job stays
        // retryable — the session sits in `scanning` until its claim goes
        // stale, so a backlog is visible via `apalis.jobs`'s pending count
        // rather than a false "clean" promotion.
        return Err(AppError::internal(
            "storage.clamd_address is not configured — refusing to promote an unscanned upload",
        ));
    }

    // Re-fetch rather than replay the first stream: the same
    // never-buffer-the-whole-object approach `retention.rs`'s
    // `verify_uploaded_checksum` already uses for its own re-download —
    // a deliberate, real bandwidth cost, only paid once the cheap checks
    // above already passed. The re-fetch is ETag-pinned (BST-7).
    // BST-7: pinned to the ETag the first pass read, so the bytes handed to
    // clamd are the bytes that were hashed and sniffed. A re-PUT of the
    // quarantine key between the two reads fails here as `Precondition`
    // rather than being scanned as if it were the same object.
    let get_result = match state
        .base
        .storage
        .store()
        .get_opts(
            quarantine_path,
            GetOptions::new().with_if_match(Some(source_etag)),
        )
        .await
    {
        Ok(result) => result,
        Err(object_store::Error::Precondition { .. }) => {
            return Ok(ScanOutcome::Rejected {
                client_reason: "uploaded object changed while it was being scanned",
                audit_detail: "source ETag changed between the scan pass and the clamd pass"
                    .to_string(),
                keep_quarantine_object: true,
            });
        }
        Err(e) => return Err(AppError::internal(e)),
    };
    if get_result.meta.size > max_bytes {
        return Ok(too_large_outcome(max_bytes));
    }
    let second_stream = get_result.into_stream();

    match clamav_instream_scan(clamd_address, max_bytes, second_stream).await? {
        ClamOutcome::TooLarge => Ok(too_large_outcome(max_bytes)),
        ClamOutcome::Result(ClamResult::Clean) => Ok(ScanOutcome::Clean {
            actual_content_type: sniffed.unwrap_or_else(|| claimed.declared_content_type.clone()),
            actual_checksum_sha256: computed_checksum,
        }),
        ClamOutcome::Result(ClamResult::Positive(signature)) => {
            Ok(ScanOutcome::Infected { signature })
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ClamResult {
    Clean,
    Positive(String),
}

/// clamd's INSTREAM answer: `stream: OK`, or `stream: <signature> FOUND`.
/// Anything else (an `ERROR` line, a size-limit refusal, nothing) is an
/// error, so the job retries and the file stays pending (fail closed).
fn parse_clamd_response(raw: &str) -> Result<ClamResult, String> {
    let response = raw.trim_end_matches('\0').trim();
    if let Some(signature) = response
        .strip_prefix("stream: ")
        .and_then(|s| s.strip_suffix(" FOUND"))
    {
        Ok(ClamResult::Positive(signature.to_string()))
    } else if response.ends_with("OK") && !response.contains("ERROR") {
        Ok(ClamResult::Clean)
    } else {
        Err(format!("unexpected clamd response: {response}"))
    }
}

/// K2-T1: what the uploader and the administrators are told when an upload
/// held malware, as `(subject, body)`. The uploader's names the file and the
/// record kind only; the administrators' also names the record, the field and
/// the scanner's signature, so they can find it and judge the threat.
fn infected_notices(
    filename: &str,
    entity: &str,
    record_id: Uuid,
    field: &str,
    signature: &str,
) -> ((String, String), (String, String)) {
    let uploader = (
        "A file you uploaded was blocked".to_owned(),
        format!(
            "The file \"{filename}\" you added to a {entity} record contained malware. \
             It was quarantined and not saved. Check the device you uploaded it from."
        ),
    );
    let admins = (
        "Malware blocked in an upload".to_owned(),
        format!(
            "The virus scanner found {signature} in \"{filename}\", uploaded to the {field} \
             field of {entity} record {record_id}. The file was quarantined and never served."
        ),
    );
    (uploader, admins)
}

/// Sends the [`infected_notices`], best effort: the rejection and its audit
/// event are already committed, so a failed notice is logged, not retried.
/// A portal uploader has no staff inbox and is told through the upload's
/// status (`rejected`) only.
async fn notify_infected(state: &EngineState, claimed: &ClaimedSession, signature: &str) {
    let ((user_subject, user_body), (admin_subject, admin_body)) = infected_notices(
        &claimed.declared_filename,
        &claimed.entity_logicalname,
        claimed.record_id,
        &claimed.field_logicalname,
        signature,
    );
    let notification_cfg = &state.base.config.notification;
    if let FileOwner::Staff(user_id) = claimed.owner {
        let request = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_owned(),
            recipient_user_ref: Some(user_id),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some(user_subject),
            body_html: None,
            body_text: Some(user_body),
            route: None,
            variables: std::collections::HashMap::new(),
            priority: "high".to_owned(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        if let Err(error) = attome_notification::dispatch::create_dispatch(
            &state.base.db,
            notification_cfg,
            request,
        )
        .await
        {
            tracing::warn!(%error, %user_id, "scan: the uploader was not told about blocked malware");
        }
    }
    attome_notification::dispatch::alert_admins(
        &state.base.db,
        notification_cfg,
        admin_subject,
        admin_body,
        "/xrm/admin/audit/search",
    )
    .await;
}

enum ClamOutcome {
    /// Running total crossed `max_bytes` mid-stream on the re-fetch —
    /// shouldn't happen (the first pass already verified the size), but
    /// guarded rather than trusted; the socket is simply dropped, no
    /// terminator/response exchange needed since the caller is rejecting
    /// regardless.
    TooLarge,
    Result(ClamResult),
}

enum HashedPrefix {
    TooLarge,
    Done {
        computed_checksum: String,
        sniff_prefix: Vec<u8>,
    },
}

/// First pass over the object: a running SHA-256 hash plus a bounded
/// leading-bytes buffer for content-type sniffing, enforcing the hard byte
/// ceiling as it goes — never clamd, never the whole object in memory (the
/// reported defect: `GetResult::bytes()` held the entire upload just to
/// hash+sniff it; at concurrency 3 x a 25 MB upload that was ~75 MB baseline
/// before ClamAV even started).
async fn hash_and_sniff(
    max_bytes: u64,
    mut object_stream: impl Stream<Item = object_store::Result<Bytes>> + Unpin,
) -> Result<HashedPrefix, AppError> {
    tokio::time::timeout(OBJECT_STREAM_TIMEOUT, async {
        let mut hasher = Sha256::new();
        let mut sniff_prefix: Vec<u8> = Vec::with_capacity(SNIFF_BUFFER_LEN);
        let mut total: u64 = 0;

        while let Some(chunk) = object_stream.try_next().await.map_err(AppError::internal)? {
            total += chunk.len() as u64;
            if total > max_bytes {
                return Ok(HashedPrefix::TooLarge);
            }
            hasher.update(&chunk);
            if sniff_prefix.len() < SNIFF_BUFFER_LEN {
                let take = (SNIFF_BUFFER_LEN - sniff_prefix.len()).min(chunk.len());
                sniff_prefix.extend_from_slice(&chunk[..take]);
            }
        }

        Ok(HashedPrefix::Done {
            computed_checksum: hex::encode(hasher.finalize()),
            sniff_prefix,
        })
    })
    .await
    .map_err(|_| AppError::internal("object hashing/sniffing timed out"))?
}

/// Minimal ClamAV `INSTREAM` client (zINSTREAM protocol): a 0-terminated
/// command, then a stream of `{u32 BE length}{chunk}` pairs terminated by a
/// zero-length chunk, then one text response line. Streams `object_stream`
/// straight onto the socket, re-chunked to `INSTREAM_CHUNK_SIZE`, instead of
/// buffering the object first. No native/C dependency — this is a plain TCP
/// protocol, unlike a client library that would bind libclamav itself
/// (guidelines §1's "isolate a native build dependency" simply doesn't apply
/// here: there is none).
async fn clamav_instream_scan(
    address: &str,
    max_bytes: u64,
    mut object_stream: impl Stream<Item = object_store::Result<Bytes>> + Unpin,
) -> Result<ClamOutcome, AppError> {
    tokio::time::timeout(CLAMD_TIMEOUT, async {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|e| AppError::internal(format!("clamd connect failed: {e}")))?;
        stream
            .write_all(b"zINSTREAM\0")
            .await
            .map_err(AppError::internal)?;

        let mut total: u64 = 0;
        while let Some(chunk) = object_stream.try_next().await.map_err(AppError::internal)? {
            total += chunk.len() as u64;
            if total > max_bytes {
                return Ok(ClamOutcome::TooLarge);
            }
            for instream_chunk in chunk.chunks(INSTREAM_CHUNK_SIZE) {
                stream
                    .write_all(&(instream_chunk.len() as u32).to_be_bytes())
                    .await
                    .map_err(AppError::internal)?;
                stream
                    .write_all(instream_chunk)
                    .await
                    .map_err(AppError::internal)?;
            }
        }
        stream
            .write_all(&0u32.to_be_bytes())
            .await
            .map_err(AppError::internal)?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(AppError::internal)?;
        let response = String::from_utf8_lossy(&response);
        parse_clamd_response(&response)
            .map(ClamOutcome::Result)
            .map_err(AppError::internal)
    })
    .await
    .map_err(|_| AppError::internal("clamd scan timed out"))?
}

async fn write_scan_audit_event(
    state: &EngineState,
    tx: &mut sqlx::Transaction<'_, Postgres>,
    claimed: &ClaimedSession,
    operation_note: &str,
) -> Result<(), AppError> {
    // D-774: a staff owner's context as before; a portal owner is recorded
    // by id and attributed as a portal user (D-579: no staff id on a portal
    // write), under the root organisation like a portal profile edit.
    let (user_ctx, org_ref) = match claimed.owner {
        FileOwner::Staff(user_id) => {
            attome_records::entity_crud::fetch_audit_ctx(state, user_id).await
        }
        FileOwner::Portal(portal_user_id) => (
            attome_audit::AuditUserContext {
                user_id: portal_user_id,
                user_name: String::new(),
                user_display_name: String::new(),
                user_email: String::new(),
                user_job_ref: None,
                user_job_name: None,
            },
            attome_core::ROOT_ORGANIZATION_ID,
        ),
    };
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Attachment,
        entity_name: Some(claimed.entity_logicalname.clone()),
        record_id: Some(claimed.record_id),
        operation: AuditOperation::FileScanned,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(claimed.field_logicalname.clone()),
        event_comment: Some(operation_note.to_string()),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());
    match claimed.owner {
        FileOwner::Staff(_) => {
            audit_service.write_in_tx(tx, event).await?;
        }
        FileOwner::Portal(portal_user_id) => {
            audit_service
                .write_in_tx_attributed(
                    tx,
                    event,
                    attome_audit::initiator::Attribution::portal_user(portal_user_id),
                )
                .await?;
        }
    }
    Ok(())
}

/// The one reject path: CAS the session to `rejected`, write the
/// `FileScanned` audit event in the same transaction, then (unless the object
/// is worth keeping as evidence) delete the quarantined bytes.
///
/// Every rejection funnels through here — the explicit scan outcomes and the
/// promote-time ETag failure alike (BST-7) — so a rejected session always has
/// exactly one audit event and one state transition.
async fn reject_session(
    state: &EngineState,
    session_id: Uuid,
    claimed: &ClaimedSession,
    quarantine_path: &ObjectPath,
    client_reason: &str,
    audit_detail: &str,
    keep_quarantine_object: bool,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE upload_session
            SET status = 'rejected', reject_reason = $1, updated_at = NOW(),
                row_version = row_version + 1
          WHERE id = $2 AND status IN ('uploaded', 'scanning')",
    )
    .bind(client_reason)
    .bind(session_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::internal(
            "upload session reject affected no rows (concurrent claim?)",
        ));
    }
    write_scan_audit_event(
        state,
        &mut tx,
        claimed,
        &format!("scan result: rejected ({audit_detail})"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;

    if !keep_quarantine_object
        && let Err(e) = state.base.storage.store().delete(quarantine_path).await
    {
        tracing::warn!(error = %e, session_id = %session_id, "scan: failed to delete rejected quarantine object");
    }
    Ok(())
}
/// Claim -> fetch+hash+sniff -> scan -> promote-or-reject. Each phase that
/// touches the database is its own transaction; the S3 GET and the clamd
/// round trip happen with no transaction open (guidelines §2/§10).
pub async fn process(state: &EngineState, session_id: Uuid) -> Result<(), AppError> {
    let Some(claimed) = claim(state, session_id).await? else {
        return Ok(());
    };

    let quarantine_path = ObjectPath::parse(&claimed.quarantine_key)
        .map_err(|e| AppError::internal(format!("invalid quarantine key: {e}")))?;
    let get_result = state.base.storage.store().get(&quarantine_path).await;
    let max_bytes = state.base.config.storage.max_upload_size_bytes;
    // BST-7: set from the first scan GET's ETag; the promote below refuses
    // to run without it.
    let mut source_etag: Option<String> = None;
    let outcome = match get_result {
        Err(e) => ScanOutcome::Rejected {
            client_reason: "upload never completed",
            audit_detail: format!("quarantine object missing at scan time: {e}"),
            keep_quarantine_object: false,
        },
        // Cheap pre-check off `head`-equivalent metadata (no bytes read
        // yet) — belt-and-braces against a quarantine object that grew past
        // `max_upload_size_bytes` between `finalize_upload_session`'s HEAD
        // check and this scan; `hash_and_sniff`'s running-total check below
        // is the same ceiling enforced again mid-stream in case the store's
        // reported size and its actual byte count ever disagree.
        Ok(get_result) if get_result.meta.size > max_bytes => too_large_outcome(max_bytes),
        Ok(get_result) => {
            // BST-7: the ETag of the bytes this pass reads is the pin every
            // later read of this object must match. A store that cannot supply
            // one cannot have its promote pinned, so the session fails closed
            // rather than promoting bytes nothing can vouch for.
            match get_result.meta.e_tag.clone() {
                Some(etag) => {
                    source_etag = Some(etag.clone());
                    let object_stream = get_result.into_stream();
                    run_scan(state, &claimed, &quarantine_path, object_stream, &etag).await?
                }
                None => ScanOutcome::Rejected {
                    client_reason: "uploaded object could not be identified for scanning",
                    audit_detail: "the store returned no ETag for the quarantine object"
                        .to_string(),
                    keep_quarantine_object: true,
                },
            }
        }
    };

    match outcome {
        ScanOutcome::Clean {
            actual_content_type,
            actual_checksum_sha256,
        } => {
            let final_key = crate::files::final_key(
                &claimed.entity_logicalname,
                claimed.record_id,
                &claimed.field_logicalname,
                session_id,
                &claimed.declared_filename,
            );
            let source_etag = source_etag.ok_or_else(|| {
                AppError::internal("a clean scan outcome without a pinned source ETag")
            })?;
            // BST-6/BST-7: a streamed, ETag-pinned promote that writes the
            // server-chosen `Content-Type` and `Content-Disposition` itself.
            // A source that changed since the scan pass — an attacker re-PUT
            // through the still-valid presigned URL — fails closed here.
            match crate::files::promote_quarantine_object(
                state,
                &claimed.quarantine_key,
                &final_key,
                &actual_content_type,
                &claimed.declared_filename,
                &source_etag,
            )
            .await?
            {
                crate::files::PromoteOutcome::SourceChanged => {
                    return reject_session(
                        state,
                        session_id,
                        &claimed,
                        &quarantine_path,
                        "uploaded object changed before it could be promoted",
                        "source ETag changed between the scan pass and the promote",
                        true,
                    )
                    .await;
                }
                crate::files::PromoteOutcome::Promoted => {}
            }

            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            let updated = sqlx::query(
                "UPDATE upload_session
                    SET status = 'clean', final_key = $1, actual_content_type = $2,
                        actual_checksum_sha256 = $3, updated_at = NOW(),
                        row_version = row_version + 1
                  WHERE id = $4 AND status = 'scanning'",
            )
            .bind(&final_key)
            .bind(&actual_content_type)
            .bind(&actual_checksum_sha256)
            .bind(session_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            if updated.rows_affected() != 1 {
                return Err(AppError::internal(
                    "upload session promote affected no rows (concurrent claim?)",
                ));
            }
            // BST-7: the audit record names the exact object version the
            // scan promoted, so a later dispute can be answered from the
            // trail alone.
            write_scan_audit_event(
                state,
                &mut tx,
                &claimed,
                &format!("scan result: clean; pinned etag {source_etag}"),
            )
            .await?;
            attome_db::tx::commit(tx).await?;

            if let Err(e) = state.base.storage.store().delete(&quarantine_path).await {
                tracing::warn!(error = %e, session_id = %session_id, "scan: failed to delete promoted quarantine copy");
            }
        }
        ScanOutcome::Rejected {
            client_reason,
            audit_detail,
            keep_quarantine_object,
        } => {
            reject_session(
                state,
                session_id,
                &claimed,
                &quarantine_path,
                client_reason,
                &audit_detail,
                keep_quarantine_object,
            )
            .await?;
        }
        ScanOutcome::Infected { signature } => {
            reject_session(
                state,
                session_id,
                &claimed,
                &quarantine_path,
                "rejected",
                &format!("malware signature: {signature}"),
                true,
            )
            .await?;
            tracing::warn!(
                %session_id,
                entity = %claimed.entity_logicalname,
                record_id = %claimed.record_id,
                "scan: malware found; the upload is quarantined"
            );
            notify_infected(state, &claimed, &signature).await;
        }
    }
    Ok(())
}

/// `EngineJob::PruneExpiredUploadSessions` (UP-1). Two bounded passes, each
/// `LIMIT SWEEP_BATCH_LIMIT` oldest-first; neither ever touches a `legal_hold`
/// session or one with an unexpired `retention_expires_at` (mirrors
/// `P-data-lifecycle`'s fail-closed-against-deletion posture).
///
/// 1. `pending` past the session TTL — the client never finalized it.
///    Expired, object deleted.
/// 2. `uploaded`/`scanning` past `SCAN_DEADLINE_SECS` — the scan never
///    completed. Rejected with `"scan did not complete"`, one `FileScanned`
///    audit event, and the object **kept**: unknown content is treated like a
///    malware positive, and the quarantine bucket's lifecycle rule ages it
///    out (`deploy/storage/quarantine-lifecycle-setup.sh`).
///
/// `uploaded` is deliberately absent from pass 1: those rows have a scan job
/// queued, and expiring them at the 15-minute TTL destroyed legitimate
/// uploads behind any backlog longer than that (UP-F1).
pub async fn prune_expired_sessions(state: &EngineState) -> Result<(), AppError> {
    expire_abandoned_pending_sessions(state).await?;
    reject_scan_deadline_sessions(state).await
}

/// UP-1.1: `pending` sessions whose client never finalized them, past the
/// session TTL. The only pass that deletes a quarantine object.
async fn expire_abandoned_pending_sessions(state: &EngineState) -> Result<(), AppError> {
    let cutoff =
        Utc::now() - chrono::Duration::seconds(crate::files::UPLOAD_SESSION_TTL_SECS as i64);

    let expired: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, quarantine_key FROM upload_session
          WHERE status = 'pending' AND created_at < $1
            AND legal_hold = false
            AND (retention_expires_at IS NULL OR retention_expires_at < NOW())
            AND is_deleted = false
          ORDER BY created_at
          LIMIT $2",
    )
    .bind(cutoff)
    .bind(SWEEP_BATCH_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for (session_id, quarantine_key) in expired {
        let updated = sqlx::query(
            "UPDATE upload_session
                SET status = 'expired', updated_at = NOW(), row_version = row_version + 1
              WHERE id = $1 AND status = 'pending'",
        )
        .bind(session_id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if updated.rows_affected() != 1 {
            continue; // raced with finalize picking it up — leave it alone
        }
        if let Ok(path) = ObjectPath::parse(&quarantine_key)
            && let Err(e) = state.base.storage.store().delete(&path).await
        {
            tracing::warn!(error = %e, session_id = %session_id, "orphan sweep: failed to delete expired quarantine object");
        }
    }
    Ok(())
}

/// UP-1.2: `uploaded`/`scanning` sessions past `SCAN_DEADLINE_SECS`. Routed
/// through the scan job's own [`reject_session`], so the transition, the
/// single `FileScanned` audit event and the keep-the-object posture are
/// identical to a scan-time rejection (U3, UP-D2).
async fn reject_scan_deadline_sessions(state: &EngineState) -> Result<(), AppError> {
    let cutoff = Utc::now() - chrono::Duration::seconds(SCAN_DEADLINE_SECS);

    type DeadlineRow = (
        Uuid,
        String,
        Uuid,
        String,
        Option<Uuid>,
        Option<Uuid>,
        String,
        String,
        String,
        Option<String>,
    );
    let stale: Vec<DeadlineRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id, field_logicalname, owner_user_ref,
                owner_portal_user_ref, quarantine_key, declared_filename, declared_content_type,
                declared_checksum_sha256
           FROM upload_session
          WHERE status IN ('uploaded', 'scanning')
            AND created_at < $1
            AND legal_hold = false
            AND (retention_expires_at IS NULL OR retention_expires_at < NOW())
            AND is_deleted = false
          ORDER BY created_at
          LIMIT $2",
    )
    .bind(cutoff)
    .bind(SWEEP_BATCH_LIMIT)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for (
        session_id,
        entity_logicalname,
        record_id,
        field_logicalname,
        owner_user_ref,
        owner_portal_user_ref,
        quarantine_key,
        declared_filename,
        declared_content_type,
        declared_checksum_sha256,
    ) in stale
    {
        let quarantine_path = ObjectPath::parse(&quarantine_key)
            .map_err(|e| AppError::internal(format!("invalid quarantine key: {e}")))?;
        // One malformed row (both or neither owner, which the validated
        // CHECK rules out) must not stop the rest of the sweep.
        let Ok(owner) = FileOwner::from_columns(owner_user_ref, owner_portal_user_ref) else {
            tracing::error!(%session_id, "upload session has both or neither owner; skipped by the deadline sweep");
            continue;
        };
        let claimed = ClaimedSession {
            entity_logicalname,
            record_id,
            field_logicalname,
            owner,
            quarantine_key,
            declared_filename,
            declared_content_type,
            declared_checksum_sha256,
        };
        reject_session(
            state,
            session_id,
            &claimed,
            &quarantine_path,
            "scan did not complete",
            "no scanner verdict within the 24 h scan deadline",
            true,
        )
        .await?;
    }
    Ok(())
}

// ── K2-T2: the weekly rescan of recent files ────────────────────────────────

/// Files promoted this many days ago or less are scanned again.
pub const RESCAN_WINDOW_DAYS: i64 = 30;
/// A file rescanned less than this many days ago waits for next week.
const RESCAN_EVERY_DAYS: i64 = 6;
/// Files one run rescans; the next run picks up after the last.
const RESCAN_BATCH: i64 = 200;

/// What one rescan run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RescanStats {
    pub scanned: u32,
    pub infected: u32,
    /// The stored file was gone (deleted with its record, or tidied up).
    pub missing: u32,
}

/// Where an infected file goes when a rescan finds it: under the quarantine
/// prefix, so no download path serves it. Pure.
pub fn rescan_quarantine_key(final_key: &str) -> String {
    format!("{}rescan/{final_key}", crate::files::QUARANTINE_PREFIX)
}

type RescanRow = (
    Uuid,
    String,
    Uuid,
    String,
    Option<Uuid>,
    Option<Uuid>,
    String,
    String,
    String,
);

/// Marks a session's file as rescanned now.
async fn mark_rescanned(state: &EngineState, session_id: Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE upload_session SET rescanned_at = NOW() WHERE id = $1")
        .bind(session_id)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// K2-T2: scans again, with today's signatures, every clean file promoted in
/// the last [`RESCAN_WINDOW_DAYS`] days that was not rescanned this week, up
/// to [`RESCAN_BATCH`] a run. A file now found infected is moved under the
/// quarantine prefix (no download serves it), its session becomes
/// `rejected` with an audit event, and the uploader and administrators are
/// told, as for a first-scan hit. Without a configured scanner nothing runs
/// (the files already passed one scan); a scanner error stops the run and the
/// job retries.
pub async fn rescan_recent(state: &EngineState) -> Result<RescanStats, AppError> {
    let mut stats = RescanStats::default();
    let clamd_address = state.base.config.storage.clamd_address.trim().to_owned();
    if clamd_address.is_empty() {
        tracing::info!("upload rescan: no scanner configured; skipped");
        return Ok(stats);
    }
    let max_bytes = state.base.config.storage.max_upload_size_bytes;
    let rows: Vec<RescanRow> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id, field_logicalname, owner_user_ref,
                owner_portal_user_ref, final_key, declared_filename, declared_content_type
           FROM upload_session
          WHERE status = 'clean' AND is_deleted = false AND final_key IS NOT NULL
            AND updated_at > NOW() - make_interval(days => $1::int)
            AND (rescanned_at IS NULL OR rescanned_at < NOW() - make_interval(days => $2::int))
          ORDER BY updated_at
          LIMIT $3",
    )
    .bind(RESCAN_WINDOW_DAYS as i32)
    .bind(RESCAN_EVERY_DAYS as i32)
    .bind(RESCAN_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    for (
        session_id,
        entity_logicalname,
        record_id,
        field_logicalname,
        owner_user_ref,
        owner_portal_user_ref,
        final_key,
        declared_filename,
        declared_content_type,
    ) in rows
    {
        let Ok(owner) = FileOwner::from_columns(owner_user_ref, owner_portal_user_ref) else {
            tracing::error!(%session_id, "upload rescan: a session with both or neither owner; skipped");
            mark_rescanned(state, session_id).await?;
            continue;
        };
        let path = ObjectPath::parse(&final_key)
            .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
        let stream = match state.base.storage.store().get(&path).await {
            Ok(object) => object.into_stream(),
            Err(object_store::Error::NotFound { .. }) => {
                stats.missing += 1;
                mark_rescanned(state, session_id).await?;
                continue;
            }
            Err(e) => return Err(AppError::internal(e)),
        };
        stats.scanned += 1;
        match clamav_instream_scan(&clamd_address, max_bytes, stream).await? {
            ClamOutcome::Result(ClamResult::Positive(signature)) => {
                stats.infected += 1;
                let quarantine = rescan_quarantine_key(&final_key);
                let quarantine_path = ObjectPath::parse(&quarantine)
                    .map_err(|e| AppError::internal(format!("invalid quarantine key: {e}")))?;
                let store = state.base.storage.store();
                store
                    .copy(&path, &quarantine_path)
                    .await
                    .map_err(AppError::internal)?;
                store.delete(&path).await.map_err(AppError::internal)?;
                let claimed = ClaimedSession {
                    entity_logicalname,
                    record_id,
                    field_logicalname,
                    owner,
                    quarantine_key: quarantine,
                    declared_filename,
                    declared_content_type,
                    declared_checksum_sha256: None,
                };
                let mut tx = attome_db::tx::begin(&state.base.db).await?;
                sqlx::query(
                    "UPDATE upload_session
                        SET status = 'rejected', reject_reason = 'rejected',
                            rescanned_at = NOW(), updated_at = NOW(),
                            row_version = row_version + 1
                      WHERE id = $1",
                )
                .bind(session_id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                write_scan_audit_event(
                    state,
                    &mut tx,
                    &claimed,
                    &format!("rescan result: malware signature: {signature}; file quarantined"),
                )
                .await?;
                attome_db::tx::commit(tx).await?;
                tracing::warn!(
                    %session_id,
                    entity = %claimed.entity_logicalname,
                    record_id = %claimed.record_id,
                    "upload rescan: malware found in a stored file; it is quarantined"
                );
                notify_infected(state, &claimed, &signature).await;
            }
            ClamOutcome::Result(ClamResult::Clean) | ClamOutcome::TooLarge => {
                mark_rescanned(state, session_id).await?;
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_hold_rescan_quarantines_under_the_prefix() {
        let key = rescan_quarantine_key("core_contact/0190/photo/0191/face.png");
        assert_eq!(
            key,
            "_quarantine/rescan/core_contact/0190/photo/0191/face.png"
        );
        assert!(ObjectPath::parse(&key).is_ok());
    }

    /// K2-T1: the EICAR test file's clamd answer is malware, a clean answer is
    /// clean, and anything else keeps the file pending (the job retries).
    #[test]
    fn scan_hold_reads_clamd_answers_and_fails_closed() {
        assert_eq!(
            parse_clamd_response("stream: Eicar-Test-Signature FOUND\0"),
            Ok(ClamResult::Positive("Eicar-Test-Signature".to_owned()))
        );
        assert_eq!(
            parse_clamd_response("stream: Win.Test.EICAR_HDB-1 FOUND\n"),
            Ok(ClamResult::Positive("Win.Test.EICAR_HDB-1".to_owned()))
        );
        assert_eq!(parse_clamd_response("stream: OK\0"), Ok(ClamResult::Clean));
        for refused in [
            "",
            "INSTREAM size limit exceeded. ERROR",
            "stream: lstat() failed: No such file. ERROR",
            "UNKNOWN COMMAND",
        ] {
            assert!(parse_clamd_response(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn scan_hold_notices_tell_the_uploader_less_than_the_administrators() {
        let record = Uuid::nil();
        let ((user_subject, user_body), (admin_subject, admin_body)) = infected_notices(
            "invoice.pdf",
            "account",
            record,
            "contract_file",
            "Eicar-Test-Signature",
        );
        assert!(!user_subject.is_empty() && !admin_subject.is_empty());
        assert!(user_body.contains("invoice.pdf"), "{user_body}");
        assert!(!user_body.contains("Eicar"), "{user_body}");
        assert!(admin_body.contains("Eicar-Test-Signature"), "{admin_body}");
        assert!(admin_body.contains(&record.to_string()), "{admin_body}");
        assert!(admin_body.contains("contract_file"), "{admin_body}");
    }

    #[test]
    fn sha256_of_known_bytes_matches_expected_hex() {
        let digest = hex::encode(Sha256::digest(b"hello"));
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
