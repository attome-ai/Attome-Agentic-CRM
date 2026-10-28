/// F007 / P-file-upload-pipeline — upload sessions, quarantine, and a
/// trustworthy file-reference contract for `file`-typed entity fields.
///
/// The browser still talks to the object store directly (PUT to
/// `upload_url`, GET from `download_url`) — this crate hands out short-lived
/// URLs, never proxies the byte stream (`attome_server::app`'s
/// `max_body_size_bytes` would otherwise apply). What changed from the
/// original presigned-URL broker: a session must exist (`upload_session`,
/// migrations/0058) before any URL is issued, the PUT targets a quarantine
/// key rather than the file's final location, and nothing is trusted until
/// `finalize` + the async scan job (`files_scan.rs`) promote it to `clean`.
/// The generic entity-mutation write path (`entity_mutation.rs`'s
/// `lock_file_field_sessions`) is what actually enforces that a file-field
/// value names a completed, owned, clean session — this module only manages
/// the session lifecycle.
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::capability::{Available, ObjectStorage};
use std::time::Duration;

use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::{EngineState, quote_ident};
use attome_security::RecordAction;
use attome_security::record_action::{Delete, Read, Update};
use attome_storage::StorageError;
use attome_types::AppError;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post},
};
use chrono::{DateTime, Utc};
use futures_util::TryStreamExt;
use object_store::{
    Attribute, Attributes, GetOptions, ObjectStoreExt, buffered::BufWriter,
    path::Path as ObjectPath,
};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use attome_records::entity_crud::require_record_access;
pub use attome_records::entity_mutation::FileOwner;
use attome_types::{ErrorResponse, PaginatedResponse};
use utoipa::{IntoParams, ToSchema};

/// Long enough for a client to start the transfer, short enough that a
/// leaked URL isn't a standing credential.
const DEFAULT_PRESIGN_EXPIRY: Duration = Duration::from_secs(15 * 60);

/// How long an upload session's presigned URL — and the session itself, for
/// orphan-sweep purposes — stays valid. Never varied per-deployment, not a
/// config knob.
pub(crate) const UPLOAD_SESSION_TTL_SECS: u64 = 900;

/// Object-key prefix the presigned PUT targets — never the location a clean
/// file is served from. An internal object-key convention, never varied
/// per-deployment.
pub(crate) const QUARANTINE_PREFIX: &str = "_quarantine/";

fn storage_error(e: StorageError) -> AppError {
    AppError::internal(e)
}

/// Content types an `image` field (U9, field type 18) accepts — checked
/// against the declared type when an upload session is created, against the
/// object's magic bytes at finalize, and again against the bytes the scan
/// job hashes before promotion (a presigned PUT stays valid for the session
/// TTL, so the bytes finalize saw are not necessarily the bytes promoted).
/// SVG is deliberately absent: it is XML that can carry script.
pub const IMAGE_CONTENT_TYPES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp"];

/// Content types a generic `file` field accepts — the D-144 allowlist,
/// restored by D-617 after `9316ef2bc` deleted it with no decision record
/// (BST-13/BST-F12). A platform-wide security allowlist: not customer-tunable,
/// never varied per-deployment (config-surface reduction item 23), and a
/// superset of [`IMAGE_CONTENT_TYPES`], which stays the narrower per-field-type
/// list for `image` fields.
///
/// `text/html`, `image/svg+xml` and `application/xhtml+xml` are deliberately
/// absent. They are markup a browser renders as script when the object is
/// served inline, which is why the promote path also forces
/// `Content-Disposition: attachment` (BST-6) — the two controls are
/// independent and both required.
pub const ALLOWED_CONTENT_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
    "text/plain",
    "text/csv",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    // N22-T2/J6-T3: call recordings and voice notes, as the scan's sniff
    // names them (MP3, WAV, Ogg, M4A).
    "audio/mpeg",
    "audio/x-wav",
    "audio/ogg",
    "audio/m4a",
];

/// Content types whose bytes carry no reliable magic signature, so the scan
/// job's `infer` sniff legitimately finds nothing for them. Anything else in
/// [`ALLOWED_CONTENT_TYPES`] must be identifiable by its own bytes before it
/// is promoted (BST-13).
pub(crate) const SNIFF_FREE_CONTENT_TYPES: &[&str] = &["text/plain", "text/csv"];

/// How many leading bytes finalize reads to sniff an image upload's real
/// type — every signature in [`IMAGE_CONTENT_TYPES`] fits well inside it.
const IMAGE_SNIFF_BYTES: u64 = 64;

/// The type's essence: the MIME type with parameters stripped, trimmed and
/// lower-cased, so `Text/Plain; charset=utf-8` and `text/plain` are one type.
pub fn content_type_essence(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Whether `content_type` (parameters and case ignored) is one of
/// [`ALLOWED_CONTENT_TYPES`].
pub fn is_allowed_content_type(content_type: &str) -> bool {
    ALLOWED_CONTENT_TYPES.contains(&content_type_essence(content_type).as_str())
}

/// Whether `content_type` (parameters and case ignored) is one of
/// [`IMAGE_CONTENT_TYPES`].
pub fn is_allowed_image_type(content_type: &str) -> bool {
    IMAGE_CONTENT_TYPES.contains(&content_type_essence(content_type).as_str())
}

/// Whether `entity.field` is an `image` field (a `file` field restricted to
/// [`IMAGE_CONTENT_TYPES`]). `false` for anything the registry does not
/// know — the file routes' own resolution rejects that separately.
pub fn is_image_field(state: &EngineState, entity: &str, field: &str) -> bool {
    let registry = state.entities.load();
    registry.get(entity).is_some_and(|meta| {
        meta.attrs
            .iter()
            .any(|a| a.logicalname == field && a.field_type() == attome_core::FieldType::Image)
    })
}

/// Resolves `entity_input`/`field_input` from the metadata registry and
/// confirms the field stores file keys: `file` (int code 12, or legacy alias
/// 13 — the same pair `attome_core::FieldType::from_int` recognises,
/// C-16/M01 §7) or `image` (18, U9), whose storage type is `file`.
pub(crate) async fn resolve_file_field(
    state: &EngineState,
    entity_input: &str,
    field_input: &str,
) -> Result<(Uuid, String, String), AppError> {
    let registry = state.entities.load();
    let meta = registry.get(entity_input).ok_or(AppError::NotFound)?;
    let attr = meta
        .attrs
        .iter()
        .find(|a| a.logicalname == field_input)
        .ok_or(AppError::NotFound)?;

    if !attr.is_file_backed() {
        return Err(AppError::Validation(format!(
            "{field_input} is not a file field"
        )));
    }

    Ok((
        meta.entity_id,
        meta.logicalname.clone(),
        attr.logicalname.clone(),
    ))
}

/// `filename` is client-supplied and flows straight into an S3 object path,
/// so it's reduced to a safe character set and any `..` run collapsed —
/// otherwise a name like `../../field/x` would still traverse out of this
/// key's prefix even with `/` itself blocked, since `.` alone is kept
/// (needed for extensions like `.jpg`).
fn safe_filename(filename: &str) -> String {
    let safe_name: String = filename
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    safe_name.replace("..", "_")
}

/// The object's final (post-promotion) key layout:
/// `{entity}/{record_id}/{field}/{session_id}-{filename}` — unchanged from
/// the pre-pipeline `object_key()` shape, except the uuid prefix is now the
/// session's own id (already `uuidv7()`, D-018) instead of a fresh
/// `Uuid::new_v4()`.
///
/// Public so a server-generated file (docgen's attach, owner decision 3) is
/// stored under the same layout the field's download path
/// ([`is_owned_file_key`]) and compliance archiving expect.
pub fn final_key(
    entity: &str,
    record_id: Uuid,
    field: &str,
    session_id: Uuid,
    filename: &str,
) -> String {
    format!(
        "{entity}/{record_id}/{field}/{session_id}-{}",
        safe_filename(filename)
    )
}

/// The quarantine location the client PUTs to — never the location a clean
/// file is ultimately served from (§4's "alternatives considered": a prefix
/// inside the existing bucket, not a second bucket/credential pair).
fn quarantine_key(
    prefix: &str,
    entity: &str,
    record_id: Uuid,
    field: &str,
    session_id: Uuid,
    filename: &str,
) -> String {
    format!(
        "{prefix}{}",
        final_key(entity, record_id, field, session_id, filename)
    )
}

/// A file value is only valid for the record and field whose upload route
/// minted it. Kept as defense-in-depth on the download path even though the
/// write path (`entity_mutation::lock_file_field_sessions`) is the actual
/// gate — a hand-crafted key pointing at a different record's object must
/// still fail here independently. Public so `attome_compliance::archive` applies
/// the same check to the keys it copies (CLEANUP-REVIEW 2.10).
pub fn is_owned_file_key(entity: &str, record_id: Uuid, field: &str, key: &str) -> bool {
    let prefix = format!("{entity}/{record_id}/{field}/");
    key.strip_prefix(&prefix)
        .is_some_and(|suffix| !suffix.is_empty())
}

/// BST-6 — the `Content-Disposition` every promoted object carries.
///
/// `attachment` is what stops a stored `text/html` (or any other markup the
/// browser would happily render) from executing on the object store's own
/// origin when an Angular client `window.open`s a presigned GET. The RFC 6266
/// `filename*` form carries the uploader's original name back to the user
/// without letting that name inject a header — no CR, no LF, no quote — and
/// without mangling a non-ASCII one. Everything outside a conservative
/// `attr-char` set is percent-encoded over its UTF-8 bytes.
pub(crate) fn attachment_disposition(filename: &str) -> String {
    let mut encoded = String::with_capacity(filename.len());
    for byte in filename.as_bytes() {
        let c = *byte as char;
        if c.is_ascii_alphanumeric()
            || matches!(
                c,
                '.' | '-' | '_' | '~' | '+' | '!' | '#' | '$' | '&' | '^' | '`' | '|'
            )
        {
            encoded.push(c);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    format!("attachment; filename*=UTF-8''{encoded}")
}

/// BST-6/BST-7 — what a promote attempt did.
pub(crate) enum PromoteOutcome {
    /// The scanned bytes were streamed to their final key with the metadata
    /// this server chose.
    Promoted,
    /// The source object changed after the scan pass read it — the `if_match`
    /// on the ETag the scan saw failed. Nothing was written and the session
    /// must fail closed.
    SourceChanged,
}

/// BST-6/BST-7 — the one promote operation: stream the quarantined object into
/// its final key, pinning the exact bytes the scan saw and replacing the
/// uploader's metadata with this server's.
///
/// A plain `copy()` cannot do this. `object_store` 0.14.1's copy keeps the
/// uploader's `Content-Type` and cannot send `x-amz-copy-source-if-match`, so
/// the object that reached a record could be an unscanned re-PUT of the
/// quarantine key (BST-F3/G-18) whose bytes nothing has seen. This is a
/// streamed read plus a streamed write — never the whole object resident —
/// bounded by the caller's own size ceiling, and it writes the final object's
/// `Content-Type`/`Content-Disposition` itself (BST-F2/G-4).
pub(crate) async fn promote_quarantine_object(
    state: &EngineState,
    quarantine_key: &str,
    final_key: &str,
    content_type: &str,
    filename: &str,
    if_match: &str,
) -> Result<PromoteOutcome, AppError> {
    let source = ObjectPath::parse(quarantine_key).map_err(AppError::internal)?;
    let target = ObjectPath::parse(final_key).map_err(AppError::internal)?;

    let get = state
        .base
        .storage
        .store()
        .get_opts(&source, GetOptions::new().with_if_match(Some(if_match)))
        .await;
    let mut stream = match get {
        Ok(result) => result.into_stream(),
        Err(object_store::Error::Precondition { .. }) => return Ok(PromoteOutcome::SourceChanged),
        Err(e) => return Err(AppError::internal(e)),
    };

    let mut attributes = Attributes::new();
    attributes.insert(Attribute::ContentType, content_type.to_string().into());
    attributes.insert(
        Attribute::ContentDisposition,
        attachment_disposition(filename).into(),
    );

    let mut writer =
        BufWriter::new(state.base.storage.store_arc(), target).with_attributes(attributes);
    while let Some(chunk) = stream.try_next().await.map_err(AppError::internal)? {
        writer.put(chunk).await.map_err(AppError::internal)?;
    }
    writer.shutdown().await.map_err(AppError::internal)?;

    Ok(PromoteOutcome::Promoted)
}

#[derive(Deserialize, ToSchema)]
pub struct UploadSessionRequest {
    pub filename: String,
    pub content_type: String,
    pub declared_size_bytes: i64,
    pub checksum_sha256: Option<String>,
}

impl std::fmt::Debug for UploadSessionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadSessionRequest")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct UploadSessionResponse {
    pub session_id: Uuid,
    pub upload_url: String,
    pub expires_in_secs: u64,
}

impl std::fmt::Debug for UploadSessionResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadSessionResponse")
            .finish_non_exhaustive()
    }
}

/// How much upload one portal user may hold (D-774 item 4), counted by
/// [`PORTAL_QUOTA_COUNTED`]. A fixed default; a per-portal policy column only
/// when a customer needs one.
pub const PORTAL_USER_UPLOAD_QUOTA_BYTES: u64 = 1 << 30;

/// Which of a portal owner's sessions (alias `s`) count toward a portal
/// quota, and at what size: in flight at the declared size; clean at the
/// actual size while it is under a day old or is the current file of the
/// field it was uploaded for. A clean upload no record kept stops counting
/// after a day, so abandoned uploads can't fill a quota for good (the staff
/// caps count every clean session, unchanged). The `EXISTS` probes
/// `core_file_version_one_current_idx`.
pub const PORTAL_QUOTA_COUNTED: &str = "COALESCE(SUM(CASE
        WHEN s.status IN ('pending', 'uploaded', 'scanning') THEN s.declared_max_size_bytes
        WHEN s.status = 'clean' THEN s.actual_size_bytes
        ELSE 0
    END), 0)::bigint";
pub const PORTAL_QUOTA_SESSIONS: &str = "s.is_deleted = false AND (
        s.status IN ('pending', 'uploaded', 'scanning')
        OR (s.status = 'clean' AND (
            s.created_at > NOW() - INTERVAL '1 day'
            OR EXISTS (SELECT 1 FROM file_version v
                        WHERE v.entity = s.entity_logicalname AND v.record_id = s.record_id
                          AND v.field = s.field_logicalname AND v.is_current = true
                          AND v.is_deleted = false AND v.object_key = s.final_key))))";

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Item 26 remediation — soft caps on how much quarantine/storage exposure
/// one user, or (D-099: one customer per deployment) the deployment as a
/// whole, can hold at once. Runs inside `create_upload_session`'s own short
/// transaction, right before the session INSERT (guidelines §2: begin,
/// lock/read, write, commit — no external I/O in between).
///
/// A cap is only enforced when configured (`storage.max_user_storage_bytes`/
/// `max_deployment_storage_bytes`, both `None` by default) — a deployment
/// that hasn't set one pays no extra query or lock for it. When a cap *is*
/// set, its own `pg_try_advisory_xact_lock` first serializes concurrent
/// session-creation attempts against the same scope (per-user, or
/// deployment-wide for the total cap) — without it, two concurrent requests
/// could both read "under quota" and both insert, overshooting the cap by up
/// to one session each (the same TOCTOU the existing per-(record,field) lock
/// above closes for that narrower scope). This is a best-effort cost/abuse
/// control, not a hard security boundary, so a `Conflict` on lock contention
/// simply asks the caller to retry rather than queuing behind a blocking lock
/// (guidelines §2: never a blocking session advisory lock).
/// Z6-T7: one cap's use once the new upload is counted, for the warning past
/// `storage.quota_warning_pct`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaUse {
    /// The setting that sets the cap.
    pub limit: &'static str,
    /// Whose files it counts: `deployment`, `entity:<name>`, `user:<id>`.
    pub scope: String,
    pub used: u64,
    pub max: u64,
}

impl QuotaUse {
    /// Whether the use is at or past `pct` percent of the cap.
    pub fn past(&self, pct: u8) -> bool {
        self.max > 0 && u128::from(self.used) * 100 >= u128::from(self.max) * u128::from(pct)
    }
}

async fn check_storage_quota(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    storage_cfg: &attome_config::StorageSection,
    owner: FileOwner,
    entity_name: &str,
    new_bytes: u64,
) -> Result<Vec<QuotaUse>, AppError> {
    let mut uses = Vec::new();
    // A staff user's cap is configured (or absent); a portal user's is the
    // fixed D-774 default, on its own lock key and owner column.
    let (max_owner_bytes, lock_key, owner_column, owner_id) = match owner {
        FileOwner::Staff(id) => (
            storage_cfg.max_user_storage_bytes,
            format!("xrm-files/upload-quota:user:{id}"),
            "owner_user_ref",
            id,
        ),
        FileOwner::Portal(id) => (
            Some(PORTAL_USER_UPLOAD_QUOTA_BYTES),
            format!("xrm-files/upload-quota:portal-user:{id}"),
            "owner_portal_user_ref",
            id,
        ),
    };
    if let Some(max_user_bytes) = max_owner_bytes {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_records::FILES_ADVISORY_LOCK_NAMESPACE)
            .bind(&lock_key)
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            return Err(AppError::Conflict(
                "another upload session is being created for your account, retry shortly",
            ));
        }

        // `owner_column` and the portal fragments are constants, never input.
        let sql = match owner {
            FileOwner::Staff(_) => format!(
                "SELECT COALESCE(SUM(CASE
                        WHEN status IN ('pending', 'uploaded', 'scanning') THEN declared_max_size_bytes
                        WHEN status = 'clean' THEN actual_size_bytes
                        ELSE 0
                    END), 0)::bigint
                 FROM upload_session
                 WHERE {owner_column} = $1 AND is_deleted = false
                   AND status IN ('pending', 'uploaded', 'scanning', 'clean')"
            ),
            FileOwner::Portal(_) => format!(
                "SELECT {PORTAL_QUOTA_COUNTED} FROM upload_session s
                 WHERE s.{owner_column} = $1 AND {PORTAL_QUOTA_SESSIONS}"
            ),
        };
        let used: i64 = sqlx::query_scalar(&sql)
            .bind(owner_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;

        let after = (used.max(0) as u64).saturating_add(new_bytes);
        if after > max_user_bytes {
            // Z6-T7 / AA9-T4: the quota, named.
            return Err(AppError::LimitExceeded {
                limit: "storage.max_user_storage_bytes",
                value: i64::try_from(max_user_bytes).unwrap_or(i64::MAX),
                next: attome_types::error::NextStep::ContactAdmin,
            });
        }
        if matches!(owner, FileOwner::Staff(_)) {
            uses.push(QuotaUse {
                limit: "storage.max_user_storage_bytes",
                scope: format!("user:{owner_id}"),
                used: after,
                max: max_user_bytes,
            });
        }
    }

    // Z6-T7: the cap on one entity's files, counted like a user's.
    if let Some(&max_entity_bytes) = storage_cfg.max_entity_storage_bytes.get(entity_name) {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_records::FILES_ADVISORY_LOCK_NAMESPACE)
            .bind(format!("xrm-files/upload-quota:entity:{entity_name}"))
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            return Err(AppError::Conflict(
                "another upload session is being created for this entity, retry shortly",
            ));
        }
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(CASE
                    WHEN status IN ('pending', 'uploaded', 'scanning') THEN declared_max_size_bytes
                    WHEN status = 'clean' THEN actual_size_bytes
                    ELSE 0
                END), 0)::bigint
             FROM upload_session
             WHERE entity_logicalname = $1 AND is_deleted = false
               AND status IN ('pending', 'uploaded', 'scanning', 'clean')",
        )
        .bind(entity_name)
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        let after = (used.max(0) as u64).saturating_add(new_bytes);
        if after > max_entity_bytes {
            return Err(AppError::LimitExceeded {
                limit: "storage.max_entity_storage_bytes",
                value: i64::try_from(max_entity_bytes).unwrap_or(i64::MAX),
                next: attome_types::error::NextStep::ContactAdmin,
            });
        }
        uses.push(QuotaUse {
            limit: "storage.max_entity_storage_bytes",
            scope: format!("entity:{entity_name}"),
            used: after,
            max: max_entity_bytes,
        });
    }

    if let Some(max_deployment_bytes) = storage_cfg.max_deployment_storage_bytes {
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
            .bind(attome_records::FILES_ADVISORY_LOCK_NAMESPACE)
            .bind("xrm-files/upload-quota:deployment")
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
        if !locked {
            return Err(AppError::Conflict(
                "another upload session is being created for this deployment, retry shortly",
            ));
        }

        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(actual_size_bytes), 0)::bigint
             FROM upload_session
             WHERE status = 'clean' AND is_deleted = false",
        )
        .fetch_one(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        let after = (used.max(0) as u64).saturating_add(new_bytes);
        if after > max_deployment_bytes {
            return Err(AppError::LimitExceeded {
                limit: "storage.max_deployment_storage_bytes",
                value: i64::try_from(max_deployment_bytes).unwrap_or(i64::MAX),
                next: attome_types::error::NextStep::ContactAdmin,
            });
        }
        uses.push(QuotaUse {
            limit: "storage.max_deployment_storage_bytes",
            scope: "deployment".into(),
            used: after,
            max: max_deployment_bytes,
        });
    }

    Ok(uses)
}

/// Z6-T7: tells administrators about each cap at or past
/// `storage.quota_warning_pct`, once a day per cap (a Redis key per cap, scope
/// and day, set only if absent), after the session is committed. Best effort:
/// a failure is logged and the upload goes on.
async fn warn_near_quota(state: &EngineState, uses: &[QuotaUse]) {
    let pct = state.base.config.storage.quota_warning_pct;
    let day = chrono::Utc::now().format("%Y-%m-%d");
    for quota in uses.iter().filter(|u| u.past(pct)) {
        let key = format!(
            "attome-document:quota-warning:{}:{}:{day}",
            quota.limit, quota.scope
        );
        match state
            .base
            .redis
            .set_nx(&key, "1", Some(Duration::from_secs(2 * 24 * 3600)))
            .await
        {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(%error, limit = quota.limit, "storage quota warning: not sent");
                continue;
            }
        }
        let share = u128::from(quota.used) * 100 / u128::from(quota.max.max(1));
        tracing::warn!(
            limit = quota.limit,
            scope = %quota.scope,
            used = quota.used,
            max = quota.max,
            "file storage passed {pct}% of its cap"
        );
        attome_notification::dispatch::alert_admins(
            &state.base.db,
            &state.base.config.notification,
            format!("File storage at {share}% of its limit"),
            format!(
                "{} ({}) holds {} of {} bytes. Uploads past the limit are refused.",
                quota.limit, quota.scope, quota.used, quota.max
            ),
            "/xrm/admin/settings",
        )
        .await;
    }
}

// ── POST /api/v1/{entity}/{id}/files/{field}/upload-session ───────────────
//
// Creates a server-side session recording the declared size/type/checksum
// policy, then returns a presigned PUT targeting the quarantine key. Nothing
// is trusted until `finalize` (below) HEAD-verifies the upload and the async
// scan job (files_scan.rs) promotes a clean result.
/// Start a file upload
///
/// Opens an upload session and returns a short-lived URL to PUT the bytes to, in quarantine; nothing
/// is trusted until the session is finalised and the scan passes. Refused while someone else has the
/// file checked out. Needs update rights on the record.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/files/{field}/upload-session",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
    ),
    request_body = UploadSessionRequest,
    responses(
        (status = 200, description = "Success", body = UploadSessionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(
        ("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs / entity_crud update"), "only records upload intent; the eventual scan result (FileScanned) and field promotion (Entity/Update) are audited on their own paths"))),
        // Z5-T3: the request is a small JSON description; the file itself
        // goes straight to the object store.
        ("x-body-limit" = json!(65_536)),
        ("x-auth" = json!("session")),
        ("x-idempotent" = json!(false)),
    ),
)]
async fn create_upload_session(
    State(state): State<EngineState>,
    // Writing a record's file field is an update to that record.
    ctx: Authorized<RecordScoped<Update>>,
    // D-344: this route's whole product is a contract the object store has to
    // honour — "PUT your bytes here, then finalize". Issuing a presigned URL
    // against a store this node cannot reach hands the caller a 200 for an
    // upload that will fail at the PUT, on the browser's side of the wire
    // where this platform can neither see it nor retry it. 503 up front is
    // the honest answer. (Node readiness is untouched — D-167.)
    _storage: Available<ObjectStorage>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
    Json(body): Json<UploadSessionRequest>,
) -> Result<Json<UploadSessionResponse>, AppError> {
    let (entity_id, entity_name, field_name) =
        resolve_file_field(&state, &entity_input, &field_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;
    // K1-T2: no upload into a file someone else has checked out.
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    if attome_records::entity_mutation::file_checked_out_by_other(
        &mut conn,
        &entity_name,
        record_id,
        std::slice::from_ref(&field_name),
        Some(ctx.user_id),
    )
    .await?
    .is_some()
    {
        return Err(AppError::Conflict(
            "the file is checked out by someone else; it can change after check-in",
        ));
    }
    drop(conn);
    Ok(Json(
        start_upload(
            &state,
            FileOwner::Staff(ctx.user_id),
            &entity_name,
            record_id,
            &field_name,
            body,
        )
        .await?,
    ))
}

/// Opens an upload session for `owner` on `field_name` of `record_id` and
/// returns the presigned PUT to its quarantine key. The caller has already
/// authorized writing the field on the record (the staff route: record
/// access; the portal route: its plan). One path for both (D-774).
pub async fn start_upload(
    state: &EngineState,
    owner: FileOwner,
    entity_name: &str,
    record_id: Uuid,
    field_name: &str,
    body: UploadSessionRequest,
) -> Result<UploadSessionResponse, AppError> {
    if body.filename.trim().is_empty() {
        return Err(AppError::Validation("filename must not be empty".into()));
    }
    // U9/D-617: an `image` field accepts only image content types; every other
    // file-backed field accepts only the platform allowlist. Refused here,
    // before a session row or a presigned URL exists, with the allowed list in
    // the message — the client learns what to send, and no bytes move
    // (BST-13). Finalize and the scan job re-check the bytes themselves.
    if is_image_field(state, entity_name, field_name) {
        if !is_allowed_image_type(&body.content_type) {
            return Err(AppError::Validation(format!(
                "{field_name} is an image field; content_type must be one of: {}",
                IMAGE_CONTENT_TYPES.join(", ")
            )));
        }
    } else if !is_allowed_content_type(&body.content_type) {
        return Err(AppError::Validation(format!(
            "content_type {} is not an allowed upload type; allowed: {}",
            content_type_essence(&body.content_type),
            ALLOWED_CONTENT_TYPES.join(", ")
        )));
    }
    let storage_cfg = &state.base.config.storage;
    if body.declared_size_bytes <= 0
        || body.declared_size_bytes as u64 > storage_cfg.max_upload_size_bytes
    {
        return Err(AppError::Validation(format!(
            "declared_size_bytes must be between 1 and {}",
            storage_cfg.max_upload_size_bytes
        )));
    }
    if let Some(checksum) = &body.checksum_sha256
        && !valid_sha256_hex(checksum)
    {
        return Err(AppError::Validation(
            "checksum_sha256 must be 64 hex characters".into(),
        ));
    }

    let session_id = Uuid::now_v7();
    let key = quarantine_key(
        QUARANTINE_PREFIX,
        entity_name,
        record_id,
        field_name,
        session_id,
        &body.filename,
    );

    // guidelines §2 Layer 2 — bounds concurrent-session creation for the same
    // field to one in flight, closing a trivial quarantine-storage
    // exhaustion vector. Item 26 remediation adds two more layers around
    // this same short transaction: the `presign` rate-limit category
    // (attome-server/middleware/rate_limit.rs) bounds how fast one caller can
    // reach this handler at all, and `check_storage_quota` below bounds how
    // much quarantine/storage footprint one user or the deployment can hold
    // at once. Not held across any external I/O: the INSERT is the only
    // write done under it.
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let lock_key = format!("xrm-files/upload-session:{record_id}:{field_name}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_records::FILES_ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "an upload session is already being created for this field",
        ));
    }
    let quota_uses = check_storage_quota(
        &mut tx,
        storage_cfg,
        owner,
        entity_name,
        body.declared_size_bytes as u64,
    )
    .await?;
    let (owner_user_ref, owner_portal_user_ref) = owner.columns();
    sqlx::query(
        "INSERT INTO upload_session
            (id, entity_logicalname, record_id, field_logicalname, owner_user_ref,
             owner_portal_user_ref, quarantine_key, declared_filename, declared_content_type,
             declared_max_size_bytes, declared_checksum_sha256, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'pending')",
    )
    .bind(session_id)
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .bind(owner_user_ref)
    .bind(owner_portal_user_ref)
    .bind(&key)
    .bind(&body.filename)
    .bind(&body.content_type)
    .bind(body.declared_size_bytes)
    .bind(&body.checksum_sha256)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    warn_near_quota(state, &quota_uses).await;

    let ttl = Duration::from_secs(UPLOAD_SESSION_TTL_SECS);
    let upload_url = attome_storage::presign_upload(&state.base.storage, &key, ttl)
        .await
        .map_err(storage_error)?;

    Ok(UploadSessionResponse {
        session_id,
        upload_url,
        expires_in_secs: ttl.as_secs(),
    })
}

/// A file the platform generated itself (a docgen-rendered PDF, say) and
/// already wrote to its final object-store location, for
/// [`record_generated_clean_file`].
pub struct GeneratedCleanFile<'a> {
    /// The upload session's id. The caller mints it (`Uuid::now_v7()`)
    /// before writing the object, because it is part of the object's
    /// [`final_key`].
    pub session_id: Uuid,
    pub entity: &'a str,
    pub record_id: Uuid,
    pub field: &'a str,
    /// Who the file is attributed to (the requester of the generation).
    pub owner: FileOwner,
    /// Where the bytes already live; stored as both the quarantine and the
    /// final key, since the object never passes through quarantine. Must be
    /// [`final_key`]`(entity, record_id, field, session_id, filename)` — a key
    /// outside the field's own prefix is refused, since the field's download
    /// path and compliance archiving would both refuse it later.
    pub object_key: &'a str,
    pub filename: &'a str,
    pub content_type: &'a str,
    pub size_bytes: i64,
    /// Lowercase hex SHA-256 of the stored bytes.
    pub checksum_sha256: &'a str,
}

impl std::fmt::Debug for GeneratedCleanFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GeneratedCleanFile").finish_non_exhaustive()
    }
}

/// Records an upload session for a server-generated file that is already
/// clean: the row is inserted straight into `clean` (no presign, no
/// finalize, no scan), with the declared and actual size/type/checksum equal
/// because the server produced the bytes itself. Writing `object_key` into
/// the file field afterwards (through the generic update path) then passes
/// `entity_mutation::lock_file_field_sessions`, the same gate a user upload
/// goes through. The caller authorises the attach and vouches that the
/// bytes are trusted; this function owns only the upload-session row's
/// shape (CLEANUP-REVIEW 2.10). Returns the new session id.
pub async fn record_generated_clean_file(
    state: &EngineState,
    file: GeneratedCleanFile<'_>,
) -> Result<Uuid, AppError> {
    let session_id = file.session_id;
    if !is_owned_file_key(file.entity, file.record_id, file.field, file.object_key) {
        return Err(AppError::internal(format!(
            "generated file key {:?} is outside {}/{}/{}/",
            file.object_key, file.entity, file.record_id, file.field
        )));
    }
    let (owner_user_ref, owner_portal_user_ref) = file.owner.columns();
    sqlx::query(
        "INSERT INTO upload_session \
            (id, entity_logicalname, record_id, field_logicalname, owner_user_ref, \
             owner_portal_user_ref, quarantine_key, final_key, declared_filename, \
             declared_content_type, declared_max_size_bytes, declared_checksum_sha256, \
             actual_size_bytes, actual_content_type, actual_checksum_sha256, status) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8, $9, $10, $11, $10, $9, $11, 'clean')",
    )
    .bind(session_id)
    .bind(file.entity)
    .bind(file.record_id)
    .bind(file.field)
    .bind(owner_user_ref)
    .bind(owner_portal_user_ref)
    .bind(file.object_key)
    .bind(file.filename)
    .bind(file.content_type)
    .bind(file.size_bytes)
    .bind(file.checksum_sha256)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(session_id)
}

#[derive(Serialize, ToSchema)]
pub struct FinalizeResponse {
    pub session_id: Uuid,
    pub status: &'static str,
}

impl std::fmt::Debug for FinalizeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FinalizeResponse").finish_non_exhaustive()
    }
}

type SessionRowTuple = (String, i64, Option<Uuid>, Option<Uuid>, String, i64);

struct SessionRow {
    quarantine_key: String,
    declared_max_size_bytes: i64,
    owner_user_ref: Option<Uuid>,
    owner_portal_user_ref: Option<Uuid>,
    status: String,
    row_version: i64,
}

impl From<SessionRowTuple> for SessionRow {
    fn from(
        (
            quarantine_key,
            declared_max_size_bytes,
            owner_user_ref,
            owner_portal_user_ref,
            status,
            row_version,
        ): SessionRowTuple,
    ) -> Self {
        Self {
            quarantine_key,
            declared_max_size_bytes,
            owner_user_ref,
            owner_portal_user_ref,
            status,
            row_version,
        }
    }
}

// ── POST .../upload-session/{session_id}/finalize ─────────────────────────
//
// HEAD-verifies the uploaded object's size against the session's declared
// policy (content-type is never trusted from a client-controlled PUT header
// — the async scan job sniffs actual bytes instead, see files_scan.rs). A
// size mismatch or missing object rejects the session and deletes the
// quarantine object; otherwise the session moves to `uploaded` and the scan
// job is enqueued in the same commit as that transition (guidelines §9).
//
// Deliberately does NOT hold a database transaction across the HEAD call
// (guidelines §2/§10 — never hold a transaction across external I/O): the
// decisive state transition is a single row_version-CAS UPDATE, issued only
// after the HEAD result is known, so two concurrent finalize calls for the
// same session can never both win.
/// Finish a file upload
///
/// Checks the uploaded object is there and queues its scan; once clean, the file can be set on the
/// field through the record API. Needs update rights on the record.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/files/{field}/upload-session/{session_id}/finalize",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
        ("session_id" = Uuid, Path, description = "The upload session"),
    ),
    responses(
        (status = 200, description = "Success", body = FinalizeResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("files_scan.rs / entity_crud update"), "moves the session to uploaded and enqueues the scan job; the scan result (FileScanned) and field promotion (Entity/Update) are audited on their own paths")))),
)]
async fn finalize_upload_session(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    // D-344: finalize HEAD-verifies the quarantined object before the
    // row_version-CAS that promotes the session. With the store unreachable
    // that HEAD fails and the caller gets a 500 describing an internal
    // error — accurate about the code path, useless about the cause. A 503
    // naming `object_storage` is retriable and diagnosable.
    _storage: Available<ObjectStorage>,
    Path((entity_input, record_id, field_input, session_id)): Path<(String, Uuid, String, Uuid)>,
) -> Result<Json<FinalizeResponse>, AppError> {
    let (entity_id, entity_name, field_name) =
        resolve_file_field(&state, &entity_input, &field_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;
    Ok(Json(
        finalize_upload(
            &state,
            FileOwner::Staff(ctx.user_id),
            &entity_name,
            record_id,
            &field_name,
            session_id,
        )
        .await?,
    ))
}

/// Someone else's session: 403 to staff (unchanged); the uniform 404 to a
/// portal user, for whom another user's session and a missing one look the
/// same (C4).
fn not_yours(caller: FileOwner) -> AppError {
    match caller {
        FileOwner::Staff(_) => AppError::Forbidden,
        FileOwner::Portal(_) => AppError::NotFound,
    }
}

/// Finalizes `owner`'s upload session: HEAD-verifies the quarantined object
/// and moves the session to `uploaded` (enqueuing the scan) or `rejected`.
/// Only the session's own owner may finalize it. One path for the staff and
/// the portal route (D-774); the caller has authorized the record and field.
/// J6-T3: files the server itself fetched (a call recording) go through the
/// same pipeline as a person's upload: a session for `field_name` of the
/// record, the bytes into its quarantine key, then finalize, which queues the
/// virus scan. Nothing is attached here: the scan promotes the file, and the
/// caller sets the field once the session is clean. Answers the session id.
#[allow(clippy::too_many_arguments)]
pub async fn ingest(
    state: &EngineState,
    owner: FileOwner,
    entity_name: &str,
    record_id: Uuid,
    field_name: &str,
    filename: &str,
    content_type: &str,
    bytes: Vec<u8>,
) -> Result<Uuid, AppError> {
    let size = i64::try_from(bytes.len())
        .map_err(|_| AppError::Validation("the file is too large".into()))?;
    let session = start_upload(
        state,
        owner,
        entity_name,
        record_id,
        field_name,
        UploadSessionRequest {
            filename: filename.to_owned(),
            content_type: content_type.to_owned(),
            declared_size_bytes: size,
            checksum_sha256: None,
        },
    )
    .await?;
    let key: String = sqlx::query_scalar("SELECT quarantine_key FROM upload_session WHERE id = $1")
        .bind(session.session_id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let path = ObjectPath::parse(&key).map_err(AppError::internal)?;
    state
        .base
        .storage
        .store()
        .put(&path, bytes.into())
        .await
        .map_err(AppError::internal)?;
    finalize_upload(
        state,
        owner,
        entity_name,
        record_id,
        field_name,
        session.session_id,
    )
    .await?;
    Ok(session.session_id)
}

pub async fn finalize_upload(
    state: &EngineState,
    owner: FileOwner,
    entity_name: &str,
    record_id: Uuid,
    field_name: &str,
    session_id: Uuid,
) -> Result<FinalizeResponse, AppError> {
    let row: Option<SessionRowTuple> = sqlx::query_as(
        "SELECT quarantine_key, declared_max_size_bytes, owner_user_ref, owner_portal_user_ref,
                status, row_version
         FROM upload_session
         WHERE id = $1 AND entity_logicalname = $2 AND record_id = $3
           AND field_logicalname = $4 AND is_deleted = false",
    )
    .bind(session_id)
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(row) = row.map(SessionRow::from) else {
        return Err(AppError::NotFound);
    };
    if FileOwner::from_columns(row.owner_user_ref, row.owner_portal_user_ref)? != owner {
        return Err(not_yours(owner));
    }
    if row.status != "pending" {
        return Err(AppError::Conflict(
            "upload session has already been finalized",
        ));
    }

    let path = ObjectPath::parse(&row.quarantine_key)
        .map_err(|e| AppError::internal(StorageError::InvalidPath(e.to_string())))?;
    let head_result = state.base.storage.store().head(&path).await;

    let (mut new_status, mut reject_reason, actual_size): (
        &'static str,
        Option<&'static str>,
        Option<i64>,
    ) = match head_result {
        Err(_) => ("rejected", Some("upload never completed"), None),
        Ok(meta) if meta.size > row.declared_max_size_bytes as u64 => (
            "rejected",
            Some("uploaded object exceeds declared size"),
            Some(meta.size as i64),
        ),
        Ok(meta) => ("uploaded", None, Some(meta.size as i64)),
    };

    // U9: an `image` field's upload must *be* an image, whatever the client
    // declared — sniffed from the object's leading bytes (no transaction is
    // open across this read, same as the HEAD above). The scan job repeats
    // the check on the bytes it promotes.
    if new_status == "uploaded" && is_image_field(state, entity_name, field_name) {
        let size = actual_size.unwrap_or_default().max(0) as u64;
        let prefix = state
            .base
            .storage
            .store()
            .get_range(&path, 0..size.min(IMAGE_SNIFF_BYTES))
            .await;
        let sniffed = prefix
            .ok()
            .and_then(|bytes| infer::get(&bytes).map(|t| t.mime_type().to_owned()));
        if !sniffed.as_deref().is_some_and(is_allowed_image_type) {
            new_status = "rejected";
            reject_reason = Some("uploaded object is not an allowed image type");
        }
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE upload_session
            SET status = $1, reject_reason = $2, actual_size_bytes = $3,
                updated_at = NOW(), row_version = row_version + 1
          WHERE id = $4 AND status = 'pending' AND row_version = $5",
    )
    .bind(new_status)
    .bind(reject_reason)
    .bind(actual_size)
    .bind(session_id)
    .bind(row.row_version)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        return Err(AppError::Conflict(
            "upload session has already been finalized",
        ));
    }
    if new_status == "uploaded" {
        // P-job-queue-hardening (D-165): dedup key = the session id itself —
        // this CAS transition (`pending -> uploaded`, guarded by the
        // `rows_affected() != 1` check above) already makes a second scan
        // enqueue for the same session unlikely, but a client retry racing
        // the same finalize call still shouldn't be able to double-queue it.
        attome_jobs::enqueue_in_tx_dedup(
            &mut tx,
            attome_core::jobs::EngineJob::ScanUploadedFile { session_id },
            &session_id.to_string(),
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_db::tx::commit(tx).await?;

    if new_status == "rejected" {
        // Best-effort: an orphaned quarantine object from a mismatched
        // upload has no forensic value (unlike a malware-positive result,
        // which files_scan.rs deliberately keeps). A failed delete here just
        // leaves it for the TTL-based sweep to notice eventually — not
        // fatal to this request either way.
        if let Err(e) = state.base.storage.store().delete(&path).await {
            tracing::warn!(error = %e, session_id = %session_id, "finalize: failed to delete rejected quarantine object");
        }
    }

    Ok(FinalizeResponse {
        session_id,
        status: new_status,
    })
}

#[derive(Serialize, ToSchema)]
pub struct SessionStatusResponse {
    pub status: String,
    pub reject_reason: Option<String>,
    pub actual_size_bytes: Option<i64>,
    pub actual_content_type: Option<String>,
    /// Set only once `status = "clean"` — the value the client must PATCH
    /// onto the record's file field. Without this, a polling client would
    /// have no way to learn what the async scan job promoted the object to.
    pub final_key: Option<String>,
}

impl std::fmt::Debug for SessionStatusResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStatusResponse")
            .finish_non_exhaustive()
    }
}

// ── GET .../upload-session/{session_id} ────────────────────────────────────
//
// Status poll for the async scan job (same shape as F024's bulk-operation
// status poll). Owner-or-admin only — this is per-user upload progress, not
// record data, so `ctx.require(entity, "read")` alone isn't a sufficient gate.
/// Read an upload session
///
/// The upload session's status. Anyone who may read the record.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/files/{field}/upload-session/{session_id}",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
        ("session_id" = Uuid, Path, description = "The upload session"),
    ),
    responses(
        (status = 200, description = "Success", body = SessionStatusResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_upload_session_status(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id, field_input, session_id)): Path<(String, Uuid, String, Uuid)>,
) -> Result<Json<SessionStatusResponse>, AppError> {
    let (entity_id, entity_name, field_name) =
        resolve_file_field(&state, &entity_input, &field_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;
    Ok(Json(
        upload_status(
            &state,
            FileOwner::Staff(ctx.user_id),
            ctx.is_admin,
            &entity_name,
            record_id,
            &field_name,
            session_id,
        )
        .await?,
    ))
}

/// An upload session's progress, for its owner (or a staff admin). The caller
/// has authorized reading the record. One path for both routes (D-774).
pub async fn upload_status(
    state: &EngineState,
    requester: FileOwner,
    is_admin: bool,
    entity_name: &str,
    record_id: Uuid,
    field_name: &str,
    session_id: Uuid,
) -> Result<SessionStatusResponse, AppError> {
    type StatusRowTuple = (
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
    );
    let row: Option<StatusRowTuple> = sqlx::query_as(
        "SELECT status, reject_reason, actual_size_bytes, actual_content_type, owner_user_ref,
                owner_portal_user_ref, final_key
         FROM upload_session
         WHERE id = $1 AND entity_logicalname = $2 AND record_id = $3
           AND field_logicalname = $4 AND is_deleted = false",
    )
    .bind(session_id)
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let (status, reject_reason, actual_size_bytes, actual_content_type, staff, portal, final_key) =
        row.ok_or(AppError::NotFound)?;
    if FileOwner::from_columns(staff, portal)? != requester && !is_admin {
        return Err(not_yours(requester));
    }

    Ok(SessionStatusResponse {
        status,
        reject_reason,
        final_key,
        actual_size_bytes,
        actual_content_type,
    })
}

#[derive(Serialize, ToSchema)]
pub struct DownloadUrlResponse {
    pub download_url: String,
    pub expires_in_secs: u64,
}

impl std::fmt::Debug for DownloadUrlResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DownloadUrlResponse")
            .finish_non_exhaustive()
    }
}

/// A short-lived download URL for `key`, a stored file of `field` on
/// `record_id`, refusing a key that isn't under this record's own prefix.
/// The one presign path the staff and the portal download routes share: the
/// caller has already authorized the record and the field, and `key` is the
/// field's stored value (only a completed, clean, promoted upload is ever
/// stored there, `entity_mutation::lock_file_field_sessions`).
pub async fn record_file_download(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
    field: &str,
    key: &str,
) -> Result<DownloadUrlResponse, AppError> {
    if !is_owned_file_key(entity, record_id, field, key) {
        return Err(AppError::Validation(format!(
            "{field} contains an object key not owned by this record"
        )));
    }
    let ttl = DEFAULT_PRESIGN_EXPIRY;
    let download_url = attome_storage::presign_download(&state.base.storage, key, ttl)
        .await
        .map_err(storage_error)?;
    Ok(DownloadUrlResponse {
        download_url,
        expires_in_secs: ttl.as_secs(),
    })
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct DownloadUrlQuery {
    /// Which object key to download — **required** for a multi-file field
    /// (`options.multi`, JSONB array column), since the field itself no
    /// longer names a single object. Ignored for a single-file field, which
    /// still has only one key to serve. Ignored entirely when `version` is
    /// also present — `version` names an exact historical object on its own.
    key: Option<String>,
    /// M55 P2 (file versioning) — resolve to this version's object key
    /// (`file_version`) instead of the field's current live value.
    /// Any version ever recorded for this field can be downloaded, not only
    /// `is_current` — the version list is the read path for history; this is
    /// the read path for one specific entry in it.
    version: Option<i32>,
    /// Z6-T6: the file's 320 px thumbnail instead of the file (an image
    /// only, once the background job has made it; 404 before that).
    #[serde(default)]
    thumbnail: bool,
}

// ── GET /api/v1/{entity}/{id}/files/{field}/download-url ──────────────────
//
// Reads the object key(s) already stored on the record (written via the
// generic PATCH path, gated by `entity_mutation::lock_file_field_sessions`)
// and hands back a short-lived GET URL. Post-pipeline, the column holds a
// promoted `final_key`, never a `quarantine_key` — this handler's own logic
// is otherwise unchanged from the pre-pipeline broker.
//
// `to_jsonb(column)` reads a single-file `TEXT` column and a multi-file
// `JSONB` column through the one query — the branch on the decoded shape
// (string vs array) is what actually distinguishes them, not two SQL
// statements guessing the physical type up front.
/// Get a file's download URL
///
/// A short-lived URL to download the field's file, one of a multi-file field's files (`key`), or an
/// earlier version (`version`). Anyone who may read the record.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/files/{field}/download-url",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
        DownloadUrlQuery,
    ),
    responses(
        (status = 200, description = "Success", body = DownloadUrlResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_download_url(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
    Query(params): Query<DownloadUrlQuery>,
) -> Result<Json<DownloadUrlResponse>, AppError> {
    let (entity_id, entity_name, field_name) =
        resolve_file_field(&state, &entity_input, &field_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;

    let key = if let Some(version) = params.version {
        // M55 P2 — an explicit version bypasses the field's live value
        // entirely: the version table is its own source of truth for "what
        // object did version N ever point at", independent of whether N is
        // still `is_current`. `require_record_access` above already proved
        // the record exists, is active, and is readable by this caller.
        let object_key: Option<String> = sqlx::query_scalar(
            "SELECT object_key FROM file_version
              WHERE entity = $1 AND record_id = $2 AND field = $3 AND version_no = $4
                AND is_deleted = false",
        )
        .bind(&entity_name)
        .bind(record_id)
        .bind(&field_name)
        .bind(version)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        object_key.ok_or(AppError::NotFound)?
    } else {
        let table = quote_ident(&entity_name);
        let column = quote_ident(&field_name);
        // Outer Option: no such active record (404). Inner Option: record
        // exists but the field has never been uploaded to (422, not 404 —
        // the field and record are both real, there's just nothing to
        // download yet).
        let raw: Option<Option<serde_json::Value>> =
            sqlx::query_scalar::<_, Option<serde_json::Value>>(&format!(
                "SELECT to_jsonb({column}) FROM {table} WHERE id = $1 AND is_active = true"
            ))
            .bind(record_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;

        let value = raw
            .ok_or(AppError::NotFound)?
            .ok_or_else(|| AppError::Validation(format!("{field_name} has no file uploaded")))?;

        match value {
            serde_json::Value::String(s) => s,
            serde_json::Value::Array(items) => {
                let requested = params.key.ok_or_else(|| {
                    AppError::Validation(format!(
                        "{field_name} is a multi-file field; pass ?key=<object key>"
                    ))
                })?;
                if !items.iter().any(|v| v.as_str() == Some(requested.as_str())) {
                    return Err(AppError::Validation(format!(
                        "{field_name} does not contain that key"
                    )));
                }
                requested
            }
            _ => return Err(AppError::internal("unexpected file field value shape")),
        }
    };

    // Z6-T6: the thumbnail, after the same record and field check.
    let key = if params.thumbnail {
        crate::thumbnail::thumbnail_of(&state, &key)
            .await?
            .ok_or(AppError::NotFound)?
    } else {
        key
    };
    Ok(Json(
        record_file_download(&state, &entity_name, record_id, &field_name, &key).await?,
    ))
}

// ═══════════════════════════════════════════════════════════════════════
// M55 P2 — file versioning (D-432's plan §3 "File versioning" target design)
// ═══════════════════════════════════════════════════════════════════════
//
// Version rows themselves are written by `entity_mutation::
// create_file_versions_for_update`, inside the same transaction as the
// generic PATCH path that actually changes a file field's value (checklist
// item 2) — not by anything in this section. What lives here is the reader
// (list, and `download-url`'s `?version=` above), the mutator that doesn't
// go through ordinary entity PATCH (restore), and the retention/hold gate
// on removing a non-current version (purge).

#[derive(Serialize, ToSchema)]
struct FileVersionResponse {
    version_no: i32,
    object_key: String,
    size: Option<i64>,
    hash: Option<String>,
    content_type: Option<String>,
    /// The staff uploader; `None` for a portal user's upload (D-774).
    uploaded_by: Option<Uuid>,
    /// The portal uploader, for a portal user's upload (D-774).
    uploaded_by_portal_user: Option<Uuid>,
    scan_status: String,
    is_current: bool,
    created_at: DateTime<Utc>,
}

type FileVersionRowTuple = (
    i32,
    String,
    Option<i64>,
    Option<String>,
    Option<String>,
    Option<Uuid>,
    Option<Uuid>,
    String,
    bool,
    DateTime<Utc>,
);

impl From<FileVersionRowTuple> for FileVersionResponse {
    fn from(
        (
            version_no,
            object_key,
            size,
            hash,
            content_type,
            uploaded_by,
            uploaded_by_portal_user,
            scan_status,
            is_current,
            created_at,
        ): FileVersionRowTuple,
    ) -> Self {
        Self {
            version_no,
            object_key,
            size,
            hash,
            content_type,
            uploaded_by,
            uploaded_by_portal_user,
            scan_status,
            is_current,
            created_at,
        }
    }
}

// ── GET /api/v1/{entity}/{id}/files/{field}/versions ───────────────────────
//
// Every version ever recorded for this field, newest first. Not paged by the
// caller — a field's version history is inherently bounded by how many times
// it has been PATCHed, the same "return the whole capped result in one
// response" reasoning guidelines §12 gives for a depth-bounded structural
// walk, so `page`/`page_size` are fixed rather than driven by a query param.
/// List a file's versions
///
/// Every stored version of the field's file, newest first. Anyone who may read the record.
#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/files/{field}/versions",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
    ),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<FileVersionResponse>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_file_versions(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id, field_input)): Path<(String, Uuid, String)>,
) -> Result<Json<PaginatedResponse<FileVersionResponse>>, AppError> {
    let (entity_id, entity_name, field_name) =
        resolve_file_field(&state, &entity_input, &field_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;

    let rows: Vec<FileVersionRowTuple> = sqlx::query_as(
        "SELECT version_no, object_key, size, hash, content_type, uploaded_by,
                uploaded_by_portal_user, scan_status, is_current, created_at
           FROM file_version
          WHERE entity = $1 AND record_id = $2 AND field = $3 AND is_deleted = false
          ORDER BY version_no DESC",
    )
    .bind(&entity_name)
    .bind(record_id)
    .bind(&field_name)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let items: Vec<FileVersionResponse> = rows.into_iter().map(FileVersionResponse::from).collect();
    let total = items.len() as i64;
    Ok(Json(PaginatedResponse::new(items, total, 1, total.max(1))))
}

#[derive(Serialize, ToSchema)]
struct RestoreVersionResponse {
    version_no: i32,
    object_key: String,
}

// ── POST .../files/{field}/versions/{version_no}/restore ───────────────────
//
// Flips a prior version back to `is_current` and converges the record's live
// field value to match — a restore that only relabelled version-table rows
// without also updating the column would leave `download-url` (no
// `?version=`) still serving the version that was current a moment ago,
// which is not what "restore" means to a caller. Deliberately NOT routed
// through `entity_mutation::update_one`/`lock_file_field_sessions`: the
// object key being written back is one this table already proved was once a
// clean, owned session's promoted key (recorded by
// `create_file_versions_for_update` at the time), so re-checking it against
// a *live* `upload_session` row would wrongly demand one still
// exist — sessions are not kept forever. Same reasoning `MutationMode::
// MirroredFileWrite`'s doc comment gives for its own narrower skip. Writes
// the entity column directly instead, mirroring `entity_crud::mutations::
// restore_record`/`hard_delete_record`'s own established style of a
// dedicated hand-written statement plus a manual change-feed emission and
// audit event, rather than a generic mutation primitive built for a
// different contract.
/// Restore a file version
///
/// Makes an earlier version the field's current file. Needs update rights on the record. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/files/{field}/versions/{version_no}/restore",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
        ("version_no" = i32, Path, description = "The version number"),
    ),
    responses(
        (status = 200, description = "Success", body = RestoreVersionResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such version", body = ErrorResponse),
        (status = 409, description = "Version is already current", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Attachment, attome_audit::AuditOperation::Restore)])))),
)]
async fn restore_file_version(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Path((entity_input, record_id, field_input, version_no)): Path<(String, Uuid, String, i32)>,
) -> Result<Json<RestoreVersionResponse>, AppError> {
    let (entity_id, entity_name, field_name) =
        resolve_file_field(&state, &entity_input, &field_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Update,
    )
    .await?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let lock_key = format!("xrm-files/file-version:{entity_name}:{record_id}:{field_name}");
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(attome_records::FILES_ADVISORY_LOCK_NAMESPACE)
        .bind(&lock_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "a version change is already in progress for this field, retry shortly",
        ));
    }

    let target: Option<(String, bool)> = sqlx::query_as(
        "SELECT object_key, is_current FROM file_version
          WHERE entity = $1 AND record_id = $2 AND field = $3 AND version_no = $4
            AND is_deleted = false
          FOR UPDATE",
    )
    .bind(&entity_name)
    .bind(record_id)
    .bind(&field_name)
    .bind(version_no)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((object_key, is_current)) = target else {
        return Err(AppError::NotFound);
    };
    if is_current {
        return Err(AppError::Conflict("this version is already current"));
    }

    sqlx::query(
        "UPDATE file_version SET is_current = false
          WHERE entity = $1 AND record_id = $2 AND field = $3 AND is_current = true",
    )
    .bind(&entity_name)
    .bind(record_id)
    .bind(&field_name)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "UPDATE file_version SET is_current = true
          WHERE entity = $1 AND record_id = $2 AND field = $3 AND version_no = $4",
    )
    .bind(&entity_name)
    .bind(record_id)
    .bind(&field_name)
    .bind(version_no)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    let table = quote_ident(&entity_name);
    let column = quote_ident(&field_name);
    let updated = sqlx::query(&format!(
        "UPDATE {table} SET {column} = $1, row_version = row_version + 1, modified_at = NOW(), \
                              modified_by = $2
          WHERE id = $3 AND is_active = true"
    ))
    .bind(&object_key)
    .bind(ctx.user_id)
    .bind(record_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() != 1 {
        // Access was already proven above; a miss here means the record was
        // deactivated by a concurrent request between that check and this
        // write — surfaced as NotFound rather than a silent partial restore
        // (the version flip above is still inside this same transaction, so
        // it rolls back with everything else).
        return Err(AppError::NotFound);
    }

    attome_core::change_feed::emit_tx(
        &mut tx,
        &entity_name,
        record_id,
        attome_core::ChangeOperation::Update,
    )
    .await?;

    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(&state, ctx.user_id).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Attachment,
        entity_name: Some(entity_name.clone()),
        record_id: Some(record_id),
        operation: AuditOperation::Restore,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(field_name.clone()),
        event_comment: Some(format!("restored file version {version_no}")),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone())
        .write_in_tx(&mut tx, event)
        .await?;

    attome_db::tx::commit(tx).await?;

    Ok(Json(RestoreVersionResponse {
        version_no,
        object_key,
    }))
}

/// M55 P2 — permanently removes a non-current file version's storage object
/// and marks its row `is_deleted`. Never called through this crate's own
/// code today (item 5's priority is the gate, not a scheduled lifecycle
/// policy — see this function's own module-level section comment); exposed
/// here as a `pub(crate)` primitive plus the thin HTTP wrapper below so both
/// a future scheduled job and an admin action can call the exact same gate.
///
/// Refuses to act when:
/// - the version is `is_current` (purging it would orphan the field's live
///   value — restore first),
/// - the version's own `legal_hold`/`retention_expires_at` says no — the
///   same two columns, same fail-closed shape, `files_scan.rs::
///   prune_expired_sessions` already checks before touching a quarantined
///   upload session, and
/// - the *record* the version belongs to is under an active
///   `legal_hold` (`attome_core::legal_hold::record_is_held`) —
///   the same check `entity_crud::mutations::hard_delete_record` runs before
///   it ever deletes a record's own file objects, applied here so a
///   record-level hold protects that record's file history too, not only
///   its live field value.
pub(crate) async fn purge_file_version(
    state: &EngineState,
    actor_user_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    field_name: &str,
    version_no: i32,
) -> Result<(), AppError> {
    type VersionRow = (String, bool, bool, Option<DateTime<Utc>>);
    let row: Option<VersionRow> = sqlx::query_as(
        "SELECT object_key, is_current, legal_hold, retention_expires_at
           FROM file_version
          WHERE entity = $1 AND record_id = $2 AND field = $3 AND version_no = $4
            AND is_deleted = false",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .bind(version_no)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((object_key, is_current, legal_hold, retention_expires_at)) = row else {
        return Err(AppError::NotFound);
    };
    if is_current {
        return Err(AppError::Conflict(
            "cannot purge the current version of a file field",
        ));
    }
    if legal_hold {
        return Err(AppError::Conflict(
            "file version is under an active legal hold",
        ));
    }
    if let Some(expires) = retention_expires_at
        && expires > Utc::now()
    {
        return Err(AppError::Conflict(
            "file version is still within its retention period",
        ));
    }
    if attome_core::legal_hold::record_is_held(&state.base.db, entity_name, record_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("record is under an active legal hold"));
    }

    let purged = sqlx::query(
        "UPDATE file_version SET is_deleted = true
          WHERE entity = $1 AND record_id = $2 AND field = $3 AND version_no = $4
            AND is_deleted = false AND is_current = false",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(field_name)
    .bind(version_no)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if purged.rows_affected() != 1 {
        // Raced with a restore (flipped is_current) or another purge between
        // the checks above and this UPDATE — refuse rather than delete
        // storage for a version that may no longer be what we just verified.
        return Err(AppError::Conflict(
            "file version changed concurrently, retry",
        ));
    }

    // Audit-coverage slice (Phase 3.7): this route previously wrote no
    // event at all despite permanently destroying a file version past its
    // legal-hold/retention checks. Not in the same transaction as the
    // UPDATE above (this function has never held one — see the storage
    // cleanup's own "best-effort" comment below), so it is best-effort like
    // everything else here rather than a D-062 atomic write.
    let (user_ctx, org_ref) =
        attome_records::entity_crud::fetch_audit_ctx(state, actor_user_id).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Attachment,
        entity_name: Some(entity_name.to_owned()),
        record_id: Some(record_id),
        operation: AuditOperation::HardDelete,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(field_name.to_owned()),
        event_comment: Some(format!("purged file version {version_no}")),
        changed_fields: Vec::new(),
        snapshot_json: None,
    };
    if let Err(e) = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone())
        .write(event)
        .await
    {
        tracing::warn!(
            entity = %entity_name, record_id = %record_id, field = %field_name,
            version_no, error = %e,
            "purge: failed to write audit event for an already-committed purge"
        );
    }

    // Best-effort, same posture as every other post-commit storage cleanup
    // in this pipeline (finalize's rejected-upload delete, the orphan
    // sweep, hard-delete's file cleanup): the row is already gone and
    // committed, so a storage failure here has nothing left to roll back.
    if let Ok(path) = ObjectPath::parse(&object_key)
        && let Err(e) = state.base.storage.store().delete(&path).await
    {
        tracing::warn!(
            entity = %entity_name, record_id = %record_id, field = %field_name,
            version_no, error = %e,
            "purge: failed to delete file version storage object"
        );
    }
    Ok(())
}

// ── DELETE .../files/{field}/versions/{version_no} ──────────────────────────
/// Purge a file version
///
/// Deletes a stored version of the file for good. Needs delete rights on the record. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/{entity}/{id}/files/{field}/versions/{version_no}",
    tag = "entity",
    params(
        ("entity" = String, Path, description = "The entity's logical name"),
        ("id" = Uuid, Path, description = "The record"),
        ("field" = String, Path, description = "The file field"),
        ("version_no" = i32, Path, description = "The version number"),
    ),
    responses(
        (status = 204, description = "Version permanently purged"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such version", body = ErrorResponse),
        (status = 409, description = "Version is current, under legal hold, or within its retention period", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Attachment, attome_audit::AuditOperation::HardDelete)])))),
)]
async fn purge_file_version_route(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Delete>>,
    Path((entity_input, record_id, field_input, version_no)): Path<(String, Uuid, String, i32)>,
) -> Result<StatusCode, AppError> {
    let (entity_id, entity_name, field_name) =
        resolve_file_field(&state, &entity_input, &field_input).await?;
    require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Delete,
    )
    .await?;
    purge_file_version(
        &state,
        ctx.user_id,
        &entity_name,
        record_id,
        &field_name,
        version_no,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/{entity}/{id}/files/{field}/upload-session",
            post(create_upload_session),
        )
        .route(
            "/api/v1/{entity}/{id}/files/{field}/upload-session/{session_id}/finalize",
            post(finalize_upload_session),
        )
        .route(
            "/api/v1/{entity}/{id}/files/{field}/upload-session/{session_id}",
            get(get_upload_session_status),
        )
        .route(
            "/api/v1/{entity}/{id}/files/{field}/download-url",
            get(get_download_url),
        )
        .route(
            "/api/v1/{entity}/{id}/files/{field}/versions",
            get(list_file_versions),
        )
        .route(
            "/api/v1/{entity}/{id}/files/{field}/versions/{version_no}/restore",
            post(restore_file_version),
        )
        .route(
            "/api/v1/{entity}/{id}/files/{field}/versions/{version_no}",
            delete(purge_file_version_route),
        )
}

#[cfg(test)]
mod quota_tests {
    use super::QuotaUse;

    #[test]
    fn a_cap_is_past_its_warning_share() {
        let quota = |used| QuotaUse {
            limit: "storage.max_deployment_storage_bytes",
            scope: "deployment".into(),
            used,
            max: 1000,
        };
        assert!(!quota(799).past(80));
        assert!(quota(800).past(80));
        assert!(quota(1000).past(100));
        assert!(!QuotaUse { max: 0, ..quota(5) }.past(80));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// U9: the image allow-list — case/parameters ignored, SVG never.
    #[test]
    fn image_content_type_allow_list() {
        for ok in [
            "image/png",
            "IMAGE/JPEG",
            "image/webp; charset=binary",
            "image/gif",
        ] {
            assert!(is_allowed_image_type(ok), "{ok}");
        }
        for bad in [
            "image/svg+xml",
            "application/pdf",
            "text/html",
            "",
            "image/",
        ] {
            assert!(!is_allowed_image_type(bad), "{bad}");
        }
    }

    #[test]
    fn final_key_scopes_by_entity_record_and_field() {
        let id = Uuid::nil();
        let session_id = Uuid::nil();
        let key = final_key("core_contact", id, "avatar", session_id, "photo.jpg");
        assert!(key.starts_with(&format!("core_contact/{id}/avatar/")));
        assert!(key.ends_with("-photo.jpg"));
    }

    #[test]
    fn quarantine_key_carries_the_configured_prefix() {
        let id = Uuid::nil();
        let session_id = Uuid::nil();
        let key = quarantine_key(
            "_quarantine/",
            "core_contact",
            id,
            "avatar",
            session_id,
            "photo.jpg",
        );
        assert!(key.starts_with("_quarantine/core_contact/"));
    }

    #[test]
    fn safe_filename_sanitises_unsafe_characters() {
        let suffix = safe_filename("../../etc/passwd");
        assert!(!suffix.contains('/'));
        assert!(!suffix.contains(".."));
    }

    #[test]
    fn file_key_must_stay_with_its_entity_record_and_field() {
        let id = Uuid::nil();
        let session_id = Uuid::nil();
        let key = final_key("core_contact", id, "avatar", session_id, "photo.jpg");
        assert!(is_owned_file_key("core_contact", id, "avatar", &key));
        assert!(!is_owned_file_key(
            "core_contact",
            Uuid::new_v4(),
            "avatar",
            &key
        ));
        assert!(!is_owned_file_key("core_contact", id, "resume", &key));
        assert!(!is_owned_file_key("core_account", id, "avatar", &key));
    }

    #[test]
    fn sha256_hex_validation_rejects_wrong_length_and_non_hex() {
        assert!(valid_sha256_hex(&"a".repeat(64)));
        assert!(!valid_sha256_hex(&"a".repeat(63)));
        assert!(!valid_sha256_hex(&"z".repeat(64)));
    }
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    create_upload_session,
    finalize_upload_session,
    get_upload_session_status,
    get_download_url,
    list_file_versions,
    restore_file_version,
    purge_file_version_route
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
