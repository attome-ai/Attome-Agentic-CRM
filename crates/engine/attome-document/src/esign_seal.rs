//! K4-T2: the sealed copies of a completed envelope's PDFs.
//!
//! When the last signer signs, the completion queues
//! `EngineJob::SealEnvelope` in the same transaction. The job reads the
//! deployment's signing certificate and key (`esign.seal_certificate_file`,
//! `esign.seal_key_file`; both PEM files, see [`crate::pades::SealKey`]),
//! seals every PDF of the envelope with a PAdES signature
//! ([`crate::pades::seal`], off the runtime threads) and stores the sealed
//! copy beside the envelope (`esign/<envelope>/<document>-sealed.pdf`), its
//! SHA-256 kept on the document's row. The original file is never changed:
//! the certificate's hashes still name exactly what was signed, and the
//! sealed copy carries the original as its first revision.
//!
//! The job is idempotent: a document already sealed is skipped, so a retry
//! seals only what is left. A document that is not a PDF, or one the reader
//! cannot follow (encrypted, broken), keeps its reason in `seal_error` and is
//! not retried; a missing key leaves the envelope unsealed with a warning, so
//! setting the key and re-queuing (`POST …/seal`) seals it later.
//!
//! The owner (or an administrator) downloads a sealed copy at
//! `GET /api/v1/esign/envelopes/{id}/documents/{document_id}/sealed`.

use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::Serialize;
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::pades::{self, SealError, SealInfo, SealKey};

/// Where a sealed copy is stored.
pub fn sealed_key(envelope: Uuid, document: Uuid) -> String {
    format!("esign/{envelope}/{document}-sealed.pdf")
}

/// The deployment's seal key, or `None` when none is configured.
async fn load_key(state: &EngineState) -> Result<Option<SealKey>, AppError> {
    let section = &state.base.config.esign;
    let (cert_file, key_file) = (
        section.seal_certificate_file.trim(),
        section.seal_key_file.trim(),
    );
    if cert_file.is_empty() || key_file.is_empty() {
        return Ok(None);
    }
    let certificates = tokio::fs::read_to_string(cert_file).await.map_err(|e| {
        tracing::error!(error = %e, "esign seal: esign.seal_certificate_file cannot be read");
        AppError::internal("the signing certificate cannot be read")
    })?;
    let key = tokio::fs::read_to_string(key_file).await.map_err(|e| {
        tracing::error!(error = %e, "esign seal: esign.seal_key_file cannot be read");
        AppError::internal("the signing key cannot be read")
    })?;
    SealKey::from_pem(&certificates, &key)
        .map(Some)
        .map_err(|e| {
            tracing::error!(reason = %e, "esign seal: the configured key is unusable");
            AppError::internal("the signing key is unusable")
        })
}

/// `EngineJob::SealEnvelope`: seals a completed envelope's PDFs.
pub async fn process(state: &EngineState, envelope: Uuid) -> Result<(), AppError> {
    let head: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT title, certificate_hash FROM esign_envelope \
          WHERE id = $1 AND status = 'completed'",
    )
    .bind(envelope)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((title, certificate_hash)) = head else {
        return Ok(());
    };
    let documents: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT id, document_id, file_key FROM esign_document \
          WHERE envelope_id = $1 AND sealed_key IS NULL AND seal_error IS NULL ORDER BY position",
    )
    .bind(envelope)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if documents.is_empty() {
        return Ok(());
    }
    let Some(key) = load_key(state).await? else {
        tracing::warn!(%envelope, "esign seal: no signing certificate is configured; the envelope stays unsealed");
        return Ok(());
    };
    let key = std::sync::Arc::new(key);
    let reason = match &certificate_hash {
        Some(h) => format!("Signed by everyone ({title}); certificate {h}"),
        None => format!("Signed by everyone ({title})"),
    };
    for (row, document, file_key) in documents {
        let path = ObjectPath::parse(&file_key)
            .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
        let object = match state.base.storage.store().get(&path).await {
            Ok(o) => o,
            Err(object_store::Error::NotFound { .. }) => {
                record_error(state, row, "the signed file is no longer stored").await?;
                continue;
            }
            Err(e) => return Err(AppError::internal(e)),
        };
        if object.meta.size > pades::MAX_PDF_BYTES as u64 {
            record_error(state, row, "the file is larger than 64 MB").await?;
            continue;
        }
        let bytes = object.bytes().await.map_err(AppError::internal)?;
        if !bytes.starts_with(b"%PDF-") {
            record_error(state, row, "not a PDF").await?;
            continue;
        }
        let key = key.clone();
        let reason = reason.clone();
        let sealed = tokio::task::spawn_blocking(move || {
            pades::seal(
                &bytes,
                &key,
                &SealInfo {
                    reason: &reason,
                    location: None,
                    at: Utc::now(),
                },
            )
        })
        .await
        .map_err(AppError::internal)?;
        let sealed = match sealed {
            Ok(s) => s,
            Err(e @ (SealError::Unreadable(_) | SealError::Encrypted)) => {
                tracing::info!(%envelope, %document, reason = %e, "esign seal: a document cannot be sealed");
                record_error(state, row, &e.to_string()).await?;
                continue;
            }
            Err(e) => {
                tracing::error!(%envelope, %document, reason = %e, "esign seal: sealing failed");
                return Err(AppError::internal(e));
            }
        };
        let sha256 = hex::encode(Sha256::digest(&sealed));
        let target = sealed_key(envelope, document);
        let target_path = ObjectPath::parse(&target).map_err(AppError::internal)?;
        state
            .base
            .storage
            .store()
            .put(&target_path, sealed.into())
            .await
            .map_err(AppError::internal)?;
        sqlx::query(
            "UPDATE esign_document SET sealed_key = $2, sealed_sha256 = $3, sealed_at = now() \
              WHERE id = $1 AND sealed_key IS NULL",
        )
        .bind(row)
        .bind(&target)
        .bind(&sha256)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        tracing::info!(%envelope, %document, "esign seal: document sealed");
    }
    Ok(())
}

async fn record_error(state: &EngineState, row: Uuid, why: &str) -> Result<(), AppError> {
    sqlx::query("UPDATE esign_document SET seal_error = $2 WHERE id = $1 AND sealed_key IS NULL")
        .bind(row)
        .bind(why)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// A document's seal, as the envelope's owner sees it.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct SealedDocument {
    pub document_id: Uuid,
    /// The sealed copy's SHA-256, once sealed.
    pub sealed_sha256: Option<String>,
    pub sealed_at: Option<chrono::DateTime<Utc>>,
    /// Why the document was not sealed (not a PDF, encrypted, unreadable).
    pub seal_error: Option<String>,
}

/// The seals of an envelope's documents, in order.
pub async fn seals(state: &EngineState, envelope: Uuid) -> Result<Vec<SealedDocument>, AppError> {
    sqlx::query_as(
        "SELECT document_id, sealed_sha256, sealed_at, seal_error FROM esign_document \
          WHERE envelope_id = $1 ORDER BY position",
    )
    .bind(envelope)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// The owner (or an administrator) only; others get `NotFound`.
async fn require_owner(
    state: &EngineState,
    ctx: &SecurityContext,
    envelope: Uuid,
) -> Result<String, AppError> {
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT created_by, status FROM esign_envelope WHERE id = $1")
            .bind(envelope)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    match row {
        Some((o, status)) if o == ctx.user_id || ctx.is_admin => Ok(status),
        _ => Err(AppError::NotFound),
    }
}

/// Download a sealed document
///
/// K4-T2: the PAdES-sealed copy of one of a completed envelope's PDFs.
#[utoipa::path(
    get,
    path = "/api/v1/esign/envelopes/{id}/documents/{document_id}/sealed",
    operation_id = "get_esign_sealed_document",
    tag = "document",
    params(
        ("id" = Uuid, Path, description = "The envelope"),
        ("document_id" = Uuid, Path, description = "The document in the envelope"),
    ),
    responses(
        (status = 200, description = "The sealed PDF", content_type = "application/pdf", body = Vec<u8>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No envelope of the caller's, or the document is not sealed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// The sealed copy of an envelope's document.
async fn get_sealed(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path((id, document_id)): Path<(Uuid, Uuid)>,
) -> Result<Response, AppError> {
    require_owner(&state, &ctx, id).await?;
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT name, sealed_key FROM esign_document WHERE envelope_id = $1 AND document_id = $2",
    )
    .bind(id)
    .bind(document_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((name, Some(key))) = row else {
        return Err(AppError::NotFound);
    };
    let path = ObjectPath::parse(&key).map_err(AppError::internal)?;
    let object = match state.base.storage.store().get(&path).await {
        Ok(o) => o,
        Err(object_store::Error::NotFound { .. }) => return Err(AppError::NotFound),
        Err(e) => return Err(AppError::internal(e)),
    };
    let bytes = object.bytes().await.map_err(AppError::internal)?;
    let stem = name
        .rsplit_once('.')
        .map_or(name.as_str(), |(stem, _)| stem)
        .replace(['"', '\\', '\r', '\n', '/'], "_");
    let ascii: String = stem
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok((
        [
            (header::CONTENT_TYPE, "application/pdf".to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{ascii}-sealed.pdf\""),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// Seal a completed envelope again
///
/// K4-T2: queues the seal of the documents not sealed yet (after the
/// signing certificate was set, say). Audited.
#[utoipa::path(
    post,
    path = "/api/v1/esign/envelopes/{id}/seal",
    operation_id = "post_esign_envelope_seal",
    tag = "document",
    params(("id" = Uuid, Path, description = "The envelope")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 202, description = "The seal is queued"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No envelope of the caller's", body = ErrorResponse),
        (status = 409, description = "The envelope is not completed", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
// Queues the seal of a completed envelope's unsealed documents.
async fn post_seal(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let status = require_owner(&state, &ctx, id).await?;
    if status != "completed" {
        return Err(AppError::Conflict("the envelope is not completed"));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::SealEnvelope { envelope_id: id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "esign_envelope",
            id,
            attome_audit::AuditOperation::Update,
            "esign.envelope_seal_queued",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::ACCEPTED)
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/esign/envelopes/{id}/documents/{document_id}/sealed",
            get(get_sealed),
        )
        .route("/api/v1/esign/envelopes/{id}/seal", post(post_seal))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_sealed, post_seal), components(schemas(SealedDocument)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
