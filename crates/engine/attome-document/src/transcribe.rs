//! Recording transcription (roadmap N22-T2): a recording is an
//! `attome_document` on the record it belongs to (a call, J6-T3). The
//! `TranscribeRecording` job sends its audio to the deployment's speech
//! endpoint (N22-T1) and keeps the transcript beside the file:
//!
//! - `recording_transcript` holds the text, language, length and timed
//!   segments, keyed by the file's storage key; `GET
//!   /api/v1/documents/{id}/transcript` serves it to anyone who may read the
//!   document, so the transcript is attached to the record exactly as the
//!   recording is;
//! - `document_text` gets the text too (format `transcript`), so global
//!   search finds the call by what was said, under the document's own
//!   permissions (K1-T4).
//!
//! **Retention.** The transcript lives as long as a document names its file.
//! When retention (or anyone) purges the last such document, the hourly
//! recovery-archive job deletes the transcript and its search text
//! ([`prune_orphans`]). A soft-deleted document keeps its transcript, so a
//! restore needs no new transcription.
//!
//! A deployment without a speech endpoint skips the job quietly; a speech
//! failure fails the job so the queue retries it.

use attome_audit::security::x_audit;
use attome_audit::{AuditCategory, AuditOperation, BusinessEvent};
use attome_core::EngineState;
use attome_inference::{InferenceError, Segment, SpeechClient};
use attome_security::RecordAction;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use chrono::{DateTime, Utc};

/// A stored transcript: text, language, duration, segments, model and when.
type TranscriptRow = (
    String,
    Option<String>,
    Option<f64>,
    serde_json::Value,
    String,
    DateTime<Utc>,
);
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

const DOCUMENT_ENTITY: &str = "attome_document";

/// File extensions the speech endpoint accepts.
pub const AUDIO_EXTENSIONS: &[&str] = &[
    "mp3", "mp4", "m4a", "mpeg", "mpga", "wav", "webm", "ogg", "oga", "opus", "flac", "aac",
];

/// Whether an upload is audio the speech endpoint can read. Pure.
pub fn is_audio(content_type: Option<&str>, file_name: &str) -> bool {
    if content_type.is_some_and(|c| c.trim().to_ascii_lowercase().starts_with("audio/")) {
        return true;
    }
    file_name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
        .is_some_and(|ext| AUDIO_EXTENSIONS.contains(&ext.as_str()))
}

/// A recording's transcript.
#[derive(Debug, Serialize, ToSchema)]
pub struct TranscriptView {
    pub document_id: Uuid,
    pub text: String,
    pub language: Option<String>,
    pub duration_seconds: Option<f64>,
    /// `[{start, end, text}]`, seconds from the start.
    #[schema(value_type = Object)]
    pub segments: serde_json::Value,
    pub model: String,
    pub transcribed_at: DateTime<Utc>,
}

#[derive(Debug, sqlx::FromRow)]
struct Recording {
    file: Option<String>,
    content_type: Option<String>,
    filename: Option<String>,
}

/// Worker for `EngineJob::TranscribeRecording`. Idempotent: a second run
/// rewrites the same transcript.
pub async fn process(state: &EngineState, document_id: Uuid) -> Result<(), AppError> {
    let db = &state.base.db;
    let row: Option<Recording> = sqlx::query_as(
        "SELECT d.file, s.actual_content_type AS content_type, s.declared_filename AS filename \
           FROM attome_document d \
           LEFT JOIN upload_session s ON s.final_key = d.file AND s.status = 'clean' \
          WHERE d.id = $1 AND d.is_active = true \
          ORDER BY s.created_at DESC NULLS LAST LIMIT 1",
    )
    .bind(document_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some(Recording {
        file: Some(file_key),
        content_type,
        filename,
    }) = row
    else {
        return Ok(());
    };
    let filename =
        filename.unwrap_or_else(|| file_key.rsplit('/').next().unwrap_or("audio").to_owned());
    if !is_audio(content_type.as_deref(), &filename) {
        tracing::info!(%document_id, "transcribe: not an audio file; skipped");
        return Ok(());
    }
    let client = match SpeechClient::new(&state.base.config.inference) {
        Ok(client) => client,
        Err(InferenceError::NotConfigured(_)) => {
            tracing::info!(%document_id, "transcribe: no speech endpoint configured; skipped");
            return Ok(());
        }
        Err(e) => return Err(AppError::internal(e)),
    };
    let path = ObjectPath::parse(&file_key)
        .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
    let object = match state.base.storage.store().get(&path).await {
        Ok(object) => object,
        Err(object_store::Error::NotFound { .. }) => return Ok(()),
        Err(e) => return Err(AppError::internal(e)),
    };
    if object.meta.size > attome_inference::speech::MAX_AUDIO_BYTES as u64 {
        tracing::info!(%document_id, size = object.meta.size, "transcribe: recording over the upload limit; skipped");
        return Ok(());
    }
    let audio = object.bytes().await.map_err(AppError::internal)?;
    let transcript = client
        .transcribe(&audio, &filename, None)
        .await
        .map_err(AppError::internal)?;
    let segments = segments_json(&transcript.segments);

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(
        "INSERT INTO recording_transcript \
             (file_key, content_text, language, duration_seconds, segments, model) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (file_key) DO UPDATE \
            SET content_text = EXCLUDED.content_text, language = EXCLUDED.language, \
                duration_seconds = EXCLUDED.duration_seconds, segments = EXCLUDED.segments, \
                model = EXCLUDED.model, transcribed_at = now()",
    )
    .bind(&file_key)
    .bind(&transcript.text)
    .bind(&transcript.language)
    .bind(transcript.duration)
    .bind(&segments)
    .bind(client.model_id())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO document_text (file_key, format, content_text) VALUES ($1, 'transcript', $2) \
         ON CONFLICT (file_key) DO UPDATE \
            SET format = EXCLUDED.format, content_text = EXCLUDED.content_text, extracted_at = now()",
    )
    .bind(&file_key)
    .bind(&transcript.text)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // The documents naming the file reindex with the new text (K1-T4).
    let documents: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM attome_document WHERE file = $1 AND is_active = true")
            .bind(&file_key)
            .fetch_all(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    for id in &documents {
        attome_core::change_feed::emit_tx(
            &mut tx,
            DOCUMENT_ENTITY,
            *id,
            attome_core::ChangeOperation::Update,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    tracing::info!(%document_id, chars = transcript.text.chars().count(), "recording transcribed");
    Ok(())
}

/// The segments as stored. Pure.
pub fn segments_json(segments: &[Segment]) -> serde_json::Value {
    serde_json::Value::Array(
        segments
            .iter()
            .map(|s| serde_json::json!({"start": s.start, "end": s.end, "text": s.text.trim()}))
            .collect(),
    )
}

/// Deletes transcripts (and their search text) whose file no document names
/// any more; the number deleted.
pub async fn prune_orphans(db: &attome_db::DbPool) -> Result<u64, AppError> {
    let gone = sqlx::query(
        "DELETE FROM recording_transcript t \
          WHERE NOT EXISTS (SELECT 1 FROM attome_document d WHERE d.file = t.file_key)",
    )
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    sqlx::query(
        "DELETE FROM document_text x WHERE x.format = 'transcript' \
            AND NOT EXISTS (SELECT 1 FROM attome_document d WHERE d.file = x.file_key)",
    )
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(gone)
}

/// The document's id in the registry, when the document entity is installed.
fn document_entity_id(state: &EngineState) -> Option<Uuid> {
    state
        .entities
        .load()
        .get(DOCUMENT_ENTITY)
        .map(|m| m.entity_id)
}

async fn require_document(
    state: &EngineState,
    ctx: &SecurityContext,
    document_id: Uuid,
    action: RecordAction,
) -> Result<(), AppError> {
    let entity_id = document_entity_id(state).ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        state,
        ctx,
        entity_id,
        DOCUMENT_ENTITY,
        document_id,
        action,
    )
    .await
}

/// A recording's transcript, for anyone who may read the document.
#[utoipa::path(
    get,
    path = "/api/v1/documents/{id}/transcript",
    tag = "entity",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = TranscriptView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "No such document, not readable, or not transcribed yet", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn get_transcript(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(document_id): Path<Uuid>,
) -> Result<Json<TranscriptView>, AppError> {
    require_document(&state, &ctx, document_id, RecordAction::Read).await?;
    let row: Option<TranscriptRow> =
        sqlx::query_as(
            "SELECT t.content_text, t.language, t.duration_seconds, t.segments, t.model, t.transcribed_at \
               FROM attome_document d JOIN recording_transcript t ON t.file_key = d.file \
              WHERE d.id = $1",
        )
        .bind(document_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let (text, language, duration_seconds, segments, model, transcribed_at) =
        row.ok_or(AppError::NotFound)?;
    Ok(Json(TranscriptView {
        document_id,
        text,
        language,
        duration_seconds,
        segments,
        model,
        transcribed_at,
    }))
}

/// Asks for a recording to be transcribed (again); needs update access to the
/// document. The work runs on the job queue.
#[utoipa::path(
    post,
    path = "/api/v1/documents/{id}/transcribe",
    tag = "entity",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::BusinessEvent, AuditOperation::Update)])))),
    responses(
        (status = 202, description = "Queued"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the document", body = ErrorResponse),
        (status = 404, description = "No such document", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn post_transcribe(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(document_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    require_document(&state, &ctx, document_id, RecordAction::Update).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    enqueue_in_tx(&mut tx, document_id).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        BusinessEvent::new(
            DOCUMENT_ENTITY,
            document_id,
            AuditOperation::Update,
            "document.transcription_requested",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Queues a recording's transcription in the caller's transaction (J6-T3
/// calls this when a call recording lands).
pub async fn enqueue_in_tx(tx: &mut attome_db::Tx<'_>, document_id: Uuid) -> Result<(), AppError> {
    attome_jobs::enqueue_in_tx(
        tx,
        attome_core::jobs::EngineJob::TranscribeRecording { document_id },
    )
    .await
    .map(|_| ())
    .map_err(AppError::internal)
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/documents/{id}/transcript", get(get_transcript))
        .route(
            "/api/v1/documents/{id}/transcribe",
            axum::routing::post(post_transcribe),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_transcript, post_transcribe))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcribe_job_takes_only_audio() {
        assert!(is_audio(Some("audio/mpeg"), "x.bin"));
        assert!(is_audio(None, "call-42.WAV"));
        assert!(is_audio(Some("application/octet-stream"), "voicemail.m4a"));
        assert!(!is_audio(Some("application/pdf"), "contract.pdf"));
        assert!(!is_audio(None, "noextension"));
    }

    #[test]
    fn transcribe_job_keeps_timed_segments() {
        let stored = segments_json(&[
            Segment {
                start: 0.0,
                end: 2.5,
                text: " Hello ".into(),
            },
            Segment {
                start: 2.5,
                end: 4.0,
                text: "مرحبا".into(),
            },
        ]);
        assert_eq!(stored[0]["text"], "Hello");
        assert_eq!(stored[1]["start"], 2.5);
        assert_eq!(stored.as_array().map(Vec::len), Some(2));
    }
}
