//! M57 Phase 1 — `POST /api/v1/docgen/templates/{id}/render` and its worker.
//!
//! Security model (mirrors `attome-report::run`'s D-440 discipline exactly): a
//! render always builds its merge context through
//! `attome_records::entity_crud::read_record` — the exact record-level+field-
//! level security projection every other read path uses — under a
//! `SecurityContext` resolved **fresh from Postgres for the render's
//! `requested_by` user** (`attome_security::resolve_uncached`), never the
//! enqueuing caller's cached context and never a superuser one. The HTTP
//! handler's privilege check only gates "may this caller enqueue a render
//! using this template at all"; the actual record-level/field-level
//! decision is made twice more, independently, by the worker — once via
//! `crate::merge::build_context` for the source record, and once (if
//! `attach_to_field` is set) via `entity_crud::update_record_for` for the
//! attach write. A caller who cannot see a field cannot make it appear in
//! the rendered document by enqueueing a render, because the render itself
//! re-derives what `requested_by` can see at render time, not at
//! enqueue time.
//!
//! `docgen_render` is a migration-owned infrastructure table
//! (`0311_xrm_docgen_render.sql`), not a provisioned entity — see that
//! migration's header comment for why.

use attome_audit::{AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditSource};
use attome_core::EngineState;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::Duration;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::DocgenTemplateRead;

const TEMPLATE_ENTITY: &str = "docgen_template";
const DOWNLOAD_URL_TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Deserialize, ToSchema)]
pub struct RenderTemplateBody {
    pub record_id: Uuid,
}

impl std::fmt::Debug for RenderTemplateBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderTemplateBody").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
struct RenderEnqueueResponse {
    id: Uuid,
    status: String,
}

#[derive(Serialize, ToSchema)]
struct RenderStatusResponse {
    id: Uuid,
    template_ref: Uuid,
    entity: String,
    record_id: Uuid,
    format: String,
    status: String,
    error: Option<String>,
    attached: bool,
    attach_error: Option<String>,
    requested_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    download_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_in_secs: Option<u64>,
}

#[derive(sqlx::FromRow)]
pub(crate) struct RenderRow {
    pub(crate) id: Uuid,
    pub(crate) template_ref: Uuid,
    pub(crate) entity_logicalname: String,
    pub(crate) record_id: Uuid,
    pub(crate) status: String,
    pub(crate) format: String,
    object_key: Option<String>,
    error: Option<String>,
    attached: bool,
    attach_error: Option<String>,
    pub(crate) requested_by: Uuid,
    requested_at: DateTime<Utc>,
}

/// Creates a `pending` `docgen_render` row and enqueues its
/// `EngineJob::DocgenRender`, in one transaction — same insert-and-enqueue
/// atomicity `attome_report::run::create_run` uses. `entity`/`format` are
/// frozen onto the row at enqueue time (the "ledger row is the frozen
/// intent" discipline `ApplySchemaChangePlan`'s doc comment states) — the
/// worker re-reads the template's *current* body/stylesheet/etc, but always
/// renders against the entity/record pair recorded here.
pub(crate) async fn create_render(
    state: &EngineState,
    template_id: Uuid,
    entity: &str,
    format: &str,
    record_id: Uuid,
    requested_by: Uuid,
) -> Result<Uuid, AppError> {
    let render_id = Uuid::now_v7();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO docgen_render \
            (id, template_ref, entity_logicalname, record_id, status, format, requested_by, requested_at) \
         VALUES ($1, $2, $3, $4, 'pending', $5, $6, NOW())",
    )
    .bind(render_id)
    .bind(template_id)
    .bind(entity)
    .bind(record_id)
    .bind(format)
    .bind(requested_by)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_jobs::enqueue_in_tx(
        &mut tx,
        attome_core::jobs::EngineJob::DocgenRender { render_id },
    )
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(render_id)
}

#[utoipa::path(
    post,
    path = "/api/v1/docgen/templates/{id}/render",
    tag = "docgen",
    params(("id" = Uuid, Path)),
    request_body = RenderTemplateBody,
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("EngineJob::DocgenRender"),
        "the route only enqueues a render; the job writes entity+export in the render's completion transaction",
    )))),
    responses(
        (status = 202, description = "Success", body = RenderEnqueueResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such template", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn render_document(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DocgenTemplateRead>>,
    Path(template_id): Path<Uuid>,
    Json(body): Json<RenderTemplateBody>,
) -> Result<(StatusCode, Json<RenderEnqueueResponse>), AppError> {
    // D-766: this work escapes the S2S entity ceiling (it re-resolves the
    // caller later, or reads across entities by role), so a capped caller
    // is refused until the ceiling is carried through.
    ctx.refuse_if_capped()?;
    // Same record-level+field-security projection the generic
    // `GET /api/v1/docgen_template/{id}` applies — a caller who cannot
    // see this template cannot render it either. Also enforces
    // `is_active = true` (the generic read predicate), so a disabled
    // template 404s here exactly like it would through generic CRUD.
    let record =
        attome_records::entity_crud::read_record(&state, &ctx, TEMPLATE_ENTITY, template_id)
            .await?;
    let data = record.data();
    let entity = data
        .get("entity")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::Validation("template has no target entity configured".into()))?
        .to_string();
    let format = data
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("pdf")
        .to_string();
    if format != "pdf" {
        return Err(AppError::Validation(format!(
            "unsupported document format '{format}' — Phase 1 renders pdf only"
        )));
    }

    let render_id = create_render(
        &state,
        template_id,
        &entity,
        &format,
        body.record_id,
        ctx.user_id,
    )
    .await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(RenderEnqueueResponse {
            id: render_id,
            status: "pending".into(),
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/docgen/renders/{render_id}",
    tag = "docgen",
    params(("render_id" = Uuid, Path)),
    responses(
        (status = 200, description = "Success", body = RenderStatusResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such render", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn render_status(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<DocgenTemplateRead>>,
    Path(render_id): Path<Uuid>,
) -> Result<Json<RenderStatusResponse>, AppError> {
    let row = load_render(&state.base.db, render_id)
        .await?
        .ok_or(AppError::NotFound)?;
    // Every render's `requested_by` may see it; anyone else needs
    // `system.admin` — a render holds an actual data extract, same tighter-
    // than-the-template's-own-sharing stance `attome-report::run::run_status`
    // takes for its own runs.
    if row.requested_by != ctx.user_id && !ctx.is_admin {
        return Err(AppError::NotFound);
    }

    let (download_url, expires_in_secs) = if row.status == "completed" {
        if let Some(key) = &row.object_key {
            let url = attome_storage::presign_download(&state.base.storage, key, DOWNLOAD_URL_TTL)
                .await
                .map_err(AppError::internal)?;
            (Some(url), Some(DOWNLOAD_URL_TTL.as_secs()))
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    Ok(Json(RenderStatusResponse {
        id: row.id,
        template_ref: row.template_ref,
        entity: row.entity_logicalname,
        record_id: row.record_id,
        format: row.format,
        status: row.status,
        error: row.error,
        attached: row.attached,
        attach_error: row.attach_error,
        requested_at: row.requested_at,
        download_url,
        expires_in_secs,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/docgen/templates/{id}/render",
            post(render_document),
        )
        .route("/api/v1/docgen/renders/{render_id}", get(render_status))
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document, merged in `lib.rs::openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(render_document, render_status))]
#[derive(Debug)]
pub struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

// ── Worker ────────────────────────────────────────────────────────────────

pub(crate) async fn load_render(
    db: &attome_db::DbPool,
    render_id: Uuid,
) -> Result<Option<RenderRow>, AppError> {
    sqlx::query_as(
        "SELECT id, template_ref, entity_logicalname, record_id, status, format, \
                object_key, error, attached, attach_error, \
                requested_by, requested_at \
         FROM docgen_render WHERE id = $1 AND is_deleted = false",
    )
    .bind(render_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

async fn load_template_fields(
    state: &EngineState,
    security: &SecurityContext,
    template_id: Uuid,
) -> Result<Option<Value>, AppError> {
    match attome_records::entity_crud::read_record(state, security, TEMPLATE_ENTITY, template_id)
        .await
    {
        Ok(record) => Ok(Some(record.data().clone())),
        Err(AppError::NotFound) | Err(AppError::Forbidden) => Ok(None),
        Err(e) => Err(e),
    }
}

async fn mark_running(db: &attome_db::DbPool, render_id: Uuid) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE docgen_render SET status = 'running', started_at = NOW(), updated_at = NOW(), \
            row_version = row_version + 1 WHERE id = $1",
    )
    .bind(render_id)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

async fn mark_failed(state: &EngineState, render_id: Uuid, message: &str) -> Result<(), AppError> {
    tracing::warn!(%render_id, error = %message, "docgen render failed");
    sqlx::query(
        "UPDATE docgen_render SET status = 'failed', error = $2, completed_at = NOW(), \
            updated_at = NOW(), row_version = row_version + 1 WHERE id = $1",
    )
    .bind(render_id)
    .bind(message)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Worker for `EngineJob::DocgenRender`. Re-derives everything from
/// `render_id` rather than a job payload snapshot (same discipline
/// `attome_report::run::process` follows) and re-resolves `requested_by`'s
/// `SecurityContext` directly from Postgres — D-440's property, restated
/// for this crate in `document/decisions/foundation/D-463.md`.
pub async fn process(state: &EngineState, render_id: Uuid) -> Result<(), AppError> {
    let Some(render) = load_render(&state.base.db, render_id).await? else {
        tracing::warn!(%render_id, "docgen render: render not found, dropping job");
        return Ok(());
    };
    if render.status != "pending" {
        // At-least-once redelivery of an already-started render — nothing
        // to do.
        return Ok(());
    }

    let security = attome_security::resolve_uncached(&state.base.db, render.requested_by).await?;
    if security.require(TEMPLATE_ENTITY, "read").is_err() {
        mark_failed(
            state,
            render_id,
            "docgen render authorization was revoked before processing",
        )
        .await?;
        return Ok(());
    }

    let Some(template) = load_template_fields(state, &security, render.template_ref).await? else {
        mark_failed(
            state,
            render_id,
            "template not found, inactive, or no longer visible",
        )
        .await?;
        return Ok(());
    };

    let Some(body) = template.get("body").and_then(Value::as_str) else {
        mark_failed(
            state,
            render_id,
            "template body is empty or not visible to the requesting user",
        )
        .await?;
        return Ok(());
    };
    let stylesheet = template
        .get("stylesheet")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let page_size = template
        .get("page_size")
        .and_then(Value::as_str)
        .unwrap_or("A4");
    let margin_mm = template.get("margin_mm").and_then(Value::as_f64);
    let attach_to_field = template
        .get("attach_to_field")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let template_name = template
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("document")
        .to_string();

    // The security-critical step: builds the merge context under `security`
    // (requested_by's freshly-resolved permissions), which is what makes a
    // hidden field render empty — see crate::merge's doc comment.
    let merge_ctx = match crate::merge::build_context(
        state,
        &security,
        &render.entity_logicalname,
        render.record_id,
    )
    .await
    {
        Ok(ctx) => ctx,
        Err(AppError::NotFound) => {
            mark_failed(state, render_id, "source record not found or not visible").await?;
            return Ok(());
        }
        Err(e) => {
            mark_failed(
                state,
                render_id,
                &format!("failed to build merge context: {e}"),
            )
            .await?;
            return Ok(());
        }
    };

    let merged_body = match crate::merge::render_template(body, &merge_ctx) {
        Ok(html) => html,
        Err(e) => {
            mark_failed(state, render_id, &format!("template render failed: {e}")).await?;
            return Ok(());
        }
    };

    let escaped_stylesheet = stylesheet.replace("</style>", "&lt;/style&gt;");
    let full_html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><style>{escaped_stylesheet}</style></head><body>{merged_body}</body></html>"
    );

    if full_html.len() > state.base.config.docgen.max_html_bytes {
        mark_failed(
            state,
            render_id,
            &format!(
                "rendered HTML exceeds the {}-byte cap",
                state.base.config.docgen.max_html_bytes
            ),
        )
        .await?;
        return Ok(());
    }

    // SSRF-shaped guard on the FINAL merged HTML — see crate::ssrf's doc
    // comment for why this runs after substitution, not on the raw body.
    if let Err(e) = crate::ssrf::guard(&full_html) {
        mark_failed(state, render_id, &e.to_string()).await?;
        return Ok(());
    }

    mark_running(&state.base.db, render_id).await?;

    let bytes = match crate::render_client::render_pdf(
        &state.base.config.docgen,
        &full_html,
        page_size,
        margin_mm,
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            mark_failed(state, render_id, &format!("render failed: {e}")).await?;
            return Ok(());
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let checksum = hex::encode(hasher.finalize());
    let size_bytes = bytes.len() as i64;

    let object_key = format!("docgen-renders/{}/{render_id}.pdf", render.template_ref);
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid docgen render object key: {e}")))?;
    if let Err(e) = state.base.storage.store().put(&path, bytes.into()).await {
        mark_failed(state, render_id, &format!("upload failed: {e}")).await?;
        return Ok(());
    }

    // D-062 / audit plan 3.6: the `completed` transition (which is what makes
    // the document downloadable) and its Entity+Export audit event commit in
    // one transaction, opened only after the render call and the upload
    // (no external I/O inside it). A failed audit write rolls the transition
    // back; the retry story is on the error branch below.
    let (user_ctx, org_ref) = attome_audit::fetch_audit_ctx(state, render.requested_by).await;
    let event = AuditEvent {
        organization_ref: org_ref,
        category: AuditCategory::Entity,
        entity_name: Some(render.entity_logicalname.clone()),
        record_id: Some(render.record_id),
        operation: AuditOperation::Export,
        version_before: None,
        version_after: None,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::BackgroundJob,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: Some(render_id),
        event_name: None,
        event_comment: Some(format!(
            "document generated from template {} ({} bytes)",
            render.template_ref, size_bytes
        )),
        changed_fields: vec![],
        snapshot_json: None,
    };

    if let Err(e) =
        complete_render(state, render_id, &object_key, &checksum, size_bytes, event).await
    {
        // The rolled-back transition leaves the row `running`, and this
        // job's own guard (`status != "pending"` → no-op) means a queue
        // retry would never finish it — so record the failure durably
        // (no download URL is ever offered for a non-`completed` row) and
        // still return the error so the job run is visibly failed. The
        // requester re-renders; nothing was delivered without evidence.
        mark_failed(
            state,
            render_id,
            &format!("completion could not be recorded: {e}"),
        )
        .await?;
        return Err(e);
    }

    // Runs only after the completion + audit commit, so a record never gets
    // a generated document attached for a render that has no audit evidence.
    // It has its own transaction and its own audit trail (update_record_for).
    if let Some(field) = attach_to_field {
        attach_generated_file(
            state,
            &security,
            render_id,
            &render.entity_logicalname,
            render.record_id,
            &field,
            &object_key,
            &checksum,
            size_bytes,
            &template_name,
            render.requested_by,
        )
        .await;
    }

    Ok(())
}

/// Moves a render to `completed` and writes its audit event in one
/// transaction (D-062): either both commit or neither does.
async fn complete_render(
    state: &EngineState,
    render_id: Uuid,
    object_key: &str,
    checksum: &str,
    size_bytes: i64,
    event: AuditEvent,
) -> Result<(), AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "UPDATE docgen_render \
            SET status = 'completed', object_key = $2, checksum = $3, size_bytes = $4, \
                completed_at = NOW(), \
                duration_ms = GREATEST(0, EXTRACT(EPOCH FROM (NOW() - started_at)) * 1000)::bigint, \
                updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(render_id)
    .bind(object_key)
    .bind(checksum)
    .bind(size_bytes)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::audit_service(state)
        .write_in_tx(&mut tx, event)
        .await?;
    attome_db::tx::commit(tx).await
}

/// Best-effort M55 file-version attach — never fails the render itself: the
/// document is already generated and downloadable regardless of whether
/// this succeeds. Reuses the exact write primitive every other field write
/// uses (`entity_crud::update_record_for`, guidelines §9), fed by a
/// synthetic, already-`clean` `upload_session` row — the same
/// mechanism `finalize_upload_session`/`files_scan::process` create for a
/// real user upload, minted here directly since a server-generated document
/// never goes through the quarantine/scan pipeline a client-supplied upload
/// does (there is no untrusted client byte stream to scan; the bytes came
/// out of the render sidecar under this crate's own control).
#[allow(clippy::too_many_arguments)]
async fn attach_generated_file(
    state: &EngineState,
    security: &SecurityContext,
    render_id: Uuid,
    entity: &str,
    record_id: Uuid,
    field: &str,
    object_key: &str,
    checksum: &str,
    size_bytes: i64,
    template_name: &str,
    requested_by: Uuid,
) {
    if let Err(e) = try_attach_generated_file(
        state,
        security,
        entity,
        record_id,
        field,
        object_key,
        checksum,
        size_bytes,
        template_name,
        requested_by,
    )
    .await
    {
        let message = e.to_string();
        tracing::warn!(%render_id, entity, field, error = %message, "docgen: attach_to_field failed");
        let _ = sqlx::query(
            "UPDATE docgen_render SET attach_error = $2, updated_at = NOW(), \
                row_version = row_version + 1 WHERE id = $1",
        )
        .bind(render_id)
        .bind(&message)
        .execute(&state.base.db)
        .await;
        return;
    }

    let _ = sqlx::query(
        "UPDATE docgen_render SET attached = TRUE, updated_at = NOW(), \
            row_version = row_version + 1 WHERE id = $1",
    )
    .bind(render_id)
    .execute(&state.base.db)
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn try_attach_generated_file(
    state: &EngineState,
    security: &SecurityContext,
    entity: &str,
    record_id: Uuid,
    field: &str,
    object_key: &str,
    checksum: &str,
    size_bytes: i64,
    template_name: &str,
    requested_by: Uuid,
) -> Result<(), AppError> {
    security.require(entity, "update")?;

    let registry = state.entities.load();
    let is_file_field = registry
        .get(entity)
        .and_then(|meta| meta.attrs.iter().find(|a| a.logicalname == field))
        .map(|attr| matches!(attr.field_type_int, 12 | 13))
        .unwrap_or(false);
    if !is_file_field {
        return Err(AppError::Validation(format!(
            "attach_to_field '{field}' is not a file-type field on '{entity}'"
        )));
    }

    let before =
        attome_records::entity_crud::read_record(state, security, entity, record_id).await?;
    let expected_row_version = before.row_version();

    // Owner decision 3 (CLEANUP-REVIEW batch 1): the field gets its own copy
    // of the PDF under the field's canonical key. The render's own object
    // (`docgen-renders/...`) stays where it is for the render-status
    // download; a key outside `{entity}/{record_id}/{field}/` would be
    // refused by the field's download path and skipped by compliance
    // archiving. The copy happens before any database write, so a failed
    // copy leaves no session row and no field value behind; a failed write
    // after it removes the copy again (below).
    let session_id = Uuid::now_v7();
    let (filename, field_key) =
        attached_file_key(entity, record_id, field, session_id, template_name);
    let src = ObjectPath::parse(object_key)
        .map_err(|e| AppError::internal(format!("invalid docgen render object key: {e}")))?;
    let dest = ObjectPath::parse(&field_key)
        .map_err(|e| AppError::internal(format!("invalid attached file key: {e}")))?;
    state
        .base
        .storage
        .store()
        .copy(&src, &dest)
        .await
        .map_err(|e| {
            AppError::internal(format!("copying the rendered PDF to the field failed: {e}"))
        })?;

    let recorded = async {
        // attome-document owns the upload-session state machine; a rendered PDF
        // enters it already `clean` (CLEANUP-REVIEW 2.10).
        attome_document::files::record_generated_clean_file(
            state,
            attome_document::files::GeneratedCleanFile {
                session_id,
                entity,
                record_id,
                field,
                owner: attome_document::files::FileOwner::Staff(requested_by),
                object_key: &field_key,
                filename: &filename,
                content_type: "application/pdf",
                size_bytes,
                checksum_sha256: checksum,
            },
        )
        .await?;

        attome_records::entity_crud::update_record_for(
            state,
            security,
            requested_by,
            entity,
            record_id,
            expected_row_version,
            serde_json::json!({ field: field_key }),
        )
        .await
    }
    .await;

    if let Err(e) = recorded {
        // The field never got the key, so its copy is unreferenced: remove it
        // (best effort; the caller records the attach error either way).
        if let Err(delete_err) = state.base.storage.store().delete(&dest).await {
            tracing::warn!(
                key = %field_key,
                error = %delete_err,
                "docgen: could not remove the copy of a failed attach"
            );
        }
        return Err(e);
    }

    Ok(())
}

/// The filename and object key an attached render is stored under: the
/// field's canonical upload key (`attome_document::files::final_key`), never the
/// render's own `docgen-renders/...` key. Returns `(filename, key)`.
fn attached_file_key(
    entity: &str,
    record_id: Uuid,
    field: &str,
    session_id: Uuid,
    template_name: &str,
) -> (String, String) {
    let filename = format!("{template_name}.pdf");
    let key = attome_document::files::final_key(entity, record_id, field, session_id, &filename);
    (filename, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Owner decision 3: an attached render is recorded under the field's own
    /// key — the one the field's download path and compliance archiving
    /// accept — not the render's `docgen-renders/...` key.
    #[test]
    fn attached_file_key_is_the_fields_canonical_key() {
        let record_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        let (filename, key) = attached_file_key(
            "core_contact",
            record_id,
            "contract",
            session_id,
            "Offer letter",
        );
        assert_eq!(filename, "Offer letter.pdf");
        assert_eq!(
            key,
            format!("core_contact/{record_id}/contract/{session_id}-Offer_letter.pdf")
        );
        assert!(!key.starts_with("docgen-renders/"), "{key}");
        assert!(
            attome_document::files::is_owned_file_key("core_contact", record_id, "contract", &key),
            "{key} must be owned by the field it is attached to"
        );
        assert!(
            !attome_document::files::is_owned_file_key("core_contact", record_id, "other", &key),
            "{key} must not pass as another field's file"
        );
    }

    /// A template name cannot steer the key out of the field's prefix.
    #[test]
    fn attached_file_key_neutralises_path_characters_in_the_template_name() {
        let record_id = Uuid::now_v7();
        let (_, key) = attached_file_key(
            "core_contact",
            record_id,
            "contract",
            Uuid::now_v7(),
            "../../x/y",
        );
        assert!(
            attome_document::files::is_owned_file_key("core_contact", record_id, "contract", &key),
            "{key}"
        );
        assert!(!key.contains(".."), "{key}");
        assert_eq!(key.matches('/').count(), 3, "{key}");
    }
}
