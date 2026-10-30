//! Q14-T5: bulk reassign and bulk share, as a background batch job with a
//! preview and progress.
//!
//! `POST /api/v1/admin/security/record-shares/bulk` names an operation
//! (`reassign` to a new owner, or `share` with a principal), an entity, and
//! the records: an explicit list of ids, or every live record one user owns.
//! With `preview: true` it answers how many records match and the first 50,
//! and changes nothing. Otherwise it starts a batch ([`attome_jobs::batch`])
//! and enqueues the job that runs it, in one transaction, and answers `202`
//! with the batch id; progress and cancel are `GET /api/v1/jobs/{id}` and
//! `POST /api/v1/jobs/{id}/cancel`.
//!
//! The job reads the records by keyset on `id`, 500 at a time. Each chunk's
//! writes, its checkpoint and one security event naming the chunk's record
//! ids commit together, so a worker that dies mid-job redoes at most one
//! chunk and never writes an event for a chunk that did not land. A reassign
//! is the single-record reassign ([`super::shares::reassign_owner_for`]) for
//! many: the owner columns change and the new owner gets an `action` share.
//! A share is the same upsert the share route makes.

use attome_audit::AuditOperation;
use attome_audit::security::{
    ExemptReason, MandatoryCategory, SecurityAuditor, SecurityEvent, write_security_event,
    x_audit_exempt,
};
use attome_core::EngineState;
use attome_jobs::registry::BoxError;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

/// The registered job type's name (`crates/apps/attome/src/jobs.rs`).
pub const BULK_ACCESS_JOB: &str = "security_bulk_access";

/// Records one chunk changes, in one transaction with one security event.
const CHUNK: i64 = 500;

/// Records a preview lists.
const PREVIEW: i64 = 50;

/// The longest explicit id list one request may name; a larger set is
/// selected by owner instead, so the job payload stays small.
const MAX_IDS: usize = 10_000;

/// Which records a bulk operation covers: exactly one of the two.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct RecordSelection {
    /// These records (at most 10,000).
    #[serde(default)]
    pub record_ids: Option<Vec<Uuid>>,
    /// Every live record owned by the user with this email.
    #[serde(default)]
    pub owner_email: Option<String>,
}

/// What to do to the selected records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BulkOperation {
    /// Make the user or team the owner, with an `action` share.
    Reassign,
    /// Share with the user or team at `capability`.
    Share,
}

#[derive(Deserialize, ToSchema)]
pub(super) struct BulkAccessBody {
    operation: BulkOperation,
    entity: String,
    records: RecordSelection,
    /// The new owner or the share's principal: a user by email ...
    #[serde(default)]
    user_email: Option<String>,
    /// ... or a team by name (exactly one of the two).
    #[serde(default)]
    team_name: Option<String>,
    /// For `share`: `view`, `action` or `deny`. Ignored for `reassign`.
    #[serde(default)]
    capability: Option<String>,
    /// `true`: answer the count and the first 50 records, change nothing.
    #[serde(default)]
    preview: bool,
}

#[derive(Serialize, ToSchema)]
pub(super) struct BulkAccessPreview {
    /// Live records the operation would change.
    count: i64,
    /// The first 50 of them, by id.
    record_ids: Vec<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub(super) struct BulkAccessStarted {
    /// The batch: `GET /api/v1/jobs/{job_id}` for progress.
    job_id: Uuid,
    total: i64,
    /// The first 50 records, as the preview shows them.
    record_ids: Vec<Uuid>,
}

/// The records, resolved to what SQL filters on.
#[derive(Debug, Clone, Deserialize, Serialize)]
enum Selected {
    Ids(Vec<Uuid>),
    OwnedBy(Uuid),
}

/// The job's payload: everything resolved and checked when it was started.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BulkAccessPayload {
    batch_id: Uuid,
    actor: Uuid,
    operation: BulkOperation,
    /// `entity_info.logicalname`, read from the database, never the request.
    entity: String,
    entity_ref: Uuid,
    selected: Selected,
    principal_type: i16,
    principal_id: Uuid,
    /// The share capability (`action` for a reassign).
    capability: i16,
}

/// Up to `limit` live selected record ids after `after`, by id.
async fn select_ids<'c, E: sqlx::PgExecutor<'c>>(
    db: E,
    entity: &str,
    selected: &Selected,
    after: Uuid,
    limit: i64,
) -> Result<Vec<Uuid>, sqlx::Error> {
    // `entity` is `entity_info.logicalname` as stored; quoted all the same.
    match selected {
        Selected::Ids(ids) => {
            sqlx::query_scalar(&format!(
                "SELECT id FROM {table} WHERE is_active = true AND id = ANY($1) AND id > $2 \
                 ORDER BY id LIMIT $3",
                table = attome_core::quote_ident(entity)
            ))
            .bind(ids)
            .bind(after)
            .bind(limit)
            .fetch_all(db)
            .await
        }
        Selected::OwnedBy(owner) => {
            sqlx::query_scalar(&format!(
                "SELECT id FROM {table} WHERE is_active = true AND owner_ref = $1 AND id > $2 \
                 ORDER BY id LIMIT $3",
                table = attome_core::quote_ident(entity)
            ))
            .bind(owner)
            .bind(after)
            .bind(limit)
            .fetch_all(db)
            .await
        }
    }
}

async fn count_selected(
    db: &attome_db::DbPool,
    entity: &str,
    selected: &Selected,
) -> Result<i64, sqlx::Error> {
    match selected {
        Selected::Ids(ids) => {
            sqlx::query_scalar(&format!(
                "SELECT count(*) FROM {table} WHERE is_active = true AND id = ANY($1)",
                table = attome_core::quote_ident(entity)
            ))
            .bind(ids)
            .fetch_one(db)
            .await
        }
        Selected::OwnedBy(owner) => {
            sqlx::query_scalar(&format!(
                "SELECT count(*) FROM {table} WHERE is_active = true AND owner_ref = $1",
                table = attome_core::quote_ident(entity)
            ))
            .bind(owner)
            .fetch_one(db)
            .await
        }
    }
}

async fn resolve_selection(
    db: &attome_db::DbPool,
    records: &RecordSelection,
) -> Result<Selected, AppError> {
    match (&records.record_ids, records.owner_email.as_deref()) {
        (Some(ids), None) => {
            if ids.is_empty() {
                return Err(AppError::Validation("records.record_ids is empty".into()));
            }
            if ids.len() > MAX_IDS {
                return Err(AppError::Validation(format!(
                    "records.record_ids names {} records; at most {MAX_IDS}, or select by \
                     records.owner_email",
                    ids.len()
                )));
            }
            Ok(Selected::Ids(ids.clone()))
        }
        (None, Some(email)) => {
            let (_, owner) = super::shares::resolve_principal(db, Some(email), None).await?;
            Ok(Selected::OwnedBy(owner))
        }
        _ => Err(AppError::Validation(
            "records names exactly one of record_ids or owner_email".into(),
        )),
    }
}

/// Bulk reassign or share, previewed or started as a background job.
///
/// Q14-T5: with `preview` the count and first 50 records; otherwise a batch
/// job that works 500 records at a time, each chunk with its own security
/// event naming its records. Progress at `GET /api/v1/jobs/{job_id}`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/record-shares/bulk",
    tag = "admin-security",
    request_body = BulkAccessBody,
    extensions(("x-audit-exempt" = json!(x_audit_exempt(
        ExemptReason::Delegated,
        Some("security_bulk_access job"),
        "a preview writes nothing; a start only queues the batch, and the job writes one Access/OwnerChange or Access/Grant event per chunk of 500 with the chunk's record ids",
    )))),
    responses(
        (status = 200, description = "Preview: the count and the first 50 records", body = BulkAccessPreview),
        (status = 202, description = "Started: the batch to follow", body = BulkAccessStarted),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn bulk_access(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Roles>>,
    Json(body): Json<BulkAccessBody>,
) -> Result<Response, AppError> {
    let db = &state.base.db;
    let (entity_ref, entity) = super::shared::resolve_entity_ref_and_name(db, &body.entity).await?;
    let (principal_type, principal_id) =
        super::shares::resolve_principal(db, body.user_email.as_deref(), body.team_name.as_deref())
            .await?;
    let capability = match body.operation {
        BulkOperation::Reassign => 1,
        BulkOperation::Share => {
            super::shares::capability_to_i16(body.capability.as_deref().ok_or_else(|| {
                AppError::Validation("capability is required for a share".into())
            })?)?
        }
    };
    let selected = resolve_selection(db, &body.records).await?;
    let count = count_selected(db, &entity, &selected)
        .await
        .map_err(AppError::internal)?;
    let first = select_ids(db, &entity, &selected, Uuid::nil(), PREVIEW)
        .await
        .map_err(AppError::internal)?;
    if body.preview {
        return Ok(Json(BulkAccessPreview {
            count,
            record_ids: first,
        })
        .into_response());
    }

    let mut tx = attome_db::tx::begin(db).await?;
    let batch_id =
        attome_jobs::batch::start(&mut tx, BULK_ACCESS_JOB, Some(count), Some(ctx.user_id))
            .await
            .map_err(AppError::internal)?;
    let payload = BulkAccessPayload {
        batch_id,
        actor: ctx.user_id,
        operation: body.operation,
        entity,
        entity_ref,
        selected,
        principal_type,
        principal_id,
        capability,
    };
    let job = attome_core::jobs::JOB_TYPES
        .job(BULK_ACCESS_JOB, &payload)
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(BulkAccessStarted {
            job_id: batch_id,
            total: count,
            record_ids: first,
        }),
    )
        .into_response())
}

struct BulkAccessBatch {
    db: attome_db::DbPool,
    auditor: SecurityAuditor,
    payload: BulkAccessPayload,
}

impl attome_jobs::batch::BatchJob for BulkAccessBatch {
    type Chunk = Vec<Uuid>;

    async fn next_chunk(
        &self,
        checkpoint: Option<&Value>,
    ) -> Result<Option<(Self::Chunk, Value)>, BoxError> {
        let after = checkpoint
            .and_then(|c| c["after"].as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_else(Uuid::nil);
        let ids = select_ids(
            &self.db,
            &self.payload.entity,
            &self.payload.selected,
            after,
            CHUNK,
        )
        .await?;
        Ok(ids
            .last()
            .copied()
            .map(|last| (ids, json!({ "after": last }))))
    }

    async fn process(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ids: Self::Chunk,
    ) -> Result<i64, BoxError> {
        let p = &self.payload;
        let changed: Vec<Uuid> = match p.operation {
            BulkOperation::Reassign => {
                sqlx::query_scalar(&format!(
                    "UPDATE {table} \
                     SET owner_ref = $1, owner_type = $2, modified_by = $3, modified_at = NOW(), \
                         row_version = row_version + 1 \
                     WHERE id = ANY($4) AND is_active = true RETURNING id",
                    table = attome_core::quote_ident(&p.entity)
                ))
                .bind(p.principal_id)
                .bind(p.principal_type)
                .bind(p.actor)
                .bind(&ids)
                .fetch_all(&mut **tx)
                .await?
            }
            BulkOperation::Share => {
                sqlx::query_scalar(&format!(
                    "SELECT id FROM {table} WHERE id = ANY($1) AND is_active = true",
                    table = attome_core::quote_ident(&p.entity)
                ))
                .bind(&ids)
                .fetch_all(&mut **tx)
                .await?
            }
        };
        if changed.is_empty() {
            return Ok(0);
        }
        // The same upsert as a single share or reassign: refreshing
        // `granted_by` when the share is already there.
        sqlx::query(
            "INSERT INTO record_share \
                (record_id, entity_ref, principal_type, principal_id, capability, granted_by) \
             SELECT unnest($1::uuid[]), $2, $3, $4, $5, $6 \
             ON CONFLICT (record_id, entity_ref, principal_type, principal_id, capability) \
             DO UPDATE SET granted_by = EXCLUDED.granted_by",
        )
        .bind(&changed)
        .bind(p.entity_ref)
        .bind(p.principal_type)
        .bind(p.principal_id)
        .bind(p.capability)
        .bind(p.actor)
        .execute(&mut **tx)
        .await?;
        let operation = match p.operation {
            BulkOperation::Reassign => AuditOperation::OwnerChange,
            BulkOperation::Share => AuditOperation::Grant,
        };
        let ids_text: Vec<String> = changed.iter().map(Uuid::to_string).collect();
        let event = SecurityEvent::new(
            MandatoryCategory::Access,
            operation,
            p.actor,
            &p.entity,
            None,
        )
        .named("security.bulk_access")
        .occurrence_count(i32::try_from(changed.len()).unwrap_or(i32::MAX))
        .comment(format!(
            "bulk {} batch {}: {} records: {}",
            match p.operation {
                BulkOperation::Reassign => "reassign",
                BulkOperation::Share => "share",
            },
            p.batch_id,
            changed.len(),
            ids_text.join(",")
        ));
        write_security_event(tx, &self.auditor.service(), event)
            .await
            .map_err(|e| Box::new(e) as BoxError)?;
        Ok(i64::try_from(changed.len()).unwrap_or(i64::MAX))
    }
}

/// Runs a bulk reassign or share batch from its last checkpoint (the
/// registered job's handler). Safe to repeat: a finished batch does nothing,
/// and a chunk that did not commit is redone whole.
pub async fn run_bulk_access(
    state: &EngineState,
    payload: BulkAccessPayload,
) -> Result<(), BoxError> {
    let principal = (payload.principal_type, payload.principal_id);
    let batch_id = payload.batch_id;
    let job = BulkAccessBatch {
        db: state.base.db.clone(),
        auditor: SecurityAuditor::from_state(state),
        payload,
    };
    attome_jobs::batch::run(&state.base.db, batch_id, &job).await?;
    // Outside every transaction: only a user principal holds a cached
    // security context that names its shares.
    if principal.0 == 0 {
        state
            .base
            .security
            .invalidate_sync(principal.1)
            .await
            .map_err(|e| Box::new(e) as BoxError)?;
    }
    Ok(())
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/admin/security/record-shares/bulk",
        post(bulk_access),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(bulk_access),
    components(schemas(
        BulkAccessBody,
        BulkAccessPreview,
        BulkAccessStarted,
        BulkOperation,
        RecordSelection
    ))
)]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
