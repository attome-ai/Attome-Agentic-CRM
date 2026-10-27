//! K7-T1: records management: categories, declarations and dispositions.
//!
//! - **Categories** (`records_category`) name a kind of record and how long
//!   it is kept (`retention_days`).
//! - **Declaring** a record under a category makes it immutable: the generic
//!   update, delete, hard delete and restore refuse it with `409`
//!   (`attome_records::entity_crud::declared`). Erasure (R2) still applies,
//!   and refuses a record under a legal hold (R4) as it always does.
//! - **Disposition** destroys a declared record once its keeping is over. One
//!   person requests it; another approves or rejects it (the requester
//!   cannot decide their own request). Approval refuses a record under a
//!   legal hold, purges it the way retention does (key destroyed, values
//!   scrubbed, Security/Erasure audit event) and stores a certificate: what
//!   was disposed, under which category, who asked, who approved and when,
//!   with its SHA-256.
//!
//! Every route is an administrator's. Categories and declarations write a
//! Configuration security event in their own transaction.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::{EngineState, quote_ident};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most categories listed.
const MAX_CATEGORIES: i64 = 500;

/// A records category.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[schema(as = RecordsCategory)]
pub struct Category {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// How long a record of this category is kept, in days.
    pub retention_days: Option<i32>,
    pub created_at: DateTime<Utc>,
}

/// A new records category.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = RecordsCategoryBody)]
pub struct CategoryBody {
    pub name: String,
    pub description: Option<String>,
    pub retention_days: Option<i32>,
}

/// A record to declare.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = RecordDeclarationBody)]
pub struct DeclarationBody {
    pub entity: String,
    pub record_id: Uuid,
    pub category_id: Uuid,
}

/// A declared record.
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = RecordDeclared)]
pub struct Declared {
    pub entity: String,
    pub record_id: Uuid,
    pub category_id: Uuid,
    pub declared_at: DateTime<Utc>,
}

/// A record whose disposition is asked for.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = RecordDispositionBody)]
pub struct DispositionBody {
    pub entity: String,
    pub record_id: Uuid,
}

/// A disposition decision.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = RecordDispositionDecision)]
pub struct DecisionBody {
    /// `approve` or `reject`.
    pub decision: String,
    pub reason: Option<String>,
}

/// A disposition request.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
#[schema(as = RecordDisposition)]
pub struct Disposition {
    pub id: Uuid,
    pub entity: String,
    pub record_id: Uuid,
    pub category_ref: Uuid,
    pub requested_by: Uuid,
    pub requested_at: DateTime<Utc>,
    /// `pending`, `approved` or `rejected`.
    pub status: String,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub reason: Option<String>,
    /// What was disposed, under which category, by whom and when.
    #[schema(value_type = Option<Object>)]
    pub certificate: Option<Value>,
    pub certificate_sha256: Option<String>,
}

const DISPOSITION_COLUMNS: &str = "id, entity, record_id, category_ref, requested_by, \
    requested_at, status, reviewed_by, reviewed_at, reason, certificate, certificate_sha256";

/// A disposition certificate and its SHA-256 (over its canonical JSON text).
/// Pure.
pub fn certificate(
    disposition: &Disposition,
    category: &str,
    reviewer: Uuid,
    at: DateTime<Utc>,
) -> (Value, String) {
    let cert = json!({
        "format": "attome-disposition-certificate/v1",
        "disposition_id": disposition.id,
        "entity": disposition.entity,
        "record_id": disposition.record_id,
        "category": category,
        "requested_by": disposition.requested_by,
        "requested_at": disposition.requested_at,
        "approved_by": reviewer,
        "disposed_at": at,
        "method": "key destroyed and values scrubbed",
    });
    let digest = hex::encode(Sha256::digest(cert.to_string().as_bytes()));
    (cert, digest)
}

fn checked_name(name: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 200 {
        return Err(AppError::Validation(
            "a category has a name of up to 200 characters".into(),
        ));
    }
    Ok(name.to_owned())
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/records/categories",
    operation_id = "records_category_create",
    tag = "admin",
    request_body = CategoryBody,
    responses(
        (status = 201, description = "The category", body = Category),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 409, description = "A category of that name exists", body = ErrorResponse),
        (status = 422, description = "No name, or a retention that is not positive", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
)]
/// Creates a records category.
///
/// A category names a kind of record and how long it is kept; records are
/// declared under one.
async fn create_category(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Json(body): Json<CategoryBody>,
) -> Result<(StatusCode, Json<Category>), AppError> {
    let name = checked_name(&body.name)?;
    if body.retention_days.is_some_and(|d| d <= 0) {
        return Err(AppError::Validation("retention_days is positive".into()));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let created: Option<Category> = sqlx::query_as(
        "INSERT INTO records_category (name, description, retention_days, created_by) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (name) DO NOTHING \
         RETURNING id, name, description, retention_days, created_at",
    )
    .bind(&name)
    .bind(
        body.description
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty()),
    )
    .bind(body.retention_days)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let created = created.ok_or(AppError::Conflict("a category of that name exists"))?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "records_category",
            Some(created.id),
        )
        .named("records.category_created")
        .comment(format!("records category {name}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/records/categories",
    operation_id = "records_category_list",
    tag = "admin",
    responses(
        (status = 200, description = "Every category, by name", body = PaginatedResponse<Category>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
/// Lists the records categories.
///
/// Every category in one page, by name.
async fn list_categories(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
) -> Result<Json<PaginatedResponse<Category>>, AppError> {
    let items: Vec<Category> = sqlx::query_as(
        "SELECT id, name, description, retention_days, created_at FROM records_category \
          ORDER BY name LIMIT $1",
    )
    .bind(MAX_CATEGORIES)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        1,
        MAX_CATEGORIES,
    )))
}

/// The record exists and is live.
async fn require_record(
    state: &EngineState,
    entity: &str,
    record_id: Uuid,
) -> Result<(), AppError> {
    if state.entities.load().get(entity).is_none() {
        return Err(AppError::NotFound);
    }
    let live: bool = sqlx::query_scalar(&format!(
        "SELECT EXISTS (SELECT 1 FROM {} WHERE id = $1 AND is_active)",
        quote_ident(entity)
    ))
    .bind(record_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if live {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/records/declarations",
    operation_id = "records_declare",
    tag = "admin",
    request_body = DeclarationBody,
    responses(
        (status = 201, description = "The record is declared and immutable", body = Declared),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 404, description = "No such entity, record or category", body = ErrorResponse),
        (status = 409, description = "The record is already declared", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
)]
/// Declares a record under a records category.
///
/// From then on the generic write path refuses the record's updates,
/// deletes and restores; it leaves only by erasure or an approved
/// disposition.
async fn declare(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Json(body): Json<DeclarationBody>,
) -> Result<(StatusCode, Json<Declared>), AppError> {
    require_record(&state, &body.entity, body.record_id).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let category: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM records_category WHERE id = $1)")
            .bind(body.category_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if !category {
        return Err(AppError::NotFound);
    }
    let declared_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "INSERT INTO record_declaration (entity, record_id, category_ref, declared_by) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (entity, record_id) DO NOTHING \
         RETURNING declared_at",
    )
    .bind(&body.entity)
    .bind(body.record_id)
    .bind(body.category_id)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let declared_at = declared_at.ok_or(AppError::Conflict("the record is already declared"))?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            &body.entity,
            Some(body.record_id),
        )
        .named("records.declared")
        .comment(format!("declared under category {}", body.category_id)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(Declared {
            entity: body.entity,
            record_id: body.record_id,
            category_id: body.category_id,
            declared_at,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/records/dispositions",
    operation_id = "records_disposition_request",
    tag = "admin",
    request_body = DispositionBody,
    responses(
        (status = 201, description = "The pending request; another administrator decides it", body = Disposition),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator", body = ErrorResponse),
        (status = 404, description = "The record is not declared", body = ErrorResponse),
        (status = 409, description = "A disposition of the record is already pending", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
)]
/// Asks for a declared record's disposition.
///
/// The request waits for a second administrator; nothing is destroyed until
/// it is approved.
async fn request_disposition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Json(body): Json<DispositionBody>,
) -> Result<(StatusCode, Json<Disposition>), AppError> {
    let category: Option<Uuid> = sqlx::query_scalar(
        "SELECT category_ref FROM record_declaration \
          WHERE entity = $1 AND record_id = $2 AND disposed_at IS NULL",
    )
    .bind(&body.entity)
    .bind(body.record_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let category = category.ok_or(AppError::NotFound)?;
    let created: Option<Disposition> = sqlx::query_as(&format!(
        "INSERT INTO record_disposition (entity, record_id, category_ref, requested_by) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (entity, record_id) WHERE status = 'pending' \
         DO NOTHING RETURNING {DISPOSITION_COLUMNS}"
    ))
    .bind(&body.entity)
    .bind(body.record_id)
    .bind(category)
    .bind(ctx.user_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let created = created.ok_or(AppError::Conflict(
        "a disposition of the record is already pending",
    ))?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/records/dispositions/{id}/decide",
    operation_id = "records_disposition_decide",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The disposition request")),
    request_body = DecisionBody,
    responses(
        (status = 200, description = "Decided; an approval carries the certificate", body = Disposition),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not an administrator, or the request's own requester", body = ErrorResponse),
        (status = 404, description = "No such request", body = ErrorResponse),
        (status = 409, description = "Already decided, or the record is under a legal hold", body = ErrorResponse),
        (status = 422, description = "The decision is neither approve nor reject", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Erasure)])))),
)]
/// Approves or rejects a disposition request.
///
/// The requester cannot decide their own request. Approval refuses a record
/// under a legal hold; otherwise it purges the record (key destroyed, values
/// scrubbed, audited) and stores the disposition certificate with its
/// SHA-256.
async fn decide_disposition(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
    Json(body): Json<DecisionBody>,
) -> Result<Json<Disposition>, AppError> {
    let approve = match body.decision.trim() {
        "approve" => true,
        "reject" => false,
        _ => {
            return Err(AppError::Validation("decision is approve or reject".into()));
        }
    };
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| r.chars().take(1_000).collect::<String>());
    let db = &state.base.db;
    let request: Disposition = sqlx::query_as(&format!(
        "SELECT {DISPOSITION_COLUMNS} FROM record_disposition WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;
    if request.requested_by == ctx.user_id {
        return Err(AppError::Forbidden);
    }
    if request.status != "pending" {
        return Err(AppError::Conflict("the disposition was already decided"));
    }
    if !approve {
        let decided: Option<Disposition> = sqlx::query_as(&format!(
            "UPDATE record_disposition SET status = 'rejected', reviewed_by = $2, \
                    reviewed_at = now(), reason = $3 \
              WHERE id = $1 AND status = 'pending' RETURNING {DISPOSITION_COLUMNS}"
        ))
        .bind(id)
        .bind(ctx.user_id)
        .bind(&reason)
        .fetch_optional(db)
        .await
        .map_err(AppError::internal)?;
        return decided
            .map(Json)
            .ok_or(AppError::Conflict("the disposition was already decided"));
    }
    if attome_core::legal_hold::record_is_held(db, &request.entity, request.record_id)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict("the record is under a legal hold"));
    }
    // Claimed before the purge: of two approvers at once, one disposes.
    let claimed = sqlx::query(
        "UPDATE record_disposition SET status = 'approved', reviewed_by = $2, \
                reviewed_at = now(), reason = $3 \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(id)
    .bind(ctx.user_id)
    .bind(&reason)
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if claimed != 1 {
        return Err(AppError::Conflict("the disposition was already decided"));
    }
    let purged = crate::retention::purge_record(
        &state,
        &request.entity,
        request.record_id,
        ctx.user_id,
        "records_disposition",
    )
    .await;
    if let Err(e) = purged {
        sqlx::query(
            "UPDATE record_disposition SET status = 'pending', reviewed_by = NULL, \
                    reviewed_at = NULL WHERE id = $1",
        )
        .bind(id)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
        return Err(e);
    }
    let category: String = sqlx::query_scalar("SELECT name FROM records_category WHERE id = $1")
        .bind(request.category_ref)
        .fetch_one(db)
        .await
        .map_err(AppError::internal)?;
    let at = Utc::now();
    let (cert, digest) = certificate(&request, &category, ctx.user_id, at);
    let mut tx = attome_db::tx::begin(db).await?;
    let decided: Disposition = sqlx::query_as(&format!(
        "UPDATE record_disposition SET certificate = $2, certificate_sha256 = $3 \
          WHERE id = $1 RETURNING {DISPOSITION_COLUMNS}"
    ))
    .bind(id)
    .bind(&cert)
    .bind(&digest)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE record_declaration SET disposed_at = $3 WHERE entity = $1 AND record_id = $2",
    )
    .bind(&request.entity)
    .bind(request.record_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(decided))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/records/categories",
            post(create_category).get(list_categories),
        )
        .route("/api/v1/admin/records/declarations", post(declare))
        .route(
            "/api/v1/admin/records/dispositions",
            post(request_disposition),
        )
        .route(
            "/api/v1/admin/records/dispositions/{id}/decide",
            post(decide_disposition),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        create_category,
        list_categories,
        declare,
        request_disposition,
        decide_disposition
    ),
    components(schemas(
        Category,
        CategoryBody,
        DeclarationBody,
        Declared,
        DispositionBody,
        DecisionBody,
        Disposition
    ))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_certificate_hash_covers_its_text() {
        let d = Disposition {
            id: Uuid::from_u128(1),
            entity: "contract".into(),
            record_id: Uuid::from_u128(2),
            category_ref: Uuid::from_u128(3),
            requested_by: Uuid::from_u128(4),
            requested_at: Utc::now(),
            status: "pending".into(),
            reviewed_by: None,
            reviewed_at: None,
            reason: None,
            certificate: None,
            certificate_sha256: None,
        };
        let at = Utc::now();
        let (cert, digest) = certificate(&d, "Contracts", Uuid::from_u128(5), at);
        assert_eq!(cert["category"], "Contracts");
        assert_eq!(cert["approved_by"], json!(Uuid::from_u128(5)));
        assert_eq!(digest.len(), 64);
        assert_eq!(
            digest,
            hex::encode(Sha256::digest(cert.to_string().as_bytes()))
        );
        assert!(checked_name("  ").is_err());
        assert_eq!(checked_name(" Contracts ").unwrap(), "Contracts");
    }
}
