//! R1-T1: restriction and rectification requests.
//!
//! **Restriction.** `POST …/restrict` resolves a pending `restriction`
//! request's scopes to the subject's live records (the same
//! `(entity, match_attribute)` scopes access and erasure take) and places one
//! `processing_restriction` row per record; the request is fulfilled and the
//! restriction is in force until `POST …/lift`. What "in force" means is
//! `attome_core::processing_restriction`'s module doc: AI, bulk export and
//! marketing email leave those records out, while people who may read them
//! still can.
//!
//! **Rectification.** The corrections themselves are ordinary record edits
//! through the generic entity API (validated, audited, versioned like any
//! other edit); `POST …/rectify` closes the request with what was corrected,
//! or rejects it with the reason, so the request carries its own outcome.
//!
//! Every request gets its response deadline when it is recorded
//! (`dsr_admin::insert_request`, `processing_restriction::response_deadline`).

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent};
use attome_core::{EngineState, quote_ident};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::dsr_admin::DsrScope;

/// The most characters a rectification's resolution keeps.
pub const MAX_RESOLUTION_CHARS: usize = 4_000;

/// `POST …/restrict`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RestrictBody {
    pub scopes: Vec<DsrScope>,
}

/// How many records one scope restricted.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeRestriction {
    pub entity_logicalname: String,
    pub records: i64,
}

/// A restriction placed or lifted.
#[derive(Debug, Serialize, ToSchema)]
pub struct RestrictionResult {
    /// The DSR request.
    pub id: Uuid,
    pub status: String,
    pub scopes: Vec<ScopeRestriction>,
}

/// `POST …/rectify`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RectifyBody {
    /// `fulfilled` (the records were corrected) or `rejected`.
    pub outcome: String,
    /// What was corrected, or why the request was rejected.
    pub resolution: String,
}

/// A rectification's outcome, checked. Pure.
pub fn check_rectification(body: &RectifyBody) -> Result<(&'static str, String), AppError> {
    let outcome = match body.outcome.trim() {
        "fulfilled" => "fulfilled",
        "rejected" => "rejected",
        _ => {
            return Err(AppError::Validation(
                "outcome is fulfilled or rejected".into(),
            ));
        }
    };
    let resolution = body.resolution.trim();
    if resolution.is_empty() || resolution.chars().count() > MAX_RESOLUTION_CHARS {
        return Err(AppError::Validation(format!(
            "resolution is 1 to {MAX_RESOLUTION_CHARS} characters"
        )));
    }
    Ok((outcome, resolution.to_owned()))
}

/// The subject's live record ids in one scope, the scope checked against
/// the live metadata first (its identifiers are quoted, its value bound).
async fn scope_records(
    state: &EngineState,
    scope: &DsrScope,
    subject_reference: &str,
) -> Result<Vec<Uuid>, AppError> {
    let registry = state.entities.load();
    let meta = registry
        .get(scope.entity())
        .ok_or_else(|| AppError::Validation(format!("unknown entity: {}", scope.entity())))?;
    if !meta
        .attrs
        .iter()
        .any(|a| a.logicalname == scope.match_attribute())
    {
        return Err(AppError::Validation(format!(
            "{} is not a registered attribute of {}",
            scope.match_attribute(),
            scope.entity()
        )));
    }
    let mut sql = String::from("SELECT id FROM ");
    sql.push_str(&quote_ident(scope.entity()));
    sql.push_str(" WHERE ");
    sql.push_str(&quote_ident(scope.match_attribute()));
    sql.push_str(" = $1");
    if !meta.is_append_only {
        sql.push_str(" AND is_active = true");
    }
    sqlx::query_scalar(&sql)
        .bind(subject_reference)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Restricts the processing of a subject's records (R1-T1).
///
/// For a pending `restriction` request: every live record the scopes match
/// is left out of AI, bulk export and marketing email until the restriction
/// is lifted. People who may read the records still can. The request is
/// fulfilled.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dsr/requests/{id}/restrict",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The restriction request's id")),
    request_body = RestrictBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The records are restricted", body = RestrictionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No pending restriction request with this id", body = ErrorResponse),
        (status = 422, description = "No scopes, or a scope naming an unknown entity or attribute", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn restrict(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
    Json(body): Json<RestrictBody>,
) -> Result<Json<RestrictionResult>, AppError> {
    if body.scopes.is_empty() {
        return Err(AppError::Validation("scopes must not be empty".into()));
    }
    let subject: Option<String> = sqlx::query_scalar(
        "SELECT subject_reference FROM dsr_request \
          WHERE id = $1 AND request_type = 'restriction' AND status = 'pending' \
            AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let subject = subject.ok_or(AppError::Conflict(
        "no pending restriction request with this id",
    ))?;

    let mut matched = Vec::with_capacity(body.scopes.len());
    for scope in &body.scopes {
        matched.push((
            scope.entity().to_owned(),
            scope_records(&state, scope, &subject).await?,
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut scopes = Vec::with_capacity(matched.len());
    for (entity, ids) in &matched {
        let placed = sqlx::query(
            "INSERT INTO processing_restriction \
                 (entity_logicalname, record_id, dsr_request_id, placed_by) \
             SELECT $1, r, $2, $3 FROM unnest($4::uuid[]) AS r \
              WHERE NOT EXISTS (SELECT 1 FROM processing_restriction p \
                                 WHERE p.entity_logicalname = $1 AND p.record_id = r \
                                   AND p.lifted_at IS NULL)",
        )
        .bind(entity)
        .bind(id)
        .bind(ctx.user_id)
        .bind(ids)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        scopes.push(ScopeRestriction {
            entity_logicalname: entity.clone(),
            records: i64::try_from(placed).unwrap_or(i64::MAX),
        });
    }
    let updated = sqlx::query(
        "UPDATE dsr_request SET status = 'fulfilled', fulfilled_at = NOW(), \
                row_version = row_version + 1, updated_at = NOW() \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "no pending restriction request with this id",
        ));
    }
    let total: i64 = scopes.iter().map(|s| s.records).sum();
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Update,
            ctx.user_id,
            "dsr_request",
            Some(id),
        )
        .named("dsr_restriction_placed")
        .comment(format!("{total} record(s) restricted")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(RestrictionResult {
        id,
        status: "fulfilled".to_owned(),
        scopes,
    }))
}

/// Lifts a restriction (R1-T1).
///
/// Every record the restriction request restricted is processed normally
/// again. The request stays fulfilled; the lift is recorded on each
/// restriction and in the audit trail.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dsr/requests/{id}/lift",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The restriction request's id")),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The restriction is lifted", body = RestrictionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No restriction request with this id", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn lift(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<Json<RestrictionResult>, AppError> {
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status FROM dsr_request \
          WHERE id = $1 AND request_type = 'restriction' AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let status = status.ok_or(AppError::NotFound)?;

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let lifted: Vec<(String, i64)> = sqlx::query_as(
        "WITH lifted AS ( \
             UPDATE processing_restriction SET lifted_at = NOW(), lifted_by = $2 \
              WHERE dsr_request_id = $1 AND lifted_at IS NULL \
              RETURNING entity_logicalname) \
         SELECT entity_logicalname, count(*) FROM lifted GROUP BY entity_logicalname",
    )
    .bind(id)
    .bind(ctx.user_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = lifted.iter().map(|(_, n)| n).sum();
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Update,
            ctx.user_id,
            "dsr_request",
            Some(id),
        )
        .named("dsr_restriction_lifted")
        .comment(format!("{total} record(s) no longer restricted")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(RestrictionResult {
        id,
        status,
        scopes: lifted
            .into_iter()
            .map(|(entity_logicalname, records)| ScopeRestriction {
                entity_logicalname,
                records,
            })
            .collect(),
    }))
}

/// Closes a rectification request (R1-T1).
///
/// The corrections are made through the ordinary record API first; this
/// records the outcome on the request — `fulfilled` with what was corrected,
/// or `rejected` with the reason the data was found accurate.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dsr/requests/{id}/rectify",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The rectification request's id")),
    request_body = RectifyBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The request is closed", body = RestrictionResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "No pending rectification request with this id", body = ErrorResponse),
        (status = 422, description = "A bad outcome, or an empty or too long resolution", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn rectify(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
    Json(body): Json<RectifyBody>,
) -> Result<Json<RestrictionResult>, AppError> {
    let (outcome, resolution) = check_rectification(&body)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let updated = sqlx::query(
        "UPDATE dsr_request SET status = $2, resolution = $3, \
                fulfilled_at = CASE WHEN $2 = 'fulfilled' THEN NOW() END, \
                row_version = row_version + 1, updated_at = NOW() \
          WHERE id = $1 AND request_type = 'rectification' AND status = 'pending' \
            AND is_deleted = false",
    )
    .bind(id)
    .bind(outcome)
    .bind(&resolution)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if updated.rows_affected() == 0 {
        return Err(AppError::Conflict(
            "no pending rectification request with this id",
        ));
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Update,
            ctx.user_id,
            "dsr_request",
            Some(id),
        )
        .named("dsr_rectification_closed")
        .comment(format!("rectification {outcome}")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(RestrictionResult {
        id,
        status: outcome.to_owned(),
        scopes: Vec::new(),
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/api/v1/admin/dsr/requests/{id}/restrict", post(restrict))
        .route("/api/v1/admin/dsr/requests/{id}/lift", post(lift))
        .route("/api/v1/admin/dsr/requests/{id}/rectify", post(rectify))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(restrict, lift, rectify))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsr_restriction_rectification_needs_an_outcome_and_a_resolution() {
        let body = |outcome: &str, resolution: &str| RectifyBody {
            outcome: outcome.into(),
            resolution: resolution.into(),
        };
        assert_eq!(
            check_rectification(&body("fulfilled", " Phone corrected ")).ok(),
            Some(("fulfilled", "Phone corrected".to_owned()))
        );
        assert!(check_rectification(&body("rejected", "Data was accurate")).is_ok());
        assert!(check_rectification(&body("done", "x")).is_err());
        assert!(check_rectification(&body("fulfilled", "  ")).is_err());
        let long = "x".repeat(MAX_RESOLUTION_CHARS + 1);
        assert!(check_rectification(&body("fulfilled", &long)).is_err());
    }
}
