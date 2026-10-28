//! P-data-protection-governance §4 "Per-record legal hold" — the admin
//! surface that actually places/releases a `legal_hold` row.
//! Without this, `attome_core::legal_hold::record_is_held` (checked by
//! `attome_metadata::purge::scrub_record`/`attome_audit::erasure::destroy_key`,
//! D-266) would have no way to ever return `Some` outside a direct database
//! write — this module is what makes the feature reachable through the API.
//! A dedicated route (guidelines §9: this isn't CRUD on a registered
//! entity), mounted with the `strict_authz` re-resolve layer at `system.rs`,
//! same pattern as `retention_admin.rs`/`dsr_admin.rs`.
//!
//! TODO (needs live Postgres/Rust toolchain to actually run — this session
//! has neither): unverified.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, SelfService, area};
use attome_types::ErrorResponse;
use attome_types::{AppError, OnePageQuery, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct LegalHoldSummary {
    id: Uuid,
    entity_logicalname: String,
    record_id: Option<Uuid>,
    matter_reference: String,
    placed_by: Uuid,
    placed_at: DateTime<Utc>,
    released_at: Option<DateTime<Utc>>,
}

/// M15 (Data Governance, D-413) steward-defaulting hook: `place_hold`'s
/// response — every `LegalHoldSummary` field plus one additive
/// `resolved_steward_ref`, rather than nesting `LegalHoldSummary` inside a
/// wrapper object, so this stays a backward-compatible superset of the
/// pre-D-413 response shape (guidelines §12: prefer additive changes) — a
/// caller reading only the original fields sees no change.
/// `resolved_steward_ref` is the accountable steward for the held entity's
/// data domain, resolved at placement time via
/// `attome_core::resolve_steward_for_domain`. Purely informational — it
/// does not gate or route the hold, it just tells the placing admin who else
/// should probably know about it (matches the M15 plan §3 "steward is the
/// default reviewer" intent, for the one queue in this crate that actually
/// has entity context at creation time; see `governance_admin.rs`'s header
/// for why `dsr_admin.rs`'s DSR queue does not get the same hook in this
/// pass). `None` when the entity has no assigned domain, or its domain names
/// neither a steward nor a deputy.
#[derive(Serialize, ToSchema)]
struct PlaceLegalHoldResult {
    id: Uuid,
    entity_logicalname: String,
    record_id: Option<Uuid>,
    matter_reference: String,
    placed_by: Uuid,
    placed_at: DateTime<Utc>,
    released_at: Option<DateTime<Utc>>,
    resolved_steward_ref: Option<Uuid>,
}

impl PlaceLegalHoldResult {
    fn from_row(hold: LegalHoldSummary, resolved_steward_ref: Option<Uuid>) -> Self {
        Self {
            id: hold.id,
            entity_logicalname: hold.entity_logicalname,
            record_id: hold.record_id,
            matter_reference: hold.matter_reference,
            placed_by: hold.placed_by,
            placed_at: hold.placed_at,
            released_at: hold.released_at,
            resolved_steward_ref,
        }
    }
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
struct ListLegalHoldsQuery {
    /// `"active" | "released"`. Defaults to `"active"` — the common case
    /// (an operator checking what's currently frozen), matching
    /// `retention_admin.rs::list_actions`'s "no filter = the operationally
    /// interesting subset" precedent... except that endpoint defaults to
    /// unfiltered; this one defaults to `active` specifically because an
    /// unbounded, ever-growing history of released holds is the
    /// less-common query.
    status: Option<String>,
    /// Only this entity (its logical name).
    entity_logicalname: Option<String>,
    /// One-based: page 1 is the first page.
    #[param(minimum = 1)]
    page: Option<i64>,
    /// Rows per page.
    page_size: Option<i64>,
}

/// List legal holds
///
/// The legal holds placed on records, active and released. Compliance administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/legal-holds",
    tag = "admin",
    params(ListLegalHoldsQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<LegalHoldSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_holds(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Query(query): Query<ListLegalHoldsQuery>,
) -> Result<Json<PaginatedResponse<LegalHoldSummary>>, AppError> {
    let status = query.status.as_deref().unwrap_or("active");
    if status != "active" && status != "released" {
        return Err(AppError::Validation(
            "status must be one of: active, released".into(),
        ));
    }
    let PageWindow {
        page,
        page_size,
        offset,
    } = PageWindow::resolve(
        query.page,
        query.page_size,
        PageBase::One,
        DEFAULT_PAGE_SIZE,
    );
    let want_active = status == "active";

    let items: Vec<LegalHoldSummary> = sqlx::query_as(
        "SELECT id, entity_logicalname, record_id, matter_reference, placed_by, placed_at, \
                released_at \
           FROM legal_hold \
          WHERE is_deleted = false \
            AND (released_at IS NULL) = $1 \
            AND ($2::text IS NULL OR entity_logicalname = $2) \
          ORDER BY placed_at DESC \
          LIMIT $3 OFFSET $4",
    )
    .bind(want_active)
    .bind(&query.entity_logicalname)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM legal_hold \
          WHERE is_deleted = false \
            AND (released_at IS NULL) = $1 \
            AND ($2::text IS NULL OR entity_logicalname = $2)",
    )
    .bind(want_active)
    .bind(&query.entity_logicalname)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct PlaceLegalHoldBody {
    entity_logicalname: String,
    /// `None` = a whole-entity hold. Not validated as "must currently
    /// exist" — a hold may legitimately be placed ahead of a record's
    /// creation (e.g. a litigation matter naming a customer before their
    /// first record in a new entity exists) or survive the record's own
    /// soft-delete; `record_is_held`'s check is by id match, not by live
    /// row existence.
    record_id: Option<Uuid>,
    matter_reference: String,
}

/// Place a legal hold
///
/// Holds one record of a known entity, so retention leaves it alone; the record need not exist yet.
/// Compliance administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/legal-holds",
    tag = "admin",
    request_body = PlaceLegalHoldBody,
    responses(
        (status = 201, description = "Success", body = PlaceLegalHoldResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Activated)])))),
)]
async fn place_hold(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Json(body): Json<PlaceLegalHoldBody>,
) -> Result<(StatusCode, Json<PlaceLegalHoldResult>), AppError> {
    let entity_logicalname = body.entity_logicalname.trim();
    if state.entities.load().get(entity_logicalname).is_none() {
        return Err(AppError::Validation(format!(
            "unknown entity: {entity_logicalname}"
        )));
    }
    let matter_reference = body.matter_reference.trim();
    if matter_reference.is_empty() {
        return Err(AppError::Validation("matter_reference is required".into()));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: LegalHoldSummary = sqlx::query_as(
        "INSERT INTO legal_hold (entity_logicalname, record_id, matter_reference, placed_by) \
         VALUES ($1, $2, $3, $4) \
         RETURNING id, entity_logicalname, record_id, matter_reference, placed_by, placed_at, released_at",
    )
    .bind(entity_logicalname)
    .bind(body.record_id)
    .bind(matter_reference)
    .bind(ctx.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Activated,
            ctx.user_id,
            "legal_hold",
            Some(row.id),
        )
        .named("legal_hold.place"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    // M15 (D-413) steward-defaulting hook — see PlaceLegalHoldResult's doc
    // comment. One extra read-only join against tables already open in this
    // transaction-free request; a failure here is treated the same as every
    // other DB error in this handler (masked 500), not swallowed.
    let resolved_steward_ref =
        attome_core::resolve_steward_for_domain(&state.base.db, entity_logicalname).await?;

    Ok((
        StatusCode::CREATED,
        Json(PlaceLegalHoldResult::from_row(row, resolved_steward_ref)),
    ))
}

/// Release a legal hold
///
/// Releases the hold; releasing one already released changes nothing and still answers 200.
/// Compliance administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/legal-holds/{id}/release",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The hold")),
    responses(
        (status = 200, description = "Success", body = LegalHoldSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Closed)])))),
)]
async fn release_hold(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
) -> Result<Json<LegalHoldSummary>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: Option<LegalHoldSummary> = sqlx::query_as(
        "UPDATE legal_hold \
            SET released_at = COALESCE(released_at, NOW()), updated_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND is_deleted = false \
          RETURNING id, entity_logicalname, record_id, matter_reference, placed_by, placed_at, released_at",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let row = row.ok_or(AppError::NotFound)?;

    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Closed,
            ctx.user_id,
            "legal_hold",
            Some(id),
        )
        .named("legal_hold.release"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;

    Ok(Json(row))
}

/// R4-T1: what a hold on `hold_entity` (one record, or the whole entity
/// when `hold_record` is `None`) keeps: the record itself, its file
/// versions, and every captured email linked to it (`links` are an email's
/// `(entity, record)` links). Pure; the database check is
/// `attome_core::legal_hold::record_is_held`, which this mirrors.
pub fn hold_scope_covers(
    hold_entity: &str,
    hold_record: Option<Uuid>,
    item_entity: &str,
    item_record: Uuid,
    links: &[(&str, Uuid)],
) -> bool {
    let matches = |entity: &str, record: Uuid| {
        entity == hold_entity && hold_record.is_none_or(|r| r == record)
    };
    matches(item_entity, item_record)
        || (item_entity == "communication" && links.iter().any(|(e, r)| matches(e, *r)))
}

/// The most custodians one request adds.
pub const MAX_CUSTODIANS: usize = 200;

/// People to ask to keep what a hold covers.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddCustodiansBody {
    pub user_ids: Vec<Uuid>,
}

/// One custodian of a hold.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct HoldCustodian {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub notified_at: DateTime<Utc>,
    pub acknowledged_at: Option<DateTime<Utc>>,
}

/// The notice a custodian receives. Pure.
pub fn custodian_notice(matter: &str, link: &str) -> (String, String) {
    (
        format!("Legal hold: {matter} / حفظ قانوني: {matter}"),
        format!(
            "You are a custodian in the legal hold \"{matter}\". Do not delete, alter or \
             discard any record, file, email or chat message about it until you are told the \
             hold is released. Acknowledge this notice: {link}\n\n\
             أنت من الأمناء في الحفظ القانوني \"{matter}\". لا تحذف أو تعدل أو تتلف أي سجل أو ملف \
             أو بريد أو رسالة محادثة تتعلق به حتى يُبلغك أحد برفع الحفظ. أقرّ باستلام هذا الإشعار: {link}"
        ),
    )
}

/// Ask people to keep what a hold covers
///
/// R4-T1: adds custodians to an active hold and emails each new one the
/// notice with a link to acknowledge it. Someone already a custodian is not
/// told again.
#[utoipa::path(
    post,
    path = "/api/v1/admin/legal-holds/{id}/custodians",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The hold")),
    request_body = AddCustodiansBody,
    responses(
        (status = 200, description = "The users newly told", body = Vec<Uuid>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active hold", body = ErrorResponse),
        (status = 422, description = "No users, too many, or a user that does not exist", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Update)])))),
)]
async fn add_custodians(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
    Json(body): Json<AddCustodiansBody>,
) -> Result<Json<Vec<Uuid>>, AppError> {
    if body.user_ids.is_empty() || body.user_ids.len() > MAX_CUSTODIANS {
        return Err(AppError::Validation(format!(
            "user_ids has 1 to {MAX_CUSTODIANS} users"
        )));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let matter: Option<String> = sqlx::query_scalar(
        "SELECT matter_reference FROM legal_hold \
          WHERE id = $1 AND is_deleted = false AND released_at IS NULL FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let matter = matter.ok_or(AppError::NotFound)?;
    let known: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT id) FROM user_account WHERE id = ANY($1) AND is_active",
    )
    .bind(&body.user_ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let distinct: std::collections::BTreeSet<&Uuid> = body.user_ids.iter().collect();
    if usize::try_from(known).unwrap_or(0) != distinct.len() {
        return Err(AppError::Validation(
            "every user must exist and be active".into(),
        ));
    }
    let added: Vec<(Uuid, Option<String>)> = sqlx::query_as(
        "WITH added AS ( \
           INSERT INTO legal_hold_custodian (hold_ref, user_ref, notified_by) \
           SELECT $1, u, $2 FROM unnest($3::uuid[]) AS u \
           ON CONFLICT DO NOTHING RETURNING user_ref) \
         SELECT a.user_ref, u.email FROM added a JOIN user_account u ON u.id = a.user_ref",
    )
    .bind(id)
    .bind(ctx.user_id)
    .bind(&body.user_ids)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let link = format!(
        "{}/xrm/legal-holds/{id}",
        state.base.config.frontend_url().trim_end_matches('/')
    );
    let (subject, text) = custodian_notice(&matter, &link);
    for (_, email) in &added {
        let Some(email) = email.clone() else { continue };
        attome_jobs::enqueue_in_tx(
            &mut tx,
            attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
                to: email,
                subject: subject.clone(),
                text_body: text.clone(),
                html_body: None,
                delivery_id: None,
                from_override: None,
                message_id: None,
                in_reply_to: None,
                references: None,
                communication_id: None,
                attachments: Vec::new(),
                stream: Default::default(),
                list_unsubscribe: None,
            })),
        )
        .await
        .map_err(AppError::internal)?;
    }
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "legal_hold",
            Some(id),
        )
        .named("legal_hold.custodians")
        .comment(format!("{} custodian(s) told", added.len())),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(added.into_iter().map(|(user, _)| user).collect()))
}

/// A hold's custodians
///
/// R4-T1: who was told, when, and who has acknowledged.
#[utoipa::path(
    get,
    path = "/api/v1/admin/legal-holds/{id}/custodians",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The hold"), OnePageQuery),
    responses(
        (status = 200, description = "A page of custodians", body = PaginatedResponse<HoldCustodian>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_custodians(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Compliance>>,
    Path(id): Path<Uuid>,
    Query(q): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<HoldCustodian>>, AppError> {
    let window = q.window();
    let rows: Vec<HoldCustodian> = sqlx::query_as(
        "SELECT c.user_ref AS user_id, u.email, c.notified_at, c.acknowledged_at \
           FROM legal_hold_custodian c LEFT JOIN user_account u ON u.id = c.user_ref \
          WHERE c.hold_ref = $1 ORDER BY c.notified_at, c.user_ref LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM legal_hold_custodian WHERE hold_ref = $1")
            .bind(id)
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        rows,
        total,
        window.page,
        window.page_size,
    )))
}

/// Acknowledge a legal hold notice
///
/// R4-T1: the signed-in custodian confirms they received the notice. Only a
/// custodian of the hold may; acknowledging again changes nothing.
#[utoipa::path(
    post,
    path = "/api/v1/legal-holds/{id}/acknowledge",
    tag = "compliance",
    params(("id" = Uuid, Path, description = "The hold")),
    responses(
        (status = 204, description = "Acknowledged"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "The caller is not a custodian of this hold", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Update)])))),
)]
async fn acknowledge_hold(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let custodian: Option<Option<DateTime<Utc>>> = sqlx::query_scalar(
        "UPDATE legal_hold_custodian SET acknowledged_at = COALESCE(acknowledged_at, now()) \
          WHERE hold_ref = $1 AND user_ref = $2 RETURNING acknowledged_at",
    )
    .bind(id)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    require_custodian(custodian.is_some())?;
    attome_audit::security::write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::security::SecurityEvent::new(
            attome_audit::security::MandatoryCategory::Security,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "legal_hold",
            Some(id),
        )
        .named("legal_hold.acknowledge"),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

/// R4-T1: only a custodian of the hold acknowledges it; anyone else gets the
/// same 404 as a hold that does not exist.
fn require_custodian(is_custodian: bool) -> Result<(), AppError> {
    if is_custodian {
        Ok(())
    } else {
        Err(AppError::NotFound)
    }
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/legal-holds",
            get(list_holds).post(place_hold),
        )
        .route("/api/v1/admin/legal-holds/{id}/release", post(release_hold))
        .route(
            "/api/v1/admin/legal-holds/{id}/custodians",
            get(list_custodians).post(add_custodians),
        )
        .route(
            "/api/v1/legal-holds/{id}/acknowledge",
            post(acknowledge_hold),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_holds,
    place_hold,
    release_hold,
    add_custodians,
    list_custodians,
    acknowledge_hold
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hold_scope_record_entity_and_linked_mail() {
        let account = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        let mail = Uuid::from_u128(9);
        // A hold on one account keeps that account, not another.
        assert!(hold_scope_covers(
            "account",
            Some(account),
            "account",
            account,
            &[]
        ));
        assert!(!hold_scope_covers(
            "account",
            Some(account),
            "account",
            other,
            &[]
        ));
        // A whole-entity hold keeps every record of it.
        assert!(hold_scope_covers("account", None, "account", other, &[]));
        // Captured mail linked to the held account is kept too.
        assert!(hold_scope_covers(
            "account",
            Some(account),
            "communication",
            mail,
            &[("contact", other), ("account", account)]
        ));
        assert!(!hold_scope_covers(
            "account",
            Some(account),
            "communication",
            mail,
            &[("account", other)]
        ));
        // Links only extend holds to communications.
        assert!(!hold_scope_covers(
            "account",
            Some(account),
            "task",
            mail,
            &[("account", account)]
        ));
    }

    #[test]
    fn hold_scope_notice_is_bilingual_and_carries_the_link() {
        let (subject, body) =
            custodian_notice("Case 42", "https://crm.example.sa/xrm/legal-holds/1");
        assert!(subject.contains("Case 42") && subject.contains("حفظ قانوني"));
        assert_eq!(
            body.matches("https://crm.example.sa/xrm/legal-holds/1")
                .count(),
            2
        );
        assert!(require_custodian(true).is_ok());
        assert!(matches!(require_custodian(false), Err(AppError::NotFound)));
    }
}
