//! P-data-protection-governance §4 "DSR admin surface" — the data-subject-
//! rights (access/erasure/portability/objection) request-tracking and
//! fulfillment API. A dedicated route (guidelines §9: this isn't CRUD on a
//! registered entity), gated on `system.admin` and mounted with the
//! `strict_authz` re-resolve layer at `system.rs`'s composition point —
//! matching `retention_admin.rs`'s established pattern, not
//! `erasure_admin.rs`'s older one (this plan's own §4 design note on
//! privileged-authz freshness, guidelines §7).
//!
//! Access/portability fulfillment reuses D-177's masked NDJSON -> object
//! store -> checksum-verify export mechanism verbatim
//! (`retention::export_columns`/`masked_select_expr`/
//! `stream_masked_export_to_store`/`verify_uploaded_checksum`), scoped by a
//! caller-supplied `(entity_logicalname, match_attribute)` pair per entity
//! instead of by partition — a DSR request is inherently cross-entity (a
//! `subject_reference` like an email address doesn't map to one table), so
//! the caller (an admin who knows the deployment's schema) names which
//! entities and which attribute identifies the subject in each.
//! `match_attribute` is validated against the entity's live registered
//! attributes before use — never interpolated from unvalidated input
//! (guidelines §4).
//!
//! Erasure fulfillment calls the existing D-107 `attome_audit::destroy_key`
//! (unchanged signature aside from this plan's new `entity_logicalname`
//! parameter — see that function's own doc comment) for every live record
//! matching the request's scopes, and writes the same shape of
//! `AuditOperation::Erasure` event `erasure_admin.rs::do_erase_record`
//! writes, linking the DSR request to that evidence via `evidence_ref`.
//! Deliberately does NOT also call `attome_metadata::purge::scrub_record` — D-107
//! crypto-shredding is what this plan's §4 design names for DSR erasure;
//! nulling the record's own live field values is a separate, existing
//! action (soft-delete via the generic entity API, then the ordinary
//! retention purge sweep once past grace) not folded in here.
//!
//! All three fulfillment paths check `attome_core::legal_hold::
//! record_is_held` per matching record. Access/portability exclude a held
//! record from the export and report how many were withheld (a partial,
//! visible export, not a silent one) rather than failing the whole request —
//! a subject's right to access their non-held data isn't extinguished by a
//! hold on one specific other record. Erasure is all-or-nothing per request:
//! a request whose scope includes ANY held record erases nothing and is set
//! to `status = "blocked"` with `block_reason` naming the matter reference
//! (P-data-protection-governance §3: "must show as blocked/pending with the
//! hold as the attributed reason").
//!
//! D-268: `fulfill_erasure` is now routed through the D-195 four-eyes
//! approval gate (`ACTION_DSR_FULFILL_ERASURE`, a distinct action_type from
//! `erasure_admin::ACTION_SECURITY_ERASURE` since the payload shapes differ —
//! see that constant's own doc comment). `fulfill_access`/`fulfill_portability`
//! remain ungated: neither is irreversible the way key destruction is (an
//! access/portability export can simply be re-run), matching
//! `approval_admin::PRODUCTION_MANDATORY_ACTIONS`'s existing
//! reversible-vs-irreversible line.
//!
//! Live-verified against a real Postgres/Redis/object store — see D-268
//! (`crates/engine/attome-api/tests/dsr_admin.rs`).

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_audit::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
};
use attome_core::{DataClassification, EngineState, TransferDecision, quote_ident};
use attome_server::authz::{Admin, Authorized};
use attome_types::ErrorResponse;
use attome_types::{AppError, PaginatedResponse};
use attome_types::{DEFAULT_PAGE_SIZE, PageBase, PageWindow};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use object_store::path::Path as ObjectPath;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// D-195/P-four-eyes-approval — gates `fulfill_erasure` below the same way
/// `erasure_admin::ACTION_SECURITY_ERASURE` gates direct-record erasure: both
/// ultimately call the same D-107 `attome_audit::destroy_key`, so both are
/// equally irreversible once executed (see `approval_admin::
/// PRODUCTION_MANDATORY_ACTIONS`'s doc comment for that exact criterion — this
/// action_type is listed there alongside `security.erasure`). A distinct
/// action_type rather than reusing `ACTION_SECURITY_ERASURE`: that one's
/// `execute_approved` arm assumes a `{logicalname, record_id}` payload
/// (erasing one record), not this flow's `{request_id, scopes}` (erasing
/// every record a DSR request's scopes resolve to) — exactly the distinction
/// this module's own former TODO named as the reason not to misroute through
/// it.
pub const ACTION_DSR_FULFILL_ERASURE: &str = "dsr.fulfill_erasure";

fn valid_request_type(s: &str) -> bool {
    matches!(s, "access" | "erasure" | "portability" | "objection")
}

/// Worst-case severity ordering for picking one classification across a
/// whole entity's attributes — local to this module rather than an `Ord`
/// impl on `DataClassification` itself, since no other caller needs to
/// compare classifications (attribute-level code only ever reads one field's
/// value directly).
fn classification_rank(c: DataClassification) -> u8 {
    match c {
        DataClassification::General => 0,
        DataClassification::Personal => 1,
        DataClassification::SensitiveSpecialCategory => 2,
    }
}

// ── Request tracking ───────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
struct DsrRequestQuery {
    /// `"pending" | "blocked" | "fulfilled" | "rejected"`.
    status: Option<String>,
    /// `"access" | "erasure" | "portability" | "objection"`.
    request_type: Option<String>,
    /// One-based: page 1 is the first page.
    page: Option<i64>,
    page_size: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
struct DsrRequestSummary {
    id: Uuid,
    subject_reference: String,
    request_type: String,
    status: String,
    block_reason: Option<String>,
    requested_by: Uuid,
    requested_at: DateTime<Utc>,
    fulfilled_at: Option<DateTime<Utc>>,
    evidence_ref: Option<String>,
}

/// `GET /api/v1/admin/dsr/requests` — `system.admin` only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/dsr/requests",
    tag = "admin",
    params(DsrRequestQuery),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<DsrRequestSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_requests(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<DsrRequestQuery>,
) -> Result<Json<PaginatedResponse<DsrRequestSummary>>, AppError> {
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

    let items: Vec<DsrRequestSummary> = sqlx::query_as(
        "SELECT id, subject_reference, request_type, status, block_reason, requested_by, \
                requested_at, fulfilled_at, evidence_ref \
           FROM dsr_request \
          WHERE is_deleted = false \
            AND ($1::text IS NULL OR status = $1) \
            AND ($2::text IS NULL OR request_type = $2) \
          ORDER BY requested_at DESC \
          LIMIT $3 OFFSET $4",
    )
    .bind(&query.status)
    .bind(&query.request_type)
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM dsr_request \
          WHERE is_deleted = false \
            AND ($1::text IS NULL OR status = $1) \
            AND ($2::text IS NULL OR request_type = $2)",
    )
    .bind(&query.status)
    .bind(&query.request_type)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}

#[derive(Deserialize, ToSchema)]
struct CreateDsrRequestBody {
    subject_reference: String,
    request_type: String,
}

/// `POST /api/v1/admin/dsr/requests` — `system.admin` only. Just records the
/// ask (`status = 'pending'`); fulfillment is a separate, explicit call to
/// one of the three `fulfill-*` endpoints below.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dsr/requests",
    tag = "admin",
    request_body = CreateDsrRequestBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Success", body = DsrRequestSummary),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_request(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<CreateDsrRequestBody>,
) -> Result<(StatusCode, Json<DsrRequestSummary>), AppError> {
    let subject_reference = body.subject_reference.trim();
    if subject_reference.is_empty() {
        return Err(AppError::Validation("subject_reference is required".into()));
    }
    let request_type = body.request_type.trim().to_lowercase();
    if !valid_request_type(&request_type) {
        return Err(AppError::Validation(
            "request_type must be one of: access, erasure, portability, objection".into(),
        ));
    }

    let row = insert_request(&state, subject_reference, &request_type, ctx.user_id).await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Records a pending request and its business event in one transaction.
async fn insert_request(
    state: &EngineState,
    subject_reference: &str,
    request_type: &str,
    actor: Uuid,
) -> Result<DsrRequestSummary, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let row: DsrRequestSummary = sqlx::query_as(
        "INSERT INTO dsr_request (subject_reference, request_type, requested_by) \
         VALUES ($1, $2, $3) \
         RETURNING id, subject_reference, request_type, status, block_reason, requested_by, \
                   requested_at, fulfilled_at, evidence_ref",
    )
    .bind(subject_reference)
    .bind(request_type)
    .bind(actor)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // D-062: the request and its event commit together. The subject
    // reference is personal data and stays out of the event.
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "dsr_request",
            row.id,
            AuditOperation::Create,
            "dsr.request_create",
            actor,
        )
        .comment(format!("{request_type} request recorded")),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(row)
}

/// Records an `access` request for `subject_reference` and fulfills it at
/// once, through the same export as `POST …/fulfill-access` (masked NDJSON,
/// checksum-verified, legal-hold aware, one `Security`/`Export` event), plus
/// `supplements`. For another engine's own "export this person's data"
/// action (web portal plan G-14), so there is one export mechanism. The
/// request stays listed under `GET /api/v1/admin/dsr/requests`; if the export
/// fails it stays `pending` there, like a failed manual fulfillment.
pub async fn record_and_fulfill_access(
    state: &EngineState,
    subject_reference: &str,
    scopes: Vec<DsrScope>,
    supplements: &[DsrSupplement],
    actor: Uuid,
) -> Result<FulfillExportResult, AppError> {
    let subject_reference = subject_reference.trim();
    if subject_reference.is_empty() {
        return Err(AppError::Validation("subject_reference is required".into()));
    }
    let request = insert_request(state, subject_reference, "access", actor).await?;
    do_fulfill_export(
        state,
        request.id,
        ExportKind::Access,
        FulfillExportBody {
            scopes,
            admin_override: false,
        },
        supplements,
        actor,
    )
    .await
}

// ── Access / portability fulfillment ────────────────────────────────────────

/// `pub(crate)`/`Serialize` (beyond the `Deserialize` every other body-only
/// struct in this file needs): `approval_admin::gate`'s payload round-trips
/// through `approval_request.payload` (JSONB) as an opaque `Value`,
/// and `execute_approved`'s `ACTION_DSR_FULFILL_ERASURE` arm deserializes it
/// straight back into `Vec<DsrScope>` — reusing this type there rather than
/// duplicating its two fields, same as every other wired action_type's
/// payload struct lives next to its own flow, not in `approval_admin.rs`.
#[derive(Deserialize, Serialize, Clone, ToSchema)]
pub struct DsrScope {
    entity_logicalname: String,
    /// Attribute logicalname identifying the subject within this entity
    /// (e.g. `"email"`) — validated against the entity's live registered
    /// attributes before use.
    match_attribute: String,
}

impl std::fmt::Debug for DsrScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsrScope").finish_non_exhaustive()
    }
}

impl DsrScope {
    /// A scope for another engine's own access export (web portal plan G-14).
    /// Validated like a caller-supplied one when the export runs.
    pub fn new(entity_logicalname: impl Into<String>, match_attribute: impl Into<String>) -> Self {
        Self {
            entity_logicalname: entity_logicalname.into(),
            match_attribute: match_attribute.into(),
        }
    }
}

/// Rows another engine owns outside any registered entity (an
/// infrastructure table the scopes above can't name), exported into the same
/// request through the same masked NDJSON -> object store -> checksum path,
/// under `dsr-exports/{type}/{request_id}/{name}.ndjson`. Each row is one JSON
/// object; the supplying engine chooses the columns (web portal plan G-14:
/// `webportal_consent`). Gated as `Personal` data.
pub struct DsrSupplement {
    /// `[a-z0-9_]`, 1-63 chars: it becomes an object-key segment.
    pub name: String,
    pub rows: Vec<String>,
}

impl std::fmt::Debug for DsrSupplement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsrSupplement").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
struct FulfillExportBody {
    scopes: Vec<DsrScope>,
    /// P-data-protection-governance §4 cross-border transfer gate. Set only
    /// once an admin has separately confirmed the export destination is
    /// authorized to receive out-of-region restricted data — every use is
    /// logged (`tracing::warn!`), never silent.
    #[serde(default)]
    admin_override: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ScopeExportResult {
    pub entity_logicalname: String,
    pub object_key: String,
    pub checksum: String,
    pub exported_rows: i64,
    pub withheld_for_legal_hold: i64,
}

impl std::fmt::Debug for ScopeExportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScopeExportResult").finish_non_exhaustive()
    }
}

#[derive(Serialize, ToSchema)]
pub struct FulfillExportResult {
    /// The DSR request this export fulfilled.
    pub id: Uuid,
    pub status: String,
    pub scopes: Vec<ScopeExportResult>,
}

impl std::fmt::Debug for FulfillExportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FulfillExportResult")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum ExportKind {
    Access,
    Portability,
}

impl ExportKind {
    fn request_type(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Portability => "portability",
        }
    }
}

/// Shared by `fulfill_access`/`fulfill_portability` — same masked-export
/// mechanism, same evidence shape; only the request's own `request_type`
/// column and the object-key prefix differ, matching this plan's §4 note
/// that portability is "the same export in a documented machine-readable
/// shape" as access, not a different mechanism.
async fn do_fulfill_export(
    state: &EngineState,
    request_id: Uuid,
    kind: ExportKind,
    body: FulfillExportBody,
    supplements: &[DsrSupplement],
    actor: Uuid,
) -> Result<FulfillExportResult, AppError> {
    if body.scopes.is_empty() {
        return Err(AppError::Validation("scopes must not be empty".into()));
    }
    for supplement in supplements {
        let name = &supplement.name;
        if name.is_empty()
            || name.len() > 63
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(AppError::internal(format!(
                "invalid DSR supplement name: {name}"
            )));
        }
    }

    let subject_reference: Option<String> = sqlx::query_scalar(
        "SELECT subject_reference FROM dsr_request \
          WHERE id = $1 AND request_type = $2 AND status = 'pending' AND is_deleted = false",
    )
    .bind(request_id)
    .bind(kind.request_type())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let subject_reference = subject_reference.ok_or(AppError::Conflict(
        "DSR request was not found, is not pending, or its type does not match this endpoint",
    ))?;

    let registry = state.entities.load();

    // M24/D-428: an access/portability export must include the subject's
    // consent history (every grant AND withdrawal — audit_consent is
    // append-only, so this is the full timeline, not just the current
    // state) so a subject can see everything the platform holds about their
    // permissions, without every DSR caller having to remember to name
    // audit_consent explicitly. A caller-supplied scope for it (e.g. a
    // different match_attribute) is left alone rather than duplicated.
    let mut scopes = body.scopes.clone();
    if !scopes
        .iter()
        .any(|s| s.entity_logicalname == "audit_consent")
    {
        scopes.push(DsrScope {
            entity_logicalname: "audit_consent".to_string(),
            match_attribute: "subject_reference".to_string(),
        });
    }
    let mut results = Vec::with_capacity(scopes.len() + 1);

    // M35 v1 Track A: the subject's memory rows are always exported too (see
    // `export_subject_memories`). Memory is free-text personal data with no
    // attribute metadata to classify, so it is gated as `Personal` — and gated
    // here, before any scope uploads, so a blocked memory transfer cannot
    // leave the entity scopes' objects already written.
    check_export_transfer(
        state,
        DataClassification::Personal,
        MEMORY_EXPORT_SCOPE,
        request_id,
        actor,
        body.admin_override,
    )?;
    // Supplements are personal data with no attribute metadata, gated like
    // memory and before any upload.
    for supplement in supplements {
        check_export_transfer(
            state,
            DataClassification::Personal,
            &supplement.name,
            request_id,
            actor,
            body.admin_override,
        )?;
    }

    for scope in &scopes {
        let meta = registry.get(&scope.entity_logicalname).ok_or_else(|| {
            AppError::Validation(format!("unknown entity: {}", scope.entity_logicalname))
        })?;
        if !meta
            .attrs
            .iter()
            .any(|a| a.logicalname == scope.match_attribute)
        {
            return Err(AppError::Validation(format!(
                "{} is not a registered attribute of {}",
                scope.match_attribute, scope.entity_logicalname
            )));
        }

        // Cross-border transfer gate (§4) — worst-case classification
        // across this entity's attributes. A no-op when
        // deployment.data_region is unset (no residency claim configured).
        let classification = meta
            .attrs
            .iter()
            .map(|a| a.data_classification)
            .max_by_key(|c| classification_rank(*c))
            .unwrap_or_default();
        check_export_transfer(
            state,
            classification,
            &scope.entity_logicalname,
            request_id,
            actor,
            body.admin_override,
        )?;

        let table = quote_ident(&scope.entity_logicalname);
        let match_col = quote_ident(&scope.match_attribute);
        // Generic CRUD's live predicate for a provisioned entity table
        // (`entity_crud/mutations.rs`); an append-only table has no
        // soft-delete lifecycle and no `is_active` column at all
        // (`provision/table.rs::ensure_is_active`), so it gets none.
        let live = if meta.is_append_only {
            ""
        } else {
            " AND is_active = true"
        };
        let matching_ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {table} WHERE {match_col} = $1{live}"
        ))
        .bind(&subject_reference)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

        let mut live_ids = Vec::with_capacity(matching_ids.len());
        let mut withheld = 0i64;
        for record_id in matching_ids {
            if attome_core::legal_hold::record_is_held(
                &state.base.db,
                &scope.entity_logicalname,
                record_id,
            )
            .await?
            .is_some()
            {
                withheld += 1;
            } else {
                live_ids.push(record_id);
            }
        }

        let object_key = format!(
            "dsr-exports/{}/{request_id}/{}.ndjson",
            kind.request_type(),
            scope.entity_logicalname
        );
        let path = ObjectPath::parse(&object_key)
            .map_err(|e| AppError::internal(format!("invalid DSR export object key: {e}")))?;

        let (exported_rows, checksum) = if live_ids.is_empty() {
            // Every match withheld, or none matched — still a valid result,
            // not a skipped scope: the caller must see zero rows explicitly.
            (0i64, String::new())
        } else {
            let columns =
                crate::retention::export_columns(&state.base.db, &scope.entity_logicalname).await?;
            let select_expr = crate::retention::masked_select_expr(&columns);
            let sql = format!(
                "SELECT row_to_json(t)::text FROM (SELECT {select_expr} FROM {table} \
                 WHERE id = ANY($1) ORDER BY id) t"
            );
            let rows = sqlx::query_scalar::<_, String>(&sql)
                .bind(&live_ids)
                .fetch(&state.base.db);
            crate::retention::stream_masked_export_to_store(
                rows,
                state.base.storage.store_arc(),
                path.clone(),
            )
            .await?
        };

        if exported_rows > 0
            && !crate::retention::verify_uploaded_checksum(
                state.base.storage.store(),
                &path,
                &checksum,
            )
            .await?
        {
            return Err(AppError::internal(format!(
                "DSR export checksum mismatch after upload for {object_key}"
            )));
        }

        results.push(ScopeExportResult {
            entity_logicalname: scope.entity_logicalname.clone(),
            object_key,
            checksum,
            exported_rows,
            withheld_for_legal_hold: withheld,
        });
    }

    for supplement in supplements {
        results.push(export_supplement(state, kind, request_id, supplement).await?);
    }
    results.push(export_subject_memories(state, kind, request_id, &subject_reference).await?);

    let evidence_ref = serde_json::to_string(&results).map_err(AppError::internal)?;
    let exported_rows: i64 = results.iter().map(|r| r.exported_rows).sum();
    // D-541 rule 7: a data-subject export is `Security` + `Export`, written in
    // the transaction that marks the request fulfilled (D-062). The object
    // uploads above happen before it, so no transaction spans external I/O;
    // a failed event leaves the request pending and the request fails.
    let mut tx = SecurityTx::begin(
        state,
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Export,
            actor,
            "dsr_request",
            Some(request_id),
        )
        .named(format!("dsr_{}_export", kind.request_type()))
        .comment(format!(
            "{} export fulfilled: {} scope file(s), {exported_rows} row(s)",
            kind.request_type(),
            results.len()
        )),
    )
    .await?;
    let fulfilled = sqlx::query(
        "UPDATE dsr_request SET status = 'fulfilled', fulfilled_at = NOW(), \
                evidence_ref = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1 AND status = 'pending'",
    )
    .bind(request_id)
    .bind(&evidence_ref)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if fulfilled != 1 {
        return Err(AppError::Conflict(
            "this request was fulfilled or changed concurrently",
        ));
    }
    tx.commit().await?;

    Ok(FulfillExportResult {
        id: request_id,
        status: "fulfilled".to_string(),
        scopes: results,
    })
}

/// `POST /api/v1/admin/dsr/requests/{id}/fulfill-access` — `system.admin` only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dsr/requests/{id}/fulfill-access",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Export)])))),
    request_body = FulfillExportBody,
    responses(
        (status = 200, description = "Success", body = FulfillExportResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn fulfill_access(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<FulfillExportBody>,
) -> Result<Json<FulfillExportResult>, AppError> {
    let result = do_fulfill_export(&state, id, ExportKind::Access, body, &[], ctx.user_id).await?;
    Ok(Json(result))
}

/// `POST /api/v1/admin/dsr/requests/{id}/fulfill-portability` — `system.admin` only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dsr/requests/{id}/fulfill-portability",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Export)])))),
    request_body = FulfillExportBody,
    responses(
        (status = 200, description = "Success", body = FulfillExportResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn fulfill_portability(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<FulfillExportBody>,
) -> Result<Json<FulfillExportResult>, AppError> {
    let result =
        do_fulfill_export(&state, id, ExportKind::Portability, body, &[], ctx.user_id).await?;
    Ok(Json(result))
}

// ── Erasure fulfillment ─────────────────────────────────────────────────────

#[derive(Deserialize, ToSchema)]
struct FulfillErasureBody {
    scopes: Vec<DsrScope>,
}

#[derive(Serialize)]
struct ErasedRecord {
    entity_logicalname: String,
    record_id: Uuid,
    key_destroyed: bool,
}

#[derive(Serialize)]
pub struct FulfillErasureResult {
    id: Uuid,
    status: String,
    block_reason: Option<String>,
    erased: Vec<ErasedRecord>,
    /// M24/D-428 — count of `audit_consent` withdrawal rows appended for this
    /// subject. Always 0 on a `blocked` result (nothing is written, same
    /// all-or-nothing posture as `erased`).
    consents_withdrawn: i64,
    /// M35/D-451 — count of `memory` rows deleted for this subject.
    /// Always 0 on a `blocked` result, and also 0 when `subject_reference`
    /// does not resolve to a known `user_account` (most DSR subjects
    /// are named by an entity attribute, not necessarily a platform user) —
    /// same unconditional-but-often-a-no-op shape as `consents_withdrawn`.
    memories_deleted: i64,
}

impl std::fmt::Debug for FulfillErasureResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FulfillErasureResult")
            .finish_non_exhaustive()
    }
}

#[derive(sqlx::FromRow)]
struct LatestConsent {
    purpose_ref: Uuid,
    status: String,
    regarding_entity: Option<String>,
    regarding_id: Option<String>,
}

/// M24/D-428: appends a withdrawal row for every one of `subject_reference`'s
/// currently `granted` consent purposes — "currently granted" meaning the
/// most recent `audit_consent` row per `purpose_ref` (by `created_at`) has
/// `status = 'granted'`, same decision `attome-notification`'s consent gate
/// makes. Deliberately does NOT touch (let alone crypto-shred) the ledger
/// rows themselves: the evidentiary value of "a grant happened and was
/// later withdrawn" is exactly what a privacy-erasure request must
/// preserve, not destroy — see D-428.
async fn withdraw_consents_for_subject(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    subject_reference: &str,
    dsr_request_id: Uuid,
) -> Result<i64, AppError> {
    let latest: Vec<LatestConsent> = sqlx::query_as(
        "SELECT DISTINCT ON (purpose_ref) purpose_ref, status, regarding_entity, regarding_id \
         FROM audit_consent WHERE subject_reference = $1 \
         ORDER BY purpose_ref, created_at DESC",
    )
    .bind(subject_reference)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;

    let mut withdrawn = 0i64;
    for row in latest {
        if row.status != "granted" {
            continue;
        }
        let evidence = format!("withdrawn via DSR erasure request {dsr_request_id}");
        sqlx::query(
            "INSERT INTO audit_consent \
                 (purpose_ref, regarding_entity, regarding_id, subject_reference, status, \
                  withdrawn_at, source, evidence) \
             VALUES ($1, $2, $3, $4, 'withdrawn', NOW(), 'api', $5)",
        )
        .bind(row.purpose_ref)
        .bind(&row.regarding_entity)
        .bind(&row.regarding_id)
        .bind(subject_reference)
        .bind(&evidence)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        withdrawn += 1;
    }
    Ok(withdrawn)
}

#[derive(Serialize)]
struct FulfillErasurePending {
    approval_pending: bool,
    approval_request_id: Uuid,
}

/// `POST /api/v1/admin/dsr/requests/{id}/fulfill-erasure` — `system.admin`
/// only. D-195: gated behind `approval.required_actions` via
/// `ACTION_DSR_FULFILL_ERASURE` (empty/off by default, same opt-in shape as
/// every other wired action — see `erasure_admin::erase_record` for the
/// identical pattern this mirrors). When gated, submits an approval request
/// instead of erasing anything and returns `202` with `approval_pending: true`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/dsr/requests/{id}/fulfill-erasure",
    tag = "admin",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Erasure)])))),
    request_body = FulfillErasureBody,
    responses(
        (status = 200, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn fulfill_erasure(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<FulfillErasureBody>,
) -> Result<Response, AppError> {
    if body.scopes.is_empty() {
        return Err(AppError::Validation("scopes must not be empty".into()));
    }

    if let Some(request) = attome_audit::approval::gate(
        &state,
        ACTION_DSR_FULFILL_ERASURE,
        serde_json::json!({ "request_id": id, "scopes": body.scopes }),
        ctx.user_id,
    )
    .await?
    {
        return Ok((
            StatusCode::ACCEPTED,
            Json(FulfillErasurePending {
                approval_pending: true,
                approval_request_id: request.id,
            }),
        )
            .into_response());
    }

    let result = do_fulfill_erasure(&state, ctx.user_id, id, body.scopes).await?;
    Ok(Json(result).into_response())
}

/// The real mutation, factored out so `fulfill_erasure` (the direct, un-gated
/// path) and `approval_admin::execute_approved` (the approved-and-executed
/// path) call the exact same code — one execution path per action, same
/// convention `erasure_admin::do_erase_record` established.
pub async fn do_fulfill_erasure(
    state: &EngineState,
    actor_id: Uuid,
    id: Uuid,
    scopes: Vec<DsrScope>,
) -> Result<FulfillErasureResult, AppError> {
    let subject_reference: Option<String> = sqlx::query_scalar(
        "SELECT subject_reference FROM dsr_request \
          WHERE id = $1 AND request_type = 'erasure' AND status = 'pending' AND is_deleted = false",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let subject_reference = subject_reference.ok_or(AppError::Conflict(
        "DSR request was not found, is not a pending erasure request, or already actioned",
    ))?;

    let registry = state.entities.load();

    // Resolve every scope's matching live record ids first — erasure is
    // all-or-nothing per request (plan §3: "a DSR erasure request cannot
    // force through a hold"), so nothing is destroyed until every candidate
    // record has been checked.
    let mut plan: Vec<(String, Uuid)> = Vec::new();
    for scope in &scopes {
        let meta = registry.get(&scope.entity_logicalname).ok_or_else(|| {
            AppError::Validation(format!("unknown entity: {}", scope.entity_logicalname))
        })?;
        if !meta
            .attrs
            .iter()
            .any(|a| a.logicalname == scope.match_attribute)
        {
            return Err(AppError::Validation(format!(
                "{} is not a registered attribute of {}",
                scope.match_attribute, scope.entity_logicalname
            )));
        }

        let table = quote_ident(&scope.entity_logicalname);
        let match_col = quote_ident(&scope.match_attribute);
        // Generic CRUD's live predicate for a provisioned entity table
        // (`entity_crud/mutations.rs`); an append-only table has no
        // soft-delete lifecycle and no `is_active` column at all
        // (`provision/table.rs::ensure_is_active`), so it gets none.
        let live = if meta.is_append_only {
            ""
        } else {
            " AND is_active = true"
        };
        let ids: Vec<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {table} WHERE {match_col} = $1{live}"
        ))
        .bind(&subject_reference)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        plan.extend(
            ids.into_iter()
                .map(|record_id| (scope.entity_logicalname.clone(), record_id)),
        );
    }

    if plan.is_empty() {
        // M24/D-428: an erasure request naming only audit_consent-adjacent
        // scopes (or none at all) can still be meaningful work — withdrawing
        // every currently granted consent, below — so only fail here when
        // there is truly nothing to do either way.
        let has_active_consents: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM ( \
                     SELECT DISTINCT ON (purpose_ref) status FROM audit_consent \
                      WHERE subject_reference = $1 \
                      ORDER BY purpose_ref, created_at DESC \
                 ) latest WHERE latest.status = 'granted' \
             )",
        )
        .bind(&subject_reference)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        if !has_active_consents {
            return Err(AppError::Conflict(
                "no records matched this request's scopes and no active consents exist to \
                 withdraw — nothing to erase",
            ));
        }
    }

    for (entity_logicalname, record_id) in &plan {
        if let Some(hold) =
            attome_core::legal_hold::record_is_held(&state.base.db, entity_logicalname, *record_id)
                .await?
        {
            let block_reason = format!(
                "record {record_id} in {entity_logicalname} is under legal hold (matter: {})",
                hold.matter_reference
            );
            let mut tx = SecurityTx::begin(
                state,
                SecurityEvent::new(
                    MandatoryCategory::Security,
                    AuditOperation::Erasure,
                    actor_id,
                    "dsr_request",
                    Some(id),
                )
                .named("dsr_erasure_blocked")
                .outcome(attome_audit::AuditOutcome::Failed)
                .comment(block_reason.clone()),
            )
            .await?;
            sqlx::query(
                "UPDATE dsr_request SET status = 'blocked', block_reason = $2, \
                        updated_at = NOW(), row_version = row_version + 1 WHERE id = $1",
            )
            .bind(id)
            .bind(&block_reason)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            tx.commit().await?;

            return Ok(FulfillErasureResult {
                id,
                status: "blocked".to_string(),
                block_reason: Some(block_reason),
                erased: vec![],
                consents_withdrawn: 0,
                memories_deleted: 0,
            });
        }
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let (user_ctx, organization_ref) = attome_audit::fetch_audit_ctx(state, actor_id).await;
    let audit_service = AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone());

    let mut erased = Vec::with_capacity(plan.len());
    for (entity_logicalname, record_id) in &plan {
        let key_destroyed =
            attome_audit::destroy_key(&mut tx, entity_logicalname, *record_id, actor_id).await?;
        // D-788 rule 9 / security review L6: the subject's record values in
        // the 30-day recovery archive are erased with it, in the same
        // transaction (as the direct erasure route does).
        let archived_erased =
            attome_core::recovery_archive::erase_record(&mut tx, entity_logicalname, *record_id)
                .await?;
        if archived_erased > 0 {
            tracing::info!(record_id = %record_id, archived_erased,
                "DSR erasure: recovery-archive values deleted");
        }
        // Solution 7 Phase 2 design §9.3: release-report conflict items seal
        // the record's values (theirs and ours) and its business key, and the
        // record baseline hashes them; both go with the subject, in the same
        // transaction.
        let report_erased =
            attome_core::release_report::erase_record(&mut tx, entity_logicalname, *record_id)
                .await?;
        if report_erased > 0 {
            tracing::info!(record_id = %record_id, report_erased,
                "DSR erasure: release-report conflict items deleted");
        }

        let event = AuditEvent {
            organization_ref,
            category: AuditCategory::Security,
            entity_name: Some(entity_logicalname.clone()),
            record_id: Some(*record_id),
            operation: AuditOperation::Erasure,
            version_before: None,
            version_after: None,
            user_context: user_ctx.clone(),
            changed_on: Utc::now(),
            source: AuditSource::Api,
            request_context: AuditRequestContext::default(),
            correlation_id: None,
            batch_id: None,
            event_name: Some("dsr_erasure".to_string()),
            event_comment: Some(format!(
                "crypto-shredding key destroyed for {entity_logicalname}/{record_id} via DSR \
                 request {id} (D-107/P-data-protection-governance)"
            )),
            changed_fields: vec![],
            snapshot_json: None,
        };
        audit_service.write_in_tx(&mut tx, event).await?;

        erased.push(ErasedRecord {
            entity_logicalname: entity_logicalname.clone(),
            record_id: *record_id,
            key_destroyed,
        });
    }

    // M24/D-428: withdraw every currently `granted` consent this subject
    // holds — appending a new row each time, never touching the row that
    // recorded the grant (see that function's own doc comment for why this
    // does NOT crypto-shred audit_consent itself, unlike the caller-named
    // `scopes` above).
    let consents_withdrawn = withdraw_consents_for_subject(&mut tx, &subject_reference, id).await?;

    // M35/D-451: memory is per-principal (`owner_principal`), never named by
    // the caller-supplied `scopes` (those name entities, and `memory`
    // is an infra table, not a provisioned entity) — so this is an
    // unconditional step, same shape as `withdraw_consents_for_subject`
    // above. Most DSR subjects are named by an arbitrary entity attribute
    // (frequently, but not always, an email), so resolution is best-effort:
    // a `subject_reference` that doesn't match a known
    // `user_account.email` simply deletes nothing, the same
    // "unconditional but often a no-op" shape consent withdrawal already has
    // for a subject with no consent rows.
    let memories_deleted = match memory_owner_for_subject(&mut *tx, &subject_reference).await? {
        Some(owner_principal) => attome_search::erase_for_subject(&mut tx, owner_principal).await?,
        None => 0,
    };

    let evidence_ref = serde_json::to_string(&erased).map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE dsr_request SET status = 'fulfilled', fulfilled_at = NOW(), \
                evidence_ref = $2, updated_at = NOW(), row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(id)
    .bind(&evidence_ref)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // The request-level summary: per-record `dsr_erasure` events above exist
    // only when a scope matched a record; this one exists for every
    // fulfilment, including a consent- or memory-only one.
    attome_audit::security::write_security_event(
        &mut tx,
        &audit_service,
        SecurityEvent::new(
            MandatoryCategory::Security,
            AuditOperation::Erasure,
            actor_id,
            "dsr_request",
            Some(id),
        )
        .named("dsr_erasure_fulfilled")
        .outcome(attome_audit::AuditOutcome::Succeeded)
        .comment(format!(
            "{} record key(s) destroyed, {consents_withdrawn} consent(s) withdrawn, \
             {memories_deleted} memorie(s) deleted",
            erased.len()
        )),
    )
    .await?;

    tx.commit().await.map_err(AppError::internal)?;

    Ok(FulfillErasureResult {
        id,
        status: "fulfilled".to_string(),
        block_reason: None,
        erased,
        consents_withdrawn,
        memories_deleted,
    })
}

/// M35/D-451 — resolves a DSR `subject_reference` to a memory owner's user
/// id via `user_account.email`, the same case-insensitive match
/// `idx_core_systemuser_lower_email` (migration `0000`) exists to serve.
/// `None` when the subject isn't a known platform user — see
/// `FulfillErasureResult::memories_deleted`'s doc comment for why that's a
/// normal, expected outcome rather than an error.
async fn memory_owner_for_subject<'e, E>(
    db: E,
    subject_reference: &str,
) -> Result<Option<Uuid>, AppError>
where
    E: sqlx::PgExecutor<'e>,
{
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM user_account WHERE lower(email) = lower($1)")
            .bind(subject_reference)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    Ok(owner)
}

/// The name the memory export is reported under in `FulfillExportResult::
/// scopes` and in its object key — the infra table's own name, the same way
/// the consent history is reported under `audit_consent`.
const MEMORY_EXPORT_SCOPE: &str = "memory";

/// P-data-protection-governance §4 cross-border transfer gate for one export
/// scope. A no-op when `deployment.data_region` is unset (no residency claim
/// configured).
fn check_export_transfer(
    state: &EngineState,
    classification: DataClassification,
    scope_name: &str,
    request_id: Uuid,
    actor: Uuid,
    admin_override: bool,
) -> Result<(), AppError> {
    let Some(deployment_region) = state.base.config.deployment.data_region.as_deref() else {
        return Ok(());
    };
    match attome_core::assert_transfer_allowed(
        classification,
        &state.base.config.storage.s3_region,
        deployment_region,
        admin_override,
    ) {
        TransferDecision::Blocked => Err(AppError::Conflict(
            "export destination region does not match the deployment's declared \
             data_region for restricted data — set admin_override to proceed \
             (P-data-protection-governance)",
        )),
        TransferDecision::AllowedWithOverride => {
            tracing::warn!(
                entity = %scope_name,
                request_id = %request_id,
                actor = %actor,
                "DSR export proceeding cross-region under an explicit admin override"
            );
            Ok(())
        }
        TransferDecision::Allowed => Ok(()),
    }
}

/// M35 v1 Track A (M24/D-428): the subject's `memory` rows, exported
/// unconditionally alongside the caller-named scopes. Memory is per-principal
/// (D-451) and lives in an infra table, so no `DsrScope` can name it — the
/// same reason erasure runs `erase_for_subject` as its own step. The subject
/// resolves to a memory owner exactly as erasure resolves it
/// (`memory_owner_for_subject`); a subject who is not a platform user owns no
/// memory and gets an explicit zero-row scope, never a skipped one. Legal
/// holds attach to entity records, so nothing here is withheld. The caller
/// runs this scope's transfer gate before any upload.
async fn export_subject_memories(
    state: &EngineState,
    kind: ExportKind,
    request_id: Uuid,
    subject_reference: &str,
) -> Result<ScopeExportResult, AppError> {
    let object_key = format!(
        "dsr-exports/{}/{request_id}/{MEMORY_EXPORT_SCOPE}.ndjson",
        kind.request_type()
    );
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid DSR export object key: {e}")))?;

    let (exported_rows, checksum) =
        match memory_owner_for_subject(&state.base.db, subject_reference).await? {
            None => (0i64, String::new()),
            Some(owner_principal) => {
                let rows = sqlx::query_scalar::<_, String>(
                    attome_search::corpus::memory::MEMORY_EXPORT_SQL,
                )
                .bind(owner_principal)
                .fetch(&state.base.db);
                crate::retention::stream_masked_export_to_store(
                    rows,
                    state.base.storage.store_arc(),
                    path.clone(),
                )
                .await?
            }
        };

    if exported_rows > 0
        && !crate::retention::verify_uploaded_checksum(state.base.storage.store(), &path, &checksum)
            .await?
    {
        return Err(AppError::internal(format!(
            "DSR export checksum mismatch after upload for {object_key}"
        )));
    }

    Ok(ScopeExportResult {
        entity_logicalname: MEMORY_EXPORT_SCOPE.to_string(),
        object_key,
        checksum,
        exported_rows,
        withheld_for_legal_hold: 0,
    })
}

/// One [`DsrSupplement`], exported like [`export_subject_memories`].
async fn export_supplement(
    state: &EngineState,
    kind: ExportKind,
    request_id: Uuid,
    supplement: &DsrSupplement,
) -> Result<ScopeExportResult, AppError> {
    let object_key = format!(
        "dsr-exports/{}/{request_id}/{}.ndjson",
        kind.request_type(),
        supplement.name
    );
    let path = ObjectPath::parse(&object_key)
        .map_err(|e| AppError::internal(format!("invalid DSR export object key: {e}")))?;
    let (exported_rows, checksum) = if supplement.rows.is_empty() {
        (0i64, String::new())
    } else {
        let rows = futures_util::stream::iter(
            supplement
                .rows
                .iter()
                .cloned()
                .map(Ok::<String, sqlx::Error>),
        );
        crate::retention::stream_masked_export_to_store(
            rows,
            state.base.storage.store_arc(),
            path.clone(),
        )
        .await?
    };
    if exported_rows > 0
        && !crate::retention::verify_uploaded_checksum(state.base.storage.store(), &path, &checksum)
            .await?
    {
        return Err(AppError::internal(format!(
            "DSR export checksum mismatch after upload for {object_key}"
        )));
    }
    Ok(ScopeExportResult {
        entity_logicalname: supplement.name.clone(),
        object_key,
        checksum,
        exported_rows,
        withheld_for_legal_hold: 0,
    })
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/dsr/requests",
            get(list_requests).post(create_request),
        )
        .route(
            "/api/v1/admin/dsr/requests/{id}/fulfill-access",
            post(fulfill_access),
        )
        .route(
            "/api/v1/admin/dsr/requests/{id}/fulfill-portability",
            post(fulfill_portability),
        )
        .route(
            "/api/v1/admin/dsr/requests/{id}/fulfill-erasure",
            post(fulfill_erasure),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(
    list_requests,
    create_request,
    fulfill_access,
    fulfill_portability,
    fulfill_erasure
))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
