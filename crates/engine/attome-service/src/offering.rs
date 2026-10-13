//! Service Offering (M70 target design §3, D-423) — the catalog unit an
//! admin configures and a requester picks from. `create_work_request_from_offering`
//! is the sanctioned, additional path for creating a work request that
//! inherits an offering's defaults (priority, SLA policy, the M84 queue
//! placeholder). Same shape `license_admin.rs` documents for
//! `license`: ordinary generic-entity CREATE on `service_work_request`
//! remains reachable for staff who aren't starting from a catalog item —
//! this route is layered beside it, not a replacement for it.
use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_records::entity_mutation::{CreateStamp, MutationMode, Principal, create_one_as};
use attome_records::mutation_ring::MutationActor;
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{OfferingRead, WorkRequestCreate};
use crate::intake::{IntakeEntity, audit_entity_write, put_opt};
use crate::{routing, token};

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct OfferingSummary {
    pub id: Uuid,
    pub name: String,
    pub category: Option<String>,
    pub description: Option<String>,
    pub default_priority: String,
    pub fulfilment: String,
}

#[derive(sqlx::FromRow)]
struct OfferingRow {
    id: Uuid,
    category: Option<String>,
    default_priority: String,
    default_queue_ref: Option<String>,
    default_sla_policy_id: Option<Uuid>,
}

/// Loads an active offering by id — `AppError::NotFound` for a missing,
/// inactive, or deleted row (the offering's own `is_active` flag doubles as
/// the soft-delete predicate).
async fn load_active_offering(db: &DbPool, offering_id: Uuid) -> Result<OfferingRow, AppError> {
    sqlx::query_as::<_, OfferingRow>(
        "SELECT id, category, default_priority, default_queue_ref, default_sla_policy_id \
         FROM service_offering \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(offering_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWorkRequestFromOfferingRequest {
    pub title: String,
    pub description: Option<String>,
    /// `project_request | change_request | issue_report | it_request |
    /// hr_request | access_request | custom` — the same `service_work_request
    /// .request_type` choice set. Not derived from the offering: an offering
    /// can plausibly back more than one request type, so the caller states
    /// it explicitly, the same "don't guess a product decision" reasoning
    /// `convert.rs`'s required parent lookups already apply.
    pub request_type: String,
    /// The `user_account` this request is filed on behalf of — the
    /// caller's choice, made explicit, same reasoning as `convert.rs`'s
    /// `project_id`/`organization_id` fields.
    pub requester_id: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateWorkRequestFromOfferingResponse {
    pub work_request_id: Uuid,
    pub status: String,
    /// The self-service portal bearer token (`{public_id}.{secret}`) —
    /// returned exactly once, here. Only its argon2 hash is persisted
    /// (`service_work_request.portal_secret_hash`); this response is the only
    /// place the raw secret ever exists.
    pub portal_token: String,
}

/// The actual creation — loads the offering, evaluates routing, mints a
/// portal token, and creates the work request through the entity engine
/// (`entity_mutation::create_one_as`, M70 Phase 1): validation, lookup
/// liveness (requester, offering, SLA policy), default/calculation/formula
/// rules, the state model's initial state and the change-feed row all apply,
/// exactly as for a generic `POST /api/v1/service_work_request`. The
/// creator share, the `Entity` audit event and the route's business event
/// are written in the same transaction.
///
/// Checks `service_work_request.create` itself (the HTTP route's
/// extractor checks it too), so a non-HTTP caller cannot skip it. `pub` so
/// this crate's integration tests exercise it directly; the thin handler
/// below only shapes the response.
pub async fn create_work_request_from_offering(
    state: &EngineState,
    ctx: &SecurityContext,
    offering_id: Uuid,
    body: CreateWorkRequestFromOfferingRequest,
    ring: &attome_auth::PepperRing,
) -> Result<CreateWorkRequestFromOfferingResponse, AppError> {
    ctx.require_key(WorkRequestCreate::KEY)?;
    let db = &state.base.db;
    let offering = load_active_offering(db, offering_id).await?;

    // M45 Phase 3 (REVIEW-2026-09-02 finding #8): `evaluate_routing` now
    // queries live `kind = 'routing'` rules — see `routing.rs`'s module doc
    // for exactly what a matched rule can and cannot override (`queue_ref`
    // only, v1 scope). `None` when no configured rule matches, same as
    // before.
    let routing_ctx = routing::RoutingContext {
        request_type: &body.request_type,
        category: offering.category.as_deref(),
    };
    let decision = routing::evaluate_routing(db, &routing_ctx).await?;
    let effective = routing::resolve_effective_defaults(
        decision.as_ref(),
        &offering.default_priority,
        offering.default_queue_ref.as_deref(),
        offering.default_sla_policy_id,
    );

    // Argon2/HMAC work and every pool read happen before the transaction
    // opens (guidelines §4: no external I/O inside a transaction).
    let issued = token::issue(ring).await?;
    let entity = IntakeEntity::resolve(state, "service_work_request").await?;
    let actor = MutationActor::fetch(state, ctx.user_id).await;

    let mut record = Map::new();
    record.insert("title".into(), Value::String(body.title.clone()));
    put_opt(&mut record, "description", body.description.clone());
    record.insert(
        "request_type".into(),
        Value::String(body.request_type.clone()),
    );
    record.insert(
        "requester_id".into(),
        Value::String(body.requester_id.to_string()),
    );
    record.insert("status".into(), Value::String("new".into()));
    record.insert("offering_id".into(), Value::String(offering.id.to_string()));
    record.insert("priority".into(), Value::String(effective.priority.clone()));
    put_opt(&mut record, "queue_ref", effective.queue_ref.clone());
    put_opt(
        &mut record,
        "sla_policy_id",
        effective.sla_policy_ref.map(|id| id.to_string()),
    );

    let mut tx = attome_db::tx::begin(db).await?;
    let created = create_one_as(
        &mut tx,
        state,
        Principal::Staff(ctx),
        &entity.name,
        &entity.attrs,
        &record,
        CreateStamp::staff(ctx.user_id, actor.org_ref),
        MutationMode::Strict,
    )
    .await?;
    let work_request_id = created.record_id;

    // The portal credential is minted by this route, never supplied by the
    // caller: `portal_public_id`/`portal_secret_hash` are `is_sensitive`
    // attributes, so passing them through `create_one_as` would demand a
    // field-write grant the requester has no reason to hold (and holding one
    // would let them overwrite the hash through generic PATCH). So the engine
    // creates the record and this one scoped statement stamps the two
    // engine-minted columns on the row just inserted, in the same
    // transaction — the same "a value the engine cannot bind" shape
    // `attome-api::communication`'s `thread_id` backfill uses. Nothing a
    // rule, formula or audit diff should see lives in these two columns.
    let stamped = sqlx::query(
        "UPDATE service_work_request \
         SET portal_public_id = $2, portal_secret_hash = $3 WHERE id = $1",
    )
    .bind(work_request_id)
    .bind(issued.public_id.to_string())
    .bind(&issued.secret_hash)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if stamped.rows_affected() != 1 {
        return Err(AppError::internal(
            "work request row vanished between create and token stamp",
        ));
    }

    attome_records::entity_crud::grant_creator_share(
        &mut tx,
        entity.id,
        work_request_id,
        ctx.user_id,
    )
    .await?;
    audit_entity_write(
        &mut tx,
        state,
        &actor,
        &entity,
        &created,
        AuditOperation::Create,
        &record,
        "work_request.create_from_offering",
    )
    .await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            entity.name.as_str(),
            work_request_id,
            AuditOperation::Create,
            "work_request.create_from_offering",
            ctx.user_id,
        )
        .comment(format!("created from service offering {offering_id}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    attome_records::rw_pin::pin_write_with_current_lsn(
        state,
        ctx.user_id,
        "create work request from offering",
    )
    .await;

    // "audit which rule routed" (target design §3). Storing the matched rule
    // on the record is M70 Phase 2.
    if let Some(decision) = &decision {
        tracing::info!(
            work_request_id = %work_request_id,
            rule_id = %decision.matched_rule_id,
            "work request routed by rule"
        );
    }

    Ok(CreateWorkRequestFromOfferingResponse {
        work_request_id,
        status: "new".to_owned(),
        portal_token: issued.bearer,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/service-offering/active",
    tag = "service",
    responses(
        (status = 200, description = "Success", body = Vec<OfferingSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_active_offerings(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<OfferingRead>>,
) -> Result<Json<Vec<OfferingSummary>>, AppError> {
    let rows = sqlx::query_as::<_, OfferingSummary>(
        "SELECT id, name, category, description, default_priority, fulfilment \
         FROM service_offering \
         WHERE (is_active IS NULL OR is_active = true) \
         ORDER BY name",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(rows))
}

#[utoipa::path(
    post,
    path = "/api/v1/service-offering/{id}/create-work-request",
    tag = "service",
    params(("id" = Uuid, Path)),
    request_body = CreateWorkRequestFromOfferingRequest,
    responses(
        (status = 201, description = "Success", body = CreateWorkRequestFromOfferingResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active offering", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create),
        (attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create),
    ])))),
)]
async fn create_work_request(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<WorkRequestCreate>>,
    Path(offering_id): Path<Uuid>,
    Json(body): Json<CreateWorkRequestFromOfferingRequest>,
) -> Result<(StatusCode, Json<CreateWorkRequestFromOfferingResponse>), AppError> {
    let response = create_work_request_from_offering(
        &state,
        &ctx,
        offering_id,
        body,
        &state.base.pepper_ring(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(response)))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/service-offering/active",
            get(list_active_offerings),
        )
        .route(
            "/api/v1/service-offering/{id}/create-work-request",
            post(create_work_request),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI
/// document; merged by this crate's own `openapi()`.
#[derive(utoipa::OpenApi)]
#[openapi(paths(list_active_offerings, create_work_request))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
