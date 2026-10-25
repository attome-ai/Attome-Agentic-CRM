//! M14-T1: builder-defined inbound endpoints.
//!
//! Administrators define hooks under `/api/v1/admin/inbound-hooks`
//! (`inbound_hook`, migration 0217); each create, change and removal is a
//! Configuration event in the same transaction. The secret is sealed under
//! the integration credential key and never returned (only its last four
//! characters). A provider calls `POST /api/v1/hooks/{name}`, which is
//! public and bypass-listed by its exact one-segment shape; the hook's own
//! checks are the credential:
//!
//! 1. the hook is active (else 404);
//! 2. the caller's address is in `ip_allow`, and with `require_mtls` the
//!    TLS edge verified its certificate (else 403);
//! 3. the signature or bearer secret checks out, and a signed timestamp is
//!    in its window (else 401), `attome_integration::inbound::verify`;
//! 4. the body is JSON carrying `schema.required` (else 422);
//! 5. its event id is claimed for the first time (else 409, a replay).
//!
//! M14-T3: the call is acknowledged fast. The event is written to the hook's
//! inbox (`inbound_hook_event`, migration 0218, unique by hook and event
//! id) with a job ([`PROCESS_JOB`]) in the same transaction, and the
//! answer is 202 at once. A delivery whose event id is already in the inbox
//! is acknowledged as a duplicate and not processed again. The job runs the
//! handler as the hook's `run_as` service user, through the ordinary paths,
//! so rules, record security and audit apply:
//! `{"type": "record", "entity": "...", "fields": {"attr": "/json/pointer"}}`
//! creates a record from the body; `{"type": "flow", "definition_id": "..."}`
//! starts the flow's published version with the body as context.
//!
//! M14-T4 (`attome_integration::inbound_handlers`): a record handler with a
//! `key` attribute (an external id) upserts: the live record holding the
//! event's key value is updated through the generic update path, with its
//! current row version, and a record is created only when none holds it.
//! Set the hook's `ordering_key` to the same field so two events of one key
//! never race to create it. An `events` handler routes by the event type at
//! its `event_type` pointer to a record or flow handler (or its `default`);
//! an event of an unrouted type is done and ignored.
//!
//! With an `ordering_key` (a JSON pointer into the body), events of one key
//! are processed strictly in the order they arrived: a job claims the
//! key's oldest waiting event, under a short advisory lock held only while it
//! claims, and works through the key's queue. An event of the key still
//! being processed holds the others back. An event that fails is retried by
//! the job, and after [`MAX_ATTEMPTS`] it is marked failed, stops holding
//! its key back, and its job is in the dead-letter inbox (M5), where a
//! replay starts it again.

use std::net::SocketAddr;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent};
use attome_core::EngineState;
use attome_integration::inbound;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, Query, Request, State},
    http::StatusCode,
    routing::{get, patch, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::ToSchema;
use uuid::Uuid;

/// The largest body a hook reads.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// M14-T3: the registered job type that processes one inbox event
/// (payload [`ProcessEvent`]).
pub const PROCESS_JOB: &str = "inbound_hook_process";

/// M14-T3: tries before an event is marked failed; the job type's own
/// attempt budget is the same.
pub const MAX_ATTEMPTS: i32 = 5;

/// How long an event may sit in `processing` before a later job takes it
/// over (its worker died).
const PROCESSING_LEASE_MINUTES: i32 = 10;

/// M14-T3: the job payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    pub event_id: Uuid,
}

/// One inbound hook, as administrators see it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct InboundHookView {
    pub id: Uuid,
    pub name: String,
    /// `{kind, preset?, header?, encoding?, prefix?, timestamp_header?, id_header?}`.
    #[schema(value_type = Object)]
    pub auth: Value,
    pub ip_allow: Vec<String>,
    pub require_mtls: bool,
    /// `{required: [field, …]}`.
    #[schema(value_type = Object)]
    pub schema: Value,
    #[schema(value_type = Object)]
    pub handler: Value,
    pub run_as: Uuid,
    /// M14-T3: a JSON pointer into the body; events with the same value are
    /// processed in arrival order.
    pub ordering_key: Option<String>,
    pub is_active: bool,
    pub secret_last4: Option<String>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, name, auth, ip_allow, require_mtls, body_schema AS schema, handler, \
                       run_as, ordering_key, is_active, secret_last4, row_version, created_at, \
                       updated_at";

/// A hook's definition.
#[derive(Debug, Deserialize, ToSchema)]
pub struct InboundHookBody {
    pub name: String,
    #[schema(value_type = Object)]
    pub auth: Value,
    /// The shared secret: required to create, a new one rotates it.
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub ip_allow: Vec<String>,
    #[serde(default)]
    pub require_mtls: bool,
    #[serde(default)]
    #[schema(value_type = Object)]
    pub schema: Value,
    #[schema(value_type = Object)]
    pub handler: Value,
    /// The service user the handler runs as.
    pub run_as: Uuid,
    /// M14-T3: a JSON pointer into the body (`/order/id`) whose value orders
    /// processing; none processes events as they come.
    #[serde(default)]
    pub ordering_key: Option<String>,
    #[serde(default = "default_true")]
    pub is_active: bool,
}

/// A change to a hook.
#[derive(Debug, Deserialize, ToSchema)]
pub struct InboundHookUpdate {
    #[serde(flatten)]
    pub body: InboundHookBody,
    pub row_version: i64,
}

fn default_true() -> bool {
    true
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 63
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

fn valid_cidr(entry: &str) -> bool {
    let (net, bits) = match entry.split_once('/') {
        Some((net, bits)) => (net, Some(bits)),
        None => (entry, None),
    };
    match net.trim().parse::<std::net::IpAddr>() {
        Ok(ip) => bits.is_none_or(|b| {
            b.parse::<u32>()
                .is_ok_and(|b| b <= if ip.is_ipv4() { 32 } else { 128 })
        }),
        Err(_) => false,
    }
}

/// Checks a definition: its name, auth, addresses, schema and handler.
async fn check_body(
    state: &EngineState,
    body: &InboundHookBody,
    creating: bool,
) -> Result<(), AppError> {
    if !valid_name(&body.name) {
        return Err(AppError::Validation(
            "name is lower-case letters, digits, _ and -, at most 63 characters".into(),
        ));
    }
    inbound::check_auth(&body.auth).map_err(AppError::Validation)?;
    if body
        .ordering_key
        .as_deref()
        .is_some_and(|p| !p.starts_with('/') || p.len() > 200)
    {
        return Err(AppError::Validation(
            "ordering_key is a JSON pointer such as /order/id".into(),
        ));
    }
    match body.secret.as_deref() {
        Some(secret) if !(8..=4096).contains(&secret.len()) => {
            return Err(AppError::Validation(
                "secret is 8 to 4096 characters".into(),
            ));
        }
        None if creating => return Err(AppError::Validation("secret is required".into())),
        _ => {}
    }
    if body.ip_allow.len() > 100 || !body.ip_allow.iter().all(|e| valid_cidr(e)) {
        return Err(AppError::Validation(
            "ip_allow is at most 100 addresses or CIDRs".into(),
        ));
    }
    let schema_ok = body.schema.is_null()
        || (body.schema.is_object()
            && body.schema.get("required").is_none_or(|r| {
                r.as_array()
                    .is_some_and(|fields| fields.iter().all(Value::is_string))
            }));
    if !schema_ok {
        return Err(AppError::Validation(
            "schema is {\"required\": [field names]}".into(),
        ));
    }
    attome_integration::inbound_handlers::check_shape(&body.handler)
        .map_err(AppError::Validation)?;
    for leaf in attome_integration::inbound_handlers::leaves(&body.handler) {
        check_leaf_targets(state, leaf).await?;
    }
    let active: Option<bool> =
        sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
            .bind(body.run_as)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if active != Some(true) {
        return Err(AppError::Validation("run_as is an active user".into()));
    }
    Ok(())
}

/// A record handler's entity and attributes exist, and a flow handler's
/// flow does (the shape is checked already).
async fn check_leaf_targets(state: &EngineState, leaf: &Value) -> Result<(), AppError> {
    if leaf["type"].as_str() == Some("flow") {
        let id = leaf["definition_id"]
            .as_str()
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| AppError::Validation("a flow handler names definition_id".into()))?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM workflow_definition WHERE id = $1 AND NOT is_deleted)",
        )
        .bind(id)
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        return if exists {
            Ok(())
        } else {
            Err(AppError::Validation("no such flow".into()))
        };
    }
    let entity = leaf["entity"].as_str().unwrap_or_default();
    let registry = state.entities.load();
    let Some(meta) = registry.get(entity) else {
        return Err(AppError::Validation(format!(
            "handler entity {entity:?} is not an entity"
        )));
    };
    for attribute in leaf["fields"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys())
    {
        if !meta.attrs.iter().any(|a| &a.logicalname == attribute) {
            return Err(AppError::Validation(format!(
                "{attribute:?} is not an attribute of {entity}"
            )));
        }
    }
    Ok(())
}

fn schema_of(body: &InboundHookBody) -> Value {
    if body.schema.is_object() {
        body.schema.clone()
    } else {
        Value::Object(Map::new())
    }
}

async fn audit(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    actor: Uuid,
    operation: AuditOperation,
    name: &'static str,
    id: Uuid,
    comment: String,
) -> Result<(), AppError> {
    attome_audit::security::write_security_event(
        tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            operation,
            actor,
            "inbound_hook",
            Some(id),
        )
        .named(name)
        .comment(comment),
    )
    .await
    .map(|_| ())
}

/// List inbound hooks
///
/// List inbound hooks. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/inbound-hooks",
    tag = "admin",
    operation_id = "list_inbound_hooks",
    params(OnePageQuery),
    responses(
        (status = 200, description = "Every inbound hook, by name", body = PaginatedResponse<InboundHookView>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_hooks(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(page): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<InboundHookView>>, AppError> {
    let w = page.window();
    let items: Vec<InboundHookView> = sqlx::query_as(&format!(
        "SELECT {COLUMNS} FROM inbound_hook WHERE NOT is_deleted ORDER BY name, id LIMIT $1 OFFSET $2"
    ))
    .bind(w.page_size)
    .bind(w.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM inbound_hook WHERE NOT is_deleted")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        w.page,
        w.page_size,
    )))
}

/// Create an inbound hook
///
/// Create an inbound hook. Administrators only. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/inbound-hooks",
    tag = "admin",
    operation_id = "create_inbound_hook",
    description = "Defines an inbound endpoint at /api/v1/hooks/{name} (M14-T1): its authentication (hmac with a preset or custom header and encoding, or bearer), address allow-list, mTLS, required body fields, and handler (create or, by a key attribute, upsert a record, or start a flow, as run_as; an events handler routes by event type). The secret is sealed and never returned.",
    request_body = InboundHookBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created", body = InboundHookView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 409, description = "A hook of this name exists", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_hook(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<InboundHookBody>,
) -> Result<(StatusCode, Json<InboundHookView>), AppError> {
    check_body(&state, &body, true).await?;
    let id = Uuid::now_v7();
    let secret = body.secret.as_deref().unwrap_or_default();
    let sealed = inbound::seal_secret(&state, id, secret)?;
    let last4: String = secret
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let view: InboundHookView = sqlx::query_as(&format!(
        "INSERT INTO inbound_hook \
             (id, name, auth, secret_sealed, secret_last4, ip_allow, require_mtls, body_schema, \
              handler, run_as, is_active, created_by, ordering_key) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT DO NOTHING RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(&body.name)
    .bind(&body.auth)
    .bind(&sealed)
    .bind(&last4)
    .bind(&body.ip_allow)
    .bind(body.require_mtls)
    .bind(schema_of(&body))
    .bind(&body.handler)
    .bind(body.run_as)
    .bind(body.is_active)
    .bind(ctx.user_id)
    .bind(&body.ordering_key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::Conflict("an inbound hook of this name exists"))?;
    audit(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Create,
        "inbound_hook.create",
        id,
        format!("inbound hook {} defined", body.name),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((StatusCode::CREATED, Json(view)))
}

/// Update an inbound hook
///
/// Update an inbound hook. Administrators only. Audited.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/inbound-hooks/{id}",
    tag = "admin",
    operation_id = "update_inbound_hook",
    description = "Changes an inbound hook (M14-T1); a new secret rotates it.",
    params(("id" = Uuid, Path)),
    request_body = InboundHookUpdate,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Changed", body = InboundHookView),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such hook", body = ErrorResponse),
        (status = 409, description = "Changed since read, or the name is taken", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_hook(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(update): Json<InboundHookUpdate>,
) -> Result<Json<InboundHookView>, AppError> {
    let body = &update.body;
    check_body(&state, body, false).await?;
    let sealed = body
        .secret
        .as_deref()
        .map(|secret| inbound::seal_secret(&state, id, secret))
        .transpose()?;
    let last4: Option<String> = body.secret.as_deref().map(|s| {
        s.chars()
            .rev()
            .take(4)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    });
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let view: Option<InboundHookView> = sqlx::query_as(&format!(
        "UPDATE inbound_hook SET name = $3, auth = $4, \
                secret_sealed = COALESCE($5, secret_sealed), secret_last4 = COALESCE($6, secret_last4), \
                ip_allow = $7, require_mtls = $8, body_schema = $9, handler = $10, run_as = $11, \
                is_active = $12, ordering_key = $13, row_version = row_version + 1, \
                updated_at = now() \
          WHERE id = $1 AND row_version = $2 AND NOT is_deleted RETURNING {COLUMNS}"
    ))
    .bind(id)
    .bind(update.row_version)
    .bind(&body.name)
    .bind(&body.auth)
    .bind(sealed)
    .bind(last4)
    .bind(&body.ip_allow)
    .bind(body.require_mtls)
    .bind(schema_of(body))
    .bind(&body.handler)
    .bind(body.run_as)
    .bind(body.is_active)
    .bind(&body.ordering_key)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            AppError::Conflict("an inbound hook of this name exists")
        }
        other => AppError::internal(other),
    })?;
    let Some(view) = view else {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM inbound_hook WHERE id = $1 AND NOT is_deleted)",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        return Err(if exists {
            AppError::VersionConflict
        } else {
            AppError::NotFound
        });
    };
    audit(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::Update,
        "inbound_hook.update",
        id,
        format!(
            "inbound hook {} changed{}",
            body.name,
            if body.secret.is_some() {
                ", secret rotated"
            } else {
                ""
            }
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(view))
}

/// Delete an inbound hook
///
/// Delete an inbound hook. Administrators only. Audited.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/inbound-hooks/{id}",
    tag = "admin",
    operation_id = "delete_inbound_hook",
    description = "Removes an inbound hook (M14-T1); its endpoint answers 404 from then on.",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller is not an administrator", body = ErrorResponse),
        (status = 404, description = "No such hook", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_hook(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let name: Option<String> = sqlx::query_scalar(
        "UPDATE inbound_hook SET is_deleted = true, is_active = false, \
                name = name || '#' || id::text, row_version = row_version + 1, updated_at = now() \
          WHERE id = $1 AND NOT is_deleted RETURNING name",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(name) = name else {
        return Err(AppError::NotFound);
    };
    audit(
        &mut tx,
        &state,
        ctx.user_id,
        AuditOperation::SoftDelete,
        "inbound_hook.delete",
        id,
        format!("inbound hook {name} removed"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct LiveHook {
    id: Uuid,
    name: String,
    auth: Value,
    secret_sealed: String,
    ip_allow: Vec<String>,
    require_mtls: bool,
    body_schema: Value,
    handler: Value,
    run_as: Uuid,
    ordering_key: Option<String>,
}

const LIVE_COLUMNS: &str = "id, name, auth, secret_sealed, ip_allow, require_mtls, body_schema, \
                            handler, run_as, ordering_key";

/// What an accepted call did.
#[derive(Debug, Serialize, ToSchema)]
pub struct HookAccepted {
    pub accepted: bool,
    /// The inbox event the call was written to.
    pub event_id: Uuid,
    /// The event id was already in the inbox: acknowledged, not processed
    /// again.
    pub duplicate: bool,
}

/// What a processed event did.
#[derive(Debug, Serialize)]
struct HandlerOutcome {
    record_id: Option<Uuid>,
    instance_id: Option<Uuid>,
    /// M14-T4: a keyed record handler updated the record holding the key.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    updated: bool,
    /// M14-T4: no route took the event's type.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    ignored: bool,
}

/// The ordering value of `payload` at `pointer`, as text.
pub fn ordering_value(pointer: Option<&str>, payload: &Value) -> Option<String> {
    let value = payload.pointer(pointer?)?;
    match value {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => Some(other.to_string()),
    }
    .filter(|v| !v.is_empty())
    .map(|v| v.chars().take(200).collect())
}

/// The record a record handler creates from `payload`.
pub fn record_body(handler: &Value, payload: &Value) -> Map<String, Value> {
    attome_integration::inbound_handlers::record_fields(handler, payload)
}

/// M14-T4: the live record of `entity` holding `value` in `key`.
async fn record_by_key(
    state: &EngineState,
    entity: &str,
    key: &str,
    value: &Value,
) -> Result<Option<Uuid>, AppError> {
    let (_, entity_name, attrs, is_append_only) =
        attome_records::entity_crud::resolve_entity(state, entity).await?;
    let attr = attrs
        .iter()
        .find(|a| a.logicalname == key)
        .ok_or_else(|| AppError::Validation(format!("{key:?} is not an attribute of {entity}")))?;
    let Some(text) = attome_records::entity_mutation::json_to_str(value, attr) else {
        return Err(AppError::Validation(format!(
            "the event's {key} is not a value for that attribute"
        )));
    };
    let live = attome_core::sql_ident::live_row_predicate("t", is_append_only)
        .map(|p| format!(" AND {p}"))
        .unwrap_or_default();
    let sql = format!(
        "SELECT t.id FROM {} t WHERE t.{} = $1{}{live} ORDER BY t.id LIMIT 1",
        attome_core::quote_ident(&entity_name),
        attome_core::quote_ident(&attr.logicalname),
        attome_records::entity_mutation::sql_cast(attr),
    );
    sqlx::query_scalar(&attome_db::tag_dynamic("inbound_hook.upsert", &sql))
        .bind(text)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)
}

async fn run_handler(
    state: &EngineState,
    hook: &LiveHook,
    name: &str,
    payload: Value,
) -> Result<HandlerOutcome, AppError> {
    let ctx = state.base.security.resolve(hook.run_as).await?;
    let Some(handler) = attome_integration::inbound_handlers::select(&hook.handler, &payload)
    else {
        return Ok(HandlerOutcome {
            record_id: None,
            instance_id: None,
            updated: false,
            ignored: true,
        });
    };
    match handler["type"].as_str() {
        Some("record") => {
            let entity = handler["entity"].as_str().unwrap_or_default();
            let body = record_body(handler, &payload);
            let existing = match attome_integration::inbound_handlers::upsert_key(handler, &body)
                .map_err(AppError::Validation)?
            {
                Some((key, value)) => record_by_key(state, entity, key, value).await?,
                None => None,
            };
            if let Some(id) = existing {
                // Read as the service user: a record it may not see is a 404,
                // never a silent second record.
                let current =
                    attome_records::entity_crud::read_record(state, &ctx, entity, id).await?;
                attome_records::entity_crud::update_record_for(
                    state,
                    &ctx,
                    hook.run_as,
                    entity,
                    id,
                    current.row_version(),
                    Value::Object(body),
                )
                .await?;
                return Ok(HandlerOutcome {
                    record_id: Some(id),
                    instance_id: None,
                    updated: true,
                    ignored: false,
                });
            }
            let (record_id, _) = attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                hook.run_as,
                entity,
                Value::Object(body),
            )
            .await?;
            Ok(HandlerOutcome {
                record_id: Some(record_id),
                instance_id: None,
                updated: false,
                ignored: false,
            })
        }
        Some("flow") => {
            let definition = handler["definition_id"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(AppError::NotFound)?;
            let version: Uuid = sqlx::query_scalar(
                "SELECT id FROM workflow_definition_version \
                  WHERE definition_id = $1 AND status = 'published' \
                  ORDER BY published_at DESC NULLS LAST, id DESC LIMIT 1",
            )
            .bind(definition)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?
            .ok_or_else(|| {
                AppError::Validation("the hook's flow has no published version".into())
            })?;
            let instance = attome_workflow::instance_admin::start_instance_internal(
                state,
                version,
                None,
                Some(hook.run_as),
                None,
                serde_json::json!({ "trigger": "hook", "hook": name, "body": payload }),
            )
            .await?;
            Ok(HandlerOutcome {
                record_id: None,
                instance_id: Some(instance),
                updated: false,
                ignored: false,
            })
        }
        _ => Err(AppError::internal("inbound hook has no handler")),
    }
}

/// Receive an inbound hook
///
/// Receive an inbound hook.
#[utoipa::path(
    post,
    path = "/api/v1/hooks/{name}",
    tag = "integration",
    operation_id = "call_inbound_hook",
    description = "A provider's call to a builder-defined endpoint (M14-T1). Public: the hook's own checks are the credential (address allow-list and mTLS, then signature or bearer secret with a timestamp window, then the body's required fields, then a once-only event id). Accepted calls create a record or start a flow as the hook's service user.",
    params(("name" = String, Path)),
    request_body(content = Object, description = "The provider's JSON event"),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::Delegated,
        Some("attome_records::entity_crud::create_record_for / attome_workflow::instance_admin::start_instance_internal"),
        "inbound provider events: the record create or flow start a call causes writes its own audit event, as the hook's service user"
    )))),
    responses(
        (status = 202, description = "Accepted", body = HookAccepted),
        (status = 401, description = "Bad signature or secret, or a timestamp outside the window", body = ErrorResponse),
        (status = 403, description = "The caller's address or certificate is not allowed", body = ErrorResponse),
        (status = 404, description = "No active hook of this name", body = ErrorResponse),
        (status = 409, description = "A replay of an event already accepted", body = ErrorResponse),
        (status = 422, description = "The body is not JSON or lacks a required field", body = ErrorResponse),
    ),
)]
async fn call_hook(
    State(state): State<EngineState>,
    Path(name): Path<String>,
    request: Request,
) -> Result<(StatusCode, Json<HookAccepted>), AppError> {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let (parts, body) = request.into_parts();
    let headers = parts.headers;
    let body = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| AppError::Validation("the body is too large".into()))?;

    let hook: LiveHook = sqlx::query_as(&format!(
        "SELECT {LIVE_COLUMNS} FROM inbound_hook WHERE name = $1 AND is_active AND NOT is_deleted"
    ))
    .bind(&name)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)?;

    let config = &state.base.config;
    if !hook.ip_allow.is_empty() || hook.require_mtls {
        let Some(peer) = peer else {
            return Err(AppError::Forbidden);
        };
        let client =
            attome_server::middleware::client_ip::client_ip_from_parts(peer, &headers, config);
        if !inbound::ip_allowed(&hook.ip_allow, client) {
            return Err(AppError::Forbidden);
        }
        if hook.require_mtls {
            let verified = headers
                .get(inbound::MTLS_VERIFIED_HEADER)
                .and_then(|v| v.to_str().ok())
                == Some("SUCCESS");
            if !config.is_trusted_proxy(peer.to_canonical()) || !verified {
                return Err(AppError::Forbidden);
            }
        }
    }

    let secret = inbound::open_secret(&state, hook.id, &hook.secret_sealed)?;
    let verified = inbound::verify(&hook.auth, &secret, &headers, &body, Utc::now().timestamp())
        .map_err(AppError::from)?;
    drop(secret);

    let payload: Value = serde_json::from_slice(&body)
        .map_err(|_| AppError::Validation("the body is not JSON".into()))?;
    let missing = inbound::missing_fields(&hook.body_schema, &payload);
    if !missing.is_empty() {
        return Err(AppError::Validation(format!(
            "the body lacks {}",
            missing.join(", ")
        )));
    }

    if !inbound::claim_nonce(&state, hook.id, &verified.nonce, verified.ttl_secs).await? {
        return Err(AppError::Conflict(
            "replay: this event was already accepted",
        ));
    }
    match accept(&state, &hook, &verified.nonce, payload).await {
        Ok(accepted) => Ok((StatusCode::ACCEPTED, Json(accepted))),
        Err(error) => {
            inbound::release_nonce(&state, hook.id, &verified.nonce).await;
            Err(error)
        }
    }
}

/// M14-T3: writes the event to the inbox with its job, in one transaction;
/// a known event id is a duplicate and enqueues nothing.
async fn accept(
    state: &EngineState,
    hook: &LiveHook,
    event_key: &str,
    payload: Value,
) -> Result<HookAccepted, AppError> {
    let ordering = ordering_value(hook.ordering_key.as_deref(), &payload);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let inserted: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO inbound_hook_event (hook_id, event_key, ordering_key, payload) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (hook_id, event_key) DO NOTHING RETURNING id",
    )
    .bind(hook.id)
    .bind(event_key)
    .bind(&ordering)
    .bind(&payload)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(event_id) = inserted else {
        let existing: Uuid = sqlx::query_scalar(
            "SELECT id FROM inbound_hook_event WHERE hook_id = $1 AND event_key = $2",
        )
        .bind(hook.id)
        .bind(event_key)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        return Ok(HookAccepted {
            accepted: true,
            event_id: existing,
            duplicate: true,
        });
    };
    let job = attome_jobs::RegisteredJob {
        name: PROCESS_JOB.to_owned(),
        version: 1,
        payload: serde_json::to_value(ProcessEvent { event_id }).map_err(AppError::internal)?,
        next: None,
    };
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(HookAccepted {
        accepted: true,
        event_id,
        duplicate: false,
    })
}

#[derive(sqlx::FromRow)]
struct EventRow {
    id: Uuid,
    hook_id: Uuid,
    ordering_key: Option<String>,
    payload: Value,
    attempts: i32,
}

/// Claims the next event to process for `event_id`'s queue: the event itself
/// when its hook has no ordering, else its key's oldest waiting event while
/// no other event of the key is being processed.
async fn claim_next(state: &EngineState, event_id: Uuid) -> Result<Option<EventRow>, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let own: Option<(Uuid, Option<String>)> =
        sqlx::query_as("SELECT hook_id, ordering_key FROM inbound_hook_event WHERE id = $1")
            .bind(event_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let Some((hook_id, key)) = own else {
        return Ok(None);
    };
    let lease = format!("{PROCESSING_LEASE_MINUTES} minutes");
    let claimed = match key {
        None => sqlx::query_as::<_, EventRow>(
            "UPDATE inbound_hook_event SET status = 'processing', attempts = attempts + 1, \
                    claimed_at = now() \
              WHERE id = $1 AND (status = 'received' \
                    OR (status = 'processing' AND claimed_at < now() - $2::interval)) \
             RETURNING id, hook_id, ordering_key, payload, attempts",
        )
        .bind(event_id)
        .bind(&lease)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?,
        Some(key) => {
            let locked: bool =
                sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
                    .bind(crate::ADVISORY_LOCK_NAMESPACE)
                    .bind(format!("attome-api/inbound-hook-order:{hook_id}:{key}"))
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            if !locked {
                // Another job is claiming this key's next event right now;
                // retry rather than exit, so an event is never left behind.
                return Err(AppError::Conflict(
                    "another job is claiming this key's next event; retried",
                ));
            }
            sqlx::query_as::<_, EventRow>(
                "UPDATE inbound_hook_event SET status = 'processing', attempts = attempts + 1, \
                        claimed_at = now() \
                  WHERE id = ( \
                     SELECT e.id FROM inbound_hook_event e \
                      WHERE e.hook_id = $1 AND e.ordering_key = $2 \
                        AND (e.status = 'received' \
                             OR (e.status = 'processing' AND e.claimed_at < now() - $3::interval)) \
                        AND NOT EXISTS (SELECT 1 FROM inbound_hook_event p \
                                         WHERE p.hook_id = $1 AND p.ordering_key = $2 \
                                           AND p.status = 'processing' \
                                           AND p.claimed_at >= now() - $3::interval) \
                      ORDER BY e.received_at, e.id LIMIT 1) \
                 RETURNING id, hook_id, ordering_key, payload, attempts",
            )
            .bind(hook_id)
            .bind(&key)
            .bind(&lease)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?
        }
    };
    attome_db::tx::commit(tx).await?;
    Ok(claimed)
}

/// M14-T3: the [`PROCESS_JOB`] handler. Processes `event_id`, or for an
/// ordered hook its key's queue up to and past it, oldest first. A handler
/// failure puts the event back for the job's retry, or after
/// [`MAX_ATTEMPTS`] marks it failed; either way the job fails, so the last
/// failure is in the dead-letter inbox.
pub async fn process_event(state: &EngineState, event_id: Uuid) -> Result<(), AppError> {
    // A replay from the dead-letter inbox starts the event again.
    sqlx::query(
        "UPDATE inbound_hook_event SET status = 'received', attempts = 0, error = NULL \
          WHERE id = $1 AND status = 'failed'",
    )
    .bind(event_id)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    while let Some(event) = claim_next(state, event_id).await? {
        let hook: Option<LiveHook> = sqlx::query_as(&format!(
            "SELECT {LIVE_COLUMNS} FROM inbound_hook WHERE id = $1 AND NOT is_deleted"
        ))
        .bind(event.hook_id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let outcome = match &hook {
            Some(hook) => run_handler(state, hook, &hook.name, event.payload.clone()).await,
            None => Err(AppError::NotFound),
        };
        match outcome {
            Ok(done) => {
                sqlx::query(
                    "UPDATE inbound_hook_event SET status = 'done', processed_at = now(), \
                            error = NULL, result = $2 WHERE id = $1",
                )
                .bind(event.id)
                .bind(serde_json::to_value(&done).map_err(AppError::internal)?)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
            }
            Err(error) => {
                let status = if event.attempts >= MAX_ATTEMPTS {
                    "failed"
                } else {
                    "received"
                };
                sqlx::query("UPDATE inbound_hook_event SET status = $2, error = $3 WHERE id = $1")
                    .bind(event.id)
                    .bind(status)
                    .bind(error.to_string().chars().take(500).collect::<String>())
                    .execute(&state.base.db)
                    .await
                    .map_err(AppError::internal)?;
                return Err(error);
            }
        }
        if event.ordering_key.is_none() {
            break;
        }
    }
    Ok(())
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/inbound-hooks",
            get(list_hooks).post(create_hook),
        )
        .route(
            "/api/v1/admin/inbound-hooks/{id}",
            patch(update_hook).delete(delete_hook),
        )
        .route("/api/v1/hooks/{name}", post(call_hook))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_hooks, create_hook, update_hook, delete_hook, call_hook))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_inbox_orders_by_the_key_in_the_body() {
        let payload = serde_json::json!({ "order": { "id": 42 }, "shop": "riyadh", "empty": "" });
        assert_eq!(
            ordering_value(Some("/order/id"), &payload),
            Some("42".into())
        );
        assert_eq!(
            ordering_value(Some("/shop"), &payload),
            Some("riyadh".into())
        );
        assert_eq!(ordering_value(Some("/empty"), &payload), None);
        assert_eq!(ordering_value(Some("/missing"), &payload), None);
        assert_eq!(ordering_value(None, &payload), None);
    }

    #[test]
    fn inbound_hook_record_body_reads_json_pointers() {
        let handler = serde_json::json!({
            "type": "record", "entity": "lead",
            "fields": { "title": "/data/subject", "source": "/provider", "missing": "/none" }
        });
        let payload = serde_json::json!({ "data": { "subject": "New order" }, "provider": "shop" });
        let body = record_body(&handler, &payload);
        assert_eq!(body["title"], "New order");
        assert_eq!(body["source"], "shop");
        assert!(!body.contains_key("missing"));
        assert!(valid_name("shop-orders_1"));
        assert!(!valid_name("Shop"));
        assert!(valid_cidr("10.0.0.0/8") && valid_cidr("2001:db8::/32") && valid_cidr("1.2.3.4"));
        assert!(!valid_cidr("10.0.0.0/33") && !valid_cidr("nope"));
    }
}
