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
//! Then the handler runs as the hook's `run_as` service user, through the
//! ordinary paths, so rules, record security and audit apply:
//! `{"type": "record", "entity": "...", "fields": {"attr": "/json/pointer"}}`
//! creates a record from the body; `{"type": "flow", "definition_id": "..."}`
//! starts the flow's published version with the body as context. A call
//! whose handler fails gives its event id back, so the provider's retry is
//! not refused as a replay.

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
    pub is_active: bool,
    pub secret_last4: Option<String>,
    pub row_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

const COLUMNS: &str = "id, name, auth, ip_allow, require_mtls, body_schema AS schema, handler, \
                       run_as, is_active, secret_last4, row_version, created_at, updated_at";

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
    match body.handler["type"].as_str() {
        Some("record") => {
            let entity = body.handler["entity"].as_str().unwrap_or_default();
            let registry = state.entities.load();
            let Some(meta) = registry.get(entity) else {
                return Err(AppError::Validation(format!(
                    "handler entity {entity:?} is not an entity"
                )));
            };
            let fields = body.handler["fields"]
                .as_object()
                .cloned()
                .unwrap_or_default();
            if fields.is_empty() {
                return Err(AppError::Validation(
                    "a record handler maps at least one attribute to a body field".into(),
                ));
            }
            for (attribute, pointer) in &fields {
                if !meta.attrs.iter().any(|a| &a.logicalname == attribute) {
                    return Err(AppError::Validation(format!(
                        "{attribute:?} is not an attribute of {entity}"
                    )));
                }
                if !pointer
                    .as_str()
                    .is_some_and(|p| p.is_empty() || p.starts_with('/'))
                {
                    return Err(AppError::Validation(format!(
                        "the body field for {attribute} is a JSON pointer such as /data/id"
                    )));
                }
            }
        }
        Some("flow") => {
            let id = body.handler["definition_id"]
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
            if !exists {
                return Err(AppError::Validation("no such flow".into()));
            }
        }
        _ => {
            return Err(AppError::Validation(
                "handler.type is record or flow".into(),
            ));
        }
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

#[utoipa::path(
    post,
    path = "/api/v1/admin/inbound-hooks",
    tag = "admin",
    operation_id = "create_inbound_hook",
    description = "Defines an inbound endpoint at /api/v1/hooks/{name} (M14-T1): its authentication (hmac with a preset or custom header and encoding, or bearer), address allow-list, mTLS, required body fields, and handler (create a record or start a flow as run_as). The secret is sealed and never returned.",
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
              handler, run_as, is_active, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
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
                is_active = $12, row_version = row_version + 1, updated_at = now() \
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

#[utoipa::path(
    delete,
    path = "/api/v1/admin/inbound-hooks/{id}",
    tag = "admin",
    operation_id = "delete_inbound_hook",
    description = "Removes an inbound hook (M14-T1); its endpoint answers 404 from then on.",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Delete)])))),
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
        AuditOperation::Delete,
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
    auth: Value,
    secret_sealed: String,
    ip_allow: Vec<String>,
    require_mtls: bool,
    body_schema: Value,
    handler: Value,
    run_as: Uuid,
}

/// What an accepted call did.
#[derive(Debug, Serialize, ToSchema)]
pub struct HookAccepted {
    pub accepted: bool,
    pub record_id: Option<Uuid>,
    pub instance_id: Option<Uuid>,
}

/// The record a record handler creates from `payload`.
pub fn record_body(handler: &Value, payload: &Value) -> Map<String, Value> {
    handler["fields"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(attribute, pointer)| {
            let pointer = pointer.as_str()?;
            let value = if pointer.is_empty() {
                Some(payload)
            } else {
                payload.pointer(pointer)
            }?;
            (!value.is_null()).then(|| (attribute.clone(), value.clone()))
        })
        .collect()
}

async fn run_handler(
    state: &EngineState,
    hook: &LiveHook,
    name: &str,
    payload: Value,
) -> Result<HookAccepted, AppError> {
    let ctx = state.base.security.resolve(hook.run_as).await?;
    match hook.handler["type"].as_str() {
        Some("record") => {
            let entity = hook.handler["entity"].as_str().unwrap_or_default();
            let body = record_body(&hook.handler, &payload);
            let (record_id, _) = attome_records::entity_crud::create_record_for(
                state,
                &ctx,
                hook.run_as,
                entity,
                Value::Object(body),
            )
            .await?;
            Ok(HookAccepted {
                accepted: true,
                record_id: Some(record_id),
                instance_id: None,
            })
        }
        Some("flow") => {
            let definition = hook.handler["definition_id"]
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
            Ok(HookAccepted {
                accepted: true,
                record_id: None,
                instance_id: Some(instance),
            })
        }
        _ => Err(AppError::internal("inbound hook has no handler")),
    }
}

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

    let hook: LiveHook = sqlx::query_as(
        "SELECT id, auth, secret_sealed, ip_allow, require_mtls, body_schema, handler, run_as \
           FROM inbound_hook WHERE name = $1 AND is_active AND NOT is_deleted",
    )
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
    match run_handler(&state, &hook, &name, payload).await {
        Ok(accepted) => Ok((StatusCode::ACCEPTED, Json(accepted))),
        Err(error) => {
            inbound::release_nonce(&state, hook.id, &verified.nonce).await;
            Err(error)
        }
    }
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
