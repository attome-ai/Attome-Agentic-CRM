//! J5-T3: a WhatsApp number's approved message templates, synced from Meta,
//! with each template variable mapped to the attribute that fills it.
//!
//! A number is a WhatsApp system (an integration system whose config has
//! `"social": "whatsapp"`, as J5-T2 and N18-T1 read it); its config names
//! the WhatsApp Business Account (`waba_id`) the templates belong to, and
//! its sealed credential holds `access_token`.
//!
//! - `GET /api/v1/admin/integrations/whatsapp/numbers` lists the numbers.
//! - `POST .../whatsapp/{id}/templates/sync` reads Meta's approved templates
//!   (`GET /{waba_id}/message_templates?status=APPROVED`, following pages)
//!   into `whatsapp_template` (migration 0356): new ones added, changed
//!   ones updated with their variable maps kept where the variable still
//!   exists, and ones no longer approved removed.
//! - `GET .../whatsapp/{id}/templates` lists a number's templates.
//! - `PUT .../whatsapp/templates/{template_id}/variables` sets the map
//!   (`{"body.1": "first_name"}`) under the template's row version.
//!
//! Integration administrators only; the sync and the map are audited as
//! configuration.

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Duration;

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    http::{HeaderMap, header::IF_MATCH},
    routing::{get, post, put},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::connector::adapters::{social, whatsapp};
use crate::system::IntegrationSystem;

const SYNC_TIMEOUT: Duration = Duration::from_secs(20);
/// Pages of templates one sync follows.
const MAX_PAGES: usize = 20;
/// Templates one number keeps.
const MAX_TEMPLATES: usize = 2000;

fn client() -> &'static attome_outbound::http::Outbound {
    // Q21-T1: the provider's public API only.
    static CLIENT: OnceLock<attome_outbound::http::Outbound> = OnceLock::new();
    CLIENT.get_or_init(|| {
        attome_outbound::http::shared(attome_outbound::http::Purpose::public("whatsapp"), |b| {
            b.timeout(SYNC_TIMEOUT)
        })
    })
}

/// A template as Meta lists it, approved.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteTemplate {
    pub name: String,
    pub language: String,
    pub category: String,
    pub components: Value,
}

/// The approved templates on one page of Meta's answer, and the next
/// page's URL. Pure.
pub fn parse_page(body: &Value) -> (Vec<RemoteTemplate>, Option<String>) {
    let templates = body
        .get("data")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|t| t.get("status").and_then(Value::as_str) == Some("APPROVED"))
                .filter_map(|t| {
                    Some(RemoteTemplate {
                        name: t.get("name")?.as_str()?.to_owned(),
                        language: t.get("language")?.as_str()?.to_owned(),
                        category: t
                            .get("category")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned(),
                        components: t.get("components").cloned().unwrap_or(json!([])),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let next = body
        .pointer("/paging/next")
        .and_then(Value::as_str)
        .filter(|u| u.starts_with("https://graph.facebook.com/"))
        .map(str::to_owned);
    (templates, next)
}

/// The variables a template's components take, as `header.1`, `body.1`,
/// `body.2`, ... in order. Pure.
pub fn variables(components: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for component in components.as_array().into_iter().flatten() {
        let kind = component
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_lowercase();
        let Some(text) = component.get("text").and_then(Value::as_str) else {
            continue;
        };
        let mut seen = BTreeSet::new();
        let mut rest = text;
        while let Some(start) = rest.find("{{") {
            let after = &rest[start + 2..];
            let Some(end) = after.find("}}") else {
                break;
            };
            if let Ok(n) = after[..end].trim().parse::<u32>() {
                seen.insert(n);
            }
            rest = &after[end + 2..];
        }
        out.extend(seen.into_iter().map(|n| format!("{kind}.{n}")));
    }
    out
}

/// `map` kept to the variables a template still takes. Pure.
pub fn kept_map(map: &Value, variables: &[String]) -> Value {
    let mut out = Map::new();
    if let Some(entries) = map.as_object() {
        for (key, value) in entries {
            if variables.contains(key) {
                out.insert(key.clone(), value.clone());
            }
        }
    }
    Value::Object(out)
}

/// Whether `map` names only `variables`, each with an attribute name. Pure.
pub fn check_map(map: &Value, variables: &[String]) -> Result<(), AppError> {
    let entries = map
        .as_object()
        .ok_or_else(|| AppError::Validation("variable_map must be an object".into()))?;
    for (key, value) in entries {
        if !variables.contains(key) {
            return Err(AppError::Validation(format!(
                "variable_map: the template has no variable {key}"
            )));
        }
        let ok = value.as_str().is_some_and(|a| {
            !a.is_empty()
                && a.len() <= 63
                && a.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        });
        if !ok {
            return Err(AppError::Validation(format!(
                "variable_map: {key} must name an attribute (lowercase letters, digits, _)"
            )));
        }
    }
    Ok(())
}

/// A WhatsApp number.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WhatsAppNumber {
    pub id: Uuid,
    pub name: String,
    pub phone_number_id: Option<String>,
    pub waba_id: Option<String>,
    pub templates: i64,
    pub synced_at: Option<DateTime<Utc>>,
}

/// One template of a number.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct WhatsAppTemplate {
    pub id: Uuid,
    pub name: String,
    pub language: String,
    pub category: String,
    #[schema(value_type = Object)]
    pub components: Value,
    pub variables: Vec<String>,
    /// Variable to attribute, e.g. `{"body.1": "first_name"}`.
    #[schema(value_type = Object)]
    pub variable_map: Value,
    pub synced_at: DateTime<Utc>,
    pub row_version: i64,
}

/// What a sync did.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct SyncResult {
    pub added: u64,
    pub updated: u64,
    pub removed: u64,
}

/// A variable map to set.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VariableMapBody {
    #[schema(value_type = Object)]
    pub variable_map: Value,
}

fn is_whatsapp(system: &IntegrationSystem) -> bool {
    social::config(system).get("social").and_then(Value::as_str) == Some("whatsapp")
}

async fn whatsapp_system(state: &EngineState, id: Uuid) -> Result<IntegrationSystem, AppError> {
    let system = crate::system::load(&state.base.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    if is_whatsapp(&system) {
        Ok(system)
    } else {
        Err(AppError::NotFound)
    }
}

/// Reads the number's approved templates from Meta and brings
/// `whatsapp_template` in line with them.
pub async fn sync(state: &EngineState, system: &IntegrationSystem) -> Result<SyncResult, AppError> {
    let config = social::config(system);
    let waba = config
        .get("waba_id")
        .and_then(Value::as_str)
        .filter(|w| !w.trim().is_empty() && w.chars().all(|c| c.is_ascii_digit()))
        .ok_or_else(|| {
            AppError::Validation("whatsapp: the number names no waba_id (digits only)".into())
        })?;
    let version = config
        .get("graph_version")
        .and_then(Value::as_str)
        .filter(|v| v.starts_with('v') && v.len() <= 8)
        .unwrap_or(whatsapp::DEFAULT_GRAPH_VERSION);
    let token = social::sealed_secret(state, system, "access_token").await?;
    let mut url = Some(format!(
        "https://graph.facebook.com/{version}/{waba}/message_templates?status=APPROVED&limit=100"
    ));
    let mut remote: Vec<RemoteTemplate> = Vec::new();
    for _ in 0..MAX_PAGES {
        let Some(page_url) = url.take() else { break };
        let response = token
            .bearer(client().get(page_url))
            .send()
            .await
            .map_err(AppError::internal)?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            tracing::warn!(system = %system.id, %status, "whatsapp: template list refused");
            return Err(AppError::Validation(
                "whatsapp: Meta refused the template list; check the number's token and waba_id"
                    .into(),
            ));
        }
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        let (templates, next) = parse_page(&body);
        remote.extend(templates);
        if remote.len() >= MAX_TEMPLATES {
            remote.truncate(MAX_TEMPLATES);
            break;
        }
        url = next;
    }

    let mut out = SyncResult::default();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let mut kept: Vec<(String, String)> = Vec::new();
    for t in &remote {
        let vars = variables(&t.components);
        let existing: Option<(Uuid, Value)> = sqlx::query_as(
            "SELECT id, variable_map FROM whatsapp_template \
              WHERE system_id = $1 AND name = $2 AND language = $3 FOR UPDATE",
        )
        .bind(system.id)
        .bind(&t.name)
        .bind(&t.language)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        match existing {
            Some((id, map)) => {
                sqlx::query(
                    "UPDATE whatsapp_template SET category = $2, components = $3, variables = $4, \
                            variable_map = $5, synced_at = now(), row_version = row_version + 1 \
                      WHERE id = $1",
                )
                .bind(id)
                .bind(&t.category)
                .bind(&t.components)
                .bind(&vars)
                .bind(kept_map(&map, &vars))
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                out.updated += 1;
            }
            None => {
                sqlx::query(
                    "INSERT INTO whatsapp_template \
                        (system_id, name, language, category, components, variables) \
                     VALUES ($1, $2, $3, $4, $5, $6)",
                )
                .bind(system.id)
                .bind(&t.name)
                .bind(&t.language)
                .bind(&t.category)
                .bind(&t.components)
                .bind(&vars)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                out.added += 1;
            }
        }
        kept.push((t.name.clone(), t.language.clone()));
    }
    let names: Vec<String> = kept.iter().map(|(n, l)| format!("{n}\u{1f}{l}")).collect();
    let removed = sqlx::query(
        "DELETE FROM whatsapp_template \
          WHERE system_id = $1 AND NOT ((name || chr(31) || language) = ANY($2))",
    )
    .bind(system.id)
    .bind(&names)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    out.removed = removed.rows_affected();
    attome_db::tx::commit(tx).await?;
    Ok(out)
}

/// `If-Match: "<row_version>"`, required.
fn if_match(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers.get(IF_MATCH).ok_or_else(|| {
        AppError::Validation("If-Match: \"<row_version>\" is required to change a template".into())
    })?;
    let value = raw
        .to_str()
        .map_err(|_| AppError::Validation("If-Match header must be ASCII".into()))?
        .trim()
        .trim_matches('"');
    value
        .parse::<i64>()
        .map_err(|_| AppError::Validation(format!("If-Match must be a row_version, got: {value}")))
}

/// List WhatsApp numbers
///
/// The deployment's WhatsApp numbers (integration systems with
/// `"social": "whatsapp"`), with their template counts.
#[utoipa::path(
    get,
    path = "/api/v1/admin/integrations/whatsapp/numbers",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<WhatsAppNumber>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_numbers(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Integrations>>,
) -> Result<Json<PaginatedResponse<WhatsAppNumber>>, AppError> {
    type Row = (Uuid, String, Option<String>, i64, Option<DateTime<Utc>>);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT s.id, s.name, s.config, \
                (SELECT COUNT(*) FROM whatsapp_template t WHERE t.system_id = s.id), \
                (SELECT MAX(t.synced_at) FROM whatsapp_template t WHERE t.system_id = s.id) \
           FROM integration_system s \
          WHERE s.is_active IS NOT FALSE AND s.config IS NOT NULL \
            AND s.config ~ '\"social\"\\s*:\\s*\"whatsapp\"' \
          ORDER BY s.name, s.id LIMIT 200",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let items: Vec<WhatsAppNumber> = rows
        .into_iter()
        .map(|(id, name, config, templates, synced_at)| {
            let config: Value = config
                .as_deref()
                .and_then(|c| serde_json::from_str(c).ok())
                .unwrap_or(Value::Null);
            let text = |k: &str| config.get(k).and_then(Value::as_str).map(str::to_owned);
            WhatsAppNumber {
                id,
                name,
                phone_number_id: text("phone_number_id"),
                waba_id: text("waba_id"),
                templates,
                synced_at,
            }
        })
        .collect();
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(items, total, 1, 200)))
}

/// Sync a number's templates
///
/// Reads the number's approved message templates from Meta and keeps them:
/// new ones added, changed ones updated (their variable maps kept where the
/// variable still exists), ones no longer approved removed. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/integrations/whatsapp/{id}/templates/sync",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The WhatsApp system")),
    responses(
        (status = 200, description = "Synced", body = SyncResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such WhatsApp number", body = ErrorResponse),
        (status = 422, description = "The number names no waba_id or has no access token, or Meta refused the list", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn post_sync(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Integrations>>,
    Path(id): Path<Uuid>,
) -> Result<Json<SyncResult>, AppError> {
    let system = whatsapp_system(&state, id).await?;
    let result = sync(&state, &system).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "integration_system",
            Some(id),
        )
        .comment(format!(
            "whatsapp templates synced: {} added, {} updated, {} removed",
            result.added, result.updated, result.removed
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(result))
}

/// List a number's templates
///
/// The number's synced templates with their variables and variable maps.
#[utoipa::path(
    get,
    path = "/api/v1/admin/integrations/whatsapp/{id}/templates",
    tag = "admin",
    params(("id" = Uuid, Path, description = "The WhatsApp system")),
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<WhatsAppTemplate>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such WhatsApp number", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_templates(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Integrations>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PaginatedResponse<WhatsAppTemplate>>, AppError> {
    whatsapp_system(&state, id).await?;
    let items: Vec<WhatsAppTemplate> = sqlx::query_as(
        "SELECT id, name, language, category, components, variables, variable_map, synced_at, \
                row_version \
           FROM whatsapp_template WHERE system_id = $1 ORDER BY name, language LIMIT $2",
    )
    .bind(id)
    .bind(i64::try_from(MAX_TEMPLATES).unwrap_or(i64::MAX))
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let page_size = total.max(1);
    Ok(Json(PaginatedResponse::new(items, total, 1, page_size)))
}

/// Map a template's variables
///
/// Sets which attribute fills each of the template's variables, under the
/// template's row version (`If-Match`). Audited.
#[utoipa::path(
    put,
    path = "/api/v1/admin/integrations/whatsapp/templates/{template_id}/variables",
    tag = "admin",
    params(
        ("template_id" = Uuid, Path, description = "The template"),
        ("If-Match" = String, Header, description = "The template's row_version, quoted"),
    ),
    request_body = VariableMapBody,
    responses(
        (status = 200, description = "The template as it now stands", body = WhatsAppTemplate),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such template", body = ErrorResponse),
        (status = 409, description = "version_conflict: the template changed since it was read", body = ErrorResponse),
        (status = 422, description = "A bad If-Match, an unknown variable or a bad attribute name", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[
        (attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update),
    ])))),
)]
async fn put_variables(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::Integrations>>,
    Path(template_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<VariableMapBody>,
) -> Result<Json<WhatsAppTemplate>, AppError> {
    let expected = if_match(&headers)?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let current: Option<(Vec<String>, i64, Uuid)> = sqlx::query_as(
        "SELECT variables, row_version, system_id FROM whatsapp_template WHERE id = $1 FOR UPDATE",
    )
    .bind(template_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((vars, version, system_id)) = current else {
        return Err(AppError::NotFound);
    };
    if version != expected {
        return Err(AppError::VersionConflict);
    }
    check_map(&body.variable_map, &vars)?;
    let updated: WhatsAppTemplate = sqlx::query_as(
        "UPDATE whatsapp_template SET variable_map = $2, row_version = row_version + 1 \
          WHERE id = $1 \
         RETURNING id, name, language, category, components, variables, variable_map, synced_at, \
                   row_version",
    )
    .bind(template_id)
    .bind(&body.variable_map)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            attome_audit::AuditOperation::Update,
            ctx.user_id,
            "integration_system",
            Some(system_id),
        )
        .comment(format!(
            "whatsapp template {} variables mapped",
            updated.name
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(updated))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/integrations/whatsapp/numbers",
            get(list_numbers),
        )
        .route(
            "/api/v1/admin/integrations/whatsapp/{id}/templates/sync",
            post(post_sync),
        )
        .route(
            "/api/v1/admin/integrations/whatsapp/{id}/templates",
            get(list_templates),
        )
        .route(
            "/api/v1/admin/integrations/whatsapp/templates/{template_id}/variables",
            put(put_variables),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(list_numbers, post_sync, list_templates, put_variables),
    components(schemas(WhatsAppNumber, WhatsAppTemplate, SyncResult, VariableMapBody))
)]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_approved_templates_and_their_variables() {
        let page = json!({
            "data": [
                { "name": "order_ready", "language": "ar", "status": "APPROVED", "category": "UTILITY",
                  "components": [
                    { "type": "HEADER", "format": "TEXT", "text": "Order {{1}}" },
                    { "type": "BODY", "text": "Hello {{1}}, order {{2}} is ready. {{1}}" }
                  ] },
                { "name": "promo", "language": "en", "status": "REJECTED", "components": [] }
            ],
            "paging": { "next": "https://graph.facebook.com/v21.0/1/message_templates?after=x" }
        });
        let (templates, next) = parse_page(&page);
        assert_eq!(templates.len(), 1);
        assert_eq!(templates[0].name, "order_ready");
        assert!(next.is_some());
        assert_eq!(
            variables(&templates[0].components),
            vec!["header.1", "body.1", "body.2"]
        );
        let (_, elsewhere) =
            parse_page(&json!({ "data": [], "paging": { "next": "https://evil.test/x" } }));
        assert!(elsewhere.is_none(), "paging never leaves Meta's API");
    }

    #[test]
    fn maps_name_known_variables_and_attributes() {
        let vars = vec!["body.1".to_owned(), "body.2".to_owned()];
        assert!(check_map(&json!({ "body.1": "first_name" }), &vars).is_ok());
        assert!(check_map(&json!({ "body.3": "first_name" }), &vars).is_err());
        assert!(check_map(&json!({ "body.1": "First Name" }), &vars).is_err());
        assert_eq!(
            kept_map(&json!({ "body.1": "a", "body.9": "b" }), &vars),
            json!({ "body.1": "a" })
        );
    }
}
