//! Q3-T1: SCIM 2.0 provisioning (RFC 7643 core schema, RFC 7644 protocol)
//! for identity providers (Entra ID, Okta, ...).
//!
//! **Tokens.** An administrator issues one bearer token per IdP
//! (`POST /api/v1/admin/scim/tokens`, `scim_token`, migration 0231): the
//! token (`<public id>.<secret>`) is shown once and kept only as a peppered
//! hash, with an optional address allow-list. Every SCIM call presents it;
//! a wrong, revoked or out-of-network token is a 401 or 403 before anything
//! is read. Issuing and revoking are Credential events.
//!
//! **Users** (`/scim/v2/Users`) are user accounts: `userName` is the sign-in
//! email, `externalId` the IdP's id (kept per token), `active` the account
//! state. Creating, replacing, patching and deactivating write through one
//! path with a Security event in the same transaction. Deactivating (an
//! `active: false` patch or a DELETE) takes the account's email lock, bumps
//! its auth epoch and revokes its API keys, like the admin disable; an
//! account is never deleted. A create repeated with the same `externalId`
//! answers the account already made (bulk-safe); a `userName` held by
//! another account is a 409 `uniqueness`.
//!
//! **Groups** (`/scim/v2/Groups`) are teams; membership changes add and
//! remove team members, each an Access event. Adding a member already there
//! or removing one not there changes nothing.
//!
//! **Requests.** Filters are `eq` on `userName` and `externalId` (users) or
//! `displayName` and `externalId` (groups). PATCH takes `add`, `replace`
//! and `remove`, with a path (`active`, `name.givenName`,
//! `emails[type eq "work"].value`, `members[value eq "<id>"]`, ...) or a
//! value object, in the shapes Entra (capitalised ops, string booleans) and
//! Okta send. Errors are SCIM error documents.

use std::net::{IpAddr, SocketAddr};

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Extension, Json, Router,
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
const LIST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";
const ERROR_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:Error";
/// The most resources one list answers.
const MAX_COUNT: i64 = 200;

// ── The protocol, pure ──────────────────────────────────────────────────

/// A list filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    UserName(String),
    ExternalId(String),
    DisplayName(String),
}

/// Parses `<attribute> eq "<value>"` (attribute and operator in any case).
pub fn parse_filter(raw: &str) -> Result<Filter, String> {
    let raw = raw.trim();
    let mut parts = raw.splitn(3, char::is_whitespace);
    let attribute = parts.next().unwrap_or_default();
    let op = parts.next().unwrap_or_default();
    let value = parts.next().unwrap_or_default().trim();
    if !op.eq_ignore_ascii_case("eq") {
        return Err("only the eq filter is supported".into());
    }
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or("the filter value is a quoted string")?
        .replace("\\\"", "\"");
    match attribute.to_ascii_lowercase().as_str() {
        "username" => Ok(Filter::UserName(value)),
        "externalid" => Ok(Filter::ExternalId(value)),
        "displayname" => Ok(Filter::DisplayName(value)),
        _ => Err(format!("filtering on {attribute} is not supported")),
    }
}

/// A user as SCIM describes it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UserDoc {
    pub user_name: String,
    pub external_id: Option<String>,
    pub display_name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub active: bool,
}

impl UserDoc {
    /// The account's display name: SCIM's, else given and family names,
    /// else the user name.
    pub fn name(&self) -> String {
        if let Some(d) = self
            .display_name
            .as_deref()
            .filter(|d| !d.trim().is_empty())
        {
            return d.trim().to_owned();
        }
        let joined = [self.given_name.as_deref(), self.family_name.as_deref()]
            .into_iter()
            .flatten()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        if joined.is_empty() {
            self.user_name.clone()
        } else {
            joined
        }
    }

    /// The sign-in email: the primary (or work, or first) email, else the
    /// user name.
    pub fn sign_in_email(&self) -> String {
        self.email
            .clone()
            .unwrap_or_else(|| self.user_name.clone())
            .trim()
            .to_lowercase()
    }
}

/// `true`, `false`, `"True"`, `"false"`, ...
fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        Value::String(s) if s.eq_ignore_ascii_case("true") => Some(true),
        Value::String(s) if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn text(v: &Value) -> Option<String> {
    v.as_str()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn pick_email(emails: &Value) -> Option<String> {
    let list = emails.as_array()?;
    let primary = list.iter().find(|e| e["primary"].as_bool() == Some(true));
    let work = list.iter().find(|e| e["type"].as_str() == Some("work"));
    primary
        .or(work)
        .or(list.first())
        .and_then(|e| text(&e["value"]))
}

/// Reads a User resource (create or replace).
pub fn user_from_json(doc: &Value) -> Result<UserDoc, String> {
    let user_name = text(&doc["userName"]).ok_or("userName is required")?;
    Ok(UserDoc {
        user_name,
        external_id: text(&doc["externalId"]),
        display_name: text(&doc["displayName"]),
        given_name: text(&doc["name"]["givenName"]),
        family_name: text(&doc["name"]["familyName"]),
        email: pick_email(&doc["emails"]),
        active: doc.get("active").and_then(as_bool).unwrap_or(true),
    })
}

fn set_user_attr(user: &mut UserDoc, path: &str, value: Option<&Value>) -> Result<(), String> {
    let lower = path.trim().to_ascii_lowercase();
    let string = || value.and_then(text);
    match lower.as_str() {
        "active" => {
            user.active = match value {
                Some(v) => as_bool(v).ok_or("active is a boolean")?,
                None => user.active,
            }
        }
        "username" => {
            user.user_name = string().ok_or("userName cannot be removed")?;
        }
        "externalid" => user.external_id = string(),
        "displayname" => user.display_name = string(),
        "name.givenname" => user.given_name = string(),
        "name.familyname" => user.family_name = string(),
        "name" => {
            if let Some(v) = value {
                user.given_name = text(&v["givenName"]).or(user.given_name.take());
                user.family_name = text(&v["familyName"]).or(user.family_name.take());
            } else {
                user.given_name = None;
                user.family_name = None;
            }
        }
        "emails" => user.email = value.and_then(pick_email),
        p if p.starts_with("emails[") => user.email = string(),
        other => return Err(format!("patching {other} is not supported")),
    }
    Ok(())
}

/// Applies a PatchOp document's operations to `user`.
pub fn apply_user_patch(user: &mut UserDoc, patch: &Value) -> Result<(), String> {
    let ops = patch["Operations"]
        .as_array()
        .ok_or("Operations is required")?;
    for op in ops {
        let kind = op["op"].as_str().unwrap_or_default().to_ascii_lowercase();
        let path = op["path"].as_str();
        match (kind.as_str(), path) {
            ("add" | "replace", Some(path)) => set_user_attr(user, path, Some(&op["value"]))?,
            ("add" | "replace", None) => {
                let values = op["value"]
                    .as_object()
                    .ok_or("an operation without a path carries an object")?;
                for (key, value) in values {
                    set_user_attr(user, key, Some(value))?;
                }
            }
            ("remove", Some(path)) => set_user_attr(user, path, None)?,
            ("remove", None) => return Err("a remove operation names its path".into()),
            (other, _) => return Err(format!("unknown operation {other:?}")),
        }
    }
    Ok(())
}

/// What a group patch does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupPatch {
    pub display_name: Option<String>,
    pub add: Vec<Uuid>,
    pub remove: Vec<Uuid>,
    /// The whole membership, when replaced.
    pub replace: Option<Vec<Uuid>>,
}

fn member_ids(value: &Value) -> Result<Vec<Uuid>, String> {
    let list = match value {
        Value::Array(list) => list.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    };
    list.iter()
        .map(|m| {
            m["value"]
                .as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| "a member's value is a user id".to_owned())
        })
        .collect()
}

/// Reads a Group PatchOp document.
pub fn group_patch(patch: &Value) -> Result<GroupPatch, String> {
    let ops = patch["Operations"]
        .as_array()
        .ok_or("Operations is required")?;
    let mut out = GroupPatch::default();
    for op in ops {
        let kind = op["op"].as_str().unwrap_or_default().to_ascii_lowercase();
        let path = op["path"].as_str().map(str::trim);
        let lower = path.map(str::to_ascii_lowercase);
        match (kind.as_str(), lower.as_deref()) {
            ("add", Some("members")) => out.add.extend(member_ids(&op["value"])?),
            ("replace", Some("members")) => out.replace = Some(member_ids(&op["value"])?),
            ("remove", Some("members")) => match &op["value"] {
                Value::Null => out.replace = Some(Vec::new()),
                value => out.remove.extend(member_ids(value)?),
            },
            ("remove", Some(p)) if p.starts_with("members[value eq") => {
                let id = path
                    .and_then(|p| p.split('"').nth(1))
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .ok_or("members[value eq \"<id>\"] names a user id")?;
                out.remove.push(id);
            }
            ("add" | "replace", Some("displayname")) => out.display_name = text(&op["value"]),
            ("add" | "replace", None) => {
                let values = op["value"]
                    .as_object()
                    .ok_or("an operation without a path carries an object")?;
                if let Some(name) = values.get("displayName") {
                    out.display_name = text(name);
                }
                if let Some(members) = values.get("members") {
                    if kind == "add" {
                        out.add.extend(member_ids(members)?);
                    } else {
                        out.replace = Some(member_ids(members)?);
                    }
                }
            }
            (other, p) => {
                return Err(format!(
                    "operation {other:?} on {} is not supported",
                    p.unwrap_or("the group")
                ));
            }
        }
    }
    Ok(out)
}

/// A user account as a SCIM User resource.
pub fn user_resource(
    id: Uuid,
    email: &str,
    name: Option<&str>,
    external_id: Option<&str>,
    active: bool,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
) -> Value {
    let mut doc = json!({
        "schemas": [USER_SCHEMA],
        "id": id,
        "userName": email,
        "displayName": name,
        "active": active,
        "emails": [{ "value": email, "type": "work", "primary": true }],
        "meta": {
            "resourceType": "User",
            "created": created,
            "lastModified": updated,
            "location": format!("/scim/v2/Users/{id}"),
        },
    });
    if let Some(external) = external_id {
        doc["externalId"] = json!(external);
    }
    doc
}

/// The address-allow check (CIDR or single address); an empty list allows
/// every address.
pub fn ip_allowed(allow: &[String], ip: Option<IpAddr>) -> bool {
    if allow.is_empty() {
        return true;
    }
    let Some(ip) = ip.map(|ip| ip.to_canonical()) else {
        return false;
    };
    allow.iter().any(|entry| {
        let (net, bits) = match entry.split_once('/') {
            Some((net, bits)) => (net, bits.parse::<u32>().ok()),
            None => (entry.as_str(), None),
        };
        let Ok(net) = net.trim().parse::<IpAddr>() else {
            return false;
        };
        match (ip, net.to_canonical()) {
            (IpAddr::V4(a), IpAddr::V4(n)) => {
                let bits = bits.unwrap_or(32).min(32);
                let mask = u32::MAX.checked_shl(32 - bits).unwrap_or(0);
                u32::from(a) & mask == u32::from(n) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(n)) => {
                let bits = bits.unwrap_or(128).min(128);
                let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                u128::from(a) & mask == u128::from(n) & mask
            }
            _ => false,
        }
    })
}

/// An address or a CIDR (`10.0.0.0/8`, `2001:db8::/32`).
pub fn valid_cidr(entry: &str) -> bool {
    let (net, bits) = match entry.split_once('/') {
        Some((net, bits)) => (net, Some(bits)),
        None => (entry, None),
    };
    let Ok(net) = net.trim().parse::<IpAddr>() else {
        return false;
    };
    let max = if net.is_ipv4() { 32 } else { 128 };
    bits.is_none_or(|b| b.parse::<u32>().is_ok_and(|b| b <= max))
}

// ── Errors ───────────────────────────────────────────────────────────────

/// A SCIM error document.
fn scim_error(status: StatusCode, scim_type: Option<&str>, detail: &str) -> Response {
    let mut body = json!({
        "schemas": [ERROR_SCHEMA],
        "status": status.as_u16().to_string(),
        "detail": detail,
    });
    if let Some(t) = scim_type {
        body["scimType"] = json!(t);
    }
    (status, scim_json(body)).into_response()
}

fn from_app(error: AppError) -> Response {
    match error {
        AppError::NotFound => scim_error(StatusCode::NOT_FOUND, None, "no such resource"),
        AppError::Unauthorized => {
            scim_error(StatusCode::UNAUTHORIZED, None, "bad or revoked token")
        }
        AppError::Forbidden => scim_error(
            StatusCode::FORBIDDEN,
            None,
            "this address may not use the token",
        ),
        AppError::Validation(detail) => {
            scim_error(StatusCode::BAD_REQUEST, Some("invalidValue"), &detail)
        }
        AppError::Conflict(detail) => scim_error(StatusCode::CONFLICT, Some("uniqueness"), detail),
        other => {
            tracing::error!(error = %other, "SCIM request failed");
            scim_error(StatusCode::INTERNAL_SERVER_ERROR, None, "internal error")
        }
    }
}

fn scim_json(body: Value) -> ([(header::HeaderName, &'static str); 1], Json<Value>) {
    (
        [(header::CONTENT_TYPE, "application/scim+json")],
        Json(body),
    )
}

type ScimResult = Result<Response, Response>;

fn bad(detail: impl Into<String>) -> Response {
    scim_error(
        StatusCode::BAD_REQUEST,
        Some("invalidValue"),
        &detail.into(),
    )
}

// ── Tokens ───────────────────────────────────────────────────────────────

/// An authenticated SCIM token.
#[derive(Debug, Clone)]
struct Token {
    id: Uuid,
    name: String,
    /// The administrator who issued it: the actor of its audit events.
    created_by: Uuid,
}

async fn authenticate(
    state: &EngineState,
    headers: &HeaderMap,
    peer: Option<IpAddr>,
) -> Result<Token, Response> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or_else(|| from_app(AppError::Unauthorized))?;
    let (public_id, secret) = presented
        .split_once('.')
        .and_then(|(p, s)| Uuid::parse_str(p).ok().map(|p| (p, s)))
        .ok_or_else(|| from_app(AppError::Unauthorized))?;
    let row: Option<(Uuid, String, String, Vec<String>, bool, Uuid)> = sqlx::query_as(
        "SELECT id, name, secret_hash, ip_allow, is_active, created_by FROM scim_token \
          WHERE public_id = $1",
    )
    .bind(public_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(|e| from_app(AppError::internal(e)))?;
    let ring = state.base.pepper_ring();
    let Some((id, name, hash, ip_allow, active, created_by)) = row else {
        let _ = attome_auth::apikey_hash::hash_peppered_secret(&ring, secret);
        return Err(from_app(AppError::Unauthorized));
    };
    match attome_auth::apikey_hash::verify_peppered_secret(&ring, secret, &hash)
        .await
        .map_err(from_app)?
    {
        attome_auth::VerifyOutcome::Fail => return Err(from_app(AppError::Unauthorized)),
        attome_auth::VerifyOutcome::Ok | attome_auth::VerifyOutcome::OkNeedsRehash => {}
    }
    if !active {
        return Err(from_app(AppError::Unauthorized));
    }
    let client = peer.map(|p| {
        attome_server::middleware::client_ip::client_ip_from_parts(p, headers, &state.base.config)
    });
    if !ip_allowed(&ip_allow, client) {
        return Err(from_app(AppError::Forbidden));
    }
    let _ = sqlx::query("UPDATE scim_token SET last_used_at = now() WHERE id = $1")
        .bind(id)
        .execute(&state.base.db)
        .await;
    Ok(Token {
        id,
        name,
        created_by,
    })
}

fn peer_of(connect: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<IpAddr> {
    connect.map(|Extension(ConnectInfo(addr))| addr.ip())
}

async fn event(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    token: &Token,
    category: MandatoryCategory,
    operation: AuditOperation,
    target: (&'static str, Uuid),
    name: &'static str,
) -> Result<(), AppError> {
    write_security_event(
        tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            category,
            operation,
            token.created_by,
            target.0,
            Some(target.1),
        )
        .named(name)
        .comment(format!("SCIM token {}", token.name)),
    )
    .await
    .map(|_| ())
}

// ── Users ────────────────────────────────────────────────────────────────

type UserRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    bool,
    DateTime<Utc>,
    DateTime<Utc>,
);

const USER_COLUMNS: &str =
    "id, email, user_name, scim_external_id, is_active, created_at, updated_at";

fn user_json(row: &UserRow) -> Value {
    user_resource(
        row.0,
        &row.1,
        row.2.as_deref(),
        row.3.as_deref(),
        row.4,
        row.5,
        row.6,
    )
}

async fn load_user(state: &EngineState, id: Uuid) -> Result<UserRow, AppError> {
    sqlx::query_as(&format!(
        "SELECT {USER_COLUMNS} FROM user_account WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .ok_or(AppError::NotFound)
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListQuery {
    pub filter: Option<String>,
    #[serde(rename = "startIndex")]
    pub start_index: Option<i64>,
    pub count: Option<i64>,
}

fn list_response(resources: Vec<Value>, total: i64, start: i64) -> Value {
    json!({
        "schemas": [LIST_SCHEMA],
        "totalResults": total,
        "startIndex": start,
        "itemsPerPage": resources.len(),
        "Resources": resources,
    })
}

/// Lists users (SCIM).
#[utoipa::path(
    get,
    path = "/scim/v2/Users",
    tag = "integration",
    operation_id = "scim_list_users",
    params(ListQuery),
    responses(
        (status = 200, description = "A SCIM ListResponse of users", body = Object),
        (status = 401, description = "Bad or revoked token"),
        (status = 403, description = "The address may not use the token"),
    ),
)]
async fn list_users(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Query(q): Query<ListQuery>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).clamp(0, MAX_COUNT);
    let filter = q
        .filter
        .as_deref()
        .map(parse_filter)
        .transpose()
        .map_err(bad)?;
    let (by_name, by_external) = match &filter {
        Some(Filter::UserName(v)) => (Some(v.to_lowercase()), None),
        Some(Filter::ExternalId(v)) => (None, Some(v.clone())),
        Some(Filter::DisplayName(_)) => return Err(bad("users filter on userName or externalId")),
        None => (None, None),
    };
    // Users this token provisioned, or found by their sign-in email.
    let scope = "($1::text IS NULL OR email = $1) \
                 AND ($2::text IS NULL OR (scim_external_id = $2 AND scim_token_ref = $3)) \
                 AND ($1::text IS NOT NULL OR scim_token_ref = $3)";
    let rows: Vec<UserRow> = sqlx::query_as(&format!(
        "SELECT {USER_COLUMNS} FROM user_account WHERE {scope} \
          ORDER BY created_at, id OFFSET $4 LIMIT $5"
    ))
    .bind(&by_name)
    .bind(&by_external)
    .bind(token.id)
    .bind(start - 1)
    .bind(count)
    .fetch_all(&state.base.db)
    .await
    .map_err(|e| from_app(AppError::internal(e)))?;
    let total: i64 =
        sqlx::query_scalar(&format!("SELECT count(*) FROM user_account WHERE {scope}"))
            .bind(&by_name)
            .bind(&by_external)
            .bind(token.id)
            .fetch_one(&state.base.db)
            .await
            .map_err(|e| from_app(AppError::internal(e)))?;
    Ok(scim_json(list_response(
        rows.iter().map(user_json).collect(),
        total,
        start,
    ))
    .into_response())
}

/// Reads a user (SCIM).
#[utoipa::path(
    get,
    path = "/scim/v2/Users/{id}",
    tag = "integration",
    operation_id = "scim_get_user",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "A SCIM User", body = Object),
        (status = 401, description = "Bad or revoked token"),
        (status = 404, description = "No such user"),
    ),
)]
async fn get_user(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> ScimResult {
    authenticate(&state, &headers, peer_of(connect)).await?;
    let row = load_user(&state, id).await.map_err(from_app)?;
    Ok(scim_json(user_json(&row)).into_response())
}

/// Writes `doc` onto account `id` (or a new account), with the account
/// state rules of a disable when it turns inactive.
async fn write_user(
    state: &EngineState,
    token: &Token,
    id: Option<Uuid>,
    doc: &UserDoc,
) -> Result<(Uuid, bool), AppError> {
    let email = doc.sign_in_email();
    if !email.contains('@') {
        return Err(AppError::Validation(
            "userName (or a primary email) is an email address".into(),
        ));
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    if !attome_auth::email_identity::try_lock_email(&mut tx, &email).await? {
        return Err(AppError::Conflict(
            "this email is in a concurrent operation; retry",
        ));
    }
    // Bulk-safe: a create repeated with the same externalId is the account
    // already made.
    let existing = match (id, doc.external_id.as_deref()) {
        (Some(id), _) => Some(id),
        (None, Some(external)) => sqlx::query_scalar(
            "SELECT id FROM user_account WHERE scim_token_ref = $1 AND scim_external_id = $2",
        )
        .bind(token.id)
        .bind(external)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::internal)?,
        (None, None) => None,
    };
    let taken: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM user_account WHERE email = $1 AND is_active AND ($2::uuid IS NULL OR id <> $2)",
    )
    .bind(&email)
    .bind(existing)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if taken.is_some() && doc.active {
        return Err(AppError::Conflict("another account has this userName"));
    }
    let (user_id, created, was_active) = match existing {
        Some(user_id) => {
            let was_active: Option<bool> =
                sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1 FOR UPDATE")
                    .bind(user_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(AppError::internal)?;
            let was_active = was_active.ok_or(AppError::NotFound)?;
            sqlx::query(
                "UPDATE user_account SET email = $2, user_name = $3, is_active = $4, \
                        scim_external_id = COALESCE($5, scim_external_id), \
                        scim_token_ref = COALESCE(scim_token_ref, $6), updated_at = now(), \
                        row_version = row_version + 1 \
                  WHERE id = $1",
            )
            .bind(user_id)
            .bind(&email)
            .bind(doc.name())
            .bind(doc.active)
            .bind(&doc.external_id)
            .bind(token.id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (user_id, false, was_active)
        }
        None => {
            let user_id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO user_account \
                     (id, email, user_name, is_active, email_verified, scim_external_id, \
                      scim_token_ref) \
                 VALUES ($1, $2, $3, $4, true, $5, $6)",
            )
            .bind(user_id)
            .bind(&email)
            .bind(doc.name())
            .bind(doc.active)
            .bind(&doc.external_id)
            .bind(token.id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            (user_id, true, doc.active)
        }
    };
    if was_active && !doc.active {
        // As the admin disable: sessions end, API keys go.
        attome_auth::epoch::bump_in_tx(&mut tx, user_id).await?;
        sqlx::query("UPDATE api_key SET is_active = false WHERE user_ref = $1 AND is_active")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    }
    let (operation, name) = if created {
        (AuditOperation::Create, "scim.user_created")
    } else if was_active && !doc.active {
        (AuditOperation::AccountDisabled, "scim.user_deactivated")
    } else if !was_active && doc.active {
        (AuditOperation::AccountEnabled, "scim.user_reactivated")
    } else {
        (AuditOperation::Update, "scim.user_updated")
    };
    event(
        &mut tx,
        state,
        token,
        MandatoryCategory::Security,
        operation,
        ("user_account", user_id),
        name,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((user_id, created))
}

/// Creates a user (SCIM).
#[utoipa::path(
    post,
    path = "/scim/v2/Users",
    tag = "integration",
    operation_id = "scim_create_user",
    request_body(content = Object, description = "A SCIM User"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created (or the account a repeated create already made)", body = Object),
        (status = 400, description = "invalidValue"),
        (status = 401, description = "Bad or revoked token"),
        (status = 409, description = "uniqueness: another account has this userName"),
    ),
)]
async fn create_user(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(body): Json<Value>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let doc = user_from_json(&body).map_err(bad)?;
    let (id, _) = write_user(&state, &token, None, &doc)
        .await
        .map_err(from_app)?;
    let row = load_user(&state, id).await.map_err(from_app)?;
    Ok((StatusCode::CREATED, scim_json(user_json(&row))).into_response())
}

/// Replaces a user (SCIM).
#[utoipa::path(
    put,
    path = "/scim/v2/Users/{id}",
    tag = "integration",
    operation_id = "scim_replace_user",
    params(("id" = Uuid, Path)),
    request_body(content = Object, description = "A SCIM User"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Replaced", body = Object),
        (status = 400, description = "invalidValue"),
        (status = 401, description = "Bad or revoked token"),
        (status = 404, description = "No such user"),
        (status = 409, description = "uniqueness"),
    ),
)]
async fn replace_user(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    load_user(&state, id).await.map_err(from_app)?;
    let doc = user_from_json(&body).map_err(bad)?;
    write_user(&state, &token, Some(id), &doc)
        .await
        .map_err(from_app)?;
    let row = load_user(&state, id).await.map_err(from_app)?;
    Ok(scim_json(user_json(&row)).into_response())
}

/// The account as a SCIM document, to patch.
fn user_doc_of(row: &UserRow) -> UserDoc {
    UserDoc {
        user_name: row.1.clone(),
        external_id: row.3.clone(),
        display_name: row.2.clone(),
        given_name: None,
        family_name: None,
        email: Some(row.1.clone()),
        active: row.4,
    }
}

/// Patches a user (SCIM): `active` false deactivates the account.
#[utoipa::path(
    patch,
    path = "/scim/v2/Users/{id}",
    tag = "integration",
    operation_id = "scim_patch_user",
    params(("id" = Uuid, Path)),
    request_body(content = Object, description = "A SCIM PatchOp"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Patched", body = Object),
        (status = 400, description = "invalidValue"),
        (status = 401, description = "Bad or revoked token"),
        (status = 404, description = "No such user"),
    ),
)]
async fn patch_user(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let row = load_user(&state, id).await.map_err(from_app)?;
    let mut doc = user_doc_of(&row);
    let before_name = doc.user_name.clone();
    apply_user_patch(&mut doc, &body).map_err(bad)?;
    // A patched userName is the new sign-in email.
    if doc.user_name != before_name && doc.email.as_deref() == Some(before_name.as_str()) {
        doc.email = None;
    }
    write_user(&state, &token, Some(id), &doc)
        .await
        .map_err(from_app)?;
    let row = load_user(&state, id).await.map_err(from_app)?;
    Ok(scim_json(user_json(&row)).into_response())
}

/// Deactivates a user (SCIM DELETE): the account stays, inactive.
#[utoipa::path(
    delete,
    path = "/scim/v2/Users/{id}",
    tag = "integration",
    operation_id = "scim_delete_user",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, AuditOperation::AccountDisabled)])))),
    responses(
        (status = 204, description = "Deactivated"),
        (status = 401, description = "Bad or revoked token"),
        (status = 404, description = "No such user"),
    ),
)]
async fn delete_user(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let row = load_user(&state, id).await.map_err(from_app)?;
    let mut doc = user_doc_of(&row);
    doc.active = false;
    write_user(&state, &token, Some(id), &doc)
        .await
        .map_err(from_app)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ── Groups ───────────────────────────────────────────────────────────────

/// A team's name, SCIM external id, and created and updated times.
type GroupRow = (String, Option<String>, DateTime<Utc>, DateTime<Utc>);

async fn group_json(state: &EngineState, id: Uuid) -> Result<Value, AppError> {
    let row: Option<GroupRow> = sqlx::query_as(
        "SELECT name, scim_external_id, created_at, updated_at FROM team \
          WHERE id = $1 AND NOT is_deleted",
    )
    .bind(id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let (name, external, created, updated) = row.ok_or(AppError::NotFound)?;
    let members: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT u.id, u.email FROM user_account_mm_team m JOIN user_account u ON u.id = m.user_ref \
          WHERE m.team_ref = $1 AND NOT m.is_deleted ORDER BY u.email LIMIT 5000",
    )
    .bind(id)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut doc = json!({
        "schemas": [GROUP_SCHEMA],
        "id": id,
        "displayName": name,
        "members": members
            .iter()
            .map(|(id, email)| json!({ "value": id, "display": email, "$ref": format!("/scim/v2/Users/{id}") }))
            .collect::<Vec<_>>(),
        "meta": {
            "resourceType": "Group",
            "created": created,
            "lastModified": updated,
            "location": format!("/scim/v2/Groups/{id}"),
        },
    });
    if let Some(external) = external {
        doc["externalId"] = json!(external);
    }
    Ok(doc)
}

/// Applies membership changes to team `team`, each an Access event.
async fn change_members(
    tx: &mut attome_db::Tx<'_>,
    state: &EngineState,
    token: &Token,
    team: Uuid,
    patch: &GroupPatch,
) -> Result<(), AppError> {
    let current: Vec<Uuid> = sqlx::query_scalar(
        "SELECT user_ref FROM user_account_mm_team WHERE team_ref = $1 AND NOT is_deleted",
    )
    .bind(team)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let (add, remove): (Vec<Uuid>, Vec<Uuid>) = match &patch.replace {
        Some(all) => (
            all.iter()
                .filter(|u| !current.contains(u))
                .copied()
                .collect(),
            current
                .iter()
                .filter(|u| !all.contains(u))
                .copied()
                .collect(),
        ),
        None => (
            patch
                .add
                .iter()
                .filter(|u| !current.contains(u))
                .copied()
                .collect(),
            patch
                .remove
                .iter()
                .filter(|u| current.contains(u))
                .copied()
                .collect(),
        ),
    };
    for user in &add {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM user_account WHERE id = $1)")
                .bind(user)
                .fetch_one(&mut **tx)
                .await
                .map_err(AppError::internal)?;
        if !exists {
            return Err(AppError::Validation(format!("member {user} is not a user")));
        }
        sqlx::query("INSERT INTO user_account_mm_team (user_ref, team_ref) VALUES ($1, $2)")
            .bind(user)
            .bind(team)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?;
    }
    if !remove.is_empty() {
        sqlx::query(
            "UPDATE user_account_mm_team SET is_deleted = true, updated_at = now() \
              WHERE team_ref = $1 AND user_ref = ANY($2) AND NOT is_deleted",
        )
        .bind(team)
        .bind(&remove)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    if !add.is_empty() || !remove.is_empty() {
        event(
            tx,
            state,
            token,
            MandatoryCategory::Access,
            AuditOperation::Update,
            ("team", team),
            "scim.group_members_changed",
        )
        .await?;
    }
    Ok(())
}

/// Lists groups (SCIM).
#[utoipa::path(
    get,
    path = "/scim/v2/Groups",
    tag = "integration",
    operation_id = "scim_list_groups",
    params(ListQuery),
    responses(
        (status = 200, description = "A SCIM ListResponse of groups", body = Object),
        (status = 401, description = "Bad or revoked token"),
    ),
)]
async fn list_groups(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Query(q): Query<ListQuery>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let start = q.start_index.unwrap_or(1).max(1);
    let count = q.count.unwrap_or(100).clamp(0, MAX_COUNT);
    let filter = q
        .filter
        .as_deref()
        .map(parse_filter)
        .transpose()
        .map_err(bad)?;
    let (by_name, by_external) = match &filter {
        Some(Filter::DisplayName(v)) => (Some(v.clone()), None),
        Some(Filter::ExternalId(v)) => (None, Some(v.clone())),
        Some(Filter::UserName(_)) => return Err(bad("groups filter on displayName or externalId")),
        None => (None, None),
    };
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM team WHERE NOT is_deleted AND scim_token_ref = $3 \
            AND ($1::text IS NULL OR name = $1) AND ($2::text IS NULL OR scim_external_id = $2) \
          ORDER BY created_at, id OFFSET $4 LIMIT $5",
    )
    .bind(&by_name)
    .bind(&by_external)
    .bind(token.id)
    .bind(start - 1)
    .bind(count)
    .fetch_all(&state.base.db)
    .await
    .map_err(|e| from_app(AppError::internal(e)))?;
    let mut resources = Vec::with_capacity(ids.len());
    for id in &ids {
        resources.push(group_json(&state, *id).await.map_err(from_app)?);
    }
    let total = i64::try_from(resources.len()).unwrap_or(0) + start - 1;
    Ok(scim_json(list_response(resources, total, start)).into_response())
}

/// Creates a group (SCIM): a team.
#[utoipa::path(
    post,
    path = "/scim/v2/Groups",
    tag = "integration",
    operation_id = "scim_create_group",
    request_body(content = Object, description = "A SCIM Group"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Created (or the team a repeated create already made)", body = Object),
        (status = 400, description = "invalidValue"),
        (status = 401, description = "Bad or revoked token"),
    ),
)]
async fn create_group(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Json(body): Json<Value>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let name = text(&body["displayName"]).ok_or_else(|| bad("displayName is required"))?;
    let external = text(&body["externalId"]);
    let members = member_ids(&body["members"]).map_err(bad)?;
    let run = async {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let existing: Option<Uuid> = match &external {
            Some(external) => sqlx::query_scalar(
                "SELECT id FROM team WHERE scim_token_ref = $1 AND scim_external_id = $2 \
                   AND NOT is_deleted",
            )
            .bind(token.id)
            .bind(external)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?,
            None => None,
        };
        let team = match existing {
            Some(team) => team,
            None => {
                let team = Uuid::now_v7();
                sqlx::query(
                    "INSERT INTO team (id, name, scim_external_id, scim_token_ref) \
                     VALUES ($1, $2, $3, $4)",
                )
                .bind(team)
                .bind(&name)
                .bind(&external)
                .bind(token.id)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
                event(
                    &mut tx,
                    &state,
                    &token,
                    MandatoryCategory::Access,
                    AuditOperation::Create,
                    ("team", team),
                    "scim.group_created",
                )
                .await?;
                team
            }
        };
        change_members(
            &mut tx,
            &state,
            &token,
            team,
            &GroupPatch {
                add: members,
                ..GroupPatch::default()
            },
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        Ok::<Uuid, AppError>(team)
    };
    let team = run.await.map_err(from_app)?;
    let doc = group_json(&state, team).await.map_err(from_app)?;
    Ok((StatusCode::CREATED, scim_json(doc)).into_response())
}

/// Reads a group (SCIM).
#[utoipa::path(
    get,
    path = "/scim/v2/Groups/{id}",
    tag = "integration",
    operation_id = "scim_get_group",
    params(("id" = Uuid, Path)),
    responses(
        (status = 200, description = "A SCIM Group", body = Object),
        (status = 401, description = "Bad or revoked token"),
        (status = 404, description = "No such group"),
    ),
)]
async fn get_group(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> ScimResult {
    authenticate(&state, &headers, peer_of(connect)).await?;
    Ok(scim_json(group_json(&state, id).await.map_err(from_app)?).into_response())
}

/// Patches a group (SCIM): its name and members.
#[utoipa::path(
    patch,
    path = "/scim/v2/Groups/{id}",
    tag = "integration",
    operation_id = "scim_patch_group",
    params(("id" = Uuid, Path)),
    request_body(content = Object, description = "A SCIM PatchOp"),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, AuditOperation::Update)])))),
    responses(
        (status = 204, description = "Patched"),
        (status = 400, description = "invalidValue"),
        (status = 401, description = "Bad or revoked token"),
        (status = 404, description = "No such group"),
    ),
)]
async fn patch_group(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let patch = group_patch(&body).map_err(bad)?;
    group_json(&state, id).await.map_err(from_app)?;
    let run = async {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        if let Some(name) = &patch.display_name {
            sqlx::query("UPDATE team SET name = $2, updated_at = now() WHERE id = $1")
                .bind(id)
                .bind(name)
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            event(
                &mut tx,
                &state,
                &token,
                MandatoryCategory::Access,
                AuditOperation::Update,
                ("team", id),
                "scim.group_renamed",
            )
            .await?;
        }
        change_members(&mut tx, &state, &token, id, &patch).await?;
        attome_db::tx::commit(tx).await?;
        Ok::<(), AppError>(())
    };
    run.await.map_err(from_app)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// Deletes a group (SCIM): the team is removed and its members leave it.
#[utoipa::path(
    delete,
    path = "/scim/v2/Groups/{id}",
    tag = "integration",
    operation_id = "scim_delete_group",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Access, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Deleted"),
        (status = 401, description = "Bad or revoked token"),
        (status = 404, description = "No such group"),
    ),
)]
async fn delete_group(
    State(state): State<EngineState>,
    headers: HeaderMap,
    connect: Option<Extension<ConnectInfo<SocketAddr>>>,
    Path(id): Path<Uuid>,
) -> ScimResult {
    let token = authenticate(&state, &headers, peer_of(connect)).await?;
    let run = async {
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        let done = sqlx::query(
            "UPDATE team SET is_deleted = true, updated_at = now() WHERE id = $1 AND NOT is_deleted",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        if done.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        sqlx::query(
            "UPDATE user_account_mm_team SET is_deleted = true, updated_at = now() \
              WHERE team_ref = $1 AND NOT is_deleted",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        event(
            &mut tx,
            &state,
            &token,
            MandatoryCategory::Access,
            AuditOperation::SoftDelete,
            ("team", id),
            "scim.group_deleted",
        )
        .await?;
        attome_db::tx::commit(tx).await?;
        Ok::<(), AppError>(())
    };
    run.await.map_err(from_app)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ── Token administration ────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct NewScimToken {
    /// The identity provider it is for (`Entra ID`, `Okta`, ...).
    pub name: String,
    /// Addresses or CIDRs the IdP calls from; none for any.
    #[serde(default)]
    pub ip_allow: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IssuedScimToken {
    pub id: Uuid,
    pub name: String,
    /// The bearer token, shown this once.
    pub token: String,
}

#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct ScimTokenSummary {
    pub id: Uuid,
    pub name: String,
    pub ip_allow: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Issues a SCIM token for an identity provider.
#[utoipa::path(
    post,
    path = "/api/v1/admin/scim/tokens",
    tag = "admin",
    operation_id = "scim_issue_token",
    request_body = NewScimToken,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Issued; the token is shown once", body = IssuedScimToken),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn issue_token(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<NewScimToken>,
) -> Result<(StatusCode, Json<IssuedScimToken>), AppError> {
    let name = body.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(AppError::Validation("name is 1 to 100 characters".into()));
    }
    if body.ip_allow.len() > 100 || !body.ip_allow.iter().all(|e| valid_cidr(e)) {
        return Err(AppError::Validation(
            "ip_allow is at most 100 addresses or CIDRs".into(),
        ));
    }
    let id = Uuid::now_v7();
    let public_id = Uuid::now_v7();
    let secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let hash = attome_auth::apikey_hash::hash_peppered_secret(&state.base.pepper_ring(), &secret);
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    sqlx::query(
        "INSERT INTO scim_token (id, public_id, name, secret_hash, ip_allow, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(public_id)
    .bind(name)
    .bind(&hash)
    .bind(&body.ip_allow)
    .bind(ctx.user_id)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::Create,
            ctx.user_id,
            "scim_token",
            Some(id),
        )
        .named("scim.token_issued")
        .comment(format!("SCIM token for {name}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok((
        StatusCode::CREATED,
        Json(IssuedScimToken {
            id,
            name: name.to_owned(),
            token: format!("{public_id}.{secret}"),
        }),
    ))
}

/// Lists SCIM tokens (never their secrets).
#[utoipa::path(
    get,
    path = "/api/v1/admin/scim/tokens",
    tag = "admin",
    operation_id = "scim_list_tokens",
    responses(
        (status = 200, description = "Success", body = PaginatedResponse<ScimTokenSummary>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_tokens(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
) -> Result<Json<PaginatedResponse<ScimTokenSummary>>, AppError> {
    let items: Vec<ScimTokenSummary> = sqlx::query_as(
        "SELECT id, name, ip_allow, is_active, created_at, last_used_at FROM scim_token \
          ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total = i64::try_from(items.len()).unwrap_or(0);
    Ok(Json(PaginatedResponse::new(items, total, 1, 200)))
}

/// Revokes a SCIM token.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/scim/tokens/{id}",
    tag = "admin",
    operation_id = "scim_revoke_token",
    params(("id" = Uuid, Path)),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Credential, AuditOperation::SoftDelete)])))),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such active token", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn revoke_token(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let done = sqlx::query("UPDATE scim_token SET is_active = false WHERE id = $1 AND is_active")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if done.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(&state),
        SecurityEvent::new(
            MandatoryCategory::Credential,
            AuditOperation::SoftDelete,
            ctx.user_id,
            "scim_token",
            Some(id),
        )
        .named("scim.token_revoked"),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The SCIM routes (bypass-listed by their `/scim/v2/` prefix; the token is
/// the credential) and the token administration.
pub fn routes() -> Router<EngineState> {
    Router::new()
        .route("/scim/v2/Users", get(list_users).post(create_user))
        .route(
            "/scim/v2/Users/{id}",
            get(get_user)
                .put(replace_user)
                .patch(patch_user)
                .delete(delete_user),
        )
        .route("/scim/v2/Groups", get(list_groups).post(create_group))
        .route(
            "/scim/v2/Groups/{id}",
            get(get_group).patch(patch_group).delete(delete_group),
        )
        .route(
            "/api/v1/admin/scim/tokens",
            post(issue_token).get(list_tokens),
        )
        .route(
            "/api/v1/admin/scim/tokens/{id}",
            axum::routing::delete(revoke_token),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_users,
        get_user,
        create_user,
        replace_user,
        patch_user,
        delete_user,
        list_groups,
        create_group,
        get_group,
        patch_group,
        delete_group,
        issue_token,
        list_tokens,
        revoke_token
    ),
    components(schemas(NewScimToken, IssuedScimToken, ScimTokenSummary))
)]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entra ID's create (from its SCIM validator).
    fn entra_create() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User",
                        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
            "externalId": "8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159",
            "userName": "Test_User_ab6490ee-1e48-479e-a20b-2d77186b5dd1@contoso.sa",
            "active": true,
            "displayName": "Sara Al-Otaibi",
            "emails": [{ "primary": true, "type": "work", "value": "Sara.Otaibi@contoso.sa" }],
            "name": { "givenName": "Sara", "familyName": "Al-Otaibi" }
        })
    }

    /// Okta's create.
    fn okta_create() -> Value {
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "omar@example.sa",
            "name": { "givenName": "Omar", "familyName": "Haddad" },
            "emails": [{ "primary": true, "value": "omar@example.sa", "type": "work" }],
            "displayName": "Omar Haddad",
            "locale": "en-US",
            "externalId": "00ujl29u0le5T6Aj10h7",
            "groups": [],
            "password": "never-stored",
            "active": true
        })
    }

    #[test]
    fn scim_entra_and_okta_users_are_read() {
        let entra = user_from_json(&entra_create()).unwrap();
        assert_eq!(
            entra.sign_in_email(),
            "sara.otaibi@contoso.sa",
            "the primary email"
        );
        assert_eq!(entra.name(), "Sara Al-Otaibi");
        assert_eq!(
            entra.external_id.as_deref(),
            Some("8aa1a0c0-c4c3-4bc0-b4a5-2ef676900159")
        );
        assert!(entra.active);
        let okta = user_from_json(&okta_create()).unwrap();
        assert_eq!(okta.sign_in_email(), "omar@example.sa");
        assert_eq!(okta.external_id.as_deref(), Some("00ujl29u0le5T6Aj10h7"));
        assert!(
            user_from_json(&json!({ "active": true })).is_err(),
            "userName is required"
        );
    }

    #[test]
    fn scim_filters_parse() {
        assert_eq!(
            parse_filter("userName eq \"sara@contoso.sa\"").unwrap(),
            Filter::UserName("sara@contoso.sa".into())
        );
        assert_eq!(
            parse_filter("externalId EQ \"00ujl29u0le5T6Aj10h7\"").unwrap(),
            Filter::ExternalId("00ujl29u0le5T6Aj10h7".into())
        );
        assert_eq!(
            parse_filter("displayName eq \"Sales Team\"").unwrap(),
            Filter::DisplayName("Sales Team".into())
        );
        assert!(parse_filter("userName co \"sara\"").is_err());
        assert!(parse_filter("title eq \"x\"").is_err());
    }

    #[test]
    fn scim_entra_patch_deactivates_and_changes_email() {
        let mut user = user_from_json(&entra_create()).unwrap();
        apply_user_patch(
            &mut user,
            &json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    { "op": "Replace", "path": "active", "value": "False" },
                    { "op": "Add", "path": "emails[type eq \"work\"].value", "value": "sara@new.sa" },
                    { "op": "Replace", "path": "name.familyName", "value": "Otaibi" }
                ]
            }),
        )
        .unwrap();
        assert!(!user.active, "Entra sends the boolean as a string");
        assert_eq!(user.sign_in_email(), "sara@new.sa");
        assert_eq!(user.family_name.as_deref(), Some("Otaibi"));
    }

    #[test]
    fn scim_okta_patch_without_a_path() {
        let mut user = user_from_json(&okta_create()).unwrap();
        apply_user_patch(
            &mut user,
            &json!({ "Operations": [{ "op": "replace", "value": { "active": false } }] }),
        )
        .unwrap();
        assert!(!user.active);
        assert!(apply_user_patch(&mut user, &json!({ "Operations": [{ "op": "move" }] })).is_err());
    }

    #[test]
    fn scim_group_patches_from_both_idps() {
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        // Okta adds members with a path.
        let okta = group_patch(&json!({ "Operations": [
            { "op": "add", "path": "members", "value": [{ "value": a.to_string(), "display": "x" }] }
        ]}))
        .unwrap();
        assert_eq!(okta.add, vec![a]);
        // Entra removes one by filter and renames without a path.
        let entra = group_patch(&json!({ "Operations": [
            { "op": "Remove", "path": format!("members[value eq \"{b}\"]") },
            { "op": "Replace", "value": { "displayName": "Sales East" } }
        ]}))
        .unwrap();
        assert_eq!(entra.remove, vec![b]);
        assert_eq!(entra.display_name.as_deref(), Some("Sales East"));
        let replace = group_patch(&json!({ "Operations": [
            { "op": "replace", "path": "members", "value": [{ "value": a.to_string() }] }
        ]}))
        .unwrap();
        assert_eq!(replace.replace, Some(vec![a]));
        assert!(
            group_patch(&json!({ "Operations": [
                { "op": "add", "path": "members", "value": [{ "value": "not-an-id" }] }
            ]}))
            .is_err()
        );
    }

    #[test]
    fn scim_token_addresses() {
        let allow = vec!["10.0.0.0/8".to_owned(), "2001:db8::1".to_owned()];
        assert!(ip_allowed(&allow, "10.2.3.4".parse().ok()));
        assert!(ip_allowed(&allow, "2001:db8::1".parse().ok()));
        assert!(!ip_allowed(&allow, "192.168.1.1".parse().ok()));
        assert!(
            !ip_allowed(&allow, None),
            "an unknown address is refused when a list is set"
        );
        assert!(ip_allowed(&[], None), "no list, any address");
        assert!(valid_cidr("10.0.0.0/8") && valid_cidr("1.2.3.4") && valid_cidr("2001:db8::/32"));
        assert!(!valid_cidr("10.0.0.0/33") && !valid_cidr("nope"));
    }

    #[test]
    fn scim_user_resource_shape() {
        let id = Uuid::now_v7();
        let now = Utc::now();
        let doc = user_resource(
            id,
            "omar@example.sa",
            Some("Omar"),
            Some("00u1"),
            true,
            now,
            now,
        );
        assert_eq!(doc["schemas"][0], USER_SCHEMA);
        assert_eq!(doc["userName"], "omar@example.sa");
        assert_eq!(doc["externalId"], "00u1");
        assert_eq!(doc["meta"]["location"], format!("/scim/v2/Users/{id}"));
        assert!(doc.get("password").is_none(), "no secret is ever returned");
    }
}
