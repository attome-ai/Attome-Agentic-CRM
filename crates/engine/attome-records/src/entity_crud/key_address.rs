//! Address a record by a unique business key (roadmap S1-T6):
//! `GET` and `PATCH /api/v1/{entity}/key/{keyspec}`, where `keyspec` is
//! `attr=value` pairs joined by `,` (e.g. `accountnumber=A-100`). The
//! attributes must be the entity's declared business key, one external-id
//! attribute, or a key an upsert already built a unique index for; anything
//! else is 422 `not a unique key`. The record is then read or updated
//! through exactly the same handlers as `/api/v1/{entity}/{id}`.

use attome_auth::SessionClaims;
use attome_core::changeset::RecordingCtx;
use attome_core::{AttrInfo, EngineState, quote_ident};
use attome_security::record_action::{Read, Update};
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::resolve::resolve_entity;

/// The most `attr=value` pairs a key takes.
const MAX_PAIRS: usize = 4;

/// The name of the unique index an upsert builds for `match_attr_names`
/// (in the order given), the same one `upsert` creates.
pub(crate) fn upsert_index_name(entity_name: &str, match_attr_names: &[&str]) -> String {
    let key_material = match_attr_names.join("_");
    let digest = format!("{:x}", Sha256::digest(key_material.as_bytes()));
    format!("ux_{entity_name}_upsert_{}", &digest[..16])
}

/// `a=1,b=x` into `[("a", "1"), ("b", "x")]`.
pub fn parse_keyspec(raw: &str) -> Result<Vec<(String, String)>, AppError> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for part in raw.split(',') {
        let (name, value) = part
            .split_once('=')
            .ok_or_else(|| AppError::Validation(format!("key part {part:?} is not attr=value")))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(AppError::Validation("a key part has no attribute".into()));
        }
        if pairs.iter().any(|(n, _)| n == name) {
            return Err(AppError::Validation(format!("key names {name} twice")));
        }
        pairs.push((name.to_owned(), value.to_owned()));
    }
    if pairs.len() > MAX_PAIRS {
        return Err(AppError::Validation(format!(
            "a key takes at most {MAX_PAIRS} attributes"
        )));
    }
    Ok(pairs)
}

/// The id of the live record `pairs` names: 404 when none, 409 when the
/// key is not unique after all.
async fn resolve_key(
    state: &EngineState,
    entity_name: &str,
    attrs: &[AttrInfo],
    is_append_only: bool,
    pairs: &[(String, String)],
) -> Result<Uuid, AppError> {
    let mut key_attrs: Vec<&AttrInfo> = Vec::with_capacity(pairs.len());
    for (name, _) in pairs {
        let attr = attrs
            .iter()
            .find(|a| &a.logicalname == name)
            .ok_or_else(|| AppError::Validation("not a unique key".into()))?;
        key_attrs.push(attr);
    }
    let names: Vec<&str> = pairs.iter().map(|(n, _)| n.as_str()).collect();
    let business_key = attome_metadata::provision::read_business_key(&state.base.db, entity_name)
        .await?
        .and_then(|k| k.fields)
        .unwrap_or_default();
    let is_business_key = !business_key.is_empty()
        && business_key.len() == names.len()
        && business_key.iter().all(|f| names.contains(&f.as_str()));
    let is_external = key_attrs.len() == 1 && super::upsert::is_external_id(key_attrs[0]);
    let unique = is_business_key
        || is_external
        || sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
            .bind(quote_ident(&upsert_index_name(entity_name, &names)))
            .fetch_one(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if !unique {
        return Err(AppError::Validation("not a unique key".into()));
    }
    let mut conditions: Vec<String> = key_attrs
        .iter()
        .enumerate()
        .map(|(i, attr)| {
            format!(
                "{} = ${}{}",
                quote_ident(&attr.logicalname),
                i + 1,
                crate::entity_mutation::sql_cast(attr)
            )
        })
        .collect();
    if let Some(live) = attome_core::live_row_predicate("t", is_append_only) {
        conditions.push(live);
    }
    let sql = format!(
        "SELECT t.id FROM {} t WHERE {} LIMIT 2",
        quote_ident(entity_name),
        conditions.join(" AND ")
    );
    let mut query = sqlx::query_scalar::<_, Uuid>(&sql);
    for (_, value) in pairs {
        query = query.bind(value);
    }
    let ids = query
        .fetch_all(&state.base.db)
        .await
        .map_err(|_| AppError::Validation("a key value does not fit its attribute".into()))?;
    match ids.as_slice() {
        [] => Err(AppError::NotFound),
        [id] => Ok(*id),
        _ => Err(AppError::Conflict("more than one record has this key")),
    }
}

async fn id_for(state: &EngineState, entity_input: &str, keyspec: &str) -> Result<Uuid, AppError> {
    let pairs = parse_keyspec(keyspec)?;
    let (_, entity_name, attrs, is_append_only) = resolve_entity(state, entity_input).await?;
    resolve_key(state, &entity_name, &attrs, is_append_only, &pairs).await
}

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/key/{keyspec}",
    tag = "entity",
    operation_id = "get_record_by_key",
    params(
        ("entity" = String, Path),
        ("keyspec" = String, Path, description = "attr=value pairs joined by `,`, naming a unique key"),
        super::response::SelectParam,
        super::expand::ExpandParam,
    ),
    responses(
        (status = 200, description = "The record, as GET /api/v1/{entity}/{id} returns it"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No live record has this key", body = ErrorResponse),
        (status = 409, description = "More than one record has this key", body = ErrorResponse),
        (status = 422, description = "The attributes are not a unique key", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_by_key(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, keyspec)): Path<(String, String)>,
    select: Query<super::response::SelectParam>,
    expand: Query<super::expand::ExpandParam>,
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, AppError> {
    let id = id_for(&state, &entity_input, &keyspec).await?;
    super::mutations::get_record(
        State(state),
        ctx,
        Path((entity_input, id)),
        select,
        expand,
        headers,
    )
    .await
}

#[utoipa::path(
    patch,
    path = "/api/v1/{entity}/key/{keyspec}",
    tag = "entity",
    operation_id = "update_record_by_key",
    params(
        ("entity" = String, Path),
        ("keyspec" = String, Path, description = "attr=value pairs joined by `,`, naming a unique key"),
    ),
    responses(
        (status = 200, description = "The updated record, as PATCH /api/v1/{entity}/{id} returns it"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No live record has this key", body = ErrorResponse),
        (status = 409, description = "The record changed since If-Match, or more than one record has this key", body = ErrorResponse),
        (status = 422, description = "The attributes are not a unique key, or If-Match is missing", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn patch_by_key(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    claims: Extension<SessionClaims>,
    recording: RecordingCtx,
    Path((entity_input, keyspec)): Path<(String, String)>,
    select: Query<super::response::SelectParam>,
    cookie: Option<Extension<attome_server::middleware::auth::CookieSession>>,
    headers: axum::http::HeaderMap,
    body: Json<Value>,
) -> Result<axum::response::Response, AppError> {
    let id = id_for(&state, &entity_input, &keyspec).await?;
    super::mutations::update_record(
        State(state),
        ctx,
        claims,
        recording,
        Path((entity_input, id)),
        select,
        cookie,
        headers,
        body,
    )
    .await
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(get_by_key, patch_by_key))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keyspec_reads_pairs() {
        assert_eq!(
            parse_keyspec("accountnumber=A-100").expect("one"),
            vec![("accountnumber".to_owned(), "A-100".to_owned())]
        );
        assert_eq!(
            parse_keyspec("country=SA,code=1=2").expect("two"),
            vec![
                ("country".to_owned(), "SA".to_owned()),
                ("code".to_owned(), "1=2".to_owned())
            ],
            "only the first = splits"
        );
        assert_eq!(
            upsert_index_name("account", &["accountnumber"]),
            upsert_index_name("account", &["accountnumber"])
        );
    }

    #[test]
    fn parse_keyspec_rejects_duplicates_and_more_than_four() {
        assert!(parse_keyspec("a=1,a=2").is_err());
        assert!(parse_keyspec("a=1,b=2,c=3,d=4,e=5").is_err());
        assert!(parse_keyspec("novalue").is_err());
        assert!(parse_keyspec("=x").is_err());
    }
}
