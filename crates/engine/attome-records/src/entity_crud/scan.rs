//! Scan to find (roadmap B16-T5): `GET /api/v1/scan/find` resolves a scanned
//! value to the records holding it in a scan-enabled field (`options.scan`,
//! B16-T3).
//!
//! Every hit goes through [`super::resolve_visible`], so a record the caller
//! may not read never appears, and the caller's entity read privilege is
//! checked before an entity is searched at all. Sensitive fields are never
//! matched: a hit on one would confirm a value the caller may not see. The
//! whole route is hidden (404) while the `scan.enabled` flag is off.

use std::collections::HashMap;

use attome_core::{EngineState, EntityMeta, FieldType, quote_ident};
use attome_security::SecurityContextExt;
use attome_server::authz::{Authorized, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse, PaginatedResponse};
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

/// At most this many scan-enabled fields are searched for one scan.
pub const MAX_SCAN_ATTRIBUTES: usize = 20;
/// At most this many records are returned for one scan.
pub const MAX_SCAN_HITS: usize = 50;
/// The longest value accepted; no barcode format comes near it.
const MAX_SCAN_VALUE_CHARS: usize = 512;

#[derive(Debug, Deserialize, IntoParams)]
pub struct ScanFindQuery {
    /// The scanned value, exactly as read.
    pub value: String,
    /// Search only this entity's scan-enabled fields.
    #[serde(default)]
    pub entity: Option<String>,
}

/// A record whose scan-enabled field holds the scanned value.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ScanHit {
    pub entity: String,
    pub id: Uuid,
    /// The record's primary name, when its entity declares one.
    pub name: Option<String>,
    /// The field that matched.
    pub attribute: String,
}

/// One searchable field: the entity, its id, the column and how to compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScanAttribute {
    pub entity: String,
    pub entity_id: Uuid,
    pub attribute: String,
    pub numeric: bool,
}

/// The scan-enabled, non-sensitive text and number fields, optionally of one
/// entity, in a stable order and capped at [`MAX_SCAN_ATTRIBUTES`].
pub(crate) fn scan_attributes<'a>(
    entities: impl Iterator<Item = &'a EntityMeta>,
    only: Option<&str>,
) -> Vec<ScanAttribute> {
    let mut found: Vec<ScanAttribute> = entities
        .filter(|meta| only.is_none_or(|name| meta.logicalname == name))
        .flat_map(|meta| {
            meta.attrs.iter().filter_map(move |attr| {
                let scan = attr.options.as_ref()?.get("scan")?;
                let enabled = scan
                    .get("enabled")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true);
                if !enabled || attr.is_sensitive {
                    return None;
                }
                let numeric = match attr.storage_type() {
                    FieldType::Text => false,
                    FieldType::Number => true,
                    _ => return None,
                };
                Some(ScanAttribute {
                    entity: meta.logicalname.clone(),
                    entity_id: meta.entity_id,
                    attribute: attr.logicalname.clone(),
                    numeric,
                })
            })
        })
        .collect();
    found.sort_by(|a, b| (&a.entity, &a.attribute).cmp(&(&b.entity, &b.attribute)));
    found.truncate(MAX_SCAN_ATTRIBUTES);
    found
}

/// Checks the scanned value: present, not padded, not absurdly long.
pub(crate) fn check_scan_value(value: &str) -> Result<&str, AppError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(AppError::Validation("value: scan a code first".into()));
    }
    if value.chars().count() > MAX_SCAN_VALUE_CHARS {
        return Err(AppError::Validation(format!(
            "value: at most {MAX_SCAN_VALUE_CHARS} characters"
        )));
    }
    Ok(value)
}

/// `true` when `value` can be compared with a number column without a cast
/// error.
fn is_number(value: &str) -> bool {
    value.parse::<f64>().is_ok_and(f64::is_finite)
}

/// The records the caller may read whose scan-enabled field holds `value`.
pub async fn find_scanned(
    state: &EngineState,
    ctx: &SecurityContext,
    value: &str,
    entity: Option<&str>,
) -> Result<Vec<ScanHit>, AppError> {
    let value = check_scan_value(value)?;
    let attributes = scan_attributes(state.entities.load().iter(), entity);
    let mut hits: Vec<ScanHit> = Vec::new();
    for attr in attributes {
        if hits.len() >= MAX_SCAN_HITS {
            break;
        }
        if ctx.require(&attr.entity, "read").is_err() || (attr.numeric && !is_number(value)) {
            continue;
        }
        let compare = if attr.numeric { "$1::numeric" } else { "$1" };
        let sql = format!(
            "SELECT id FROM {} WHERE {} = {compare} \
             AND (is_active IS NULL OR is_active = TRUE) ORDER BY id LIMIT $2",
            quote_ident(&attr.entity),
            quote_ident(&attr.attribute),
        );
        let remaining = MAX_SCAN_HITS - hits.len();
        let sql = attome_db::tag_dynamic("entity.scan", &sql);
        let ids: Vec<Uuid> = sqlx::query_scalar(&sql)
            .bind(value)
            .bind(i64::try_from(remaining).unwrap_or(i64::MAX))
            .fetch_all(&state.base.db)
            .await
            .map_err(attome_db::classify)?;
        if ids.is_empty() {
            continue;
        }
        let visible: HashMap<Uuid, super::ResolvedLookup> =
            super::resolve_visible(state, ctx, attr.entity_id, &ids).await;
        for id in ids {
            if let Some(found) = visible.get(&id)
                && found.exists
                && found.is_active
                && !hits
                    .iter()
                    .any(|hit| hit.id == id && hit.entity == attr.entity)
            {
                hits.push(ScanHit {
                    entity: attr.entity.clone(),
                    id,
                    name: found.name.clone(),
                    attribute: attr.attribute.clone(),
                });
            }
        }
    }
    hits.truncate(MAX_SCAN_HITS);
    Ok(hits)
}

// ── Routes ──────────────────────────────────────────────────────────────────

/// B16-T5: the records a scanned code points at.
#[utoipa::path(
    get,
    path = "/api/v1/scan/find",
    tag = "entity",
    params(ScanFindQuery),
    responses(
        (status = 200, description = "Readable records holding the value, at most 50", body = PaginatedResponse<ScanHit>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 404, description = "Scanning is switched off", body = ErrorResponse),
        (status = 422, description = "Empty or overlong value", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn scan_find(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<ScanFindQuery>,
) -> Result<Json<PaginatedResponse<ScanHit>>, AppError> {
    if !state.feature_flags().is_on("scan.enabled", &ctx).await {
        return Err(AppError::NotFound);
    }
    let hits = find_scanned(&state, &ctx, &query.value, query.entity.as_deref()).await?;
    let total = i64::try_from(hits.len()).unwrap_or(i64::MAX);
    Ok(Json(PaginatedResponse::new(
        hits,
        total,
        1,
        i64::try_from(MAX_SCAN_HITS).unwrap_or(i64::MAX),
    )))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(scan_find))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use attome_core::{AttrInfo, OnTargetDelete};
    use serde_json::json;

    fn attr(name: &str, field_type_int: i32, options: Option<serde_json::Value>) -> AttrInfo {
        AttrInfo {
            logicalname: name.to_owned(),
            field_type_int,
            is_required: false,
            max_length: None,
            is_sensitive: false,
            is_write_restricted: false,
            is_sortable: false,
            is_filterable: true,
            lookup_entity_ref: None,
            on_target_delete: OnTargetDelete::Orphan,
            data_classification: Default::default(),
            options,
        }
    }

    fn entity(name: &str, attrs: Vec<AttrInfo>) -> EntityMeta {
        EntityMeta {
            entity_id: Uuid::now_v7(),
            logicalname: name.to_owned(),
            attrs,
            is_append_only: false,
            primary_name_attribute: Some("name".to_owned()),
        }
    }

    fn scan() -> Option<serde_json::Value> {
        Some(json!({ "scan": { "formats": ["ean_13"] } }))
    }

    #[test]
    fn only_scan_enabled_text_and_number_fields_are_searched() {
        let mut secret = attr("pin", 3, scan());
        secret.is_sensitive = true;
        let entities = [
            entity(
                "asset",
                vec![
                    attr("serial", 3, scan()),
                    attr("name", 3, None),
                    attr("tag_no", 1, scan()),
                    attr("owner", 11, scan()),
                    attr(
                        "old_code",
                        3,
                        Some(json!({ "scan": { "enabled": false, "formats": ["ean_13"] } })),
                    ),
                    secret,
                ],
            ),
            entity("product", vec![attr("gtin", 3, scan())]),
        ];
        let found = scan_attributes(entities.iter(), None);
        let names: Vec<(&str, &str, bool)> = found
            .iter()
            .map(|a| (a.entity.as_str(), a.attribute.as_str(), a.numeric))
            .collect();
        assert_eq!(
            names,
            [
                ("asset", "serial", false),
                ("asset", "tag_no", true),
                ("product", "gtin", false),
            ]
        );
        let only = scan_attributes(entities.iter(), Some("product"));
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].attribute, "gtin");
    }

    #[test]
    fn attributes_are_capped() {
        let attrs = (0..30)
            .map(|i| attr(&format!("code_{i:02}"), 3, scan()))
            .collect();
        let entities = [entity("asset", attrs)];
        assert_eq!(
            scan_attributes(entities.iter(), None).len(),
            MAX_SCAN_ATTRIBUTES
        );
    }

    #[test]
    fn scan_value_is_checked() {
        assert_eq!(
            check_scan_value(" 4006381333931 ").ok(),
            Some("4006381333931")
        );
        assert!(matches!(
            check_scan_value("  "),
            Err(AppError::Validation(_))
        ));
        let long = "9".repeat(MAX_SCAN_VALUE_CHARS + 1);
        assert!(matches!(
            check_scan_value(&long),
            Err(AppError::Validation(_))
        ));
        assert!(is_number("12.5"));
        assert!(!is_number("ABC-1"));
        assert!(!is_number("NaN"));
    }
}
