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

/// Find records by a scanned code
///
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

// ── B16-T8: act on a scan ───────────────────────────────────────────────────

/// Where the device was, when the person lets scans record it.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, ToSchema)]
pub struct ScanLocation {
    pub lat: f64,
    pub lng: f64,
}

/// `POST /api/v1/scan/act`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ScanActBody {
    /// The scanned value, exactly as read.
    pub value: String,
    pub scan_action_id: Uuid,
    #[serde(default)]
    pub location: Option<ScanLocation>,
}

/// What a scan did.
#[derive(Debug, Serialize, ToSchema)]
pub struct ScanActResult {
    /// `done`, or `ambiguous` (409) with the records that matched.
    pub status: String,
    /// `open`, `run_workflow` or `set_field`.
    pub action_kind: String,
    pub record: Option<ScanHit>,
    /// The workflow instance a `run_workflow` started.
    pub workflow_instance_id: Option<Uuid>,
    /// Every match, when there was more than one.
    pub hits: Vec<ScanHit>,
}

#[derive(Debug, sqlx::FromRow)]
struct ScanActionRow {
    entity_logicalname: String,
    match_attribute: Option<String>,
    code_pattern: Option<String>,
    action_kind: String,
    workflow_ref: Option<Uuid>,
    set_field_attribute: Option<String>,
    set_field_value: Option<String>,
}

/// Whether a scanned value fits the action's code pattern (a full-match
/// regular expression); no pattern accepts every value. Pure.
pub fn fits_pattern(value: &str, pattern: Option<&str>) -> Result<bool, AppError> {
    match pattern.map(str::trim).filter(|p| !p.is_empty()) {
        None => Ok(true),
        Some(pattern) => attome_rules::full_match_regex(pattern)
            .map(|re| re.is_match(value))
            .map_err(|_| {
                AppError::Validation("the scan action's code pattern is not valid".into())
            }),
    }
}

/// Whether the person lets scans record where they were (personal setting
/// `scan.record_location`, off unless they turn it on).
fn records_location(state: &EngineState, ctx: &SecurityContext) -> bool {
    let settings = state.settings.load();
    attome_core::setting_registry()
        .get("scan.record_location")
        .map(|d| settings.resolve(d, Some(ctx.user_id), None).0)
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

/// Runs a scan action (B16-T8): resolves the scanned record exactly as
/// `scan/find` does, under the caller's permissions, then opens it, starts
/// its workflow or sets its field (through the entity engine, at the
/// record's current version), with one business event in the same
/// transaction as the change.
pub async fn act(
    state: &EngineState,
    ctx: &SecurityContext,
    body: &ScanActBody,
) -> Result<(axum::http::StatusCode, ScanActResult), AppError> {
    let action: ScanActionRow = sqlx::query_as(
        "SELECT entity_logicalname, match_attribute, code_pattern, action_kind::text AS action_kind, \
                workflow_ref, set_field_attribute, set_field_value \
           FROM scan_action \
          WHERE id = $1 AND (is_active IS NULL OR is_active = TRUE) AND coalesce(enabled, true)",
    )
    .bind(body.scan_action_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(attome_db::classify)?
    .ok_or(AppError::NotFound)?;
    let value = check_scan_value(&body.value)?;
    if !fits_pattern(value, action.code_pattern.as_deref())? {
        return Err(AppError::Validation(
            "value: this code is not one this scan action takes".into(),
        ));
    }
    let mut hits =
        find_scanned(state, ctx, value, Some(action.entity_logicalname.as_str())).await?;
    if let Some(attribute) = action.match_attribute.as_deref().filter(|a| !a.is_empty()) {
        hits.retain(|hit| hit.attribute == attribute);
    }
    let kind = action.action_kind.clone();
    match hits.len() {
        0 => return Err(AppError::NotFound),
        1 => {}
        _ => {
            return Ok((
                axum::http::StatusCode::CONFLICT,
                ScanActResult {
                    status: "ambiguous".into(),
                    action_kind: kind,
                    record: None,
                    workflow_instance_id: None,
                    hits,
                },
            ));
        }
    }
    let hit = hits.remove(0);
    let location = body
        .location
        .filter(|_| records_location(state, ctx))
        .map(|l| format!(" at {:.5},{:.5}", l.lat, l.lng))
        .unwrap_or_default();
    let comment = format!(
        "scan action {} ({kind}) on {} {}{location}",
        body.scan_action_id, hit.entity, hit.id
    );

    // A workflow starts through the starter's own transaction, before ours.
    let mut workflow_instance_id = None;
    if kind == "run_workflow" {
        ctx.require(&hit.entity, "update")?;
        let definition: String = sqlx::query_scalar(
            "SELECT logicalname FROM workflow_definition               WHERE id = $1 AND is_active = TRUE AND is_deleted = FALSE",
        )
        .bind(action.workflow_ref)
        .fetch_optional(&state.base.db)
        .await
        .map_err(attome_db::classify)?
        .ok_or_else(|| AppError::Validation("the scan action names no active workflow".into()))?;
        let starter = state.workflow_starter.as_ref().ok_or(AppError::NotFound)?;
        workflow_instance_id = Some(
            starter
                .start(
                    state,
                    attome_core::workflow_start::WorkflowStartRequest {
                        definition_logicalname: definition,
                        started_by: ctx.user_id,
                        correlation_entity_id: Some(hit.id),
                        context: serde_json::json!({
                            // B16-T13: enters at the flow's `scan` trigger.
                            "trigger": "scan",
                            "entity": hit.entity,
                            "record_id": hit.id,
                            "scanned": value,
                        }),
                    },
                )
                .await?,
        );
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    match kind.as_str() {
        "open" | "run_workflow" => {}
        "set_field" => {
            ctx.require(&hit.entity, "update")?;
            let attribute = action
                .set_field_attribute
                .as_deref()
                .filter(|a| !a.is_empty())
                .ok_or_else(|| {
                    AppError::Validation("the scan action names no field to set".into())
                })?;
            let (entity_id, entity_name, attrs, _) =
                super::resolve::resolve_entity(state, &hit.entity).await?;
            let row_version: i64 = sqlx::query_scalar(&attome_db::tag_dynamic(
                "entity.scan",
                &format!(
                    "SELECT row_version FROM {} WHERE id = $1",
                    quote_ident(&entity_name)
                ),
            ))
            .bind(hit.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(attome_db::classify)?;
            let mut patch = serde_json::Map::new();
            patch.insert(
                attribute.to_owned(),
                serde_json::Value::String(action.set_field_value.clone().unwrap_or_default()),
            );
            crate::entity_mutation::update_one(
                &mut tx,
                state,
                ctx,
                &entity_name,
                entity_id,
                hit.id,
                &attrs,
                &patch,
                ctx.user_id,
                row_version,
                crate::entity_mutation::MutationMode::Strict,
            )
            .await?;
        }
        other => {
            return Err(AppError::Validation(format!(
                "scan actions of kind {other} are not run here"
            )));
        }
    }
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            &hit.entity,
            hit.id,
            attome_audit::AuditOperation::Update,
            "scan.act",
            ctx.user_id,
        )
        .comment(comment),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok((
        axum::http::StatusCode::OK,
        ScanActResult {
            status: "done".into(),
            action_kind: kind,
            record: Some(hit),
            workflow_instance_id,
            hits: Vec::new(),
        },
    ))
}

/// B16-T8: runs the scan action bound to a scanned code.
///
/// Resolves the record as `scan/find` does: none is 404, more than one is
/// 409 listing them. Then opens it, starts the action's workflow, or sets the
/// action's field at the record's current version, with one business event.
/// An `Idempotency-Key` makes a double scan run once.
#[utoipa::path(
    post,
    path = "/api/v1/scan/act",
    tag = "entity",
    request_body = ScanActBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Done", body = ScanActResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not change the record", body = ErrorResponse),
        (status = 404, description = "Scanning is off, no such action, or no record holds the code", body = ErrorResponse),
        (status = 409, description = "More than one record holds the code", body = ScanActResult),
        (status = 422, description = "Empty, overlong or non-matching value, or a misconfigured action", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn scan_act(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<ScanActBody>,
) -> Result<(axum::http::StatusCode, Json<ScanActResult>), AppError> {
    let flags = state.feature_flags();
    // B16-T9: acting on a scan has its own flag, which needs scan.enabled.
    if !flags.is_on("scan.enabled", &ctx).await || !flags.is_on("scan.actions_enabled", &ctx).await
    {
        return Err(AppError::NotFound);
    }
    let (status, result) = act(&state, &ctx, &body).await?;
    Ok((status, Json(result)))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(scan_find, scan_act))]
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

#[cfg(test)]
mod scan_act_tests {
    use super::*;

    #[test]
    fn scan_act_codes_must_fit_the_actions_pattern() {
        assert_eq!(fits_pattern("ABC-123", None).ok(), Some(true));
        assert_eq!(fits_pattern("ABC-123", Some("  ")).ok(), Some(true));
        assert_eq!(
            fits_pattern("ABC-123", Some("[A-Z]{3}-[0-9]{3}")).ok(),
            Some(true)
        );
        assert_eq!(
            fits_pattern("ABC-1234", Some("[A-Z]{3}-[0-9]{3}")).ok(),
            Some(false)
        );
        assert!(fits_pattern("x", Some("(")).is_err());
    }
}
