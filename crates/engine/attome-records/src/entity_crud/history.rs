//! `GET /api/v1/{entity}/{id}/history` — a record's field-level change
//! history for anyone who can read the record (basic-units plan U6, ruling
//! B-R12, recorded as D-601).
//!
//! The admin audit search (`attome-audit`'s `/api/v1/admin/audit`) returns header
//! columns only and needs `Authorized<Admin>`. This route is its record-scoped
//! counterpart: it needs exactly what `GET /api/v1/{entity}/{id}` needs, and
//! returns each change (one `audit_header`) with its `audit_detail`
//! old → new pairs.
//!
//! **Field filter.** The one a record read applies
//! (`timeline::readable_attr`): a sensitive field the caller holds no
//! field-security read grant for is dropped — never named, never counted —
//! and so is a field that is no longer an attribute of the entity. A readable
//! sensitive field is reported as changed with `masked = true` and no values
//! (the audit writer already stores its values masked). A value the audit
//! writer stored encrypted (any `value_mode`, D-540) is reported the same
//! way until audited decryption exists (audit plan Phase 6.4), never as
//! ciphertext. A field whose old and new values are both empty is omitted.
//! A change whose every
//! field is dropped is dropped with it, so the caller cannot learn when a
//! hidden field changed; a change that never had field rows (a delete, a
//! restore) is kept.
//!
//! **No security event.** This is an ordinary record read, like the record
//! GET it mirrors; it writes nothing (D-601).
//!
//! **Paging.** A keyset over `(changed_on DESC, id DESC)` of the change
//! headers, with the same opaque cursor codec as the timeline (tag `change`).
//!
//! **Groups (B2-T1).** Each change names the save, import, flow run or agent
//! session it belonged to (`group_id`), who made it (`actor`) and through
//! what (`source`), so a client can fold one run's many changes into one.
//!
//! **Restore (B2-T2).** `POST /api/v1/{entity}/{id}/history/restore` puts
//! back the values a change (or a whole change set) replaced, through the
//! ordinary update with `If-Match`, so validation, rules and audit run as for
//! any edit. A withheld (sensitive or encrypted) value cannot be restored.
//!
//! **Search (B2-T4).** `GET /api/v1/history/search` finds the changes to one
//! field of one entity whose old and new values meet conditions, in a period
//! ("where the discount went above 20 last month"), among the live records
//! the caller can read under the entity's record rules.

use std::collections::HashMap;

use attome_core::{EngineState, FieldType, quote_ident};
use attome_security::RecordAction;
use attome_security::SecurityContextExt;
use attome_security::record_action::{Read, Update};
use attome_server::authz::{Authorized, RecordScoped, SelfService};
use attome_server::security::SecurityContext;
use attome_types::{AppError, CursorPage, ErrorResponse};
use axum::{
    Extension, Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::access::require_record_read;
use super::resolve::resolve_entity;
use super::timeline::{
    audit_operation_label, clamp_page_size, decode_cursor, encode_cursor, micros_to_datetime,
    readable_attr, require_live_record,
};

const CURSOR_TAG: &str = "change";

/// One change to a record: who made it, when, and which fields moved.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecordHistoryChange {
    /// The `audit_header` row.
    pub audit_id: Uuid,
    pub changed_on: DateTime<Utc>,
    /// `created`, `updated`, `soft_deleted`, `restored`, `merged`, …
    pub operation: String,
    pub user_id: Option<Uuid>,
    pub user_display_name: Option<String>,
    /// B2-T1: the change set it belongs to: `batch:<id>` (an import or bulk
    /// action), `agent:<session>`, `run:<correlation id>` (a flow run or other
    /// correlated work), `request:<id>` (one save), else `change:<audit id>`.
    /// Changes with the same value were made together.
    pub group_id: String,
    /// `user`, `agent`, `system` or `portal_user`.
    pub actor: String,
    /// `web_form`, `api`, `mobile`, `import`, `workflow`, `plugin`,
    /// `background_job`, `integration` or `migration_tool`; absent when not
    /// recorded.
    pub source: Option<String>,
    /// The agent session that made it, when an agent did.
    pub agent_session_id: Option<Uuid>,
    /// Readable fields only, by field name.
    pub fields: Vec<RecordHistoryField>,
}

/// B2-T1: the change set a history entry belongs to, from the most specific
/// grouping the audit header recorded.
pub fn change_group(
    batch_id: Option<Uuid>,
    agent_session_id: Option<Uuid>,
    correlation_id: Option<Uuid>,
    request_id: Option<&str>,
    audit_id: Uuid,
) -> String {
    if let Some(id) = batch_id {
        return format!("batch:{id}");
    }
    if let Some(id) = agent_session_id {
        return format!("agent:{id}");
    }
    if let Some(id) = correlation_id {
        return format!("run:{id}");
    }
    match request_id.map(str::trim).filter(|r| !r.is_empty()) {
        Some(request) => format!("request:{request}"),
        None => format!("change:{audit_id}"),
    }
}

/// `audit_header.initiator` as a word.
pub fn actor_label(initiator: Option<i32>) -> &'static str {
    match initiator {
        Some(1) => "agent",
        Some(2) => "system",
        Some(3) => "portal_user",
        _ => "user",
    }
}

/// `audit_header.source` as a word.
pub fn source_label(source: Option<i32>) -> Option<&'static str> {
    Some(match source? {
        0 => "web_form",
        1 => "api",
        2 => "mobile",
        3 => "import",
        4 => "workflow",
        5 => "plugin",
        6 => "background_job",
        7 => "integration",
        8 => "migration_tool",
        _ => return None,
    })
}

/// One field's old → new pair within a change.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RecordHistoryField {
    pub field_name: String,
    pub display_name: Option<String>,
    /// The attribute's current field type (`text`, `number`, `date`, `bool`,
    /// `choice`, `lookup`, …) so a client can render the values.
    pub field_type: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub old_display_value: Option<String>,
    pub new_display_value: Option<String>,
    /// For a lookup: the referenced records' names at the time of the change.
    pub old_lookup_name: Option<String>,
    pub new_lookup_name: Option<String>,
    /// True for a sensitive field: it changed, and its values are withheld.
    pub masked: bool,
}

/// Query string for `GET /api/v1/{entity}/{id}/history`.
#[derive(Debug, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct RecordHistoryQuery {
    /// Opaque cursor from a previous page's `next_cursor`. A malformed value is
    /// a 422.
    pub cursor: Option<String>,
    /// Changes per page, 1..=200 (default 50); larger values are clamped.
    pub page_size: Option<i64>,
    /// B2-T3: only the changes to this one field (its logical name). A field
    /// the caller may not read, or that does not exist, has no history.
    pub field: Option<String>,
}

/// One `audit_header` row as the history reads it.
#[derive(sqlx::FromRow)]
struct HeaderRow {
    id: Uuid,
    operation: Option<i32>,
    changed_on: DateTime<Utc>,
    micros: i64,
    user_id: Option<Uuid>,
    user_display_name: Option<String>,
    initiator: Option<i32>,
    source: Option<i32>,
    batch_id: Option<Uuid>,
    agent_session_id: Option<Uuid>,
    correlation_id: Option<Uuid>,
    request_id: Option<String>,
}

type DetailRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<bool>,
    Option<i16>,
);

/// One page of a record's change history as `ctx`. `{entity}.read` is checked
/// here (`Forbidden`); a record the caller cannot read, or that does not exist,
/// is `NotFound`; a malformed cursor is `Validation`.
pub async fn record_history(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_input: &str,
    record_id: Uuid,
    query: &RecordHistoryQuery,
) -> Result<CursorPage<RecordHistoryChange>, AppError> {
    let cursor = match query.cursor.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => {
            let (micros, tag, id) = decode_cursor(raw)?;
            if tag != CURSOR_TAG {
                return Err(AppError::Validation("malformed cursor".into()));
            }
            Some((micros_to_datetime(micros)?, id))
        }
    };
    let page_size = clamp_page_size(query.page_size);

    let (entity_id, entity_name, attrs, is_append_only) =
        resolve_entity(state, entity_input).await?;
    ctx.require(&entity_name, "read")?;
    require_record_read(state, ctx, entity_id, &entity_name, record_id).await?;
    require_live_record(state, &entity_name, is_append_only, record_id).await?;

    // The field filter, resolved once: every readable attribute by name (or
    // just the one asked for).
    let only = query
        .field
        .as_deref()
        .map(str::trim)
        .filter(|f| !f.is_empty());
    let readable: HashMap<&str, &attome_core::AttrInfo> = attrs
        .iter()
        .filter(|a| only.is_none_or(|f| a.logicalname == f))
        .filter_map(|a| {
            readable_attr(ctx, &entity_name, &attrs, &a.logicalname)
                .map(|a| (a.logicalname.as_str(), a))
        })
        .collect();
    // A change with no field rows (a delete, a restore) belongs to the whole
    // record, not to one field.
    let fieldless = if only.is_some() {
        ""
    } else {
        "NOT EXISTS (SELECT 1 FROM audit_detail d WHERE d.audit_ref = h.id) OR "
    };
    let readable_names: Vec<String> = readable.keys().map(|s| (*s).to_owned()).collect();

    let keyset = if cursor.is_some() {
        "AND (h.changed_on < $5 OR (h.changed_on = $5 AND h.id < $6))"
    } else {
        ""
    };
    let sql = format!(
        "SELECT h.id, h.operation::int AS operation, h.changed_on, \
                (EXTRACT(EPOCH FROM h.changed_on) * 1000000)::bigint AS micros, \
                h.user_id, h.user_display_name, h.initiator::int AS initiator, \
                h.source::int AS source, h.batch_id, h.agent_session_id, h.correlation_id, \
                h.request_id \
         FROM audit_header h \
         WHERE h.entity_name = $1 AND h.record_id = $2 AND h.changed_on IS NOT NULL \
           AND ( {fieldless}EXISTS (SELECT 1 FROM audit_detail d \
                          WHERE d.audit_ref = h.id AND d.field_name = ANY($4) \
                            AND (COALESCE(d.old_value, '') <> '' OR COALESCE(d.new_value, '') <> '' \
                              OR COALESCE(d.old_display_value, '') <> '' \
                              OR COALESCE(d.new_display_value, '') <> '' \
                              OR COALESCE(d.old_lookup_name, '') <> '' \
                              OR COALESCE(d.new_lookup_name, '') <> '')) ) \
           {keyset} \
         ORDER BY h.changed_on DESC, h.id DESC LIMIT $3"
    );
    let mut q = sqlx::query_as::<_, HeaderRow>(&sql)
        .bind(&entity_name)
        .bind(record_id)
        .bind(page_size + 1)
        .bind(&readable_names);
    if let Some((ts, id)) = cursor {
        q = q.bind(ts).bind(id);
    }
    let mut headers = q
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;

    let has_more = headers.len() as i64 > page_size;
    headers.truncate(page_size as usize);
    let next_cursor = if has_more {
        headers
            .last()
            .map(|h| encode_cursor(h.micros, CURSOR_TAG, h.id))
    } else {
        None
    };

    let header_ids: Vec<Uuid> = headers.iter().map(|h| h.id).collect();
    let details: Vec<DetailRow> = if header_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT d.audit_ref, d.field_name::text, d.display_name::text, d.old_value, \
                    d.new_value, d.old_display_value, d.new_display_value, \
                    d.old_lookup_name, d.new_lookup_name, d.is_sensitive, d.value_mode \
             FROM audit_detail d \
             WHERE d.audit_ref = ANY($1) AND d.field_name = ANY($2) \
             ORDER BY d.field_name, d.id",
        )
        .bind(&header_ids)
        .bind(&readable_names)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
    };

    let mut by_header: HashMap<Uuid, Vec<RecordHistoryField>> = HashMap::new();
    for (
        audit_ref,
        field_name,
        display_name,
        old_value,
        new_value,
        old_display_value,
        new_display_value,
        old_lookup_name,
        new_lookup_name,
        row_sensitive,
        value_mode,
    ) in details
    {
        let Some(attr) = readable.get(field_name.as_str()) else {
            continue;
        };
        // Nothing to show when neither side had a value (an empty field
        // recorded as "changed" to empty).
        if [
            &old_value,
            &new_value,
            &old_display_value,
            &new_display_value,
            &old_lookup_name,
            &new_lookup_name,
        ]
        .iter()
        .all(|v| v.as_deref().is_none_or(str::is_empty))
        {
            continue;
        }
        // D-540: a row with a `value_mode` stores ciphertext (Encrypted,
        // Restricted) or nothing (NotCaptured). Decrypting for this read is
        // the audit plan's Phase 6.4 (audited decryption, its own
        // permission), not built yet, so such values are reported as masked
        // rather than handed to the client as ciphertext. Legacy rows (NULL
        // `value_mode`) were stored as written and are shown as before.
        let masked = attr.is_sensitive || row_sensitive.unwrap_or(false) || value_mode.is_some();
        let field_type = FieldType::from_int(attr.field_type_int).map(|t| t.as_str().to_owned());
        let field = if masked {
            RecordHistoryField {
                field_name,
                display_name,
                field_type,
                old_value: None,
                new_value: None,
                old_display_value: None,
                new_display_value: None,
                old_lookup_name: None,
                new_lookup_name: None,
                masked: true,
            }
        } else {
            RecordHistoryField {
                field_name,
                display_name,
                field_type,
                old_value,
                new_value,
                old_display_value,
                new_display_value,
                old_lookup_name,
                new_lookup_name,
                masked: false,
            }
        };
        by_header.entry(audit_ref).or_default().push(field);
    }

    let items = headers
        .into_iter()
        .map(|h| RecordHistoryChange {
            audit_id: h.id,
            changed_on: h.changed_on,
            operation: audit_operation_label(h.operation.unwrap_or(-1)).to_owned(),
            user_id: h.user_id,
            user_display_name: h.user_display_name,
            group_id: change_group(
                h.batch_id,
                h.agent_session_id,
                h.correlation_id,
                h.request_id.as_deref(),
                h.id,
            ),
            actor: actor_label(h.initiator).to_owned(),
            source: source_label(h.source).map(str::to_owned),
            agent_session_id: h.agent_session_id,
            fields: by_header.remove(&h.id).unwrap_or_default(),
        })
        .collect();
    Ok(CursorPage::new(items, next_cursor))
}

#[utoipa::path(
    get,
    path = "/api/v1/{entity}/{id}/history",
    tag = "entity",
    operation_id = "get_record_history",
    params(
        ("entity" = String, Path),
        ("id" = Uuid, Path),
        RecordHistoryQuery,
    ),
    responses(
        (status = 200, description = "One keyset page of the record's field-level change history, filtered by field security", body = CursorPage<RecordHistoryChange>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such record, or the caller cannot read it", body = ErrorResponse),
        (status = 422, description = "Malformed cursor", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_record_history(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Query(query): Query<RecordHistoryQuery>,
) -> Result<Json<CursorPage<RecordHistoryChange>>, AppError> {
    Ok(Json(
        record_history(&state, &ctx, &entity_input, record_id, &query).await?,
    ))
}

/// `POST /api/v1/{entity}/{id}/history/restore`: name one change
/// (`audit_id`) or one change set (`group_id`); `fields` narrows it.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct HistoryRestoreRequest {
    pub audit_id: Option<Uuid>,
    /// A `group_id` from the history: every change of that set to this record
    /// is undone, each field going back to its value before the set began.
    pub group_id: Option<String>,
    /// Only these fields (logical names); all the change touched when absent.
    #[serde(default)]
    pub fields: Vec<String>,
}

/// The newest changes a group restore looks through.
const MAX_GROUP_SCAN: i64 = 1000;

/// A field's value as the update path takes it, from the text the audit
/// stored: numbers and booleans parsed, a date cut to the day, empty as null.
pub fn restore_value(field_type: Option<FieldType>, raw: Option<&str>) -> Value {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return Value::Null;
    };
    match field_type {
        Some(FieldType::Number | FieldType::Currency) => raw
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map_or_else(|| Value::String(raw.to_owned()), Value::Number),
        Some(FieldType::Bool) => Value::Bool(raw == "true"),
        Some(FieldType::Date) => Value::String(raw.chars().take(10).collect()),
        _ => Value::String(raw.to_owned()),
    }
}

/// The values a change, or a change set, replaced on this record, as an
/// update body: for each field, its value before the earliest of them.
async fn values_before(
    state: &EngineState,
    ctx: &SecurityContext,
    entity_name: &str,
    attrs: &[attome_core::AttrInfo],
    record_id: Uuid,
    request: &HistoryRestoreRequest,
) -> Result<Map<String, Value>, AppError> {
    let headers: Vec<HeaderRow> = sqlx::query_as(
        "SELECT h.id, h.operation::int AS operation, h.changed_on, \
                (EXTRACT(EPOCH FROM h.changed_on) * 1000000)::bigint AS micros, \
                h.user_id, h.user_display_name, h.initiator::int AS initiator, \
                h.source::int AS source, h.batch_id, h.agent_session_id, h.correlation_id, \
                h.request_id \
         FROM audit_header h \
         WHERE h.entity_name = $1 AND h.record_id = $2 AND h.changed_on IS NOT NULL \
           AND ($3::uuid IS NULL OR h.id = $3) \
         ORDER BY h.changed_on DESC, h.id DESC LIMIT $4",
    )
    .bind(entity_name)
    .bind(record_id)
    .bind(request.audit_id)
    .bind(MAX_GROUP_SCAN)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut chosen: Vec<&HeaderRow> = match (&request.audit_id, request.group_id.as_deref()) {
        (Some(_), None) => headers.iter().collect(),
        (None, Some(group)) => headers
            .iter()
            .filter(|h| {
                change_group(
                    h.batch_id,
                    h.agent_session_id,
                    h.correlation_id,
                    h.request_id.as_deref(),
                    h.id,
                ) == group.trim()
            })
            .collect(),
        _ => {
            return Err(AppError::Validation(
                "name either audit_id or group_id".into(),
            ));
        }
    };
    if chosen.is_empty() {
        return Err(AppError::NotFound);
    }
    // Oldest first, so the first value seen for a field is the one before
    // the set began.
    chosen.sort_by_key(|h| (h.changed_on, h.id));
    let ids: Vec<Uuid> = chosen.iter().map(|h| h.id).collect();
    let order: HashMap<Uuid, usize> = ids.iter().enumerate().map(|(i, id)| (*id, i)).collect();

    let wanted: Vec<&str> = request.fields.iter().map(|f| f.trim()).collect();
    let readable: HashMap<&str, &attome_core::AttrInfo> = attrs
        .iter()
        .filter(|a| wanted.is_empty() || wanted.contains(&a.logicalname.as_str()))
        .filter_map(|a| {
            readable_attr(ctx, entity_name, attrs, &a.logicalname)
                .map(|a| (a.logicalname.as_str(), a))
        })
        .collect();
    let mut rows: Vec<(Uuid, String, Option<String>, Option<bool>, Option<i16>)> = sqlx::query_as(
        "SELECT d.audit_ref, d.field_name::text, d.old_value, d.is_sensitive, d.value_mode \
             FROM audit_detail d WHERE d.audit_ref = ANY($1) ORDER BY d.id",
    )
    .bind(&ids)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    rows.sort_by_key(|row| order.get(&row.0).copied().unwrap_or(usize::MAX));

    let mut body = Map::new();
    for (_, field, old_value, row_sensitive, value_mode) in rows {
        if body.contains_key(&field) {
            continue;
        }
        let Some(attr) = readable.get(field.as_str()) else {
            continue;
        };
        if attr.is_sensitive || row_sensitive.unwrap_or(false) || value_mode.is_some() {
            return Err(AppError::Validation(format!(
                "{field}: a withheld value cannot be restored"
            )));
        }
        let value = restore_value(
            FieldType::from_int(attr.field_type_int),
            old_value.as_deref(),
        );
        body.insert(field, value);
    }
    if body.is_empty() {
        return Err(AppError::Validation(
            "that change has no field values to restore".into(),
        ));
    }
    Ok(body)
}

/// B2-T2: restores the values a change or change set replaced, through the
/// ordinary update (`row_version` as `If-Match`).
pub async fn restore_from_history(
    state: &EngineState,
    ctx: &SecurityContext,
    acting_user: Uuid,
    entity_input: &str,
    record_id: Uuid,
    expected_version: i64,
    request: &HistoryRestoreRequest,
) -> Result<super::response::EntityRecordResponse, AppError> {
    let (entity_id, entity_name, attrs, _) = resolve_entity(state, entity_input).await?;
    ctx.require(&entity_name, "update")?;
    require_record_read(state, ctx, entity_id, &entity_name, record_id).await?;
    let body = values_before(state, ctx, &entity_name, &attrs, record_id, request).await?;
    super::update_record_for(
        state,
        ctx,
        acting_user,
        &entity_name,
        record_id,
        expected_version,
        Value::Object(body),
    )
    .await
}

/// B2-T2: puts back the values one change (`audit_id`) or one change set
/// (`group_id`, an import, run or agent session) replaced on this record,
/// through the ordinary update: `If-Match` is required and validation, rules
/// and audit run as for any edit.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/history/restore",
    tag = "entity",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    request_body = HistoryRestoreRequest,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "The record with the values restored", body = super::response::EntityRecordResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this record", body = ErrorResponse),
        (status = 404, description = "No such record or change", body = ErrorResponse),
        (status = 409, description = "The record changed since the If-Match version", body = ErrorResponse),
        (status = 422, description = "No If-Match, both or neither of audit_id and group_id, a withheld value, or the restored values fail validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn restore_history_route(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Update>>,
    Extension(claims): Extension<attome_auth::SessionClaims>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    headers: axum::http::HeaderMap,
    Json(request): Json<HistoryRestoreRequest>,
) -> Result<Json<super::response::EntityRecordResponse>, AppError> {
    let expected = super::row_version::expected_row_version(&headers)?;
    Ok(Json(
        restore_from_history(
            &state,
            &ctx,
            claims.sub,
            &entity_input,
            record_id,
            expected,
            &request,
        )
        .await?,
    ))
}

/// How a value is compared in a history search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum HistoryCompare {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    /// Text containing the value, ignoring case.
    Contains,
    /// Empty before (or after) the change.
    Empty,
}

/// Query string for `GET /api/v1/history/search`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HistorySearchQuery {
    /// The entity's logical name.
    pub entity: String,
    /// The field's logical name.
    pub field: String,
    /// A condition on the value before the change.
    pub old_op: Option<HistoryCompare>,
    pub old_value: Option<String>,
    /// A condition on the value after the change.
    pub new_op: Option<HistoryCompare>,
    pub new_value: Option<String>,
    /// Changes on or after this moment (UTC).
    pub from: Option<DateTime<Utc>>,
    /// Changes before this moment (UTC).
    pub to: Option<DateTime<Utc>>,
    /// Opaque cursor from a previous page's `next_cursor`.
    pub cursor: Option<String>,
    /// Matches per page, 1..=200 (default 50).
    pub page_size: Option<i64>,
}

/// One change a history search found.
#[derive(Debug, Clone, Serialize, ToSchema, sqlx::FromRow)]
pub struct HistoryMatch {
    pub record_id: Uuid,
    pub audit_id: Uuid,
    pub changed_on: DateTime<Utc>,
    pub user_display_name: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    #[serde(skip)]
    pub micros: i64,
}

/// The SQL condition for one side of a change: `column` compared with the
/// bound parameter `$param`, numerically for number fields. Returns the
/// condition. A side with no condition still names its parameter (bound to
/// NULL), so PostgreSQL can type every parameter.
pub fn compare_sql(
    column: &str,
    op: Option<HistoryCompare>,
    numeric: bool,
    param: usize,
) -> String {
    let Some(op) = op else {
        return format!("${param}::text IS NULL");
    };
    let value = if numeric {
        format!("(CASE WHEN {column} ~ '^-?[0-9]+(\\.[0-9]+)?$' THEN {column}::numeric END)")
    } else {
        column.to_owned()
    };
    let rhs = if numeric {
        format!("${param}::numeric")
    } else {
        format!("${param}::text")
    };
    match op {
        HistoryCompare::Eq => format!("{value} = {rhs}"),
        HistoryCompare::Ne => format!("{value} IS DISTINCT FROM {rhs}"),
        HistoryCompare::Gt => format!("{value} > {rhs}"),
        HistoryCompare::Gte => format!("{value} >= {rhs}"),
        HistoryCompare::Lt => format!("{value} < {rhs}"),
        HistoryCompare::Lte => format!("{value} <= {rhs}"),
        HistoryCompare::Contains => {
            format!(
                "{column} ILIKE '%' || replace(replace(${param}::text, '%', '\\%'), '_', '\\_') || '%'"
            )
        }
        HistoryCompare::Empty => {
            format!("(COALESCE({column}, '') = '' AND ${param}::text IS NULL)")
        }
    }
}

/// The value bound for one side: `None` for `empty` or no condition; a
/// number side must parse as a number.
fn compare_value(
    op: Option<HistoryCompare>,
    value: Option<&str>,
    numeric: bool,
    side: &str,
) -> Result<Option<String>, AppError> {
    match op {
        None | Some(HistoryCompare::Empty) => Ok(None),
        Some(op) => {
            let value = value
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| AppError::Validation(format!("{side}_value is required")))?;
            if numeric && op != HistoryCompare::Contains && value.parse::<f64>().is_err() {
                return Err(AppError::Validation(format!(
                    "{side}_value must be a number"
                )));
            }
            Ok(Some(value.to_owned()))
        }
    }
}

/// B2-T4: the changes to one field whose values meet the conditions, newest
/// first, among the live records `ctx` can read.
pub async fn search_history(
    state: &EngineState,
    ctx: &SecurityContext,
    query: &HistorySearchQuery,
) -> Result<CursorPage<HistoryMatch>, AppError> {
    let cursor = match query.cursor.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => {
            let (micros, tag, id) = decode_cursor(raw)?;
            if tag != SEARCH_CURSOR_TAG {
                return Err(AppError::Validation("malformed cursor".into()));
            }
            Some((micros_to_datetime(micros)?, id))
        }
    };
    let page_size = clamp_page_size(query.page_size);
    let (entity_id, entity, attrs, append_only) = resolve_entity(state, &query.entity).await?;
    ctx.require(&entity, "read")?;
    let attr = readable_attr(ctx, &entity, &attrs, query.field.trim()).ok_or(AppError::NotFound)?;
    if attr.is_sensitive {
        return Err(AppError::Validation(
            "a sensitive field's values cannot be searched".into(),
        ));
    }
    let numeric = matches!(
        FieldType::from_int(attr.field_type_int),
        Some(FieldType::Number | FieldType::Currency)
    );
    let old_value = compare_value(query.old_op, query.old_value.as_deref(), numeric, "old")?;
    let new_value = compare_value(query.new_op, query.new_value.as_deref(), numeric, "new")?;
    let access_level = attome_security::resolve_entity_access_level(
        &state.base.db,
        ctx.user_id,
        entity_id,
        &entity,
        RecordAction::Read,
    )
    .await?;
    let pred = attome_security::rls_predicate(
        ctx,
        entity_id,
        "",
        access_level,
        RecordAction::Read.share_capability(),
        10,
    );
    let table = quote_ident(&entity);
    let live = if append_only {
        ""
    } else {
        "AND is_active = true"
    };
    let sql = format!(
        "SELECT c.record_id, c.audit_id, c.changed_on, c.user_display_name, c.old_value, \
                c.new_value, c.micros \
         FROM (SELECT h.record_id, h.id AS audit_id, h.changed_on, h.user_display_name, \
                      d.old_value, d.new_value, \
                      (EXTRACT(EPOCH FROM h.changed_on) * 1000000)::bigint AS micros \
               FROM audit_header h JOIN audit_detail d ON d.audit_ref = h.id \
               WHERE h.entity_name = $1 AND d.field_name = $2 AND h.changed_on IS NOT NULL \
                 AND d.value_mode IS NULL AND COALESCE(d.is_sensitive, false) = false \
                 AND ($3::timestamptz IS NULL OR h.changed_on >= $3) \
                 AND ($4::timestamptz IS NULL OR h.changed_on < $4) \
                 AND ({old}) AND ({new}) \
                 AND ($8::timestamptz IS NULL OR h.changed_on < $8 \
                      OR (h.changed_on = $8 AND h.id < $9::uuid))) c \
         WHERE c.record_id IN (SELECT id FROM {table} WHERE true {live} {rls}) \
         ORDER BY c.changed_on DESC, c.audit_id DESC LIMIT $5",
        old = compare_sql("d.old_value", query.old_op, numeric, 6),
        new = compare_sql("d.new_value", query.new_op, numeric, 7),
        rls = pred.as_ref().map_or("", |p| p.sql.as_str()),
    );
    let mut q = sqlx::query_as::<_, HistoryMatch>(&sql)
        .bind(&entity)
        .bind(&attr.logicalname)
        .bind(query.from)
        .bind(query.to)
        .bind(page_size + 1)
        .bind(old_value)
        .bind(new_value)
        .bind(cursor.map(|(ts, _)| ts))
        .bind(cursor.map(|(_, id)| id));
    if let Some(p) = &pred {
        q = q
            .bind(p.binds.entity_ref)
            .bind(p.binds.caller_id)
            .bind(&p.binds.team_ids)
            .bind(p.binds.capability)
            .bind(&p.binds.accessible_org_ids)
            .bind(&p.binds.subordinate_user_ids);
    }
    let mut items = q
        .fetch_all(&state.base.db)
        .await
        .map_err(attome_db::classify)?;
    let has_more = items.len() as i64 > page_size;
    items.truncate(page_size as usize);
    let next_cursor = if has_more {
        items
            .last()
            .map(|m| encode_cursor(m.micros, SEARCH_CURSOR_TAG, m.audit_id))
    } else {
        None
    };
    Ok(CursorPage::new(items, next_cursor))
}

const SEARCH_CURSOR_TAG: &str = "hsearch";

/// B2-T4: finds the changes to one field of an entity whose old and new
/// values meet the conditions, in a period, newest first, among the live
/// records the caller can read. Sensitive and encrypted values are never
/// searched.
#[utoipa::path(
    get,
    path = "/api/v1/history/search",
    tag = "entity",
    params(HistorySearchQuery),
    responses(
        (status = 200, description = "One keyset page of matching changes", body = CursorPage<HistoryMatch>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the entity's read privilege", body = ErrorResponse),
        (status = 404, description = "No such entity, or a field the caller cannot read", body = ErrorResponse),
        (status = 422, description = "A missing or non-numeric value, a sensitive field, or a malformed cursor", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn search_history_route(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Query(query): Query<HistorySearchQuery>,
) -> Result<Json<CursorPage<HistoryMatch>>, AppError> {
    Ok(Json(search_history(&state, &ctx, &query).await?))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_record_history, restore_history_route, search_history_route))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_groups_by_the_most_specific_change_set() {
        let (batch, session, run, audit) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        assert_eq!(
            change_group(Some(batch), Some(session), Some(run), Some("r1"), audit),
            format!("batch:{batch}")
        );
        assert_eq!(
            change_group(None, Some(session), Some(run), Some("r1"), audit),
            format!("agent:{session}")
        );
        assert_eq!(
            change_group(None, None, Some(run), Some("r1"), audit),
            format!("run:{run}")
        );
        assert_eq!(
            change_group(None, None, None, Some(" r1 "), audit),
            "request:r1"
        );
        assert_eq!(
            change_group(None, None, None, Some(""), audit),
            format!("change:{audit}")
        );
    }

    #[test]
    fn history_restore_values_take_the_field_type() {
        assert_eq!(
            restore_value(Some(FieldType::Number), Some("12.5")),
            serde_json::json!(12.5)
        );
        assert_eq!(
            restore_value(Some(FieldType::Bool), Some("true")),
            Value::Bool(true)
        );
        assert_eq!(
            restore_value(Some(FieldType::Date), Some("2026-10-01T00:00:00Z")),
            Value::String("2026-10-01".into())
        );
        assert_eq!(restore_value(Some(FieldType::Text), Some("")), Value::Null);
        assert_eq!(restore_value(None, None), Value::Null);
        assert_eq!(
            restore_value(Some(FieldType::Number), Some("n/a")),
            Value::String("n/a".into())
        );
    }

    #[test]
    fn history_search_compares_numbers_and_text() {
        let gt = compare_sql("d.new_value", Some(HistoryCompare::Gt), true, 7);
        assert!(gt.contains("::numeric END) > $7::numeric"), "{gt}");
        assert_eq!(compare_sql("d.old_value", None, true, 6), "$6::text IS NULL");
        let eq = compare_sql("d.old_value", Some(HistoryCompare::Eq), false, 6);
        assert_eq!(eq, "d.old_value = $6::text");
        assert!(compare_value(Some(HistoryCompare::Gt), Some("abc"), true, "new").is_err());
        assert!(compare_value(Some(HistoryCompare::Gt), None, false, "new").is_err());
        assert_eq!(
            compare_value(Some(HistoryCompare::Lte), Some(" 20 "), true, "old").unwrap(),
            Some("20".to_owned())
        );
        assert_eq!(
            compare_value(Some(HistoryCompare::Empty), None, false, "old").unwrap(),
            None
        );
    }

    #[test]
    fn history_names_actors_and_sources() {
        assert_eq!(actor_label(Some(1)), "agent");
        assert_eq!(actor_label(None), "user");
        assert_eq!(source_label(Some(3)), Some("import"));
        assert_eq!(source_label(Some(4)), Some("workflow"));
        assert_eq!(source_label(Some(99)), None);
        assert_eq!(source_label(None), None);
    }
}
