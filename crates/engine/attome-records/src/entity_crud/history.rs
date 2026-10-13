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

use std::collections::HashMap;

use attome_core::{EngineState, FieldType};
use attome_security::SecurityContextExt;
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, RecordScoped};
use attome_server::security::SecurityContext;
use attome_types::{AppError, CursorPage, ErrorResponse};
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    /// Readable fields only, by field name.
    pub fields: Vec<RecordHistoryField>,
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
}

type HeaderRow = (
    Uuid,
    Option<i32>,
    DateTime<Utc>,
    i64,
    Option<Uuid>,
    Option<String>,
);

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

    // The field filter, resolved once: every readable attribute by name.
    let readable: HashMap<&str, &attome_core::AttrInfo> = attrs
        .iter()
        .filter_map(|a| {
            readable_attr(ctx, &entity_name, &attrs, &a.logicalname)
                .map(|a| (a.logicalname.as_str(), a))
        })
        .collect();
    let readable_names: Vec<String> = readable.keys().map(|s| (*s).to_owned()).collect();

    let keyset = if cursor.is_some() {
        "AND (h.changed_on < $5 OR (h.changed_on = $5 AND h.id < $6))"
    } else {
        ""
    };
    let sql = format!(
        "SELECT h.id, h.operation::int, h.changed_on, \
                (EXTRACT(EPOCH FROM h.changed_on) * 1000000)::bigint, \
                h.user_id, h.user_display_name \
         FROM audit_header h \
         WHERE h.entity_name = $1 AND h.record_id = $2 AND h.changed_on IS NOT NULL \
           AND ( NOT EXISTS (SELECT 1 FROM audit_detail d WHERE d.audit_ref = h.id) \
              OR EXISTS (SELECT 1 FROM audit_detail d \
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
            .map(|(id, _, _, micros, _, _)| encode_cursor(*micros, CURSOR_TAG, *id))
    } else {
        None
    };

    let header_ids: Vec<Uuid> = headers.iter().map(|h| h.0).collect();
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
        .map(
            |(id, operation, changed_on, _, user_id, user_display_name)| RecordHistoryChange {
                audit_id: id,
                changed_on,
                operation: audit_operation_label(operation.unwrap_or(-1)).to_owned(),
                user_id,
                user_display_name,
                fields: by_header.remove(&id).unwrap_or_default(),
            },
        )
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

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_record_history))]
struct ApiDocFragment;

pub(super) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
