//! Filling a call list (roadmap D21-T3), as the calling user:
//!
//! - `view`: the list's saved query (`view_ref`) run through the stored
//!   query path with the caller's record rules, paged, up to
//!   [`MAX_MEMBERS`];
//! - `tasks_due`: the caller's open phone-call activities due today;
//! - `manual`: the records the caller names, each checked for read access.
//!
//! Records without a phone number are skipped. Members are added in source
//! order under the list's lock; rebuilding keeps every existing member
//! (done ones included) and adds only records not already on the list.

use attome_core::{EngineState, quote_ident};
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege, PrivilegeKey};
use attome_server::security::SecurityContext;
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Most members one list holds.
pub const MAX_MEMBERS: i64 = 10_000;

/// The phone columns a callable record may have, in preference order.
const PHONE_COLUMNS: [&str; 3] = ["phone", "mobile_phone", "telephone"];

/// `call_list.update`: may fill a call list.
#[derive(Debug)]
pub struct CallListUpdate;

impl PrivilegeKey for CallListUpdate {
    const KEY: &'static str = "call_list.update";
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, ToSchema)]
pub struct CallListRecord {
    pub entity: String,
    pub record_id: Uuid,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct SalesBuildListBody {
    /// For a `manual` list: the records to add.
    #[serde(default)]
    pub records: Vec<CallListRecord>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesBuildStats {
    pub added: u64,
    pub already_on_list: u64,
    pub without_phone: u64,
}

/// Keeps the records of `entity` (among `ids`) that have a phone number, in
/// the order given.
async fn with_phone(
    state: &EngineState,
    entity: &str,
    ids: &[Uuid],
) -> Result<Vec<Uuid>, AppError> {
    let columns: Vec<&str> = {
        let registry = state.entities.load();
        let Some(meta) = registry.get(entity) else {
            return Ok(Vec::new());
        };
        PHONE_COLUMNS
            .iter()
            .copied()
            .filter(|c| meta.attrs.iter().any(|a| a.logicalname == *c))
            .collect()
    };
    if columns.is_empty() || ids.is_empty() {
        return Ok(Vec::new());
    }
    let any_phone = columns
        .iter()
        .map(|c| format!("COALESCE(trim({}), '') <> ''", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(" OR ");
    let keep: Vec<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {} WHERE id = ANY($1) AND ({any_phone})",
        quote_ident(entity)
    ))
    .bind(ids)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let keep: std::collections::HashSet<Uuid> = keep.into_iter().collect();
    Ok(ids.iter().copied().filter(|id| keep.contains(id)).collect())
}

/// The records a list's source gives, in source order.
async fn source_records(
    state: &EngineState,
    ctx: &SecurityContext,
    source: &str,
    view_ref: Option<&str>,
    body: &SalesBuildListBody,
) -> Result<Vec<CallListRecord>, AppError> {
    match source {
        "view" => {
            let query = view_ref
                .and_then(|v| Uuid::parse_str(v.trim()).ok())
                .ok_or_else(|| {
                    AppError::Validation("the list has no saved query (view_ref)".into())
                })?;
            let entity: Option<String> = sqlx::query_scalar(
                "SELECT e.logicalname FROM sql_query q \
                 JOIN entity_info e ON e.id = q.entity_logical_name WHERE q.id = $1",
            )
            .bind(query)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            let entity = entity.ok_or(AppError::NotFound)?;
            let ids = attome_records::query_exec::execute_stored_query_ids(
                state,
                ctx,
                query,
                None,
                Some(MAX_MEMBERS),
            )
            .await?;
            Ok(ids
                .into_iter()
                .map(|record_id| CallListRecord {
                    entity: entity.clone(),
                    record_id,
                })
                .collect())
        }
        "tasks_due" => {
            let rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT entity_name, record_id FROM activity \
                 WHERE activity_type = 'phone_call' AND status = 'open' \
                   AND due_at::date = now()::date AND owner_ref = $1 \
                   AND (is_active IS NULL OR is_active = true) \
                 ORDER BY due_at, id LIMIT $2",
            )
            .bind(ctx.user_id)
            .bind(MAX_MEMBERS)
            .fetch_all(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            Ok(rows
                .into_iter()
                .filter_map(|(entity, record)| {
                    Some(CallListRecord {
                        entity: entity?,
                        record_id: record.and_then(|r| Uuid::parse_str(&r).ok())?,
                    })
                })
                .collect())
        }
        "manual" => {
            if body.records.len() as i64 > MAX_MEMBERS {
                return Err(AppError::Validation(format!(
                    "at most {MAX_MEMBERS} records"
                )));
            }
            let mut out = Vec::with_capacity(body.records.len());
            for r in &body.records {
                let entity_id = state
                    .entities
                    .load()
                    .get(&r.entity)
                    .map(|m| m.entity_id)
                    .ok_or(AppError::NotFound)?;
                attome_records::entity_crud::require_record_access(
                    state,
                    ctx,
                    entity_id,
                    &r.entity,
                    r.record_id,
                    RecordAction::Read,
                )
                .await?;
                out.push(r.clone());
            }
            Ok(out)
        }
        _ => Err(AppError::Validation(
            "the list's source is view, tasks_due or manual".into(),
        )),
    }
}

/// Fills the list from its source as `ctx`.
pub async fn build_list(
    state: &EngineState,
    ctx: &SecurityContext,
    list: Uuid,
    body: &SalesBuildListBody,
) -> Result<SalesBuildStats, AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT source_kind, view_ref FROM call_list \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((source, view_ref)) = row else {
        return Err(AppError::NotFound);
    };
    let records = source_records(
        state,
        ctx,
        source.as_deref().unwrap_or("manual"),
        view_ref.as_deref(),
        body,
    )
    .await?;
    // Phone check per entity, keeping the source order.
    let mut stats = SalesBuildStats::default();
    let mut callable = Vec::with_capacity(records.len());
    let mut by_entity: std::collections::BTreeMap<&str, Vec<Uuid>> = Default::default();
    for r in &records {
        by_entity
            .entry(r.entity.as_str())
            .or_default()
            .push(r.record_id);
    }
    let mut phoned: std::collections::HashSet<(String, Uuid)> = Default::default();
    for (entity, ids) in &by_entity {
        for id in with_phone(state, entity, ids).await? {
            phoned.insert(((*entity).to_owned(), id));
        }
    }
    for r in records {
        if phoned.contains(&(r.entity.clone(), r.record_id)) {
            callable.push(r);
        } else {
            stats.without_phone += 1;
        }
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind(format!("attome-sales/build_list:{list}"))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Err(AppError::Conflict(
            "this list is being filled by another request",
        ));
    }
    let existing: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT entity_name, record_id FROM call_list_member \
         WHERE list_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(list)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut present: std::collections::HashSet<(String, String)> = existing
        .into_iter()
        .filter_map(|(e, r)| Some((e?, r?)))
        .collect();
    let mut position: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(position), 0)::bigint FROM call_list_member WHERE list_ref = $1",
    )
    .bind(list)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for r in callable {
        if (present.len() as i64) >= MAX_MEMBERS {
            break;
        }
        let key = (r.entity.clone(), r.record_id.to_string());
        if !present.insert(key) {
            stats.already_on_list += 1;
            continue;
        }
        position += 1;
        sqlx::query(
            "INSERT INTO call_list_member \
               (list_ref, entity_name, record_id, position, member_status, attempts, owner_ref) \
             VALUES ($1, $2, $3, $4, 'pending', 0, $5)",
        )
        .bind(list)
        .bind(&r.entity)
        .bind(r.record_id.to_string())
        .bind(position)
        .bind(ctx.user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        stats.added += 1;
    }
    attome_db::tx::commit(tx).await?;
    Ok(stats)
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/call-lists/{id}/build",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The call list")),
    request_body = SalesBuildListBody,
    responses(
        (status = 200, description = "Members added from the list's source", body = SalesBuildStats),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks call_list.update, or may not read a named record", body = ErrorResponse),
        (status = 404, description = "No such list, saved query or record", body = ErrorResponse),
        (status = 409, description = "The list is being filled by another request", body = ErrorResponse),
        (status = 422, description = "The list has no usable source", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_build_list(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<CallListUpdate>>,
    Path(list): Path<Uuid>,
    Json(body): Json<SalesBuildListBody>,
) -> Result<Json<SalesBuildStats>, AppError> {
    let stats = build_list(&state, &ctx, list, &body).await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "call_list",
            list,
            attome_audit::AuditOperation::Update,
            "sales.call_list_built",
            ctx.user_id,
        )
        .comment(format!("{} added", stats.added)),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(stats))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sales_build_list),
    components(schemas(CallListRecord, SalesBuildListBody, SalesBuildStats))
)]
pub(crate) struct ApiDocFragment;
