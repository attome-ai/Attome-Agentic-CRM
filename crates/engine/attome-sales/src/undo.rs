//! Undo of bulk line changes (roadmap D6-T8).
//!
//! A deal discount or a quote sync keeps the deal's lines as they were
//! before ([`capture_lines`]) and, once the change is done, a snapshot with
//! the resulting line versions ([`record_in_tx`], table
//! `sales_line_snapshot`); the change answers with the snapshot id. Its
//! author may undo it within [`UNDO_WINDOW_MINUTES`] minutes, once, and
//! only while nothing has touched the lines since (every live line still
//! has the version the change left). Undo puts the old lines back and
//! reprices the deal. Snapshots older than a day are removed nightly.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::split_store::OpportunityUpdate;

/// How long a change can be undone.
pub const UNDO_WINDOW_MINUTES: i64 = 30;

/// The columns a line is restored with.
const LINE_COLUMNS: &str = "product_ref, name, quantity, list_price, sales_price, \
     discount_percent, discount_amount, line_kind, recurrence, term_months, description, \
     sort_order, source_quote_line_ref, service_date";

/// The deal's live lines, as JSON rows, before a bulk change.
pub async fn capture_lines(tx: &mut attome_db::Tx<'_>, deal: Uuid) -> Result<Value, AppError> {
    let lines: Option<Value> = sqlx::query_scalar(&format!(
        "SELECT COALESCE(jsonb_agg(to_jsonb(x)), '[]'::jsonb) FROM \
           (SELECT {LINE_COLUMNS} FROM opportunity_line \
            WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true) \
            ORDER BY sort_order NULLS LAST, id) x"
    ))
    .bind(deal)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(lines.unwrap_or(Value::Array(Vec::new())))
}

async fn live_versions(
    tx: &mut attome_db::Tx<'_>,
    deal: Uuid,
) -> Result<BTreeMap<String, i64>, AppError> {
    let rows: Vec<(Uuid, i64)> = sqlx::query_as(
        "SELECT id, row_version FROM opportunity_line \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(rows
        .into_iter()
        .map(|(id, v)| (id.to_string(), v))
        .collect())
}

/// Stores the snapshot after the change, with the versions it left.
pub async fn record_in_tx(
    tx: &mut attome_db::Tx<'_>,
    deal: Uuid,
    before: Value,
    actor: Uuid,
) -> Result<Uuid, AppError> {
    let versions = live_versions(tx, deal).await?;
    sqlx::query_scalar(
        "INSERT INTO sales_line_snapshot (parent_entity, parent_id, lines, row_versions, created_by) \
         VALUES ('opportunity', $1, $2, $3, $4) RETURNING id",
    )
    .bind(deal)
    .bind(before)
    .bind(serde_json::to_value(versions).map_err(AppError::internal)?)
    .bind(actor)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Whether the lines are as the change left them.
pub fn untouched(stored: &BTreeMap<String, i64>, live: &BTreeMap<String, i64>) -> bool {
    stored == live
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesUndone {
    pub opportunity_id: Uuid,
    pub lines_restored: usize,
}

type SnapshotRow = (Uuid, Value, Value, Uuid, bool, bool);

#[utoipa::path(
    post,
    path = "/api/v1/sales/undo/{snapshot_id}",
    tag = "sales",
    params(("snapshot_id" = Uuid, Path, description = "The snapshot a deal discount or quote sync answered with")),
    responses(
        (status = 200, description = "The deal's lines are back as they were, repriced", body = SalesUndone),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Not the change's author, or caller may not update the deal", body = ErrorResponse),
        (status = 404, description = "No such snapshot", body = ErrorResponse),
        (status = 409, description = "Already undone, past 30 minutes, or the lines changed since", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_undo(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(snapshot): Path<Uuid>,
) -> Result<Json<SalesUndone>, AppError> {
    let deal: Option<Uuid> =
        sqlx::query_scalar("SELECT parent_id FROM sales_line_snapshot WHERE id = $1")
            .bind(snapshot)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some(deal) = deal else {
        return Err(AppError::NotFound);
    };
    let entity = state
        .entities
        .load()
        .get("opportunity")
        .map(|m| m.entity_id)
        .ok_or(AppError::NotFound)?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity,
        "opportunity",
        deal,
        RecordAction::Update,
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    crate::split_store::lock_deal(&mut tx, deal).await?;
    let row: Option<SnapshotRow> = sqlx::query_as(
        "SELECT parent_id, lines, row_versions, created_by, used_at IS NOT NULL, \
                created_at < now() - make_interval(mins => $2) \
         FROM sales_line_snapshot WHERE id = $1 FOR UPDATE",
    )
    .bind(snapshot)
    .bind(UNDO_WINDOW_MINUTES as i32)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((_, lines, versions, author, used, expired)) = row else {
        return Err(AppError::NotFound);
    };
    if author != ctx.user_id {
        return Err(AppError::Forbidden);
    }
    if used {
        return Err(AppError::Conflict("this change was already undone"));
    }
    if expired {
        return Err(AppError::Conflict(
            "a change can be undone for 30 minutes only",
        ));
    }
    let stored: BTreeMap<String, i64> =
        serde_json::from_value(versions).map_err(AppError::internal)?;
    if !untouched(&stored, &live_versions(&mut tx, deal).await?) {
        return Err(AppError::Conflict(
            "the deal's lines changed after this change; it can no longer be undone",
        ));
    }
    sqlx::query(
        "UPDATE opportunity_line SET is_active = false, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let count = lines.as_array().map_or(0, Vec::len);
    sqlx::query(&format!(
        "INSERT INTO opportunity_line (opportunity_ref, {LINE_COLUMNS}, owner_ref) \
         SELECT $1, {LINE_COLUMNS}, o.owner_ref \
         FROM jsonb_populate_recordset(NULL::opportunity_line, $2) r \
         CROSS JOIN (SELECT owner_ref FROM opportunity WHERE id = $1) o"
    ))
    .bind(deal)
    .bind(&lines)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    crate::opportunity_lines::reprice_in_tx(&mut tx, deal).await?;
    sqlx::query("UPDATE sales_line_snapshot SET used_at = now() WHERE id = $1")
        .bind(snapshot)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            "opportunity",
            deal,
            AuditOperation::Update,
            "sales.lines_change_undone",
            ctx.user_id,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(SalesUndone {
        opportunity_id: deal,
        lines_restored: count,
    }))
}

/// Removes snapshots older than a day; how many.
pub async fn prune(db: &attome_db::DbPool) -> Result<u64, AppError> {
    Ok(
        sqlx::query("DELETE FROM sales_line_snapshot WHERE created_at < now() - interval '1 day'")
            .execute(db)
            .await
            .map_err(AppError::internal)?
            .rows_affected(),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_sales_undo), components(schemas(SalesUndone)))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_change_since_blocks_the_undo() {
        let mut stored = BTreeMap::new();
        stored.insert("a".to_owned(), 3);
        stored.insert("b".to_owned(), 1);
        let same = stored.clone();
        assert!(untouched(&stored, &same));
        let mut bumped = stored.clone();
        bumped.insert("b".to_owned(), 2);
        assert!(!untouched(&stored, &bumped));
        let mut added = stored.clone();
        added.insert("c".to_owned(), 1);
        assert!(!untouched(&stored, &added));
    }
}
