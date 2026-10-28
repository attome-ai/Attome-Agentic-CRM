//! Primary-quote sync (roadmap D6-T7): one direction per call, never both.
//!
//! A deal and its primary quote each have a lines hash (sha256 over each
//! line's product, quantity, total and discount, in a fixed order). The
//! deal stores the hash of its last sync (`lines_synced_hash`). When both
//! sides changed since then, a sync without `force` answers
//! `409 sync_both_changed` with both line sets so the user chooses.
//!
//! `from_quote` replaces the deal's lines with copies of the quote's lines
//! (`source_quote_line_ref` set; the quote's unit price becomes the list
//! price and its discount the line discount) and reprices the deal, under
//! the deal's lock. `to_quote` is refused: quotes are priced by CPQ and
//! changed through it.

use attome_audit::AuditOperation;
use attome_core::EngineState;
use attome_security::RecordAction;
use attome_server::authz::{Authorized, Privilege};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::split_store::OpportunityUpdate;

/// One line as the hash sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SyncLine {
    pub product_ref: Option<Uuid>,
    #[schema(value_type = String)]
    pub quantity: Decimal,
    #[schema(value_type = String)]
    pub line_total: Decimal,
    #[schema(value_type = String)]
    pub discount: Decimal,
}

/// The hash of a line set, independent of the order the lines are kept in.
pub fn lines_hash(lines: &[SyncLine]) -> String {
    let mut rows: Vec<String> = lines
        .iter()
        .map(|l| {
            format!(
                "{}|{}|{}|{}",
                l.product_ref.map(|p| p.to_string()).unwrap_or_default(),
                l.quantity.normalize(),
                l.line_total.normalize(),
                l.discount.normalize()
            )
        })
        .collect();
    rows.sort();
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(rows.join("\n").as_bytes()))
    )
}

/// What a sync may do, given the two hashes and the last synced one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncDecision {
    /// Nothing differs.
    InSync,
    /// Both sides changed since the last sync: the user chooses.
    BothChanged,
    Proceed,
}

pub fn decide(deal: &str, quote: &str, synced: Option<&str>, force: bool) -> SyncDecision {
    if deal == quote {
        return SyncDecision::InSync;
    }
    let deal_changed = synced != Some(deal);
    let quote_changed = synced != Some(quote);
    if deal_changed && quote_changed && synced.is_some() && !force {
        SyncDecision::BothChanged
    } else {
        SyncDecision::Proceed
    }
}

fn dec(text: Option<String>) -> Decimal {
    text.and_then(|t| t.parse().ok()).unwrap_or(Decimal::ZERO)
}

type RawLine = (Option<Uuid>, Option<String>, Option<String>, Option<String>);

fn to_lines(rows: Vec<RawLine>) -> Vec<SyncLine> {
    rows.into_iter()
        .map(|(product, qty, total, discount)| SyncLine {
            product_ref: product,
            quantity: dec(qty),
            line_total: dec(total),
            discount: dec(discount),
        })
        .collect()
}

async fn deal_lines(tx: &mut attome_db::Tx<'_>, deal: Uuid) -> Result<Vec<SyncLine>, AppError> {
    let rows: Vec<RawLine> = sqlx::query_as(
        "SELECT product_ref, quantity::text, line_total::text, discount_amount::text \
         FROM opportunity_line \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(to_lines(rows))
}

async fn quote_lines(tx: &mut attome_db::Tx<'_>, quote: Uuid) -> Result<Vec<SyncLine>, AppError> {
    let rows: Vec<RawLine> = sqlx::query_as(
        "SELECT product_ref, quantity::text, line_total::text, discount_amount::text \
         FROM quote_line WHERE quote_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(quote)
    .fetch_all(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(to_lines(rows))
}

/// Which way to sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SyncDirection {
    FromQuote,
    ToQuote,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SalesSyncBody {
    pub direction: SyncDirection,
    /// Overwrite even when both sides changed.
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct SalesSyncResult {
    pub opportunity_id: Uuid,
    /// `synced`, `in_sync` or `sync_both_changed`.
    pub status: String,
    pub lines_synced_hash: Option<String>,
    /// Both line sets, when both changed.
    pub deal_lines: Option<Vec<SyncLine>>,
    pub quote_lines: Option<Vec<SyncLine>>,
    /// D6-T8: the snapshot that undoes the sync (30 minutes).
    pub snapshot_id: Option<Uuid>,
}

/// Sync a deal with its primary quote
///
/// Copies lines one way, from the quote to the deal or the other way. When both changed since the
/// last sync, it answers 409 `sync_both_changed` with both line sets unless `force` is set. Needs
/// update rights on the opportunity. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/sales/opportunities/{id}/sync",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The opportunity")),
    request_body = SalesSyncBody,
    responses(
        (status = 200, description = "Synced, or already in sync", body = SalesSyncResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not update this opportunity", body = ErrorResponse),
        (status = 404, description = "No such opportunity, no primary quote, or quote sync is switched off", body = ErrorResponse),
        (status = 409, description = "Both the deal and the quote changed since the last sync (`sync_both_changed`, with both line sets), or the deal is being changed", body = SalesSyncResult),
        (status = 422, description = "to_quote: quotes are changed through CPQ", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_sales_quote_sync(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<OpportunityUpdate>>,
    Path(deal): Path<Uuid>,
    Json(body): Json<SalesSyncBody>,
) -> Result<Response, AppError> {
    crate::flags::require(&state, &ctx, crate::flags::QUOTE_SYNC).await?;
    if body.direction == SyncDirection::ToQuote {
        return Err(AppError::Validation(
            "to_quote is not offered: quotes are priced and changed through CPQ".into(),
        ));
    }
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
    let row: Option<(Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT primary_quote_ref, lines_synced_hash FROM opportunity \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true) FOR UPDATE",
    )
    .bind(deal)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(quote), synced)) = row else {
        return Err(AppError::NotFound);
    };
    let ours = deal_lines(&mut tx, deal).await?;
    let theirs = quote_lines(&mut tx, quote).await?;
    let (ours_hash, theirs_hash) = (lines_hash(&ours), lines_hash(&theirs));
    match decide(&ours_hash, &theirs_hash, synced.as_deref(), body.force) {
        SyncDecision::InSync => {
            return Ok(Json(SalesSyncResult {
                opportunity_id: deal,
                status: "in_sync".into(),
                lines_synced_hash: synced,
                deal_lines: None,
                quote_lines: None,
                snapshot_id: None,
            })
            .into_response());
        }
        SyncDecision::BothChanged => {
            return Ok((
                StatusCode::CONFLICT,
                Json(SalesSyncResult {
                    opportunity_id: deal,
                    status: "sync_both_changed".into(),
                    lines_synced_hash: synced,
                    deal_lines: Some(ours),
                    quote_lines: Some(theirs),
                    snapshot_id: None,
                }),
            )
                .into_response());
        }
        SyncDecision::Proceed => {}
    }
    let before = crate::undo::capture_lines(&mut tx, deal).await?;
    sqlx::query(
        "UPDATE opportunity_line SET is_active = false, modified_at = now(), \
             row_version = row_version + 1 \
         WHERE opportunity_ref = $1 AND (is_active IS NULL OR is_active = true)",
    )
    .bind(deal)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "DELETE FROM opportunity_split WHERE opportunity_ref = $1 AND line_ref IS NOT NULL",
    )
    .bind(deal)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO opportunity_line \
           (opportunity_ref, product_ref, name, quantity, list_price, discount_amount, \
            line_kind, source_quote_line_ref, owner_ref) \
         SELECT $1, q.product_ref, p.name, q.quantity, q.unit_price, \
                CASE WHEN COALESCE(q.quantity, 0) > 0 \
                     THEN COALESCE(q.discount_amount, 0) / q.quantity ELSE NULL END, \
                'one_time', q.id, o.owner_ref \
         FROM quote_line q LEFT JOIN product p ON p.id = q.product_ref \
         CROSS JOIN opportunity o \
         WHERE q.quote_ref = $2 AND o.id = $1 AND (q.is_active IS NULL OR q.is_active = true)",
    )
    .bind(deal)
    .bind(quote)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    crate::opportunity_lines::reprice_in_tx(&mut tx, deal).await?;
    let snapshot = crate::undo::record_in_tx(&mut tx, deal, before, ctx.user_id).await?;
    let now_hash = lines_hash(&deal_lines(&mut tx, deal).await?);
    sqlx::query("UPDATE opportunity SET lines_synced_hash = $2 WHERE id = $1")
        .bind(deal)
        .bind(&now_hash)
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
            "sales.lines_synced_from_quote",
            ctx.user_id,
        )
        .comment(format!("from quote {quote}")),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Json(SalesSyncResult {
        opportunity_id: deal,
        status: "synced".into(),
        lines_synced_hash: Some(now_hash),
        deal_lines: None,
        quote_lines: None,
        snapshot_id: Some(snapshot),
    })
    .into_response())
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(post_sales_quote_sync),
    components(schemas(SyncLine, SyncDirection, SalesSyncBody, SalesSyncResult))
)]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn line(p: u128, q: i64, t: i64) -> SyncLine {
        SyncLine {
            product_ref: Some(Uuid::from_u128(p)),
            quantity: Decimal::from(q),
            line_total: Decimal::from(t),
            discount: Decimal::ZERO,
        }
    }

    #[test]
    fn the_hash_ignores_order_and_trailing_zeros() {
        let a = [line(1, 2, 100), line(2, 1, 50)];
        let b = [line(2, 1, 50), line(1, 2, 100)];
        assert_eq!(lines_hash(&a), lines_hash(&b));
        let mut c = line(1, 2, 100);
        c.line_total = Decimal::new(10000, 2);
        assert_eq!(lines_hash(&[c, line(2, 1, 50)]), lines_hash(&a));
        assert_ne!(
            lines_hash(&a),
            lines_hash(&[line(1, 3, 100), line(2, 1, 50)])
        );
    }

    #[test]
    fn both_sides_changed_asks_unless_forced() {
        assert_eq!(decide("a", "a", Some("x"), false), SyncDecision::InSync);
        assert_eq!(
            decide("a", "b", Some("x"), false),
            SyncDecision::BothChanged
        );
        assert_eq!(decide("a", "b", Some("x"), true), SyncDecision::Proceed);
        // Only the quote changed since the last sync.
        assert_eq!(decide("a", "b", Some("a"), false), SyncDecision::Proceed);
        // Never synced: nothing to compare against.
        assert_eq!(decide("a", "b", None, false), SyncDecision::Proceed);
    }
}
