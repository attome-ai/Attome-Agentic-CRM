//! F6-T12: lines that do not ship from stock are handed to their owners.
//!
//! A product's `fulfilment_kind` (fulfilment pack changeset 0005) decides a
//! line's kind at split ([`crate::split::line_kind`]). For every line that is
//! not `goods`, the split writes one named change-feed event about the
//! fulfilment line, in its own transaction:
//!
//! - [`ROUTE_EVENT`] for `service` (field service work orders), `subscription`,
//!   `warranty`, `licence` and `digital` lines: the owning module reads the
//!   line (its kind, order line, product and quantity) and does the work;
//! - [`DROPSHIP_EVENT`] for a `drop_ship` line: the vendor ships it.
//!
//! Nothing here creates work orders, subscriptions or entitlements; the
//! owners do. An owner reports a line done by raising [`FULFILLED_EVENT`]
//! about the fulfilment line (or about the order line it came from); the
//! fulfilment sweep reads it from the feed and sets the line delivered in
//! full ([`mark_fulfilled`]). A goods line is never closed this way: its
//! shipments and deliveries count it.

use attome_core::EngineState;
use attome_core::change_feed::{self, ChangeOperation};
use attome_types::AppError;
use uuid::Uuid;

/// A non-goods line handed to the module that owns its kind.
pub const ROUTE_EVENT: &str = "fulfilment.line.route";
/// A drop-ship line handed to its vendor.
pub const DROPSHIP_EVENT: &str = "fulfilment.dropship.requested";
/// An owner's report that a routed line is done.
pub const FULFILLED_EVENT: &str = "fulfilment.line.fulfilled";

/// The kinds a product's `fulfilment_kind` may name, `goods` first.
pub const KINDS: [&str; 7] = [
    "goods",
    "service",
    "subscription",
    "warranty",
    "licence",
    "digital",
    "drop_ship",
];

/// The event that routes a line of `kind`, or `None` for goods. Pure.
pub fn route_event(kind: &str) -> Option<&'static str> {
    match kind {
        "goods" => None,
        "drop_ship" => Some(DROPSHIP_EVENT),
        _ => Some(ROUTE_EVENT),
    }
}

/// Sets every routed (non-goods) live fulfilment line that `record_id`
/// names — the fulfilment line itself, or the order line it came from — as
/// delivered in full, and announces each on the change feed. Returns how
/// many lines changed; a line already delivered is left alone, so a repeated
/// report is harmless.
pub async fn mark_fulfilled(state: &EngineState, record_id: Uuid) -> Result<usize, AppError> {
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let lines: Vec<Uuid> = sqlx::query_scalar(
        "UPDATE fulfilment_order_line \
            SET quantity_delivered = quantity, row_version = row_version + 1, \
                modified_at = NOW() \
          WHERE (id = $1 OR order_line_ref = $1::text) \
            AND line_kind IS NOT NULL AND line_kind <> 'goods' \
            AND COALESCE(quantity_delivered, 0) < COALESCE(quantity, 0) \
            AND (is_active IS NULL OR is_active = true) \
          RETURNING id",
    )
    .bind(record_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    for line in &lines {
        change_feed::emit_tx(
            &mut tx,
            "fulfilment_order_line",
            *line,
            ChangeOperation::Update,
        )
        .await?;
    }
    attome_db::tx::commit(tx).await?;
    Ok(lines.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_subscription_line_emits_event() {
        assert_eq!(route_event("subscription"), Some(ROUTE_EVENT));
        assert_eq!(route_event("service"), Some(ROUTE_EVENT));
        assert_eq!(route_event("drop_ship"), Some(DROPSHIP_EVENT));
        assert_eq!(route_event("goods"), None);
        assert!(KINDS.iter().skip(1).all(|k| route_event(k).is_some()));
    }
}
