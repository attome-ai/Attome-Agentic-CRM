//! F6-T5: the stock seam. Fulfilment asks what a location holds of a
//! product without depending on the inventory engine (I6), which implements
//! [`StockSource`] and registers it on the `EngineSystem` builder. With none
//! registered, stock is not tracked and callers fall back to lead times.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use chrono::NaiveDate;
use rust_decimal::Decimal;
use uuid::Uuid;

/// What a location holds of one product.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Availability {
    pub on_hand: Decimal,
    /// Held for other orders.
    pub reserved: Decimal,
    /// Expected receipts, by the day they arrive.
    pub incoming: Vec<(NaiveDate, Decimal)>,
}

impl Availability {
    /// On hand less reserved, never below zero.
    pub fn free(&self) -> Decimal {
        (self.on_hand - self.reserved).max(Decimal::ZERO)
    }
}

/// The future [`StockSource::available`] returns.
pub type StockFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Availability>, AppError>> + Send + 'a>>;

/// Answers what a location holds; `None` when the product is not stocked
/// there.
pub trait StockSource: Send + Sync + 'static {
    fn available<'a>(&'a self, product: Uuid, location: Uuid) -> StockFuture<'a>;
}
