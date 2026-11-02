//! F11: revenue recognition over the ledger pack's revenue records
//! (changeset 0003). [`schedule`] builds the recognition schedule of an
//! invoice line (F11-T2); allocation across obligations, the other patterns,
//! contract changes and the period close follow in their own modules
//! (F11-T3 onward).

/// F11-T4: standalone selling prices and allocation across obligations.
pub mod allocation;
/// F11-T6: contract changes, previewed and applied by their IFRS 15 treatment.
pub mod change;
/// F11-T7: the monthly close: recognise, balance, approve, post, lock.
pub mod close;
/// F11-T3: contracts from orders and subscriptions, and combining them.
pub mod contract;
/// F11-T8: a close posted to an ERP's ledger instead.
pub mod erp;
/// F11-T9: loyalty points deferred as a material right.
pub mod loyalty;
/// The schedules of obligations built from orders and subscriptions.
pub mod obligation_schedule;
/// F11-T5: the recognition patterns, as amounts per period.
pub mod patterns;
pub mod schedule;
