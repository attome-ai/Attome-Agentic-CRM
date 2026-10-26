//! F11: revenue recognition over the ledger pack's revenue records
//! (changeset 0003). [`schedule`] builds the recognition schedule of an
//! invoice line (F11-T2); allocation across obligations, the other patterns,
//! contract changes and the period close follow in their own modules
//! (F11-T3 onward).

/// F11-T4: standalone selling prices and allocation across obligations.
pub mod allocation;
/// F11-T3: contracts from orders and subscriptions, and combining them.
pub mod contract;
/// F11-T9: loyalty points deferred as a material right.
pub mod loyalty;
/// F11-T5: the recognition patterns, as amounts per period.
pub mod patterns;
pub mod schedule;
