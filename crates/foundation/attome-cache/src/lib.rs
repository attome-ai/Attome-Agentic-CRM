//! Reusable stateful infrastructure whose correctness or coordination
//! semantics require state shared across application nodes rather than
//! process-local memory (guidelines §5) — not narrowly "caching."
//!
//! ## What this crate owns
//!
//! - **Local snapshot/hot caches** ([`local`]) — `MetadataCache` (arc-swap
//!   snapshots) and `HotCache` (moka, TTL-bounded).
//! - **Redis connectivity** ([`redis_pool`]) — pool/role-split factories,
//!   pinned-CA TLS, dedicated subscriber clients.
//! - **Distributed coordination primitives** ([`rate_limit`],
//!   [`sticky_primary`], [`token_window`]) — sliding-window admission
//!   control, read-your-own-writes routing, rolling budget accounting.
//! - **Buffering** ([`stream_buffer`], [`write_coalesce`]) — at-least-once
//!   Redis Streams transport, write-coalescing hash buffers.
//! - **Operational probing** ([`persistence`]) — "would this keyspace
//!   survive a restart?"
//!
//! ## Allowed / forbidden
//!
//! Allowed: reusable, cross-node, arc-swap- or Redis-backed shared-state
//! machinery with a stated source-of-truth, key shape, TTL, and
//! fail-open-vs-fail-closed classification — the bar every module above
//! already meets (see the `caching-and-state` skill's own checklist).
//!
//! Forbidden: business-specific caches keyed to one `xrm-*` concept. A
//! customer/dashboard/entity-record cache belongs to its owning engine,
//! which alone knows how to invalidate it correctly — it never moves here
//! just because reusing `RedisPool` would be convenient.
//!
//! ## Deciding whether a new concern belongs here
//!
//! [`token_window`]'s own module doc is the worked example: a brand-new
//! concern (AI token budgeting) landed in this crate rather than in
//! `attome_inference` because a token budget must be shared across app nodes
//! or it is not a budget at all, and `attome-inference` is transport-only by
//! construction (I-11, D-360) with no Redis dependency of its own. Ask the
//! same two questions of any new addition: does its correctness depend on
//! every node seeing the same value, and does no existing crate already own
//! both the concept and a place to put it?

/// Z3-T9: this node's cache numbers and the purge.
pub mod admin;
/// Z3-T5 — what a cached value depends on, for change-feed invalidation.
pub mod depends;
pub mod local;
/// The in-process store Solo runs on instead of Redis (A5).
pub mod memory;
pub mod persistence;
pub mod rate_limit;
pub mod redis_pool;
/// Z3-T1: every cache's declaration and the process registry of them.
pub mod spec;
pub mod sticky_primary;
pub mod store;
pub mod stream_buffer;
pub mod subscriber;
/// Z3-T2: the tiered cache (L1, then the shared store, then the loader).
pub mod tiered;
/// M101 slice 2 — the shared-state half of `attome_inference::budget`, which
/// shipped with no way to learn what a caller had already consumed. See the
/// module doc.
pub mod token_window;
pub mod write_coalesce;

/// BCA-21 — the failure counter every Redis call in this crate records to.
/// Crate-private: it is an implementation detail of the modules below, not a
/// second public metrics surface.
pub(crate) mod ops;
/// BCA-13 — the one place this crate's Redis operation bounds live.
pub mod timeouts;

pub use attome_config::CacheRole;
pub use local::{HotCache, MetadataCache, create_hot_cache, get_recorded};
pub use persistence::{MemoryStatus, PersistenceStatus};
pub use redis_pool::{
    RedisPool, SUBSCRIBER_CLIENTS_CREATED, create_redis_pool, create_role_redis_pool,
    create_subscriber_client, redis_ping,
};
pub use store::Store;
pub use stream_buffer::{AutoclaimResult, StreamEntry};
pub use subscriber::{Doorbell, Subscriber};
pub use token_window::{Refused, Reservation, ReserveWindow, Reserved};
