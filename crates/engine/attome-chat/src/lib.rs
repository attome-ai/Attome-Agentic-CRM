//! The internal chat engine (roadmap C9-T1).
//!
//! Direct, group and record channels, their members, messages with one level
//! of threads and an attached document, and per-channel retention under legal
//! holds. Gated on the `chat` module. The tables are infrastructure
//! (migration `0139_chat.sql`): membership is the read gate, which the
//! generic record API cannot express.

pub mod channels;
pub mod model;
pub mod retention;

pub use model::ChatModel;

/// This crate's advisory-lock namespace (`"attome-chat/…"` keys), registered in
/// `crates/apps/attome/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 44;

/// This crate's slice of the workspace OpenAPI document, merged in by
/// `attome::openapi::document()`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    channels::openapi_fragment()
}
