pub mod access_log;
pub mod admin;
pub mod claims;
pub mod concurrency;
pub mod config_clients;
pub mod crypto;
pub mod db;
pub mod middleware;
pub mod mtls;
pub mod oauth_clients;
pub mod rate_limit;
pub mod rewrap;
pub mod telemetry;

pub use claims::S2SClaims;

/// This crate's advisory-lock namespace (registry id 29,
/// `crates/server/tests/advisory_lock_namespaces.rs`), for the
/// `"attome-s2s/create-client:{slug}"` and `"attome-s2s/generate-key:…"` locks in
/// `admin.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 29;
