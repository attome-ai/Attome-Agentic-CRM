//! Attome's extension runtime (roadmap Y10, V2-D125): customer code as
//! WebAssembly on Wasmtime, which cannot crash the server or run away with
//! it. Y10-T1 is the runtime and its limits; the WIT host API is
//! `wit/attome.wit` (records through the engine with the caller's access,
//! logs, granted secrets, after-commit HTTP), bound to the record write
//! pipeline's hook stages by Y10-T2 and held to each extension's approved
//! grants by Y10-T3.

/// Y10-T3: what an extension may touch, checked before every host call.
pub mod grants;
/// The host API as a Rust trait, and AE2-T1's in-memory fake host.
pub mod host;
/// Y10-T1: the engine, the limits and running one export.
pub mod runtime;

pub use grants::{Denied, EntityGrant, Grants};
pub use host::{FakeHost, HostApi, Level, Response};
pub use runtime::{ExtensionError, Limits, Runtime};
