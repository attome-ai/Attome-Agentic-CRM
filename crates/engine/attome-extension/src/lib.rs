//! Attome's extension runtime (roadmap Y10, V2-D125): customer code as
//! WebAssembly on Wasmtime, which cannot crash the server or run away with
//! it. Y10-T1 is the runtime and its limits; the WIT host API is
//! `wit/attome.wit` (records through the engine with the caller's access,
//! logs, granted secrets, after-commit HTTP), bound to the record write
//! pipeline's hook stages by Y10-T2 and held to each extension's approved
//! grants by Y10-T3.

/// Y10-T3: what an extension may touch, checked before every host call.
pub mod grants;
/// Y10-T6: one hook call, shared by live writes and sample runs.
pub mod harness;
/// The host API as a Rust trait, and AE2-T1's in-memory fake host.
pub mod host;
/// M17-T1: job and webhook extensions and the writes they ask for.
pub mod kinds;
/// AE2-T3: a run's host calls, recorded and replayed.
pub mod record;
/// Y10-T1: the engine, the limits and running one export.
pub mod runtime;

pub use grants::{Denied, EntityGrant, Grants, HookDecl, HookPoint};
pub use harness::{HOOK_EXPORT, HookAnswer, HookInput, call_hook};
pub use host::{FakeHost, HostApi, Level, Response};
pub use record::{HostCall, Recorder, Replayer};
pub use wasmtime::Module;

pub use runtime::{CallCost, ExtensionError, Limits, MAX_OUTPUT_BYTES, Runtime, mask_secrets};
