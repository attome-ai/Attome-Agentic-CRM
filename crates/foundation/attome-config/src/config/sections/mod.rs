//! One file per `AppConfig` section family, grouped by use case / policy
//! boundary (item 25 of the platform's file-size cleanup list). Each
//! submodule is `pub(crate)` — not re-exported with a glob — so
//! `config::mod`'s explicit `pub use`/`use` lists (mirroring `lib.rs`'s
//! public surface and `tests.rs`'s needs) are the only path a name flows
//! through on its way out of this directory.

pub(crate) mod audit;
pub(crate) mod auth;
pub(crate) mod backup;
pub(crate) mod cache;
pub(crate) mod capability;
pub(crate) mod database;
pub(crate) mod deployment;
pub(crate) mod docgen;
pub(crate) mod einvoice;
pub(crate) mod events;
pub(crate) mod fleet;
pub(crate) mod inference;
pub(crate) mod integration;
pub(crate) mod metadata;
pub(crate) mod observability;
pub(crate) mod ops;
pub(crate) mod platform;
pub(crate) mod portal;
pub(crate) mod shed;
pub(crate) mod storage;
pub(crate) mod webchat;
pub(crate) mod webcrawl;
