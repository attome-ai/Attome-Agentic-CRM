//! L1-T4: a master entity's golden records, built from what each source
//! system sends.
//!
//! - [`ingest`](ingest::ingest) stores one source system's version of a
//!   record as a contribution (`<entity>__contribution`, L1-T2), holds it
//!   when it fails the entity's field validation, attaches a valid one to its
//!   golden record (found through the A29 external-id links, or created from
//!   the contribution) and queues `EngineJob::MasterRebuild`.
//! - [`rebuild`](rebuild::rebuild) recomputes the golden record from its
//!   attached contributions, attribute by attribute, by each attribute's
//!   survivorship rule (`source_system_rank`, L1-T3; else the newest value),
//!   skipping attributes a person pinned, writes the changed attributes
//!   through the generic update path (audit, row version and change feed),
//!   and records where each value came from (`<entity>__provenance`).

pub mod ingest;
pub mod rebuild;

pub use ingest::{Ingested, ingest};
pub use rebuild::{Rebuilt, rebuild};

/// The rebuild lock key of a golden record.
pub(crate) fn rebuild_lock_key(golden: uuid::Uuid) -> String {
    format!("attome-records/master-rebuild:{golden}")
}
