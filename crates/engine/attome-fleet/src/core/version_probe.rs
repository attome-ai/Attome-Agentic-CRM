//! Mirrors the exact JSON shape `GET /version` returns
//! (`crates/foundation/attome-server/src/health.rs::version`) so
//! `fleet-migrations`'s HTTP client can deserialize a real probe response
//! without hand-rolled JSON parsing. Field names and optionality match that
//! handler exactly — keep the two in sync by hand until a shared,
//! OpenAPI-generated type exists (`P-api-contract` Phase 1, not started —
//! D-189).
//!
//! `image_digest` is deliberately absent here too, for the same reason it's
//! absent from the real endpoint: see `crate::ids::ImageDigest`'s doc
//! comment.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VersionProbe {
    pub application_version: String,
    pub git_revision: String,
    pub schema_version: Option<i64>,
    pub schema_dirty: Option<bool>,
    pub configuration_version: String,
    #[serde(default)]
    pub components: BTreeMap<String, String>,
}
