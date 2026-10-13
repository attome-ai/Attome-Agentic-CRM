//! Compile-time privilege keys for this crate's two bespoke routes — every
//! other operation on `grc_*` entities goes through generic entity CRUD,
//! which already enforces `{logicalname}.{action}` itself (same posture
//! `attome-service::auth`'s module doc states for its own crate).
use attome_server::authz::PrivilegeKey;

/// `grc_assessment.update` — minted automatically by
/// `entity_privileges::seed_all` once `seed::seed` registers
/// `grc_assessment` (same `{logicalname}.{action}` convention every
/// entity's privileges follow). `lifecycle::start_assessment_route`'s
/// compile-time policy.
#[derive(Debug)]
pub struct AssessmentUpdate;

impl PrivilegeKey for AssessmentUpdate {
    const KEY: &'static str = "grc_assessment.update";
}

/// `grc_finding.update` — `lifecycle::remediate_finding_route`'s
/// compile-time policy.
#[derive(Debug)]
pub struct FindingUpdate;

impl PrivilegeKey for FindingUpdate {
    const KEY: &'static str = "grc_finding.update";
}
