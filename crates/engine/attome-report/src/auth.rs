//! Compile-time privilege keys for this crate's bespoke routes — every
//! other operation on an entity this crate seeds goes through generic
//! entity CRUD, which already enforces `{logicalname}.{action}` itself.
//!
//! These exist because `report_admin.rs`/`schedule_admin.rs`/`run.rs`'s
//! routes are not shaped `/api/v1/{entity}/...` (the report/schedule id is a
//! path segment, but the *entity name* is fixed, not client-supplied), so
//! `Authorized<RecordScoped<A>>`'s `{entity}`-path-segment autobinding
//! (`attome_server::authz::ENTITY_PATH_PARAM`) has nothing to resolve against
//! — see the security-model skill's checklist: "a fixed privilege key ->
//! Authorized<Privilege<K>>". `crates/server/tests/route_authz.rs`'s
//! `MAX_BARE_RECORD_SCOPED` ratchet is already fully claimed by
//! `query_exec::execute`/`aggregate::aggregate` (the two genuinely
//! multi/dynamic-entity routes), so a bare `Authorized<RecordScoped>` +
//! manual `ctx.require(..)` here would push that ratchet over its ceiling —
//! `Privilege<K>` is the correct enforcing policy instead, and it checks the
//! identical `{logicalname}.{action}` string `ctx.require` would have.
//! Row-level (record) scope for a *specific* report/schedule/run id is not
//! covered by this policy and is checked separately in the handler by
//! reusing `attome_records::entity_crud::read_record` (same RLS/field-security
//! path every other read goes through) — see each handler's own comment.
use attome_server::authz::PrivilegeKey;

/// `attome_report.read` — minted automatically by `entity_privileges::seed_all`
/// once `seed::seed_reports` registers the `attome_report` entity (same
/// `{logicalname}.{action}` convention every entity's privileges follow).
#[derive(Debug)]
pub struct ReportRead;

impl PrivilegeKey for ReportRead {
    const KEY: &'static str = "attome_report.read";
}

#[derive(Debug)]
pub struct ReportCreate;

impl PrivilegeKey for ReportCreate {
    const KEY: &'static str = "attome_report.create";
}

#[derive(Debug)]
pub struct ReportUpdate;

impl PrivilegeKey for ReportUpdate {
    const KEY: &'static str = "attome_report.update";
}

#[derive(Debug)]
pub struct ScheduleCreate;

impl PrivilegeKey for ScheduleCreate {
    const KEY: &'static str = "report_schedule.create";
}

#[derive(Debug)]
pub struct ScheduleUpdate;

impl PrivilegeKey for ScheduleUpdate {
    const KEY: &'static str = "report_schedule.update";
}
