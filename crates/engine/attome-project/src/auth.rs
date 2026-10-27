//! Compile-time privilege keys for this crate's bespoke routes — every
//! other operation on an entity this crate seeds goes through generic
//! entity CRUD, which already enforces `{logicalname}.{action}` itself.
use attome_server::authz::PrivilegeKey;

/// `attome_project.read` — minted automatically by `entity_privileges::seed_all`
/// once `seed::seed` registers the `attome_project` entity (same
/// `{logicalname}.{action}` convention every entity's privileges follow).
/// G4-T2: reading a queue item's history.
#[derive(Debug)]
pub struct QueueItemRead;

impl PrivilegeKey for QueueItemRead {
    const KEY: &'static str = "queue_item.read";
}

/// G4-T2: picking, releasing and transferring a queue item.
#[derive(Debug)]
pub struct QueueItemUpdate;

impl PrivilegeKey for QueueItemUpdate {
    const KEY: &'static str = "queue_item.update";
}

#[derive(Debug)]
pub struct ProjectRead;

impl PrivilegeKey for ProjectRead {
    const KEY: &'static str = "attome_project.read";
}

/// `project_program.read` — same convention as `ProjectRead`, for
/// `portfolio_program.rs`'s program summary route.
#[derive(Debug)]
pub struct ProgramRead;

impl PrivilegeKey for ProgramRead {
    const KEY: &'static str = "project_program.read";
}

/// `project_portfolio.read` — same convention, for the portfolio summary route.
#[derive(Debug)]
pub struct PortfolioRead;

impl PrivilegeKey for PortfolioRead {
    const KEY: &'static str = "project_portfolio.read";
}

/// `resource_allocation.read` — same convention, for `capacity.rs`'s
/// resource capacity route (M72).
#[derive(Debug)]
pub struct ResourceAllocationRead;

impl PrivilegeKey for ResourceAllocationRead {
    const KEY: &'static str = "resource_allocation.read";
}

/// `project_baseline.create` — same convention, for `baseline.rs`'s
/// baseline capture route. That route also requires
/// `project_baseline_item.create` (checked manually, same
/// one-compile-time-plus-one-manual shape `attome-service::convert.rs` uses)
/// since it writes both entities.
#[derive(Debug)]
pub struct ProjectBaselineCreate;

impl PrivilegeKey for ProjectBaselineCreate {
    const KEY: &'static str = "project_baseline.create";
}

/// `project_change_request.update` — same convention, for
/// `change_request.rs`'s approve/reject routes. See that module's doc
/// comment for exactly what this privilege does and does not guarantee once
/// a four-eyes approval policy is layered on top of it.
#[derive(Debug)]
pub struct ChangeRequestUpdate;

impl PrivilegeKey for ChangeRequestUpdate {
    const KEY: &'static str = "project_change_request.update";
}

/// `project_timesheet.update` — same convention, for `timesheet.rs`'s
/// submit/approve/reject routes.
#[derive(Debug)]
pub struct TimesheetUpdate;

impl PrivilegeKey for TimesheetUpdate {
    const KEY: &'static str = "project_timesheet.update";
}

/// `project_change_request.approve` (P0 0.7) — the approve/reject routes
/// require it, the same privilege the bundle puts on the state model's
/// `pending -> approved|rejected` transitions, so the bespoke route and a
/// generic PATCH demand the same thing.
#[derive(Debug)]
pub struct ChangeRequestApprove;

impl PrivilegeKey for ChangeRequestApprove {
    const KEY: &'static str = "project_change_request.approve";
}

/// `project_timesheet.approve` (P0 0.7) — same, for the timesheet
/// approve/reject routes (`submitted -> approved|rejected`).
#[derive(Debug)]
pub struct TimesheetApprove;

impl PrivilegeKey for TimesheetApprove {
    const KEY: &'static str = "project_timesheet.approve";
}
