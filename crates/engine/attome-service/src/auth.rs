//! Compile-time privilege key for this crate's one bespoke route — every
//! other operation on `service_work_request`/`service_ticket` goes through generic
//! entity CRUD, which already enforces `{logicalname}.{action}` itself.
use attome_server::authz::PrivilegeKey;

/// `service_work_request.update` — minted automatically by
/// `entity_privileges::seed_all` once `seed::seed` registers
/// `service_work_request` (same `{logicalname}.{action}` convention every
/// entity's privileges follow). The conversion route also requires
/// `service_ticket.create`, checked with `ctx.require_key(..)` inside the
/// handler rather than a second compile-time extractor — `Authorized<P>`
/// only composes one policy.
#[derive(Debug)]
pub struct WorkRequestUpdate;

impl PrivilegeKey for WorkRequestUpdate {
    const KEY: &'static str = "service_work_request.update";
}

/// `service_ticket.update` — the compile-time policy for `sla::apply_sla_policy`,
/// this crate's second bespoke route.
#[derive(Debug)]
pub struct TicketUpdate;

impl PrivilegeKey for TicketUpdate {
    const KEY: &'static str = "service_ticket.update";
}

/// `service_work_request.create` — `offering::create_work_request`'s compile-time
/// policy. Distinct from `WorkRequestUpdate` above: this route creates a new
/// `service_work_request` row from a catalog offering, it never updates one.
#[derive(Debug)]
pub struct WorkRequestCreate;

impl PrivilegeKey for WorkRequestCreate {
    const KEY: &'static str = "service_work_request.create";
}

/// `service_offering.read` — `offering::list_active_offerings`'s
/// compile-time policy (the internal "New Request" picker).
#[derive(Debug)]
pub struct OfferingRead;

impl PrivilegeKey for OfferingRead {
    const KEY: &'static str = "service_offering.read";
}

/// `service_offering.update` — `offering::publish_offering`'s compile-time
/// policy (G3-T1).
#[derive(Debug)]
pub struct OfferingUpdate;

impl PrivilegeKey for OfferingUpdate {
    const KEY: &'static str = "service_offering.update";
}

/// `service_ticket.read` — M85's `timeline::ticket_timeline` compile-time policy.
/// A read-only route, unlike `TicketUpdate` above; the entity-level gate here
/// only proves the caller may read tickets at all — `timeline::build_timeline`
/// still runs its own record-level RLS check against the specific ticket, and
/// a further per-row check against each communication/decision the feed would
/// otherwise include (see that module's doc comment).
#[derive(Debug)]
pub struct TicketRead;

impl PrivilegeKey for TicketRead {
    const KEY: &'static str = "service_ticket.read";
}
