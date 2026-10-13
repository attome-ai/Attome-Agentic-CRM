//! Compile-time privilege key for this crate's one bespoke route family.
//!
//! `/api/v1/docgen/templates/{id}/render` and
//! `/api/v1/docgen/renders/{render_id}` are not shaped `/api/v1/{entity}/...`
//! (the template/render id is a path segment, but the entity name is fixed),
//! so `Authorized<RecordScoped<A>>`'s `{entity}`-path-segment autobinding has
//! nothing to resolve against — same reasoning `attome-report::auth`'s module
//! doc gives for its own `Privilege<K>` keys, copied here verbatim. Record
//! scope for a *specific* template id is checked separately in the handler
//! via `attome_records::entity_crud::read_record` (same RLS/field-security path
//! every other read goes through); record scope for a *specific* render id
//! is `render.requested_by == ctx.user_id` (or admin), same as
//! `attome-report::run::run_status`.
use attome_server::authz::PrivilegeKey;

/// `docgen_template.read` — minted automatically by
/// `entity_privileges::seed_all` once the `attome-docgen` platform bundle
/// registers the entity.
#[derive(Debug)]
pub struct DocgenTemplateRead;

impl PrivilegeKey for DocgenTemplateRead {
    const KEY: &'static str = "docgen_template.read";
}
