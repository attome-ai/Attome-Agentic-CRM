//! Privilege-grants and field-security-profile admin API — the friendly
//! surface over the raw `user_account_mm_privilege`/`privilege`/
//! `role*`/`field_security_profile*` tables (see D-011, D-111).
//! All routes require `system.admin` (coarse gate, same as every other admin
//! surface today — per-grant-type authorization isn't seeded yet).
//!
//! Split into one submodule per admin sub-domain — this file only wires
//! `routes()`. `shared` holds the handful of helpers more than one submodule
//! needs (`invalidate_sync_all`, `resolve_entity_ref`, the shared grant-row
//! shape); everything else lives next to the single submodule that owns it.
//! `routes()` is the only public item for every sub-domain except direct
//! role-grant assignment (`user_roles`), whose `ACTION_ROLE_GRANT`/
//! `do_assign_user_role` are re-exported below — `attome-server::
//! approval_admin::execute_approved` needs to name them directly (D-195:
//! this flow's HTTP entrypoint lives in `attome-security`, but its
//! approved-and-executed dispatch is owned by `attome-server`'s generic
//! four-eyes admin surface, which cannot depend back on this crate's private
//! module internals).

mod access_reviews;
mod account_state;
/// Q1-T7: SSO-only roles and break-glass accounts.
mod auth_policy;
mod bulk_access;
pub use bulk_access::{BULK_ACCESS_JOB, BulkAccessPayload, run_bulk_access};
mod bulk_fields;
/// B17-T4: device registration, status and remote wipe.
mod devices;
mod effective_access;
mod field_security;
mod grants;
mod identity_links;
mod invitations;
mod mfa;
mod mfa_coverage;
mod organizations;
mod positions;
mod privileges;
mod role_entity_access;
mod role_grant_conditions;
mod role_grants;
mod roles;
mod sessions;
mod shared;
mod shares;
pub use shares::{Reassigned, reassign_owner_for};
mod teams;
mod user_roles;
mod users;

use attome_core::EngineState;
use axum::Router;

pub use mfa::{ACTION_MFA_RESET_ADMIN, do_reset_user_mfa};
pub use user_roles::{
    ACTION_ROLE_GRANT, RoleGrantOutcome, do_assign_user_role, grant_role_as, role_grant_event,
};

/// M03 gap 1 / D-434 — re-exported so `crates/server/src/jobs.rs` can call
/// the sweep without a `pub(crate)` visibility widening on the submodule
/// itself (same "just the one function" shape as `do_assign_user_role`
/// above).
pub use access_reviews::sweep_due_campaigns;

/// P-api-contract Phase 1 — this sub-tree's slice of the workspace OpenAPI
/// document. Mirrors `routes()` below one-for-one: every module merged there
/// is merged here; a new admin sub-domain that forgets its fragment is a
/// missing path in `openapi.json` that only review catches (D-768).
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = grants::openapi_fragment();
    for fragment in [
        access_reviews::openapi_fragment(),
        auth_policy::openapi_fragment(),
        bulk_access::openapi_fragment(),
        bulk_fields::openapi_fragment(),
        sessions::openapi_fragment(),
        privileges::openapi_fragment(),
        roles::openapi_fragment(),
        role_grants::openapi_fragment(),
        role_grant_conditions::openapi_fragment(),
        role_entity_access::openapi_fragment(),
        user_roles::openapi_fragment(),
        positions::openapi_fragment(),
        teams::openapi_fragment(),
        shares::openapi_fragment(),
        field_security::openapi_fragment(),
        devices::openapi_fragment(),
        mfa::openapi_fragment(),
        mfa_coverage::openapi_fragment(),
        account_state::openapi_fragment(),
        invitations::openapi_fragment(),
        identity_links::openapi_fragment(),
        organizations::openapi_fragment(),
        effective_access::openapi_fragment(),
        users::openapi_fragment(),
    ] {
        doc.merge(fragment);
    }
    doc
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .merge(access_reviews::routes())
        .merge(auth_policy::routes())
        .merge(bulk_access::routes())
        .merge(bulk_fields::routes())
        .merge(grants::routes())
        .merge(sessions::routes())
        .merge(privileges::routes())
        .merge(roles::routes())
        .merge(role_grants::routes())
        .merge(role_grant_conditions::routes())
        .merge(role_entity_access::routes())
        .merge(user_roles::routes())
        .merge(positions::routes())
        .merge(teams::routes())
        .merge(shares::routes())
        .merge(field_security::routes())
        .merge(devices::routes())
        .merge(mfa::routes())
        .merge(mfa_coverage::routes())
        .merge(account_state::routes())
        .merge(invitations::routes())
        .merge(identity_links::routes())
        .merge(organizations::routes())
        .merge(effective_access::routes())
        .merge(users::routes())
}
