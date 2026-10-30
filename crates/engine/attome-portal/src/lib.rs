//! Web portals for external users (D-576).
//!
//! A portal (`webportal`) is addressed by a path prefix, `/{keyword}/*`,
//! and has a type: `anonymous`, `authenticated` or `mixed`. Its users
//! (`webportal_user`) are a **separate principal** from staff: they never
//! have a row in `user_account`, their secrets live in the
//! `webportal_credential` infrastructure table (migration 0482), and a
//! portal request is never authorized through a staff `SecurityContext`.
//!
//! Phase 1: the two entities (`platform-bundles/attome-portal.json`), the
//! credential store, the portal admin and provisioning API ([`admin`]), and
//! the guards that keep generic CRUD from writing the security-relevant fields
//! ([`guard`]).
//!
//! Phase 2: portal authentication on the portal's own router ([`router`],
//! mounted with `ServerBuilder::add_audience_bundle`): typed, audience-bound
//! session tokens ([`session`]), rotating refresh families with reuse
//! detection ([`refresh`]), invitation and reset tokens ([`onetime`]), TOTP
//! ([`mfa`]), lockout, and the engine behind them ([`auth`]).
//!
//! Phase 3: portal roles, grants and field profiles ([`roles`]), and
//! `PortalSession → PortalContext → AccessPlan` ([`context`]) into the shared
//! entity engine (`attome_records::access_plan`), served at
//! `/{keyword}/api/v1/records/{entity}`.
//!
//! G-9 (plan §4.2): the per-node portal and plan-template cache
//! ([`cache`]), versioned by a Redis token every portal-admin write replaces.

pub mod account;
pub mod admin;
pub mod auth;
pub mod cache;
/// D1-T3: a verified sign-up linked to its contact.
pub mod contact_link;
pub mod context;
/// G12-T3: a portal on its own domain.
pub mod domain;
pub mod email;
pub mod guard;
pub mod keyword;
pub mod mfa;
pub mod model;
pub mod oidc;
pub mod onetime;
pub mod policy;
pub mod provision;
pub mod recovery;
pub mod refresh;
pub mod roles;
pub mod router;
pub mod secret;
pub mod session;
pub mod signup;
mod telemetry;
pub mod trusted;
pub mod trusted_account;

pub use model::PortalModel;

/// D-351: the `int4` namespace for every `"attome-portal/…"` advisory-lock key,
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 26;

pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = admin::openapi_fragment();
    doc.merge(router::openapi_fragment());
    doc.merge(<domain::DomainApiDoc as utoipa::OpenApi>::openapi());
    doc
}
