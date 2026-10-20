//! Content Management (page builder): staff build custom pages — infinite
//! editorial hierarchy, a block-based visual editor, an independently-set
//! custom URL per page, and draft/publish — and published pages are
//! servable to anonymous visitors under that URL.
//!
//! Pages (`content_page`) are a migration-owned infra table, not a
//! runtime-provisioned entity: a block tree is JSON structure the generic
//! field engine can't express, the same reasoning `webcrawl_page`/
//! `attome_document` already establish. Consequence: the free ancestors/
//! descendants hierarchy machinery wired to provisioned entities
//! (`attome-api`'s `entity_crud::hierarchy`) does not apply here —
//! `crate::hierarchy` imitates that established pattern (D-095/D-138: a
//! non-blocking, tree-wide advisory lock plus a bounded-depth cycle guard)
//! rather than reusing its code, since it operates on a different table
//! shape entirely.
//!
//! This is a real licensed module (`attome_modules::MODULE_CONTENT`), mounted
//! through `attome-api`'s existing `license_gate` helper (the same one
//! `entity_crud`/`bulk` use for `MODULE_CORE`) rather than `ModelRegistry` —
//! unlike `attome-webcrawl` (deliberately license-less, D-365), content
//! management is a standalone sellable capability. The admin surface
//! (`attome-api/src/content_admin.rs`) is `Authorized<Admin>` + license
//! gated; the public page-view surface (`content_public.rs`) is a bypass
//! route (`attome_server::middleware::bypass`) that does its own manual
//! license/publish check, since an anonymous caller has no session for the
//! usual license-gate middleware to run against and must see identical 404s
//! whether a page doesn't exist or the deployment isn't licensed for this
//! module.

pub mod admin;
pub mod analytics;
/// G11-T1: knowledge articles as a page type.
pub mod article;
/// K5-T2: page audiences and signed preview links.
pub mod audience;
pub mod blocks;
pub mod hierarchy;
pub mod landing;
pub mod model;
pub mod redirect;
pub mod render_html;
pub mod scheduling;
/// E13-T4: page search settings and JSON-LD.
pub mod seo;
pub mod sites;
pub mod space_admin;
pub mod template_admin;
/// K5-T4: linked translations with stale flags.
pub mod translations;
/// K5-T1: page versions, compare, restore and approval per space.
pub mod versions;

/// D-351 — this crate's advisory-lock namespace (`"attome-content/…"` keys),
/// registered in `crates/server/tests/advisory_lock_namespaces.rs`.
pub const ADVISORY_LOCK_NAMESPACE: i32 = 13;
