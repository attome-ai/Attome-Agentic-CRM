//! `attome-docgen` — M57 Phase 1 (Document Generation,
//! `document/module-master-plans/M57-document-generation.md`,
//! `document/decisions/foundation/D-463.md`). Turns a record into a
//! rendered PDF from an admin-authored HTML template with `{{ field }}`
//! merge tags and `{% if expr %}...{% endif %}` conditional sections.
//!
//! **Layering and isolation (the load-bearing property of this crate):**
//! rendering never happens in-process. `render_client` POSTs the merged,
//! already-permission-filtered HTML to an isolated headless-Chrome sidecar
//! (`pdf-service-dev` in dev; `deploy/docgen-render-service.md` for a real
//! deployment) reachable only on the internal network, under an explicit
//! timeout and response-size cap (guidelines §10 — a hung or malicious
//! render must fail closed, never block a request thread or a worker
//! indefinitely). The sidecar is never given secrets and never reaches
//! anything beyond its paired Chrome instance.
//!
//! **Security.** [`merge`] builds the record context through
//! `attome_records::entity_crud::read_record` — the exact record-level +
//! field-level security projection every other read path already applies —
//! so a field the caller cannot see is simply absent from the context and
//! renders as an empty string, never the real value. [`ssrf`] screens the
//! fully-merged HTML (after substitution, not just the raw template body —
//! a merge field is exactly as capable of smuggling an external URL as the
//! template author) for embedded external resource references before it
//! ever reaches the render sidecar, the same SSRF-hardening discipline
//! `attome-events`' webhook delivery (`attome_server::ssrf_guard`) and
//! `attome-webcrawl::safety` already apply to their own outbound fetches.
//!
//! **Merge language.** Conditional sections evaluate a `attome-rules` (M45)
//! boolean expression — never a second templating/expression engine
//! (D-463). `{{ field }}` substitution is this crate's own small, non-Turing
//! -complete concern (no engine call needed for plain substitution).
//!
//! `docgen_template` is a normal runtime-provisioned entity (applied at
//! boot from `platform-bundles/attome-docgen.json`) —
//! generic CRUD, per-entity privileges, audit, and record sharing all apply
//! for free. `docgen_render` (one row per render request/job) is a
//! migration-owned infrastructure table (`0311_xrm_docgen_render.sql`), same
//! reasoning `report_run` documents for itself — system-written
//! execution history, never admin-authored metadata.
pub mod auth;
pub mod merge;
pub mod model;
pub mod render;
pub mod render_client;
pub mod ssrf;

pub use model::DocgenModel;

/// P-api-contract Phase 1 — this crate's slice of the workspace OpenAPI
/// document, merged in by `server::openapi::document`.
pub fn openapi() -> utoipa::openapi::OpenApi {
    render::openapi_fragment()
}
