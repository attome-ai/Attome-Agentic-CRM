//! Solution 7 Phase 1 (D-785) — the changeset service: open, list, show,
//! close, abandon and export (`/api/v1/admin/changesets`), and what close
//! needs that only this crate has — the bundle model the translation maps
//! rows onto. Spec: `document/general/SOLUTION-7-PHASE-1-DESIGN.md` §4.6,
//! §7.
//!
//! - [`routes`] — the authoring routes (under the metadata-authoring
//!   prefix: production refuses them outside a break-glass window);
//! - [`close`] — close, abandon and sealing an automatic changeset;
//! - [`translate`] — a recorded row snapshot → logical v1 `args`;
//! - [`jcs`] — RFC 8785 canonical JSON and the document checksum;
//! - [`summary`] — the plain-language review summary.
//!
//! The recorder itself (which changeset a write records into, the row lock,
//! automatic changesets) is `attome_core::changeset`.
//!
//! The apply engine (lane L6, design §5):
//!
//! - [`plan`] — check, order and plan documents (§5.2), and fold operations
//!   onto their parents' definitions;
//! - [`ledger`] — `changeset_apply`, sharing the bundle ledger's
//!   claim scheme (§5.1);
//! - [`apply`] — the resumable `EngineJob::ApplyChangesets` worker (§5.3);
//! - [`apply_routes`] — `/api/v1/admin/metadata/changesets/{plan,apply,adopt,
//!   ledger}`;
//! - [`adopt`] — development records its own closed changesets as applied
//!   (§5.6);
//! - [`boot`] — the platform-changeset boot path (§5.7; the only path since
//!   Phase 1.5) and the owner-layer stamp's
//!   imperative-seed keys;
//! - [`platform_index`] — the compiled `changesets/platform/*.json`
//!   (generated);
//! - [`report`] — the release report of an apply run (Phase 2, §10);
//! - [`rollout_status`] — `GET /api/v1/admin/metadata/rollout/status`, the
//!   fleet console's poll (D-792), mounted with [`apply_routes`].

pub mod adopt;
pub mod apply;
pub mod apply_routes;
pub mod boot;
/// Solution 7 Phase 2 (D-787 rule 7) — business keys in the planner and applier.
pub mod business_key;
pub mod close;
pub mod jcs;
pub mod layers;
pub mod ledger;
pub mod plan;
pub mod platform_index;
/// Solution 7 Phase 2 (D-788 Topic 14) — the release report around an apply
/// run: begin, ready, the one post-apply notification.
pub mod report;
/// D-792 — the fleet console's one status call per poll.
pub mod rollout_status;
pub mod routes;
pub mod summary;
pub(crate) mod translate;

/// The document format tag.
pub const FORMAT: &str = "attome-changeset/v1";

/// The approval action that gates applying changesets on the production
/// profile — the changeset counterpart of `metadata.bundle_apply` (D-376,
/// design §5.3). Registered in `approval_admin::KNOWN_ACTION_TYPES` and
/// `PRODUCTION_MANDATORY_ACTIONS`; `execute_approved` runs
/// [`apply_routes::do_apply`] with the approved payload.
pub const ACTION_CHANGESET_APPLY: &str = "metadata.changeset_apply";
