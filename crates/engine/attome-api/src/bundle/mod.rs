//! The metadata bundle engine — `attome-bundle/v1` (P-environment-promotion,
//! Phase 1 / F273).
//!
//! A bundle is the declarative desired state of a deployment's configuration
//! metadata. This module is the read-only half of the engine:
//!
//! - [`model`] — the bundle types and the format gate ([`parse_bundle`]);
//! - [`canonical`] — deterministic bytes and the SHA-256 [`bundle_hash`];
//! - [`export`] — live metadata → bundle, every UUID reference translated to
//!   a logical key;
//! - [`plan`] — desired vs live → per-object `create|update|retire|noop|
//!   blocked`, bound to the live state by `basis_hash`.
//!
//! The write half and its surface live beside them:
//!
//! - [`ledger`] — the single plan/apply table and its status machine;
//! - [`apply`] — the durable, resumable job that closes the diff
//!   ([`run_apply_job`]), one reconcile primitive per object, one doorbell
//!   per run;
//! - [`routes`] — `/api/v1/admin/metadata/{export,import,plans,drift,sync,
//!   bundles/{name}/rollback}`;
//! - [`break_glass`] — the approved production authoring window;
//! - [`pull`] — fetch + Ed25519-verify a `deployment.bundle_ref` artifact and
//!   run it through the same plan/apply path ([`pull::sync`]), at first boot
//!   and via `POST …/metadata/sync`;
//! - [`record_sets`] — Phase 3 reference data: plan-time key resolution
//!   against live tables, apply through the ordinary entity-mutation
//!   primitives;
//! - [`derived_id`] — deterministic ids for a `Create` step's new row, so the
//!   same bundle produces the same ids on every fresh deployment (D-374
//!   amendment).
//!
//! **Why a module here and not an `xrm-bundle` crate.** The plan first said
//! "new engine crate"; it lives in `attome-api` instead because the stored-
//! query publish pipeline (`query_admin::lint_and_plan`), the sidebar, view
//! and security admin service functions that apply must call are all in this
//! crate, and a crate below it would have to depend upward. Recorded as a
//! deliberate deviation; the CI "no DDL" grep targets this directory.
//!
//! **Two rules this directory keeps, mechanically enforced by CI:**
//!
//! 1. *Allow-list.* Only the component types `model.rs` defines can be
//!    exported or planned. Users, user grants, API keys, S2S clients and
//!    secrets, the license, and sessions are not in the model and therefore
//!    cannot leak — there is no generic table reader here.
//! 2. *No schema statements of its own.* Nothing in this directory creates,
//!    alters, or drops a table or column. Apply reaches the database only
//!    through `attome-metadata`'s provisioning primitives and the existing admin
//!    service functions (D-003; `P-data-lifecycle` §8 "import must not fork
//!    provisioning logic"). The export/plan half is pure `SELECT`.
//!
//! Identity is logical keys, never UUIDs; removals are soft-retire, never a
//! hard drop; plan and apply are separate calls bound by a hash — see the
//! module docs of each file for the specifics.

pub mod apply;
pub mod break_glass;
pub mod canonical;
pub mod derived_id;
pub mod export;
pub mod ledger;
pub mod model;
/// T8-T1: a bundle with a signed manifest.
pub mod package;
pub mod plan;
pub mod platform;
pub mod pull;
pub mod record_sets;
pub mod routes;

pub use apply::{ApplySummary, run_apply_job};
pub use break_glass::ACTION_BREAK_GLASS;
pub use canonical::{bundle_hash, canonical_json, hash_bytes};
pub use derived_id::derived_id;
pub use export::{PLATFORM_VERSION, applied_schema_version, export_bundle};
pub use ledger::{ACTION_BUNDLE_APPLY, PlanRow, PlanStatus, enqueue_apply};
pub use model::{
    AppDef, AttributeDef, AttributePatch, BUNDLE_FORMAT, Bundle, BundleDependency, EntityDef,
    FieldSecurityProfileDef, FormatError, GrantCondition, KNOWN_FIELD_TYPES, PrivilegeDef,
    ProfileField, QueryDef, QueryEntityMapping, QueryRef, RecordSet, Requires, RoleDef,
    RoleEntityAccess, RoleGrant, SidebarDef, ViewDef, check_format, parse_bundle,
};
pub use plan::{
    BundlePlan, Diff, PlanAction, PlanEntry, PlanOptions, PlanSummary, build_plan, check_requires,
    diff_bundles, plan_bundle,
};
pub use platform::apply_platform_bundle;
pub use pull::{SyncOutcome, SyncStatus, fetch_and_verify, sync};
pub use record_sets::{apply_record, plan_record_sets, record_key};
pub use routes::{ApplyAccepted, do_apply_plan};
