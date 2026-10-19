//! `attome`: the server and its commands, as a library so integration tests
//! (`tests/`) build the exact app the binary runs. No business logic belongs
//! here: `auth` is route wiring only; credential flows live in `attome_auth`,
//! account management in `attome_security`.
// Deep async call graphs (an agent turn runs actions that run turns)
// overflow the default query depth.
#![recursion_limit = "512"]

// The modules moved here from v1's `server` crate refer to it by name.
extern crate self as attome;

pub mod alert_notify;
pub mod apikey_pepper_registry;
pub mod auth;
pub mod backup;
pub mod boot;
/// The other subcommands: `worker`, `migrate`, `healthcheck`,
/// `audit-chainer`, `verify-audit-chain`, `preflight`, `changeset-replay`.
pub mod cmd;
/// M53 Phase 1 (Omnichannel, web chat only, D-474) — the public web chat
/// widget endpoint. Lives here, not `attome-api`, because it needs both
/// `attome-ai` and `attome-integration` at once and neither can be a real
/// dependency of `attome-api` without a cycle — see this module's own doc
/// comment.
/// J9-T2: the co-browse session channel.
pub mod cobrowse;
pub mod db_role_seed;
/// Dev-only login-password and agent API-key seeding — physically absent from
/// release binaries (see the module's own doc comment for the three-gate
/// rationale).
#[cfg(debug_assertions)]
pub mod dev_access_seed;
pub mod jobs;
pub mod observability;
pub mod omnichannel;
pub mod openapi;
/// S2-T14: the document each caller is served.
pub mod openapi_filter;
/// S2-T7 — policy extensions on every operation.
pub mod openapi_policy;
pub mod platform_seed_lock;
pub mod readonly_role_seed;
pub mod role_seed_lock;
pub mod schedulers;
/// `attome serve`: the HTTP server (and, unless configured otherwise, the
/// inline job worker and schedulers).
pub mod serve;
