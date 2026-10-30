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
/// D20-T2: public booking links.
pub mod booking;
pub mod boot;
/// N18-T1: WhatsApp and SMS conversations answered by the channel's bot.
pub mod bot_channels;
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
#[cfg(feature = "http3")]
pub mod http3;
/// J2-T2: shared mailboxes routed into cases, leads and contacts.
pub mod inbound_mail;
pub mod jobs;
/// Q19-T2: customer-held master keys, unwrapped once at boot.
pub mod kms;
/// AB7-T3: the listening socket, inherited from a supervisor or bound.
pub mod listener;
/// D15-T2: personal emails captured onto matching records.
pub mod mail_capture;
pub mod observability;
pub mod omnichannel;
pub mod openapi;
/// S2-T14: the document each caller is served.
pub mod openapi_filter;
/// S2-T7 — policy extensions on every operation.
pub mod openapi_policy;
pub mod platform_seed_lock;
/// D9-T3: quote acceptance by guest link.
pub mod quote_accept;
pub mod readonly_role_seed;
pub mod role_seed_lock;
pub mod schedulers;
/// T5-T1: `attome scratch create`, a masked sandbox copy.
pub mod scratch;
/// Z1-T12: cloud secret stores read once at boot.
pub mod secret_sources;
/// `attome serve`: the HTTP server (and, unless configured otherwise, the
/// inline job worker and schedulers).
pub mod serve;
/// J4-T2: inbound texts and STOP opt-outs.
pub mod sms_inbound;
/// J8-T1: social channels in and replies out.
pub mod social;
/// Z5-T6: the server terminates TLS itself.
pub mod tls;
/// J6-T1: calls out and in.
pub mod voice;
/// J5-T2: WhatsApp conversations in.
pub mod whatsapp_inbound;
