//! Outbound email: SMTP by default, or Amazon SES or SendGrid per sender
//! identity (Z8-T1, [`provider`]).
//!
//! **Charter.** This crate owns: the SMTP transport and its TLS mode
//! (`implicit`/`starttls`/`none`), the send-outcome classification and the
//! one D-661 suppression rule, the delivery ledger and its transitions, the
//! reachability probe, and the four inline account-lifecycle templates. It
//! consumes `config.email` and knows nothing about XRM entities, users or
//! deployment topology (guidelines §1 — zero `xrm-*` dependencies).
//!
//! **Two tables, deliberately here (BEM-D2, a documented exception to D-274's
//! prefix ownership).** `email_delivery` and
//! `email_suppression` are read and written by
//! `suppression::` and `delivery::` — this crate's modules, carrying the
//! `xrm_notification_` prefix that migration 0062 gave them. `send()` is the one
//! choke point every producer in the workspace shares, and moving the modules
//! into `xrm-notification` would rename eight consumers for naming alone. The
//! one other reader, `xrm_notification::dispatch::is_email_suppressed`,
//! delegates to `suppression::is_suppressed` rather than repeating the query
//! (BEM-12/F8).
//!
//! **Where sending happens.** From an apalis job handler
//! (`PlatformJob::SendEmail`, guidelines §10 — a slow SMTP host must never
//! slow a request) *and* from `xrm_notification::dispatch`'s own direct,
//! non-apalis send for the notification engine's email channel (M51 Phase 1).
//! "Jobs only" was true before M51 and is not any more. Nothing on a request
//! path calls `send` directly.
//!
//! **Bookkeeping is advisory (D-166).** The ledger and the suppression list
//! record what happened; they never decide it. A ledger write that fails after
//! the relay accepted the mail must not fail the job, and a suppression write
//! that fails must not make the job claim the address was suppressed.

pub mod delivery;
mod error;
pub mod health;
mod message;
/// Z8-T1 — SMTP, Amazon SES and SendGrid behind one provider trait.
pub mod provider;
pub mod rate;
mod sender;
pub mod suppression;
pub mod templates;
#[cfg(feature = "test-support")]
pub mod testing;

pub use delivery::DeliveryStatus;
pub use error::SendError;
pub use health::{
    CAPABILITY_PROBE_TIMEOUT, EmailHealth, health_check, health_check_authenticated,
    health_check_with_timeout,
};
pub use message::{EmailAttachment, EmailMessage, EmailStream, MAX_ATTACHMENT_BYTES};
pub use sender::{catch_all, send};
