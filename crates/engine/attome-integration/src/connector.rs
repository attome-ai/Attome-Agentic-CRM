//! The connector contract — a closed catalogue, mirroring `attome-ai`'s
//! `Action` trait shape (object-safe via a boxed future, since this
//! workspace's edition doesn't make `async fn` in a trait object-safe): a
//! fixed, compile-time-enumerated set of adapters, never a user-authored
//! script. "Connector builder" (the plan's target UX) is a *configuration* of
//! [`adapters::rest::RestAdapter`] — endpoint templates, pagination style,
//! auth — not a place to run arbitrary code.
//!
//! [`connector_for`] is the only way to reach an adapter, and its match is
//! exhaustive over [`ConnectorKind`]: adding a kind is a code change and a
//! release (I-5's shape, same as `attome-ai`'s registry), never a runtime
//! registration call.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde_json::Value;

use crate::system::IntegrationSystem;

pub mod adapters;

/// `integration_system.kind` as a closed Rust enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorKind {
    Rest,
    Mailbox,
    Channel,
    Esign,
    Calendar,
    FileDrop,
    /// F5-T4: a payment gateway; its calls go through attome-billing's
    /// `PaymentGateway` trait, not pull/push.
    PaymentGateway,
}

impl ConnectorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Mailbox => "mailbox",
            Self::Channel => "channel",
            Self::Esign => "esign",
            Self::Calendar => "calendar",
            Self::FileDrop => "file_drop",
            Self::PaymentGateway => "payment_gateway",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rest" => Some(Self::Rest),
            "mailbox" => Some(Self::Mailbox),
            "channel" => Some(Self::Channel),
            "esign" => Some(Self::Esign),
            "calendar" => Some(Self::Calendar),
            "file_drop" => Some(Self::FileDrop),
            "payment_gateway" => Some(Self::PaymentGateway),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct PullResult {
    pub records: Vec<Value>,
    pub next_cursor: Option<String>,
}

#[derive(Debug)]
pub struct PushResult {
    pub ok: bool,
    pub detail: Option<String>,
}

/// One event a webhook payload decoded to — `event_type` is adapter-defined
/// (e.g. `"record.updated"`), `payload` is the raw decoded body. Phase 1
/// writes these into `integration_event` (D-425); mapping a payload onto
/// a target CRM entity via M12's `data_mapping` is Phase 2 (sync
/// runs).
#[derive(Debug)]
pub struct WebhookEvent {
    pub event_type: String,
    pub payload: Value,
}

#[derive(Debug)]
pub struct HealthResult {
    pub ok: bool,
    pub detail: Option<String>,
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// The generic capability set every adapter implements, regardless of kind.
/// Object-safe (boxed-future methods, same shape as `attome_ai::Action`) so
/// [`connector_for`] can return `&'static dyn Connector`.
///
/// Every method takes `credential` explicitly (already decrypted by the
/// caller via `crate::credential::resolve`, and sealed: Z1-T10's
/// [`crate::credential::Credential`] goes into a request without its value
/// being handed out — an adapter never touches `KeyRing`/DB itself) rather than bundling it onto
/// [`IntegrationSystem`], so the row type stays a plain, freely-loggable
/// `sqlx::FromRow` shape and the one place a secret can leak is this
/// parameter list, not a struct field some other code path might `{:?}`.
pub trait Connector: Send + Sync {
    /// Pulls records since `cursor` (an opaque, adapter-defined string).
    /// Phase 1 skeleton only — no caller invokes this yet (Phase 2 sync
    /// runs); implemented on the REST adapter for forward-compatibility,
    /// `Err` on the mailbox stub.
    fn pull<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a crate::credential::Credential>,
        cursor: Option<&'a str>,
    ) -> BoxFuture<'a, PullResult>;

    /// Pushes one outbound event/record to the system.
    fn push<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a crate::credential::Credential>,
        event: &'a Value,
    ) -> BoxFuture<'a, PushResult>;

    /// Decodes an inbound webhook body into zero or more platform events.
    /// `body` is the raw request payload; signature verification against
    /// `credential` happens in `webhook::handle_webhook` before this is
    /// called — an adapter only ever sees an already-authenticated body, so
    /// this method does not re-verify it (kept in the signature only so a
    /// future adapter that needs it — e.g. to select a sub-secret — has it
    /// without a second resolve).
    fn webhook<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a crate::credential::Credential>,
        body: &'a [u8],
    ) -> BoxFuture<'a, Vec<WebhookEvent>>;

    /// "Test connection" — a bounded, side-effect-free reachability probe.
    fn health<'a>(
        &'a self,
        system: &'a IntegrationSystem,
        credential: Option<&'a crate::credential::Credential>,
    ) -> BoxFuture<'a, HealthResult>;
}

/// The only way to reach an adapter. Exhaustive match over [`ConnectorKind`]
/// — the closed-catalogue property is the compiler refusing to build if a
/// new `ConnectorKind` variant is added without a matching arm here.
pub fn connector_for(kind: ConnectorKind) -> &'static dyn Connector {
    static REST: adapters::rest::RestAdapter = adapters::rest::RestAdapter;
    static MAILBOX: adapters::mailbox::MailboxAdapter = adapters::mailbox::MailboxAdapter;
    static WEBCHAT: adapters::webchat::WebChatAdapter = adapters::webchat::WebChatAdapter;
    match kind {
        // A gateway system's health check and base URL use the REST adapter;
        // payments go through attome-billing's gateway adapters.
        ConnectorKind::Rest | ConnectorKind::PaymentGateway => &REST,
        // M53 Phase 1 (D-474): `channel` now has a real adapter — the
        // module plan's own choice of web chat as the first channel, because
        // it needs no third-party credential (`attome-api`'s
        // `omnichannel_public` module). esign/calendar/file_drop still route
        // to the not-yet-implemented mailbox stub (M58/M83 hand-offs,
        // Phase 2+).
        ConnectorKind::Channel => &WEBCHAT,
        ConnectorKind::Mailbox
        | ConnectorKind::Esign
        | ConnectorKind::Calendar
        | ConnectorKind::FileDrop => &MAILBOX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_kind_round_trips_through_its_string_form() {
        for kind in [
            ConnectorKind::Rest,
            ConnectorKind::Mailbox,
            ConnectorKind::Channel,
            ConnectorKind::Esign,
            ConnectorKind::Calendar,
            ConnectorKind::FileDrop,
        ] {
            assert_eq!(ConnectorKind::parse(kind.as_str()), Some(kind));
        }
    }

    #[test]
    fn parse_rejects_an_unknown_kind() {
        assert_eq!(ConnectorKind::parse("smtp"), None);
        assert_eq!(ConnectorKind::parse(""), None);
    }
}
