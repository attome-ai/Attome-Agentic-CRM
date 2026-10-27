//! Q13-T1: view-as and act-as sessions, as the request pipeline applies them.
//!
//! An administrator starts a session (`attome_security::impersonation`) and
//! then sends its id in [`HEADER`] from their own signed-in browser session.
//! The `authz` middleware ([`crate::middleware::auth::authz`]) then:
//!
//! - accepts the header only on a cookie session, never an API key or S2S;
//! - asks the installed [`ImpersonationStore`] whether the session is live
//!   and belongs to this caller (30 minutes, never refreshed, ended early by
//!   the administrator), and refuses the request when it is not;
//! - resolves the **subject's** security context in place of the caller's;
//! - in view-as, refuses every request that is not a read ([`view_allows`]);
//! - in act-as, refuses credential, approval and signing actions
//!   ([`act_allows`]);
//! - logs the request (session, method, path) before it runs, and refuses it
//!   when the log cannot be written (fail closed for audit);
//! - runs the request inside [`scope`], so every audit row written for it
//!   carries both identities (`attome_audit`'s impersonation attribution).
//!
//! The session routes themselves ([`MANAGEMENT_PREFIX`]) always run as the
//! administrator, so a session can be ended while it is in use.

use std::future::Future;
use std::sync::{Arc, OnceLock};

use attome_types::AppError;
use axum::http::Method;
use chrono::{DateTime, Utc};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The request header that names the session.
pub const HEADER: &str = "x-attome-impersonation";

/// The session routes, which always run as the administrator.
pub const MANAGEMENT_PREFIX: &str = "/api/v1/admin/security/impersonation";

/// What a session allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpersonationMode {
    /// See what the person sees; change nothing.
    View,
    /// Act as the person, with their consent.
    Act,
}

impl ImpersonationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::View => "view",
            Self::Act => "act",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "view" => Some(Self::View),
            "act" => Some(Self::Act),
            _ => None,
        }
    }
}

/// A live session, attached to the request it applies to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Impersonation {
    pub session_id: Uuid,
    /// The administrator.
    pub actor_id: Uuid,
    /// The person whose access the request runs with.
    pub subject_id: Uuid,
    pub mode: ImpersonationMode,
    pub expires_at: DateTime<Utc>,
}

/// Where sessions live (`attome_security::impersonation::PgImpersonationStore`).
pub trait ImpersonationStore: Send + Sync + 'static {
    /// The live session `session_id` started by `actor_id`, if any.
    fn active<'a>(
        &'a self,
        session_id: Uuid,
        actor_id: Uuid,
    ) -> BoxFuture<'a, Result<Option<Impersonation>, AppError>>;

    /// Records one request made in `session`, before it runs.
    fn log_request<'a>(
        &'a self,
        session: &'a Impersonation,
        method: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<(), AppError>>;
}

static STORE: OnceLock<Arc<dyn ImpersonationStore>> = OnceLock::new();

/// Installs the store, once at boot. Without one the header is refused.
pub fn install(store: Arc<dyn ImpersonationStore>) {
    let _ = STORE.set(store);
}

pub(crate) fn store() -> Option<&'static Arc<dyn ImpersonationStore>> {
    STORE.get()
}

tokio::task_local! {
    static CURRENT: Impersonation;
}

/// Runs `work` as part of `session`.
pub async fn scope<F: Future>(session: Impersonation, work: F) -> F::Output {
    CURRENT.scope(session, work).await
}

/// The session the current request runs in, if any.
pub fn current() -> Option<Impersonation> {
    CURRENT.try_with(Clone::clone).ok()
}

/// Reads made with POST: running a query or a search changes nothing.
const READ_POSTS: [&str; 3] = [
    "/api/v1/query/execute",
    "/api/v1/query/run",
    "/api/v1/search",
];

/// View-as: only reads.
pub fn view_allows(method: &Method, path: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
        || (*method == Method::POST && READ_POSTS.contains(&path))
}

/// Never done as someone else: their credentials, second factors, keys and
/// sessions, their impersonation consents, approval decisions and signatures.
const ACT_REFUSED: [&str; 8] = [
    "/api/v1/auth/",
    "/api/v1/me/impersonation",
    "/api/v1/me/mfa",
    "/api/v1/me/api-keys",
    "/api/v1/me/password",
    "/api/v1/me/sessions",
    "/api/v1/approvals",
    "/api/v1/admin/",
];

/// Act-as: everything the person may do, except [`ACT_REFUSED`].
pub fn act_allows(path: &str) -> bool {
    !ACT_REFUSED.iter().any(|prefix| path.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impersonation_view_allows_reads_only() {
        assert!(view_allows(&Method::GET, "/api/v1/contact"));
        assert!(view_allows(&Method::POST, "/api/v1/query/execute"));
        assert!(!view_allows(&Method::POST, "/api/v1/contact"));
        assert!(!view_allows(&Method::PATCH, "/api/v1/contact/1"));
        assert!(!view_allows(&Method::DELETE, "/api/v1/contact/1"));
    }

    #[test]
    fn impersonation_act_refuses_credentials_and_approvals() {
        assert!(act_allows("/api/v1/contact"));
        for path in [
            "/api/v1/auth/logout",
            "/api/v1/me/mfa/totp",
            "/api/v1/approvals/1/decide",
            "/api/v1/admin/security/roles",
        ] {
            assert!(!act_allows(path), "{path}");
        }
        assert_eq!(
            ImpersonationMode::parse("act"),
            Some(ImpersonationMode::Act)
        );
        assert_eq!(ImpersonationMode::parse("login"), None);
    }
}
