//! S8-T2: rewrites requests and responses between adjacent API versions, so
//! a caller written against an older dated version keeps working after a
//! change. Each [`VersionAdapter`] knows one step (`from` → `to`) and the
//! operations (`"{METHOD} {route template}"`) it touches; the chain applies
//! them in order from the caller's version up to the current one for a
//! request, and back down for its response. Adapters are pure JSON
//! transforms: no database, no I/O.
//!
//! While the server answers one version the chain is empty and the version
//! layer never buffers a body.

use std::sync::LazyLock;

use axum::body::Body;
use axum::http::header::CONTENT_LENGTH;
use axum::response::Response;
use serde_json::Value;

use crate::middleware::idempotency::{Buffered, buffer_up_to};

/// The largest body the layer will rewrite; a larger one passes unchanged.
const MAX_ADAPTED_BODY: usize = 16 * 1024 * 1024;

/// One step between adjacent versions.
pub trait VersionAdapter: Send + Sync {
    /// The older version.
    fn from_version(&self) -> &'static str;
    /// The next version up.
    fn to_version(&self) -> &'static str;
    /// The operations it rewrites, as `"{METHOD} {route template}"`.
    fn operations(&self) -> &'static [&'static str];
    /// A request body written for `from`, as `to` expects it.
    fn request(&self, operation: &str, body: Value) -> Value;
    /// A response body produced at `to`, as a `from` caller expects it.
    fn response(&self, operation: &str, body: Value) -> Value;
}

/// The adapters, oldest step first, each step's `to` the next one's `from`.
pub struct AdapterChain {
    adapters: Vec<Box<dyn VersionAdapter>>,
}

impl std::fmt::Debug for AdapterChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterChain")
            .field("steps", &self.adapters.len())
            .finish()
    }
}

impl AdapterChain {
    /// A chain of `adapters`, refused unless each step starts where the one
    /// before it ended.
    pub fn new(adapters: Vec<Box<dyn VersionAdapter>>) -> Result<Self, String> {
        for pair in adapters.windows(2) {
            if pair[0].to_version() != pair[1].from_version() {
                return Err(format!(
                    "version adapters are not contiguous: {} -> {} is followed by {} -> {}",
                    pair[0].from_version(),
                    pair[0].to_version(),
                    pair[1].from_version(),
                    pair[1].to_version()
                ));
            }
        }
        Ok(Self { adapters })
    }

    /// The steps from `version` upward, oldest first.
    fn steps_from(&self, version: &str) -> &[Box<dyn VersionAdapter>] {
        match self
            .adapters
            .iter()
            .position(|a| a.from_version() == version)
        {
            Some(start) => &self.adapters[start..],
            None => &[],
        }
    }

    /// Whether any step from `version` up rewrites `operation`.
    pub fn applies(&self, version: &str, operation: &str) -> bool {
        self.steps_from(version)
            .iter()
            .any(|a| a.operations().contains(&operation))
    }

    /// A request from a `version` caller, as the current version expects it.
    pub fn upgrade_request(&self, version: &str, operation: &str, mut body: Value) -> Value {
        for adapter in self.steps_from(version) {
            if adapter.operations().contains(&operation) {
                body = adapter.request(operation, body);
            }
        }
        body
    }

    /// A response at the current version, as a `version` caller expects it.
    pub fn downgrade_response(&self, version: &str, operation: &str, mut body: Value) -> Value {
        for adapter in self.steps_from(version).iter().rev() {
            if adapter.operations().contains(&operation) {
                body = adapter.response(operation, body);
            }
        }
        body
    }
}

/// The server's chain: empty while it answers one version
/// (`attome_types::api_version::SUPPORTED`).
pub fn chain() -> &'static AdapterChain {
    static CHAIN: LazyLock<AdapterChain> = LazyLock::new(|| AdapterChain {
        adapters: Vec::new(),
    });
    &CHAIN
}

/// Buffers a JSON body and rewrites it with `adapt`; a body that is too
/// large or not JSON passes unchanged.
pub(crate) async fn rewrite_body(body: Body, adapt: impl FnOnce(Value) -> Value) -> Body {
    let bytes = match buffer_up_to(body, MAX_ADAPTED_BODY).await {
        Buffered::Complete(bytes) => bytes,
        Buffered::Unreplayable(body) => return body,
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(value) => Body::from(serde_json::to_vec(&adapt(value)).unwrap_or(bytes.to_vec())),
        Err(_) => Body::from(bytes),
    }
}

/// [`rewrite_body`] for a response, dropping its now-wrong length.
pub(crate) async fn rewrite_response(
    response: Response,
    adapt: impl FnOnce(Value) -> Value,
) -> Response {
    let (mut parts, body) = response.into_parts();
    parts.headers.remove(CONTENT_LENGTH);
    Response::from_parts(parts, rewrite_body(body, adapt).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The example: version 2026-04 called a contact's name `full_name`.
    struct RenameFullName;

    impl VersionAdapter for RenameFullName {
        fn from_version(&self) -> &'static str {
            "2026-04"
        }
        fn to_version(&self) -> &'static str {
            "2026-10"
        }
        fn operations(&self) -> &'static [&'static str] {
            &["POST /api/v1/contacts"]
        }
        fn request(&self, _operation: &str, mut body: Value) -> Value {
            if let Some(obj) = body.as_object_mut()
                && let Some(value) = obj.remove("full_name")
            {
                obj.insert("name".into(), value);
            }
            body
        }
        fn response(&self, _operation: &str, mut body: Value) -> Value {
            if let Some(obj) = body.as_object_mut()
                && let Some(value) = obj.remove("name")
            {
                obj.insert("full_name".into(), value);
            }
            body
        }
    }

    struct Noop(&'static str, &'static str);

    impl VersionAdapter for Noop {
        fn from_version(&self) -> &'static str {
            self.0
        }
        fn to_version(&self) -> &'static str {
            self.1
        }
        fn operations(&self) -> &'static [&'static str] {
            &[]
        }
        fn request(&self, _: &str, body: Value) -> Value {
            body
        }
        fn response(&self, _: &str, body: Value) -> Value {
            body
        }
    }

    const OP: &str = "POST /api/v1/contacts";

    #[test]
    fn an_old_caller_round_trips_through_the_rename() {
        let chain = AdapterChain::new(vec![Box::new(RenameFullName)]).unwrap();
        assert!(chain.applies("2026-04", OP));
        assert!(!chain.applies("2026-04", "GET /api/v1/contacts"));
        assert!(
            !chain.applies("2026-10", OP),
            "the current version needs no step"
        );

        let sent = json!({ "full_name": "Huda", "email": "h@example.invalid" });
        let upgraded = chain.upgrade_request("2026-04", OP, sent.clone());
        assert_eq!(
            upgraded,
            json!({ "name": "Huda", "email": "h@example.invalid" })
        );
        let answered = chain.downgrade_response("2026-04", OP, upgraded);
        assert_eq!(answered, sent, "the old caller sees its own shape back");
        assert_eq!(
            chain.upgrade_request("2026-10", OP, sent.clone()),
            sent,
            "a current caller is untouched"
        );
    }

    #[test]
    fn a_chain_with_a_gap_is_refused() {
        assert!(
            AdapterChain::new(vec![
                Box::new(Noop("2025-10", "2026-04")),
                Box::new(Noop("2026-04", "2026-10")),
            ])
            .is_ok()
        );
        assert!(
            AdapterChain::new(vec![
                Box::new(Noop("2025-10", "2026-01")),
                Box::new(Noop("2026-04", "2026-10")),
            ])
            .is_err()
        );
    }

    #[test]
    fn the_shipped_chain_is_empty_while_one_version_is_served() {
        if attome_types::api_version::SUPPORTED.len() == 1 {
            assert!(!chain().applies(attome_types::api_version::CURRENT, OP));
        }
    }
}
