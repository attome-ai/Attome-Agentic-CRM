//! The step-up caller (D-510 rules 2 and 7; attome-auth hardening 2.1b).
//!
//! `attome_auth::step_up` decides from a [`Caller`]. This builds one from what
//! authn attached to the request, and from nothing else:
//!
//! - a validated cookie session carries [`CookieSession`] and the
//!   [`SessionId`] of its refresh family;
//! - the API-key branch and S2S attach neither.
//!
//! A family, user or session id in a header, query or body never reaches the
//! step-up guard, because this reads only request extensions.

use std::convert::Infallible;

use attome_auth::SessionId;
use attome_auth::step_up::Caller;
use axum::extract::FromRequestParts;
use axum::http::{Extensions, request::Parts};

use crate::middleware::auth::CookieSession;

/// The caller as authn established it.
pub(crate) fn caller_from_extensions(extensions: &Extensions) -> Caller {
    match (
        extensions.get::<CookieSession>(),
        extensions.get::<SessionId>(),
    ) {
        (Some(_), Some(session)) => Caller::Session(*session),
        _ => Caller::NonSession,
    }
}

/// Extracts the step-up [`Caller`] from request extensions. Never fails: a
/// request authn did not mark as a cookie session is [`Caller::NonSession`],
/// which the step-up guard refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepUpCaller(pub Caller);

impl<S> FromRequestParts<S> for StepUpCaller
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(caller_from_extensions(&parts.extensions)))
    }
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use uuid::Uuid;

    use super::*;
    use crate::middleware::auth::ApiKeyIdentity;

    async fn caller_of(request: Request<Body>) -> Caller {
        let (mut parts, _body) = request.into_parts();
        let StepUpCaller(caller) = StepUpCaller::from_request_parts(&mut parts, &())
            .await
            .expect("infallible");
        caller
    }

    #[tokio::test]
    async fn a_cookie_session_with_a_sid_names_its_family() {
        let session = SessionId(Uuid::now_v7());
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(CookieSession);
        request.extensions_mut().insert(session);
        assert_eq!(caller_of(request).await, Caller::Session(session));
    }

    #[tokio::test]
    async fn a_cookie_session_without_a_sid_has_no_family() {
        let mut request = Request::new(Body::empty());
        request.extensions_mut().insert(CookieSession);
        assert_eq!(caller_of(request).await, Caller::NonSession);
    }

    #[tokio::test]
    async fn an_api_key_or_unmarked_request_has_no_family() {
        let mut api_key = Request::new(Body::empty());
        api_key
            .extensions_mut()
            .insert(ApiKeyIdentity(Uuid::now_v7()));
        assert_eq!(caller_of(api_key).await, Caller::NonSession);

        assert_eq!(
            caller_of(Request::new(Body::empty())).await,
            Caller::NonSession
        );

        let mut sid_without_cookie = Request::new(Body::empty());
        sid_without_cookie
            .extensions_mut()
            .insert(SessionId(Uuid::now_v7()));
        assert_eq!(
            caller_of(sid_without_cookie).await,
            Caller::NonSession,
            "a SessionId only counts on a request authn marked as a cookie session"
        );
    }

    /// A session or family id supplied by the client is never read.
    #[tokio::test]
    async fn client_supplied_session_ids_are_ignored() {
        let forged = Uuid::now_v7();
        let request = Request::builder()
            .uri(format!(
                "/api/v1/auth/step-up/identity_link?sid={forged}&family_id={forged}"
            ))
            .header("x-session-id", forged.to_string())
            .header("x-family-id", forged.to_string())
            .body(Body::from(format!(
                r#"{{"sid":"{forged}","family_id":"{forged}"}}"#
            )))
            .unwrap();
        assert_eq!(caller_of(request).await, Caller::NonSession);

        let real = SessionId(Uuid::now_v7());
        let mut request = Request::builder()
            .uri(format!("/api/v1/auth/step-up/identity_link?sid={forged}"))
            .header("x-session-id", forged.to_string())
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(CookieSession);
        request.extensions_mut().insert(real);
        assert_eq!(
            caller_of(request).await,
            Caller::Session(real),
            "only the validated token's sid names the family"
        );
    }
}
