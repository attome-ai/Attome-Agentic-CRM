//! Principal kinds (roadmap Z4-T2): who is calling, and which token type
//! carries that caller. Each JWT principal has its own `typ`, and every
//! validator checks `typ` (with issuer and audience), so a token minted for
//! one kind is never accepted as another. S2S callers and API keys are not
//! JWT principals: they authenticate per request through their own schemes.

use crate::session::TokenType;

/// The kinds of principal the platform authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    /// A person using the product (staff).
    Staff,
    /// An external person on a web portal (D-576).
    Portal,
    /// An AI agent acting under its own identity.
    Agent,
    /// Another service, signed per request (S2S HMAC).
    S2s,
    /// A script holding an API key.
    ApiKey,
}

/// The session token type a principal kind carries; `None` for the kinds
/// that do not hold a session JWT.
pub fn token_type_for(kind: PrincipalKind) -> Option<TokenType> {
    match kind {
        PrincipalKind::Staff => Some(TokenType::Session),
        PrincipalKind::Portal => Some(TokenType::PortalSession),
        PrincipalKind::Agent => Some(TokenType::AgentSession),
        PrincipalKind::S2s | PrincipalKind::ApiKey => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{create_token, validate_session_token, validate_typed_session_token};
    use crate::session::SessionClaims;
    use attome_config::KeyRing;
    use attome_types::AppError;
    use uuid::Uuid;

    fn token(typ: TokenType, ring: &KeyRing) -> String {
        let now = chrono::Utc::now().timestamp();
        let claims = SessionClaims {
            sub: Uuid::now_v7(),
            iat: now,
            exp: now + 900,
            jti: Uuid::now_v7(),
            epoch: 0,
            iss: "attome-test".to_string(),
            aud: "attome-test".to_string(),
            typ,
        };
        create_token(&claims, ring).unwrap()
    }

    #[test]
    fn every_jwt_principal_has_its_own_token_type() {
        let types: Vec<TokenType> = [
            PrincipalKind::Staff,
            PrincipalKind::Portal,
            PrincipalKind::Agent,
        ]
        .into_iter()
        .filter_map(token_type_for)
        .collect();
        assert_eq!(
            types,
            [
                TokenType::Session,
                TokenType::PortalSession,
                TokenType::AgentSession
            ]
        );
        assert_eq!(token_type_for(PrincipalKind::S2s), None);
        assert_eq!(token_type_for(PrincipalKind::ApiKey), None);
    }

    #[test]
    fn agent_token_is_refused_by_staff_validation() {
        let ring = KeyRing::single("test-secret".to_string());
        let agent = token(TokenType::AgentSession, &ring);
        assert!(matches!(
            validate_session_token(&agent, &ring, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
        assert!(
            validate_typed_session_token(
                &agent,
                &ring,
                TokenType::PortalSession,
                "attome-test",
                "attome-test"
            )
            .is_err()
        );
        assert!(
            validate_typed_session_token(
                &agent,
                &ring,
                TokenType::AgentSession,
                "attome-test",
                "attome-test"
            )
            .is_ok()
        );
    }

    #[test]
    fn portal_token_is_refused_by_staff_and_agent_validation() {
        let ring = KeyRing::single("test-secret".to_string());
        let portal = token(TokenType::PortalSession, &ring);
        assert!(matches!(
            validate_session_token(&portal, &ring, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
        assert!(
            validate_typed_session_token(
                &portal,
                &ring,
                TokenType::AgentSession,
                "attome-test",
                "attome-test"
            )
            .is_err()
        );
    }

    #[test]
    fn staff_token_is_refused_as_agent() {
        let ring = KeyRing::single("test-secret".to_string());
        let staff = token(TokenType::Session, &ring);
        assert!(
            validate_typed_session_token(
                &staff,
                &ring,
                TokenType::AgentSession,
                "attome-test",
                "attome-test"
            )
            .is_err()
        );
    }
}
