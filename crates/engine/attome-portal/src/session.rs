//! Portal session tokens and cookies (D-573, D-576 item 3).
//!
//! A portal access token is a `attome_auth` session-shaped JWT with
//! `typ = PortalSession`, `sub` = the `webportal_user` id,
//! `aud = "portal:{webportal_id}"`, and `sid` = its refresh family. Staff
//! validation refuses any type but `Session`, and the portal refuses any
//! type but `PortalSession` and any audience but its own, so a token can
//! never cross from one audience to another in either direction.
//!
//! Cookies are named per portal and scoped to the portal's path. Paths only
//! limit where the browser *sends* a cookie; the type and audience checks are
//! the boundary.

use attome_auth::jwt::{create_session_token, validate_typed_session_token};
use attome_auth::session::{SessionClaims, SessionId, TokenType};
use attome_config::KeyRing;
use attome_types::AppError;
use uuid::Uuid;

/// R10 defaults, shorter than staff sessions.
pub const ACCESS_TTL_SECS: i64 = 10 * 60;
pub const REFRESH_IDLE_SECS: i64 = 24 * 60 * 60;
pub const REFRESH_ABSOLUTE_SECS: i64 = 14 * 24 * 60 * 60;

/// The `aud` every token for this portal carries.
pub fn audience(webportal_id: Uuid) -> String {
    format!("portal:{webportal_id}")
}

pub struct CookieNames {
    pub session: String,
    pub refresh: String,
}

impl std::fmt::Debug for CookieNames {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieNames").finish_non_exhaustive()
    }
}

/// `__Secure-wp_{keyword}_session` / `_refresh`. `__Host-` is impossible here
/// because it requires `Path=/`. Without `secure` (plain-http local dev) the
/// prefix is dropped, since browsers discard a `__Secure-` cookie set without
/// `Secure`.
pub fn cookie_names(keyword: &str, secure: bool) -> CookieNames {
    let prefix = if secure { "__Secure-" } else { "" };
    CookieNames {
        session: format!("{prefix}wp_{keyword}_session"),
        refresh: format!("{prefix}wp_{keyword}_refresh"),
    }
}

/// The session cookie is sent to the whole portal.
pub fn session_cookie_path(keyword: &str) -> String {
    format!("/{keyword}/")
}

/// The refresh cookie only to the portal's auth routes, like staff's
/// `Path=/api/v1/auth`.
pub fn refresh_cookie_path(keyword: &str) -> String {
    format!("/{keyword}/api/v1/auth/")
}

/// Mints an access token for `user_id` on `webportal_id`, stamped with the
/// credential's current `auth_epoch` and naming refresh family `family_id`.
pub fn mint_access(
    ring: &KeyRing,
    issuer: &str,
    webportal_id: Uuid,
    user_id: Uuid,
    epoch: i32,
    family_id: Uuid,
) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp();
    let claims = SessionClaims {
        sub: user_id,
        iat: now,
        exp: now + ACCESS_TTL_SECS,
        jti: Uuid::now_v7(),
        epoch,
        iss: issuer.to_owned(),
        aud: audience(webportal_id),
        typ: TokenType::PortalSession,
    };
    create_session_token(&claims, family_id, ring)
}

/// Validates a presented access token for `webportal_id`: signature, expiry,
/// `typ = PortalSession`, exact issuer and audience. The caller still checks
/// everything the claims point at (epoch, family, account and portal state).
pub fn validate_access(
    token: &str,
    ring: &KeyRing,
    issuer: &str,
    webportal_id: Uuid,
) -> Result<(SessionClaims, SessionId), AppError> {
    validate_typed_session_token(
        token,
        ring,
        TokenType::PortalSession,
        issuer,
        &audience(webportal_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring() -> KeyRing {
        KeyRing::single("portal-session-test-secret".into())
    }

    #[test]
    fn a_token_is_valid_only_for_its_own_portal() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let token = mint_access(&ring(), "iss", a, Uuid::now_v7(), 3, Uuid::now_v7()).unwrap();
        let (claims, _) = validate_access(&token, &ring(), "iss", a).unwrap();
        assert_eq!(claims.epoch, 3);
        assert!(validate_access(&token, &ring(), "iss", b).is_err());
        assert!(validate_access(&token, &ring(), "other", a).is_err());
    }

    #[test]
    fn cookie_names_follow_the_secure_flag() {
        let secure = cookie_names("customers", true);
        assert_eq!(secure.session, "__Secure-wp_customers_session");
        assert_eq!(secure.refresh, "__Secure-wp_customers_refresh");
        assert_eq!(
            cookie_names("customers", false).session,
            "wp_customers_session"
        );
        assert_eq!(session_cookie_path("customers"), "/customers/");
    }
}
