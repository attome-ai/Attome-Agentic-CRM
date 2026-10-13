use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// P-key-rotation-and-jwt (c) — the `typ` claim every JWT this platform
/// mints carries, so a token minted for one purpose can never be accepted for
/// another even though every JWT here is HS256-signed with the same ring
/// (audit finding #21: previously only `SessionClaims` vs. `mfa::PendingClaims`'s
/// claims *shape* distinguished them, not an explicit discriminator). This
/// replaces `mfa`'s own `PendingPurpose` — a pending-MFA token's purpose IS
/// its `typ`, so there is exactly one discriminator to check, not two that
/// could drift out of sync (plan §4: "do not add a second parallel
/// discriminator").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Session,
    MfaPendingLogin,
    MfaPendingEnroll,
    /// A session of an external principal on a web portal (D-576). Its `aud`
    /// names the portal. `validate_session_token` refuses it (it accepts only
    /// `Session`), so it can never authenticate a staff route; the portal's
    /// own authn uses [`crate::jwt::validate_typed_session_token`].
    PortalSession,
}

/// JWT claims embedded in the `session_token` HttpOnly cookie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: Uuid, // user UUID
    pub iat: i64,  // issued at (unix timestamp)
    pub exp: i64,  // expiry (unix timestamp)
    /// Unique per-token id (Plan 1.6a). Not a secret — carried in the JWT
    /// payload same as `sub`/`exp` — but lets `revocation::revoke` denylist
    /// exactly this token in Redis without needing to touch `sub`'s other
    /// live sessions (multi-device logins stay independent).
    pub jti: Uuid,
    /// The account's `user_account.auth_epoch` value at the moment this
    /// token was issued (D-113 Phase 2, wired D-121; P-session-refresh-
    /// hardening, D-129). `authn` rejects a token whose stamped epoch has
    /// fallen behind (or diverges from) the account's current one via
    /// `attome_auth::epoch::check` — sub-second revocation of a still-live
    /// access token on disable/password-reset-confirm, not just at its
    /// natural `exp`, and without a server-side session table.
    /// `#[serde(default)]` so a token issued by a pre-this-change binary
    /// (already in a browser's cookie jar at deploy time) still deserializes
    /// instead of logging every user out at deploy — this is a one-time
    /// deploy-continuity default, not an ongoing mixed-version compatibility
    /// contract (D-120: this subsystem is allowed to break compatibility
    /// outright; this default exists only because there is no operator step
    /// that could "migrate" an already-issued JWT sitting in a browser). A
    /// defaulted-in token reads as epoch 0, which is never less than or
    /// greater than a fresh account's epoch (also 0) — for any account
    /// bumped at least once, epoch 0 already fails the equality check like
    /// any other stale token.
    #[serde(default)]
    pub epoch: i32,
    /// P-key-rotation-and-jwt (c). Required since BAU-12c closed the
    /// transition window: a token without `iss`/`aud` fails to decode, and
    /// `jwt::validate_token` requires both to equal the configured values.
    pub iss: String,
    pub aud: String,
    /// Required (BAU-12a): a token without `typ` fails to decode.
    pub typ: TokenType,
}

/// The refresh-token family a session token belongs to: the validated token's
/// server-minted `sid` claim (D-510 rule 2, attome-auth hardening 2.1a).
///
/// The authn middleware attaches it to a cookie-session request next to
/// [`SessionClaims`]. It is absent for a token minted before 2.1a and never
/// present for an API-key or S2S request, which have no refresh family. It is
/// the only way to find a session's authentication context
/// (`refresh::session_context`); nothing reads that context from claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(pub Uuid);
