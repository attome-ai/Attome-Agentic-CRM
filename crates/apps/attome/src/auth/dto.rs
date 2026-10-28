//! Request/response DTOs for the auth routes (`super::local`, `super::google`,
//! `super::oidc`, `super::session`). No business logic here —
//! see each handler module for the actual behavior these types carry.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct GoogleAuthRequest {
    pub credential: String,
}

impl std::fmt::Debug for GoogleAuthRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleAuthRequest").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    /// P-registration-gating Phase 2 (D-128) — required (and validated) only
    /// when `auth.registration_mode == "invite"`; ignored in `"public"` mode,
    /// unreachable in `"disabled"` mode (the handler rejects before parsing
    /// gets this far in spirit, though the body is still parsed first).
    #[serde(default)]
    pub invitation_token: Option<String>,
}

impl std::fmt::Debug for RegisterRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterRequest").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    /// Q20-T2: a CAPTCHA token, needed only while the caller's address is
    /// challenged for a password spray (a `429` says so).
    #[serde(default)]
    pub captcha_token: Option<String>,
}

impl std::fmt::Debug for LoginRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginRequest").finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
}

impl std::fmt::Debug for AuthResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthResponse").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct ResetRequestBody {
    pub email: String,
}

impl std::fmt::Debug for ResetRequestBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetRequestBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct ResetConfirmBody {
    pub token: String,
    pub new_password: String,
}

impl std::fmt::Debug for ResetConfirmBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResetConfirmBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct VerifyEmailConfirmBody {
    pub token: String,
}

impl std::fmt::Debug for VerifyEmailConfirmBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyEmailConfirmBody")
            .finish_non_exhaustive()
    }
}

/// BAU-25 (finding BAU-F20) — the provider's redirect back. Every field is
/// optional at the wire level: RFC 6749 §4.1.2.1 says a provider that refuses
/// or a user who cancels comes back with `error` (and `error_description`)
/// and **no** `code`. Requiring `code` made axum answer a bare 400 before any
/// handler ran, so the browser stopped on a blank page instead of the login
/// error the route already knows how to render. A callback missing `state`
/// parses too and simply fails its binding check.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct OidcCallbackQuery {
    /// The authorization code to exchange. `None` on an `error` redirect.
    #[serde(default)]
    pub code: Option<String>,
    /// The `state` the provider echoes back — the flow's single-use id.
    #[serde(default)]
    pub state: Option<String>,
    /// The provider's error code (`access_denied`, `consent_required`, …).
    /// Logged as the reason; never returned to the client beyond the generic
    /// error page every other failure already gets.
    #[serde(default)]
    pub error: Option<String>,
}

impl std::fmt::Debug for OidcCallbackQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcCallbackQuery").finish_non_exhaustive()
    }
}

/// P-federation-linking-policy §4.3(a) — same wire shape as
/// `OidcCallbackQuery`, kept as its own type since the two routes are
/// independent (one bypass-listed, one not) even though the query params
/// happen to match. BAU-25 applies to it identically.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct IdentityLinkOidcCallbackQuery {
    /// The authorization code to exchange. `None` on an `error` redirect.
    #[serde(default)]
    pub code: Option<String>,
    /// The `state` the provider echoes back: the flow's single-use id.
    #[serde(default)]
    pub state: Option<String>,
    /// The provider's error code (`access_denied`, `consent_required`, ...).
    #[serde(default)]
    pub error: Option<String>,
}

impl std::fmt::Debug for IdentityLinkOidcCallbackQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityLinkOidcCallbackQuery")
            .finish_non_exhaustive()
    }
}

/// Base-auth hardening 2.1c (D-510 rule 5) — the step-up challenge a federated
/// start route continues. The operation and provider come from the path, the
/// user and family from the session token.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StepUpFederatedStartQuery {
    /// The step-up challenge to continue at the provider.
    pub challenge_id: String,
}

impl std::fmt::Debug for StepUpFederatedStartQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepUpFederatedStartQuery")
            .finish_non_exhaustive()
    }
}

/// Base-auth hardening 2.1c — the IdP's redirect back to the federated
/// step-up callback; same wire shape as `OidcCallbackQuery`, BAU-25 included.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StepUpOidcCallbackQuery {
    /// The authorization code to exchange. `None` on an `error` redirect.
    #[serde(default)]
    pub code: Option<String>,
    /// The `state` the provider echoes back: the flow's single-use id.
    #[serde(default)]
    pub state: Option<String>,
    /// The provider's error code (`access_denied`, `consent_required`, ...).
    #[serde(default)]
    pub error: Option<String>,
}

impl std::fmt::Debug for StepUpOidcCallbackQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StepUpOidcCallbackQuery")
            .finish_non_exhaustive()
    }
}

// ── MFA (P2.8 step 7, D-069) ────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MfaChallengeResponse {
    /// `"required"` (confirmed enrollment — call `/mfa/verify` or
    /// `/mfa/recovery`) or `"enrollment_required"` (`mfa_policy = "required"`,
    /// not yet enrolled — call `/mfa/pending-enroll` then `/mfa/pending-confirm`).
    pub mfa: String,
    pub pending_token: String,
}

impl std::fmt::Debug for MfaChallengeResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaChallengeResponse")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct MfaVerifyBody {
    pub pending_token: String,
    pub code: String,
    /// Q5-T4: remember this browser so later sign-ins from it skip the
    /// second factor, for as long as the person's policy allows (never for
    /// an administrator). Ignored by the recovery-code route.
    #[serde(default)]
    pub remember: bool,
}

impl std::fmt::Debug for MfaVerifyBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaVerifyBody").finish_non_exhaustive()
    }
}

#[derive(Deserialize, ToSchema)]
pub struct MfaPendingEnrollBody {
    pub pending_token: String,
}

impl std::fmt::Debug for MfaPendingEnrollBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaPendingEnrollBody")
            .finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub struct MfaEnrollResponse {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

impl std::fmt::Debug for MfaEnrollResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaEnrollResponse").finish_non_exhaustive()
    }
}

#[derive(Serialize)]
pub struct MfaPendingConfirmResponse {
    pub user_id: Uuid,
    pub recovery_codes: Vec<String>,
}

impl std::fmt::Debug for MfaPendingConfirmResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MfaPendingConfirmResponse")
            .finish_non_exhaustive()
    }
}

/// P2.8 step 5 — public provider directory for the Angular login page's
/// button list. Only `key`/`display_name` leave the process; `issuer`/
/// `client_id`/`client_secret`/`scopes`/`email_claim` are never serialized
/// here (`client_secret` in particular must never reach a GET response).
#[derive(Serialize, ToSchema)]
pub struct OidcProviderInfo {
    pub key: String,
    pub display_name: String,
}

impl std::fmt::Debug for OidcProviderInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcProviderInfo").finish_non_exhaustive()
    }
}

/// P-frontend-baseline step 5 (D-071/D-073) — closes the config-debt item:
/// the Google OAuth client id (`config.auth.oauth_google_client_id`, already
/// the value `google_login` verifies the ID token's audience against) is
/// served from here instead of being duplicated as a hardcoded literal in
/// Angular's `environment.ts`. Same "public directory, never a secret" shape
/// as `OidcProviderInfo` — a client id is not sensitive (it's visible in any
/// browser's network tab once the Sign-In button loads), only
/// `oauth_google_client_secret` must never leave this struct.
#[derive(Serialize, ToSchema)]
pub struct GoogleConfigInfo {
    /// `None` when Google sign-in isn't configured for this deployment — the
    /// login page renders no Google button, same as an empty OIDC directory.
    pub client_id: Option<String>,
}

impl std::fmt::Debug for GoogleConfigInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleConfigInfo").finish_non_exhaustive()
    }
}

/// P-registration-gating (D-128) — public directory-style config, same
/// "harmless because it's not a secret" shape as `GoogleConfigInfo`/
/// `OidcProviderInfo`: the Angular login page fetches this to decide whether
/// to render the sign-up form/link at all, instead of showing it and letting
/// every submission 403.
#[derive(Serialize, ToSchema)]
pub struct RegistrationConfigInfo {
    /// One of `"public"`/`"invite"`/`"disabled"` — see `AuthSection::registration_mode`.
    pub mode: String,
}

impl std::fmt::Debug for RegistrationConfigInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrationConfigInfo")
            .finish_non_exhaustive()
    }
}

/// Uniform ack — reset-request and reset-confirm both use this shape so the
/// enumeration-safe reset-request response is indistinguishable regardless
/// of whether the email was found.
#[derive(Serialize)]
pub struct Ack {
    pub ok: bool,
}

impl std::fmt::Debug for Ack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ack").finish_non_exhaustive()
    }
}

/// P-session-refresh-hardening (D-129) — `GET /api/v1/auth/session`'s
/// response shape; see `session_info`.
#[derive(Serialize, ToSchema)]
pub struct SessionInfo {
    pub user_id: Uuid,
    pub email: String,
}

impl std::fmt::Debug for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionInfo").finish_non_exhaustive()
    }
}

/// P-federation-linking-policy §4.3(a) UI support — `GET
/// /api/v1/auth/identity-links`'s response shape; see `identity_links`. One
/// entry per `user_identity` row linked to the caller, plus (since this
/// entry extends §4.3(a) to Google) at most one synthetic `provider_key:
/// "google"` entry when `user_account.google_sub` is set. Never includes
/// `provider_sub` — the IdP-issued subject identifier is an internal
/// correlation key, not something the UI needs to render a "linked" badge.
/// `linked_at` is `None` only for that synthetic Google entry — Google has no
/// per-link timestamp column (see `list_identities_for_user`'s doc comment).
#[derive(Serialize, ToSchema)]
pub struct IdentityLinkInfo {
    pub provider_key: String,
    pub email: String,
    pub linked_at: Option<DateTime<Utc>>,
}

impl std::fmt::Debug for IdentityLinkInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityLinkInfo").finish_non_exhaustive()
    }
}

/// Q1-T10: what sign-out answers. `redirect` is set when the session came
/// from an OIDC provider with an end-session endpoint: the browser goes
/// there so the provider ends its session too, and comes back to the app.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogoutResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
}

/// Q1-T10: a provider's back-channel logout request
/// (`application/x-www-form-urlencoded`).
#[derive(Deserialize, ToSchema)]
pub struct BackchannelLogoutForm {
    /// The signed logout token.
    pub logout_token: String,
}

impl std::fmt::Debug for BackchannelLogoutForm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackchannelLogoutForm")
            .finish_non_exhaustive()
    }
}

/// Q1-T6: the email typed on the sign-in page.
#[derive(Deserialize, ToSchema)]
pub struct OidcDiscoverRequest {
    pub email: String,
}

impl std::fmt::Debug for OidcDiscoverRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcDiscoverRequest")
            .finish_non_exhaustive()
    }
}

/// Q1-T6: the provider that email's verified domain signs in through, or
/// `null`. The same answer shape whether or not anyone has that email.
#[derive(Debug, Serialize, ToSchema)]
pub struct OidcDiscoverResponse {
    pub provider: Option<String>,
}
