/// Compile-time exact bypass list — paths that skip AuthnLayer and AuthzLayer.
/// New public endpoints MUST be explicitly added here; never make this runtime config.
pub const EXACT_BYPASS_PATHS: &[&str] = &[
    // B13-T5: the published brand, for the sign-in page; no user data.
    "/api/v1/branding/public",
    "/api/v1/auth/register",
    "/api/v1/auth/register/config",
    "/api/v1/auth/login",
    "/api/v1/auth/google",
    "/api/v1/auth/google/config",
    "/api/v1/auth/logout",
    "/api/v1/auth/refresh",
    // P-account-lifecycle: all three are called by someone who, by
    // definition, has no valid session yet (forgot their password, or is
    // confirming an emailed link before ever logging in).
    "/api/v1/auth/reset-request",
    "/api/v1/auth/reset-confirm",
    "/api/v1/auth/verify-email/confirm",
    // P2.8 step 7 (D-069): all four are reached by a caller who, by
    // definition, has no session cookie yet — password login only got as
    // far as a short-lived `pending_token` (distinct claims shape from
    // `SessionClaims`, `attome_auth::mfa`), never a real session. The token
    // itself, validated server-side inside each handler, IS the auth —
    // same reasoning as `/reset-confirm` and the OIDC subtree below. These
    // stay exact matches so no protected MFA self-service child can inherit
    // public status.
    "/api/v1/auth/mfa/verify-recovery",
    "/api/v1/auth/mfa/verify",
    "/api/v1/auth/mfa/pending-enroll",
    "/api/v1/auth/mfa/pending-confirm",
    "/health",
    "/health/ready",
    // U9-T1: the startup probe, same unauthenticated convention.
    "/health/startup",
    // P-deployment-preflight follow-up (deployment manifest): read-only
    // version/schema info, same unauthenticated diagnostic convention as the
    // /health paths above — never customer data or secrets.
    "/version",
    // Content Management (D-367): the platform's first public,
    // anonymous-facing content route — a published page's custom URL is
    // resolved client-side (Angular host app) against this endpoint. Its
    // handler (`xrm_server::content_public`) does its own manual
    // license/publish check and returns an identical 404 whether the page
    // doesn't exist, isn't published, or the deployment isn't licensed for
    // this module, so bypassing authn here reveals nothing about any of
    // those states.
    "/api/v1/content/view",
    // M37 Phase 2 (D-452): the "was this useful" vote — public-safe for the
    // same reason `/content/view` above is: an anonymous visitor reading a
    // published page must be able to vote on it without a session, and the
    // handler (`xrm_server::content_public::vote_on_page`) does its own
    // manual license/publish check plus a per-(page, address) rate limit
    // (`attome_cache::rate_limit`), so bypassing authn here reveals nothing
    // and is not an open write with no cost to abuse.
    "/api/v1/content/vote",
    // Work Intake self-service portal (M70, D-423): public offering
    // browsing and request-status-by-token lookup. Its handlers
    // (`xrm_server::service_public`) do their own manual license check and
    // return a uniform response (empty list / identical 404) whether the
    // deployment isn't licensed, the token is malformed, unknown, or wrong
    // — the same discipline `/api/v1/content/view` above already documents.
    "/api/v1/service-portal/offerings",
    "/api/v1/service-portal/status",
    // Consent Management (M24, D-428): public, anonymous consent-capture
    // entry point for a customer's own web forms. Its handler
    // (`xrm_compliance::consent_admin::capture_consent`) validates its own
    // input and writes an append-only `xrm_audit_consent` row — no customer data
    // is read back, so there is nothing here for an anonymous caller to
    // enumerate (unlike `/api/v1/content/view`'s "identical 404" concern).
    "/api/v1/consents/capture",
    // Omnichannel web chat widget (M53 Phase 1, D-474): public, anonymous
    // message-send and reply-poll routes. Same "own manual license check,
    // uniform response regardless of the reason for a miss" discipline as
    // `/api/v1/content/view` above; its handler (`server::omnichannel`) is
    // additionally rate-limited per caller IP and per resumed session
    // (`attome_cache::rate_limit`), the same defense `/api/v1/content/vote`
    // already takes for its own anonymous write.
    "/api/v1/omnichannel/webchat/message",
    "/api/v1/omnichannel/webchat/poll",
];

/// M59 Phase 1 (`xrm-integration`, D-425) — the inbound connector webhook,
/// `/api/v1/integrations/{system}/webhook`, needs a dynamic `{system}`
/// segment (a UUID path param), same reason the OIDC prefix below is a
/// subtree bypass rather than an exact entry. Its handler
/// (`xrm_integration::webhook::handle_webhook`) performs its own per-system
/// HMAC signature verification against the target system's credential —
/// nothing else is mounted under this prefix today (verified by
/// `IntegrationModel::routes()`, `xrm-integration/src/model.rs`).
///
/// C-25: this used to be a blanket `starts_with` subtree prefix in
/// `BYPASS_SUBTREE_PREFIXES`, same shape as the OIDC entry — but
/// unlike it, this prefix has no fixed suffix (`/login`, `/callback`): ANY path under `/api/v1/integrations/{system}/` bypassed authn,
/// not just `/webhook`. That made the "never let a bypass entry prefix a
/// protected route" invariant (guidelines §3) hold only by the *current*
/// absence of a sibling route, not by construction — a future admin/config
/// surface mounted at `/api/v1/integrations/{system}/config` would have been
/// silently swept into the public bypass the moment someone added it, with
/// no test able to catch the regression because the blanket prefix would
/// already match it. This function is the "segment-shape match"
/// replacement: exactly one dynamic segment, then the literal `webhook`, and
/// nothing after — so it holds by construction instead, and
/// `integrations_sibling_route_is_not_swept_into_bypass` pins the regression
/// this shape exists to prevent.
fn is_integrations_webhook_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/api/v1/integrations/") else {
        return false;
    };
    let mut segments = rest.split('/');
    let system = segments.next().unwrap_or("");
    let is_webhook = segments.next() == Some("webhook");
    let no_trailing_segment = segments.next().is_none();
    !system.is_empty() && is_webhook && no_trailing_segment
}

/// The only public route families with intentionally dynamic child segments.
/// Every entry ends in `/`, so `starts_with` cannot match a sibling such as
/// `/api/v1/auth/oidc-admin`. (The integrations webhook USED to be a third
/// entry here too — see [`is_integrations_webhook_path`]'s doc comment for
/// why it is a segment-shape match instead, not a member of this list.)
///
/// `/api/v1/auth/identity-link-callback/` (P-federation-linking-policy
/// §4.3(a)) is deliberately a SEPARATE literal prefix from
/// `/api/v1/auth/identity-link/` — the latter holds the *start* routes for
/// self-service federated-identity linking, which MUST stay protected
/// (require a live session); only the *callback* half is public, because a
/// `SameSite=Strict` session cookie (`attome_auth::cookie::build`) never
/// survives the cross-site redirect back from the IdP, so the callback
/// can't ride `Extension<SessionClaims>` at all. Sharing one prefix between
/// start and callback would silently bypass the start route too — the exact
/// mistake this comment (and `identity_link_prefix_never_bypasses_the_
/// protected_start_route` below) exists to prevent.
///
/// `/api/v1/auth/step-up-callback/` (attome-auth hardening 2.1c, D-510 rule 5)
/// follows the same split for federated step-up: the start routes under
/// `/api/v1/auth/step-up/` stay protected, and only the IdP callback is
/// public. The callback binds to the starting browser and to server-side
/// single-use state, never to the absent session cookie.
pub const BYPASS_SUBTREE_PREFIXES: &[&str] = &[
    "/api/v1/auth/oidc/",
    "/api/v1/auth/identity-link-callback/",
    "/api/v1/auth/step-up-callback/",
];

pub fn is_bypass(path: &str) -> bool {
    EXACT_BYPASS_PATHS.contains(&path)
        || BYPASS_SUBTREE_PREFIXES
            .iter()
            .any(|prefix| path.starts_with(prefix))
        || is_integrations_webhook_path(path)
}

/// Paths that skip authn/authz (they are in `EXACT_BYPASS_PATHS` above) but
/// must STILL pass the CSRF check (`middleware::csrf::csrf_protect`).
///
/// `csrf_protect`'s early-out used to be a bare `is_bypass(path)`, justified
/// as "pre-auth by definition — no session exists yet for a cross-site
/// request to ride along with". That reasoning holds for `/login`,
/// `/register`, `/reset-confirm`, the MFA login-time family, `/health*`, and
/// the OIDC subtree — none of them act on a live session cookie. It is
/// simply false for `/logout`, which by definition requires one: the whole
/// point of the route is to destroy the session the browser is carrying. A
/// bare `is_bypass` therefore let any attacker-controlled page force-log-out
/// an authenticated user with a cross-site `POST /api/v1/auth/logout`
/// (`crates/server/src/auth/mod.rs` mounts it as `post(session::logout)`).
///
/// Logout stays in `EXACT_BYPASS_PATHS` deliberately — it must remain
/// callable with an already-expired/absent cookie without a 401, which is
/// what the authn bypass buys. Only the CSRF exemption is withdrawn. A
/// legitimate logout from the SPA sends `Sec-Fetch-Site: same-origin` (and
/// an allow-listed `Origin`), so it passes `should_reject` unchanged; a
/// cross-site one no longer does. A logout request carrying no session
/// cookie at all still short-circuits in `csrf_protect` before any header
/// parsing, so the "cookie already gone" case is unaffected.
///
/// `/api/v1/auth/refresh` (D-305) is here for the same reason and one more.
/// Like logout it acts on a live browser credential — `session::refresh_session`
/// redeems the refresh cookie — so the "pre-auth by definition" argument is
/// false for it too. What makes it worse than logout is rotation: D-129's
/// `refresh::redeem` rotates on every use and revokes the whole family on
/// reuse detection, so a cross-site forced refresh does not merely log the
/// victim out, it burns the token their real tab is still holding and can trip
/// reuse detection when that tab later redeems the token it already has.
///
/// Withdrawing this exemption only matters because `csrf_protect` also counts
/// the refresh cookie as a credential — the session cookie's `Max-Age` is the
/// access token's own lifetime, so by the time the SPA calls `/refresh` it has
/// usually expired out of the jar and a session-cookie-only check would find
/// nothing to protect. See `middleware::csrf`'s `carries_cookie_credential`.
pub const CSRF_ENFORCED_BYPASS_PATHS: &[&str] = &["/api/v1/auth/logout", "/api/v1/auth/refresh"];

/// True when `path` skips authn/authz AND is exempt from the CSRF check.
/// This — not `is_bypass` — is what `csrf_protect` must branch on.
pub(crate) fn is_csrf_exempt(path: &str) -> bool {
    is_bypass(path) && !CSRF_ENFORCED_BYPASS_PATHS.contains(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_bypass_paths_match() {
        assert!(is_bypass("/api/v1/auth/login"));
        assert!(is_bypass("/health"));
        assert!(is_bypass("/health/ready"));
        assert!(is_bypass("/health/startup"));
        assert!(is_bypass("/version"));
        // U9-T2: the dependency report is for administrators.
        assert!(!is_bypass("/health/dependencies"));
    }

    #[test]
    fn a_protected_path_does_not_match() {
        assert!(!is_bypass("/api/v1/admin/security/grants"));
        assert!(!is_bypass("/api/v1/api_key"));
    }

    #[test]
    fn content_view_is_bypassed_but_its_admin_surface_is_not() {
        assert!(is_bypass("/api/v1/content/view"));
        assert!(is_csrf_exempt("/api/v1/content/view"));
        // Regression guard: the public view route must never accidentally
        // sweep the admin CRUD surface (a distinct, non-prefix path) into
        // bypass with it.
        assert!(!is_bypass("/api/v1/admin/content/pages"));
    }

    #[test]
    fn service_portal_routes_are_bypassed_but_the_catalog_admin_surface_is_not() {
        assert!(is_bypass("/api/v1/service-portal/offerings"));
        assert!(is_bypass("/api/v1/service-portal/status"));
        assert!(is_csrf_exempt("/api/v1/service-portal/offerings"));
        assert!(is_csrf_exempt("/api/v1/service-portal/status"));
        // Regression guard: the public portal routes must never accidentally
        // sweep the authenticated catalog/create-work-request surface into
        // bypass with them.
        assert!(!is_bypass("/api/v1/service-offering/active"));
        assert!(!is_bypass(
            "/api/v1/service-offering/00000000-0000-0000-0000-000000000000/create-work-request"
        ));
    }

    #[test]
    fn webchat_routes_are_bypassed_and_csrf_exempt() {
        assert!(is_bypass("/api/v1/omnichannel/webchat/message"));
        assert!(is_bypass("/api/v1/omnichannel/webchat/poll"));
        assert!(is_csrf_exempt("/api/v1/omnichannel/webchat/message"));
        assert!(is_csrf_exempt("/api/v1/omnichannel/webchat/poll"));
        // Regression guard: no other omnichannel surface (a future admin/
        // metrics route) may ever be swept into bypass by a prefix match with
        // these two exact entries.
        assert!(!is_bypass("/api/v1/admin/omnichannel/metrics"));
        assert!(!is_bypass("/api/v1/omnichannel/webchat/message/anything"));
    }

    #[test]
    fn consent_capture_is_bypassed_but_the_withdraw_and_generic_entity_surface_are_not() {
        assert!(is_bypass("/api/v1/consents/capture"));
        assert!(is_csrf_exempt("/api/v1/consents/capture"));
        // Regression guard: the public capture route must never accidentally
        // sweep the authenticated withdraw endpoint or the generic
        // /api/v1/xrm_audit_consent entity CRUD route into bypass with it.
        assert!(!is_bypass("/api/v1/consents/withdraw"));
        assert!(!is_bypass("/api/v1/xrm_audit_consent"));
    }

    #[test]
    fn public_config_routes_are_explicit() {
        assert!(is_bypass("/api/v1/auth/register/config"));
        assert!(is_bypass("/api/v1/auth/google/config"));
    }

    #[test]
    fn oidc_login_and_callback_subpaths_match_the_provider_agnostic_prefix() {
        assert!(is_bypass("/api/v1/auth/oidc/entra/login"));
        assert!(is_bypass("/api/v1/auth/oidc/entra/callback"));
    }

    #[test]
    fn exact_paths_never_bypass_lookalike_or_child_routes() {
        assert!(!is_bypass("/api/v1/auth/login-admin"));
        assert!(!is_bypass("/api/v1/auth/login/anything"));
        assert!(!is_bypass("/api/v1/auth/register-admin"));
        assert!(!is_bypass("/api/v1/auth/mfa/verify-admin"));
        assert!(!is_bypass("/health/anything"));
        assert!(!is_bypass("/health/dependencies/anything"));
        assert!(!is_bypass("/version/anything"));
    }

    #[test]
    fn subtree_prefixes_require_the_slash_boundary() {
        assert!(!is_bypass("/api/v1/auth/oidc-admin"));
    }

    #[test]
    fn mfa_login_time_paths_are_bypassed() {
        assert!(is_bypass("/api/v1/auth/mfa/verify"));
        assert!(is_bypass("/api/v1/auth/mfa/verify-recovery"));
        assert!(is_bypass("/api/v1/auth/mfa/pending-enroll"));
        assert!(is_bypass("/api/v1/auth/mfa/pending-confirm"));
    }

    #[test]
    fn mfa_self_service_paths_are_not_bypassed() {
        // Regression guard for D-069's protected MFA self-service family.
        assert!(!is_bypass("/api/v1/auth/mfa/enroll"));
        assert!(!is_bypass("/api/v1/auth/mfa/confirm"));
        assert!(!is_bypass("/api/v1/auth/mfa/disable"));
        assert!(!is_bypass("/api/v1/auth/mfa/recovery-codes/regenerate"));
    }

    #[test]
    fn removed_saml_routes_are_not_bypassed() {
        // SAML was removed (OIDC is the sole federation protocol); its old
        // public paths must not linger in the bypass list.
        assert!(!is_bypass("/api/v1/auth/saml/okta/login"));
        assert!(!is_bypass("/api/v1/auth/saml/okta/acs"));
    }

    #[test]
    fn integration_webhook_subpaths_are_bypassed() {
        assert!(is_bypass(
            "/api/v1/integrations/8f14e45f-ceea-4d5b-8f5e-4c4b4c4b4c4b/webhook"
        ));
        assert!(is_csrf_exempt(
            "/api/v1/integrations/8f14e45f-ceea-4d5b-8f5e-4c4b4c4b4c4b/webhook"
        ));
    }

    #[test]
    fn integration_webhook_prefix_requires_the_slash_boundary() {
        assert!(!is_bypass("/api/v1/integrations-admin"));
    }

    #[test]
    fn integrations_sibling_route_is_not_swept_into_bypass() {
        // Regression guard for the "segment-shape match" fix (C-25): the old
        // implementation was a blanket `starts_with("/api/v1/integrations/")`
        // subtree prefix, so ANY path under one system's segment — not just
        // `/webhook` — bypassed authn. A hypothetical sibling admin/config
        // surface at the same `{system}` segment must stay protected.
        assert!(!is_bypass(
            "/api/v1/integrations/8f14e45f-ceea-4d5b-8f5e-4c4b4c4b4c4b/config"
        ));
        assert!(!is_bypass(
            "/api/v1/integrations/8f14e45f-ceea-4d5b-8f5e-4c4b4c4b4c4b"
        ));
        // No trailing segment after `webhook` either.
        assert!(!is_bypass(
            "/api/v1/integrations/8f14e45f-ceea-4d5b-8f5e-4c4b4c4b4c4b/webhook/extra"
        ));
        // The bare prefix, and an empty `{system}` segment, must not match.
        assert!(!is_bypass("/api/v1/integrations/"));
        assert!(!is_bypass("/api/v1/integrations//webhook"));
    }

    #[test]
    fn identity_link_callback_subpaths_are_bypassed() {
        assert!(is_bypass("/api/v1/auth/identity-link-callback/oidc/entra"));
    }

    #[test]
    fn identity_link_prefix_never_bypasses_the_protected_start_route() {
        // Regression guard for P-federation-linking-policy §4.3(a): the
        // start route (session-gated) must never be swept into bypass by
        // sharing a prefix with its own public callback.
        assert!(!is_bypass("/api/v1/auth/identity-link/oidc/entra"));
    }

    #[test]
    fn google_identity_link_is_not_bypassed() {
        // Regression guard: Google's single-POST link route has no separate
        // public callback (unlike OIDC), so it must never be swept into
        // bypass by a prefix match against `/api/v1/auth/google`'s own bypass
        // entries above.
        assert!(!is_bypass("/api/v1/auth/identity-link/google"));
    }

    #[test]
    fn step_up_callbacks_are_bypassed_but_no_step_up_start_route_is() {
        // Base-auth hardening 2.1c: only the IdP callbacks are public. Every
        // step-up start and verify route must keep requiring a live session.
        assert!(is_bypass("/api/v1/auth/step-up-callback/oidc/entra"));
        assert!(!is_bypass("/api/v1/auth/step-up/identity_link"));
        assert!(!is_bypass("/api/v1/auth/step-up/identity_link/verify"));
        assert!(!is_bypass("/api/v1/auth/step-up/identity_link/oidc/entra"));
        assert!(!is_bypass("/api/v1/auth/step-up/api_key_create/oidc/entra"));
        assert!(!is_bypass("/api/v1/auth/step-up-callback"));
    }

    // ── CSRF exemption (narrower than the authn bypass) ──────────────────

    #[test]
    fn logout_bypasses_authn_but_is_not_csrf_exempt() {
        // The whole point of this split: logout must stay callable without a
        // valid session (authn bypass) while still being protected against a
        // cross-site forced logout (CSRF enforced).
        assert!(is_bypass("/api/v1/auth/logout"));
        assert!(!is_csrf_exempt("/api/v1/auth/logout"));
    }

    #[test]
    fn refresh_bypasses_authn_but_is_not_csrf_exempt() {
        // D-305. Same split as logout: refresh must stay callable with an
        // expired/absent access token (authn bypass) while a cross-site page
        // must not be able to force a refresh-family rotation. Note this
        // assertion alone does not prove the route is protected — see
        // `csrf::tests::a_refresh_cookie_alone_is_a_credential_...`, without
        // which this entry would be inert for a jar holding only the refresh
        // cookie.
        assert!(is_bypass("/api/v1/auth/refresh"));
        assert!(!is_csrf_exempt("/api/v1/auth/refresh"));
    }

    #[test]
    fn genuinely_pre_auth_paths_remain_csrf_exempt() {
        // These carry no live session cookie for a cross-site request to ride
        // on, so withdrawing their exemption would only break them.
        assert!(is_csrf_exempt("/api/v1/auth/login"));
        assert!(is_csrf_exempt("/api/v1/auth/register"));
        assert!(is_csrf_exempt("/api/v1/auth/reset-confirm"));
        assert!(is_csrf_exempt("/api/v1/auth/mfa/verify"));
        assert!(is_csrf_exempt("/api/v1/auth/oidc/entra/callback"));
        assert!(is_csrf_exempt("/health"));
    }

    #[test]
    fn a_protected_path_is_never_csrf_exempt() {
        // Non-bypassed routes were already CSRF-checked; this guards against a
        // future edit inverting the `is_bypass && !enforced` composition.
        assert!(!is_csrf_exempt("/api/v1/admin/security/grants"));
        assert!(!is_csrf_exempt("/api/v1/api_key"));
    }

    #[test]
    fn every_csrf_enforced_path_is_actually_a_bypass_path() {
        // A typo'd entry here would be silently inert — it would exempt
        // nothing and protect nothing, because `is_csrf_exempt` only ever
        // consults this list for paths that already passed `is_bypass`.
        for path in CSRF_ENFORCED_BYPASS_PATHS {
            assert!(
                is_bypass(path),
                "{path} is listed as CSRF-enforced but is not a bypass path at all — \
                 either it is misspelled or it belongs nowhere in this file"
            );
        }
    }
}
