//! Generic OIDC federation (P2.8, D-065) — config-driven provider login,
//! callback, the public provider directory, and self-service account linking.

use attome_auth::{SessionClaims, cookie};
use attome_server::AppState;
use attome_types::AppError;
use axum::{
    Form, Json,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
};

use super::dto::{
    BackchannelLogoutForm, IdentityLinkOidcCallbackQuery, OidcCallbackQuery, OidcDiscoverRequest,
    OidcDiscoverResponse, OidcProviderInfo,
};
use super::session::issue_session_cookies_for;
use attome_auth::auth_context::AuthContext;
use attome_types::ErrorResponse;

// ── Browser binding for self-service identity linking (B3) ───────────────────
//
// `identity_link_*_start` stashes the caller's user id in the single-use,
// server-side state, and the bypass-listed callback trusts that state alone
// to choose which account the IdP identity gets linked to. On its own that
// lets an attacker start a link against THEIR account, hand the resulting
// authorize URL to a victim, and have the victim's IdP identity bound to the
// attacker's account when the victim's browser completes the round trip: the
// `state`/`RelayState` the IdP echoes back is a URL value, and proves nothing
// about *which browser* is completing the flow.
//
// The fix: the start route also sets a short-lived cookie carrying that same
// state id, and the callback refuses to do anything — before the single-use
// state is consumed, before the IdP is contacted — unless the cookie is
// present AND equals the state the IdP echoed. A browser only ever holds the
// cookie for a flow IT started (`HttpOnly`, no `Domain`, `__Host-` under TLS
// — nothing cross-origin can plant one), so an attacker-started state can
// only be completed from the attacker's own browser. The value is the state
// id itself rather than a MAC of it: the property that matters is "present
// only in the starting browser", not secrecy — the attacker already knows
// their own state, and the id is already a platform-minted 128-bit UUIDv7.
//
// Why not `attome_auth::cookie::build`: it hard-codes `SameSite=Strict`, and a
// Strict cookie is exactly what the browser withholds on the cross-site
// top-level navigation back from the IdP (the same reason the session cookie
// cannot carry the linking user — see `identity_link_oidc_callback`'s doc).
// The OIDC callback is a top-level GET redirect, for which `Lax` is both
// sufficient and the tightest that works. Everything else
// mirrors `cookie::build`: `HttpOnly`, `Path=/`, `Secure` + `__Host-` gated
// on `config.auth.secure_cookies` exactly like `cookie::session_cookie_name`,
// so plain-http local dev keeps working.

/// Which redirect flow a binding cookie belongs to. One cookie per flow (not
/// one shared name) so flows started back-to-back in the same browser cannot
/// overwrite each other's binding, and so each can carry the `SameSite` its
/// own callback binding needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IdentityLinkFlow {
    Oidc,
    /// Base-auth hardening 2.1c (D-510 rule 5) — a federated step-up. The
    /// callback trusts only server-side state, exactly like a link callback,
    /// so it needs the same binding to the browser that started it.
    StepUpOidc,
    /// BAU-4a (G-10, finding BAU-F1) — the ordinary staff **sign-in**
    /// (`oidc_login` / `oidc_callback`). It is bypass-listed and has no
    /// session to bind to, so before this flow existed the callback trusted
    /// `state` alone and a sign-in started by an attacker could be completed
    /// in a victim's browser, signing the victim in to the attacker's account
    /// (login CSRF). Same one-cookie-per-flow reasoning as the two above.
    Login,
}

/// Comfortably longer than the server-side state's own 300s TTL
/// (`attome_auth::oidc`), which stays the real deadline — the
/// cookie only has to outlive it, never extend it.
pub(super) const IDENTITY_LINK_COOKIE_MAX_AGE_SECS: u64 = 600;

/// `__Host-`-prefixed under TLS, bare on plain-http dev — the same split, for
/// the same browser-enforced reason, as `cookie::session_cookie_name`.
pub(super) fn identity_link_cookie_name(flow: IdentityLinkFlow, secure: bool) -> &'static str {
    match (flow, secure) {
        (IdentityLinkFlow::Oidc, true) => "__Host-identity_link_oidc",
        (IdentityLinkFlow::Oidc, false) => "identity_link_oidc",
        (IdentityLinkFlow::StepUpOidc, true) => "__Host-step_up_oidc",
        (IdentityLinkFlow::StepUpOidc, false) => "step_up_oidc",
        (IdentityLinkFlow::Login, true) => "__Host-oidc_login",
        (IdentityLinkFlow::Login, false) => "oidc_login",
    }
}

fn build_identity_link_cookie(
    flow: IdentityLinkFlow,
    secure: bool,
    value: &str,
    max_age_secs: u64,
) -> String {
    let name = identity_link_cookie_name(flow, secure);
    debug_assert!(
        !name.starts_with("__Host-") || secure,
        "__Host- cookie {name} requires Secure"
    );
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{name}={value}; HttpOnly{secure_flag}; SameSite=Lax; Path=/; Max-Age={max_age_secs}")
}

/// The `Set-Cookie` value the start route issues alongside its redirect to
/// the IdP: the state id (the OIDC `state`) the IdP will echo
/// back, which the callback then demands as this cookie.
pub(super) fn identity_link_cookie_set(
    flow: IdentityLinkFlow,
    secure: bool,
    state_id: &str,
) -> String {
    build_identity_link_cookie(flow, secure, state_id, IDENTITY_LINK_COOKIE_MAX_AGE_SECS)
}

/// Clears the binding cookie (`Max-Age=0`), same shape as `cookie::clear`.
pub(super) fn identity_link_cookie_clear(flow: IdentityLinkFlow, secure: bool) -> String {
    build_identity_link_cookie(flow, secure, "", 0)
}

/// The callback-side half: the browser must present the flow's binding
/// cookie and it must equal `echoed_state`, the state the IdP sent back.
/// Anything else is `Unauthorized` — the request did not come from the
/// browser that started this link. `echoed_state` is a platform-minted
/// UUID the IdP echoes in the URL, not a secret, so a plain comparison
/// leaks nothing.
///
/// BAU-4b: returns the `BoundState` proof `attome_auth::oidc::complete_login`
/// now requires, so the header read and the check that gates the flow are one
/// step rather than two that a caller could separate.
pub(super) fn require_identity_link_binding(
    headers: &HeaderMap,
    flow: IdentityLinkFlow,
    secure: bool,
    echoed_state: &str,
) -> Result<attome_auth::oidc::BoundState, AppError> {
    let name = identity_link_cookie_name(flow, secure);
    match cookie::extract(headers, name) {
        Some(presented) => attome_auth::oidc::bind_to_browser(Some(&presented), echoed_state)
            .inspect_err(|_| {
                tracing::warn!(
                    "identity_link: binding cookie {name} does not match the echoed state — \
                     callback did not arrive in the browser that started this link"
                );
            }),
        None => {
            tracing::warn!(
                "identity_link: binding cookie {name} absent — \
                 callback did not arrive in the browser that started this link"
            );
            Err(AppError::Unauthorized)
        }
    }
}

/// The value of query parameter `name` in `url`, form-urlencoding-decoded.
/// How the start routes recover the state id `attome_auth` minted and put in
/// the IdP redirect URL — `start_login` returns only the URL, and the id is
/// deliberately not exposed any other way (it is the single-use gate).
pub(super) fn redirect_url_query_param(url: &str, name: &str) -> Option<String> {
    let (_, query) = url.split_once('?')?;
    let query = query.split('#').next().unwrap_or(query);
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (key == name).then(|| form_urldecode(value))
    })
}

fn form_urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let decoded = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .ok()
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                match decoded {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Start an OIDC sign-in
///
/// P2.8 (D-065) — starts the generic OIDC authorization-code + PKCE flow for
/// a provider from configuration or added on screen (Q1-T3,
/// `state.oidc_providers`). Redirects the browser straight to the IdP;
/// `AppError::NotFound` for an unconfigured
/// provider key (never 401/403 — an unconfigured provider isn't a protected
/// resource, it just doesn't exist, same `FeatureHidden`-style reasoning as
/// an unlicensed module route). Bypass-listed: the caller has no session yet.
#[utoipa::path(
    get,
    path = "/api/v1/auth/oidc/{provider}/login",
    tag = "auth",
    params(("provider" = String, Path, description = "The OIDC provider's key")),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn oidc_login(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let provider_config = state
        .oidc_providers
        .get(&provider)
        .ok_or(AppError::NotFound)?
        .config;
    let redirect_uri = format!(
        "{}/api/v1/auth/oidc/{provider}/callback",
        state.config.frontend_url()
    );
    let authorize_url = attome_auth::oidc::start_login(
        &state.redis_coordination,
        &state.redis,
        &provider_config,
        &provider,
        &redirect_uri,
        None,
    )
    .await?;
    // BAU-4a (G-10, finding BAU-F1): bind the sign-in to the browser that
    // started it. The callback demands this cookie back before it will consume
    // the single-use state or contact the IdP, so an attacker who starts a
    // sign-in and hands the callback URL to a victim cannot have the victim's
    // browser complete it into the *attacker's* account. Fail closed if the
    // URL somehow carries no state — a redirect without the binding would
    // reopen exactly the hole this closes (the already-written server-side
    // state just ages out on its own TTL).
    let state_id = redirect_url_query_param(&authorize_url, "state")
        .ok_or_else(|| AppError::internal("oidc authorize url carries no state parameter"))?;
    let secure = state.config.auth.secure_cookies;
    let binding_cookie = identity_link_cookie_set(IdentityLinkFlow::Login, secure, &state_id);
    Ok((
        AppendHeaders([(header::SET_COOKIE, binding_cookie)]),
        Redirect::to(&authorize_url),
    )
        .into_response())
}

/// P2.8 (D-065) — the IdP redirects the browser back here with `code`+`state`.
/// Exchanges the code, verifies the ID token (signature/aud/iss/nonce —
/// `attome_auth::oidc::complete_login`), JIT-links the account
/// (`attome_security::accounts::link_oidc_identity`), issues the same session
/// cookies every other login path issues, and redirects to the frontend —
/// this is a top-level browser navigation from the IdP, not a fetch/XHR call,
/// so a redirect (not JSON) is the only response an IdP's redirect can
/// consume. Bypass-listed, same reasoning as `/refresh`.
///
/// P2.8 step 5: any failure also redirects (to `{frontend_url}/login?oidc_error=1`)
/// rather than returning the raw `AppError` JSON body — a JSON blob mid IdP-redirect
/// isn't actionable for a browser user, and the `AppError` detail (e.g. exactly which
/// claim/state check failed) isn't for the client anyway (see §6). The real reason is
/// logged server-side, same as any other recoverable anomaly.
#[utoipa::path(
    get,
    path = "/api/v1/auth/oidc/{provider}/callback",
    tag = "auth",
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Login)])))),
    params(
        ("provider" = String, Path, description = "The OIDC provider's key"),
        OidcCallbackQuery,
    ),
    responses(
        (status = 200, description = "Success"),
        (status = 409, description = "Seat limit reached for a first-time account", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn oidc_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(auditor): Extension<attome_audit::security::SecurityAuditor>,
    Extension(license): Extension<super::LicenseHandle>,
    Path(provider): Path<String>,
    Query(query): Query<OidcCallbackQuery>,
) -> Response {
    // BAU-4a (G-10, finding BAU-F1) — checked first, before the single-use
    // state is consumed and before the IdP is contacted, so a request from a
    // browser that did not start this sign-in leaves the genuine flow's state
    // intact and costs no token exchange. See the module section above.
    let secure = state.config.auth.secure_cookies;
    // BAU-25 (finding BAU-F20): the provider's own refusal comes first. A user
    // who cancels, or consent that is refused, redirects back with `error` and
    // no code — before this, the required `code`/`state` query extraction
    // answered axum's bare 400 and the browser stopped on a blank page.
    // Nothing is consumed, and the binding cookie is deliberately left alone so
    // a genuine in-flight flow in that browser keeps working.
    if let Some(error) = query.error.as_deref() {
        tracing::warn!(
            "oidc_callback: provider={provider} answered error={error}; nothing consumed"
        );
        return oidc_error_redirect(&state, AppError::Unauthorized);
    }
    let (Some(code), Some(state_id)) = (query.code.as_deref(), query.state.as_deref()) else {
        tracing::warn!("oidc_callback: provider={provider} answered with no code and no error");
        return oidc_error_redirect(&state, AppError::Unauthorized);
    };
    let binding =
        require_identity_link_binding(&headers, IdentityLinkFlow::Login, secure, state_id);
    let bound = binding.is_ok();
    let outcome = match binding {
        Ok(bound_state) => {
            oidc_callback_inner(&state, &auditor, &provider, code, &license, bound_state).await
        }
        Err(e) => Err(e),
    };
    match outcome {
        Ok(mut response) => {
            // The cookie has served its one flow. Deliberately not cleared on a
            // binding failure: that request was not made by the browser that
            // started the sign-in, so a cookie a genuine in-flight flow may
            // still need is not this request's to discard.
            if bound {
                clear_binding_cookie(&mut response, IdentityLinkFlow::Login, secure);
            }
            response
        }
        Err(e) => {
            tracing::warn!("oidc_callback: provider={provider} failed: {e}");
            let mut response = oidc_error_redirect(&state, e);
            if bound {
                clear_binding_cookie(&mut response, IdentityLinkFlow::Login, secure);
            }
            response
        }
    }
}

/// P2.8 step 5 — the redirect every failed sign-in callback ends with: the
/// browser lands on the login page with a reason, never on a raw JSON error
/// body mid-redirect. A `Conflict` gets its own reason so the frontend can show
/// the actionable "sign in your existing way, then link this provider" message
/// (enterprise-audit remediation, Phase 2.1); everything else, BAU-25's
/// provider-cancelled `error` redirect included, gets the generic one.
fn oidc_error_redirect(state: &AppState, error: AppError) -> Response {
    let reason = match error {
        // Q1-T8: a link-only provider found no account for this person.
        AppError::Conflict("no_linked_account") => "no_linked_account",
        AppError::Conflict(_) => "oidc_link_conflict",
        // Q1-T6: the token's tenant is not on the provider's allow-list, or
        // the email's domain is not verified for the provider.
        AppError::RequestRejected("tenant_not_allowed") => "tenant_not_allowed",
        AppError::RequestRejected("domain_not_verified") => "domain_not_verified",
        _ => "oidc_error",
    };
    let location = format!("{}/login?{reason}=1", state.config.frontend_url());
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

/// Appends a `Max-Age=0` `Set-Cookie` for `flow` to an already-built
/// response, leaving the rest of its headers — session cookies, `Location` —
/// alone.
pub(super) fn clear_binding_cookie(response: &mut Response, flow: IdentityLinkFlow, secure: bool) {
    if let Ok(value) = HeaderValue::from_str(&identity_link_cookie_clear(flow, secure)) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

async fn oidc_callback_inner(
    state: &AppState,
    auditor: &attome_audit::security::SecurityAuditor,
    provider: &str,
    code: &str,
    license: &super::LicenseHandle,
    bound: attome_auth::oidc::BoundState,
) -> Result<Response, AppError> {
    let entry = state
        .oidc_providers
        .get(provider)
        .ok_or(AppError::NotFound)?;
    let provider_config = entry.config.clone();
    // Q1-T8: what the provider does the first time it sees a person.
    let link_mode = attome_security::accounts::LinkMode::of(&entry.link_mode, entry.default_role);

    let identity = attome_auth::oidc::complete_login(
        &state.redis_coordination,
        &state.redis,
        &provider_config,
        provider,
        code,
        bound,
    )
    .await?;
    // Base-auth hardening 2.1c: a step-up flow's state completes only at the
    // step-up callback; it never signs anyone in.
    if identity.step_up.is_some() {
        return Err(AppError::Unauthorized);
    }
    // Q1-T5: an administrator's test of the provider: show what it returned,
    // sign nobody in, set no session cookie.
    if identity.purpose == attome_auth::oidc::FlowPurpose::Test {
        tracing::info!(
            provider,
            tester = ?identity.tester,
            "oidc provider test completed; no session issued"
        );
        return Ok(test_result_page(
            &state.config.frontend_url(),
            provider,
            &identity.claims,
        ));
    }
    // Q1-T6: a provider limited to some Entra tenants signs in only theirs.
    if !attome_auth::oidc::tenant_allowed(&entry.tenant_allowlist, identity.tid.as_deref()) {
        tracing::warn!(
            provider,
            "oidc_callback: the token's tenant is not on the provider's allow-list"
        );
        return Err(AppError::RequestRejected("tenant_not_allowed"));
    }
    // Q1-T6: a provider added on screen signs in only people whose email
    // domain is verified for it; a configured provider is trusted as
    // configured, as before.
    if entry.source == attome_auth::oidc_registry::ProviderSource::Database
        && !attome_security::auth_policy::domain_verified_for(&state.db, provider, &identity.email)
            .await?
    {
        tracing::warn!(
            provider,
            "oidc_callback: the email's domain is not verified for the provider"
        );
        return Err(AppError::RequestRejected("domain_not_verified"));
    }
    // M04 Phase 2 (LIC-F2): the seat gate lives inside `link_oidc_identity`'s
    // transaction, on the branch that actually creates a row (see
    // `attome_security::accounts::link_google_account`'s doc comment for why the
    // licence is threaded in rather than read there).
    let active_license = (*license.load()).clone();
    let user_id = attome_security::accounts::link_oidc_identity(
        &state.db,
        provider,
        &identity.sub,
        &identity.email,
        &link_mode,
        &active_license,
    )
    .await?;
    // Q1-T9: a provider added on screen applies its group mappings and
    // profile claims at each sign-in, in one transaction with their events,
    // before the session exists.
    if entry.source == attome_auth::oidc_registry::ProviderSource::Database
        && let Some(provider_id) = entry.id
    {
        let groups = attome_security::oidc_mapping::groups_of(&identity.claims, &entry.claim_map);
        let mut tx = attome_db::tx::begin(&state.db).await?;
        let changes = attome_security::oidc_mapping::apply_mappings_in_tx(
            &mut tx,
            &auditor.service(),
            provider_id,
            provider,
            user_id,
            &groups,
        )
        .await?;
        attome_security::oidc_mapping::apply_profile_in_tx(
            &mut tx,
            user_id,
            &identity.claims,
            &entry.claim_map,
        )
        .await?;
        tx.commit().await.map_err(AppError::internal)?;
        if !changes.is_empty() {
            tracing::info!(provider, %user_id, ?changes, "oidc sign-in: group mappings applied");
            state.security.invalidate_sync(user_id).await?;
        }
    }
    // D-510 rule 2: the validated ID token's own authentication time, or none.
    let method = format!("oidc:{provider}");
    let cookies = issue_session_cookies_for(
        state,
        user_id,
        // Q2-T2: MFA the provider reported counts as this sign-in's second factor.
        &AuthContext::federated(identity.auth_time)
            .with_idp_mfa(identity.idp_mfa)
            // Q1-T10: sign-out and back-channel logout find the family by these.
            .with_oidc_session(provider, identity.sid.clone()),
        Some((auditor, &method)),
    )
    .await?;

    let mut headers = cookies.to_vec();
    headers.push((header::LOCATION, state.config.frontend_url()));
    Ok((StatusCode::FOUND, AppendHeaders(headers)).into_response())
}

/// P-federation-linking-policy §4.3(a) — starts the same authorization-code +
/// PKCE flow as `oidc_login`, but requires an existing session
/// (`Extension<SessionClaims>`) and stashes its `user_id` in the single-use
/// server-side `OidcState` (`attome_auth::oidc::start_login`'s `linking_user_id`
/// param) so the callback — which cannot rely on the session cookie, see
/// `identity_link_oidc_callback`'s doc comment — can bind the resulting
/// identity to the caller's own account instead of JIT-matching by email.
/// Protected: rides `AuthnLayer`/`AuthzLayer` like any other non-bypass
/// route. Deliberately NOT under the `/api/v1/auth/oidc/` bypass subtree —
/// guidelines §3: a bypass prefix must never also match a protected route,
/// so this lives at `/api/v1/auth/identity-link/oidc/{provider}` instead.
///
/// Operational note: an operator enabling self-service linking for a
/// provider must add this route's callback URL
/// (`{frontend_url}/api/v1/auth/identity-link-callback/oidc/{provider}`) as
/// an additional allowed redirect URI on that OIDC client registration — the
/// IdP will reject the exchange otherwise. Not a code concern; documented
/// here since it's easy to miss.
/// Base-auth hardening 2.1d (D-510 rules 7 and 9) — the guard for the
/// identity-link start routes. They are browser navigations, which cannot
/// handle a JSON `reauth_required`, so a session without a fresh step-up for
/// `identity_link` gets `Some` redirect to the settings page carrying a
/// re-authentication marker. The caller returns it before creating provider
/// state, setting a binding cookie or contacting the IdP. An API-key or S2S
/// caller, or a session without a live family, still gets its plain error.
pub(super) async fn identity_link_step_up_redirect(
    state: &AppState,
    caller: attome_auth::step_up::Caller,
    user_id: uuid::Uuid,
) -> Result<Option<Response>, AppError> {
    let operation = attome_auth::step_up::Operation::IdentityLink;
    match attome_auth::step_up::require_recent_auth(
        &state.db,
        caller,
        user_id,
        operation,
        state.config.refresh_absolute_lifetime_secs(),
    )
    .await
    {
        Ok(()) => Ok(None),
        Err(AppError::ReauthRequired { .. }) => {
            let location = format!(
                "{}/settings/security?reauth_required={}",
                state.config.frontend_url(),
                operation.as_str()
            );
            Ok(Some(Redirect::to(&location).into_response()))
        }
        Err(other) => Err(other),
    }
}

/// Start linking an OIDC identity
///
/// Redirects the signed-in caller to the OIDC provider to link that identity to their own account, as the linking policy allows. The provider returns to the identity-link callback.
#[utoipa::path(
    get,
    path = "/api/v1/auth/identity-link/oidc/{provider}",
    tag = "auth",
    params(("provider" = String, Path, description = "The OIDC provider's key")),
    responses(
        (status = 200, description = "Not returned: every accepted request gets a 303 redirect. Listed because every documented operation declares a 2xx."),
        (status = 303, description = "Redirect to the provider. When the session has no step-up for `identity_link` within 5 minutes, redirect instead to `{frontend}/settings/security?reauth_required=identity_link`, with no provider state created"),
        (status = 401, description = "Missing or invalid credentials, or a session without a live refresh family", body = ErrorResponse),
        (status = 403, description = "An API-key or S2S caller: only a cookie session may link an identity", body = ErrorResponse),
        (status = 404, description = "No such provider", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = [])),
)]
pub(super) async fn identity_link_oidc_start(
    State(state): State<AppState>,
    Extension(claims): Extension<SessionClaims>,
    attome_server::step_up::StepUpCaller(caller): attome_server::step_up::StepUpCaller,
    // Self-scoped by design: links only to the caller's own `claims.sub`.
    _ctx: attome_server::authz::Authorized<attome_server::authz::SelfService>,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let provider_config = state
        .oidc_providers
        .get(&provider)
        .ok_or(AppError::NotFound)?
        .config;
    if let Some(redirect) = identity_link_step_up_redirect(&state, caller, claims.sub).await? {
        return Ok(redirect);
    }
    let redirect_uri = format!(
        "{}/api/v1/auth/identity-link-callback/oidc/{provider}",
        state.config.frontend_url()
    );
    let authorize_url = attome_auth::oidc::start_login(
        &state.redis_coordination,
        &state.redis,
        &provider_config,
        &provider,
        &redirect_uri,
        Some(claims.sub),
    )
    .await?;
    // B3 browser binding (see the module section above): the callback will
    // demand the state id the IdP echoes back as a cookie only this browser
    // holds. Fail closed if the URL somehow carries none — a redirect
    // without the binding would reopen exactly the hole this closes (the
    // already-written server-side state just ages out on its own TTL).
    let state_id = redirect_url_query_param(&authorize_url, "state")
        .ok_or_else(|| AppError::internal("oidc authorize url carries no state parameter"))?;
    let secure = state.config.auth.secure_cookies;
    let binding_cookie = identity_link_cookie_set(IdentityLinkFlow::Oidc, secure, &state_id);
    Ok((
        AppendHeaders([(header::SET_COOKIE, binding_cookie)]),
        Redirect::to(&authorize_url),
    )
        .into_response())
}

/// OIDC identity-link callback
///
/// P-federation-linking-policy §4.3(a) callback — bypass-listed
/// (`attome_server::middleware::bypass`'s `/api/v1/auth/identity-link-callback/`
/// subtree prefix). This route deliberately does NOT require
/// `Extension<SessionClaims>`, even though it only ever does anything useful
/// for a caller who was logged in a moment ago: session cookies here are
/// `SameSite=Strict` (`attome_auth::cookie::build`), so the browser never
/// re-attaches one on this cross-site redirect back from the IdP — the
/// target user comes entirely from `OidcIdentity::linking_user_id`, resolved
/// server-side from the single-use state `identity_link_oidc_start` stashed
/// before redirecting to the IdP. Same failure-redirect shape as
/// `oidc_callback` (P2.8 step 5 precedent).
#[utoipa::path(
    get,
    path = "/api/v1/auth/identity-link-callback/oidc/{provider}",
    tag = "auth",
    params(
        ("provider" = String, Path, description = "The OIDC provider's key"),
        IdentityLinkOidcCallbackQuery,
    ),
    responses(
        (status = 200, description = "Success"),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn identity_link_oidc_callback(
    State(state): State<AppState>,
    Extension(auditor): Extension<attome_audit::security::SecurityAuditor>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<IdentityLinkOidcCallbackQuery>,
) -> Response {
    let secure = state.config.auth.secure_cookies;
    // BAU-25 (finding BAU-F20): a cancelled link comes back as `error` with
    // no code. Same shape as the sign-in callback above — redirect to this
    // route's own error target, consume nothing, and leave the binding cookie
    // alone so a genuine in-flight link in that browser keeps working.
    let (Some(code), Some(state_id)) = (query.code.as_deref(), query.state.as_deref()) else {
        if let Some(error) = query.error.as_deref() {
            tracing::warn!(
                "identity_link_oidc_callback: provider={provider} answered error={error}; \
                 nothing consumed"
            );
        } else {
            tracing::warn!(
                "identity_link_oidc_callback: provider={provider} answered without a code \
                 and without an error"
            );
        }
        let location = format!(
            "{}/settings/security?identity_link_error=1",
            state.config.frontend_url()
        );
        return (StatusCode::FOUND, [(header::LOCATION, location)]).into_response();
    };
    // B3 browser binding — checked first, before the single-use state is
    // consumed and before the IdP is contacted, so a request from the wrong
    // browser leaves the genuine flow's state intact and costs no token
    // exchange. See the module section above.
    let binding = require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, secure, state_id);
    let bound = binding.is_ok();
    let outcome = match binding {
        Ok(bound_state) => {
            identity_link_oidc_callback_inner(&state, &auditor, &provider, code, bound_state).await
        }
        Err(e) => Err(e),
    };
    let location = match outcome {
        Ok(()) => format!(
            "{}/settings/security?identity_linked=1",
            state.config.frontend_url()
        ),
        Err(e) => {
            tracing::warn!("identity_link_oidc_callback: provider={provider} failed: {e}");
            let reason = if matches!(e, AppError::Conflict(_)) {
                "identity_link_conflict"
            } else {
                "identity_link_error"
            };
            format!(
                "{}/settings/security?{reason}=1",
                state.config.frontend_url()
            )
        }
    };
    let mut response_headers = Vec::with_capacity(2);
    if bound {
        // The cookie has served its one flow, whether that flow went on to
        // succeed or fail — clear it. Deliberately NOT cleared on a binding
        // failure: that request was not made by the browser that started
        // the link, so a cookie a genuine in-flight flow may still need is
        // not this request's to discard.
        response_headers.push((
            header::SET_COOKIE,
            identity_link_cookie_clear(IdentityLinkFlow::Oidc, secure),
        ));
    }
    response_headers.push((header::LOCATION, location));
    (StatusCode::FOUND, AppendHeaders(response_headers)).into_response()
}

async fn identity_link_oidc_callback_inner(
    state: &AppState,
    auditor: &attome_audit::security::SecurityAuditor,
    provider: &str,
    code: &str,
    bound: attome_auth::oidc::BoundState,
) -> Result<(), AppError> {
    let provider_config = state
        .oidc_providers
        .get(provider)
        .ok_or(AppError::NotFound)?
        .config;

    let identity = attome_auth::oidc::complete_login(
        &state.redis_coordination,
        &state.redis,
        &provider_config,
        provider,
        code,
        bound,
    )
    .await?;
    // Defensive: this callback path is dedicated to the linking flow. A
    // state entry with no linking_user_id can't be reached through the
    // normal UI (only identity_link_oidc_start ever sets it), but costs
    // nothing to reject explicitly rather than falling through to any
    // JIT-by-email logic.
    let user_id = identity.linking_user_id.ok_or(AppError::Unauthorized)?;

    // BAU-26 (finding BAU-F19): a new sign-in method on an account is a
    // credential change and must reach the audit trail — the same
    // `Credential` + `Create` event the self-service Google link and the
    // admin identity-link route write, committed inside the link's own
    // transaction. This callback used the variant that takes no hook, so an
    // identity linked through it appeared in no audit trail at all. (It is a
    // GET callback, outside D-542's mutating-route declaration rule either
    // way; the declaration half stays owed.)
    let hook = attome_audit::security::account_event_hook(
        auditor.service(),
        attome_audit::security::MandatoryCategory::Credential,
        attome_audit::AuditOperation::Create,
        "user_account",
        format!("identity_link:oidc {provider} self_service"),
    );
    attome_security::accounts::link_identity_to_user_with(
        &state.db,
        user_id,
        provider,
        &identity.sub,
        &identity.email,
        &hook,
    )
    .await
}

/// List sign-in providers
///
/// P2.8 step 5 — public directory of configured OIDC providers so the Angular
/// login page can render provider buttons without duplicating provider keys/
/// labels in frontend config (killing the hardcoded-client-id pattern that
/// `google_login` still has). Falls under the `/api/v1/auth/oidc/` bypass
/// prefix already in force for the login/callback routes — no bypass-list
/// change needed. Never serializes `issuer`/`client_id`/`client_secret`/
/// `scopes`/`email_claim` — see `OidcProviderInfo`.
#[utoipa::path(
    get,
    path = "/api/v1/auth/oidc/providers",
    tag = "auth",
    responses(
        (status = 200, description = "Success", body = Vec<OidcProviderInfo>),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
)]
pub(super) async fn oidc_providers(State(state): State<AppState>) -> Json<Vec<OidcProviderInfo>> {
    // Q1-T3: configuration and on-screen providers, sorted by key.
    let providers: Vec<OidcProviderInfo> = state
        .oidc_providers
        .list()
        .iter()
        .map(|p| OidcProviderInfo {
            key: p.key.clone(),
            display_name: p.config.display_name.clone(),
        })
        .collect();
    Json(providers)
}

/// Q1-T5: the claims a test sign-in shows; a value under a name like
/// `*token*` is masked.
pub(super) fn test_claims(claims: &serde_json::Value) -> serde_json::Value {
    let Some(map) = claims.as_object() else {
        return serde_json::json!({});
    };
    serde_json::Value::Object(
        map.iter()
            .map(|(name, value)| {
                let shown = if name.to_ascii_lowercase().contains("token") {
                    serde_json::json!("********")
                } else {
                    value.clone()
                };
                (name.clone(), shown)
            })
            .collect(),
    )
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Q1-T5: the page a test sign-in ends on. It lists the claims and, when the
/// admin page that opened it is still its opener, posts them there and
/// closes. The claims are JSON escaped for the script (no `<` survives).
fn test_result_page(frontend_url: &str, provider: &str, claims: &serde_json::Value) -> Response {
    let shown = test_claims(claims);
    let rows: String = shown
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, value)| {
            let value = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            format!(
                "<tr><th>{}</th><td>{}</td></tr>",
                html_escape(name),
                html_escape(&value)
            )
        })
        .collect();
    let message = serde_json::json!({
        "type": "attome-oidc-test",
        "provider": provider,
        "claims": shown,
    })
    .to_string()
    .replace('<', "\\u003c");
    let origin = serde_json::Value::String(frontend_url.to_owned()).to_string();
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Provider test</title></head>\
         <body><h1>{provider}</h1><p>Nobody was signed in. The provider returned:</p>\
         <table>{rows}</table>\
         <script>(function(){{var m={message};if(window.opener){{window.opener.postMessage(m,{origin});window.close();}}}})();</script>\
         </body></html>",
        provider = html_escape(provider),
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

/// Test a sign-in provider
///
/// Starts a sign-in through the provider for the administrator to check it: the returned address opens the provider, and the ordinary sign-in callback then shows the claims it returned and signs nobody in. The flow is bound to this browser like a sign-in. Administrators only; writes nothing durable.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/oidc-providers/{id}/test",
    operation_id = "test_oidc_provider",
    tag = "admin-security",
    params(("id" = String, Path, description = "The provider's id, or a configured provider's key")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::ReadOnly, None, "starts a test sign-in: a single-use state in the cache and a binding cookie; nothing durable, no session")))),
    responses(
        (status = 200, description = "The address to open", body = OidcTestStart),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such provider", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn oidc_provider_test(
    State(state): State<AppState>,
    ctx: attome_server::authz::Authorized<attome_server::authz::Admin>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let key = if state.oidc_providers.get(&id).is_some() {
        id
    } else {
        let id: uuid::Uuid = id.parse().map_err(|_| AppError::NotFound)?;
        sqlx::query_scalar("SELECT key FROM oidc_provider WHERE id = $1 AND NOT is_deleted")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(AppError::internal)?
            .ok_or(AppError::NotFound)?
    };
    let entry = state.oidc_providers.get(&key).ok_or(AppError::NotFound)?;
    // The ordinary sign-in callback, which every provider has registered.
    let redirect_uri = format!(
        "{}/api/v1/auth/oidc/{key}/callback",
        state.config.frontend_url()
    );
    let authorize_url = attome_auth::oidc::start_test_login(
        &state.redis_coordination,
        &state.redis,
        &entry.config,
        &key,
        &redirect_uri,
        ctx.user_id,
    )
    .await?;
    let state_id = redirect_url_query_param(&authorize_url, "state")
        .ok_or_else(|| AppError::internal("oidc authorize url carries no state parameter"))?;
    let binding_cookie = identity_link_cookie_set(
        IdentityLinkFlow::Login,
        state.config.auth.secure_cookies,
        &state_id,
    );
    Ok((
        AppendHeaders([(header::SET_COOKIE, binding_cookie)]),
        Json(OidcTestStart { authorize_url }),
    )
        .into_response())
}

/// Q1-T5: where to send the administrator's browser.
#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub(super) struct OidcTestStart {
    pub authorize_url: String,
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
/// Find the sign-in provider for an email
///
/// Email-first sign-in: answers the key of the provider whose verified domain
/// the email is on, or `null`, so the sign-in page can send the person
/// straight to it. Always 200 and the same shape, and it never looks at user
/// accounts, so it tells nobody whether an account exists. Only domains of
/// providers added on screen route; rate limited as a credential route. No
/// session.
#[utoipa::path(
    post,
    path = "/api/v1/auth/oidc/discover",
    tag = "auth",
    request_body = OidcDiscoverRequest,
    responses(
        (status = 200, description = "The provider's key, or `null`", body = OidcDiscoverResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::ReadOnly, None, "looks up which provider an email domain routes to; changes nothing")))),
)]
pub(super) async fn oidc_discover(
    State(state): State<AppState>,
    Json(body): Json<OidcDiscoverRequest>,
) -> Result<Json<OidcDiscoverResponse>, AppError> {
    let provider = attome_security::auth_policy::provider_for_email(&state.db, &body.email)
        .await?
        // A provider the registry no longer lists cannot be signed in with.
        .filter(|key| state.oidc_providers.get(key).is_some());
    Ok(Json(OidcDiscoverResponse { provider }))
}

/// How long a logout token's id is remembered: past its `iat` window, so a
/// replay inside the window always finds it.
const LOGOUT_TOKEN_REPLAY_TTL_SECS: i64 = 600;

/// Receive a back-channel logout
///
/// OpenID Connect Back-Channel Logout 1.0: the provider posts a signed logout
/// token naming a provider session (`sid`) or a person (`sub`), and every
/// Attome session signed in through that provider for it ends at once: the
/// refresh families are revoked and the person's live access tokens stop, in
/// one transaction. The token is checked against the provider's published
/// keys, issuer, audience, an `iat` within five minutes, the back-channel
/// logout event and no `nonce`; a token id already used is refused. A token
/// that names nobody Attome knows still answers 200. Sessions from a
/// password or another provider are not touched. No session; audited.
#[utoipa::path(
    post,
    path = "/api/v1/auth/oidc/{provider}/backchannel-logout",
    tag = "auth",
    params(("provider" = String, Path, description = "The OIDC provider's key")),
    request_body(content = BackchannelLogoutForm, content_type = "application/x-www-form-urlencoded"),
    responses(
        (status = 200, description = "The sessions the token names have ended"),
        (status = 400, description = "A logout token that fails verification, or one already used", body = ErrorResponse),
        (status = 404, description = "No such provider", body = ErrorResponse),
    ),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Security, attome_audit::AuditOperation::Logout)])))),
)]
pub(super) async fn oidc_backchannel_logout(
    State(state): State<AppState>,
    Extension(auditor): Extension<attome_audit::security::SecurityAuditor>,
    Path(provider): Path<String>,
    Form(form): Form<BackchannelLogoutForm>,
) -> Response {
    // §2.8: the answer is never cached, whatever it is.
    let no_store = [(header::CACHE_CONTROL, "no-store")];
    match backchannel_logout_inner(&state, &auditor, &provider, &form.logout_token).await {
        Ok(()) => (StatusCode::OK, no_store).into_response(),
        Err(error) => (no_store, error).into_response(),
    }
}

async fn backchannel_logout_inner(
    state: &AppState,
    auditor: &attome_audit::security::SecurityAuditor,
    provider: &str,
    logout_token: &str,
) -> Result<(), AppError> {
    let entry = state
        .oidc_providers
        .get(provider)
        .ok_or(AppError::NotFound)?;
    let token =
        attome_auth::oidc::verify_logout_token(&state.redis, &entry.config, provider, logout_token)
            .await
            .map_err(|error| match error {
                AppError::Unauthorized => {
                    tracing::warn!(
                        provider,
                        "backchannel logout: the logout token failed verification"
                    );
                    AppError::RequestRejected("logout_token")
                }
                // A discovery or key fetch failure: the provider retries.
                other => other,
            })?;
    let target = match (token.sid.as_deref(), token.sub.as_deref()) {
        (Some(sid), sub) => {
            let user = match sub {
                Some(sub) => {
                    attome_security::accounts::user_for_identity(&state.db, provider, sub).await?
                }
                None => None,
            };
            attome_auth::refresh::OidcLogoutTarget::Sid { sid, user }
        }
        (None, Some(sub)) => {
            match attome_security::accounts::user_for_identity(&state.db, provider, sub).await? {
                Some(user) => attome_auth::refresh::OidcLogoutTarget::User(user),
                // Nobody here is linked to that subject: nothing to end.
                None => return Ok(()),
            }
        }
        (None, None) => return Err(AppError::RequestRejected("logout_token")),
    };
    let replay_key = uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_URL,
        format!("oidc-logout:{provider}:{}", token.jti).as_bytes(),
    );
    let hook = attome_audit::security::account_event_hook(
        auditor.service(),
        attome_audit::security::MandatoryCategory::Security,
        attome_audit::AuditOperation::Logout,
        "user_account",
        format!("logout oidc:{provider} backchannel"),
    );
    match attome_auth::refresh::revoke_oidc_sessions(
        &state.db,
        provider,
        target,
        replay_key,
        LOGOUT_TOKEN_REPLAY_TTL_SECS,
        &hook,
    )
    .await?
    {
        attome_auth::refresh::OidcLogoutOutcome::Replayed => {
            tracing::warn!(provider, "backchannel logout: a logout token was replayed");
            Err(AppError::RequestRejected("logout_token_replayed"))
        }
        attome_auth::refresh::OidcLogoutOutcome::Ended(users) => {
            for user_id in &users {
                attome_auth::epoch::invalidate_cache(&state.redis_coordination, *user_id).await;
            }
            tracing::info!(
                provider,
                ended = users.len(),
                "backchannel logout: sessions ended"
            );
            Ok(())
        }
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(
    oidc_login,
    oidc_callback,
    oidc_backchannel_logout,
    oidc_discover,
    identity_link_oidc_start,
    identity_link_oidc_callback,
    oidc_providers,
    oidc_provider_test
))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

/// Pure-function half of the B3 browser binding — the cookie shape in both
/// `secure_cookies` modes, the state-id recovery from an IdP redirect URL,
/// and the accept/reject matrix. The end-to-end half (start sets it, the
/// callback demands it, nothing is linked/consumed without it) is
/// `crates/server/tests/identity_link_binding.rs`.
#[cfg(test)]
mod identity_link_binding_tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_cookie(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn oidc_cookie_is_host_prefixed_secure_and_lax_under_tls() {
        let value = identity_link_cookie_set(IdentityLinkFlow::Oidc, true, "abc");
        assert_eq!(
            value,
            "__Host-identity_link_oidc=abc; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600"
        );
    }

    #[test]
    fn oidc_cookie_is_bare_named_and_not_secure_on_plain_http_dev() {
        // Same reasoning as `cookie::session_cookie_name(false)`: a browser
        // silently drops a __Host- cookie without Secure, so dev must not
        // prefix it.
        let value = identity_link_cookie_set(IdentityLinkFlow::Oidc, false, "abc");
        assert_eq!(
            value,
            "identity_link_oidc=abc; HttpOnly; SameSite=Lax; Path=/; Max-Age=600"
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn cookie_lifetime_is_at_most_ten_minutes() {
        assert!(IDENTITY_LINK_COOKIE_MAX_AGE_SECS <= 600);
    }

    #[test]
    fn clear_empties_the_value_and_zeroes_max_age() {
        let value = identity_link_cookie_clear(IdentityLinkFlow::Oidc, true);
        assert!(value.starts_with("__Host-identity_link_oidc=;"));
        assert!(value.ends_with("; Max-Age=0"));
    }

    #[test]
    fn query_param_is_recovered_from_the_idp_redirect_url() {
        let url = "https://idp.example/authorize?response_type=code&client_id=x&state=0192abcd-1234-7000-8000-000000000001&nonce=n";
        assert_eq!(
            redirect_url_query_param(url, "state").as_deref(),
            Some("0192abcd-1234-7000-8000-000000000001")
        );
        assert_eq!(redirect_url_query_param(url, "missing"), None);
        assert_eq!(
            redirect_url_query_param("https://idp.example/authorize", "state"),
            None
        );
    }

    #[test]
    fn binding_passes_only_when_the_cookie_equals_the_echoed_state() {
        let headers = headers_with_cookie("other=1; identity_link_oidc=abc; more=2");
        assert!(
            require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, false, "abc").is_ok()
        );
    }

    #[test]
    fn binding_rejects_a_missing_cookie() {
        let headers = HeaderMap::new();
        assert!(matches!(
            require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, false, "abc"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn binding_rejects_a_mismatched_cookie() {
        let headers = headers_with_cookie("identity_link_oidc=not-abc");
        assert!(matches!(
            require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, false, "abc"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn binding_rejects_an_empty_state_even_if_the_cookie_is_empty_too() {
        let headers = headers_with_cookie("identity_link_oidc=");
        assert!(matches!(
            require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, false, ""),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn binding_reads_the_secure_name_under_tls_and_ignores_the_bare_one() {
        // No dual-read for a brand-new cookie: under TLS only the __Host-
        // name counts, so a bare-named cookie (which a browser would only
        // hold from plain-http) cannot satisfy a TLS deployment.
        let headers = headers_with_cookie("identity_link_oidc=abc");
        assert!(
            require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, true, "abc").is_err()
        );
        let headers = headers_with_cookie("__Host-identity_link_oidc=abc");
        assert!(
            require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, true, "abc").is_ok()
        );
    }

    #[test]
    fn binding_for_one_flow_does_not_satisfy_the_other() {
        let headers = headers_with_cookie("step_up_oidc=abc");
        assert!(
            require_identity_link_binding(&headers, IdentityLinkFlow::Oidc, false, "abc").is_err()
        );
        assert!(
            require_identity_link_binding(&headers, IdentityLinkFlow::StepUpOidc, false, "abc")
                .is_ok()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Q1-T5: a test sign-in's page signs nobody in: no session cookie, the
    /// claims shown with any token masked, and no markup from a claim.
    #[tokio::test]
    async fn test_flow_never_issues_session() {
        let claims = serde_json::json!({
            "email": "admin@example.test",
            "groups": ["finance"],
            "amr": ["pwd", "mfa"],
            "access_token_hash": "secret-hash",
            "name": "<script>alert(1)</script>",
        });
        let response = test_result_page("https://app.example", "okta", &claims);
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(header::SET_COOKIE).is_none(),
            "a test flow never sets a cookie"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("admin@example.test"));
        assert!(!body.contains("secret-hash"), "a token claim is masked");
        assert!(
            !body.contains("<script>alert"),
            "claims are escaped: {body}"
        );
        assert!(
            body.contains("\"https://app.example\""),
            "posts to the app only"
        );
    }
}
