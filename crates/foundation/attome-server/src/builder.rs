//! Compiler-enforced route assembly (D-052). Replaces the convention-only
//! version of D-019 ("never mount a route bundle outside this single
//! composition point") with a type that makes the violation impossible
//! instead of just discouraged in a comment — the exact gap that let
//! `/api/v1/auth/api-keys` skip authz/body-limit/s2s before Plan 1.3.

use std::sync::Arc;

use attome_config::AppConfig;
use axum::{Router, middleware};

use crate::{
    app,
    middleware::host_gate::{self, HostAudience},
    state::AppState,
};

/// A route bundle, opaque to everything except [`ServerBuilder`] — the inner
/// `Router` has no public accessor, so no calling code anywhere can
/// `.merge()` a bundle directly onto an already-layered `app`; the compiler
/// rejects it, because `RouteBundle` exposes no such method.
///
/// Construct with [`RouteBundle::new`] once a bundle's own state is fully
/// applied (a bare `Router`, not `Router<S>` — call `.with_state(..)` first
/// if a bundle-producing function returns a generic router).
pub struct RouteBundle(Router);

impl std::fmt::Debug for RouteBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteBundle").finish_non_exhaustive()
    }
}

impl RouteBundle {
    pub fn new(router: Router) -> Self {
        Self(router)
    }
}

/// The only function that turns accumulated [`RouteBundle`]s into a runnable
/// `axum::Router` — hard-codes the D-019 composition order (`apply_inner_layers`
/// → the injected S2S layer → `apply_pre_auth_rate_limit` → `apply_mutation_gate`
/// → `apply_authoring_gate` → liveness merge → `apply_outer_layers`, matching
/// the coding guidelines' Tower Middleware Pipeline section) at the type level
/// instead of in a comment.
/// `apply_mutation_gate` (P-audit-chain-hardening item (e)) is additive: it
/// only ever rejects a mutating request while
/// `AppState::audit_ingest_backlog_exceeded` is true, which stays false
/// unless a deployment spawns `xrm_server::spawn_ingest_backlog_refresh` —
/// unwired deployments see byte-identical behavior to before this layer
/// existed. `apply_authoring_gate` (P-environment-promotion Phase 0) is
/// likewise additive: it only ever rejects a mutating request to a
/// metadata-authoring prefix while `config.app.deployment_profile` is
/// `"production"` (and no break-glass window is open) — the development
/// profile, every read, and every other route are untouched.
///
/// `s2s_layer` is injected rather than called directly (e.g.
/// `xrm_server::apply_s2s_layer`) because `attome-server` must stay
/// `xrm-*`-agnostic (workspace crate rule: "base-* crates must compile with
/// zero xrm-* dependencies") — only the consuming binary (`crates/server`),
/// which already depends on both `attome-server` and `xrm-server`, is allowed
/// to name that function. `ServerBuilder` only guarantees WHERE in the
/// sequence it runs, not what it is.
pub struct ServerBuilder {
    state: AppState,
    config: AppConfig,
    router: Router,
    audience_router: Router,
    liveness_router: Router,
    web_root: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBuilder").finish_non_exhaustive()
    }
}

impl ServerBuilder {
    pub fn new(state: AppState, config: AppConfig) -> Self {
        Self {
            state,
            config,
            router: Router::new(),
            audience_router: Router::new(),
            liveness_router: Router::new(),
            web_root: None,
        }
    }

    /// Merges a bundle into the accumulated bare router. Order between
    /// bundles doesn't matter (route paths don't overlap) — only that every
    /// bundle goes through this method, never a raw `.merge()` on the final
    /// `app` from `build()`.
    pub fn add_bundle(mut self, bundle: RouteBundle) -> Self {
        self.router = self.router.merge(bundle.0);
        self
    }

    /// Mounts routes that authenticate a **different audience** than the
    /// staff session (D-573/D-576: a web portal's external users), each bundle
    /// carrying its own authn layer.
    ///
    /// They skip exactly the staff-principal layers of `apply_inner_layers`
    /// (staff authn, CSRF, authz, the authenticated per-user rate limit,
    /// idempotency) and the injected S2S layer, because all of those assume a
    /// staff `SessionClaims`/`SecurityContext`. They still pass through
    /// `apply_pre_auth_rate_limit`, `apply_mutation_gate`,
    /// `apply_authoring_gate` and `apply_outer_layers`
    /// (request id, trace, CORS, timeout, body limit), exactly like staff
    /// routes.
    ///
    /// This is not a bypass list. Nothing here makes a staff route public: a
    /// request only skips staff authn by matching a route in an audience
    /// bundle, and those routes live under paths no staff route uses (a portal
    /// is `/{keyword}/api/v1/...`, and `api` and `xrm` are reserved keywords).
    /// Every route in such a bundle must reject a request its own authn layer
    /// does not accept; the caller owns that contract, and its isolation tests
    /// (`crates/server/tests/portal_auth.rs`) prove it.
    pub fn add_audience_bundle(mut self, bundle: RouteBundle) -> Self {
        self.audience_router = self.audience_router.merge(bundle.0);
        self
    }

    /// Mounts routes that must skip `apply_pre_auth_rate_limit`,
    /// `apply_mutation_gate`, `apply_authoring_gate`, the injected S2S layer,
    /// and `apply_inner_layers`
    /// (authn/csrf/authz/rate_limit/idempotency) entirely — today
    /// `attome_server::liveness_routes()` (`GET /health` and `/health/ready`). These routes still
    /// pass through `apply_outer_layers` (RequestId/Trace/CORS/Timeout/
    /// BodyLimit), none of which depend on Redis or the database, so a
    /// liveness stays independent and readiness can return its own accurate
    /// dependency-specific 503 (see `liveness_routes`'s doc comment).
    ///
    /// Deliberately a NARROW, explicitly-named escape hatch from the D-052
    /// "everything goes through `RouteBundle`" rule — unlike `add_bundle`,
    /// which only accepts the opaque `RouteBundle` type, this takes a bare
    /// `Router` so the exemption is visible at its one call site in
    /// `main.rs`, not hidden inside a middleware function's path check.
    /// Callers must pass a state-resolved `Router` (same contract as
    /// `RouteBundle::new`), and must only ever pass unauthenticated,
    /// Redis/DB-independent routes here — anything else silently skips the
    /// entire auth/rate-limit/mutation-gate stack.
    pub fn with_liveness_routes(mut self, router: Router) -> Self {
        self.liveness_router = self.liveness_router.merge(router);
        self
    }

    /// Serves the built web app from `root` for every `GET` outside the API
    /// (`crate::web`), ahead of the rate limits and authentication (the
    /// sign-in page must load without a session) and inside the outer
    /// layers, so the security headers and request ids still apply.
    pub fn with_web_root(mut self, root: Option<std::path::PathBuf>) -> Self {
        self.web_root = root;
        self
    }

    pub fn build(self, s2s_layer: impl FnOnce(Router) -> Router) -> Router {
        // An explicit fallback on the staff router, set *before* its layers,
        // so an unmatched path still goes through staff authn (an
        // unauthenticated caller gets 401, not a 404 that says which paths
        // exist). BSV-F09: the 404 is the JSON envelope, like every other
        // error. Without it, merging the audience router below would hand
        // the merged router that router's default, unlayered fallback.
        // A5: the 405 likewise; axum's default is a bare status. It only
        // reaches routes registered by now, and runs inside staff authn too.
        let staff = self
            .router
            .fallback(|| async { attome_types::AppError::NotFound })
            .method_not_allowed_fallback(|| async { attome_types::AppError::MethodNotAllowed });
        let with_inner = app::apply_inner_layers(staff, self.state.clone());
        let with_s2s = s2s_layer(with_inner);
        // D-585: each audience answers only on its own host set, checked
        // before any authentication. Applied to each router before the
        // merge, so each gate wraps only its own routes (and the staff
        // fallback, which is how an unmatched path on a portal host ends).
        let config = Arc::new(self.config.clone());
        let staff_gated = with_s2s.layer(middleware::from_fn_with_state(
            (config.clone(), HostAudience::Staff),
            host_gate::gate,
        ));
        let audience_gated = self.audience_router.layer(middleware::from_fn_with_state(
            (config, HostAudience::Portal),
            host_gate::gate,
        ));
        // Audience bundles join after the staff inner layers and the S2S layer
        // (neither wraps them: `Router::layer` only wraps routes that exist
        // when it is called) and before every layer below, which wraps both.
        let with_audiences = staff_gated.merge(audience_gated);
        let with_pre_auth_limit =
            app::apply_pre_auth_rate_limit(with_audiences, self.state.clone());
        let with_mutation_gate = app::apply_mutation_gate(with_pre_auth_limit, self.state.clone());
        let with_authoring_gate = app::apply_authoring_gate(with_mutation_gate, self.state.clone());
        let with_liveness = with_authoring_gate.merge(self.liveness_router);
        let with_web = match self.web_root {
            Some(root) => with_liveness.layer(middleware::from_fn_with_state(
                crate::web::WebRoot(Arc::new(root)),
                crate::web::serve_web,
            )),
            None => with_liveness,
        };
        // Y8-T7: every response names the metadata version this node serves,
        // so a browser, an SDK client or an agent notices a new model.
        let version = self.state.metadata_version.clone();
        let with_version = with_web.layer(middleware::map_response(
            move |mut response: axum::response::Response| {
                let applied = version.load(std::sync::atomic::Ordering::Relaxed);
                async move {
                    if applied > 0
                        && let Ok(value) = axum::http::HeaderValue::from_str(&applied.to_string())
                    {
                        response
                            .headers_mut()
                            .insert(app::METADATA_VERSION_HEADER, value);
                    }
                    response
                }
            },
        ));
        app::apply_outer_layers(with_version, &self.config)
    }
}
