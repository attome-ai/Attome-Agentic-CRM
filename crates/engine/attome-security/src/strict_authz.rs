//! P-authz-revocation-epoch (D-116) goal (a): a small `axum::middleware`
//! layer for the privileged/admin-gated route bundles — `attome-server`'s
//! `admin`/`license_admin`/`s2s_admin`/`schema`/`sidebar`, plus this crate's
//! own grant/revoke `admin::routes()` — see `attome-server/src/system.rs`'s
//! `core_routes` for exactly where each is layered on.
//!
//! Runs AFTER `attome_server`'s `authz` middleware, which already resolved and
//! inserted the `AuthorizedContext` extension from the ordinary cache (up to
//! 60s stale, D-012). This layer re-checks that context against the live
//! `xrm:authz_epoch:{user_id}` counter and replaces the extension with a
//! confirmed-fresh one before the handler's `Authorized<P>` extractor runs its
//! policy check — so a just-revoked admin cannot keep performing further
//! privileged operations for the rest of the ordinary TTL.

use attome_core::EngineState;
use attome_server::authz::AuthorizedContext;
use attome_types::AppError;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Config kill switch: `security.strict_privileged_authz` (default true).
/// `false` restores pre-epoch behavior for these bundles only — emergency
/// rollback, meant to be removed again after one release of burn-in (see the
/// plan's rollout section).
pub async fn strict_authz(
    State(state): State<EngineState>,
    mut req: Request,
    next: Next,
) -> Response {
    if !state.base.config.security.strict_privileged_authz {
        return next.run(req).await;
    }

    let Some(user_id) = req
        .extensions()
        .get::<AuthorizedContext>()
        .map(|c| c.get().user_id)
    else {
        // attome-server's `authz` always runs ahead of this layer and always
        // attaches an AuthorizedContext on a non-bypass path (or short-circuits
        // with an error response first) — reaching here without one means
        // the pipeline order was violated. Fail closed, same as authz itself.
        return AppError::Forbidden.into_response();
    };

    match state.base.security.resolve_strict(user_id).await {
        Ok(fresh) => {
            // Replaces the ordinary (up to 60s stale, D-012) context with the
            // epoch-confirmed one, so the `Authorized<P>` extractor in the
            // handler below decides against the fresh privileges rather than
            // the cached ones. The fresh context is narrowed by the request's
            // entity ceiling exactly as authz narrowed the cached one (D-766).
            let fresh = AuthorizedContext::for_request(req.extensions(), fresh);
            req.extensions_mut().insert(fresh);
            next.run(req).await
        }
        Err(e) => e.into_response(),
    }
}
