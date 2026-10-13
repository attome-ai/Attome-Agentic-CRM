//! Policy-typed authorization extraction.
//!
//! # Why this module exists
//!
//! Authorization used to be opt-in per handler. `middleware::auth::authz`
//! resolved a [`SecurityContext`] and attached it as `Extension<SecurityContext>`;
//! it did not authorize. Enforcement depended on every handler remembering to
//! call `.require_admin()` / `.require(entity, action)` from
//! `xrm_security::SecurityContextExt`. That is OWASP A01 arriving by omission:
//! a new admin handler merged without its `require_admin()` line is a silent
//! privilege escalation that passes `clippy`, passes CI, and passes review,
//! because the missing line is invisible — nothing in the type system, the
//! router, or the test suite tells you either way.
//!
//! This module moves the check into the extractor. A handler names the policy
//! it runs under in its own signature:
//!
//! ```rust,ignore
//! async fn list_roles(
//!     State(state): State<XrmState>,
//!     ctx: Authorized<Admin>,
//! ) -> Result<Json<Vec<Role>>, AppError> {
//!     // `ctx` cannot exist unless Admin::authorize returned Ok.
//! }
//! ```
//!
//! [`Authorized<P>`] implements `FromRequestParts`, and its only constructor
//! runs `P::authorize`. There is no way to hold one without the check having
//! passed, so the `require_admin()?` line is not merely conventional any more —
//! it is the extractor, and it cannot be forgotten.
//!
//! # What this does and does not guarantee
//!
//! Be precise about the boundary, because overclaiming here is its own hazard:
//!
//! - **Guaranteed by the compiler.** Once a handler names `Authorized<Admin>`,
//!   the admin check provably ran before the body executed. Forgetting the
//!   check inside a handler that names a policy is not expressible. The same
//!   holds for `Authorized<RecordScoped<A>>` and its `{entity}.{action}`
//!   check, with the caveat in [`RecordScoped`]'s docs: it authorizes the
//!   *entity*, and record-level scope still needs the database and so still
//!   lives in the handler.
//! - **Guaranteed by construction.** `authz` inserts [`AuthorizedContext`], not
//!   a bare `SecurityContext`, and `AuthorizedContext`'s field is private. A
//!   handler written the old way — `Extension(ctx): Extension<SecurityContext>`
//!   — no longer resolves an extension and fails every request closed, rather
//!   than succeeding unauthorized. That is a runtime failure, not a compile
//!   error: `Extension<T>: FromRequestParts` holds for any `T: Clone`, so axum's
//!   extractor model cannot make the *retrieval* a type error. It can only make
//!   it impossible to succeed.
//! - **Not guaranteed here.** A handler that names no policy at all and reads
//!   nothing from the request is still legal Rust. That residual gap is closed
//!   by the route-policy guard test in `crates/server/tests/route_authz.rs`,
//!   which asserts every routed handler in the workspace names a policy or sits
//!   in an explicitly justified allowlist.
//!
//! # Choosing a policy
//!
//! [`Admin`], [`Privilege<K>`] and [`RecordScoped<A>`] are *self-enforcing*:
//! the extractor performs the whole check. Bare [`RecordScoped`] (i.e.
//! `RecordScoped<Dynamic>`) and [`SelfService`] are *declarations* — the
//! extractor cannot perform their check, so they exist to make the posture
//! explicit and greppable instead of silent. Picking one of those two is a
//! deliberate statement, reviewable as such; picking nothing is no longer
//! possible for a handler that needs the caller's identity.

use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;

use attome_types::AppError;
use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;

use crate::security::SecurityContext;

/// The extension `middleware::auth::authz` actually attaches.
///
/// The inner `SecurityContext` is private so that `Extension<SecurityContext>`
/// resolves to nothing and [`Authorized<P>`] becomes the only path from a
/// handler signature to the caller's identity. Middleware that legitimately
/// needs the context before any handler runs (`xrm_security::strict_authz`
/// re-resolving it against the live revocation epoch) uses [`Self::get`] /
/// [`Self::new`]; those are deliberately awkward to reach for from a handler
/// and are covered by the route-policy guard test.
#[derive(Clone, Debug)]
pub struct AuthorizedContext(Arc<SecurityContext>, bool);

impl AuthorizedContext {
    /// Wraps a freshly resolved context. Called by `authz`, and by
    /// `strict_authz` when it replaces the ordinary cached context with an
    /// epoch-confirmed one.
    pub fn new(ctx: Arc<SecurityContext>) -> Self {
        Self(ctx, false)
    }

    /// Wraps a freshly resolved context, first narrowing it by the request's
    /// [`EntityCeiling`](crate::security::EntityCeiling) when it carries one
    /// (D-766). The only constructor the two attach points use.
    ///
    /// D-791 rule 3: a request that did not authenticate with a cookie session
    /// (an API key, or an S2S client acting as its service user) gets a copy
    /// marked [`SecurityContext::service_principal`], which exempts it from
    /// business-rule `hidden`/`disabled` policies. The mark is per request;
    /// the cached context is never changed.
    pub fn for_request(extensions: &axum::http::Extensions, ctx: Arc<SecurityContext>) -> Self {
        let service = extensions
            .get::<crate::middleware::auth::CookieSession>()
            .is_none();
        match extensions.get::<crate::security::EntityCeiling>() {
            Some(ceiling) => {
                let mut capped = ceiling.apply(&ctx);
                capped.service_principal = service;
                Self(Arc::new(capped), true)
            }
            None if service => Self(Arc::new(ctx.as_service_principal()), false),
            None => Self(ctx, false),
        }
    }

    /// True when the context was narrowed by an entity ceiling (D-766).
    pub fn is_capped(&self) -> bool {
        self.1
    }

    /// Borrows the wrapped context. For middleware only — a handler should
    /// name a policy via [`Authorized<P>`] instead.
    pub fn get(&self) -> &SecurityContext {
        &self.0
    }

    /// Clones the shared handle (an `Arc` bump, not a deep copy). For
    /// middleware only, same as [`Self::get`].
    pub fn to_inner(&self) -> Arc<SecurityContext> {
        Arc::clone(&self.0)
    }
}

/// The slice of the request the extractor resolves on a policy's behalf.
///
/// Deliberately thin. The extractor runs before the handler and must stay
/// cheap and infallible-in-the-safe-direction, so it reads exactly one matched
/// path segment — never the body, the query string, or the database. A policy
/// that needs more than this belongs in the handler.
#[derive(Debug, Clone, Copy)]
pub struct PolicyScope<'a> {
    /// Value of the path parameter named by
    /// [`AuthorizationPolicy::PATH_PARAM`], percent-decoded by axum's router.
    ///
    /// `None` when the policy named no parameter, **or** when the matched
    /// route has no segment by that name. A policy that needs the value must
    /// treat `None` as a refusal: the alternative is a route mounted on a path
    /// the policy cannot see, silently admitting everyone.
    pub path_param: Option<&'a str>,
}

/// An authorization rule decided from the resolved context plus, at most, one
/// matched path segment (see [`PolicyScope`]).
///
/// Implementors are zero-sized marker types used only as the `P` in
/// [`Authorized<P>`]. `NAME` is used in the `Forbidden` rejection's log line so
/// an operator can tell *which* gate refused, not merely that one did.
pub trait AuthorizationPolicy {
    /// Human-readable policy name for diagnostics (e.g. `"admin"`).
    const NAME: &'static str;

    /// Path parameter this policy authorizes against, if it needs one — the
    /// bare name as it appears in the route pattern, so `"entity"` for
    /// `/api/v1/{entity}/{id}`.
    ///
    /// `None` (the default) means the extractor performs no path lookup at
    /// all, which is the right answer for every policy decidable from the
    /// context alone.
    const PATH_PARAM: Option<&'static str> = None;

    /// Whether a ceiling-narrowed (D-766) caller may pass this policy. `false`
    /// for a policy whose routes decide visibility from something other than
    /// the context's entity privileges — the ceiling could not bind them.
    const ALLOW_CAPPED: bool = true;

    /// Returns `Ok(())` iff `ctx` satisfies this policy. Must fail closed,
    /// including when `scope.path_param` is `None` but the policy needs it.
    fn authorize(ctx: &SecurityContext, scope: PolicyScope<'_>) -> Result<(), AppError>;
}

/// Extracted caller identity, proven to satisfy policy `P`.
///
/// Derefs to [`SecurityContext`], so a converted handler body keeps working
/// unchanged: `ctx.user_id`, `ctx.is_admin`, `&ctx` passed where
/// `&SecurityContext` is expected, and `ctx.require(entity, action)` through
/// `xrm_security::SecurityContextExt` all resolve by auto-deref.
///
/// Deliberately does **not** implement `Clone`: `ctx.clone()` in a converted
/// handler must keep meaning `SecurityContext::clone` (via deref), not silently
/// produce another `Authorized<P>` and change an inferred type downstream.
pub struct Authorized<P: AuthorizationPolicy> {
    ctx: Arc<SecurityContext>,
    capped: bool,
    _policy: PhantomData<P>,
}

/// Hand-written rather than derived: `#[derive(Debug)]` would add a spurious
/// `P: Debug` bound, forcing every zero-sized policy marker to derive `Debug`
/// purely to satisfy a bound the output never uses.
impl<P: AuthorizationPolicy> std::fmt::Debug for Authorized<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authorized")
            .field("policy", &P::NAME)
            .field("user_id", &self.ctx.user_id)
            .field("is_admin", &self.ctx.is_admin)
            .finish_non_exhaustive()
    }
}

impl<P: AuthorizationPolicy> Authorized<P> {
    /// Consumes the wrapper for the call site that needs to keep the context
    /// beyond the borrow (storing it in a struct, moving it into a spawned
    /// task). Reading through `Deref` is preferred.
    pub fn into_inner(self) -> Arc<SecurityContext> {
        self.ctx
    }

    /// True when the caller's context was narrowed by an entity ceiling.
    pub fn is_capped(&self) -> bool {
        self.capped
    }

    /// D-766 containment for a handler whose work escapes the narrowed
    /// context — a job re-resolved later by user id, or a read whose
    /// visibility is computed from roles in SQL. Refuses a capped caller.
    pub fn refuse_if_capped(&self) -> Result<(), AppError> {
        if self.capped {
            tracing::warn!(
                policy = P::NAME,
                user_id = %self.ctx.user_id,
                "refused: this route cannot honour an S2S entity ceiling (D-766)"
            );
            return Err(AppError::Forbidden);
        }
        Ok(())
    }
}

impl<P: AuthorizationPolicy> Deref for Authorized<P> {
    type Target = SecurityContext;

    fn deref(&self) -> &Self::Target {
        &self.ctx
    }
}

impl<S, P> FromRequestParts<S> for Authorized<P>
where
    S: Send + Sync,
    P: AuthorizationPolicy,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Absent extension => `authz` never ran for this path. That happens
        // only if a protected route was mounted outside the standard stack, or
        // a bypass prefix was widened to cover it. Either way the safe answer
        // is 401, never "carry on without a context".
        let Some(wrapper) = parts.extensions.get::<AuthorizedContext>() else {
            tracing::error!(
                policy = P::NAME,
                path = %parts.uri.path(),
                "authorization context missing — this route did not pass through the \
                 authz middleware; check the bypass list and route composition",
            );
            return Err(AppError::Unauthorized);
        };
        // Taken before the path lookup below, which needs `parts` mutably.
        // An `Arc` bump, not a deep copy.
        let ctx = wrapper.to_inner();
        let capped = wrapper.is_capped();
        if capped && !P::ALLOW_CAPPED {
            tracing::warn!(
                policy = P::NAME,
                path = %parts.uri.path(),
                "refused: an entity-capped S2S caller cannot use this policy (D-766)"
            );
            return Err(AppError::Forbidden);
        }

        // Only policies that declared a parameter pay for this. `&()` rather
        // than `_state`: `RawPathParams`' extractor impl is state-agnostic
        // (`impl<S: Send + Sync>`) and reads the router's own match, so there
        // is nothing for `S` to contribute and nothing to plumb through.
        let params = match P::PATH_PARAM {
            None => None,
            // The error arm is `MissingPathParams` (a route with no
            // parameters at all) or `InvalidUtf8InPathParam`. Both leave
            // `path_param` `None` below, which a policy needing the value must
            // refuse — the extractor never turns a failed lookup into an
            // unchecked pass.
            Some(_) => RawPathParams::from_request_parts(parts, &()).await.ok(),
        };
        let path_param = params.as_ref().zip(P::PATH_PARAM).and_then(|(p, name)| {
            p.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value)
        });

        P::authorize(&ctx, PolicyScope { path_param })?;

        Ok(Self {
            ctx,
            capped,
            _policy: PhantomData,
        })
    }
}

// ── Policies ────────────────────────────────────────────────────────────────

/// Requires the reserved `system.admin` privilege.
///
/// Self-enforcing: replaces a handler's `ctx.require_admin()?` line entirely.
/// The `is_admin` field is computed by the resolver from the same
/// `system.admin` privilege key `xrm_security::ADMIN_PRIVILEGE_KEY` names —
/// this check is intentionally a duplicate of
/// `xrm_security::SecurityContextExt::require_admin`'s body, because the
/// extractor must live in attome-server (it owns the extension) and attome-server
/// cannot name a type or trait from xrm-security (dependency direction,
/// guidelines §1). Three lines of duplication across the layer boundary is the
/// price of not inverting that edge; the pair is locked together by
/// `admin_policy_matches_require_admin` in xrm-security's context tests.
#[derive(Debug)]
pub struct Admin;

impl AuthorizationPolicy for Admin {
    const NAME: &'static str = "admin";

    fn authorize(ctx: &SecurityContext, _scope: PolicyScope<'_>) -> Result<(), AppError> {
        if ctx.is_admin {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

/// A flat privilege key known at compile time, used as `Privilege<K>`.
///
/// For an entity name taken from the request path use [`RecordScoped<A>`],
/// which composes the key from that segment and a compile-time action verb.
/// For a key only known at runtime — `xrm_core_sql_query.required_privilege`,
/// or an entity the route does not name — use bare [`RecordScoped`] and call
/// `ctx.require_key(..)` / `ctx.require(entity, action)` in the handler.
pub trait PrivilegeKey {
    /// The `xrm_core_privilege.key` value the caller must hold.
    const KEY: &'static str;
}

/// Requires a compile-time-known flat privilege key, or admin.
///
/// Self-enforcing, same as [`Admin`]: replaces `ctx.require_key(SOME_KEY)?`.
pub struct Privilege<K: PrivilegeKey>(PhantomData<K>);

impl<K: PrivilegeKey> std::fmt::Debug for Privilege<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Privilege").finish_non_exhaustive()
    }
}

impl<K: PrivilegeKey> AuthorizationPolicy for Privilege<K> {
    const NAME: &'static str = K::KEY;

    fn authorize(ctx: &SecurityContext, _scope: PolicyScope<'_>) -> Result<(), AppError> {
        if ctx.is_admin || ctx.privileges.contains(K::KEY) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

/// Path parameter [`RecordScoped<A>`] reads the entity name from.
///
/// One name, not a per-policy knob: every entity-scoped route in this platform
/// spells that segment `{entity}` (`/api/v1/{entity}`,
/// `/api/v1/{entity}/{id}/files/{field}/download-url`, …), and a route that
/// wanted a different spelling would be the interesting thing to notice rather
/// than to configure around.
pub const ENTITY_PATH_PARAM: &str = "entity";

/// The action verb(s) a [`RecordScoped<A>`] route requires on its entity.
///
/// Implementors are zero-sized markers naming a verb known at compile time.
/// The verbs themselves are the deployment's vocabulary, not attome-server's —
/// this crate owns only the mechanism, the same way [`PrivilegeKey`] is
/// declared here and its keys are named upstream.
pub trait RecordActionKind {
    /// Every verb the caller must hold for the route's entity; **all** are
    /// required, so `["create", "update"]` means create *and* update.
    ///
    /// Empty means the verb is only knowable at runtime — see [`Dynamic`].
    const ACTIONS: &'static [&'static str];
}

/// The verb is only knowable at runtime, so the handler still owns the check.
///
/// This is bare [`RecordScoped`]'s parameter, and it is the *declaration*
/// half of the policy: the extractor admits every authenticated caller, and
/// the handler remains responsible for its `ctx.require(entity, action)?`
/// call. Correct where the entity is not a path segment at all
/// (`query_exec::execute` resolves it from the stored query) — and a smell
/// anywhere else, which is why the route census counts these and ratchets the
/// count downward.
#[derive(Debug)]
pub struct Dynamic;

impl RecordActionKind for Dynamic {
    const ACTIONS: &'static [&'static str] = &[];
}

/// The route authorizes against the entity named by its `{entity}` path
/// segment, for the compile-time action verb(s) `A` (D-353, amending D-300).
///
/// **Self-enforcing whenever `A` names a verb.** The extractor reads the
/// matched `{entity}` segment and performs `ctx.require(entity, action)` for
/// each of `A::ACTIONS`, so the handler's own `require` line is the extractor
/// and cannot be forgotten. What it does *not* cover, and what the handler
/// still owns:
///
/// - **Record-level scope.** Holding `account.read` is not permission to read
///   *this* account row; `xrm_security::rls` / `require_record_access` decide
///   that, and they need the database.
/// - **Runtime-varying verbs.** `bulk::enqueue` requires `{entity}.bulk`
///   statically *and* `{entity}.{body.operation}` from the request body. The
///   static half moves here; the body-dependent half cannot.
/// - **Conditional gates.** `upsert_record` additionally requires admin only
///   when it would provision a new index; `query_exec::execute` only for a
///   stored query with no `required_privilege`. A policy is a property of the
///   whole handler — a check inside a branch is not one (D-300).
///
/// The `{entity}` segment is used verbatim. That is sound because every
/// consumer resolves the entity by exact logicalname
/// (`EntityMetaRegistry::get`, or `WHERE logicalname = $1`), so a request that
/// resolves at all resolves to the name the caller typed. The one visible
/// difference is for an entity that does not exist: the extractor now answers
/// 403 before the handler's lookup answers 404, which is the safer of the two
/// and stops an unprivileged caller enumerating the metadata by probing.
pub struct RecordScoped<A: RecordActionKind = Dynamic>(PhantomData<A>);

impl<A: RecordActionKind> std::fmt::Debug for RecordScoped<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordScoped").finish_non_exhaustive()
    }
}

impl<A: RecordActionKind> AuthorizationPolicy for RecordScoped<A> {
    const NAME: &'static str = "record-scoped";

    // `Dynamic` skips the lookup entirely rather than resolving a segment
    // nothing will read.
    const PATH_PARAM: Option<&'static str> = if A::ACTIONS.is_empty() {
        None
    } else {
        Some(ENTITY_PATH_PARAM)
    };

    fn authorize(ctx: &SecurityContext, scope: PolicyScope<'_>) -> Result<(), AppError> {
        if A::ACTIONS.is_empty() {
            return Ok(());
        }

        // Reached when a `RecordScoped<A>` handler is mounted on a route with
        // no `{entity}` segment. Refusing is the only safe answer — admitting
        // would make the policy a decoration on exactly the route that got it
        // wrong — and it is loud, because it is a composition bug, not traffic.
        let Some(entity) = scope.path_param else {
            tracing::error!(
                policy = Self::NAME,
                param = ENTITY_PATH_PARAM,
                "route has no {{{ENTITY_PATH_PARAM}}} path segment for its RecordScoped policy \
                 to authorize against; the route pattern and the handler's policy disagree",
            );
            return Err(AppError::Forbidden);
        };

        if ctx.is_admin {
            return Ok(());
        }
        for action in A::ACTIONS {
            // Intentionally the same three lines as
            // `xrm_security::SecurityContextExt::require`, for the same reason
            // `Admin` duplicates `require_admin`: the extractor must live in
            // attome-server (it owns the extension) and attome-server cannot name a
            // trait from xrm-security (guidelines §1). The pair is locked
            // together by `record_scoped_policy_matches_require` in
            // xrm-security's context tests.
            if !ctx.privileges.contains(&format!("{entity}.{action}")) {
                return Err(AppError::Forbidden);
            }
        }
        Ok(())
    }
}

/// The route is authenticated-only by design: it acts on the caller's own
/// account and there is no further privilege to check.
///
/// **Declaration, not enforcement.** Legitimate uses are narrow — reading your
/// own resolved context (`whoami`), your own MFA enrolment, your own API keys,
/// your own sidebar (which filters its rows by the caller's privileges rather
/// than gating the route). Anything acting on *another* principal's data wants
/// [`Admin`] or [`RecordScoped<A>`] instead.
#[derive(Debug)]
pub struct SelfService;

impl AuthorizationPolicy for SelfService {
    const NAME: &'static str = "self-service";
    // Search, graph, knowledge, saved searches, AI conversations and the
    // sidebar sit behind this policy and compute visibility from the user's
    // roles, not the narrowed context (D-766).
    const ALLOW_CAPPED: bool = false;

    fn authorize(_ctx: &SecurityContext, _scope: PolicyScope<'_>) -> Result<(), AppError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use axum::http::Request;
    use uuid::Uuid;

    use super::*;

    fn ctx(is_admin: bool, privileges: &[&str]) -> SecurityContext {
        SecurityContext {
            user_id: Uuid::now_v7(),
            is_admin,
            privileges: privileges.iter().map(|p| (*p).to_owned()).collect(),
            field_grants: HashSet::new(),
            field_write_grants: HashSet::new(),
            bulk_fields: Default::default(),
            epoch: 0,
            accessible_org_ids: Vec::new(),
            team_ids: Vec::new(),
            position_hierarchy_enabled: false,
            subordinate_user_ids: Vec::new(),
            condition_grants: HashMap::new(),
            role_ids: None,
            service_principal: false,
        }
    }

    /// D-791 rule 3: only a cookie session is interactive; an API-key or S2S
    /// request's context is marked a service principal, capped or not, and
    /// the resolved (cached) context itself is never changed.
    #[test]
    fn for_request_marks_every_non_cookie_caller_a_service_principal() {
        let resolved = Arc::new(ctx(false, &["account.read"]));

        let mut cookie = axum::http::Extensions::new();
        cookie.insert(crate::middleware::auth::CookieSession);
        let interactive = AuthorizedContext::for_request(&cookie, Arc::clone(&resolved));
        assert!(!interactive.get().service_principal);

        let api_key =
            AuthorizedContext::for_request(&axum::http::Extensions::new(), Arc::clone(&resolved));
        assert!(api_key.get().service_principal);
        assert_eq!(api_key.get().privileges, resolved.privileges);

        let mut s2s = axum::http::Extensions::new();
        s2s.insert(crate::security::EntityCeiling::new([
            "account.read".to_owned()
        ]));
        let capped = AuthorizedContext::for_request(&s2s, Arc::clone(&resolved));
        assert!(capped.is_capped());
        assert!(capped.get().service_principal);

        assert!(
            !resolved.service_principal,
            "the cached context is untouched"
        );
    }

    struct SidebarManage;
    impl PrivilegeKey for SidebarManage {
        const KEY: &'static str = "sidebar.manage";
    }

    struct Read;
    impl RecordActionKind for Read {
        const ACTIONS: &'static [&'static str] = &["read"];
    }

    struct CreateAndUpdate;
    impl RecordActionKind for CreateAndUpdate {
        const ACTIONS: &'static [&'static str] = &["create", "update"];
    }

    async fn extract<P: AuthorizationPolicy>(
        context: Option<SecurityContext>,
    ) -> Result<Authorized<P>, AppError> {
        let mut req = Request::builder().uri("/api/v1/admin/x").body(()).unwrap();
        if let Some(c) = context {
            req.extensions_mut()
                .insert(AuthorizedContext::new(Arc::new(c)));
        }
        let (mut parts, _) = req.into_parts();
        Authorized::<P>::from_request_parts(&mut parts, &()).await
    }

    async fn extract_capped<P: AuthorizationPolicy>(
        context: SecurityContext,
        ceiling: &[&str],
    ) -> Result<Authorized<P>, AppError> {
        let mut extensions = axum::http::Extensions::new();
        extensions.insert(crate::security::EntityCeiling::new(
            ceiling.iter().map(|k| (*k).to_owned()),
        ));
        let mut req = Request::builder().uri("/api/v1/admin/x").body(()).unwrap();
        req.extensions_mut().insert(AuthorizedContext::for_request(
            &extensions,
            Arc::new(context),
        ));
        let (mut parts, _) = req.into_parts();
        Authorized::<P>::from_request_parts(&mut parts, &()).await
    }

    // ── D-766 entity ceiling ────────────────────────────────────────────────

    #[tokio::test]
    async fn a_capped_caller_is_refused_on_self_service() {
        let got =
            extract_capped::<SelfService>(ctx(false, &["account.read"]), &["account.read"]).await;
        assert!(matches!(got, Err(AppError::Forbidden)), "{got:?}");
    }

    #[tokio::test]
    async fn a_capped_caller_passes_a_privilege_policy_inside_its_ceiling() {
        let got = extract_capped::<Privilege<SidebarManage>>(
            ctx(false, &["sidebar.manage", "account.read"]),
            &["contact.read"],
        )
        .await
        .expect("a non-entity privilege is outside the ceiling's concern");
        assert!(got.is_capped());
        assert!(
            !got.privileges.contains("account.read"),
            "narrowed by the ceiling"
        );
        assert!(matches!(got.refuse_if_capped(), Err(AppError::Forbidden)));
    }

    #[tokio::test]
    async fn an_uncapped_caller_is_not_marked_capped() {
        let got = extract::<SelfService>(Some(ctx(false, &[])))
            .await
            .expect("self-service");
        assert!(!got.is_capped());
        assert!(got.refuse_if_capped().is_ok());
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn admin_policy_admits_an_admin() {
        let got = extract::<Admin>(Some(ctx(true, &[]))).await;
        assert!(got.is_ok(), "an admin must satisfy Admin: {got:?}");
    }

    #[tokio::test]
    async fn admin_policy_rejects_a_non_admin() {
        let got = extract::<Admin>(Some(ctx(false, &["account.read"]))).await;
        assert!(
            matches!(got, Err(AppError::Forbidden)),
            "a non-admin must be Forbidden, got {got:?}"
        );
    }

    /// The whole point of the module: the check is the extractor, so a handler
    /// body never runs for an unauthorized caller regardless of what it does or
    /// forgets to do.
    #[tokio::test]
    async fn admin_policy_denies_before_any_handler_body_could_run() {
        assert!(extract::<Admin>(Some(ctx(false, &[]))).await.is_err());
    }

    // ── Privilege<K> ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn privilege_policy_admits_the_exact_key() {
        let got = extract::<Privilege<SidebarManage>>(Some(ctx(false, &["sidebar.manage"]))).await;
        assert!(got.is_ok(), "holding the key must admit: {got:?}");
    }

    #[tokio::test]
    async fn privilege_policy_rejects_a_different_key() {
        let got = extract::<Privilege<SidebarManage>>(Some(ctx(false, &["sidebar.read"]))).await;
        assert!(matches!(got, Err(AppError::Forbidden)));
    }

    #[tokio::test]
    async fn privilege_policy_admits_an_admin_without_the_key() {
        let got = extract::<Privilege<SidebarManage>>(Some(ctx(true, &[]))).await;
        assert!(got.is_ok(), "admin short-circuits every key: {got:?}");
    }

    // ── Declaration-only policies ───────────────────────────────────────────

    #[tokio::test]
    async fn declaration_policies_admit_any_authenticated_caller() {
        assert!(extract::<RecordScoped>(Some(ctx(false, &[]))).await.is_ok());
        assert!(
            extract::<RecordScoped<Dynamic>>(Some(ctx(false, &[])))
                .await
                .is_ok(),
            "bare RecordScoped and RecordScoped<Dynamic> are the same policy"
        );
        assert!(extract::<SelfService>(Some(ctx(false, &[]))).await.is_ok());
    }

    // ── RecordScoped<A> ─────────────────────────────────────────────────────

    /// A parameterised policy on a route with no `{entity}` segment cannot
    /// authorize anything, so it must refuse. Admitting would leave the
    /// decoration on precisely the route whose composition is wrong.
    #[tokio::test]
    async fn record_scoped_refuses_when_the_route_has_no_entity_segment() {
        // `extract` builds bare `Parts` — no router match, so no path params.
        let got = extract::<RecordScoped<Read>>(Some(ctx(false, &["account.read"]))).await;
        assert!(
            matches!(got, Err(AppError::Forbidden)),
            "an unresolvable entity segment must be Forbidden, got {got:?}"
        );
    }

    /// Even an admin: the composition is broken either way, and quietly
    /// admitting the one caller who would have passed anyway is how the bug
    /// survives to reach a non-admin.
    #[tokio::test]
    async fn record_scoped_refuses_an_admin_when_the_route_has_no_entity_segment() {
        let got = extract::<RecordScoped<Read>>(Some(ctx(true, &[]))).await;
        assert!(matches!(got, Err(AppError::Forbidden)), "got {got:?}");
    }

    // ── Missing context fails closed ────────────────────────────────────────

    /// A protected route that never passed through `authz` must 401, not admit
    /// an unauthenticated caller. Covers every policy including the
    /// declaration-only ones, which would otherwise be the easy hole: they
    /// return `Ok(())` from `authorize`, so the guard has to be the absent
    /// extension itself.
    #[tokio::test]
    async fn a_missing_context_is_unauthorized_for_every_policy() {
        assert!(matches!(
            extract::<Admin>(None).await,
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            extract::<Privilege<SidebarManage>>(None).await,
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            extract::<RecordScoped>(None).await,
            Err(AppError::Unauthorized)
        ));
        // Unauthorized, not Forbidden: "no context at all" outranks "cannot
        // resolve the entity segment", so a route mounted outside the authz
        // stack still reports the reason an operator can act on.
        assert!(matches!(
            extract::<RecordScoped<Read>>(None).await,
            Err(AppError::Unauthorized)
        ));
        assert!(matches!(
            extract::<SelfService>(None).await,
            Err(AppError::Unauthorized)
        ));
    }

    // ── Deref ergonomics ────────────────────────────────────────────────────

    #[tokio::test]
    async fn authorized_derefs_to_the_underlying_context() {
        let c = ctx(true, &["account.read"]);
        let user_id = c.user_id;
        let authorized = extract::<Admin>(Some(c)).await.expect("admin");

        // Field access through Deref, and `&Authorized<P>` coercing to
        // `&SecurityContext` — the two shapes every converted handler relies on.
        assert_eq!(authorized.user_id, user_id);
        assert!(authorized.is_admin);
        fn takes_ctx(c: &SecurityContext) -> bool {
            c.privileges.contains("account.read")
        }
        assert!(takes_ctx(&authorized));
        assert_eq!(authorized.into_inner().user_id, user_id);
    }

    // ── RecordScoped<A> against a real router ───────────────────────────────
    //
    // The unit tests above drive `from_request_parts` on hand-built `Parts`,
    // which can never carry a router match — so they can only ever prove the
    // *refusal* half. Resolving `{entity}` needs axum to have actually matched
    // the route, and the private `UrlParams` extension it writes cannot be
    // inserted by hand. These drive the composed service instead.
    //
    // Every handler below has **no body**: it returns 200 and reads nothing.
    // That is the property under test. Before this change these handlers would
    // have been the bug — `Authorized<RecordScoped>` admitted everyone and the
    // `ctx.require(...)` line that did the work lived in the body. A test whose
    // handler still performed its own check would pass for the wrong reason.

    mod router {
        use axum::body::Body;
        use axum::http::StatusCode;
        use axum::routing::get;
        use axum::{Extension, Router};
        use tower::ServiceExt;

        use super::*;

        /// Emptied on purpose — see the module comment above.
        async fn read_handler(_ctx: Authorized<RecordScoped<Read>>) -> StatusCode {
            StatusCode::OK
        }

        async fn create_and_update_handler(
            _ctx: Authorized<RecordScoped<CreateAndUpdate>>,
        ) -> StatusCode {
            StatusCode::OK
        }

        fn app(context: SecurityContext) -> Router {
            Router::new()
                .route("/api/v1/{entity}/{id}", get(read_handler))
                .route("/api/v1/{entity}/upsert", get(create_and_update_handler))
                // A parameterised policy on a route that names no `{entity}`.
                .route("/api/v1/no-entity", get(read_handler))
                // Stands in for `middleware::auth::authz`, which is what
                // attaches this in the real stack.
                .layer(Extension(AuthorizedContext::new(Arc::new(context))))
        }

        async fn status(context: SecurityContext, uri: &str) -> StatusCode {
            app(context)
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .expect("router is infallible")
                .status()
        }

        /// The headline guarantee: the handler does nothing, and the caller is
        /// still refused for want of `account.read`.
        #[tokio::test]
        async fn an_emptied_handler_still_refuses_a_caller_without_the_privilege() {
            let uri = "/api/v1/account/0192f0c0-0000-7000-8000-000000000000";
            assert_eq!(
                status(ctx(false, &[]), uri).await,
                StatusCode::FORBIDDEN,
                "no privileges at all"
            );
            assert_eq!(
                status(ctx(false, &["account.update"]), uri).await,
                StatusCode::FORBIDDEN,
                "the wrong action on the right entity"
            );
            assert_eq!(
                status(ctx(false, &["contact.read"]), uri).await,
                StatusCode::FORBIDDEN,
                "the right action on a different entity — the segment is what \
                 picks the key, so this is the case a hardcoded key would miss"
            );
        }

        #[tokio::test]
        async fn the_matching_privilege_admits_and_admin_short_circuits() {
            let uri = "/api/v1/account/0192f0c0-0000-7000-8000-000000000000";
            assert_eq!(
                status(ctx(false, &["account.read"]), uri).await,
                StatusCode::OK
            );
            assert_eq!(status(ctx(true, &[]), uri).await, StatusCode::OK);
        }

        /// `ACTIONS` is a conjunction. Holding one of a multi-verb policy's
        /// verbs is not holding the policy — upsert genuinely writes both ways.
        #[tokio::test]
        async fn a_multi_action_policy_requires_every_action() {
            let uri = "/api/v1/account/upsert";
            assert_eq!(
                status(ctx(false, &["account.create"]), uri).await,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                status(ctx(false, &["account.update"]), uri).await,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                status(ctx(false, &["account.create", "account.update"]), uri).await,
                StatusCode::OK
            );
        }

        /// The entity name comes from the segment, so a caller cannot reach a
        /// second entity with the first one's grant.
        #[tokio::test]
        async fn the_privilege_is_keyed_to_the_matched_segment() {
            let ctx_read_account = || ctx(false, &["account.read"]);
            assert_eq!(
                status(
                    ctx_read_account(),
                    "/api/v1/account/0192f0c0-0000-7000-8000-000000000000"
                )
                .await,
                StatusCode::OK
            );
            assert_eq!(
                status(
                    ctx_read_account(),
                    "/api/v1/contact/0192f0c0-0000-7000-8000-000000000000"
                )
                .await,
                StatusCode::FORBIDDEN
            );
        }

        /// Composition bug, not traffic: the route pattern and the handler's
        /// policy disagree, and the only safe answer is to refuse.
        #[tokio::test]
        async fn a_route_without_an_entity_segment_refuses_everyone() {
            assert_eq!(
                status(ctx(false, &["account.read"]), "/api/v1/no-entity").await,
                StatusCode::FORBIDDEN
            );
            assert_eq!(
                status(ctx(true, &[]), "/api/v1/no-entity").await,
                StatusCode::FORBIDDEN
            );
        }

        /// Percent-encoding is axum's job, and it does it before we see the
        /// value — so the key built here is the decoded name, not the raw
        /// segment. Pinned because a caller who could pick which of the two
        /// gets used would pick the one they hold.
        #[tokio::test]
        async fn the_segment_is_percent_decoded_before_the_key_is_built() {
            let uri = "/api/v1/my%20entity/0192f0c0-0000-7000-8000-000000000000";
            assert_eq!(
                status(ctx(false, &["my entity.read"]), uri).await,
                StatusCode::OK
            );
            assert_eq!(
                status(ctx(false, &["my%20entity.read"]), uri).await,
                StatusCode::FORBIDDEN
            );
        }
    }
}
