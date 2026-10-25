//! Account disable/enable (P-account-state-enforcement, audit finding #2).
//! Makes "disable a user" actually stick: revokes every refresh token the
//! account holds, invalidates its cached SecurityContext (fan-out to every
//! node via the security_version doorbell, same as a grant/revoke), and
//! records the change in the audit ledger. Does NOT denylist the user's
//! currently-live access-token jtis — the server has no session registry to
//! enumerate them from. A live 15-minute access token therefore keeps working
//! until it naturally expires, UNLESS the request hits one of the
//! privileged/admin-gated bundles behind `strict_authz` (P-authz-revocation-
//! epoch, D-116), which re-checks the live epoch on every call regardless of
//! TTL — closed for that class, not just documented as a gap. For every other
//! (ordinary) route the worst case remains the 60s cache TTL, D-012.

use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_server::security::SecurityContext;
use attome_types::AppError;
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
};
use uuid::Uuid;

use crate::context::SecurityContextExt;
use attome_types::ErrorResponse;

async fn set_user_active(
    state: &EngineState,
    ctx: &SecurityContext,
    target_user_id: Uuid,
    active: bool,
) -> Result<StatusCode, AppError> {
    ctx.require_admin()?;

    // An admin who could lock themselves out of the platform is a support
    // incident waiting to happen — refuse it outright rather than trusting
    // "the admin meant to do that" (§8 of the plan).
    if !active && target_user_id == ctx.user_id {
        return Err(AppError::Validation(
            "cannot disable your own account".into(),
        ));
    }

    let mut tx = attome_db::tx::begin(&state.base.db).await?;

    // Resolve the target's current email, and take the same
    // namespaced advisory lock register/link_google_account/
    // link_external_identity take (attome_auth::email_identity, D-121 extends
    // D-113) — serializes this disable/enable against a concurrent
    // registration or federation login racing the same email, so neither side
    // can observe a pre-write snapshot of the other. A target with no email
    // (shouldn't happen for a real user_account row, but the column is
    // nullable) skips the lock — there is no email identity to race on.
    let target: Option<Option<String>> =
        sqlx::query_scalar("SELECT email FROM user_account WHERE id = $1")
            .bind(target_user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    let Some(target_email) = target else {
        return Err(AppError::NotFound);
    };
    if let Some(email) = &target_email
        && !attome_auth::email_identity::try_lock_email(&mut tx, email).await?
    {
        return Err(AppError::Conflict(
            "account email is involved in a concurrent operation, retry",
        ));
    }

    let updated: Option<Uuid> =
        sqlx::query_scalar("UPDATE user_account SET is_active = $1 WHERE id = $2 RETURNING id")
            .bind(active)
            .bind(target_user_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(AppError::internal)?;
    if updated.is_none() {
        return Err(AppError::NotFound);
    }

    // Phase 2 (D-113 design, wired here per D-121's corrected sequencing):
    // bump auth_epoch inside the SAME transaction as the is_active flip and
    // its audit row — a disable that commits its is_active flip but crashes
    // before bumping the epoch would leave a stale-but-still-epoch-valid
    // token workable until the refresh-revocation/authz-cache paths catch
    // it; keeping both in one transaction means either both land or neither
    // does. Only bumped on disable — re-enabling a user does not need to
    // invalidate its own still-live tokens (there are none; the account was
    // disabled), but re-enable also bumps for symmetry: a token issued
    // *while* the account was disabled cannot exist, but bumping here keeps
    // the invariant "every state transition bumps the epoch" simple to
    // reason about rather than special-casing one direction.
    let new_epoch = attome_auth::epoch::bump_in_tx(&mut tx, target_user_id).await?;

    // D-121 (extends D-113 review item 6): disabling a user through this
    // admin endpoint is a termination-style action, not a temporary
    // suspend — there is no separate "suspend" endpoint on this platform
    // today, so this is the only meaning "disable" has. Re-enabling does
    // NOT restore previously-disabled keys (an operator who wants a
    // terminated integration back must issue a new key) — without this, a
    // disable/enable cycle would silently un-revoke every API key the user
    // ever created, which is not bounded by any cache TTL (unlike the
    // authn/authz paths above) and was the review's own point: it is
    // indefinite, not a cache window.
    if !active {
        sqlx::query(
            "UPDATE api_key SET is_active = false WHERE user_ref = $1 AND is_active = true",
        )
        .bind(target_user_id)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }

    // Audit plan 3.3: written through the mandatory security writer, in the
    // same transaction as the flip, the epoch bump and the key revocation.
    write_security_event(
        &mut tx,
        &attome_audit::audit_service(state),
        SecurityEvent::new(
            MandatoryCategory::Security,
            if active {
                AuditOperation::AccountEnabled
            } else {
                AuditOperation::AccountDisabled
            },
            ctx.user_id,
            "user_account",
            Some(target_user_id),
        )
        .named(if active {
            "account_enabled"
        } else {
            "account_disabled"
        })
        .comment(if active {
            "administrator re-enabled a user account"
        } else {
            "administrator disabled a user account"
        }),
    )
    .await?;

    // P-session-refresh-hardening (D-129) closed the residual window where a
    // live 15-minute access token kept working after disable, by wiring
    // auth_epoch into SessionClaims/authn so a stale token is now rejected
    // sub-second instead of surviving to its natural exp — but that's a
    // token-validation change, not a second bump here: the unconditional
    // `bump_in_tx` call above (D-113/D-121's original design, already inside
    // this same transaction) already covers disable. A second call here
    // double-bumped auth_epoch by 2 on every disable instead of 1 — found via
    // account_disable.rs's disable_bumps_epoch_and_revokes_api_keys_enable_does_not_restore_keys
    // test, never reached by CI until this session. No live token could ever
    // have carried the skipped intermediate value (attome_auth::epoch::check
    // rejects on exact inequality, `claimed_epoch != current` — any epoch a
    // token was actually issued with before this call is still != whatever
    // the new value is, doubled or not), so this never under-invalidated;
    // it just violated the documented "bumps exactly once" invariant, burned
    // an extra UPDATE every disable, and even logged the wrong value (the
    // discarded second call's return was never assigned to `new_epoch`
    // below, so the info! log already showed the pre-second-bump number even
    // before this fix — the clearest sign this call was never intentional).

    tx.commit().await.map_err(AppError::internal)?;

    if !active {
        // Existing machinery only (per plan §4c) — no new subsystem.
        attome_auth::refresh::revoke_all_for_user(&state.base.db, target_user_id).await?;
        attome_auth::epoch::invalidate_cache(&state.base.redis, target_user_id).await;
    }
    state.base.security.invalidate_sync(target_user_id).await?;
    // Drop the cached auth_epoch (attome_auth::epoch, Phase 2/D-121) so the
    // next request re-reads Postgres immediately instead of serving the
    // pre-bump value for up to CACHE_TTL_SECS — commit-then-invalidate,
    // same ordering as SecurityResolver::invalidate_sync above (never
    // invalidate before the bump is durable).
    attome_auth::epoch::invalidate_cache(&state.base.redis_coordination, target_user_id).await;

    tracing::info!(
        user_id = %target_user_id,
        admin_id = %ctx.user_id,
        active,
        new_epoch,
        "admin changed a user's account-active state"
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Disable a user
///
/// `Authorized<Admin>` rather than the delegate's own `require_admin()` doing
/// all the work: `set_user_active` still performs that check (it is also
/// reachable from other callers), but the gate now also holds at this route's
/// own boundary, where it is visible to a reviewer reading the handler alone.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/users/{id}/disable",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The user")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::AccountDisabled)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn disable_user(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    set_user_active(&state, &ctx, user_id, false).await
}

/// Enable a user
///
/// Lets a disabled user sign in again. Administrators only; audited.
#[utoipa::path(
    post,
    path = "/api/v1/admin/security/users/{id}/enable",
    tag = "admin-security",
    params(("id" = Uuid, Path, description = "The user")),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Security, AuditOperation::AccountEnabled)])))),
    responses(
        (status = 204, description = "Success"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 409, description = "The account email is held by a concurrent operation, retry", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn enable_user(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    set_user_active(&state, &ctx, user_id, true).await
}

pub(super) fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/security/users/{id}/disable",
            post(disable_user),
        )
        .route(
            "/api/v1/admin/security/users/{id}/enable",
            post(enable_user),
        )
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(disable_user, enable_user))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
