//! The audit-side view of "who is acting": the `AuditUserContext` and
//! organization every `AuditEvent` carries, resolved from
//! `user_account` through `EngineState`'s 60s `audit_users` L1 cache.
//!
//! Lived in `attome-server::entity_crud::access` until ARCH-5
//! (PLATFORM-REVIEW-2026-08-24), when the compliance route bundles that call
//! it moved into `attome-compliance` and could no longer reach it without an
//! `attome-compliance -> attome-server` reverse edge. It is a shared primitive of
//! the same class as `attome_core::crud` (ARCH-1a-i): every crate that
//! writes an `AuditEvent` for a user-initiated action needs it, and nothing
//! about it is entity-CRUD-specific — so it belongs beside the event type it
//! populates.

use attome_cache::HotCache;
use attome_core::{AuditUserInfo, EngineState};
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    AuditCategory, AuditEvent, AuditOperation, AuditRequestContext, AuditService, AuditSource,
    AuditUserContext,
};

#[derive(sqlx::FromRow)]
struct UserRow {
    user_name: Option<String>,
    email: Option<String>,
    organization_ref: Option<Uuid>,
}

/// Fetches user name, email, and org from user_account — through the 60s
/// L1 moka cache on EngineState (ex-audit-finding #43: these denormalized display
/// fields were re-queried on every create/update/delete). Never fails —
/// returns empty strings and nil UUID if the user isn't found.
///
/// A *database error* is not "user not found" (B15): the degraded context it
/// yields is still used for this one event, but it is never written into
/// `audit_users`, so a transient pool timeout cannot pin an empty name onto
/// every audit row the caller writes for the next 60 seconds.
pub async fn fetch_audit_ctx(state: &EngineState, user_id: Uuid) -> (AuditUserContext, Uuid) {
    fetch_audit_ctx_with(&state.base.db, &state.audit_users, user_id).await
}

/// Builds the `AuditService` every business-event/lifecycle audit write
/// site needs — pulled out as the one canonical copy (M26 R-15) of what used
/// to be a byte-identical constructor duplicated across a dozen call sites.
pub fn audit_service(state: &EngineState) -> AuditService<'_> {
    AuditService::new(&state.base.db, state.audit_signer.as_deref())
        .with_ingest_capture(state.base.config.audit.ingest_capture_enabled)
        .with_chainer_enabled(state.base.config.audit.chainer_enabled)
        .with_erasure_key(state.audit_erasure_key.clone())
}

/// Writes one `BusinessEvent`-category `AuditEvent` for a user-initiated
/// business-action transition (a lifecycle step, an approval decision, a
/// decision execution, ...) — the shared body every such call site used to
/// duplicate (M26 R-15, `lifecycle.rs::write_lifecycle_audit` was the first of
/// four byte-for-byte copies).
///
/// Same known-gap posture every copy shared: not atomic with the caller's own
/// commit (a separate round trip), logged rather than failing the caller's
/// response when it can't be written.
#[allow(clippy::too_many_arguments)]
pub async fn write_business_event(
    state: &EngineState,
    entity_name: &str,
    record_id: Uuid,
    operation: AuditOperation,
    event_name: &str,
    actor_id: Uuid,
    version_before: Option<i64>,
    version_after: Option<i64>,
    comment: String,
) {
    let (user_ctx, organization_ref) = fetch_audit_ctx(state, actor_id).await;
    let event = AuditEvent {
        organization_ref,
        category: AuditCategory::BusinessEvent,
        entity_name: Some(entity_name.to_string()),
        record_id: Some(record_id),
        operation,
        version_before,
        version_after,
        user_context: user_ctx,
        changed_on: Utc::now(),
        source: AuditSource::Api,
        request_context: AuditRequestContext::default(),
        correlation_id: None,
        batch_id: None,
        event_name: Some(event_name.to_string()),
        event_comment: Some(comment),
        changed_fields: vec![],
        snapshot_json: None,
    };
    if let Err(e) = audit_service(state).write(event).await {
        tracing::error!(
            entity_name,
            record_id = %record_id,
            error = %e,
            "failed to write business event audit event",
        );
    }
}

/// The pool-and-cache half of [`fetch_audit_ctx`], split out so the
/// error-path contract can be tested against a dead pool without building
/// an `EngineState` (which needs Redis and object storage).
async fn fetch_audit_ctx_with(
    db: &PgPool,
    cache: &HotCache<AuditUserInfo>,
    user_id: Uuid,
) -> (AuditUserContext, Uuid) {
    let cache_key = attome_core::audit_user_cache_key(user_id);
    // OPS-2: `hot_cache_lookups_total{cache="audit_users"}`. A miss here is a
    // Postgres round trip on the mutation path, so the hit rate is the signal
    // that this cache is still earning its place.
    let info = match attome_cache::get_recorded(cache, &cache_key, "audit_users").await {
        Some(hit) => hit,
        None => {
            let row: Result<Option<UserRow>, sqlx::Error> = sqlx::query_as(
                "SELECT user_name, email, organization_ref FROM user_account WHERE id = $1",
            )
            .bind(user_id)
            .fetch_optional(db)
            .await;

            match row {
                Ok(row) => {
                    // A genuine miss (unknown user) is a stable fact worth
                    // caching; only a successful lookup reaches this insert.
                    let info = row
                        .map(|r| AuditUserInfo {
                            user_name: r.user_name,
                            email: r.email,
                            organization_ref: r.organization_ref,
                        })
                        .unwrap_or_default();
                    cache.insert(cache_key, info.clone()).await;
                    info
                }
                Err(e) => {
                    // sqlx's Display never includes the DSN or credentials;
                    // it is the pool/driver error class plus the server
                    // message.
                    tracing::warn!(
                        %user_id,
                        error = %e,
                        "audit user lookup failed; this event gets a degraded audit context and \
                         the failure is not cached"
                    );
                    AuditUserInfo::default()
                }
            }
        }
    };

    let user_ctx = AuditUserContext {
        user_id,
        user_name: info.user_name.clone().unwrap_or_default(),
        user_display_name: info.user_name.unwrap_or_default(),
        user_email: info.email.unwrap_or_default(),
        user_job_ref: None,
        user_job_name: None,
    };
    (
        user_ctx,
        info.organization_ref
            .unwrap_or(attome_core::ROOT_ORGANIZATION_ID),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// A pool whose every acquire fails: `connect_lazy` never touches the
    /// network, port 1 refuses immediately, and the short `acquire_timeout`
    /// bounds how long sqlx keeps retrying the connect before it gives up.
    fn dead_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_millis(500))
            .connect_lazy("postgres://user:pass@127.0.0.1:1/db")
            .expect("connect_lazy must not touch the network")
    }

    /// B15: a database error must not be cached as "this user has no name".
    #[tokio::test]
    async fn a_database_error_yields_a_degraded_context_but_writes_nothing_to_the_cache() {
        let db = dead_pool();
        let cache: HotCache<AuditUserInfo> = attome_cache::create_hot_cache(16, 60);
        let user_id = Uuid::now_v7();

        let (ctx, org) = fetch_audit_ctx_with(&db, &cache, user_id).await;

        assert_eq!(ctx.user_id, user_id);
        assert!(
            ctx.user_name.is_empty()
                && ctx.user_display_name.is_empty()
                && ctx.user_email.is_empty(),
            "the degraded context is still returned for this one event"
        );
        assert_eq!(org, attome_core::ROOT_ORGANIZATION_ID);
        assert!(
            cache
                .get(&attome_core::audit_user_cache_key(user_id))
                .await
                .is_none(),
            "a pool failure was inserted into audit_users — every audit row for this user \
             would carry the degraded context for the next 60s"
        );
    }

    /// The companion contract: a cached entry is served without touching the
    /// pool at all (which here would fail), so the cache really is consulted
    /// first.
    #[tokio::test]
    async fn a_cache_hit_is_served_without_touching_the_pool() {
        let db = dead_pool();
        let cache: HotCache<AuditUserInfo> = attome_cache::create_hot_cache(16, 60);
        let user_id = Uuid::now_v7();
        let org = Uuid::now_v7();
        cache
            .insert(
                attome_core::audit_user_cache_key(user_id),
                AuditUserInfo {
                    user_name: Some("cached-user".into()),
                    email: Some("cached@example.test".into()),
                    organization_ref: Some(org),
                },
            )
            .await;

        let (ctx, resolved_org) = fetch_audit_ctx_with(&db, &cache, user_id).await;

        assert_eq!(ctx.user_name, "cached-user");
        assert_eq!(ctx.user_display_name, "cached-user");
        assert_eq!(ctx.user_email, "cached@example.test");
        assert_eq!(resolved_org, org);
    }
}
