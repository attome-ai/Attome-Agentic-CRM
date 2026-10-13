//! The outbound door — the only sanctioned way to reach a [`Connector`] for a
//! call this deployment *makes*, and the one place
//! `integration_system.rate_limit` is enforced.
//!
//! **The gap this closes.** `rate_limit` has been an admin-writable column
//! since M59 Phase 1 (`seed.rs`, labelled "Rate Limit (requests/min)"), is
//! accepted by `admin.rs`'s create/update bodies, is selected by
//! `system::load`, and was read by nothing. An admin could configure a limit,
//! see it persisted, see it round-trip through the API — and every outbound
//! call still went out unthrottled. A configured control that silently does
//! nothing is worse than an absent one, because the operator believes they are
//! protected.
//!
//! **Outbound only, deliberately.** A `rate_limit` on a *system* row describes
//! how fast we may call that system: it exists to respect the provider's
//! published quota, and overrunning it gets the customer's API key throttled
//! or banned. It is not an inbound flood control, and [`crate::webhook`]
//! deliberately does not route through here — throttling a provider's webhook
//! deliveries would drop events the durable inbox (D-425) exists to never
//! lose, and the provider's own retry policy, not ours, decides what happens
//! next. Inbound volume is already bounded by the router-level pre-auth
//! limiter every route sits behind (see `webhook.rs`'s module doc).
//!
//! **One bucket per system**, keyed by row id rather than by `base_url`: two
//! systems pointed at the same host are two separate quota agreements with
//! that provider (different credentials, usually different plans), and
//! merging them would throttle one admin's integration because of another's.

use attome_cache::RedisPool;
use attome_types::AppError;

use crate::connector::{Connector, ConnectorKind, connector_for};
use crate::system::IntegrationSystem;

/// Redis key for a system's outbound bucket. `{crate}:{purpose}:{id}` per
/// `caching-and-state`; `attome_cache::rate_limit::check` adds no prefix of its
/// own, so this must already be fully namespaced or unrelated callers collide.
fn rate_limit_key(system: &IntegrationSystem) -> String {
    format!("attome-integration:rl:system:{}", system.id)
}

/// Converts the stored `rate_limit` into a requests-per-minute limit, or
/// `None` when this system is unlimited.
///
/// The column is `number` (provisioned as `numeric`, read as `f64`), so a
/// fractional or negative value is representable even though neither is
/// meaningful. Both are treated as *unlimited* rather than as "zero
/// requests allowed": a limit of 0 configured by accident would take a working
/// integration completely offline, and the failure would look like the
/// provider being down. Rejecting the value at write time is `admin.rs`'s job
/// (it does not yet — see this module's test), not this function's.
fn limit_rpm(system: &IntegrationSystem) -> Option<i32> {
    let raw = system.rate_limit?;
    if !raw.is_finite() || raw < 1.0 {
        return None;
    }
    // Saturate rather than wrap: a nonsense huge value means "effectively
    // unlimited", which is what i32::MAX gives us.
    Some(raw.min(i32::MAX as f64) as i32)
}

/// Admits one outbound call against this system's configured quota.
///
/// `Ok(())` when the system is unlimited or the call fits in the current
/// window; `Err(AppError::TooManyRequests { retry_after_secs: None })` when it does not.
///
/// **Fails closed on a Redis outage.** `attome_cache::rate_limit::check` returns
/// `Err` rather than admitting on a timeout, and that is the right posture
/// here even though a provider quota is not a security control: the cost of a
/// false rejection is one failed "test connection" a human retries, while the
/// cost of a false admission is spending a customer's third-party quota — and
/// a banned API key is recovered by talking to the provider, not by restarting
/// Redis.
pub async fn admit(redis: &RedisPool, system: &IntegrationSystem) -> Result<(), AppError> {
    let Some(limit) = limit_rpm(system) else {
        return Ok(());
    };

    let outcome = attome_cache::rate_limit::check(redis, &rate_limit_key(system), limit).await?;
    if !outcome.allowed {
        // Same metric family every other rejection in this platform emits, so
        // one dashboard covers connector throttling alongside S2S and HTTP.
        // No-op when no recorder was installed (observability.metrics_port == 0).
        metrics::counter!("security_rejection_total", "reason" => "integration_rate_limit")
            .increment(1);
        tracing::info!(
            system_id = %system.id,
            limit_rpm = limit,
            retry_after_secs = outcome.retry_after_secs,
            "outbound connector call refused — system is over its configured rate limit"
        );
        return Err(AppError::TooManyRequests {
            retry_after_secs: None,
        });
    }
    Ok(())
}

/// Admits the call, then hands back the adapter. **The only way a caller
/// should reach an adapter for an outbound call.**
///
/// Shaped as "admit, then return the connector" rather than as a free-standing
/// check a caller remembers to run first, for the same reason
/// `attome_ai::execute::dispatch` gates before it looks up an executor: a
/// check that can be skipped by writing the obvious code is not a control. A
/// caller that reaches for `connector_for` directly is either doing inbound
/// work (`webhook.rs`, exempt by design above) or has bypassed the quota.
pub async fn outbound(
    redis: &RedisPool,
    system: &IntegrationSystem,
    kind: ConnectorKind,
) -> Result<&'static dyn Connector, AppError> {
    admit(redis, system).await?;
    Ok(connector_for(kind))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn system_with(rate_limit: Option<f64>) -> IntegrationSystem {
        IntegrationSystem {
            id: Uuid::nil(),
            name: "Test".into(),
            kind: "rest".into(),
            base_url: "https://example.com".into(),
            auth_type: "api_key".into(),
            credential_ref: None,
            rate_limit,
            status: "active".into(),
            health_last_ok_at: None,
            health_last_error: None,
            service_principal_ref: Uuid::nil().to_string(),
            config: None,
            row_version: 0,
        }
    }

    /// An unconfigured limit means unlimited — the behaviour every deployment
    /// has today. Enforcing a limit nobody set would break working
    /// integrations on upgrade.
    #[test]
    fn an_unset_rate_limit_is_unlimited() {
        assert_eq!(limit_rpm(&system_with(None)), None);
    }

    /// **The direction that matters.** Zero, a negative, a fraction below one,
    /// and NaN all mean unlimited rather than "allow nothing". A limit of 0
    /// typo'd into the admin form must not take a working integration offline
    /// in a way that looks like the provider being down.
    #[test]
    fn a_nonsensical_limit_is_unlimited_rather_than_a_total_block() {
        // `INFINITY` belongs here rather than with the saturating cases
        // below: "infinitely many requests per minute" *is* unlimited, and
        // reading it as `i32::MAX` would cost a pointless Redis round-trip on
        // every call to say yes.
        for raw in [0.0, -1.0, 0.5, f64::NAN, f64::NEG_INFINITY, f64::INFINITY] {
            assert_eq!(
                limit_rpm(&system_with(Some(raw))),
                None,
                "rate_limit = {raw} must read as unlimited, never as a zero allowance"
            );
        }
    }

    #[test]
    fn a_configured_limit_is_carried_through_and_truncated_to_rpm() {
        assert_eq!(limit_rpm(&system_with(Some(60.0))), Some(60));
        assert_eq!(limit_rpm(&system_with(Some(1.0))), Some(1));
        // Fractions above one truncate rather than round up — 2.9 rpm admits
        // 2, never 3, so the provider's stated ceiling is never exceeded.
        assert_eq!(limit_rpm(&system_with(Some(2.9))), Some(2));
    }

    /// A finite-but-absurd limit saturates instead of wrapping. `as i32` past
    /// `i32::MAX` is already a saturating cast in Rust 2021+, but the explicit
    /// `.min()` documents the intent and survives a future change of integer
    /// type — a wrapped negative here would be read by Redis as "allow
    /// nothing" and silently take the integration offline.
    #[test]
    fn an_absurd_finite_limit_saturates_rather_than_wrapping_negative() {
        assert_eq!(limit_rpm(&system_with(Some(1e18))), Some(i32::MAX));
        assert!(limit_rpm(&system_with(Some(1e18))).unwrap() > 0);
    }

    /// Two systems never share a bucket, even pointed at the same host — see
    /// the module doc.
    #[test]
    fn each_system_gets_its_own_bucket() {
        let mut a = system_with(Some(10.0));
        let mut b = system_with(Some(10.0));
        a.id = Uuid::from_u128(1);
        b.id = Uuid::from_u128(2);
        assert_ne!(rate_limit_key(&a), rate_limit_key(&b));
        assert!(rate_limit_key(&a).starts_with("attome-integration:rl:system:"));
    }

    /// Strips whole-line `//` comments so a source-scanning assertion below
    /// reads code, not prose. Without this, writing the words this module's
    /// comments already contain ("never `connector_for` directly") would trip
    /// the very test explaining the rule — a false failure that teaches the
    /// next reader to delete the test rather than trust it.
    fn code_lines(source: &str) -> String {
        source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// **The structural claim, asserted against the source.** `admin.rs` is
    /// the crate's only outbound call site; it must reach its adapter through
    /// [`outbound`], never through a bare `connector_for`. Same
    /// source-scanning shape as `attome-ai`'s
    /// `the_model_registry_check_precedes_generation` tests, and for the same
    /// reason: the ordering is the control, and a diff that reorders it looks
    /// entirely ordinary.
    #[test]
    fn the_outbound_call_site_goes_through_the_rate_limit_guard() {
        let source = code_lines(include_str!("admin.rs"));
        assert!(
            source.contains("guard::outbound("),
            "admin.rs must reach its adapter through guard::outbound, so the \
             configured rate limit is enforced"
        );
        assert!(
            !source.contains("connector_for("),
            "admin.rs must not call connector_for directly — that bypasses \
             the per-system rate limit"
        );
    }

    /// The inbound path is exempt **on purpose**, and the exemption is pinned
    /// so a future "make it consistent" change has to read the reasoning
    /// first: throttling a provider's webhook deliveries drops events the
    /// durable inbox exists to never lose.
    #[test]
    fn the_inbound_webhook_path_is_deliberately_not_rate_limited() {
        let source = code_lines(include_str!("webhook.rs"));
        assert!(
            source.contains("connector_for("),
            "webhook.rs is inbound and deliberately calls connector_for directly"
        );
        assert!(
            !source.contains("guard::outbound("),
            "webhook.rs is inbound — routing it through the outbound quota \
             would drop provider events (see guard.rs's module doc)"
        );
    }
}
