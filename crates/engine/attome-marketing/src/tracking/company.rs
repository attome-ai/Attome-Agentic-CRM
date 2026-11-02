//! E14-T10: the company a session's visitor likely works for, from the
//! truncated IP address through the customer's D24 provider
//! (`attome_integration::ip_company`).
//!
//! Off by default twice over: the deployment's `marketing.tracking_company`
//! flag and the site's `company_recognition` must both be on, and a
//! provider connection must be configured; otherwise no call is made. It
//! runs after a batch's transaction has committed, never inside one.
//!
//! The answer lands on the session only (`likely_company`, and
//! `likely_account_ref` when exactly one live account has the company's
//! domain as its `email_domain`), never on a person: a network is not a
//! named visitor.

use std::sync::OnceLock;
use std::time::Duration;

use attome_cache::Store;
use attome_cache::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
use attome_cache::tiered::TieredCache;
use attome_core::EngineState;
use attome_integration::ip_company::{CALL_TIMEOUT, CompanyByIp, LikelyCompany};
use attome_types::AppError;
use uuid::Uuid;

/// The flag that switches recognition on.
pub const FLAG: &str = "marketing.tracking_company";

/// The provider answer cache.
///
/// - Source of truth: the configured provider.
/// - Key: `marketing:company:{ip_prefix}`.
/// - TTL: 24 hours.
/// - Invalidation: none beyond the TTL.
/// - Failure: a Redis error asks the provider uncached; a failed or slow
///   call is not cached (the next batch asks again); "no company" is.
/// - Cold start: empty.
static COMPANY_SPEC: CacheSpec = CacheSpec {
    name: "marketing:company",
    crate_name: "marketing",
    purpose: "company",
    source_of_truth: "the customer's IP-to-company provider",
    ttl: Duration::from_secs(24 * 60 * 60),
    jitter_pct: 10,
    l1_capacity: 10_000,
    partition: Partition::Shared,
    sensitivity: CacheSensitivity::Plain,
    failure: FailureMode::FallBackToSource,
    invalidation: "none; the 24-hour TTL",
    cold_start: "empty",
    warm_on_start: false,
};

/// The cached provider answers.
#[derive(Debug)]
pub struct CompanyCache {
    cache: TieredCache<Option<LikelyCompany>>,
}

impl CompanyCache {
    pub fn new(store: Option<Store>) -> Result<Self, AppError> {
        Ok(Self {
            cache: TieredCache::new(&COMPANY_SPEC, store)?,
        })
    }
}

/// The process's cache, over the deployment's Redis.
fn cache(state: &EngineState) -> Option<&'static CompanyCache> {
    static CACHE: OnceLock<Option<CompanyCache>> = OnceLock::new();
    CACHE
        .get_or_init(|| match CompanyCache::new(Some(state.base.redis.clone())) {
            Ok(cache) => Some(cache),
            Err(error) => {
                tracing::error!(%error, "company recognition: cache refused");
                None
            }
        })
        .as_ref()
}

/// The company `ip_prefix` likely belongs to: `None` unless `enabled`
/// (the flag and the site's switch), else the cached answer or the
/// provider's within [`CALL_TIMEOUT`]. A failed call is `None`, uncached.
pub async fn recognise(
    enabled: bool,
    provider: &dyn CompanyByIp,
    cache: &CompanyCache,
    ip_prefix: &str,
) -> Option<LikelyCompany> {
    let ip_prefix = ip_prefix.trim();
    if !enabled || ip_prefix.is_empty() {
        return None;
    }
    let lookup = async {
        match tokio::time::timeout(CALL_TIMEOUT, provider.lookup(ip_prefix)).await {
            Ok(answer) => answer,
            Err(_) => Err(AppError::internal("ip company provider timed out")),
        }
    };
    match cache.cache.get_or_load(ip_prefix, lookup).await {
        Ok(found) => found,
        Err(error) => {
            tracing::debug!(%error, "company recognition: no answer");
            None
        }
    }
}

/// After a batch of `session` on `site_key` from `ip_prefix` committed:
/// recognises the company when the flag, the site and a provider allow it
/// and stores it on the session. True when a company was stored.
pub async fn after_batch(
    state: &EngineState,
    site_key: &str,
    session: Uuid,
    ip_prefix: &str,
) -> Result<bool, AppError> {
    if !state.feature_flags().is_on_for_deployment(FLAG) {
        return Ok(false);
    }
    let db = &state.base.db;
    // A session already recognised, or a site with recognition off, asks
    // nothing.
    let wanted: Option<bool> = sqlx::query_scalar(
        "SELECT COALESCE(t.company_recognition, false) \
           FROM marketing_web_session s \
           JOIN marketing_tracked_site t ON t.site_key = s.site_key \
                                        AND t.is_active IS NOT FALSE \
          WHERE s.id = $1 AND s.site_key = $2 AND NOT s.is_bot \
            AND s.likely_company IS NULL",
    )
    .bind(session)
    .bind(site_key)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    if wanted != Some(true) {
        return Ok(false);
    }
    let Some(provider) = attome_integration::ip_company::configured(state).await? else {
        return Ok(false);
    };
    let Some(cache) = cache(state) else {
        return Ok(false);
    };
    let Some(company) = recognise(true, &provider, cache, ip_prefix).await else {
        return Ok(false);
    };
    let account = match company.domain.as_deref() {
        Some(domain) => {
            let ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT id FROM account WHERE lower(email_domain) = $1 \
                   AND (is_active IS NULL OR is_active = true) \
                 ORDER BY created_at, id LIMIT 2",
            )
            .bind(domain)
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?;
            // Two accounts with one domain name neither.
            match ids.as_slice() {
                [only] => Some(*only),
                _ => None,
            }
        }
        None => None,
    };
    let stored = sqlx::query(
        "UPDATE marketing_web_session \
            SET likely_company = $3, likely_account_ref = $4 \
          WHERE id = $1 AND site_key = $2 AND likely_company IS NULL",
    )
    .bind(session)
    .bind(site_key)
    .bind(&company.name)
    .bind(account)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(stored.rows_affected() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;

    /// A provider that must not be asked.
    struct Panics;

    impl CompanyByIp for Panics {
        fn lookup<'a>(
            &'a self,
            _ip_prefix: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<LikelyCompany>, AppError>> + Send + 'a>>
        {
            panic!("the provider was called with recognition off")
        }
    }

    /// Answers one company and counts its calls.
    #[derive(Default)]
    struct Counting(std::sync::atomic::AtomicUsize);

    impl CompanyByIp for Counting {
        fn lookup<'a>(
            &'a self,
            _ip_prefix: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Option<LikelyCompany>, AppError>> + Send + 'a>>
        {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {
                Ok(Some(LikelyCompany {
                    name: "Acme Trading".into(),
                    domain: Some("acme.sa".into()),
                }))
            })
        }
    }

    #[tokio::test]
    async fn no_provider_call_when_flag_off() {
        let cache = CompanyCache::new(None).unwrap();
        assert_eq!(recognise(false, &Panics, &cache, "203.0.113.0").await, None);
    }

    #[tokio::test]
    async fn an_answer_is_cached_per_prefix() {
        let cache = CompanyCache::new(None).unwrap();
        let provider = Counting::default();
        let expected = Some(LikelyCompany {
            name: "Acme Trading".into(),
            domain: Some("acme.sa".into()),
        });
        let first = recognise(true, &provider, &cache, "198.51.100.0").await;
        let again = recognise(true, &provider, &cache, "198.51.100.0").await;
        assert_eq!(first, expected);
        assert_eq!(again, expected);
        assert_eq!(provider.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
