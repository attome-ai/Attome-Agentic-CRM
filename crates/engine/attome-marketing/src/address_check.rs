//! Email address checks (roadmap E6-T6): syntax within the RFC 5321 length
//! limits, role addresses, the shipped disposable-domain list, typo
//! suggestions for the large providers and a cached MX lookup.
//!
//! Only a syntax error makes an address invalid; the other findings make it
//! risky, so a form or import warns instead of refusing. The record
//! validator on `contact.email` and `lead.email` therefore refuses syntax
//! errors only: a validator is synchronous and has no network, and the
//! warnings come from [`check_address`] where the caller (form, import)
//! shows them.
//!
//! The MX lookup goes through [`MxResolver`], so tests and deployments pick
//! the resolver. No DNS resolver crate ships yet ([`NoMxResolver`] answers
//! "unknown", which is never a finding); adding one (hickory-resolver,
//! rustls, no native build) needs a lockfile change made on a build machine.
//! An unknown answer, including a resolver past its two seconds, never
//! blocks a save.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::time::Duration;

use attome_cache::Store;
use attome_cache::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
use attome_cache::tiered::TieredCache;
use attome_types::AppError;

/// The longest address (RFC 5321 path limit less the angle brackets).
pub const MAX_ADDRESS: usize = 254;
/// The longest local part.
pub const MAX_LOCAL: usize = 64;

static DISPOSABLE: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../data/disposable_domains.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

const ROLE_LOCALS: &[&str] = &[
    "info", "sales", "admin", "support", "noreply", "no-reply", "contact", "hello",
];

const TYPO_TARGETS: &[&str] = &[
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "yahoo.com",
    "icloud.com",
];

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressIssue {
    Empty,
    TooLong,
    LocalTooLong,
    NotOneAt,
    BadLocal,
    BadDomain,
    RoleAddress,
    DisposableDomain,
    LikelyTypo,
    NoMx,
}

/// The overall verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressStatus {
    Valid,
    Risky,
    Invalid,
}

/// The result of checking one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressCheck {
    pub status: AddressStatus,
    pub issues: Vec<AddressIssue>,
    /// A corrected address when the domain looks like a typo.
    pub suggestion: Option<String>,
}

/// Syntax only: lengths, exactly one `@`, a sane local part and a domain
/// with at least one dot and no empty labels.
pub fn check_syntax(address: &str) -> Result<(), AddressIssue> {
    let address = address.trim();
    if address.is_empty() {
        return Err(AddressIssue::Empty);
    }
    if address.len() > MAX_ADDRESS {
        return Err(AddressIssue::TooLong);
    }
    let mut parts = address.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(AddressIssue::NotOneAt);
    };
    if local.len() > MAX_LOCAL {
        return Err(AddressIssue::LocalTooLong);
    }
    let local_ok = !local.is_empty()
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || "!#$%&'*+/=?^_`{|}~.-".contains(c)
                // RFC 6531: an internationalised local part.
                || (!c.is_ascii() && c.is_alphanumeric())
        });
    if !local_ok {
        return Err(AddressIssue::BadLocal);
    }
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                // An internationalised domain (e.g. Arabic) as typed, not
                // only its punycode form.
                && l.chars().all(|c| {
                    c.is_ascii_alphanumeric() || c == '-' || (!c.is_ascii() && c.is_alphanumeric())
                })
        });
    if !domain_ok {
        return Err(AddressIssue::BadDomain);
    }
    Ok(())
}

/// Whether the local part is a shared role mailbox.
pub fn is_role_address(local: &str) -> bool {
    let local = local.to_ascii_lowercase();
    ROLE_LOCALS.contains(&local.as_str())
}

/// Whether `domain` is on the shipped disposable list.
pub fn is_disposable(domain: &str) -> bool {
    DISPOSABLE.contains(domain.to_ascii_lowercase().as_str())
}

/// The large provider `domain` is one or two edits away from, if any.
pub fn typo_suggestion(domain: &str) -> Option<&'static str> {
    let domain = domain.to_ascii_lowercase();
    if TYPO_TARGETS.contains(&domain.as_str()) {
        return None;
    }
    TYPO_TARGETS
        .iter()
        .map(|t| (*t, edit_distance(&domain, t)))
        .filter(|(_, d)| (1..=2).contains(d))
        .min_by_key(|(_, d)| *d)
        .map(|(t, _)| t)
}

/// Levenshtein distance with adjacent transpositions (optimal string
/// alignment), so "gmial" is one edit from "gmail".
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut best = (d[i - 1][j] + 1)
                .min(d[i][j - 1] + 1)
                .min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                best = best.min(d[i - 2][j - 2] + 1);
            }
            d[i][j] = best;
        }
    }
    d[a.len()][b.len()]
}

/// Every check that needs no network. `has_mx` is the caller's DNS answer
/// for the domain when it has one (`None` when not looked up).
pub fn check_address_offline(address: &str, has_mx: Option<bool>) -> AddressCheck {
    if let Err(issue) = check_syntax(address) {
        return AddressCheck {
            status: AddressStatus::Invalid,
            issues: vec![issue],
            suggestion: None,
        };
    }
    let address = address.trim();
    let (local, domain) = address.rsplit_once('@').unwrap_or((address, ""));
    let mut issues = Vec::new();
    if is_role_address(local) {
        issues.push(AddressIssue::RoleAddress);
    }
    let disposable = is_disposable(domain);
    if disposable {
        issues.push(AddressIssue::DisposableDomain);
    }
    // A known disposable domain is spelled as meant, not a typo.
    let suggestion = if disposable {
        None
    } else {
        typo_suggestion(domain).map(|d| format!("{local}@{d}"))
    };
    if suggestion.is_some() {
        issues.push(AddressIssue::LikelyTypo);
    }
    if has_mx == Some(false) {
        issues.push(AddressIssue::NoMx);
    }
    AddressCheck {
        status: if issues.is_empty() {
            AddressStatus::Valid
        } else {
            AddressStatus::Risky
        },
        issues,
        suggestion,
    }
}

/// How long one MX lookup may take before its answer counts as unknown.
pub const MX_TIMEOUT: Duration = Duration::from_secs(2);

/// Answers whether a domain has MX records. `None` is unknown (no resolver,
/// a DNS failure): never a finding and never cached.
pub trait MxResolver: Send + Sync {
    fn has_mx<'a>(
        &'a self,
        domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<bool>> + Send + 'a>>;
}

/// The resolver until a DNS crate ships: every answer is unknown.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoMxResolver;

impl MxResolver for NoMxResolver {
    fn has_mx<'a>(
        &'a self,
        _domain: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<bool>> + Send + 'a>> {
        Box::pin(async { None })
    }
}

/// The MX answer cache.
///
/// - Source of truth: the domain's DNS MX records.
/// - Key: `marketing:mx:{domain}` (lower case).
/// - TTL: 24 hours; DNS changes show after it.
/// - Invalidation: none beyond the TTL.
/// - Failure: a Redis error looks the domain up uncached; an unknown answer
///   is an error to the cache, so it is never stored.
/// - Cold start: empty.
static MX_SPEC: CacheSpec = CacheSpec {
    name: "marketing:mx",
    crate_name: "marketing",
    purpose: "mx",
    source_of_truth: "the domain's DNS MX records",
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

/// The cached MX lookup. One per process, over the deployment's store.
#[derive(Debug)]
pub struct MxCache {
    cache: TieredCache<bool>,
}

impl MxCache {
    pub fn new(store: Option<Store>) -> Result<Self, AppError> {
        Ok(Self {
            cache: TieredCache::new(&MX_SPEC, store)?,
        })
    }

    /// Whether `domain` has MX records: the cached answer, else the
    /// resolver's within [`MX_TIMEOUT`]. Unknown is `None`.
    pub async fn has_mx(&self, resolver: &dyn MxResolver, domain: &str) -> Option<bool> {
        let domain = domain.trim().to_lowercase();
        if domain.is_empty() {
            return None;
        }
        let lookup = async {
            match tokio::time::timeout(MX_TIMEOUT, resolver.has_mx(&domain)).await {
                Ok(Some(answer)) => Ok(answer),
                Ok(None) => Err(AppError::NotFound),
                Err(_) => {
                    tracing::debug!(%domain, "mx lookup timed out; unknown");
                    Err(AppError::NotFound)
                }
            }
        };
        self.cache.get_or_load(&domain, lookup).await.ok()
    }
}

/// Every check, with the MX answer from `cache` and `resolver`. The MX
/// lookup runs only for an address whose syntax passed.
pub async fn check_address(
    address: &str,
    resolver: &dyn MxResolver,
    cache: &MxCache,
) -> AddressCheck {
    if check_syntax(address).is_err() {
        return check_address_offline(address, None);
    }
    let domain = address
        .trim()
        .rsplit_once('@')
        .map(|(_, d)| d)
        .unwrap_or_default();
    let has_mx = cache.has_mx(resolver, domain).await;
    check_address_offline(address, has_mx)
}

/// The record validator on `contact.email` and `lead.email`: refuses an
/// address with a syntax error, accepts a missing or empty one. Warnings
/// (role, disposable, typo, no MX) are [`check_address`]'s, not a refusal.
pub fn validate_email_record(
    record: &serde_json::Map<String, serde_json::Value>,
    _registry: &attome_core::meta_registry::EntityMetaRegistry,
) -> Result<(), String> {
    match record.get("email") {
        Some(serde_json::Value::String(email)) if !email.trim().is_empty() => check_syntax(email)
            .map_err(|issue| format!("email: not a valid email address ({})", issue_code(&issue))),
        _ => Ok(()),
    }
}

/// A stable code for an issue, for messages and the wire.
pub fn issue_code(issue: &AddressIssue) -> &'static str {
    match issue {
        AddressIssue::Empty => "empty",
        AddressIssue::TooLong => "too_long",
        AddressIssue::LocalTooLong => "local_too_long",
        AddressIssue::NotOneAt => "not_one_at",
        AddressIssue::BadLocal => "bad_local",
        AddressIssue::BadDomain => "bad_domain",
        AddressIssue::RoleAddress => "role_address",
        AddressIssue::DisposableDomain => "disposable_domain",
        AddressIssue::LikelyTypo => "likely_typo",
        AddressIssue::NoMx => "no_mx",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Counts its lookups; every domain has MX except `nomx.example`.
    #[derive(Default)]
    struct Counting(AtomicUsize);

    impl MxResolver for Counting {
        fn has_mx<'a>(
            &'a self,
            domain: &'a str,
        ) -> Pin<Box<dyn Future<Output = Option<bool>> + Send + 'a>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Some(domain != "nomx.example") })
        }
    }

    #[tokio::test]
    async fn cached_mx_needs_no_lookup() {
        let cache = MxCache::new(None).unwrap();
        let resolver = Counting::default();
        let first = check_address("a@Acme.sa", &resolver, &cache).await;
        let second = check_address("b@acme.sa", &resolver, &cache).await;
        assert_eq!(first.status, AddressStatus::Valid);
        assert_eq!(second.status, AddressStatus::Valid);
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
        let none = check_address("a@nomx.example", &resolver, &cache).await;
        assert_eq!(none.issues, vec![AddressIssue::NoMx]);
    }

    #[tokio::test]
    async fn an_unknown_answer_is_no_finding_and_not_cached() {
        let cache = MxCache::new(None).unwrap();
        let c = check_address("a@unknown.sa", &NoMxResolver, &cache).await;
        assert_eq!(c.status, AddressStatus::Valid);
        let resolver = Counting::default();
        check_address("a@unknown.sa", &resolver, &cache).await;
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn syntax_errors_are_invalid() {
        let cache = MxCache::new(None).unwrap();
        let resolver = Counting::default();
        let c = check_address("not an address", &resolver, &cache).await;
        assert_eq!(c.status, AddressStatus::Invalid);
        assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn the_validator_refuses_syntax_errors_only() {
        let registry = attome_core::meta_registry::EntityMetaRegistry::default();
        let record = |email: &str| {
            let mut m = serde_json::Map::new();
            m.insert("email".into(), serde_json::Value::String(email.into()));
            m
        };
        assert!(validate_email_record(&record("a@b@c.com"), &registry).is_err());
        assert!(validate_email_record(&record("info@mailinator.com"), &registry).is_ok());
        assert!(validate_email_record(&record(""), &registry).is_ok());
        assert!(validate_email_record(&serde_json::Map::new(), &registry).is_ok());
        assert_eq!(check_syntax("سارة@مثال.السعودية"), Ok(()));
    }

    #[test]
    fn syntax_rules() {
        assert_eq!(check_syntax("a.b+tag@example.co.sa"), Ok(()));
        assert_eq!(check_syntax(""), Err(AddressIssue::Empty));
        assert_eq!(check_syntax("a@b@c.com"), Err(AddressIssue::NotOneAt));
        assert_eq!(
            check_syntax("a..b@example.com"),
            Err(AddressIssue::BadLocal)
        );
        assert_eq!(check_syntax("a@localhost"), Err(AddressIssue::BadDomain));
        assert_eq!(
            check_syntax(&format!("{}@example.com", "a".repeat(65))),
            Err(AddressIssue::LocalTooLong)
        );
    }

    #[test]
    fn role_addresses_are_risky_not_invalid() {
        let c = check_address_offline("Info@acme.sa", None);
        assert_eq!(c.status, AddressStatus::Risky);
        assert_eq!(c.issues, vec![AddressIssue::RoleAddress]);
    }

    #[test]
    fn disposable_domains_are_flagged() {
        assert!(is_disposable("Mailinator.com"));
        let c = check_address_offline("x@yopmail.com", Some(true));
        assert_eq!(c.issues, vec![AddressIssue::DisposableDomain]);
    }

    #[test]
    fn gmial_suggests_gmail() {
        let c = check_address_offline("sara@gmial.com", None);
        assert_eq!(c.suggestion.as_deref(), Some("sara@gmail.com"));
        assert!(c.issues.contains(&AddressIssue::LikelyTypo));
        assert_eq!(typo_suggestion("gmail.com"), None);
        assert_eq!(typo_suggestion("example.com"), None);
    }

    #[test]
    fn no_mx_is_risky_and_a_clean_address_is_valid() {
        assert_eq!(
            check_address_offline("a@acme.sa", Some(false)).issues,
            vec![AddressIssue::NoMx]
        );
        assert_eq!(
            check_address_offline("a@acme.sa", Some(true)).status,
            AddressStatus::Valid
        );
    }
}
