//! Z3-T1: the cache declaration. Every cache states, in one `static`, what
//! guidelines §5 asks of it: its source of truth, key shape, TTL, how it is
//! invalidated, how it fails and how it starts cold; and registers that
//! declaration once at start-up, so the process can list every cache it runs
//! (`registered()`).
//!
//! ```
//! use std::time::Duration;
//! use attome_cache::spec::{CacheSensitivity, CacheSpec, FailureMode, Partition};
//!
//! static ROLE_NAMES: CacheSpec = CacheSpec {
//!     name: "security:role_names",
//!     crate_name: "security",
//!     purpose: "role_names",
//!     source_of_truth: "the role table",
//!     ttl: Duration::from_secs(300),
//!     jitter_pct: 10,
//!     l1_capacity: 1_000,
//!     partition: Partition::Shared,
//!     sensitivity: CacheSensitivity::Plain,
//!     failure: FailureMode::FallBackToSource,
//!     invalidation: "deleted on every role write",
//!     cold_start: "filled on first read",
//!     warm_on_start: false,
//! };
//! attome_cache::spec::register(&ROLE_NAMES);
//! assert_eq!(ROLE_NAMES.key("42"), "security:role_names:42");
//! ```

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// Whose values one entry holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Partition {
    /// The same for every caller.
    Shared,
    PerUser,
    PerSession,
    /// The same for every caller with one set of permissions.
    PerPermissionSet,
}

/// Where a value may be kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSensitivity {
    Plain,
    /// Encrypted before it reaches Redis.
    EncryptedInRedis,
    /// Process memory only, never Redis.
    LocalOnly,
}

/// What a read does when the cache is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    /// Read the source of truth.
    FallBackToSource,
    /// Refuse (a security control: replay, revocation).
    FailClosed,
}

/// One cache's declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheSpec {
    /// `crate:purpose`, unique in the process.
    pub name: &'static str,
    pub crate_name: &'static str,
    pub purpose: &'static str,
    pub source_of_truth: &'static str,
    pub ttl: Duration,
    /// How far, in percent, an entry's TTL is spread so entries written
    /// together do not expire together. At most 50.
    pub jitter_pct: u8,
    /// The most entries the in-process (L1) tier holds.
    pub l1_capacity: u64,
    pub partition: Partition,
    pub sensitivity: CacheSensitivity,
    pub failure: FailureMode,
    /// What removes or replaces a stale entry.
    pub invalidation: &'static str,
    /// What a cold (empty) cache does.
    pub cold_start: &'static str,
    /// Filled at start-up rather than on first read.
    pub warm_on_start: bool,
}

/// Why a declaration is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpecError {
    #[error("cache {0}: a TTL of zero never expires")]
    ZeroTtl(&'static str),
    #[error("cache {0}: jitter over 50%")]
    Jitter(&'static str),
    #[error("cache {0}: the name is not crate:purpose in lower-case letters, digits, _ or -")]
    Name(&'static str),
    #[error("cache {0}: the name does not match crate_name:purpose")]
    NameParts(&'static str),
    #[error("cache {0}: an L1 capacity of zero")]
    Capacity(&'static str),
}

fn valid_part(part: &str) -> bool {
    !part.is_empty()
        && part
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

impl CacheSpec {
    /// Checks the declaration: a TTL, jitter at most 50%, a `crate:purpose`
    /// name that matches its parts, and an L1 capacity.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.ttl.is_zero() {
            return Err(SpecError::ZeroTtl(self.name));
        }
        if self.jitter_pct > 50 {
            return Err(SpecError::Jitter(self.name));
        }
        let Some((krate, purpose)) = self.name.split_once(':') else {
            return Err(SpecError::Name(self.name));
        };
        if !valid_part(krate) || !valid_part(purpose) {
            return Err(SpecError::Name(self.name));
        }
        if krate != self.crate_name || purpose != self.purpose {
            return Err(SpecError::NameParts(self.name));
        }
        if self.l1_capacity == 0 {
            return Err(SpecError::Capacity(self.name));
        }
        Ok(())
    }

    /// The Redis key of `id`: `{crate}:{purpose}:{id}` (guidelines §5).
    pub fn key(&self, id: &str) -> String {
        format!("{}:{}:{id}", self.crate_name, self.purpose)
    }
}

static REGISTRY: OnceLock<Mutex<Vec<&'static CacheSpec>>> = OnceLock::new();

fn registry() -> &'static Mutex<Vec<&'static CacheSpec>> {
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

/// Registers `spec` for this process. The same declaration twice is a no-op;
/// a second, different declaration under one name is a bug: a panic in a
/// debug build, an `error` log (the first one stays) in release. An invalid
/// declaration is refused the same way.
pub fn register(spec: &'static CacheSpec) {
    if let Err(error) = spec.validate() {
        if cfg!(debug_assertions) {
            panic!("{error}");
        }
        tracing::error!(%error, "cache declaration refused");
        return;
    }
    let mut specs = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match specs.iter().find(|s| s.name == spec.name) {
        Some(existing) if **existing == *spec => {}
        Some(_) => {
            if cfg!(debug_assertions) {
                panic!("cache {} declared twice, differently", spec.name);
            }
            tracing::error!(
                cache = spec.name,
                "cache declared twice, differently; the first stays"
            );
        }
        None => specs.push(spec),
    }
}

/// Every declaration registered so far, by name.
pub fn registered() -> Vec<&'static CacheSpec> {
    let mut specs = registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    specs.sort_by_key(|s| s.name);
    specs
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn spec(name: &'static str, purpose: &'static str, ttl: u64) -> CacheSpec {
        CacheSpec {
            name,
            crate_name: "cache",
            purpose,
            source_of_truth: "a test",
            ttl: Duration::from_secs(ttl),
            jitter_pct: 10,
            l1_capacity: 10,
            partition: Partition::Shared,
            sensitivity: CacheSensitivity::Plain,
            failure: FailureMode::FallBackToSource,
            invalidation: "none",
            cold_start: "empty",
            warm_on_start: false,
        }
    }

    static SAME: CacheSpec = spec("cache:same", "same", 60);
    static SAME_AGAIN: CacheSpec = spec("cache:same", "same", 60);

    #[test]
    fn validate_rejects_zero_ttl() {
        assert_eq!(
            spec("cache:zero", "zero", 0).validate(),
            Err(SpecError::ZeroTtl("cache:zero"))
        );
        assert!(spec("cache:ok", "ok", 1).validate().is_ok());
        assert_eq!(
            spec("Cache:Bad", "Bad", 1).validate(),
            Err(SpecError::Name("Cache:Bad"))
        );
        assert_eq!(
            spec("cache:a", "b", 1).validate(),
            Err(SpecError::NameParts("cache:a"))
        );
        let mut wide = spec("cache:wide", "wide", 1);
        wide.jitter_pct = 51;
        assert_eq!(wide.validate(), Err(SpecError::Jitter("cache:wide")));
    }

    #[test]
    fn key_has_namespace_shape() {
        assert_eq!(spec("cache:k", "k", 1).key("7"), "cache:k:7");
    }

    #[test]
    fn duplicate_register_same_spec_is_ok() {
        register(&SAME);
        register(&SAME_AGAIN);
        let named: Vec<_> = registered()
            .into_iter()
            .filter(|s| s.name == "cache:same")
            .collect();
        assert_eq!(named.len(), 1);
    }
}
