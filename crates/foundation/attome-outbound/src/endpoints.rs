//! AB6-T5: one [`Service`] per endpoint of an outside system, so one
//! customer endpoint that is down opens only its own breaker, not every
//! connector's or every webhook's.
//!
//! Process-local and rebuildable (guidelines §5): an entry is made on first
//! use, and a restart starts every endpoint closed. The map holds at most
//! `cap` endpoints; past that the one used least recently is dropped, which
//! only forgets its breaker's recent history.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use crate::{Policy, Service};

/// The services of one kind of endpoint (webhook targets, REST connectors),
/// by endpoint key.
#[derive(Debug)]
pub struct EndpointServices {
    name: &'static str,
    policy: Policy,
    cap: usize,
    inner: Mutex<Entries>,
}

#[derive(Debug, Default)]
struct Entries {
    by_key: HashMap<String, (Arc<Service>, u64)>,
    clock: u64,
}

impl EndpointServices {
    /// `name` is every endpoint service's name (a metric and log label);
    /// `policy` each one's limits.
    pub fn new(name: &'static str, policy: Policy, cap: usize) -> Self {
        Self {
            name,
            policy,
            cap: cap.max(1),
            inner: Mutex::new(Entries::default()),
        }
    }

    /// The service for `key`, made on first use.
    pub fn get(&self, key: &str) -> Arc<Service> {
        self.get_with(key, self.policy)
    }

    /// [`EndpointServices::get`], with `policy` for a service made now (an
    /// endpoint whose timeout is its own configuration).
    pub fn get_with(&self, key: &str, policy: Policy) -> Arc<Service> {
        let mut entries = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        entries.clock += 1;
        let now = entries.clock;
        if let Some((service, used)) = entries.by_key.get_mut(key) {
            *used = now;
            return service.clone();
        }
        if entries.by_key.len() >= self.cap
            && let Some(oldest) = entries
                .by_key
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| k.clone())
        {
            entries.by_key.remove(&oldest);
        }
        let service = Arc::new(Service::new(self.name, policy));
        entries
            .by_key
            .insert(key.to_owned(), (service.clone(), now));
        service
    }

    /// Endpoints held now.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .by_key
            .len()
    }

    /// Whether none is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_get_their_own_service_and_the_least_used_is_dropped() {
        let endpoints = EndpointServices::new("test", Policy::default(), 2);
        let a = endpoints.get("a");
        assert!(
            Arc::ptr_eq(&a, &endpoints.get("a")),
            "the same endpoint, the same service"
        );
        let b = endpoints.get("b");
        assert!(!Arc::ptr_eq(&a, &b));
        endpoints.get("a");
        endpoints.get("c");
        assert_eq!(endpoints.len(), 2);
        assert!(
            Arc::ptr_eq(&a, &endpoints.get("a")),
            "a was used last, so b went"
        );
        assert!(!Arc::ptr_eq(&b, &endpoints.get("b")), "b is made again");
    }
}
