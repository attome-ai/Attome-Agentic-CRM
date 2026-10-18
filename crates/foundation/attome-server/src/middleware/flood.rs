//! Z5-T5: flood protection, right after the web firewall and before rate
//! limiting, authentication and any database work.
//!
//! - **Global cap.** At most `app.max_concurrent_requests` (default 1024)
//!   requests run at once on this node; one more answers `503 overloaded`
//!   with `Retry-After: 1`.
//! - **Per-address cap.** At most `app.max_concurrent_per_ip` (default 64)
//!   from one address (the pre-auth rate limiter's subject: an IPv6 address
//!   by its prefix); one more answers `429` with `Retry-After: 1`.
//!
//! A permit is held for the handler call only: it is released when the
//! response is returned, never across a streamed body.
//!
//! **State.** Observational and per node (guidelines §5): a semaphore per
//! address, in a map of at most [`MAX_ADDRESSES`] entries; an entry goes when
//! its last request finishes. When the map is full a new address is not
//! limited individually (the global cap still holds) and
//! `http_flood_untracked_total` counts it. Every refusal counts in
//! `http_rejections_total{layer="flood", reason="global"|"per_ip"}`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use attome_config::AppConfig;
use attome_types::AppError;
use axum::extract::Request;
use axum::http::{HeaderValue, header::RETRY_AFTER};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::middleware::client_ip::{client_ip, rate_limit_subject};

/// The most addresses tracked at once.
pub const MAX_ADDRESSES: usize = 100_000;

/// The node's caps and the per-address semaphores.
#[derive(Debug)]
pub struct FloodGuard {
    global: Arc<Semaphore>,
    per_address: usize,
    addresses: Mutex<HashMap<String, Arc<Semaphore>>>,
}

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    Global,
    PerAddress,
}

/// The permits a request holds while its handler runs.
#[derive(Debug)]
pub struct Admitted<'a> {
    guard: &'a FloodGuard,
    address: Option<String>,
    _global: OwnedSemaphorePermit,
    per_address: Option<OwnedSemaphorePermit>,
}

impl Drop for Admitted<'_> {
    fn drop(&mut self) {
        // Release the address permit first, then drop the entry when nobody
        // else holds it.
        self.per_address.take();
        if let Some(address) = &self.address {
            let mut map = self
                .guard
                .addresses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let idle = map.get(address).is_some_and(|semaphore| {
                Arc::strong_count(semaphore) == 1
                    && semaphore.available_permits() == self.guard.per_address
            });
            if idle {
                map.remove(address);
            }
        }
    }
}

impl FloodGuard {
    pub fn new(global: usize, per_address: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global.max(1))),
            per_address: per_address.max(1),
            addresses: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_config(config: &AppConfig) -> Self {
        Self::new(
            config.app.max_concurrent_requests,
            config.app.max_concurrent_per_ip,
        )
    }

    /// Admits one request from `address`, or says why not.
    pub fn admit(&self, address: &str) -> Result<Admitted<'_>, Refusal> {
        let global = Arc::clone(&self.global)
            .try_acquire_owned()
            .map_err(|_| Refusal::Global)?;
        let semaphore = {
            let mut map = self
                .addresses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match map.get(address) {
                Some(semaphore) => Some(Arc::clone(semaphore)),
                None if map.len() < MAX_ADDRESSES => {
                    let semaphore = Arc::new(Semaphore::new(self.per_address));
                    map.insert(address.to_owned(), Arc::clone(&semaphore));
                    Some(semaphore)
                }
                None => None,
            }
        };
        let Some(semaphore) = semaphore else {
            metrics::counter!("http_flood_untracked_total").increment(1);
            return Ok(Admitted {
                guard: self,
                address: None,
                _global: global,
                per_address: None,
            });
        };
        let mut admitted = Admitted {
            guard: self,
            address: Some(address.to_owned()),
            _global: global,
            per_address: None,
        };
        match semaphore.try_acquire_owned() {
            Ok(permit) => {
                admitted.per_address = Some(permit);
                Ok(admitted)
            }
            // `admitted` drops here: the global permit goes back and an
            // otherwise idle entry is removed.
            Err(_) => Err(Refusal::PerAddress),
        }
    }

    /// How many addresses are tracked now.
    pub fn tracked(&self) -> usize {
        self.addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

/// The refusal's response: 503 or 429, each with `Retry-After: 1`.
pub fn refusal_response(refusal: Refusal) -> Response {
    let (mut response, reason) = match refusal {
        Refusal::Global => (
            AppError::Overloaded("flood: global").into_response(),
            "global",
        ),
        Refusal::PerAddress => (
            AppError::TooManyRequests {
                retry_after_secs: Some(1),
            }
            .into_response(),
            "per_ip",
        ),
    };
    metrics::counter!("http_rejections_total", "layer" => "flood", "reason" => reason).increment(1);
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

/// The layer itself; see the module doc.
pub async fn flood_guard(
    guard: Arc<FloodGuard>,
    config: Arc<AppConfig>,
    req: Request,
    next: Next,
) -> Response {
    let address = client_ip(&req, &config)
        .map(|ip| rate_limit_subject(ip, config.rate_limit.ipv6_bucket_prefix))
        .unwrap_or_else(|| "unknown".to_owned());
    match guard.admit(&address) {
        Ok(admitted) => {
            let response = next.run(req).await;
            drop(admitted);
            response
        }
        Err(refusal) => refusal_response(refusal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_cap_returns_503_with_retry_after() {
        let guard = FloodGuard::new(2, 10);
        let a = guard.admit("10.0.0.1").unwrap();
        let b = guard.admit("10.0.0.2").unwrap();
        let refused = guard.admit("10.0.0.3").unwrap_err();
        assert_eq!(refused, Refusal::Global);
        let response = refusal_response(refused);
        assert_eq!(response.status(), 503);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
        drop(a);
        assert!(
            guard.admit("10.0.0.3").is_ok(),
            "a finished request frees a slot"
        );
        drop(b);
    }

    #[test]
    fn per_ip_cap_returns_429() {
        let guard = FloodGuard::new(100, 2);
        let a = guard.admit("10.0.0.1").unwrap();
        let _b = guard.admit("10.0.0.1").unwrap();
        let refused = guard.admit("10.0.0.1").unwrap_err();
        assert_eq!(refused, Refusal::PerAddress);
        let response = refusal_response(refused);
        assert_eq!(response.status(), 429);
        assert_eq!(response.headers()[RETRY_AFTER], "1");
        assert!(
            guard.admit("10.0.0.2").is_ok(),
            "another address is not limited"
        );
        drop(a);
        assert!(guard.admit("10.0.0.1").is_ok());
    }

    #[test]
    fn an_idle_address_is_forgotten() {
        let guard = FloodGuard::new(10, 2);
        let a = guard.admit("10.0.0.1").unwrap();
        assert_eq!(guard.tracked(), 1);
        drop(a);
        assert_eq!(guard.tracked(), 0);
        // A refused request leaves nothing behind either.
        let _x = guard.admit("10.0.0.9").unwrap();
        let _y = guard.admit("10.0.0.9").unwrap();
        assert!(guard.admit("10.0.0.9").is_err());
        assert_eq!(guard.tracked(), 1);
    }
}
