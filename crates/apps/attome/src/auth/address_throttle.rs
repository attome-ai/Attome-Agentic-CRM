//! The per-address sign-in budget (roadmap Z4-T10), beside the per-account
//! one in `local.rs`: [`FAILURES_PER_WINDOW`] failed sign-ins from one client
//! address (an IPv6 address by its configured prefix) in
//! [`WINDOW_SECS`], across every account, and that address waits until the
//! window ends. It stops one address trying one password against many
//! accounts, which the per-account budget cannot see.
//!
//! Only failures count, so a busy office behind one address signing in
//! correctly is never held. The check runs before the password is verified;
//! a coordination-store error fails closed (`Internal`), like the account
//! budget.
//!
//! Key: `server:rl:login_ip:{subject}` — a counter whose first failure sets
//! the window's expiry. Source of truth: the coordination store; it is lost
//! harmlessly on a restart of a memory store (the window starts again).

use std::net::IpAddr;
use std::time::Duration;

use attome_cache::Store;
use attome_types::AppError;
use fred::interfaces::{KeysInterface, LuaInterface};

/// Failed sign-ins one address may make in a window.
pub const FAILURES_PER_WINDOW: i64 = 20;
/// The window, in seconds.
pub const WINDOW_SECS: i64 = 15 * 60;
const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;

/// The budget's key for `ip`.
pub fn key(ip: IpAddr, ipv6_prefix: u8) -> String {
    format!(
        "server:rl:login_ip:{}",
        attome_server::middleware::client_ip::rate_limit_subject(ip, ipv6_prefix)
    )
}

/// INCR the counter; the first failure starts the window.
const RECORD_SCRIPT: &str = r#"
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
"#;

/// The seconds left before `key` may sign in again, or `None` while it is
/// under budget.
pub async fn blocked(store: &Store, key: &str) -> Result<Option<u64>, AppError> {
    let (count, ttl) = match store {
        Store::Memory(memory) => memory
            .transaction(|ks| -> Result<(i64, Option<Duration>), String> {
                let count = ks
                    .get_str(key)
                    .map_err(|e| e.to_string())?
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                Ok((count, ks.ttl(key).flatten()))
            })
            .map(|(count, ttl)| (count, ttl.map_or(-1, |t| t.as_secs() as i64)))
            .map_err(AppError::internal)?,
        Store::Redis(pool) => {
            let count: Option<i64> = tokio::time::timeout(OP_TIMEOUT, pool.get(key))
                .await
                .map_err(|_| AppError::internal("login address budget: timed out"))?
                .map_err(AppError::internal)?;
            let count = count.unwrap_or(0);
            if count < FAILURES_PER_WINDOW {
                return Ok(None);
            }
            let ttl: i64 = tokio::time::timeout(OP_TIMEOUT, pool.ttl(key))
                .await
                .map_err(|_| AppError::internal("login address budget: timed out"))?
                .map_err(AppError::internal)?;
            (count, ttl)
        }
    };
    Ok(over_budget(count, ttl))
}

/// Whether `count` failures are over budget, and for how long, given the
/// counter's remaining `ttl` in seconds (negative when it has none).
fn over_budget(count: i64, ttl: i64) -> Option<u64> {
    (count >= FAILURES_PER_WINDOW).then_some(if ttl > 0 {
        ttl as u64
    } else {
        WINDOW_SECS as u64
    })
}

/// Counts one failed sign-in from `key`'s address.
pub async fn record_failure(store: &Store, key: &str) -> Result<(), AppError> {
    match store {
        Store::Memory(memory) => memory
            .transaction(|ks| -> Result<(), String> {
                let n = ks.incr_by(key, 1).map_err(|e| e.to_string())?;
                if n == 1 {
                    ks.expire(key, Duration::from_secs(WINDOW_SECS as u64));
                }
                Ok(())
            })
            .map_err(AppError::internal),
        Store::Redis(pool) => tokio::time::timeout(
            OP_TIMEOUT,
            pool.eval::<i64, _, _, _>(
                RECORD_SCRIPT,
                vec![key.to_owned()],
                vec![WINDOW_SECS.to_string()],
            ),
        )
        .await
        .map_err(|_| AppError::internal("login address budget: timed out"))?
        .map(|_| ())
        .map_err(AppError::internal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_held_from_the_budget_for_the_rest_of_its_window() {
        assert_eq!(over_budget(FAILURES_PER_WINDOW - 1, 600), None);
        assert_eq!(over_budget(FAILURES_PER_WINDOW, 600), Some(600));
        assert_eq!(
            over_budget(FAILURES_PER_WINDOW + 5, -1),
            Some(WINDOW_SECS as u64)
        );
    }

    #[test]
    fn ipv6_addresses_share_their_prefix_budget() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        assert_eq!(key(a, 64), key(b, 64));
        assert!(key(a, 64).starts_with("server:rl:login_ip:"));
    }

    #[tokio::test]
    async fn the_twenty_first_failure_is_held_in_the_memory_store() {
        let store = Store::Memory(std::sync::Arc::new(attome_cache::memory::MemoryStore::new()));
        let key = key("198.51.100.7".parse().unwrap(), 64);
        for _ in 0..FAILURES_PER_WINDOW {
            assert_eq!(blocked(&store, &key).await.unwrap(), None);
            record_failure(&store, &key).await.unwrap();
        }
        let wait = blocked(&store, &key).await.unwrap().expect("held");
        assert!(wait > 0 && wait <= WINDOW_SECS as u64);
    }
}
