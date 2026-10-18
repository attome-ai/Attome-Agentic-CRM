//! Q20-T2: growing delays per account and password-spray detection.
//!
//! **Delays.** After [`DELAY_AFTER`] failed sign-ins in a row for one account
//! (the hashed email, so an unknown address is treated the same), every
//! further attempt waits before its password is checked: 1, 2, 4, 8 and 16
//! seconds, then [`MAX_DELAY_SECS`]. The wait comes before the check, so a
//! right and a wrong password take the same time, and it is a `tokio` sleep,
//! never a blocked thread. A successful sign-in clears the streak; otherwise
//! it expires [`STREAK_TTL_SECS`] after the last failure.
//!
//! **Spray.** When [`SPRAY_ACCOUNTS`] different accounts fail from one
//! address within a fixed [`SPRAY_WINDOW_SECS`] window, the address is
//! challenged for [`CHALLENGE_SECS`]: a sign-in from it must carry a CAPTCHA
//! token that the configured provider (`portal.captcha`) accepts, and is
//! refused with `429` when no provider is configured. The address budget
//! (`address_throttle`, 20 failures in 15 minutes) blocks an address before
//! 20 accounts could fail, so the spray threshold sits below it. ASNs are
//! not known to the server, so detection is per address (an IPv6 address is
//! its configured prefix, as in the address budget).
//!
//! **Redis** (coordination pool, every call bounded by [`OP_TIMEOUT`]):
//! `attome-auth:login-guard:streak:{account}` (counter),
//! `attome-auth:login-guard:spray:{address}:{window}` (set of account
//! hashes) and `attome-auth:login-guard:challenge:{address}` (flag). Like
//! the address budget, a Redis error fails the sign-in rather than silently
//! dropping the control.

use std::time::Duration;

use attome_cache::Store;
use attome_types::AppError;
use fred::interfaces::{KeysInterface, LuaInterface};

/// Failures in a row before attempts are delayed.
pub const DELAY_AFTER: i64 = 3;
/// The longest delay.
pub const MAX_DELAY_SECS: u64 = 30;
/// How long a failure streak lasts after its last failure.
pub const STREAK_TTL_SECS: i64 = 15 * 60;
/// The spray window.
pub const SPRAY_WINDOW_SECS: i64 = 10 * 60;
/// Distinct failing accounts from one address that make a spray.
pub const SPRAY_ACCOUNTS: i64 = 10;
/// How long a spraying address stays challenged.
pub const CHALLENGE_SECS: i64 = 10 * 60;

const OP_TIMEOUT: Duration = attome_cache::timeouts::REQUEST_PATH;
const PREFIX: &str = "attome-auth:login-guard";

/// The wait before an attempt on an account with `streak` failures in a
/// row, never longer than `cap_secs` (the request must still finish inside
/// its own timeout).
pub fn delay_for(streak: i64, cap_secs: u64) -> Duration {
    if streak <= DELAY_AFTER {
        return Duration::ZERO;
    }
    let exponent = (streak - DELAY_AFTER - 1).min(16) as u32;
    Duration::from_secs((1u64 << exponent).min(MAX_DELAY_SECS).min(cap_secs))
}

fn streak_key(account: &str) -> String {
    format!("{PREFIX}:streak:{account}")
}

fn spray_key(address: &str, window: i64) -> String {
    format!("{PREFIX}:spray:{address}:{window}")
}

fn challenge_key(address: &str) -> String {
    format!("{PREFIX}:challenge:{address}")
}

/// The start of the spray window holding `now` (unix seconds).
pub fn spray_window(now: i64) -> i64 {
    now - now.rem_euclid(SPRAY_WINDOW_SECS)
}

async fn bounded<T, E: std::fmt::Display>(
    what: &'static str,
    f: impl std::future::Future<Output = Result<T, E>>,
) -> Result<T, AppError> {
    tokio::time::timeout(OP_TIMEOUT, f)
        .await
        .map_err(|_| AppError::internal(format!("login guard {what}: timed out")))?
        .map_err(|e| AppError::internal(format!("login guard {what}: {e}")))
}

/// The account's current failure streak.
pub async fn streak(store: &Store, account: &str) -> Result<i64, AppError> {
    let key = streak_key(account);
    match store {
        Store::Memory(memory) => memory
            .transaction(|ks| ks.get_str(&key))
            .map(|v| v.and_then(|v| v.parse().ok()).unwrap_or(0))
            .map_err(|e| AppError::internal(e.to_string())),
        Store::Redis(pool) => bounded("streak", pool.get::<Option<i64>, _>(key))
            .await
            .map(Option::unwrap_or_default),
    }
}

const STREAK_SCRIPT: &str = r#"
local n = redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[1])
return n
"#;

/// Counts one failure for the account; returns the new streak.
pub async fn record_account_failure(store: &Store, account: &str) -> Result<i64, AppError> {
    let key = streak_key(account);
    match store {
        Store::Memory(memory) => memory
            .transaction(|ks| -> Result<i64, attome_cache::memory::WrongType> {
                let n = ks.incr_by(&key, 1)?;
                ks.expire(&key, Duration::from_secs(STREAK_TTL_SECS as u64));
                Ok(n)
            })
            .map_err(|e| AppError::internal(e.to_string())),
        Store::Redis(pool) => {
            bounded(
                "streak",
                pool.eval::<i64, _, _, _>(
                    STREAK_SCRIPT,
                    vec![key],
                    vec![STREAK_TTL_SECS.to_string()],
                ),
            )
            .await
        }
    }
}

/// Clears the account's streak after a successful sign-in. Best effort: a
/// leftover streak only delays this account's next failures a little.
pub async fn clear_streak(store: &Store, account: &str) {
    let key = streak_key(account);
    let result = match store {
        Store::Memory(memory) => {
            memory.transaction(|ks| ks.del(&key));
            Ok(())
        }
        Store::Redis(pool) => bounded("clear", pool.del::<i64, _>(key)).await.map(|_| ()),
    };
    if let Err(error) = result {
        tracing::warn!(%error, "login guard: failure streak not cleared");
    }
}

/// SADD the account, refresh the set's TTL, and when the set reaches the
/// threshold raise the challenge flag if it is not already up. Returns 2
/// when this call raised it, 1 when it was already up, 0 below threshold.
const SPRAY_SCRIPT: &str = r#"
redis.call('SADD', KEYS[1], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
local n = redis.call('SCARD', KEYS[1])
if n >= tonumber(ARGV[3]) then
  if redis.call('SET', KEYS[2], '1', 'NX', 'EX', ARGV[4]) then
    return 2
  end
  return 1
end
return 0
"#;

/// Records that `account` failed from `address` at `now`; `true` when this
/// failure started a challenge (the caller writes the security event once).
pub async fn record_spray(
    store: &Store,
    address: &str,
    account: &str,
    now: i64,
) -> Result<bool, AppError> {
    let set = spray_key(address, spray_window(now));
    let flag = challenge_key(address);
    let raised = match store {
        Store::Memory(memory) => memory
            .transaction(|ks| -> Result<i64, attome_cache::memory::WrongType> {
                ks.sadd(&set, account)?;
                ks.expire(&set, Duration::from_secs(2 * SPRAY_WINDOW_SECS as u64));
                if (ks.smembers(&set)?.len() as i64) < SPRAY_ACCOUNTS {
                    return Ok(0);
                }
                let ttl = Some(Duration::from_secs(CHALLENGE_SECS as u64));
                Ok(if ks.set_nx(&flag, "1", ttl) { 2 } else { 1 })
            })
            .map_err(|e| AppError::internal(e.to_string()))?,
        Store::Redis(pool) => {
            bounded(
                "spray",
                pool.eval::<i64, _, _, _>(
                    SPRAY_SCRIPT,
                    vec![set, flag],
                    vec![
                        account.to_owned(),
                        (2 * SPRAY_WINDOW_SECS).to_string(),
                        SPRAY_ACCOUNTS.to_string(),
                        CHALLENGE_SECS.to_string(),
                    ],
                ),
            )
            .await?
        }
    };
    Ok(raised == 2)
}

/// The seconds left on `address`'s challenge, or `None` when it has none.
pub async fn challenge_active(store: &Store, address: &str) -> Result<Option<u64>, AppError> {
    let key = challenge_key(address);
    let ttl = match store {
        Store::Memory(memory) => memory.transaction(|ks| match ks.ttl(&key) {
            None => -2,
            Some(None) => -1,
            Some(Some(left)) => left.as_secs().max(1) as i64,
        }),
        Store::Redis(pool) => bounded("challenge", pool.ttl::<i64, _>(key)).await?,
    };
    Ok(match ttl {
        -2 => None,
        left if left > 0 => Some(left as u64),
        _ => Some(CHALLENGE_SECS as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Store {
        Store::Memory(std::sync::Arc::new(attome_cache::memory::MemoryStore::new()))
    }

    #[test]
    fn delays_start_after_three_failures_and_double_to_thirty_seconds() {
        let secs = |streak| delay_for(streak, 60).as_secs();
        assert_eq!([secs(0), secs(1), secs(3)], [0, 0, 0]);
        assert_eq!(
            [
                secs(4),
                secs(5),
                secs(6),
                secs(7),
                secs(8),
                secs(9),
                secs(50)
            ],
            [1, 2, 4, 8, 16, 30, 30]
        );
        assert_eq!(
            delay_for(9, 25).as_secs(),
            25,
            "never past the request timeout"
        );
    }

    #[tokio::test]
    async fn a_streak_counts_failures_and_a_success_clears_it() {
        let store = store();
        assert_eq!(streak(&store, "acct").await.unwrap(), 0);
        for expected in 1..=4 {
            assert_eq!(
                record_account_failure(&store, "acct").await.unwrap(),
                expected
            );
        }
        assert_eq!(streak(&store, "acct").await.unwrap(), 4);
        assert_eq!(streak(&store, "other").await.unwrap(), 0, "per account");
        clear_streak(&store, "acct").await;
        assert_eq!(streak(&store, "acct").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn ten_accounts_from_one_address_challenge_it_once() {
        let store = store();
        // A fake clock: every failure lands in the same window.
        let now = 1_800_000_000 - 1_800_000_000 % SPRAY_WINDOW_SECS + 5;
        for n in 1..SPRAY_ACCOUNTS {
            let raised = record_spray(&store, "addr", &format!("acct-{n}"), now)
                .await
                .unwrap();
            assert!(!raised, "account {n} is below the threshold");
        }
        // The same account again is not a new account.
        assert!(!record_spray(&store, "addr", "acct-1", now).await.unwrap());
        assert_eq!(challenge_active(&store, "addr").await.unwrap(), None);

        assert!(
            record_spray(&store, "addr", "acct-last", now + 1)
                .await
                .unwrap()
        );
        assert!(challenge_active(&store, "addr").await.unwrap().is_some());
        assert!(
            !record_spray(&store, "addr", "acct-more", now + 2)
                .await
                .unwrap(),
            "the event is written once per challenge"
        );
        assert_eq!(challenge_active(&store, "elsewhere").await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_spray_count_starts_again_in_the_next_window() {
        let store = store();
        let now = 1_800_000_000 - 1_800_000_000 % SPRAY_WINDOW_SECS;
        for n in 1..SPRAY_ACCOUNTS {
            record_spray(&store, "addr", &format!("acct-{n}"), now)
                .await
                .unwrap();
        }
        let next = now + SPRAY_WINDOW_SECS;
        assert!(
            !record_spray(&store, "addr", "acct-new", next)
                .await
                .unwrap()
        );
        assert_eq!(challenge_active(&store, "addr").await.unwrap(), None);
    }
}
