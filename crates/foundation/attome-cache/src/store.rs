//! The one handle every shared-state primitive takes: Redis, or the
//! in-process [`MemoryStore`] Solo runs on (A5; `docs/solo-memory-backend.md`).
//!
//! Callers never match on the variant. They call a named operation
//! (`rate_limit::check`, `token_window::reserve`, ...) and that operation owns
//! both forms: the Redis script or command, and a closure run inside
//! [`MemoryStore::transaction`] that does the same read-modify-write while the
//! store is locked.
//!
//! A call site that has not been ported yet asks for the pool with
//! [`Store::redis`], which is an error in memory mode, so an unported feature
//! reports that it needs Redis instead of silently doing nothing.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use fred::prelude::*;

use attome_types::AppError;

use crate::memory::MemoryStore;
use crate::redis_pool::RedisPool;

/// Redis, or process memory.
#[derive(Clone)]
pub enum Store {
    Redis(RedisPool),
    Memory(Arc<MemoryStore>),
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Store::Redis(_) => "Store::Redis",
            Store::Memory(_) => "Store::Memory",
        })
    }
}

impl From<RedisPool> for Store {
    fn from(pool: RedisPool) -> Self {
        Store::Redis(pool)
    }
}

impl From<Arc<MemoryStore>> for Store {
    fn from(store: Arc<MemoryStore>) -> Self {
        Store::Memory(store)
    }
}

impl Store {
    /// The cache store and the coordination store the configuration asks for.
    /// `cache.backend = "memory"` gives one in-process store, shared by both
    /// roles; `redis` connects as `create_redis_pool` and
    /// `create_role_redis_pool` do.
    pub async fn from_config(
        config: &attome_config::AppConfig,
    ) -> Result<(Store, Store), AppError> {
        match config.cache.backend {
            attome_config::CacheBackend::Memory => {
                let store = Store::memory();
                Ok((store.clone(), store))
            }
            attome_config::CacheBackend::Redis => {
                let redis = crate::redis_pool::create_redis_pool(config)
                    .await
                    .map_err(AppError::internal)?;
                let coordination = crate::redis_pool::create_role_redis_pool(
                    config,
                    attome_config::CacheRole::Coordination,
                    &redis,
                )
                .await
                .map_err(AppError::internal)?;
                Ok((Store::Redis(redis), Store::Redis(coordination)))
            }
        }
    }

    /// A fresh in-process store (Solo, and tests that need no Redis).
    pub fn memory() -> Self {
        Store::Memory(Arc::new(MemoryStore::new()))
    }

    /// The Redis pool, for a feature that has no memory form yet. Memory mode
    /// answers with a typed unavailable error naming the limitation.
    pub fn redis(&self) -> Result<&RedisPool, AppError> {
        match self {
            Store::Redis(pool) => Ok(pool),
            Store::Memory(_) => Err(AppError::CapabilityUnavailable("redis")),
        }
    }

    /// Liveness: a Redis `PING`, or always true for the in-process store.
    pub async fn ping(&self) -> bool {
        match self {
            Store::Redis(pool) => crate::redis_pool::redis_ping(pool).await,
            Store::Memory(_) => true,
        }
    }

    /// Whether this is the in-process store.
    pub fn is_memory(&self) -> bool {
        matches!(self, Store::Memory(_))
    }
}

/// Primitive key-value operations, one Redis command or one memory
/// transaction each. Every Redis call is bounded by
/// [`crate::timeouts::REQUEST_PATH`], and a timeout or error is an `Err`, so a
/// caller keeps the fail-closed behaviour it chooses: an error here must not be
/// read as "absent".
impl Store {
    fn redis_err(what: &str, e: impl std::fmt::Display) -> AppError {
        AppError::internal(format!("redis {what} failed: {e}"))
    }

    fn timed_out(what: &str) -> AppError {
        AppError::internal(format!("redis {what} timed out"))
    }

    fn wrong_type(key: &str) -> AppError {
        AppError::internal(format!("key {key} holds a value of another type"))
    }

    /// `SET key value [PX ttl]`.
    pub async fn set(
        &self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
        ttl: Option<Duration>,
    ) -> Result<(), AppError> {
        let key = key.as_ref();
        let value = value.as_ref();
        match self {
            Store::Memory(memory) => {
                memory.transaction(|ks| ks.set(key, value, ttl));
                Ok(())
            }
            Store::Redis(pool) => {
                let expiry = ttl.map(|d| Expiration::PX(d.as_millis().max(1) as i64));
                tokio::time::timeout(
                    crate::timeouts::REQUEST_PATH,
                    pool.set::<(), _, _>(key, value, expiry, None, false),
                )
                .await
                .map_err(|_| Self::timed_out("set"))?
                .map_err(|e| Self::redis_err("set", e))
            }
        }
    }

    /// `SET key value NX [PX ttl]`: true when this call stored the value.
    pub async fn set_nx(
        &self,
        key: impl AsRef<str>,
        value: impl AsRef<str>,
        ttl: Option<Duration>,
    ) -> Result<bool, AppError> {
        let key = key.as_ref();
        let value = value.as_ref();
        match self {
            Store::Memory(memory) => Ok(memory.transaction(|ks| ks.set_nx(key, value, ttl))),
            Store::Redis(pool) => {
                let expiry = ttl.map(|d| Expiration::PX(d.as_millis().max(1) as i64));
                let stored: Option<String> = tokio::time::timeout(
                    crate::timeouts::REQUEST_PATH,
                    pool.set(key, value, expiry, Some(SetOptions::NX), false),
                )
                .await
                .map_err(|_| Self::timed_out("set nx"))?
                .map_err(|e| Self::redis_err("set nx", e))?;
                Ok(stored.is_some())
            }
        }
    }

    /// `PUBLISH channel message`: how many subscribers received it.
    pub async fn publish(
        &self,
        channel: impl AsRef<str>,
        message: impl AsRef<str>,
    ) -> Result<i64, AppError> {
        let channel = channel.as_ref();
        let message = message.as_ref();
        match self {
            Store::Memory(memory) => Ok(memory.publish(channel, message) as i64),
            Store::Redis(pool) => tokio::time::timeout(
                crate::timeouts::REQUEST_PATH,
                pool.next().publish::<i64, _, _>(channel, message),
            )
            .await
            .map_err(|_| Self::timed_out("publish"))?
            .map_err(|e| Self::redis_err("publish", e)),
        }
    }

    /// `GET key`.
    pub async fn get(&self, key: impl AsRef<str>) -> Result<Option<String>, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => memory
                .transaction(|ks| ks.get_str(key))
                .map_err(|_| Self::wrong_type(key)),
            Store::Redis(pool) => tokio::time::timeout(
                crate::timeouts::REQUEST_PATH,
                pool.get::<Option<String>, _>(key),
            )
            .await
            .map_err(|_| Self::timed_out("get"))?
            .map_err(|e| Self::redis_err("get", e)),
        }
    }

    /// `GETDEL key`: reads and removes in one step (single-use values).
    pub async fn getdel(&self, key: impl AsRef<str>) -> Result<Option<String>, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => memory
                .transaction(|ks| {
                    let value = ks.get_str(key)?;
                    if value.is_some() {
                        ks.del(key);
                    }
                    Ok(value)
                })
                .map_err(|_: crate::memory::WrongType| Self::wrong_type(key)),
            Store::Redis(pool) => tokio::time::timeout(
                crate::timeouts::REQUEST_PATH,
                pool.getdel::<Option<String>, _>(key),
            )
            .await
            .map_err(|_| Self::timed_out("getdel"))?
            .map_err(|e| Self::redis_err("getdel", e)),
        }
    }

    /// `DEL key`: how many keys were removed.
    pub async fn del(&self, key: impl AsRef<str>) -> Result<i64, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => Ok(i64::from(memory.transaction(|ks| ks.del(key)))),
            Store::Redis(pool) => {
                let removed: i64 =
                    tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.del(key))
                        .await
                        .map_err(|_| Self::timed_out("del"))?
                        .map_err(|e| Self::redis_err("del", e))?;
                Ok(removed)
            }
        }
    }

    /// `EXISTS key`: 1 when present, else 0.
    pub async fn exists(&self, key: impl AsRef<str>) -> Result<i64, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => Ok(i64::from(memory.transaction(|ks| ks.exists(key)))),
            Store::Redis(pool) => {
                let n: i64 = tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.exists(key))
                    .await
                    .map_err(|_| Self::timed_out("exists"))?
                    .map_err(|e| Self::redis_err("exists", e))?;
                Ok(n)
            }
        }
    }

    /// `INCR key` with no expiry. Returns the new value.
    pub async fn incr(&self, key: impl AsRef<str>) -> Result<i64, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => memory
                .transaction(|ks| ks.incr_by(key, 1))
                .map_err(|_| Self::wrong_type(key)),
            Store::Redis(pool) => {
                tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.incr(key))
                    .await
                    .map_err(|_| Self::timed_out("incr"))?
                    .map_err(|e| Self::redis_err("incr", e))
            }
        }
    }

    /// `INCR key`, then expire it after `ttl` when the key was just created
    /// (so a counter's window starts at its first hit). Returns the new value.
    pub async fn incr_with_ttl(
        &self,
        key: impl AsRef<str>,
        ttl: Duration,
    ) -> Result<i64, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => memory
                .transaction(|ks| {
                    let value = ks.incr_by(key, 1)?;
                    if value == 1 {
                        ks.expire(key, ttl);
                    }
                    Ok(value)
                })
                .map_err(|_: crate::memory::WrongType| Self::wrong_type(key)),
            Store::Redis(pool) => {
                let value: i64 =
                    tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.incr(key))
                        .await
                        .map_err(|_| Self::timed_out("incr"))?
                        .map_err(|e| Self::redis_err("incr", e))?;
                if value == 1 {
                    let _: bool = tokio::time::timeout(
                        crate::timeouts::REQUEST_PATH,
                        pool.pexpire(key, ttl.as_millis().max(1) as i64, None),
                    )
                    .await
                    .map_err(|_| Self::timed_out("expire"))?
                    .map_err(|e| Self::redis_err("expire", e))?;
                }
                Ok(value)
            }
        }
    }

    /// `TTL key` with Redis' answers: `-2` no such key, `-1` no expiry, else
    /// the seconds left.
    pub async fn ttl(&self, key: impl AsRef<str>) -> Result<i64, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => Ok(match memory.transaction(|ks| ks.ttl(key)) {
                None => -2,
                Some(None) => -1,
                Some(Some(left)) => left.as_secs() as i64,
            }),
            Store::Redis(pool) => {
                tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.ttl(key))
                    .await
                    .map_err(|_| Self::timed_out("ttl"))?
                    .map_err(|e| Self::redis_err("ttl", e))
            }
        }
    }

    /// Remaining lifetime of `key` in seconds: `None` when the key is absent
    /// or has no expiry.
    pub async fn ttl_secs(&self, key: impl AsRef<str>) -> Result<Option<i64>, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => Ok(memory
                .transaction(|ks| ks.ttl(key))
                .flatten()
                .map(|d| d.as_secs() as i64)),
            Store::Redis(pool) => {
                let ttl: i64 = tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.ttl(key))
                    .await
                    .map_err(|_| Self::timed_out("ttl"))?
                    .map_err(|e| Self::redis_err("ttl", e))?;
                Ok((ttl >= 0).then_some(ttl))
            }
        }
    }

    /// `SADD key member`: true when the member was new.
    pub async fn sadd(
        &self,
        key: impl AsRef<str>,
        member: impl AsRef<str>,
    ) -> Result<bool, AppError> {
        let key = key.as_ref();
        let member = member.as_ref();
        match self {
            Store::Memory(memory) => memory
                .transaction(|ks| ks.sadd(key, member))
                .map_err(|_| Self::wrong_type(key)),
            Store::Redis(pool) => {
                let added: i64 =
                    tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.sadd(key, member))
                        .await
                        .map_err(|_| Self::timed_out("sadd"))?
                        .map_err(|e| Self::redis_err("sadd", e))?;
                Ok(added > 0)
            }
        }
    }

    /// `SREM key member`.
    pub async fn srem(
        &self,
        key: impl AsRef<str>,
        member: impl AsRef<str>,
    ) -> Result<bool, AppError> {
        let key = key.as_ref();
        let member = member.as_ref();
        match self {
            Store::Memory(memory) => memory
                .transaction(|ks| ks.srem(key, member))
                .map_err(|_| Self::wrong_type(key)),
            Store::Redis(pool) => {
                let removed: i64 =
                    tokio::time::timeout(crate::timeouts::REQUEST_PATH, pool.srem(key, member))
                        .await
                        .map_err(|_| Self::timed_out("srem"))?
                        .map_err(|e| Self::redis_err("srem", e))?;
                Ok(removed > 0)
            }
        }
    }

    /// `SMEMBERS key`.
    pub async fn smembers(&self, key: impl AsRef<str>) -> Result<HashSet<String>, AppError> {
        let key = key.as_ref();
        match self {
            Store::Memory(memory) => memory
                .transaction(|ks| ks.smembers(key))
                .map_err(|_| Self::wrong_type(key)),
            Store::Redis(pool) => tokio::time::timeout(
                crate::timeouts::REQUEST_PATH,
                pool.smembers::<HashSet<String>, _>(key),
            )
            .await
            .map_err(|_| Self::timed_out("smembers"))?
            .map_err(|e| Self::redis_err("smembers", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_has_no_redis_pool() {
        let store = Store::memory();
        assert!(store.is_memory());
        assert!(store.redis().is_err());
    }

    #[tokio::test]
    async fn memory_primitives_round_trip() {
        let store = Store::memory();
        store.set("k", "v", None).await.unwrap();
        assert_eq!(store.get("k").await.unwrap().as_deref(), Some("v"));
        assert!(!store.set_nx("k", "other", None).await.unwrap());
        assert!(store.set_nx("n", "1", None).await.unwrap());
        assert_eq!(store.exists("k").await.unwrap(), 1);
        assert_eq!(store.del("k").await.unwrap(), 1);
        assert_eq!(store.get("k").await.unwrap(), None);
        let ttl = Duration::from_secs(30);
        assert_eq!(store.incr_with_ttl("c", ttl).await.unwrap(), 1);
        assert_eq!(store.incr_with_ttl("c", ttl).await.unwrap(), 2);
        assert!(store.ttl_secs("c").await.unwrap().is_some());
        assert!(store.sadd("s", "a").await.unwrap());
        assert!(!store.sadd("s", "a").await.unwrap());
        assert_eq!(store.smembers("s").await.unwrap().len(), 1);
        assert!(store.srem("s", "a").await.unwrap());
    }

    #[test]
    fn debug_prints_only_the_variant() {
        assert_eq!(format!("{:?}", Store::memory()), "Store::Memory");
    }
}
