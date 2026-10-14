//! The in-process key-value store Solo runs on instead of Redis (A5).
//!
//! It holds the data types the platform's Redis use needs (strings, hashes,
//! sets and sorted sets, each with an optional expiry) and pub/sub channels,
//! all in one process. A single server needs no cross-node coordination, so
//! process memory is a sound home for what Redis holds elsewhere: caches,
//! rate-limit windows, replay nonces and revocation markers (guidelines §5:
//! every one of these is reconstructable or fails closed on loss, and a
//! restart clears them, as a Redis restart without persistence would).
//!
//! **Atomicity.** Redis runs a Lua script as one step; here
//! [`MemoryStore::transaction`] runs a closure with the store locked, so a
//! read-modify-write sequence (a rate-limit window, a token budget) is atomic
//! in the same sense. The lock is a `std::sync::Mutex` held only inside that
//! closure, never across an `.await`.
//!
//! **Expiry** is lazy: an expired entry is dropped when touched, and
//! [`MemoryStore::sweep_expired`] reclaims the rest (the owner runs it
//! periodically).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::broadcast;

/// Capacity of each pub/sub channel's buffer: a subscriber that falls this
/// far behind sees `Lagged` and resynchronises from its source of truth, as
/// it must after a Redis reconnect.
const CHANNEL_CAPACITY: usize = 1024;

/// One stored value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Hash(HashMap<String, String>),
    Set(HashSet<String>),
    /// Members ordered by `(score, member)`, plus each member's score.
    ZSet(ZSet),
}

/// A sorted set: Redis' ordering is by score, then member.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ZSet {
    ordered: BTreeSet<(Score, String)>,
    scores: HashMap<String, f64>,
}

/// A total order over `f64` scores (NaN never stored: callers pass numbers).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Score(f64);

impl Eq for Score {}

impl PartialOrd for Score {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Score {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl ZSet {
    /// Adds or re-scores `member`.
    pub fn add(&mut self, score: f64, member: &str) {
        if let Some(old) = self.scores.insert(member.to_owned(), score) {
            self.ordered.remove(&(Score(old), member.to_owned()));
        }
        self.ordered.insert((Score(score), member.to_owned()));
    }

    /// Removes `member`; true when it was present (Redis `ZREM`).
    pub fn remove(&mut self, member: &str) -> bool {
        match self.scores.remove(member) {
            Some(score) => {
                self.ordered.remove(&(Score(score), member.to_owned()));
                true
            }
            None => false,
        }
    }

    /// Removes members scored within `[min, max]`; returns how many.
    pub fn remove_range_by_score(&mut self, min: f64, max: f64) -> usize {
        let doomed: Vec<(Score, String)> = self
            .ordered
            .iter()
            .filter(|(score, _)| score.0 >= min && score.0 <= max)
            .cloned()
            .collect();
        for entry in &doomed {
            self.ordered.remove(entry);
            self.scores.remove(&entry.1);
        }
        doomed.len()
    }

    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ordered.is_empty()
    }

    /// The lowest-scored member and its score.
    pub fn first(&self) -> Option<(f64, &str)> {
        self.ordered
            .iter()
            .next()
            .map(|(score, member)| (score.0, member.as_str()))
    }

    /// Members in score order.
    pub fn members(&self) -> impl Iterator<Item = (f64, &str)> {
        self.ordered
            .iter()
            .map(|(score, member)| (score.0, member.as_str()))
    }
}

#[derive(Debug, Clone)]
struct Entry {
    value: Value,
    expires_at: Option<Instant>,
}

impl Entry {
    fn live(&self, now: Instant) -> bool {
        self.expires_at.is_none_or(|at| at > now)
    }
}

/// The keyspace, as a transaction closure sees it. Every method observes
/// expiry, so an expired key reads as absent.
#[derive(Debug, Default)]
pub struct Keyspace {
    entries: HashMap<String, Entry>,
}

/// A value of the wrong type for the operation (Redis' `WRONGTYPE`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("operation against a key holding the wrong kind of value: {0}")]
pub struct WrongType(pub String);

impl Keyspace {
    fn entry(&mut self, key: &str) -> Option<&mut Entry> {
        let now = Instant::now();
        if self.entries.get(key).is_some_and(|entry| !entry.live(now)) {
            self.entries.remove(key);
        }
        self.entries.get_mut(key)
    }

    /// The value at `key`, if live.
    pub fn get(&mut self, key: &str) -> Option<&Value> {
        self.entry(key).map(|entry| &entry.value)
    }

    /// The string at `key`, if live.
    pub fn get_str(&mut self, key: &str) -> Result<Option<String>, WrongType> {
        match self.entry(key).map(|entry| &entry.value) {
            None => Ok(None),
            Some(Value::Str(s)) => Ok(Some(s.clone())),
            Some(_) => Err(WrongType(key.to_owned())),
        }
    }

    /// Stores a string, replacing any value and expiry (`SET key value [PX ttl]`).
    pub fn set(&mut self, key: &str, value: &str, ttl: Option<Duration>) {
        self.entries.insert(
            key.to_owned(),
            Entry {
                value: Value::Str(value.to_owned()),
                expires_at: ttl.map(|ttl| Instant::now() + ttl),
            },
        );
    }

    /// `SET key value NX [PX ttl]`: stores only when absent; true when stored.
    pub fn set_nx(&mut self, key: &str, value: &str, ttl: Option<Duration>) -> bool {
        if self.entry(key).is_some() {
            return false;
        }
        self.set(key, value, ttl);
        true
    }

    /// Removes `key`; true when it was live.
    pub fn del(&mut self, key: &str) -> bool {
        let existed = self.entry(key).is_some();
        self.entries.remove(key);
        existed
    }

    pub fn exists(&mut self, key: &str) -> bool {
        self.entry(key).is_some()
    }

    /// Remaining time to live: `None` for an absent key, `Some(None)` for a
    /// key with no expiry.
    pub fn ttl(&mut self, key: &str) -> Option<Option<Duration>> {
        let now = Instant::now();
        self.entry(key)
            .map(|entry| entry.expires_at.map(|at| at.saturating_duration_since(now)))
    }

    /// Sets a live key's expiry; false when the key is absent.
    pub fn expire(&mut self, key: &str, ttl: Duration) -> bool {
        match self.entry(key) {
            Some(entry) => {
                entry.expires_at = Some(Instant::now() + ttl);
                true
            }
            None => false,
        }
    }

    /// `INCRBY`: an absent key counts from 0 and keeps no expiry.
    pub fn incr_by(&mut self, key: &str, by: i64) -> Result<i64, WrongType> {
        let current = match self.entry(key) {
            None => 0,
            Some(Entry {
                value: Value::Str(s),
                ..
            }) => s.parse::<i64>().map_err(|_| WrongType(key.to_owned()))?,
            Some(_) => return Err(WrongType(key.to_owned())),
        };
        let next = current.saturating_add(by);
        match self.entry(key) {
            Some(entry) => entry.value = Value::Str(next.to_string()),
            None => self.set(key, &next.to_string(), None),
        }
        Ok(next)
    }

    fn with_hash(&mut self, key: &str) -> Result<&mut HashMap<String, String>, WrongType> {
        if self.entry(key).is_none() {
            self.entries.insert(
                key.to_owned(),
                Entry {
                    value: Value::Hash(HashMap::new()),
                    expires_at: None,
                },
            );
        }
        match self.entries.get_mut(key).map(|entry| &mut entry.value) {
            Some(Value::Hash(hash)) => Ok(hash),
            _ => Err(WrongType(key.to_owned())),
        }
    }

    /// `HSET`.
    pub fn hset(&mut self, key: &str, field: &str, value: &str) -> Result<(), WrongType> {
        self.with_hash(key)?
            .insert(field.to_owned(), value.to_owned());
        Ok(())
    }

    /// `HINCRBY`.
    pub fn hincr_by(&mut self, key: &str, field: &str, by: i64) -> Result<i64, WrongType> {
        let hash = self.with_hash(key)?;
        let current = match hash.get(field) {
            None => 0,
            Some(v) => v.parse::<i64>().map_err(|_| WrongType(key.to_owned()))?,
        };
        let next = current.saturating_add(by);
        hash.insert(field.to_owned(), next.to_string());
        Ok(next)
    }

    /// `HGETALL` (empty for an absent key).
    pub fn hgetall(&mut self, key: &str) -> Result<HashMap<String, String>, WrongType> {
        match self.entry(key).map(|entry| &entry.value) {
            None => Ok(HashMap::new()),
            Some(Value::Hash(hash)) => Ok(hash.clone()),
            Some(_) => Err(WrongType(key.to_owned())),
        }
    }

    /// `HDEL`; removes the key when the hash empties, as Redis does.
    pub fn hdel(&mut self, key: &str, field: &str) -> Result<bool, WrongType> {
        let removed = match self.entry(key).map(|entry| &mut entry.value) {
            None => return Ok(false),
            Some(Value::Hash(hash)) => hash.remove(field).is_some(),
            Some(_) => return Err(WrongType(key.to_owned())),
        };
        if matches!(self.get(key), Some(Value::Hash(hash)) if hash.is_empty()) {
            self.entries.remove(key);
        }
        Ok(removed)
    }

    fn with_set(&mut self, key: &str) -> Result<&mut HashSet<String>, WrongType> {
        if self.entry(key).is_none() {
            self.entries.insert(
                key.to_owned(),
                Entry {
                    value: Value::Set(HashSet::new()),
                    expires_at: None,
                },
            );
        }
        match self.entries.get_mut(key).map(|entry| &mut entry.value) {
            Some(Value::Set(set)) => Ok(set),
            _ => Err(WrongType(key.to_owned())),
        }
    }

    /// `SADD`; true when the member was new.
    pub fn sadd(&mut self, key: &str, member: &str) -> Result<bool, WrongType> {
        Ok(self.with_set(key)?.insert(member.to_owned()))
    }

    /// `SREM`; removes the key when the set empties.
    pub fn srem(&mut self, key: &str, member: &str) -> Result<bool, WrongType> {
        let removed = match self.entry(key).map(|entry| &mut entry.value) {
            None => return Ok(false),
            Some(Value::Set(set)) => set.remove(member),
            Some(_) => return Err(WrongType(key.to_owned())),
        };
        if matches!(self.get(key), Some(Value::Set(set)) if set.is_empty()) {
            self.entries.remove(key);
        }
        Ok(removed)
    }

    /// `SMEMBERS` (empty for an absent key).
    pub fn smembers(&mut self, key: &str) -> Result<HashSet<String>, WrongType> {
        match self.entry(key).map(|entry| &entry.value) {
            None => Ok(HashSet::new()),
            Some(Value::Set(set)) => Ok(set.clone()),
            Some(_) => Err(WrongType(key.to_owned())),
        }
    }

    /// The sorted set at `key`, created empty when absent.
    pub fn zset(&mut self, key: &str) -> Result<&mut ZSet, WrongType> {
        if self.entry(key).is_none() {
            self.entries.insert(
                key.to_owned(),
                Entry {
                    value: Value::ZSet(ZSet::default()),
                    expires_at: None,
                },
            );
        }
        match self.entries.get_mut(key).map(|entry| &mut entry.value) {
            Some(Value::ZSet(zset)) => Ok(zset),
            _ => Err(WrongType(key.to_owned())),
        }
    }

    /// Drops a sorted set, hash or set left empty by an operation (Redis
    /// never stores an empty collection).
    pub fn drop_if_empty(&mut self, key: &str) {
        let empty = match self.get(key) {
            Some(Value::ZSet(zset)) => zset.is_empty(),
            Some(Value::Hash(hash)) => hash.is_empty(),
            Some(Value::Set(set)) => set.is_empty(),
            _ => false,
        };
        if empty {
            self.entries.remove(key);
        }
    }

    /// Live keys matching a Redis glob (`*`, `?`, and literal characters).
    pub fn keys(&mut self, pattern: &str) -> Vec<String> {
        let now = Instant::now();
        self.entries.retain(|_, entry| entry.live(now));
        let mut keys: Vec<String> = self
            .entries
            .keys()
            .filter(|key| glob_match(pattern, key))
            .cloned()
            .collect();
        keys.sort_unstable();
        keys
    }

    fn sweep(&mut self) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.live(now));
        before - self.entries.len()
    }
}

/// Redis `KEYS`/`SCAN MATCH` globbing: `*` any run, `?` one character.
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// The in-process store: a locked keyspace and pub/sub channels.
#[derive(Debug, Default)]
pub struct MemoryStore {
    keyspace: Mutex<Keyspace>,
    channels: Mutex<HashMap<String, broadcast::Sender<String>>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, Keyspace> {
        // A panic inside a transaction leaves the keyspace consistent (every
        // operation completes or does nothing), so a poisoned lock is safe to
        // keep using.
        self.keyspace.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `f` with the keyspace locked: the in-process counterpart of a
    /// Redis Lua script. `f` must not block or await.
    pub fn transaction<R>(&self, f: impl FnOnce(&mut Keyspace) -> R) -> R {
        f(&mut self.lock())
    }

    /// Drops every expired entry; returns how many.
    pub fn sweep_expired(&self) -> usize {
        self.lock().sweep()
    }

    /// Delivers `message` to the channel's current subscribers; returns how
    /// many received it (Redis `PUBLISH`).
    pub fn publish(&self, channel: &str, message: &str) -> usize {
        let channels = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        channels
            .get(channel)
            .and_then(|sender| sender.send(message.to_owned()).ok())
            .unwrap_or(0)
    }

    /// Subscribes to `channel`; messages published after this call arrive.
    pub fn subscribe(&self, channel: &str) -> broadcast::Receiver<String> {
        let mut channels = self.channels.lock().unwrap_or_else(PoisonError::into_inner);
        channels
            .entry(channel.to_owned())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_set_get_and_expire() {
        let store = MemoryStore::new();
        store.transaction(|ks| {
            ks.set("a", "1", None);
            ks.set("b", "2", Some(Duration::from_millis(0)));
            assert_eq!(ks.get_str("a").unwrap(), Some("1".into()));
            assert_eq!(
                ks.get_str("b").unwrap(),
                None,
                "a zero ttl is already expired"
            );
            assert!(ks.set_nx("c", "x", None));
            assert!(!ks.set_nx("c", "y", None));
            assert_eq!(ks.incr_by("n", 5).unwrap(), 5);
            assert_eq!(ks.incr_by("n", -2).unwrap(), 3);
            assert!(ks.incr_by("c", 1).is_err(), "not a number");
            assert!(ks.del("a"));
            assert!(!ks.exists("a"));
            assert_eq!(ks.ttl("c"), Some(None));
            assert!(ks.expire("c", Duration::from_secs(60)));
            assert!(
                ks.ttl("c")
                    .flatten()
                    .is_some_and(|d| d <= Duration::from_secs(60))
            );
        });
    }

    #[test]
    fn hashes_and_sets_drop_when_empty() {
        let store = MemoryStore::new();
        store.transaction(|ks| {
            ks.hset("h", "f", "v").unwrap();
            assert_eq!(ks.hincr_by("h", "n", 4).unwrap(), 4);
            assert_eq!(ks.hgetall("h").unwrap().len(), 2);
            assert!(ks.hdel("h", "f").unwrap());
            assert!(ks.hdel("h", "n").unwrap());
            assert!(!ks.exists("h"));
            assert!(ks.sadd("s", "m").unwrap());
            assert!(!ks.sadd("s", "m").unwrap());
            assert!(ks.srem("s", "m").unwrap());
            assert!(!ks.exists("s"));
            ks.set("str", "x", None);
            assert!(ks.hset("str", "f", "v").is_err(), "wrong type");
        });
    }

    #[test]
    fn sorted_sets_order_by_score_then_member() {
        let store = MemoryStore::new();
        store.transaction(|ks| {
            let z = ks.zset("z").unwrap();
            z.add(3.0, "c");
            z.add(1.0, "b");
            z.add(1.0, "a");
            z.add(2.0, "c");
            assert_eq!(z.len(), 3);
            assert_eq!(z.first(), Some((1.0, "a")));
            let order: Vec<&str> = z.members().map(|(_, m)| m).collect();
            assert_eq!(order, ["a", "b", "c"]);
            assert_eq!(z.remove_range_by_score(0.0, 1.5), 2);
            ks.drop_if_empty("z");
            assert!(ks.exists("z"));
        });
    }

    #[test]
    fn keys_follow_redis_globs() {
        let store = MemoryStore::new();
        store.transaction(|ks| {
            for key in ["rl:a:1", "rl:b:2", "other"] {
                ks.set(key, "v", None);
            }
            assert_eq!(ks.keys("rl:*"), ["rl:a:1", "rl:b:2"]);
            assert_eq!(ks.keys("rl:?:1"), ["rl:a:1"]);
            assert_eq!(ks.keys("*"), ["other", "rl:a:1", "rl:b:2"]);
        });
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b", "acb_"));
    }

    #[test]
    fn sweep_reclaims_expired_entries() {
        let store = MemoryStore::new();
        store.transaction(|ks| {
            ks.set("gone", "v", Some(Duration::ZERO));
            ks.set("kept", "v", None);
        });
        assert_eq!(store.sweep_expired(), 1);
        assert!(store.transaction(|ks| ks.exists("kept")));
    }

    #[tokio::test]
    async fn pub_sub_delivers_to_current_subscribers() {
        let store = MemoryStore::new();
        assert_eq!(store.publish("ch", "early"), 0, "nobody listening yet");
        let mut rx = store.subscribe("ch");
        assert_eq!(store.publish("ch", "hello"), 1);
        assert_eq!(rx.recv().await.unwrap(), "hello");
    }
}
