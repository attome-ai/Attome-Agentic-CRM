//! Z3-T5: what a cached value was computed from, so a write elsewhere can
//! drop exactly the entries it made stale. A [`TieredCache`] read through
//! [`get_or_load_depending`](crate::tiered::TieredCache::get_or_load_depending)
//! records its key under each [`Dependency`]; the change-feed invalidation
//! bus (`attome_core::cache_invalidation`) calls
//! [`InvalidateDeps::invalidate_dependency`] for each recorded write, on
//! every node.
//!
//! The index is this node's own (dependency -> keys), bounded: past twice
//! the cache's L1 capacity it is cleared together with the L1, which only
//! costs reloads. A key is recorded before its value loads, and the value is
//! kept only if the key is still recorded under each dependency afterwards,
//! so a load racing a write cannot keep the old value.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;

use uuid::Uuid;

/// What a cached value depends on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Dependency {
    /// Any record of the entity (a list, a count, an aggregate).
    Entity(String),
    /// One record.
    Record(String, Uuid),
}

impl Dependency {
    /// The dependencies a write of `record_id` of `entity` makes stale:
    /// the record itself and everything over its entity.
    pub fn of_write(entity: &str, record_id: Uuid) -> [Self; 2] {
        [
            Self::Record(entity.to_owned(), record_id),
            Self::Entity(entity.to_owned()),
        ]
    }
}

/// A cache that can drop the entries depending on something.
pub trait InvalidateDeps: Send + Sync {
    fn cache_name(&self) -> &'static str;

    /// Drops every entry this node recorded under `dependency`, from the L1
    /// and the shared store. Returns how many keys it dropped.
    fn invalidate_dependency<'a>(
        &'a self,
        dependency: &'a Dependency,
    ) -> Pin<Box<dyn Future<Output = usize> + Send + 'a>>;

    /// Drops this node's whole L1 and dependency index (the bus starts
    /// from the feed's current position, so nothing older may stay).
    fn flush_local(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// Dependency -> keys, with a running count of recorded pairs.
#[derive(Debug, Default)]
pub(crate) struct DepIndex {
    by_dependency: HashMap<Dependency, HashSet<String>>,
    pairs: usize,
}

impl DepIndex {
    /// Records `key` under each of `dependencies`. `false` when the index
    /// is over `limit` pairs and was cleared instead: the caller then drops
    /// its L1 too.
    pub(crate) fn record(&mut self, key: &str, dependencies: &[Dependency], limit: usize) -> bool {
        if self.pairs + dependencies.len() > limit {
            self.by_dependency.clear();
            self.pairs = 0;
            return false;
        }
        for dependency in dependencies {
            if self
                .by_dependency
                .entry(dependency.clone())
                .or_default()
                .insert(key.to_owned())
            {
                self.pairs += 1;
            }
        }
        true
    }

    /// Takes the keys recorded under `dependency`.
    pub(crate) fn take(&mut self, dependency: &Dependency) -> HashSet<String> {
        let keys = self.by_dependency.remove(dependency).unwrap_or_default();
        self.pairs = self.pairs.saturating_sub(keys.len());
        keys
    }

    pub(crate) fn clear(&mut self) {
        self.by_dependency.clear();
        self.pairs = 0;
    }

    /// Whether `key` is still recorded under every one of `dependencies`
    /// (none of them was invalidated since it was recorded).
    pub(crate) fn still_recorded(&self, key: &str, dependencies: &[Dependency]) -> bool {
        dependencies.iter().all(|dependency| {
            self.by_dependency
                .get(dependency)
                .is_some_and(|keys| keys.contains(key))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_index_takes_keys_by_dependency_and_clears_past_its_limit() {
        let mut index = DepIndex::default();
        let account = Dependency::Entity("account".to_owned());
        let one = Dependency::Record("account".to_owned(), Uuid::nil());
        assert!(index.record("a", &[account.clone(), one.clone()], 10));
        assert!(index.record("b", std::slice::from_ref(&account), 10));
        assert!(index.still_recorded("a", &[account.clone(), one.clone()]));
        assert_eq!(index.take(&one), HashSet::from(["a".to_owned()]));
        assert!(!index.still_recorded("a", &[account.clone(), one.clone()]));
        assert!(index.still_recorded("b", std::slice::from_ref(&account)));
        assert_eq!(
            index.take(&account),
            HashSet::from(["a".to_owned(), "b".to_owned()])
        );
        assert!(index.take(&account).is_empty());
        for n in 0..5 {
            assert!(index.record(&format!("k{n}"), std::slice::from_ref(&account), 5));
        }
        assert!(
            !index.record("over", std::slice::from_ref(&account), 5),
            "past the limit"
        );
        assert!(index.take(&account).is_empty(), "cleared");
    }
}
