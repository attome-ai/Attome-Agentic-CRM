//! BIN-FX1 — one pooled [`GenerationClient`] per live `AppConfig`.
//!
//! Building a client per turn or per action call built a fresh
//! `reqwest::Client`, and with it a fresh TCP/TLS handshake every call. The
//! client is cheap to clone (its connection pool is shared), so this keeps one
//! per configuration and hands out clones.
//!
//! Cache contract (caching-and-state): source of truth is the process's
//! `Arc<AppConfig>`, which is immutable for its lifetime; the key is that
//! `Arc`'s identity, held as a `Weak` so the entry dies with its config (a new
//! config is a new key, never a stale hit); no TTL is needed; nothing is
//! shared across nodes; a cold start builds on first use; a build failure is
//! returned and nothing is cached.

use std::sync::{Arc, Mutex, PoisonError, Weak};

use attome_config::AppConfig;
use attome_inference::{GenerationClient, InferenceError};

type Slot<K, C> = Mutex<Vec<(Weak<K>, C)>>;

static GENERATION: Slot<AppConfig, GenerationClient> = Mutex::new(Vec::new());

/// The generation client for `config.inference.generation`, built once per
/// config and cloned per call.
pub fn generation_client(config: &Arc<AppConfig>) -> Result<GenerationClient, InferenceError> {
    cached(&GENERATION, config, |config| {
        GenerationClient::new(&config.inference)
    })
}

fn cached<K, C: Clone, E>(
    slot: &Slot<K, C>,
    key: &Arc<K>,
    build: impl FnOnce(&K) -> Result<C, E>,
) -> Result<C, E> {
    let mut entries = slot.lock().unwrap_or_else(PoisonError::into_inner);
    entries.retain(|(owner, _)| owner.strong_count() > 0);
    if let Some((_, client)) = entries
        .iter()
        .find(|(owner, _)| std::ptr::eq(owner.as_ptr(), Arc::as_ptr(key)))
    {
        return Ok(client.clone());
    }
    let client = build(key)?;
    entries.push((Arc::downgrade(key), client.clone()));
    Ok(client)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn a_config_builds_once_a_new_config_builds_its_own_and_a_dropped_one_is_pruned() {
        let slot: Slot<String, usize> = Mutex::new(Vec::new());
        let builds = AtomicUsize::new(0);
        let build = |_: &String| -> Result<usize, ()> { Ok(builds.fetch_add(1, Ordering::SeqCst)) };

        let first = Arc::new("a".to_owned());
        assert_eq!(cached(&slot, &first, build), Ok(0));
        assert_eq!(cached(&slot, &first, build), Ok(0), "reused, not rebuilt");
        assert_eq!(builds.load(Ordering::SeqCst), 1);

        let second = Arc::new("a".to_owned());
        assert_eq!(
            cached(&slot, &second, build),
            Ok(1),
            "keyed by identity, not value"
        );

        drop(first);
        assert_eq!(cached(&slot, &second, build), Ok(1));
        assert_eq!(
            slot.lock().unwrap().len(),
            1,
            "the dropped config's entry is gone"
        );

        let failing = Arc::new("b".to_owned());
        assert_eq!(cached(&slot, &failing, |_| Err::<usize, ()>(())), Err(()));
        assert_eq!(
            slot.lock().unwrap().len(),
            1,
            "a failed build caches nothing"
        );
    }
}
