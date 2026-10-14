//! The cooked registry (roadmap Y1-T7): the runtime's view of the published
//! metadata, served from memory.
//!
//! - **Source of truth:** `metadata_artefact`, addressed by content hash, as
//!   listed by a version's [`CookManifest`].
//! - **Key:** `(kind, key)`, the cooker's artefact key (`<kind>:<id>`).
//! - **TTL:** none. A snapshot is immutable; it is replaced whole.
//! - **Invalidation:** a version switch ([`CookedRegistry::load_version`])
//!   swaps in a new snapshot in one step; requests holding the old one keep
//!   it until they finish.
//! - **Cold start:** the current version is loaded at boot.
//!
//! Nothing here reads `metadata_object` or its versions: a request only ever
//! touches memory. A lookup that misses is a bug (the cooker produced no such
//! artefact, or the caller asked for the wrong type), so it is logged at warn
//! and counted in `attome_model_lookup_miss_total`.

use std::any::Any;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use arc_swap::ArcSwap;
use attome_db::DbPool;
use attome_types::AppError;
use serde::de::DeserializeOwned;

use crate::cooker::CookManifest;

/// One artefact: its bytes, and the decoded value once someone asked for it.
struct Entry {
    payload: Arc<[u8]>,
    decoded: OnceLock<Option<Arc<dyn Any + Send + Sync>>>,
}

/// One published version's artefacts.
#[derive(Default)]
pub struct CookedSnapshot {
    pub version: i64,
    pub manifest: CookManifest,
    entries: BTreeMap<(String, String), Entry>,
}

impl std::fmt::Debug for CookedSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookedSnapshot")
            .field("version", &self.version)
            .field("artefacts", &self.entries.len())
            .finish()
    }
}

/// The in-memory registry of the current published version.
pub struct CookedRegistry {
    current: ArcSwap<CookedSnapshot>,
    misses: AtomicU64,
}

impl std::fmt::Debug for CookedRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookedRegistry")
            .field("current", &self.current.load())
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .finish()
    }
}

impl Default for CookedRegistry {
    fn default() -> Self {
        Self {
            current: ArcSwap::from_pointee(CookedSnapshot::default()),
            misses: AtomicU64::new(0),
        }
    }
}

/// The kind part of an artefact key (`form:0190...` -> `form`).
fn kind_of(key: &str) -> &str {
    key.split(':').next().unwrap_or(key)
}

impl CookedRegistry {
    /// The current snapshot; hold it for a whole request.
    pub fn snapshot(&self) -> Arc<CookedSnapshot> {
        self.current.load_full()
    }

    /// How many lookups have missed since start.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    fn miss(&self, kind: &str, key: &str, why: &str) {
        self.misses.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("attome_model_lookup_miss_total", "kind" => kind.to_owned()).increment(1);
        tracing::warn!(kind, key, why, "cooked metadata lookup missed");
    }

    /// The artefact `(kind, key)` decoded as `T`, from memory only. The first
    /// lookup decodes it; later ones share the value.
    pub fn get<T: DeserializeOwned + Send + Sync + 'static>(
        &self,
        kind: &str,
        key: &str,
    ) -> Option<Arc<T>> {
        let snapshot = self.current.load();
        let Some(entry) = snapshot.entries.get(&(kind.to_owned(), key.to_owned())) else {
            self.miss(kind, key, "no such artefact");
            return None;
        };
        let decoded = entry.decoded.get_or_init(|| {
            serde_json::from_slice::<T>(&entry.payload)
                .ok()
                .map(|value| Arc::new(value) as Arc<dyn Any + Send + Sync>)
        });
        match decoded.clone().map(Arc::downcast::<T>) {
            Some(Ok(value)) => Some(value),
            _ => {
                self.miss(
                    kind,
                    key,
                    "the artefact does not decode as the requested type",
                );
                None
            }
        }
    }

    /// Builds a snapshot from artefact payloads already in hand (by content
    /// hash) and swaps it in. Every manifest entry must have its payload.
    pub fn load_from_artefacts(
        &self,
        version: i64,
        manifest: CookManifest,
        payloads: &BTreeMap<String, Vec<u8>>,
    ) -> Result<(), AppError> {
        let mut entries = BTreeMap::new();
        for (key, entry) in &manifest.artefacts {
            let payload = payloads.get(&entry.content_hash).ok_or_else(|| {
                AppError::internal(format!(
                    "artefact {} for {key} is missing from metadata_artefact",
                    entry.content_hash
                ))
            })?;
            entries.insert(
                (kind_of(key).to_owned(), key.clone()),
                Entry {
                    payload: Arc::from(payload.as_slice()),
                    decoded: OnceLock::new(),
                },
            );
        }
        self.current.store(Arc::new(CookedSnapshot {
            version,
            manifest,
            entries,
        }));
        Ok(())
    }

    /// Fetches a version's artefacts by hash and swaps them in.
    pub async fn load_version(
        &self,
        pool: &DbPool,
        version: i64,
        manifest: CookManifest,
    ) -> Result<(), AppError> {
        let hashes: Vec<String> = manifest
            .artefacts
            .values()
            .map(|entry| entry.content_hash.clone())
            .collect();
        let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
            "SELECT content_hash, payload FROM metadata_artefact WHERE content_hash = ANY($1)",
        )
        .bind(&hashes)
        .fetch_all(pool)
        .await
        .map_err(AppError::internal)?;
        let payloads: BTreeMap<String, Vec<u8>> = rows.into_iter().collect();
        self.load_from_artefacts(version, manifest, &payloads)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cooker::ManifestEntry;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    struct Form {
        title: String,
    }

    fn version(title: &str) -> (CookManifest, BTreeMap<String, Vec<u8>>) {
        let payload = format!("{{\"title\":\"{title}\"}}").into_bytes();
        let hash = format!("hash-{title}");
        let mut manifest = CookManifest::default();
        manifest.artefacts.insert(
            "form:1".to_owned(),
            ManifestEntry {
                content_hash: hash.clone(),
                input_hash: "i".to_owned(),
            },
        );
        (manifest, BTreeMap::from([(hash, payload)]))
    }

    #[test]
    fn old_arc_survives_swap() {
        let registry = CookedRegistry::default();
        let (manifest, payloads) = version("first");
        registry
            .load_from_artefacts(1, manifest, &payloads)
            .unwrap();
        let held = registry.get::<Form>("form", "form:1").unwrap();
        let (manifest, payloads) = version("second");
        registry
            .load_from_artefacts(2, manifest, &payloads)
            .unwrap();
        assert_eq!(
            held.title, "first",
            "a value taken before the swap is unchanged"
        );
        assert_eq!(
            registry.get::<Form>("form", "form:1").unwrap().title,
            "second"
        );
        assert_eq!(registry.snapshot().version, 2);
    }

    #[test]
    fn miss_is_counted() {
        let registry = CookedRegistry::default();
        assert!(registry.get::<Form>("form", "form:404").is_none());
        let (manifest, payloads) = version("x");
        registry
            .load_from_artefacts(1, manifest, &payloads)
            .unwrap();
        assert!(
            registry.get::<Vec<u8>>("form", "form:1").is_none(),
            "wrong type"
        );
        assert_eq!(registry.misses(), 2);
        let (manifest, _) = version("y");
        assert!(
            registry
                .load_from_artefacts(2, manifest, &BTreeMap::new())
                .is_err(),
            "a manifest entry without its payload is refused"
        );
    }
}
