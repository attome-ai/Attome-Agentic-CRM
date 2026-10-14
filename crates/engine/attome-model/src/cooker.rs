//! The deterministic cooker (roadmap Y1-T6): a version's objects become
//! content-hashed artefacts the runtime serves from memory.
//!
//! Each object is cooked by its kind on its own, under the key
//! `<kind>:<object id>`. The object's *input hash* covers its own content
//! hash and the content hashes of the objects it references within the
//! version, so changing one object recooks exactly it and what reads it; an
//! unchanged input hash reuses the previous artefact. Inputs are sorted by
//! (kind, id) and every map is a `BTreeMap`, so the same version always cooks
//! to byte-identical artefacts. Kinds must not put timestamps or random ids
//! in a payload.
//!
//! [`cook`] is pure: it returns the manifest and the artefacts that are new;
//! [`write_artefacts`] stores them (`INSERT ... ON CONFLICT DO NOTHING`, one
//! short statement each, never inside a long transaction).

use std::collections::BTreeMap;

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::KindRegistry;
use crate::canonical::content_hash;
use crate::identity::ObjectRef;
use crate::kind::{Artefact, CookInput};
use crate::validate::VersionSet;

/// One cooked artefact in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// SHA-256 of the payload (`metadata_artefact.content_hash`).
    pub content_hash: String,
    /// The input hash it was cooked from.
    pub input_hash: String,
}

/// Every artefact of a cooked version, by key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookManifest {
    pub artefacts: BTreeMap<String, ManifestEntry>,
}

/// The result of a cook: the manifest and the artefacts not cooked before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cooked {
    pub manifest: CookManifest,
    pub new_artefacts: Vec<(String, Artefact)>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Cooks `set`, reusing `previous`'s artefacts whose inputs did not change.
pub fn cook(
    set: &VersionSet,
    previous: Option<&CookManifest>,
    registry: &KindRegistry,
) -> Result<Cooked, AppError> {
    let mut objects: Vec<_> = set.objects.iter().collect();
    objects.sort_by_key(|o| (o.kind, o.id));

    // Every document in its kind's current shape (Y1-T12): an older stored
    // row is upgraded here, never rewritten.
    let mut docs: BTreeMap<ObjectRef, serde_json::Value> = BTreeMap::new();
    for object in &objects {
        let kind = registry
            .get(object.kind.as_str())
            .ok_or_else(|| AppError::Validation(format!("no metadata kind `{}`", object.kind)))?;
        let doc = crate::upgrade::upgrade_to_current(
            kind.as_ref(),
            object.schema_version,
            object.doc.clone(),
        )?;
        docs.insert(
            ObjectRef {
                kind: object.kind,
                id: object.id,
            },
            doc,
        );
    }

    // Content hash of every object in the version, for input hashing.
    let mut hashes: BTreeMap<ObjectRef, String> = BTreeMap::new();
    for object in &objects {
        let me = ObjectRef {
            kind: object.kind,
            id: object.id,
        };
        let hash = content_hash(&docs[&me]).map_err(AppError::Validation)?;
        hashes.insert(
            ObjectRef {
                kind: object.kind,
                id: object.id,
            },
            hash,
        );
    }

    let mut manifest = CookManifest::default();
    let mut new_artefacts = Vec::new();
    for object in objects {
        let kind = registry
            .get(object.kind.as_str())
            .ok_or_else(|| AppError::Validation(format!("no metadata kind `{}`", object.kind)))?;
        let me = ObjectRef {
            kind: object.kind,
            id: object.id,
        };
        let mut inputs: Vec<String> = vec![format!("{}:{}={}", me.kind, me.id, hashes[&me])];
        let mut targets: Vec<ObjectRef> = kind
            .references(&docs[&me])
            .into_iter()
            .map(|r| r.target)
            .collect();
        targets.sort();
        targets.dedup();
        for target in targets {
            if let Some(hash) = hashes.get(&target) {
                inputs.push(format!("{}:{}={hash}", target.kind, target.id));
            }
        }
        let input_hash = sha256_hex(inputs.join("\n").as_bytes());
        let key_prefix = format!("{}:{}", me.kind, me.id);

        let reusable: Vec<(&String, &ManifestEntry)> = previous
            .map(|p| {
                p.artefacts
                    .iter()
                    .filter(|(key, entry)| {
                        (key.as_str() == key_prefix || key.starts_with(&format!("{key_prefix}/")))
                            && entry.input_hash == input_hash
                    })
                    .collect()
            })
            .unwrap_or_default();
        if !reusable.is_empty() {
            for (key, entry) in reusable {
                manifest.artefacts.insert(key.clone(), entry.clone());
            }
            continue;
        }

        let cooked = kind.cook(&[CookInput {
            id: object.id,
            name: object.name.clone(),
            doc: docs[&me].clone(),
        }])?;
        for (index, artefact) in cooked.into_iter().enumerate() {
            // The first artefact of an object takes its key; any further ones
            // are numbered under it.
            let key = if index == 0 {
                key_prefix.clone()
            } else {
                format!("{key_prefix}/{index}")
            };
            let entry = ManifestEntry {
                content_hash: sha256_hex(&artefact.payload),
                input_hash: input_hash.clone(),
            };
            manifest.artefacts.insert(key.clone(), entry);
            new_artefacts.push((key, artefact));
        }
    }
    Ok(Cooked {
        manifest,
        new_artefacts,
    })
}

/// Stores artefacts by content hash; an artefact already stored is kept.
pub async fn write_artefacts(
    pool: &DbPool,
    artefacts: &[(String, Artefact)],
) -> Result<(), AppError> {
    for (_, artefact) in artefacts {
        sqlx::query(
            "INSERT INTO metadata_artefact (content_hash, kind, payload) VALUES ($1, $2, $3) \
             ON CONFLICT (content_hash) DO NOTHING",
        )
        .bind(sha256_hex(&artefact.payload))
        .bind(artefact.kind.as_str())
        .bind(&artefact.payload)
        .execute(pool)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{KindName, ObjectId};
    use crate::kind::{Issue, Kind, RefMode, Reference, ValidationCtx};
    use crate::validate::VersionObject;
    use serde_json::{Value, json};
    use std::sync::Arc;

    /// Cooks `{"title", "reads": [id]}` into the title bytes.
    struct Page;

    impl Kind for Page {
        fn name(&self) -> KindName {
            KindName("test_page")
        }
        fn schema_version(&self) -> u32 {
            1
        }
        fn json_schema(&self) -> Value {
            json!({})
        }
        fn validate_shape(&self, _doc: &Value) -> Result<(), Vec<Issue>> {
            Ok(())
        }
        fn references(&self, doc: &Value) -> Vec<Reference> {
            doc["reads"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str()?.parse().ok())
                .map(|id| Reference {
                    target: ObjectRef {
                        kind: KindName("test_page"),
                        id: ObjectId(id),
                    },
                    mode: RefMode::Reads,
                })
                .collect()
        }
        fn check(&self, _doc: &Value, _ctx: &dyn ValidationCtx) -> Vec<Issue> {
            Vec::new()
        }
        fn cook(&self, docs: &[CookInput]) -> Result<Vec<Artefact>, AppError> {
            Ok(docs
                .iter()
                .map(|d| Artefact {
                    kind: KindName("test_page"),
                    source: Some(d.id),
                    payload: d.doc["title"].as_str().unwrap_or("").as_bytes().to_vec(),
                })
                .collect())
        }
        fn agent_tool_description(&self) -> &'static str {
            "a test page"
        }
    }

    fn registry() -> KindRegistry {
        let mut registry = KindRegistry::default();
        registry.register(Arc::new(Page)).unwrap();
        registry
    }

    fn page(id: ObjectId, title: &str, reads: &[ObjectId]) -> VersionObject {
        VersionObject {
            kind: KindName("test_page"),
            id,
            name: title.to_owned(),
            schema_version: 1,
            doc: json!({
                "title": title,
                "reads": reads.iter().map(ToString::to_string).collect::<Vec<_>>()
            }),
        }
    }

    #[test]
    fn same_set_cooks_identical_manifest() {
        let (a, b) = (ObjectId::new(), ObjectId::new());
        let set = VersionSet {
            objects: vec![page(b, "b", &[a]), page(a, "a", &[])],
            ..VersionSet::default()
        };
        let mut reversed = set.clone();
        reversed.objects.reverse();
        let first = cook(&set, None, &registry()).unwrap();
        let second = cook(&reversed, None, &registry()).unwrap();
        assert_eq!(
            first.manifest, second.manifest,
            "input order does not matter"
        );
        assert_eq!(first.new_artefacts.len(), 2);
        let again = cook(&set, Some(&first.manifest), &registry()).unwrap();
        assert_eq!(again.manifest, first.manifest);
        assert!(
            again.new_artefacts.is_empty(),
            "nothing changed, nothing recooked"
        );
    }

    #[test]
    fn one_change_recooks_only_dependents() {
        let (a, b, c) = (ObjectId::new(), ObjectId::new(), ObjectId::new());
        let before = VersionSet {
            objects: vec![page(a, "a", &[]), page(b, "b", &[a]), page(c, "c", &[])],
            ..VersionSet::default()
        };
        let first = cook(&before, None, &registry()).unwrap();
        let after = VersionSet {
            objects: vec![page(a, "a2", &[]), page(b, "b", &[a]), page(c, "c", &[])],
            ..VersionSet::default()
        };
        let second = cook(&after, Some(&first.manifest), &registry()).unwrap();
        let recooked: Vec<&str> = second
            .new_artefacts
            .iter()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            recooked.len(),
            2,
            "a changed and b reads a; c is reused: {recooked:?}"
        );
        assert!(recooked.contains(&format!("test_page:{a}").as_str()));
        assert!(recooked.contains(&format!("test_page:{b}").as_str()));
        assert_eq!(
            second.manifest.artefacts[&format!("test_page:{c}")],
            first.manifest.artefacts[&format!("test_page:{c}")]
        );
    }
}
