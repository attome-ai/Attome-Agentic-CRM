//! Q16-T3: inclusion proofs and evidence packs.
//!
//! The chainer seals events in batches: each batch's leaves are its events'
//! `event_hash` values in id order, folded pairwise with SHA-256 (an odd
//! node pairs with itself) into the batch's `merkle_root`, which is signed
//! with Ed25519 over `prev_batch_hash|merkle_root` and, when anchoring is on,
//! written to `audit-chain-anchors/{organization}/{batch}.json`. A proof is
//! the sibling hashes from one leaf up to that root; anyone holding the
//! signing key's public half can check it without the database:
//!
//! 1. start from the event's `event_hash`;
//! 2. for each step, SHA-256 the two 32-byte values, the step's `hash` on
//!    the `side` it names;
//! 3. the result is `merkle_root`;
//! 4. the Ed25519 `signature` (base64) verifies against `public_key`
//!    (base64) over the bytes `prev_batch_hash|merkle_root`.

use std::collections::BTreeMap;

use attome_db::DbPool;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::chainer::hex_decode_32;

/// Which side of the running hash a sibling sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProofSide {
    Left,
    Right,
}

/// One step up the tree: the sibling's hash (hex) and its side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ProofStep {
    pub hash: String,
    pub side: ProofSide,
}

fn pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The path from leaf `index` to the root of `leaves`, built the way the
/// chainer builds the root.
pub fn merkle_path(leaves: &[[u8; 32]], index: usize) -> Vec<ProofStep> {
    let mut path = Vec::new();
    let mut level = leaves.to_vec();
    let mut i = index;
    while level.len() > 1 {
        let (sibling, side) = if i % 2 == 0 {
            (*level.get(i + 1).unwrap_or(&level[i]), ProofSide::Right)
        } else {
            (level[i - 1], ProofSide::Left)
        };
        path.push(ProofStep {
            hash: hex::encode(sibling),
            side,
        });
        level = level
            .chunks(2)
            .map(|p| pair(&p[0], p.get(1).unwrap_or(&p[0])))
            .collect();
        i /= 2;
    }
    path
}

/// The root `path` leads to from `leaf`, or `None` for a malformed step.
pub fn root_from_path(leaf: [u8; 32], path: &[ProofStep]) -> Option<[u8; 32]> {
    path.iter().try_fold(leaf, |acc, step| {
        let sibling = hex_decode_32(&step.hash).ok()?;
        Some(match step.side {
            ProofSide::Right => pair(&acc, &sibling),
            ProofSide::Left => pair(&sibling, &acc),
        })
    })
}

/// Whether `path` takes the leaf `leaf_hex` to `root_hex`.
pub fn verify_inclusion(leaf_hex: &str, path: &[ProofStep], root_hex: &str) -> bool {
    let Ok(leaf) = hex_decode_32(leaf_hex) else {
        return false;
    };
    root_from_path(leaf, path).is_some_and(|root| hex::encode(root) == root_hex)
}

/// One event's inclusion proof.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InclusionProof {
    pub event_id: Uuid,
    pub event_hash: String,
    pub batch_id: Uuid,
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub path: Vec<ProofStep>,
    pub merkle_root: String,
    pub prev_batch_hash: String,
    pub signing_key_id: Option<String>,
    /// Base64 Ed25519 signature over `prev_batch_hash|merkle_root`.
    pub signature: Option<String>,
    /// Base64 public half of the signing key, from `audit_signing_key`.
    pub public_key: Option<String>,
    /// Where the batch root is anchored when external anchoring is on.
    pub anchor_key: String,
}

/// A sealed batch, with its leaves in order.
struct Batch {
    organization: Uuid,
    prev_batch_hash: String,
    merkle_root: String,
    signing_key_id: Option<String>,
    signature: Option<String>,
    public_key: Option<String>,
    /// (event id, event hash) in id order.
    leaves: Vec<(Uuid, String)>,
}

async fn load_batch(db: &DbPool, batch_id: Uuid) -> Result<Batch, AppError> {
    let row: Option<(Uuid, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT organization_ref, prev_batch_hash, merkle_root, signing_key_id, signature
           FROM audit_chain_batch WHERE id = $1",
    )
    .bind(batch_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (organization, prev_batch_hash, merkle_root, signing_key_id, signature) =
        row.ok_or_else(|| AppError::internal("an event names a chain batch that does not exist"))?;
    let leaves: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, event_hash FROM audit_header
          WHERE organization_ref = $1 AND chain_batch_ref = $2
          ORDER BY id",
    )
    .bind(organization)
    .bind(batch_id)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let public_key: Option<String> = match &signing_key_id {
        Some(key_id) => {
            sqlx::query_scalar("SELECT public_key FROM audit_signing_key WHERE key_id = $1")
                .bind(key_id)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?
        }
        None => None,
    };
    Ok(Batch {
        organization,
        prev_batch_hash,
        merkle_root,
        signing_key_id,
        signature,
        public_key,
        leaves,
    })
}

fn proof_in(batch_id: Uuid, batch: &Batch, event_id: Uuid) -> Result<InclusionProof, AppError> {
    let index = batch
        .leaves
        .iter()
        .position(|(id, _)| *id == event_id)
        .ok_or_else(|| AppError::internal("an event is missing from its own chain batch"))?;
    let hashes: Vec<[u8; 32]> = batch
        .leaves
        .iter()
        .map(|(_, hash)| hex_decode_32(hash))
        .collect::<Result<_, _>>()?;
    let path = merkle_path(&hashes, index);
    let event_hash = batch.leaves[index].1.clone();
    // A proof that does not lead to the stored root means the stored rows
    // were changed: refuse it rather than hand out evidence that fails.
    if !verify_inclusion(&event_hash, &path, &batch.merkle_root) {
        tracing::error!(%batch_id, %event_id, "audit batch leaves no longer reproduce its root");
        return Err(AppError::internal(
            "the audit batch no longer reproduces its signed root",
        ));
    }
    Ok(InclusionProof {
        event_id,
        event_hash,
        batch_id,
        leaf_index: index,
        leaf_count: batch.leaves.len(),
        path,
        merkle_root: batch.merkle_root.clone(),
        prev_batch_hash: batch.prev_batch_hash.clone(),
        signing_key_id: batch.signing_key_id.clone(),
        signature: batch.signature.clone(),
        public_key: batch.public_key.clone(),
        anchor_key: format!("audit-chain-anchors/{}/{batch_id}.json", batch.organization),
    })
}

/// The inclusion proof of the event `event_id`: `NotFound` when there is no
/// such event, `Conflict` while it waits to be sealed into a batch.
pub async fn proof_for(db: &DbPool, event_id: Uuid) -> Result<InclusionProof, AppError> {
    let batch_id: Option<Option<Uuid>> =
        sqlx::query_scalar("SELECT chain_batch_ref FROM audit_header WHERE id = $1")
            .bind(event_id)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let batch_id = batch_id
        .ok_or(AppError::NotFound)?
        .ok_or(AppError::Conflict(
            "the event has not been sealed into a chain batch yet",
        ))?;
    let batch = load_batch(db, batch_id).await?;
    proof_in(batch_id, &batch, event_id)
}

/// The most events one evidence pack holds.
pub const MAX_PACK_EVENTS: i64 = 2_000;

/// What an evidence pack covers: a time range, or one record.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EvidencePackRequest {
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    pub to: Option<chrono::DateTime<chrono::Utc>>,
    pub entity_name: Option<String>,
    pub record_id: Option<Uuid>,
}

/// A public signing key.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PackKey {
    pub key_id: String,
    pub public_key: String,
    pub retired_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Events, their proofs, the public keys and how to check them offline.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EvidencePack {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Vec<Object>)]
    pub events: Vec<serde_json::Value>,
    pub proofs: Vec<InclusionProof>,
    pub public_keys: Vec<PackKey>,
    pub how_to_verify: Vec<String>,
}

/// Builds the evidence pack for `request`: every sealed event in range (at
/// most [`MAX_PACK_EVENTS`]), each with its proof.
pub async fn evidence_pack(
    db: &DbPool,
    request: &EvidencePackRequest,
) -> Result<EvidencePack, AppError> {
    type EventRow = (
        Uuid,
        Option<Uuid>,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
        Option<Uuid>,
        Option<i32>,
        Option<Uuid>,
        Option<chrono::DateTime<chrono::Utc>>,
        String,
        i16,
        Uuid,
    );
    let rows: Vec<EventRow> = match (request, request.from, request.to) {
        (
            EvidencePackRequest {
                entity_name: Some(entity),
                record_id: Some(record),
                ..
            },
            _,
            _,
        ) => sqlx::query_as(
            "SELECT id, organization_ref, created_at, entity_name, record_id, operation, user_id,
                    changed_on, event_hash, hash_version, chain_batch_ref
               FROM audit_header
              WHERE entity_name = $1 AND record_id = $2 AND chain_batch_ref IS NOT NULL
              ORDER BY id LIMIT $3",
        )
        .bind(entity)
        .bind(record)
        .bind(MAX_PACK_EVENTS + 1)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?,
        (_, Some(from), Some(to)) if from < to => sqlx::query_as(
            "SELECT id, organization_ref, created_at, entity_name, record_id, operation, user_id,
                    changed_on, event_hash, hash_version, chain_batch_ref
               FROM audit_header
              WHERE created_at >= $1 AND created_at < $2 AND chain_batch_ref IS NOT NULL
              ORDER BY id LIMIT $3",
        )
        .bind(from)
        .bind(to)
        .bind(MAX_PACK_EVENTS + 1)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?,
        _ => {
            return Err(AppError::Validation(
                "an evidence pack covers a time range (from before to) or one record \
                 (entity_name and record_id)"
                    .into(),
            ));
        }
    };
    if rows.len() as i64 > MAX_PACK_EVENTS {
        return Err(AppError::Validation(format!(
            "the range holds more than {MAX_PACK_EVENTS} sealed events; narrow it"
        )));
    }
    let mut batches: BTreeMap<Uuid, Batch> = BTreeMap::new();
    let mut proofs = Vec::with_capacity(rows.len());
    let mut events = Vec::with_capacity(rows.len());
    for (
        id,
        org,
        created_at,
        entity,
        record,
        operation,
        user,
        changed_on,
        hash,
        version,
        batch_id,
    ) in rows
    {
        if let std::collections::btree_map::Entry::Vacant(slot) = batches.entry(batch_id) {
            slot.insert(load_batch(db, batch_id).await?);
        }
        let batch = &batches[&batch_id];
        proofs.push(proof_in(batch_id, batch, id)?);
        events.push(serde_json::json!({
            "id": id, "organization_ref": org, "created_at": created_at,
            "entity_name": entity, "record_id": record, "operation": operation,
            "user_id": user, "changed_on": changed_on, "event_hash": hash,
            "hash_version": version, "chain_batch_ref": batch_id,
        }));
    }
    let public_keys: Vec<PackKey> =
        sqlx::query_as::<_, (String, String, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT key_id, public_key, retired_at FROM audit_signing_key ORDER BY created_at",
        )
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(key_id, public_key, retired_at)| PackKey {
            key_id,
            public_key,
            retired_at,
        })
        .collect();
    Ok(EvidencePack {
        generated_at: chrono::Utc::now(),
        events,
        proofs,
        public_keys,
        how_to_verify: vec![
            "For each proof, start from event_hash (hex).".into(),
            "For each step in path, SHA-256 the two 32-byte values with step.hash on the side \
             step.side names."
                .into(),
            "The result must equal merkle_root.".into(),
            "Verify the Ed25519 signature (base64) with the public key (base64) of \
             signing_key_id over the bytes prev_batch_hash|merkle_root."
                .into(),
            "With external anchoring on, the object at anchor_key holds the same root.".into(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> [u8; 32] {
        Sha256::digest([n]).into()
    }

    #[test]
    fn every_leaf_proves_into_the_chainers_root() {
        for count in 1..=9u8 {
            let leaves: Vec<[u8; 32]> = (0..count).map(leaf).collect();
            let root = crate::chainer::merkle_root(&leaves);
            for (index, l) in leaves.iter().enumerate() {
                let path = merkle_path(&leaves, index);
                assert!(
                    verify_inclusion(&hex::encode(l), &path, &root),
                    "leaf {index} of {count}"
                );
            }
        }
    }

    #[test]
    fn a_changed_leaf_or_step_fails() {
        let leaves: Vec<[u8; 32]> = (0..5u8).map(leaf).collect();
        let root = crate::chainer::merkle_root(&leaves);
        let path = merkle_path(&leaves, 2);
        assert!(!verify_inclusion(&hex::encode(leaf(42)), &path, &root));
        let mut bent = path.clone();
        bent[0].side = match bent[0].side {
            ProofSide::Left => ProofSide::Right,
            ProofSide::Right => ProofSide::Left,
        };
        assert!(!verify_inclusion(&hex::encode(leaves[2]), &bent, &root));
    }

    /// The whole offline check, as the pack describes it: the path reaches
    /// the root, and the signature over `prev|root` verifies with the
    /// public key alone.
    #[test]
    fn a_proof_verifies_offline() {
        let leaves: Vec<[u8; 32]> = (0..6u8).map(leaf).collect();
        let root = crate::chainer::merkle_root(&leaves);
        let signer = attome_core::audit_signing::AuditSigner::from_config("k1", &"07".repeat(32))
            .expect("signer");
        let signature = signer.sign("prev-batch-hash", &root);
        let public_key = signer.verifying_key_b64();

        let path = merkle_path(&leaves, 4);
        assert!(verify_inclusion(&hex::encode(leaves[4]), &path, &root));
        assert!(attome_core::audit_signing::verify_with_key(
            "prev-batch-hash",
            &root,
            &signature,
            &public_key
        ));
        assert!(!attome_core::audit_signing::verify_with_key(
            "another-prev",
            &root,
            &signature,
            &public_key
        ));
    }
}
