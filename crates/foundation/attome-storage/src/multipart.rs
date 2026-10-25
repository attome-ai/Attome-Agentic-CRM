//! Resumable multipart uploads (roadmap Z6-T2), over any object store.
//!
//! The client puts each part to its own object beside the upload's target
//! (`<key>.parts/<n>`, through a presigned PUT), so the parts survive a
//! restart of the server or the client: [`parts_present`] lists what has
//! arrived, and only the missing parts need sending again. [`assemble`]
//! then streams the parts in order into one multipart write of the target
//! and returns its size and SHA-256; [`discard`] removes the parts. Every
//! part but the last is [`PART_SIZE`] long, which keeps each one above the
//! S3 multipart minimum.

use std::collections::BTreeMap;

use object_store::{ObjectStoreExt, path::Path};
use sha2::{Digest, Sha256};

use crate::{StorageClient, StorageError};

/// Every part but the last is this long: 8 MiB.
pub const PART_SIZE: u64 = 8 * 1024 * 1024;

/// The most parts one upload has.
pub const MAX_PARTS: u32 = 10_000;

fn path_of(key: &str) -> Result<Path, StorageError> {
    Path::parse(key).map_err(|e| StorageError::InvalidPath(e.to_string()))
}

/// The prefix the parts of the upload to `key` live under.
pub fn parts_prefix(key: &str) -> String {
    format!("{key}.parts")
}

/// Where part `n` (1-based) of the upload to `key` lives.
pub fn part_key(key: &str, n: u32) -> String {
    format!("{}/{n:05}", parts_prefix(key))
}

/// How many parts an upload of `size` bytes has, or `None` when it would
/// need more than [`MAX_PARTS`]. Pure.
pub fn part_count(size: u64) -> Option<u32> {
    let count = size.div_ceil(PART_SIZE).max(1);
    u32::try_from(count).ok().filter(|c| *c <= MAX_PARTS)
}

/// The length part `n` of an upload of `size` bytes must have. Pure.
pub fn expected_part_size(size: u64, n: u32) -> u64 {
    let count = part_count(size).unwrap_or(1);
    if n < count {
        PART_SIZE
    } else {
        size - PART_SIZE * u64::from(count - 1)
    }
}

/// The parts of the upload to `key` that have arrived: part number to size.
pub async fn parts_present(
    client: &StorageClient,
    key: &str,
) -> Result<BTreeMap<u32, u64>, StorageError> {
    let prefix = parts_prefix(key);
    let entries = crate::mirror::list_prefix(client, &prefix).await?;
    Ok(entries
        .into_iter()
        .filter_map(|e| {
            let n = e.key.rsplit('/').next()?.parse::<u32>().ok()?;
            Some((n, e.size))
        })
        .collect())
}

/// Why the parts cannot be assembled yet, or `None` when every part of an
/// upload of `size` bytes has arrived with the right length. Pure.
pub fn missing_or_wrong(present: &BTreeMap<u32, u64>, size: u64) -> Option<String> {
    let count = part_count(size)?;
    let missing: Vec<u32> = (1..=count).filter(|n| !present.contains_key(n)).collect();
    if !missing.is_empty() {
        return Some(format!("parts not yet uploaded: {missing:?}"));
    }
    let wrong: Vec<u32> = (1..=count)
        .filter(|n| present.get(n).copied() != Some(expected_part_size(size, *n)))
        .collect();
    if !wrong.is_empty() {
        return Some(format!("parts with the wrong length: {wrong:?}"));
    }
    None
}

/// The assembled object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    pub size: u64,
    /// Lowercase hex SHA-256 of the whole object.
    pub sha256: String,
}

/// Writes parts `1..=count` of the upload to `key`, in order, as the object
/// `key`, one part in memory at a time. The parts are left in place;
/// [`discard`] removes them once the caller has recorded the result.
pub async fn assemble(
    client: &StorageClient,
    key: &str,
    count: u32,
) -> Result<Assembled, StorageError> {
    let store = client.store();
    let mut upload = store.put_multipart(&path_of(key)?).await?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    for n in 1..=count {
        let part = match store.get(&path_of(&part_key(key, n))?).await {
            Ok(got) => got.bytes().await,
            Err(e) => Err(e),
        };
        let bytes = match part {
            Ok(bytes) => bytes,
            Err(e) => {
                let _ = upload.abort().await;
                return Err(e.into());
            }
        };
        hasher.update(&bytes);
        size += bytes.len() as u64;
        if let Err(e) = upload.put_part(bytes.into()).await {
            let _ = upload.abort().await;
            return Err(e.into());
        }
    }
    upload.complete().await?;
    Ok(Assembled {
        size,
        sha256: hex::encode(hasher.finalize()),
    })
}

/// Removes every part of the upload to `key` that arrived.
pub async fn discard(client: &StorageClient, key: &str) -> Result<(), StorageError> {
    for n in parts_present(client, key).await?.into_keys() {
        crate::mirror::delete_object(client, &part_key(key, n)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use object_store::memory::InMemory;

    use super::*;

    #[test]
    fn multipart_parts_are_counted_and_sized() {
        assert_eq!(part_count(1), Some(1));
        assert_eq!(part_count(PART_SIZE), Some(1));
        assert_eq!(part_count(PART_SIZE + 1), Some(2));
        assert_eq!(part_count(PART_SIZE * u64::from(MAX_PARTS) + 1), None);
        assert_eq!(expected_part_size(PART_SIZE * 2 + 5, 1), PART_SIZE);
        assert_eq!(expected_part_size(PART_SIZE * 2 + 5, 3), 5);
        let present = BTreeMap::from([(1, PART_SIZE), (3, 5)]);
        assert!(missing_or_wrong(&present, PART_SIZE * 2 + 5).is_some());
    }

    /// Z6-T2: three parts, the client and server start again after the first
    /// two, the third arrives, and the assembled object has the checksum of
    /// the whole file.
    #[tokio::test]
    async fn multipart_resume_completes_after_restart() {
        let memory = Arc::new(InMemory::new());
        let key = "uploads/quarantine/report.bin";
        let size = PART_SIZE * 2 + 1024;
        let whole: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let part = |n: u32| {
            let start = usize::try_from(PART_SIZE * u64::from(n - 1)).unwrap();
            let end = usize::try_from((PART_SIZE * u64::from(n)).min(size)).unwrap();
            whole[start..end].to_vec()
        };

        let first = crate::client::client_over(memory.clone(), &[7; 32], "");
        for n in [1, 2] {
            crate::mirror::write_object(&first, &part_key(key, n), part(n))
                .await
                .unwrap();
        }
        drop(first);

        let again = crate::client::client_over(memory.clone(), &[7; 32], "");
        let present = parts_present(&again, key).await.unwrap();
        assert_eq!(present.keys().copied().collect::<Vec<_>>(), vec![1, 2]);
        assert!(missing_or_wrong(&present, size).is_some());
        crate::mirror::write_object(&again, &part_key(key, 3), part(3))
            .await
            .unwrap();
        let present = parts_present(&again, key).await.unwrap();
        assert_eq!(missing_or_wrong(&present, size), None);

        let assembled = assemble(&again, key, 3).await.unwrap();
        assert_eq!(assembled.size, size);
        assert_eq!(assembled.sha256, hex::encode(Sha256::digest(&whole)));
        let back = crate::mirror::read_object(&again, key).await.unwrap();
        assert_eq!(back, whole);
        discard(&again, key).await.unwrap();
        assert!(parts_present(&again, key).await.unwrap().is_empty());
    }
}
