//! Reading every object out and writing objects back, for the local backup
//! (roadmap U6-T1) and `attome restore` (U6-T2). The caller decides where the
//! copies live and checks their contents; this module only talks to the
//! store.

use object_store::{ObjectStoreExt, path::Path};

use crate::{StorageClient, StorageError};

/// One object in the bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectEntry {
    pub key: String,
    pub size: u64,
    /// The store's entity tag, when it gives one; unchanged while the
    /// object is.
    pub e_tag: Option<String>,
}

fn path_of(key: &str) -> Result<Path, StorageError> {
    Path::parse(key).map_err(|e| StorageError::InvalidPath(e.to_string()))
}

/// Every object in the bucket, sorted by key. Walks one prefix level at a
/// time, so no listing holds more than one folder's entries.
pub async fn list_all(client: &StorageClient) -> Result<Vec<ObjectEntry>, StorageError> {
    let store = client.store();
    let mut pending: Vec<Option<Path>> = vec![None];
    let mut entries = Vec::new();
    while let Some(prefix) = pending.pop() {
        let listed = store.list_with_delimiter(prefix.as_ref()).await?;
        pending.extend(listed.common_prefixes.into_iter().map(Some));
        entries.extend(listed.objects.into_iter().map(|meta| ObjectEntry {
            key: meta.location.to_string(),
            size: meta.size,
            e_tag: meta.e_tag,
        }));
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(entries)
}

/// One object's bytes.
pub async fn read_object(client: &StorageClient, key: &str) -> Result<Vec<u8>, StorageError> {
    let result = client.store().get(&path_of(key)?).await?;
    Ok(result.bytes().await?.to_vec())
}

/// Writes one object, replacing what the key held.
pub async fn write_object(
    client: &StorageClient,
    key: &str,
    bytes: Vec<u8>,
) -> Result<(), StorageError> {
    client.store().put(&path_of(key)?, bytes.into()).await?;
    Ok(())
}
