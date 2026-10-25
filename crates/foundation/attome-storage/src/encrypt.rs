//! Z6-T4: files encrypted at rest by the server, for a backend that does not
//! encrypt them itself (local disk), or for any backend when
//! `storage.encrypt_client_side` is set.
//!
//! Every object gets its own random data key, wrapped by the deployment's
//! `storage.encryption_key` ring through the shared envelope
//! (`attome_auth::envelope`, associated data `attome-storage/file-key`), so
//! rotating the ring never rewrites a file: only the small wrapped key
//! names the key id it was sealed under. The wrapped key travels in the
//! object's own header, so every engine's put and get is covered without a
//! file table.
//!
//! # Format
//!
//! ```text
//! header (HEADER_LEN bytes, fixed):
//!   "ATSE" | version 1 | nonce prefix (7) | wrapped key length (u16 BE)
//!   | wrapped key, zero-padded to WRAPPED_MAX
//! then chunks of CHUNK plaintext bytes (the last may be shorter, and an
//! empty file is one empty chunk), each AES-256-GCM sealed with
//!   nonce = prefix (7) | chunk index (u32 BE) | 1 for the last chunk, else 0
//!   associated data = the header
//! ```
//!
//! The last-chunk flag means a file cut short at a chunk boundary does not
//! open, and the header as associated data means a wrapped key moved to
//! another file does not either. Reading needs at most two chunks in memory,
//! and a byte range reads only the chunks it covers.
//!
//! An object without the header (written before encryption was turned on)
//! reads back unchanged. Listing reports stored sizes; a head or get reports
//! the plaintext size.

use std::fmt;
use std::ops::Range;
use std::sync::Arc;

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use async_trait::async_trait;
use attome_config::KeyRing;
use bytes::Bytes;
use futures_util::stream::{self, BoxStream, StreamExt};
use object_store::path::Path;
use object_store::{
    CopyOptions, GetOptions, GetRange, GetResult, GetResultPayload, ListResult, MultipartUpload,
    ObjectMeta, ObjectStore, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions,
    Result, UploadPart,
};

/// The first bytes of an encrypted object.
pub const MAGIC: &[u8; 4] = b"ATSE";
const VERSION: u8 = 1;
/// Plaintext bytes per chunk.
pub const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
const PREFIX: usize = 7;
/// Room for the wrapped data key: the envelope is
/// `2 + key id (at most 255) + nonce (12) + key (32) + tag (16)`.
const WRAPPED_MAX: usize = 320;
/// The fixed header length.
pub const HEADER_LEN: usize = MAGIC.len() + 1 + PREFIX + 2 + WRAPPED_MAX;
/// Ciphertext bytes per full chunk.
const SEALED_CHUNK: u64 = (CHUNK + TAG) as u64;
/// What a multipart upload buffers before it sends a part: the smallest part
/// S3 accepts.
const PART_MIN: usize = 5 << 20;
const RING: &str = "storage.encryption_key";
const KEY_AAD: &[u8] = b"attome-storage/file-key";
const STORE: &str = "encrypted";

/// Why an object could not be sealed or opened. Never carries key material.
#[derive(Debug, thiserror::Error)]
pub enum CryptError {
    #[error("{0}")]
    Key(String),
    #[error("the stored file did not decrypt: the wrong key, or it was altered or cut short")]
    Open,
    #[error("the stored file is not in the encrypted format")]
    Format,
}

fn store_error(error: CryptError) -> object_store::Error {
    object_store::Error::Generic {
        store: STORE,
        source: Box::new(error),
    }
}

fn nonce(prefix: &[u8; PREFIX], index: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..PREFIX].copy_from_slice(prefix);
    n[PREFIX..PREFIX + 4].copy_from_slice(&index.to_be_bytes());
    n[11] = u8::from(last);
    n
}

/// How many chunks a file of `plain` bytes has: at least one. Pure.
pub fn chunk_count(plain: u64) -> u64 {
    plain.div_ceil(CHUNK as u64).max(1)
}

/// The stored size of a file of `plain` bytes. Pure.
pub fn ciphertext_len(plain: u64) -> u64 {
    HEADER_LEN as u64 + plain + chunk_count(plain) * TAG as u64
}

/// The plaintext size of an encrypted object of `stored` bytes; `None` for
/// a size no encrypted object can have. Pure.
pub fn plaintext_len(stored: u64) -> Option<u64> {
    let body = stored.checked_sub(HEADER_LEN as u64)?;
    let (full, rem) = (body / SEALED_CHUNK, body % SEALED_CHUNK);
    match rem {
        0 if full == 0 => None,
        0 => Some(full * CHUNK as u64),
        r if r < TAG as u64 => None,
        r => Some(full * CHUNK as u64 + r - TAG as u64),
    }
}

/// Whether `bytes` starts with an encrypted object's header. Pure.
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= HEADER_LEN && bytes[..MAGIC.len()] == MAGIC[..] && bytes[MAGIC.len()] == VERSION
}

/// The chunks a plaintext `range` of a `plain`-byte file needs, and the
/// stored bytes that hold them: `(first chunk, chunk after the last, stored
/// range)`. `range` is non-empty and within the file. Pure.
pub fn chunk_span(range: &Range<u64>, plain: u64) -> (u64, u64, Range<u64>) {
    let first = range.start / CHUNK as u64;
    let end = range.end.div_ceil(CHUNK as u64).max(first + 1);
    let stored = ciphertext_len(plain);
    let header = HEADER_LEN as u64;
    (
        first,
        end,
        header + first * SEALED_CHUNK..(header + end * SEALED_CHUNK).min(stored),
    )
}

/// A file's open data key.
pub struct FileKey {
    cipher: Aes256Gcm,
    prefix: [u8; PREFIX],
    header: Vec<u8>,
}

impl fmt::Debug for FileKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKey").finish_non_exhaustive()
    }
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for Opener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl FileKey {
    fn seal_chunk(&self, index: u64, last: bool, plain: &[u8]) -> Result<Vec<u8>, CryptError> {
        let index = u32::try_from(index).map_err(|_| CryptError::Format)?;
        self.cipher
            .encrypt(
                Nonce::from_slice(&nonce(&self.prefix, index, last)),
                Payload {
                    msg: plain,
                    aad: &self.header,
                },
            )
            .map_err(|_| CryptError::Key("file encryption failed".into()))
    }

    fn open_chunk(&self, index: u64, last: bool, sealed: &[u8]) -> Result<Vec<u8>, CryptError> {
        let index = u32::try_from(index).map_err(|_| CryptError::Format)?;
        self.cipher
            .decrypt(
                Nonce::from_slice(&nonce(&self.prefix, index, last)),
                Payload {
                    msg: sealed,
                    aad: &self.header,
                },
            )
            .map_err(|_| CryptError::Open)
    }
}

/// A new file key and its header, the key wrapped by `ring`'s active key.
pub fn new_file_key(ring: &KeyRing) -> Result<FileKey, CryptError> {
    let data_key = Aes256Gcm::generate_key(&mut OsRng);
    let wrapped = attome_auth::envelope::encrypt_bytes_with_aad(RING, ring, &data_key, KEY_AAD)
        .map_err(|e| CryptError::Key(e.to_string()))?;
    if wrapped.len() > WRAPPED_MAX {
        return Err(CryptError::Key(format!(
            "{RING}: the active key id is too long"
        )));
    }
    let mut prefix = [0u8; PREFIX];
    prefix.copy_from_slice(&Aes256Gcm::generate_nonce(&mut OsRng)[..PREFIX]);
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&prefix);
    header.extend_from_slice(&(wrapped.len() as u16).to_be_bytes());
    header.extend_from_slice(&wrapped);
    header.resize(HEADER_LEN, 0);
    Ok(FileKey {
        cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&data_key)),
        prefix,
        header,
    })
}

/// The key of an encrypted object, from its first [`HEADER_LEN`] bytes.
pub fn open_header(ring: &KeyRing, bytes: &[u8]) -> Result<FileKey, CryptError> {
    if !is_sealed(bytes) {
        return Err(CryptError::Format);
    }
    let header = &bytes[..HEADER_LEN];
    let at = MAGIC.len() + 1;
    let mut prefix = [0u8; PREFIX];
    prefix.copy_from_slice(&header[at..at + PREFIX]);
    let len = u16::from_be_bytes([header[at + PREFIX], header[at + PREFIX + 1]]) as usize;
    let start = at + PREFIX + 2;
    let wrapped = header
        .get(start..start + len)
        .filter(|_| len <= WRAPPED_MAX)
        .ok_or(CryptError::Format)?;
    let data_key = attome_auth::envelope::decrypt_bytes_with_aad(RING, ring, wrapped, KEY_AAD)
        .map_err(|_| CryptError::Open)?;
    if data_key.len() != 32 {
        return Err(CryptError::Open);
    }
    Ok(FileKey {
        cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&data_key)),
        prefix,
        header: header.to_vec(),
    })
}

/// Seals a file fed in pieces; holds at most one chunk.
pub struct Sealer {
    key: FileKey,
    buf: Vec<u8>,
    index: u64,
    started: bool,
}

impl Sealer {
    pub fn new(ring: &KeyRing) -> Result<Self, CryptError> {
        Ok(Self {
            key: new_file_key(ring)?,
            buf: Vec::new(),
            index: 0,
            started: false,
        })
    }

    /// The header (first call only) and every chunk now known not to be the
    /// last.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptError> {
        let mut out = Vec::new();
        if !self.started {
            self.started = true;
            out.extend_from_slice(&self.key.header);
        }
        self.buf.extend_from_slice(data);
        while self.buf.len() > CHUNK {
            let chunk: Vec<u8> = self.buf.drain(..CHUNK).collect();
            out.extend(self.key.seal_chunk(self.index, false, &chunk)?);
            self.index += 1;
        }
        Ok(out)
    }

    /// The rest: the last chunk (empty for an empty file).
    pub fn finish(mut self) -> Result<Vec<u8>, CryptError> {
        let mut out = self.push(&[])?;
        out.extend(self.key.seal_chunk(self.index, true, &self.buf)?);
        Ok(out)
    }
}

/// Opens a file fed in pieces after its header; holds at most two chunks.
pub struct Opener {
    key: FileKey,
    buf: Vec<u8>,
    index: u64,
}

impl Opener {
    pub fn new(key: FileKey) -> Self {
        Self {
            key,
            buf: Vec::new(),
            index: 0,
        }
    }

    /// The plaintext of every chunk now known not to be the last.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<u8>, CryptError> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        while self.buf.len() as u64 > SEALED_CHUNK {
            let sealed: Vec<u8> = self.buf.drain(..CHUNK + TAG).collect();
            out.extend(self.key.open_chunk(self.index, false, &sealed)?);
            self.index += 1;
        }
        Ok(out)
    }

    /// The last chunk's plaintext; fails when the file was cut short.
    pub fn finish(self) -> Result<Vec<u8>, CryptError> {
        if self.buf.len() < TAG {
            return Err(CryptError::Open);
        }
        self.key.open_chunk(self.index, true, &self.buf)
    }
}

/// A whole file sealed. Pure but for the random key.
pub fn seal(ring: &KeyRing, plain: &[u8]) -> Result<Vec<u8>, CryptError> {
    let mut sealer = Sealer::new(ring)?;
    let mut out = sealer.push(plain)?;
    out.extend(sealer.finish()?);
    Ok(out)
}

/// A whole sealed file opened.
pub fn open(ring: &KeyRing, stored: &[u8]) -> Result<Vec<u8>, CryptError> {
    let mut opener = Opener::new(open_header(ring, stored)?);
    let mut out = opener.push(&stored[HEADER_LEN..])?;
    out.extend(opener.finish()?);
    Ok(out)
}

/// Opens the stored chunks `first..end` of a `plain`-byte file and returns
/// the plaintext `range` from them.
fn open_span(
    key: &FileKey,
    stored: &[u8],
    first: u64,
    end: u64,
    plain: u64,
    range: &Range<u64>,
) -> Result<Vec<u8>, CryptError> {
    let total = chunk_count(plain);
    let mut out = Vec::new();
    let mut at = 0usize;
    for index in first..end {
        let len = if index + 1 == total {
            stored.len() - at
        } else {
            CHUNK + TAG
        };
        let sealed = stored.get(at..at + len).ok_or(CryptError::Format)?;
        out.extend(key.open_chunk(index, index + 1 == total, sealed)?);
        at += len;
    }
    let skip = (range.start - first * CHUNK as u64) as usize;
    let take = (range.end - range.start) as usize;
    out.get(skip..skip + take)
        .map(<[u8]>::to_vec)
        .ok_or(CryptError::Format)
}

/// An object store that encrypts what is put and decrypts what is read.
pub struct Encrypted {
    inner: Arc<dyn ObjectStore>,
    ring: Arc<KeyRing>,
}

impl Encrypted {
    pub fn new(inner: Arc<dyn ObjectStore>, ring: KeyRing) -> Self {
        Self {
            inner,
            ring: Arc::new(ring),
        }
    }
}

impl fmt::Debug for Encrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypted")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Encrypted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Encrypted({})", self.inner)
    }
}

/// A multipart upload sealed as it goes; sends parts of at least
/// [`PART_MIN`] bytes.
struct SealingUpload {
    inner: Box<dyn MultipartUpload>,
    sealer: Option<Sealer>,
    out: Vec<u8>,
}

impl fmt::Debug for SealingUpload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealingUpload")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MultipartUpload for SealingUpload {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        let Some(sealer) = self.sealer.as_mut() else {
            return Box::pin(async { Err(store_error(CryptError::Format)) });
        };
        for piece in &data {
            match sealer.push(piece) {
                Ok(sealed) => self.out.extend(sealed),
                Err(error) => return Box::pin(async move { Err(store_error(error)) }),
            }
        }
        if self.out.len() >= PART_MIN {
            let part = std::mem::take(&mut self.out);
            self.inner.put_part(part.into())
        } else {
            Box::pin(async { Ok(()) })
        }
    }

    async fn complete(&mut self) -> Result<PutResult> {
        let sealer = self
            .sealer
            .take()
            .ok_or_else(|| store_error(CryptError::Format))?;
        self.out.extend(sealer.finish().map_err(store_error)?);
        let part = std::mem::take(&mut self.out);
        self.inner.put_part(part.into()).await?;
        self.inner.complete().await
    }

    async fn abort(&mut self) -> Result<()> {
        self.inner.abort().await
    }
}

#[async_trait]
impl ObjectStore for Encrypted {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> Result<PutResult> {
        let ring = self.ring.clone();
        let sealed = tokio::task::spawn_blocking(move || {
            let mut sealer = Sealer::new(&ring)?;
            let mut out = Vec::with_capacity(
                usize::try_from(ciphertext_len(payload.content_length() as u64)).unwrap_or(0),
            );
            for piece in &payload {
                out.extend(sealer.push(piece)?);
            }
            out.extend(sealer.finish()?);
            Ok::<_, CryptError>(out)
        })
        .await?
        .map_err(store_error)?;
        self.inner.put_opts(location, sealed.into(), opts).await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> Result<Box<dyn MultipartUpload>> {
        let sealer = Sealer::new(&self.ring).map_err(store_error)?;
        let inner = self.inner.put_multipart_opts(location, opts).await?;
        Ok(Box::new(SealingUpload {
            inner,
            sealer: Some(sealer),
            out: Vec::new(),
        }))
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        // The conditions (if-match and the rest) are checked here, once.
        let head = self
            .inner
            .get_opts(
                location,
                GetOptions {
                    head: true,
                    range: None,
                    ..options.clone()
                },
            )
            .await?;
        let meta = head.meta.clone();
        if meta.size < HEADER_LEN as u64 {
            return self.inner.get_opts(location, options).await;
        }
        let version = GetOptions {
            version: options.version.clone(),
            ..GetOptions::default()
        };
        let header = self
            .inner
            .get_opts(
                location,
                GetOptions {
                    range: Some(GetRange::Bounded(0..HEADER_LEN as u64)),
                    ..version.clone()
                },
            )
            .await?
            .bytes()
            .await?;
        if !is_sealed(&header) {
            return self.inner.get_opts(location, options).await;
        }
        let key = open_header(&self.ring, &header).map_err(store_error)?;
        let plain = plaintext_len(meta.size).ok_or_else(|| store_error(CryptError::Format))?;
        let plain_meta = ObjectMeta {
            size: plain,
            ..meta
        };
        if options.head {
            return Ok(GetResult {
                payload: GetResultPayload::Stream(stream::empty().boxed()),
                meta: plain_meta,
                range: 0..plain,
                attributes: head.attributes,
                extensions: head.extensions,
            });
        }
        let Some(asked) = &options.range else {
            let body = self
                .inner
                .get_opts(
                    location,
                    GetOptions {
                        range: Some(GetRange::Offset(HEADER_LEN as u64)),
                        ..version
                    },
                )
                .await?;
            let attributes = body.attributes.clone();
            let inner = body.into_stream();
            let opened = stream::try_unfold(
                (inner, Some(Opener::new(key))),
                |(mut inner, opener)| async move {
                    let Some(mut opener) = opener else {
                        return Ok(None);
                    };
                    loop {
                        match inner.next().await {
                            Some(Ok(piece)) => {
                                let out = opener.push(&piece).map_err(store_error)?;
                                if !out.is_empty() {
                                    return Ok(Some((Bytes::from(out), (inner, Some(opener)))));
                                }
                            }
                            Some(Err(error)) => return Err(error),
                            None => {
                                let out = opener.finish().map_err(store_error)?;
                                return Ok(Some((Bytes::from(out), (inner, None))));
                            }
                        }
                    }
                },
            )
            .boxed();
            return Ok(GetResult {
                payload: GetResultPayload::Stream(opened),
                meta: plain_meta,
                range: 0..plain,
                attributes,
                extensions: head.extensions,
            });
        };
        let range = asked
            .as_range(plain)
            .map_err(|error| object_store::Error::Generic {
                store: STORE,
                source: Box::new(error),
            })?;
        if range.is_empty() {
            return Ok(GetResult {
                payload: GetResultPayload::Stream(stream::empty().boxed()),
                meta: plain_meta,
                range,
                attributes: head.attributes,
                extensions: head.extensions,
            });
        }
        let (first, end, stored_range) = chunk_span(&range, plain);
        let body = self
            .inner
            .get_opts(
                location,
                GetOptions {
                    range: Some(GetRange::Bounded(stored_range)),
                    ..version
                },
            )
            .await?;
        let attributes = body.attributes.clone();
        let stored = body.bytes().await?;
        let bytes = open_span(&key, &stored, first, end, plain, &range).map_err(store_error)?;
        Ok(GetResult {
            payload: GetResultPayload::Stream(
                stream::once(async { Ok(Bytes::from(bytes)) }).boxed(),
            ),
            meta: plain_meta,
            range,
            attributes,
            extensions: head.extensions,
        })
    }

    fn delete_stream(
        &self,
        locations: BoxStream<'static, Result<Path>>,
    ) -> BoxStream<'static, Result<Path>> {
        self.inner.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> BoxStream<'static, Result<ObjectMeta>> {
        self.inner.list(prefix)
    }

    fn list_with_offset(
        &self,
        prefix: Option<&Path>,
        offset: &Path,
    ) -> BoxStream<'static, Result<ObjectMeta>> {
        self.inner.list_with_offset(prefix, offset)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> Result<ListResult> {
        self.inner.list_with_delimiter(prefix).await
    }

    async fn copy_opts(&self, from: &Path, to: &Path, options: CopyOptions) -> Result<()> {
        self.inner.copy_opts(from, to, options).await
    }

    async fn rename_opts(&self, from: &Path, to: &Path, options: RenameOptions) -> Result<()> {
        self.inner.rename_opts(from, to, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::ObjectStoreExt;
    use object_store::memory::InMemory;
    use std::collections::HashMap;

    fn ring(id: &str) -> KeyRing {
        KeyRing {
            keys: HashMap::from([(id.to_owned(), "11".repeat(32))]),
            active_key_id: id.to_owned(),
        }
    }

    #[test]
    fn encrypt_round_trips_every_size_and_differs_from_plaintext() {
        let ring = ring("k1");
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 5] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let stored = seal(&ring, &plain).unwrap();
            assert_eq!(stored.len() as u64, ciphertext_len(size as u64), "{size}");
            assert_eq!(plaintext_len(stored.len() as u64), Some(size as u64));
            assert!(is_sealed(&stored));
            if size >= 64 {
                assert!(
                    !stored.windows(64).any(|w| w == &plain[..64]),
                    "plaintext visible at size {size}"
                );
            }
            assert_eq!(open(&ring, &stored).unwrap(), plain, "{size}");
        }
    }

    #[test]
    fn encrypt_refuses_altered_cut_or_rekeyed_files() {
        let ring = ring("k1");
        let plain = vec![7u8; CHUNK + 10];
        let stored = seal(&ring, &plain).unwrap();
        let mut altered = stored.clone();
        altered[HEADER_LEN + 3] ^= 1;
        assert!(open(&ring, &altered).is_err());
        // Cut at the chunk boundary: the first chunk is not marked last.
        let cut = &stored[..HEADER_LEN + CHUNK + TAG];
        assert!(open(&ring, cut).is_err());
        // Another ring cannot unwrap the file key.
        let other = KeyRing {
            keys: HashMap::from([("k1".to_owned(), "22".repeat(32))]),
            active_key_id: "k1".to_owned(),
        };
        assert!(open(&other, &stored).is_err());
        // Another file's header does not open this body.
        let second = seal(&ring, &plain).unwrap();
        let mut swapped = second[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&stored[HEADER_LEN..]);
        assert!(open(&ring, &swapped).is_err());
    }

    #[test]
    fn encrypt_survives_a_ring_rotation() {
        let old = ring("k1");
        let stored = seal(&old, b"kept").unwrap();
        let mut rotated = ring("k2");
        rotated.keys.insert("k1".into(), "11".repeat(32));
        assert_eq!(open(&rotated, &stored).unwrap(), b"kept");
    }

    #[test]
    fn encrypt_chunk_span_covers_the_range() {
        let plain = 3 * CHUNK as u64 + 10;
        let (first, end, stored) = chunk_span(&(CHUNK as u64 + 5..CHUNK as u64 + 6), plain);
        assert_eq!((first, end), (1, 2));
        assert_eq!(stored.start, HEADER_LEN as u64 + SEALED_CHUNK);
        assert_eq!(stored.end, HEADER_LEN as u64 + 2 * SEALED_CHUNK);
        let (_, end, stored) = chunk_span(&(plain - 1..plain), plain);
        assert_eq!(end, 4);
        assert_eq!(stored.end, ciphertext_len(plain));
    }

    #[tokio::test]
    async fn encrypt_store_puts_ciphertext_and_reads_plaintext() {
        let memory: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = Encrypted::new(memory.clone(), ring("k1"));
        let path = Path::from("e/1/f/report.csv");
        let plain: Vec<u8> = (0..CHUNK * 2 + 100).map(|i| (i % 13) as u8).collect();
        store.put(&path, plain.clone().into()).await.unwrap();

        let raw = memory.get(&path).await.unwrap().bytes().await.unwrap();
        assert!(is_sealed(&raw));
        assert_ne!(&raw[HEADER_LEN..HEADER_LEN + 64], &plain[..64]);

        let back = store.get(&path).await.unwrap();
        assert_eq!(back.meta.size, plain.len() as u64);
        assert_eq!(back.bytes().await.unwrap(), plain);
        assert_eq!(store.head(&path).await.unwrap().size, plain.len() as u64);
        let start = CHUNK as u64 - 3;
        let part = store.get_range(&path, start..start + 10).await.unwrap();
        assert_eq!(&part[..], &plain[start as usize..start as usize + 10]);

        // An object written before encryption reads back unchanged.
        let old = Path::from("e/1/f/old.txt");
        memory
            .put(&old, Bytes::from_static(b"plain").into())
            .await
            .unwrap();
        assert_eq!(
            store.get(&old).await.unwrap().bytes().await.unwrap(),
            &b"plain"[..]
        );
    }

    #[tokio::test]
    async fn encrypt_store_multipart_upload_round_trips() {
        let memory: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store = Encrypted::new(memory, ring("k1"));
        let path = Path::from("exports/big.jsonl");
        let mut upload = store.put_multipart(&path).await.unwrap();
        let piece = vec![3u8; 3 * CHUNK];
        for _ in 0..3 {
            upload.put_part(piece.clone().into()).await.unwrap();
        }
        upload.complete().await.unwrap();
        let back = store.get(&path).await.unwrap().bytes().await.unwrap();
        assert_eq!(back.len(), 9 * CHUNK);
        assert!(back.iter().all(|b| *b == 3));
    }
}
