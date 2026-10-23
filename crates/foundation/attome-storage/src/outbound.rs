//! AB6-T4: every object store call goes through `attome_outbound` as the
//! service `object_storage`, so an outage opens one breaker and fails fast
//! instead of every request waiting out its own timeout, a request's
//! deadline bounds its storage calls, and retries share one budget.
//!
//! [`Guarded`] wraps a cloud store (S3, Azure, GCS; local disk has no network
//! to guard). The store's own retry layer is turned off when it is built
//! (`client.rs`), so a call is retried here only:
//!
//! - a GET, a HEAD, a list page, a delete, or a PUT or copy that overwrites a
//!   fixed key (the same request twice leaves the same object);
//! - never a create-if-absent PUT or copy, a rename, or a multipart upload:
//!   starting one is not retried, and its parts and completion go to the
//!   store directly, as the upload handle the store returns.
//!
//! A refused request (not found, a precondition, a permission) passes through
//! unchanged and does not count against the breaker. Listing streams pass
//! through unchanged.

use std::fmt;
use std::ops::Range;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use object_store::path::Path;
use object_store::{
    CopyMode, CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta,
    ObjectStore, PutMode, PutMultipartOptions, PutOptions, PutPayload, PutResult, RenameOptions,
    Result,
};

/// The object store as one outbound service. Its per-attempt timeout is the
/// store's own per-request timeout.
pub(crate) fn object_storage_service() -> attome_outbound::Service {
    attome_outbound::Service::new(
        "object_storage",
        attome_outbound::Policy {
            timeout: crate::client::S3_REQUEST_TIMEOUT,
            ..attome_outbound::Policy::default()
        },
    )
}

static OBJECT_STORAGE: LazyLock<attome_outbound::Service> = LazyLock::new(object_storage_service);

/// A store error, as `attome_outbound` judges it.
pub(crate) struct StoreError(pub(crate) object_store::Error);

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl attome_outbound::Retryable for StoreError {
    fn retryable(&self) -> bool {
        // `Generic` is what a store reports for a timeout, a refused
        // connection and a 429 or 5xx; the typed variants are refusals.
        matches!(self.0, object_store::Error::Generic { .. })
    }
}

fn into_store_error(error: attome_outbound::OutboundError<StoreError>) -> object_store::Error {
    match error {
        attome_outbound::OutboundError::Failed(StoreError(error)) => error,
        other => object_store::Error::Generic {
            store: "object_storage",
            source: other.to_string().into(),
        },
    }
}

/// A store whose calls go through the `object_storage` outbound service.
pub(crate) struct Guarded {
    inner: Arc<dyn ObjectStore>,
    service: &'static attome_outbound::Service,
}

impl Guarded {
    pub(crate) fn new(inner: Arc<dyn ObjectStore>) -> Self {
        Self {
            inner,
            service: &OBJECT_STORAGE,
        }
    }

    async fn call<T, F, Fut>(&self, idempotent: bool, attempt: F) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, StoreError>>,
    {
        attome_outbound::call(
            self.service,
            attome_outbound::CallClass::Interactive,
            idempotent,
            attempt,
        )
        .await
        .map_err(into_store_error)
    }
}

impl fmt::Debug for Guarded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guarded")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Guarded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guarded({})", self.inner)
    }
}

#[async_trait]
impl ObjectStore for Guarded {
    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> Result<PutResult> {
        let idempotent = matches!(opts.mode, PutMode::Overwrite);
        self.call(idempotent, || {
            let (payload, opts) = (payload.clone(), opts.clone());
            async move {
                self.inner
                    .put_opts(location, payload, opts)
                    .await
                    .map_err(StoreError)
            }
        })
        .await
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOptions,
    ) -> Result<Box<dyn MultipartUpload>> {
        self.call(false, || {
            let opts = opts.clone();
            async move {
                self.inner
                    .put_multipart_opts(location, opts)
                    .await
                    .map_err(StoreError)
            }
        })
        .await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> Result<GetResult> {
        self.call(true, || {
            let options = options.clone();
            async move {
                self.inner
                    .get_opts(location, options)
                    .await
                    .map_err(StoreError)
            }
        })
        .await
    }

    async fn get_ranges(&self, location: &Path, ranges: &[Range<u64>]) -> Result<Vec<Bytes>> {
        self.call(true, || async move {
            self.inner
                .get_ranges(location, ranges)
                .await
                .map_err(StoreError)
        })
        .await
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
        self.call(true, || async move {
            self.inner
                .list_with_delimiter(prefix)
                .await
                .map_err(StoreError)
        })
        .await
    }

    async fn copy_opts(&self, from: &Path, to: &Path, options: CopyOptions) -> Result<()> {
        let idempotent = matches!(options.mode, CopyMode::Overwrite);
        self.call(idempotent, || {
            let options = options.clone();
            async move {
                self.inner
                    .copy_opts(from, to, options)
                    .await
                    .map_err(StoreError)
            }
        })
        .await
    }

    async fn rename_opts(&self, from: &Path, to: &Path, options: RenameOptions) -> Result<()> {
        self.call(false, || {
            let options = options.clone();
            async move {
                self.inner
                    .rename_opts(from, to, options)
                    .await
                    .map_err(StoreError)
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use object_store::ObjectStoreExt;
    use object_store::memory::InMemory;

    use super::*;

    #[tokio::test]
    async fn a_guarded_store_passes_calls_and_refusals_through() {
        let store = Guarded::new(Arc::new(InMemory::new()));
        let key = Path::from("a/b.txt");
        store
            .put(&key, PutPayload::from_static(b"x"))
            .await
            .expect("put");
        assert_eq!(store.head(&key).await.expect("head").size, 1);
        assert!(matches!(
            store.get(&Path::from("missing")).await,
            Err(object_store::Error::NotFound { .. })
        ));
        assert!(!attome_outbound::Retryable::retryable(&StoreError(
            object_store::Error::NotFound {
                path: "x".into(),
                source: "gone".into()
            }
        )));
        assert!(format!("{store}").starts_with("Guarded("));
    }
}
