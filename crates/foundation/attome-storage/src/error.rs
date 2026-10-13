use std::time::Duration;

use thiserror::Error;

use crate::presign::MAX_PRESIGN_EXPIRY;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("object store error: {0}")]
    Store(#[from] object_store::Error),

    /// Signing a presigned URL failed: crypto-provider config, credential
    /// fetch, or URL construction inside `AmazonS3::signed_url`. Never
    /// "unsupported" — the only backend this crate builds always signs. The
    /// source is kept so a caller's `AppError::internal` logs the real cause
    /// while the HTTP client sees only a masked 500.
    #[error("presign failed: {0}")]
    Presign(#[source] object_store::Error),

    /// A presign `expires_in` outside SigV4's range: at least one whole
    /// second (`X-Amz-Expires` is whole seconds), at most seven days.
    #[error("presign expiry {0:?} is outside the allowed range of 1s to {max:?}", max = MAX_PRESIGN_EXPIRY)]
    InvalidExpiry(Duration),

    #[error("invalid object path: {0}")]
    InvalidPath(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presign_keeps_the_underlying_object_store_error_as_its_source() {
        let err = StorageError::Presign(object_store::Error::Generic {
            store: "S3",
            source: "credential fetch failed".into(),
        });

        assert!(err.to_string().starts_with("presign failed: "));
        let source = std::error::Error::source(&err).expect("Presign must expose its cause");
        assert!(source.to_string().contains("credential fetch failed"));
    }

    #[test]
    fn invalid_expiry_names_the_allowed_range() {
        assert_eq!(
            StorageError::InvalidExpiry(Duration::ZERO).to_string(),
            "presign expiry 0ns is outside the allowed range of 1s to 604800s"
        );
    }

    #[test]
    fn invalid_path_includes_the_reason_in_its_display_message() {
        let err = StorageError::InvalidPath("segment cannot be '..'".to_string());
        assert_eq!(
            err.to_string(),
            "invalid object path: segment cannot be '..'"
        );
    }
}
