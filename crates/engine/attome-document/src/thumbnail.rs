//! Z6-T6: thumbnails of clean images, made in the background.
//!
//! When the upload scan promotes a PNG, JPEG or WebP file to `clean`
//! (`files_scan::process`), it queues `EngineJob::FileThumbnail` in the same
//! transaction. [`process`] reads the promoted object, scales it to fit
//! [`THUMB_SIZE`] pixels on its longer side with the pure-Rust `image`
//! crate (on a blocking thread, guidelines §10), stores the result as a PNG
//! beside the original at [`thumbnail_key`], and records that key on the
//! upload session. The download route serves it with `?thumbnail=true`
//! after the same record and field check as the original
//! (`files::get_download_url`), so a thumbnail is never readable by someone
//! who cannot read the file.
//!
//! The job is idempotent: a second run overwrites the same key with the
//! same bytes. An image too large to read ([`MAX_SOURCE_BYTES`]) or one that
//! does not decode gets no thumbnail; that is logged, not retried.

use attome_core::EngineState;
use attome_types::AppError;
use image::{ImageFormat, imageops::FilterType};
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use uuid::Uuid;

/// The longer side of a thumbnail, in pixels.
pub const THUMB_SIZE: u32 = 320;
/// The largest original read for a thumbnail.
pub const MAX_SOURCE_BYTES: u64 = 25 * 1024 * 1024;
/// The largest original, in pixels, decoded for a thumbnail (a decompression
/// bomb guard: a small file can declare a huge image).
pub const MAX_SOURCE_PIXELS: u64 = 40_000_000;

/// Whether a clean file of `content_type` gets a thumbnail. Pure.
pub fn is_thumbnailable(content_type: &str) -> bool {
    format_of(content_type).is_some()
}

fn format_of(content_type: &str) -> Option<ImageFormat> {
    match content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "image/png" => Some(ImageFormat::Png),
        "image/jpeg" | "image/jpg" => Some(ImageFormat::Jpeg),
        "image/webp" => Some(ImageFormat::WebP),
        _ => None,
    }
}

/// Where a file's thumbnail is stored: beside the original, under the same
/// record prefix, so the owned-key check that guards downloads holds. Pure.
pub fn thumbnail_key(final_key: &str) -> String {
    format!("{final_key}.thumb.png")
}

/// Why no thumbnail was made.
#[derive(Debug, PartialEq, Eq)]
pub enum ThumbnailError {
    /// Not a PNG, JPEG or WebP.
    Unsupported,
    /// Larger than [`MAX_SOURCE_PIXELS`].
    TooLarge,
    /// The bytes did not decode or the PNG did not encode.
    Unreadable(String),
}

/// A PNG of `bytes` (an image of `content_type`) fitting [`THUMB_SIZE`] on
/// its longer side, never scaled up. Pure.
pub fn make_thumbnail(bytes: &[u8], content_type: &str) -> Result<Vec<u8>, ThumbnailError> {
    let format = format_of(content_type).ok_or(ThumbnailError::Unsupported)?;
    let reader = image::ImageReader::with_format(std::io::Cursor::new(bytes), format);
    let (width, height) = reader
        .into_dimensions()
        .map_err(|e| ThumbnailError::Unreadable(e.to_string()))?;
    if u64::from(width) * u64::from(height) > MAX_SOURCE_PIXELS {
        return Err(ThumbnailError::TooLarge);
    }
    let image = image::load_from_memory_with_format(bytes, format)
        .map_err(|e| ThumbnailError::Unreadable(e.to_string()))?;
    let scaled = if width.max(height) > THUMB_SIZE {
        image.resize(THUMB_SIZE, THUMB_SIZE, FilterType::Triangle)
    } else {
        image
    };
    let mut out = std::io::Cursor::new(Vec::new());
    scaled
        .write_to(&mut out, ImageFormat::Png)
        .map_err(|e| ThumbnailError::Unreadable(e.to_string()))?;
    Ok(out.into_inner())
}

/// `EngineJob::FileThumbnail`: makes and stores the thumbnail of one clean
/// upload session's file.
pub async fn process(state: &EngineState, session_id: Uuid) -> Result<(), AppError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT final_key, actual_content_type FROM upload_session \
          WHERE id = $1 AND status = 'clean' AND is_deleted = false",
    )
    .bind(session_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((Some(final_key), Some(content_type))) = row else {
        return Ok(());
    };
    if !is_thumbnailable(&content_type) {
        return Ok(());
    }
    let path = ObjectPath::parse(&final_key)
        .map_err(|e| AppError::internal(format!("invalid stored file key: {e}")))?;
    let object = match state.base.storage.store().get(&path).await {
        Ok(object) => object,
        Err(object_store::Error::NotFound { .. }) => return Ok(()),
        Err(e) => return Err(AppError::internal(e)),
    };
    if object.meta.size > MAX_SOURCE_BYTES {
        tracing::info!(%session_id, size = object.meta.size, "thumbnail: original too large; none made");
        return Ok(());
    }
    let bytes = object.bytes().await.map_err(AppError::internal)?;
    let made = tokio::task::spawn_blocking(move || make_thumbnail(&bytes, &content_type))
        .await
        .map_err(AppError::internal)?;
    let png = match made {
        Ok(png) => png,
        Err(e) => {
            tracing::info!(%session_id, reason = ?e, "thumbnail: none made");
            return Ok(());
        }
    };
    let key = thumbnail_key(&final_key);
    let thumb_path = ObjectPath::parse(&key).map_err(AppError::internal)?;
    state
        .base
        .storage
        .store()
        .put(&thumb_path, png.into())
        .await
        .map_err(AppError::internal)?;
    sqlx::query(
        "UPDATE upload_session SET thumbnail_key = $2, updated_at = NOW(), \
                row_version = row_version + 1 \
          WHERE id = $1 AND status = 'clean'",
    )
    .bind(session_id)
    .bind(&key)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// The thumbnail key recorded for the clean upload whose promoted object is
/// `final_key`, if one was made.
pub async fn thumbnail_of(
    state: &EngineState,
    final_key: &str,
) -> Result<Option<String>, AppError> {
    sqlx::query_scalar(
        "SELECT thumbnail_key FROM upload_session \
          WHERE final_key = $1 AND status = 'clean' AND is_deleted = false \
            AND thumbnail_key IS NOT NULL \
          ORDER BY updated_at DESC LIMIT 1",
    )
    .bind(final_key)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}
