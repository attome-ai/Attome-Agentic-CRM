//! Page redirects (roadmap E13-T5): a page's old `url_path` keeps working
//! after the path changes. [`record_path_change`] runs in the transaction
//! that changes the path; the public page routes call [`resolve`] when no
//! live page holds a path and answer with a permanent redirect to the
//! page's current path, percent-encoded ([`encode_path`]) so an Arabic path
//! travels as plain ASCII.

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use uuid::Uuid;

/// Records that `page` moved from `old_path` to `new_path`, and releases
/// any redirect that pointed `new_path` elsewhere (the page now owns it).
/// A no-op when the path did not change.
pub async fn record_path_change(
    tx: &mut Tx<'_>,
    page: Uuid,
    old_path: &str,
    new_path: &str,
) -> Result<(), AppError> {
    if old_path == new_path {
        return Ok(());
    }
    release_path(tx, new_path).await?;
    sqlx::query(
        "INSERT INTO content_page_redirect (old_path, page_id) VALUES ($1, $2) \
         ON CONFLICT (old_path) DO UPDATE SET page_id = EXCLUDED.page_id, created_at = now()",
    )
    .bind(old_path)
    .bind(page)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Drops the redirect from `path`, for a page that now lives there.
pub async fn release_path(tx: &mut Tx<'_>, path: &str) -> Result<(), AppError> {
    sqlx::query("DELETE FROM content_page_redirect WHERE old_path = $1")
        .bind(path)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// The current path and space of the published page `old_path` redirects
/// to, when its audience is one of `audiences` (a redirect never names a
/// page the caller could not read).
pub async fn resolve(
    db: &DbPool,
    old_path: &str,
    audiences: &[String],
) -> Result<Option<(Uuid, String)>, AppError> {
    sqlx::query_as(
        "SELECT p.content_space_id, p.url_path FROM content_page_redirect r \
           JOIN content_page p ON p.id = r.page_id \
          WHERE r.old_path = $1 AND p.is_deleted = FALSE AND p.url_path <> r.old_path \
            AND p.status = 'published' AND p.audience = ANY($2)",
    )
    .bind(old_path)
    .bind(audiences)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// `path` percent-encoded for a URL: every byte but ASCII letters, digits,
/// `-`, `.`, `_`, `~` and `/` becomes `%XX`. Pure.
pub fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arabic_path_is_percent_encoded() {
        assert_eq!(encode_path("/guide/start-1"), "/guide/start-1");
        assert_eq!(encode_path("/دليل"), "/%D8%AF%D9%84%D9%8A%D9%84");
        assert_eq!(encode_path("/a b?c"), "/a%20b%3Fc");
    }
}
