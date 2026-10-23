//! The web app, served by the same process as the API (a Solo install is one
//! binary and PostgreSQL; there is no separate web server to set up).
//!
//! [`serve_web`] answers a `GET`/`HEAD` for any path outside the API
//! (`/api`, a portal's `/{keyword}/api`, `/health`, `/metrics`) from the
//! built web app's directory: the file when it exists, otherwise
//! `index.html` for a path without an extension (the app's own routes), and
//! the API's ordinary handling for everything else. It reads only files
//! under the root: a path segment that is empty, `.` or `..`, or holds a
//! `\` or `:`, is never joined.
//!
//! `index.html` is sent `no-cache` so a new release is picked up at once;
//! the other files (content-hashed by the build) are cacheable for an hour.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

/// The directory the web app is served from.
#[derive(Debug, Clone)]
pub struct WebRoot(pub Arc<PathBuf>);

/// Whether `path` belongs to the server rather than the web app.
fn is_server_path(path: &str) -> bool {
    path == "/api"
        || path.starts_with("/api/")
        || path.contains("/api/")
        || path.ends_with("/api")
        || path == "/health"
        || path.starts_with("/health/")
        || path == "/metrics"
        || path.starts_with("/.well-known/")
}

/// The file under `root` that `path` names, or `None` when a segment could
/// leave the root.
fn file_for(root: &Path, path: &str) -> Option<PathBuf> {
    let mut file = root.to_path_buf();
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return Some(root.join("index.html"));
    }
    for segment in trimmed.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.contains('\\')
            || segment.contains(':')
        {
            return None;
        }
        file.push(segment);
    }
    Some(file)
}

/// The content type for a file name.
fn content_type(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Q21-T2: the nonce one page's inline scripts carry. [`serve_web`] puts it
/// on the `index.html` response; the security headers layer reads it and
/// names it in that response's `script-src`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CspNonce(pub String);

/// A fresh 128-bit nonce, base64.
fn new_nonce() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>())
}

/// `html` with `nonce` on Angular's root element (`ngCspNonce`, which Angular
/// puts on the styles and scripts it adds) and on every `<script>` tag that
/// has none.
fn with_nonce(html: &str, nonce: &str) -> String {
    let html = html.replacen("<app-root", &format!("<app-root ngCspNonce=\"{nonce}\""), 1);
    let mut out = String::with_capacity(html.len() + 64);
    let mut rest = html.as_str();
    while let Some(at) = rest.find("<script") {
        let (before, tag) = rest.split_at(at);
        out.push_str(before);
        let end = tag.find('>').unwrap_or(tag.len());
        let head = &tag[..end];
        if head.contains("nonce=") {
            out.push_str(head);
        } else {
            out.push_str("<script");
            out.push_str(&format!(" nonce=\"{nonce}\""));
            out.push_str(&head["<script".len()..]);
        }
        rest = &tag[end..];
    }
    out.push_str(rest);
    out
}

async fn file_response(path: &Path, method: &Method) -> Option<Response> {
    let mut bytes = tokio::fs::read(path).await.ok()?;
    let is_index = path.file_name().is_some_and(|name| name == "index.html");
    let nonce = is_index.then(new_nonce);
    if let Some(nonce) = &nonce
        && let Ok(html) = std::str::from_utf8(&bytes)
    {
        bytes = with_nonce(html, nonce).into_bytes();
    }
    let cache = if is_index {
        "no-cache"
    } else {
        "public, max-age=3600"
    };
    let body = if *method == Method::HEAD {
        Body::empty()
    } else {
        Body::from(bytes)
    };
    let mut response = (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(content_type(path)),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static(cache)),
        ],
        body,
    )
        .into_response();
    if let Some(nonce) = nonce {
        response.extensions_mut().insert(CspNonce(nonce));
    }
    Some(response)
}

/// The middleware: the web app for its own paths, the API for the rest.
pub async fn serve_web(State(root): State<WebRoot>, request: Request, next: Next) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    if !(method == Method::GET || method == Method::HEAD) || is_server_path(&path) {
        return next.run(request).await;
    }
    let Some(file) = file_for(&root.0, &path) else {
        return next.run(request).await;
    };
    let is_file = tokio::fs::metadata(&file)
        .await
        .is_ok_and(|meta| meta.is_file());
    if is_file && let Some(response) = file_response(&file, &method).await {
        return response;
    }
    // An app route (no extension) gets the app; a missing asset falls
    // through to the API's 404.
    let has_extension = path
        .rsplit('/')
        .next()
        .is_some_and(|last| last.contains('.'));
    if !has_extension
        && let Some(response) = file_response(&root.0.join("index.html"), &method).await
    {
        return response;
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Q21-T2: a page gets a fresh nonce on its root element and on each
    /// script without one.
    #[test]
    fn csp_nonce_is_put_on_the_page() {
        let html = r#"<html><head><script>boot()</script><script nonce="x" src="a.js"></script></head><body><app-root></app-root><script src="main.js"></script></body></html>"#;
        let page = with_nonce(html, "N1");
        assert!(page.contains(r#"<app-root ngCspNonce="N1">"#), "{page}");
        assert!(
            page.contains(r#"<script nonce="N1">boot()</script>"#),
            "{page}"
        );
        assert!(page.contains(r#"<script nonce="x" src="a.js">"#), "{page}");
        assert!(
            page.contains(r#"<script nonce="N1" src="main.js">"#),
            "{page}"
        );
        let (a, b) = (new_nonce(), new_nonce());
        assert_ne!(a, b);
        assert_eq!(a.len(), 24, "16 bytes, base64");
    }

    #[test]
    fn server_paths_are_left_to_the_api() {
        for path in [
            "/api",
            "/api/v1/x",
            "/acme/api/v1/records",
            "/health",
            "/health/ready",
            "/metrics",
        ] {
            assert!(is_server_path(path), "{path}");
        }
        for path in [
            "/",
            "/login",
            "/model/forms/1",
            "/main-ABC.js",
            "/assets/i18n/ar.json",
        ] {
            assert!(!is_server_path(path), "{path}");
        }
    }

    #[test]
    fn a_path_never_leaves_the_root() {
        let root = Path::new("/srv/web");
        assert_eq!(file_for(root, "/"), Some(root.join("index.html")));
        assert_eq!(file_for(root, "/a/b.js"), Some(root.join("a").join("b.js")));
        assert_eq!(file_for(root, "/../etc/passwd"), None);
        assert_eq!(file_for(root, "/a//b"), None);
        assert_eq!(file_for(root, "/a/./b"), None);
        assert_eq!(file_for(root, "/..\\x"), None);
        assert_eq!(file_for(root, "/C:/x"), None);
    }

    #[test]
    fn content_types_follow_the_extension() {
        assert_eq!(
            content_type(Path::new("main.js")),
            "text/javascript; charset=utf-8"
        );
        assert_eq!(
            content_type(Path::new("index.HTML")),
            "text/html; charset=utf-8"
        );
        assert_eq!(content_type(Path::new("blob")), "application/octet-stream");
    }

    #[tokio::test]
    async fn the_app_is_served_and_its_routes_fall_back_to_index() {
        use axum::Router;
        use axum::routing::get;
        use tower::ServiceExt;

        let dir = std::env::temp_dir().join(format!("attome-web-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), "<html>app</html>").unwrap();
        std::fs::write(dir.join("main.js"), "console.log(1)").unwrap();
        let app = Router::new()
            .route("/api/v1/ping", get(|| async { "pong" }))
            .layer(axum::middleware::from_fn_with_state(
                WebRoot(Arc::new(dir.clone())),
                serve_web,
            ));
        let get_body = |uri: &'static str| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                    .await
                    .unwrap();
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                    .await
                    .unwrap();
                (status, String::from_utf8_lossy(&bytes).into_owned())
            }
        };
        assert_eq!(
            get_body("/").await,
            (StatusCode::OK, "<html>app</html>".into())
        );
        assert_eq!(get_body("/main.js").await.1, "console.log(1)");
        assert_eq!(get_body("/model/forms/1").await.1, "<html>app</html>");
        assert_eq!(get_body("/api/v1/ping").await.1, "pong");
        assert_eq!(get_body("/missing.js").await.0, StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
