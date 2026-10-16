//! Q21-T4: a JSON request body deeper than [`MAX_JSON_DEPTH`] levels, or
//! with an array longer than [`MAX_JSON_ARRAY_LEN`] items, is refused with
//! `413 payload_too_large` before any handler deserialises it into types.
//! `serde_json` itself stops at 128 levels; a deep body still costs a
//! recursive walk per level, and a huge array a large allocation, in every
//! handler that accepts `Value`. One scan over bytes the body limit has
//! already bounded settles both before authentication or a handler runs.
//!
//! Only a body declared as JSON (`application/json` or `+json`) is scanned;
//! uploads, forms and bodiless requests pass untouched. The scan is a byte
//! state machine (strings and escapes skipped), not a parse: a body that is
//! not valid JSON is left for the handler's own extractor to reject.

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use attome_types::AppError;

/// The deepest nesting of arrays and objects a request body may have.
pub const MAX_JSON_DEPTH: usize = 64;

/// The most items one array in a request body may hold.
pub const MAX_JSON_ARRAY_LEN: usize = 10_000;

/// Why a body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonShapeError {
    TooDeep,
    ArrayTooLong,
}

/// Checks nesting depth and array lengths of a JSON document without parsing
/// it. Malformed input is not an error here (the handler's parser decides).
pub fn check_json_shape(
    bytes: &[u8],
    max_depth: usize,
    max_array_len: usize,
) -> Result<(), JsonShapeError> {
    // One entry per open container: `Some(items so far)` for an array (an
    // item is counted when its first byte is seen), `None` for an object.
    let mut stack: Vec<Option<usize>> = Vec::new();
    // Inside an array, whether the next value starts a new item.
    let mut expecting_item = false;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        if expecting_item && b != b']' {
            expecting_item = false;
            if let Some(Some(count)) = stack.last_mut() {
                *count += 1;
                if *count > max_array_len {
                    return Err(JsonShapeError::ArrayTooLong);
                }
            }
        }
        match b {
            b'"' => in_string = true,
            b'[' => {
                stack.push(Some(0));
                if stack.len() > max_depth {
                    return Err(JsonShapeError::TooDeep);
                }
                expecting_item = true;
            }
            b'{' => {
                stack.push(None);
                if stack.len() > max_depth {
                    return Err(JsonShapeError::TooDeep);
                }
            }
            b']' | b'}' => {
                stack.pop();
                expecting_item = false;
            }
            b',' => expecting_item = matches!(stack.last(), Some(Some(_))),
            _ => {}
        }
    }
    Ok(())
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase()
        })
        .is_some_and(|mime| mime == "application/json" || mime.ends_with("+json"))
}

/// Layered directly inside `RequestBodyLimitLayer` (`app::apply_outer_layers`),
/// so the bytes read here are already bounded by `app.max_body_size_bytes`.
/// A body that cannot be read (over the limit, or the client went away) is
/// answered `413`, as the body limit itself would.
pub async fn reject_oversized_json_shape(req: Request, next: Next) -> Response {
    if !is_json(req.headers()) {
        return next.run(req).await;
    }
    let (parts, body) = req.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, usize::MAX).await else {
        return AppError::PayloadTooLarge.into_response();
    };
    if let Err(reason) = check_json_shape(&bytes, MAX_JSON_DEPTH, MAX_JSON_ARRAY_LEN) {
        tracing::info!(?reason, path = %parts.uri.path(), "json body refused by shape");
        return AppError::PayloadTooLarge.into_response();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod request_limits {
    use super::*;
    use axum::{Router, http::StatusCode, routing::post};
    use tower::ServiceExt;

    fn nested(depth: usize) -> String {
        format!("{}1{}", "[".repeat(depth), "]".repeat(depth))
    }

    #[test]
    fn depth_at_the_limit_passes_and_one_more_is_refused() {
        assert_eq!(check_json_shape(nested(64).as_bytes(), 64, 10), Ok(()));
        assert_eq!(
            check_json_shape(nested(65).as_bytes(), 64, 10),
            Err(JsonShapeError::TooDeep)
        );
        let objects = format!("{}{}", r#"{"a":"#.repeat(65), "}".repeat(65));
        assert_eq!(
            check_json_shape(objects.as_bytes(), 64, 10),
            Err(JsonShapeError::TooDeep)
        );
    }

    #[test]
    fn array_length_counts_items_not_bytes() {
        assert_eq!(check_json_shape(b"[]", 64, 3), Ok(()));
        assert_eq!(check_json_shape(b"[1, 2, 3]", 64, 3), Ok(()));
        assert_eq!(
            check_json_shape(b"[1,2,3,4]", 64, 3),
            Err(JsonShapeError::ArrayTooLong)
        );
        // Commas inside objects and strings are not array items.
        assert_eq!(
            check_json_shape(br#"[{"a":1,"b":2,"c":3,"d":4}, "x,y,z,w"]"#, 64, 3),
            Ok(())
        );
        // Brackets inside strings, escaped quotes included, are text.
        assert_eq!(check_json_shape(br#"["[[[[\"]]]]"]"#, 2, 3), Ok(()));
        // Nested arrays count separately.
        assert_eq!(check_json_shape(b"[[1,2,3],[1,2,3]]", 64, 3), Ok(()));
    }

    fn app() -> Router {
        Router::new()
            .route("/echo", post(|body: String| async move { body }))
            .layer(axum::middleware::from_fn(reject_oversized_json_shape))
    }

    fn json_request(body: String, content_type: &str) -> Request {
        axum::http::Request::builder()
            .method("POST")
            .uri("/echo")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn a_deep_json_body_is_refused_before_the_handler() {
        let res = app()
            .oneshot(json_request(nested(65), "application/json"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let long = format!("[{}0]", "0,".repeat(MAX_JSON_ARRAY_LEN));
        let res = app()
            .oneshot(json_request(long, "application/merge-patch+json"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn an_ordinary_body_reaches_the_handler_unchanged() {
        let body = r#"{"name":"a","tags":[1,2,3]}"#.to_owned();
        let res = app()
            .oneshot(json_request(
                body.clone(),
                "application/json; charset=utf-8",
            ))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let echoed = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(echoed, body.as_bytes());
        // A body not declared as JSON is never scanned.
        let res = app()
            .oneshot(json_request(nested(100), "text/plain"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
