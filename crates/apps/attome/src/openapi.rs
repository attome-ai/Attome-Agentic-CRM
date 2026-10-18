//! P-api-contract Phase 1 — the workspace's single OpenAPI composition point.
//!
//! This crate is the only one that can see every layer at once (guidelines §3's
//! "assembly is centralized"), so the final merge lives here rather than in
//! `attome-api`: the engine layer cannot name `crates/server`'s auth handlers,
//! and it cannot name an engine that is mounted into `ModelRegistry` from
//! outside it (`attome-workflow`).
//!
//! Two consumers, one document:
//!   * `GET /api/v1/openapi.json` (mounted below, behind the normal
//!     authenticated middleware stack — deliberately *not* bypass-listed, per
//!     P-api-contract §4: no public-SDK consumer justifies handing the full
//!     route/schema map to an unauthenticated caller on a self-hosted
//!     deployment);
//!   * `server --print-openapi` (`main.rs`), the offline path Angular's
//!     `generate:api` codegen and CI's drift check use, so neither needs a
//!     live authenticated server just to read the contract.

use attome_auth::session::SessionClaims;
use attome_server::AppState;
use attome_types::ErrorResponse;
use axum::{Extension, Json, Router, routing::get};
use std::sync::{Arc, LazyLock};

/// Built once per process: assembling the document walks every generated
/// fragment, and it cannot change at runtime. `Arc` so the handler clones a
/// pointer rather than the whole document per request.
static DOCUMENT: LazyLock<Arc<utoipa::openapi::OpenApi>> = LazyLock::new(|| Arc::new(build()));

fn build() -> utoipa::openapi::OpenApi {
    // `attome_api::openapi_document()` already carries attome-server's root
    // identity/security schemes and the whole engine layer it can reach.
    let mut doc = attome_api::openapi_document();
    // Engines mounted through `ModelRegistry` from this crate — keep this list
    // in step with `boot`'s model registrations.
    doc.merge(attome_workflow::openapi());
    doc.merge(attome_ai::openapi());
    doc.merge(attome_portal::openapi());
    doc.merge(attome_sales::openapi());
    doc.merge(attome_callintel::openapi());
    doc.merge(attome_marketing::openapi());
    doc.merge(attome_billing::openapi());
    doc.merge(attome_einvoice::openapi());
    doc.merge(attome_commission::openapi());
    doc.merge(attome_partner::openapi());
    doc.merge(attome_fulfilment::openapi());
    doc.merge(attome_workforce::openapi());
    doc.merge(attome_contract::openapi());
    doc.merge(attome_offline::openapi());
    doc.merge(attome_procurement::openapi());
    doc.merge(attome_hr::openapi());
    doc.merge(attome_search::engine::openapi());
    doc.merge(attome_report::openapi());
    doc.merge(attome_integration::openapi());
    // M41 Phase 1 (Process Intelligence, D-462) — same reasoning as the
    // engines above: `.register(attome_process::ProcessModel)` happens in
    // `boot.rs` (this crate), and `attome-process` has no dependency on
    // `attome-api` to merge this fragment from that layer instead.
    doc.merge(attome_process::openapi());
    // M57 Phase 1 (Document Generation, D-463) — same reasoning as
    // attome-process above.
    doc.merge(attome_docgen::openapi());
    // M36 Phase 0+1 (Predictive Intelligence, D-473) — same reasoning as
    // attome-process/attome-docgen above.
    doc.merge(attome_predict::openapi());
    // Trading Platform Phase 1 (document/TRADING-PLATFORM-PLAN.md) — same
    // reasoning as attome-process/attome-docgen/attome-predict above:
    // `.register(trd_engine::TrdModel)` happens in `boot.rs` (this crate),
    // and `trd-engine` sits above `attome-api` in the layer stack, so it has
    // no dependency on `attome-api` to merge this fragment from that layer
    // instead.
    // This crate's own auth surface.
    doc.merge(crate::auth::openapi());
    // M53 Phase 1 (Omnichannel, web chat only, D-474) — the public web chat
    // widget endpoint, mounted directly in `main.rs` for the same reason
    // `crate::auth::openapi()` is merged from here rather than from
    // `attome-api`.
    doc.merge(crate::omnichannel::openapi());
    doc.merge(<SelfDoc as utoipa::OpenApi>::openapi());
    // M61 Phase 1 (API Management, D-438) — applied last, against the fully
    // merged document: attome_server::middleware::deprecation::DEPRECATED_PATHS
    // is the single source of truth for both halves of a deprecation notice
    // (response headers, applied per-request by that module's middleware;
    // `deprecated: true` + `x-sunset`/`x-replacement` here), and a registry
    // entry can name a path mounted by any layer, so this can't run any
    // earlier than the point where every layer's paths are already present.
    attome_server::middleware::deprecation::apply_to_openapi(&mut doc);
    // S2-T2: every operation says how it is authenticated.
    declare_security(&mut doc);
    // Q20-T1: and which rate-limit class it is counted in.
    declare_rate_class(&mut doc);
    // S2-T7: and its privilege, risk, idempotency and cache policy.
    crate::openapi_policy::apply(&mut doc);
    // S2-T12: the webhook a subscription receives, as OpenAPI 3.1's
    // top-level `webhooks`. utoipa has no field for it; `extensions` is
    // flattened into the document's top level when it is serialised.
    doc.extensions
        .get_or_insert_with(Default::default)
        .insert("webhooks".to_owned(), webhooks());
    // S2-T8: the document names the release it describes.
    doc.info.version = env!("CARGO_PKG_VERSION").to_owned();
    // Z14-T2: every error code, as one enum the SDK can generate.
    doc.components
        .get_or_insert_with(Default::default)
        .schemas
        .insert(
            "ErrorCode".to_owned(),
            attome_types::error_codes::openapi_schema(),
        );
    doc
}

/// The assembled document. Cheap after the first call.
/// S2-T2: the security requirement of an operation whose annotation names
/// none, from the same rules the router enforces: a bypass-listed path
/// (`attome_server::middleware::bypass::is_bypass`) and a web portal's
/// sign-in flows are public (an empty requirement); the portal's account
/// and second-factor routes need its session; the S2S web-portal API needs
/// S2S signing; any other route takes a session, an API key or S2S signing,
/// since `s2s_authn` runs before `authn` on every non-bypass route.
fn security_for(path: &str) -> Vec<utoipa::openapi::security::SecurityRequirement> {
    use utoipa::openapi::security::SecurityRequirement;
    let scheme = |name: &str| SecurityRequirement::new(name, Vec::<String>::new());
    if attome_server::middleware::bypass::is_bypass(path) {
        return vec![SecurityRequirement::default()];
    }
    if let Some(portal) = path.strip_prefix("/{keyword}/api/v1/") {
        if portal.starts_with("auth/") && !portal.starts_with("auth/mfa/") {
            return vec![SecurityRequirement::default()];
        }
        return vec![scheme("portal_session")];
    }
    if path.starts_with("/api/v1/s2s/webportals/") {
        return vec![scheme("s2s_hmac")];
    }
    vec![
        scheme("session_cookie"),
        scheme("api_key"),
        scheme("s2s_hmac"),
    ]
}

/// S2-T2: fills in [`security_for`] on every operation that declares none.
fn declare_security(doc: &mut utoipa::openapi::OpenApi) {
    for (path, item) in doc.paths.paths.iter_mut() {
        for operation in [
            &mut item.get,
            &mut item.put,
            &mut item.post,
            &mut item.delete,
            &mut item.options,
            &mut item.head,
            &mut item.patch,
            &mut item.trace,
        ]
        .into_iter()
        .flatten()
        {
            if operation.security.is_none() {
                operation.security = Some(security_for(path));
            }
        }
    }
}

/// Q20-T1: `x-rate-class` on every operation, and `x-cache`, its cache
/// class (AA7-T1): the rate-limit category the
/// limiter counts it in (`attome_server::middleware::rate_limit::
/// category_for`, the one table both read), `api` unless listed.
fn declare_rate_class(doc: &mut utoipa::openapi::OpenApi) {
    use utoipa::openapi::extensions::Extensions;
    for (path, item) in doc.paths.paths.iter_mut() {
        for (method, operation) in [
            ("GET", &mut item.get),
            ("PUT", &mut item.put),
            ("POST", &mut item.post),
            ("DELETE", &mut item.delete),
            ("OPTIONS", &mut item.options),
            ("HEAD", &mut item.head),
            ("PATCH", &mut item.patch),
            ("TRACE", &mut item.trace),
        ] {
            let Some(operation) = operation else {
                continue;
            };
            let class = attome_server::middleware::rate_limit::category_for(method, path);
            // AA7-T1: and how its responses may be cached.
            let cache = match attome_server::middleware::cache_policy::class_for(
                &axum::http::Method::from_bytes(method.as_bytes())
                    .unwrap_or(axum::http::Method::GET),
                path,
            ) {
                attome_server::middleware::cache_policy::CacheClass::NoStore => "no-store",
                attome_server::middleware::cache_policy::CacheClass::PrivateRevalidate => {
                    "private-revalidate"
                }
                attome_server::middleware::cache_policy::CacheClass::Immutable => "immutable",
            };
            let extra: Extensions = [
                ("x-rate-class", serde_json::Value::from(class)),
                ("x-cache", serde_json::Value::from(cache)),
            ]
            .into_iter()
            .collect();
            match &mut operation.extensions {
                Some(existing) => existing.merge(extra),
                None => operation.extensions = Some(extra),
            }
        }
    }
}

/// S2-T12: `webhooks.entityChanged` — the delivery a subscription's target
/// receives (`attome_events::delivery`): the `WebhookPayload` body, the
/// signature header and the retry rules.
fn webhooks() -> serde_json::Value {
    let signature = format!(
        "`t=<unix ms>,v1=<hex>`: HMAC-SHA256, keyed with the subscription's secret \
         (hex-decoded), over `<t>.<raw body>`. Recompute it over the exact bytes received, \
         compare in constant time, and reject a `t` far from your clock. Header: `{}`.",
        attome_events::crypto::SIGNATURE_HEADER
    );
    serde_json::json!({
        "entityChanged": {
            "post": {
                "operationId": "webhook_entity_changed",
                "summary": "A record a subscription watches changed",
                "description": "Sent to a subscription's `target_url` for each matching change. \
                    Any 2xx answer ends the delivery. Any other status, a connection failure, or no \
                    answer within 15 seconds is retried: the wait starts at 10 seconds and doubles \
                    up to 15 minutes, until the subscription's `max_attempts` (8 for the `standard` \
                    retry class, 20 for `extended`, at most 25), after which the delivery is \
                    dead-lettered and can be replayed by an administrator. A target the SSRF guard \
                    rejects at send time is dead-lettered at once. Retries carry the same \
                    `Idempotency-Key`, so drop a key you have already handled.",
                "tags": ["webhooks"],
                "parameters": [
                    {
                        "name": attome_events::crypto::SIGNATURE_HEADER,
                        "in": "header",
                        "required": true,
                        "description": signature,
                        "schema": { "type": "string", "pattern": "^t=[0-9]+,v1=[0-9a-f]{64}$" }
                    },
                    {
                        "name": "Idempotency-Key",
                        "in": "header",
                        "required": true,
                        "description": "The event id, the same on every retry of one event.",
                        "schema": { "type": "string", "format": "uuid" }
                    }
                ],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/WebhookPayload" }
                        }
                    }
                },
                "responses": {
                    "2XX": { "description": "Received; the delivery is done." },
                    "default": { "description": "Anything else is retried, as described above." }
                }
            }
        }
    })
}

pub fn document() -> Arc<utoipa::openapi::OpenApi> {
    Arc::clone(&DOCUMENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(openapi_json))]
struct SelfDoc;

#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    tag = "operations",
    summary = "This API's own OpenAPI 3.1 document",
    responses(
        (status = 200, description = "The generated OpenAPI 3.1 document"),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn openapi_json(
    // Not read — its presence is what makes the route unreachable without a
    // valid session/API key, matching every other non-bypass-listed route.
    Extension(_claims): Extension<SessionClaims>,
) -> Json<Arc<utoipa::openapi::OpenApi>> {
    Json(document())
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/v1/openapi.json", get(openapi_json))
}

#[cfg(test)]
mod tests {
    /// S2-T8: the version is the release's, not a placeholder.
    #[test]
    fn document_version_is_package_version() {
        assert_eq!(super::document().info.version, env!("CARGO_PKG_VERSION"));
        assert!(super::document().info.license.is_some());
    }

    /// S2-T2: every operation declares how it is authenticated, a public
    /// one with an explicit empty requirement.
    #[test]
    fn every_operation_declares_security() {
        let doc = serde_json::to_value(&*super::document()).unwrap();
        let mut missing = Vec::new();
        for (path, item) in doc["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                if operation.get("responses").is_some() && operation.get("security").is_none() {
                    missing.push(format!("{} {path}", method.to_uppercase()));
                }
            }
        }
        assert!(missing.is_empty(), "{missing:#?}");
    }

    /// Q20-T1: every operation names its rate-limit class.
    #[test]
    fn every_operation_has_a_rate_class() {
        let doc = serde_json::to_value(&*super::document()).unwrap();
        let mut missing = Vec::new();
        for (path, item) in doc["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                if operation.get("responses").is_some() && !operation["x-rate-class"].is_string() {
                    missing.push(format!("{} {path}", method.to_uppercase()));
                }
            }
        }
        assert!(missing.is_empty(), "{missing:#?}");
        assert_eq!(
            doc["paths"]["/api/v1/auth/login"]["post"]["x-rate-class"],
            "credential"
        );
    }

    /// S2-T2: the rules [`super::security_for`] applies.
    #[test]
    fn security_follows_the_router() {
        let names = |path: &str| -> Vec<String> {
            serde_json::to_value(super::security_for(path))
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .flat_map(|r| r.as_object().unwrap().keys().cloned().collect::<Vec<_>>())
                .collect()
        };
        assert!(names("/api/v1/auth/login").is_empty(), "public");
        assert!(names("/health").is_empty(), "public");
        assert!(
            names("/{keyword}/api/v1/auth/login").is_empty(),
            "portal sign-in is public"
        );
        assert_eq!(
            names("/{keyword}/api/v1/auth/mfa/enroll"),
            ["portal_session"]
        );
        assert_eq!(
            names("/{keyword}/api/v1/records/{entity}"),
            ["portal_session"]
        );
        assert_eq!(
            names("/api/v1/s2s/webportals/{keyword}/login"),
            ["s2s_hmac"]
        );
        assert_eq!(
            names("/api/v1/query/execute"),
            ["session_cookie", "api_key", "s2s_hmac"]
        );
    }

    /// Every operation has its own `operationId`. utoipa takes the handler's
    /// function name, so two `start_run` handlers collide, and the generated
    /// TypeScript then refuses to compile (duplicate identifier).
    #[test]
    fn operation_ids_are_unique() {
        let doc = serde_json::to_value(&*super::document()).unwrap();
        let mut seen = std::collections::BTreeMap::new();
        let mut duplicates = Vec::new();
        for (path, item) in doc["paths"].as_object().unwrap() {
            for (method, operation) in item.as_object().unwrap() {
                if let Some(id) = operation["operationId"].as_str() {
                    let here = format!("{} {path}", method.to_uppercase());
                    if let Some(first) = seen.insert(id.to_owned(), here.clone()) {
                        duplicates.push(format!("{id}: {first} and {here}"));
                    }
                }
            }
        }
        assert!(
            duplicates.is_empty(),
            "give each a distinct `operation_id = \"...\"` in its #[utoipa::path]: {duplicates:#?}"
        );
    }
}
