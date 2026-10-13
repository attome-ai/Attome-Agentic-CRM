//! P-api-contract Phase 1 — the root of the workspace's one OpenAPI document.
//!
//! Every handler-owning file across `base-*`, `xrm-*`, and `crates/server`
//! carries `#[utoipa::path]` annotations and exposes an `openapi_fragment()`.
//! Those fragments merge upward: file → crate → here is where the document's
//! *identity* lives (`info`, the security schemes, the tag list), because this
//! crate owns the authentication middleware the schemes describe and is the one
//! layer both `xrm-*` and `crates/server` already depend on.
//!
//! The assembled result is served at `GET /api/v1/openapi.json` and printed by
//! `server --print-openapi`; see `crates/server/src/openapi.rs` for the final
//! merge (it is the only crate that can see every layer at once).

use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, SecurityScheme},
};

/// The two credentials `middleware::auth` actually accepts, plus the S2S
/// signature used by external systems. Declared as a `Modify` rather than in
/// the derive because utoipa has no attribute form for security schemes.
struct SecuritySchemes;

impl Modify for SecuritySchemes {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);

        // `attome_auth::cookie::session_cookie_name` — `__Host-session_token`
        // over HTTPS, `session_token` on plain-http local dev.
        components.add_security_scheme(
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "__Host-session_token",
                "Browser session cookie issued by POST /api/v1/auth/login. Mutating \
                 requests additionally require the CSRF conditions enforced by \
                 `middleware::csrf`.",
            ))),
        );

        // `middleware::auth::extract_api_key` — `Authorization: ApiKey <pub>:<secret>`.
        // Modelled as `apiKey`/`header`/`Authorization` rather than `http`,
        // because `ApiKey` is not one of the IANA HTTP auth schemes an `http`
        // security scheme is allowed to name.
        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                "Authorization",
                "`Authorization: ApiKey <public_key>:<secret>`, issued by \
                 POST /api/v1/auth/api-keys.",
            ))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Attome XRM API",
        version = "1.0.0",
        description = "The Attome XRM platform's HTTP API. Entity record shapes under \
                       `/api/v1/{entity}` are resolved from each deployment's runtime \
                       metadata (D-003) and therefore cannot be enumerated statically — \
                       those operations document the generic envelope only. Fetch \
                       `GET /api/v1/schema/{logicalname}` for a live entity's fields.",
    ),
    modifiers(&SecuritySchemes),
    tags(
        (name = "auth", description = "Sessions, credentials, MFA, and federation"),
        (name = "entity", description = "Generic metadata-driven record CRUD"),
        (name = "query", description = "Stored-query and view execution"),
        (name = "schema", description = "Runtime entity metadata"),
        (name = "sidebar", description = "Navigation tree"),
        (name = "notification", description = "User notification inbox"),
        (name = "workflow", description = "Workflow definitions and instances"),
        (name = "admin", description = "Platform administration"),
        (name = "admin-security", description = "Security, access control, and S2S administration"),
        (name = "admin-webcrawl", description = "Web Crawling for Knowledge Base"),
        (name = "operations", description = "Health, readiness, and version probes"),
    ),
)]
struct RootDoc;

/// This crate's contribution: the document's identity plus the unauthenticated
/// health/version probes it mounts itself.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let mut doc = RootDoc::openapi();
    doc.merge(crate::health::openapi_fragment());
    doc
}
