//! S13-T1: the package catalogue. Each deployment keeps a private catalogue
//! of signed packages: an administrator adds one (pushed, or taken from a
//! partner catalogue), another administrator reviews it, and an approved
//! version installs through the T8 package path (`packages/preview`, then
//! the metadata apply). A partner catalogue is a URL serving an
//! `attome-catalogue/v1` index, configured with the publisher key its
//! packages are signed with (`packages.partner_catalogues`); configuring it
//! trusts that key for its publisher.
//!
//! ```json
//! { "format": "attome-catalogue/v1", "packages": [ <attome-package/v1>, … ] }
//! ```
//!
//! | route | does |
//! |---|---|
//! | `GET  /api/v1/admin/packages/catalogue` | the private catalogue, newest first |
//! | `POST /api/v1/admin/packages/catalogue` | add a package (pushed, or from a partner) for review |
//! | `POST /api/v1/admin/packages/catalogue/{id}/review` | approve or reject it (not by who added it) |
//! | `POST /api/v1/admin/packages/catalogue/{id}/install` | preview an approved version's install |
//! | `GET  /api/v1/admin/packages/partner-catalogues/{name}` | a partner catalogue's packages, verified |
//!
//! Built here, beside the package engine it installs through, rather than
//! as a crate of its own: it shares the package types and the install path.

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx};
use attome_core::EngineState;
use attome_server::authz::{Admin, Authorized};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PaginatedResponse};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use utoipa::ToSchema;
use uuid::Uuid;

use super::package::{Package, check_manifest, verify};

/// The format of a catalogue index.
pub const CATALOGUE_FORMAT: &str = "attome-catalogue/v1";

/// The setting naming the partner catalogues: `[{name, url, publisher, key}]`.
pub const PARTNER_CATALOGUES_SETTING: &str = "packages.partner_catalogues";

/// The largest catalogue index read.
const MAX_INDEX_BYTES: usize = 64 * 1024 * 1024;

/// One partner catalogue from [`PARTNER_CATALOGUES_SETTING`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partner {
    pub name: String,
    pub url: String,
    pub publisher: String,
    pub key: String,
}

/// The configured partner catalogues.
pub fn partners(state: &EngineState) -> Vec<Partner> {
    let Some(descriptor) = attome_core::setting_registry().get(PARTNER_CATALOGUES_SETTING) else {
        return Vec::new();
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            Some(Partner {
                name: entry.get("name")?.as_str()?.to_owned(),
                url: entry.get("url")?.as_str()?.to_owned(),
                publisher: entry.get("publisher")?.as_str()?.to_owned(),
                key: entry.get("key")?.as_str()?.to_owned(),
            })
        })
        .collect()
}

/// What a package asks of the deployment, shown before review: how it is
/// installed, the components it carries, the entities it brings or
/// extends with their field counts, and the roles it defines. Pure.
pub fn permissions(package: &Package) -> Value {
    json!({
        "mode": package.manifest.mode,
        "contents": package.manifest.contents,
        "entities": package.bundle.entities.iter()
            .map(|e| json!({ "entity": e.logicalname, "fields": e.attributes.len() }))
            .collect::<Vec<_>>(),
        "roles": package.bundle.roles.iter().map(|r| r.name.clone()).collect::<Vec<_>>(),
        "depends": package.manifest.depends,
    })
}

/// One package a partner catalogue offers.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PartnerItem {
    pub package_id: String,
    pub version: String,
    pub publisher: String,
    /// What it asks of the deployment ([`permissions`]).
    #[schema(value_type = Object)]
    pub permissions: Value,
    /// Signed with the partner's key and its manifest is valid.
    pub verified: bool,
    /// Why it is not verified.
    pub problems: Vec<String>,
}

/// A catalogue index read: each line, with its package when it reads.
pub type IndexItems = Vec<(PartnerItem, Option<Package>)>;

/// Reads a partner's catalogue index and checks each package against the
/// partner's publisher and key. A package that does not read is skipped
/// with a problem on a placeholder line. Pure.
pub fn read_index(bytes: &[u8], partner: &Partner) -> Result<IndexItems, String> {
    let index: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("the catalogue does not read: {e}"))?;
    if index.get("format").and_then(Value::as_str) != Some(CATALOGUE_FORMAT) {
        return Err(format!("the catalogue is not {CATALOGUE_FORMAT}"));
    }
    let trusted = [(partner.publisher.clone(), partner.key.clone())];
    let mut out = Vec::new();
    for (i, raw) in index
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let package: Package = match serde_json::from_value(raw.clone()) {
            Ok(package) => package,
            Err(e) => {
                out.push((
                    PartnerItem {
                        package_id: format!("packages[{i}]"),
                        version: String::new(),
                        publisher: String::new(),
                        permissions: Value::Null,
                        verified: false,
                        problems: vec![format!("does not read: {e}")],
                    },
                    None,
                ));
                continue;
            }
        };
        let mut problems = check_manifest(&package.manifest);
        if let Err(e) = verify(&package, &trusted) {
            problems.push(e);
        }
        out.push((
            PartnerItem {
                package_id: package.manifest.id.clone(),
                version: package.manifest.version.clone(),
                publisher: package.manifest.publisher.clone(),
                permissions: permissions(&package),
                verified: problems.is_empty(),
                problems,
            },
            Some(package),
        ));
    }
    Ok(out)
}

async fn fetch_index(partner: &Partner) -> Result<IndexItems, AppError> {
    if !partner.url.starts_with("https://") {
        return Err(AppError::Validation(format!(
            "partner catalogue {}: the url is https://",
            partner.name
        )));
    }
    // The operator configured this URL, so its host may be private.
    let purpose = attome_outbound::http::Purpose::public("package-catalogue")
        .with_private_urls([partner.url.as_str()]);
    let client =
        attome_outbound::http::client(purpose, |b| b.timeout(std::time::Duration::from_secs(30)))
            .map_err(|e| AppError::internal(format!("building the catalogue http client: {e}")))?;
    let resp =
        client.get(&partner.url).send().await.map_err(|e| {
            AppError::Validation(format!("fetching catalogue {}: {e}", partner.name))
        })?;
    if !resp.status().is_success() {
        return Err(AppError::Validation(format!(
            "fetching catalogue {}: HTTP {}",
            partner.name,
            resp.status()
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| AppError::Validation(format!("reading catalogue {}: {e}", partner.name)))?;
    if bytes.len() > MAX_INDEX_BYTES {
        return Err(AppError::Validation(format!(
            "catalogue {} is over {} MB",
            partner.name,
            MAX_INDEX_BYTES / (1024 * 1024)
        )));
    }
    read_index(&bytes, partner).map_err(AppError::Validation)
}

/// One version in the private catalogue.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct CatalogueEntry {
    pub id: Uuid,
    pub package_id: String,
    pub version: String,
    pub publisher: String,
    /// Where it came from: `pushed`, or `partner:<name>`.
    pub source: String,
    #[schema(value_type = Object)]
    pub permissions: Value,
    /// `pending`, `approved` or `rejected`.
    pub review_status: String,
    pub review_note: Option<String>,
    pub added_by: Uuid,
    pub reviewed_by: Option<Uuid>,
    pub reviewed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

const ENTRY_COLUMNS: &str = "id, package_id, version, publisher, source, permissions, review_status, \
     review_note, added_by, reviewed_by, reviewed_at, created_at";

/// The private catalogue
///
/// S13-T1: the signed package versions added to this deployment's catalogue, newest first, with
/// what each asks of the deployment and its review status. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/packages/catalogue",
    operation_id = "list_package_catalogue",
    tag = "admin-metadata",
    params(OnePageQuery),
    responses(
        (status = 200, description = "The catalogue", body = PaginatedResponse<CatalogueEntry>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn list_catalogue(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Query(query): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<CatalogueEntry>>, AppError> {
    let window = query.window();
    let items: Vec<CatalogueEntry> = sqlx::query_as(&format!(
        "SELECT {ENTRY_COLUMNS} FROM package_catalogue ORDER BY created_at DESC, id DESC \
         LIMIT $1 OFFSET $2"
    ))
    .bind(window.page_size)
    .bind(window.offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM package_catalogue")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(
        items,
        total,
        window.page,
        window.page_size,
    )))
}

/// Body of `POST /api/v1/admin/packages/catalogue`: a pushed package, or a
/// partner's package by id and version.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AddToCatalogueBody {
    /// An `attome-package/v1` document.
    #[serde(default)]
    #[schema(value_type = Option<Object>)]
    pub package: Option<Value>,
    /// A partner catalogue's name, with `package_id` and `version`.
    #[serde(default)]
    pub partner: Option<String>,
    #[serde(default)]
    pub package_id: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

/// Add a package to the catalogue
///
/// S13-T1: adds a signed package version for review: pushed as `package` (signed by a trusted
/// publisher), or taken from partner catalogue `partner` by `package_id` and `version` (signed with
/// that partner's key). Its manifest must be valid; a version already in the catalogue is a
/// conflict. It waits for review by another administrator. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/packages/catalogue",
    operation_id = "add_to_package_catalogue",
    tag = "admin-metadata",
    request_body = AddToCatalogueBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 201, description = "Added, pending review", body = CatalogueEntry),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such partner catalogue, or it does not offer that version", body = ErrorResponse),
        (status = 409, description = "That version is already in the catalogue", body = ErrorResponse),
        (status = 422, description = "The package does not read, is not signed by a trusted publisher, or its manifest is wrong", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn add_to_catalogue(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Json(body): Json<AddToCatalogueBody>,
) -> Result<(StatusCode, Json<CatalogueEntry>), AppError> {
    let (package, source) = match (body.package, body.partner) {
        (Some(raw), None) => {
            let package: Package = serde_json::from_value(raw)
                .map_err(|e| AppError::Validation(format!("the package does not read: {e}")))?;
            verify(&package, &super::routes::trusted_publishers(&state))
                .map_err(AppError::Validation)?;
            (package, "pushed".to_owned())
        }
        (None, Some(name)) => {
            let (Some(package_id), Some(version)) = (body.package_id, body.version) else {
                return Err(AppError::Validation(
                    "a partner's package is named by package_id and version".to_owned(),
                ));
            };
            let partner = partners(&state)
                .into_iter()
                .find(|p| p.name == name)
                .ok_or(AppError::NotFound)?;
            let (item, package) = fetch_index(&partner)
                .await?
                .into_iter()
                .find(|(item, _)| item.package_id == package_id && item.version == version)
                .ok_or(AppError::NotFound)?;
            let Some(package) = package.filter(|_| item.verified) else {
                return Err(AppError::Validation(item.problems.join("; ")));
            };
            (package, format!("partner:{name}"))
        }
        _ => {
            return Err(AppError::Validation(
                "send the package, or a partner with package_id and version".to_owned(),
            ));
        }
    };
    let problems = check_manifest(&package.manifest);
    if !problems.is_empty() {
        return Err(AppError::Validation(problems.join("; ")));
    }
    let document = serde_json::to_value(&package).map_err(AppError::internal)?;
    let id = Uuid::now_v7();
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Create,
            ctx.user_id,
            "package_catalogue",
            Some(id),
        )
        .named("package_catalogue.add")
        .comment(format!(
            "package {} {} added to the catalogue from {source}",
            package.manifest.id, package.manifest.version
        )),
    )
    .await?;
    let entry: Option<CatalogueEntry> = sqlx::query_as(&format!(
        "INSERT INTO package_catalogue \
             (id, package_id, version, publisher, source, package, permissions, added_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (package_id, version) DO NOTHING \
         RETURNING {ENTRY_COLUMNS}"
    ))
    .bind(id)
    .bind(&package.manifest.id)
    .bind(&package.manifest.version)
    .bind(&package.manifest.publisher)
    .bind(&source)
    .bind(&document)
    .bind(permissions(&package))
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(entry) = entry else {
        return Err(AppError::Conflict(
            "that version is already in the catalogue",
        ));
    };
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(entry)))
}

/// A review's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[schema(as = CatalogueReviewDecision)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Approved,
    Rejected,
}

/// Body of `POST /api/v1/admin/packages/catalogue/{id}/review`.
#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = CatalogueReviewBody)]
pub struct ReviewBody {
    pub decision: ReviewDecision,
    #[serde(default)]
    pub note: Option<String>,
}

/// Review a catalogue package
///
/// S13-T1: approves or rejects a pending package version. The administrator who added it cannot
/// review it. Only an approved version installs. Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/packages/catalogue/{id}/review",
    operation_id = "review_catalogue_package",
    tag = "admin-metadata",
    params(("id" = Uuid, Path, description = "The catalogue entry")),
    request_body = ReviewBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Configuration, attome_audit::AuditOperation::Update)])))),
    responses(
        (status = 200, description = "Reviewed", body = CatalogueEntry),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entry", body = ErrorResponse),
        (status = 409, description = "Already reviewed", body = ErrorResponse),
        (status = 422, description = "The reviewer added it, or the note is too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn review(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<CatalogueEntry>, AppError> {
    if body.note.as_ref().is_some_and(|n| n.chars().count() > 2000) {
        return Err(AppError::Validation(
            "note: at most 2000 characters".to_owned(),
        ));
    }
    let added_by: Option<Uuid> =
        sqlx::query_scalar("SELECT added_by FROM package_catalogue WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    if added_by.ok_or(AppError::NotFound)? == ctx.user_id {
        return Err(AppError::Validation(
            "a package is reviewed by an administrator other than who added it".to_owned(),
        ));
    }
    let decision = match body.decision {
        ReviewDecision::Approved => "approved",
        ReviewDecision::Rejected => "rejected",
    };
    let mut tx = SecurityTx::begin(
        &state,
        SecurityEvent::new(
            MandatoryCategory::Configuration,
            AuditOperation::Update,
            ctx.user_id,
            "package_catalogue",
            Some(id),
        )
        .named("package_catalogue.review")
        .comment(format!("catalogue package {decision}")),
    )
    .await?;
    let entry: Option<CatalogueEntry> = sqlx::query_as(&format!(
        "UPDATE package_catalogue \
            SET review_status = $2, review_note = $3, reviewed_by = $4, reviewed_at = now() \
          WHERE id = $1 AND review_status = 'pending' \
          RETURNING {ENTRY_COLUMNS}"
    ))
    .bind(id)
    .bind(decision)
    .bind(&body.note)
    .bind(ctx.user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let Some(entry) = entry else {
        return Err(AppError::Conflict("the package was already reviewed"));
    };
    tx.commit().await?;
    Ok(Json(entry))
}

/// Install a catalogue package
///
/// S13-T1: previews the install of an approved catalogue version through the T8 package path:
/// the same checks and persisted plan as `POST /api/v1/admin/packages/preview`. Installing is
/// applying that plan (`POST /api/v1/admin/metadata/import?mode=apply`). Administrators only.
#[utoipa::path(
    post,
    path = "/api/v1/admin/packages/catalogue/{id}/install",
    operation_id = "install_catalogue_package",
    tag = "admin-metadata",
    params(("id" = Uuid, Path, description = "The catalogue entry")),
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(attome_audit::security::ExemptReason::Delegated, Some("EngineJob::ApplyMetadataBundle (bundle/apply.rs::audit_entity_change)"), "only computes and persists a proposal, as packages/preview does; installing applies that plan through mode=apply, whose job audits every schema change")))),
    responses(
        (status = 200, description = "The preview and the persisted plan", body = super::routes::PackagePreviewResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such entry", body = ErrorResponse),
        (status = 409, description = "The version is not approved", body = ErrorResponse),
        (status = 422, description = "The package no longer verifies, or its namespace is wrong for this deployment", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn install(
    State(state): State<EngineState>,
    ctx: Authorized<Admin>,
    Path(id): Path<Uuid>,
) -> Result<Json<super::routes::PackagePreviewResponse>, AppError> {
    let row: Option<(Value, String)> =
        sqlx::query_as("SELECT package, review_status FROM package_catalogue WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let (document, status) = row.ok_or(AppError::NotFound)?;
    if status != "approved" {
        return Err(AppError::Conflict(
            "only an approved package version installs",
        ));
    }
    let package: Package = serde_json::from_value(document).map_err(AppError::internal)?;
    super::routes::preview_document(&state, package, ctx.user_id)
        .await
        .map(Json)
}

/// A partner catalogue's offer.
#[derive(Debug, Serialize, ToSchema)]
pub struct PartnerCatalogue {
    pub name: String,
    pub publisher: String,
    pub packages: Vec<PartnerItem>,
}

/// A partner catalogue
///
/// S13-T1: fetches partner catalogue `name` (`packages.partner_catalogues`) and lists its packages,
/// each checked against the partner's publisher key: what it asks of the deployment and whether it
/// verifies. Read-only; add one to the private catalogue to review and install it. Administrators
/// only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/packages/partner-catalogues/{name}",
    operation_id = "get_partner_catalogue",
    tag = "admin-metadata",
    params(("name" = String, Path, description = "The partner catalogue's name")),
    responses(
        (status = 200, description = "The partner's packages", body = PartnerCatalogue),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 404, description = "No such partner catalogue", body = ErrorResponse),
        (status = 422, description = "The catalogue could not be fetched or does not read", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn partner_catalogue(
    State(state): State<EngineState>,
    _ctx: Authorized<Admin>,
    Path(name): Path<String>,
) -> Result<Json<PartnerCatalogue>, AppError> {
    let partner = partners(&state)
        .into_iter()
        .find(|p| p.name == name)
        .ok_or(AppError::NotFound)?;
    let packages = fetch_index(&partner)
        .await?
        .into_iter()
        .map(|(item, _)| item)
        .collect();
    Ok(Json(PartnerCatalogue {
        name: partner.name,
        publisher: partner.publisher,
        packages,
    }))
}

pub fn routes() -> Router<EngineState> {
    Router::new()
        .route(
            "/api/v1/admin/packages/catalogue",
            get(list_catalogue).post(add_to_catalogue),
        )
        .route("/api/v1/admin/packages/catalogue/{id}/review", post(review))
        .route(
            "/api/v1/admin/packages/catalogue/{id}/install",
            post(install),
        )
        .route(
            "/api/v1/admin/packages/partner-catalogues/{name}",
            get(partner_catalogue),
        )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(list_catalogue, add_to_catalogue, review, install, partner_catalogue))]
struct ApiDocFragment;

pub fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    fn signed(key: &SigningKey, publisher: &str, version: &str) -> Value {
        let mut package: Package = serde_json::from_value(json!({
            "format": "attome-package/v1",
            "manifest": {
                "id": "com.example.fleet", "publisher": publisher, "namespace": "exf",
                "version": version, "platform": ">=0.1.0", "contents": ["entities", "roles"],
                "mode": "managed"
            },
            "bundle": {
                "format": "attome-bundle/v1",
                "requires": { "platform_version": ">=0.1.0", "schema_version": 1 },
                "entities": [{ "logicalname": "exf_vehicle", "display_name": "Vehicle",
                    "attributes": [{ "logicalname": "plate", "display_name": "Plate", "field_type": "text" }] }]
            }
        }))
        .expect("package");
        super::super::package::sign(&mut package, key).expect("sign");
        serde_json::to_value(package).expect("value")
    }

    fn partner(key: &SigningKey) -> Partner {
        Partner {
            name: "example".into(),
            url: "https://catalogue.example.test/index.json".into(),
            publisher: "Example Co".into(),
            key: base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes()),
        }
    }

    #[test]
    fn catalogue_index_verifies_each_package_against_the_partner_key() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let other = SigningKey::from_bytes(&[4u8; 32]);
        let index = json!({
            "format": CATALOGUE_FORMAT,
            "packages": [
                signed(&key, "Example Co", "1.0.0"),
                signed(&other, "Example Co", "1.1.0"),
                { "format": "attome-package/v1" }
            ]
        });
        let items = read_index(index.to_string().as_bytes(), &partner(&key)).expect("index");
        assert_eq!(items.len(), 3);
        assert!(items[0].0.verified, "{:?}", items[0].0.problems);
        assert_eq!(
            items[0].0.permissions["entities"][0]["entity"],
            "exf_vehicle"
        );
        assert_eq!(items[0].0.permissions["entities"][0]["fields"], 1);
        assert_eq!(items[0].0.permissions["mode"], "managed");
        assert!(!items[1].0.verified, "signed with another key");
        assert!(
            !items[2].0.verified && items[2].1.is_none(),
            "does not read"
        );
    }

    #[test]
    fn catalogue_index_of_another_format_is_refused() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let index = json!({ "format": "attome-bundle/v1", "packages": [] });
        assert!(read_index(index.to_string().as_bytes(), &partner(&key)).is_err());
        assert!(read_index(b"not json", &partner(&key)).is_err());
    }
}
