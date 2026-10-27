//! `GET /api/v1/admin/sbom` (roadmap AC7-T11): what this deployment runs —
//! the release's bill of materials embedded at build time (`build.rs`: the
//! release gate's CycloneDX file, or one derived from `Cargo.lock` in other
//! builds) and the configuration packs installed through the changeset
//! ledger. Administrators only; reads, changes nothing.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::Serialize;
use serde_json::Value;
use utoipa::ToSchema;

/// The embedded CycloneDX document.
const SBOM_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/sbom.json"));

/// One installed configuration pack.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct InstalledPack {
    /// The pack's scope (`crm`, `sales`, …).
    pub name: String,
    /// The highest changeset of the pack applied.
    pub version: i32,
    /// `product`, `project` or `customer`.
    pub layer: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SbomResponse {
    /// The release's CycloneDX 1.5 bill of materials.
    #[schema(value_type = Object)]
    pub release: Value,
    pub packs: Vec<InstalledPack>,
}

/// The embedded document, parsed (an unreadable one is reported as such,
/// never as an error to the caller).
fn release_bom() -> Value {
    serde_json::from_str(SBOM_JSON).unwrap_or_else(|_| {
        serde_json::json!({ "bomFormat": "CycloneDX", "error": "the embedded document does not parse" })
    })
}

/// Software bill of materials
///
/// Software bill of materials. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/sbom",
    tag = "admin",
    operation_id = "get_sbom",
    responses(
        (status = 200, description = "The release's bill of materials and the installed packs", body = SbomResponse),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_sbom(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::Deployment>>,
) -> Result<Json<SbomResponse>, AppError> {
    let packs: Vec<InstalledPack> = sqlx::query_as(
        "SELECT scope AS name, MAX(seq) AS version, layer FROM changeset_apply \
          WHERE layer <> 'platform' AND status IN ('succeeded', 'adopted') \
          GROUP BY scope, layer ORDER BY layer, scope",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(SbomResponse {
        release: release_bom(),
        packs,
    }))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/admin/sbom", get(get_sbom))
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_sbom), components(schemas(SbomResponse, InstalledPack)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_bom_is_cyclonedx_with_components() {
        let bom = release_bom();
        assert_eq!(bom["bomFormat"], "CycloneDX");
        let components = bom["components"].as_array().expect("components");
        assert!(
            components.iter().any(|c| c["name"] == "serde"),
            "registry packages are listed"
        );
        assert!(
            components.iter().all(|c| c["purl"]
                .as_str()
                .is_some_and(|p| p.starts_with("pkg:cargo/"))),
            "each has a cargo package URL"
        );
    }
}
