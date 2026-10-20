//! `EngineModel` registration for Document Management (M55, D-486).
//!
//! **This model gates the document-management surface only, never the generic
//! file-field path.** See the crate doc for why: `files::routes()` serves
//! `file`-typed attributes on any entity and is core, so `attome-api` keeps
//! mounting it in `core_routes()`. What is gated here is
//! `/api/v1/documents/tree`, `/api/v1/documents/folders`, and — through
//! [`owned_entities`](EngineModel::owned_entities) — the `attome_document` entity's
//! records on the generic CRUD path.

use attome_core::model::RecordValidator;
use attome_core::{EngineModel, EngineState, EntityMetaRegistry};
use attome_modules::{MODULE_DOCUMENT, ModuleId};
use axum::Router;
use serde_json::{Map, Value};

/// `attome_document.record_id` names the record a document belongs to: a
/// UUID, or nothing. Anything else is refused at write (422), because the
/// record-level read check compares it as a UUID and would otherwise fail
/// every read of the row (AC5-T8 found the gap).
pub fn validate_document_record(
    obj: &Map<String, Value>,
    _registry: &EntityMetaRegistry,
) -> Result<(), String> {
    match obj.get("record_id") {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(id)) if uuid::Uuid::parse_str(id.trim()).is_ok() => Ok(()),
        Some(_) => {
            Err("record_id must be the id (a UUID) of the record the document belongs to".into())
        }
    }
}

#[derive(Debug)]
pub struct DocumentModel;

impl EngineModel for DocumentModel {
    fn name(&self) -> &'static str {
        "attome-document"
    }

    fn module_id(&self) -> ModuleId {
        MODULE_DOCUMENT
    }

    fn routes(&self) -> Router<EngineState> {
        crate::documents_tree::routes().merge(crate::esign::routes())
    }

    /// `attome_document` is provisioned by `platform-bundles/attome-document.json`,
    /// applied at boot by `attome-api`'s `system.rs` (D-478). Declaring it
    /// here is what makes `/api/v1/attome_document` apply the same
    /// `MODULE_DOCUMENT` check `routes()` gets from `ModelRegistry` — without
    /// it the bespoke routes would 404 unlicensed while the raw records stayed
    /// readable and writable through the generic path on any licence holding
    /// `MODULE_CORE` (D-383, the SEC-5 shape).
    ///
    /// `document_folder` (migration `0124`) and
    /// `upload_session` (`0058`) are migration-owned infrastructure
    /// tables, not provisioned entities, so they are not listed and cannot be.
    fn owned_entities(&self) -> &'static [&'static str] {
        &["attome_document"]
    }

    fn record_validators(&self) -> &'static [(&'static str, RecordValidator)] {
        &[("attome_document", validate_document_record)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// D-486 found `MODULE_DOCUMENT` allocated and gating nothing — the only
    /// references in the workspace were its own definition and the
    /// `MODULE_MAP` row. This pins that the model claims that bit and not a
    /// sibling's: a copy-paste from another engine would silently put document
    /// management behind, say, the content or report licence.
    #[test]
    fn the_model_claims_the_document_module_bit() {
        let model = DocumentModel;
        assert_eq!(
            (model.module_id().word, model.module_id().mask),
            (MODULE_DOCUMENT.word, MODULE_DOCUMENT.mask)
        );
        assert_eq!(model.name(), "attome-document");
    }

    /// The D-383 half. `attome_document` is a provisioned entity, so leaving
    /// `owned_entities()` at the default `&[]` would gate the routes and leave
    /// the records open — which is exactly the hole this extraction closes.
    #[test]
    fn a_document_names_its_record_by_uuid() {
        let registry = EntityMetaRegistry::default();
        let body = |v: Value| v.as_object().cloned().unwrap_or_default();
        let id = uuid::Uuid::now_v7().to_string();
        assert!(
            validate_document_record(&body(serde_json::json!({ "record_id": id })), &registry)
                .is_ok()
        );
        assert!(
            validate_document_record(&body(serde_json::json!({ "record_id": null })), &registry)
                .is_ok()
        );
        assert!(
            validate_document_record(&body(serde_json::json!({ "name": "x" })), &registry).is_ok()
        );
        assert!(
            validate_document_record(
                &body(serde_json::json!({ "record_id": "not-a-uuid" })),
                &registry
            )
            .is_err()
        );
        assert!(
            validate_document_record(&body(serde_json::json!({ "record_id": 7 })), &registry)
                .is_err()
        );
    }

    #[test]
    fn the_provisioned_entity_is_declared() {
        assert_eq!(DocumentModel.owned_entities(), &["attome_document"]);
    }

    /// **The regression guard for the licence split.** `files::routes()` must
    /// never be reachable through this model: it serves `file`-typed
    /// attributes on every entity, and gating it on a paid bit would break
    /// file fields on a core-only licence. If someone later "tidies up" by
    /// merging it in here, this fails.
    #[test]
    fn the_generic_file_field_path_is_not_gated_by_this_model() {
        let router: Router<EngineState> = DocumentModel.routes();
        assert!(
            !format!("{router:?}").contains("files"),
            "files::routes() serves /api/v1/{{entity}}/{{id}}/files/{{field}} for any \
             entity and is core — it stays in attome-api's core_routes(), ungated. \
             See this crate's module doc and D-486."
        );
    }
}
