//! `attome-document` — Document Management (M55), extracted from `attome-api` by
//! **D-486**.
//!
//! Three modules moved here byte-for-byte from `attome-api/src/`:
//!
//! * `files` — the upload-session state machine (`upload_session`,
//!   migration `0058`), quarantine → scan → promote, presigned PUT/GET
//!   brokering, and file versioning with restore. The browser talks to the
//!   object store directly; this crate hands out short-lived URLs and never
//!   proxies the byte stream.
//! * `files_scan` — the async ClamAV pass (D-144). **Fails closed**: an upload
//!   whose scan cannot complete stays in `scanning` and never promotes.
//! * `documents_tree` — the document folder tree (`document_folder`,
//!   migration `0124`) over the `attome_document` entity.
//!
//! ## The licence split, which is the one thing here that is not a pure move
//!
//! D-486 called `MODULE_DOCUMENT` (bit 10) a live gap: it was allocated and
//! gated **nothing**. Closing it needs care, because the two halves of this
//! crate are not the same product.
//!
//! * **`files::routes()` is core, not a module.** It serves
//!   `/api/v1/{entity}/{id}/files/{field}/…` — the generic upload path for a
//!   `file`-typed attribute on *any* entity, and
//!   `attome_records::entity_mutation`'s `lock_file_field_sessions` refuses
//!   a file-field write whose session is not a completed, owned, clean one.
//!   Gating it on a paid bit would make `file` fields stop working on a
//!   core-only licence — a regression dressed as a licence fix. It stays
//!   mounted in `attome-api`'s `core_routes()`, exactly where it was.
//! * **`documents_tree::routes()` and the `attome_document` entity are the
//!   module.** `/api/v1/documents/tree` and `/api/v1/documents/folders` are a
//!   document-management surface over a provisioned entity, and nothing else
//!   in the platform needs them to function. [`DocumentModel`] gates those,
//!   and declares `attome_document` in `owned_entities()` so generic entity CRUD
//!   applies the same check (D-383) rather than leaving the records readable
//!   through `/api/v1/attome_document` on any licence holding `MODULE_CORE`.
//!
//! That is a **behaviour change on an unlicensed deployment** and the only one
//! in this extraction: `/api/v1/documents/*` and `attome_document` records now
//! 404 without `MODULE_DOCUMENT`. Everything else — every route path, wire
//! shape, privilege check and migration — is unchanged.

pub mod checkout;
pub mod documents_tree;
pub mod engine;
pub mod esign;
pub mod files;
pub mod files_scan;
/// A23-T9: an import's row errors as a file to fix and send back.
pub mod import_error_file;
/// A23-T7: import phases as durable jobs, and recurring imports.
pub mod import_jobs;
/// A23-T2: CSV and XLSX import files read into rows of text cells.
pub mod import_reader;
/// A23-T8: the import routes.
pub mod import_routes;
/// A23-T3: staging an import file's rows into import_stage with COPY.
pub mod import_stage;
/// Z6-T3: the weekly read-back of a sample of stored files.
pub mod integrity;
/// Z6-T2: resumable multipart uploads.
pub mod multipart_routes;
pub mod share;
/// K1-T4: document text for global search.
pub mod text_extract;
/// Z6-T6: thumbnails of clean images, made in the background.
pub mod thumbnail;
/// N22-T2: recording transcripts.
pub mod transcribe;

pub use engine::DocumentModel;

/// This crate's slice of the workspace OpenAPI document.
///
/// Merged by `attome-api`'s `openapi.rs` rather than by
/// `server::openapi::document`: unlike `attome-search`/`attome-process`/`attome-docgen`,
/// `attome-api` has a real (non-dev) dependency on this crate — it mounts
/// `files::routes()` in `core_routes()` — so it can reach the fragment from
/// the engine layer and the list in `crates/server` stays shorter.
pub fn openapi() -> utoipa::openapi::OpenApi {
    // S2-T9: only the folder tree is the document model's (MODULE_DOCUMENT);
    // files, share links and checkout are mounted under core.
    let core = |fragment| attome_server::openapi::tag_module(fragment, "core");
    let mut doc = core(files::openapi_fragment());
    doc.merge(attome_server::openapi::tag_module(
        documents_tree::openapi_fragment(),
        "document",
    ));
    doc.merge(core(share::openapi_fragment()));
    doc.merge(core(checkout::openapi_fragment()));
    // K4-T1: e-signature envelopes, under the document module.
    doc.merge(attome_server::openapi::tag_module(
        esign::openapi_fragment(),
        "document",
    ));
    doc.merge(core(transcribe::openapi_fragment()));
    doc.merge(core(multipart_routes::openapi_fragment()));
    // A23-T8: file imports, under core like the generic record API.
    doc.merge(core(import_routes::openapi_fragment()));
    doc
}
