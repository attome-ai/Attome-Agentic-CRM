//! Documents another engine writes itself (roadmap F4-T13's invoice): the
//! engine builds the HTML, this module renders it to a PDF and attaches it
//! to a file field of the record, through the same pieces a template render
//! uses: the SSRF guard on the final HTML, the size cap, the render sidecar
//! and the attach path that copies the PDF under the field's own key and
//! writes the field through the generic update (so record access, field
//! rules and audit apply as for any edit).
//!
//! The renderer is a [`PdfRenderer`], so tests (and a deployment without
//! the sidecar) can supply their own; [`SidecarRenderer`] is the sidecar.

use std::future::Future;
use std::pin::Pin;

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use object_store::{ObjectStoreExt, path::Path as ObjectPath};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Turns HTML into PDF bytes.
pub trait PdfRenderer: Send + Sync {
    fn render<'a>(
        &'a self,
        config: &'a attome_config::DocgenSection,
        html: &'a str,
        page_size: &'a str,
        margin_mm: Option<f64>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>>;
}

/// The render sidecar (`config.docgen.render_service_url`).
#[derive(Debug, Default, Clone, Copy)]
pub struct SidecarRenderer;

impl PdfRenderer for SidecarRenderer {
    fn render<'a>(
        &'a self,
        config: &'a attome_config::DocgenSection,
        html: &'a str,
        page_size: &'a str,
        margin_mm: Option<f64>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, AppError>> + Send + 'a>> {
        Box::pin(crate::render_client::render_pdf(
            config, html, page_size, margin_mm,
        ))
    }
}

/// Renders `html` (a whole document) and attaches the PDF to `field` of the
/// record as `security`, named `{label}.pdf`.
#[allow(clippy::too_many_arguments)]
pub async fn render_to_field(
    state: &EngineState,
    security: &SecurityContext,
    renderer: &dyn PdfRenderer,
    entity: &str,
    record_id: Uuid,
    field: &str,
    label: &str,
    html: &str,
    page_size: &str,
) -> Result<(), AppError> {
    let config = &state.base.config.docgen;
    if html.len() > config.max_html_bytes {
        return Err(AppError::Validation(format!(
            "the document's HTML exceeds the {}-byte cap",
            config.max_html_bytes
        )));
    }
    crate::ssrf::guard(html)?;
    let bytes = renderer.render(config, html, page_size, None).await?;
    let checksum = hex::encode(Sha256::digest(&bytes));
    let size_bytes = i64::try_from(bytes.len()).unwrap_or(i64::MAX);
    // The rendered bytes land under a scratch key, are copied under the
    // field's own key by the attach, and the scratch copy is removed.
    let scratch = format!(
        "docgen-generated/{entity}/{record_id}/{}.pdf",
        Uuid::now_v7()
    );
    let path = ObjectPath::parse(&scratch)
        .map_err(|e| AppError::internal(format!("invalid generated document key: {e}")))?;
    state
        .base
        .storage
        .store()
        .put(&path, bytes.into())
        .await
        .map_err(|e| AppError::internal(format!("storing the generated document failed: {e}")))?;
    let attached = crate::render::try_attach_generated_file(
        state,
        security,
        entity,
        record_id,
        field,
        &scratch,
        &checksum,
        size_bytes,
        label,
        security.user_id,
    )
    .await;
    if let Err(e) = state.base.storage.store().delete(&path).await {
        tracing::warn!(key = %scratch, error = %e, "docgen: could not remove a generated document's scratch copy");
    }
    attached
}
