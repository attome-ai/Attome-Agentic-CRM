//! Y4-T3: what the app's job runner does with the web crawler
//! (`attome-webcrawl`), so a build without the `webcrawl` feature compiles it
//! out. Without it a crawl job queued by an earlier build drains quietly and
//! the hourly recrawl queues nothing.

use attome_core::EngineState;
use attome_types::AppError;
use uuid::Uuid;

/// Crawls target `target_id` (K6).
pub async fn crawl(state: &EngineState, target_id: Uuid) -> Result<(), AppError> {
    #[cfg(feature = "webcrawl")]
    attome_webcrawl::crawl::run(state, target_id).await?;
    #[cfg(not(feature = "webcrawl"))]
    let _ = (state, target_id);
    Ok(())
}

/// Fetches one linked document into the file pipeline (K6-T6).
pub async fn fetch_document(state: &EngineState, page_id: Uuid) -> Result<(), AppError> {
    #[cfg(feature = "webcrawl")]
    attome_webcrawl::documents::fetch_document(state, page_id).await?;
    #[cfg(not(feature = "webcrawl"))]
    let _ = (state, page_id);
    Ok(())
}

/// Queues the recrawls that are due (K6-T3); how many.
pub async fn recrawl_due(state: &EngineState) -> Result<u64, AppError> {
    #[cfg(feature = "webcrawl")]
    let queued = attome_webcrawl::schedule::enqueue_due(state, chrono::Utc::now()).await?;
    #[cfg(not(feature = "webcrawl"))]
    let queued = {
        let _ = state;
        0
    };
    Ok(queued)
}
