//! A28-T3: a task-local switch that lets an import create records with
//! empty fields left empty, instead of filled with their attributes'
//! defaults. The create path reads [`defaults_skipped`].

tokio::task_local! {
    static SKIP_DEFAULTS: bool;
}

/// Runs `fut` with attribute defaults applied on create (`apply` true, the
/// normal case) or left out (an import that asked for its cells as given).
pub async fn with_defaults<F: std::future::Future>(apply: bool, fut: F) -> F::Output {
    if apply {
        fut.await
    } else {
        SKIP_DEFAULTS.scope(true, fut).await
    }
}

/// True inside [`with_defaults`]`(false, ..)`.
pub fn defaults_skipped() -> bool {
    SKIP_DEFAULTS.try_with(|skip| *skip).unwrap_or(false)
}
