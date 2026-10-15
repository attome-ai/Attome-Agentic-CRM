//! The id of the HTTP request the current task serves (roadmap U4-T5), so
//! work it starts (a queued job) can name it. `attome-server`'s request-meta
//! layer sets it; it lives here, the lowest crate, so `attome-jobs` (below
//! `attome-server`) can read it. Outside a request (a job, boot code, a test)
//! there is none.

use std::future::Future;

tokio::task_local! {
    static REQUEST_ID: String;
}

/// The current request's id, if this task serves one.
pub fn current() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// Runs `fut` as part of the request `id`.
pub async fn scope<F: Future>(id: String, fut: F) -> F::Output {
    REQUEST_ID.scope(id, fut).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_id_is_seen_inside_its_scope_only() {
        assert_eq!(current(), None);
        let seen = scope("req-1".to_owned(), async { current() }).await;
        assert_eq!(seen.as_deref(), Some("req-1"));
        assert_eq!(current(), None);
    }
}
