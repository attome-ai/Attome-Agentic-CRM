//! The id of the HTTP request the current task serves (roadmap U4-T5), so
//! work it starts (a queued job) can name it. `attome-server`'s request-meta
//! layer sets it; it lives here, the lowest crate, so `attome-jobs` (below
//! `attome-server`) can read it. Outside a request (a job, boot code, a test)
//! there is none.

use std::future::Future;

tokio::task_local! {
    static REQUEST_ID: String;
    static OVERRIDE_REASON: Option<String>;
}

/// The longest override reason kept (A3-T4); the rest is cut.
pub const MAX_OVERRIDE_REASON_CHARS: usize = 500;

/// The current request's id, if this task serves one.
pub fn current() -> Option<String> {
    REQUEST_ID.try_with(Clone::clone).ok()
}

/// Runs `fut` as part of the request `id`.
pub async fn scope<F: Future>(id: String, fut: F) -> F::Output {
    REQUEST_ID.scope(id, fut).await
}

/// A3-T4: why the caller asks to save a record a check refuses (the
/// `X-Override-Reason` header), if it gave one. Whether the caller may
/// override is decided where the check runs.
pub fn override_reason() -> Option<String> {
    OVERRIDE_REASON.try_with(Clone::clone).ok().flatten()
}

/// Runs `fut` with the request's override reason, trimmed and cut to
/// [`MAX_OVERRIDE_REASON_CHARS`]; a blank one counts as none.
pub async fn with_override_reason<F: Future>(reason: Option<&str>, fut: F) -> F::Output {
    let reason = reason
        .map(str::trim)
        .filter(|r| !r.is_empty())
        .map(|r| r.chars().take(MAX_OVERRIDE_REASON_CHARS).collect());
    OVERRIDE_REASON.scope(reason, fut).await
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

    #[tokio::test]
    async fn an_override_reason_is_trimmed_and_a_blank_one_is_none() {
        assert_eq!(override_reason(), None);
        let seen =
            with_override_reason(Some("  late invoice  "), async { override_reason() }).await;
        assert_eq!(seen.as_deref(), Some("late invoice"));
        let blank = with_override_reason(Some("   "), async { override_reason() }).await;
        assert_eq!(blank, None);
        let long = "x".repeat(MAX_OVERRIDE_REASON_CHARS + 5);
        let cut = with_override_reason(Some(&long), async { override_reason() }).await;
        assert_eq!(
            cut.map(|r| r.chars().count()),
            Some(MAX_OVERRIDE_REASON_CHARS)
        );
    }
}
