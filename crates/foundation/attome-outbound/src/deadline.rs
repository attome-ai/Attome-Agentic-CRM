//! A request's deadline, carried to every outside call it makes. The server
//! sets it once per request ([`with_deadline`]); a call reads what is left
//! ([`remaining`]) and never waits past it.

use std::future::Future;
use std::time::Duration;

use tokio::time::Instant;

tokio::task_local! {
    static DEADLINE: Instant;
}

/// Runs `fut` with `deadline` as its deadline. An enclosing, earlier
/// deadline still wins.
pub async fn with_deadline<F: Future>(deadline: Instant, fut: F) -> F::Output {
    scope(deadline, fut).await
}

/// [`with_deadline`] as a nameable future, for a tower service whose
/// `Future` type must be spelled out. The enclosing deadline is read when
/// this is called.
pub fn scope<F: Future>(
    deadline: Instant,
    fut: F,
) -> tokio::task::futures::TaskLocalFuture<Instant, F> {
    let deadline = DEADLINE
        .try_with(|outer| (*outer).min(deadline))
        .unwrap_or(deadline);
    DEADLINE.scope(deadline, fut)
}

/// The time left before the current deadline; `None` outside one.
pub fn remaining() -> Option<Duration> {
    DEADLINE
        .try_with(|deadline| deadline.saturating_duration_since(Instant::now()))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_earlier_deadline_wins() {
        assert_eq!(remaining(), None);
        let soon = Instant::now() + Duration::from_millis(100);
        let later = Instant::now() + Duration::from_secs(60);
        with_deadline(soon, async {
            with_deadline(later, async {
                let left = remaining().unwrap();
                assert!(left <= Duration::from_millis(100), "{left:?}");
            })
            .await;
        })
        .await;
    }
}
