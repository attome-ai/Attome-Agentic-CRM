//! How many calls to one service may be in flight at once, kept apart for
//! interactive requests and background work, so a backlog of jobs cannot
//! take every slot a person's request needs.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Who a call is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallClass {
    /// A person is waiting on the answer.
    Interactive,
    /// A job, a sweep, a sync.
    Background,
}

/// One service's two pools of slots.
#[derive(Debug, Clone)]
pub struct Bulkheads {
    interactive: Arc<Semaphore>,
    background: Arc<Semaphore>,
}

impl Bulkheads {
    pub fn new(interactive: usize, background: usize) -> Self {
        Self {
            interactive: Arc::new(Semaphore::new(interactive.max(1))),
            background: Arc::new(Semaphore::new(background.max(1))),
        }
    }

    /// A slot for `class`, waiting at most `wait`; `None` when none freed.
    pub async fn acquire(&self, class: CallClass, wait: Duration) -> Option<OwnedSemaphorePermit> {
        let pool = match class {
            CallClass::Interactive => Arc::clone(&self.interactive),
            CallClass::Background => Arc::clone(&self.background),
        };
        tokio::time::timeout(wait, pool.acquire_owned())
            .await
            .ok()
            .and_then(Result::ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_full_pool_does_not_take_the_other_ones_slots() {
        let bulkheads = Bulkheads::new(1, 1);
        let held = bulkheads
            .acquire(CallClass::Background, Duration::from_millis(10))
            .await
            .unwrap();
        assert!(
            bulkheads
                .acquire(CallClass::Background, Duration::from_millis(10))
                .await
                .is_none(),
            "background is full"
        );
        assert!(
            bulkheads
                .acquire(CallClass::Interactive, Duration::from_millis(10))
                .await
                .is_some(),
            "interactive keeps its own slot"
        );
        drop(held);
    }
}
