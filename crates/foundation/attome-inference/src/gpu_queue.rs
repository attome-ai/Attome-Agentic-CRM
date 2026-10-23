//! Z9-T6: a concurrency queue per self-hosted model. A model on the
//! deployment's own hardware serves a few calls at once
//! (`inference.catalogue[].max_concurrent`, default 4); more would only slow
//! every call down, so the rest wait their turn here.
//!
//! - A chat call (someone is waiting for it) waits at most [`CHAT_WAIT`],
//!   then fails with [`QueueError::Busy`], a retryable error.
//! - A batch call waits as long as it takes, and batch calls together never
//!   hold the last slot, so a chat call always has one to wait for.
//!
//! The queues are per process: each node holds its own model slots, which is
//! what a model server on that node can take. Nothing about them outlives
//! the process.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Calls a self-hosted model serves at once when the catalogue says nothing.
pub const DEFAULT_SLOTS: usize = 4;

/// The longest a chat call waits for a slot.
pub const CHAT_WAIT: Duration = Duration::from_secs(10);

/// Who is waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    /// A person is waiting for the answer.
    Chat,
    /// A background job.
    Batch,
}

/// Why a call got no slot.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum QueueError {
    #[error("model {model} is busy; try again shortly")]
    Busy { model: String },
}

impl attome_outbound::Retryable for QueueError {
    fn retryable(&self) -> bool {
        true
    }
}

/// One model's slots.
#[derive(Debug)]
pub struct ModelQueue {
    model: String,
    slots: Arc<Semaphore>,
    /// Batch calls take one of these first: one fewer than the slots.
    batch: Arc<Semaphore>,
    chat_wait: Duration,
}

/// A held slot; dropping it frees the slot.
#[derive(Debug)]
pub struct Turn {
    _slot: OwnedSemaphorePermit,
    _batch: Option<OwnedSemaphorePermit>,
}

impl ModelQueue {
    pub fn new(model: &str, slots: usize) -> Self {
        Self::with_wait(model, slots, CHAT_WAIT)
    }

    fn with_wait(model: &str, slots: usize, chat_wait: Duration) -> Self {
        let slots = slots.max(1);
        Self {
            model: model.to_owned(),
            slots: Arc::new(Semaphore::new(slots)),
            batch: Arc::new(Semaphore::new(slots.saturating_sub(1).max(1))),
            chat_wait,
        }
    }

    /// Waits for a slot at `priority`.
    pub async fn acquire(&self, priority: Priority) -> Result<Turn, QueueError> {
        let busy = || QueueError::Busy {
            model: self.model.clone(),
        };
        match priority {
            Priority::Chat => {
                let slot = tokio::time::timeout(self.chat_wait, self.slots.clone().acquire_owned())
                    .await
                    .map_err(|_| busy())?
                    .map_err(|_| busy())?;
                Ok(Turn {
                    _slot: slot,
                    _batch: None,
                })
            }
            Priority::Batch => {
                let batch = self
                    .batch
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| busy())?;
                let slot = self
                    .slots
                    .clone()
                    .acquire_owned()
                    .await
                    .map_err(|_| busy())?;
                Ok(Turn {
                    _slot: slot,
                    _batch: Some(batch),
                })
            }
        }
    }

    /// Slots free now.
    pub fn available(&self) -> usize {
        self.slots.available_permits()
    }
}

/// Every self-hosted model's queue, by model id.
#[derive(Debug, Default)]
pub struct GpuQueues {
    queues: Mutex<HashMap<String, Arc<ModelQueue>>>,
}

impl GpuQueues {
    /// `model`'s queue, made with `slots` the first time it is asked for.
    pub fn get(&self, model: &str, slots: usize) -> Arc<ModelQueue> {
        let mut queues = self
            .queues
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        queues
            .entry(model.to_owned())
            .or_insert_with(|| Arc::new(ModelQueue::new(model, slots)))
            .clone()
    }
}

/// The process's queues.
pub fn queues() -> &'static GpuQueues {
    static QUEUES: LazyLock<GpuQueues> = LazyLock::new(GpuQueues::default);
    &QUEUES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn gpu_queue_fifth_concurrent_call_waits() {
        let queue = Arc::new(ModelQueue::new("local", 4));
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(queue.acquire(Priority::Chat).await.expect("a free slot"));
        }
        assert_eq!(queue.available(), 0);

        let waiting = tokio::spawn({
            let queue = queue.clone();
            async move { queue.acquire(Priority::Chat).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!waiting.is_finished(), "the fifth call waits for a slot");

        held.pop();
        waiting.await.unwrap().expect("it gets the freed slot");
    }

    #[tokio::test]
    async fn gpu_queue_chat_gives_up_with_a_retryable_error() {
        let queue = ModelQueue::with_wait("local", 1, Duration::from_millis(20));
        let _held = queue.acquire(Priority::Chat).await.unwrap();
        let err = queue.acquire(Priority::Chat).await.unwrap_err();
        assert_eq!(
            err,
            QueueError::Busy {
                model: "local".into()
            }
        );
        assert!(attome_outbound::Retryable::retryable(&err));
    }

    #[tokio::test]
    async fn gpu_queue_batch_leaves_a_slot_for_chat() {
        let queue = Arc::new(ModelQueue::new("local", 3));
        let a = queue.acquire(Priority::Batch).await.unwrap();
        let b = queue.acquire(Priority::Batch).await.unwrap();
        let third_batch = tokio::spawn({
            let queue = queue.clone();
            async move { queue.acquire(Priority::Batch).await.map(|_| ()) }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !third_batch.is_finished(),
            "batch never takes the last slot"
        );
        let chat = queue.acquire(Priority::Chat).await;
        assert!(chat.is_ok(), "the last slot is chat's");
        drop((a, b, chat));
        third_batch.await.unwrap().unwrap();
    }

    #[test]
    fn gpu_queue_is_one_per_model() {
        let queues = GpuQueues::default();
        assert!(Arc::ptr_eq(&queues.get("a", 4), &queues.get("a", 9)));
        assert!(!Arc::ptr_eq(&queues.get("a", 4), &queues.get("b", 4)));
        assert_eq!(queues.get("c", 0).available(), 1, "at least one slot");
    }
}
