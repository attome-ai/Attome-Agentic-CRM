//! Token deltas — `message.delta` (C11 B3, P-3, rows A-78…A-81).
//!
//! **Transport, never state (I-14).** A delta is the text a model is producing
//! right now, relayed so a person can watch an answer form. It is never
//! persisted, never replayed and never given a stream cursor: the ledger's
//! `message.completed` is the answer, and it supersedes every delta for its
//! turn. That is what lets this module be lossy by design.
//!
//! ## Across nodes
//!
//! The node running a turn is not necessarily the node holding the client's
//! `/stream` connection, and `/stream` keeps no in-process state that
//! correctness depends on. So deltas travel on Redis pub/sub, on
//! [`channel`]`(conversation_id)`:
//!
//! - **Publishing** ([`Publisher`]) runs beside the model call. The model
//!   client's delta callback is synchronous, so it only queues text; a small
//!   task coalesces what arrives within [`COALESCE`] into one publish, each
//!   bounded by [`PUBLISH_TIMEOUT`]. The turn waits for that task
//!   ([`Publisher::finish`]) before it writes `message.completed`, so no delta
//!   for a turn is published after its answer is committed.
//! - **Receiving** ([`subscribe`]) is one pattern subscription per process,
//!   fanned out in memory to every open `/stream`. That in-process state is
//!   observational and rebuilt on demand (coding-guidelines §5): losing it
//!   loses deltas, never an answer.
//!
//! ## Failure
//!
//! Redis unavailable means no deltas — the turn runs exactly as it would have,
//! and the client still receives `message.completed`. This is a transport
//! degrading, not a security control failing open: a delta authorizes
//! nothing, carries no tool call and can be acted on by nobody (A-79, A-81).
//!
//! ## What is never a delta
//!
//! Tool names and arguments: `attome_inference::GenerationClient::
//! generate_stream` passes only text to its callback, and a proposal exists
//! for a client only once it is persisted (I-13). And nothing on the public
//! widget streams at all — its reply is decided after the turn (A-80).

use std::sync::Mutex;
use std::time::{Duration, Instant};

use attome_cache::Store;
use fred::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use uuid::Uuid;

/// The pub/sub channel a conversation's deltas travel on.
pub fn channel(conversation_id: Uuid) -> String {
    format!("{CHANNEL_PREFIX}{conversation_id}")
}

/// Every delta channel starts with this; the receiving side subscribes to the
/// pattern `attome-ai:delta:*`.
pub const CHANNEL_PREFIX: &str = "attome-ai:delta:";

/// Text arriving within this window is published as one message.
pub const COALESCE: Duration = Duration::from_millis(40);

/// One publish may take this long before the publisher gives up on Redis for
/// the rest of the turn. Deliberately below `attome_cache::timeouts::REQUEST_PATH`
/// (300 ms): a publish sits inside a streaming answer, so a slow Redis must cost
/// less than a request-path call would.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_millis(250);

/// How long [`Publisher::finish`] waits for queued text to go out.
const FINISH_TIMEOUT: Duration = Duration::from_secs(2);

/// One published delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    pub conversation_id: Uuid,
    pub turn_id: Uuid,
    pub text: String,
}

/// The most deltas queued for publishing at once; past it a delta is
/// dropped (Y13-T3: every in-process queue is bounded). A turn's coalescing
/// task drains it every [`COALESCE`].
const DELTA_QUEUE: usize = 4096;

/// Publishes one turn's text deltas.
pub struct Publisher {
    tx: mpsc::Sender<String>,
    task: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher").finish_non_exhaustive()
    }
}

impl Publisher {
    /// Starts the publishing task for one turn.
    ///
    /// A bare `tokio::spawn` is sanctioned here (coding-guidelines §10): the
    /// work is disposable and its loss harmless, and the task ends when the
    /// turn drops its sender.
    pub fn start(redis: Store, conversation_id: Uuid, turn_id: Uuid) -> Self {
        let (tx, rx) = mpsc::channel(DELTA_QUEUE);
        let task = tokio::spawn(run(redis, conversation_id, turn_id, rx));
        Self { tx, task }
    }

    /// The callback handed to the model client. Queues text; never blocks.
    pub fn sink(&self) -> impl FnMut(&str) + Send + use<> {
        let tx = self.tx.clone();
        move |text: &str| {
            // A closed receiver means the publisher gave up, and a full queue
            // drops this delta (deltas are lossy, Y13-T3); the turn goes on.
            let _ = tx.try_send(text.to_owned());
        }
    }

    /// Waits for queued text to be published, bounded by [`FINISH_TIMEOUT`].
    pub async fn finish(self) {
        drop(self.tx);
        if tokio::time::timeout(FINISH_TIMEOUT, self.task)
            .await
            .is_err()
        {
            tracing::debug!("delta publisher did not drain in time; the answer is unaffected");
        }
    }
}

async fn run(redis: Store, conversation_id: Uuid, turn_id: Uuid, mut rx: mpsc::Receiver<String>) {
    let channel = channel(conversation_id);
    let mut broken = false;
    while let Some(first) = rx.recv().await {
        let mut text = first;
        // Coalesce whatever else arrives in the window into one publish.
        let window = tokio::time::sleep(COALESCE);
        tokio::pin!(window);
        loop {
            tokio::select! {
                biased;
                more = rx.recv() => match more {
                    Some(more) => text.push_str(&more),
                    None => break,
                },
                _ = &mut window => break,
            }
        }
        if broken {
            continue; // drain without publishing
        }
        let payload = match serde_json::to_string(&Delta {
            conversation_id,
            turn_id,
            text,
        }) {
            Ok(payload) => payload,
            Err(_) => continue,
        };
        match tokio::time::timeout(PUBLISH_TIMEOUT, redis.publish(channel.as_str(), &payload)).await
        {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => {
                crate::turn_metrics::delta_publish_failed(crate::turn_metrics::DELTA_PUBLISH_ERROR);
                tracing::debug!(%error, "delta publish failed; no more deltas this turn");
                broken = true;
            }
            Err(_) => {
                crate::turn_metrics::delta_publish_failed(
                    crate::turn_metrics::DELTA_PUBLISH_TIMEOUT,
                );
                tracing::debug!("delta publish timed out; no more deltas this turn");
                broken = true;
            }
        }
    }
}

/// The process-wide fan-out: a sender every `/stream` subscribes to, and a
/// token its forwarding task holds for as long as it runs.
struct Hub {
    tx: broadcast::Sender<Delta>,
    /// Dead once the forwarding task has ended — its connection dropped for
    /// good, or the runtime that spawned it shut down. A dead hub is rebuilt
    /// rather than handed out: a sender whose forwarder is gone delivers
    /// nothing, silently.
    alive: std::sync::Weak<()>,
}

static HUB: tokio::sync::Mutex<Option<Hub>> = tokio::sync::Mutex::const_new(None);

/// When the last attempt to connect the fan-out failed. A `/stream` opened
/// while Redis is down should not wait on a doomed connection every time.
static LAST_FAILURE: Mutex<Option<Instant>> = Mutex::new(None);

const RETRY_AFTER: Duration = Duration::from_secs(30);
/// One connection attempt: the shared `attome_cache::timeouts::CONNECT` class.
const CONNECT_TIMEOUT: Duration = attome_cache::timeouts::CONNECT;
/// Deltas buffered per receiver before a slow `/stream` starts skipping them.
const FAN_OUT_CAPACITY: usize = 1024;

/// Starts connecting the fan-out in the background and returns at once.
///
/// Called when a conversation starts, so the subscription is in place before
/// its first answer streams. Without it the first `/stream` a process serves
/// builds the subscription itself, and a fast answer can be published before
/// anyone is listening — lost, as a delta may be, but needlessly.
pub fn warm(store: attome_cache::Store, config: std::sync::Arc<attome_config::AppConfig>) {
    // Disposable work whose loss is harmless (coding-guidelines §10).
    tokio::spawn(async move {
        let _ = subscribe(&store, &config).await;
    });
}

/// A receiver of every delta this process sees, or `None` when Redis cannot
/// be reached — in which case the caller streams durable events only.
pub async fn subscribe(
    store: &attome_cache::Store,
    config: &attome_config::AppConfig,
) -> Option<broadcast::Receiver<Delta>> {
    let mut hub = HUB.lock().await;
    if let Some(live) = hub.as_ref().filter(|h| h.alive.strong_count() > 0) {
        return Some(live.tx.subscribe());
    }
    if LAST_FAILURE
        .lock()
        .ok()
        .and_then(|at| *at)
        .is_some_and(|at| at.elapsed() < RETRY_AFTER)
    {
        return None;
    }
    match connect(store, config).await {
        Ok(built) => {
            let receiver = built.tx.subscribe();
            *hub = Some(built);
            Some(receiver)
        }
        Err(reason) => {
            tracing::warn!(
                reason,
                "delta fan-out unavailable; streaming durable events only (retried after 30 s)"
            );
            if let Ok(mut at) = LAST_FAILURE.lock() {
                *at = Some(Instant::now());
            }
            None
        }
    }
}

/// The in-process fan-out: the store's own broadcast of every publish,
/// filtered to this feature's channel family.
fn connect_memory(memory: &std::sync::Arc<attome_cache::memory::MemoryStore>) -> Hub {
    let (tx, _) = broadcast::channel(FAN_OUT_CAPACITY);
    let fan_out = tx.clone();
    let mut messages = memory.subscribe_all();
    let token = std::sync::Arc::new(());
    let alive = std::sync::Arc::downgrade(&token);
    // Supervision of one in-process listener for the life of its runtime (§10).
    tokio::spawn(async move {
        let _token = token;
        loop {
            match messages.recv().await {
                Ok((channel, raw)) => {
                    if channel.starts_with(CHANNEL_PREFIX)
                        && let Ok(delta) = serde_json::from_str::<Delta>(&raw)
                    {
                        let _ = fan_out.send(delta);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });
    Hub { tx, alive }
}

async fn connect(
    store: &attome_cache::Store,
    config: &attome_config::AppConfig,
) -> Result<Hub, &'static str> {
    if let attome_cache::Store::Memory(memory) = store {
        return Ok(connect_memory(memory));
    }
    let client = tokio::time::timeout(
        CONNECT_TIMEOUT,
        attome_cache::create_subscriber_client(config),
    )
    .await
    .map_err(|_| "timed out")?
    .map_err(|_| "connect failed")?;
    tokio::time::timeout(
        CONNECT_TIMEOUT,
        client.psubscribe(format!("{CHANNEL_PREFIX}*")),
    )
    .await
    .map_err(|_| "timed out")?
    .map_err(|_| "subscribe failed")?;
    // Re-subscribes the pattern after a reconnect.
    let _resubscribe = client.manage_subscriptions();
    let (tx, _) = broadcast::channel(FAN_OUT_CAPACITY);
    let fan_out = tx.clone();
    let mut messages = client.message_rx();
    // The subscriber client has no reconnect policy, so a connection error is
    // final for it — and its message channel does not close, because this
    // task holds the client. Watching errors is what ends a dead hub instead
    // of leaving it "alive" and silent until the process restarts.
    let mut errors = client.error_rx();
    let token = std::sync::Arc::new(());
    let alive = std::sync::Arc::downgrade(&token);
    // Supervision of one connection for the life of its runtime (§10).
    tokio::spawn(async move {
        let _token = token;
        let _client = client;
        loop {
            tokio::select! {
                message = messages.recv() => match message {
                    Ok(message) => {
                        let Some(raw) = message.value.as_str() else {
                            continue;
                        };
                        if let Ok(delta) = serde_json::from_str::<Delta>(&raw) {
                            let _ = fan_out.send(delta);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
                error = errors.recv() => match error {
                    Ok(error) => {
                        tracing::warn!(
                            %error,
                            "delta fan-out lost its Redis connection; the next /stream reconnects it"
                        );
                        break;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                },
            }
        }
    });
    Ok(Hub { tx, alive })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_conversation_has_its_own_channel_under_the_pattern() {
        let id = Uuid::now_v7();
        assert_eq!(channel(id), format!("attome-ai:delta:{id}"));
        assert!(channel(id).starts_with(CHANNEL_PREFIX));
    }

    #[test]
    fn a_delta_round_trips() {
        let delta = Delta {
            conversation_id: Uuid::now_v7(),
            turn_id: Uuid::now_v7(),
            text: "مرحبا".into(),
        };
        let wire = serde_json::to_string(&delta).unwrap();
        assert_eq!(serde_json::from_str::<Delta>(&wire).unwrap(), delta);
    }
}
