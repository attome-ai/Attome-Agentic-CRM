//! The doorbell listener: one dedicated connection to the pub/sub of whichever
//! [`Store`] the deployment runs on.
//!
//! Metadata, security, audit-user, feature-flag, state-model, relationship and
//! rule invalidations are published as "doorbells" and every node reloads on
//! receipt. On Redis that is a dedicated subscriber connection (never the
//! request-path pool, so a slow subscriber cannot head-of-line-block ordinary
//! traffic). On the in-process store it is the store's own broadcast channels,
//! so a Solo process hears its own doorbells exactly as a cluster node would.

use std::sync::{Arc, Mutex, PoisonError};

use attome_config::AppConfig;
use attome_types::AppError;
use fred::interfaces::{EventInterface, PubsubInterface};

use crate::memory::MemoryStore;
use crate::redis_pool::create_subscriber_client;
use crate::store::Store;
use fred::clients::SubscriberClient;

/// One doorbell: the channel it rang on and its text payload, if any.
#[derive(Debug, Clone)]
pub struct Doorbell {
    pub channel: String,
    pub payload: Option<String>,
}

type Handler = Arc<dyn Fn(&Doorbell) + Send + Sync>;

/// A subscriber on either backend. Register handlers with
/// [`on_message`](Self::on_message), then [`subscribe`](Self::subscribe) to
/// each channel.
pub enum Subscriber {
    Redis(SubscriberClient),
    Memory(MemorySubscriber),
}

impl std::fmt::Debug for Subscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Subscriber::Redis(_) => "Subscriber::Redis",
            Subscriber::Memory(_) => "Subscriber::Memory",
        })
    }
}

/// The in-process subscriber's state.
pub struct MemorySubscriber {
    store: Arc<MemoryStore>,
    handlers: Arc<Mutex<Vec<Handler>>>,
}

impl std::fmt::Debug for MemorySubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemorySubscriber")
    }
}

impl Subscriber {
    /// Connects a subscriber on the same backend as `store`.
    pub async fn connect(store: &Store, config: &AppConfig) -> Result<Self, AppError> {
        match store {
            Store::Redis(_) => {
                let client = create_subscriber_client(config)
                    .await
                    .map_err(AppError::internal)?;
                client.manage_subscriptions();
                Ok(Subscriber::Redis(client))
            }
            Store::Memory(memory) => Ok(Subscriber::Memory(MemorySubscriber {
                store: Arc::clone(memory),
                handlers: Arc::new(Mutex::new(Vec::new())),
            })),
        }
    }

    /// Calls `handler` for every doorbell on any subscribed channel. A
    /// handler filters on `channel` itself and must not block.
    pub fn on_message(&self, handler: impl Fn(&Doorbell) + Send + Sync + 'static) {
        match self {
            Subscriber::Redis(client) => {
                client.on_message(move |msg| {
                    handler(&Doorbell {
                        channel: msg.channel.to_string(),
                        payload: msg.value.as_str().map(|s| s.to_string()),
                    });
                    Ok(())
                });
            }
            Subscriber::Memory(memory) => {
                memory
                    .handlers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(Arc::new(handler));
            }
        }
    }

    /// Calls `handler` after the connection to the server is re-established,
    /// when a doorbell may have been missed. The in-process store never
    /// disconnects, so this never fires there.
    pub fn on_reconnect(&self, handler: impl Fn() + Send + Sync + 'static) {
        if let Subscriber::Redis(client) = self {
            client.on_reconnect(move |_server| {
                handler();
                Ok(())
            });
        }
    }

    /// Subscribes to `channel`.
    pub async fn subscribe(&self, channel: &str) -> Result<(), AppError> {
        match self {
            Subscriber::Redis(client) => {
                client.subscribe(channel).await.map_err(AppError::internal)
            }
            Subscriber::Memory(memory) => {
                let mut rx = memory.store.subscribe(channel);
                let handlers = Arc::clone(&memory.handlers);
                let channel = channel.to_owned();
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(payload) => {
                                let bell = Doorbell {
                                    channel: channel.clone(),
                                    payload: Some(payload),
                                };
                                let snapshot: Vec<Handler> = handlers
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .clone();
                                for handler in snapshot {
                                    handler(&bell);
                                }
                            }
                            // A lagging subscriber missed doorbells: ring every
                            // handler once so each reloads from its source of
                            // truth, as it would after a Redis reconnect.
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                let bell = Doorbell {
                                    channel: channel.clone(),
                                    payload: None,
                                };
                                let snapshot: Vec<Handler> = handlers
                                    .lock()
                                    .unwrap_or_else(PoisonError::into_inner)
                                    .clone();
                                for handler in snapshot {
                                    handler(&bell);
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                });
                Ok(())
            }
        }
    }
}
