//! Z9-T4: falling back to the next allowed model. A call routed by
//! [`crate::router`] runs on the best candidate; when that model's breaker is
//! open, it is busy, it times out, or it fails in a way that says the model
//! is unwell (the error's [`Retryable::counts_as_failure`]), the call moves to
//! the next candidate, in the router's order. Candidates are only ever the
//! models the data rules let receive the content, so a fallback can never
//! send it anywhere the first choice could not have.
//!
//! A refusal of the request itself (a 4xx: bad input, too long) is the
//! caller's answer, not a reason to try another model; it returns at once.
//!
//! Each model has its own breaker (an `attome-outbound` service keyed by
//! model id, [`model_breakers`]), so a failing model is skipped without being
//! called until its breaker lets a probe through. The answer says which model
//! gave it and which were passed over, and why ([`Routed`]).
//!
//! A self-hosted model also takes its turn in its [`crate::gpu_queue`]: a
//! chat call that waits past the queue's limit passes that model over as
//! busy, as a full bulkhead does.

use std::future::Future;
use std::sync::LazyLock;

use attome_config::DataLabel;
use attome_outbound::{CallClass, EndpointServices, OutboundError, Policy, Retryable};
use serde::Serialize;

use crate::catalogue::{Catalogue, ModelEntry};
use crate::gpu_queue::{GpuQueues, Priority};
use crate::router::{RouteError, TaskNeeds, candidates};

/// The per-model breakers of routed calls, by model id.
pub fn model_breakers() -> &'static EndpointServices {
    static BREAKERS: LazyLock<EndpointServices> =
        LazyLock::new(|| EndpointServices::new("ai_route", Policy::default(), 256));
    &BREAKERS
}

/// Why a model was passed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason", content = "detail")]
pub enum SkipReason {
    /// Its breaker was open; it was not called.
    BreakerOpen,
    /// No slot freed in time.
    Busy,
    Timeout,
    /// It failed; the error's text.
    Failed(String),
}

/// One model a call passed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub model: String,
    #[serde(flatten)]
    pub reason: SkipReason,
}

/// An answer and where it came from: the response metadata of a routed call.
#[derive(Debug, Clone, PartialEq)]
pub struct Routed<T> {
    pub value: T,
    /// The model that answered.
    pub model: String,
    /// The models tried before it, in order; empty when the first answered.
    pub fell_back: Vec<Skipped>,
}

/// Why a routed call has no answer.
#[derive(Debug, thiserror::Error)]
pub enum FallbackError<E> {
    /// No model may take the task (the router's refusal).
    #[error(transparent)]
    Route(#[from] RouteError),
    /// The model refused the request itself; no other model was tried.
    #[error("model {model} refused the request: {error}")]
    Refused { model: String, error: E },
    /// Every allowed model was passed over.
    #[error("every model allowed for task {task:?} failed or is unavailable")]
    Exhausted { task: String, tried: Vec<Skipped> },
}

/// Where a routed call takes its turns: the per-model breakers (normally
/// [`model_breakers`]) and the self-hosted models' queues (normally
/// [`crate::gpu_queue::queues`]).
#[derive(Debug, Clone, Copy)]
pub struct Gates<'a> {
    pub breakers: &'a EndpointServices,
    pub queues: &'a GpuQueues,
}

impl Gates<'static> {
    /// The process's breakers and queues.
    pub fn shared() -> Self {
        Self {
            breakers: model_breakers(),
            queues: crate::gpu_queue::queues(),
        }
    }
}

/// Runs `call` on the best model for `needs` and `label`, then on each next
/// allowed candidate while the one before fails or is unavailable. Each
/// attempt waits its turn in a self-hosted model's queue at `priority`, then
/// goes through that model's breaker; `idempotent` lets the outbound layer
/// retry a model before moving on.
pub async fn call_with_fallback<T, E, F, Fut>(
    catalogue: &Catalogue,
    needs: &TaskNeeds<'_>,
    label: DataLabel,
    gates: Gates<'_>,
    priority: Priority,
    idempotent: bool,
    mut call: F,
) -> Result<Routed<T>, FallbackError<E>>
where
    E: Retryable + std::fmt::Display,
    F: FnMut(&ModelEntry) -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    let models = candidates(catalogue, needs, label)?;
    let mut fell_back = Vec::new();
    for model in models {
        let _turn = if model.self_hosted {
            match gates
                .queues
                .get(&model.id, model.max_concurrent)
                .acquire(priority)
                .await
            {
                Ok(permit) => Some(permit),
                Err(_) => {
                    tracing::warn!(task = needs.task, model = %model.id, "inference: model queue full");
                    fell_back.push(Skipped {
                        model: model.id.clone(),
                        reason: SkipReason::Busy,
                    });
                    continue;
                }
            }
        } else {
            None
        };
        let service = gates.breakers.get(&model.id);
        let reason =
            match attome_outbound::call(&service, CallClass::Interactive, idempotent, || {
                call(model)
            })
            .await
            {
                Ok(value) => {
                    if !fell_back.is_empty() {
                        tracing::warn!(
                            task = needs.task,
                            model = %model.id,
                            passed_over = fell_back.len(),
                            "inference: answered by a fallback model"
                        );
                    }
                    return Ok(Routed {
                        value,
                        model: model.id.clone(),
                        fell_back,
                    });
                }
                Err(OutboundError::Open { .. }) => SkipReason::BreakerOpen,
                Err(OutboundError::Busy) => SkipReason::Busy,
                Err(OutboundError::Timeout) => SkipReason::Timeout,
                Err(OutboundError::Failed(error)) if error.counts_as_failure() => {
                    SkipReason::Failed(error.to_string())
                }
                Err(OutboundError::Failed(error)) => {
                    return Err(FallbackError::Refused {
                        model: model.id.clone(),
                        error,
                    });
                }
            };
        tracing::warn!(task = needs.task, model = %model.id, ?reason, "inference: model passed over");
        fell_back.push(Skipped {
            model: model.id.clone(),
            reason,
        });
    }
    Err(FallbackError::Exhausted {
        task: needs.task.to_owned(),
        tried: fell_back,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use attome_config::ModelCapability;
    use attome_outbound::BreakerConfig;
    use attome_outbound::retry::RetryPolicy;

    use super::*;
    use crate::router::PreferredSize;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeError {
        Down,
        BadInput,
    }

    impl std::fmt::Display for FakeError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self {
                Self::Down => "the model server is down",
                Self::BadInput => "the prompt is too long",
            })
        }
    }

    impl Retryable for FakeError {
        fn retryable(&self) -> bool {
            *self == Self::Down
        }
    }

    use DataLabel::{Health, Internal, Personal};

    fn model(id: &str, cost: f64, labels: &[DataLabel]) -> ModelEntry {
        ModelEntry {
            id: id.to_owned(),
            adapter: "openai_compatible".to_owned(),
            capabilities: vec![ModelCapability::Chat],
            max_context: 32_000,
            cost_per_1k_tokens: cost,
            self_hosted: true,
            allowed_labels: labels.to_vec(),
            max_concurrent: 4,
        }
    }

    fn catalogue() -> Catalogue {
        Catalogue {
            models: vec![
                model("cheap", 0.0, &[Internal, Health]),
                model("no-health", 0.5, &[Internal, Personal]),
                model("backup", 1.0, &[Internal, Health]),
            ],
            allow_external_provider: false,
        }
    }

    const CHAT: TaskNeeds<'static> = TaskNeeds {
        task: "case.summarise",
        capabilities: &[ModelCapability::Chat],
        min_context: 1_000,
        preferred: PreferredSize::Small,
    };

    /// Breakers that open after two failures and retry nothing, so a test
    /// sees each model called once per attempt.
    fn breakers() -> EndpointServices {
        EndpointServices::new(
            "ai_route_test",
            Policy {
                timeout: Duration::from_secs(5),
                retry: RetryPolicy {
                    max_attempts: 1,
                    ..RetryPolicy::default()
                },
                breaker: BreakerConfig {
                    window: 4,
                    min_calls: 2,
                    failure_rate: 0.5,
                    open_for: Duration::from_secs(60),
                    probes: 1,
                },
                ..Policy::default()
            },
            16,
        )
    }

    fn gates<'a>(breakers: &'a EndpointServices, queues: &'a GpuQueues) -> Gates<'a> {
        Gates { breakers, queues }
    }

    #[tokio::test]
    async fn fallback_skips_a_failing_model_for_the_next_allowed_one() {
        let breakers = breakers();
        let queues = GpuQueues::default();
        let called = Mutex::new(Vec::new());
        let answer = call_with_fallback(
            &catalogue(),
            &CHAT,
            Health,
            gates(&breakers, &queues),
            Priority::Chat,
            false,
            |m| {
                called.lock().unwrap().push(m.id.clone());
                let id = m.id.clone();
                async move {
                    if id == "cheap" {
                        Err(FakeError::Down)
                    } else {
                        Ok(format!("summary by {id}"))
                    }
                }
            },
        )
        .await
        .expect("an answer");
        // `no-health` may not receive Health content: never called.
        assert_eq!(*called.lock().unwrap(), ["cheap", "backup"]);
        assert_eq!(answer.model, "backup");
        assert_eq!(answer.value, "summary by backup");
        assert_eq!(
            answer.fell_back,
            [Skipped {
                model: "cheap".into(),
                reason: SkipReason::Failed("the model server is down".into()),
            }]
        );
    }

    #[tokio::test]
    async fn fallback_passes_over_an_open_breaker_without_calling_it() {
        let breakers = breakers();
        let queues = GpuQueues::default();
        for _ in 0..2 {
            let _ = call_with_fallback(
                &catalogue(),
                &CHAT,
                Internal,
                gates(&breakers, &queues),
                Priority::Chat,
                false,
                |m| {
                    let id = m.id.clone();
                    async move {
                        if id == "cheap" {
                            Err(FakeError::Down)
                        } else {
                            Ok(())
                        }
                    }
                },
            )
            .await;
        }
        let called = Mutex::new(Vec::new());
        let answer = call_with_fallback(
            &catalogue(),
            &CHAT,
            Internal,
            gates(&breakers, &queues),
            Priority::Chat,
            false,
            |m| {
                called.lock().unwrap().push(m.id.clone());
                async { Ok::<_, FakeError>(()) }
            },
        )
        .await
        .unwrap();
        assert_eq!(
            *called.lock().unwrap(),
            ["no-health"],
            "cheap's breaker is open"
        );
        assert_eq!(answer.fell_back[0].reason, SkipReason::BreakerOpen);
    }

    #[tokio::test]
    async fn fallback_stops_at_a_refused_request_and_reports_exhaustion() {
        let breakers = breakers();
        let queues = GpuQueues::default();
        let refused = call_with_fallback(
            &catalogue(),
            &CHAT,
            Health,
            gates(&breakers, &queues),
            Priority::Chat,
            false,
            |_| async { Err::<(), _>(FakeError::BadInput) },
        )
        .await;
        assert!(matches!(
            refused,
            Err(FallbackError::Refused { ref model, error: FakeError::BadInput }) if model == "cheap"
        ));

        let exhausted = call_with_fallback(
            &catalogue(),
            &CHAT,
            Health,
            gates(&breakers, &queues),
            Priority::Chat,
            false,
            |_| async { Err::<(), _>(FakeError::Down) },
        )
        .await;
        let Err(FallbackError::Exhausted { tried, .. }) = exhausted else {
            panic!("every allowed model failed");
        };
        let tried: Vec<&str> = tried.iter().map(|s| s.model.as_str()).collect();
        assert_eq!(tried, ["cheap", "backup"], "only Health-allowed models");

        let none = call_with_fallback(
            &Catalogue {
                models: vec![model("no-health", 0.0, &[Internal])],
                allow_external_provider: false,
            },
            &CHAT,
            Health,
            gates(&breakers, &queues),
            Priority::Chat,
            false,
            |_| async { Ok::<_, FakeError>(()) },
        )
        .await;
        assert!(matches!(
            none,
            Err(FallbackError::Route(RouteError::NoModelForLabel { .. }))
        ));
    }
}
