//! Z7-T7: a job's handler run at once, in this process, and schedule time
//! moved without sleeping.
//!
//! [`run_now`] builds the job the way a producer does
//! (`JobRegistry::job`, so an unknown name or a bad payload fails the same)
//! and runs its handler directly, with no queue in between. [`advance`]
//! moves a `FakeClock` (Z15-T5) and ticks the given schedules at its time
//! (`attome_jobs::schedule::tick_at_clock`), returning the ones that came due
//! and enqueued their job.

use attome_jobs::schedule::{Schedule, tick_at_clock};
use attome_jobs::{Job, JobRegistry, RegistryError};
use attome_types::clock::FakeClock;
use serde::Serialize;

/// Runs the job `name` with `payload` through its registered handler now.
pub async fn run_now<C>(
    registry: &JobRegistry<C>,
    ctx: C,
    name: &str,
    payload: &impl Serialize,
) -> Result<(), RegistryError> {
    let job = registry.job(name, payload)?;
    registry.run(ctx, job).await
}

/// Moves `clock` on by `by`, then ticks each `(name, schedule, job)` at the
/// clock's time. Returns the names of the schedules that came due, each of
/// which enqueued its job once.
pub async fn advance<J: Job>(
    pool: &sqlx::PgPool,
    clock: &FakeClock,
    by: chrono::Duration,
    schedules: &[(&str, &Schedule, J)],
) -> Result<Vec<String>, sqlx::Error> {
    clock.advance(by);
    let mut due = Vec::new();
    for (name, schedule, job) in schedules {
        if tick_at_clock(pool, name, schedule, job.clone(), clock).await? {
            due.push((*name).to_owned());
        }
    }
    Ok(due)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Serialize, serde::Deserialize)]
    struct Count {
        by: usize,
    }

    #[test]
    fn run_now_calls_the_handler_at_once() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let registry: JobRegistry<Arc<AtomicUsize>> = JobRegistry::new();
            registry
                .register(
                    attome_jobs::JobType::new("count", 1),
                    |counter: Arc<AtomicUsize>, job| async move {
                        counter.fetch_add(job.payload::<Count>()?.by, Ordering::SeqCst);
                        Ok(())
                    },
                )
                .unwrap();
            let counter = Arc::new(AtomicUsize::new(0));
            run_now(&registry, Arc::clone(&counter), "count", &Count { by: 3 })
                .await
                .unwrap();
            assert_eq!(counter.load(Ordering::SeqCst), 3);
            let unknown = run_now(&registry, counter, "nope", &Count { by: 1 }).await;
            assert!(matches!(unknown, Err(RegistryError::UnknownType(_))));
        });
    }
}
