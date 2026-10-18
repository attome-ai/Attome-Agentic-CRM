//! Z2-T10: counts the SQL statements a piece of async work runs, so a test
//! can hold a hot path to a query budget (an N+1 guard).
//!
//! sqlx emits one `tracing` event per statement (target `sqlx::query`, from
//! its statement logger, which runs in the task that awaited the query). A
//! global subscriber with [`QueryCountLayer`] counts those events against the
//! task-local scope [`count_queries`] opens, so concurrent tests in other
//! tasks do not add to each other's counts. Work spawned onto another task is
//! not counted.
//!
//! The subscriber is process-global: a test binary that counts queries must
//! not install another global subscriber. [`count_queries`] panics if one is
//! already installed.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use tracing_subscriber::Layer;
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::{Context, SubscriberExt};

tokio::task_local! {
    static SCOPE: Arc<AtomicUsize>;
    /// AA4-T6: each statement's summary, when [`record_queries`] opened the
    /// scope.
    static RECORD: Arc<std::sync::Mutex<Vec<String>>>;
}

/// Reads sqlx's `summary` field: the statement's start, its Z2-T8 tag
/// comment first when it has one.
struct Summary(String);

impl tracing::field::Visit for Summary {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "summary" {
            self.0 = format!("{value:?}");
        }
    }
}

/// Counts `sqlx::query` events into the current [`count_queries`] scope.
#[derive(Debug, Clone, Copy, Default)]
pub struct QueryCountLayer;

impl<S: tracing::Subscriber> Layer<S> for QueryCountLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target() == "sqlx::query" {
            let _ = SCOPE.try_with(|count| count.fetch_add(1, Ordering::Relaxed));
            let _ = RECORD.try_with(|record| {
                let mut summary = Summary(String::new());
                event.record(&mut summary);
                record
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(summary.0);
            });
        }
    }
}

static INSTALLED: OnceLock<bool> = OnceLock::new();

/// Installs the counting subscriber once per process; `false` when another
/// global subscriber was there first.
pub fn install() -> bool {
    *INSTALLED.get_or_init(|| {
        let layer = QueryCountLayer
            .with_filter(Targets::new().with_target("sqlx::query", LevelFilter::TRACE));
        tracing::subscriber::set_global_default(tracing_subscriber::registry().with(layer)).is_ok()
    })
}

/// Runs `work` and returns its output with the number of SQL statements it
/// ran in its own task.
pub async fn count_queries<F: Future>(work: F) -> (F::Output, usize) {
    assert!(
        install(),
        "count_queries needs its own global tracing subscriber; another one is installed"
    );
    let count = Arc::new(AtomicUsize::new(0));
    let out = SCOPE.scope(Arc::clone(&count), work).await;
    (out, count.load(Ordering::Relaxed))
}

/// AA4-T6: runs `work` and returns its output with each SQL statement it ran
/// in its own task, as sqlx summarises it (the tag comment first), so a test
/// can count the statements of one kind.
pub async fn record_queries<F: Future>(work: F) -> (F::Output, Vec<String>) {
    assert!(
        install(),
        "record_queries needs its own global tracing subscriber; another one is installed"
    );
    let record = Arc::new(std::sync::Mutex::new(Vec::new()));
    let out = RECORD.scope(Arc::clone(&record), work).await;
    let statements = std::mem::take(
        &mut *record
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    );
    (out, statements)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_sqlx_query_events_in_scope() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let ((), n) = count_queries(async {
                tracing::info!(target: "sqlx::query", "SELECT 1");
                tracing::info!(target: "sqlx::query", "SELECT 2");
                tracing::info!(target: "other", "not a query");
            })
            .await;
            assert_eq!(n, 2);
            // Outside a scope nothing is counted, and nothing panics.
            tracing::info!(target: "sqlx::query", "SELECT 3");
            let ((), none) = count_queries(async {}).await;
            assert_eq!(none, 0);
            let ((), recorded) = record_queries(async {
                tracing::info!(target: "sqlx::query", summary = "/* a.b */ SELECT 1", "x");
            })
            .await;
            assert_eq!(recorded.len(), 1);
            assert!(recorded[0].contains("/* a.b */"), "{recorded:?}");
        });
    }
}
