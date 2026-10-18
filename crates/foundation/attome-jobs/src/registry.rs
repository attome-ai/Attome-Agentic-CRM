//! Z7-T1: job types registered at run time, so an engine, app or extension
//! adds a job without editing the application's job enum.
//!
//! The application's enum keeps one variant that carries a [`RegisteredJob`]
//! (`{name, version, payload}`), so the stored envelope and apalis's storage
//! type stay fixed. The worker hands that variant to [`JobRegistry::run`],
//! which finds the handler by name. A name no handler is registered for on
//! this worker fails the attempt with `unknown_job_type`, so the row retries
//! within its budget (a newer node may know it) and then lands in the dead
//! letters: it is never dropped.
//!
//! **State.** The registry lives in process memory and is filled by code at
//! start-up, the same on every node running the same binary; it holds no
//! data, only handlers, so it is rebuilt on every start. The concurrency cap
//! of a type ([`JobType::max_concurrency`]) is per node.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::JobPriority;

/// What a handler returns on failure.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

type BoxFuture = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>;
type Handler<C> = Arc<dyn Fn(C, RegisteredJob) -> BoxFuture + Send + Sync>;

/// Which queue a registered job runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// The default queue: short jobs, someone may be waiting.
    Fast,
    /// The batch queue: open-ended work whose cost grows with the number of
    /// records ([`crate::Job::is_batch`]).
    Batch,
}

/// What a registered job type declares about its jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobType {
    /// The stored name; also a metric label, so a fixed string.
    pub name: &'static str,
    /// The newest payload version this binary's handler reads. A job written
    /// with a higher version fails with `newer_job_version` until this node
    /// is upgraded; a lower one reaches the handler, which upgrades it.
    pub version: u16,
    pub lane: Lane,
    pub priority: JobPriority,
    /// Attempts before the job is dead-lettered.
    pub max_attempts: i32,
    /// Jobs of this type one node runs at once; `None` for no cap beyond the
    /// worker's own.
    pub max_concurrency: Option<u32>,
}

impl JobType {
    /// A fast-lane, normal-priority type with five attempts and no cap.
    pub const fn new(name: &'static str, version: u16) -> Self {
        Self {
            name,
            version,
            lane: Lane::Fast,
            priority: JobPriority::Normal,
            max_attempts: 5,
            max_concurrency: None,
        }
    }
}

/// One job of a registered type, as the application's job enum carries it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisteredJob {
    pub name: String,
    pub version: u16,
    pub payload: serde_json::Value,
}

impl RegisteredJob {
    /// The payload read back as `T`.
    pub fn payload<T: serde::de::DeserializeOwned>(&self) -> Result<T, BoxError> {
        serde_json::from_value(self.payload.clone()).map_err(|e| {
            format!(
                "job '{}' version {}: the payload does not match: {e}",
                self.name, self.version
            )
            .into()
        })
    }
}

/// Why a registration or a run was refused.
#[derive(Debug)]
pub enum RegistryError {
    /// Two registrations under one name.
    Duplicate(&'static str),
    /// No type with this name is registered on this node.
    UnknownType(String),
    /// The job was written by a newer handler than this node has.
    NewerVersion {
        name: String,
        version: u16,
        known: u16,
    },
    /// The payload could not be written as JSON.
    Payload(String),
    /// The handler failed.
    Failed(BoxError),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(f, "job type '{name}' is registered twice"),
            Self::UnknownType(name) => write!(
                f,
                "unknown_job_type: no job type named '{name}' is registered on this worker"
            ),
            Self::NewerVersion {
                name,
                version,
                known,
            } => write!(
                f,
                "newer_job_version: job '{name}' is version {version}, this worker reads up to {known}"
            ),
            Self::Payload(detail) => write!(f, "job payload: {detail}"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(e) => Some(&**e),
            _ => None,
        }
    }
}

struct Entry<C> {
    job_type: JobType,
    handler: Handler<C>,
    permits: Option<Arc<Semaphore>>,
}

/// The registered job types, each with its handler. `C` is what every
/// handler is given (the application's state).
pub struct JobRegistry<C> {
    types: RwLock<BTreeMap<&'static str, Arc<Entry<C>>>>,
}

impl<C> Default for JobRegistry<C> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C> fmt::Debug for JobRegistry<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobRegistry")
            .field("types", &self.names())
            .finish()
    }
}

impl<C> JobRegistry<C> {
    /// An empty registry; `const`, so it can be a `static`.
    pub const fn new() -> Self {
        Self {
            types: RwLock::new(BTreeMap::new()),
        }
    }

    fn entry(&self, name: &str) -> Option<Arc<Entry<C>>> {
        self.types
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(name)
            .cloned()
    }

    /// Registers `job_type` with its handler. A second registration under the
    /// same name is refused: two engines must not share a job name.
    pub fn register<F, Fut>(&self, job_type: JobType, handler: F) -> Result<(), RegistryError>
    where
        F: Fn(C, RegisteredJob) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), BoxError>> + Send + 'static,
    {
        let mut types = self
            .types
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if types.contains_key(job_type.name) {
            return Err(RegistryError::Duplicate(job_type.name));
        }
        let permits = job_type
            .max_concurrency
            .map(|cap| Arc::new(Semaphore::new(usize::try_from(cap.max(1)).unwrap_or(1))));
        let handler: Handler<C> = Arc::new(move |ctx, job| Box::pin(handler(ctx, job)));
        types.insert(
            job_type.name,
            Arc::new(Entry {
                job_type,
                handler,
                permits,
            }),
        );
        Ok(())
    }

    /// The declaration of the type named `name`, if registered here.
    pub fn job_type(&self, name: &str) -> Option<JobType> {
        self.entry(name).map(|entry| entry.job_type)
    }

    /// Every registered name, sorted.
    pub fn names(&self) -> Vec<&'static str> {
        self.types
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .keys()
            .copied()
            .collect()
    }

    /// A job of the registered type `name` carrying `payload`, at the type's
    /// current version. Refused for a name not registered here, so a typo
    /// fails at the producer rather than in the dead letters.
    pub fn job(
        &self,
        name: &str,
        payload: &impl Serialize,
    ) -> Result<RegisteredJob, RegistryError> {
        let job_type = self
            .job_type(name)
            .ok_or_else(|| RegistryError::UnknownType(name.to_owned()))?;
        let payload =
            serde_json::to_value(payload).map_err(|e| RegistryError::Payload(e.to_string()))?;
        Ok(RegisteredJob {
            name: job_type.name.to_owned(),
            version: job_type.version,
            payload,
        })
    }

    /// Runs `job` through its type's handler, within the type's concurrency
    /// cap on this node.
    pub async fn run(&self, ctx: C, job: RegisteredJob) -> Result<(), RegistryError> {
        let entry = self
            .entry(&job.name)
            .ok_or_else(|| RegistryError::UnknownType(job.name.clone()))?;
        if job.version > entry.job_type.version {
            return Err(RegistryError::NewerVersion {
                name: job.name,
                version: job.version,
                known: entry.job_type.version,
            });
        }
        let _permit = match &entry.permits {
            Some(permits) => Some(
                Arc::clone(permits)
                    .acquire_owned()
                    .await
                    .map_err(|e| RegistryError::Failed(e.into()))?,
            ),
            None => None,
        };
        (entry.handler)(ctx, job)
            .await
            .map_err(RegistryError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[derive(Serialize, Deserialize)]
    struct Greeting {
        to: String,
    }

    #[tokio::test]
    async fn a_registered_type_runs_its_handler() {
        let registry: JobRegistry<Arc<AtomicUsize>> = JobRegistry::new();
        registry
            .register(
                JobType::new("greet", 1),
                |count: Arc<AtomicUsize>, job| async move {
                    let greeting: Greeting = job.payload()?;
                    assert_eq!(greeting.to, "world");
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .expect("register");
        let job = registry
            .job(
                "greet",
                &Greeting {
                    to: "world".to_owned(),
                },
            )
            .expect("build the job");
        assert_eq!(job.version, 1);
        let count = Arc::new(AtomicUsize::new(0));
        registry
            .run(Arc::clone(&count), job)
            .await
            .expect("run the job");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unknown_name_fails_with_unknown_job_type() {
        let registry: JobRegistry<()> = JobRegistry::new();
        assert!(matches!(
            registry.job("missing", &()),
            Err(RegistryError::UnknownType(_))
        ));
        let job = RegisteredJob {
            name: "missing".to_owned(),
            version: 1,
            payload: serde_json::Value::Null,
        };
        let err = registry.run((), job).await.expect_err("unknown type");
        assert!(err.to_string().starts_with("unknown_job_type"), "{err}");
    }

    #[tokio::test]
    async fn a_second_registration_under_one_name_is_refused() {
        let registry: JobRegistry<()> = JobRegistry::new();
        registry
            .register(JobType::new("once", 1), |(), _| async { Ok(()) })
            .expect("first");
        assert!(matches!(
            registry.register(JobType::new("once", 2), |(), _| async { Ok(()) }),
            Err(RegistryError::Duplicate("once"))
        ));
        assert_eq!(registry.names(), ["once"]);
    }

    #[tokio::test]
    async fn a_newer_payload_version_is_refused_and_an_older_one_runs() {
        let registry: JobRegistry<()> = JobRegistry::new();
        registry
            .register(JobType::new("versioned", 2), |(), job| async move {
                assert_eq!(job.version, 1, "the handler sees the stored version");
                Ok(())
            })
            .expect("register");
        let newer = RegisteredJob {
            name: "versioned".to_owned(),
            version: 3,
            payload: serde_json::Value::Null,
        };
        let err = registry.run((), newer).await.expect_err("newer version");
        assert!(err.to_string().starts_with("newer_job_version"), "{err}");
        let older = RegisteredJob {
            name: "versioned".to_owned(),
            version: 1,
            payload: serde_json::Value::Null,
        };
        registry.run((), older).await.expect("older version runs");
    }

    #[tokio::test]
    async fn the_concurrency_cap_holds_on_one_node() {
        let registry: Arc<JobRegistry<Arc<(AtomicUsize, AtomicUsize)>>> =
            Arc::new(JobRegistry::new());
        let capped = JobType {
            max_concurrency: Some(2),
            ..JobType::new("capped", 1)
        };
        registry
            .register(
                capped,
                |gauge: Arc<(AtomicUsize, AtomicUsize)>, _| async move {
                    let now = gauge.0.fetch_add(1, Ordering::SeqCst) + 1;
                    gauge.1.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    gauge.0.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                },
            )
            .expect("register");
        let gauge = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
        let mut runs = Vec::new();
        for _ in 0..6 {
            let registry = Arc::clone(&registry);
            let gauge = Arc::clone(&gauge);
            let job = registry.job("capped", &()).expect("job");
            runs.push(tokio::spawn(async move { registry.run(gauge, job).await }));
        }
        for run in runs {
            run.await.expect("join").expect("run");
        }
        assert_eq!(
            gauge.1.load(Ordering::SeqCst),
            2,
            "never more than two at once"
        );
    }
}
