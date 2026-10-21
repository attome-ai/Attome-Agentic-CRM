//! The job contract: what a job type declares about itself, and the versioned
//! envelope every job is stored in.
//!
//! attome-jobs knows no job kinds. The application defines one enum of its
//! jobs (serde's default, externally tagged representation) and implements
//! [`Job`] for it; this crate routes, stores and decodes it.

use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// What a job type declares about each job. Implemented by the application's
/// job enum.
///
/// The type must serialize with serde's default externally tagged enum
/// representation: a unit variant as `"Name"`, any other as
/// `{"Name": <payload>}`. [`JobEnvelope`] relies on that shape to store the
/// variant name separately from the payload.
pub trait Job:
    Serialize + DeserializeOwned + Clone + fmt::Debug + Send + Sync + Unpin + 'static
{
    /// The variant name, exactly as serde tags it. Stored in the envelope and
    /// used as a metric label, so it must be a fixed string per variant.
    fn kind(&self) -> &'static str;

    /// True for open-ended work whose cost grows with the number of records
    /// (bulk edits, imports, exports). Such jobs run on the batch queue, so
    /// they never occupy the fast queue's worker slots.
    fn is_batch(&self) -> bool {
        false
    }

    /// The lane this job polls in.
    fn priority(&self) -> JobPriority {
        JobPriority::Normal
    }

    /// Attempts before the job is dead-lettered. Declared per kind, so the
    /// budget never depends on which enqueue function a producer called.
    fn max_attempts(&self) -> i32 {
        5
    }

    /// Z7-T3: the kinds of this job type that may run only so many at once,
    /// as `(kind, max_running)`, across every worker of the deployment.
    /// Written at worker start by [`crate::install_concurrency_caps`]; a kind
    /// not listed is not capped.
    fn concurrency_caps() -> &'static [(&'static str, i32)]
    where
        Self: Sized,
    {
        &[]
    }
}

/// The priority lane a job enqueues into. `apalis.get_jobs` polls
/// `ORDER BY priority DESC, run_at ASC`, so a higher lane runs sooner.
///
/// This is a poll-order preference, not a fairness guarantee: the poll has no
/// aging, so a lane kept continuously full can delay a lower one for as long
/// as it stays full. Bursts of high-priority work delay low-priority work;
/// they do not abandon it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobPriority {
    /// Periodic maintenance nobody is waiting on.
    Low,
    /// The default lane; apalis's own default priority, `0`.
    Normal,
    /// A person is waiting on the outcome, or another system has a delivery
    /// deadline (outbound email, a webhook).
    High,
}

impl JobPriority {
    pub const ALL: [Self; 3] = [Self::Low, Self::Normal, Self::High];

    /// The `apalis.jobs.priority` value this lane maps to.
    pub const fn apalis_priority(self) -> i32 {
        match self {
            Self::Low => -10,
            Self::Normal => 0,
            Self::High => 10,
        }
    }

    /// Stable metric label.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

/// The envelope version this binary writes.
pub const CURRENT_ENVELOPE_VERSION: u16 = 1;

/// The variant name [`JobEnvelope::Unrecognized`] carries for a row that is
/// not a current envelope, or whose `variant` is not a string: a fixed
/// constant, never a row's own text used as a metric label.
pub const MALFORMED_VARIANT_TAG: &str = "<malformed>";

/// How a job is stored in `apalis.jobs.job`:
/// `{"version", "variant", "payload", "trace_context"}`, plus `request_id`
/// when the job was queued while serving a request (U4-T5), so the request
/// can be traced to its jobs. Decoding ignores it.
///
/// **Decoding never fails, whatever the JSON.** apalis-sql decodes every row
/// its claim query returns with `.expect(...)`, before any handler runs, so a
/// decode error there panics the poller, and the same row is claimed again
/// after restart: one bad row becomes a crash loop. So a newer `version`, an
/// unknown variant, a payload whose shape this binary no longer matches, and a
/// row that is not an envelope at all decode to [`Self::Unrecognized`]. The
/// worker fails that attempt with a clear error, and the row ends as a normal
/// dead letter.
#[derive(Debug, Clone)]
pub enum JobEnvelope<J> {
    /// A job this binary understands. `trace_context` is the W3C `traceparent`
    /// of whatever caused the enqueue, kept as a string so binaries of
    /// different versions all round-trip it.
    Known {
        job: J,
        trace_context: Option<String>,
    },
    /// A row this binary cannot process. It exists only as a decode result
    /// and is never enqueued.
    Unrecognized { variant: String, version: u16 },
}

impl<J: Job> JobEnvelope<J> {
    pub fn new(job: J) -> Self {
        Self::Known {
            job,
            trace_context: None,
        }
    }

    pub fn new_with_trace_context(job: J, trace_context: Option<String>) -> Self {
        Self::Known { job, trace_context }
    }

    pub fn is_recognized(&self) -> bool {
        matches!(self, Self::Known { .. })
    }
}

impl<J: Job> Serialize for JobEnvelope<J> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let (job, trace_context) = match self {
            Self::Known { job, trace_context } => (job, trace_context),
            Self::Unrecognized { variant, .. } => {
                return Err(serde::ser::Error::custom(format!(
                    "cannot serialize an unrecognized job envelope (variant={variant}); it exists \
                     only as a decode result"
                )));
            }
        };
        // The job's own tagged form is `"Name"` or `{"Name": <payload>}`. Only
        // the inner payload is stored (`null` for a unit variant): decoding
        // rebuilds the tagged form from `variant` and `payload`.
        let full = serde_json::to_value(job).map_err(serde::ser::Error::custom)?;
        let payload = match full {
            serde_json::Value::Object(mut map) => {
                map.remove(job.kind()).unwrap_or(serde_json::Value::Null)
            }
            _ => serde_json::Value::Null,
        };
        let mut envelope = serde_json::Map::with_capacity(5);
        envelope.insert("version".to_owned(), CURRENT_ENVELOPE_VERSION.into());
        envelope.insert("variant".to_owned(), job.kind().into());
        envelope.insert("payload".to_owned(), payload);
        envelope.insert(
            "trace_context".to_owned(),
            trace_context
                .clone()
                .map_or(serde_json::Value::Null, serde_json::Value::String),
        );
        if let Some(request_id) = attome_types::request_scope::current() {
            envelope.insert(
                "request_id".to_owned(),
                serde_json::Value::String(request_id),
            );
        }
        serde_json::Value::Object(envelope).serialize(serializer)
    }
}

impl<'de, J: Job> Deserialize<'de> for JobEnvelope<J> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        Ok(decode(&value))
    }
}

fn decode<J: Job>(value: &serde_json::Value) -> JobEnvelope<J> {
    let malformed = |version| JobEnvelope::Unrecognized {
        variant: MALFORMED_VARIANT_TAG.to_owned(),
        version,
    };
    let Some(raw_variant) = value.get("variant") else {
        return malformed(0);
    };
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .unwrap_or(0);
    let Some(variant) = raw_variant.as_str() else {
        return malformed(version);
    };
    let unrecognized = || JobEnvelope::Unrecognized {
        variant: variant.to_owned(),
        version,
    };
    if version > CURRENT_ENVELOPE_VERSION {
        return unrecognized();
    }
    let payload = value
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let trace_context = value
        .get("trace_context")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let tagged = match payload {
        serde_json::Value::Null => serde_json::Value::String(variant.to_owned()),
        other => serde_json::json!({ variant: other }),
    };
    match serde_json::from_value::<J>(tagged) {
        Ok(job) => JobEnvelope::Known { job, trace_context },
        Err(_) => unrecognized(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    enum Sample {
        Sweep,
        Index { entity: String },
        Bulk(u32),
    }

    impl Job for Sample {
        fn kind(&self) -> &'static str {
            match self {
                Self::Sweep => "Sweep",
                Self::Index { .. } => "Index",
                Self::Bulk(_) => "Bulk",
            }
        }
    }

    #[tokio::test]
    async fn correlation_a_job_queued_in_a_request_names_it() {
        let outside = serde_json::to_value(JobEnvelope::new(Sample::Sweep)).unwrap();
        assert!(outside.get("request_id").is_none());
        let inside = attome_types::request_scope::scope("req-7".to_owned(), async {
            serde_json::to_value(JobEnvelope::new(Sample::Bulk(3))).unwrap()
        })
        .await;
        assert_eq!(inside["request_id"], "req-7");
        let decoded: JobEnvelope<Sample> = serde_json::from_value(inside).unwrap();
        assert!(decoded.is_recognized());
    }

    fn round_trip(job: Sample) -> JobEnvelope<Sample> {
        let stored = serde_json::to_value(JobEnvelope::new(job)).unwrap();
        serde_json::from_value(stored).unwrap()
    }

    #[test]
    fn every_variant_shape_round_trips() {
        for job in [
            Sample::Sweep,
            Sample::Index {
                entity: "account".into(),
            },
            Sample::Bulk(7),
        ] {
            match round_trip(job.clone()) {
                JobEnvelope::Known { job: back, .. } => assert_eq!(back, job),
                other @ JobEnvelope::Unrecognized { .. } => {
                    panic!("{job:?} decoded to {other:?}")
                }
            }
        }
    }

    #[test]
    fn the_stored_shape_separates_variant_and_payload() {
        let stored = serde_json::to_value(JobEnvelope::new_with_trace_context(
            Sample::Index {
                entity: "account".into(),
            },
            Some("00-trace".into()),
        ))
        .unwrap();
        assert_eq!(
            stored,
            serde_json::json!({
                "version": 1,
                "variant": "Index",
                "payload": {"entity": "account"},
                "trace_context": "00-trace"
            })
        );
        let unit = serde_json::to_value(JobEnvelope::new(Sample::Sweep)).unwrap();
        assert_eq!(unit["payload"], serde_json::Value::Null);
    }

    #[test]
    fn bad_rows_decode_to_unrecognized_and_never_error() {
        let cases = [
            serde_json::json!({"version": 1, "variant": "Gone", "payload": null}),
            serde_json::json!({"version": 9, "variant": "Sweep", "payload": null}),
            serde_json::json!({"version": 1, "variant": "Index", "payload": {"wrong": 1}}),
            serde_json::json!({"version": 1, "variant": 42}),
            serde_json::json!({"anything": "else"}),
            serde_json::json!("just a string"),
            serde_json::Value::Null,
        ];
        for case in cases {
            let decoded: JobEnvelope<Sample> = serde_json::from_value(case.clone()).unwrap();
            assert!(!decoded.is_recognized(), "{case} decoded as known");
        }
    }

    #[test]
    fn an_unrecognized_envelope_refuses_to_serialize() {
        let envelope: JobEnvelope<Sample> = JobEnvelope::Unrecognized {
            variant: "Gone".into(),
            version: 1,
        };
        assert!(serde_json::to_value(envelope).is_err());
    }
}
