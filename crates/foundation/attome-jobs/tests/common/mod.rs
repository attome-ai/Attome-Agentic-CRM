//! The job type the queue tests enqueue. attome-jobs knows no job kinds, so
//! the tests bring their own, covering every shape and policy the queue
//! routes on: unit, struct and tuple variants; both queues; all three
//! priority lanes; three attempt budgets.

#![allow(dead_code, reason = "each test binary uses a different subset")]

use attome_jobs::{Job, JobPriority};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestJob {
    /// Periodic maintenance: low lane, 3 attempts.
    Sweep,
    PruneHistory,
    Revalidate,
    SlaSweep,
    /// Index build: low lane, 10 attempts.
    BuildIndex {
        entity_logicalname: String,
        field_logicalname: String,
    },
    /// Someone is waiting: high lane, 10 attempts.
    FanOut {
        dispatch_id: Uuid,
    },
    RunWorkflow {
        instance_id: Uuid,
    },
    ScanFile {
        session_id: Uuid,
    },
    /// Batch queue, normal lane, 5 attempts.
    Rewrap {
        domain: String,
    },
    /// Batch queue, high lane, 10 attempts.
    BulkEdit(BulkEditPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkEditPayload {
    pub bulk_op_id: Uuid,
    pub entity_logicalname: String,
    pub operation: String,
    pub records: Vec<serde_json::Value>,
    pub user_id: Uuid,
}

impl Job for TestJob {
    fn kind(&self) -> &'static str {
        match self {
            Self::Sweep => "Sweep",
            Self::PruneHistory => "PruneHistory",
            Self::Revalidate => "Revalidate",
            Self::SlaSweep => "SlaSweep",
            Self::BuildIndex { .. } => "BuildIndex",
            Self::FanOut { .. } => "FanOut",
            Self::RunWorkflow { .. } => "RunWorkflow",
            Self::ScanFile { .. } => "ScanFile",
            Self::Rewrap { .. } => "Rewrap",
            Self::BulkEdit(_) => "BulkEdit",
        }
    }

    fn is_batch(&self) -> bool {
        matches!(self, Self::Rewrap { .. } | Self::BulkEdit(_))
    }

    fn priority(&self) -> JobPriority {
        match self {
            Self::FanOut { .. }
            | Self::RunWorkflow { .. }
            | Self::ScanFile { .. }
            | Self::BulkEdit(_) => JobPriority::High,
            Self::Rewrap { .. } => JobPriority::Normal,
            Self::Sweep
            | Self::PruneHistory
            | Self::Revalidate
            | Self::SlaSweep
            | Self::BuildIndex { .. } => JobPriority::Low,
        }
    }

    fn max_attempts(&self) -> i32 {
        match self {
            Self::Sweep | Self::PruneHistory | Self::Revalidate | Self::SlaSweep => 3,
            Self::Rewrap { .. } => 5,
            Self::BuildIndex { .. }
            | Self::FanOut { .. }
            | Self::RunWorkflow { .. }
            | Self::ScanFile { .. }
            | Self::BulkEdit(_) => 10,
        }
    }
}
