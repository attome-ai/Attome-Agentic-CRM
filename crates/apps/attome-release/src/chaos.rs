//! The fault catalogue (roadmap AB9-T1): every fault a chaos run can inject,
//! what a correct deployment does under it, which feature's rule it proves
//! and how the fault is undone. The chaos runner reads this list; nothing
//! here injects anything.

/// A fault a chaos run can inject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultKind {
    ProcessKill,
    PostgresRestart,
    PostgresPause,
    DiskFill,
    RedisDown,
    RedisPause,
    FileStoreDown,
    AiSlow,
    AiFailing,
    EmailDown,
    CertExpired,
    QueueFlood,
    NetworkDelay,
}

impl FaultKind {
    /// Every kind, so the catalogue's completeness is testable.
    pub const ALL: &'static [FaultKind] = &[
        Self::ProcessKill,
        Self::PostgresRestart,
        Self::PostgresPause,
        Self::DiskFill,
        Self::RedisDown,
        Self::RedisPause,
        Self::FileStoreDown,
        Self::AiSlow,
        Self::AiFailing,
        Self::EmailDown,
        Self::CertExpired,
        Self::QueueFlood,
        Self::NetworkDelay,
    ];
}

/// One catalogue entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultSpec {
    pub kind: FaultKind,
    pub name: &'static str,
    /// The observable behaviour of a correct deployment.
    pub expected: &'static str,
    /// The roadmap features whose rules the fault proves.
    pub proves: &'static [&'static str],
    /// How the fault is undone.
    pub undo: &'static str,
    /// Injecting it needs network administration (tc/netem) on the host.
    pub needs_net_admin: bool,
    pub default_duration_secs: u32,
}

pub const CATALOGUE: &[FaultSpec] = &[
    FaultSpec {
        kind: FaultKind::ProcessKill,
        name: "process-kill",
        expected: "The killed node's requests fail over to the others; durable jobs it held are retried by another node after their lease; no write is half done.",
        proves: &["AB2", "Z7"],
        undo: "Start the process again.",
        needs_net_admin: false,
        default_duration_secs: 60,
    },
    FaultSpec {
        kind: FaultKind::PostgresRestart,
        name: "postgres-restart",
        expected: "Requests during the restart answer 503 db_unavailable (GET and idempotent requests are retried inside the server's window); the pool reconnects without a server restart.",
        proves: &["AB2", "AB6"],
        undo: "Nothing: Postgres comes back by itself.",
        needs_net_admin: false,
        default_duration_secs: 30,
    },
    FaultSpec {
        kind: FaultKind::PostgresPause,
        name: "postgres-pause",
        expected: "Requests time out at their route deadline with 504, the pool does not grow without bound, and readiness turns not ready until Postgres answers.",
        proves: &["AB6", "U9"],
        undo: "Unpause the Postgres container.",
        needs_net_admin: false,
        default_duration_secs: 30,
    },
    FaultSpec {
        kind: FaultKind::DiskFill,
        name: "disk-fill",
        expected: "Uploads refuse with a clear storage error, logs keep rotating, and the disk alert fires; nothing already stored is lost.",
        proves: &["AB10", "Z6"],
        undo: "Delete the fill file.",
        needs_net_admin: false,
        default_duration_secs: 120,
    },
    FaultSpec {
        kind: FaultKind::RedisDown,
        name: "redis-down",
        expected: "Rate limits and replay checks refuse with 503 (they fail closed); records still save when AB5 is built, otherwise the server reports not ready.",
        proves: &["AB5", "Q20"],
        undo: "Start Redis again.",
        needs_net_admin: false,
        default_duration_secs: 60,
    },
    FaultSpec {
        kind: FaultKind::RedisPause,
        name: "redis-pause",
        expected: "Cache reads time out within the Redis timeout and fall back to Postgres; security checks fail closed; no request hangs.",
        proves: &["AB5", "AB6"],
        undo: "Unpause the Redis container.",
        needs_net_admin: false,
        default_duration_secs: 30,
    },
    FaultSpec {
        kind: FaultKind::FileStoreDown,
        name: "file-store-down",
        expected: "Uploads and downloads answer 503 with Retry-After; records without files still save; the file-store dependency shows down.",
        proves: &["AB6", "U9"],
        undo: "Start the object store again.",
        needs_net_admin: false,
        default_duration_secs: 60,
    },
    FaultSpec {
        kind: FaultKind::AiSlow,
        name: "ai-slow",
        expected: "Assistant turns stop at their deadline with a clear message; nothing else slows down; the AI breaker opens after repeated timeouts.",
        proves: &["AB6", "N31"],
        undo: "Remove the added latency.",
        needs_net_admin: true,
        default_duration_secs: 120,
    },
    FaultSpec {
        kind: FaultKind::AiFailing,
        name: "ai-failing",
        expected: "The fallback model answers when one is set, otherwise the assistant says it is unavailable; records and flows are unaffected.",
        proves: &["N25", "N31"],
        undo: "Point the provider back at the real endpoint.",
        needs_net_admin: false,
        default_duration_secs: 120,
    },
    FaultSpec {
        kind: FaultKind::EmailDown,
        name: "email-down",
        expected: "Emails stay in the outbox and are sent after the server returns; the business change that wrote them is not rolled back.",
        proves: &["Z8"],
        undo: "Start the mail server again.",
        needs_net_admin: false,
        default_duration_secs: 120,
    },
    FaultSpec {
        kind: FaultKind::CertExpired,
        name: "cert-expired",
        expected: "Outbound calls to the expired endpoint fail the TLS check and are not sent in clear; the certificate alert fires.",
        proves: &["AB10", "Q21"],
        undo: "Restore the valid certificate.",
        needs_net_admin: false,
        default_duration_secs: 60,
    },
    FaultSpec {
        kind: FaultKind::QueueFlood,
        name: "queue-flood",
        expected: "Interactive requests keep their latency while background jobs drain at the throttled pace; the backlog alert fires and clears.",
        proves: &["AA10", "Z7"],
        undo: "Let the flood drain or cancel the flood jobs.",
        needs_net_admin: false,
        default_duration_secs: 300,
    },
    FaultSpec {
        kind: FaultKind::NetworkDelay,
        name: "network-delay",
        expected: "Requests slow by the added delay but stay within their deadlines or fail at them; no retry storm (retries keep their budget).",
        proves: &["AB6"],
        undo: "Remove the netem delay.",
        needs_net_admin: true,
        default_duration_secs: 120,
    },
];

/// The catalogue entry named `name`.
pub fn by_name(name: &str) -> Option<&'static FaultSpec> {
    CATALOGUE.iter().find(|f| f.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn every_kind_has_one_spec() {
        for kind in FaultKind::ALL {
            let count = CATALOGUE.iter().filter(|f| f.kind == *kind).count();
            assert_eq!(count, 1, "{kind:?}");
        }
        assert_eq!(CATALOGUE.len(), FaultKind::ALL.len());
    }

    #[test]
    fn names_are_unique() {
        let names: HashSet<&str> = CATALOGUE.iter().map(|f| f.name).collect();
        assert_eq!(names.len(), CATALOGUE.len());
        assert_eq!(
            by_name("redis-down").map(|f| f.kind),
            Some(FaultKind::RedisDown)
        );
        assert!(by_name("nope").is_none());
    }

    #[test]
    fn every_spec_says_what_it_proves_and_how_to_undo() {
        for f in CATALOGUE {
            assert!(!f.proves.is_empty(), "{}", f.name);
            assert!(!f.expected.is_empty() && !f.undo.is_empty(), "{}", f.name);
        }
    }
}
