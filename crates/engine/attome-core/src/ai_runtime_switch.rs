//! The deployment-wide runtime AI switch — the read side (C11 B5, P-5, row
//! A-85).
//!
//! `config.inference.ai` is read once, at process start. This is the overlay an
//! operator flips during an incident, stored in `ai_runtime_switch`
//! (migration 0494) and changed through `attome-ai`'s audited admin route. It lives
//! here, below `attome-ai`, `attome-search`, `attome-workflow` and `trd-engine`, because
//! every one of them decides whether an AI surface may run, and every one must
//! read the same answer.
//!
//! ## It can only narrow
//!
//! Effective enablement is `config AND runtime`, per surface and for the master
//! switch. A row can turn off what the configuration enabled; nothing here can
//! turn on what it disabled. An absent row means "not narrowed at runtime".
//!
//! ## It fails closed
//!
//! Readers see a process-wide snapshot. [`refresh`] rereads the table at most
//! once per [`REFRESH_EVERY`]; the async entry points that decide whether AI
//! may run call it first. A snapshot older than [`STALE_AFTER`] — never read,
//! or unreadable since — makes **every** surface off: this is a security
//! control, and an unknown state is not an enabled one (coding-guidelines §5).
//! [`STALE_AFTER`] is also the propagation bound: a change made on one node is
//! seen by every other within it.
//!
//! ## Why the effective value is `&'static`
//!
//! The gate and the tool list borrow an `&AiEnablement`. [`effective`] returns
//! one of the 32 possible combinations from a static table, so every existing
//! borrower keeps its shape and nothing allocates per call.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use attome_config::{AiEnablement, AiSurface};
use sqlx::PgPool;

/// How often the snapshot is reread, at most.
pub const REFRESH_EVERY: Duration = Duration::from_secs(1);

/// A snapshot older than this is treated as unknown: every surface off.
pub const STALE_AFTER: Duration = Duration::from_secs(5);

/// How long one read of the table may take.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// What a runtime switch row can turn off. `All` is the master switch;
/// `WebChat` is the public widget, which has its own configuration section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwitchSurface {
    All,
    Fields,
    Chat,
    SemanticSearch,
    WorkflowNodes,
    WebChat,
}

impl SwitchSurface {
    /// Every surface, in the order the admin screen lists them.
    pub const ALL: [SwitchSurface; 6] = [
        Self::All,
        Self::Fields,
        Self::Chat,
        Self::SemanticSearch,
        Self::WorkflowNodes,
        Self::WebChat,
    ];

    /// The stored name, matching migration 0494's `CHECK`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Fields => "fields",
            Self::Chat => "chat",
            Self::SemanticSearch => "semantic_search",
            Self::WorkflowNodes => "workflow_nodes",
            Self::WebChat => "webchat",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == value)
    }

    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy)]
struct Snapshot {
    /// Per surface: switched off at runtime.
    off: [bool; 6],
    /// When the table was last read successfully.
    read_at: Option<Instant>,
    /// When a read was last attempted, successful or not. Gates rereads, so
    /// while the database is failing, callers queued behind one failed read
    /// return at once (failing closed) instead of each trying their own.
    attempted_at: Option<Instant>,
}

static SNAPSHOT: RwLock<Snapshot> = RwLock::new(Snapshot {
    off: [false; 6],
    read_at: None,
    attempted_at: None,
});

/// Serializes rereads so a burst of requests after the snapshot ages issues
/// one query, not one each.
static REFRESHING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn snapshot() -> Snapshot {
    // A poisoned lock means a writer panicked mid-update; the value it left
    // is still a complete `Copy` struct, and the staleness rule still applies.
    *SNAPSHOT
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn store(off: [bool; 6]) {
    let mut guard = SNAPSHOT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    *guard = Snapshot {
        off,
        read_at: Some(now),
        attempted_at: Some(now),
    };
}

fn mark_attempt() {
    SNAPSHOT
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .attempted_at = Some(Instant::now());
}

/// Rereads the table when the snapshot is older than [`REFRESH_EVERY`].
///
/// A failed read leaves the snapshot as it was; once that is older than
/// [`STALE_AFTER`], every surface reads as off. The failure is logged, not
/// returned: callers go on to ask [`effective`], which already answers "off".
pub async fn refresh(db: &PgPool) {
    if attempted_within(REFRESH_EVERY) {
        return;
    }
    let _one_reader = REFRESHING.lock().await;
    if attempted_within(REFRESH_EVERY) {
        return;
    }
    reread(db).await;
}

/// Rereads the table now, whatever the snapshot's age — after this node
/// changed a switch, so it takes effect here at once.
pub async fn reload(db: &PgPool) {
    let _one_reader = REFRESHING.lock().await;
    reread(db).await;
}

async fn reread(db: &PgPool) {
    let read = tokio::time::timeout(
        READ_TIMEOUT,
        sqlx::query_as::<_, (String, bool)>("SELECT surface, enabled FROM ai_runtime_switch")
            .fetch_all(db),
    )
    .await;
    match read {
        Ok(Ok(rows)) => {
            let mut off = [false; 6];
            for (surface, enabled) in rows {
                match SwitchSurface::parse(&surface) {
                    Some(surface) => off[surface.index()] = !enabled,
                    // The table's CHECK makes this unreachable. An unknown row
                    // cannot say what it narrows, so it narrows everything.
                    None => off = [true; 6],
                }
            }
            store(off);
        }
        Ok(Err(error)) => {
            mark_attempt();
            read_failed(READ_FAILURE_ERROR);
            tracing::warn!(%error, "runtime AI switch unreadable; AI surfaces fail closed")
        }
        Err(_) => {
            mark_attempt();
            read_failed(READ_FAILURE_TIMEOUT);
            tracing::warn!("runtime AI switch read timed out; AI surfaces fail closed")
        }
    }
}

/// Chatbot plan C13.1: one per failed reread of the table. Once the snapshot
/// passes [`STALE_AFTER`] every AI surface is off, so a sustained rate here is
/// an AI outage whose cause is the database, not the switch.
pub const READ_FAILURES_TOTAL: &str = "ai_runtime_switch_read_failures_total";

/// The `reason` label: the query failed, or it outran [`READ_TIMEOUT`]. A
/// closed set — the error text itself is never a label.
pub const READ_FAILURE_ERROR: &str = "error";
pub const READ_FAILURE_TIMEOUT: &str = "timeout";

fn read_failed(reason: &'static str) {
    metrics::counter!(READ_FAILURES_TOTAL, "reason" => reason).increment(1);
}

fn attempted_within(age: Duration) -> bool {
    snapshot().attempted_at.is_some_and(|at| at.elapsed() < age)
}

/// Per surface, whether the runtime switch has it off — or `None` when the
/// snapshot is unknown (never read, or stale), which callers treat as off.
fn runtime_off() -> Option<[bool; 6]> {
    let snapshot = snapshot();
    snapshot
        .read_at
        .filter(|at| at.elapsed() < STALE_AFTER)
        .map(|_| snapshot.off)
}

/// `config AND runtime` — what the gate, the tool list and every AI surface
/// should consult instead of `config.inference.ai` alone.
pub fn effective(config: &AiEnablement) -> &'static AiEnablement {
    let Some(off) = runtime_off() else {
        return &COMBOS[0];
    };
    let on = |s: SwitchSurface| !off[s.index()];
    let bit = |b: bool, shift: usize| usize::from(b) << shift;
    let index = bit(config.enabled && on(SwitchSurface::All), 0)
        | bit(config.fields && on(SwitchSurface::Fields), 1)
        | bit(config.chat && on(SwitchSurface::Chat), 2)
        | bit(
            config.semantic_search && on(SwitchSurface::SemanticSearch),
            3,
        )
        | bit(config.workflow_nodes && on(SwitchSurface::WorkflowNodes), 4);
    &COMBOS[index]
}

/// Whether the public widget may answer, as far as the runtime switch goes:
/// neither the master switch nor the widget's own is off. The widget's
/// configuration and the chat surface are checked by its caller as before.
pub fn allows_webchat() -> bool {
    runtime_off()
        .is_some_and(|off| !off[SwitchSurface::All.index()] && !off[SwitchSurface::WebChat.index()])
}

/// Whether the runtime switch — not the configuration — has `surface` off, or
/// the snapshot is unknown. For the admin read, which reports the two apart.
pub fn runtime_enabled(surface: SwitchSurface) -> Option<bool> {
    runtime_off().map(|off| !off[surface.index()])
}

/// Whether `surface` is allowed by `config AND runtime`.
pub fn allows(config: &AiEnablement, surface: AiSurface) -> bool {
    effective(config).allows(surface)
}

const fn combo(i: usize) -> AiEnablement {
    AiEnablement {
        enabled: i & 1 != 0,
        fields: i & 2 != 0,
        chat: i & 4 != 0,
        semantic_search: i & 8 != 0,
        workflow_nodes: i & 16 != 0,
    }
}

static COMBOS: [AiEnablement; 32] = [
    combo(0),
    combo(1),
    combo(2),
    combo(3),
    combo(4),
    combo(5),
    combo(6),
    combo(7),
    combo(8),
    combo(9),
    combo(10),
    combo(11),
    combo(12),
    combo(13),
    combo(14),
    combo(15),
    combo(16),
    combo(17),
    combo(18),
    combo(19),
    combo(20),
    combo(21),
    combo(22),
    combo(23),
    combo(24),
    combo(25),
    combo(26),
    combo(27),
    combo(28),
    combo(29),
    combo(30),
    combo(31),
];

#[cfg(test)]
pub(crate) fn set_for_test(off: [bool; 6], read_at: Option<Instant>) {
    let mut guard = SNAPSHOT.write().unwrap_or_else(|p| p.into_inner());
    *guard = Snapshot {
        off,
        read_at,
        attempted_at: read_at,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_on() -> AiEnablement {
        AiEnablement {
            enabled: true,
            fields: true,
            chat: true,
            semantic_search: true,
            workflow_nodes: true,
        }
    }

    /// One test, because the snapshot is process-wide: cases run in order
    /// rather than racing each other.
    #[test]
    fn the_switch_only_narrows_and_fails_closed() {
        // Never read: everything off, whatever the configuration says.
        set_for_test([false; 6], None);
        assert!(!allows(&all_on(), AiSurface::Chat));
        assert!(!allows_webchat());

        // Fresh, nothing switched off: the configuration decides.
        set_for_test([false; 6], Some(Instant::now()));
        assert!(allows(&all_on(), AiSurface::Chat));
        assert!(allows_webchat());
        let mut chat_off_in_config = all_on();
        chat_off_in_config.chat = false;
        assert!(
            !allows(&chat_off_in_config, AiSurface::Chat),
            "the runtime switch can never enable what the configuration disabled"
        );

        // Chat off at runtime: chat alone goes; fields stay.
        let mut off = [false; 6];
        off[SwitchSurface::Chat.index()] = true;
        set_for_test(off, Some(Instant::now()));
        assert!(!allows(&all_on(), AiSurface::Chat));
        assert!(allows(&all_on(), AiSurface::Fields));
        assert!(allows_webchat(), "the widget has its own switch");

        // The master switch takes everything, the widget included.
        let mut off = [false; 6];
        off[SwitchSurface::All.index()] = true;
        set_for_test(off, Some(Instant::now()));
        for surface in [
            AiSurface::Fields,
            AiSurface::Chat,
            AiSurface::SemanticSearch,
            AiSurface::WorkflowNodes,
        ] {
            assert!(!allows(&all_on(), surface));
        }
        assert!(!allows_webchat());

        // Stale: unknown, so off.
        set_for_test(
            [false; 6],
            Instant::now().checked_sub(STALE_AFTER + Duration::from_secs(1)),
        );
        assert!(!allows(&all_on(), AiSurface::Fields));
        assert_eq!(runtime_enabled(SwitchSurface::Chat), None);
    }

    #[test]
    fn a_failed_read_counts_under_a_closed_reason() {
        use std::collections::BTreeMap;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::{Arc, Mutex};

        use metrics::{
            Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString,
            Unit,
        };

        #[derive(Default)]
        struct Cell(AtomicU64);
        impl CounterFn for Cell {
            fn increment(&self, value: u64) {
                self.0.fetch_add(value, Ordering::Relaxed);
            }
            fn absolute(&self, value: u64) {
                self.0.store(value, Ordering::Relaxed);
            }
        }

        /// Counter totals per `name{label=value,…}`.
        #[derive(Default)]
        struct Capture(Mutex<BTreeMap<String, Arc<Cell>>>);
        impl Capture {
            fn get(&self, series: &str) -> u64 {
                self.0
                    .lock()
                    .unwrap()
                    .get(series)
                    .map_or(0, |c| c.0.load(Ordering::Relaxed))
            }
        }
        impl Recorder for Capture {
            fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
            fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
                let labels: Vec<String> = key
                    .labels()
                    .map(|l| format!("{}={}", l.key(), l.value()))
                    .collect();
                let series = format!("{}{{{}}}", key.name(), labels.join(","));
                Counter::from_arc(self.0.lock().unwrap().entry(series).or_default().clone())
            }
            fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
                Gauge::noop()
            }
            fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
                Histogram::noop()
            }
        }

        let capture = Capture::default();
        metrics::with_local_recorder(&capture, || {
            read_failed(READ_FAILURE_ERROR);
            read_failed(READ_FAILURE_ERROR);
            read_failed(READ_FAILURE_TIMEOUT);
        });
        assert_eq!(
            capture.get("ai_runtime_switch_read_failures_total{reason=error}"),
            2
        );
        assert_eq!(
            capture.get("ai_runtime_switch_read_failures_total{reason=timeout}"),
            1
        );
        assert_eq!(capture.0.lock().unwrap().len(), 2, "no other series");
    }

    #[test]
    fn every_combination_is_its_own_index() {
        for (i, c) in COMBOS.iter().enumerate() {
            let back = usize::from(c.enabled)
                | usize::from(c.fields) << 1
                | usize::from(c.chat) << 2
                | usize::from(c.semantic_search) << 3
                | usize::from(c.workflow_nodes) << 4;
            assert_eq!(back, i);
        }
        for s in SwitchSurface::ALL {
            assert_eq!(SwitchSurface::parse(s.as_str()), Some(s));
        }
    }
}
