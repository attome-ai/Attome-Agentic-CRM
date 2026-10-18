//! AA1-T5: where one request's time went, for the `Server-Timing` response
//! header `attome-server` writes.
//!
//! The server's timing layer opens a [`scope`] per request; inside it, the
//! layers and calls that know a phase add to it: authentication and
//! permissions through markers around their layers, the database through the
//! `sqlx::query` events, outside calls through `attome_outbound::call`. It
//! lives here, the lowest crate, so `attome-outbound` can add to it. Outside
//! a scope (a job, boot code, a test) every call is a no-op.
//!
//! Request-scoped only (guidelines §5): nothing is shared between requests
//! or nodes, and nothing but phase names and durations is kept.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The phases a request is split into. `mw` (the middleware's own time) is
/// what is left of the total once the others that ran outside the handler
/// are taken away; `db` and `ext` are counted wherever they ran, so they
/// overlap `auth`, `perm` and `app`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Authentication (the `authn` layer).
    Auth,
    /// Permission resolution (the `authz` layer).
    Perm,
    /// SQL statements, summed.
    Db,
    /// The handler, its response serialization included.
    App,
    /// Calls to outside services, summed.
    Ext,
}

impl Phase {
    const ALL: [Phase; 5] = [Phase::Auth, Phase::Perm, Phase::Db, Phase::App, Phase::Ext];

    fn index(self) -> usize {
        match self {
            Phase::Auth => 0,
            Phase::Perm => 1,
            Phase::Db => 2,
            Phase::App => 3,
            Phase::Ext => 4,
        }
    }

    /// The name in the header.
    pub fn name(self) -> &'static str {
        match self {
            Phase::Auth => "auth",
            Phase::Perm => "perm",
            Phase::Db => "db",
            Phase::App => "app",
            Phase::Ext => "ext",
        }
    }
}

/// One request's measurements.
#[derive(Debug, Default, Clone)]
pub struct Timings {
    spent: [Duration; 5],
    open: [Option<Instant>; 5],
    admin: bool,
}

impl Timings {
    /// The time spent in `phase`.
    pub fn get(&self, phase: Phase) -> Duration {
        self.spent[phase.index()]
    }

    /// Whether the caller was resolved as an administrator.
    pub fn admin(&self) -> bool {
        self.admin
    }

    /// Ends every phase still open at `now` (a layer that answered without
    /// calling the next one never reaches its end marker).
    pub fn close_all(&mut self, now: Instant) {
        for phase in Phase::ALL {
            if let Some(start) = self.open[phase.index()].take() {
                self.spent[phase.index()] += now.saturating_duration_since(start);
            }
        }
    }

    /// The `Server-Timing` value for a request that took `total`: `mw`
    /// first, then each phase, durations in milliseconds.
    pub fn header_value(&self, total: Duration) -> String {
        let outside_app = self.get(Phase::Auth) + self.get(Phase::Perm) + self.get(Phase::App);
        let mw = total.saturating_sub(outside_app);
        let mut out = format!("mw;dur={:.3}", millis(mw));
        for phase in Phase::ALL {
            out.push_str(&format!(
                ", {};dur={:.3}",
                phase.name(),
                millis(self.get(phase))
            ));
        }
        out
    }
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

tokio::task_local! {
    static TIMINGS: Arc<Mutex<Timings>>;
}

fn with<R>(f: impl FnOnce(&mut Timings) -> R) -> Option<R> {
    TIMINGS
        .try_with(|timings| {
            let mut guard = timings
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            f(&mut guard)
        })
        .ok()
}

/// Runs `fut` as one timed request and returns what it measured.
pub async fn scope<F: Future>(fut: F) -> (F::Output, Timings) {
    let timings = Arc::new(Mutex::new(Timings::default()));
    let output = TIMINGS.scope(Arc::clone(&timings), fut).await;
    let measured = timings
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    (output, measured)
}

/// Whether the current task is inside a timed request.
pub fn active() -> bool {
    TIMINGS.try_with(|_| ()).is_ok()
}

/// Adds `spent` to `phase`.
pub fn add(phase: Phase, spent: Duration) {
    with(|timings| timings.spent[phase.index()] += spent);
}

/// Starts `phase` now.
pub fn open(phase: Phase) {
    let now = Instant::now();
    with(|timings| timings.open[phase.index()] = Some(now));
}

/// Ends `phase`, adding the time since [`open`].
pub fn close(phase: Phase) {
    let now = Instant::now();
    with(|timings| {
        if let Some(start) = timings.open[phase.index()].take() {
            timings.spent[phase.index()] += now.saturating_duration_since(start);
        }
    });
}

/// Records whether the caller is an administrator.
pub fn note_admin(admin: bool) {
    with(|timings| timings.admin = admin);
}

/// Runs `fut`, adding its time to `phase`.
pub async fn timed<F: Future>(phase: Phase, fut: F) -> F::Output {
    if !active() {
        return fut.await;
    }
    let start = Instant::now();
    let output = fut.await;
    add(phase, start.elapsed());
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn outside_a_scope_nothing_is_recorded() {
        add(Phase::Db, Duration::from_millis(5));
        open(Phase::Auth);
        close(Phase::Auth);
        assert!(!active());
    }

    #[tokio::test]
    async fn phases_add_up_inside_a_scope() {
        let ((), timings) = scope(async {
            add(Phase::Db, Duration::from_millis(2));
            add(Phase::Db, Duration::from_millis(3));
            open(Phase::Auth);
            close(Phase::Auth);
            note_admin(true);
        })
        .await;
        assert_eq!(timings.get(Phase::Db), Duration::from_millis(5));
        assert!(timings.admin());
        let header = timings.header_value(Duration::from_millis(10));
        assert!(header.starts_with("mw;dur="), "{header}");
        for name in ["auth", "perm", "db", "app", "ext"] {
            assert!(header.contains(&format!("{name};dur=")), "{header}");
        }
    }
}
