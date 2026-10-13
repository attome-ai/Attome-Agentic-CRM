//! M01 Core C-23 ("Error discrimination at the DB boundary"): turns a
//! `sqlx::Error` fresh off a query/execute call into the right `AppError`
//! instead of the reflexive `AppError::internal(e)` almost every call site in
//! this workspace used before this existed (`document/xrm/module/M01-core/
//! master-plan.md` §7 C-23: 2,413 `internal(e)` sites, 1,522 sitting directly
//! behind a DB call — a unique-key collision or a bad foreign key surfaced
//! as an opaque 500 `internal_error` instead of a client-actionable 409/422).
//!
//! Deliberately narrow: only the four SQLSTATEs whose meaning to the caller
//! never depends on which query hit them are classified here.
//!
//! - `23505` unique_violation -> [`attome_types::AppError::Conflict`]:
//!   deterministic and client-actionable — the row (or a row sharing its key)
//!   already exists, and no amount of retrying without changing the input
//!   fixes it.
//! - `23503` foreign_key_violation -> [`attome_types::AppError::Validation`]:
//!   the request named a record that does not exist (or no longer does),
//!   the same class of client mistake generic entity/lookup validation
//!   already reports as a 422 elsewhere.
//! - `40001` serialization_failure / `40P01` deadlock_detected ->
//!   [`attome_types::AppError::Conflict`], with an explicit retry hint in the
//!   message: both are PostgreSQL telling an otherwise-correct transaction to
//!   simply run again, not a defect in the statement that hit them.
//! - `sqlx::Error::PoolTimedOut` / `PoolClosed` ->
//!   [`attome_types::AppError::Overloaded`]`("db_pool")` (503): the pool could
//!   not hand out a connection, which says nothing about the request itself
//!   (attome-db hardening Phase 1.2). `classify` is the raiser, so it logs the
//!   breaker name `Overloaded`'s contract says the raiser must log. An acquire
//!   timeout also runs the hook installed with [`set_acquire_timeout_hook`]
//!   (attome-db hardening 4.3); a closed pool doesn't.
//! - A **lost connection** — SQLSTATE class `08`, `57P01`
//!   (admin_shutdown: a switchover), `57P02` (crash_shutdown), `57P03`
//!   (cannot_connect_now), `53300` (too_many_connections), or a raw
//!   `sqlx::Error::Io`/`Tls` — -> [`attome_types::AppError::Overloaded`]
//!   `("db_unavailable")` (503, wire code unchanged: this is not a new
//!   variant, D-506/OD-4). The statement's outcome is unknown and the
//!   request is retryable; logging `event = "db.unavailable"` at `warn` is
//!   what makes it alertable, where it used to be an unremarkable 500.
//! - `55P03` lock_not_available -> `Conflict` with a retry hint: PostgreSQL
//!   declined to wait for a lock, which says nothing about the request.
//! - `57014` query_canceled (a `statement_timeout` firing) stays a masked
//!   500 — it is not safe to tell a client its request is retryable when the
//!   database may have done part of the work — but it logs
//!   `event = "db.statement_timeout"` and runs the hook installed with
//!   [`set_statement_timeout_hook`] so the condition is observable and
//!   countable rather than invisible.
//! - Everything else -> [`attome_types::AppError::internal`] (masked 500) —
//!   the exact behavior every call site already had before this function
//!   existed. `classify` is strictly additive discrimination; it never
//!   downgrades a genuine internal failure.
//!
//! A caller that already carries a more specific, human-facing message for
//! one of these codes (a "that name is taken" 409, a "no such entity" 422)
//! keeps its own check for that one code and message, and falls through to
//! `classify` only for the codes it was not already handling — see
//! `xrm_entity_engine::entity_mutation::classify_db_error` and its siblings
//! for that shape. Adopted at the entity engine (`entity_mutation.rs`,
//! `query_admin.rs`) and security db (`xrm-security/src/db.rs`) boundaries.

use std::borrow::Cow;
use std::sync::OnceLock;

use attome_types::AppError;

/// attome-db hardening 4.3: the process-wide callback run once per pool acquire
/// timeout. It keeps this crate metrics-free: `attome-server` installs a hook
/// that increments its Prometheus counter, and a process that installs none
/// (the audit binaries, `migrate`, tests) pays one `OnceLock` read.
static ACQUIRE_TIMEOUT_HOOK: OnceLock<fn()> = OnceLock::new();

/// Installs the callback [`classify`] and [`crate::tx::begin`] run on every
/// `sqlx::Error::PoolTimedOut`. A closed pool (`PoolClosed`) is not an acquire
/// timeout and doesn't run it.
///
/// Set-once for the life of the process: returns `false`, and changes
/// nothing, if a hook is already installed. The hook runs on the failing task,
/// so it must be cheap and must not block; incrementing a metrics counter is
/// the intended use.
pub fn set_acquire_timeout_hook(hook: fn()) -> bool {
    ACQUIRE_TIMEOUT_HOOK.set(hook).is_ok()
}

/// Runs the installed acquire-timeout hook, if any.
pub(crate) fn note_acquire_timeout() {
    if let Some(hook) = ACQUIRE_TIMEOUT_HOOK.get() {
        hook();
    }
}

/// BDB-F6 / 3.1b — the process-wide callback run once per `57014`
/// (`statement_timeout`) seen by [`classify`]. Same set-once, metrics-free
/// shape as [`set_acquire_timeout_hook`]: `attome-server` installs one that
/// increments `db_statement_timeouts_total`; a process that installs none
/// (the audit binaries, `migrate`, tests) pays one `OnceLock` read.
static STATEMENT_TIMEOUT_HOOK: OnceLock<fn()> = OnceLock::new();

/// Installs the callback [`classify`] runs on every `57014`. Set-once for the
/// life of the process: returns `false`, and changes nothing, if a hook is
/// already installed. Must be cheap and must not block.
pub fn set_statement_timeout_hook(hook: fn()) -> bool {
    STATEMENT_TIMEOUT_HOOK.set(hook).is_ok()
}

/// Runs the installed statement-timeout hook, if any.
pub(crate) fn note_statement_timeout() {
    if let Some(hook) = STATEMENT_TIMEOUT_HOOK.get() {
        hook();
    }
}

/// BDB-F9 / 3.2 — the SQLSTATE attached to a driver error, when there is one.
/// Exported so a caller that carries its own human-facing message for a code
/// (a "that name is taken" 409, a "no such entity" 422) can test for it
/// without re-implementing the `as_database_error().code()` unwrap that used
/// to be copied into 5 local `is_unique*` helpers.
///
/// Returns a [`Cow`] rather than `&str` because `DatabaseError::code`'s
/// contract permits an owned value; the PostgreSQL driver this workspace uses
/// always borrows, so the common path allocates nothing. Compare with
/// `.as_deref() == Some("23505")`.
pub fn sqlstate(error: &sqlx::Error) -> Option<Cow<'_, str>> {
    error
        .as_database_error()
        .and_then(|db_error| db_error.code())
}

/// `true` iff `error` is SQLSTATE `23505` (unique_violation). The shorthand
/// for callers that already have a more specific message than
/// [`classify`]'s generic one.
pub fn is_unique_violation(error: &sqlx::Error) -> bool {
    sqlstate(error).as_deref() == Some("23505")
}

/// Classifies a `sqlx::Error` into the `AppError` a caller should return.
/// Never forwards the driver's own error text to the client — masking stays
/// `AppError::internal`'s job, and this function only ever constructs the
/// client-facing variants below with a fixed, static/generic message.
pub fn classify(error: sqlx::Error) -> AppError {
    if matches!(error, sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed) {
        tracing::warn!(
            error = %error,
            breaker = "db_pool",
            "database connection pool could not provide a connection"
        );
        if matches!(error, sqlx::Error::PoolTimedOut) {
            note_acquire_timeout();
        }
        return AppError::Overloaded("db_pool");
    }
    // A transport-level loss. The connection died rather than the statement
    // being rejected, so the outcome is unknown and retry is meaningful —
    // the same 503 class as an exhausted pool (OD-4: no new variant).
    if matches!(error, sqlx::Error::Io(_) | sqlx::Error::Tls(_)) {
        return db_unavailable(&error);
    }
    // Owner it: the fallback arms below move `error` by value.
    let code = sqlstate(&error).map(|code| code.into_owned());
    match code.as_deref() {
        Some("23505") => AppError::Conflict("a record with this key already exists"),
        Some("23503") => AppError::Validation(
            "the request references a record that does not exist or has been removed".to_string(),
        ),
        Some("40001") | Some("40P01") => AppError::Conflict(
            "the database detected a conflicting concurrent transaction; retry the request",
        ),
        Some("55P03") => {
            AppError::Conflict("the database could not acquire a lock in time; retry the request")
        }
        Some("57014") => {
            tracing::warn!(
                event = "db.statement_timeout",
                error = %error,
                "a statement hit statement_timeout; the operation's outcome is unknown"
            );
            note_statement_timeout();
            AppError::internal(error)
        }
        Some(code) if is_connection_loss_sqlstate(code) => db_unavailable(&error),
        _ => AppError::internal(error),
    }
}

/// The 503 path for a lost connection: one `warn` naming the event operators
/// alert on, then the shared `Overloaded` variant whose wire code stays
/// `overloaded` (OD-4).
fn db_unavailable(error: &sqlx::Error) -> AppError {
    tracing::warn!(
        event = "db.unavailable",
        breaker = "db_unavailable",
        error = %error,
        "database connection lost; the operation's outcome is unknown and the request is \
         retryable"
    );
    AppError::Overloaded("db_unavailable")
}

/// SQLSTATEs that mean the connection — not the statement — failed. Class `08`
/// is the whole connection-exception class; the four named codes are the
/// server-side variants PostgreSQL raises without a class-`08` code.
fn is_connection_loss_sqlstate(code: &str) -> bool {
    code.starts_with("08") || matches!(code, "57P01" | "57P02" | "57P03" | "53300")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `sqlx::Error` variants with no underlying `DatabaseError` at all (a
    /// missing row, a driver/protocol-level failure) must still mask to
    /// `Internal` rather than panicking or being misclassified — `classify`
    /// only ever recognizes an actual PostgreSQL SQLSTATE.
    #[test]
    fn a_non_database_error_masks_to_internal() {
        match classify(sqlx::Error::RowNotFound) {
            AppError::Internal(_) => {}
            other => panic!("expected Internal for a non-database sqlx error, got {other:?}"),
        }
    }

    /// attome-db hardening Phase 1.2: a pool that can't hand out a connection
    /// is a 503 `Overloaded("db_pool")`, not a masked 500.
    #[test]
    fn a_pool_timeout_is_overloaded() {
        match classify(sqlx::Error::PoolTimedOut) {
            AppError::Overloaded(breaker) => assert_eq!(breaker, "db_pool"),
            other => panic!("expected Overloaded(\"db_pool\") for PoolTimedOut, got {other:?}"),
        }
    }

    #[test]
    fn a_closed_pool_is_overloaded() {
        match classify(sqlx::Error::PoolClosed) {
            AppError::Overloaded(breaker) => assert_eq!(breaker, "db_pool"),
            other => panic!("expected Overloaded(\"db_pool\") for PoolClosed, got {other:?}"),
        }
    }

    #[test]
    fn a_protocol_error_masks_to_internal() {
        let err = sqlx::Error::Protocol("simulated protocol desync".to_string());
        match classify(err) {
            AppError::Internal(_) => {}
            other => panic!("expected Internal for a protocol-level sqlx error, got {other:?}"),
        }
    }

    /// A hand-built `DatabaseError` carrying an arbitrary SQLSTATE. The
    /// unit-level counterpart of `tests/classify.rs`'s live `RAISE ... USING
    /// ERRCODE`: it covers the classes a live reproduction cannot cheaply
    /// raise (a switchover's `57P01`, `53300`, the whole class-`08` range)
    /// without a synthetic backend.
    #[derive(Debug)]
    struct SyntheticDbError {
        code: &'static str,
    }

    impl std::fmt::Display for SyntheticDbError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "synthetic database error {}", self.code)
        }
    }

    impl std::error::Error for SyntheticDbError {}

    impl sqlx::error::DatabaseError for SyntheticDbError {
        fn message(&self) -> &str {
            "synthetic database error"
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(Cow::Borrowed(self.code))
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }

    fn synthetic(code: &'static str) -> sqlx::Error {
        sqlx::Error::Database(Box::new(SyntheticDbError { code }))
    }

    /// BDB-F6 / 3.1a — a connection lost mid-statement is a retryable 503, not
    /// an opaque 500. Class `08` is the whole connection-exception class; the
    /// four named codes are the server-side variants PostgreSQL raises without
    /// a class-`08` code (a switchover, an admin shutdown, too many
    /// connections).
    #[test]
    fn connection_loss_codes_are_overloaded_db_unavailable() {
        for code in [
            "08000", "08001", "08003", "08004", "08006", "08007", "08P01", "57P01", "57P02",
            "57P03", "53300",
        ] {
            match classify(synthetic(code)) {
                AppError::Overloaded(breaker) => assert_eq!(breaker, "db_unavailable", "{code}"),
                other => panic!(
                    "expected Overloaded(\"db_unavailable\") for SQLSTATE {code}, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn an_io_error_is_overloaded_db_unavailable() {
        let err = sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "simulated reset",
        ));
        match classify(err) {
            AppError::Overloaded(breaker) => assert_eq!(breaker, "db_unavailable"),
            other => {
                panic!("expected Overloaded(\"db_unavailable\") for a lost socket, got {other:?}")
            }
        }
    }

    #[test]
    fn lock_not_available_is_a_conflict_with_a_retry_hint() {
        match classify(synthetic("55P03")) {
            AppError::Conflict(message) => assert!(
                message.to_ascii_lowercase().contains("retry"),
                "expected a retry hint in the conflict message, got: {message}"
            ),
            other => panic!("expected Conflict for SQLSTATE 55P03, got {other:?}"),
        }
    }

    /// `57014` is not safe to present to a client as retryable (the database
    /// may have done part of the work), so it stays a masked 500 — but it must
    /// be observable. This is the only test in the lib binary that classifies
    /// `57014`, so the process-wide set-once hook's counter is deterministic.
    #[test]
    fn a_statement_timeout_stays_internal_and_runs_the_hook_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static CALLS: AtomicUsize = AtomicUsize::new(0);
        fn count_call() {
            CALLS.fetch_add(1, Ordering::SeqCst);
        }
        assert!(
            set_statement_timeout_hook(count_call),
            "the first install must succeed"
        );
        assert!(
            !set_statement_timeout_hook(count_call),
            "the statement-timeout hook is set-once"
        );
        match classify(synthetic("57014")) {
            AppError::Internal(_) => {}
            other => panic!("expected Internal for SQLSTATE 57014, got {other:?}"),
        }
        assert_eq!(
            CALLS.load(Ordering::SeqCst),
            1,
            "classify runs the statement-timeout hook exactly once"
        );
    }

    /// BDB-F9 / 3.2 — the exported helpers: `sqlstate` returns the code,
    /// `is_unique_violation` the one shorthand callers with their own message
    /// need.
    #[test]
    fn sqlstate_and_is_unique_violation_are_exported() {
        let unique = synthetic("23505");
        assert_eq!(sqlstate(&unique).as_deref(), Some("23505"));
        assert!(is_unique_violation(&unique));

        let foreign_key = synthetic("23503");
        assert_eq!(sqlstate(&foreign_key).as_deref(), Some("23503"));
        assert!(!is_unique_violation(&foreign_key));

        assert_eq!(sqlstate(&sqlx::Error::RowNotFound), None);
    }
}
