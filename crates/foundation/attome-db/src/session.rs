//! BDB-F11 / plan 4.1 — a process-wide count of open unpooled sessions.
//!
//! The pools report their own size; an unpooled `PgConnection` (a workflow
//! execution claim, a secret-rewrap lock, an attribute-index build, the
//! platform-seed lock) is invisible to every pool metric and to the boot
//! capacity report. Wrapping it in [`UnpooledSession`] counts it for exactly
//! as long as it is alive, and [`unpooled_sessions_open`] is what attome-server's
//! metrics refresh loop exports as `db_unpooled_sessions_open` — attome-db stays
//! metrics-free, as it does for the acquire-timeout hook.

use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};

use sqlx::{Connection as _, PgConnection};

static OPEN: AtomicUsize = AtomicUsize::new(0);

/// How many [`UnpooledSession`]s this process holds right now.
pub fn unpooled_sessions_open() -> usize {
    OPEN.load(Ordering::Relaxed)
}

/// Decrements on drop, so a session that is dropped without [`UnpooledSession::close`]
/// (an early `?`, a panic, a cancelled future) is still uncounted.
struct OpenGuard;

impl OpenGuard {
    fn acquire() -> Self {
        OPEN.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        OPEN.fetch_sub(1, Ordering::Relaxed);
    }
}

/// One unpooled PostgreSQL session, counted while it is open. Derefs to
/// [`PgConnection`], so a caller passes `&mut *session` wherever it passed
/// `&mut conn`.
pub struct UnpooledSession {
    conn: PgConnection,
    _open: OpenGuard,
}

impl std::fmt::Debug for UnpooledSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnpooledSession").finish_non_exhaustive()
    }
}

impl UnpooledSession {
    /// Starts counting `conn`. Wrap the connection the moment a builder
    /// returns it (`create_runtime_session`, `create_migrator_connection`).
    pub fn new(conn: PgConnection) -> Self {
        Self {
            conn,
            _open: OpenGuard::acquire(),
        }
    }

    /// Closes the session gracefully (a `Terminate` message rather than a
    /// dropped socket). The count falls whether or not the close succeeds.
    pub async fn close(self) -> Result<(), sqlx::Error> {
        let Self { conn, _open } = self;
        conn.close().await
    }
}

impl From<PgConnection> for UnpooledSession {
    fn from(conn: PgConnection) -> Self {
        Self::new(conn)
    }
}

impl Deref for UnpooledSession {
    type Target = PgConnection;

    fn deref(&self) -> &PgConnection {
        &self.conn
    }
}

impl DerefMut for UnpooledSession {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.conn
    }
}
