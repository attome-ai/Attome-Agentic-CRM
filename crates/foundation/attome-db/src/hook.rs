//! A caller-supplied step that runs inside a base-layer transaction,
//! immediately before it commits (audit plan item 3.6 and the part A D-062
//! gap).
//!
//! `base-*` crates own mutations whose audit event lives in `xrm-audit`, a
//! crate they can never depend on (layer guard, guidelines §1). Writing the
//! event after the base function committed is not atomic: the mutation can
//! commit with no event (D-062). [`BeforeCommit`] inverts the dependency
//! instead. A base function that commits its own transaction takes a hook,
//! runs it with that transaction and the value it is about to return, and
//! commits only if the hook succeeds. An `xrm-*` caller passes a hook that
//! writes the audit event; a failed write rolls the base mutation back.
//!
//! The hook runs on the same connection, so it must do database work only:
//! no HTTP, Redis, object storage or other external I/O (guidelines §4).
//! [`NoHook`] keeps every existing call site's behavior.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;

use crate::Tx;

/// The future a [`BeforeCommit`] hook returns.
pub type HookFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AppError>> + Send + 'a>>;

/// Runs inside a base-layer transaction just before it commits, with the
/// value the base function is about to return. An `Err` rolls the whole
/// transaction back and is returned to the caller unchanged.
pub trait BeforeCommit<T: ?Sized>: Send + Sync {
    fn before_commit<'a>(&'a self, tx: &'a mut Tx<'_>, committed: &'a T) -> HookFuture<'a>;
}

/// Two hooks run in order in the same transaction: the first, then the
/// second, and an `Err` from either rolls the whole transaction back. For a
/// caller whose transition has two independent obligations — its audit event
/// and a projection another layer owns — without either knowing the other.
pub struct Chain<'h, T: ?Sized>(pub &'h dyn BeforeCommit<T>, pub &'h dyn BeforeCommit<T>);

impl<T: ?Sized> std::fmt::Debug for Chain<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chain").finish_non_exhaustive()
    }
}

impl<T: ?Sized + Sync> BeforeCommit<T> for Chain<'_, T> {
    fn before_commit<'a>(&'a self, tx: &'a mut Tx<'_>, committed: &'a T) -> HookFuture<'a> {
        Box::pin(async move {
            self.0.before_commit(tx, committed).await?;
            self.1.before_commit(tx, committed).await
        })
    }
}

/// The hook that does nothing: the base function behaves exactly as it did
/// before hooks existed.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHook;

impl<T: ?Sized + Sync> BeforeCommit<T> for NoHook {
    fn before_commit<'a>(&'a self, _tx: &'a mut Tx<'_>, _committed: &'a T) -> HookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}
