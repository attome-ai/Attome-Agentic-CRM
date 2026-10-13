//! Solution 7 Phase 2 (D-788; `SOLUTION-7-PHASE-2-DESIGN.md` §7.4) — the
//! field reference-hook registry.
//!
//! Almost every reference to a field is its name (`logicalname`): view
//! columns and filters, stored-query SQL, rule targets and expressions, state
//! models, workflow nodes, labels (`e.f`, `e.f.v`), field-security entries,
//! lineage rows, and customer objects. A rename in place and a real delete
//! therefore run every registered hook inside the executor's transaction:
//!
//! - [`FieldReferenceHook::scan`] reports the references and the
//!   **blockers** (references in *our* layers the hook cannot rewrite or
//!   remove safely: an ambiguous identifier in our stored query, a grant
//!   condition that would widen access if removed, ...). Any blocker refuses
//!   the whole change and is listed to the caller.
//! - [`FieldReferenceHook::rename`] rewrites the references;
//!   [`FieldReferenceHook::remove`] removes the pure consequences of the field
//!   (labels, lineage, profile entries) and adjusts or removes customer
//!   objects.
//!
//! Customer objects never block: their hook adjusts them and returns a
//! [`ReportItemDraft`]; the executor writes the drafts into the release
//! report (`crate::release_report::record_drafts`: the apply run's report
//! inside its scope, else a standalone `change` report) in a short
//! transaction of its own once the change committed (a failure there is
//! logged and labelled, never a failure of the change).
//!
//! The trait lives here (every engine crate can implement it without a new
//! edge); the registry of record is built in `attome-server`, which sees every
//! engine.

use std::future::Future;
use std::pin::Pin;

use attome_types::AppError;
use serde::Serialize;
use serde_json::Value;
use sqlx::PgConnection;
use uuid::Uuid;

/// A boxed, `Send` future borrowing the hook and the connection.
pub type HookFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// Who owns a referencing object. Customer objects are `owner_layer =
/// 'customer'`, or user-owned (personal/shared views, a user's dashboard):
/// customer data even before Phase 3 stamps layers on them (design §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefOwner {
    Ours,
    Customer,
}

/// One object that references the field.
#[derive(Debug, Clone, Serialize)]
pub struct FieldRef {
    /// The hook that found it (`"views"`, `"labels"`, ...).
    pub hook: &'static str,
    /// `view`, `stored_query`, `rule`, `label`, ...
    pub object_kind: String,
    pub object_ref: Option<Uuid>,
    /// A human name for the object (view name, rule name, label key).
    pub name: String,
    pub owner: RefOwner,
}

/// A reference in our layers that stops the change (design §3.1 step 6,
/// §3.2 plan-time blocks).
#[derive(Debug, Clone, Serialize)]
pub struct Blocker {
    pub hook: &'static str,
    pub object_kind: String,
    pub object_ref: Option<Uuid>,
    pub name: String,
    /// Why it cannot be rewritten or removed automatically.
    pub reason: String,
}

/// What [`FieldReferenceHook::scan`] found.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RefScan {
    pub refs: Vec<FieldRef>,
    pub blockers: Vec<Blocker>,
}

impl RefScan {
    pub fn extend(&mut self, other: RefScan) {
        self.refs.extend(other.refs);
        self.blockers.extend(other.blockers);
    }
}

/// A cache a hook touched; the caller refreshes each one once after commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheTouch {
    Rules,
    StateModels,
    Labels,
    Views,
    /// A field-security profile changed: its holders' cached grants.
    SecurityProfile(Uuid),
    /// A role's grants changed: its holders' cached security contexts.
    SecurityRole(Uuid),
}

/// A release-report item a hook or executor produced (design §10.2). The
/// executor records it through `crate::release_report::record_drafts`, which
/// turns it into a report item (`NewItem::from_draft`).
#[derive(Debug, Clone, Serialize)]
pub struct ReportItemDraft {
    /// `customer_object_adjusted`, `customer_object_removed`,
    /// `breaking_api_change`, `field_deleted`, `conversion_nulled`,
    /// `choice_removed_in_use`.
    pub kind: &'static str,
    pub entity: String,
    pub field: Option<String>,
    pub object_kind: Option<String>,
    pub object_ref: Option<Uuid>,
    /// Counts, names, what changed — never record values.
    pub detail: Value,
}

/// What a rename/remove run of one hook did.
#[derive(Debug, Clone, Default)]
pub struct HookOutcome {
    pub caches: Vec<CacheTouch>,
    pub report: Vec<ReportItemDraft>,
    /// Rows rewritten or removed, for logs.
    pub touched: u64,
}

impl HookOutcome {
    pub fn merge(&mut self, other: HookOutcome) {
        for cache in other.caches {
            if !self.caches.contains(&cache) {
                self.caches.push(cache);
            }
        }
        self.report.extend(other.report);
        self.touched += other.touched;
    }
}

/// One name-keyed store of field references (design §7.4).
pub trait FieldReferenceHook: Send + Sync {
    /// Stable name (`"views"`, `"field_security"`, ...).
    fn name(&self) -> &'static str;

    /// References to `entity.field`, split by owner, and the blockers a
    /// rename (`renaming = true`) or a delete (`false`) would hit. Reads
    /// only.
    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        renaming: bool,
    ) -> HookFuture<'a, RefScan>;

    /// Rewrites `entity.old` to `entity.new` in the caller's transaction.
    fn rename<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        old: &'a str,
        new: &'a str,
    ) -> HookFuture<'a, HookOutcome>;

    /// The field is being deleted: remove its consequence references, adjust
    /// or remove customer objects. Our blocking references were refused by
    /// `scan` first, so they are not here any more.
    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome>;
}

/// The registered hooks, run in order.
pub struct FieldHooks {
    hooks: Vec<Box<dyn FieldReferenceHook>>,
}

impl std::fmt::Debug for FieldHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldHooks").finish_non_exhaustive()
    }
}

impl FieldHooks {
    pub fn new(hooks: Vec<Box<dyn FieldReferenceHook>>) -> Self {
        Self { hooks }
    }

    /// The registered hook names, in order (the registry-coverage test).
    pub fn names(&self) -> Vec<&'static str> {
        self.hooks.iter().map(|h| h.name()).collect()
    }

    pub async fn scan(
        &self,
        conn: &mut PgConnection,
        entity: &str,
        field: &str,
        renaming: bool,
    ) -> Result<RefScan, AppError> {
        let mut out = RefScan::default();
        for hook in &self.hooks {
            out.extend(hook.scan(conn, entity, field, renaming).await?);
        }
        Ok(out)
    }

    pub async fn rename(
        &self,
        conn: &mut PgConnection,
        entity: &str,
        old: &str,
        new: &str,
    ) -> Result<HookOutcome, AppError> {
        let mut out = HookOutcome::default();
        for hook in &self.hooks {
            out.merge(hook.rename(conn, entity, old, new).await?);
        }
        Ok(out)
    }

    pub async fn remove(
        &self,
        conn: &mut PgConnection,
        entity: &str,
        field: &str,
    ) -> Result<HookOutcome, AppError> {
        let mut out = HookOutcome::default();
        for hook in &self.hooks {
            out.merge(hook.remove(conn, entity, field).await?);
        }
        Ok(out)
    }
}

/// The lineage store (`metadata_reference.to_attribute`, D-466):
/// rows follow a rename and go with a deleted field. Owned here with the
/// table's writer ([`crate::metadata_reference`]).
#[derive(Debug)]
pub struct LineageHook;

impl FieldReferenceHook for LineageHook {
    fn name(&self) -> &'static str {
        "lineage"
    }

    fn scan<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
        _renaming: bool,
    ) -> HookFuture<'a, RefScan> {
        Box::pin(async move {
            let rows: Vec<(String, Uuid, String)> = sqlx::query_as(
                "SELECT from_kind, from_ref, from_label FROM metadata_reference \
                 WHERE to_entity = $1 AND to_attribute = $2",
            )
            .bind(entity)
            .bind(field)
            .fetch_all(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            Ok(RefScan {
                refs: rows
                    .into_iter()
                    .map(|(kind, id, label)| FieldRef {
                        hook: "lineage",
                        object_kind: format!("lineage:{kind}"),
                        object_ref: Some(id),
                        name: label,
                        owner: RefOwner::Ours,
                    })
                    .collect(),
                blockers: Vec::new(),
            })
        })
    }

    fn rename<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        old: &'a str,
        new: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let done = sqlx::query(
                "UPDATE metadata_reference SET to_attribute = $3 \
                 WHERE to_entity = $1 AND to_attribute = $2",
            )
            .bind(entity)
            .bind(old)
            .bind(new)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            Ok(HookOutcome {
                touched: done.rows_affected(),
                ..HookOutcome::default()
            })
        })
    }

    fn remove<'a>(
        &'a self,
        conn: &'a mut PgConnection,
        entity: &'a str,
        field: &'a str,
    ) -> HookFuture<'a, HookOutcome> {
        Box::pin(async move {
            let done = sqlx::query(
                "DELETE FROM metadata_reference WHERE to_entity = $1 AND to_attribute = $2",
            )
            .bind(entity)
            .bind(field)
            .execute(&mut *conn)
            .await
            .map_err(AppError::internal)?;
            Ok(HookOutcome {
                touched: done.rows_affected(),
                ..HookOutcome::default()
            })
        })
    }
}
