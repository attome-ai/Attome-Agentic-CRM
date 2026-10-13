//! Dashboard 10/10 Phase 6 ("My Work and Action Center") — a read model over
//! actionable work other engines already own. Dashboard never stores or
//! decides work; this trait is the seam a provider implements to be listed.
//!
//! Same shape as [`crate::model::EngineModel`] (a plain, `Send + Sync +
//! 'static` trait, boxed into a registry) except its methods are async —
//! this crate has no precedent for a dyn-compatible async trait of its own,
//! so it follows `attome_db::hook::BeforeCommit`'s established convention (a
//! manually boxed future, not the `async_trait` crate, which this workspace
//! does not use).
//!
//! **Visibility rule** every implementation must enforce, in both `list` and
//! `actions` (the plan's own words, `document/xrm/pending_full_plan/
//! dashboard-10-10.md`'s "My Work architecture"): an item is visible to the
//! caller only when (a) the source record is readable
//! (`attome_records::entity_crud::access::require_record_access`, from
//! whichever crate the provider already depends on for its own routes) AND
//! (b) the caller is eligible to act on it *right now* (approver resolution
//! including delegation — `attome_audit::approval::resolve_step_approvers` —
//! or `attome_core::available_transitions`) AND (c) the item is still
//! open. This trait cannot enforce that itself — the same "declaration, not
//! enforcement" posture `attome_server::authz`'s `SelfService`/bare
//! `RecordScoped` already document for HTTP routes. `attome-core` itself
//! never depends on `attome-records`/`attome-audit` (layer direction,
//! guidelines §1) — only a provider implementation, in whichever crate
//! already depends on them, does the actual check.
//!
//! Dashboard implements no provider of its own: `attome-dashboard` owns
//! `dashboard_decision`, which is a genuine provider (see the plan's
//! table), but the Dashboard *presentation* (the Action Center widget) is a
//! caller of this registry, not a provider in it.

use std::future::Future;
use std::pin::Pin;

use attome_server::security::SecurityContext;
use attome_types::{AppError, CursorPage};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::state::EngineState;

/// The future every [`MyWorkProvider`] method returns — same shape as
/// `attome_db::hook::HookFuture`, this crate's own established pattern for a
/// dyn-compatible async trait method.
pub type MyWorkFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// One authoritative action a caller may take on a [`MyWorkItem`] — never
/// business logic of its own, only a pointer to the route that already owns
/// it. Dashboard (or any other caller) invokes `route` directly; the
/// provider never evaluates the action, only names it (the plan's "Dashboard
/// implements no business rule").
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MyWorkAction {
    /// Stable key for the action, e.g. `"approve"`, `"reject"` — not
    /// displayed directly.
    pub key: String,
    /// HTTP method the action's route expects.
    pub method: String,
    /// The authoritative route, with the item's own ids already substituted
    /// (e.g. `/api/v1/approvals/{id}/decide`) — never a template the caller
    /// has to fill in.
    pub route: String,
}

/// One actionable work item, from whichever provider owns it.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MyWorkItem {
    /// The provider's own `name()` — lets a caller group/filter without a
    /// second lookup. Owned, not `&'static str`: `#[derive(Deserialize)]`
    /// cannot prove a borrowed field outlives an arbitrary deserializer
    /// lifetime, and every construction site already has a `&'static str`
    /// literal to hand, so `.to_string()` there costs nothing that matters.
    pub provider: String,
    /// The owning entity's logical name, for a client that wants to link to
    /// the record or run its own further checks.
    pub source_entity: String,
    pub record_id: Uuid,
    pub title: String,
    pub due_date: Option<DateTime<Utc>>,
    /// Free-form, provider-defined (`"high"`/`"1"`/...) — Dashboard does not
    /// interpret it beyond display.
    pub priority: Option<String>,
    /// The record's own state/status label, for display only.
    pub state: String,
    /// Resolved once, at list time, under this same visibility rule —
    /// `actions()` re-resolves them fresh at click time, since eligibility
    /// can change between the two (the plan's "checked at list time and
    /// again at action time").
    pub actions: Vec<MyWorkAction>,
    /// The optimistic-concurrency version the item's `actions` routes expect
    /// back, when they take one — for an approval that is the approval
    /// request's current `row_version`, which `POST /api/v1/approvals/{id}/
    /// decide` requires. Omitted (`None`) by every provider whose actions
    /// need no version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_version: Option<i64>,
}

/// A page of [`MyWorkItem`]s in the platform's keyset envelope
/// ([`CursorPage`]): `next_cursor` is omitted on the last page.
// A newtype, not `type MyWorkPage = CursorPage<MyWorkItem>`: utoipa's path
// macro cannot see an alias's generic argument, so the alias published a
// `MyWorkItem` `$ref` that resolved to nothing (BTY-12). `transparent` keeps
// the wire shape exactly `CursorPage`'s.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(transparent)]
pub struct MyWorkPage(pub CursorPage<MyWorkItem>);

impl MyWorkPage {
    pub fn new(items: Vec<MyWorkItem>, next_cursor: Option<String>) -> Self {
        Self(CursorPage::new(items, next_cursor))
    }
}

/// Implemented by whichever engine owns a kind of actionable work — the
/// Approvals/Workflow/Service/Project/Decisions providers the plan names.
/// Registered into a `Vec<Box<dyn MyWorkProvider>>`-shaped collector the
/// same way `EngineModel` is (see `attome-server`'s `ModelRegistry` for that
/// half) — a second, parallel registry, since a provider and an `EngineModel`
/// answer unrelated questions (route/licence composition vs. "what does
/// this caller have to do").
pub trait MyWorkProvider: Send + Sync + 'static {
    /// Stable identifier, also the value [`MyWorkItem::provider`] carries.
    fn name(&self) -> &'static str;

    /// How many open items this provider has for the caller — cheap, no
    /// item bodies, for a sidebar/tile count. Must apply the same
    /// visibility rule `list` does, or the count and the list disagree.
    fn count<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
    ) -> MyWorkFuture<'a, usize>;

    /// A page of this provider's open items visible to the caller, under
    /// the trait's own visibility rule (see module doc).
    fn list<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        cursor: Option<&'a str>,
        limit: usize,
    ) -> MyWorkFuture<'a, MyWorkPage>;

    /// Re-resolves the actions available on one specific item, fresh, at
    /// the moment the caller is about to act — never trusts `list`'s
    /// earlier snapshot. `record_id` names the item within this provider.
    /// Returns an empty `Vec` (not an error) for an item that is no longer
    /// actionable by this caller — same "the item disappears" posture the
    /// plan's concurrency section describes for a decided approval.
    fn actions<'a>(
        &'a self,
        state: &'a EngineState,
        ctx: &'a SecurityContext,
        record_id: Uuid,
    ) -> MyWorkFuture<'a, Vec<MyWorkAction>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use utoipa::OpenApi;

    #[utoipa::path(get, path = "/my-work", responses((status = 200, body = MyWorkPage)))]
    #[allow(dead_code)]
    fn list_my_work() {}

    // Mirrors attome-server's `my_work` fragment, which registers `MyWorkItem`
    // because the generic envelope inlines it and the Angular client names it.
    #[derive(OpenApi)]
    #[openapi(paths(list_my_work), components(schemas(MyWorkItem)))]
    struct Doc;

    fn collect_refs(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::Object(m) => {
                for (k, x) in m {
                    if k == "$ref"
                        && let Some(s) = x.as_str()
                    {
                        out.push(s.to_string());
                    }
                    collect_refs(x, out);
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| collect_refs(x, out)),
            _ => {}
        }
    }

    /// BTY-12: the `MyWorkPage` response must publish a document whose every
    /// `$ref` resolves, or `npm run generate:api` refuses it. The component
    /// keeps its name because the Angular client reads `Schemas['MyWorkPage']`
    /// and `Schemas['MyWorkItem']`.
    #[test]
    fn my_work_page_openapi_refs_all_resolve() {
        let doc = serde_json::to_value(Doc::openapi()).expect("serialize");
        for name in ["MyWorkPage", "MyWorkItem", "MyWorkAction"] {
            assert!(
                doc["components"]["schemas"].get(name).is_some(),
                "{name} component missing: {}",
                doc["components"]
            );
        }
        let mut refs = Vec::new();
        collect_refs(&doc, &mut refs);
        assert!(!refs.is_empty());
        for r in refs {
            let name = r
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("unexpected ref {r}"));
            assert!(
                doc["components"]["schemas"].get(name).is_some(),
                "unresolvable $ref {r}; schemas: {:?}",
                doc["components"]["schemas"]
                    .as_object()
                    .map(|m| m.keys().collect::<Vec<_>>())
            );
        }
    }

    /// BTY-12 / BTY-F6: one keyset shape — the last page omits `next_cursor`
    /// exactly as `CursorPage` does, rather than sending `null`.
    #[test]
    fn my_work_page_serializes_as_the_canonical_cursor_page() {
        let last = serde_json::to_value(MyWorkPage::new(Vec::new(), None)).expect("serialize");
        assert_eq!(last, serde_json::json!({ "items": [] }));
        let more = serde_json::to_value(MyWorkPage::new(Vec::new(), Some("c1".into())))
            .expect("serialize");
        assert_eq!(
            more,
            serde_json::json!({ "items": [], "next_cursor": "c1" })
        );
    }
}
