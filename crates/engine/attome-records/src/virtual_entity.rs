//! L8-T1: virtual entities. A metadata entity whose rows live outside the
//! deployment's database, served by a [`VirtualProvider`] registered for it
//! ([`register`]). The generic record routes find the provider first
//! ([`provider_for`]) and call it instead of the database:
//!
//! - `GET /api/v1/{entity}` lists through [`list`]: each filter must be one
//!   the provider says it can apply ([`VirtualProvider::supports`]), else
//!   the request is refused with 422 naming the filter, rather than
//!   filtered partly; sort, page size and cursor pass through;
//! - `GET /api/v1/{entity}/{id}` reads one through [`VirtualProvider::get`];
//! - `POST` and `PATCH` reach the provider's optional `create` and `update`
//!   (405 when it has none); `DELETE` is 405.
//!
//! **Access is entity-level only** (V2-D1628 (2)): whoever holds the
//! entity's privilege for the operation (checked by the route's extractor,
//! as for any entity) reads every row the provider returns; owners, shares
//! and record filters do not apply to external rows. Record ids are UUIDs:
//! a provider maps its own keys to them (a UUIDv5 of the key, say).
//!
//! **Cache.** A list answer is kept per entity and query for [`CACHE_TTL`]:
//! the source of truth is the provider; the key is the entity and the
//! query's canonical text; at most [`CACHE_ENTRIES`] answers are kept (the
//! oldest go first); a write through `create` or `update` drops the
//! entity's answers on this node, and another node's copies expire within
//! the TTL; a provider failure is never cached; a cold cache simply asks
//! the provider. It is process-local and safe to lose.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use attome_core::filter::Filter;
use attome_types::AppError;
use serde_json::{Map, Value};
use uuid::Uuid;

/// How long a list answer is kept.
pub const CACHE_TTL: Duration = Duration::from_secs(30);
/// List answers kept at most.
pub const CACHE_ENTRIES: usize = 1_000;

/// A boxed future, so the trait stays object-safe without a macro crate.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One list request, as the provider sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct VirtualQuery {
    pub filters: Vec<Filter>,
    /// The field and whether it sorts descending.
    pub sort: Option<(String, bool)>,
    pub page_size: i64,
    pub cursor: Option<String>,
    pub select: Option<Vec<String>>,
}

impl VirtualQuery {
    /// The query as cache-key text. Pure.
    pub fn cache_key(&self, entity: &str) -> String {
        let filters: Vec<String> = self
            .filters
            .iter()
            .map(|f| {
                format!(
                    "{}|{}|{}",
                    f.field,
                    f.op,
                    f.value.as_ref().map(Value::to_string).unwrap_or_default()
                )
            })
            .collect();
        format!(
            "{entity}\u{1f}{}\u{1f}{:?}\u{1f}{}\u{1f}{:?}\u{1f}{:?}",
            filters.join("\u{1e}"),
            self.sort,
            self.page_size,
            self.cursor,
            self.select
        )
    }
}

/// One page of rows.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VirtualPage {
    pub items: Vec<Map<String, Value>>,
    pub next_cursor: Option<String>,
}

/// Where a virtual entity's rows come from.
pub trait VirtualProvider: Send + Sync {
    /// Whether the provider can apply `op` on `field` itself.
    fn supports(&self, field: &str, op: &str) -> bool;

    /// One page matching `query`.
    fn list<'a>(&'a self, query: &'a VirtualQuery) -> BoxFut<'a, Result<VirtualPage, AppError>>;

    /// One row, or `None`.
    fn get(&self, id: Uuid) -> BoxFut<'_, Result<Option<Map<String, Value>>, AppError>>;

    /// Creates a row and answers it; a read-only provider keeps the default.
    fn create<'a>(
        &'a self,
        _values: &'a Map<String, Value>,
    ) -> BoxFut<'a, Result<Map<String, Value>, AppError>> {
        Box::pin(async { Err(AppError::MethodNotAllowed) })
    }

    /// Changes a row and answers it; a read-only provider keeps the default.
    fn update<'a>(
        &'a self,
        _id: Uuid,
        _values: &'a Map<String, Value>,
    ) -> BoxFut<'a, Result<Map<String, Value>, AppError>> {
        Box::pin(async { Err(AppError::MethodNotAllowed) })
    }
}

type Providers = HashMap<String, Arc<dyn VirtualProvider>>;

fn providers() -> &'static RwLock<Providers> {
    static SLOT: OnceLock<RwLock<Providers>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(HashMap::new()))
}

type Cached = HashMap<String, (Instant, VirtualPage)>;

fn cache() -> &'static Mutex<Cached> {
    static SLOT: OnceLock<Mutex<Cached>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Makes `entity` virtual, served by `provider`; replaces an earlier one.
pub fn register(entity: &str, provider: Arc<dyn VirtualProvider>) {
    providers()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .insert(entity.to_owned(), provider);
    forget(entity);
}

/// Makes `entity` an ordinary entity again.
pub fn unregister(entity: &str) {
    providers()
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(entity);
    forget(entity);
}

/// The provider of `entity`, when it is virtual.
pub fn provider_for(entity: &str) -> Option<Arc<dyn VirtualProvider>> {
    providers()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(entity)
        .cloned()
}

/// Drops every cached answer of `entity`.
pub fn forget(entity: &str) {
    let prefix = format!("{entity}\u{1f}");
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .retain(|key, _| !key.starts_with(&prefix));
}

/// The filters `provider` cannot apply, as `field op`. Pure.
pub fn unsupported(provider: &dyn VirtualProvider, filters: &[Filter]) -> Vec<String> {
    filters
        .iter()
        .filter(|f| !provider.supports(&f.field, &f.op))
        .map(|f| format!("{} {}", f.field, f.op))
        .collect()
}

/// Lists `entity` through `provider`, from the cache when fresh.
pub async fn list(
    entity: &str,
    provider: &dyn VirtualProvider,
    query: &VirtualQuery,
) -> Result<VirtualPage, AppError> {
    let refused = unsupported(provider, &query.filters);
    if !refused.is_empty() {
        return Err(AppError::Validation(format!(
            "{entity} is a virtual entity whose source cannot filter on: {}",
            refused.join(", ")
        )));
    }
    let key = query.cache_key(entity);
    if let Some((at, page)) = cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned()
        && at.elapsed() < CACHE_TTL
    {
        return Ok(page);
    }
    let page = provider.list(query).await?;
    let mut cached = cache().lock().unwrap_or_else(|e| e.into_inner());
    if cached.len() >= CACHE_ENTRIES {
        let oldest = cached
            .iter()
            .min_by_key(|(_, (at, _))| *at)
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            cached.remove(&oldest);
        }
    }
    cached.insert(key, (Instant::now(), page.clone()));
    Ok(page)
}

/// Creates through `provider`; drops the entity's cached answers.
pub async fn create(
    entity: &str,
    provider: &dyn VirtualProvider,
    body: &Value,
) -> Result<Map<String, Value>, AppError> {
    let values = body
        .as_object()
        .ok_or_else(|| AppError::Validation("the body is an object of field values".into()))?;
    let row = provider.create(values).await?;
    forget(entity);
    Ok(row)
}

/// Updates through `provider`; drops the entity's cached answers.
pub async fn update(
    entity: &str,
    provider: &dyn VirtualProvider,
    id: Uuid,
    body: &Value,
) -> Result<Map<String, Value>, AppError> {
    let values = body
        .as_object()
        .ok_or_else(|| AppError::Validation("the body is an object of field values".into()))?;
    let row = provider.update(id, values).await?;
    forget(entity);
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Rows in memory; filters `eq` on `country` only; counts list calls.
    struct Fake {
        rows: Vec<Map<String, Value>>,
        calls: AtomicUsize,
    }

    impl VirtualProvider for Fake {
        fn supports(&self, field: &str, op: &str) -> bool {
            field == "country" && op == "eq"
        }

        fn list<'a>(
            &'a self,
            query: &'a VirtualQuery,
        ) -> BoxFut<'a, Result<VirtualPage, AppError>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let items = self
                    .rows
                    .iter()
                    .filter(|row| {
                        query.filters.iter().all(|f| {
                            row.get(&f.field).and_then(Value::as_str)
                                == f.value.as_ref().and_then(Value::as_str)
                        })
                    })
                    .take(usize::try_from(query.page_size).unwrap_or(0))
                    .cloned()
                    .collect();
                Ok(VirtualPage {
                    items,
                    next_cursor: None,
                })
            })
        }

        fn get(&self, id: Uuid) -> BoxFut<'_, Result<Option<Map<String, Value>>, AppError>> {
            Box::pin(async move {
                Ok(self
                    .rows
                    .iter()
                    .find(|row| row.get("id").and_then(Value::as_str) == Some(&id.to_string()))
                    .cloned())
            })
        }
    }

    fn row(id: Uuid, name: &str, country: &str) -> Map<String, Value> {
        json!({ "id": id.to_string(), "name": name, "country": country })
            .as_object()
            .cloned()
            .unwrap_or_default()
    }

    fn query(filters: Vec<Filter>) -> VirtualQuery {
        VirtualQuery {
            filters,
            sort: None,
            page_size: 50,
            cursor: None,
            select: None,
        }
    }

    #[tokio::test]
    async fn virtual_entity_lists_and_opens_from_a_fake_provider() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        let fake = Arc::new(Fake {
            rows: vec![row(a, "Riyadh branch", "SA"), row(b, "Cairo branch", "EG")],
            calls: AtomicUsize::new(0),
        });
        let entity = format!("virtual_branch_{}", Uuid::now_v7().simple());
        register(&entity, fake.clone());
        let provider = provider_for(&entity).expect("registered");

        let saudi = query(vec![Filter {
            field: "country".into(),
            op: "eq".into(),
            value: Some(json!("SA")),
        }]);
        let page = list(&entity, provider.as_ref(), &saudi).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0]["name"], "Riyadh branch");
        list(&entity, provider.as_ref(), &saudi).await.unwrap();
        assert_eq!(
            fake.calls.load(Ordering::SeqCst),
            1,
            "the second answer is cached"
        );

        let opened = provider.get(b).await.unwrap().expect("found");
        assert_eq!(opened["name"], "Cairo branch");

        let by_name = query(vec![Filter {
            field: "name".into(),
            op: "contains".into(),
            value: Some(json!("Cairo")),
        }]);
        let refused = list(&entity, provider.as_ref(), &by_name).await;
        assert!(
            matches!(&refused, Err(AppError::Validation(m)) if m.contains("name contains")),
            "{refused:?}"
        );

        let written = create(&entity, provider.as_ref(), &json!({ "name": "x" })).await;
        assert!(
            matches!(written, Err(AppError::MethodNotAllowed)),
            "read-only by default"
        );

        unregister(&entity);
        assert!(provider_for(&entity).is_none());
    }
}
