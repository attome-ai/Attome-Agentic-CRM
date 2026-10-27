//! Q14-T3: entities whose records are controlled by a parent record.
//!
//! An entity's settings (`attome_model::kinds::entity_settings`) may say
//! `"access": { "mode": "controlled_by_parent", "lookup": "<attribute id>" }`:
//! one many-to-one lookup of the entity names the parent. A person then sees
//! and changes a child record exactly when they may do the same to its parent
//! record ([`crate::rls`] compiles the parent's filter into
//! `EXISTS (SELECT 1 FROM parent WHERE parent.id = child.lookup AND ...)`),
//! and their level on the child is their level on the parent
//! ([`crate::db::resolve_entity_access_level`]). An explicit deny on the child
//! record still wins.
//!
//! **One hop.** The parent's filter is the parent's own role levels, shares,
//! rules and deny. A parent that is itself controlled by its parent is not
//! followed further.
//!
//! - **Source of truth:** the published metadata version's cooked
//!   `entity_settings` artefacts, resolved against `attribute_info` and
//!   `entity_info` when a version is loaded.
//! - **Key:** the child entity id.
//! - **Invalidation:** [`install`] replaces the whole set; the metadata
//!   runtime calls it every time this node loads or follows a version.
//! - **Cold start and failure:** empty until the first version is loaded at
//!   boot: every entity keeps its own access. When resolving fails the
//!   previous set stays, and the next load retries; a lookup that no longer
//!   resolves is left out and named in the log.
//!
//! Every name spliced into SQL is a validated logical name from
//! `attribute_info`/`entity_info`, quoted with `quote_ident`; every id is a
//! UUID written by its own formatter. Never request data.
//!
//! Search and audit lists, which filter many entities at once, apply the
//! child's own levels, as they do for sharing rules: they show less, never
//! more, than the child's own roles allow.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// `attribute_info.type` for a lookup.
const LOOKUP_TYPE: i32 = 11;

/// One child entity's parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentLink {
    pub child: Uuid,
    /// The child's lookup column (a validated logical name).
    pub lookup_column: String,
    pub parent: Uuid,
    /// The parent entity's logical name, which is also its table.
    pub parent_name: String,
}

type Links = Arc<HashMap<Uuid, ParentLink>>;

/// (attribute id, entity, logical name, type, parent entity id, parent name).
type AttributeRow = (
    Uuid,
    Option<Uuid>,
    Option<String>,
    Option<i32>,
    Uuid,
    String,
);

fn slot() -> &'static RwLock<Links> {
    static SLOT: OnceLock<RwLock<Links>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Arc::new(HashMap::new())))
}

/// Replaces every link. A link whose parent is the child itself is left out.
pub fn install(links: impl IntoIterator<Item = ParentLink>) {
    let map: HashMap<Uuid, ParentLink> = links
        .into_iter()
        .filter(|l| l.parent != l.child)
        .map(|l| (l.child, l))
        .collect();
    // A poisoned lock still holds a whole map; replacing it is safe.
    *slot().write().unwrap_or_else(|e| e.into_inner()) = Arc::new(map);
}

/// The parent of `child`, when its records are controlled by one.
pub fn link_for(child: Uuid) -> Option<ParentLink> {
    slot()
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(&child)
        .cloned()
}

/// The links of `(child entity, lookup attribute)` pairs: each attribute must
/// be a live lookup of that entity to a live entity with valid logical names.
/// A pair that does not resolve is left out and named in the log.
pub async fn resolve(db: &DbPool, pairs: &[(Uuid, Uuid)]) -> Result<Vec<ParentLink>, AppError> {
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let attributes: Vec<Uuid> = pairs.iter().map(|(_, a)| *a).collect();
    let rows: Vec<AttributeRow> = sqlx::query_as(
        "SELECT a.id, a.entity_ref, a.logicalname, a.\"type\", pe.id, pe.logicalname \
             FROM attribute_info a \
             JOIN entity_info pe ON pe.id = a.lookup_entity_ref \
                AND COALESCE(pe.is_active, true) = true \
             WHERE a.id = ANY($1) AND COALESCE(a.is_active, true) = true",
    )
    .bind(&attributes)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let by_attribute: HashMap<Uuid, _> = rows.into_iter().map(|r| (r.0, r)).collect();
    let mut links = Vec::with_capacity(pairs.len());
    for (child, attribute) in pairs {
        let link = by_attribute.get(attribute).and_then(
            |(_, entity, column, kind, parent, parent_name)| {
                let column = column.as_deref()?;
                (*entity == Some(*child)
                    && *kind == Some(LOOKUP_TYPE)
                    && attome_db::ident::is_logical_name(column)
                    && attome_db::ident::is_logical_name(parent_name))
                .then(|| ParentLink {
                    child: *child,
                    lookup_column: column.to_owned(),
                    parent: *parent,
                    parent_name: parent_name.clone(),
                })
            },
        );
        match link {
            Some(link) => links.push(link),
            None => tracing::warn!(
                %child,
                %attribute,
                "controlled-by-parent access: the lookup is not a live lookup of the entity; \
                 the entity keeps its own access"
            ),
        }
    }
    Ok(links)
}
