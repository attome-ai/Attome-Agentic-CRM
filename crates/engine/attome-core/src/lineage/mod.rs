//! L5-T2: lineage edges captured at publish.
//!
//! A published definition says what it reads, writes, derives or is
//! triggered by. An [`EdgeSource`] turns one kind of definition into
//! [`Edge`]s at attribute level when it can parse the definition, and at
//! entity level marked `entity_only` when it cannot (raw SQL, an expression
//! that does not parse): an attribute is never guessed. The parsers for
//! expressions, query trees, attribute lists and agent definitions are in
//! [`capture`]; flows implement the trait in `attome-workflow`, which owns
//! their graph.
//!
//! [`write_edges`] replaces one definition's edges in the publish's own
//! transaction under a new graph version (`lineage_version`), so the graph
//! as it stood after every publish can be told apart.

pub mod capture;

use attome_types::AppError;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// How a definition uses its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeKind {
    /// It is started by changes to the target.
    Triggers,
    Reads,
    /// It computes a value from the target.
    Derives,
    Writes,
}

impl EdgeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Triggers => "triggers",
            Self::Reads => "reads",
            Self::Derives => "derives",
            Self::Writes => "writes",
        }
    }
}

/// How sure the parser is of the edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// Only the entity is known; the definition could not be parsed.
    EntityOnly,
    /// Parsed from the definition.
    Parsed,
}

impl Confidence {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EntityOnly => "entity_only",
            Self::Parsed => "parsed",
        }
    }
}

/// One edge from a definition to an entity or one of its attributes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Edge {
    pub to_entity: String,
    pub to_attribute: Option<String>,
    pub kind: EdgeKind,
    pub confidence: Confidence,
}

impl Edge {
    /// A parsed, attribute-level edge.
    pub fn attribute(entity: &str, attribute: &str, kind: EdgeKind) -> Self {
        Edge {
            to_entity: entity.to_owned(),
            to_attribute: Some(attribute.to_owned()),
            kind,
            confidence: Confidence::Parsed,
        }
    }

    /// A parsed edge to the entity as a whole (a trigger on any change).
    pub fn entity(entity: &str, kind: EdgeKind) -> Self {
        Edge {
            to_entity: entity.to_owned(),
            to_attribute: None,
            kind,
            confidence: Confidence::Parsed,
        }
    }

    /// An edge to the entity of a definition that could not be parsed.
    pub fn entity_only(entity: &str, kind: EdgeKind) -> Self {
        Edge {
            to_entity: entity.to_owned(),
            to_attribute: None,
            kind,
            confidence: Confidence::EntityOnly,
        }
    }
}

/// Turns one kind of definition into its edges. Pure: no data is read.
pub trait EdgeSource {
    fn edges(&self, def: &Value) -> Vec<Edge>;
}

/// One edge per target: the strongest use (writes over derives over reads
/// over triggers) and the surer confidence, in target order.
pub fn merge(edges: Vec<Edge>) -> Vec<Edge> {
    let mut by_target: std::collections::BTreeMap<(String, Option<String>), Edge> =
        std::collections::BTreeMap::new();
    for edge in edges {
        let key = (edge.to_entity.clone(), edge.to_attribute.clone());
        match by_target.get_mut(&key) {
            Some(kept) => {
                kept.kind = kept.kind.max(edge.kind);
                kept.confidence = kept.confidence.max(edge.confidence);
            }
            None => {
                by_target.insert(key, edge);
            }
        }
    }
    by_target.into_values().collect()
}

/// Replaces the edges of `(from_kind, from_ref)` with `edges`, in the
/// publish's transaction, under a new graph version; the version.
pub async fn write_edges(
    tx: &mut Transaction<'_, Postgres>,
    from_kind: &str,
    from_ref: Uuid,
    from_label: &str,
    edges: Vec<Edge>,
) -> Result<i64, AppError> {
    crate::try_xact_lock(
        tx,
        &format!("attome-core/metadata-reference:{from_kind}:{from_ref}"),
        "metadata reference write already in progress for this object",
    )
    .await?;
    crate::try_xact_lock(
        tx,
        "attome-core/lineage-version",
        "another publish is recording its lineage; retry",
    )
    .await?;
    let version: i64 = sqlx::query_scalar(
        "INSERT INTO lineage_version (version) \
         SELECT COALESCE(MAX(version), 0) + 1 FROM lineage_version RETURNING version",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    sqlx::query("DELETE FROM metadata_reference WHERE from_kind = $1 AND from_ref = $2")
        .bind(from_kind)
        .bind(from_ref)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    for edge in merge(edges) {
        sqlx::query(
            "INSERT INTO metadata_reference \
                (from_kind, from_ref, from_label, to_entity, to_attribute, to_kind, \
                 edge_kind, confidence, graph_version) \
             VALUES ($1, $2, $3, $4, $5, 'entity', $6, $7, $8) \
             ON CONFLICT (from_kind, from_ref, to_entity, to_attribute) DO NOTHING",
        )
        .bind(from_kind)
        .bind(from_ref)
        .bind(from_label)
        .bind(&edge.to_entity)
        .bind(edge.to_attribute.as_deref().unwrap_or(""))
        .bind(edge.kind.as_str())
        .bind(edge.confidence.as_str())
        .bind(version)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    }
    Ok(version)
}
