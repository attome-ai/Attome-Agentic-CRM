//! L5-T5: hand-documented lineage links and outside systems as nodes.
//!
//! A steward records a link the graph cannot parse: an outside system (a
//! connector, an event subscriber, an import feed, a warehouse export, an
//! L1 source) that feeds or reads an entity, or a definition's use the
//! parser missed. The system is a `lineage_system` row (migration 0090) and
//! its node `system:<id>`; the link is a `metadata_reference` edge with
//! confidence `hand`, `documented_by` and a `note`, under a new graph
//! version, so `as of` reads and compares see it like any other edge.
//!
//! A definition's republish replaces only its parsed edges
//! ([`write_edges`](super::write_edges) keeps `hand` ones), and a hand link
//! never overwrites a parsed edge between the same two nodes. Removing a
//! link keeps it in `lineage_edge_history` for the versions it was valid in.
//!
//! Connector definitions (S12) carry endpoints, not entity names, so their
//! links are documented here by hand rather than written at publish.

use attome_types::AppError;
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

/// The use a link records.
pub const EDGE_KINDS: &[&str] = &["reads", "writes", "derives", "triggers"];
/// How a system's data moves.
pub const DIRECTIONS: &[&str] = &["inbound", "outbound", "both"];
/// The longest note.
pub const MAX_NOTE: usize = 2000;

/// The node a link starts at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkFrom {
    /// An outside system, by name (created when new).
    System {
        name: String,
        kind: String,
        direction: String,
    },
    /// A definition: its kind and id.
    Definition { kind: String, id: Uuid },
}

/// One link to document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualLink {
    pub from: LinkFrom,
    pub to_entity: String,
    pub to_attribute: Option<String>,
    pub edge_kind: String,
    pub note: String,
}

fn short_name(what: &str, v: &str) -> Result<(), AppError> {
    if v.trim().is_empty() || v.len() > 200 || v.chars().any(char::is_control) {
        return Err(AppError::Validation(format!(
            "{what} is a name of 1 to 200 characters"
        )));
    }
    Ok(())
}

/// Every problem with `link`, before anything is read. Pure.
pub fn check(link: &ManualLink) -> Result<(), AppError> {
    match &link.from {
        LinkFrom::System {
            name,
            kind,
            direction,
        } => {
            short_name("system", name)?;
            short_name("system kind", kind)?;
            if !DIRECTIONS.contains(&direction.as_str()) {
                return Err(AppError::Validation(format!(
                    "direction is one of {}",
                    DIRECTIONS.join(", ")
                )));
            }
        }
        LinkFrom::Definition { kind, .. } => {
            if kind == "system"
                || kind == "entity"
                || kind.is_empty()
                || kind.len() > 64
                || !kind.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            {
                return Err(AppError::Validation(
                    "from_kind is a definition kind such as workflow, query or metric".into(),
                ));
            }
        }
    }
    short_name("to_entity", &link.to_entity)?;
    if let Some(a) = &link.to_attribute {
        short_name("to_attribute", a)?;
    }
    if !EDGE_KINDS.contains(&link.edge_kind.as_str()) {
        return Err(AppError::Validation(format!(
            "edge_kind is one of {}",
            EDGE_KINDS.join(", ")
        )));
    }
    if link.note.trim().is_empty() || link.note.len() > MAX_NOTE {
        return Err(AppError::Validation(format!(
            "a hand-documented link needs a note of at most {MAX_NOTE} characters"
        )));
    }
    Ok(())
}

/// Whether `user` may document links to `entity`: an owner or steward of
/// the entity's data domain (`system.admin` is checked by the caller).
pub async fn may_document(
    conn: &mut PgConnection,
    entity: &str,
    user: Uuid,
) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM entity_info e \
                          JOIN governance_role g ON g.domain_ref = e.domain_ref \
                         WHERE e.logicalname = $1 AND g.user_id = $2 \
                           AND g.role IN ('owner', 'steward'))",
    )
    .bind(entity)
    .bind(user)
    .fetch_one(conn)
    .await
    .map_err(AppError::internal)
}

async fn next_version(tx: &mut Transaction<'_, Postgres>) -> Result<i64, AppError> {
    crate::try_xact_lock(
        tx,
        "attome-core/lineage-version",
        "another publish is recording its lineage; retry",
    )
    .await?;
    sqlx::query_scalar(
        "INSERT INTO lineage_version (version) \
         SELECT COALESCE(MAX(version), 0) + 1 FROM lineage_version RETURNING version",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

/// Records `link` by `documented_by`; the edge's id and the graph version.
pub async fn add(
    tx: &mut Transaction<'_, Postgres>,
    link: &ManualLink,
    documented_by: Uuid,
) -> Result<(Uuid, i64), AppError> {
    check(link)?;
    let attribute = link.to_attribute.as_deref().unwrap_or("");
    let known: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM entity_info e WHERE e.logicalname = $1 \
                           AND COALESCE(e.is_active, true) \
                           AND ($2 = '' OR EXISTS (SELECT 1 FROM attribute_info a \
                                 WHERE a.entity_ref = e.id AND a.logicalname = $2 \
                                   AND COALESCE(a.is_active, true))))",
    )
    .bind(&link.to_entity)
    .bind(attribute)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    if !known {
        return Err(AppError::Validation(format!(
            "{}{} is not a live entity or attribute",
            link.to_entity,
            if attribute.is_empty() {
                String::new()
            } else {
                format!(".{attribute}")
            }
        )));
    }
    let (from_kind, from_ref, from_label) = match &link.from {
        LinkFrom::System {
            name,
            kind,
            direction,
        } => {
            let id: Uuid = sqlx::query_scalar(
                "INSERT INTO lineage_system (name, kind, direction) VALUES ($1, $2, $3) \
                 ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind, \
                     direction = EXCLUDED.direction \
                 RETURNING id",
            )
            .bind(name.trim())
            .bind(kind.trim())
            .bind(direction)
            .fetch_one(&mut **tx)
            .await
            .map_err(AppError::internal)?;
            ("system".to_owned(), id, name.trim().to_owned())
        }
        LinkFrom::Definition { kind, id } => (kind.clone(), *id, String::new()),
    };
    crate::try_xact_lock(
        tx,
        &format!("attome-core/metadata-reference:{from_kind}:{from_ref}"),
        "metadata reference write already in progress for this object",
    )
    .await?;
    let version = next_version(tx).await?;
    // A parsed edge between the same nodes stays: the definition already
    // says it, and a hand note must not replace what the parser read.
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO metadata_reference \
             (from_kind, from_ref, from_label, to_entity, to_attribute, to_kind, edge_kind, \
              confidence, graph_version, documented_by, note) \
         VALUES ($1, $2, $3, $4, $5, 'entity', $6, 'hand', $7, $8, $9) \
         ON CONFLICT (from_kind, from_ref, to_entity, to_attribute) DO UPDATE \
            SET edge_kind = EXCLUDED.edge_kind, note = EXCLUDED.note, \
                documented_by = EXCLUDED.documented_by, graph_version = EXCLUDED.graph_version, \
                updated_at = now() \
          WHERE metadata_reference.confidence = 'hand' \
         RETURNING id",
    )
    .bind(&from_kind)
    .bind(from_ref)
    .bind(&from_label)
    .bind(&link.to_entity)
    .bind(attribute)
    .bind(&link.edge_kind)
    .bind(version)
    .bind(documented_by)
    .bind(link.note.trim())
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let id = id.ok_or(AppError::Conflict(
        "the graph already records this link from the definition itself",
    ))?;
    Ok((id, version))
}

/// What a removal took away, for its audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removed {
    pub from_kind: String,
    pub from_ref: Uuid,
    pub to_entity: String,
    pub to_attribute: String,
    pub version: i64,
}

/// Removes the hand-documented link `id`, keeping it in the history.
pub async fn remove(tx: &mut Transaction<'_, Postgres>, id: Uuid) -> Result<Removed, AppError> {
    let row: Option<(String, Uuid, String, String)> = sqlx::query_as(
        "SELECT from_kind, from_ref, to_entity, to_attribute FROM metadata_reference \
          WHERE id = $1 AND confidence = 'hand'",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let Some((from_kind, from_ref, to_entity, to_attribute)) = row else {
        return Err(AppError::NotFound);
    };
    crate::try_xact_lock(
        tx,
        &format!("attome-core/metadata-reference:{from_kind}:{from_ref}"),
        "metadata reference write already in progress for this object",
    )
    .await?;
    let version = next_version(tx).await?;
    sqlx::query(
        "INSERT INTO lineage_edge_history \
             (from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
              edge_kind, confidence, valid_from, valid_to) \
         SELECT from_kind, from_ref, from_label, to_kind, to_ref, to_entity, to_attribute, \
                edge_kind, confidence, graph_version, $2 \
           FROM metadata_reference WHERE id = $1",
    )
    .bind(id)
    .bind(version)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    let deleted =
        sqlx::query("DELETE FROM metadata_reference WHERE id = $1 AND confidence = 'hand'")
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
    if deleted == 0 {
        return Err(AppError::NotFound);
    }
    Ok(Removed {
        from_kind,
        from_ref,
        to_entity,
        to_attribute,
        version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(from: LinkFrom) -> ManualLink {
        ManualLink {
            from,
            to_entity: "account".into(),
            to_attribute: Some("vat_number".into()),
            edge_kind: "writes".into(),
            note: "The ERP's nightly customer export".into(),
        }
    }

    #[test]
    fn manual_link_check_needs_a_note_and_known_kinds() {
        let system = LinkFrom::System {
            name: "SAP B1".into(),
            kind: "erp".into(),
            direction: "inbound".into(),
        };
        assert!(check(&link(system.clone())).is_ok());
        let mut no_note = link(system.clone());
        no_note.note = "  ".into();
        assert!(check(&no_note).is_err());
        let mut bad_kind = link(system);
        bad_kind.edge_kind = "copies".into();
        assert!(check(&bad_kind).is_err());
        assert!(
            check(&link(LinkFrom::System {
                name: "x".into(),
                kind: "erp".into(),
                direction: "sideways".into(),
            }))
            .is_err()
        );
        for kind in ["system", "entity", "Work Flow", ""] {
            assert!(
                check(&link(LinkFrom::Definition {
                    kind: kind.into(),
                    id: Uuid::nil(),
                }))
                .is_err(),
                "{kind}"
            );
        }
        assert!(
            check(&link(LinkFrom::Definition {
                kind: "workflow".into(),
                id: Uuid::nil(),
            }))
            .is_ok()
        );
    }
}
