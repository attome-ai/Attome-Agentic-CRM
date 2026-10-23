//! L5-T3: the one impact engine.
//!
//! [`impact`] walks the lineage graph downstream of a set of draft metadata
//! changes: the definitions with an edge to a changed attribute (or, for an
//! entity-only edge, to its entity), then the definitions with an edge to
//! those (a dashboard showing a metric that reads the attribute; a model
//! object targeted as `<kind>:<id>`), up to a
//! depth (default [`DEFAULT_DEPTH`], at most [`MAX_DEPTH`]). Each affected
//! definition is reported once, at the shallowest depth it is reached.
//!
//! A change is **breaking** for a definition when it deletes an attribute,
//! or changes its type, and the definition uses that attribute directly
//! (depth 1, an attribute-level edge that reads, derives or writes it, as
//! parsed or documented by hand). An entity-only edge is reported as
//! affected, never as breaking: which attributes it uses is not known.
//!
//! The field changes' plan and apply steps (`attome-api` `field_changes`)
//! call it and refuse a delete or retype with its breaking list. Kinds a
//! field reference hook already rewrites or adjusts (stored queries,
//! workflows: [`HOOKED_KINDS`]) are left to that hook, so a customer object
//! there is still adjusted rather than blocking (D-788); every other reader
//! (dashboards, metrics, model definitions) blocks. Items the caller may not
//! see are counted in `hidden`, never named. A1, A9, A30 and AD6 call this
//! function; there is no second impact implementation.

use serde::Serialize;
use sqlx::PgConnection;
use uuid::Uuid;

use attome_types::AppError;

/// The depth walked when none is given.
pub const DEFAULT_DEPTH: u8 = 5;
/// The deepest walk.
pub const MAX_DEPTH: u8 = 10;

/// Definition kinds a field reference hook handles on delete and rename.
pub const HOOKED_KINDS: &[&str] = &["query", "workflow"];

/// What a draft change does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, utoipa::ToSchema)]
#[schema(as = LineageChangeKind)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    DeleteAttribute,
    ChangeAttributeType,
    RenameAttribute,
    /// Any other change to the entity or attribute.
    Other,
}

impl ChangeKind {
    /// Whether a direct use of the attribute stops working.
    pub fn breaks_direct_use(self) -> bool {
        matches!(self, Self::DeleteAttribute | Self::ChangeAttributeType)
    }
}

/// One draft metadata change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, utoipa::ToSchema)]
pub struct MetadataChange {
    pub entity: String,
    /// `None` for a change to the entity itself.
    pub attribute: Option<String>,
    pub kind: ChangeKind,
}

/// A definition downstream of a change.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct Affected {
    pub from_kind: String,
    pub from_ref: Uuid,
    pub from_label: String,
    /// 1 for a direct use.
    pub depth: i32,
    pub edge_kind: String,
    pub confidence: String,
    /// The edge names the changed attribute (not only its entity).
    pub attribute_level: bool,
    /// Index into the changes it is downstream of.
    #[serde(skip)]
    pub change: usize,
}

/// A definition a change would break.
#[derive(Debug, Clone, PartialEq, Serialize, utoipa::ToSchema)]
pub struct Breaking {
    pub change: MetadataChange,
    pub from_kind: String,
    pub from_ref: Uuid,
    pub from_label: String,
    pub edge_kind: String,
}

/// The impact of a set of changes.
#[derive(Debug, Clone, Default, Serialize, utoipa::ToSchema)]
pub struct ImpactReport {
    pub affected: Vec<Affected>,
    pub breaking: Vec<Breaking>,
    /// Affected definitions the caller may not see, counted only.
    pub hidden: usize,
}

/// Whether `affected` breaks under `change`.
pub fn is_breaking(change: &MetadataChange, affected: &Affected) -> bool {
    change.kind.breaks_direct_use()
        && affected.depth == 1
        && affected.attribute_level
        && affected.confidence != "entity_only"
        && matches!(affected.edge_kind.as_str(), "reads" | "derives" | "writes")
        && !HOOKED_KINDS.contains(&affected.from_kind.as_str())
}

type WalkRow = (String, Uuid, String, i32, String, String, bool);

/// The impact of `changes`, walked `depth` edges deep (clamped to 1 ..=
/// [`MAX_DEPTH`]). `visible` says whether the caller may see a definition.
pub async fn impact(
    conn: &mut PgConnection,
    changes: &[MetadataChange],
    depth: u8,
    visible: impl Fn(&str, Uuid) -> bool,
) -> Result<ImpactReport, AppError> {
    let depth = i32::from(depth.clamp(1, MAX_DEPTH));
    let mut report = ImpactReport::default();
    for (i, change) in changes.iter().enumerate() {
        let rows: Vec<WalkRow> = sqlx::query_as(
            "WITH RECURSIVE walk (from_kind, from_ref, from_label, depth, edge_kind, confidence, \
                                  attribute_level, path) AS ( \
                 SELECT r.from_kind, r.from_ref, r.from_label, 1, r.edge_kind, r.confidence, \
                        r.to_attribute <> '', ARRAY[r.from_kind || ':' || r.from_ref::text] \
                   FROM metadata_reference r \
                  WHERE r.to_kind = 'entity' AND r.to_entity = $1 \
                    AND ($2::text IS NULL OR r.to_attribute = $2 OR r.to_attribute = '') \
                 UNION ALL \
                 SELECT r.from_kind, r.from_ref, r.from_label, w.depth + 1, r.edge_kind, \
                        r.confidence, false, w.path || (r.from_kind || ':' || r.from_ref::text) \
                   FROM walk w \
                   JOIN metadata_reference r \
                     ON (r.to_kind = w.from_kind AND r.to_ref = w.from_ref) \
                     OR r.to_entity = w.from_kind || ':' || w.from_ref::text \
                  WHERE w.depth < $3 \
                    AND NOT (r.from_kind || ':' || r.from_ref::text) = ANY (w.path) \
             ) \
             SELECT DISTINCT ON (from_kind, from_ref) \
                    from_kind, from_ref, from_label, depth, edge_kind, confidence, attribute_level \
               FROM walk \
              ORDER BY from_kind, from_ref, depth, attribute_level DESC",
        )
        .bind(&change.entity)
        .bind(change.attribute.as_deref())
        .bind(depth)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        for (from_kind, from_ref, from_label, depth, edge_kind, confidence, attribute_level) in rows
        {
            let affected = Affected {
                from_kind,
                from_ref,
                from_label,
                depth,
                edge_kind,
                confidence,
                attribute_level,
                change: i,
            };
            if !visible(&affected.from_kind, affected.from_ref) {
                report.hidden += 1;
                continue;
            }
            if is_breaking(change, &affected) {
                report.breaking.push(Breaking {
                    change: change.clone(),
                    from_kind: affected.from_kind.clone(),
                    from_ref: affected.from_ref,
                    from_label: affected.from_label.clone(),
                    edge_kind: affected.edge_kind.clone(),
                });
            }
            report.affected.push(affected);
        }
    }
    Ok(report)
}

/// The breaking items as field-change blockers.
pub fn blockers(report: &ImpactReport) -> Vec<crate::changeset::field_hooks::Blocker> {
    report
        .breaking
        .iter()
        .map(|b| crate::changeset::field_hooks::Blocker {
            hook: "lineage_impact",
            object_kind: b.from_kind.clone(),
            object_ref: Some(b.from_ref),
            name: b.from_label.clone(),
            reason: format!(
                "field_in_use: the {} {} the field (lineage)",
                b.from_kind, b.edge_kind
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn affected(kind: &str, depth: i32, edge: &str, confidence: &str, attr: bool) -> Affected {
        Affected {
            from_kind: kind.into(),
            from_ref: Uuid::nil(),
            from_label: "Revenue".into(),
            depth,
            edge_kind: edge.into(),
            confidence: confidence.into(),
            attribute_level: attr,
            change: 0,
        }
    }

    #[test]
    fn lineage_impact_breaks_only_direct_parsed_uses() {
        let delete = MetadataChange {
            entity: "invoice".into(),
            attribute: Some("amount".into()),
            kind: ChangeKind::DeleteAttribute,
        };
        assert!(is_breaking(
            &delete,
            &affected("metric", 1, "reads", "parsed", true)
        ));
        assert!(is_breaking(
            &delete,
            &affected("dashboard", 1, "derives", "hand", true)
        ));
        assert!(
            !is_breaking(&delete, &affected("dashboard", 2, "reads", "parsed", false)),
            "a dashboard over the metric is affected, not broken"
        );
        assert!(
            !is_breaking(
                &delete,
                &affected("metric", 1, "reads", "entity_only", false)
            ),
            "entity-only: not known to use it"
        );
        assert!(
            !is_breaking(&delete, &affected("metric", 1, "triggers", "parsed", true)),
            "a trigger on the entity still works"
        );
        assert!(
            !is_breaking(&delete, &affected("query", 1, "reads", "parsed", true)),
            "stored queries are their hook's to decide"
        );
        let rename = MetadataChange {
            kind: ChangeKind::RenameAttribute,
            ..delete.clone()
        };
        assert!(!is_breaking(
            &rename,
            &affected("metric", 1, "reads", "parsed", true)
        ));
        let retype = MetadataChange {
            kind: ChangeKind::ChangeAttributeType,
            ..delete
        };
        assert!(is_breaking(
            &retype,
            &affected("metric", 1, "reads", "parsed", true)
        ));
    }

    #[test]
    fn lineage_impact_blockers_name_the_reader() {
        let report = ImpactReport {
            affected: Vec::new(),
            breaking: vec![Breaking {
                change: MetadataChange {
                    entity: "invoice".into(),
                    attribute: Some("amount".into()),
                    kind: ChangeKind::DeleteAttribute,
                },
                from_kind: "metric".into(),
                from_ref: Uuid::nil(),
                from_label: "Revenue".into(),
                edge_kind: "reads".into(),
            }],
            hidden: 0,
        };
        let blockers = blockers(&report);
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].name, "Revenue");
        assert!(blockers[0].reason.starts_with("field_in_use"));
    }
}
