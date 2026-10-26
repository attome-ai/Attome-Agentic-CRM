//! Q14-T4: why a person can, or cannot, see or change one record.
//!
//! [`explain`] gathers the facts the record filter decides on, for the
//! person asked about (never the caller), and [`evaluate`] walks the sources
//! in the order the filter applies them: administrator, the entity
//! privilege, the role level, the business unit, ownership, a share to the
//! person or one of their teams, an entity-wide default share, a sharing
//! rule, and an explicit deny. Every source is listed with whether it grants,
//! denies or does not apply, and the one that decides is marked. The filter
//! itself (`crate::rls`) stays the only enforcement; this module only reads.

use attome_db::DbPool;
use attome_server::security::{AccessLevel, SecurityContext};
use attome_types::AppError;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::context::SecurityContextExt;
use crate::db::RecordAction;
use crate::rls::Capability;
use crate::sharing_rules::{RuleSource, SharingRule};

/// What one source does for the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    Grants,
    Denies,
    NotApplicable,
}

/// One source of access, in the order the filter applies them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AccessSource {
    /// `admin`, `privilege`, `role_level`, `business_unit`, `ownership`,
    /// `user_share`, `team_share`, `default_share`, `sharing_rule` or `deny`.
    pub source: &'static str,
    pub effect: Effect,
    /// A short reason, in English.
    pub detail: String,
    /// The source that decides the outcome.
    pub winning: bool,
}

/// The answer for one person, record and operation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AccessExplanation {
    pub user_id: Uuid,
    /// `read`, `update` or `delete`.
    pub action: &'static str,
    pub allowed: bool,
    pub sources: Vec<AccessSource>,
}

/// What the filter decides on, for one person and record.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessFacts {
    pub is_admin: bool,
    pub has_privilege: bool,
    pub level: Option<AccessLevel>,
    /// The record is in a unit the person's business-unit tier reaches.
    pub in_unit: bool,
    /// The person's roles let an owner see their records, and they own it.
    pub owner_sees: bool,
    pub user_share: bool,
    pub team_share: bool,
    pub default_share: bool,
    /// The sharing rule that gives the person the record.
    pub rule: Option<Uuid>,
    /// `user` or `team` when an explicit deny share applies.
    pub deny: Option<&'static str>,
}

fn source(source: &'static str, grants: bool, detail: impl Into<String>) -> AccessSource {
    AccessSource {
        source,
        effect: if grants {
            Effect::Grants
        } else {
            Effect::NotApplicable
        },
        detail: detail.into(),
        winning: false,
    }
}

/// Walks the facts in filter order. An administrator always passes; a
/// missing privilege, then an explicit deny, refuse; otherwise the first
/// source that grants decides, and with none the record is out of reach.
pub fn evaluate(facts: &AccessFacts) -> (bool, Vec<AccessSource>) {
    let level = facts.level.unwrap_or(AccessLevel::None);
    let mut sources = vec![
        source(
            "admin",
            facts.is_admin,
            if facts.is_admin {
                "an administrator reaches every record"
            } else {
                "not an administrator"
            },
        ),
        AccessSource {
            source: "privilege",
            effect: if facts.has_privilege {
                Effect::NotApplicable
            } else {
                Effect::Denies
            },
            detail: if facts.has_privilege {
                "holds the entity privilege for this operation".into()
            } else {
                "does not hold the entity privilege for this operation".into()
            },
            winning: false,
        },
        source(
            "role_level",
            level == AccessLevel::Global,
            format!("role level for this entity and operation: {level:?}"),
        ),
        source(
            "business_unit",
            level == AccessLevel::BusinessUnit && facts.in_unit,
            if level != AccessLevel::BusinessUnit {
                "the role level is not business unit".to_owned()
            } else if facts.in_unit {
                "the record is in a unit the role level reaches".to_owned()
            } else {
                "the record is outside the units the role level reaches".to_owned()
            },
        ),
        source(
            "ownership",
            facts.owner_sees,
            if facts.owner_sees {
                "owns the record and a role lets owners see their records"
            } else {
                "does not own the record, or no role lets owners see theirs"
            },
        ),
        source(
            "user_share",
            facts.user_share,
            if facts.user_share {
                "the record is shared with the person"
            } else {
                "no share to the person"
            },
        ),
        source(
            "team_share",
            facts.team_share,
            if facts.team_share {
                "the record is shared with one of the person's teams"
            } else {
                "no share to the person's teams"
            },
        ),
        source(
            "default_share",
            facts.default_share,
            if facts.default_share {
                "the entity is shared by default with the person or a team"
            } else {
                "no default share"
            },
        ),
        source(
            "sharing_rule",
            facts.rule.is_some(),
            match facts.rule {
                Some(id) => format!("sharing rule {id} gives the person this record"),
                None => "no sharing rule gives the person this record".to_owned(),
            },
        ),
        AccessSource {
            source: "deny",
            effect: if facts.deny.is_some() {
                Effect::Denies
            } else {
                Effect::NotApplicable
            },
            detail: match facts.deny {
                Some(to) => format!("an explicit deny share to the {to} wins over every grant"),
                None => "no deny share".to_owned(),
            },
            winning: false,
        },
    ];
    let winner = if facts.is_admin {
        Some(0)
    } else if !facts.has_privilege {
        Some(1)
    } else if facts.deny.is_some() {
        Some(sources.len() - 1)
    } else {
        sources.iter().position(|s| s.effect == Effect::Grants)
    };
    let allowed = match winner {
        Some(i) => sources[i].effect == Effect::Grants,
        None => false,
    };
    if let Some(i) = winner {
        sources[i].winning = true;
    }
    (allowed, sources)
}

/// Whether `rule` gives the record (owned as the facts say) to `target`.
fn rule_matches(
    rule: &SharingRule,
    record_org: Option<Uuid>,
    owner_type: Option<i16>,
    owner: Option<Uuid>,
    owner_roles: &[Uuid],
) -> bool {
    match rule.source {
        RuleSource::Unit(unit) => record_org == Some(unit),
        RuleSource::Team(team) => owner_type == Some(1) && owner == Some(team),
        RuleSource::Role(role) => owner_type == Some(0) && owner_roles.contains(&role),
    }
}

/// Explains `action` on `entity_name`'s record `record_id` for the person
/// `target` is the resolved context of. `NotFound` when there is no such
/// live record.
pub async fn explain(
    db: &DbPool,
    target: &SecurityContext,
    entity_ref: Uuid,
    entity_name: &str,
    record_id: Uuid,
    action: RecordAction,
) -> Result<AccessExplanation, AppError> {
    let table = attome_core::quote_ident(entity_name);
    let record: Option<(Option<Uuid>, Option<Uuid>, Option<i16>)> = sqlx::query_as(&format!(
        "SELECT organization_ref, owner_ref, owner_type FROM {table} \
         WHERE id = $1 AND (is_active IS NULL OR is_active = true)"
    ))
    .bind(record_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let (record_org, owner, owner_type) = record.ok_or(AppError::NotFound)?;

    let required = action.share_capability();
    let level =
        crate::db::resolve_entity_access_level(db, target.user_id, entity_ref, entity_name, action)
            .await?;
    let owner_visible =
        crate::db::resolve_owner_visible(db, target.user_id, entity_ref, entity_name, action)
            .await?;
    let units = if target
        .unit_scope
        .excludes_children(entity_ref, action.as_str())
    {
        &target.unit_scope.own_org_ids
    } else {
        &target.accessible_org_ids
    };
    let shares: Vec<(i16, i16)> = sqlx::query_as(
        "SELECT capability, principal_type FROM record_share \
         WHERE record_id = $1 AND entity_ref = $2 \
           AND ((principal_type = 0 AND principal_id = $3) \
             OR (principal_type = 1 AND principal_id = ANY($4)))",
    )
    .bind(record_id)
    .bind(entity_ref)
    .bind(target.user_id)
    .bind(&target.team_ids)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let allows = |capability: i16| (required.as_i16()..=1).contains(&capability);
    let default_share = crate::db::resolve_default_share_entities(
        db,
        target.user_id,
        &target.team_ids,
        required.as_i16(),
    )
    .await?
    .contains(&entity_ref);
    let owner_roles: Vec<Uuid> = match (owner_type, owner) {
        (Some(0), Some(owner)) => crate::db::resolve_role_ids(db, owner).await?,
        _ => Vec::new(),
    };
    let rule = crate::sharing_rules::rules_for(entity_ref)
        .into_iter()
        .filter(|rule| (required == Capability::View || rule.write) && rule.targets(target))
        .find(|rule| rule_matches(rule, record_org, owner_type, owner, &owner_roles))
        .map(|rule| rule.id);

    let facts = AccessFacts {
        is_admin: target.is_admin,
        has_privilege: target
            .require(entity_name, action.privilege_action())
            .is_ok(),
        level: Some(level),
        in_unit: record_org.is_some_and(|org| units.contains(&org)),
        owner_sees: owner_visible && owner_type == Some(0) && owner == Some(target.user_id),
        user_share: shares.iter().any(|&(c, p)| p == 0 && allows(c)),
        team_share: shares.iter().any(|&(c, p)| p == 1 && allows(c)),
        default_share,
        rule,
        deny: shares
            .iter()
            .find(|&&(c, _)| c == crate::rls_fragment::DENY_CAPABILITY)
            .map(|&(_, p)| if p == 0 { "user" } else { "team" }),
    };
    let (allowed, sources) = evaluate(&facts);
    Ok(AccessExplanation {
        user_id: target.user_id,
        action: action.as_str(),
        allowed,
        sources,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn winner(sources: &[AccessSource]) -> &'static str {
        sources
            .iter()
            .find(|s| s.winning)
            .map_or("none", |s| s.source)
    }

    #[test]
    fn explain_a_shared_record() {
        let facts = AccessFacts {
            has_privilege: true,
            level: Some(AccessLevel::Team),
            team_share: true,
            ..AccessFacts::default()
        };
        let (allowed, sources) = evaluate(&facts);
        assert!(allowed);
        assert_eq!(winner(&sources), "team_share");
        assert_eq!(sources.iter().filter(|s| s.winning).count(), 1);
    }

    #[test]
    fn explain_a_denied_record() {
        let facts = AccessFacts {
            has_privilege: true,
            level: Some(AccessLevel::Global),
            user_share: true,
            deny: Some("team"),
            ..AccessFacts::default()
        };
        let (allowed, sources) = evaluate(&facts);
        assert!(
            !allowed,
            "a deny share wins over a Global level and a share"
        );
        assert_eq!(winner(&sources), "deny");
    }

    #[test]
    fn explain_admin_missing_privilege_and_nothing_granted() {
        let (allowed, sources) = evaluate(&AccessFacts {
            is_admin: true,
            deny: Some("user"),
            ..AccessFacts::default()
        });
        assert!(allowed);
        assert_eq!(winner(&sources), "admin");

        let (allowed, sources) = evaluate(&AccessFacts {
            level: Some(AccessLevel::Global),
            ..AccessFacts::default()
        });
        assert!(!allowed);
        assert_eq!(winner(&sources), "privilege");

        let (allowed, sources) = evaluate(&AccessFacts {
            has_privilege: true,
            level: Some(AccessLevel::BusinessUnit),
            in_unit: false,
            ..AccessFacts::default()
        });
        assert!(!allowed);
        assert_eq!(winner(&sources), "none");
        let bu = sources
            .iter()
            .find(|s| s.source == "business_unit")
            .unwrap();
        assert!(bu.detail.contains("outside"), "{}", bu.detail);
    }

    #[test]
    fn explain_rule_sources_match_the_record_owner() {
        let (unit, team, role) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let rule = |source| SharingRule {
            id: Uuid::now_v7(),
            entity: Uuid::now_v7(),
            source,
            target: crate::sharing_rules::RuleTarget::Team(Uuid::now_v7()),
            write: false,
        };
        assert!(rule_matches(
            &rule(RuleSource::Unit(unit)),
            Some(unit),
            Some(0),
            None,
            &[]
        ));
        assert!(rule_matches(
            &rule(RuleSource::Team(team)),
            None,
            Some(1),
            Some(team),
            &[]
        ));
        assert!(!rule_matches(
            &rule(RuleSource::Team(team)),
            None,
            Some(0),
            Some(team),
            &[]
        ));
        assert!(rule_matches(
            &rule(RuleSource::Role(role)),
            None,
            Some(0),
            Some(Uuid::now_v7()),
            &[role]
        ));
    }
}
