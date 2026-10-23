//! L2-T7: data quality alerts to the people who look after the data.
//!
//! After the daily snapshot ([`after_snapshot`], called by
//! `crate::quality_score::run_snapshot`) each entity's overall score is
//! compared with its target (`quality_target.threshold`, default 70) and
//! with yesterday's snapshot: a fall of more than `quality.drop_alert_points`
//! (default 10) is a sudden drop. An entity below target or dropping gets one
//! notification a day (`quality_alert_sent`, migration 0235, keyed by entity
//! and day), with the issues' main source (channel, import or person) in the
//! message.
//!
//! It goes to the stewards of the entity's data domain (L3 governance
//! roles), else its owners, else the holders of the compliance
//! administration area (`admin.compliance`, Q12), else the longest-standing
//! full administrator: never to every holder of `system.admin`.

use std::collections::HashMap;

use attome_config::NotificationSection;
use attome_core::EngineState;
use attome_db::DbPool;
use attome_notification::dispatch::{DispatchRequest, create_dispatch};
use attome_types::AppError;
use uuid::Uuid;

/// The setting for a sudden drop, in score points.
pub const DROP_SETTING: &str = "quality.drop_alert_points";
/// A sudden drop when the setting is unset.
pub const DEFAULT_DROP_POINTS: f64 = 10.0;

/// Why an entity is alerted.
#[derive(Debug, Clone, PartialEq)]
pub enum Reason {
    BelowTarget { score: f64, threshold: f64 },
    Drop { score: f64, yesterday: f64 },
}

/// Why `today`'s overall score alerts, if it does. Pure.
pub fn reasons(
    today: f64,
    yesterday: Option<f64>,
    threshold: f64,
    drop_points: f64,
) -> Vec<Reason> {
    let mut out = Vec::new();
    if today < threshold {
        out.push(Reason::BelowTarget {
            score: today,
            threshold,
        });
    }
    if let Some(yesterday) = yesterday
        && yesterday - today > drop_points
    {
        out.push(Reason::Drop {
            score: today,
            yesterday,
        });
    }
    out
}

/// The issues' main source: `(kind, value, open issues)`.
pub type Source = (String, String, i64);

/// The alert's subject and body. Pure.
pub fn message(entity: &str, reasons: &[Reason], source: Option<&Source>) -> (String, String) {
    let score = reasons
        .iter()
        .map(|r| match r {
            Reason::BelowTarget { score, .. } | Reason::Drop { score, .. } => *score,
        })
        .next()
        .unwrap_or_default();
    let subject = format!("Data quality: {entity} is at {score:.0}%");
    let mut lines: Vec<String> = reasons
        .iter()
        .map(|r| match r {
            Reason::BelowTarget { score, threshold } => format!(
                "The overall score of '{entity}' is {score:.0}%, below its target of {threshold:.0}%."
            ),
            Reason::Drop { score, yesterday } => format!(
                "The overall score of '{entity}' fell from {yesterday:.0}% to {score:.0}% since yesterday."
            ),
        })
        .collect();
    if let Some((kind, value, count)) = source {
        lines.push(format!(
            "Most open issues ({count}) came from the {kind} {value}."
        ));
    }
    lines.push("Review at /admin/data/quality.".to_owned());
    (subject, lines.join("\n"))
}

async fn privilege_holders(db: &DbPool, key: &str) -> Result<Vec<Uuid>, AppError> {
    sqlx::query_scalar(
        "SELECT su.id FROM user_account su \
          WHERE (su.is_active IS NULL OR su.is_active = true) \
            AND (EXISTS (SELECT 1 FROM user_account_mm_privilege up \
                           JOIN privilege p ON p.id = up.privilege_ref \
                          WHERE up.user_ref = su.id AND up.is_active = true AND p.is_active = true \
                            AND p.key = $1) \
                 OR EXISTS (SELECT 1 FROM user_account_mm_role ur \
                              JOIN role_mm_privilege rp ON rp.role_ref = ur.role_ref \
                              JOIN privilege p ON p.id = rp.privilege_ref \
                             WHERE ur.user_ref = su.id AND ur.is_deleted = false \
                               AND rp.is_deleted = false AND p.is_active = true AND p.key = $1)) \
          ORDER BY su.created_at, su.id",
    )
    .bind(key)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)
}

/// Who is told about `entity`: its domain's stewards, else its owners, else
/// the compliance administrators, else the first full administrator.
pub async fn recipients(db: &DbPool, entity: &str) -> Result<Vec<Uuid>, AppError> {
    for role in ["steward", "owner"] {
        let found: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT g.user_id FROM entity_info e \
               JOIN governance_role g ON g.domain_ref = e.domain_ref \
               JOIN user_account u ON u.id = g.user_id \
              WHERE e.logicalname = $1 AND g.role = $2 \
                AND (u.is_active IS NULL OR u.is_active = true)",
        )
        .bind(entity)
        .bind(role)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        if !found.is_empty() {
            return Ok(found);
        }
    }
    let compliance = privilege_holders(db, "admin.compliance").await?;
    if !compliance.is_empty() {
        return Ok(compliance);
    }
    Ok(privilege_holders(db, "system.admin")
        .await?
        .into_iter()
        .take(1)
        .collect())
}

/// The kind and value most of `entity`'s open issues came from.
async fn main_source(db: &DbPool, entity: &str) -> Result<Option<Source>, AppError> {
    sqlx::query_as(
        "SELECT kind, value, n FROM ( \
             SELECT 'channel' AS kind, source_channel AS value, count(*) AS n \
               FROM quality_issue WHERE entity_logicalname = $1 AND status = 'open' \
                AND source_channel IS NOT NULL GROUP BY source_channel \
             UNION ALL \
             SELECT 'import', source_import_id::text, count(*) \
               FROM quality_issue WHERE entity_logicalname = $1 AND status = 'open' \
                AND source_import_id IS NOT NULL GROUP BY source_import_id \
             UNION ALL \
             SELECT 'person', source_actor::text, count(*) \
               FROM quality_issue WHERE entity_logicalname = $1 AND status = 'open' \
                AND source_actor IS NOT NULL GROUP BY source_actor \
         ) s ORDER BY n DESC, kind, value LIMIT 1",
    )
    .bind(entity)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)
}

/// Alerts every entity below target or dropping today, once per day; how
/// many entities were alerted.
pub async fn after_snapshot(
    state: &EngineState,
    notification_cfg: &NotificationSection,
) -> Result<usize, AppError> {
    let db = &state.base.db;
    let drop_points = attome_core::setting_registry()
        .get(DROP_SETTING)
        .map(|d| state.settings.load().resolve(d, None, None).0)
        .and_then(|v| v.as_f64())
        .filter(|p| *p >= 0.0)
        .unwrap_or(DEFAULT_DROP_POINTS);
    let today: Vec<(String, f64, Option<f64>)> = sqlx::query_as(
        "SELECT s.entity, s.score::float8, y.score::float8 FROM quality_snapshot s \
           LEFT JOIN quality_snapshot y ON y.entity = s.entity AND y.dimension = 'overall' \
                                       AND y.day = s.day - 1 \
          WHERE s.dimension = 'overall' AND s.day = CURRENT_DATE",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let thresholds: HashMap<String, f64> =
        sqlx::query_as("SELECT entity, threshold::float8 FROM quality_target")
            .fetch_all(db)
            .await
            .map_err(AppError::internal)?
            .into_iter()
            .collect();
    let mut alerted = 0;
    for (entity, score, yesterday) in today {
        let threshold = thresholds
            .get(&entity)
            .copied()
            .unwrap_or(crate::quality::dimensions::DEFAULT_THRESHOLD);
        let why = reasons(score, yesterday, threshold, drop_points);
        if why.is_empty() {
            continue;
        }
        // One alert per entity per day, however often the job runs.
        let first = sqlx::query(
            "INSERT INTO quality_alert_sent (entity, day) VALUES ($1, CURRENT_DATE) \
             ON CONFLICT (entity, day) DO NOTHING",
        )
        .bind(&entity)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected()
            == 1;
        if !first {
            continue;
        }
        let source = main_source(db, &entity).await?;
        let (subject, body) = message(&entity, &why, source.as_ref());
        let to = recipients(db, &entity).await?;
        for user_id in &to {
            let req = DispatchRequest {
                template_key: None,
                locale: "en".to_string(),
                recipient_user_ref: Some(*user_id),
                is_global: false,
                organization_ref: None,
                channels: None,
                subject: Some(subject.clone()),
                body_html: None,
                body_text: Some(body.clone()),
                route: Some("/admin/data/quality".to_string()),
                variables: HashMap::new(),
                priority: "high".to_string(),
                escalate_after_minutes: None,
                escalate_channels: None,
            };
            if let Err(e) = create_dispatch(db, notification_cfg, req).await {
                tracing::error!(error = %e, %user_id, %entity, "data quality alert dispatch failed");
            }
        }
        alerted += 1;
    }
    Ok(alerted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_alert_reasons_below_target_and_drop() {
        assert!(reasons(80.0, Some(85.0), 70.0, 10.0).is_empty());
        assert_eq!(
            reasons(65.0, Some(70.0), 70.0, 10.0),
            vec![Reason::BelowTarget {
                score: 65.0,
                threshold: 70.0
            }]
        );
        assert_eq!(
            reasons(75.0, Some(90.0), 70.0, 10.0),
            vec![Reason::Drop {
                score: 75.0,
                yesterday: 90.0
            }]
        );
        assert_eq!(reasons(60.0, Some(95.0), 70.0, 10.0).len(), 2);
        assert!(reasons(75.0, None, 70.0, 10.0).is_empty());
    }

    #[test]
    fn quality_alert_message_names_the_main_source() {
        let (subject, body) = message(
            "account",
            &[Reason::Drop {
                score: 72.0,
                yesterday: 91.0,
            }],
            Some(&("channel".into(), "import".into(), 40)),
        );
        assert_eq!(subject, "Data quality: account is at 72%");
        assert!(body.contains("fell from 91% to 72%"), "{body}");
        assert!(
            body.contains("Most open issues (40) came from the channel import."),
            "{body}"
        );
    }
}
