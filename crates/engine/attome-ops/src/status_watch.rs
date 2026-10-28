//! AB11-T4: draft incidents opened for components that stay down.
//!
//! The registered job [`TICK_JOB`] runs every minute while the setting
//! `ops.status_watch` is on. Each run reads every component's state from
//! the capability probes (never probing itself), keeps
//! `ops_status_component.degraded_since` (migration 0315) set while a
//! component is down and clears it when it recovers, and opens one internal
//! draft incident (`auto_created`) for a component down at least
//! [`DETECTION_DELAY_MINUTES`] that no open incident lists. With
//! `ops.status_auto_publish_minutes` above zero, an automatic draft older
//! than that gets an `investigating` update in both languages; otherwise a
//! person publishes it. One node runs a tick at a time (an advisory lock),
//! so a component gets one draft.

use std::collections::HashSet;

use attome_audit::AuditOperation;
use attome_audit::security::{MandatoryCategory, SecurityEvent, write_security_event};
use attome_core::EngineState;
use attome_types::AppError;
use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

use crate::public_status::state_of_capability;

/// The registered job that runs [`tick`].
pub const TICK_JOB: &str = "ops_status_watch";

/// How many minutes a component stays down before a draft opens.
pub const DETECTION_DELAY_MINUTES: i64 = 3;

/// What one tick did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WatchStats {
    pub drafted: u32,
    pub published: u32,
}

/// One component as a tick sees it.
#[derive(Debug, Clone)]
pub struct Watched {
    pub key: String,
    pub name_en: String,
    pub name_ar: String,
    /// Since when it has been down, once this tick has updated it.
    pub down_since: Option<DateTime<Utc>>,
}

/// The components that get a draft now: down at least
/// [`DETECTION_DELAY_MINUTES`], and listed by no open incident. Pure.
pub fn components_to_draft<'a>(
    components: &'a [Watched],
    listed_by_open_incident: &HashSet<String>,
    now: DateTime<Utc>,
) -> Vec<&'a Watched> {
    components
        .iter()
        .filter(|c| {
            c.down_since
                .is_some_and(|since| now - since >= Duration::minutes(DETECTION_DELAY_MINUTES))
        })
        .filter(|c| !listed_by_open_incident.contains(&c.key))
        .collect()
}

/// The titles of an automatic draft, in English and Arabic. Pure.
pub fn draft_titles(component: &Watched) -> (String, String) {
    (
        format!("{} is unavailable", component.name_en),
        format!("{} غير متاح", component.name_ar),
    )
}

/// The text of the update an automatic draft is published with. Pure.
pub fn investigating_text(component_en: &str, component_ar: &str) -> (String, String) {
    (
        format!("{component_en} is unavailable. We are investigating and will post updates here."),
        format!("{component_ar} غير متاح حاليًا. نعمل على التحقق من المشكلة وسننشر التحديثات هنا."),
    )
}

fn setting(state: &EngineState, key: &str) -> Option<serde_json::Value> {
    attome_core::setting_registry()
        .get(key)
        .map(|d| state.settings.load().resolve(d, None, None).0)
}

fn event(name: &str, id: Uuid, operation: AuditOperation, comment: String) -> SecurityEvent {
    SecurityEvent::new(
        MandatoryCategory::Configuration,
        operation,
        Uuid::nil(),
        "ops_incident",
        Some(id),
    )
    .named(name.to_owned())
    .comment(comment)
}

/// One watch run. Does nothing while `ops.status_watch` is off or another
/// node holds the tick.
pub async fn tick(state: &EngineState) -> Result<WatchStats, AppError> {
    let mut stats = WatchStats::default();
    if setting(state, "ops.status_watch").and_then(|v| v.as_bool()) != Some(true) {
        return Ok(stats);
    }
    let reports = state.base.capabilities.snapshot();
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1, hashtext($2))")
        .bind(crate::ADVISORY_LOCK_NAMESPACE)
        .bind("attome-ops/status-watch:tick")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    if !locked {
        return Ok(stats);
    }
    let rows: Vec<(String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT key, name_en, name_ar, capability FROM ops_status_component ORDER BY sort, key",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let down: Vec<String> = rows
        .iter()
        .filter(|(_, _, _, capability)| {
            capability.as_deref().is_some_and(|c| {
                state_of_capability(reports.iter().find(|r| r.capability == c).map(|r| r.state))
                    == "down"
            })
        })
        .map(|(key, ..)| key.clone())
        .collect();
    let since: Vec<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "UPDATE ops_status_component \
            SET degraded_since = CASE WHEN key = ANY($1) THEN COALESCE(degraded_since, now()) END \
          RETURNING key, degraded_since",
    )
    .bind(&down)
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let watched: Vec<Watched> = rows
        .into_iter()
        .map(|(key, name_en, name_ar, _)| Watched {
            down_since: since.iter().find(|(k, _)| *k == key).and_then(|(_, s)| *s),
            key,
            name_en,
            name_ar,
        })
        .collect();
    let listed: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT unnest(components) FROM ops_incident WHERE resolved_at IS NULL",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let listed: HashSet<String> = listed.into_iter().collect();
    let now = Utc::now();
    for component in components_to_draft(&watched, &listed, now) {
        let (title_en, title_ar) = draft_titles(component);
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO ops_incident (title_en, title_ar, audience, state, components, impact, \
                                       started_at, auto_created) \
             VALUES ($1, $2, 'internal', 'draft', ARRAY[$3], 'major', $4, true) RETURNING id",
        )
        .bind(&title_en)
        .bind(&title_ar)
        .bind(&component.key)
        .bind(component.down_since.unwrap_or(now))
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        write_security_event(
            &mut tx,
            &attome_audit::audit_service(state),
            event(
                "ops.incident_created",
                id,
                AuditOperation::Create,
                format!("automatic incident draft: {title_en}"),
            ),
        )
        .await?;
        stats.drafted += 1;
    }
    let after = setting(state, "ops.status_auto_publish_minutes")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if after > 0 {
        let due: Vec<(Uuid, String, String)> = sqlx::query_as(
            "SELECT i.id, c.name_en, c.name_ar FROM ops_incident i \
               JOIN ops_status_component c ON c.key = i.components[1] \
              WHERE i.auto_created AND i.state = 'draft' AND i.resolved_at IS NULL \
                AND i.started_at <= now() - make_interval(mins => $1) \
              FOR UPDATE OF i",
        )
        .bind(i32::try_from(after).unwrap_or(i32::MAX))
        .fetch_all(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        for (id, name_en, name_ar) in due {
            let (body_en, body_ar) = investigating_text(&name_en, &name_ar);
            sqlx::query(
                "INSERT INTO ops_incident_update (incident_id, stage, body_en, body_ar) \
                 VALUES ($1, 'investigating', $2, $3)",
            )
            .bind(id)
            .bind(&body_en)
            .bind(&body_ar)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            sqlx::query(
                "UPDATE ops_incident SET state = 'investigating', \
                    published_at = COALESCE(published_at, now()), row_version = row_version + 1 \
                  WHERE id = $1",
            )
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            write_security_event(
                &mut tx,
                &attome_audit::audit_service(state),
                event(
                    "ops.incident_update_published",
                    id,
                    AuditOperation::Create,
                    format!("automatic incident published after {after} minutes: {name_en}"),
                ),
            )
            .await?;
            stats.published += 1;
        }
    }
    attome_db::tx::commit(tx).await?;
    if stats.drafted > 0 || stats.published > 0 {
        crate::public_status::invalidate();
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn component(key: &str, down_minutes: Option<i64>, now: DateTime<Utc>) -> Watched {
        Watched {
            key: key.into(),
            name_en: key.into(),
            name_ar: key.into(),
            down_since: down_minutes.map(|m| now - Duration::minutes(m)),
        }
    }

    #[test]
    fn draft_after_three_minutes() {
        let now = Utc::now();
        let components = [
            component("search", Some(3), now),
            component("email", Some(2), now),
            component("ai", None, now),
        ];
        let keys: Vec<&str> = components_to_draft(&components, &HashSet::new(), now)
            .iter()
            .map(|c| c.key.as_str())
            .collect();
        assert_eq!(keys, ["search"]);
    }

    #[test]
    fn no_duplicate_draft_while_open() {
        let now = Utc::now();
        let components = [component("search", Some(10), now)];
        let open: HashSet<String> = ["search".to_owned()].into_iter().collect();
        assert!(components_to_draft(&components, &open, now).is_empty());
    }

    #[test]
    fn automatic_text_is_in_both_languages() {
        let (en, ar) = investigating_text("Search", "البحث");
        assert!(en.contains("Search") && ar.contains("البحث"));
        let (title_en, title_ar) = draft_titles(&Watched {
            key: "search".into(),
            name_en: "Search".into(),
            name_ar: "البحث".into(),
            down_since: None,
        });
        assert_eq!(title_en, "Search is unavailable");
        assert!(title_ar.starts_with("البحث"));
    }
}
