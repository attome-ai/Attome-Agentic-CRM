//! E14-T7: an anonymous visitor identified as a lead or contact.
//!
//! When a visitor becomes known (a form submitted, a tracked email clicked,
//! a portal sign-in, a chat's details step) and `marketing.tracking_identify`
//! is on and the visitor consented to marketing, [`identify`]:
//!
//! 1. moves every web session of that visitor id that names no one yet to
//!    the person (`marketing_web_session.contact_ref` or `lead_ref`), in one
//!    transaction;
//! 2. writes the person's first and latest touch (source, medium, campaign,
//!    landing page, referrer and when) from the visitor's earliest and
//!    latest sessions that carried a landing page: the `first_touch_*`
//!    fields only while they are empty, `latest_touch_*` always, through the
//!    generic update path so validation, rules and audit run. A deployment
//!    without the marketing pack's `0011` fields gets the session link only.
//!
//! Sessions marked as a bot's are never linked.

use attome_core::EngineState;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use uuid::Uuid;

/// The feature flag that turns identification on.
pub const FLAG: &str = "marketing.tracking_identify";

/// Who the visitor turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifyTarget {
    Contact(Uuid),
    Lead(Uuid),
}

impl IdentifyTarget {
    pub fn entity(self) -> &'static str {
        match self {
            Self::Contact(_) => "contact",
            Self::Lead(_) => "lead",
        }
    }

    pub fn id(self) -> Uuid {
        match self {
            Self::Contact(id) | Self::Lead(id) => id,
        }
    }

    fn session_column(self) -> &'static str {
        match self {
            Self::Contact(_) => "contact_ref",
            Self::Lead(_) => "lead_ref",
        }
    }
}

/// How the visitor became known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    FormSubmit,
    EmailClick,
    PortalSignIn,
    Chat,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FormSubmit => "form_submit",
            Self::EmailClick => "email_click",
            Self::PortalSignIn => "portal_sign_in",
            Self::Chat => "chat",
        }
    }
}

/// One session's campaign tags.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct Touch {
    pub source: Option<String>,
    pub medium: Option<String>,
    pub campaign: Option<String>,
    pub landing_url: Option<String>,
    pub referrer: Option<String>,
    pub at: DateTime<Utc>,
}

/// What one identification did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Identified {
    pub sessions_linked: u64,
    pub touches_written: bool,
}

fn put(patch: &mut Map<String, Value>, prefix: &str, touch: &Touch) {
    let fields = [
        ("source", &touch.source),
        ("medium", &touch.medium),
        ("campaign", &touch.campaign),
        ("landing_url", &touch.landing_url),
        ("referrer", &touch.referrer),
    ];
    for (name, value) in fields {
        patch.insert(
            format!("{prefix}_{name}"),
            value
                .as_deref()
                .map(|v| json!(v.chars().take(1000).collect::<String>()))
                .unwrap_or(Value::Null),
        );
    }
    patch.insert(
        format!("{prefix}_at"),
        json!(touch.at.to_rfc3339_opts(SecondsFormat::Secs, true)),
    );
}

/// The touch fields to write: `latest_touch_*` from `latest`, and
/// `first_touch_*` from `first` only when the person has none yet. Pure.
pub fn touch_patch(
    first_already_set: bool,
    first: Option<&Touch>,
    latest: Option<&Touch>,
) -> Map<String, Value> {
    let mut patch = Map::new();
    if !first_already_set && let Some(first) = first {
        put(&mut patch, "first_touch", first);
    }
    if let Some(latest) = latest {
        put(&mut patch, "latest_touch", latest);
    }
    patch
}

async fn touch(
    state: &EngineState,
    visitor_id: Uuid,
    newest: bool,
) -> Result<Option<Touch>, AppError> {
    let order = if newest { "DESC" } else { "ASC" };
    sqlx::query_as(&format!(
        "SELECT utm_source AS source, utm_medium AS medium, utm_campaign AS campaign, \
                landing_url, referrer, started_at AS at \
           FROM marketing_web_session \
          WHERE visitor_id = $1 AND NOT is_bot AND landing_url IS NOT NULL \
          ORDER BY started_at {order} LIMIT 1"
    ))
    .bind(visitor_id)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Identifies `visitor_id` as `target`; `acting_user` and `ctx` are the
/// caller's (the form intake user, the portal user …).
pub async fn identify(
    state: &EngineState,
    ctx: &SecurityContext,
    acting_user: Uuid,
    visitor_id: Uuid,
    target: IdentifyTarget,
    source: Source,
    marketing_consent: bool,
) -> Result<Identified, AppError> {
    if !marketing_consent || !state.feature_flags().is_on_for_deployment(FLAG) {
        return Ok(Identified::default());
    }
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    let column = target.session_column();
    let linked = sqlx::query(&format!(
        "UPDATE marketing_web_session SET {column} = $2 \
          WHERE visitor_id = $1 AND {column} IS NULL AND NOT is_bot"
    ))
    .bind(visitor_id)
    .bind(target.id())
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    attome_db::tx::commit(tx).await?;

    let entity = target.entity();
    let attrs: Vec<String> = state
        .entities
        .load()
        .get(entity)
        .map(|m| m.attrs.iter().map(|a| a.logicalname.clone()).collect())
        .unwrap_or_default();
    if !attrs.iter().any(|a| a == "latest_touch_at") {
        return Ok(Identified {
            sessions_linked: linked,
            touches_written: false,
        });
    }
    let (first, latest) = (
        touch(state, visitor_id, false).await?,
        touch(state, visitor_id, true).await?,
    );
    if latest.is_none() {
        return Ok(Identified {
            sessions_linked: linked,
            touches_written: false,
        });
    }
    let current: Option<(i64, bool)> = sqlx::query_as(&format!(
        "SELECT row_version, first_touch_at IS NOT NULL FROM {} \
          WHERE id = $1 AND is_active IS NOT FALSE",
        attome_core::quote_ident(entity)
    ))
    .bind(target.id())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some((row_version, first_set)) = current else {
        return Ok(Identified {
            sessions_linked: linked,
            touches_written: false,
        });
    };
    let patch: Map<String, Value> = touch_patch(first_set, first.as_ref(), latest.as_ref())
        .into_iter()
        .filter(|(k, _)| attrs.iter().any(|a| a == k))
        .collect();
    attome_records::entity_crud::update_record_for(
        state,
        ctx,
        acting_user,
        entity,
        target.id(),
        row_version,
        Value::Object(patch),
    )
    .await?;
    tracing::debug!(%visitor_id, entity, source = source.as_str(), linked, "visitor identified");
    Ok(Identified {
        sessions_linked: linked,
        touches_written: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(campaign: &str, at: &str) -> Touch {
        Touch {
            source: Some("google".into()),
            medium: Some("cpc".into()),
            campaign: Some(campaign.into()),
            landing_url: Some("https://www.example.sa/offer".into()),
            referrer: None,
            at: at.parse().unwrap(),
        }
    }

    #[test]
    fn identify_never_overwrites_first_touch() {
        let first = touch("launch", "2026-09-01T10:00:00Z");
        let latest = touch("ramadan", "2026-10-20T10:00:00Z");
        let fresh = touch_patch(false, Some(&first), Some(&latest));
        assert_eq!(fresh["first_touch_campaign"], "launch");
        assert_eq!(fresh["latest_touch_campaign"], "ramadan");
        assert_eq!(fresh["first_touch_at"], "2026-09-01T10:00:00Z");
        assert_eq!(fresh["latest_touch_referrer"], Value::Null);
        let known = touch_patch(true, Some(&first), Some(&latest));
        assert!(!known.contains_key("first_touch_campaign"));
        assert_eq!(known["latest_touch_source"], "google");
        assert!(touch_patch(false, None, None).is_empty());
    }

    #[test]
    fn identify_targets_name_their_session_column() {
        let id = Uuid::now_v7();
        assert_eq!(IdentifyTarget::Lead(id).session_column(), "lead_ref");
        assert_eq!(IdentifyTarget::Contact(id).entity(), "contact");
        assert_eq!(Source::EmailClick.as_str(), "email_click");
    }
}
