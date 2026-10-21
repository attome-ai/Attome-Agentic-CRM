//! Follower notifications (roadmap C2-T1). [`sweep`] reads record changes
//! off the change feed (its own cursor, `attome-notification/follows`) and
//! tells each record's followers in the app: the users who follow it
//! (`follow`) and, implicitly, its owner. The person who made the change is
//! never told about it, and a follower who can no longer read the record is
//! skipped (the record rules decide, as for any read).
//!
//! Which changes a follower hears about is theirs to choose: each
//! notification carries the `record_followed` preference category, so the
//! notification preferences can mute it or move it to another channel.

use attome_core::EngineState;
use attome_core::change_feed::ChangeOperation;
use attome_security::{RecordAction, resolve_entity_access_level, rls_predicate};
use attome_types::AppError;
use uuid::Uuid;

use crate::dispatch::{DispatchRequest, create_dispatch_in_tx};

/// The change-feed consumer.
pub const FOLLOW_CONSUMER: &str = "attome-notification/follows";

/// The preference category of follower notifications.
pub const FOLLOW_CATEGORY: &str = "record_followed";

const SWEEP_BATCH: i64 = 200;

/// Most followers one change notifies.
const MAX_FOLLOWERS: i64 = 200;

/// What a follower is told, by operation.
pub fn verb(op: ChangeOperation) -> Option<&'static str> {
    match op {
        ChangeOperation::Update => Some("updated"),
        ChangeOperation::Delete => Some("deleted"),
        ChangeOperation::Restore => Some("restored"),
        _ => None,
    }
}

/// Who to tell: followers and owner, without the person who made the change.
pub fn recipients(followers: &[Uuid], owner: Option<Uuid>, actor: Option<Uuid>) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = followers.iter().copied().chain(owner).collect();
    out.sort_unstable();
    out.dedup();
    out.retain(|u| Some(*u) != actor && !u.is_nil());
    out
}

/// Whether `user` may read the record now.
async fn can_read(
    state: &EngineState,
    user: Uuid,
    entity_id: Uuid,
    entity: &str,
    record: Uuid,
) -> Result<bool, AppError> {
    let Ok(ctx) = state.base.security.resolve_strict(user).await else {
        // A deactivated or missing user hears nothing.
        return Ok(false);
    };
    let level =
        resolve_entity_access_level(&state.base.db, user, entity_id, entity, RecordAction::Read)
            .await?;
    let pred = rls_predicate(
        &ctx,
        entity_id,
        "",
        level,
        RecordAction::Read.share_capability(),
        2,
    );
    let sql = format!(
        "SELECT EXISTS (SELECT 1 FROM {} WHERE id = $1 {})",
        attome_core::quote_ident(entity),
        pred.as_ref().map_or("", |p| p.sql.as_str())
    );
    let mut q = sqlx::query_scalar::<_, bool>(&sql).bind(record);
    if let Some(p) = &pred {
        q = attome_security::bind_rls_predicate(q, &p.binds);
    }
    q.fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)
}

/// Notifies followers of the changes since the cursor; notifications made.
pub async fn sweep(state: &EngineState) -> Result<u64, AppError> {
    let events = {
        let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::read_batch(&mut conn, FOLLOW_CONSUMER, SWEEP_BATCH).await?
    };
    let Some(last) = events.last().cloned() else {
        return Ok(0);
    };
    let mut sent = 0;
    for event in &events {
        let Some(verb) = event.operation().and_then(verb) else {
            continue;
        };
        // B5-T3: a quiet write (a bulk edit run without automation) tells
        // no follower.
        if event.quiet || event.entity_logicalname == "follow" || event.event_name.is_some() {
            continue;
        }
        let (entity_id, display) = {
            let registry = state.entities.load();
            let Some(meta) = registry.get(&event.entity_logicalname) else {
                continue;
            };
            (meta.entity_id, meta.logicalname.clone())
        };
        let followers: Vec<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM follow \
             WHERE entity_name = $1 AND record_id = $2 AND user_id IS NOT NULL \
               AND (is_active IS NULL OR is_active = true) LIMIT $3",
        )
        .bind(&event.entity_logicalname)
        .bind(event.record_id.to_string())
        .bind(MAX_FOLLOWERS)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let people: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT after->>'owner_ref', after->>'modified_by' FROM entity_change_event WHERE id = $1",
        )
        .bind(event.id)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        let (owner, actor) = people.unwrap_or((None, None));
        let parse = |v: Option<String>| v.and_then(|s| Uuid::parse_str(&s).ok());
        let to = recipients(&followers, parse(owner), parse(actor));
        for user in to {
            if !can_read(
                state,
                user,
                entity_id,
                &event.entity_logicalname,
                event.record_id,
            )
            .await?
            {
                continue;
            }
            let req = DispatchRequest {
                template_key: None,
                locale: "en".to_owned(),
                recipient_user_ref: Some(user),
                is_global: false,
                organization_ref: None,
                channels: Some(vec!["in_app".to_owned()]),
                subject: Some(format!("A {display} you follow was {verb}")),
                body_html: None,
                body_text: Some(format!("{display} {} was {verb}.", event.record_id)),
                route: Some(format!(
                    "/xrm/entity/{}/{}",
                    event.entity_logicalname, event.record_id
                )),
                variables: std::collections::HashMap::new(),
                priority: "normal".to_owned(),
                escalate_after_minutes: None,
                escalate_channels: None,
            };
            let mut tx = attome_db::tx::begin(&state.base.db).await?;
            create_dispatch_in_tx(
                &mut tx,
                &state.base.config.notification,
                req,
                Some(FOLLOW_CATEGORY),
            )
            .await?;
            attome_db::tx::commit(tx).await?;
            sent += 1;
        }
    }
    let mut conn = state.base.db.acquire().await.map_err(AppError::internal)?;
    attome_core::change_feed::advance(&mut conn, FOLLOW_CONSUMER, &last).await?;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_actor_never_hears_of_their_own_change() {
        let (a, b, owner) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        assert_eq!(recipients(&[a, b], Some(owner), Some(a)), vec![b, owner]);
        // The owner also following is told once.
        assert_eq!(recipients(&[owner], Some(owner), None), vec![owner]);
        assert!(recipients(&[], None, None).is_empty());
    }

    #[test]
    fn only_updates_deletes_and_restores_are_told() {
        assert_eq!(verb(ChangeOperation::Update), Some("updated"));
        assert_eq!(verb(ChangeOperation::Delete), Some("deleted"));
        assert_eq!(verb(ChangeOperation::Restore), Some("restored"));
        assert_eq!(verb(ChangeOperation::Create), None);
    }
}
