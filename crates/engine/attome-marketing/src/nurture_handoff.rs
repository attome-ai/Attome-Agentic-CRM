//! E9-T5: a nurtured person is handed to sales once each time their score
//! rises to the programme's hand-off score.
//!
//! D18's points models write `points_score` (one row per model and record)
//! but emit no crossing, so the crossing is found here: a programme names the
//! points model (`handoff_score_model`, its id) and the score
//! (`handoff_threshold`), and each nurture state remembers whether its
//! person's score is at or above it (`above_threshold`, migration 0368).
//! [`detect`] (run by the nurture tick) compares the two: rising to the
//! score is a crossing ([`crossing`]), falling below it re-arms. A crossing,
//! in one transaction, inserts the `marketing_handoff` row (its
//! `crossing_event_id` a fresh id, unique, so a crossing is handed off once),
//! with a summary (the score, the content most recently seen and a next step),
//! moves the state to `handed_off` (so the journey run waiting on it goes on,
//! E9-T3) and writes a business audit event. After the commit, [`assigned`]
//! qualifies the person (`lifecycle_stage` = `sales_qualified`, through the
//! record engine as the programme's author), records the owner the app's
//! D4 assignment left on the record, sets the due time from the programme's
//! SLA hours on the working calendar (E9-T7) and notifies the assignee. A
//! state that is handed off keeps its row, for recycling (E9-T6).

use attome_core::EngineState;
use attome_types::AppError;
use chrono::Utc;
use serde_json::{Value, json};
use uuid::Uuid;

/// States checked per pass.
const BATCH: i64 = 1_000;
/// Content items a summary lists.
const SUMMARY_CONTENT: i64 = 10;

/// What a score means for a state: `Some(true)` a crossing (it rose to the
/// threshold), `Some(false)` re-armed (it fell below), `None` nothing new.
/// Pure.
pub fn crossing(score: f64, threshold: f64, above: bool) -> Option<bool> {
    match (score >= threshold, above) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    }
}

/// A hand-off just made.
#[derive(Debug, Clone, PartialEq)]
pub struct NewHandoff {
    pub id: Uuid,
    pub program: Uuid,
    pub person: Uuid,
    pub entity: String,
    pub sla_hours: Option<f64>,
}

/// A candidate: programme, person, entity, above, threshold, score, SLA hours.
type Candidate = (Uuid, Uuid, Option<String>, bool, f64, f64, Option<f64>);

/// Finds the crossings among active nurture states and hands each person
/// off; the hand-offs made.
pub async fn detect(state: &EngineState) -> Result<Vec<NewHandoff>, AppError> {
    let db = &state.base.db;
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('points_score') IS NOT NULL \
            AND to_regclass('marketing_nurture_program') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(Vec::new());
    }
    let candidates: Vec<Candidate> = sqlx::query_as(
        "SELECT s.program_id, s.person_id, s.person_entity, s.above_threshold, \
                p.handoff_threshold::float8, sc.score::float8, p.sla_business_hours::float8 \
           FROM marketing_nurture_state s \
           JOIN marketing_nurture_program p ON p.id = s.program_id AND p.is_active IS NOT FALSE \
           JOIN points_score sc ON sc.model_id = p.handoff_score_model \
                               AND sc.record_id = s.person_id::text \
                               AND sc.is_active IS NOT FALSE \
          WHERE s.status = 'active' AND p.handoff_threshold IS NOT NULL \
            AND sc.score IS NOT NULL \
          ORDER BY s.program_id, s.person_id LIMIT $1",
    )
    .bind(BATCH)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut made = Vec::new();
    for (program, person, entity, above, threshold, score, sla_hours) in candidates {
        match crossing(score, threshold, above) {
            Some(true) => {
                let entity = entity.unwrap_or_else(|| "contact".to_owned());
                if let Some(id) =
                    hand_off(state, program, person, &entity, score, threshold).await?
                {
                    made.push(NewHandoff {
                        id,
                        program,
                        person,
                        entity,
                        sla_hours,
                    });
                }
            }
            Some(false) => {
                sqlx::query(
                    "UPDATE marketing_nurture_state SET above_threshold = false \
                      WHERE program_id = $1 AND person_id = $2",
                )
                .bind(program)
                .bind(person)
                .execute(db)
                .await
                .map_err(AppError::internal)?;
            }
            None => {}
        }
    }
    Ok(made)
}

/// What sales sees first: the score, the content most recently seen and a
/// next step. Pure over what was read.
pub fn summary(score: f64, threshold: f64, seen: &[(String, String)]) -> Value {
    json!({
        "score": score,
        "threshold": threshold,
        "content_seen": seen
            .iter()
            .map(|(kind, id)| json!({ "kind": kind, "id": id }))
            .collect::<Vec<_>>(),
        "next_step": "call",
    })
}

/// The crossing's hand-off, in one transaction; `None` when the state had
/// already moved on (another pass handed it off).
async fn hand_off(
    state: &EngineState,
    program: Uuid,
    person: Uuid,
    entity: &str,
    score: f64,
    threshold: f64,
) -> Result<Option<Uuid>, AppError> {
    let db = &state.base.db;
    let seen: Vec<(String, String)> = sqlx::query_as(
        "SELECT content_kind, content_id FROM marketing_content_seen \
          WHERE person_id = $1 ORDER BY first_seen_at DESC LIMIT $2",
    )
    .bind(person)
    .bind(SUMMARY_CONTENT)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(db).await?;
    let moved = sqlx::query(
        "UPDATE marketing_nurture_state SET status = 'handed_off', above_threshold = true \
          WHERE program_id = $1 AND person_id = $2 AND status = 'active'",
    )
    .bind(program)
    .bind(person)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if moved == 0 {
        attome_db::tx::commit(tx).await?;
        return Ok(None);
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO marketing_handoff \
            (program_id, person_id, crossing_event_id, score, summary, status) \
         VALUES ($1, $2, uuidv7(), $3, $4, 'pending') RETURNING id",
    )
    .bind(program)
    .bind(person)
    .bind(score)
    .bind(summary(score, threshold, &seen))
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            entity,
            person,
            attome_audit::AuditOperation::Update,
            "marketing.handed_to_sales",
            Uuid::nil(),
        )
        .comment(format!(
            "score {score} reached the hand-off score {threshold} (hand-off {id})"
        )),
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(id))
}

/// After a hand-off: qualifies the person, records who owns them now (the
/// app has run D4 assignment for a lead), sets when sales must decide, and
/// notifies that owner. A step that fails is logged; the hand-off stands.
pub async fn assigned(state: &EngineState, handoff: &NewHandoff) -> Result<(), AppError> {
    let db = &state.base.db;
    let author: Option<Uuid> = sqlx::query_scalar(
        "SELECT COALESCE(owner_ref, created_by) FROM marketing_nurture_program WHERE id = $1",
    )
    .bind(handoff.program)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    if let Err(error) = qualify(state, author, &handoff.entity, handoff.person).await {
        tracing::warn!(%error, person = %handoff.person, "hand-off: the person was not qualified");
    }
    let owner: Option<Uuid> = sqlx::query_scalar(&format!(
        "SELECT owner_ref FROM {} WHERE id = $1",
        attome_core::quote_ident(&handoff.entity)
    ))
    .bind(handoff.person)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let due = crate::handoff_sla::default_calendar()
        .and_then(|calendar| crate::handoff_sla::due_at(&calendar, Utc::now(), handoff.sla_hours));
    let due = match due {
        Ok(due) => Some(due),
        Err(error) => {
            tracing::warn!(%error, "hand-off: no due time");
            None
        }
    };
    sqlx::query("UPDATE marketing_handoff SET assigned_to = $2, due_at = $3 WHERE id = $1")
        .bind(handoff.id)
        .bind(owner)
        .bind(due)
        .execute(db)
        .await
        .map_err(AppError::internal)?;
    let Some(owner) = owner else {
        return Ok(());
    };
    let request = attome_notification::dispatch::DispatchRequest {
        template_key: None,
        locale: "en".to_string(),
        recipient_user_ref: Some(owner),
        is_global: false,
        organization_ref: None,
        channels: None,
        subject: Some("A lead is ready for sales".to_owned()),
        body_html: None,
        body_text: Some(
            "Marketing handed a person to you: their score reached the hand-off score. \
             Accept or return the hand-off."
                .to_owned(),
        ),
        route: Some(format!("/xrm/entity/{}/{}", handoff.entity, handoff.person)),
        variables: std::collections::HashMap::new(),
        priority: "high".to_string(),
        escalate_after_minutes: None,
        escalate_channels: None,
    };
    if let Err(error) =
        attome_notification::dispatch::create_dispatch(db, &state.base.config.notification, request)
            .await
    {
        tracing::warn!(%error, handoff = %handoff.id, "hand-off: notification failed");
    }
    Ok(())
}

/// Sets the person's `lifecycle_stage` to `sales_qualified` through the
/// record engine, as `author` (the programme's owner).
async fn qualify(
    state: &EngineState,
    author: Option<Uuid>,
    entity: &str,
    person: Uuid,
) -> Result<(), AppError> {
    let Some(author) = author else {
        return Err(AppError::Validation(
            "the programme has no owner to act as".into(),
        ));
    };
    let version: Option<i64> = sqlx::query_scalar(&format!(
        "SELECT row_version FROM {} WHERE id = $1",
        attome_core::quote_ident(entity)
    ))
    .bind(person)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let Some(version) = version else {
        return Err(AppError::NotFound);
    };
    let ctx = state.base.security.resolve_strict(author).await?;
    attome_records::entity_crud::update_record_for(
        state,
        &ctx,
        author,
        entity,
        person,
        version,
        json!({ "lifecycle_stage": "sales_qualified" }),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_crossing_is_the_rise_to_the_threshold() {
        assert_eq!(
            crossing(50.0, 50.0, false),
            Some(true),
            "reaching it crosses"
        );
        assert_eq!(crossing(80.0, 50.0, true), None, "staying above does not");
        assert_eq!(
            crossing(40.0, 50.0, true),
            Some(false),
            "falling below re-arms"
        );
        assert_eq!(crossing(40.0, 50.0, false), None);
    }

    #[test]
    fn the_summary_lists_what_was_seen() {
        let s = summary(
            72.0,
            60.0,
            &[
                ("email".into(), "d-1".into()),
                ("email".into(), "d-2".into()),
            ],
        );
        assert_eq!(s["score"], json!(72.0));
        assert_eq!(s["content_seen"].as_array().map(Vec::len), Some(2));
        assert_eq!(s["next_step"], json!("call"));
    }
}
