//! Nurture track moves (roadmap E9-T4): when a person's lifecycle stage,
//! interest or language changes, they move to the track that fits them
//! best, keeping the content they have seen so nothing repeats; a customer
//! leaves acquisition-only programmes.
//!
//! The best track matches the stage exactly before a track for `any` stage,
//! then the interest exactly before a track with no interest, then the
//! language exactly before `any`; ties go to the lower position. Read from
//! the change feed (consumer [`CONSUMER`]), for programmes with
//! `tracks_enabled` only.

use attome_types::AppError;
use uuid::Uuid;

/// The change-feed consumer name.
pub const CONSUMER: &str = "attome-marketing/nurture_tracks";

/// Events read per pass.
const BATCH: i64 = 500;

/// A track as the choice needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Track {
    pub id: Uuid,
    pub stage: String,
    pub interest: Option<String>,
    pub language: String,
    pub position: i64,
}

/// What is known about the person.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Person {
    pub stage: Option<String>,
    pub interest: Option<String>,
    pub language: Option<String>,
}

fn same(a: Option<&str>, b: &str) -> bool {
    a.is_some_and(|a| a.trim().eq_ignore_ascii_case(b.trim()))
}

/// The track that fits best, if any fits at all.
pub fn best_track(tracks: &[Track], person: &Person) -> Option<Uuid> {
    tracks
        .iter()
        .filter_map(|t| {
            let stage = if same(person.stage.as_deref(), &t.stage) {
                2
            } else if t.stage == "any" {
                1
            } else {
                return None;
            };
            let interest = match t
                .interest
                .as_deref()
                .map(str::trim)
                .filter(|i| !i.is_empty())
            {
                None => 1,
                Some(i) if same(person.interest.as_deref(), i) => 2,
                Some(_) => return None,
            };
            let language = if same(person.language.as_deref(), &t.language) {
                2
            } else if t.language == "any" {
                1
            } else {
                return None;
            };
            Some(((stage, interest, language), -t.position, t.id))
        })
        .max()
        .map(|(_, _, id)| id)
}

/// Reads the next batch of lead and contact changes and moves the people
/// they touch; the number of states changed.
pub async fn run(db: &attome_db::DbPool) -> Result<u64, AppError> {
    let installed: bool =
        sqlx::query_scalar("SELECT to_regclass('marketing_nurture_track') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let mut conn = db.acquire().await.map_err(AppError::internal)?;
    let events = attome_core::change_feed::read_batch(&mut conn, CONSUMER, BATCH).await?;
    drop(conn);
    if events.is_empty() {
        return Ok(0);
    }
    let mut people: Vec<(String, Uuid)> = events
        .iter()
        .filter(|e| e.entity_logicalname == "lead" || e.entity_logicalname == "contact")
        .map(|e| (e.entity_logicalname.clone(), e.record_id))
        .collect();
    people.sort();
    people.dedup();
    let mut changed = 0;
    for (entity, person) in people {
        changed += move_person(db, &entity, person).await?;
    }
    if let Some(last) = events.last() {
        let mut conn = db.acquire().await.map_err(AppError::internal)?;
        attome_core::change_feed::advance(&mut conn, CONSUMER, last).await?;
    }
    Ok(changed)
}

type StateRow = (Uuid, Option<Uuid>, bool);

async fn move_person(db: &attome_db::DbPool, entity: &str, person: Uuid) -> Result<u64, AppError> {
    let states: Vec<StateRow> = sqlx::query_as(
        "SELECT s.program_id, s.track_id, COALESCE(p.acquisition_only, false) \
         FROM marketing_nurture_state s \
         JOIN marketing_nurture_program p ON p.id = s.program_id \
         WHERE s.person_id = $1 AND s.status = 'active' \
           AND COALESCE(p.tracks_enabled, false) = true",
    )
    .bind(person)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    if states.is_empty() {
        return Ok(0);
    }
    let language = if entity == "contact" {
        "preferred_language"
    } else {
        "NULL::text"
    };
    let row: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(&format!(
        "SELECT lifecycle_stage, nurture_interest, {language} FROM {} WHERE id = $1",
        attome_core::quote_ident(entity)
    ))
    .bind(person)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((stage, interest, language)) = row else {
        return Ok(0);
    };
    let facts = Person {
        stage,
        interest,
        language,
    };
    let mut changed = 0;
    for (program, current, acquisition_only) in states {
        if acquisition_only && same(facts.stage.as_deref(), "customer") {
            changed += sqlx::query(
                "UPDATE marketing_nurture_state SET status = 'exited', paused_reason = 'customer' \
                 WHERE program_id = $1 AND person_id = $2 AND status = 'active'",
            )
            .bind(program)
            .bind(person)
            .execute(db)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
            continue;
        }
        let tracks: Vec<(
            Uuid,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<f64>,
        )> = sqlx::query_as(
            "SELECT id, lifecycle_stage, interest, language, position::float8 \
                 FROM marketing_nurture_track \
                 WHERE program_ref = $1 AND (is_active IS NULL OR is_active = true)",
        )
        .bind(program)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let tracks: Vec<Track> = tracks
            .into_iter()
            .map(|(id, stage, interest, language, position)| Track {
                id,
                stage: stage.unwrap_or_else(|| "any".to_owned()),
                interest,
                language: language.unwrap_or_else(|| "any".to_owned()),
                position: position.map_or(0, |p| p as i64),
            })
            .collect();
        let best = best_track(&tracks, &facts);
        if best.is_some() && best != current {
            // Content seen is kept per person, not per track, so a move
            // never sends the same item again.
            changed += sqlx::query(
                "UPDATE marketing_nurture_state SET track_id = $3, position = 0 \
                 WHERE program_id = $1 AND person_id = $2 AND status = 'active'",
            )
            .bind(program)
            .bind(person)
            .bind(best)
            .execute(db)
            .await
            .map_err(AppError::internal)?
            .rows_affected();
        }
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn track(
        id: u128,
        stage: &str,
        interest: Option<&str>,
        language: &str,
        position: i64,
    ) -> Track {
        Track {
            id: Uuid::from_u128(id),
            stage: stage.into(),
            interest: interest.map(str::to_owned),
            language: language.into(),
            position,
        }
    }

    fn person(stage: &str, interest: Option<&str>, language: &str) -> Person {
        Person {
            stage: Some(stage.into()),
            interest: interest.map(str::to_owned),
            language: Some(language.into()),
        }
    }

    #[test]
    fn interest_change_moves_track() {
        let tracks = [
            track(1, "lead", None, "any", 1),
            track(2, "lead", Some("ERP"), "any", 2),
            track(3, "any", Some("CRM"), "ar", 3),
        ];
        assert_eq!(
            best_track(&tracks, &person("lead", None, "en")),
            Some(Uuid::from_u128(1))
        );
        assert_eq!(
            best_track(&tracks, &person("lead", Some("erp"), "en")),
            Some(Uuid::from_u128(2)),
            "the exact interest wins"
        );
        assert_eq!(
            best_track(&tracks, &person("subscriber", Some("CRM"), "ar")),
            Some(Uuid::from_u128(3))
        );
        assert_eq!(
            best_track(&tracks, &person("subscriber", Some("CRM"), "en")),
            None
        );
    }

    #[test]
    fn customer_exits_acquisition_programme() {
        assert!(same(Some("Customer"), "customer"));
        assert!(!same(None, "customer"));
        let tie = [
            track(4, "any", None, "any", 5),
            track(5, "any", None, "any", 2),
        ];
        assert_eq!(
            best_track(&tie, &person("lead", None, "en")),
            Some(Uuid::from_u128(5)),
            "the lower position wins a tie"
        );
    }
}
