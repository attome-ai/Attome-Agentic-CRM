//! Webinar sync (roadmap E22-T1) for events held on Zoom or Microsoft
//! Teams (`marketing_event.webinar_provider` and `webinar_id`).
//!
//! Before the webinar, each registered or confirmed registration is pushed
//! to the platform once ([`push_due`]), and keeps the platform's
//! registrant id and the person's own join link. After the webinar ends
//! (half an hour's grace for the report to settle), its attendance is read
//! once ([`pull_due`]): a registration whose email attended becomes
//! `attended` with its minutes online, one that did not becomes `no_show`;
//! cancelled and waitlisted registrations are left alone. The platform
//! calls happen outside any transaction; each result is written after.
//!
//! The `webinar_sync` job runs both every fifteen minutes.

use std::collections::HashMap;

use attome_core::EngineState;
use attome_integration::connector::adapters::video::Attendee;
use attome_integration::connector::adapters::video::webinar::{self, Registrant, WebinarProvider};
use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Registrations pushed per run.
const PUSH_BATCH: i64 = 200;
/// Webinars read per run.
const PULL_BATCH: i64 = 20;

/// One registration as the attendance match needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub id: Uuid,
    pub email: Option<String>,
    pub status: String,
}

/// What attendance makes of a registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub id: Uuid,
    /// `attended` or `no_show`.
    pub status: &'static str,
    pub minutes: i64,
}

/// Matches the platform's attendance to the registrations by email (any
/// case; one person's several joins add up). Only registered, confirmed
/// and attended registrations change. Pure.
pub fn match_attendance(registrations: &[Registration], attendees: &[Attendee]) -> Vec<Outcome> {
    let mut seconds: HashMap<String, i64> = HashMap::new();
    for a in attendees {
        if let Some(email) = &a.email {
            *seconds.entry(email.trim().to_lowercase()).or_default() += a.seconds.max(0);
        }
    }
    registrations
        .iter()
        .filter(|r| matches!(r.status.as_str(), "registered" | "confirmed" | "attended"))
        .map(|r| {
            let attended = r
                .email
                .as_ref()
                .and_then(|e| seconds.get(&e.trim().to_lowercase()))
                .copied();
            match attended {
                Some(s) => Outcome {
                    id: r.id,
                    status: "attended",
                    minutes: (s + 59) / 60,
                },
                // Checked in at the door of a hybrid event: still attended.
                None if r.status == "attended" => Outcome {
                    id: r.id,
                    status: "attended",
                    minutes: 0,
                },
                None => Outcome {
                    id: r.id,
                    status: "no_show",
                    minutes: 0,
                },
            }
        })
        .collect()
}

type PushRow = (Uuid, Option<String>, String, String, String, Option<Uuid>);

/// Pushes registrations not yet at their platform. Returns how many were.
pub async fn push_due(state: &EngineState) -> Result<u32, AppError> {
    let rows: Vec<PushRow> = sqlx::query_as(
        "SELECT r.id, r.attendee_name, r.attendee_email, e.webinar_provider, e.webinar_id, \
                e.webinar_organizer_ref \
           FROM marketing_event_registration r \
           JOIN marketing_event e ON e.id = r.event_ref \
          WHERE e.webinar_provider IS NOT NULL AND e.webinar_id IS NOT NULL \
            AND (e.starts_at IS NULL OR e.starts_at > now()) \
            AND e.is_active IS NOT FALSE AND r.is_active IS NOT FALSE \
            AND r.status IN ('registered', 'confirmed') \
            AND r.webinar_registrant_id IS NULL AND r.attendee_email IS NOT NULL \
          ORDER BY r.created_at LIMIT $1",
    )
    .bind(PUSH_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut pushed = 0;
    for (id, name, email, provider, webinar_id, organizer) in rows {
        let Some(provider) = WebinarProvider::parse(&provider) else {
            continue;
        };
        let (first_name, last_name) = webinar::split_name(name.as_deref().unwrap_or(&email));
        let registrant = Registrant {
            email,
            first_name,
            last_name,
        };
        match webinar::push_registrant(state, provider, &webinar_id, organizer, &registrant).await {
            Ok(done) => {
                sqlx::query(
                    "UPDATE marketing_event_registration \
                        SET webinar_registrant_id = $2, webinar_join_url = $3, modified_at = now() \
                      WHERE id = $1 AND webinar_registrant_id IS NULL",
                )
                .bind(id)
                .bind(&done.registrant_id)
                .bind(&done.join_url)
                .execute(&state.base.db)
                .await
                .map_err(AppError::internal)?;
                pushed += 1;
            }
            Err(e) => {
                tracing::warn!(registration = %id, error = %e, "webinar: registrant not pushed; retried next run");
            }
        }
    }
    Ok(pushed)
}

type PullRow = (Uuid, String, String, Option<Uuid>);

/// Reads the attendance of webinars that ended. Returns how many were read.
pub async fn pull_due(state: &EngineState, now: DateTime<Utc>) -> Result<u32, AppError> {
    let events: Vec<PullRow> = sqlx::query_as(
        "SELECT id, webinar_provider, webinar_id, webinar_organizer_ref FROM marketing_event \
          WHERE webinar_provider IS NOT NULL AND webinar_id IS NOT NULL \
            AND attendance_synced_at IS NULL AND is_active IS NOT FALSE \
            AND ends_at < $1 - interval '30 minutes' AND ends_at > $1 - interval '30 days' \
          ORDER BY ends_at LIMIT $2",
    )
    .bind(now)
    .bind(PULL_BATCH)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut read = 0;
    for (event, provider, webinar_id, organizer) in events {
        let Some(provider) = WebinarProvider::parse(&provider) else {
            continue;
        };
        let attendees = match webinar::attendance(state, provider, &webinar_id, organizer).await {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!(%event, error = %e, "webinar: attendance not read; retried next run");
                continue;
            }
        };
        let registrations: Vec<Registration> = sqlx::query_as::<_, (Uuid, Option<String>, String)>(
            "SELECT id, attendee_email, status FROM marketing_event_registration \
                  WHERE event_ref = $1 AND is_active IS NOT FALSE",
        )
        .bind(event)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?
        .into_iter()
        .map(|(id, email, status)| Registration { id, email, status })
        .collect();
        let outcomes = match_attendance(&registrations, &attendees);
        let ids: Vec<Uuid> = outcomes.iter().map(|o| o.id).collect();
        let statuses: Vec<&str> = outcomes.iter().map(|o| o.status).collect();
        let minutes: Vec<i64> = outcomes.iter().map(|o| o.minutes).collect();
        let mut tx = attome_db::tx::begin(&state.base.db).await?;
        sqlx::query(
            "UPDATE marketing_event_registration r \
                SET status = u.status, webinar_minutes = u.minutes, modified_at = now() \
               FROM UNNEST($1::uuid[], $2::text[], $3::int8[]) AS u(id, status, minutes) \
              WHERE r.id = u.id",
        )
        .bind(&ids)
        .bind(&statuses)
        .bind(&minutes)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        sqlx::query("UPDATE marketing_event SET attendance_synced_at = now() WHERE id = $1")
            .bind(event)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        attome_db::tx::commit(tx).await?;
        tracing::info!(%event, attendees = attendees.len(), registrations = ids.len(), "webinar: attendance read");
        read += 1;
    }
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(n: u128, email: &str, status: &str) -> Registration {
        Registration {
            id: Uuid::from_u128(n),
            email: Some(email.into()),
            status: status.into(),
        }
    }

    fn seen(email: &str, seconds: i64) -> Attendee {
        Attendee {
            name: None,
            email: Some(email.into()),
            seconds,
        }
    }

    #[test]
    fn webinar_sync_matches_attendance_by_email() {
        let regs = [
            reg(1, "Lina@X.com", "registered"),
            reg(2, "omar@x.com", "confirmed"),
            reg(3, "sara@x.com", "cancelled"),
            reg(4, "door@x.com", "attended"),
        ];
        let attendees = [
            seen("lina@x.com", 1200),
            seen("LINA@x.com", 610),
            seen("stranger@x.com", 99),
        ];
        let outcomes = match_attendance(&regs, &attendees);
        assert_eq!(
            outcomes,
            vec![
                Outcome {
                    id: Uuid::from_u128(1),
                    status: "attended",
                    minutes: 31
                },
                Outcome {
                    id: Uuid::from_u128(2),
                    status: "no_show",
                    minutes: 0
                },
                Outcome {
                    id: Uuid::from_u128(4),
                    status: "attended",
                    minutes: 0
                },
            ]
        );
    }
}
