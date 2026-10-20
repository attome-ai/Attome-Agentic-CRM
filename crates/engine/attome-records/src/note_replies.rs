//! C1-T1: note replies are records (`note_reply`), not a JSON list on the
//! note. [`move_legacy_replies`] runs at boot and moves every reply still
//! held in a note's `replies` text into its own `note_reply` row: the same
//! text, attachments, author and time, on the same parent record as the
//! note (a reply is a polymorphic child like the note, so it is read only
//! by someone who can read that record). The note's `replies` is cleared in
//! the same transaction, so the move runs once per note and a restart picks
//! up where it stopped. A list that is not JSON is left where it is and
//! logged, never dropped. The `replies` attribute itself goes in a later
//! release, once every deployment has booted this.
//!
//! A moved reply's attachment keys stay in the note's `files` field, where
//! they were uploaded; the web opens them through the note. New replies
//! keep their files on their own record.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// Notes read per batch.
const BATCH: i64 = 200;

/// One reply as the old JSON list held it.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LegacyReply {
    #[serde(default)]
    pub author_id: Option<String>,
    #[serde(default)]
    pub note_text: String,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub attachments: Option<Value>,
}

/// The replies in a note's old `replies` text; `None` when it is not a JSON
/// list (left in place). Pure.
pub fn parse_legacy(raw: &str) -> Option<Vec<LegacyReply>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some(Vec::new());
    }
    serde_json::from_str::<Vec<LegacyReply>>(trimmed).ok()
}

/// A reply's author: its own id when it is one, else the note's author. Pure.
pub fn author(reply: &LegacyReply, note_author: Option<Uuid>) -> Option<Uuid> {
    reply
        .author_id
        .as_deref()
        .and_then(|id| Uuid::parse_str(id).ok())
        .or(note_author)
}

/// A reply's time: its own when it parses, else the note's. Pure.
pub fn created_at(reply: &LegacyReply, note_created: DateTime<Utc>) -> DateTime<Utc> {
    reply
        .created_at
        .as_deref()
        .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
        .map_or(note_created, |t| t.with_timezone(&Utc))
}

/// A note with replies to move: id, parent, replies text, then the
/// ownership the replies inherit (author, owner, owner type, organization)
/// and the note's time.
type NoteRow = (
    Uuid,
    String,
    String,
    String,
    Option<Uuid>,
    Option<Uuid>,
    i16,
    Option<Uuid>,
    DateTime<Utc>,
);

/// Moves every note's JSON replies into `note_reply` rows. Idempotent;
/// returns how many replies moved.
pub async fn move_legacy_replies(db: &DbPool) -> Result<u64, AppError> {
    let tables: (bool, bool) = sqlx::query_as(
        "SELECT to_regclass('note') IS NOT NULL, to_regclass('note_reply') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if tables != (true, true) {
        return Ok(0);
    }
    let mut moved = 0u64;
    let mut after = Uuid::nil();
    loop {
        let notes: Vec<NoteRow> = sqlx::query_as(
            "SELECT id, entity_name, record_id, replies, created_by, owner_ref, owner_type, \
                    organization_ref, created_at \
               FROM note \
              WHERE id > $1 AND replies IS NOT NULL AND btrim(replies) <> '' \
              ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(BATCH)
        .fetch_all(db)
        .await
        .map_err(AppError::internal)?;
        let Some(last) = notes.last() else {
            break;
        };
        after = last.0;
        for (
            note_id,
            entity_name,
            record_id,
            raw,
            created_by,
            owner_ref,
            owner_type,
            organization_ref,
            note_created,
        ) in notes
        {
            let Some(replies) = parse_legacy(&raw) else {
                tracing::warn!(%note_id, "note replies are not a JSON list; left on the note");
                continue;
            };
            let mut tx = attome_db::tx::begin(db).await?;
            for reply in &replies {
                let attachments = reply
                    .attachments
                    .as_ref()
                    .filter(|a| a.as_array().is_some_and(|a| !a.is_empty()))
                    .map(Value::to_string);
                sqlx::query(
                    "INSERT INTO note_reply \
                       (id, note_id, entity_name, record_id, note_text, attachments, \
                        created_by, owner_ref, owner_type, organization_ref, created_at, modified_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)",
                )
                .bind(Uuid::now_v7())
                .bind(note_id.to_string())
                .bind(&entity_name)
                .bind(&record_id)
                .bind(&reply.note_text)
                .bind(attachments)
                .bind(author(reply, created_by))
                .bind(owner_ref)
                .bind(owner_type)
                .bind(organization_ref)
                .bind(created_at(reply, note_created))
                .execute(&mut *tx)
                .await
                .map_err(AppError::internal)?;
            }
            // Cleared only if nobody changed it meanwhile; otherwise the
            // rows roll back and the next boot moves the newer list.
            let cleared =
                sqlx::query("UPDATE note SET replies = NULL WHERE id = $1 AND replies = $2")
                    .bind(note_id)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(AppError::internal)?
                    .rows_affected();
            if cleared == 1 {
                tx.commit().await.map_err(AppError::internal)?;
                moved += replies.len() as u64;
            } else {
                tx.rollback().await.map_err(AppError::internal)?;
            }
        }
    }
    if moved > 0 {
        tracing::info!(moved, "note replies moved to note_reply records");
    }
    Ok(moved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_old_list_parses_and_bad_text_is_left_alone() {
        let raw = r#"[{"id":"x","author_id":"0192a3b4-0000-7000-8000-000000000001","author_name":"Sara",
            "note_text":"First","created_at":"2026-08-14T11:00:00Z",
            "attachments":[{"name":"a.pdf","key":"note/n/files/k"}]},{"note_text":"Second"}]"#;
        let replies = parse_legacy(raw).unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].note_text, "First");
        assert_eq!(parse_legacy("  "), Some(Vec::new()));
        assert_eq!(parse_legacy("not json"), None);
    }

    #[test]
    fn author_and_time_fall_back_to_the_note() {
        let note_author = Uuid::now_v7();
        let note_created = DateTime::parse_from_rfc3339("2026-08-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let own = LegacyReply {
            author_id: Some("0192a3b4-0000-7000-8000-000000000001".into()),
            note_text: String::new(),
            created_at: Some("2026-08-14T11:00:00Z".into()),
            attachments: None,
        };
        assert_eq!(
            author(&own, Some(note_author)),
            Uuid::parse_str("0192a3b4-0000-7000-8000-000000000001").ok()
        );
        assert_eq!(
            created_at(&own, note_created).to_rfc3339(),
            "2026-08-14T11:00:00+00:00"
        );
        let bare = LegacyReply {
            author_id: Some("You".into()),
            note_text: String::new(),
            created_at: Some("yesterday".into()),
            attachments: None,
        };
        assert_eq!(author(&bare, Some(note_author)), Some(note_author));
        assert_eq!(created_at(&bare, note_created), note_created);
    }
}
