//! D22-T5: one analysis per finished call transcript (V2-D1588 (3)).
//!
//! **Queueing.** When N22 finishes a recording's transcript (the app's
//! `TranscribeRecording` job, after it commits), [`on_transcript_final`]
//! checks the call intelligence module and the setting [`SETTING`], finds the
//! activity the recording's document is attached to, and, unless an analysis
//! of that activity and transcript version (the transcript's time) exists
//! already, in one transaction: stores the **redacted** copy of the
//! transcript (`call_transcript_redacted`, migration 0372: emails, phone
//! numbers and IBANs masked with the AI masker, each segment keeping its
//! speaker label), creates the `call_analysis` row as `queued`, and queues
//! the [`JOB`] job. The analysis never runs during the call.
//!
//! **Running.** [`run`] reads the redacted copy only, never the raw
//! transcript. Talk patterns need to know who is staff and who is the
//! customer, so every segment needs a role label ([`role_of`]: the
//! dual-channel roles `staff`/`agent` and `customer`/`caller`); a call with
//! any other or missing label is marked `skipped`. Otherwise it computes the
//! talk patterns (D22-T3) and the tracker hits by exact term (D22-T4; example
//! phrases need embeddings, which this job does not compute), then, in one
//! transaction, replaces the analysis's `tracker_hit` findings and marks it
//! `done` with its figures. A failure marks it `failed`.

use attome_core::EngineState;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use super::talk::{Segment, Speaker, talk_patterns};
use super::trackers::{CompiledTrackers, chunk_transcript, match_chunk};

/// The job's name; its payload is [`AnalysePayload`].
pub const JOB: &str = "callintel_analyse";
/// The setting that turns call analysis on (off by default).
pub const SETTING: &str = "callintel.enabled";

/// The job's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysePayload {
    pub analysis_id: Uuid,
}

/// The role a speaker label names, if any. Pure.
pub fn role_of(label: &str) -> Option<Speaker> {
    match label.trim().to_ascii_lowercase().as_str() {
        "staff" | "agent" | "rep" => Some(Speaker::Staff),
        "customer" | "caller" | "client" => Some(Speaker::Customer),
        _ => None,
    }
}

/// The redacted copy of stored transcript segments (`[{start, end, text,
/// speaker?}]`, seconds): times in milliseconds, text masked. Pure.
pub fn redact(segments: &Value) -> Vec<Value> {
    let mut masker = attome_ai::pii_mask::Masker::new();
    segments
        .as_array()
        .map(|list| {
            list.iter()
                .map(|s| {
                    let ms = |key: &str| {
                        s.get(key)
                            .and_then(Value::as_f64)
                            .map_or(0, |v| (v.max(0.0) * 1000.0).round() as u64)
                    };
                    json!({
                        "start_ms": ms("start"),
                        "end_ms": ms("end"),
                        "speaker": s.get("speaker").and_then(Value::as_str),
                        "text": masker.mask_text(s.get("text").and_then(Value::as_str).unwrap_or("")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The redacted segments as talk segments; `None` when any lacks a role.
/// Pure.
pub fn labelled(redacted: &[Value]) -> Option<Vec<Segment>> {
    redacted
        .iter()
        .map(|s| {
            Some(Segment {
                speaker: role_of(s.get("speaker")?.as_str()?)?,
                start_ms: s.get("start_ms").and_then(Value::as_u64).unwrap_or(0),
                end_ms: s.get("end_ms").and_then(Value::as_u64).unwrap_or(0),
                text: s
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            })
        })
        .collect()
}

fn enabled(state: &EngineState) -> bool {
    if !state.modules.load().has(attome_modules::MODULE_CALLINTEL) {
        return false;
    }
    let Some(descriptor) = attome_core::setting_registry().get(SETTING) else {
        return false;
    };
    let (value, _) = state.settings.load().resolve(descriptor, None, None);
    value.as_bool().unwrap_or(false)
}

type TranscriptRow = (Uuid, String, Value);

/// Queues the analysis of `document`'s finished transcript when call
/// analysis is on and the document is a call activity's; the analysis id,
/// or `None` when nothing was queued.
pub async fn on_transcript_final(
    state: &EngineState,
    document: Uuid,
) -> Result<Option<Uuid>, AppError> {
    if !enabled(state) {
        return Ok(None);
    }
    let db = &state.base.db;
    let row: Option<TranscriptRow> = sqlx::query_as(
        "SELECT d.record_id::uuid, t.transcribed_at::text, t.segments \
           FROM attome_document d \
           JOIN recording_transcript t ON t.file_key = d.file \
          WHERE d.id = $1 AND d.entity_name = 'activity' \
            AND (d.is_active IS NULL OR d.is_active = true)",
    )
    .bind(document)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((activity, version, segments)) = row else {
        return Ok(None);
    };
    let redacted = Value::Array(redact(&segments));
    let analysis = Uuid::now_v7();
    let job = attome_core::jobs::JOB_TYPES
        .job(
            JOB,
            &AnalysePayload {
                analysis_id: analysis,
            },
        )
        .map_err(AppError::internal)?;
    let mut tx = attome_db::tx::begin(db).await?;
    // One analysis per activity and transcript version.
    let created: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO call_analysis (id, activity_id, transcript_version, status, is_active, \
             row_version, created_at) \
         SELECT $1, $2, $3, 'queued', true, 0, now() \
          WHERE NOT EXISTS (SELECT 1 FROM call_analysis \
                             WHERE activity_id = $2 AND transcript_version = $3 \
                               AND (is_active IS NULL OR is_active = true)) \
         RETURNING id",
    )
    .bind(analysis)
    .bind(activity.to_string())
    .bind(&version)
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    if created.is_none() {
        tx.rollback().await.map_err(AppError::internal)?;
        return Ok(None);
    }
    sqlx::query("INSERT INTO call_transcript_redacted (analysis_id, segments) VALUES ($1, $2)")
        .bind(analysis)
        .bind(&redacted)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_jobs::enqueue_in_tx(&mut tx, attome_core::jobs::EngineJob::Registered(job))
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(Some(analysis))
}

async fn mark(state: &EngineState, analysis: Uuid, status: &str) -> Result<(), AppError> {
    sqlx::query(
        "UPDATE call_analysis SET status = $2, analysed_at = now(), \
             row_version = row_version + 1 WHERE id = $1",
    )
    .bind(analysis)
    .bind(status)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Runs one queued analysis; its final status (`done`, `skipped`, `failed`).
pub async fn run(state: &EngineState, analysis: Uuid) -> Result<&'static str, AppError> {
    match analyse(state, analysis).await {
        Ok("done") => {
            // D22-T6: one model call over the redacted copy; a refusal or a
            // failure there leaves the analysis done.
            match super::extract::extract(state, analysis).await {
                Ok(found) => tracing::debug!(%analysis, found, "call extraction"),
                Err(error) => tracing::warn!(%analysis, %error, "call extraction not made"),
            }
            Ok("done")
        }
        Ok(status) => Ok(status),
        Err(error) => {
            tracing::warn!(%analysis, %error, "call analysis failed");
            mark(state, analysis, "failed").await?;
            Ok("failed")
        }
    }
}

type TrackerDbRow = (Uuid, Option<f64>, Option<String>);

async fn analyse(state: &EngineState, analysis: Uuid) -> Result<&'static str, AppError> {
    let db = &state.base.db;
    let stored: Option<Value> =
        sqlx::query_scalar("SELECT segments FROM call_transcript_redacted WHERE analysis_id = $1")
            .bind(analysis)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let Some(Value::Array(redacted)) = stored else {
        mark(state, analysis, "skipped").await?;
        return Ok("skipped");
    };
    let Some(segments) = labelled(&redacted).filter(|s| !s.is_empty()) else {
        tracing::info!(%analysis, "call analysis skipped: speakers are not labelled staff and customer");
        mark(state, analysis, "skipped").await?;
        return Ok("skipped");
    };
    let patterns = talk_patterns(&segments);
    let rows: Vec<TrackerDbRow> = sqlx::query_as(
        "SELECT id, version::float8, exact_terms FROM call_tracker \
          WHERE COALESCE(enabled, true) AND (is_active IS NULL OR is_active = true)",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let compiled = CompiledTrackers::build(
        rows.into_iter()
            .map(|(id, version, terms)| {
                let terms = terms
                    .unwrap_or_default()
                    .split(['\n', ','])
                    .map(str::trim)
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                    .collect();
                (id, version.unwrap_or(0.0) as i64, terms, Vec::new())
            })
            .collect(),
    );
    let mut hits = Vec::new();
    for chunk in chunk_transcript(&segments) {
        for hit in match_chunk(&compiled, &chunk.text, None) {
            hits.push((
                hit.tracker,
                chunk.text.clone(),
                chunk.start_ms,
                chunk.end_ms,
            ));
        }
    }

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query("DELETE FROM call_finding WHERE analysis_ref = $1 AND kind = 'tracker_hit'")
        .bind(analysis)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    for (tracker, text, start, end) in &hits {
        sqlx::query(
            "INSERT INTO call_finding (id, analysis_ref, kind, tracker_ref, text, start_ms, end_ms, \
                 is_active, row_version, created_at) \
             VALUES ($1, $2, 'tracker_hit', $3, $4, $5, $6, true, 0, now())",
        )
        .bind(Uuid::now_v7())
        .bind(analysis)
        .bind(tracker)
        .bind(text)
        .bind(*start as f64)
        .bind(*end as f64)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "UPDATE call_analysis SET status = 'done', analysed_at = now(), \
             staff_talk_share = $2, longest_monologue_s = $3, customer_longest_story_s = $4, \
             interruptions = $5, staff_questions = $6, customer_questions = $7, \
             staff_words_per_minute = $8, row_version = row_version + 1 \
          WHERE id = $1",
    )
    .bind(analysis)
    .bind(patterns.staff_talk_share)
    .bind(patterns.longest_monologue_s)
    .bind(patterns.customer_longest_story_s)
    .bind(f64::from(patterns.interruptions))
    .bind(f64::from(patterns.staff_questions))
    .bind(f64::from(patterns.customer_questions))
    .bind(patterns.staff_words_per_minute)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    // D22-T11: other engines read the done analysis from the record.
    attome_core::change_feed::emit_named(
        &mut tx,
        "call_analysis",
        analysis,
        attome_core::ChangeOperation::Update,
        super::signals::ANALYSIS_DONE_EVENT,
    )
    .await?;
    attome_db::tx::commit(tx).await?;
    Ok("done")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_come_from_role_labels_only() {
        assert_eq!(role_of("Agent"), Some(Speaker::Staff));
        assert_eq!(role_of("customer"), Some(Speaker::Customer));
        assert_eq!(role_of("SPEAKER_00"), None);
    }

    #[test]
    fn the_copy_is_redacted_and_timed_in_ms() {
        let raw = json!([
            {"start": 0.0, "end": 2.5, "text": "write to ali@example.com", "speaker": "staff"},
            {"start": 2.5, "end": 4.0, "text": "call me on +966501234567", "speaker": "customer"},
        ]);
        let copy = redact(&raw);
        let text = serde_json::to_string(&copy).unwrap();
        assert!(!text.contains("ali@example.com"), "{text}");
        assert!(!text.contains("501234567"), "{text}");
        assert_eq!(copy[0]["end_ms"], 2500);
        assert_eq!(labelled(&copy).map(|s| s.len()), Some(2));
    }

    #[test]
    fn an_unlabelled_segment_skips_the_call() {
        let copy = redact(&json!([
            {"start": 0.0, "end": 1.0, "text": "hello", "speaker": "staff"},
            {"start": 1.0, "end": 2.0, "text": "hi"},
        ]));
        assert!(labelled(&copy).is_none());
    }
}
