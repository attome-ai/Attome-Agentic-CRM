//! D22-T6: questions, objections, next steps, price mentions and scorecard
//! proposals from one model call per call.
//!
//! After [`super::job::run`] finishes an analysis, [`extract`] sends the
//! **redacted** transcript (never audio, never the raw text) with the
//! versioned prompt [`EXTRACT_PROMPT_V1`] to the deployment's generation
//! model for [`TASK`] (the self-hosted one unless the AI provider settings
//! name another), once, through the AI budget guard as the call's owner; a
//! refused budget or a failed call leaves the analysis as it is and is
//! logged. The reply is read as JSON ([`parse_reply`]): an item whose
//! `start_ms` does not fall inside a segment of the transcript is dropped,
//! so nothing is placed where nothing was said. Findings replace the
//! analysis's earlier findings of those kinds; scorecard answers are written
//! as **proposed** values only (`confirmed_value` is left for a person);
//! the analysis keeps the model's id. No sentiment of staff is scored.

use attome_core::EngineState;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

/// The AI task name for this call.
pub const TASK: &str = "callintel.extract";

/// The extraction prompt, version 1. The transcript follows as untrusted
/// content; the model answers one JSON object.
pub const EXTRACT_PROMPT_V1: &str = "You read a sales or service call transcript. Each segment is \
given as [start_ms-end_ms speaker] text. Personal details are masked as tokens like [EMAIL_1]; keep \
them as they are. Answer with one JSON object and nothing else: {\"questions\": [], \"objections\": [], \
\"next_steps\": [], \"price_mentions\": [], \"scorecard\": []}. Each item of the first four lists is \
{\"text\": short quote or summary, \"start_ms\": the start_ms of the segment it comes from, \
\"speaker\": \"staff\" or \"customer\"}. Each scorecard item is {\"question_key\": a key from the \
scorecard given, \"value\": \"yes\", \"no\" or \"unclear\", \"start_ms\": the segment that shows it}. \
Use only start_ms values that appear in the transcript. Do not judge anyone's mood or tone.";

/// One item the model found.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Item {
    pub text: String,
    pub start_ms: u64,
    #[serde(default)]
    pub speaker: Option<String>,
}

/// One proposed scorecard answer.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ScorecardItem {
    pub question_key: String,
    pub value: String,
    pub start_ms: u64,
}

/// The model's reply.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct Extraction {
    #[serde(default)]
    pub questions: Vec<Item>,
    #[serde(default)]
    pub objections: Vec<Item>,
    #[serde(default)]
    pub next_steps: Vec<Item>,
    #[serde(default)]
    pub price_mentions: Vec<Item>,
    #[serde(default)]
    pub scorecard: Vec<ScorecardItem>,
}

/// The reply as an [`Extraction`], keeping only items whose `start_ms`
/// falls inside one of `spans` (start inclusive, end exclusive) and
/// scorecard answers with a known key and value. `None` when the reply is
/// not the JSON asked for. Pure.
pub fn parse_reply(reply: &str, spans: &[(u64, u64)], keys: &[String]) -> Option<Extraction> {
    let body = reply.trim();
    let body = body
        .strip_prefix("```json")
        .or_else(|| body.strip_prefix("```"))
        .map(|b| b.trim_end_matches("```").trim())
        .unwrap_or(body);
    let mut out: Extraction = serde_json::from_str(body).ok()?;
    let inside = |ms: u64| spans.iter().any(|(start, end)| *start <= ms && ms < *end);
    for list in [
        &mut out.questions,
        &mut out.objections,
        &mut out.next_steps,
        &mut out.price_mentions,
    ] {
        list.retain(|i| inside(i.start_ms) && !i.text.trim().is_empty());
        for item in list.iter_mut() {
            item.text = item.text.trim().chars().take(500).collect();
            if !matches!(item.speaker.as_deref(), Some("staff" | "customer")) {
                item.speaker = None;
            }
        }
    }
    out.scorecard.retain(|s| {
        inside(s.start_ms)
            && keys.contains(&s.question_key)
            && matches!(s.value.as_str(), "yes" | "no" | "unclear")
    });
    Some(out)
}

/// The scorecard's question keys: a JSON array of `{key}` objects or of
/// strings, else one key per line before a colon. Pure.
pub fn scorecard_keys(questions: &str) -> Vec<String> {
    if let Ok(Value::Array(items)) = serde_json::from_str::<Value>(questions) {
        return items
            .iter()
            .filter_map(|i| {
                i.get("key")
                    .and_then(Value::as_str)
                    .or_else(|| i.as_str())
                    .map(str::to_owned)
            })
            .collect();
    }
    questions
        .lines()
        .filter_map(|l| l.split(':').next())
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(str::to_owned)
        .collect()
}

type ScorecardRow = (Uuid, Option<f64>, Option<String>);

/// Runs the extraction for `analysis`; how many findings and answers were
/// written (0 when the model was not asked or did not answer usefully).
pub async fn extract(state: &EngineState, analysis: Uuid) -> Result<usize, AppError> {
    let db = &state.base.db;
    let row: Option<(Value, Option<Uuid>)> = sqlx::query_as(
        "SELECT r.segments, COALESCE(act.owner_ref, act.created_by) \
           FROM call_transcript_redacted r \
           JOIN call_analysis a ON a.id = r.analysis_id \
           LEFT JOIN activity act ON act.id::text = a.activity_id \
          WHERE r.analysis_id = $1",
    )
    .bind(analysis)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((Value::Array(segments), Some(owner))) = row else {
        return Ok(0);
    };
    let spans: Vec<(u64, u64)> = segments
        .iter()
        .map(|s| {
            let at = |k: &str| s.get(k).and_then(Value::as_u64).unwrap_or(0);
            (at("start_ms"), at("end_ms").max(at("start_ms") + 1))
        })
        .collect();
    let transcript: String = segments
        .iter()
        .map(|s| {
            format!(
                "[{}-{} {}] {}",
                s.get("start_ms").and_then(Value::as_u64).unwrap_or(0),
                s.get("end_ms").and_then(Value::as_u64).unwrap_or(0),
                s.get("speaker")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                s.get("text").and_then(Value::as_str).unwrap_or("")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let scorecard: Option<ScorecardRow> = sqlx::query_as(
        "SELECT id, version::float8, questions FROM call_scorecard \
          WHERE (is_active IS NULL OR is_active = true) \
          ORDER BY version DESC NULLS LAST, created_at DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let keys = scorecard
        .as_ref()
        .and_then(|(_, _, q)| q.as_deref())
        .map(scorecard_keys)
        .unwrap_or_default();

    let security = state.base.security.resolve_strict(owner).await?;
    let ctx = attome_ai::context::ActionContext::user(security);
    let client = attome_ai::inference_client::client_for(state, TASK).await?;
    let mut request =
        attome_inference::generate::GenerationRequest::new(attome_ai::prompt::assemble(&[
            attome_ai::prompt::Segment::trusted(format!(
                "{EXTRACT_PROMPT_V1}\nScorecard question keys: {}",
                keys.join(", ")
            )),
            attome_ai::prompt::Segment::untrusted("call transcript", transcript),
        ]));
    request.temperature = 0.0;
    let grant = match attome_ai::budget_guard::admit(
        state,
        &ctx,
        attome_inference::budget::Priority::Chat,
        TASK,
        &mut request,
    )
    .await
    {
        Ok(grant) => grant,
        Err(error) => {
            tracing::info!(%analysis, %error, "call extraction skipped: budget");
            return Ok(0);
        }
    };
    let generated = match client.generate(request).await {
        Ok(generated) => generated,
        Err(error) => {
            tracing::warn!(%analysis, error = %error, "call extraction: the model did not answer");
            return Ok(0);
        }
    };
    grant.settle(state, &generated.usage).await;
    let Some(found) = parse_reply(&generated.text, &spans, &keys) else {
        tracing::warn!(%analysis, "call extraction: the reply was not the JSON asked for");
        return Ok(0);
    };

    let mut tx = attome_db::tx::begin(db).await?;
    sqlx::query(
        "DELETE FROM call_finding WHERE analysis_ref = $1 \
            AND kind IN ('question', 'objection', 'next_step', 'price_mention')",
    )
    .bind(analysis)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;
    let mut written = 0;
    for (kind, items) in [
        ("question", &found.questions),
        ("objection", &found.objections),
        ("next_step", &found.next_steps),
        ("price_mention", &found.price_mentions),
    ] {
        for item in items.iter() {
            sqlx::query(
                "INSERT INTO call_finding (id, analysis_ref, kind, text, start_ms, speaker, \
                     is_active, row_version, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, true, 0, now())",
            )
            .bind(Uuid::now_v7())
            .bind(analysis)
            .bind(kind)
            .bind(&item.text)
            .bind(item.start_ms as f64)
            .bind(item.speaker.as_deref())
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            written += 1;
        }
    }
    if let Some((scorecard_id, version, _)) = &scorecard {
        sqlx::query(
            "DELETE FROM call_scorecard_answer WHERE analysis_ref = $1 AND confirmed_value IS NULL",
        )
        .bind(analysis)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        for answer in &found.scorecard {
            sqlx::query(
                "INSERT INTO call_scorecard_answer (id, analysis_ref, scorecard_ref, \
                     scorecard_version, question_key, proposed_value, proposed_evidence_ms, \
                     is_active, row_version, created_at) \
                 SELECT $1, $2, $3, $4, $5, $6, $7, true, 0, now() \
                  WHERE NOT EXISTS (SELECT 1 FROM call_scorecard_answer \
                                     WHERE analysis_ref = $2 AND question_key = $5)",
            )
            .bind(Uuid::now_v7())
            .bind(analysis)
            .bind(scorecard_id)
            .bind(*version)
            .bind(&answer.question_key)
            .bind(&answer.value)
            .bind(answer.start_ms as f64)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            written += 1;
        }
    }
    sqlx::query("UPDATE call_analysis SET model_id = $2 WHERE id = $1")
        .bind(analysis)
        .bind(client.model_id())
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
    attome_db::tx::commit(tx).await?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPANS: [(u64, u64); 2] = [(0, 4000), (4000, 9000)];

    #[test]
    fn invalid_timestamps_are_dropped() {
        let reply = r#"```json
        {"questions": [{"text": "What is your budget?", "start_ms": 1000, "speaker": "staff"},
                       {"text": "Invented", "start_ms": 99999}],
         "objections": [{"text": "Too expensive", "start_ms": 4000, "speaker": "customer"}],
         "price_mentions": [{"text": "", "start_ms": 5000}],
         "scorecard": [{"question_key": "asked_budget", "value": "yes", "start_ms": 1000},
                       {"question_key": "made_up", "value": "yes", "start_ms": 1000},
                       {"question_key": "asked_budget", "value": "maybe", "start_ms": 1000},
                       {"question_key": "asked_budget", "value": "no", "start_ms": 12000}]}
        ```"#;
        let keys = vec!["asked_budget".to_owned()];
        let found = parse_reply(reply, &SPANS, &keys).unwrap();
        assert_eq!(found.questions.len(), 1, "the invented time is dropped");
        assert_eq!(found.objections.len(), 1);
        assert!(found.price_mentions.is_empty(), "an empty text is dropped");
        assert_eq!(found.scorecard.len(), 1, "only a known key, value and time");
        assert_eq!(found.scorecard[0].value, "yes");
    }

    #[test]
    fn a_reply_that_is_not_json_is_none() {
        assert!(parse_reply("I cannot help", &SPANS, &[]).is_none());
    }

    #[test]
    fn scorecard_keys_read_json_or_lines() {
        assert_eq!(
            scorecard_keys(r#"[{"key": "greeted"}, "asked_budget"]"#),
            vec!["greeted", "asked_budget"]
        );
        assert_eq!(
            scorecard_keys("greeted: Did they greet?\nasked_budget: Budget?"),
            vec!["greeted", "asked_budget"]
        );
    }
}
