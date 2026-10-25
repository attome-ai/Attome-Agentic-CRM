//! Mentions (roadmap C4-T1): text about a record (a note, a comment, a
//! reply) names people as `@[user:<id>]` and teams as `@[team:<id>]` — ids,
//! never names, so a renamed person stays mentioned. Saying them over
//! `POST /api/v1/{entity}/{id}/mentions` notifies each person named and each
//! member of each team named, except the author. A person who may not read
//! the record is not notified at all: a notification would carry the
//! record's name and the text, which they may not see.

use std::collections::BTreeSet;

use attome_core::EngineState;
use attome_security::RecordAction;
use attome_security::record_action::Read;
use attome_server::authz::{Authorized, RecordScoped};
use attome_types::{AppError, ErrorResponse};
use axum::{
    Json, Router,
    extract::{Path, State},
    routing::post,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The most people and teams one text may mention.
const MAX_MENTIONS: usize = 50;
/// The most characters of the text a notification quotes.
const EXCERPT_CHARS: usize = 280;

/// The ids a text mentions.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Mentions {
    pub users: Vec<Uuid>,
    pub teams: Vec<Uuid>,
}

/// Reads every `@[user:<id>]` and `@[team:<id>]` token; anything else
/// (a malformed token, an unknown kind) is plain text. Each id once.
pub fn parse_mentions(text: &str) -> Mentions {
    let mut out = Mentions::default();
    let mut rest = text;
    while let Some(at) = rest.find("@[") {
        rest = &rest[at + 2..];
        let Some(end) = rest.find(']') else { break };
        let token = &rest[..end];
        if let Some((kind, id)) = token.split_once(':')
            && let Ok(id) = Uuid::parse_str(id.trim())
        {
            let list = match kind {
                "user" => Some(&mut out.users),
                "team" => Some(&mut out.teams),
                _ => None,
            };
            if let Some(list) = list
                && !list.contains(&id)
            {
                list.push(id);
            }
        }
        rest = &rest[end + 1..];
    }
    out
}

/// The text with every mention token replaced by `@`, for a notification
/// excerpt.
fn excerpt(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find("@[") {
        out.push_str(&rest[..at]);
        out.push('@');
        rest = match rest[at..].find(']') {
            Some(end) => &rest[at + end + 1..],
            None => "",
        };
    }
    out.push_str(rest);
    let trimmed: String = out.chars().take(EXCERPT_CHARS).collect();
    trimmed.trim().to_owned()
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct MentionBody {
    /// The text that mentions people, with `@[user:<id>]` / `@[team:<id>]`.
    pub text: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MentionOutcome {
    /// People notified.
    pub notified: usize,
    /// People mentioned (directly or through a team) who may not read the
    /// record, or are inactive, and were not notified.
    pub skipped: usize,
}

/// Notifies everyone `text` mentions who may read the record.
pub async fn notify_mentions(
    state: &EngineState,
    author_id: Uuid,
    entity_id: Uuid,
    entity_name: &str,
    record_id: Uuid,
    text: &str,
) -> Result<MentionOutcome, AppError> {
    let mentions = parse_mentions(text);
    if mentions.users.len() + mentions.teams.len() > MAX_MENTIONS {
        return Err(AppError::Validation(format!(
            "a text may mention at most {MAX_MENTIONS} people and teams"
        )));
    }
    let mut people: BTreeSet<Uuid> = mentions.users.iter().copied().collect();
    if !mentions.teams.is_empty() {
        let members: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT user_ref FROM user_account_mm_team \
              WHERE team_ref = ANY($1) AND NOT is_deleted",
        )
        .bind(&mentions.teams)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        people.extend(members);
    }
    people.remove(&author_id);

    let quote = excerpt(text);
    let mut outcome = MentionOutcome {
        notified: 0,
        skipped: 0,
    };
    for person in people {
        let active: Option<bool> =
            sqlx::query_scalar("SELECT is_active FROM user_account WHERE id = $1")
                .bind(person)
                .fetch_optional(&state.base.db)
                .await
                .map_err(AppError::internal)?;
        if active != Some(true) {
            outcome.skipped += 1;
            continue;
        }
        let ctx = attome_security::resolve_uncached(&state.base.db, person).await?;
        let can_read = attome_records::entity_crud::require_record_access(
            state,
            &ctx,
            entity_id,
            entity_name,
            record_id,
            RecordAction::Read,
        )
        .await;
        match can_read {
            Ok(()) => {}
            Err(AppError::Forbidden | AppError::NotFound) => {
                outcome.skipped += 1;
                continue;
            }
            Err(e) => return Err(e),
        }
        let request = attome_notification::dispatch::DispatchRequest {
            template_key: None,
            locale: "en".to_owned(),
            recipient_user_ref: Some(person),
            is_global: false,
            organization_ref: None,
            channels: None,
            subject: Some("You were mentioned".to_owned()),
            body_html: None,
            body_text: Some(quote.clone()),
            route: Some(format!("/{entity_name}/{record_id}")),
            variables: std::collections::HashMap::new(),
            priority: "normal".to_owned(),
            escalate_after_minutes: None,
            escalate_channels: None,
        };
        attome_notification::dispatch::create_dispatch(
            &state.base.db,
            &state.base.config.notification,
            request,
        )
        .await?;
        outcome.notified += 1;
    }
    Ok(outcome)
}

/// Mention people on a record
///
/// Mention people on a record. Needs read access to the entity's records. Audited.
#[utoipa::path(
    post,
    path = "/api/v1/{entity}/{id}/mentions",
    tag = "entity",
    operation_id = "notify_record_mentions",
    params(("entity" = String, Path), ("id" = Uuid, Path)),
    request_body = MentionBody,
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Create)])))),
    responses(
        (status = 200, description = "Who was notified, and how many were not because they may not read the record", body = MentionOutcome),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller may not read the record", body = ErrorResponse),
        (status = 422, description = "Too many mentions", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn mention(
    State(state): State<EngineState>,
    ctx: Authorized<RecordScoped<Read>>,
    Path((entity_input, record_id)): Path<(String, Uuid)>,
    Json(body): Json<MentionBody>,
) -> Result<Json<MentionOutcome>, AppError> {
    let (entity_id, entity_name, _, _) =
        attome_records::entity_crud::resolve_entity(&state, &entity_input).await?;
    attome_records::entity_crud::require_record_access(
        &state,
        &ctx,
        entity_id,
        &entity_name,
        record_id,
        RecordAction::Read,
    )
    .await?;
    let outcome = notify_mentions(
        &state,
        ctx.user_id,
        entity_id,
        &entity_name,
        record_id,
        &body.text,
    )
    .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(&state),
        attome_audit::BusinessEvent::new(
            entity_name.as_str(),
            record_id,
            attome_audit::AuditOperation::Create,
            "record.mentioned",
            ctx.user_id,
        ),
    )
    .await?;
    tx.commit().await.map_err(AppError::internal)?;
    Ok(Json(outcome))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route("/api/v1/{entity}/{id}/mentions", post(mention))
}

/// This file's slice of the workspace OpenAPI document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(mention), components(schemas(MentionBody, MentionOutcome)))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mentions_are_read_as_ids() {
        let u = Uuid::now_v7();
        let t = Uuid::now_v7();
        let text = format!(
            "Hi @[user:{u}] and @[team:{t}], also @[user:{u}] again @[role:{u}] @[user:nope]"
        );
        let m = parse_mentions(&text);
        assert_eq!(m.users, vec![u]);
        assert_eq!(m.teams, vec![t]);
        assert_eq!(parse_mentions("no mentions @[ here"), Mentions::default());
    }

    #[test]
    fn excerpts_drop_the_tokens() {
        let u = Uuid::now_v7();
        assert_eq!(
            excerpt(&format!("ask @[user:{u}] about it")),
            "ask @ about it"
        );
        assert_eq!(excerpt(&"x".repeat(400)).len(), EXCERPT_CHARS);
    }
}
