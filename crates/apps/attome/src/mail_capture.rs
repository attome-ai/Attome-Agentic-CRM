//! D15-T2: emails from people's own mailboxes captured onto the records
//! they are about (the rules are `attome_integration::mail_capture`).
//!
//! The `mail_capture` job (every five minutes) reads each D15-T1 connection
//! from where it stopped: a Microsoft 365 inbox and sent items (Graph delta,
//! the person's own token), or a Gmail mailbox (history, drafts, spam and
//! trash left out). A message on which a contact or lead the person may read
//! appears becomes **one** communication, written as the person through the
//! generic create path (status `logged`; nothing is sent), on the first
//! match, and linked (`communication_link`) to every other matching contact
//! and lead and to the open opportunities of the matched contacts' accounts,
//! so it shows on each of their timelines. It joins the thread of the
//! message it answers. Each `Message-ID` is captured once, whoever's mailbox
//! it is read from. A person turns capture off with `mail_capture.enabled`.

use attome_core::EngineState;
use attome_integration::connector::adapters::mail::{MailMessage, gmail, graph};
use attome_integration::connector::adapters::user_mail_sync::{Provider, access_token};
use attome_integration::mail_capture::{capturable, direction, domain_list, external_addresses};
use attome_security::SecurityContextExt;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde_json::{Value, json};
use uuid::Uuid;

/// Most records one email is linked to.
const MAX_LINKS: usize = 20;
/// Longest body kept.
const MAX_BODY_CHARS: usize = 100_000;

/// What one run did, for the log.
#[derive(Debug, Default, Clone, Copy)]
pub struct Summary {
    pub captured: u32,
    pub failed: u32,
}

fn setting(state: &EngineState, user: Uuid, key: &str) -> Value {
    let settings = state.settings.load();
    attome_core::setting_registry()
        .get(key)
        .map(|d| settings.resolve(d, Some(user), None).0)
        .unwrap_or(Value::Null)
}

/// One pass over every connected mailbox.
pub async fn run(state: &EngineState) -> Result<Summary, AppError> {
    let connections: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT c.user_id, c.provider, coalesce(c.account_email, u.email) \
           FROM user_mail_connection c JOIN user_account u ON u.id = c.user_id \
          WHERE u.is_active = true ORDER BY c.user_id, c.provider",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let mut summary = Summary::default();
    for (user, provider, own) in connections {
        let Some(provider) = Provider::parse(&provider) else {
            continue;
        };
        if setting(state, user, "mail_capture.enabled").as_bool() == Some(false) {
            continue;
        }
        let own = own.unwrap_or_default();
        match capture_mailbox(state, user, provider, &own).await {
            Ok(n) => summary.captured += n,
            Err(error) => {
                summary.failed += 1;
                tracing::warn!(%user, provider = provider.as_str(), %error, "mail capture: mailbox skipped");
            }
        }
    }
    Ok(summary)
}

async fn capture_mailbox(
    state: &EngineState,
    user: Uuid,
    provider: Provider,
    own: &str,
) -> Result<u32, AppError> {
    let Some(token) = access_token(state, user, provider).await? else {
        return Ok(0);
    };
    let ctx = state.base.security.resolve(user).await?;
    if ctx.require("communication", "create").is_err() {
        return Ok(0);
    }
    let excluded = domain_list(
        setting(state, user, "mail_capture.excluded_domains")
            .as_str()
            .unwrap_or_default(),
    );
    let cursor: Option<String> = sqlx::query_scalar(
        "SELECT cursor FROM mail_capture_state WHERE user_id = $1 AND provider = $2",
    )
    .bind(user)
    .bind(provider.as_str())
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .flatten();
    let (messages, next) = match provider {
        Provider::Microsoft => {
            let kept: Value = cursor
                .as_deref()
                .and_then(|c| serde_json::from_str(c).ok())
                .unwrap_or(Value::Null);
            let (mut inbox, inbox_next) = graph::read(
                &token,
                "me",
                "inbox",
                kept.get("inbox").and_then(Value::as_str),
            )
            .await?;
            let (sent, sent_next) = graph::read(
                &token,
                "me",
                "sentitems",
                kept.get("sent").and_then(Value::as_str),
            )
            .await?;
            inbox.extend(sent);
            (
                inbox,
                Some(json!({ "inbox": inbox_next, "sent": sent_next }).to_string()),
            )
        }
        Provider::Google => gmail::read(&token, cursor.as_deref(), false).await?,
    };
    let mut captured = 0;
    for message in &messages {
        match capture(state, &ctx, user, own, &excluded, message).await {
            Ok(true) => captured += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%user, message = %message.id, %error, "mail capture: message skipped")
            }
        }
    }
    sqlx::query(
        "INSERT INTO mail_capture_state (user_id, provider, cursor) VALUES ($1, $2, $3) \
         ON CONFLICT (user_id, provider) DO UPDATE SET cursor = EXCLUDED.cursor, updated_at = now()",
    )
    .bind(user)
    .bind(provider.as_str())
    .bind(next)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(captured)
}

/// The records the addresses belong to, as far as the person may read
/// them: contacts and leads by email, then the open opportunities of the
/// contacts' accounts. The first is where the communication is written.
async fn matching_records(
    state: &EngineState,
    ctx: &SecurityContext,
    addresses: &[String],
) -> Result<Vec<(String, Uuid)>, AppError> {
    let mut out: Vec<(String, Uuid)> = Vec::new();
    let mut accounts: Vec<Uuid> = Vec::new();
    for entity in ["contact", "lead"] {
        let (has_email, has_account) = match state.entities.load().get(entity) {
            Some(meta) => (
                meta.attrs.iter().any(|a| a.logicalname == "email"),
                meta.attrs.iter().any(|a| a.logicalname == "account_ref"),
            ),
            None => (false, false),
        };
        if !has_email || ctx.require(entity, "read").is_err() {
            continue;
        }
        let account = if has_account {
            "account_ref"
        } else {
            "NULL::uuid"
        };
        let rows: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(&format!(
            "SELECT id, {account} FROM {entity} \
              WHERE lower(email) = ANY($1) AND is_active IS NOT FALSE ORDER BY id LIMIT $2"
        ))
        .bind(addresses)
        .bind(MAX_LINKS as i64)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        for (id, account) in rows {
            out.push((entity.to_owned(), id));
            if let Some(account) = account
                && !accounts.contains(&account)
            {
                accounts.push(account);
            }
        }
    }
    let opportunities_ok = state
        .entities
        .load()
        .get("opportunity")
        .is_some_and(|meta| {
            meta.attrs.iter().any(|a| a.logicalname == "account_ref")
                && meta.attrs.iter().any(|a| a.logicalname == "stage")
        });
    if !accounts.is_empty() && opportunities_ok && ctx.require("opportunity", "read").is_ok() {
        let rows: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM opportunity \
              WHERE account_ref = ANY($1) AND is_active IS NOT FALSE \
                AND (stage IS NULL OR stage NOT IN ('closed_won', 'closed_lost')) \
              ORDER BY id LIMIT $2",
        )
        .bind(&accounts)
        .bind(MAX_LINKS as i64)
        .fetch_all(&state.base.db)
        .await
        .map_err(AppError::internal)?;
        out.extend(rows.into_iter().map(|id| ("opportunity".to_owned(), id)));
    }
    out.truncate(MAX_LINKS);
    Ok(out)
}

fn clip(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

/// Captures one message; false when it is not captured (rules, already
/// captured, or about nobody known).
async fn capture(
    state: &EngineState,
    ctx: &SecurityContext,
    user: Uuid,
    own: &str,
    excluded: &[String],
    message: &MailMessage,
) -> Result<bool, AppError> {
    if !capturable(message) {
        return Ok(false);
    }
    let Some(message_id) = message.message_id.clone() else {
        return Ok(false);
    };
    let seen: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mail_capture_message WHERE message_id = $1)",
    )
    .bind(&message_id)
    .fetch_one(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    if seen {
        return Ok(false);
    }
    let addresses = external_addresses(message, own, excluded);
    if addresses.is_empty() {
        return Ok(false);
    }
    let matches = matching_records(state, ctx, &addresses).await?;
    let Some((entity, record)) = matches.first().cloned() else {
        return Ok(false);
    };

    // The message it answers, if Attome has it: same thread.
    let earlier: Vec<String> = message
        .in_reply_to
        .iter()
        .chain(message.references.iter().rev())
        .map(|id| format!("<{id}>"))
        .collect();
    let parent: Option<(Uuid, Option<Uuid>)> = if earlier.is_empty() {
        None
    } else {
        sqlx::query_as(
            "SELECT id, thread_id FROM communication \
              WHERE message_id = ANY($1) AND is_active IS NOT FALSE \
              ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&earlier)
        .fetch_optional(&state.base.db)
        .await
        .map_err(AppError::internal)?
    };

    let all: Vec<String> = message
        .from
        .iter()
        .chain(&message.to)
        .chain(&message.cc)
        .map(|a| a.address.clone())
        .collect();
    let dir = direction(message, own);
    let mut body = json!({
        "entity_name": entity,
        "record_id": record.to_string(),
        "channel": "email",
        "direction": dir,
        "subject": clip(message.subject.as_deref().unwrap_or_default(), 1000),
        "body": clip(message.text.as_deref().or(message.html.as_deref()).unwrap_or_default(), MAX_BODY_CHARS),
        "status": "logged",
        "to_addresses": clip(&all.join(", "), 4000),
        "message_id": format!("<{message_id}>"),
    });
    if let Some(date) = &message.date {
        body["sent_at"] = json!(date);
    }
    if !message.references.is_empty() {
        let refs: Vec<String> = message
            .references
            .iter()
            .map(|r| format!("<{r}>"))
            .collect();
        body["references_header"] = json!(clip(&refs.join(" "), 4000));
    }
    if dir == "outbound" {
        body["author_id"] = json!(user.to_string());
    }
    if let Some((parent_id, thread)) = parent {
        body["in_reply_to"] = json!(parent_id.to_string());
        body["thread_id"] = json!(thread.unwrap_or(parent_id).to_string());
    }
    let id = Uuid::now_v7();
    let (id, created) = attome_records::entity_crud::create_record_with_id_for(
        state,
        ctx,
        user,
        "communication",
        body,
        id,
    )
    .await?;
    if parent.is_none() {
        // A new thread: its root is the message itself.
        attome_records::entity_crud::update_record_for(
            state,
            ctx,
            user,
            "communication",
            id,
            created.row_version(),
            json!({ "thread_id": id.to_string() }),
        )
        .await?;
    }
    for (other_entity, other) in matches.iter().skip(1) {
        sqlx::query(
            "INSERT INTO communication_link (communication_id, entity_name, record_id) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(id)
        .bind(other_entity)
        .bind(other)
        .execute(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    }
    sqlx::query(
        "INSERT INTO mail_capture_message (message_id, communication_id, user_id) VALUES ($1, $2, $3) \
         ON CONFLICT (message_id) DO NOTHING",
    )
    .bind(&message_id)
    .bind(id)
    .bind(user)
    .execute(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(true)
}
