//! J1-T1: each user's email signature, appended to the record emails they
//! compose or reply to ([`crate::communication::write_communication_with`]
//! with `signature: true`). Stored in the migration-owned `email_signature`
//! (migration 0252), one row per user, read and written only through the
//! caller's own `/api/v1/me/email-signature`.
//!
//! The signature is plain text. Appended to a plain-text body it follows the
//! RFC 3676 separator line (`-- `); appended to an HTML body it is escaped and
//! its lines joined with `<br>`, so a signature can never carry markup.

use attome_audit::security::{MandatoryCategory, SecurityEvent, SecurityTx, x_audit};
use attome_audit::{AuditCategory, AuditOperation};
use attome_core::EngineState;
use attome_server::authz::{Authorized, SelfService};
use attome_types::{AppError, ErrorResponse};
use axum::{Json, Router, extract::State, routing::get};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Longest signature kept, in characters; mirrors migration 0252's CHECK.
pub const MAX_SIGNATURE_CHARS: usize = 4000;

/// The caller's signature. `body` is empty and `row_version` is 0 when none
/// is set.
#[derive(Debug, Serialize, ToSchema)]
pub struct EmailSignature {
    pub body: String,
    pub row_version: i64,
}

/// A signature to store. An empty `body` clears it. `row_version` is the one
/// last read (0 when there was none).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PutEmailSignature {
    pub body: String,
    pub row_version: i64,
}

/// `user_id`'s signature, or `None` when they have none.
pub async fn for_user(pool: &attome_db::DbPool, user_id: Uuid) -> Result<Option<String>, AppError> {
    let body: Option<String> =
        sqlx::query_scalar("SELECT body FROM email_signature WHERE user_ref = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::internal)?;
    Ok(body.filter(|b| !b.trim().is_empty()))
}

/// `body` with `signature` after it: below an RFC 3676 `-- ` line for plain
/// text, or escaped with `<br>` line breaks for HTML.
pub fn append(body: &str, signature: &str, is_html: bool) -> String {
    let signature = signature.trim_end();
    if signature.trim().is_empty() {
        return body.to_string();
    }
    if is_html {
        let lines: Vec<String> = signature
            .lines()
            .map(|l| attome_html::escape_html(l.trim_end()))
            .collect();
        format!(
            "{body}<p class=\"signature\">-- <br>{}</p>",
            lines.join("<br>")
        )
    } else {
        format!("{}\n\n-- \n{signature}", body.trim_end())
    }
}

async fn read(pool: &attome_db::DbPool, user_id: Uuid) -> Result<EmailSignature, AppError> {
    let row: Option<(String, i64)> =
        sqlx::query_as("SELECT body, row_version FROM email_signature WHERE user_ref = $1")
            .bind(user_id)
            .fetch_optional(pool)
            .await
            .map_err(AppError::internal)?;
    Ok(row.map_or(
        EmailSignature {
            body: String::new(),
            row_version: 0,
        },
        |(body, row_version)| EmailSignature { body, row_version },
    ))
}

async fn write(
    state: &EngineState,
    user_id: Uuid,
    body: PutEmailSignature,
) -> Result<EmailSignature, AppError> {
    if body.body.chars().count() > MAX_SIGNATURE_CHARS {
        return Err(AppError::Validation(format!(
            "a signature is at most {MAX_SIGNATURE_CHARS} characters"
        )));
    }
    let text = body.body.trim_end().to_string();
    let event = SecurityEvent::new(
        MandatoryCategory::Configuration,
        AuditOperation::Update,
        user_id,
        "email_signature",
        None,
    )
    .named("email_signature_updated");
    let mut stx = SecurityTx::begin(state, event).await?;

    let stored = if body.row_version == 0 {
        // A concurrent first write loses here rather than overwriting.
        sqlx::query_scalar::<_, i64>(
            "INSERT INTO email_signature (user_ref, body) VALUES ($1, $2) \
             ON CONFLICT (user_ref) DO NOTHING RETURNING row_version",
        )
        .bind(user_id)
        .bind(&text)
        .fetch_optional(&mut *stx)
        .await
        .map_err(AppError::internal)?
    } else {
        sqlx::query_scalar::<_, i64>(
            "UPDATE email_signature \
             SET body = $2, row_version = row_version + 1, updated_at = now() \
             WHERE user_ref = $1 AND row_version = $3 RETURNING row_version",
        )
        .bind(user_id)
        .bind(&text)
        .bind(body.row_version)
        .fetch_optional(&mut *stx)
        .await
        .map_err(AppError::internal)?
    };
    let Some(row_version) = stored else {
        return Err(AppError::VersionConflict);
    };
    stx.commit().await?;
    Ok(EmailSignature {
        body: text,
        row_version,
    })
}

/// The caller's own email signature (J1-T1).
#[utoipa::path(
    get,
    path = "/api/v1/me/email-signature",
    tag = "notification",
    responses(
        (status = 200, description = "The caller's signature, empty when none is set", body = EmailSignature),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_my_signature(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
) -> Result<Json<EmailSignature>, AppError> {
    Ok(Json(read(&state.base.db, ctx.user_id).await?))
}

/// Sets the caller's own email signature (J1-T1); an empty body clears it.
#[utoipa::path(
    put,
    path = "/api/v1/me/email-signature",
    tag = "notification",
    request_body = PutEmailSignature,
    responses(
        (status = 200, description = "The stored signature", body = EmailSignature),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 409, description = "row_version is stale", body = ErrorResponse),
        (status = 422, description = "The signature is too long", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(x_audit(&[(AuditCategory::Configuration, AuditOperation::Update)])))),
)]
async fn put_my_signature(
    State(state): State<EngineState>,
    ctx: Authorized<SelfService>,
    Json(body): Json<PutEmailSignature>,
) -> Result<Json<EmailSignature>, AppError> {
    Ok(Json(write(&state, ctx.user_id, body).await?))
}

pub(crate) fn routes() -> Router<EngineState> {
    Router::new().route(
        "/api/v1/me/email-signature",
        get(get_my_signature).put(put_my_signature),
    )
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(get_my_signature, put_my_signature))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_gets_the_rfc3676_separator() {
        assert_eq!(
            append("Hello\n\n", "Sara\nSales", false),
            "Hello\n\n-- \nSara\nSales"
        );
    }

    #[test]
    fn html_signature_is_escaped_with_line_breaks() {
        let out = append("<p>Hi</p>", "Sara <sales>\nAcme & Co", true);
        assert_eq!(
            out,
            "<p>Hi</p><p class=\"signature\">-- <br>Sara &lt;sales&gt;<br>Acme &amp; Co</p>"
        );
    }

    #[test]
    fn a_blank_signature_leaves_the_body_alone() {
        assert_eq!(append("Hello", "  \n ", false), "Hello");
    }
}
