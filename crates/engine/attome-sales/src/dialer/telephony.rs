//! D21-T6: the dialer's telephone is J6.
//!
//! [`DialerTelephony`] is what the dialer needs from a phone system: start
//! a call (logged on the record, ringing the agent's own phone and then the
//! customer, showing the caller id chosen for the customer's country) and
//! drop a recorded voicemail into a call. [`J6Telephony`] does both through
//! `attome_integration`'s voice API; Attome opens no audio stream, the
//! provider plays and connects everything. Each J6 call has a 10-second
//! timeout, answered as `CapabilityUnavailable("telephony")`, and none is
//! made inside a database transaction. One call at a time: a call is only
//! ever started from the agent's own request.
//!
//! The caller id is only ever a number the voice system owns
//! ([`choose_caller_id`]): the call list's rule for the customer's country,
//! else its catch-all rule, else the system's own number. A voicemail drop
//! is refused unless the call list allows it.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use attome_core::EngineState;
use attome_integration::connector::adapters::voice;
use attome_integration::system::IntegrationSystem;
use attome_server::security::SecurityContext;
use attome_types::AppError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// The longest a J6 call may take.
pub const J6_TIMEOUT: Duration = Duration::from_secs(10);

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AppError>> + Send + 'a>>;

/// A `caller_id_rule` row: the number shown to customers in a country.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct CallerIdRule {
    /// An ISO country code (`SA`), a dialling prefix (`+966`), or `*` for
    /// every other country.
    pub country_code: String,
    pub phone_number: String,
}

/// A call the dialer started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct CallHandle {
    pub call_id: Uuid,
    /// The `phone_call` activity logged for it; the outcome is recorded on it.
    pub activity_id: Uuid,
}

/// What the dialer needs from a phone system.
pub trait DialerTelephony: Send + Sync {
    /// Starts a call from the person in `ctx` to `to` about a record.
    fn dial<'a>(
        &'a self,
        ctx: &'a SecurityContext,
        to: &'a str,
        caller_id: Option<&'a str>,
        about: (&'a str, Uuid),
    ) -> BoxFuture<'a, CallHandle>;

    /// Plays `recording_ref` (an https recording) into the call and hangs up.
    fn drop_voicemail<'a>(
        &'a self,
        handle: &'a CallHandle,
        recording_ref: &'a str,
    ) -> BoxFuture<'a, ()>;
}

/// Dialling prefixes of the countries the product ships for, longest first.
const PREFIXES: &[(&str, &str)] = &[
    ("+966", "SA"),
    ("+971", "AE"),
    ("+965", "KW"),
    ("+974", "QA"),
    ("+973", "BH"),
    ("+968", "OM"),
    ("+962", "JO"),
    ("+961", "LB"),
    ("+20", "EG"),
    ("+44", "GB"),
    ("+1", "US"),
];

/// The ISO country and dialling prefix of an E.164 number, when known. Pure.
pub fn country_of(number: &str) -> Option<(&'static str, &'static str)> {
    PREFIXES
        .iter()
        .find(|(prefix, _)| number.starts_with(prefix))
        .map(|(prefix, iso)| (*iso, *prefix))
}

/// The caller id for a call to `to`: the rule for its country (by ISO code
/// or prefix), else the catch-all `*` rule, else none, and only ever a
/// number in `owned`. Pure.
pub fn choose_caller_id(rules: &[CallerIdRule], owned: &[String], to: &str) -> Option<String> {
    let owned: Vec<String> = owned.iter().filter_map(|n| voice::e164(n)).collect();
    let (iso, prefix) = country_of(to).unwrap_or(("", ""));
    let pick = |matches: &dyn Fn(&str) -> bool| {
        rules
            .iter()
            .filter(|r| matches(r.country_code.trim()))
            .filter_map(|r| voice::e164(&r.phone_number))
            .find(|n| owned.contains(n))
    };
    pick(&|c: &str| !iso.is_empty() && (c.eq_ignore_ascii_case(iso) || c == prefix))
        .or_else(|| pick(&|c: &str| c == "*"))
}

/// A voicemail drop is allowed only on a call list that allows it. Pure.
pub fn voicemail_allowed(enabled: Option<bool>) -> Result<(), AppError> {
    if enabled == Some(true) {
        Ok(())
    } else {
        Err(AppError::Validation(
            "voicemail drop is off for this call list".into(),
        ))
    }
}

/// J6's voice system, as the dialer's telephone.
pub struct J6Telephony {
    pub state: EngineState,
    pub system: IntegrationSystem,
}

fn timed_out(_: tokio::time::error::Elapsed) -> AppError {
    AppError::CapabilityUnavailable("telephony")
}

impl DialerTelephony for J6Telephony {
    fn dial<'a>(
        &'a self,
        ctx: &'a SecurityContext,
        to: &'a str,
        caller_id: Option<&'a str>,
        about: (&'a str, Uuid),
    ) -> BoxFuture<'a, CallHandle> {
        Box::pin(async move {
            let started = tokio::time::timeout(
                J6_TIMEOUT,
                voice::start_call(&self.state, ctx, &self.system, to, caller_id, about, false),
            )
            .await
            .map_err(timed_out)??;
            Ok(CallHandle {
                call_id: started.call_id,
                activity_id: started.activity_id,
            })
        })
    }

    fn drop_voicemail<'a>(
        &'a self,
        handle: &'a CallHandle,
        recording_ref: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            tokio::time::timeout(
                J6_TIMEOUT,
                voice::drop_voicemail(&self.state, &self.system, handle.call_id, recording_ref),
            )
            .await
            .map_err(timed_out)?
        })
    }
}

/// A telephone that dials nothing, for tests: it records what it was asked.
#[cfg(any(test, feature = "test-support"))]
#[derive(Default)]
pub struct FakeTelephony {
    pub dialled: std::sync::Mutex<Vec<(String, Option<String>)>>,
    pub dropped: std::sync::Mutex<Vec<(Uuid, String)>>,
}

#[cfg(any(test, feature = "test-support"))]
impl DialerTelephony for FakeTelephony {
    fn dial<'a>(
        &'a self,
        _ctx: &'a SecurityContext,
        to: &'a str,
        caller_id: Option<&'a str>,
        _about: (&'a str, Uuid),
    ) -> BoxFuture<'a, CallHandle> {
        Box::pin(async move {
            if let Ok(mut d) = self.dialled.lock() {
                d.push((to.to_owned(), caller_id.map(str::to_owned)));
            }
            Ok(CallHandle {
                call_id: Uuid::now_v7(),
                activity_id: Uuid::now_v7(),
            })
        })
    }

    fn drop_voicemail<'a>(
        &'a self,
        handle: &'a CallHandle,
        recording_ref: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Ok(mut d) = self.dropped.lock() {
                d.push((handle.call_id, recording_ref.to_owned()));
            }
            Ok(())
        })
    }
}

// ── Routes ──────────────────────────────────────────────────────────────────

/// A call to make from a call list.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DialRequest {
    /// The number, E.164.
    pub to: String,
    /// The record the call is about.
    pub entity_name: String,
    pub record_id: Uuid,
}

/// A voicemail to drop into a call.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VoicemailRequest {
    pub call_id: Uuid,
    /// The recorded message (https).
    pub recording_url: String,
}

async fn telephone(state: &EngineState) -> Result<J6Telephony, AppError> {
    let system = voice::systems(state)
        .await?
        .into_iter()
        .next()
        .ok_or(AppError::NotFound)?;
    Ok(J6Telephony {
        state: state.clone(),
        system,
    })
}

async fn list_exists(state: &EngineState, list: Uuid) -> Result<Option<Option<bool>>, AppError> {
    sqlx::query_scalar(
        "SELECT voicemail_enabled FROM call_list WHERE id = $1 AND is_active IS NOT FALSE",
    )
    .bind(list)
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)
}

/// Starts a call from the list, with the caller id for the customer's country.
pub async fn dial(
    state: &EngineState,
    telephony: &dyn DialerTelephony,
    ctx: &SecurityContext,
    list: Uuid,
    req: &DialRequest,
    owned: &[String],
) -> Result<CallHandle, AppError> {
    list_exists(state, list).await?.ok_or(AppError::NotFound)?;
    let to =
        voice::e164(&req.to).ok_or_else(|| AppError::Validation("to: an E.164 number".into()))?;
    let rules: Vec<CallerIdRule> = sqlx::query_as(
        "SELECT country_code, phone_number FROM caller_id_rule \
          WHERE is_active IS NOT FALSE AND country_code IS NOT NULL AND phone_number IS NOT NULL \
          ORDER BY id",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    let caller_id = choose_caller_id(&rules, owned, &to);
    telephony
        .dial(
            ctx,
            &to,
            caller_id.as_deref(),
            (&req.entity_name, req.record_id),
        )
        .await
}

/// Drops a voicemail into the caller's own call, when the list allows it.
pub async fn drop_voicemail_for_list(
    state: &EngineState,
    telephony: &dyn DialerTelephony,
    user: Uuid,
    list: Uuid,
    req: &VoicemailRequest,
) -> Result<(), AppError> {
    let enabled = list_exists(state, list).await?.ok_or(AppError::NotFound)?;
    voicemail_allowed(enabled)?;
    let call: Option<(Option<Uuid>, Option<Uuid>)> =
        sqlx::query_as("SELECT user_id, activity_id FROM voice_call WHERE id = $1")
            .bind(req.call_id)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
    let Some((Some(owner), Some(activity))) = call else {
        return Err(AppError::NotFound);
    };
    if owner != user {
        // Only the person on the call drops a message into it.
        return Err(AppError::NotFound);
    }
    let handle = CallHandle {
        call_id: req.call_id,
        activity_id: activity,
    };
    telephony
        .drop_voicemail(&handle, &req.recording_url)
        .await?;
    let mut tx = attome_db::tx::begin(&state.base.db).await?;
    attome_audit::write_business_event_in_tx(
        &mut tx,
        &attome_audit::audit_service(state),
        attome_audit::BusinessEvent::new(
            "activity",
            activity,
            attome_audit::AuditOperation::Update,
            "call.voicemail_dropped",
            user,
        ),
    )
    .await?;
    attome_db::tx::commit(tx).await
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/call-lists/{id}/dial",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The call list")),
    request_body = DialRequest,
    responses(
        (status = 200, description = "Ringing the caller's phone; the call is logged", body = CallHandle),
        (status = 403, description = "Caller lacks call_list.call or may not log calls on the record", body = attome_types::ErrorResponse),
        (status = 404, description = "No such call list, or no voice system", body = attome_types::ErrorResponse),
        (status = 422, description = "Not an E.164 number, no agent number set, or the provider refused", body = attome_types::ErrorResponse),
        (status = 503, description = "The phone system did not answer in time", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::Entity, attome_audit::AuditOperation::Create)])))),
)]
pub(crate) async fn post_dial(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<
        attome_server::authz::Privilege<super::claim::CallListCall>,
    >,
    axum::extract::Path(list): axum::extract::Path<Uuid>,
    axum::Json(req): axum::Json<DialRequest>,
) -> Result<axum::Json<CallHandle>, AppError> {
    let telephony = telephone(&state).await?;
    let owned = voice::owned_numbers(&voice::config(&telephony.system));
    Ok(axum::Json(
        dial(&state, &telephony, &ctx, list, &req, &owned).await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/sales/call-lists/{id}/voicemail",
    tag = "sales",
    params(("id" = Uuid, Path, description = "The call list")),
    request_body = VoicemailRequest,
    responses(
        (status = 204, description = "The message is playing; the call hangs up after it"),
        (status = 403, description = "Caller lacks call_list.call", body = attome_types::ErrorResponse),
        (status = 404, description = "No such call list, or not the caller's call", body = attome_types::ErrorResponse),
        (status = 422, description = "Voicemail drop is off for this list, or not an https recording", body = attome_types::ErrorResponse),
        (status = 503, description = "The phone system did not answer in time", body = attome_types::ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
    extensions(("x-audit" = json!(attome_audit::security::x_audit(&[(attome_audit::AuditCategory::BusinessEvent, attome_audit::AuditOperation::Update)])))),
)]
pub(crate) async fn post_voicemail(
    axum::extract::State(state): axum::extract::State<EngineState>,
    ctx: attome_server::authz::Authorized<
        attome_server::authz::Privilege<super::claim::CallListCall>,
    >,
    axum::extract::Path(list): axum::extract::Path<Uuid>,
    axum::Json(req): axum::Json<VoicemailRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    let telephony = telephone(&state).await?;
    drop_voicemail_for_list(&state, &telephony, ctx.user_id, list, &req).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(post_dial, post_voicemail))]
pub(crate) struct ApiDocFragment;

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(country: &str, number: &str) -> CallerIdRule {
        CallerIdRule {
            country_code: country.into(),
            phone_number: number.into(),
        }
    }

    #[test]
    fn never_returns_unowned_number() {
        let owned = vec!["+966110000000".to_owned(), "+97140000000".to_owned()];
        let rules = vec![
            rule("SA", "+966 11 000 0000"),
            rule("+971", "+971 4 000 0000"),
            rule("KW", "+965 2200 0000"),
            rule("*", "+966110000000"),
        ];
        assert_eq!(
            choose_caller_id(&rules, &owned, "+966551234567"),
            Some("+966110000000".into())
        );
        assert_eq!(
            choose_caller_id(&rules, &owned, "+971501234567"),
            Some("+97140000000".into())
        );
        // Kuwait's rule names a number the system does not own: the catch-all.
        assert_eq!(
            choose_caller_id(&rules, &owned, "+96550001111"),
            Some("+966110000000".into())
        );
        // No rule may ever put an unowned number on the call.
        let unowned = vec![rule("SA", "+966 12 999 9999"), rule("*", "+1 555 000 0000")];
        assert_eq!(choose_caller_id(&unowned, &owned, "+966551234567"), None);
        assert_eq!(choose_caller_id(&rules, &[], "+966551234567"), None);
    }

    #[test]
    fn dialer_telephony_voicemail_needs_the_list_to_allow_it() {
        assert!(voicemail_allowed(Some(true)).is_ok());
        assert!(voicemail_allowed(Some(false)).is_err());
        assert!(voicemail_allowed(None).is_err());
        assert_eq!(country_of("+966551234567"), Some(("SA", "+966")));
        assert_eq!(country_of("+201001234567"), Some(("EG", "+20")));
        assert_eq!(country_of("+81312345678"), None);
    }

    #[tokio::test]
    async fn dialer_telephony_fake_records_calls() {
        let fake = FakeTelephony::default();
        let handle = CallHandle {
            call_id: Uuid::nil(),
            activity_id: Uuid::nil(),
        };
        fake.drop_voicemail(&handle, "https://x/vm.mp3")
            .await
            .unwrap();
        assert_eq!(fake.dropped.lock().unwrap().len(), 1);
    }
}
