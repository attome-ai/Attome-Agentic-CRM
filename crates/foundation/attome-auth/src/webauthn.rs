//! Passkeys (roadmap Z4-T6): the WebAuthn relying-party building block the
//! passkey sign-in (Q6) and passkey second factor (Q5) call. Verification is
//! `webauthn_rp` (pure Rust, RustCrypto; no OpenSSL): Ed25519, ES256, ES384
//! and RS256 keys, `none` attestation.
//!
//! A ceremony is two calls. `start_*` returns the options the browser passes
//! to `navigator.credentials.create` / `get` and stores the encoded ceremony
//! state in `webauthn_challenge`, so any node can finish what another
//! started. `finish_*` takes the browser's response JSON
//! (`PublicKeyCredential.toJSON()`), spends the challenge once
//! (`UPDATE … WHERE used_at IS NULL`, one row or refused) and verifies.
//! A challenge lives [`CHALLENGE_TTL_SECS`] seconds.
//!
//! Credentials are discoverable passkeys whose user handle is the account id
//! (16 bytes), so one assertion path serves both a sign-in that names no user
//! and a second factor for a known one. An assertion whose signature counter
//! did not move past a stored non-zero counter is refused as a cloned
//! authenticator. Every refusal is [`AppError::Unauthorized`]; the reason is
//! logged, never returned.

use attome_db::DbPool;
use attome_types::AppError;
use chrono::{Duration, Utc};
use uuid::Uuid;
use webauthn_rp::bin::{Decode, Encode};
use webauthn_rp::request::auth::AuthenticationVerificationOptions;
use webauthn_rp::request::register::{
    Nickname, PublicKeyCredentialUserEntity, RegistrationVerificationOptions, UserHandle16,
    Username,
};
use webauthn_rp::request::{AsciiDomain, PublicKeyCredentialDescriptor, RpId, TimedCeremony};
use webauthn_rp::response::register::{CompressedPubKey, DynamicState, StaticState};
use webauthn_rp::response::{AuthTransports, AuthenticatorTransport, CredentialId};
use webauthn_rp::{
    AuthenticatedCredential, DiscoverableAuthentication16, DiscoverableAuthenticationServerState,
    DiscoverableCredentialRequestOptions, PublicKeyCredentialCreationOptions, Registration,
    RegistrationServerState,
};

/// How long a ceremony may take (the options' timeout is the same 300 s).
pub const CHALLENGE_TTL_SECS: i64 = 300;
/// Expired challenge rows removed per `start_*` call, so abandoned
/// ceremonies never pile up and no call does unbounded work.
const EXPIRED_SWEEP_LIMIT: i64 = 100;

const PURPOSE_REGISTRATION: &str = "registration";
const PURPOSE_ASSERTION: &str = "assertion";

/// A stored key as `webauthn_rp` decodes it.
type StoredKey = CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>;

/// The transport names WebAuthn uses, with the flag each maps to.
const TRANSPORTS: [(&str, AuthenticatorTransport); 6] = [
    ("ble", AuthenticatorTransport::Ble),
    ("hybrid", AuthenticatorTransport::Hybrid),
    ("internal", AuthenticatorTransport::Internal),
    ("nfc", AuthenticatorTransport::Nfc),
    ("smart-card", AuthenticatorTransport::SmartCard),
    ("usb", AuthenticatorTransport::Usb),
];
/// The bit each transport has in `AuthTransports`' encoding, in
/// [`TRANSPORTS`] order.
const TRANSPORT_BITS: [u8; 6] = [0x1, 0x2, 0x4, 0x8, 0x10, 0x20];

/// Who the credentials belong to: the RP id (the deployment's host name) and
/// the origins a response may come from. No origins means `https://<rp id>`.
#[derive(Debug)]
pub struct RelyingParty {
    rp_id: RpId,
    origins: Vec<String>,
}

impl RelyingParty {
    /// `rp_id` must be a host name (`crm.example.com`, `localhost`): labels
    /// of ASCII letters, digits and hyphens. `AsciiDomain` alone accepts any
    /// ASCII.
    pub fn new(rp_id: &str, origins: Vec<String>) -> Result<Self, AppError> {
        let not_a_domain =
            || AppError::Validation("passkey relying party id is not a domain".into());
        let host_name = rp_id.split('.').all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
        if !host_name {
            return Err(not_a_domain());
        }
        let domain = AsciiDomain::try_from(rp_id.to_owned()).map_err(|_| not_a_domain())?;
        Ok(Self {
            rp_id: RpId::Domain(domain),
            origins,
        })
    }
}

/// A passkey that just verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asserted {
    /// The account the passkey belongs to.
    pub user_ref: Uuid,
    /// The `webauthn_credential` row.
    pub credential_ref: Uuid,
}

/// Starts registering a passkey for `user_ref`. Returns the creation options
/// for `navigator.credentials.create`. The account's live passkeys are
/// excluded so an authenticator is not registered twice.
pub async fn start_registration(
    db: &DbPool,
    rp: &RelyingParty,
    user_ref: Uuid,
    user_name: &str,
    display_name: Option<&str>,
) -> Result<serde_json::Value, AppError> {
    let handle = user_handle(user_ref);
    let name = Username::try_from(user_name)
        .map_err(|_| AppError::Validation("passkey user name is not usable".into()))?;
    let display_name = display_name
        .map(Nickname::try_from)
        .transpose()
        .map_err(|_| AppError::Validation("passkey display name is not usable".into()))?;
    let existing: Vec<(Vec<u8>, Vec<String>)> = sqlx::query_as(
        "SELECT credential_id, transports FROM webauthn_credential \
          WHERE user_ref = $1 AND NOT is_deleted",
    )
    .bind(user_ref)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut exclude = Vec::with_capacity(existing.len());
    for (id, transports) in existing {
        exclude.push(PublicKeyCredentialDescriptor {
            id: CredentialId::<Vec<u8>>::decode(id).map_err(AppError::internal)?,
            transports: transports_from_names(&transports)?,
        });
    }
    let user = PublicKeyCredentialUserEntity {
        name,
        id: &handle,
        display_name,
    };
    let (server, client) = PublicKeyCredentialCreationOptions::passkey(&rp.rp_id, user, exclude)
        .start_ceremony()
        .map_err(AppError::internal)?;
    let state = server.encode().map_err(AppError::internal)?;
    let options = serde_json::to_value(&client).map_err(AppError::internal)?;
    store_challenge(
        db,
        Some(user_ref),
        PURPOSE_REGISTRATION,
        server.sent_challenge().0,
        &state,
    )
    .await?;
    Ok(options)
}

/// Finishes a registration `start_registration` began for `user_ref`.
/// Returns the new `webauthn_credential` id.
pub async fn finish_registration(
    db: &DbPool,
    rp: &RelyingParty,
    user_ref: Uuid,
    response_json: &[u8],
    label: Option<&str>,
) -> Result<Uuid, AppError> {
    let registration = Registration::from_json_relaxed(response_json)
        .map_err(|_| AppError::Validation("passkey registration response is malformed".into()))?;
    let challenge = registration
        .challenge_relaxed()
        .map_err(|_| AppError::Validation("passkey registration response is malformed".into()))?;
    let state = take_challenge(db, Some(user_ref), PURPOSE_REGISTRATION, challenge.0).await?;
    let server = RegistrationServerState::<16>::decode(state.as_slice())
        .map_err(|e| AppError::internal(format!("stored passkey registration state: {e}")))?;
    let options = RegistrationVerificationOptions::<String, String> {
        allowed_origins: &rp.origins,
        ..RegistrationVerificationOptions::default()
    };
    let credential = server
        .verify(&rp.rp_id, &registration, &options)
        .map_err(|e| refused("registration", &e))?;
    let static_state = credential
        .static_state()
        .encode()
        .map_err(AppError::internal)?;
    let dynamic = credential.dynamic_state();
    let dynamic_state = dynamic.encode().map_err(AppError::internal)?;
    let transports = transport_names(credential.transports());
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO webauthn_credential \
             (user_ref, credential_id, public_key, dynamic_state, sign_count, transports, label) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (credential_id) DO NOTHING RETURNING id",
    )
    .bind(user_ref)
    .bind(credential.id().as_ref())
    .bind(&static_state)
    .bind(dynamic_state.as_slice())
    .bind(i64::from(dynamic.sign_count))
    .bind(&transports)
    .bind(label)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    id.ok_or(AppError::Conflict("passkey already registered"))
}

/// Starts a passkey assertion. `user_ref` is the account a second factor is
/// for, or `None` for a sign-in that names no user. Returns the request
/// options for `navigator.credentials.get`.
pub async fn start_assertion(
    db: &DbPool,
    rp: &RelyingParty,
    user_ref: Option<Uuid>,
) -> Result<serde_json::Value, AppError> {
    let (server, client) = DiscoverableCredentialRequestOptions::passkey(&rp.rp_id)
        .start_ceremony()
        .map_err(AppError::internal)?;
    let state = server.encode().map_err(AppError::internal)?;
    let options = serde_json::to_value(&client).map_err(AppError::internal)?;
    store_challenge(
        db,
        user_ref,
        PURPOSE_ASSERTION,
        server.sent_challenge().0,
        &state,
    )
    .await?;
    Ok(options)
}

/// Finishes an assertion `start_assertion` began with the same `user_ref`.
/// When `user_ref` is given, a passkey of any other account is refused.
pub async fn finish_assertion(
    db: &DbPool,
    rp: &RelyingParty,
    user_ref: Option<Uuid>,
    response_json: &[u8],
) -> Result<Asserted, AppError> {
    let authentication = DiscoverableAuthentication16::from_json_relaxed(response_json)
        .map_err(|_| AppError::Validation("passkey assertion response is malformed".into()))?;
    let challenge = authentication
        .challenge_relaxed()
        .map_err(|_| AppError::Validation("passkey assertion response is malformed".into()))?;
    let state = take_challenge(db, user_ref, PURPOSE_ASSERTION, challenge.0).await?;
    let server = DiscoverableAuthenticationServerState::decode(state.as_slice())
        .map_err(|e| AppError::internal(format!("stored passkey assertion state: {e}")))?;

    let raw_id = authentication.raw_id();
    let row: Option<(Uuid, Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT id, user_ref, public_key, dynamic_state FROM webauthn_credential \
          WHERE credential_id = $1 AND NOT is_deleted",
    )
    .bind(raw_id.as_ref())
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((credential_ref, owner, public_key, stored_dynamic)) = row else {
        tracing::warn!("passkey assertion refused: unknown credential");
        return Err(AppError::Unauthorized);
    };
    if user_ref.is_some_and(|expected| expected != owner) {
        tracing::warn!(%credential_ref, "passkey assertion refused: passkey of another account");
        return Err(AppError::Unauthorized);
    }
    let handle = user_handle(owner);
    let static_state = StaticState::<StoredKey>::decode(public_key.as_slice())
        .map_err(|e| AppError::internal(format!("stored passkey key: {e}")))?;
    let stored_dynamic: [u8; 7] = stored_dynamic
        .as_slice()
        .try_into()
        .map_err(|_| AppError::internal("stored passkey state is not 7 bytes"))?;
    let dynamic = DynamicState::decode(stored_dynamic)
        .map_err(|e| AppError::internal(format!("stored passkey state: {e}")))?;
    let mut credential = AuthenticatedCredential::new(raw_id, &handle, static_state, dynamic)
        .map_err(|e| AppError::internal(format!("stored passkey: {e}")))?;
    // The default counter rule refuses a counter that did not move past a
    // stored non-zero one (a cloned authenticator).
    let options = AuthenticationVerificationOptions::<String, String> {
        allowed_origins: &rp.origins,
        ..AuthenticationVerificationOptions::default()
    };
    server
        .verify(&rp.rp_id, &authentication, &mut credential, &options)
        .map_err(|e| refused("assertion", &e))?;
    let updated = credential.dynamic_state();
    let updated_state = updated.encode().map_err(AppError::internal)?;
    // Compare-and-set on the state read above: of two assertions racing past
    // the same counter, only one is accepted.
    let written = sqlx::query(
        "UPDATE webauthn_credential \
            SET dynamic_state = $2, sign_count = $3, last_used_at = now() \
          WHERE id = $1 AND dynamic_state = $4 AND NOT is_deleted",
    )
    .bind(credential_ref)
    .bind(updated_state.as_slice())
    .bind(i64::from(updated.sign_count))
    .bind(stored_dynamic.as_slice())
    .execute(db)
    .await
    .map_err(AppError::internal)?
    .rows_affected();
    if written != 1 {
        tracing::warn!(%credential_ref, "passkey assertion refused: a concurrent assertion won");
        return Err(AppError::Unauthorized);
    }
    Ok(Asserted {
        user_ref: owner,
        credential_ref,
    })
}

/// The account id as a 16-byte WebAuthn user handle.
fn user_handle(user_ref: Uuid) -> UserHandle16 {
    match UserHandle16::decode(user_ref.into_bytes()) {
        Ok(handle) => handle,
        Err(never) => match never {},
    }
}

async fn store_challenge(
    db: &DbPool,
    user_ref: Option<Uuid>,
    purpose: &str,
    challenge: u128,
    state: &[u8],
) -> Result<(), AppError> {
    sqlx::query(
        "DELETE FROM webauthn_challenge WHERE id IN \
           (SELECT id FROM webauthn_challenge WHERE expires_at < now() LIMIT $1)",
    )
    .bind(EXPIRED_SWEEP_LIMIT)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    sqlx::query(
        "INSERT INTO webauthn_challenge (user_ref, purpose, challenge, state, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_ref)
    .bind(purpose)
    .bind(challenge.to_le_bytes().as_slice())
    .bind(state)
    .bind(Utc::now() + Duration::seconds(CHALLENGE_TTL_SECS))
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// Spends an open challenge once and returns its stored ceremony state. A
/// used, expired, unknown or other-account challenge is refused.
async fn take_challenge(
    db: &DbPool,
    user_ref: Option<Uuid>,
    purpose: &str,
    challenge: u128,
) -> Result<Vec<u8>, AppError> {
    let state: Option<Vec<u8>> = sqlx::query_scalar(
        "UPDATE webauthn_challenge SET used_at = now() \
          WHERE challenge = $1 AND purpose = $2 AND user_ref IS NOT DISTINCT FROM $3 \
            AND used_at IS NULL AND expires_at > now() \
          RETURNING state",
    )
    .bind(challenge.to_le_bytes().as_slice())
    .bind(purpose)
    .bind(user_ref)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    state.ok_or_else(|| {
        tracing::warn!(
            purpose,
            "passkey ceremony refused: challenge is used, expired or unknown"
        );
        AppError::Unauthorized
    })
}

fn refused(ceremony: &'static str, e: &dyn std::fmt::Display) -> AppError {
    tracing::warn!(ceremony, reason = %e, "passkey ceremony refused");
    AppError::Unauthorized
}

fn transport_names(transports: AuthTransports) -> Vec<String> {
    TRANSPORTS
        .iter()
        .filter(|(_, t)| transports.contains(*t))
        .map(|(name, _)| (*name).to_owned())
        .collect()
}

fn transports_from_names(names: &[String]) -> Result<AuthTransports, AppError> {
    let bits = TRANSPORTS
        .iter()
        .zip(TRANSPORT_BITS)
        .filter(|((name, _), _)| names.iter().any(|n| n == name))
        .fold(0u8, |acc, (_, bit)| acc | bit);
    AuthTransports::decode(bits).map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_names_round_trip() {
        let names = vec!["internal".to_owned(), "usb".to_owned()];
        let transports = transports_from_names(&names).unwrap();
        assert_eq!(transport_names(transports), names);
    }

    #[test]
    fn rp_id_must_be_a_domain() {
        assert!(RelyingParty::new("crm.example.com", Vec::new()).is_ok());
        assert!(RelyingParty::new("not a domain", Vec::new()).is_err());
        assert!(RelyingParty::new("crm..example.com", Vec::new()).is_err());
        assert!(RelyingParty::new("", Vec::new()).is_err());
    }
}
