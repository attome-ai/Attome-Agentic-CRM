//! Z4-T6: passkeys — a passkey registers and then signs in, a spent
//! challenge is refused, and a counter that did not move is refused as a
//! cloned authenticator.
//!
//! The server's challenges are random, so a recorded browser response cannot
//! answer a fresh ceremony. The tests drive a software authenticator instead:
//! a fixed Ed25519 key that builds the `clientDataJSON`, `none` attestation
//! object and signed authenticator data a browser and authenticator send.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_auth::webauthn::{self, RelyingParty};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

const RP_ID: &str = "crm.attome.test";
const ORIGIN: &str = "https://crm.attome.test";

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

fn rp() -> RelyingParty {
    RelyingParty::new(RP_ID, vec![ORIGIN.to_owned()]).expect("relying party")
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A platform authenticator holding one Ed25519 passkey.
struct Authenticator {
    key: SigningKey,
    credential_id: [u8; 16],
}

impl Authenticator {
    fn new(seed: u8) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            credential_id: *Uuid::now_v7().as_bytes(),
        }
    }

    fn client_data(kind: &str, options: &Value) -> Vec<u8> {
        let challenge = options["challenge"]
            .as_str()
            .expect("options carry a challenge");
        json!({
            "type": kind,
            "challenge": challenge,
            "origin": ORIGIN,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    /// `rpIdHash`, flags (user present and verified, plus `extra`) and the
    /// big-endian signature counter.
    fn auth_data_head(extra_flags: u8, sign_count: u32) -> Vec<u8> {
        let mut data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        data.push(0b0000_0101 | extra_flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data
    }

    /// The `PublicKeyCredential.toJSON()` of `navigator.credentials.create`.
    fn register(&self, options: &Value) -> Vec<u8> {
        let client_data = Self::client_data("webauthn.create", options);
        // Attested credential data: a zero AAGUID, the id, the COSE key.
        let mut auth_data = Self::auth_data_head(0b0100_0000, 0);
        auth_data.extend_from_slice(&[0; 16]);
        auth_data.extend_from_slice(&16u16.to_be_bytes());
        auth_data.extend_from_slice(&self.credential_id);
        // {1: 1 (OKP), 3: -8 (EdDSA), -1: 6 (Ed25519), -2: x}
        auth_data.extend_from_slice(&[0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20]);
        auth_data.extend_from_slice(self.key.verifying_key().as_bytes());
        // {"fmt": "none", "attStmt": {}, "authData": auth_data}
        let mut attestation = vec![0xa3, 0x63];
        attestation.extend_from_slice(b"fmt");
        attestation.push(0x64);
        attestation.extend_from_slice(b"none");
        attestation.push(0x67);
        attestation.extend_from_slice(b"attStmt");
        attestation.push(0xa0);
        attestation.push(0x68);
        attestation.extend_from_slice(b"authData");
        let len = u8::try_from(auth_data.len()).expect("short authenticator data");
        attestation.extend_from_slice(&[0x58, len]);
        attestation.extend_from_slice(&auth_data);
        json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "attestationObject": b64(&attestation),
                "transports": ["internal"],
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        })
        .to_string()
        .into_bytes()
    }

    /// The `PublicKeyCredential.toJSON()` of `navigator.credentials.get`.
    fn assert(&self, options: &Value, user_ref: Uuid, sign_count: u32) -> Vec<u8> {
        let client_data = Self::client_data("webauthn.get", options);
        let auth_data = Self::auth_data_head(0, sign_count);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature = self.key.sign(&signed);
        json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(&client_data),
                "authenticatorData": b64(&auth_data),
                "signature": b64(&signature.to_bytes()),
                "userHandle": b64(user_ref.as_bytes()),
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        })
        .to_string()
        .into_bytes()
    }
}

/// Registers `authenticator` for a new account and returns the account id.
async fn registered(db: &DbPool, authenticator: &Authenticator) -> Uuid {
    let user = Uuid::now_v7();
    let options = webauthn::start_registration(db, &rp(), user, "sara@example.com", Some("Sara"))
        .await
        .expect("start registration");
    assert_eq!(options["rp"]["id"], RP_ID);
    assert_eq!(options["user"]["id"], b64(user.as_bytes()));
    webauthn::finish_registration(
        db,
        &rp(),
        user,
        &authenticator.register(&options),
        Some("laptop"),
    )
    .await
    .expect("finish registration");
    user
}

#[tokio::test]
async fn registration_then_assertion_succeeds() {
    let db = skip_if_no_db!(pool().await);
    let authenticator = Authenticator::new(7);
    let user = registered(&db, &authenticator).await;

    // A sign-in that names no user finds the account from the passkey.
    let options = webauthn::start_assertion(&db, &rp(), None)
        .await
        .expect("start assertion");
    let asserted =
        webauthn::finish_assertion(&db, &rp(), None, &authenticator.assert(&options, user, 1))
            .await
            .expect("passkey signs in");
    assert_eq!(asserted.user_ref, user);

    // As a second factor for the same account, with a higher counter.
    let options = webauthn::start_assertion(&db, &rp(), Some(user))
        .await
        .expect("start assertion");
    let second = webauthn::finish_assertion(
        &db,
        &rp(),
        Some(user),
        &authenticator.assert(&options, user, 2),
    )
    .await
    .expect("passkey second factor");
    assert_eq!(second, asserted);

    // A second factor asked for another account refuses this passkey.
    let other = Uuid::now_v7();
    let options = webauthn::start_assertion(&db, &rp(), Some(other))
        .await
        .expect("start assertion");
    let refused = webauthn::finish_assertion(
        &db,
        &rp(),
        Some(other),
        &authenticator.assert(&options, user, 3),
    )
    .await;
    assert!(
        matches!(refused, Err(AppError::Unauthorized)),
        "{refused:?}"
    );

    let stored: i64 =
        sqlx::query_scalar("SELECT sign_count FROM webauthn_credential WHERE user_ref = $1")
            .bind(user)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(stored, 2, "the counter moved with each accepted assertion");
}

#[tokio::test]
async fn replayed_challenge_is_refused() {
    let db = skip_if_no_db!(pool().await);
    let authenticator = Authenticator::new(8);
    let user = registered(&db, &authenticator).await;

    let options = webauthn::start_assertion(&db, &rp(), None)
        .await
        .expect("start assertion");
    webauthn::finish_assertion(&db, &rp(), None, &authenticator.assert(&options, user, 1))
        .await
        .expect("first use");
    // The same challenge again, even with a fresh signature and counter.
    let replayed =
        webauthn::finish_assertion(&db, &rp(), None, &authenticator.assert(&options, user, 2))
            .await;
    assert!(
        matches!(replayed, Err(AppError::Unauthorized)),
        "{replayed:?}"
    );

    // A registration challenge is spent once too.
    let options = webauthn::start_registration(&db, &rp(), user, "sara@example.com", None)
        .await
        .expect("start registration");
    let again = Authenticator::new(9);
    webauthn::finish_registration(&db, &rp(), user, &again.register(&options), None)
        .await
        .expect("second passkey");
    let third = Authenticator::new(10);
    let replayed =
        webauthn::finish_registration(&db, &rp(), user, &third.register(&options), None).await;
    assert!(
        matches!(replayed, Err(AppError::Unauthorized)),
        "{replayed:?}"
    );
}

#[tokio::test]
async fn lower_sign_count_is_refused() {
    let db = skip_if_no_db!(pool().await);
    let authenticator = Authenticator::new(11);
    let user = registered(&db, &authenticator).await;

    let options = webauthn::start_assertion(&db, &rp(), None)
        .await
        .expect("start assertion");
    webauthn::finish_assertion(&db, &rp(), None, &authenticator.assert(&options, user, 5))
        .await
        .expect("counter 5");
    for count in [5, 4] {
        let options = webauthn::start_assertion(&db, &rp(), None)
            .await
            .expect("start assertion");
        let cloned = webauthn::finish_assertion(
            &db,
            &rp(),
            None,
            &authenticator.assert(&options, user, count),
        )
        .await;
        assert!(
            matches!(cloned, Err(AppError::Unauthorized)),
            "counter {count} after 5: {cloned:?}"
        );
    }
}
