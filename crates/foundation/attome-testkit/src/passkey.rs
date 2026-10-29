//! Q6-T1: a software passkey authenticator for tests that drive the passkey
//! ceremonies through the HTTP routes.
//!
//! The server's challenges are random, so a recorded browser response cannot
//! answer a fresh ceremony. [`Authenticator`] holds a fixed Ed25519 key and
//! builds what a browser and a platform authenticator send: the
//! `clientDataJSON`, a `none` attestation object and signed authenticator
//! data, as `PublicKeyCredential.toJSON()`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A platform authenticator holding one Ed25519 passkey for `rp_id`, used
/// from `origin`.
pub struct Authenticator {
    key: SigningKey,
    credential_id: [u8; 16],
    rp_id: String,
    origin: String,
    sign_count: u32,
}

impl std::fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The private key stays out of test output.
        f.debug_struct("Authenticator")
            .field("rp_id", &self.rp_id)
            .field("origin", &self.origin)
            .field("sign_count", &self.sign_count)
            .finish_non_exhaustive()
    }
}

impl Authenticator {
    /// A passkey whose key comes from `seed`, for the relying party `rp_id`
    /// (`localhost`) used from `origin` (`http://localhost:4199`).
    pub fn new(seed: u8, rp_id: &str, origin: &str) -> Self {
        Self {
            key: SigningKey::from_bytes(&[seed; 32]),
            credential_id: *Uuid::now_v7().as_bytes(),
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
            sign_count: 0,
        }
    }

    fn client_data(&self, kind: &str, options: &Value) -> Vec<u8> {
        let challenge = options["challenge"]
            .as_str()
            .unwrap_or_else(|| panic!("options carry no challenge: {options}"));
        json!({
            "type": kind,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    /// `rpIdHash`, flags (user present and verified, plus `extra`) and the
    /// big-endian signature counter.
    fn auth_data_head(&self, extra_flags: u8, sign_count: u32) -> Vec<u8> {
        let mut data = Sha256::digest(self.rp_id.as_bytes()).to_vec();
        data.push(0b0000_0101 | extra_flags);
        data.extend_from_slice(&sign_count.to_be_bytes());
        data
    }

    /// The `PublicKeyCredential.toJSON()` of `navigator.credentials.create`
    /// for the creation `options`.
    pub fn register(&self, options: &Value) -> Value {
        let client_data = self.client_data("webauthn.create", options);
        // Attested credential data: a zero AAGUID, the id, the COSE key.
        let mut auth_data = self.auth_data_head(0b0100_0000, 0);
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
        let len =
            u8::try_from(auth_data.len()).unwrap_or_else(|_| panic!("long authenticator data"));
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
    }

    /// The `PublicKeyCredential.toJSON()` of `navigator.credentials.get` for
    /// the request `options`, as `user_ref`'s passkey. Each call moves the
    /// signature counter on, as a real authenticator does.
    pub fn assert(&mut self, options: &Value, user_ref: Uuid) -> Value {
        self.sign_count += 1;
        let client_data = self.client_data("webauthn.get", options);
        let auth_data = self.auth_data_head(0, self.sign_count);
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
    }
}
