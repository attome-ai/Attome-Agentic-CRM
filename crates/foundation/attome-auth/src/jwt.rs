//! P-key-rotation-and-jwt (c) — HS256 stays the signing algorithm (D-041:
//! one deployment is both the sole signer and sole verifier; asymmetric
//! JWKS is the rejected-for-now alternative, see that decision's named
//! migration trigger). What changes here: `auth.jwt_secret` is a
//! [`attome_config::KeyRing`] rather than a bare secret, every token's header
//! carries `kid` naming which ring entry signed it, and every token's claims
//! carry `iss`/`aud`/`typ` — validated (not just carried) — so a session
//! token and an MFA pending token are distinguishable by more than claims
//! *shape*, and rotating `jwt_secret` no longer force-logs-out every user
//! (the retired `kid` stays acceptable for verification as long as it stays
//! in the ring — same overlap-window mechanism as `envelope.rs`'s `KeyRing`
//! use elsewhere, deliberately the same shape per plan §4).
//!
//! Z4-T3: a deployment may now sign with Ed25519 instead (EdDSA, keys in
//! `auth.jwt_signing_keys`); see the EdDSA section below. HS256 stays the
//! default and keeps verifying the tokens issued before a cut-over.

use std::sync::{Arc, PoisonError, RwLock};

use crate::session::{SessionClaims, SessionId, TokenType};
use attome_config::KeyRing;
use attome_types::AppError;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

// ── Z4-T3: EdDSA signing ─────────────────────────────────────────────────────
//
// `auth.jwt_signing_keys` holds Ed25519 seeds by key id. It is installed once
// per configuration load ([`install_signing_keys`], from `AppState::new`),
// so the public functions below keep taking only the HS256 ring every caller
// already passes. With an active seed, new tokens are EdDSA; a token's header
// `alg` picks the verifier, so HS256 tokens issued before the cut-over keep
// verifying under `jwt_secret` until they expire. Any other `alg` is refused.

static SIGNING_KEYS: RwLock<Option<Arc<KeyRing>>> = RwLock::new(None);

/// Installs the Ed25519 ring (`auth.jwt_signing_keys`); an empty ring
/// returns signing to HS256.
pub fn install_signing_keys(ring: &KeyRing) {
    let next = (!ring.is_empty()).then(|| Arc::new(ring.clone()));
    *SIGNING_KEYS.write().unwrap_or_else(PoisonError::into_inner) = next;
}

fn signing_keys() -> Option<Arc<KeyRing>> {
    SIGNING_KEYS
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Z4-T4: the JSON Web Key Set (RFC 7517) of `eddsa`: one `OKP`/`Ed25519`
/// key per seed, public half only, by key id. HS256 secrets have no place
/// here, so this takes only the Ed25519 ring; a malformed seed is skipped
/// (config load already refuses one).
pub fn jwks_for(eddsa: Option<&KeyRing>) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut keys = Vec::new();
    if let Some(ring) = eddsa {
        let mut ids: Vec<&String> = ring.keys.keys().collect();
        ids.sort();
        for kid in ids {
            let Ok(seed) = ed25519_seed(&ring.keys[kid]) else {
                continue;
            };
            keys.push(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "x": URL_SAFE_NO_PAD.encode(ed25519_public(&seed)),
                "use": "sig",
                "alg": "EdDSA",
            }));
        }
    }
    serde_json::json!({ "keys": keys })
}

/// [`jwks_for`] of the installed ring.
pub fn jwks() -> serde_json::Value {
    jwks_for(signing_keys().as_deref())
}

/// A seed from its hex form.
fn ed25519_seed(hex_seed: &str) -> Result<[u8; 32], AppError> {
    hex::decode(hex_seed)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| AppError::internal("auth.jwt_signing_keys holds a malformed seed"))
}

/// The PKCS#8 v1 document for an Ed25519 seed (RFC 8410), which is what
/// `EncodingKey::from_ed_der` reads.
fn ed25519_pkcs8(seed: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(seed);
    der
}

/// The raw public key for a seed, which is what `DecodingKey::from_ed_der`
/// reads.
fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

/// Mints a token for any claims type that carries `typ`/`iss`/`aud` the same
/// way `SessionClaims`/`mfa::PendingClaims` do — signed under the installed
/// Ed25519 ring's active key when there is one (Z4-T3), else `ring`'s
/// active HS256 key, with that key's id stamped in the header as `kid`.
pub(crate) fn encode_claims<T: Serialize>(claims: &T, ring: &KeyRing) -> Result<String, AppError> {
    encode_claims_with(claims, ring, signing_keys().as_deref())
}

/// [`encode_claims`] with the Ed25519 ring passed explicitly.
pub(crate) fn encode_claims_with<T: Serialize>(
    claims: &T,
    ring: &KeyRing,
    eddsa: Option<&KeyRing>,
) -> Result<String, AppError> {
    if let Some(eddsa) = eddsa
        && let Some(seed) = eddsa.active()
    {
        let seed = ed25519_seed(seed)?;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(eddsa.active_key_id.clone());
        return encode(
            &header,
            claims,
            &EncodingKey::from_ed_der(&ed25519_pkcs8(&seed)),
        )
        .map_err(AppError::internal);
    }
    let active_secret = ring
        .active()
        .ok_or_else(|| AppError::internal("auth.jwt_secret has no active key configured"))?;
    let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
    header.kid = Some(ring.active_key_id.clone());
    encode(
        &header,
        claims,
        &EncodingKey::from_secret(active_secret.as_bytes()),
    )
    .map_err(AppError::internal)
}

/// Decodes and signature-verifies a token against `ring`, using the header's
/// `kid` to pick the exact signing key. A `kid`-less token is rejected
/// (BAU-12b): every token minted since D-130 carries one, and D-120 allows
/// the break. A `kid` that IS present but names no entry in the
/// ring is hard-rejected rather than falling back to the active key — this
/// repo's sole minter (`encode_claims`) always stamps the real signing key's
/// id, so a legitimate token's `kid` is never "present but unknown"; the
/// only way to reach that state is a malformed/tampered/cross-environment
/// header, and silently reinterpreting it as "verify against whatever key is
/// active right now" (audit finding #6) would let such a token slip through
/// whenever it happens to also be signed under the active key, defeating the
/// purpose of naming a key at all. Does NOT check `typ`/`iss`/`aud` —
/// callers that care about those (both do) check them themselves, since the
/// two claims shapes enforce different things (`validate_token` requires
/// `typ == Session`; `mfa::verify_pending_token` requires a specific pending
/// `typ`).
pub(crate) fn decode_claims<T: DeserializeOwned>(
    token: &str,
    ring: &KeyRing,
) -> Result<T, AppError> {
    decode_claims_with(token, ring, signing_keys().as_deref())
}

/// [`decode_claims`] with the Ed25519 ring passed explicitly. The header's
/// `alg` picks the ring: `EdDSA` the Ed25519 one, `HS256` `ring`; anything
/// else is refused.
pub(crate) fn decode_claims_with<T: DeserializeOwned>(
    token: &str,
    ring: &KeyRing,
    eddsa: Option<&KeyRing>,
) -> Result<T, AppError> {
    let header = decode_header(token).map_err(|_| AppError::Unauthorized)?;
    let kid = header.kid.ok_or(AppError::Unauthorized)?;
    match header.alg {
        Algorithm::HS256 => {}
        Algorithm::EdDSA => {
            let seed = eddsa
                .and_then(|ring| ring.get(&kid))
                .ok_or(AppError::Unauthorized)?;
            let public = ed25519_public(&ed25519_seed(seed)?);
            let mut validation = Validation::new(Algorithm::EdDSA);
            validation.validate_aud = false;
            return decode::<T>(token, &DecodingKey::from_ed_der(&public), &validation)
                .map(|data| data.claims)
                .map_err(|_| AppError::Unauthorized);
        }
        _ => return Err(AppError::Unauthorized),
    }
    let secret = ring.get(&kid).ok_or(AppError::Unauthorized)?;

    // required_spec_claims defaults to {"exp"} — jsonwebtoken's own 60s
    // leeway on exp/iat/nbf is kept as-is (plan §4: "existing 60s leeway
    // kept"). iss/aud are checked manually in validate_token/verify_pending_token
    // rather than via `Validation::set_issuer`/`set_audience`, so a token
    // minted before this feature (no iss/aud claim at all) still decodes —
    // see those functions' soft-check comments. `validate_aud` must be
    // disabled explicitly: jsonwebtoken 9's default `Validation` validates
    // `aud` against `Validation::aud` whenever the claims carry an `aud`
    // field at all, even an empty string — since `set_audience` is never
    // called here (audience is a manual soft-check below), every token
    // would otherwise fail decode with `InvalidAudience` before the claims
    // are even readable.
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_aud = false;
    decode::<T>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|_| AppError::Unauthorized)
}

/// A session token under a fresh, unregistered refresh family: for tests and
/// tools that need a valid token without a real login. Real sessions come from
/// [`create_session_token`] via `accounts::issue_access_token`.
pub fn create_token(claims: &SessionClaims, ring: &KeyRing) -> Result<String, AppError> {
    create_session_token(claims, Uuid::now_v7(), ring)
}

/// What a session JWT carries: [`SessionClaims`] plus the server-minted `sid`,
/// the id of the refresh-token family the session belongs to (D-510 rule 2).
///
/// A wrapper rather than a field on `SessionClaims`, so the in-process
/// `SessionClaims` values built for API-key, S2S and test requests stay as they
/// are and carry no session id. The token carries no authentication time,
/// methods or elevation: those are read from the family `sid` names.
#[derive(Serialize, Deserialize)]
struct SessionTokenClaims {
    #[serde(flatten)]
    claims: SessionClaims,
    sid: Uuid,
}

/// Mints a session token whose `sid` names the refresh family `family_id`.
/// `accounts::issue_access_token` is the only caller that mints real sessions.
pub fn create_session_token(
    claims: &SessionClaims,
    family_id: Uuid,
    ring: &KeyRing,
) -> Result<String, AppError> {
    encode_claims(
        &SessionTokenClaims {
            claims: claims.clone(),
            sid: family_id,
        },
        ring,
    )
}

/// Validates a session-shaped token of an exact type `typ` whose `iss` and
/// `aud` must equal `issuer`/`audience` exactly. Used by audiences other than the staff session (D-576's
/// portal sessions); the caller still owns every server-side check the
/// claims point at (epoch, revocation, account state).
pub fn validate_typed_session_token(
    token: &str,
    ring: &KeyRing,
    typ: TokenType,
    issuer: &str,
    audience: &str,
) -> Result<(SessionClaims, SessionId), AppError> {
    let token_claims: SessionTokenClaims = decode_claims(token, ring)?;
    let claims = token_claims.claims;
    if claims.typ != typ || claims.iss != issuer || claims.aud != audience {
        return Err(AppError::Unauthorized);
    }
    Ok((claims, SessionId(token_claims.sid)))
}

/// Validates a session token: signature (via `kid`/ring, see `decode_claims`),
/// `typ == Session` (rejects an MFA pending token presented as a session
/// token — today only shape-rejected, per audit finding #21), and `iss`/`aud`.
///
/// `iss` and `aud` must equal the configured values exactly, and the token
/// must carry `sid`.
pub fn validate_token(
    token: &str,
    ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<SessionClaims, AppError> {
    validate_session_token(token, ring, issuer, audience).map(|(claims, _)| claims)
}

/// [`validate_token`], also returning the token's session id (D-510 rule 2).
/// The authn
/// middleware attaches it to the request as the only way to find the session's
/// refresh family; nothing reads authentication context from the token itself.
pub fn validate_session_token(
    token: &str,
    ring: &KeyRing,
    issuer: &str,
    audience: &str,
) -> Result<(SessionClaims, SessionId), AppError> {
    validate_session_token_with(token, ring, signing_keys().as_deref(), issuer, audience)
}

/// [`validate_session_token`] with the Ed25519 ring passed explicitly
/// (Z4-T11: tests and the fuzz target never share the installed one).
pub fn validate_session_token_with(
    token: &str,
    ring: &KeyRing,
    eddsa: Option<&KeyRing>,
    issuer: &str,
    audience: &str,
) -> Result<(SessionClaims, SessionId), AppError> {
    let token_claims: SessionTokenClaims = decode_claims_with(token, ring, eddsa)?;
    let sid = SessionId(token_claims.sid);
    let claims = token_claims.claims;
    if claims.typ != TokenType::Session {
        return Err(AppError::Unauthorized);
    }
    if claims.iss != issuer || claims.aud != audience {
        return Err(AppError::Unauthorized);
    }
    Ok((claims, sid))
}

#[cfg(test)]
mod eddsa_tests {
    use super::*;

    fn hs256() -> KeyRing {
        KeyRing::single("test-only-hs256-secret-32-bytes-minimum".into())
    }

    fn eddsa(kid: &str, seed_byte: u8) -> KeyRing {
        KeyRing {
            keys: std::iter::once((kid.to_owned(), format!("{seed_byte:02x}").repeat(32)))
                .collect(),
            active_key_id: kid.to_owned(),
        }
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        exp: i64,
    }

    fn claims() -> Claims {
        Claims {
            sub: "someone".into(),
            exp: chrono::Utc::now().timestamp() + 600,
        }
    }

    #[test]
    fn eddsa_token_round_trips() {
        let ring = eddsa("ed1", 7);
        let token = encode_claims_with(&claims(), &hs256(), Some(&ring)).unwrap();
        let header = decode_header(&token).unwrap();
        assert_eq!(header.alg, Algorithm::EdDSA);
        assert_eq!(header.kid.as_deref(), Some("ed1"));
        let back: Claims = decode_claims_with(&token, &hs256(), Some(&ring)).unwrap();
        assert_eq!(back, claims_with_exp(back.exp));
        // Another seed under the same kid does not verify it.
        assert!(decode_claims_with::<Claims>(&token, &hs256(), Some(&eddsa("ed1", 8))).is_err());
    }

    fn claims_with_exp(exp: i64) -> Claims {
        Claims {
            sub: "someone".into(),
            exp,
        }
    }

    #[test]
    fn hs256_token_still_verifies_during_cutover() {
        let old = encode_claims_with(&claims(), &hs256(), None).unwrap();
        assert_eq!(decode_header(&old).unwrap().alg, Algorithm::HS256);
        let back: Claims = decode_claims_with(&old, &hs256(), Some(&eddsa("ed1", 7))).unwrap();
        assert_eq!(back.sub, "someone");
    }

    #[test]
    fn alg_none_is_refused() {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = b64.encode(br#"{"alg":"none","typ":"JWT","kid":"legacy"}"#);
        let body = b64.encode(serde_json::to_vec(&claims()).unwrap());
        let token = format!("{header}.{body}.");
        assert!(decode_claims_with::<Claims>(&token, &hs256(), Some(&eddsa("ed1", 7))).is_err());
        // HS384 under a known kid is refused too: only HS256 and EdDSA verify.
        let mut hs384 = Header::new(Algorithm::HS384);
        hs384.kid = Some("legacy".into());
        let token = encode(
            &hs384,
            &claims(),
            &EncodingKey::from_secret(hs256().active().unwrap().as_bytes()),
        )
        .unwrap();
        assert!(decode_claims_with::<Claims>(&token, &hs256(), None).is_err());
    }

    /// Z4-T11: a session token signed with the Ed25519 ring, expiring at
    /// `exp` and naming `audience`.
    fn eddsa_session(ring: &KeyRing, exp: i64, audience: &str) -> String {
        let now = chrono::Utc::now().timestamp();
        encode_claims_with(
            &SessionTokenClaims {
                claims: SessionClaims {
                    sub: uuid::Uuid::now_v7(),
                    iat: now - 10,
                    exp,
                    jti: uuid::Uuid::now_v7(),
                    epoch: 0,
                    iss: "attome-test".into(),
                    aud: audience.into(),
                    typ: TokenType::Session,
                },
                sid: uuid::Uuid::now_v7(),
            },
            &hs256(),
            Some(ring),
        )
        .unwrap()
    }

    #[test]
    fn expired_eddsa_token_is_refused() {
        let ring = eddsa("ed1", 9);
        let now = chrono::Utc::now().timestamp();
        let live = eddsa_session(&ring, now + 600, "attome-test");
        assert!(
            validate_session_token_with(&live, &hs256(), Some(&ring), "attome-test", "attome-test")
                .is_ok(),
            "control: a live token verifies"
        );
        // Past jsonwebtoken's 60 s leeway.
        let expired = eddsa_session(&ring, now - 120, "attome-test");
        assert!(
            validate_session_token_with(
                &expired,
                &hs256(),
                Some(&ring),
                "attome-test",
                "attome-test"
            )
            .is_err()
        );
    }

    #[test]
    fn wrong_audience_eddsa_token_is_refused() {
        let ring = eddsa("ed1", 9);
        let token = eddsa_session(&ring, chrono::Utc::now().timestamp() + 600, "elsewhere");
        assert!(
            validate_session_token_with(
                &token,
                &hs256(),
                Some(&ring),
                "attome-test",
                "attome-test"
            )
            .is_err()
        );
    }

    #[test]
    fn jwks_lists_only_public_eddsa_keys() {
        let ring = eddsa("ed1", 7);
        let set = jwks_for(Some(&ring));
        let keys = set["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "OKP");
        assert_eq!(keys[0]["crv"], "Ed25519");
        assert_eq!(keys[0]["kid"], "ed1");
        assert!(
            keys[0].get("d").is_none() && keys[0].get("k").is_none(),
            "no private half"
        );
        // The listed key verifies a token the ring signed.
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let x = URL_SAFE_NO_PAD
            .decode(keys[0]["x"].as_str().unwrap())
            .unwrap();
        let token = encode_claims_with(&claims(), &hs256(), Some(&ring)).unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;
        assert!(decode::<Claims>(&token, &DecodingKey::from_ed_der(&x), &validation).is_ok());
        assert_eq!(jwks_for(None)["keys"], serde_json::json!([]));
    }

    #[test]
    fn eddsa_token_with_unknown_kid_is_refused() {
        let token = encode_claims_with(&claims(), &hs256(), Some(&eddsa("ed1", 7))).unwrap();
        assert!(decode_claims_with::<Claims>(&token, &hs256(), Some(&eddsa("ed2", 7))).is_err());
        assert!(
            decode_claims_with::<Claims>(&token, &hs256(), None).is_err(),
            "no Ed25519 ring installed"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn ring(secret: &str) -> KeyRing {
        KeyRing::single(secret.to_string())
    }

    fn claims(exp_offset_secs: i64) -> SessionClaims {
        let now = chrono::Utc::now().timestamp();
        SessionClaims {
            sub: Uuid::now_v7(),
            iat: now,
            exp: now + exp_offset_secs,
            jti: Uuid::now_v7(),
            epoch: 0,
            iss: "attome-test".to_string(),
            aud: "attome-test".to_string(),
            typ: TokenType::Session,
        }
    }

    /// D-576: a portal session never authenticates as a staff session, a
    /// staff session never validates as a portal session, and a portal
    /// session for one audience never validates for another.
    #[test]
    fn typed_session_tokens_are_isolated_by_type_and_audience() {
        let r = ring("test-secret");
        let family = Uuid::now_v7();
        let mut portal = claims(900);
        portal.typ = TokenType::PortalSession;
        portal.aud = "portal:a".into();
        let token = create_session_token(&portal, family, &r).unwrap();

        let (decoded, sid) = validate_typed_session_token(
            &token,
            &r,
            TokenType::PortalSession,
            "attome-test",
            "portal:a",
        )
        .unwrap();
        assert_eq!(decoded.sub, portal.sub);
        assert_eq!(sid, SessionId(family));

        // Not a staff session, even with lenient staff validation.
        assert!(validate_session_token(&token, &r, "attome-test", "portal:a").is_err());
        // Wrong audience, wrong issuer, wrong type.
        for (typ, iss, aud) in [
            (TokenType::PortalSession, "attome-test", "portal:b"),
            (TokenType::PortalSession, "other", "portal:a"),
            (TokenType::Session, "attome-test", "portal:a"),
        ] {
            assert!(validate_typed_session_token(&token, &r, typ, iss, aud).is_err());
        }
        // A staff session is not a portal session, whatever its aud.
        let mut staff = claims(900);
        staff.aud = "portal:a".into();
        let staff_token = create_session_token(&staff, family, &r).unwrap();
        assert!(
            validate_typed_session_token(
                &staff_token,
                &r,
                TokenType::PortalSession,
                "attome-test",
                "portal:a"
            )
            .is_err()
        );
        // Expired.
        let mut expired = claims(-3600);
        expired.typ = TokenType::PortalSession;
        expired.aud = "portal:a".into();
        let expired = create_session_token(&expired, family, &r).unwrap();
        assert!(
            validate_typed_session_token(
                &expired,
                &r,
                TokenType::PortalSession,
                "attome-test",
                "portal:a"
            )
            .is_err()
        );
    }

    #[test]
    fn create_then_validate_roundtrips_the_same_claims() {
        let r = ring("test-secret");
        let original = claims(900);
        let token = create_token(&original, &r).unwrap();
        let decoded = validate_token(&token, &r, "attome-test", "attome-test").unwrap();
        assert_eq!(decoded.sub, original.sub);
        assert_eq!(decoded.jti, original.jti);
        assert_eq!(decoded.exp, original.exp);
    }

    /// D-510 rule 2: a session token's `sid` names its refresh family and
    /// survives validation unchanged.
    #[test]
    fn a_session_token_round_trips_its_session_id() {
        let r = ring("test-secret");
        let original = claims(900);
        let family_id = Uuid::now_v7();
        let token = create_session_token(&original, family_id, &r).unwrap();
        let (decoded, sid) =
            validate_session_token(&token, &r, "attome-test", "attome-test").unwrap();
        assert_eq!(decoded.sub, original.sub);
        assert_eq!(sid, SessionId(family_id));
    }

    /// `sid` is required: a signed session token without one is refused.
    #[test]
    fn a_token_without_a_session_id_is_rejected() {
        let r = ring("test-secret");
        let payload = serde_json::to_value(claims(900)).unwrap();
        let token = encode_claims(&payload, &r).unwrap();
        assert!(matches!(
            validate_session_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    /// The token carries a session id and nothing about freshness: no
    /// `auth_time`, `amr` or `elevated_until`, so no reader can mistake a claim
    /// for the authoritative context held on the refresh family.
    #[test]
    fn a_session_token_carries_no_authentication_context() {
        use base64::Engine as _;
        let r = ring("test-secret");
        let token = create_session_token(&claims(900), Uuid::now_v7(), &r).unwrap();
        let payload = token.split('.').nth(1).unwrap();
        let json: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .unwrap(),
        )
        .unwrap();
        let object = json.as_object().unwrap();
        assert!(object.contains_key("sid"));
        for field in ["auth_time", "amr", "elevated_until"] {
            assert!(!object.contains_key(field), "{field} must not be a claim");
        }
    }

    /// A signed token that nevertheless carries freshness-looking claims yields
    /// only the session id; there is no field those claims could land in.
    #[test]
    fn freshness_claims_in_a_token_are_ignored() {
        let r = ring("test-secret");
        let base = claims(900);
        let family_id = Uuid::now_v7();
        let mut payload = serde_json::to_value(&base).unwrap();
        let object = payload.as_object_mut().unwrap();
        object.insert("sid".into(), serde_json::json!(family_id));
        object.insert("auth_time".into(), serde_json::json!(base.iat));
        object.insert("amr".into(), serde_json::json!(["pwd", "otp"]));
        object.insert("elevated_until".into(), serde_json::json!(base.exp));
        let token = encode_claims(&payload, &r).unwrap();

        let (decoded, sid) =
            validate_session_token(&token, &r, "attome-test", "attome-test").unwrap();
        assert_eq!(decoded.sub, base.sub);
        assert_eq!(sid, SessionId(family_id));
    }

    #[test]
    fn validate_rejects_an_expired_token() {
        // jsonwebtoken's default leeway on `exp` is 60s, so the offset must
        // clear that window to actually be rejected.
        let r = ring("test-secret");
        let token = create_token(&claims(-120), &r).unwrap();
        assert!(matches!(
            validate_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn validate_rejects_a_token_signed_with_a_different_secret() {
        let signing_ring = ring("correct-secret");
        let verify_ring = ring("wrong-secret");
        let token = create_token(&claims(900), &signing_ring).unwrap();
        assert!(matches!(
            validate_token(&token, &verify_ring, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn validate_rejects_a_tampered_token_payload() {
        let r = ring("test-secret");
        let token = create_token(&claims(900), &r).unwrap();
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_payload = if parts[1].ends_with('A') {
            format!("{}B", &parts[1][..parts[1].len() - 1])
        } else {
            format!("{}A", &parts[1][..parts[1].len() - 1])
        };
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");
        assert!(matches!(
            validate_token(&tampered, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn validate_rejects_a_pending_typ_presented_as_a_session_token() {
        use crate::mfa::PendingClaims;
        let r = ring("test-secret");
        let now = chrono::Utc::now().timestamp();
        let pending = PendingClaims {
            sub: Uuid::now_v7(),
            typ: TokenType::MfaPendingLogin,
            iat: now,
            exp: now + 300,
            iss: "attome-test".to_string(),
            aud: "attome-test".to_string(),
            jti: Uuid::now_v7(),
        };
        let token = encode_claims(&pending, &r).unwrap();
        assert!(matches!(
            validate_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn validate_rejects_a_mismatched_issuer() {
        let r = ring("test-secret");
        let token = create_token(&claims(900), &r).unwrap();
        assert!(matches!(
            validate_token(&token, &r, "some-other-issuer", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn validate_rejects_a_token_with_no_iss_aud_claims() {
        // An empty iss/aud is a mismatch like any other.
        let r = ring("test-secret");
        let mut old_style = claims(900);
        old_style.iss = String::new();
        old_style.aud = String::new();
        let token = create_token(&old_style, &r).unwrap();
        assert!(matches!(
            validate_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn validate_accepts_a_correctly_stamped_token() {
        let r = ring("test-secret");
        let token = create_token(&claims(900), &r).unwrap();
        assert!(validate_token(&token, &r, "attome-test", "attome-test").is_ok());
    }

    #[test]
    fn an_old_kid_still_verifies_while_it_stays_in_the_ring_and_fails_once_removed() {
        let mut r = ring("original-secret");
        let old_kid = r.active_key_id.clone();
        let token = create_token(&claims(900), &r).unwrap();

        // Rotate: new active key, old one stays in the ring (overlap window).
        r.keys
            .insert("v2".to_string(), "rotated-secret".to_string());
        r.active_key_id = "v2".to_string();
        assert!(validate_token(&token, &r, "attome-test", "attome-test").is_ok());

        // End the overlap window: remove the old key entirely.
        r.keys.remove(&old_kid);
        assert!(matches!(
            validate_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn a_present_but_unrecognized_kid_is_rejected_even_when_the_active_key_would_verify_it() {
        // Audit finding #6: the old fallback treated "no kid" and "kid
        // present but unknown" the same way (retry against the active key).
        // Craft a token whose header names a kid that isn't in the ring at
        // all, but which is genuinely signed with the CURRENT active
        // secret — under the old fallback this would have verified
        // successfully despite the inconsistent header; it must now be
        // rejected outright since encode_claims never produces this shape.
        let r = ring("test-secret");
        let active_secret = r.active().unwrap().to_string();
        let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some("not-a-real-kid".to_string());
        let token = encode(
            &header,
            &claims(900),
            &EncodingKey::from_secret(active_secret.as_bytes()),
        )
        .unwrap();
        assert!(matches!(
            validate_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    /// BAU-12b: a token whose header names no key is refused, even when the
    /// active key would verify its signature.
    #[test]
    fn a_kidless_token_is_rejected() {
        let r = ring("test-secret");
        let active_secret = r.active().unwrap().to_string();
        let token = encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            &claims(900),
            &EncodingKey::from_secret(active_secret.as_bytes()),
        )
        .unwrap();
        assert!(matches!(
            validate_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    /// BAU-12a: `typ` has no default, so a signed token without it fails to
    /// decode instead of reading as a session.
    #[test]
    fn a_token_without_typ_is_rejected() {
        let r = ring("test-secret");
        let mut payload = serde_json::to_value(claims(900)).unwrap();
        payload.as_object_mut().unwrap().remove("typ");
        let token = encode_claims(&payload, &r).unwrap();
        assert!(matches!(
            validate_token(&token, &r, "attome-test", "attome-test"),
            Err(AppError::Unauthorized)
        ));
    }

    #[test]
    fn new_tokens_are_signed_under_the_active_kid() {
        let mut r = ring("original-secret");
        r.keys
            .insert("v2".to_string(), "rotated-secret".to_string());
        r.active_key_id = "v2".to_string();

        let token = create_token(&claims(900), &r).unwrap();
        let header = decode_header(&token).unwrap();
        assert_eq!(header.kid.as_deref(), Some("v2"));
    }
}
