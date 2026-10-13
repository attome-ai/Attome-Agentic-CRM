//! TOTP for portal users (R10). Same parameters as staff MFA (SHA-1, 6
//! digits, 30-second steps, one step of clock skew) and the same replay rule:
//! a code is accepted only for a time-step later than the last one accepted.
//! Secrets are envelope-encrypted under `auth.mfa_encryption_key`, in a field
//! name of their own so a staff ciphertext can never be read back as a portal
//! one or the reverse.

use attome_config::KeyRing;
use attome_types::AppError;
use totp_rs::{Algorithm, Builder, Secret, Totp};

const FIELD_NAME: &str = "webportal_credential.mfa_secret";
const DIGITS: u8 = 6;
const SKEW: u8 = 1;
const STEP_SECS: u64 = 30;

pub fn encrypt(ring: &KeyRing, secret_base32: &str) -> Result<String, AppError> {
    attome_auth::envelope::encrypt(FIELD_NAME, ring, secret_base32)
}

pub fn decrypt(ring: &KeyRing, encoded: &str) -> Result<String, AppError> {
    attome_auth::envelope::decrypt(FIELD_NAME, ring, encoded)
}

/// A fresh random base32 secret.
pub fn generate_secret() -> String {
    Secret::generate().to_base32()
}

fn totp(secret_base32: &str, issuer: &str, account: &str) -> Result<Totp, AppError> {
    let secret = Secret::try_from_base32(secret_base32)
        .map_err(|_| AppError::internal("stored portal mfa secret is not valid base32"))?;
    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(DIGITS)
        .with_skew(u16::from(SKEW))
        .with_step_duration(STEP_SECS)
        .with_secret(secret)
        .with_issuer(Some(issuer.to_owned()))
        .with_account_name(account.to_owned())
        .build()
        .map_err(AppError::internal)
}

/// The `otpauth://` URI an authenticator app scans.
pub fn provisioning_uri(
    secret_base32: &str,
    issuer: &str,
    account: &str,
) -> Result<String, AppError> {
    totp(secret_base32, issuer, account)?
        .to_url()
        .map_err(AppError::internal)
}

/// The accepted time-step, or `None`. Takes the newest matching step within
/// the skew window, and refuses one at or before `last_step` (replay).
pub fn verify(
    secret_base32: &str,
    code: &str,
    last_step: Option<i64>,
    now_secs: u64,
) -> Result<Option<i64>, AppError> {
    let code = code.trim();
    if code.len() != usize::from(DIGITS) || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(None);
    }
    let t = totp(secret_base32, "attome", "portal")?;
    let current = now_secs / STEP_SECS;
    let first = current.saturating_sub(u64::from(SKEW));
    let last = current.saturating_add(u64::from(SKEW));
    for step in (first..=last).rev() {
        let expected = t.generate(step * STEP_SECS).to_string();
        if ct_eq(&expected, code) {
            let step = i64::try_from(step).map_err(AppError::internal)?;
            return Ok(match last_step {
                Some(prev) if step <= prev => None,
                _ => Some(step),
            });
        }
    }
    Ok(None)
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Test helper: the code for `secret_base32` at `now_secs`.
pub fn code_at(secret_base32: &str, now_secs: u64) -> Result<String, AppError> {
    Ok(totp(secret_base32, "attome", "portal")?
        .generate(now_secs)
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_verifies_once_and_is_then_a_replay() {
        let secret = generate_secret();
        let now = 1_900_000_000;
        let code = code_at(&secret, now).unwrap();
        let step = verify(&secret, &code, None, now).unwrap().expect("valid");
        assert_eq!(verify(&secret, &code, Some(step), now).unwrap(), None);
        assert_eq!(verify(&secret, "000000x", None, now).unwrap(), None);
        // Two steps out of the skew window.
        assert_eq!(verify(&secret, &code, None, now + 90).unwrap(), None);
    }

    #[test]
    fn secrets_round_trip_through_the_envelope() {
        let ring = KeyRing::single("ab".repeat(32));
        let secret = generate_secret();
        assert_eq!(
            decrypt(&ring, &encrypt(&ring, &secret).unwrap()).unwrap(),
            secret
        );
    }
}
