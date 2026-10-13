//! MFA recovery codes for portal users (D-588 item 1).
//!
//! Ten single-use codes, shown once when MFA is confirmed or the set is
//! regenerated. Only a peppered HMAC of each is stored (D-500), in the
//! portal-owned `webportal_mfa_recovery_code` (migration 0489), never in
//! the staff table. A code is `xxxxx-xxxxx` over a 32-letter alphabet with no
//! look-alike characters (50 bits), so it can never be mistaken for a 6-digit
//! TOTP code.

use attome_auth::apikey_hash::{PepperRing, hash_peppered_secret};
use attome_types::AppError;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::secret;

pub const CODE_COUNT: usize = 10;
const HALF: usize = 5;
/// Crockford base32, lowercase: no `i`, `l`, `o` or `u`.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// One fresh code, `xxxxx-xxxxx`.
fn generate() -> String {
    let bytes = Uuid::new_v4().into_bytes();
    // Bytes 6 and 8 carry the v4 version and variant bits; the rest are
    // fully random.
    let chars: Vec<char> = [0, 1, 2, 3, 4, 5, 7, 9, 10, 11]
        .iter()
        .map(|&i| char::from(ALPHABET[usize::from(bytes[i] & 31)]))
        .collect();
    let (a, b) = chars.split_at(HALF);
    format!(
        "{}-{}",
        a.iter().collect::<String>(),
        b.iter().collect::<String>()
    )
}

/// The canonical form of a presented code (lowercase, no separators or
/// spaces), or `None` when it can't be a recovery code.
pub fn normalise(presented: &str) -> Option<String> {
    let code: String = presented
        .chars()
        .filter(|c| !matches!(c, '-' | ' '))
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (code.len() == HALF * 2 && code.bytes().all(|b| ALPHABET.contains(&b))).then_some(code)
}

/// Replaces the user's whole set and returns the new codes for display.
pub async fn replace_all(
    conn: &mut PgConnection,
    ring: &PepperRing,
    user_id: Uuid,
) -> Result<Vec<String>, AppError> {
    sqlx::query("DELETE FROM webportal_mfa_recovery_code WHERE webportal_user_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    let mut codes = Vec::with_capacity(CODE_COUNT);
    for _ in 0..CODE_COUNT {
        let code = generate();
        let canonical = normalise(&code).ok_or_else(|| AppError::internal("bad recovery code"))?;
        sqlx::query(
            "INSERT INTO webportal_mfa_recovery_code (id, webportal_user_id, code_hash) \
             VALUES ($1, $2, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(user_id)
        .bind(hash_peppered_secret(ring, &canonical))
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        codes.push(code);
    }
    Ok(codes)
}

/// Removes every code (MFA disabled).
pub async fn delete_all(conn: &mut PgConnection, user_id: Uuid) -> Result<(), AppError> {
    sqlx::query("DELETE FROM webportal_mfa_recovery_code WHERE webportal_user_id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(())
}

/// Consumes `presented` if it matches one of the user's unused codes. Every
/// unused code is checked whatever the outcome, so the time taken says
/// nothing about which one matched.
pub async fn consume(
    conn: &mut PgConnection,
    ring: &PepperRing,
    user_id: Uuid,
    presented: &str,
) -> Result<bool, AppError> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, code_hash FROM webportal_mfa_recovery_code \
         WHERE webportal_user_id = $1 AND used_at IS NULL \
         FOR UPDATE",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(AppError::internal)?;
    let Some(canonical) = normalise(presented) else {
        secret::verify(ring, presented, None).await?;
        return Ok(false);
    };
    let mut matched = None;
    for (id, hash) in &rows {
        if secret::verify(ring, &canonical, Some(hash)).await? && matched.is_none() {
            matched = Some(*id);
        }
    }
    if rows.is_empty() {
        secret::verify(ring, &canonical, None).await?;
    }
    let Some(id) = matched else {
        return Ok(false);
    };
    sqlx::query("UPDATE webportal_mfa_recovery_code SET used_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(AppError::internal)?;
    Ok(true)
}

/// Unused codes left.
pub async fn remaining(conn: &mut PgConnection, user_id: Uuid) -> Result<i64, AppError> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM webportal_mfa_recovery_code \
         WHERE webportal_user_id = $1 AND used_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(AppError::internal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_codes_have_the_documented_shape() {
        for _ in 0..200 {
            let code = generate();
            assert_eq!(code.len(), 11, "{code}");
            assert_eq!(&code[5..6], "-");
            assert!(normalise(&code).is_some(), "{code}");
        }
    }

    #[test]
    fn normalise_accepts_spacing_and_case_and_nothing_else() {
        assert_eq!(normalise("AB3DE-FG4HJ").as_deref(), Some("ab3defg4hj"));
        assert_eq!(normalise("ab3de fg4hj").as_deref(), Some("ab3defg4hj"));
        // A TOTP code is never a recovery code.
        assert_eq!(normalise("123456"), None);
        // Look-alike letters are outside the alphabet.
        assert_eq!(normalise("abcde-fghil"), None);
        assert_eq!(normalise("abcde-fghjkm"), None);
    }
}
