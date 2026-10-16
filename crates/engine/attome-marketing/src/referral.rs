//! Referrals (roadmap E31-T1): each contact gets one code; a lead that
//! arrives with a code (on a form, or through a link carrying it) is
//! attributed to the code's contact, once per lead; when the lead converts
//! (`converted_account_ref` set) the referrer earns [`REWARD_POINTS`]
//! loyalty points, once (migration 0096, nightly in [`reward_converted`]).
//!
//! A lead whose email or phone matches the referrer's own is a
//! self-referral and is refused; a lead already referred keeps its first
//! referral.

use attome_types::AppError;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Loyalty points a converted referral earns.
pub const REWARD_POINTS: i64 = 500;

/// Code length; the alphabet leaves out 0, O, 1, I and L.
pub const CODE_LEN: usize = 8;
const ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// A readable code derived from an id (stable, so asking twice gives the
/// same code; a collision is resolved by the caller with a salt).
pub fn code_for(id: Uuid, salt: u32) -> String {
    let mut n = id.as_u128() ^ (u128::from(salt) << 64);
    let mut out = String::with_capacity(CODE_LEN);
    for _ in 0..CODE_LEN {
        out.push(char::from(ALPHABET[(n % ALPHABET.len() as u128) as usize]));
        n /= ALPHABET.len() as u128;
    }
    out
}

/// Normalises a typed code: upper case, no spaces or dashes.
pub fn normalise(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn same_contact(a: Option<&str>, b: Option<&str>) -> bool {
    let norm = |s: &str| {
        s.trim()
            .to_lowercase()
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>()
    };
    matches!((a, b), (Some(a), Some(b)) if !a.trim().is_empty() && norm(a) == norm(b))
}

/// Whether the lead is the referrer under another name.
pub fn is_self_referral(
    referrer: (Option<&str>, Option<&str>),
    lead: (Option<&str>, Option<&str>),
) -> bool {
    same_contact(referrer.0, lead.0) || same_contact(referrer.1, lead.1)
}

/// Why a referral was not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    UnknownCode,
    SelfReferral,
    AlreadyReferred,
}

/// The contact's code, created on first ask.
pub async fn code_of(db: &attome_db::DbPool, contact: Uuid) -> Result<String, AppError> {
    if let Some(code) =
        sqlx::query_scalar::<_, String>("SELECT code FROM referral_code WHERE contact_id = $1")
            .bind(contact)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?
    {
        return Ok(code);
    }
    for salt in 0..8 {
        let code = code_for(contact, salt);
        let inserted = sqlx::query(
            "INSERT INTO referral_code (code, contact_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(&code)
        .bind(contact)
        .execute(db)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if inserted == 1 {
            return Ok(code);
        }
        // Another request may have created this contact's code meanwhile.
        if let Some(existing) =
            sqlx::query_scalar::<_, String>("SELECT code FROM referral_code WHERE contact_id = $1")
                .bind(contact)
                .fetch_optional(db)
                .await
                .map_err(AppError::internal)?
        {
            return Ok(existing);
        }
    }
    Err(AppError::internal(
        "no free referral code after eight tries",
    ))
}

/// Attributes a lead to a code; `Ok(Err(..))` says why it was refused.
pub async fn attribute(
    db: &attome_db::DbPool,
    code: &str,
    lead: Uuid,
) -> Result<Result<Uuid, Refused>, AppError> {
    let code = normalise(code);
    let referrer: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT c.id, c.email, c.phone FROM referral_code r JOIN contact c ON c.id = r.contact_id \
         WHERE r.code = $1",
    )
    .bind(&code)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    let Some((_, ref_email, ref_phone)) = referrer else {
        return Ok(Err(Refused::UnknownCode));
    };
    let lead_row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT email, phone FROM lead WHERE id = $1")
            .bind(lead)
            .fetch_optional(db)
            .await
            .map_err(AppError::internal)?;
    let (lead_email, lead_phone) = lead_row.unwrap_or((None, None));
    if is_self_referral(
        (ref_email.as_deref(), ref_phone.as_deref()),
        (lead_email.as_deref(), lead_phone.as_deref()),
    ) {
        return Ok(Err(Refused::SelfReferral));
    }
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO referral (code, lead_id) VALUES ($1, $2) \
         ON CONFLICT (lead_id) DO NOTHING RETURNING id",
    )
    .bind(&code)
    .bind(lead)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;
    Ok(id.ok_or(Refused::AlreadyReferred))
}

/// Rewards every attributed referral whose lead converted; the number
/// rewarded. Each reward is a loyalty `earn` keyed by the referral.
pub async fn reward_converted(db: &attome_db::DbPool, now: DateTime<Utc>) -> Result<u64, AppError> {
    let installed: bool = sqlx::query_scalar(
        "SELECT to_regclass('referral') IS NOT NULL AND to_regclass('lead') IS NOT NULL",
    )
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    if !installed {
        return Ok(0);
    }
    let due: Vec<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT r.id, c.contact_id FROM referral r \
         JOIN referral_code c ON c.code = r.code JOIN lead l ON l.id = r.lead_id \
         WHERE r.status = 'attributed' AND l.converted_account_ref IS NOT NULL \
         ORDER BY r.id LIMIT 500",
    )
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let mut rewarded = 0;
    for (referral, referrer) in due {
        let mut tx = attome_db::tx::begin(db).await?;
        let moved = sqlx::query(
            "UPDATE referral SET status = 'rewarded', rewarded_at = $2 \
             WHERE id = $1 AND status = 'attributed'",
        )
        .bind(referral)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?
        .rows_affected();
        if moved == 1 {
            sqlx::query(
                "INSERT INTO loyalty_ledger \
                   (member_entity, member_id, kind, points, reference, occurred_at, expires_at) \
                 VALUES ('contact', $1, 'earn', $2, $3, $4, $5) \
                 ON CONFLICT (kind, reference) DO NOTHING",
            )
            .bind(referrer)
            .bind(REWARD_POINTS)
            .bind(format!("referral:{referral}"))
            .bind(now)
            .bind(now.checked_add_months(chrono::Months::new(crate::loyalty::EARN_VALID_MONTHS)))
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
            rewarded += 1;
        }
        attome_db::tx::commit(tx).await?;
    }
    Ok(rewarded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_readable_and_salted() {
        let id = Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        let code = code_for(id, 0);
        assert_eq!(code.len(), CODE_LEN);
        assert_eq!(code, code_for(id, 0));
        assert_ne!(code, code_for(id, 1));
        assert!(!code.contains(['0', 'O', '1', 'I', 'L']));
        assert_eq!(normalise(" ab-cd 23 "), "ABCD23");
    }

    #[test]
    fn self_referral_is_caught_by_email_or_phone() {
        assert!(is_self_referral(
            (Some("Sara@Example.com"), None),
            (Some(" sara@example.com"), None)
        ));
        assert!(is_self_referral(
            (None, Some("+966 50-123-4567")),
            (None, Some("+966501234567"))
        ));
        assert!(!is_self_referral(
            (Some("sara@example.com"), Some("+966501234567")),
            (Some("omar@example.com"), None)
        ));
        assert!(!is_self_referral((Some(""), None), (Some(""), None)));
    }
}
