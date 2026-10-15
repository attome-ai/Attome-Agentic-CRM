//! Breached and reused passwords (roadmap Q7-T1).
//!
//! **Breached.** A new password whose SHA-1 is in an offline set of breached
//! passwords is refused. The set is checked locally, so no password or
//! hash prefix ever leaves the server (a sovereign deployment calls no
//! outside service). A small seed list ships in the binary
//! (`data/breached-passwords.sha1`); a deployment loads the full offline set
//! (the Have I Been Pwned download, `HASH` or `HASH:COUNT` per line) with
//! `auth.breach_list_file`, and replaces the file to update it.
//! [`crate::password::validate_policy`] runs the check, so every path that
//! sets a password goes through it.
//!
//! **Reused.** A password reset may not reuse the current password or any of
//! the [`HISTORY_DEPTH`] before it: [`reused`] checks them, and
//! [`remember`] keeps the replaced hash, inside the reset's transaction.

use std::path::Path;
use std::sync::OnceLock;

use attome_types::AppError;
use sha1::{Digest, Sha1};
use sqlx::PgConnection;
use uuid::Uuid;

/// How many earlier passwords a new one may not repeat, besides the current
/// one.
pub const HISTORY_DEPTH: i64 = 5;

/// The seed list compiled into the binary.
const SHIPPED: &str = include_str!("../data/breached-passwords.sha1");

static BREACHED: OnceLock<BreachedSet> = OnceLock::new();

/// A sorted set of SHA-1 digests of breached passwords.
#[derive(Debug, Default)]
pub struct BreachedSet {
    hashes: Vec<[u8; 20]>,
}

impl BreachedSet {
    /// Reads `HASH` or `HASH:COUNT` lines (40 hex digits, either case);
    /// blank lines, `#` comments and malformed lines are skipped.
    pub fn parse(text: &str) -> Self {
        let mut hashes: Vec<[u8; 20]> = text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let hex = line.split(':').next()?.trim();
                if hex.len() != 40 {
                    return None;
                }
                let mut digest = [0u8; 20];
                hex::decode_to_slice(hex, &mut digest).ok()?;
                Some(digest)
            })
            .collect();
        hashes.sort_unstable();
        hashes.dedup();
        Self { hashes }
    }

    /// Whether `password` is in the set.
    pub fn contains(&self, password: &str) -> bool {
        let digest: [u8; 20] = Sha1::digest(password.as_bytes()).into();
        self.hashes.binary_search(&digest).is_ok()
    }

    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }
}

/// Loads the deployment's offline set from `path`, together with the seed
/// list, for this process. Call once at boot, before the first password is
/// set; returns how many hashes are in force, or the read error (boot fails
/// rather than run with a check the operator configured but did not get).
pub fn load_file(path: &Path) -> std::io::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let set = BreachedSet::parse(&format!("{text}\n{SHIPPED}"));
    let count = set.len();
    if BREACHED.set(set).is_err() {
        tracing::warn!("breached password set was already fixed; the file was not applied");
    }
    Ok(count)
}

fn active() -> &'static BreachedSet {
    BREACHED.get_or_init(|| BreachedSet::parse(SHIPPED))
}

/// Whether `password` is a known breached password.
pub fn is_breached(password: &str) -> bool {
    active().contains(password)
}

/// Whether `password` is the user's current password or one of the
/// [`HISTORY_DEPTH`] before it. Each comparison is a full KDF verify, run off
/// the async threads by [`crate::password::verify_password_async`].
pub async fn reused(
    db: &attome_db::DbPool,
    user_id: Uuid,
    password: &str,
) -> Result<bool, AppError> {
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT password_hash FROM user_account WHERE id = $1 AND password_hash IS NOT NULL \
         UNION ALL \
         (SELECT password_hash FROM password_history WHERE user_id = $1 \
          ORDER BY created_at DESC LIMIT $2)",
    )
    .bind(user_id)
    .bind(HISTORY_DEPTH)
    .fetch_all(db)
    .await
    .map_err(attome_db::classify)?;
    for hash in &hashes {
        if crate::password::verify_password_async(password, hash).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Keeps `old_hash` as the user's newest earlier password and drops any
/// beyond [`HISTORY_DEPTH`], in the caller's transaction.
pub async fn remember(
    conn: &mut PgConnection,
    user_id: Uuid,
    old_hash: &str,
) -> Result<(), AppError> {
    sqlx::query("INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(old_hash)
        .execute(&mut *conn)
        .await
        .map_err(attome_db::classify)?;
    sqlx::query(
        "DELETE FROM password_history WHERE user_id = $1 AND id NOT IN \
         (SELECT id FROM password_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2)",
    )
    .bind(user_id)
    .bind(HISTORY_DEPTH)
    .execute(&mut *conn)
    .await
    .map_err(attome_db::classify)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_policy_refuses_a_shipped_breached_password() {
        assert!(is_breached("password1234"));
        assert!(is_breached("qwerty123456"));
        assert!(!is_breached("violet-harbour-kettle-93"));
    }

    #[test]
    fn password_policy_reads_hibp_lines_and_skips_noise() {
        let set = BreachedSet::parse(
            "# comment\n\
             E6B6AFBD6D76BB5D2041542D7D2E3FAC5BB05593:12345\n\
             e6b6afbd6d76bb5d2041542d7d2e3fac5bb05593\n\
             not-a-hash\n\
             \n",
        );
        assert_eq!(set.len(), 1);
        assert!(set.contains("password1234"));
        assert!(!set.contains("password12345"));
    }

    #[test]
    fn password_policy_shipped_list_parses_whole() {
        let lines = SHIPPED
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .count();
        assert_eq!(BreachedSet::parse(SHIPPED).len(), lines);
    }
}
