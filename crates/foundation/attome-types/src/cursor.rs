//! Z14-T5: keyset cursors a client cannot forge.
//!
//! A route builds its own cursor text (sort keys plus id, in whatever form
//! it decodes) and [`crate::CursorPage`] serializes it sealed, as
//! `<payload>.<tag>`: the payload is the text in base64url, the tag
//! HMAC-SHA256 over the payload, in base64url. A route reads an incoming
//! cursor through [`open`], which checks the tag in constant time and
//! answers `400 invalid_cursor` (`AppError::InvalidCursor`) for anything a
//! server did not issue.
//!
//! The key is derived from the deployment's `auth.jwt_secret` ring, so every
//! node of a deployment issues and accepts the same cursors: `AppState::new`
//! installs it ([`install_keys`]). New cursors are signed with the active
//! key; a key still in the ring keeps verifying, so a rotation does not
//! break a client mid-way through a listing. A process that never installs
//! a key (a unit test) signs with a random one of its own.

use std::sync::OnceLock;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::AppError;

type HmacSha256 = Hmac<Sha256>;

/// What a deployment secret is bound to before it signs a cursor, so the
/// cursor key is never the secret itself.
const DERIVE_LABEL: &[u8] = b"attome/keyset-cursor/v1";

/// The longest cursor accepted, sealed (a cursor is a few sort keys).
pub const MAX_SEALED_LEN: usize = 4_096;

struct CursorKeys {
    /// Signs new cursors.
    active: [u8; 32],
    /// Verify: the active key first, then every other key in the ring.
    verify: Vec<[u8; 32]>,
}

static KEYS: OnceLock<CursorKeys> = OnceLock::new();

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn derive(secret: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC takes a key of any length");
    mac.update(DERIVE_LABEL);
    mac.finalize().into_bytes().into()
}

/// Installs the deployment's cursor keys from its secret ring: `active`
/// signs, `all` (the active one included or not) verifies. The first call
/// wins; later calls are ignored. Without an active secret nothing is
/// installed and the process keeps its own random key.
pub fn install_keys<'a>(active: Option<&'a [u8]>, all: impl IntoIterator<Item = &'a [u8]>) {
    let Some(active) = active.filter(|s| !s.is_empty()) else {
        return;
    };
    let active = derive(active);
    let mut verify = vec![active];
    for secret in all.into_iter().filter(|s| !s.is_empty()) {
        let key = derive(secret);
        if !verify.contains(&key) {
            verify.push(key);
        }
    }
    let _ = KEYS.set(CursorKeys { active, verify });
}

fn keys() -> &'static CursorKeys {
    KEYS.get_or_init(|| {
        // No deployment key: a random one, good for this process only.
        let mut active = [0u8; 32];
        active[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        active[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        CursorKeys {
            active,
            verify: vec![active],
        }
    })
}

#[expect(clippy::expect_used, reason = "HMAC accepts a key of any length")]
fn tag(key: &[u8; 32], payload: &str) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(payload.as_bytes());
    mac
}

/// Seals a route's cursor text for a client.
pub fn seal(raw: &str) -> String {
    let payload = B64URL.encode(raw.as_bytes());
    let signature = tag(&keys().active, &payload).finalize().into_bytes();
    format!("{payload}.{}", B64URL.encode(signature))
}

/// The cursor text a sealed cursor carries, or `InvalidCursor` when the
/// server did not issue it (bad shape, bad encoding, bad signature).
pub fn open(sealed: &str) -> Result<String, AppError> {
    if sealed.len() > MAX_SEALED_LEN {
        return Err(AppError::InvalidCursor);
    }
    let (payload, signature) = sealed.split_once('.').ok_or(AppError::InvalidCursor)?;
    let signature = B64URL
        .decode(signature)
        .map_err(|_| AppError::InvalidCursor)?;
    let signed = keys()
        .verify
        .iter()
        .any(|key| tag(key, payload).verify_slice(&signature).is_ok());
    if !signed {
        return Err(AppError::InvalidCursor);
    }
    let raw = B64URL
        .decode(payload)
        .map_err(|_| AppError::InvalidCursor)?;
    String::from_utf8(raw).map_err(|_| AppError::InvalidCursor)
}

/// [`open`] over an optional cursor parameter; an absent or blank one is
/// no cursor (the first page).
pub fn open_opt(sealed: Option<&str>) -> Result<Option<String>, AppError> {
    sealed
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(open)
        .transpose()
}

/// [`open_opt`] for a route whose cursor is a row id.
pub fn open_uuid(sealed: Option<&str>) -> Result<Option<uuid::Uuid>, AppError> {
    open_opt(sealed)?
        .map(|raw| uuid::Uuid::parse_str(&raw).map_err(|_| AppError::InvalidCursor))
        .transpose()
}

/// `CursorPage::next_cursor`'s serializer: the cursor leaves sealed, while
/// code in the process keeps reading the route's own text.
pub(crate) fn serialize_sealed<S: serde::Serializer>(
    raw: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match raw {
        Some(raw) => serializer.serialize_some(&seal(raw)),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "test assertions")]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips_through_seal_and_open() {
        let raw = "1700000000123456|note|0190a7e2-8a8c-7e43-9a49-2b1d3f6c9d10";
        let sealed = seal(raw);
        assert!(!sealed.contains(raw), "the payload is encoded");
        assert_eq!(open(&sealed).unwrap(), raw);
        assert_eq!(open_opt(None).unwrap(), None);
        assert_eq!(open_opt(Some("  ")).unwrap(), None);
        let id = uuid::Uuid::now_v7();
        assert_eq!(open_uuid(Some(&seal(&id.to_string()))).unwrap(), Some(id));
        assert!(matches!(
            open_uuid(Some(&seal("not an id"))),
            Err(AppError::InvalidCursor)
        ));
        // A bare id, as cursors were before they were signed, is refused.
        assert!(matches!(
            open_uuid(Some(&id.to_string())),
            Err(AppError::InvalidCursor)
        ));
    }

    #[test]
    fn cursor_page_serializes_its_next_cursor_sealed() {
        let page = crate::CursorPage::new(vec![1], Some("raw-cursor".to_owned()));
        assert_eq!(page.next_cursor.as_deref(), Some("raw-cursor"));
        let json = serde_json::to_value(&page).unwrap();
        let sent = json["next_cursor"].as_str().unwrap();
        assert_ne!(sent, "raw-cursor");
        assert_eq!(open(sent).unwrap(), "raw-cursor");
        let last = serde_json::to_value(crate::CursorPage::<i32>::new(vec![], None)).unwrap();
        assert!(last.get("next_cursor").is_none());
    }

    #[test]
    fn cursor_forged_or_altered_is_rejected() {
        let sealed = seal("42|abc");
        let (payload, signature) = sealed.split_once('.').unwrap();
        // A client's own cursor text, unsigned or with a made-up tag.
        let forged_payload = B64URL.encode(b"41|abc");
        for bad in [
            "42|abc".to_owned(),
            forged_payload.clone(),
            format!("{forged_payload}.{signature}"),
            format!("{payload}.{}", B64URL.encode([0u8; 32])),
            format!("{payload}."),
            format!("{payload}.!!"),
            String::new(),
            "x".repeat(MAX_SEALED_LEN + 1),
        ] {
            assert!(
                matches!(open(&bad), Err(AppError::InvalidCursor)),
                "{bad} was accepted"
            );
        }
    }

    #[test]
    fn cursor_key_is_derived_never_the_secret() {
        let secret = b"a deployment secret";
        assert_ne!(&derive(secret)[..secret.len().min(32)], &secret[..]);
        assert_eq!(derive(secret), derive(secret));
        assert_ne!(derive(secret), derive(b"another secret"));
    }
}
