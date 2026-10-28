//! Q5-T6: a risky password sign-in asks for the second factor again, even on
//! a remembered browser (Q5-T4). Risky is any of:
//!
//! - **a new device**: no sign-in in the last 90 days from the same browser
//!   family (browser and operating system, [`device_family`]);
//! - **a new country**: no sign-in in the last 90 days from the country the
//!   address is in, by the offline database `auth.geoip_database` names
//!   (none configured: the country is not checked);
//! - **recent failures**: three or more wrong passwords in a row just before
//!   (the account's back-off streak, Q20-T2).
//!
//! What was seen is kept in `sign_in_seen` (migration 0326): one row per
//! person, kind and value with the last time, never the address itself. A
//! person with no row at all has no history to compare with and is not
//! flagged, so turning this on does not ask everyone again at once.

use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// How far back a device or country still counts as known.
pub const KNOWN_FOR_DAYS: i32 = 90;
/// Wrong passwords in a row that make a sign-in risky.
pub const RECENT_FAILURES: u32 = 3;

/// Why a sign-in is risky; all `false` is not risky.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Risk {
    pub new_device: bool,
    pub new_country: bool,
    pub recent_failures: bool,
}

impl Risk {
    pub fn any(self) -> bool {
        self.new_device || self.new_country || self.recent_failures
    }

    /// The reasons, for a log line.
    pub fn reasons(self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.new_device {
            out.push("new_device");
        }
        if self.new_country {
            out.push("new_country");
        }
        if self.recent_failures {
            out.push("recent_failures");
        }
        out
    }
}

/// The browser family and operating system of a `User-Agent`, such as
/// `chrome/windows`; version numbers are left out, so an update is not a new
/// device. Pure.
pub fn device_family(user_agent: &str) -> String {
    let ua = user_agent.to_ascii_lowercase();
    let browser = if ua.contains("edg/") || ua.contains("edge/") {
        "edge"
    } else if ua.contains("opr/") || ua.contains("opera") {
        "opera"
    } else if ua.contains("firefox/") || ua.contains("fxios/") {
        "firefox"
    } else if ua.contains("chrome/") || ua.contains("crios/") || ua.contains("chromium/") {
        "chrome"
    } else if ua.contains("safari/") {
        "safari"
    } else if ua.trim().is_empty() {
        "none"
    } else {
        "other"
    };
    let os = if ua.contains("windows") {
        "windows"
    } else if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios") {
        "ios"
    } else if ua.contains("android") {
        "android"
    } else if ua.contains("mac os") || ua.contains("macintosh") {
        "macos"
    } else if ua.contains("linux") || ua.contains("x11") {
        "linux"
    } else {
        "other"
    };
    format!("{browser}/{os}")
}

/// What is known about a person's past sign-ins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    /// Any row at all.
    pub any: bool,
    pub device_known: bool,
    /// `None` when the sign-in's country is unknown.
    pub country_known: Option<bool>,
}

/// The risk of a sign-in from what is known. Pure.
pub fn judge(history: &History, failures_in_a_row: u32) -> Risk {
    Risk {
        new_device: history.any && !history.device_known,
        new_country: history.any && history.country_known == Some(false),
        recent_failures: failures_in_a_row >= RECENT_FAILURES,
    }
}

/// The risk of `user_id` signing in now from `device` (a [`device_family`])
/// and `country` (ISO code, when known), after `failures_in_a_row` wrong
/// passwords.
pub async fn assess(
    db: &DbPool,
    user_id: Uuid,
    device: &str,
    country: Option<&str>,
    failures_in_a_row: u32,
) -> Result<Risk, AppError> {
    let (any, device_known, country_known): (bool, bool, bool) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM sign_in_seen WHERE user_ref = $1), \
                EXISTS (SELECT 1 FROM sign_in_seen WHERE user_ref = $1 AND kind = 'device' \
                         AND value = $2 AND last_seen_at > now() - make_interval(days => $4)), \
                EXISTS (SELECT 1 FROM sign_in_seen WHERE user_ref = $1 AND kind = 'country' \
                         AND value = $3 AND last_seen_at > now() - make_interval(days => $4))",
    )
    .bind(user_id)
    .bind(device)
    .bind(country.unwrap_or_default())
    .bind(KNOWN_FOR_DAYS)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;
    Ok(judge(
        &History {
            any,
            device_known,
            country_known: country.map(|_| country_known),
        },
        failures_in_a_row,
    ))
}

/// Records a completed sign-in's device and country (when known).
pub async fn remember(
    db: &DbPool,
    user_id: Uuid,
    device: &str,
    country: Option<&str>,
) -> Result<(), AppError> {
    let mut kinds = vec!["device".to_owned()];
    let mut values = vec![device.to_owned()];
    if let Some(country) = country {
        kinds.push("country".to_owned());
        values.push(country.to_owned());
    }
    sqlx::query(
        "INSERT INTO sign_in_seen (user_ref, kind, value) \
         SELECT $1, k, v FROM unnest($2::text[], $3::text[]) AS s(k, v) \
         ON CONFLICT (user_ref, kind, value) DO UPDATE SET last_seen_at = now()",
    )
    .bind(user_id)
    .bind(&kinds)
    .bind(&values)
    .execute(db)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_country_is_flagged() {
        let history = History {
            any: true,
            device_known: true,
            country_known: Some(false),
        };
        let risk = judge(&history, 0);
        assert!(risk.new_country && !risk.new_device && risk.any());
        // No country database: the country is not judged.
        let unknown = History {
            country_known: None,
            ..history
        };
        assert!(!judge(&unknown, 0).any());
    }

    #[test]
    fn known_device_and_country_is_not_flagged() {
        let history = History {
            any: true,
            device_known: true,
            country_known: Some(true),
        };
        assert!(!judge(&history, 2).any());
        assert!(judge(&history, 3).recent_failures, "three wrong passwords");
        assert!(
            !judge(&History::default(), 0).any(),
            "no history at all is not judged"
        );
    }

    #[test]
    fn device_family_ignores_versions() {
        let a = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/130.0.0.0 Safari/537.36";
        let b = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/131.0.0.0 Safari/537.36";
        assert_eq!(device_family(a), "chrome/windows");
        assert_eq!(device_family(a), device_family(b));
        let edge =
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/130.0 Safari/537.36 Edg/130.0";
        assert_eq!(device_family(edge), "edge/windows");
        let iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 \
                      Version/17.0 Mobile/15E148 Safari/604.1";
        assert_eq!(device_family(iphone), "safari/ios");
    }
}
