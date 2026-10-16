//! Relationship strength (roadmap O7-T1), pure: how well a user knows a
//! contact, from their interactions. Each interaction counts by kind (a
//! meeting more than an email) and fades with a half-life, so recent
//! contact matters more than old; a relationship where both sides reach out
//! scores higher than one where only the user does, since replies are what
//! make it two-way.
//!
//! The score is 0 to 100: the decayed weight passed through a saturating
//! curve, times a reciprocity factor between 0.5 (one-way) and 1.

use chrono::{DateTime, Utc};
use serde::Serialize;

/// Days for an interaction's weight to halve.
pub const HALF_LIFE_DAYS: f64 = 45.0;

/// The decayed weight at which the score reaches about 63.
pub const SATURATION: f64 = 10.0;

/// What kind of contact it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Email,
    Call,
    Meeting,
    Message,
}

impl Kind {
    pub fn weight(self) -> f64 {
        match self {
            Self::Email | Self::Message => 1.0,
            Self::Call => 2.0,
            Self::Meeting => 3.0,
        }
    }

    /// Reads an activity type or communication channel.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "email" => Some(Self::Email),
            "phone_call" | "call" => Some(Self::Call),
            "meeting" | "visit" => Some(Self::Meeting),
            "sms" | "whatsapp" | "chat" | "message" => Some(Self::Message),
            _ => None,
        }
    }
}

/// One interaction between the user and the contact.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Interaction {
    pub at: DateTime<Utc>,
    pub kind: Kind,
    /// The contact started it (an inbound email, a call they made).
    pub from_contact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Strength {
    /// 0 to 100.
    pub score: f64,
    pub last_interaction: Option<DateTime<Utc>>,
    pub interactions: usize,
    /// Share of the decayed weight the contact started, 0 to 1.
    pub reciprocity: f64,
}

/// Scores the interactions at `now`.
pub fn strength(interactions: &[Interaction], now: DateTime<Utc>) -> Strength {
    let mut total = 0.0;
    let mut inbound = 0.0;
    for i in interactions {
        let days = (now - i.at).num_seconds().max(0) as f64 / 86_400.0;
        let w = i.kind.weight() * 0.5f64.powf(days / HALF_LIFE_DAYS);
        total += w;
        if i.from_contact {
            inbound += w;
        }
    }
    let reciprocity = if total > 0.0 { inbound / total } else { 0.0 };
    // Fully two-way at an even split; one-way halves the score.
    let balance = 0.5 + (2.0 * reciprocity).min(1.0) * 0.5;
    let level = 1.0 - (-total / SATURATION).exp();
    Strength {
        score: ((level * balance * 100.0) * 10.0).round() / 10.0,
        last_interaction: interactions.iter().map(|i| i.at).max(),
        interactions: interactions.len(),
        reciprocity: (reciprocity * 100.0).round() / 100.0,
    }
}

#[cfg(test)]
mod relationship_strength {
    use super::*;
    use chrono::{Duration, TimeZone};

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0)
            .single()
            .unwrap_or_default()
    }

    fn many(days_ago: i64, count: usize, from_contact_every: usize) -> Vec<Interaction> {
        (0..count)
            .map(|i| Interaction {
                at: now() - Duration::days(days_ago + i as i64),
                kind: Kind::Email,
                from_contact: from_contact_every > 0 && i % from_contact_every == 0,
            })
            .collect()
    }

    #[test]
    fn recent_two_way_contact_is_strong() {
        let recent = strength(&many(1, 20, 2), now());
        let old = strength(&many(200, 20, 2), now());
        assert!(recent.score > 70.0, "{}", recent.score);
        assert!(
            old.score < recent.score / 3.0,
            "{} vs {}",
            old.score,
            recent.score
        );
    }

    #[test]
    fn one_way_contact_counts_half() {
        let two_way = strength(&many(1, 20, 2), now());
        let one_way = strength(&many(1, 20, 0), now());
        assert_eq!(one_way.reciprocity, 0.0);
        assert!((one_way.score - two_way.score / 2.0).abs() < 1.0);
    }

    #[test]
    fn meetings_weigh_more_and_nothing_scores_zero() {
        let email = strength(&many(1, 1, 1), now());
        let meeting = strength(
            &[Interaction {
                at: now() - Duration::days(1),
                kind: Kind::Meeting,
                from_contact: true,
            }],
            now(),
        );
        assert!(meeting.score > email.score);
        assert_eq!(strength(&[], now()).score, 0.0);
        assert_eq!(Kind::parse("visit"), Some(Kind::Meeting));
    }
}
