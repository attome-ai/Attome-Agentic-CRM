//! Talk patterns (roadmap D22-T3): pure arithmetic over a call's speaker
//! segments, the shape the N22 transcript produces. No I/O.
//!
//! Adjacent segments of one speaker are merged before monologues are
//! measured, so a pause inside one person's turn does not split it. An
//! interruption is a segment that starts before the other speaker's previous
//! segment has ended. A question is a run of `?` or the Arabic question mark
//! (U+061F) inside a segment's text.

use serde::{Deserialize, Serialize};

/// Who is speaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Speaker {
    Staff,
    Customer,
}

impl Speaker {
    fn other(self) -> Self {
        match self {
            Self::Staff => Self::Customer,
            Self::Customer => Self::Staff,
        }
    }
}

/// One stretch of speech.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Segment {
    pub speaker: Speaker,
    pub start_ms: u64,
    pub end_ms: u64,
    pub text: String,
}

impl Segment {
    fn duration_ms(&self) -> u64 {
        self.end_ms.saturating_sub(self.start_ms)
    }
}

/// The patterns of one call.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TalkPatterns {
    /// Share of all talk time spoken by staff, 0 to 1.
    pub staff_talk_share: f64,
    /// Share of all talk time spoken by the customer, 0 to 1.
    pub customer_talk_share: f64,
    /// Longest uninterrupted staff turn, in seconds.
    pub longest_monologue_s: f64,
    /// Longest uninterrupted customer turn, in seconds.
    pub customer_longest_story_s: f64,
    pub interruptions: u32,
    pub staff_questions: u32,
    pub customer_questions: u32,
    pub staff_words_per_minute: f64,
}

/// Computes the talk patterns of `segments`, in any order.
pub fn talk_patterns(segments: &[Segment]) -> TalkPatterns {
    let mut ordered: Vec<&Segment> = segments.iter().collect();
    ordered.sort_by_key(|s| (s.start_ms, s.end_ms));

    let mut staff_ms = 0u64;
    let mut customer_ms = 0u64;
    let mut staff_words = 0u64;
    let mut staff_questions = 0u32;
    let mut customer_questions = 0u32;
    for s in &ordered {
        let questions = count_questions(&s.text);
        match s.speaker {
            Speaker::Staff => {
                staff_ms += s.duration_ms();
                staff_words += s.text.split_whitespace().count() as u64;
                staff_questions += questions;
            }
            Speaker::Customer => {
                customer_ms += s.duration_ms();
                customer_questions += questions;
            }
        }
    }

    let total_ms = staff_ms + customer_ms;
    let (staff_talk_share, customer_talk_share) = if total_ms == 0 {
        (0.0, 0.0)
    } else {
        (
            staff_ms as f64 / total_ms as f64,
            customer_ms as f64 / total_ms as f64,
        )
    };
    let staff_words_per_minute = if staff_ms == 0 {
        0.0
    } else {
        staff_words as f64 / (staff_ms as f64 / 60_000.0)
    };

    TalkPatterns {
        staff_talk_share,
        customer_talk_share,
        longest_monologue_s: longest_turn_ms(&ordered, Speaker::Staff) as f64 / 1000.0,
        customer_longest_story_s: longest_turn_ms(&ordered, Speaker::Customer) as f64 / 1000.0,
        interruptions: interruptions(&ordered),
        staff_questions,
        customer_questions,
        staff_words_per_minute,
    }
}

/// Runs of `?` or `؟`: "Really??" is one question.
fn count_questions(text: &str) -> u32 {
    let mut count = 0;
    let mut in_run = false;
    for c in text.chars() {
        let is_mark = c == '?' || c == '\u{061F}';
        if is_mark && !in_run {
            count += 1;
        }
        in_run = is_mark;
    }
    count
}

/// The longest turn of `speaker`, merging that speaker's consecutive
/// segments (in start order) into one turn.
fn longest_turn_ms(ordered: &[&Segment], speaker: Speaker) -> u64 {
    let mut longest = 0u64;
    let mut turn: Option<(u64, u64)> = None;
    for s in ordered {
        if s.speaker == speaker {
            turn = Some(match turn {
                Some((start, end)) => (start, end.max(s.end_ms)),
                None => (s.start_ms, s.end_ms),
            });
        } else if let Some((start, end)) = turn.take() {
            longest = longest.max(end.saturating_sub(start));
        }
    }
    if let Some((start, end)) = turn {
        longest = longest.max(end.saturating_sub(start));
    }
    longest
}

/// Segments that start before the other speaker's latest segment ended.
fn interruptions(ordered: &[&Segment]) -> u32 {
    let mut last_end_staff: Option<u64> = None;
    let mut last_end_customer: Option<u64> = None;
    let mut count = 0;
    for s in ordered {
        let other_end = match s.speaker.other() {
            Speaker::Staff => last_end_staff,
            Speaker::Customer => last_end_customer,
        };
        if other_end.is_some_and(|end| s.start_ms < end) {
            count += 1;
        }
        let own = match s.speaker {
            Speaker::Staff => &mut last_end_staff,
            Speaker::Customer => &mut last_end_customer,
        };
        *own = Some(own.map_or(s.end_ms, |end| end.max(s.end_ms)));
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(speaker: Speaker, start_ms: u64, end_ms: u64, text: &str) -> Segment {
        Segment {
            speaker,
            start_ms,
            end_ms,
            text: text.to_owned(),
        }
    }

    #[test]
    fn talk_share_sums_to_one() {
        let p = talk_patterns(&[
            seg(Speaker::Staff, 0, 30_000, "hello there"),
            seg(Speaker::Customer, 30_000, 40_000, "hi"),
            seg(Speaker::Staff, 40_000, 50_000, "so"),
        ]);
        assert!((p.staff_talk_share + p.customer_talk_share - 1.0).abs() < 1e-9);
        assert!((p.staff_talk_share - 0.8).abs() < 1e-9);
    }

    #[test]
    fn arabic_question_mark_counts() {
        let p = talk_patterns(&[
            seg(Speaker::Staff, 0, 1_000, "كيف حالك؟ هل الوقت مناسب؟"),
            seg(Speaker::Customer, 1_000, 2_000, "Really?? yes. And you?"),
        ]);
        assert_eq!(p.staff_questions, 2);
        assert_eq!(p.customer_questions, 2);
    }

    #[test]
    fn overlap_counts_as_interruption() {
        let p = talk_patterns(&[
            seg(Speaker::Staff, 0, 10_000, "let me explain the plan"),
            seg(Speaker::Customer, 8_000, 12_000, "wait"),
            seg(Speaker::Staff, 12_000, 13_000, "sure"),
        ]);
        assert_eq!(p.interruptions, 1);
    }

    #[test]
    fn adjacent_segments_of_one_speaker_form_one_turn() {
        let p = talk_patterns(&[
            seg(Speaker::Staff, 0, 10_000, "one"),
            seg(Speaker::Staff, 11_000, 20_000, "two"),
            seg(Speaker::Customer, 20_000, 25_000, "ok"),
        ]);
        assert!((p.longest_monologue_s - 20.0).abs() < 1e-9);
        assert!((p.customer_longest_story_s - 5.0).abs() < 1e-9);
    }

    #[test]
    fn words_per_minute_uses_staff_talk_time() {
        let p = talk_patterns(&[seg(Speaker::Staff, 0, 30_000, "a b c d e f g h i j")]);
        assert!((p.staff_words_per_minute - 20.0).abs() < 1e-9);
    }

    #[test]
    fn an_empty_call_is_all_zero() {
        let p = talk_patterns(&[]);
        assert_eq!(p.interruptions, 0);
        assert_eq!(p.staff_talk_share, 0.0);
        assert_eq!(p.staff_words_per_minute, 0.0);
    }
}
