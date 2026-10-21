//! AI6: meeting briefs before a meeting and notes after it, on the
//! `ai_meeting_brief` and `ai_meeting_notes` entities (platform bundle
//! `attome-ai-meeting`). A meeting is an `activity` whose `activity_type` is
//! `meeting`; it points at the record it is about through `entity_name` and
//! `record_id`.

pub mod brief;
pub mod run;
