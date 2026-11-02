//! D22 call analysis: transcripts, talk ratios, topics and coaching notes.

/// D22-T7: tasks from findings, confirmed scores and comments.
pub mod coach;
/// D22-T6: questions, objections, next steps, price mentions and scorecard proposals.
pub mod extract;
/// D22-T5: one analysis per finished transcript, over its redacted copy.
pub mod job;
/// D22-T8: the call page and coaching routes.
pub mod routes;
/// D22-T11: the analysis-done event and competitors as trackers.
pub mod signals;
pub mod talk;
pub mod trackers;
/// D22-T9: nightly trend aggregates.
pub mod trends;
