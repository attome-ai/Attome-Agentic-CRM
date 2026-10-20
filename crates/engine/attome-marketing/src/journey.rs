//! Journeys (roadmap E8): a journey is a workflow of kind `journey`
//! (migration 0168) with its settings in a `marketing_journey` record,
//! keyed by the workflow's logical name. [`enrol`] puts people in;
//! [`guard::JourneyGuard`] checks the exit and goal conditions before every
//! node of a journey's run.

pub mod action_step;
pub mod control_step;
pub mod enrol;
pub mod entry;
pub mod guard;

pub use enrol::{EnrolOutcome, PersonRef, enrol};
