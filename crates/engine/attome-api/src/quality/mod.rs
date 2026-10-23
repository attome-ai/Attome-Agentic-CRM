//! L2-T2: data quality, second version. [`dimensions`] holds the six
//! dimensions and their weighting, pure; the daily sweep
//! (`crate::quality_score`) measures them.

/// L2-T7: alerts to the stewards after the daily snapshot.
pub mod alerts;
pub mod dimensions;
/// L2-T3: scoring as records change, and the resumable rescan.
pub mod incremental;
