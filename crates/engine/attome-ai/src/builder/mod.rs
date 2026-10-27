//! AD6: the building agent's skills. Each reads through the N12 build tools'
//! own paths and changes no metadata; the documentation job writes only its
//! own table.

/// AD6-T2: documentation for every published metadata version.
pub mod docs;
pub mod explain;
/// A1-T13 (part): spreadsheet column types for a drafted model.
pub mod infer;
/// A1-T13 (part): findings on a drafted model.
pub mod review;
