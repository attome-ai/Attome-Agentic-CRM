//! AD6: the building agent's skills. Each reads through the N12 build tools'
//! own paths and changes no metadata; the documentation job writes only its
//! own table.

/// AD6-T2: documentation for every published metadata version.
pub mod docs;
/// AD1-T1: reuse, extend, ask or create for each drafted entity.
pub mod entities;
pub mod explain;
/// AD2-T1: a drafted form by names, as a form document by ids.
pub mod forms;
/// A1-T13 (part): spreadsheet column types for a drafted model.
pub mod infer;
/// A1-T13 (part): findings on a drafted model.
pub mod review;
