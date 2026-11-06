//! AD6: the building agent's skills. Each reads through the N12 build tools'
//! own paths and changes no metadata; the documentation job writes only its
//! own table.

/// AD9-T1: a hook extension and its tests from a description, as files.
pub mod code;
/// AD6-T2: documentation for every published metadata version.
pub mod docs;
/// AD1-T1: reuse, extend, ask or create for each drafted entity.
pub mod entities;
pub mod explain;
/// AD2-T1: a drafted form by names, as a form document by ids.
pub mod forms;
/// AD5-T1: a model from several uploaded sheets, with lookups and the import.
pub mod from_files;
/// AD11-T1: a source CRM's model as a draft, and what cannot move.
pub mod import_config;
/// A1-T13 (part): spreadsheet column types for a drafted model.
pub mod infer;
/// A1-T13 (part): findings on a drafted model.
pub mod review;
/// AD10-T1: the builder suite's graders on a drafted model.
pub mod suite;
