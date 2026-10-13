//! Language handling for the search index.
//!
//! Everything here runs at **both** index time and query time, from the same
//! code. That symmetry is the whole contract: a normalization or stemming step
//! applied on one side only degrades matching silently and progressively, with
//! no error to notice and no way for a user to tell a broken search from an
//! empty result set.

pub mod arabic;
pub mod stem;

pub use arabic::normalize_ar;
pub use stem::{stem_ar, stem_en};
