//! `attome-sdk`: the stable SDK that every engine and pack is written against,
//! Attome's own built-in modules included (see `docs/architecture.md`). It follows semantic
//! versioning: internal crates may change freely, this crate cannot break
//! without a major version.
//!
//! The API arrives with the first engines; today the crate only states its
//! version, so packs can check what they were built against.

/// The SDK version this build carries.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_the_package_version() {
        assert_eq!(SDK_VERSION, env!("CARGO_PKG_VERSION"));
        assert!(!SDK_VERSION.is_empty());
    }
}
