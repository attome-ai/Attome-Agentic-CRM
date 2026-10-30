//! AB8-T1: the public keys this binary trusts to sign a release manifest
//! (`attome_ops::release_manifest::verify_manifest`). Two slots, current
//! and next, so the release key can rotate: a release signed with the next
//! key is accepted by binaries that already carry it.
//!
//! These are placeholders whose private halves were never kept, so nothing
//! verifies against them until the release process (`/release-and-deploy`)
//! puts the real release keys here.

/// Base64 Ed25519 public keys: the current release key, then the next.
pub const RELEASE_PUBLIC_KEYS: &[&str] = &[
    "UfxiT6hhASd3Ndn1TfCUBtBGNsiaFU2qFssf2DtWKd8=",
    "kD57wAmaqFXQxvFGpRsGlUOSQ+rGCHHZcfKjncsgRlk=",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_slot_holds_a_valid_key() {
        assert_eq!(RELEASE_PUBLIC_KEYS.len(), 2, "current and next");
        for key in RELEASE_PUBLIC_KEYS {
            assert!(
                attome_ops::evidence::verifying_key(key).is_ok(),
                "{key} is not an Ed25519 public key"
            );
        }
    }
}
