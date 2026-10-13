//! P-data-protection-governance §4 "Cross-border transfer gate" — one
//! reusable, pure decision function called explicitly from every export path
//! that can move data outside the deployment's own storage boundary (D-177's
//! `execute_partition_archive`, this plan's DSR access/portability export,
//! and any future eDiscovery export). Deliberately not a middleware layer:
//! the set of "exports" is small, named, and already admin-gated, so a
//! generic interceptor would be over-engineering for this surface (plan §4's
//! own "rejected alternative" reasoning applies here too).
//!
//! Named `transfer_gate` rather than the plan sketch's literal
//! `data_classification::assert_transfer_allowed` module path — kept as its
//! own module instead of folded into `meta_registry` (which owns
//! [`crate::DataClassification`] for attribute-metadata reasons) so this
//! pure policy function stays independently testable and doesn't bloat that
//! file's already-large surface. Same function name and signature shape the
//! plan describes.

use crate::DataClassification;

/// The outcome of checking one export against its data's classification and
/// the transfer's source/destination regions. Never a bare `bool` — the
/// `AllowedWithOverride` case must be distinguishable from ordinary
/// `Allowed` so a call site can log/audit the override instead of silently
/// treating it as routine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDecision {
    /// Either the data carries no transfer restriction (`General`), or the
    /// destination matches the deployment's declared region — proceeds with
    /// no special handling.
    Allowed,
    /// Restricted data (`Personal`/`SensitiveSpecialCategory`) leaving the
    /// deployment's declared region, but the caller passed
    /// `admin_override: true` — the export may proceed, but the call site
    /// MUST log/audit this explicitly (e.g. an `AuditOperation` event naming
    /// the override) rather than treating it identically to `Allowed`.
    AllowedWithOverride,
    /// Restricted data leaving the deployment's declared region with no
    /// override — the caller must refuse the export outright.
    Blocked,
}

/// Pure decision table, no I/O: `classification` is the (worst-case, if the
/// export spans multiple fields/records) `DataClassification` of the data
/// being exported; `destination_region`/`deployment_region` are plain region
/// strings (e.g. `"bh-1"`, `"eu-west-1"`) compared case-insensitively —
/// this function does not validate that either string is a real region
/// (that's the caller's config's job, e.g.
/// `AppConfig::validate`'s `deployment.data_region` check).
///
/// `General` data is never restricted, matching `is_sensitive`'s existing
/// narrower precedent of not gating unclassified fields. `Personal` and
/// `SensitiveSpecialCategory` are treated identically here — both regimes
/// named in this plan (Bahrain PDPL/GCC PDPLs/GDPR) restrict cross-border
/// transfer of personal data generally, not only its "special category"
/// subset, so there is no policy reason to let personal data cross a border
/// more freely than sensitive data at this layer; a future customer-specific
/// carve-out would extend this match arm, not the caller.
pub fn assert_transfer_allowed(
    classification: DataClassification,
    destination_region: &str,
    deployment_region: &str,
    admin_override: bool,
) -> TransferDecision {
    let restricted = matches!(
        classification,
        DataClassification::Personal | DataClassification::SensitiveSpecialCategory
    );
    if !restricted || destination_region.eq_ignore_ascii_case(deployment_region) {
        return TransferDecision::Allowed;
    }
    if admin_override {
        TransferDecision::AllowedWithOverride
    } else {
        TransferDecision::Blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn general_data_is_always_allowed_regardless_of_region() {
        assert_eq!(
            assert_transfer_allowed(DataClassification::General, "us-east-1", "bh-1", false),
            TransferDecision::Allowed
        );
    }

    #[test]
    fn restricted_data_in_region_is_allowed() {
        assert_eq!(
            assert_transfer_allowed(DataClassification::Personal, "bh-1", "bh-1", false),
            TransferDecision::Allowed
        );
        assert_eq!(
            assert_transfer_allowed(
                DataClassification::SensitiveSpecialCategory,
                "BH-1",
                "bh-1",
                false
            ),
            TransferDecision::Allowed,
            "region comparison must be case-insensitive"
        );
    }

    #[test]
    fn restricted_data_out_of_region_without_override_is_blocked() {
        assert_eq!(
            assert_transfer_allowed(DataClassification::Personal, "us-east-1", "bh-1", false),
            TransferDecision::Blocked
        );
        assert_eq!(
            assert_transfer_allowed(
                DataClassification::SensitiveSpecialCategory,
                "us-east-1",
                "eu-west-1",
                false
            ),
            TransferDecision::Blocked
        );
    }

    #[test]
    fn restricted_data_out_of_region_with_override_is_allowed_but_flagged() {
        assert_eq!(
            assert_transfer_allowed(DataClassification::Personal, "us-east-1", "bh-1", true),
            TransferDecision::AllowedWithOverride
        );
    }
}
