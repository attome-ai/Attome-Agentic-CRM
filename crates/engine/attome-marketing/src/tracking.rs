//! E14 website tracking: page visits, identification, company lookup,
//! custom events and return-visit alerts. Every part sits behind its own
//! feature flag, off by default (`marketing.tracking*`).

pub mod bots;
pub mod collect;
/// E14-T7: a visitor identified as a lead or contact.
pub mod identify;
/// E14-T8: one visit summary per closed, identified session.
pub mod summary;
pub mod writer;

/// The flags that switch tracking on, in dependency order.
pub const TRACKING_FLAGS: &[&str] = &[
    "marketing.tracking",
    "marketing.tracking_external_sites",
    "marketing.tracking_identify",
    "marketing.tracking_company",
    "marketing.tracking_custom_events",
    "marketing.tracking_alerts",
];

#[cfg(test)]
mod tests {
    use super::TRACKING_FLAGS;

    #[test]
    fn tracking_flags_default_off() {
        let registry = attome_core::feature_flag_registry();
        for key in TRACKING_FLAGS {
            let flag = registry
                .get(key)
                .unwrap_or_else(|| panic!("{key} is registered"));
            assert!(!flag.default, "{key} is off by default");
            assert_eq!(flag.module, attome_modules::MODULE_MARKETING);
        }
    }
}
