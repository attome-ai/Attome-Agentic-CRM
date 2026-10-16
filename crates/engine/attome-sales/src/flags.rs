//! D6-T13: the feature flags the opportunity-line features sit behind, all
//! off by default. A route of a switched-off feature answers
//! `404 feature_hidden`.

pub const OPPORTUNITY_LINES: &str = "sales.opportunity_lines";
pub const RECURRING_LINES: &str = "sales.recurring_lines";
pub const SCHEDULES: &str = "sales.schedules";
pub const QUOTE_SYNC: &str = "sales.quote_sync";
pub const PRODUCT_SUGGESTIONS: &str = "sales.product_suggestions";
pub const DEAL_TEAMS: &str = "sales.deal_teams";
pub const SPLITS: &str = "sales.splits";
pub const LINE_SPLITS: &str = "sales.line_splits";
pub const PARTNER_MEMBERS: &str = "sales.partner_members";

/// A switched-off feature's routes answer 404, as if absent.
pub async fn require(
    state: &attome_core::EngineState,
    ctx: &attome_server::security::SecurityContext,
    key: &str,
) -> Result<(), attome_types::AppError> {
    if state.feature_flags().is_on(key, ctx).await {
        Ok(())
    } else {
        Err(attome_types::AppError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sales_flags_off_by_default() {
        let registry = attome_core::feature_flag_registry();
        for key in [
            OPPORTUNITY_LINES,
            RECURRING_LINES,
            SCHEDULES,
            QUOTE_SYNC,
            PRODUCT_SUGGESTIONS,
        ] {
            let flag = registry
                .get(key)
                .unwrap_or_else(|| panic!("{key} is registered"));
            assert!(!flag.default, "{key} is off by default");
            assert_eq!(flag.module, attome_modules::MODULE_SALES);
        }
    }
}
