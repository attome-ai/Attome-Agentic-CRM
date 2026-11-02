//! F11-T12: the three revenue actions are registered on the ledger module and
//! none writes. (The explanation's content is
//! `revrec::tests::explain_cites_rule_and_ssp_version`.)

use attome_ai::actions::revrec::{DRAFT_DISCLOSURE, EXPLAIN_PERIOD, PROPOSE_RULE};
use attome_ai::descriptor::{Effect, RiskTier};

#[test]
fn no_action_writes() {
    let all = attome_ai::actions::all();
    let mut ids: Vec<&str> = all
        .iter()
        .filter(|d| d.id.0.starts_with("revrec."))
        .map(|d| d.id.0)
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, [DRAFT_DISCLOSURE, EXPLAIN_PERIOD, PROPOSE_RULE]);
    for d in all.iter().filter(|d| d.id.0.starts_with("revrec.")) {
        assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
        assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        assert_eq!(d.module, attome_modules::MODULE_LEDGER, "{}", d.id.0);
    }
}
