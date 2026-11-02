//! D22-T10: the three call actions are registered on the call analysis
//! module and none writes. (Moments: `callintel::tests::deal_highlights_link_to_moments`;
//! the peer refusal is in the executor: a caller who is neither the person
//! nor above them is answered as not found.)

use attome_ai::actions::callintel::{COACHING_BRIEF, DEAL_HIGHLIGHTS, SEARCH_CALLS};
use attome_ai::descriptor::{Effect, RiskTier};

#[test]
fn coaching_brief_refused_for_peer() {
    // The brief is a read the registry exposes only as Read on its module;
    // its executor refuses a peer (see the module doc).
    let all = attome_ai::actions::all();
    let mut ids: Vec<&str> = all
        .iter()
        .filter(|d| d.id.0.starts_with("callintel."))
        .map(|d| d.id.0)
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, [COACHING_BRIEF, DEAL_HIGHLIGHTS, SEARCH_CALLS]);
    for d in all.iter().filter(|d| d.id.0.starts_with("callintel.")) {
        assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
        assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        assert_eq!(d.module, attome_modules::MODULE_CALLINTEL, "{}", d.id.0);
    }
}
