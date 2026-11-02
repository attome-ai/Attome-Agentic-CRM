//! F8-T11: the three commerce actions are in the registry, all read-only,
//! gated on the sales module, and none of them changes a price, a
//! promotion, a refund or an order. (The cross-shopper refusal itself is
//! `commerce::tests::order_track_refuses_other_shoppers_order`.)

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_ai::actions::commerce::{DRAFT_DESCRIPTION, ORDER_TRACK, PRODUCT_ANSWER};
use attome_ai::descriptor::{Effect, RiskTier};

#[test]
fn registry_lists_three_commerce_actions() {
    let all = attome_ai::actions::all();
    let commerce: Vec<_> = all
        .iter()
        .filter(|d| d.id.0.starts_with("commerce."))
        .collect();
    let mut ids: Vec<&str> = commerce.iter().map(|d| d.id.0).collect();
    ids.sort_unstable();
    assert_eq!(ids, [DRAFT_DESCRIPTION, ORDER_TRACK, PRODUCT_ANSWER]);
    for d in commerce {
        assert_eq!(d.risk, RiskTier::Read, "{}", d.id.0);
        assert_eq!(d.effect, Effect::Read, "{}", d.id.0);
        assert_eq!(d.module, attome_modules::MODULE_SALES, "{}", d.id.0);
    }
    assert!(
        !all.iter().any(|d| {
            let id = d.id.0;
            id.starts_with("commerce.")
                && ["price", "promotion", "refund", "release", "cancel"]
                    .iter()
                    .any(|word| id.contains(word))
        }),
        "no commerce tool changes prices, offers, refunds or orders"
    );
}
