//! Sourcing (roadmap F6-T4), pure: which location ships each line of an
//! order, under the order's sourcing rule, with the reason kept so a person
//! can see why. The stock figures come from the inventory seam (I6); without
//! inventory every location counts as having stock.
//!
//! - `Fixed`: one named location ships everything.
//! - `NearestWithStock`: each line from the nearest location that can ship
//!   all of it.
//! - `FewestShipments`: the fewest locations that cover every line, nearest
//!   first among equal choices; a line no single location covers is split.

use std::collections::BTreeMap;
use uuid::Uuid;

/// A ship-from location.
#[derive(Debug, Clone, PartialEq)]
pub struct Location {
    pub id: Uuid,
    /// Distance to the delivery address, in kilometres.
    pub distance_km: f64,
    /// Available quantity per product; `None` when stock is not tracked.
    pub stock: Option<BTreeMap<Uuid, u32>>,
}

impl Location {
    fn available(&self, product: Uuid) -> u32 {
        self.stock
            .as_ref()
            .map_or(u32::MAX, |s| s.get(&product).copied().unwrap_or(0))
    }
}

/// One order line to source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    pub id: Uuid,
    pub product: Uuid,
    pub quantity: u32,
}

/// The sourcing rule of an order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Fixed(Uuid),
    NearestWithStock,
    FewestShipments,
}

/// One allocation: part or all of a line from one location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub line: Uuid,
    pub location: Uuid,
    pub quantity: u32,
    pub reason: &'static str,
}

/// The sourcing of an order; `short` lists what no location can ship.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub allocations: Vec<Allocation>,
    pub short: Vec<(Uuid, u32)>,
}

impl Plan {
    /// The number of shipments (distinct locations).
    pub fn shipments(&self) -> usize {
        let mut locations: Vec<Uuid> = self.allocations.iter().map(|a| a.location).collect();
        locations.sort_unstable();
        locations.dedup();
        locations.len()
    }
}

fn by_distance(locations: &[Location]) -> Vec<&Location> {
    let mut sorted: Vec<&Location> = locations.iter().collect();
    sorted.sort_by(|a, b| {
        a.distance_km
            .total_cmp(&b.distance_km)
            .then(a.id.cmp(&b.id))
    });
    sorted
}

/// Sources `lines` from `locations` under `rule`.
pub fn source(rule: Rule, lines: &[Line], locations: &[Location]) -> Plan {
    let mut plan = Plan::default();
    match rule {
        Rule::Fixed(location) => {
            let Some(loc) = locations.iter().find(|l| l.id == location) else {
                plan.short = lines.iter().map(|l| (l.id, l.quantity)).collect();
                return plan;
            };
            for line in lines {
                let take = line.quantity.min(loc.available(line.product));
                if take > 0 {
                    plan.allocations.push(Allocation {
                        line: line.id,
                        location: loc.id,
                        quantity: take,
                        reason: "fixed_location",
                    });
                }
                if take < line.quantity {
                    plan.short.push((line.id, line.quantity - take));
                }
            }
        }
        Rule::NearestWithStock => {
            let ordered = by_distance(locations);
            for line in lines {
                match ordered
                    .iter()
                    .find(|l| l.available(line.product) >= line.quantity)
                {
                    Some(loc) => plan.allocations.push(Allocation {
                        line: line.id,
                        location: loc.id,
                        quantity: line.quantity,
                        reason: "nearest_with_stock",
                    }),
                    None => split_line(&mut plan, line, &ordered, &mut BTreeMap::new()),
                }
            }
        }
        Rule::FewestShipments => {
            let ordered = by_distance(locations);
            let mut remaining: Vec<Line> = lines.to_vec();
            let mut used: BTreeMap<(Uuid, Uuid), u32> = BTreeMap::new();
            // Repeatedly take the location that fully covers the most of the
            // remaining lines (nearest on ties).
            loop {
                let free = |loc: &Location, product: Uuid, used: &BTreeMap<(Uuid, Uuid), u32>| {
                    loc.available(product)
                        .saturating_sub(used.get(&(loc.id, product)).copied().unwrap_or(0))
                };
                let best = ordered
                    .iter()
                    .map(|loc| {
                        let covered = remaining
                            .iter()
                            .filter(|l| free(loc, l.product, &used) >= l.quantity)
                            .count();
                        (loc, covered)
                    })
                    .filter(|(_, covered)| *covered > 0)
                    .max_by(|a, b| {
                        a.1.cmp(&b.1)
                            .then(b.0.distance_km.total_cmp(&a.0.distance_km))
                    });
                let Some((loc, _)) = best else {
                    break;
                };
                remaining.retain(|line| {
                    if free(loc, line.product, &used) >= line.quantity {
                        plan.allocations.push(Allocation {
                            line: line.id,
                            location: loc.id,
                            quantity: line.quantity,
                            reason: "fewest_shipments",
                        });
                        *used.entry((loc.id, line.product)).or_default() += line.quantity;
                        false
                    } else {
                        true
                    }
                });
            }
            for line in &remaining {
                split_line(&mut plan, line, &ordered, &mut used);
            }
        }
    }
    plan
}

/// Splits a line nobody can ship whole across locations, nearest first.
fn split_line(
    plan: &mut Plan,
    line: &Line,
    ordered: &[&Location],
    used: &mut BTreeMap<(Uuid, Uuid), u32>,
) {
    let mut left = line.quantity;
    for loc in ordered {
        if left == 0 {
            break;
        }
        let already = used.get(&(loc.id, line.product)).copied().unwrap_or(0);
        let free = loc.available(line.product).saturating_sub(already);
        let take = left.min(free);
        if take > 0 {
            plan.allocations.push(Allocation {
                line: line.id,
                location: loc.id,
                quantity: take,
                reason: "split_no_single_location",
            });
            *used.entry((loc.id, line.product)).or_default() += take;
            left -= take;
        }
    }
    if left > 0 {
        plan.short.push((line.id, left));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn loc(n: u128, km: f64, stock: &[(u128, u32)]) -> Location {
        Location {
            id: u(n),
            distance_km: km,
            stock: Some(stock.iter().map(|(p, q)| (u(*p), *q)).collect()),
        }
    }

    fn line(n: u128, product: u128, quantity: u32) -> Line {
        Line {
            id: u(n),
            product: u(product),
            quantity,
        }
    }

    #[test]
    fn nearest_with_stock_picks_per_line() {
        let locations = [
            loc(1, 10.0, &[(100, 1)]),
            loc(2, 50.0, &[(100, 5), (200, 5)]),
        ];
        let plan = source(
            Rule::NearestWithStock,
            &[line(1, 100, 1), line(2, 200, 2)],
            &locations,
        );
        assert_eq!(plan.allocations[0].location, u(1));
        assert_eq!(plan.allocations[1].location, u(2));
        assert_eq!(plan.shipments(), 2);
    }

    #[test]
    fn fewest_shipments_prefers_one_location() {
        let locations = [
            loc(1, 10.0, &[(100, 1)]),
            loc(2, 50.0, &[(100, 5), (200, 5)]),
        ];
        let plan = source(
            Rule::FewestShipments,
            &[line(1, 100, 1), line(2, 200, 2)],
            &locations,
        );
        assert_eq!(plan.shipments(), 1);
        assert!(plan.allocations.iter().all(|a| a.location == u(2)));
    }

    #[test]
    fn fewest_shipments_does_not_ship_more_than_the_stock() {
        let locations = [loc(1, 10.0, &[(100, 3)]), loc(2, 20.0, &[(100, 3)])];
        let plan = source(
            Rule::FewestShipments,
            &[line(1, 100, 2), line(2, 100, 2)],
            &locations,
        );
        let from_1: u32 = plan
            .allocations
            .iter()
            .filter(|a| a.location == u(1))
            .map(|a| a.quantity)
            .sum();
        assert!(from_1 <= 3, "{plan:?}");
        assert!(plan.short.is_empty());
    }

    #[test]
    fn a_line_no_location_covers_is_split_then_short() {
        let locations = [loc(1, 10.0, &[(100, 2)]), loc(2, 20.0, &[(100, 3)])];
        let plan = source(Rule::NearestWithStock, &[line(1, 100, 7)], &locations);
        let shipped: u32 = plan.allocations.iter().map(|a| a.quantity).sum();
        assert_eq!(shipped, 5);
        assert_eq!(plan.short, vec![(u(1), 2)]);
    }

    #[test]
    fn fixed_location_ships_what_it_has() {
        let locations = [loc(1, 10.0, &[(100, 2)])];
        let plan = source(Rule::Fixed(u(1)), &[line(1, 100, 3)], &locations);
        assert_eq!(plan.allocations[0].quantity, 2);
        assert_eq!(plan.short, vec![(u(1), 1)]);
        let untracked = Location {
            id: u(9),
            distance_km: 1.0,
            stock: None,
        };
        let plan = source(Rule::Fixed(u(9)), &[line(1, 100, 3)], &[untracked]);
        assert!(plan.short.is_empty());
    }
}
