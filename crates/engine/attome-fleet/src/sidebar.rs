//! The Fleet menu group (design §7.2), added to `GET /api/v1/sidebar/get` at
//! serve time through `attome_api::sidebar::SidebarContributor`. Nothing is
//! ever written to `sidebar`, so no customer database carries the rows;
//! the gated boot path layers [`contributions`] onto the app only when the
//! gate is open. Admins only: every console route is `Authorized<Admin>`.

use std::sync::Arc;

use attome_api::sidebar::{SidebarContributions, SidebarContributor, SidebarItem};

/// The Angular routes lane FC-C builds under `/xrm/fleet/**`.
const ITEMS: [(&str, &str, &str); 4] = [
    ("fleet-deployments", "Deployments", "/xrm/fleet/deployments"),
    (
        "fleet-release-reports",
        "Release reports",
        "/xrm/fleet/release-reports",
    ),
    ("fleet-publish", "Publish", "/xrm/fleet/publish"),
    ("fleet-rollouts", "Rollouts", "/xrm/fleet/rollouts"),
];

#[derive(Debug)]
pub struct FleetSidebar;

impl SidebarContributor for FleetSidebar {
    fn contribute(&self, is_admin: bool) -> Vec<SidebarItem> {
        if !is_admin {
            return Vec::new();
        }
        vec![SidebarItem {
            id: "fleet".to_owned(),
            name: "Fleet".to_owned(),
            icon: "la-network-wired".to_owned(),
            color: String::new(),
            route: String::new(),
            is_disabled: false,
            child: ITEMS
                .iter()
                .map(|(id, name, route)| SidebarItem {
                    id: (*id).to_owned(),
                    name: (*name).to_owned(),
                    icon: String::new(),
                    color: String::new(),
                    route: (*route).to_owned(),
                    is_disabled: false,
                    child: Vec::new(),
                })
                .collect(),
        }]
    }
}

/// The request extension the composition root layers onto the app.
pub fn contributions() -> SidebarContributions {
    SidebarContributions(Arc::new(FleetSidebar))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admins_get_one_fleet_group_with_the_four_pages() {
        let items = FleetSidebar.contribute(true);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Fleet");
        assert_eq!(
            items[0]
                .child
                .iter()
                .map(|c| c.route.as_str())
                .collect::<Vec<_>>(),
            [
                "/xrm/fleet/deployments",
                "/xrm/fleet/release-reports",
                "/xrm/fleet/publish",
                "/xrm/fleet/rollouts"
            ]
        );
    }

    #[test]
    fn everyone_else_gets_nothing() {
        assert!(FleetSidebar.contribute(false).is_empty());
    }
}
