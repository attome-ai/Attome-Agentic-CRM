//! AK6-T1 step 2: capabilities that need setting up before they are any use.
//! Until one is configured its working screens are left out of the sidebar,
//! and an administrator sees a "Set up" entry naming it instead, linking to
//! where it is configured. Configured is read from the deployment's
//! configuration, so it follows a restart with the new configuration.
//!
//! Today that is the AI assistant, which needs a generation model endpoint
//! (`inference.generation.base_url`): without one the playground, sessions,
//! agents, personalities, tones and spend screens have nothing to show.

use attome_config::AppConfig;

use crate::sidebar::SidebarItem;

/// One capability that needs setting up.
#[derive(Debug)]
pub struct Capability {
    pub key: &'static str,
    pub name_en: &'static str,
    pub name_ar: &'static str,
    /// Where it is set up (kept in the sidebar).
    pub setup_route: &'static str,
    /// The sidebar routes left out until it is configured.
    pub routes: &'static [&'static str],
    configured: fn(&AppConfig) -> bool,
}

impl Capability {
    pub fn configured(&self, config: &AppConfig) -> bool {
        (self.configured)(config)
    }
}

fn ai_configured(config: &AppConfig) -> bool {
    !config.inference.generation.base_url.trim().is_empty()
}

/// Every capability that needs setting up.
pub const CAPABILITIES: [Capability; 1] = [Capability {
    key: "ai",
    name_en: "AI assistant",
    name_ar: "المساعد الذكي",
    setup_route: "/xrm/ai/status",
    routes: &[
        "/xrm/ai/playground",
        "/xrm/ai/sessions",
        "/xrm/ai/spend",
        "/xrm/entity/ai_agent/list",
        "/xrm/entity/ai_personality/list",
        "/xrm/entity/ai_tone/list",
    ],
    configured: ai_configured,
}];

/// The capabilities `config` has not set up.
pub fn pending(config: &AppConfig) -> Vec<&'static Capability> {
    CAPABILITIES
        .iter()
        .filter(|c| !c.configured(config))
        .collect()
}

/// Whether a sidebar `route` belongs to a capability still pending. Pure.
pub fn hidden(pending: &[&Capability], route: &str) -> bool {
    pending.iter().any(|c| c.routes.contains(&route))
}

/// The "Set up" entry for an administrator, with one child per pending
/// capability; none when nothing is pending. Pure.
pub fn setup_item(pending: &[&Capability], locale: &str) -> Option<SidebarItem> {
    if pending.is_empty() {
        return None;
    }
    let arabic = locale.starts_with("ar");
    Some(SidebarItem {
        id: "setup".to_owned(),
        name: if arabic { "الإعداد" } else { "Set up" }.to_owned(),
        icon: "las la-tools".to_owned(),
        color: String::new(),
        route: String::new(),
        is_disabled: false,
        child: pending
            .iter()
            .map(|c| SidebarItem {
                id: format!("setup-{}", c.key),
                name: if arabic { c.name_ar } else { c.name_en }.to_owned(),
                icon: "las la-cog".to_owned(),
                color: String::new(),
                route: c.setup_route.to_owned(),
                is_disabled: false,
                child: Vec::new(),
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_hides_a_pending_capability_and_names_it() {
        let all: Vec<&Capability> = CAPABILITIES.iter().collect();
        assert!(hidden(&all, "/xrm/ai/playground"));
        assert!(!hidden(&all, "/xrm/ai/status"), "where it is set up stays");
        assert!(!hidden(&[], "/xrm/ai/playground"));
        let item = setup_item(&all, "ar-SA").unwrap();
        assert_eq!(item.name, "الإعداد");
        assert_eq!(item.child[0].route, "/xrm/ai/status");
        assert_eq!(
            setup_item(&all, "en").unwrap().child[0].name,
            "AI assistant"
        );
        assert!(setup_item(&[], "en").is_none());
        for c in &CAPABILITIES {
            assert!(!c.routes.contains(&c.setup_route), "{}", c.key);
        }
    }
}
