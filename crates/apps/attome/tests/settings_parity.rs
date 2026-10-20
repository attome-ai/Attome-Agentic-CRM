//! U10-T2: every registered setting is reachable from every surface — the
//! admin console (its area), the API (`/api/v1/admin/settings`), the CLI
//! (`attome settings`) and the agent tool (`settings.set`). A boot-time-only
//! setting lives in the configuration file: the console shows it read-only
//! and the API, the CLI and the tool cannot change it. The test names each
//! missing surface.

use attome_core::setting_descriptor::area;
use attome_core::setting_registry;

const CONSOLE: &str =
    include_str!("../../../../web/projects/xrm/core/admin/console/admin-console.component.ts");

fn words(list: &[&str]) -> Vec<String> {
    list.iter().map(|w| (*w).to_owned()).collect()
}

#[test]
fn every_setting_has_a_console_page_api_field_cli_command_and_mcp_tool() {
    let console_areas = CONSOLE
        .split_once("ADMIN_AREAS = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(list, _)| list.to_owned())
        .unwrap_or_default();
    let settable = attome_ai::actions::settings::settable_keys();
    let mut missing = Vec::new();
    for d in setting_registry().iter() {
        let key = d.key;
        let area = area(key);
        if area == "other" || !console_areas.contains(&format!("'{area}'")) {
            missing.push(format!(
                "{key}: console page (area `{area}` is not one of the console's areas)"
            ));
        }
        if attome::cmd::settings::parse(&words(&["get", key, "--url", "http://crm"])).is_err() {
            missing.push(format!(
                "{key}: CLI command (`attome settings get` refuses the key)"
            ));
        }
        if d.boot_time_only {
            if settable.contains(&key) {
                missing.push(format!(
                    "{key}: boot-time-only but the agent tool can set it"
                ));
            }
            continue;
        }
        // The admin API lists and writes every runtime setting.
        if !setting_registry().runtime_eligible().any(|r| r.key == key) {
            missing.push(format!(
                "{key}: API field (not served by /api/v1/admin/settings)"
            ));
        }
        if attome::cmd::settings::parse(&words(&["set", key, "null", "--url", "http://crm"]))
            .is_err()
        {
            missing.push(format!(
                "{key}: CLI command (`attome settings set` refuses the key)"
            ));
        }
        if !settable.contains(&key) {
            missing.push(format!("{key}: MCP tool (`settings.set` does not name it)"));
        }
    }
    assert!(
        missing.is_empty(),
        "settings missing a surface:\n{}",
        missing.join("\n")
    );
}

#[test]
fn the_settings_tools_are_in_the_tool_catalogue() {
    let ids: Vec<&str> = attome_ai::actions::all()
        .into_iter()
        .map(|d| d.id.0)
        .collect();
    for tool in [
        attome_ai::actions::settings::SETTINGS_LIST,
        attome_ai::actions::settings::SETTINGS_SET,
    ] {
        assert!(ids.contains(&tool), "{tool} is not offered");
    }
}
