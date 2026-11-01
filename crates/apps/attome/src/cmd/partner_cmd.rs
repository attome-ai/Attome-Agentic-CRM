//! F9-T8: `attome partner portal-roles`, which sets up one portal's partner
//! roles through the portal admin API, so each grant is validated and audited
//! as an administrator's would be.
//!
//! ```text
//! attome partner portal-roles --portal <id> [--target <name> | --url <url>]
//! ```
//!
//! Running it again creates nothing new and puts each grant back as defined.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use attome_portal::partner_roles::{role_body, role_grants};
use serde_json::Value;
use uuid::Uuid;

use crate::cmd::login::{Auth, credentials};
use crate::cmd::model_files::{answer, authorised, client};
use crate::cmd::output::take_value;

const DEFAULT_URL: &str = "http://127.0.0.1:7865";
const USAGE: &str =
    "usage: attome partner portal-roles --portal <id> [--target <name> | --url <url>]";

/// The id of the role called `name` in a role listing. Pure.
fn role_named(listing: &Value, name: &str) -> Option<Uuid> {
    listing["items"]
        .as_array()?
        .iter()
        .find(|role| role["name"] == name)
        .and_then(|role| role["id"].as_str())
        .and_then(|id| id.parse().ok())
}

async fn role_id(url: &str, auth: &Auth, portal: Uuid, name: &str) -> Result<Uuid, String> {
    let roles = format!("{url}/api/v1/admin/webportals/{portal}/roles");
    let reach = |error: reqwest::Error| format!("reach {url}: {error}");
    let listing = answer(
        authorised(client(url)?.get(&roles), auth.as_deref())
            .send()
            .await
            .map_err(reach)?,
    )
    .await?;
    if let Some(id) = role_named(&listing, name) {
        return Ok(id);
    }
    let created = answer(
        authorised(client(url)?.post(&roles), auth.as_deref())
            .json(&role_body(name))
            .send()
            .await
            .map_err(reach)?,
    )
    .await?;
    created["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .ok_or_else(|| format!("the server gave {name} no id"))
}

async fn install(url: &str, auth: &Auth, portal: Uuid) -> Result<usize, String> {
    let mut granted = 0;
    for (name, grants) in role_grants() {
        let role = role_id(url, auth, portal, name).await?;
        for (entity, spec) in grants {
            let path =
                format!("{url}/api/v1/admin/webportals/{portal}/roles/{role}/grants/{entity}");
            let response = authorised(client(url)?.put(path), auth.as_deref())
                .json(&spec)
                .send()
                .await
                .map_err(|error| format!("reach {url}: {error}"))?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(format!("{name} on {entity}: {status} {body}"));
            }
            granted += 1;
        }
        println!("{name}: ready");
    }
    Ok(granted)
}

/// `attome partner`.
pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let portal = take_value(&mut args, "--portal")?.ok_or(USAGE)?;
    let portal: Uuid = portal
        .parse()
        .map_err(|_| format!("--portal: `{portal}` is not an id"))?;
    let target = take_value(&mut args, "--target")?;
    let url = take_value(&mut args, "--url")?
        .or_else(|| std::env::var("ATTOME_URL").ok())
        .unwrap_or_else(|| DEFAULT_URL.to_owned());
    if args != ["portal-roles"] {
        return Err(USAGE.to_owned());
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("start the runtime: {error}"))?;
    let granted = runtime.block_on(async {
        let api_key = std::env::var("ATTOME_API_KEY").ok();
        let (url, auth) =
            credentials(url.trim_end_matches('/').to_owned(), api_key, target).await?;
        install(&url, &auth, portal).await
    })?;
    println!("{granted} grants set");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_listed_role_is_found_by_name() {
        let id = Uuid::now_v7();
        let listing = json!({ "items": [{ "name": "partner_sales", "id": id }] });
        assert_eq!(role_named(&listing, "partner_sales"), Some(id));
        assert_eq!(role_named(&listing, "partner_admin"), None);
    }
}
