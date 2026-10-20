//! The daily blocklist check (roadmap E6-T8): each sending domain and
//! sending IP against each DNS blocklist this deployment may query.
//!
//! **Which lists.** A blocklist's terms decide who may query it and at what
//! volume; the commercial lists (Spamhaus, Barracuda and the like) need a
//! subscription for a business's own use. So [`BLOCKLISTS`] is empty: no
//! list is queried by default, and a deployment names the lists it is
//! entitled to in `marketing.blocklist_zones` (its own Spamhaus DQS zone,
//! for instance). Nothing runs unless the deliverability policy's
//! `blocklist_enabled` is on.
//!
//! **Targets.** The sending domains the deliverability rollup saw in the
//! last thirty days, and the IPs in `marketing.blocklist_ips`.
//!
//! **A lookup** is one DNS A query (the system resolver, three seconds): an
//! answer in 127.0.0.0/8 is "listed", except 127.255.255.x, which lists use
//! for "query refused"; no answer and a timeout are never "listed". Every
//! result is a `marketing_blocklist_check` row; a target that turns from
//! not listed to listed is logged as an error once (the deliverability
//! alert of E6-T10 takes it from there when it is built).

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;

use attome_core::EngineState;
use attome_types::AppError;
use serde::Deserialize;
use serde_json::Value;

/// How long one blocklist lookup may take.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// A list a deployment may query.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct BlocklistDef {
    pub name: String,
    pub zone: String,
    /// `domain` or `ip`.
    pub kind: String,
    /// Why this deployment may query it.
    #[serde(default)]
    pub licence_note: Option<String>,
}

/// The lists queried without configuration: none, until a list's terms
/// are confirmed to allow a customer's own commercial use at its volume.
/// Candidates checked so far, all refused for that reason:
// - Spamhaus ZEN/DBL public mirrors: free only for low-volume,
//   non-commercial use; a business uses its DQS zone (configure it).
// - Barracuda BRBL: requires registering the querying resolver.
// - SpamCop SCBL: not confirmed.
pub const BLOCKLISTS: &[(&str, &str, &str)] = &[];

/// What a DNS A query answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Found(Vec<IpAddr>),
    NotFound,
    TimedOut,
}

/// The A lookup, injectable so tests need no network.
pub trait ALookup: Send + Sync {
    fn lookup_a<'a>(&'a self, name: &'a str) -> Pin<Box<dyn Future<Output = Lookup> + Send + 'a>>;
}

/// The system resolver, through the runtime.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl ALookup for SystemResolver {
    fn lookup_a<'a>(&'a self, name: &'a str) -> Pin<Box<dyn Future<Output = Lookup> + Send + 'a>> {
        Box::pin(async move {
            match tokio::time::timeout(LOOKUP_TIMEOUT, tokio::net::lookup_host((name, 0))).await {
                Err(_) => Lookup::TimedOut,
                Ok(Err(_)) => Lookup::NotFound,
                Ok(Ok(addrs)) => {
                    let ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                    if ips.is_empty() {
                        Lookup::NotFound
                    } else {
                        Lookup::Found(ips)
                    }
                }
            }
        })
    }
}

/// The name to query for `target` on `zone`: a domain as is, an IPv4
/// address with its octets reversed, an IPv6 address as reversed nibbles.
/// `None` for an IP list given a domain or the reverse. Pure.
pub fn query_name(target: &str, kind: &str, zone: &str) -> Option<String> {
    let zone = zone.trim().trim_matches('.');
    match (kind, target.parse::<IpAddr>()) {
        ("ip", Ok(IpAddr::V4(v4))) => {
            let [a, b, c, d] = v4.octets();
            Some(format!("{d}.{c}.{b}.{a}.{zone}"))
        }
        ("ip", Ok(IpAddr::V6(v6))) => {
            let hex: String = v6.octets().iter().map(|b| format!("{b:02x}")).collect();
            let nibbles: Vec<String> = hex.chars().rev().map(String::from).collect();
            Some(format!("{}.{zone}", nibbles.join(".")))
        }
        ("domain", Err(_)) => Some(format!("{}.{zone}", target.trim().trim_matches('.'))),
        _ => None,
    }
}

/// Whether an answer means "listed": an address in 127.0.0.0/8 other than
/// 127.255.255.x (the lists' "refused" answers). Pure.
pub fn is_listed(answer: &Lookup) -> bool {
    match answer {
        Lookup::Found(ips) => ips.iter().any(|ip| match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                o[0] == 127 && !(o[1] == 255 && o[2] == 255)
            }
            IpAddr::V6(_) => false,
        }),
        Lookup::NotFound | Lookup::TimedOut => false,
    }
}

/// Checks one target on one list.
pub async fn check_target(
    resolver: &dyn ALookup,
    target: &str,
    list: &BlocklistDef,
) -> (bool, Option<String>) {
    let Some(name) = query_name(target, &list.kind, &list.zone) else {
        return (false, Some("not a target this list checks".into()));
    };
    let answer = resolver.lookup_a(&name).await;
    let detail = match &answer {
        Lookup::Found(ips) => Some(
            ips.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        Lookup::NotFound => None,
        Lookup::TimedOut => Some("timeout".into()),
    };
    (is_listed(&answer), detail)
}

/// Whether a check result is news: listed now, and not listed (or never
/// checked) before. Pure.
pub fn newly_listed(previous: Option<bool>, listed: bool) -> bool {
    listed && previous != Some(true)
}

fn setting(state: &EngineState, key: &str) -> Value {
    let store = state.settings.load();
    attome_core::setting_registry()
        .get(key)
        .map(|d| store.resolve(d, None, None).0)
        .unwrap_or(Value::Null)
}

/// The lists configured for this deployment (built-in first).
pub fn configured_lists(state: &EngineState) -> Vec<BlocklistDef> {
    let mut lists: Vec<BlocklistDef> = BLOCKLISTS
        .iter()
        .map(|(name, zone, kind)| BlocklistDef {
            name: (*name).into(),
            zone: (*zone).into(),
            kind: (*kind).into(),
            licence_note: None,
        })
        .collect();
    if let Ok(more) =
        serde_json::from_value::<Vec<BlocklistDef>>(setting(state, "marketing.blocklist_zones"))
    {
        lists.extend(
            more.into_iter()
                .filter(|l| matches!(l.kind.as_str(), "domain" | "ip")),
        );
    }
    lists
}

/// One policy flag from the deliverability policy (the first active one).
pub async fn policy_flag(state: &EngineState, flag: &str) -> Result<bool, AppError> {
    let column = match flag {
        "blocklist_enabled" | "postmaster_enabled" | "snds_enabled" => flag,
        _ => return Ok(false),
    };
    let on: Option<Option<bool>> = sqlx::query_scalar(&format!(
        "SELECT {} FROM marketing_deliverability_policy WHERE is_active IS NOT FALSE \
          ORDER BY created_at LIMIT 1",
        attome_core::quote_ident(column)
    ))
    .fetch_optional(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(on.flatten() == Some(true))
}

/// What one run did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CheckRun {
    pub checks: u32,
    pub listed: u32,
    pub newly_listed: u32,
}

/// The daily run; nothing unless the policy's `blocklist_enabled` is on.
pub async fn run(state: &EngineState, resolver: &dyn ALookup) -> Result<CheckRun, AppError> {
    let mut run = CheckRun::default();
    if !policy_flag(state, "blocklist_enabled").await? {
        return Ok(run);
    }
    let lists = configured_lists(state);
    if lists.is_empty() {
        return Ok(run);
    }
    let mut targets: Vec<(String, &str)> = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT sending_domain FROM marketing_deliverability_daily \
          WHERE day >= current_date - 30 AND sending_domain <> ''",
    )
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?
    .into_iter()
    .map(|d| (d, "domain"))
    .collect();
    if let Ok(ips) =
        serde_json::from_value::<Vec<String>>(setting(state, "marketing.blocklist_ips"))
    {
        targets.extend(
            ips.into_iter()
                .filter(|ip| ip.trim().parse::<IpAddr>().is_ok())
                .map(|ip| (ip.trim().to_owned(), "ip")),
        );
    }
    for (target, kind) in &targets {
        for list in lists.iter().filter(|l| l.kind == *kind) {
            let (listed, detail) = check_target(resolver, target, list).await;
            let previous: Option<bool> = sqlx::query_scalar(
                "SELECT listed FROM marketing_blocklist_check \
                  WHERE target = $1 AND list_name = $2 ORDER BY checked_at DESC LIMIT 1",
            )
            .bind(target)
            .bind(&list.name)
            .fetch_optional(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            sqlx::query(
                "INSERT INTO marketing_blocklist_check (target, target_kind, list_name, listed, detail) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(target)
            .bind(kind)
            .bind(&list.name)
            .bind(listed)
            .bind(&detail)
            .execute(&state.base.db)
            .await
            .map_err(AppError::internal)?;
            run.checks += 1;
            if listed {
                run.listed += 1;
            }
            if newly_listed(previous, listed) {
                run.newly_listed += 1;
                tracing::error!(%target, list = %list.name, "deliverability: a sending target is newly blocklisted");
            }
        }
    }
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub(Lookup);

    impl ALookup for Stub {
        fn lookup_a<'a>(
            &'a self,
            _name: &'a str,
        ) -> Pin<Box<dyn Future<Output = Lookup> + Send + 'a>> {
            let answer = self.0.clone();
            Box::pin(async move { answer })
        }
    }

    fn list(kind: &str) -> BlocklistDef {
        BlocklistDef {
            name: "test".into(),
            zone: "bl.example".into(),
            kind: kind.into(),
            licence_note: None,
        }
    }

    #[tokio::test]
    async fn listed_target_detected() {
        let stub = Stub(Lookup::Found(vec!["127.0.0.2".parse().unwrap()]));
        assert!(check_target(&stub, "192.0.2.10", &list("ip")).await.0);
        assert_eq!(
            query_name("192.0.2.10", "ip", "bl.example").as_deref(),
            Some("10.2.0.192.bl.example")
        );
        assert_eq!(
            query_name("mail.example.com", "domain", "dbl.example.").as_deref(),
            Some("mail.example.com.dbl.example")
        );
        assert!(query_name("mail.example.com", "ip", "bl.example").is_none());
        let refused = Stub(Lookup::Found(vec!["127.255.255.254".parse().unwrap()]));
        assert!(!check_target(&refused, "192.0.2.10", &list("ip")).await.0);
    }

    #[tokio::test]
    async fn timeout_is_not_listed() {
        let (listed, detail) =
            check_target(&Stub(Lookup::TimedOut), "example.com", &list("domain")).await;
        assert!(!listed);
        assert_eq!(detail.as_deref(), Some("timeout"));
        assert!(
            !check_target(&Stub(Lookup::NotFound), "example.com", &list("domain"))
                .await
                .0
        );
    }

    #[test]
    fn alert_only_on_change() {
        assert!(newly_listed(None, true));
        assert!(newly_listed(Some(false), true));
        assert!(!newly_listed(Some(true), true));
        assert!(!newly_listed(Some(false), false));
        assert!(
            BLOCKLISTS.is_empty(),
            "no list is queried without its terms confirmed"
        );
    }
}
