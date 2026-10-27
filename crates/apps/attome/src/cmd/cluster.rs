//! `attome cluster plan` (roadmap U2-T1): the files a deployment profile
//! needs, for one target, printed so an operator can review and copy them.
//!
//! ```text
//! attome cluster plan --profile solo|team|ha|scale [--target native|compose|helm] [--dir <dir>]
//! ```
//!
//! A profile (`deploy/profiles/<name>.json`, built into the binary) lists
//! its services with their role (`server`, `worker`, `postgres`,
//! `pgbouncer`, `cache`), replicas, CPU (percent of one core) and memory,
//! and the configuration settings it needs (`jobs.run_worker_inline` is
//! false exactly when the profile runs workers of its own). The sizes are
//! proposals from `loadtest/profiles.json` until AA2 measures them.
//!
//! - `native` (default): the systemd units for the server and each worker
//!   (`attome service install`'s unit, with the profile's caps) and the
//!   settings as a `config.json` overlay. PostgreSQL, PgBouncer and the cache
//!   are the operating system's own packages, sized in the overlay's notes.
//! - `compose`: one `docker-compose.yml` with every service, its replicas and
//!   limits.
//! - `helm`: a values file for `deploy/helm/attome` (replicas and resources
//!   of the server and worker).
//!
//! Nothing is written or installed: the command only prints.
//! `attome cluster create` and `expand` install a profile over SSH
//! ([`super::cluster_ssh`], U3-T1).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::service::{ServiceLimits, systemd_unit};

/// The profiles built into the binary.
const PROFILES: [(&str, &str); 4] = [
    (
        "solo",
        include_str!("../../../../../deploy/profiles/solo.json"),
    ),
    (
        "team",
        include_str!("../../../../../deploy/profiles/team.json"),
    ),
    ("ha", include_str!("../../../../../deploy/profiles/ha.json")),
    (
        "scale",
        include_str!("../../../../../deploy/profiles/scale.json"),
    ),
];

/// The service roles a profile may use.
pub const ROLES: [&str; 5] = ["server", "worker", "postgres", "pgbouncer", "cache"];

/// The image the compose file and the chart run.
const IMAGE: &str = "ghcr.io/attome-ai/attome";

const USAGE: &str = "\
attome cluster plan: print the deployment files of a profile

Usage:
  attome cluster plan --profile <solo|team|ha|scale> [--target native|compose|helm] [--dir <dir>]
  attome cluster create --profile <p> --hosts <user@host,...> --binary <path> [--target native|compose] [--dry-run]
  attome cluster expand --hosts <user@host,...> --join <user@host> --binary <path> [--dry-run]

  --profile  the deployment profile (deploy/profiles/<name>.json)
  --target   native (default: systemd units and a config overlay), compose or helm
  --dir      the data directory the native units run in (default /var/lib/attome)
";

/// One service of a profile.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Service {
    pub name: String,
    pub role: String,
    pub replicas: u32,
    pub cpu_percent: u32,
    pub memory_mb: u64,
}

/// A deployment profile.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub services: Vec<Service>,
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
}

impl Profile {
    /// The replicas of a role (0 when the profile has none).
    pub fn replicas(&self, role: &str) -> u32 {
        self.services
            .iter()
            .filter(|s| s.role == role)
            .map(|s| s.replicas)
            .sum()
    }

    fn of(&self, role: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.role == role)
    }
}

/// A built-in profile by name.
pub fn profile(name: &str) -> Result<Profile, String> {
    let (_, text) = PROFILES
        .iter()
        .find(|(n, _)| *n == name)
        .ok_or_else(|| format!("unknown profile `{name}`: solo, team, ha or scale"))?;
    let profile: Profile =
        serde_json::from_str(text).map_err(|e| format!("profile {name}: {e}"))?;
    check(&profile)?;
    Ok(profile)
}

/// What a profile must hold together. Pure.
pub fn check(profile: &Profile) -> Result<(), String> {
    let name = &profile.name;
    for s in &profile.services {
        if !ROLES.contains(&s.role.as_str()) {
            return Err(format!(
                "{name}: {} has role `{}`, not one of {}",
                s.name,
                s.role,
                ROLES.join(", ")
            ));
        }
        if s.cpu_percent == 0 || s.memory_mb == 0 {
            return Err(format!("{name}: {} needs a CPU and a memory size", s.name));
        }
    }
    if profile.replicas("server") == 0 || profile.replicas("postgres") == 0 {
        return Err(format!(
            "{name}: a profile runs at least one server and one PostgreSQL"
        ));
    }
    let inline = profile
        .settings
        .get("jobs.run_worker_inline")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if inline == (profile.replicas("worker") > 0) {
        return Err(format!(
            "{name}: jobs.run_worker_inline must be false exactly when the profile runs workers"
        ));
    }
    Ok(())
}

fn limits(s: &Service) -> ServiceLimits {
    ServiceLimits {
        memory_mb: s.memory_mb,
        cpu_percent: s.cpu_percent,
    }
}

/// The settings as a nested `config.json` overlay (`jobs.run_worker_inline`
/// becomes `{"jobs": {"run_worker_inline": ...}}`). Pure.
pub fn config_overlay(profile: &Profile) -> Value {
    let mut root = Map::new();
    for (key, value) in &profile.settings {
        let mut parts = key.split('.').peekable();
        let mut node = &mut root;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                node.insert(part.to_owned(), value.clone());
            } else {
                let next = node
                    .entry(part.to_owned())
                    .or_insert_with(|| Value::Object(Map::new()));
                if !next.is_object() {
                    *next = Value::Object(Map::new());
                }
                let Value::Object(map) = next else { break };
                node = map;
            }
        }
    }
    Value::Object(root)
}

/// The native target: units for the server and workers, and the overlay. Pure.
pub fn native(profile: &Profile, exe: &Path, dir: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    if let Some(server) = profile.of("server") {
        files.push((
            "/etc/systemd/system/attome.service".to_owned(),
            systemd_unit(exe, dir, Some(limits(server))),
        ));
    }
    if let Some(worker) = profile.of("worker") {
        let unit = systemd_unit(exe, dir, Some(limits(worker)))
            .replace(
                &format!("{} serve", exe.display()),
                &format!("{} worker", exe.display()),
            )
            .replace(
                "Attome CRM server (attome serve)",
                "Attome CRM job worker (attome worker)",
            );
        for n in 1..=worker.replicas {
            files.push((
                format!("/etc/systemd/system/attome-worker@{n}.service"),
                unit.clone(),
            ));
        }
    }
    let mut notes = Vec::new();
    for s in profile
        .services
        .iter()
        .filter(|s| !matches!(s.role.as_str(), "server" | "worker"))
    {
        notes.push(format!(
            "{} x{}: {} MiB, {}% CPU",
            s.name, s.replicas, s.memory_mb, s.cpu_percent
        ));
    }
    let mut overlay = config_overlay(profile);
    if let Value::Object(map) = &mut overlay {
        map.insert(
            "_comment".to_owned(),
            json!(format!(
                "attome cluster plan --profile {}: merge into config.json. Size the operating system's own services as: {}",
                profile.name,
                notes.join("; ")
            )),
        );
    }
    files.push((
        format!("{}/config.{}.json", dir.display(), profile.name),
        serde_json::to_string_pretty(&overlay).unwrap_or_default() + "\n",
    ));
    files
}

fn compose_service(
    name: &str,
    image: &str,
    command: Option<&str>,
    s: &Service,
    extra: &str,
) -> String {
    let command = command.map_or(String::new(), |c| format!("    command: [\"{c}\"]\n"));
    format!(
        "  {name}:\n    image: {image}\n{command}    deploy:\n      replicas: {}\n      resources:\n        limits:\n          cpus: \"{:.2}\"\n          memory: {}M\n    restart: unless-stopped\n{extra}",
        s.replicas,
        f64::from(s.cpu_percent) / 100.0,
        s.memory_mb
    )
}

/// The compose target: one file with every service. Pure.
pub fn compose(profile: &Profile) -> Vec<(String, String)> {
    let mut out = format!(
        "# attome cluster plan --profile {} --target compose\n# {}\nservices:\n",
        profile.name, profile.description
    );
    let app = format!("{IMAGE}:${{ATTOME_VERSION}}");
    let config = "    volumes:\n      - ./config.json:/etc/attome/config.json:ro\n    environment:\n      CONFIG_FILE: /etc/attome/config.json\n";
    for s in &profile.services {
        let block = match s.role.as_str() {
            "server" => compose_service(
                &s.name,
                &app,
                Some("serve"),
                s,
                &format!("{config}    ports:\n      - \"8080\"\n"),
            ),
            "worker" => compose_service(&s.name, &app, Some("worker"), s, config),
            "postgres" => compose_service(
                &s.name,
                "pgvector/pgvector:pg18",
                None,
                s,
                "    environment:\n      POSTGRES_PASSWORD: ${DB_PASSWORD}\n    volumes:\n      - pgdata:/var/lib/postgresql/data\n",
            ),
            "pgbouncer" => compose_service(&s.name, "edoburu/pgbouncer:latest", None, s, ""),
            _ => compose_service(
                &s.name,
                "docker.dragonflydb.io/dragonflydb/dragonfly:latest",
                None,
                s,
                "",
            ),
        };
        out.push_str(&block);
    }
    out.push_str("volumes:\n  pgdata: {}\n");
    vec![("docker-compose.yml".to_owned(), out)]
}

/// The helm target: values for `deploy/helm/attome`. Pure.
pub fn helm(profile: &Profile) -> Vec<(String, String)> {
    let block = |name: &str, s: Option<&Service>| match s {
        Some(s) => format!(
            "{name}:\n  replicas: {}\n  resources:\n    requests:\n      cpu: {}m\n      memory: {}Mi\n    limits:\n      cpu: {}m\n      memory: {}Mi\n",
            s.replicas,
            s.cpu_percent * 10 / 2,
            s.memory_mb / 2,
            s.cpu_percent * 10,
            s.memory_mb
        ),
        None => format!("{name}:\n  replicas: 0\n"),
    };
    let text = format!(
        "# attome cluster plan --profile {} --target helm\n# {}\n# helm install attome deploy/helm/attome -f values.{}.yaml\n{}{}",
        profile.name,
        profile.description,
        profile.name,
        block("server", profile.of("server")),
        block("worker", profile.of("worker")),
    );
    vec![(format!("values.{}.yaml", profile.name), text)]
}

fn plan(args: &[String]) -> Result<(), String> {
    let mut profile_name = None;
    let mut target = "native".to_owned();
    let mut dir = "/var/lib/attome".to_owned();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let value = |rest: &mut std::slice::Iter<'_, String>| {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value\n\n{USAGE}"))
        };
        match arg.as_str() {
            "--profile" => profile_name = Some(value(&mut rest)?),
            "--target" => target = value(&mut rest)?,
            "--dir" => dir = value(&mut rest)?,
            other => return Err(format!("unknown argument `{other}`\n\n{USAGE}")),
        }
    }
    let profile =
        profile(&profile_name.ok_or_else(|| format!("--profile is required\n\n{USAGE}"))?)?;
    let exe = std::env::current_exe().unwrap_or_else(|_| "/usr/local/bin/attome".into());
    let files = match target.as_str() {
        "native" => native(&profile, &exe, Path::new(&dir)),
        "compose" => compose(&profile),
        "helm" => helm(&profile),
        other => return Err(format!("unknown target `{other}`: native, compose or helm")),
    };
    for (path, contents) in files {
        println!("# ---- {path}\n{contents}");
    }
    Ok(())
}

/// `attome cluster ...`.
pub fn run(args: &[String]) -> ExitCode {
    let result = match args.first().map(String::as_str) {
        Some("plan") => plan(&args[1..]),
        Some("create") => super::cluster_ssh::run_create(&args[1..]),
        Some("expand") => super::cluster_ssh::run_expand(&args[1..]),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("attome cluster: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_load_and_hold_together() {
        for (name, _) in PROFILES {
            let p = profile(name).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(p.name, name);
            assert!(p.replicas("server") >= 1);
        }
        assert!(
            profile("ha").unwrap().replicas("server") >= 2,
            "ha runs two servers"
        );
        assert!(profile("galaxy").is_err());
    }

    #[test]
    fn profiles_need_workers_to_match_the_inline_setting() {
        let mut p = profile("team").unwrap();
        p.settings
            .insert("jobs.run_worker_inline".into(), json!(true));
        assert!(check(&p).is_err());
        let mut solo = profile("solo").unwrap();
        solo.services.retain(|s| s.role != "postgres");
        assert!(check(&solo).is_err());
    }

    #[test]
    fn profiles_generate_every_target() {
        for (name, _) in PROFILES {
            let p = profile(name).unwrap();
            let native = native(
                &p,
                Path::new("/usr/local/bin/attome"),
                Path::new("/var/lib/attome"),
            );
            assert!(
                native[0]
                    .1
                    .contains("ExecStart=/usr/local/bin/attome serve"),
                "{name}"
            );
            assert_eq!(
                native
                    .iter()
                    .filter(|(path, _)| path.contains("attome-worker@"))
                    .count() as u32,
                p.replicas("worker"),
                "{name}: one unit per worker"
            );
            let overlay: Value = serde_json::from_str(&native.last().unwrap().1).unwrap();
            assert_eq!(
                overlay["jobs"]["run_worker_inline"],
                json!(p.replicas("worker") == 0),
                "{name}"
            );
            let compose = &compose(&p)[0].1;
            assert!(compose.starts_with("# attome cluster plan"));
            assert_eq!(
                compose.matches("    deploy:\n").count(),
                p.services.len(),
                "{name}"
            );
            let helm = &helm(&p)[0].1;
            assert!(
                helm.contains(&format!("server:\n  replicas: {}", p.replicas("server"))),
                "{name}"
            );
        }
    }

    #[test]
    fn profiles_overlay_nests_dotted_keys() {
        let mut p = profile("solo").unwrap();
        p.settings
            .insert("database.replica_max_lag_secs".into(), json!(5));
        let overlay = config_overlay(&p);
        assert_eq!(overlay["database"]["node_count"], json!(1));
        assert_eq!(overlay["database"]["replica_max_lag_secs"], json!(5));
    }
}
