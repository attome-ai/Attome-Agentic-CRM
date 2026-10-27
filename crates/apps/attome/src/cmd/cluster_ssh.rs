//! `attome cluster create` and `attome cluster expand` (roadmap U3-T1): put
//! a deployment profile ([`super::cluster`]) onto hosts over SSH.
//!
//! ```text
//! attome cluster create --profile <p> --hosts <user@host,...> --binary <attome for the hosts>
//!                       [--target native|compose] [--dir <dir>] [--identity <key>] [--dry-run]
//! attome cluster expand --hosts <user@new,...> --join <user@existing> --binary <...>
//!                       [--dir <dir>] [--identity <key>] [--dry-run]
//! ```
//!
//! The profile's services are spread over the hosts ([`assign`]): the first
//! host keeps PostgreSQL, PgBouncer and the cache, and the servers and
//! workers go round the hosts in turn. For each host ([`host_steps`]):
//! check it is Linux with systemd, copy the binary and the profile's files
//! that host runs (its systemd units, the config overlay), install the
//! operating system's own PostgreSQL, PgBouncer or cache packages where the
//! host keeps them, write the cluster's join file (`cluster.json`, every
//! node and what it runs) and start the units. `compose` puts the whole
//! profile on one host as a compose project instead.
//!
//! `expand` reads the join file from a host already in the cluster, adds
//! the new hosts as server nodes, installs them, and writes the grown join
//! file to every node.
//!
//! SSH is the system's own OpenSSH client (`ssh`, on Linux, macOS and
//! Windows 10+), in batch mode, so keys and known hosts are the operator's
//! usual ones; file contents go over the connection's standard input. No
//! SSH library is linked into the binary (the Rust ones pull in `rsa` with
//! RUSTSEC-2023-0071). `--dry-run` prints every step instead.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use super::cluster::{Profile, compose, native, profile};

const USAGE: &str = "\
attome cluster create|expand: install a profile on hosts over SSH

Usage:
  attome cluster create --profile <solo|team|ha|scale> --hosts <user@host,...> --binary <path>
                        [--target native|compose] [--dir <dir>] [--identity <key>] [--dry-run]
  attome cluster expand --hosts <user@host,...> --join <user@host> --binary <path>
                        [--dir <dir>] [--identity <key>] [--dry-run]

  --hosts     the hosts to install, as ssh targets
  --join      expand: a host already in the cluster (its join file is read)
  --binary    the attome binary built for the hosts (copied to /usr/local/bin/attome)
  --target    native (default: systemd units) or compose (one host, a compose project)
  --dir       the data directory (default /var/lib/attome)
  --identity  the private key ssh uses (default: the ssh client's own)
  --dry-run   print the steps, run nothing
";

/// Where the binary goes on each host.
pub const REMOTE_EXE: &str = "/usr/local/bin/attome";

/// One host's connection.
pub trait Remote {
    /// The ssh target (`user@host`).
    fn target(&self) -> &str;
    /// Runs a shell command; its standard output, or why it failed.
    fn run(&mut self, command: &str) -> Result<String, String>;
    /// Writes `contents` to `path` (mode `mode`).
    fn put(&mut self, path: &str, contents: &[u8], mode: &str) -> Result<(), String>;
}

/// A host over the system's `ssh` client.
pub struct SshRemote {
    target: String,
    identity: Option<PathBuf>,
}

impl SshRemote {
    pub fn new(target: &str, identity: Option<PathBuf>) -> Self {
        Self {
            target: target.to_owned(),
            identity,
        }
    }

    fn command(&self, remote: &str) -> Command {
        let mut c = Command::new("ssh");
        c.args(["-o", "BatchMode=yes", "-o", "ConnectTimeout=20"]);
        if let Some(key) = &self.identity {
            c.arg("-i").arg(key);
        }
        c.arg(&self.target).arg(remote);
        c
    }
}

impl Remote for SshRemote {
    fn target(&self) -> &str {
        &self.target
    }

    fn run(&mut self, command: &str) -> Result<String, String> {
        let out = self
            .command(command)
            .output()
            .map_err(|e| format!("cannot run ssh: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            Err(format!(
                "{}: `{command}` failed: {}",
                self.target,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn put(&mut self, path: &str, contents: &[u8], mode: &str) -> Result<(), String> {
        let remote = format!(
            "mkdir -p {dir} && cat > {path}.part && chmod {mode} {path}.part && mv {path}.part {path}",
            dir = shell_quote(parent_of(path)),
            path = shell_quote(path),
        );
        let mut child = self
            .command(&remote)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run ssh: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(contents)
                .map_err(|e| format!("{}: writing {path}: {e}", self.target))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("cannot run ssh: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "{}: writing {path} failed: {}",
                self.target,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

/// `text` as one POSIX shell word. Pure.
pub fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) => "/",
        Some(i) => &path[..i],
        None => ".",
    }
}

/// One node of the cluster and the services it runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub host: String,
    /// Role names (`server`, `worker`, `postgres`, `pgbouncer`, `cache`); a
    /// worker appears once per replica on the node.
    pub services: Vec<String>,
}

/// The join file every node keeps (`<dir>/cluster.json`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterFile {
    pub profile: String,
    pub target: String,
    pub nodes: Vec<Node>,
}

/// The profile's services spread over `hosts`: the first host keeps the
/// stateful ones (PostgreSQL, PgBouncer, cache), servers then workers go
/// round the hosts in turn. Pure.
pub fn assign(profile: &Profile, hosts: &[String]) -> Result<Vec<Node>, String> {
    if hosts.is_empty() {
        return Err("--hosts names no host".into());
    }
    let mut nodes: Vec<Node> = hosts
        .iter()
        .map(|h| Node {
            host: h.clone(),
            services: Vec::new(),
        })
        .collect();
    for role in ["postgres", "pgbouncer", "cache"] {
        if profile.replicas(role) > 0 {
            nodes[0].services.push(role.to_owned());
        }
    }
    let mut next = 0usize;
    for role in ["server", "worker"] {
        for _ in 0..profile.replicas(role) {
            nodes[next % hosts.len()].services.push(role.to_owned());
            next += 1;
        }
    }
    Ok(nodes)
}

/// One step on a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Run(String),
    Put {
        path: String,
        contents: Vec<u8>,
        mode: &'static str,
    },
}

/// The operating-system packages of a stateful role, installed with
/// whichever package manager the host has.
fn package_step(role: &str) -> Option<String> {
    let (apt, dnf) = match role {
        "postgres" => ("postgresql", "postgresql-server"),
        "pgbouncer" => ("pgbouncer", "pgbouncer"),
        "cache" => ("redis-server", "redis"),
        _ => return None,
    };
    Some(format!(
        "if command -v apt-get >/dev/null; then sudo apt-get install -y {apt}; \
         elif command -v dnf >/dev/null; then sudo dnf install -y {dnf}; \
         else echo 'no apt-get or dnf: install {apt} by hand' >&2; exit 1; fi"
    ))
}

/// What installing `node` takes, in order. `binary` is the binary's bytes
/// (or nothing, on a dry run). Pure.
pub fn host_steps(
    profile: &Profile,
    node: &Node,
    cluster: &ClusterFile,
    dir: &str,
    binary: &[u8],
) -> Vec<Step> {
    let mut steps = vec![
        Step::Run("test \"$(uname -s)\" = Linux && command -v systemctl >/dev/null".into()),
        Step::Run(format!("sudo mkdir -p {}", shell_quote(dir))),
        Step::Put {
            path: REMOTE_EXE.into(),
            contents: binary.to_vec(),
            mode: "0755",
        },
    ];
    for role in &node.services {
        if let Some(step) = package_step(role) {
            steps.push(Step::Run(step));
        }
    }
    let files = native(profile, Path::new(REMOTE_EXE), Path::new(dir));
    let workers = node.services.iter().filter(|s| *s == "worker").count();
    let runs_server = node.services.iter().any(|s| s == "server");
    // The node's worker units are numbered 1.. on that node.
    let mut units = Vec::new();
    for (path, contents) in &files {
        let unit = path.rsplit('/').next().unwrap_or(path);
        let keep = if unit == "attome.service" {
            runs_server
        } else if let Some(n) = unit
            .strip_prefix("attome-worker@")
            .and_then(|r| r.strip_suffix(".service"))
            .and_then(|n| n.parse::<usize>().ok())
        {
            n <= workers
        } else {
            // The config overlay goes to every node.
            true
        };
        if keep {
            steps.push(Step::Put {
                path: path.clone(),
                contents: contents.clone().into_bytes(),
                mode: "0644",
            });
            if unit.ends_with(".service") {
                units.push(unit.to_owned());
            }
        }
    }
    let join = serde_json::to_string_pretty(cluster).unwrap_or_default() + "\n";
    steps.push(Step::Put {
        path: format!("{dir}/cluster.json"),
        contents: join.into_bytes(),
        mode: "0644",
    });
    if !units.is_empty() {
        steps.push(Step::Run("sudo systemctl daemon-reload".into()));
        steps.push(Step::Run(format!(
            "sudo systemctl enable --now {}",
            units.join(" ")
        )));
    }
    steps
}

/// The steps of a compose cluster: the whole profile on one host. Pure.
pub fn compose_steps(profile: &Profile, cluster: &ClusterFile, dir: &str) -> Vec<Step> {
    let mut steps = vec![Step::Run(
        "command -v docker >/dev/null && docker compose version >/dev/null".into(),
    )];
    for (name, contents) in compose(profile) {
        steps.push(Step::Put {
            path: format!("{dir}/{name}"),
            contents: contents.into_bytes(),
            mode: "0644",
        });
    }
    steps.push(Step::Put {
        path: format!("{dir}/cluster.json"),
        contents: (serde_json::to_string_pretty(cluster).unwrap_or_default() + "\n").into_bytes(),
        mode: "0644",
    });
    steps.push(Step::Run(format!(
        "cd {} && docker compose up -d",
        shell_quote(dir)
    )));
    steps
}

/// Runs `steps` on `remote`, or prints them when `dry_run`.
pub fn apply(remote: &mut dyn Remote, steps: &[Step], dry_run: bool) -> Result<(), String> {
    for step in steps {
        match step {
            Step::Run(cmd) if dry_run => println!("{}: run {cmd}", remote.target()),
            Step::Put { path, contents, .. } if dry_run => {
                println!(
                    "{}: write {path} ({} bytes)",
                    remote.target(),
                    contents.len()
                );
            }
            Step::Run(cmd) => {
                remote.run(cmd)?;
            }
            Step::Put {
                path,
                contents,
                mode,
            } => remote.put(path, contents, mode)?,
        }
    }
    Ok(())
}

/// The cluster grown by `hosts`, each a server node. Pure.
pub fn grown(cluster: &ClusterFile, hosts: &[String]) -> Result<ClusterFile, String> {
    let mut out = cluster.clone();
    for h in hosts {
        if out.nodes.iter().any(|n| &n.host == h) {
            return Err(format!("{h} is already in the cluster"));
        }
        out.nodes.push(Node {
            host: h.clone(),
            services: vec!["server".into()],
        });
    }
    Ok(out)
}

/// Creates the cluster on `remotes` (in `--hosts` order).
pub fn create(
    profile: &Profile,
    target: &str,
    remotes: &mut [Box<dyn Remote>],
    dir: &str,
    binary: &[u8],
    dry_run: bool,
) -> Result<ClusterFile, String> {
    let hosts: Vec<String> = remotes.iter().map(|r| r.target().to_owned()).collect();
    let cluster = ClusterFile {
        profile: profile.name.clone(),
        target: target.to_owned(),
        nodes: match target {
            "compose" => vec![Node {
                host: hosts.first().cloned().ok_or("--hosts names no host")?,
                services: profile.services.iter().map(|s| s.role.clone()).collect(),
            }],
            _ => assign(profile, &hosts)?,
        },
    };
    if target == "compose" {
        if remotes.len() != 1 {
            return Err("a compose cluster runs on one host".into());
        }
        apply(
            remotes[0].as_mut(),
            &compose_steps(profile, &cluster, dir),
            dry_run,
        )?;
        return Ok(cluster);
    }
    for (remote, node) in remotes.iter_mut().zip(&cluster.nodes) {
        apply(
            remote.as_mut(),
            &host_steps(profile, node, &cluster, dir, binary),
            dry_run,
        )?;
    }
    Ok(cluster)
}

/// Adds `new` hosts to the cluster `join` belongs to and rewrites every
/// node's join file. `others` are the cluster's other existing nodes'
/// connections, by target (the join file names them).
pub fn expand(
    join: &mut dyn Remote,
    new: &mut [Box<dyn Remote>],
    connect: &mut dyn FnMut(&str) -> Box<dyn Remote>,
    dir: &str,
    binary: &[u8],
    dry_run: bool,
) -> Result<ClusterFile, String> {
    let text = join.run(&format!(
        "cat {}",
        shell_quote(&format!("{dir}/cluster.json"))
    ))?;
    let cluster: ClusterFile = serde_json::from_str(&text)
        .map_err(|e| format!("{}: the join file does not read: {e}", join.target()))?;
    if cluster.target != "native" {
        return Err("only a native cluster can grow".into());
    }
    let profile = profile(&cluster.profile)?;
    let hosts: Vec<String> = new.iter().map(|r| r.target().to_owned()).collect();
    let grown = grown(&cluster, &hosts)?;
    let join_file = (serde_json::to_string_pretty(&grown).unwrap_or_default() + "\n").into_bytes();
    for remote in new.iter_mut() {
        let node = grown
            .nodes
            .iter()
            .find(|n| n.host == remote.target())
            .cloned()
            .ok_or("a new host is missing from the grown cluster")?;
        apply(
            remote.as_mut(),
            &host_steps(&profile, &node, &grown, dir, binary),
            dry_run,
        )?;
    }
    let write_join = [Step::Put {
        path: format!("{dir}/cluster.json"),
        contents: join_file,
        mode: "0644",
    }];
    for node in &cluster.nodes {
        if node.host == join.target() {
            apply(join, &write_join, dry_run)?;
        } else {
            apply(connect(&node.host).as_mut(), &write_join, dry_run)?;
        }
    }
    Ok(grown)
}

struct Args {
    profile: Option<String>,
    hosts: Vec<String>,
    join: Option<String>,
    binary: Option<PathBuf>,
    target: String,
    dir: String,
    identity: Option<PathBuf>,
    dry_run: bool,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        profile: None,
        hosts: Vec::new(),
        join: None,
        binary: None,
        target: "native".into(),
        dir: "/var/lib/attome".into(),
        identity: None,
        dry_run: false,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value\n\n{USAGE}"))
        };
        match arg.as_str() {
            "--profile" => out.profile = Some(value()?),
            "--hosts" => {
                out.hosts = value()?
                    .split(',')
                    .map(str::trim)
                    .filter(|h| !h.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            "--join" => out.join = Some(value()?),
            "--binary" => out.binary = Some(PathBuf::from(value()?)),
            "--target" => out.target = value()?,
            "--dir" => out.dir = value()?,
            "--identity" => out.identity = Some(PathBuf::from(value()?)),
            "--dry-run" => out.dry_run = true,
            other => return Err(format!("unknown argument `{other}`\n\n{USAGE}")),
        }
    }
    if !matches!(out.target.as_str(), "native" | "compose") {
        return Err(format!(
            "unknown target `{}`: native or compose",
            out.target
        ));
    }
    Ok(out)
}

fn binary_bytes(args: &Args) -> Result<Vec<u8>, String> {
    if args.target == "compose" {
        return Ok(Vec::new());
    }
    let path = args
        .binary
        .as_ref()
        .ok_or_else(|| format!("--binary is required\n\n{USAGE}"))?;
    if args.dry_run {
        return Ok(Vec::new());
    }
    std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// `attome cluster create ...`.
pub fn run_create(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let profile = profile(
        a.profile
            .as_deref()
            .ok_or_else(|| format!("--profile is required\n\n{USAGE}"))?,
    )?;
    let binary = binary_bytes(&a)?;
    let mut remotes: Vec<Box<dyn Remote>> = a
        .hosts
        .iter()
        .map(|h| Box::new(SshRemote::new(h, a.identity.clone())) as Box<dyn Remote>)
        .collect();
    let cluster = create(
        &profile,
        &a.target,
        &mut remotes,
        &a.dir,
        &binary,
        a.dry_run,
    )?;
    for node in &cluster.nodes {
        println!("{}: {}", node.host, node.services.join(", "));
    }
    Ok(())
}

/// `attome cluster expand ...`.
pub fn run_expand(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let join = a
        .join
        .as_deref()
        .ok_or_else(|| format!("--join is required\n\n{USAGE}"))?;
    let binary = binary_bytes(&a)?;
    let mut join_remote = SshRemote::new(join, a.identity.clone());
    let mut new: Vec<Box<dyn Remote>> = a
        .hosts
        .iter()
        .map(|h| Box::new(SshRemote::new(h, a.identity.clone())) as Box<dyn Remote>)
        .collect();
    let identity = a.identity.clone();
    let mut connect =
        move |host: &str| Box::new(SshRemote::new(host, identity.clone())) as Box<dyn Remote>;
    let cluster = expand(
        &mut join_remote,
        &mut new,
        &mut connect,
        &a.dir,
        &binary,
        a.dry_run,
    )?;
    println!("{} nodes", cluster.nodes.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::*;

    /// A fake SSH target: records every command and file, answers `uname`
    /// and `cat` from what it holds.
    #[derive(Default)]
    struct Host {
        commands: Vec<String>,
        files: BTreeMap<String, Vec<u8>>,
    }

    struct Fake {
        target: String,
        host: Rc<RefCell<Host>>,
    }

    impl Remote for Fake {
        fn target(&self) -> &str {
            &self.target
        }

        fn run(&mut self, command: &str) -> Result<String, String> {
            let mut host = self.host.borrow_mut();
            host.commands.push(command.to_owned());
            if let Some(path) = command.strip_prefix("cat ") {
                let path = path.trim_matches('\'');
                return host
                    .files
                    .get(path)
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .ok_or_else(|| format!("no {path}"));
            }
            Ok(String::new())
        }

        fn put(&mut self, path: &str, contents: &[u8], _mode: &str) -> Result<(), String> {
            self.host
                .borrow_mut()
                .files
                .insert(path.to_owned(), contents.to_vec());
            Ok(())
        }
    }

    fn fakes(names: &[&str]) -> (Vec<Box<dyn Remote>>, Vec<Rc<RefCell<Host>>>) {
        let hosts: Vec<Rc<RefCell<Host>>> = names
            .iter()
            .map(|_| Rc::new(RefCell::new(Host::default())))
            .collect();
        let remotes = names
            .iter()
            .zip(&hosts)
            .map(|(n, h)| {
                Box::new(Fake {
                    target: (*n).to_owned(),
                    host: Rc::clone(h),
                }) as Box<dyn Remote>
            })
            .collect();
        (remotes, hosts)
    }

    #[test]
    fn cluster_create_two_nodes_installs_and_joins() {
        let team = profile("team").unwrap();
        let (mut remotes, hosts) = fakes(&["root@a", "root@b"]);
        let cluster = create(
            &team,
            "native",
            &mut remotes,
            "/var/lib/attome",
            b"ELF",
            false,
        )
        .unwrap();
        assert_eq!(cluster.nodes.len(), 2);
        assert!(cluster.nodes[0].services.contains(&"postgres".to_owned()));
        assert!(cluster.nodes[0].services.contains(&"server".to_owned()));
        let a = hosts[0].borrow();
        assert_eq!(a.files[REMOTE_EXE], b"ELF");
        assert!(a.files.contains_key("/etc/systemd/system/attome.service"));
        assert!(
            a.commands
                .iter()
                .any(|c| c.contains("apt-get install -y postgresql"))
        );
        assert!(
            a.commands
                .last()
                .unwrap()
                .starts_with("sudo systemctl enable --now")
        );
        let join: ClusterFile =
            serde_json::from_slice(&hosts[1].borrow().files["/var/lib/attome/cluster.json"])
                .unwrap();
        assert_eq!(join, cluster);
        // The second host runs no database.
        assert!(
            !hosts[1]
                .borrow()
                .commands
                .iter()
                .any(|c| c.contains("postgresql"))
        );
        let apps: u32 = cluster
            .nodes
            .iter()
            .flat_map(|n| &n.services)
            .filter(|s| *s == "server" || *s == "worker")
            .count() as u32;
        assert_eq!(apps, team.replicas("server") + team.replicas("worker"));
    }

    #[test]
    fn cluster_create_expand_adds_a_node_and_rewrites_every_join_file() {
        let solo = profile("solo").unwrap();
        let (mut remotes, hosts) = fakes(&["root@a"]);
        create(&solo, "native", &mut remotes, "/srv/attome", b"ELF", false).unwrap();
        let (mut new, new_hosts) = fakes(&["root@b"]);
        let mut join = remotes.remove(0);
        let mut connect = |h: &str| -> Box<dyn Remote> { panic!("no other node expected: {h}") };
        let grown = expand(
            join.as_mut(),
            &mut new,
            &mut connect,
            "/srv/attome",
            b"ELF",
            false,
        )
        .unwrap();
        assert_eq!(grown.nodes.len(), 2);
        assert_eq!(grown.nodes[1].services, ["server"]);
        for h in [&hosts[0], &new_hosts[0]] {
            let file: ClusterFile =
                serde_json::from_slice(&h.borrow().files["/srv/attome/cluster.json"]).unwrap();
            assert_eq!(file, grown);
        }
        assert!(
            new_hosts[0]
                .borrow()
                .files
                .contains_key("/etc/systemd/system/attome.service")
        );
        let (mut again, _) = fakes(&["root@b"]);
        let mut join2: Box<dyn Remote> = Box::new(Fake {
            target: "root@a".into(),
            host: Rc::clone(&hosts[0]),
        });
        assert!(
            expand(
                join2.as_mut(),
                &mut again,
                &mut connect,
                "/srv/attome",
                b"",
                false
            )
            .is_err()
        );
    }

    #[test]
    fn cluster_create_compose_runs_on_one_host_and_quotes_paths() {
        let team = profile("team").unwrap();
        let (mut one, hosts) = fakes(&["root@a"]);
        create(&team, "compose", &mut one, "/opt/my attome", b"", false).unwrap();
        assert!(
            hosts[0]
                .borrow()
                .commands
                .last()
                .unwrap()
                .contains("cd '/opt/my attome' && docker compose up -d")
        );
        let (mut two, _) = fakes(&["root@a", "root@b"]);
        assert!(create(&team, "compose", &mut two, "/opt", b"", false).is_err());
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert!(assign(&team, &[]).is_err());
    }
}
