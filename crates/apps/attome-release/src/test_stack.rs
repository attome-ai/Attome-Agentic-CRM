//! The test stack `attome test` starts on its own (roadmap Z15-T2).
//!
//! When a tier needs a database and `DATABASE_URL` is not set, it runs a
//! throwaway PostgreSQL 18 with pgvector and a Redis in Docker, on ports that
//! do not collide with a development server's (5556 and 6380), and points the
//! test processes at them. `attome-testkit` then creates and migrates one
//! database per test process, so no template step is needed here.
//!
//! A port that already answers is taken as the stack from an earlier run and
//! reused. The containers are left running for the next run; remove them
//! with `docker rm -f attome-test-postgres attome-test-redis`. An object
//! store is not started: S3 tests skip without one (and fail under
//! `--release`, as they should, until `S3_ACCESS_KEY`/`S3_SECRET_KEY` point
//! at one).

use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

/// One container of the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    pub container: &'static str,
    pub image: &'static str,
    pub host_port: u16,
    pub container_port: u16,
    pub env: &'static [&'static str],
}

/// The stack's services.
pub const SERVICES: [Service; 2] = [
    Service {
        container: "attome-test-postgres",
        image: "pgvector/pgvector:pg18",
        host_port: 5556,
        container_port: 5432,
        env: &["POSTGRES_PASSWORD=attometest"],
    },
    Service {
        container: "attome-test-redis",
        image: "redis:7",
        host_port: 6380,
        container_port: 6379,
        env: &[],
    },
];

/// The variables the test processes get, named as `attome-testkit` and the
/// CI workflow name them.
pub fn stack_env() -> Vec<(String, String)> {
    [
        (
            "DATABASE_URL",
            "postgres://postgres:attometest@127.0.0.1:5556/postgres",
        ),
        ("TEST_REDIS_HOST", "127.0.0.1"),
        ("TEST_REDIS_PORT", "6380"),
        ("REDIS_URL", "redis://127.0.0.1:6380/0"),
    ]
    .iter()
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect()
}

/// The services that still need starting, given which ports answer.
pub fn to_start(port_open: impl Fn(u16) -> bool) -> Vec<Service> {
    SERVICES
        .iter()
        .copied()
        .filter(|service| !port_open(service.host_port))
        .collect()
}

fn port_open(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok()
}

fn docker(args: &[&str]) -> Result<String, String> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .map_err(|error| {
            format!("cannot run docker ({error}); install Docker or set DATABASE_URL")
        })?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    } else {
        Err(format!(
            "docker {} failed: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn start(service: &Service) -> Result<(), String> {
    // A stopped container from an earlier run would block the name.
    let _ = docker(&["rm", "-f", service.container]);
    let ports = format!("127.0.0.1:{}:{}", service.host_port, service.container_port);
    let mut args = vec![
        "run",
        "-d",
        "--name",
        service.container,
        "-p",
        ports.as_str(),
    ];
    for pair in service.env {
        args.extend(["-e", *pair]);
    }
    args.push(service.image);
    docker(&args).map(|_| ())
}

/// Waits until PostgreSQL accepts connections (an open port is not enough:
/// the server restarts once during first-time initialisation).
fn wait_ready(timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut ready_twice = 0;
    while Instant::now() < deadline {
        let ready = port_open(5556)
            && docker(&[
                "exec",
                "attome-test-postgres",
                "pg_isready",
                "-h",
                "127.0.0.1",
                "-U",
                "postgres",
            ])
            .is_ok();
        ready_twice = if ready { ready_twice + 1 } else { 0 };
        if ready_twice >= 2 && port_open(6380) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "the test stack did not become ready within {} s",
        timeout.as_secs()
    ))
}

/// The environment for the test processes: empty when the caller manages
/// the services (`DATABASE_URL` set, or `--no-stack`); otherwise the stack's,
/// after starting what is missing. With `dry_run` nothing is started.
pub fn ensure(dry_run: bool) -> Result<Vec<(String, String)>, String> {
    if std::env::var_os("DATABASE_URL").is_some() {
        return Ok(Vec::new());
    }
    let missing = to_start(port_open);
    if dry_run {
        for service in &missing {
            crate::say(&format!(
                "would start {} ({}) on port {}",
                service.container, service.image, service.host_port
            ));
        }
        return Ok(stack_env());
    }
    for service in &missing {
        crate::say(&format!(
            "attome test: starting {} on port {}",
            service.container, service.host_port
        ));
        start(service)?;
    }
    wait_ready(Duration::from_secs(90))?;
    Ok(stack_env())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_block_matches_testkit_names() {
        let names: Vec<String> = stack_env().into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            names,
            [
                "DATABASE_URL",
                "TEST_REDIS_HOST",
                "TEST_REDIS_PORT",
                "REDIS_URL"
            ]
        );
        // The ports in the URLs are the ports the containers publish.
        let env = stack_env();
        for service in SERVICES {
            assert!(
                env.iter()
                    .any(|(_, value)| value.contains(&service.host_port.to_string())),
                "{} port {} is not in the environment",
                service.container,
                service.host_port
            );
        }
    }

    #[test]
    fn an_open_port_is_reused_not_restarted() {
        let missing = to_start(|port| port == 5556);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].container, "attome-test-redis");
        assert_eq!(to_start(|_| true), Vec::new());
    }
}
