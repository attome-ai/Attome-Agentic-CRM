//! The sizing check `attome init` runs before it installs (roadmap U1-T3):
//! CPU, memory, free disk and the HTTP port against the Solo minimums.
//!
//! Below a minimum is a warning, because a small machine can still run a
//! small deployment; only free disk under [`REFUSE_DISK_BYTES`] refuses, since
//! PostgreSQL then fills the disk within days. A value the platform does not
//! report is said to be unknown, never guessed.
//!
//! The readings use the standard library, `/proc/meminfo` and `df` on Linux,
//! and PowerShell on Windows, so no platform-specific crate is needed
//! (V2-D471).

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;

const GIB: u64 = 1024 * 1024 * 1024;

/// The Solo profile's minimums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Minimum {
    pub cpus: u32,
    pub ram_bytes: u64,
    pub free_disk_bytes: u64,
}

/// Solo: 2 CPUs, 4 GB of memory, 20 GB of free disk.
pub const SOLO: Minimum = Minimum {
    cpus: 2,
    ram_bytes: 4 * GIB,
    free_disk_bytes: 20 * GIB,
};

/// Free disk below which `attome init` refuses to install.
pub const REFUSE_DISK_BYTES: u64 = 5 * GIB;

/// What the machine reports; `None` when it could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Readings {
    pub cpus: Option<u32>,
    pub ram_bytes: Option<u64>,
    pub free_disk_bytes: Option<u64>,
    pub port_free: Option<bool>,
}

/// One finding of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Below a minimum, or unknown; the install goes on.
    Warn(String),
    /// The install stops.
    Refuse(String),
}

fn gib(bytes: u64) -> String {
    // One decimal is enough for a sizing message.
    format!("{:.1} GB", bytes as f64 / GIB as f64)
}

/// Judges the readings against `minimum`. Pure, so tests can feed it any
/// machine.
pub fn judge(readings: &Readings, minimum: &Minimum, port: u16) -> Vec<Finding> {
    let mut findings = Vec::new();
    match readings.cpus {
        Some(cpus) if cpus < minimum.cpus => findings.push(Finding::Warn(format!(
            "{cpus} CPU(s); Solo wants at least {}",
            minimum.cpus
        ))),
        Some(_) => {}
        None => findings.push(Finding::Warn("the CPU count could not be read".to_owned())),
    }
    match readings.ram_bytes {
        Some(ram) if ram < minimum.ram_bytes => findings.push(Finding::Warn(format!(
            "{} of memory; Solo wants at least {}",
            gib(ram),
            gib(minimum.ram_bytes)
        ))),
        Some(_) => {}
        None => findings.push(Finding::Warn(
            "the memory size could not be read".to_owned(),
        )),
    }
    match readings.free_disk_bytes {
        Some(free) if free < REFUSE_DISK_BYTES => findings.push(Finding::Refuse(format!(
            "only {} of free disk; at least {} is needed to install, and Solo wants {}",
            gib(free),
            gib(REFUSE_DISK_BYTES),
            gib(minimum.free_disk_bytes)
        ))),
        Some(free) if free < minimum.free_disk_bytes => findings.push(Finding::Warn(format!(
            "{} of free disk; Solo wants at least {}",
            gib(free),
            gib(minimum.free_disk_bytes)
        ))),
        Some(_) => {}
        None => findings.push(Finding::Warn(
            "the free disk space could not be read".to_owned(),
        )),
    }
    if readings.port_free == Some(false) {
        findings.push(Finding::Warn(format!(
            "port {port} is in use; stop what holds it or pass --port"
        )));
    }
    findings
}

fn command_text(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn powershell(script: &str) -> Option<String> {
    command_text(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", script],
    )
}

/// Total memory in bytes.
fn ram_bytes() -> Option<u64> {
    if cfg!(windows) {
        powershell("(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory")?
            .parse()
            .ok()
    } else {
        let text = std::fs::read_to_string("/proc/meminfo").ok()?;
        let kib: u64 = text
            .lines()
            .find(|line| line.starts_with("MemTotal:"))?
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        Some(kib * 1024)
    }
}

/// Free bytes on the volume holding `dir`.
fn free_disk_bytes(dir: &Path) -> Option<u64> {
    let dir = std::fs::canonicalize(dir).ok()?;
    if cfg!(windows) {
        // `\\?\C:\...` after canonicalize: the drive root is what DriveInfo wants.
        let text = dir.to_string_lossy().replace(r"\\?\", "");
        let root: String = text.chars().take(2).collect();
        if !root.ends_with(':') {
            return None;
        }
        powershell(&format!(
            "[System.IO.DriveInfo]::new('{root}').AvailableFreeSpace"
        ))?
        .parse()
        .ok()
    } else {
        let path = dir.to_str()?;
        let text = command_text("df", &["-Pk", path])?;
        let kib: u64 = text
            .lines()
            .nth(1)?
            .split_whitespace()
            .nth(3)?
            .parse()
            .ok()?;
        Some(kib * 1024)
    }
}

/// Reads this machine: CPUs, memory, free disk where `dir` lives, and whether
/// `port` can be bound on all interfaces.
pub fn read(dir: &Path, port: u16) -> Readings {
    Readings {
        cpus: std::thread::available_parallelism()
            .ok()
            .and_then(|n| u32::try_from(n.get()).ok()),
        ram_bytes: ram_bytes(),
        free_disk_bytes: free_disk_bytes(dir),
        port_free: Some(TcpListener::bind(("0.0.0.0", port)).is_ok()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(cpus: u32, ram_gib: u64, disk_gib: u64) -> Readings {
        Readings {
            cpus: Some(cpus),
            ram_bytes: Some(ram_gib * GIB),
            free_disk_bytes: Some(disk_gib * GIB),
            port_free: Some(true),
        }
    }

    #[test]
    fn a_machine_at_the_minimum_passes_quietly() {
        assert!(judge(&machine(2, 4, 20), &SOLO, 7865).is_empty());
    }

    #[test]
    fn below_minimum_warns_but_installs() {
        let findings = judge(&machine(1, 2, 10), &SOLO, 7865);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|f| matches!(f, Finding::Warn(_))));
    }

    #[test]
    fn under_five_gigabytes_of_disk_refuses() {
        let findings = judge(&machine(8, 16, 4), &SOLO, 7865);
        assert!(matches!(findings.as_slice(), [Finding::Refuse(text)] if text.contains("4.0 GB")));
    }

    #[test]
    fn unknown_readings_and_a_busy_port_are_said_not_guessed() {
        let readings = Readings {
            cpus: None,
            ram_bytes: None,
            free_disk_bytes: None,
            port_free: Some(false),
        };
        let findings = judge(&readings, &SOLO, 7865);
        assert_eq!(findings.len(), 4);
        assert!(findings.iter().all(|f| matches!(f, Finding::Warn(_))));
        assert!(matches!(&findings[3], Finding::Warn(text) if text.contains("7865")));
    }

    #[test]
    fn this_machine_can_be_read() {
        let readings = read(Path::new("."), 0);
        assert!(readings.cpus.is_some_and(|n| n >= 1));
    }
}
