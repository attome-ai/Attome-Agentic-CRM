//! `attome service install|uninstall` (roadmap U1-T1): run `attome serve` as
//! an operating-system service, so a Solo deployment starts with the machine.
//!
//! ```text
//! attome init --database-url postgres://... --out <dir>/config.json
//! attome service install [--dir <dir>] [--dry-run]
//! attome service uninstall [--dry-run]
//! ```
//!
//! `<dir>` holds `config.json` and is the service's working directory; it
//! defaults to `%ProgramData%\Attome` on Windows and `/var/lib/attome` on
//! Linux.
//!
//! - **Windows:** registers the `attome` service (automatic start, the local
//!   system account) running `attome service-run <dir>`, which reports to the
//!   service control manager and maps its Stop and Shutdown to the same
//!   graceful drain as Ctrl+C. Needs an elevated prompt.
//! - **Linux:** writes `/etc/systemd/system/attome.service` running
//!   `attome serve` in `<dir>`, then `systemctl daemon-reload` and
//!   `systemctl enable --now attome`. Needs root. Under `/var/lib` the unit
//!   uses a systemd dynamic user that owns the directory; elsewhere it runs as
//!   root, which the unit says.
//!
//! `--dry-run` prints what would be done and changes nothing.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The service's name on both systems.
pub const SERVICE_NAME: &str = "attome";
const DISPLAY_NAME: &str = "Attome";
const DESCRIPTION: &str = "Attome CRM server (attome serve)";
const UNIT_PATH: &str = "/etc/systemd/system/attome.service";

const USAGE: &str = "\
attome service: run attome serve as an operating-system service

Usage:
  attome service install [--dir <dir>] [--dry-run]
  attome service uninstall [--dry-run]

  --dir      the directory holding config.json (from `attome init --out`);
             default %ProgramData%\\Attome on Windows, /var/lib/attome on Linux
  --dry-run  print the steps and change nothing
";

/// The default data directory for this operating system.
pub fn default_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
        base.join("Attome")
    } else {
        PathBuf::from("/var/lib/attome")
    }
}

/// The systemd unit for `exe` serving from `dir`.
pub fn systemd_unit(exe: &Path, dir: &Path) -> String {
    let user = match dir.strip_prefix("/var/lib") {
        Ok(state) if !state.as_os_str().is_empty() => format!(
            "# systemd creates a user for the service and gives it {dir}.\n\
             DynamicUser=yes\nStateDirectory={}\n",
            state.display(),
            dir = dir.display()
        ),
        _ => "# Runs as root because the data directory is outside /var/lib; move it\n\
              # there (attome service install --dir /var/lib/attome) for a dynamic user.\n\
              User=root\n"
            .to_owned(),
    };
    format!(
        "# Written by `attome service install`. Remove with `attome service uninstall`.\n\
         [Unit]\n\
         Description={DESCRIPTION}\n\
         After=network-online.target postgresql.service\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         {user}\
         WorkingDirectory={dir}\n\
         ExecStart={exe} serve\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         # SIGTERM starts the graceful drain; allow it to finish.\n\
         KillSignal=SIGTERM\n\
         TimeoutStopSec=90\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        dir = dir.display(),
        exe = exe.display(),
    )
}

/// The arguments the Windows service control manager starts the binary with.
pub fn windows_launch_arguments(dir: &Path) -> Vec<String> {
    vec!["service-run".to_owned(), dir.display().to_string()]
}

/// What `install` does, in order, for printing.
pub fn install_steps(exe: &Path, dir: &Path) -> Vec<String> {
    if cfg!(windows) {
        vec![
            format!(
                "register the Windows service `{SERVICE_NAME}` ({DISPLAY_NAME}): automatic start, \
                 local system account, `{} {}`",
                exe.display(),
                windows_launch_arguments(dir).join(" ")
            ),
            format!("start `{SERVICE_NAME}`"),
        ]
    } else {
        vec![
            format!("write {UNIT_PATH}"),
            "systemctl daemon-reload".to_owned(),
            format!("systemctl enable --now {SERVICE_NAME}"),
        ]
    }
}

fn say(text: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stdout().lock(), "{text}");
}

fn run_command(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} {} exited with {status}", args.join(" ")))
    }
}

fn install(dir: &Path, dry_run: bool) -> Result<(), String> {
    let exe =
        std::env::current_exe().map_err(|error| format!("cannot find this binary: {error}"))?;
    if !dir.join("config.json").is_file() {
        return Err(format!(
            "{} has no config.json; run `attome init --database-url <url> --out {}` first",
            dir.display(),
            dir.join("config.json").display()
        ));
    }
    let dir = std::fs::canonicalize(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    // `canonicalize` gives `\\?\C:\...` on Windows; the service needs the plain form.
    let dir = PathBuf::from(dir.display().to_string().replace(r"\\?\", ""));
    for step in install_steps(&exe, &dir) {
        say(&format!("{}{step}", if dry_run { "would " } else { "" }));
    }
    if dry_run {
        return Ok(());
    }
    if cfg!(windows) {
        windows::install(&exe, &dir)
    } else {
        std::fs::write(UNIT_PATH, systemd_unit(&exe, &dir))
            .map_err(|error| format!("{UNIT_PATH}: {error} (run as root)"))?;
        run_command("systemctl", &["daemon-reload"])?;
        run_command("systemctl", &["enable", "--now", SERVICE_NAME])
    }
}

fn uninstall(dry_run: bool) -> Result<(), String> {
    let steps: Vec<String> = if cfg!(windows) {
        vec![format!(
            "stop and delete the Windows service `{SERVICE_NAME}`"
        )]
    } else {
        vec![
            format!("systemctl disable --now {SERVICE_NAME}"),
            format!("remove {UNIT_PATH}"),
            "systemctl daemon-reload".to_owned(),
        ]
    };
    for step in steps {
        say(&format!("{}{step}", if dry_run { "would " } else { "" }));
    }
    if dry_run {
        return Ok(());
    }
    if cfg!(windows) {
        windows::uninstall()
    } else {
        run_command("systemctl", &["disable", "--now", SERVICE_NAME])?;
        std::fs::remove_file(UNIT_PATH).map_err(|error| format!("{UNIT_PATH}: {error}"))?;
        run_command("systemctl", &["daemon-reload"])
    }
}

/// `attome service ...`, from the arguments after `service`.
pub fn run(args: &[String]) -> Result<(), String> {
    let mut dir = default_dir();
    let mut dry_run = false;
    let (command, rest) = args.split_first().ok_or_else(|| USAGE.to_owned())?;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--dir" => dir = PathBuf::from(it.next().ok_or("--dir needs a value")?),
            "--dry-run" => dry_run = true,
            _ => return Err(format!("unknown option `{arg}`\n\n{USAGE}")),
        }
    }
    match command.as_str() {
        "install" => install(&dir, dry_run),
        "uninstall" => uninstall(dry_run),
        _ => Err(USAGE.to_owned()),
    }
}

/// `attome service-run <dir>`: what the Windows service control manager
/// starts. Elsewhere it refuses: systemd runs `attome serve` directly.
pub fn service_run(args: &[String]) -> Result<(), String> {
    let [dir] = args else {
        return Err("usage: attome service-run <dir>".to_owned());
    };
    if cfg!(windows) {
        windows::run_dispatcher(Path::new(dir))
    } else {
        Err(
            "attome service-run is for the Windows service control manager; \
             on Linux the systemd unit runs `attome serve`"
                .to_owned(),
        )
    }
}

#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "windows_service::define_windows_service! expands to the extern \"system\" entry \
              point the service control manager calls; the crate parses its arguments inside \
              an unsafe block it owns"
)]
mod windows {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;
    use std::time::Duration;

    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::{DESCRIPTION, DISPLAY_NAME, SERVICE_NAME};

    /// The data directory `service-run` was given, for the service thread.
    static DIR: OnceLock<PathBuf> = OnceLock::new();

    windows_service::define_windows_service!(ffi_service_main, service_main);

    pub fn install(exe: &Path, dir: &Path) -> Result<(), String> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|error| format!("cannot open the service manager (run elevated): {error}"))?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.to_path_buf(),
            launch_arguments: super::windows_launch_arguments(dir)
                .into_iter()
                .map(OsString::from)
                .collect(),
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .map_err(|error| format!("cannot create the service: {error}"))?;
        service
            .set_description(DESCRIPTION)
            .map_err(|error| format!("cannot describe the service: {error}"))?;
        service
            .start::<&str>(&[])
            .map_err(|error| format!("the service was created but did not start: {error}"))
    }

    pub fn uninstall() -> Result<(), String> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|error| {
            format!("cannot open the service manager (run elevated): {error}")
        })?;
        let service = manager
            .open_service(
                SERVICE_NAME,
                ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
            )
            .map_err(|error| format!("cannot open the service: {error}"))?;
        let status = service
            .query_status()
            .map_err(|error| format!("cannot query the service: {error}"))?;
        if status.current_state != ServiceState::Stopped {
            service
                .stop()
                .map_err(|error| format!("cannot stop the service: {error}"))?;
        }
        service
            .delete()
            .map_err(|error| format!("cannot delete the service: {error}"))
    }

    pub fn run_dispatcher(dir: &Path) -> Result<(), String> {
        let _ = DIR.set(dir.to_path_buf());
        windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|error| format!("not started by the service control manager: {error}"))
    }

    fn status(state: ServiceState, exit: u32) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(exit),
            checkpoint: 0,
            wait_hint: if state == ServiceState::StopPending {
                Duration::from_secs(90)
            } else {
                Duration::default()
            },
            process_id: None,
        }
    }

    fn service_main(_arguments: Vec<OsString>) {
        let handler = |control| match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                crate::boot::request_stop();
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(handle) = service_control_handler::register(SERVICE_NAME, handler) else {
            return;
        };
        // `attome serve` reads config.json from its working directory.
        if let Some(dir) = DIR.get()
            && std::env::set_current_dir(dir).is_err()
        {
            let _ = handle.set_service_status(status(ServiceState::Stopped, 1));
            return;
        }
        let _ = handle.set_service_status(status(ServiceState::Running, 0));
        let exit = match crate::serve::run() {
            Ok(()) => 0,
            Err(error) => {
                tracing::error!(error = %error, "attome serve stopped with an error");
                1
            }
        };
        let _ = handle.set_service_status(status(ServiceState::Stopped, exit));
    }
}

#[cfg(not(windows))]
mod windows {
    use std::path::Path;

    pub fn install(_exe: &Path, _dir: &Path) -> Result<(), String> {
        Err("Windows only".to_owned())
    }

    pub fn uninstall() -> Result<(), String> {
        Err("Windows only".to_owned())
    }

    pub fn run_dispatcher(_dir: &Path) -> Result<(), String> {
        Err("Windows only".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_under_var_lib_uses_a_dynamic_user() {
        let unit = systemd_unit(
            Path::new("/usr/local/bin/attome"),
            Path::new("/var/lib/attome"),
        );
        assert!(unit.contains("ExecStart=/usr/local/bin/attome serve\n"));
        assert!(unit.contains("WorkingDirectory=/var/lib/attome\n"));
        assert!(unit.contains("DynamicUser=yes\nStateDirectory=attome\n"));
        assert!(!unit.contains("User=root"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn unit_elsewhere_runs_as_root_and_says_so() {
        let unit = systemd_unit(Path::new("/opt/attome/attome"), Path::new("/opt/attome"));
        assert!(unit.contains("User=root\n"));
        assert!(!unit.contains("DynamicUser"));
    }

    #[test]
    fn the_windows_service_runs_service_run_with_the_directory() {
        assert_eq!(
            windows_launch_arguments(Path::new(r"C:\ProgramData\Attome")),
            ["service-run", r"C:\ProgramData\Attome"]
        );
        assert!(!install_steps(Path::new("attome"), Path::new("d")).is_empty());
    }

    #[test]
    fn unknown_subcommands_and_options_are_refused() {
        assert!(run(&[]).is_err());
        assert!(run(&["restart".to_owned()]).is_err());
        assert!(run(&["install".to_owned(), "--nope".to_owned()]).is_err());
        assert!(service_run(&[]).is_err());
    }
}
