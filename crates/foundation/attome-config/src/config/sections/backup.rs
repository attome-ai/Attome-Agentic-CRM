//! `backup` — the local database backup (roadmap U6-T1).
//!
//! On by default: every day at `hour` (UTC) the server writes a `pg_dump`
//! custom-format archive of its database to `dir` and keeps the newest
//! `keep`. The same disk as the database by default, which protects against
//! mistakes and corruption but not against losing the disk: the admin console
//! says so, and `dir` can point at a second disk or a network share.

use serde::Deserialize;

/// Days of backups kept by default.
pub const DEFAULT_KEEP: u32 = 7;
/// The hour (UTC) a backup runs by default: 02:00, outside office hours in
/// the Gulf.
pub const DEFAULT_HOUR: u32 = 2;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct BackupSection {
    /// Run the daily backup. On by default.
    pub enabled: bool,
    /// Where archives go. Unset: a `backups` folder next to the
    /// configuration file.
    pub dir: Option<String>,
    /// How many archives to keep, newest first. At least 1.
    pub keep: u32,
    /// The hour of the day (UTC, 0–23) the backup runs.
    pub hour: u32,
    /// The `pg_dump` program. Unset: `pg_dump` on the PATH.
    pub pg_dump: Option<String>,
    /// Copy the object store's files (attachments, brand assets) beside
    /// each database backup. On by default.
    pub files: bool,
}

impl Default for BackupSection {
    fn default() -> Self {
        Self {
            enabled: true,
            dir: None,
            keep: DEFAULT_KEEP,
            hour: DEFAULT_HOUR,
            pg_dump: None,
            files: true,
        }
    }
}

impl BackupSection {
    /// Where backups go: `dir`, or a `backups` folder next to the
    /// configuration file.
    pub fn resolved_dir(&self) -> std::path::PathBuf {
        match self.dir.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
            Some(dir) => std::path::PathBuf::from(dir),
            None => {
                let config_file = std::path::PathBuf::from(crate::AppConfig::config_file_path());
                config_file
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new("."))
                    .join("backups")
            }
        }
    }

    /// Shape check run by `AppConfig::validate`.
    pub fn check(&self) -> Result<(), (String, String)> {
        if self.hour > 23 {
            return Err((
                "backup.hour".into(),
                format!("must be an hour from 0 to 23, got {}", self.hour),
            ));
        }
        if self.keep == 0 {
            return Err(("backup.keep".into(), "must keep at least 1 backup".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_on_daily_and_checked() {
        let section = BackupSection::default();
        assert!(section.enabled);
        assert!(section.files);
        assert_eq!((section.keep, section.hour), (DEFAULT_KEEP, DEFAULT_HOUR));
        assert!(section.check().is_ok());
        let bad_hour = BackupSection {
            hour: 24,
            ..BackupSection::default()
        };
        assert_eq!(bad_hour.check().unwrap_err().0, "backup.hour");
        let none_kept = BackupSection {
            keep: 0,
            ..BackupSection::default()
        };
        assert_eq!(none_kept.check().unwrap_err().0, "backup.keep");
    }
}
