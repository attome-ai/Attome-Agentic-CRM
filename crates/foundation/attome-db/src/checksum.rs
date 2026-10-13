use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};
use sqlx::migrate::Migrator;
use thiserror::Error;

/// Boot-time defense-in-depth for P-migration-immutability (D-127).
///
/// `crates/apps/attome/migrations/checksums.sha256` is enforced only here: there is
/// no CI, no git hook and no repo check script (D-767, D-768), so nothing checks
/// it before a binary boots. sqlx's own `_sqlx_migrations` checksum comparison (inside
/// `Migrator::run`) is real, but it only catches tampering on a database that
/// has *already* applied that migration version — a fresh customer database
/// (D-002: one dedicated database per customer) has no prior row to compare
/// against, so a tampered-but-never-applied "frozen" migration would silently
/// apply on first install if that gate were ever skipped. This closes that gap
/// without needing a database connection at all: it compares the migrations
/// actually compiled into this binary against a compiled-in copy of the
/// frozen baseline text, using this platform's own SHA-256 over each
/// migration's SQL text — not `sqlx::migrate::Migration`'s own internal
/// checksum, which uses a different algorithm and is not part of its public
/// contract to rely on bit-for-bit.
///
/// attome-db has zero deployment-path knowledge (guidelines §1) — the caller
/// (`crates/server`, which owns `migrations/`) must load the baseline text
/// itself via `include_str!` and pass it in, same reasoning as
/// [`crate::run_migrations`] taking an already-built `Migrator` instead of
/// calling `sqlx::migrate!` itself.
///
/// A baseline entry naming a migration this binary was not built with
/// (`MissingFromBuild`) or whose compiled SQL no longer matches the frozen
/// hash (`Mismatch`) both fail closed — the caller should refuse to boot
/// (D-038: security controls fail closed). A migration compiled into this
/// binary but *absent* from the baseline is not a boot error, on purpose:
/// coverage is the migration author's job — each new migration gets its line,
/// `sha256sum --text NNNN_name.sql >> checksums.sha256` run in
/// `crates/apps/attome/migrations` (D-306; no script checks it since D-768) — and
/// **this binary owns tamper detection** (D-127). An uncovered migration is instead logged
/// once, at `warn` (`event = "db.migration.uncovered"`), so the gap is visible
/// without failing a deploy.
///
/// An **empty** baseline, by contrast, is refused when this build compiled at
/// least one migration (BDB-F4, OD-3): header-only text disables tamper
/// detection for every migration at once, which is exactly the silently absent
/// safety net D-127 exists to prevent. A build with no compiled migrations
/// still passes a zero-migration fixture.
pub fn verify_migration_checksums(
    migrator: &Migrator,
    baseline: &str,
) -> Result<(), ChecksumError> {
    verify_checksums(
        baseline,
        migrator.iter().map(|m| (m.version, m.sql.as_bytes())),
    )?;
    warn_uncovered(migrator, baseline)
}

/// One `warn` per migration compiled into this binary without a baseline
/// line, naming the regeneration command. Not an error: the local gate owns
/// coverage (D-306), the binary owns tampering (D-127) — but an operator should
/// not have to wait for the gate to learn a migration was never frozen.
fn warn_uncovered(migrator: &Migrator, baseline: &str) -> Result<(), ChecksumError> {
    let watched: HashSet<i64> = parse_baseline(baseline)?
        .into_iter()
        .map(|entry| entry.version)
        .collect();
    for migration in migrator.iter() {
        if !watched.contains(&migration.version) {
            tracing::warn!(
                event = "db.migration.uncovered",
                version = migration.version,
                description = %migration.description,
                "migration is compiled into this binary but has no entry in \
                 crates/apps/attome/migrations/checksums.sha256; append it with \
                 `sha256sum --text <file>.sql >> checksums.sha256` in that directory"
            );
        }
    }
    Ok(())
}

fn verify_checksums<'a>(
    baseline: &str,
    compiled: impl Iterator<Item = (i64, &'a [u8])>,
) -> Result<(), ChecksumError> {
    let entries = parse_baseline(baseline)?;
    let compiled: HashMap<i64, &[u8]> = compiled.collect();
    if entries.is_empty() {
        // BDB-F4 / OD-3: header-only text would disable tamper detection for
        // every migration at once. Only a build with nothing to check passes.
        if compiled.is_empty() {
            return Ok(());
        }
        return Err(ChecksumError::EmptyBaseline {
            migrations: compiled.len(),
        });
    }
    for entry in &entries {
        let Some(sql_bytes) = compiled.get(&entry.version) else {
            return Err(ChecksumError::MissingFromBuild {
                filename: entry.filename.clone(),
            });
        };
        let actual = hex_sha256(sql_bytes);
        if actual != entry.expected_hex {
            return Err(ChecksumError::Mismatch {
                filename: entry.filename.clone(),
                expected: entry.expected_hex.clone(),
                actual,
            });
        }
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct BaselineEntry {
    version: i64,
    filename: String,
    expected_hex: String,
}

/// Parses `checksums.sha256`'s format: standard `sha256sum` text-mode output
/// (`<64-hex-char-digest><two spaces><filename>`), `#`-prefixed comment lines
/// and blank lines ignored. The migration's `version` is derived from the
/// filename's own leading digits (up to the first `_`), the same convention
/// `sqlx::migrate!`'s directory resolver itself requires
/// (`NNNN_description.sql`), rather than assuming a fixed zero-padding width.
///
/// A binary-mode `sha256sum` line (`<digest> *<filename>`) is rejected with
/// its own error (attome-db hardening Phase 3.4). It is still refused, because
/// CI's migration-freeze coverage check (`awk '{print $2}'`) would read its
/// filename as `*<filename>` and report the migration unfrozen, but the error
/// says how to fix it instead of just "malformed".
fn parse_baseline(baseline: &str) -> Result<Vec<BaselineEntry>, ChecksumError> {
    let mut entries = Vec::new();
    for (idx, raw_line) in baseline.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line_no = idx + 1;
        if let Some((hex, rest)) = line.split_once(' ')
            && rest.starts_with('*')
            && hex.len() == 64
            && hex.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ChecksumError::BinaryModeBaseline { line: line_no });
        }
        let mut parts = line.splitn(2, "  ");
        let hex = parts.next().unwrap_or_default();
        let filename = parts
            .next()
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .ok_or(ChecksumError::MalformedBaseline { line: line_no })?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ChecksumError::MalformedBaseline { line: line_no });
        }
        let version = filename
            .split('_')
            .next()
            .and_then(|v| v.parse::<i64>().ok())
            .ok_or(ChecksumError::MalformedBaseline { line: line_no })?;
        entries.push(BaselineEntry {
            version,
            filename: filename.to_string(),
            expected_hex: hex.to_ascii_lowercase(),
        });
    }
    Ok(entries)
}

#[derive(Debug, Error)]
pub enum ChecksumError {
    #[error(
        "migration checksum baseline line {line} is malformed — expected \
         '<64-hex-char-sha256>  <filename>'"
    )]
    MalformedBaseline { line: usize },

    #[error(
        "migration checksum baseline line {line} is a binary-mode sha256sum line \
         ('<sha256> *<filename>') — regenerate it with `sha256sum --text`, which writes \
         '<sha256>  <filename>' (two spaces)"
    )]
    BinaryModeBaseline { line: usize },

    #[error(
        "the migration checksum baseline (crates/apps/attome/migrations/checksums.sha256) has no \
         entries, but this build compiled {migrations} migration(s) — an empty baseline \
         disables tamper detection for all of them; restore the frozen file from git and \
         retry; refusing to boot"
    )]
    EmptyBaseline { migrations: usize },

    #[error(
        "migration {filename} is recorded in the frozen checksum baseline \
         (crates/apps/attome/migrations/checksums.sha256) but is not present in this build's \
         compiled migrations — a frozen migration was deleted or renumbered (P-migration-\
         immutability, D-127); refusing to boot"
    )]
    MissingFromBuild { filename: String },

    #[error(
        "migration {filename} does not match its frozen checksum baseline (expected \
         {expected}, got {actual}) — its contents changed after being frozen (P-migration-\
         immutability, D-127); refusing to boot rather than silently applying tampered SQL"
    )]
    Mismatch {
        filename: String,
        expected: String,
        actual: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const SQL: &[u8] = b"CREATE TABLE test (id INT);\n";
    // sha256sum of SQL above, computed independently of this crate.
    const SQL_SHA256: &str = "9b29b2b613f98d10c6b10ddde2a77b9e9070592ed02b5de31ae2e91b4e8f13e7";

    #[test]
    fn matching_checksum_passes() {
        let baseline = format!("{SQL_SHA256}  0000_test.sql\n");
        let compiled = vec![(0i64, SQL)];
        assert!(verify_checksums(&baseline, compiled.into_iter()).is_ok());
    }

    #[test]
    fn header_comments_and_blank_lines_are_ignored() {
        let baseline = format!(
            "# Immutable migration baseline.\n\
             # Existing entries may never be changed or removed.\n\
             \n\
             {SQL_SHA256}  0000_test.sql\n"
        );
        let compiled = vec![(0i64, SQL)];
        assert!(verify_checksums(&baseline, compiled.into_iter()).is_ok());
    }

    #[test]
    fn tampered_migration_fails_closed() {
        let baseline = format!("{SQL_SHA256}  0000_test.sql\n");
        let tampered: &[u8] = b"CREATE TABLE test (id INT); -- extra\n";
        let compiled = vec![(0i64, tampered)];
        let err = verify_checksums(&baseline, compiled.into_iter()).unwrap_err();
        assert!(matches!(err, ChecksumError::Mismatch { .. }));
        assert!(err.to_string().contains("0000_test.sql"));
    }

    #[test]
    fn frozen_migration_missing_from_build_fails_closed() {
        let baseline = format!("{SQL_SHA256}  0000_test.sql\n");
        let compiled: Vec<(i64, &[u8])> = vec![];
        let err = verify_checksums(&baseline, compiled.into_iter()).unwrap_err();
        assert!(matches!(err, ChecksumError::MissingFromBuild { .. }));
        assert!(err.to_string().contains("0000_test.sql"));
    }

    #[test]
    fn migrations_absent_from_baseline_are_not_an_error() {
        // A migration compiled into this build but missing from
        // checksums.sha256 must not block boot: the checksum script owns coverage (D-306's
        // per-file migration-freeze job), and this check owns tamper
        // detection only (D-127).
        let baseline = format!("{SQL_SHA256}  0000_test.sql\n");
        let newer: &[u8] = b"CREATE TABLE newer (id INT);\n";
        let compiled = vec![(0i64, SQL), (1i64, newer)];
        assert!(verify_checksums(&baseline, compiled.into_iter()).is_ok());
    }

    // BDB-F4 (OD-3) — an empty baseline disables tamper detection for every
    // migration at once, so a build with anything to check must refuse it.
    #[test]
    fn empty_baseline_with_migrations_is_refused() {
        let compiled = vec![(0i64, SQL)];
        let err = verify_checksums("# frozen baseline\n\n", compiled.into_iter())
            .expect_err("an empty baseline must be refused, not pass trivially");
        assert!(
            matches!(err, ChecksumError::EmptyBaseline { migrations: 1 }),
            "{err:?}"
        );
        assert!(err.to_string().contains("refusing to boot"), "{err}");
    }

    #[test]
    fn empty_baseline_with_zero_migrations_still_passes() {
        let compiled: Vec<(i64, &[u8])> = vec![];
        assert!(verify_checksums("", compiled.into_iter()).is_ok());
    }

    #[test]
    fn uppercase_hex_in_baseline_still_matches() {
        let baseline = format!("{}  0000_test.sql\n", SQL_SHA256.to_ascii_uppercase());
        let compiled = vec![(0i64, SQL)];
        assert!(verify_checksums(&baseline, compiled.into_iter()).is_ok());
    }

    #[test]
    fn malformed_hex_length_is_rejected() {
        let baseline = "deadbeef  0000_test.sql\n";
        let compiled = vec![(0i64, SQL)];
        let err = verify_checksums(baseline, compiled.into_iter()).unwrap_err();
        assert!(matches!(err, ChecksumError::MalformedBaseline { line: 1 }));
    }

    #[test]
    fn line_without_filename_is_rejected() {
        let baseline = format!("{SQL_SHA256}\n");
        let compiled = vec![(0i64, SQL)];
        let err = verify_checksums(&baseline, compiled.into_iter()).unwrap_err();
        assert!(matches!(err, ChecksumError::MalformedBaseline { line: 1 }));
    }

    /// Base-db hardening Phase 3.4 — a binary-mode `sha256sum` line
    /// (`<digest> *<file>`) is still refused, but with an error naming the
    /// fix, and on the right line number.
    #[test]
    fn binary_mode_line_is_refused_with_a_specific_error() {
        let baseline = format!("# header\n{SQL_SHA256} *0000_test.sql\n");
        let compiled = vec![(0i64, SQL)];
        let err = verify_checksums(&baseline, compiled.into_iter()).unwrap_err();
        assert!(
            matches!(err, ChecksumError::BinaryModeBaseline { line: 2 }),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("sha256sum --text"),
            "the error must say how to regenerate the line: {err}"
        );
    }

    /// Only the full `<64 hex> *<file>` shape counts as binary mode; anything
    /// else that fails to parse stays the generic malformed-line error.
    #[test]
    fn a_short_digest_with_a_star_is_still_just_malformed() {
        let baseline = "deadbeef *0000_test.sql\n";
        let compiled = vec![(0i64, SQL)];
        let err = verify_checksums(baseline, compiled.into_iter()).unwrap_err();
        assert!(
            matches!(err, ChecksumError::MalformedBaseline { line: 1 }),
            "{err:?}"
        );
    }

    #[test]
    fn version_is_parsed_from_leading_digits_not_fixed_width() {
        // Not every future migration is guaranteed 4-digit-padded forever;
        // the parser must key off the filename's own leading-digit run.
        let baseline = format!("{SQL_SHA256}  42_test.sql\n");
        let compiled = vec![(42i64, SQL)];
        assert!(verify_checksums(&baseline, compiled.into_iter()).is_ok());
    }
}
