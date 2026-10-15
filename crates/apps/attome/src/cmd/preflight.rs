//! Deployment preflight — a one-shot, read-only diagnostic an operator runs
//! before starting `migrate`/`server`/`worker` against a real deployment. It
//! writes nothing: no schema, no migration, no object, no row.
//!
//! **One check attempts a mutation it expects to be refused** (D-352): the
//! audit-anchor append-only probe issues a `DELETE` against a reserved key
//! that never holds an anchor, and *passes only when the store denies it*.
//! Against a correctly configured deployment nothing is deleted, because
//! nothing is permitted and nothing was ever there. Against a misconfigured
//! one — the case this binary exists to catch — a versioned bucket records a
//! delete marker over a key that never had an object under it. There is no
//! read-only way to prove a credential *lacks* a permission; asserting that
//! the anchor writer cannot delete its own anchors is worth that artifact.
//! See `attome_audit::anchor::ANCHOR_APPEND_ONLY_PROBE_KEY`.
//!
//! Checks three classes of thing, in order:
//!   1. Everything `AppConfig::validate()` already checks (env vars resolved,
//!      no leftover `__TODO__` template placeholders, production-profile
//!      safety rules) — reused verbatim, not reimplemented.
//!   2. File checks — that `CONFIG_FILE` itself resolves to a regular file
//!      (not the empty directory Docker leaves at a bind-mount target whose
//!      host-side file is missing), and that the TLS CA cert paths named by
//!      config exist as files. Deliberately NOT part of
//!      `AppConfig::validate()`, which does no I/O by design — this binary is
//!      the dedicated, I/O-permitted place for that check instead of skipping
//!      it.
//!   3. Live reachability for every external dependency a deployment might
//!      need: PostgreSQL, Redis/Dragonfly, S3-compatible object storage,
//!      SMTP, ClamAV. Reuses each owning crate's existing
//!      health-check function — no reimplemented connection logic.
//!
//! Exits non-zero (after printing every failing check) if any check fails;
//! exits 0 and prints a pass/fail table otherwise. Reads config exactly like
//! `server`/`migrate` do: `CONFIG_FILE` env var, or `config.json` /
//! `config.debug.json` under `APP_ENV=debug`.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

use attome_config::AppConfig;

/// `attome doctor` (U9-T4): the same checks, reported for a person, with what
/// to do about each failure.
static READABLE: AtomicBool = AtomicBool::new(false);

/// `attome doctor`: runs every preflight check and prints a readable report.
pub fn run_doctor() -> ExitCode {
    READABLE.store(true, Ordering::Relaxed);
    run()
}

/// What to do about a failed check, by its name.
pub fn advice(check: &str) -> &'static str {
    let family = check.split('.').next().unwrap_or(check);
    match (family, check) {
        (_, "config.file") => {
            "Write the configuration with `attome init`, or point CONFIG_FILE at it."
        }
        (_, "config.validate") => {
            "Fix the setting named above in the configuration file; `attome init --force` writes a fresh one."
        }
        (_, "config.unknown_keys") => "Remove or correct the misspelt keys named above.",
        ("postgres", _) | ("database", _) => {
            "Start PostgreSQL and check database.host, port, user and password in the configuration."
        }
        ("redis", _) => {
            "Start Redis or Dragonfly, or on one server set cache.backend to \"memory\" (Solo needs no Redis)."
        }
        ("storage", _) => "Check storage.s3_endpoint and its keys, and that the bucket exists.",
        ("audit", _) => {
            "Check the audit anchor store settings; the anchor writer must not be able to delete anchors."
        }
        ("smtp", _) => {
            "Check email.smtp_host, port and credentials, or set email.enabled to false."
        }
        ("secret_file", _) => {
            "Mount the secret file at the path its _FILE variable names, readable by the service account."
        }
        ("clamav", _) => {
            "Start ClamAV, or clear storage.clamd_address to turn upload scanning off."
        }
        _ => "See the detail above.",
    }
}

struct CheckResult {
    name: String,
    ok: bool,
    detail: String,
}

fn pass(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        ok: true,
        detail: detail.into(),
    }
}

fn fail(name: impl Into<String>, detail: impl Into<String>) -> CheckResult {
    CheckResult {
        name: name.into(),
        ok: false,
        detail: detail.into(),
    }
}

#[tokio::main]
pub async fn run() -> ExitCode {
    let mut results: Vec<CheckResult> = Vec::new();

    // The config file itself, before anything tries to parse it. Docker
    // creates an *empty directory* at a bind-mount target whose host-side
    // file does not exist yet — `docker-compose.yml`'s `./config.json` and
    // `./config.runtime.json` mounts do this on a fresh clone, and
    // the compose bind-mount guard covered the committed compose paths, not an
    // operator's local filesystem (and that guard was CI; it is gone). A deployment whose `CONFIG_FILE` is a
    // directory is the failure mode this binary exists to catch first
    // (F-017).
    let config_path = AppConfig::config_file_path();
    match std::fs::metadata(&config_path) {
        // `metadata` follows symlinks, so a Kubernetes/Docker secret mount
        // (a symlink farm pointing at `..data/`) passes, as it should.
        Ok(m) if m.is_file() => results.push(pass(
            "config.file",
            format!("regular file at {config_path}"),
        )),
        Ok(m) if m.is_dir() => {
            results.push(fail(
                "config.file",
                format!(
                    "{config_path} is a directory, not a file — Docker created it from a \
                     bind mount whose host-side file is missing; remove it and create the \
                     file (from config.production.example.json) before starting"
                ),
            ));
            print_report(&results);
            return ExitCode::FAILURE;
        }
        Ok(_) => {
            results.push(fail(
                "config.file",
                format!("{config_path} is not a regular file"),
            ));
            print_report(&results);
            return ExitCode::FAILURE;
        }
        Err(e) => {
            results.push(fail("config.file", format!("{config_path}: {e}")));
            print_report(&results);
            return ExitCode::FAILURE;
        }
    }

    // Z1-T5: a secret mounted as a file (`${NAME}` read through
    // `NAME_FILE`) is checked before the load that needs it, by variable
    // name only: an unreadable one otherwise surfaces as an unresolved
    // placeholder with no word about the file.
    if let Ok(text) = std::fs::read_to_string(&config_path) {
        check_secret_files(&mut results, &text);
    }

    let config = match AppConfig::from_file() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("preflight: FAILED to load config: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Everything AppConfig::validate() already enforces (env-var resolution,
    // __TODO__ placeholder rejection, production-profile rules) — reused,
    // not reimplemented. A config that fails this is not safe to probe
    // further (a placeholder database.host, for instance, would just report
    // a confusing "unreachable" instead of the real problem).
    if let Err(e) = config.validate() {
        results.push(fail("config.validate", e.to_string()));
        print_report(&results);
        return ExitCode::FAILURE;
    }
    results.push(pass(
        "config.validate",
        "no env-var/placeholder/production-profile violations",
    ));

    // BCF-10 — preflight is the fail-closed half of unknown-key reporting: a
    // typo'd key is caught here, before a rolling upgrade, instead of showing
    // up later as a setting that silently does nothing. Boot only warns,
    // because an N-1 binary must still boot on an N config during a rollback.
    if let Err(e) = attome::boot::report_ignored_config_keys(&config, true) {
        results.push(fail("config.unknown_keys", e));
        print_report(&results);
        return ExitCode::FAILURE;
    }
    results.push(pass("config.unknown_keys", "no unknown configuration keys"));

    // ── File-existence checks ────────────────────────────────────────────
    // Deliberately not part of AppConfig::validate() (no I/O there by
    // design) — this is the dedicated place for it instead of never
    // checking at all.
    check_file(
        &mut results,
        "database.ssl_root_cert",
        config.database.ssl_root_cert.as_deref(),
    );
    check_file(
        &mut results,
        "cache.tls_ca_path",
        config.cache.tls_ca_path.as_deref(),
    );
    if let Some(coordination) = &config.cache.roles.coordination {
        check_file(
            &mut results,
            "cache.roles.coordination.tls_ca_path",
            coordination.tls_ca_path.as_deref(),
        );
    }

    // ── Live dependency reachability ──────────────────────────────────────
    match attome_db::create_direct_pool(&config).await {
        Ok(pool) => {
            match sqlx::query("SELECT 1").execute(&pool).await {
                Ok(_) => {
                    results.push(pass(
                        "postgres",
                        format!(
                            "reachable at {}:{}",
                            config.database.host, config.database.port
                        ),
                    ));
                    check_metadata_natural_keys(&mut results, &pool).await;
                }
                Err(e) => results.push(fail("postgres", e.to_string())),
            }
            pool.close().await;
        }
        Err(e) => results.push(fail("postgres", e.to_string())),
    }

    // Solo keeps its shared state in process memory (A5): there is no Redis to
    // reach, and failing on one would fail every Solo install.
    let memory_backend = config.cache.backend == attome_config::CacheBackend::Memory;
    if memory_backend {
        results.push(pass(
            "redis",
            "cache.backend = memory (Solo), no Redis needed",
        ));
    }
    match (!memory_backend).then(|| attome_cache::create_redis_pool(&config)) {
        None => {}
        Some(pool) => match pool.await {
            Ok(redis) => {
                if attome_cache::redis_ping(&redis).await {
                    results.push(pass(
                        "redis",
                        format!("reachable at {}:{}", config.cache.host, config.cache.port),
                    ));
                } else {
                    results.push(fail("redis", "ping failed"));
                }
            }
            Err(e) => results.push(fail("redis", e.to_string())),
        },
    }

    // `attome init` writes `unset` credentials for a Solo install without an
    // object store: file uploads are unavailable there, which is not a
    // failure to start.
    let storage_unconfigured = config.storage.s3_access_key == "unset";
    if storage_unconfigured {
        results.push(pass(
            "storage",
            "no object store configured (s3_access_key = \"unset\"); file uploads are unavailable",
        ));
    }
    match (!storage_unconfigured).then(|| attome_storage::create_storage_client(&config)) {
        None => {}
        Some(client) => match client.await {
            Ok(client) => {
                let health = attome_storage::health_check(&client).await;
                if health.reachable {
                    results.push(pass(
                        "storage",
                        format!("reachable at {}", config.storage.s3_endpoint),
                    ));
                } else {
                    // `detail` (never serialized) keeps the full backend error for
                    // the operator; `error` is only the public-safe category.
                    results.push(fail(
                        "storage",
                        health
                            .detail
                            .or(health.error)
                            .unwrap_or_else(|| "unreachable".into()),
                    ));
                }
                // BST-8: warn-only. From inside the container the browser-facing
                // endpoint may legitimately not resolve, so this never fails preflight.
                if let Some(public) = attome_storage::public_endpoint_health_check(&client).await
                    && !public.reachable
                {
                    eprintln!(
                        "WARN storage.s3_public_endpoint ({}): {}",
                        config.storage.s3_public_endpoint,
                        public.detail.or(public.error).unwrap_or_default()
                    );
                }
            }
            Err(e) => results.push(fail("storage", e.to_string())),
        },
    }

    // ── Audit anchor store (D-352 / TODO-004) ────────────────────────────
    // The config half of this is already enforced by `config.validate()`
    // above under `deployment_profile = "production"` (an anchor_store must
    // exist, declare a real Object Lock mode, and carry its own credential).
    // What that cannot check is whether any of it is TRUE — a declaration is
    // a string in a file. These two checks probe the live store.
    if config.audit.external_anchoring_enabled {
        match attome_audit::anchor::create_anchor_store(&config).await {
            Ok(anchor) => {
                let health = attome_storage::health_check(&anchor).await;
                if health.reachable {
                    results.push(pass(
                        "audit.anchor_store",
                        format!("bucket {} reachable", anchor.bucket()),
                    ));
                    check_anchor_append_only(&mut results, &anchor).await;
                } else {
                    results.push(fail(
                        "audit.anchor_store",
                        health
                            .detail
                            .or(health.error)
                            .unwrap_or_else(|| "unreachable".into()),
                    ));
                }
            }
            Err(e) => results.push(fail("audit.anchor_store", e.to_string())),
        }

        // Echoed, never "checked" — no S3 API this codebase speaks reports a
        // bucket's Object Lock configuration, so the only honest thing to do
        // is print what the operator declared and name the drill that proves
        // it. A pass here means "you told us", not "we confirmed".
        match &config.audit.anchor_store {
            Some(anchor) => results.push(pass(
                "audit.anchor_store.object_lock",
                format!(
                    "declared {} retention, {} day(s) — DECLARATION ONLY, not verified here; \
                     prove it with scripts/audit/anchor-immutability-drill.sh",
                    anchor.object_lock_mode, anchor.object_lock_retention_days
                ),
            )),
            None => results.push(pass(
                "audit.anchor_store.object_lock",
                "no audit.anchor_store — anchors go to the general storage bucket with this \
                 application's own (delete-capable) credential. Permitted outside production \
                 only; see deploy/audit-anchor/README.md",
            )),
        }
    } else {
        results.push(pass(
            "audit.anchor_store",
            "audit.external_anchoring_enabled = false, skipped",
        ));
    }

    // BEM-6: preflight verifies credentials too, so it uses the authenticated
    // probe - the public one deliberately sends no AUTH.
    let email_health = attome_email::health_check_authenticated(
        &config.email,
        attome_email::CAPABILITY_PROBE_TIMEOUT,
    )
    .await;
    if !email_health.enabled {
        results.push(pass("smtp", "email.enabled = false, skipped"));
    } else if email_health.reachable == Some(true) {
        results.push(pass(
            "smtp",
            format!("reachable at {}", config.email.smtp_host),
        ));
    } else {
        results.push(fail(
            "smtp",
            email_health.error.unwrap_or_else(|| "unreachable".into()),
        ));
    }

    let clamd_address = config.storage.clamd_address.trim();
    if clamd_address.is_empty() {
        results.push(pass(
            "clamav",
            "storage.clamd_address not set — malware scanning disabled (uploads fail closed \
             instead, see AppConfig::validate_production_profile)",
        ));
    } else {
        let health = attome_storage::clamav_health_check(clamd_address).await;
        if health.reachable {
            results.push(pass("clamav", format!("reachable at {clamd_address}")));
        } else {
            results.push(fail(
                "clamav",
                health
                    .detail
                    .or(health.error)
                    .unwrap_or_else(|| "unreachable".into()),
            ));
        }
    }

    print_report(&results);
    if results.iter().all(|r| r.ok) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Renders `attome_audit::anchor::probe_append_only`'s verdict as a check row.
///
/// The probe itself lives in `attome-audit`, which owns both the anchor concept
/// and the `object_store` dependency; this only decides how each outcome
/// reads to an operator. `Inconclusive` fails deliberately — "the probe did
/// not conclude" must never print like "the credential is locked down".
async fn check_anchor_append_only(
    results: &mut Vec<CheckResult>,
    anchor: &attome_storage::StorageClient,
) {
    use attome_audit::anchor::AppendOnlyProbe;

    match attome_audit::anchor::probe_append_only(anchor).await {
        AppendOnlyProbe::Denied => results.push(pass(
            "audit.anchor_store.append_only",
            "DeleteObject denied to the anchor credential, as required",
        )),
        AppendOnlyProbe::Permitted => results.push(fail(
            "audit.anchor_store.append_only",
            format!(
                "the anchor credential is allowed to DELETE from bucket {} — it must hold \
                 PutObject/GetObject/ListBucket and nothing else, or every anchor it writes is \
                 erasable by whoever holds it. Attach the producer policy from \
                 deploy/audit-anchor/ and keep delete/retention authority on a separate \
                 operator identity",
                anchor.bucket()
            ),
        )),
        AppendOnlyProbe::Inconclusive(e) => results.push(fail(
            "audit.anchor_store.append_only",
            format!("probe inconclusive, treat as unproven: {e}"),
        )),
    }
}

/// Metadata natural-key duplicates (P-environment-promotion, Phase 0 step 4).
///
/// Migration `0133_metadata_natural_keys.sql` installs partial unique indexes
/// on `sql_query (entity_logical_name, record_no)` and
/// `sidebar (parent_ref, name)` over live rows. It is the one Phase-0
/// migration that can fail against a real database — if duplicates exist —
/// and a migration that fails mid-upgrade is an incident, whereas a preflight
/// that stops *before* `migrate` with the rows named is recoverable through
/// the admin API. So this runs the same two duplicate queries the indexes
/// would reject, with predicates kept identical to the index predicates
/// (including `NULLS NOT DISTINCT` for the sidebar's root items, and the
/// default distinct-NULL semantics for unnamed / entity-less queries).
///
/// Read-only. A table that does not exist yet — a fresh database that has
/// never been migrated — is reported as a pass, since there is nothing the
/// index could collide with. A query error is a *fail*: "could not check" must
/// never read like "no duplicates" (same posture as the anchor probe above).
async fn check_metadata_natural_keys(results: &mut Vec<CheckResult>, pool: &sqlx::PgPool) {
    check_duplicate_rows(
        results,
        pool,
        "metadata.natural_keys.sql_query",
        "sql_query",
        "uq_core_sql_query_entity_name (entity, name)",
        // `record_no` IS the stored query's name (0000; the admin API's
        // `name` field); `entity_logical_name` is the entity UUID. NULL or
        // empty names and NULL entities are unconstrained by the index
        // (distinct NULLs), so they are excluded here too.
        "SELECT COALESCE(e.logicalname::text, q.entity_logical_name::text), \
                q.record_no, count(*) \
         FROM sql_query q \
         LEFT JOIN entity_info e ON e.id = q.entity_logical_name \
         WHERE (q.is_active IS NULL OR q.is_active = true) \
           AND q.record_no IS NOT NULL AND q.record_no <> '' \
           AND q.entity_logical_name IS NOT NULL \
         GROUP BY 1, 2 HAVING count(*) > 1 \
         ORDER BY 1, 2",
    )
    .await;
    check_duplicate_rows(
        results,
        pool,
        "metadata.natural_keys.sidebar",
        "sidebar",
        "uq_xrm_sidebar_parent_name (parent, name)",
        // Root items have parent_ref NULL and the index is NULLS NOT
        // DISTINCT, so NULL parents group together here, as they collide
        // there. Rendered as the parent's name (or <root>) for the operator.
        "SELECT COALESCE(min(p.name), '<root>'), s.name, count(*) \
         FROM sidebar s \
         LEFT JOIN sidebar p ON p.id = s.parent_ref \
         WHERE s.is_active = true AND s.is_deleted = false \
         GROUP BY s.parent_ref, s.name HAVING count(*) > 1 \
         ORDER BY 1, 2",
    )
    .await;
}

/// One natural-key check: `duplicates_sql` must return `(scope, name, count)`
/// rows, one per key that more than one live row shares.
async fn check_duplicate_rows(
    results: &mut Vec<CheckResult>,
    pool: &sqlx::PgPool,
    check: &str,
    table: &str,
    index: &str,
    duplicates_sql: &str,
) {
    // `to_regclass` resolves through the connection's search_path (the
    // configured schema), exactly as the migration will.
    let exists: Option<bool> = match sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(pool)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            results.push(fail(check, format!("could not probe {table}: {e}")));
            return;
        }
    };
    if exists != Some(true) {
        results.push(pass(
            check,
            format!("{table} not present yet (fresh database) — nothing to collide with, skipped"),
        ));
        return;
    }

    let rows: Vec<(Option<String>, Option<String>, i64)> =
        match sqlx::query_as(duplicates_sql).fetch_all(pool).await {
            Ok(rows) => rows,
            Err(e) => {
                results.push(fail(
                    check,
                    format!("could not check {table} for duplicates, treat as unproven: {e}"),
                ));
                return;
            }
        };

    if rows.is_empty() {
        results.push(pass(
            check,
            format!("no live duplicates in {table}; migration 0133's {index} can be installed"),
        ));
        return;
    }

    let listed = rows
        .iter()
        .map(|(scope, name, count)| {
            format!(
                "({}, {}) x{count}",
                scope.as_deref().unwrap_or("<none>"),
                name.as_deref().unwrap_or("<none>")
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    results.push(fail(
        check,
        format!(
            "{} live duplicate key(s) in {table} would make migration 0133's unique index \
             {index} fail — retire or rename all but one of each through the admin API \
             (never by hand, /xrm-api-first) before running migrate: {listed}",
            rows.len()
        ),
    ));
}

/// The `${NAME}` placeholder names in a configuration's text, once each.
fn placeholder_names(text: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        rest = &rest[start + 2..];
        let Some(end) = rest.find('}') else { break };
        let name = &rest[..end];
        if !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !names.contains(&name)
        {
            names.push(name);
        }
        rest = &rest[end + 1..];
    }
    names
}

/// Z1-T5: for each placeholder read from `NAME_FILE` (its `NAME` unset),
/// whether the file can be read. Reports the variable, never the content.
fn check_secret_files(results: &mut Vec<CheckResult>, config_text: &str) {
    for name in placeholder_names(config_text) {
        if std::env::var_os(name).is_some() {
            continue;
        }
        let Some(file) = std::env::var_os(format!("{name}_FILE")) else {
            continue;
        };
        let check = format!("secret_file.{name}");
        match std::fs::read(&file) {
            Ok(_) => results.push(pass(check, format!("{name}_FILE is readable"))),
            Err(e) => results.push(fail(
                check,
                format!(
                    "{name}_FILE ({}) cannot be read: {}",
                    file.to_string_lossy(),
                    e.kind()
                ),
            )),
        }
    }
}

fn check_file(results: &mut Vec<CheckResult>, field: impl Into<String>, path: Option<&str>) {
    match path {
        None => results.push(pass(field, "not configured, skipped")),
        // Same directory trap as the `config.file` check in `main`: bare
        // existence is not enough, because `metadata` succeeds on a directory
        // and every path checked here is read as a file. Symlinks are
        // followed, so a secret-mount link to a real file still passes.
        Some(p) => match std::fs::metadata(p) {
            Ok(m) if m.is_file() => results.push(pass(field, format!("exists at {p}"))),
            Ok(_) => results.push(fail(field, format!("{p}: not a regular file"))),
            Err(e) => results.push(fail(field, format!("{p}: {e}"))),
        },
    }
}

fn print_report(results: &[CheckResult]) {
    if READABLE.load(Ordering::Relaxed) {
        print_readable(results);
        return;
    }
    println!("preflight report:");
    for r in results {
        println!(
            "  [{}] {:<40} {}",
            if r.ok { "OK  " } else { "FAIL" },
            r.name,
            r.detail
        );
    }
    let failed = results.iter().filter(|r| !r.ok).count();
    if failed == 0 {
        println!("all {} checks passed", results.len());
    } else {
        println!("{failed}/{} checks FAILED", results.len());
    }
}

/// The doctor's report: every check on its own line, and under each failure
/// what to do.
fn print_readable(results: &[CheckResult]) {
    println!("attome doctor\n");
    for r in results {
        if r.ok {
            println!("  ok   {}: {}", r.name, r.detail);
        } else {
            println!("  fix  {}: {}", r.name, r.detail);
            println!("       -> {}", advice(&r.name));
        }
    }
    let failed = results.iter().filter(|r| !r.ok).count();
    if failed == 0 {
        println!(
            "\nEverything checked is in order ({} checks).",
            results.len()
        );
    } else {
        println!(
            "\n{failed} of {} checks need attention. Fix them and run `attome doctor` again.",
            results.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_known_check_has_specific_advice() {
        for check in [
            "config.file",
            "config.validate",
            "config.unknown_keys",
            "postgres",
            "redis",
            "storage",
            "audit.anchor_store",
            "smtp",
            "clamav",
        ] {
            assert_ne!(advice(check), "See the detail above.", "{check}");
        }
        assert_eq!(advice("something.new"), "See the detail above.");
    }

    /// Every temp path is UUID-suffixed: these run in the same process, in
    /// parallel, under a shared system temp directory.
    fn temp_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("preflight-{label}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn placeholder_names_are_listed_once_each() {
        let text = r#"{"a": "${DB_PASSWORD}", "b": "x${JWT_SECRET}y", "c": "${DB_PASSWORD}", "d": "${not ok}"}"#;
        assert_eq!(placeholder_names(text), ["DB_PASSWORD", "JWT_SECRET"]);
    }

    #[test]
    fn check_file_passes_for_a_regular_file() {
        let p = temp_path("file");
        std::fs::write(&p, b"-----BEGIN CERTIFICATE-----").expect("write temp file");

        let mut results = Vec::new();
        check_file(&mut results, "database.ssl_root_cert", p.to_str());
        let _ = std::fs::remove_file(&p);

        assert_eq!(results.len(), 1);
        assert!(results[0].ok, "detail: {}", results[0].detail);
    }

    /// F-017: `metadata` succeeds on a directory, so the old bare-existence
    /// check reported OK for exactly the artifact Docker leaves behind when a
    /// bind-mounted file is missing on the host.
    #[test]
    fn check_file_fails_for_a_directory() {
        let p = temp_path("dir");
        std::fs::create_dir(&p).expect("create temp dir");

        let mut results = Vec::new();
        check_file(&mut results, "database.ssl_root_cert", p.to_str());
        let _ = std::fs::remove_dir(&p);

        assert_eq!(results.len(), 1);
        assert!(!results[0].ok, "a directory must not pass a file check");
        assert!(results[0].detail.contains("not a regular file"));
    }

    #[test]
    fn check_file_fails_for_a_missing_path() {
        let p = temp_path("missing");

        let mut results = Vec::new();
        check_file(&mut results, "cache.tls_ca_path", p.to_str());

        assert_eq!(results.len(), 1);
        assert!(!results[0].ok);
    }

    #[test]
    fn check_file_skips_an_unconfigured_path() {
        let mut results = Vec::new();
        check_file(&mut results, "cache.tls_ca_path", None);

        assert_eq!(results.len(), 1);
        assert!(results[0].ok);
        assert!(results[0].detail.contains("skipped"));
    }
}
