//! P-db-privilege-separation follow-up (§1's "move migrations to a one-shot
//! deployment job"): a dedicated one-shot binary that runs schema bootstrap +
//! migrations + the D-117 role-password seeds + the D-120 pepper-registry
//! check, then exits — exactly the sequence `main.rs` used to always run
//! inline on every `server` boot. A deployment wires this into its release
//! pipeline as a step that runs once, ahead of starting/rolling any `server`
//! process, then sets `database.migrate_on_boot = false` so the long-lived
//! web process never needs to hold the DDL-capable/`CREATE ROLE` bootstrap
//! credentials (`database.user`/`.password`) at all.
//!
//! Deliberately NOT gated by `database.migrate_on_boot` itself — this binary
//! IS the "one-shot deployment job" that flag's doc comment describes, so it
//! always runs the sequence regardless of that flag's value. Running it
//! against a deployment that still has `migrate_on_boot = true` is harmless
//! (every step here is idempotent, same as `main.rs`'s inline sequence
//! always was) — it just means the same work also happens again on the next
//! `server` boot, byte-identical to today's behavior.
use attome::role_seed_lock;
use attome_config::AppConfig;

#[tokio::main]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let config = AppConfig::from_file()?;
    config.validate()?;
    // BCF-10 — one WARN per unknown config key, never a boot failure (BCF-D4).
    attome::boot::report_ignored_config_keys(&config, false)?;
    // P-bootstrap-credential-scoping (D-204): validate() only requires
    // database.password when migrate_on_boot=true (the dev-inline shape) —
    // a production deployment with migrate_on_boot=false is allowed to omit
    // it from server/worker's config.json entirely (that's the whole point
    // of the fix), which means validate() alone can't catch this binary
    // being handed the same credential-less config by mistake. This binary
    // IS the "one-shot deployment job" and unconditionally needs the
    // bootstrap identity regardless of migrate_on_boot's value (see this
    // file's own module doc) — check independently, fail fast with an
    // actionable message instead of a generic connect-time auth error.
    if config.database.password.is_none() {
        return Err(
            "database.password is not configured — the one-shot `migrate` binary \
                     always needs the bootstrap identity's credential (schema bootstrap, \
                     migrations, role-password seeding), regardless of \
                     database.migrate_on_boot. Set DB_PASSWORD and database.password in this \
                     binary's config.json — do not point it at a config.json rendered for \
                     server/worker (P-bootstrap-credential-scoping, D-204)."
                .into(),
        );
    }
    tracing::info!("migrate: starting one-shot schema bootstrap + migrations");

    // D-127 checksum baseline, direct (non-pgbouncer) pool, schema +
    // migrations: the same sequence `boot::init` runs when
    // `database.migrate_on_boot` is true — see
    // `attome::boot::apply_schema_migrations`.
    let migration_db = attome::boot::apply_schema_migrations(&config).await?;
    role_seed_lock::seed_roles_and_pepper_registry(&migration_db, &config).await?;
    migration_db.close().await;

    tracing::info!("migrate: done");
    Ok(())
}
