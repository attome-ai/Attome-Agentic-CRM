# Upgrade guide

Upgrading replaces the program and its web app; the database schema moves forward on the next start.
Migrations only add (tables, columns with defaults, indexes), so the previous release still runs
against an upgraded database: rolling back is replacing the program again.

[Versions and support](../versions-and-support.md) says which releases are supported and what a
major, minor or patch release may change. Read the release's `CHANGELOG.md` section first, above all
its **Breaking** list.

## Steps

1. **Back up.** `attome backup now` writes a database backup and the stored files. Check that the
   newest backup restores with `attome backup drill`.
2. **Stop the service** (`systemctl stop attome` on Linux, `Stop-Service attome` on Windows). With several
   servers, upgrade one at a time; mixed versions keep working while the schema only adds.
3. **Replace the program and the web app** with the new release's archive from the release page
   (`attome-linux-x86_64.tar.gz` or `attome-windows-x86_64.zip`, each with a `.sha256` to check):
   unpack it over `/opt/attome` or `%ProgramFiles%\Attome`. Leave `config.json` where it is; do not
   run the install script again, since `attome init` refuses to replace an existing configuration
   (its secrets would be lost).
4. **Start the service.** Migrations run at start; a migration that waits for a lock retries rather
   than blocking traffic.
5. **Check**: `attome status` shows the new version on every node; `attome doctor` checks the
   configuration and dependencies.

## Rolling back

Stop the service, put the previous release's program and web app back, and start it. Structure the
new release added stays unused. Only a contract migration (one that removes structure) cannot be
rolled back, and those run separately, days after the release that stopped using the structure, never
at start.

If data must go back too, `attome restore <archive|latest> --yes` restores a backup (stop the server
first; the current database is backed up before it is replaced).
