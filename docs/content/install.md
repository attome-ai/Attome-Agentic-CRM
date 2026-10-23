# Install guide

Attome is one program, `attome` (`attome.exe` on Windows), plus its web app, and a PostgreSQL 18
database with the `pgvector` extension. A single server (Solo) needs nothing else: its caches, rate
limits and coordination live in process memory. Redis or Dragonfly, an object store and a virus
scanner are optional and only needed for several servers or for file uploads.

Minimum for Solo: 2 CPUs, 4 GB of memory and 20 GB of free disk. `attome init` checks these and
refuses to install with less than 5 GB of free disk.

## Linux

One command installs the latest release as a systemd service. With no `--database-url` it also
installs PostgreSQL 18 with pgvector from the PostgreSQL project's own repository (Debian, Ubuntu,
RHEL, Rocky, Alma and Fedora):

```sh
curl -fsSL https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.sh \
  | sudo sh -s -- --admin you@example.com
```

Options: `--database-url <url>` to use an existing database, `--version <tag>` for a release other
than the latest, `--port <n>` (default 7865), `--prefix <dir>` (default `/opt/attome`) and
`--packs <a,b>` (default `crm`; an empty list installs none).

The program goes to `/opt/attome`, its configuration to `/var/lib/attome/config.json`.

## Windows

From an elevated PowerShell, against an existing PostgreSQL 18 database:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.ps1))) `
    -DatabaseUrl 'postgres://attome_owner:secret@127.0.0.1:5432/attome' -Admin you@example.com
```

pgvector publishes no Windows installer, so the database must be ready first: a role with
`CREATEROLE` owns the database, and a superuser has run

```sql
CREATE EXTENSION vector;
CREATE EXTENSION pg_trgm;
CREATE EXTENSION pgcrypto;
```

The program goes to `%ProgramFiles%\Attome`, its configuration to `%ProgramData%\Attome\config.json`,
and it runs as a Windows service. `-Packs crm,sales` chooses packs as on Linux.

## Running PostgreSQL in Docker

Attome itself runs natively, but its database may run in Docker (Docker Desktop on Windows), which
is the easiest way to get pgvector on Windows:

```sh
docker run -d --name attome-db -p 5432:5432 \
  -e POSTGRES_USER=attome_owner -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=attome \
  -v attome-db:/var/lib/postgresql/data pgvector/pgvector:pg18
docker exec attome-db psql -U attome_owner -d attome \
  -c "CREATE EXTENSION IF NOT EXISTS vector; CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS pgcrypto;"
```

Then install with `--database-url postgres://attome_owner:secret@127.0.0.1:5432/attome`. Keep the
volume (`attome-db`) on a disk that is backed up.

## After the install

The server and the web app answer on `http://localhost:7865/`. Sign in with the administrator's
email and the one-time password the install printed, then:

1. Set the deployment up for its country: the first-run wizard (`/xrm/admin/first-run`) installs the
   region preset (currency, VAT rates, ID formats, business week, holidays) and sets the language,
   time zone and calendar.
2. Check the server: `attome status` shows each node's version and readiness; `attome doctor` checks
   the configuration and dependencies and says what to do about each failure.
3. Plan backups: see the [backup guide](../backup.md); `attome backup now` writes one,
   `attome backup drill` proves one restores.
4. Read the [admin guide](admin.md).

## HTTPS without a proxy

A single server can serve HTTPS itself (HTTP/2, falling back to HTTP/1.1), so no reverse proxy is
needed in front of it. Point it at a certificate chain and its private key, both PEM files:

```json
"app": {
  "tls": {
    "enabled": true,
    "cert_path": "/etc/attome/tls/fullchain.pem",
    "key_path": "/etc/attome/tls/privkey.pem",
    "min_version": "1.2"
  }
}
```

- `min_version` is `"1.2"` (the default) or `"1.3"`.
- The server refuses to start, naming the setting, when a file is missing or unreadable.
- A renewed certificate is picked up without a restart: the files are read again every twelve
  hours, and at once on `SIGHUP` (Linux). A file that no longer loads keeps the current certificate
  in use and logs an error.
- Plain HTTP is not answered on the HTTPS port. Set `app.public_frontend_url` to the `https://`
  address, and turn on `auth.secure_cookies`.

## By hand

`attome init` does what the scripts do, on a machine where the binary is already in place:

```sh
attome init --database-url postgres://postgres:secret@localhost:5432/attome   # writes config.json, applies the schema
attome serve --bootstrap-admin you@example.com                               # once: the first administrator
attome service install --dir /var/lib/attome                                 # a systemd unit or a Windows service
```

`attome service install --dry-run` prints the steps without doing them. `attome sovereignty report`
lists where copies of the data live and every outside destination the configuration names.
