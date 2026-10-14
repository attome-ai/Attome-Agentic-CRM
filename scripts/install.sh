#!/bin/sh
# Attome one-command install for Linux (roadmap U1-T1).
#
#   curl -fsSL https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.sh \
#     | sudo sh -s -- --admin you@example.com
#
# Downloads the release archive (the attome binary and the web app) into
# /opt/attome, installs PostgreSQL 18 with pgvector from the PostgreSQL
# project's own repository when no --database-url is given (Debian, Ubuntu,
# RHEL, Rocky, Alma, Fedora), creates the database, then runs
# `attome init --service`, which writes /var/lib/attome/config.json, applies
# the schema, creates the first administrator and starts the systemd unit.
#
# Options:
#   --admin <email>         the first administrator (prints a one-time password)
#   --database-url <url>    use this PostgreSQL 18 database (with pgvector)
#                           instead of installing one
#   --version <tag>         a release tag such as v2.0.0 (default: the latest)
#   --port <n>              the HTTP port (default 7865)
#   --prefix <dir>          where the binary goes (default /opt/attome)
set -eu

REPO="attome-ai/Attome-Agentic-CRM"
VERSION="latest"
PREFIX="/opt/attome"
PORT="7865"
ADMIN=""
DATABASE_URL=""

while [ $# -gt 0 ]; do
  case "$1" in
    --admin) ADMIN="$2"; shift 2 ;;
    --database-url) DATABASE_URL="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    -h|--help) echo "options: --admin <email> --database-url <url> --version <tag> --port <n> --prefix <dir>"; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "run as root (sudo sh -s -- ...)"
[ "$(uname -s)" = "Linux" ] || fail "this script is for Linux; on Windows use scripts/install.ps1"
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) fail "only x86_64 builds are published so far" ;;
esac
command -v curl >/dev/null || fail "curl is required"
command -v tar >/dev/null || fail "tar is required"

# ── PostgreSQL ────────────────────────────────────────────────────────────
random_password() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

install_postgres() {
  if command -v apt-get >/dev/null; then
    say "installing PostgreSQL 18 and pgvector from apt.postgresql.org..."
    apt-get update -q
    apt-get install -y -q curl ca-certificates gnupg lsb-release
    install -d /usr/share/postgresql-common/pgdg
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list
    apt-get update -q
    apt-get install -y -q postgresql-18 postgresql-18-pgvector
  elif command -v dnf >/dev/null; then
    say "installing PostgreSQL 18 and pgvector from download.postgresql.org..."
    . /etc/os-release
    major="${VERSION_ID%%.*}"
    if [ "${ID:-}" = "fedora" ]; then
      dnf install -y "https://download.postgresql.org/pub/repos/yum/reporpms/F-${major}-x86_64/pgdg-fedora-repo-latest.noarch.rpm"
    else
      dnf install -y "https://download.postgresql.org/pub/repos/yum/reporpms/EL-${major}-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
      dnf -qy module disable postgresql || true
    fi
    dnf install -y postgresql18-server pgvector_18
    /usr/pgsql-18/bin/postgresql-18-setup initdb || true
    systemctl enable --now postgresql-18
  else
    fail "no apt or dnf here; install PostgreSQL 18 with pgvector yourself and pass --database-url"
  fi
}

if [ -z "$DATABASE_URL" ]; then
  if ! command -v psql >/dev/null; then
    install_postgres
  fi
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  PASSWORD="$(random_password)"
  say "creating the attome database and its owner role..."
  # The owner creates the application roles during the schema step, so it
  # needs CREATEROLE; the extensions need a superuser, so they are made here.
  su postgres -c "psql -v ON_ERROR_STOP=1 -q" <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'attome_owner') THEN
    CREATE ROLE attome_owner LOGIN CREATEROLE PASSWORD '$PASSWORD';
  ELSE
    ALTER ROLE attome_owner WITH LOGIN CREATEROLE PASSWORD '$PASSWORD';
  END IF;
END \$\$;
SQL
  if ! su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname = 'attome'\"" | grep -q 1; then
    su postgres -c "createdb -O attome_owner attome"
  fi
  su postgres -c "psql -v ON_ERROR_STOP=1 -q -d attome -c 'CREATE EXTENSION IF NOT EXISTS vector; CREATE EXTENSION IF NOT EXISTS pg_trgm; CREATE EXTENSION IF NOT EXISTS pgcrypto;'"
  DATABASE_URL="postgres://attome_owner:${PASSWORD}@127.0.0.1:5432/attome"
fi

# ── The release ───────────────────────────────────────────────────────────
ASSET="attome-linux-x86_64.tar.gz"
if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
say "downloading $ASSET ($VERSION)..."
curl -fsSL "$BASE/$ASSET" -o "$WORK/$ASSET"
curl -fsSL "$BASE/$ASSET.sha256" -o "$WORK/$ASSET.sha256"
(cd "$WORK" && sha256sum -c "$ASSET.sha256" >/dev/null) || fail "the download's checksum does not match"
mkdir -p "$PREFIX"
tar -xzf "$WORK/$ASSET" -C "$PREFIX"
chmod 0755 "$PREFIX/attome"
ln -sf "$PREFIX/attome" /usr/local/bin/attome

# ── Install and start ─────────────────────────────────────────────────────
set -- init --database-url "$DATABASE_URL" --port "$PORT" --service
[ -n "$ADMIN" ] && set -- "$@" --admin "$ADMIN"
mkdir -p /var/lib/attome
# The service serves the web app from app.web_root; the archive's copy is
# next to the binary, which `attome serve` finds by itself.
"$PREFIX/attome" "$@"
