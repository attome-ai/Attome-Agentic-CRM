# P1.8d load-testing harness — shared helpers. Dot-sourced by every script in
# this directory; not meant to be run directly.
#
# Safety (plan §8's mitigation for "dev-stack contamination"): every entry
# point that touches the loadtest stack goes through Assert-LoadtestSafety,
# which requires $env:LOADTEST_ACK -eq 'yes' AND the configured database name
# to contain "loadtest". This can never point at attomedb/attome_dev.

$script:LoadtestDbName = "attome_loadtest"
$script:LoadtestDbHost = "127.0.0.1"
$script:LoadtestDbPort = 5556
$script:LoadtestCacheHost = "127.0.0.1"
$script:LoadtestCachePort = 6380
$script:LoadtestBasePort = 7900
$script:LoadtestJwtSecret = "loadtest-throwaway-jwt-secret-do-not-reuse-anywhere-else-32chars-min"
$script:LoadtestApikeyHashPepper = "loadtest-throwaway-api_key-pepper-do-not-reuse-anywhere-else-32chars-min"
# P1.8d step 5 — pgbouncer overlay (docker-compose.pgbouncer.yml), fronting
# postgres-loadtest only; see that file and loadtest/pgbouncer/pgbouncer.ini
# for why this is a separate port from the real P1.12 recipe's 6432.
$script:LoadtestPgbouncerHost = "127.0.0.1"
$script:LoadtestPgbouncerPort = 6433

$script:RepoRoot = Resolve-Path "$PSScriptRoot/../.."
$script:LoadtestDir = Resolve-Path "$PSScriptRoot/.."
$script:GenDir = Join-Path $script:LoadtestDir ".generated"
$script:LogDir = Join-Path $script:LoadtestDir "logs"
$script:ResultsDir = Join-Path $script:LoadtestDir "results"
$script:PidFile = Join-Path $script:GenDir "pids.txt"
# IsWindows/IsLinux exist on PowerShell 7+ (pwsh, incl. GitHub-hosted
# ubuntu-latest runners' preinstalled pwsh); Windows PowerShell 5.1 has
# neither variable defined at all, which is itself a reliable "this is
# Windows" signal (5.1 never runs anywhere but Windows).
$script:IsWindowsHost = -not (Test-Path variable:IsWindows) -or $IsWindows
# One binary in v2: `attome serve` is a node, `attome audit-chainer` the chainer.
$script:ServerExe = if ($script:IsWindowsHost) {
    Join-Path $script:RepoRoot "target/release/attome.exe"
} else {
    Join-Path $script:RepoRoot "target/release/attome"
}
# D-316 made the audit chainer a separate OS process (crates/server/src/bin/
# audit_chainer.rs) and the ONLY writer of audit_header once
# audit.chainer_enabled is on. It has to run alongside the nodes for a
# -ChainerEnabled measurement to mean anything — see Start-LoadtestChainer.
$script:ChainerExe = $script:ServerExe
$script:ChainerPidFile = Join-Path $script:GenDir "chainer-pid.txt"
# curl.exe on Windows; the plain binary on Linux (PowerShell 7 dropped 5.1's
# `curl` -> Invoke-WebRequest alias on every platform, so this resolves to the
# real program either way). seed.ps1 shells out to this.
$script:CurlExe = if ($script:IsWindowsHost) { "curl.exe" } else { "curl" }

function Assert-LoadtestSafety {
    if ($env:LOADTEST_ACK -ne "yes") {
        throw "Refusing to run: set `$env:LOADTEST_ACK = 'yes' first (this is the harness's " +
              "guard against accidentally running load against a real stack — see loadtest/README.md)."
    }
    if ($script:LoadtestDbName -notlike "*loadtest*") {
        throw "Refusing to run: configured database name '$($script:LoadtestDbName)' does not " +
              "contain 'loadtest' — this guard exists so the harness can never be pointed at " +
              "attomedb/attome_dev by accident. Fix `$script:LoadtestDbName in common.ps1."
    }
    New-Item -ItemType Directory -Force -Path $script:GenDir, $script:LogDir, $script:ResultsDir | Out-Null
}

function New-LoadtestConfig {
    param(
        [Parameter(Mandatory)][int]$Port,
        [string]$BootstrapAdminEmail = "",
        # P1.8d step 5 (P1.12 exercise): "direct" (default) points database.host/port
        # straight at postgres-loadtest, same as before this param existed. "pgbouncer"
        # points them at the docker-compose.pgbouncer.yml overlay instead and sets
        # database.direct_url to the direct connection, so migrations/bootstrap still
        # bypass the pooler (D-049/guidelines §4 migrations note — sqlx::migrate!'s
        # advisory lock is session-scoped, transaction pooling would break it).
        [ValidateSet("direct", "pgbouncer")]
        [string]$Topology = "direct",
        # P1.8d step 6 (P1.13 re-run): re-runs the same k6 matrix with
        # audit.chainer_enabled=true instead of this harness's prior default of
        # false, to compare against the 2026-07-19 sync-path baseline.
        [switch]$ChainerEnabled
    )

    $bootstrapLine = if ($BootstrapAdminEmail) { "`"$BootstrapAdminEmail`"" } else { "null" }

    $dbHost = $script:LoadtestDbHost
    $dbPort = $script:LoadtestDbPort
    $directUrlLine = "null"
    if ($Topology -eq "pgbouncer") {
        $dbHost = $script:LoadtestPgbouncerHost
        $dbPort = $script:LoadtestPgbouncerPort
        $directUrl = "postgres://postgres:loadtest-throwaway-pw@$($script:LoadtestDbHost):$($script:LoadtestDbPort)/$($script:LoadtestDbName)?options=-c%20search_path%3Dattome_loadtest"
        $directUrlLine = "`"$directUrl`""
    }
    $chainerEnabledLine = if ($ChainerEnabled) { "true" } else { "false" }

    # Full AppConfig shape (matches config.example.json), values swapped to
    # the isolated loadtest Postgres/Dragonfly instances. APP_ENV=debug is
    # always set alongside this file (see Start-LoadtestNodes) so the
    # database.readonly-required-outside-debug check (D-038) relaxes to a
    # WARN+fallback — this harness has no separate readonly role/migration
    # wired up, and doesn't need one to measure request latency.
    return @"
{
  "app": {
    "port": $Port,
    "server_host": "0.0.0.0",
    "frontend_host": "localhost",
    "frontend_port": 4200,
    "public_frontend_url": null,
    "max_body_size_bytes": 10485760,
    "request_timeout_secs": 30
  },
  "database": {
    "host": "$dbHost",
    "port": $dbPort,
    "dbname": "$(if ($Topology -eq 'pgbouncer') { 'attome_loadtest_pooled' } else { $script:LoadtestDbName })",
    "user": "postgres",
    "password": "loadtest-throwaway-pw",
    "schema": "attome_loadtest",
    "connection_number": 50,
    "timeout": 5.0,
    "direct_url": $directUrlLine,
    "sticky_primary_ttl_secs": 5,
    "ssl_mode": "prefer",
    "ssl_root_cert": null,
    "disable_statement_cache": false
  },
  "cache": {
    "host": "$($script:LoadtestCacheHost)",
    "port": $($script:LoadtestCachePort),
    "password": "",
    "db": 0,
    "connection_pool_size": 64,
    "timeout": 2000,
    "metadata_registry_enabled": true,
    "roles": { "coordination": null },
    "tls_enabled": false,
    "tls_ca_path": null
  },
  "storage": {
    "s3_endpoint": "http://localhost:9000",
    "s3_public_endpoint": "",
    "s3_region": "us-east-1",
    "s3_access_key": "loadtest",
    "s3_secret_key": "loadtest",
    "s3_bucket": "attome-loadtest",
    "s3_verify_ssl": false
  },
  "auth": {
    "jwt_secret": "$($script:LoadtestJwtSecret)",
    "jwt_issuer": "attome-loadtest",
    "apikey_hash_pepper": "$($script:LoadtestApikeyHashPepper)",
    "jwt_expiry_hours": 1,
    "access_token_expiry_mins": 60,
    "refresh_token_expiry_days": 30,
    "secure_cookies": false,
    "oauth_google_client_id": "",
    "oauth_google_client_secret": "",
    "require_verified_email": false,
    "apikey_default_expiry_days": null,
    "_registration_mode_note": "D-128 defaults this to \"disabled\", which 403s seed.ps1's two /api/v1/auth/register calls and so blocks the whole harness. \"public\" is safe here and only here: this config is generated per run for the isolated, throwaway attome_loadtest stack that Assert-LoadtestSafety pins by database name. Never copy this line into a real deployment's config.",
    "registration_mode": "public"
  },
  "rate_limit": {
    "anonymous_rpm": 100000000,
    "authenticated_rpm": 100000000,
    "pre_auth_rpm": 100000000,
    "_categories_note": "Deliberately empty (D-145): an unlisted category falls back to the effectively-unlimited top-level budgets above, which is what a load test needs — a rate limiter that engages mid-run measures the limiter, not the platform. Replaced per_endpoint_limits, which AppConfig now rejects outright as a DeprecatedField, i.e. no node here could boot at all until TODO-014's pre-run pass.",
    "categories": {}
  },
  "observability": {
    "metrics_port": 0,
    "log_sampling_rate": 1.0,
    "trace_sampling_rate": 0.0,
    "enable_distributed_tracing": false
  },
  "email": { "enabled": false, "smtp_host": "localhost", "smtp_port": 1025, "smtp_user": "",
    "smtp_password": "", "smtp_from_address": "loadtest@attome.local", "smtp_from_name": "loadtest",
    "smtp_use_tls": false, "queue_poll_seconds": 30, "max_retries": 1, "batch_size": 1 },
  "google_ai": { "api_key": "" },
  "s2s": { "enabled": false, "key_encryption_key": "", "failure_alert_threshold": 100, "access_log_enabled": false },
  "security": {
    "bootstrap_admin_email": $bootstrapLine,
    "trusted_proxy_cidrs": []
  },
  "cors": { "allowed_origins": ["http://localhost:4200"] },
  "audit": {
    "signing_enabled": false,
    "signing_key_id": "loadtest-key",
    "signing_private_key": "",
    "ingest_capture_enabled": false,
    "chainer_enabled": $chainerEnabledLine
  },
  "jobs": { "worker_concurrency": 10 },
  "oidc": { "providers": {} }
}
"@
}

function Start-LoadtestNodes {
    param(
        [int]$Count = 1,
        [string]$BootstrapAdminEmail = "",
        [ValidateSet("direct", "pgbouncer")]
        [string]$Topology = "direct",
        [switch]$ChainerEnabled
    )
    Assert-LoadtestSafety

    # The chainer binary is part of the same build (autodiscovered from
    # crates/server/src/bin/), so one `cargo build` covers both — but an older
    # target/ dir predating D-316 can hold `server` without `audit_chainer`,
    # which would only surface as a missing-file error further down.
    if (-not (Test-Path $script:ServerExe) -or -not (Test-Path $script:ChainerExe)) {
        Write-Host "Building release server binaries (first run only)..."
        & cargo build --release -p attome
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    }

    if (Test-Path $script:PidFile) {
        Write-Warning "loadtest/.generated/pids.txt already exists — stopping any nodes it references first."
        Stop-LoadtestNodes
    }

    function Start-OneNode {
        param([int]$Port)
        $cfgPath = Join-Path $script:GenDir "config-node-$Port.json"
        # Set-Content -Encoding utf8 writes a BOM on Windows PowerShell 5.1,
        # which serde_json doesn't skip (fails "expected value at line 1
        # column 1") — write UTF-8 without BOM explicitly instead.
        $cfgJson = New-LoadtestConfig -Port $Port -BootstrapAdminEmail $BootstrapAdminEmail `
            -Topology $Topology -ChainerEnabled:$ChainerEnabled
        [System.IO.File]::WriteAllText($cfgPath, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))

        $env:APP_ENV = "debug"
        $env:CONFIG_FILE = $cfgPath
        # attome_config::AppConfig::from_file() calls dotenvy::dotenv(), which
        # walks UP from the process's working directory (crates/apps/attome, set
        # below) looking for a .env file -- it finds attome-website/.env,
        # the real dev .env with a DATABASE_URL pointed at the shared
        # attomedb/attome_dev database. create_pool() prefers $env:DATABASE_URL
        # over the config file's database section when it's set, so without
        # this override every actual data operation (not migrations, which
        # use direct_database_url() with no env check) silently ran against
        # the real dev database instead of this isolated one -- confirmed by
        # finding this harness's test entities/users actually written there.
        # dotenvy never overwrites an already-set env var, so setting the
        # CORRECT value here first is what makes that .env file harmless.
        #
        # P1.8d step 5: this MUST track -Topology, not just always point
        # straight at postgres-loadtest — otherwise $env:DATABASE_URL would
        # silently override the config file's pgbouncer host/port and this
        # entire exercise would still be hitting Postgres directly.
        $env:DATABASE_URL = if ($Topology -eq "pgbouncer") {
            "postgres://postgres:loadtest-throwaway-pw@$($script:LoadtestPgbouncerHost):$($script:LoadtestPgbouncerPort)/attome_loadtest_pooled?options=-c%20search_path%3Dattome_loadtest"
        } else {
            "postgres://postgres:loadtest-throwaway-pw@$($script:LoadtestDbHost):$($script:LoadtestDbPort)/$($script:LoadtestDbName)?options=-c%20search_path%3Dattome_loadtest"
        }
        $stdout = Join-Path $script:LogDir "node-$Port.out.log"
        $stderr = Join-Path $script:LogDir "node-$Port.err.log"

        # -WindowStyle is a Windows-only parameter: PowerShell 7 on Linux
        # throws "The parameter '-WindowStyle' is not supported for this
        # platform" rather than ignoring it, which would fail every node start
        # on the dedicated Linux host this harness is meant to run on. There
        # are no windows to hide there anyway (stdout/stderr already redirect
        # to loadtest/logs), so the parameter is simply dropped.
        $startArgs = @{
            FilePath               = $script:ServerExe
            ArgumentList           = @("serve")
            WorkingDirectory       = (Join-Path $script:RepoRoot "crates/apps/attome")
            RedirectStandardOutput = $stdout
            RedirectStandardError  = $stderr
            PassThru               = $true
        }
        if ($script:IsWindowsHost) { $startArgs.WindowStyle = "Hidden" }
        $proc = Start-Process @startArgs
        "$($proc.Id)`t$Port" | Add-Content -Path $script:PidFile
    }

    $ports = @()
    for ($i = 0; $i -lt $Count; $i++) { $ports += $script:LoadtestBasePort + $i }

    # Cold-boot finding (worth keeping, not just working around): every node
    # runs the same idempotent bootstrap-entity seeding (core_apikey,
    # core_audit_header, ...) via attome-metadata::ensure_entity, which takes a
    # per-logicalname pg_try_advisory_xact_lock (non-blocking, no retry).
    # Starting N>1 nodes simultaneously against a cold/never-seeded database
    # means two nodes can race for the same lock; the loser gets
    # Conflict("entity provisioning already in progress") and its boot fails
    # outright — reproduced with just the first node staggered (nodes 2/3/4
    # still raced each other), so every node is started fully sequentially
    # here (start, wait-ready, next) rather than only the first. This is a
    # workaround for this harness's cold-start case, not a claim the
    # underlying no-retry race is fine in production — see the LOADTEST
    # results doc: a real multi-node deployment's nodes come up staggered in
    # practice (rolling restarts), but a simultaneous cold start (e.g. a
    # fresh docker-compose up --scale server=N) would hit this today.
    foreach ($port in $ports) {
        Start-OneNode -Port $port
        Wait-NodeReady -Port $port
    }
    Start-Sleep -Seconds 1
    Write-Host "$Count node(s) ready on ports: $($ports -join ', ')"

    # Strictly after the nodes: audit_chainer.rs's module doc requires the
    # server to have applied migrations first (one process owns schema).
    if ($ChainerEnabled) {
        Start-LoadtestChainer -Topology $Topology
    }

    return $ports
}

function Start-LoadtestChainer {
    # D-316: with audit.chainer_enabled on, AuditService::write stops writing
    # audit_header entirely and only appends to audit_ingest — this
    # process is then the sole writer of the chain. Nothing in this harness
    # used to start it, so every -ChainerEnabled run measured a deployment
    # whose audit chain never advanced: the ingest backlog grows for the whole
    # run, and once it crosses audit.ingest_backlog_threshold the server's
    # mutation gate answers 503 instead of performing the write. At the 15-30s
    # windows the 2026-07-19/21 passes used that never had time to bite; at
    # TODO-014's >=10min x >=100 VUs it decides the result. Found by TODO-014's
    # pre-run pass.
    param(
        [ValidateSet("direct", "pgbouncer")]
        [string]$Topology = "direct"
    )
    Assert-LoadtestSafety

    if (-not (Test-Path $script:ChainerExe)) {
        throw "audit_chainer binary not found at $($script:ChainerExe) — build it with " +
              "``cargo build --release -p attome``."
    }
    if (Test-Path $script:ChainerPidFile) { Stop-LoadtestChainer }

    # Same config the nodes got (the chainer reads only database/audit from it
    # and never binds app.port — it has no HTTP surface), so the two can never
    # disagree about which Postgres or which audit stage they are running.
    $cfgPath = Join-Path $script:GenDir "config-chainer.json"
    $cfgJson = New-LoadtestConfig -Port $script:LoadtestBasePort -Topology $Topology -ChainerEnabled
    [System.IO.File]::WriteAllText($cfgPath, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))

    $env:APP_ENV = "debug"
    $env:CONFIG_FILE = $cfgPath
    $env:DATABASE_URL = if ($Topology -eq "pgbouncer") {
        "postgres://postgres:loadtest-throwaway-pw@$($script:LoadtestPgbouncerHost):$($script:LoadtestPgbouncerPort)/attome_loadtest_pooled?options=-c%20search_path%3Dattome_loadtest"
    } else {
        "postgres://postgres:loadtest-throwaway-pw@$($script:LoadtestDbHost):$($script:LoadtestDbPort)/$($script:LoadtestDbName)?options=-c%20search_path%3Dattome_loadtest"
    }

    $stdout = Join-Path $script:LogDir "chainer.out.log"
    $stderr = Join-Path $script:LogDir "chainer.err.log"
    $startArgs = @{
        FilePath               = $script:ChainerExe
        ArgumentList           = @("audit-chainer")
        WorkingDirectory       = (Join-Path $script:RepoRoot "crates/apps/attome")
        RedirectStandardOutput = $stdout
        RedirectStandardError  = $stderr
        PassThru               = $true
    }
    if ($script:IsWindowsHost) { $startArgs.WindowStyle = "Hidden" }
    $proc = Start-Process @startArgs
    "$($proc.Id)" | Set-Content -Path $script:ChainerPidFile

    # It has no readiness endpoint to poll, so "did it survive its own startup
    # checks" is the available signal — and it is a real one: the binary hard-
    # exits (non-zero) on the ingest_capture_enabled+chainer_disabled pair, and
    # on an unreachable database. Failing here beats discovering mid-run that
    # nothing was draining the queue.
    Start-Sleep -Seconds 3
    $alive = $null -ne (Get-Process -Id $proc.Id -ErrorAction SilentlyContinue)
    if (-not $alive) {
        throw "audit_chainer exited immediately after start — see $stderr"
    }
    Write-Host "audit chainer running (pid $($proc.Id))"
}

function Stop-LoadtestChainer {
    if (-not (Test-Path $script:ChainerPidFile)) { return }
    $chainerPid = (Get-Content $script:ChainerPidFile | Select-Object -First 1)
    try { Stop-Process -Id $chainerPid -Force -ErrorAction Stop } catch { }
    Remove-Item $script:ChainerPidFile -Force
}

function Wait-NodeReady {
    # 127.0.0.1, not "localhost" -- on this machine, Invoke-WebRequest against
    # a not-yet-listening "localhost" port has been observed taking several
    # seconds per failed attempt (IPv6-then-IPv4 fallback), which can burn
    # the whole timeout budget in just a couple of early retries even though
    # the server actually starts listening within ~1s. 127.0.0.1 skips that
    # resolution step entirely.
    param([Parameter(Mandatory)][int]$Port, [int]$TimeoutSecs = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSecs)
    while ((Get-Date) -lt $deadline) {
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/health/ready" -UseBasicParsing -TimeoutSec 3
            if ($resp.StatusCode -eq 200) { return }
        } catch { }
        Start-Sleep -Milliseconds 500
    }
    throw "Node on port $Port did not become ready within ${TimeoutSecs}s — check loadtest/logs/node-$Port.err.log"
}

function Get-PgLoadtestConnectionCount {
    # P1.8d step 5 (P1.12 exercise) — counts real backend connections against
    # the physical postgres-loadtest instance, regardless of topology (direct
    # app-node connections, or the handful pgbouncer itself holds open to the
    # same instance under transaction pooling). Uses the docker exec'd psql
    # inside the postgres-loadtest container so this works without a native
    # psql client on the host.
    docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -t -A -c `
        "SELECT count(*) FROM pg_stat_activity WHERE datname = 'attome_loadtest'"
}

function Get-PgLoadtestBlockedSessionCount {
    # P1.8d step 10 (DDL-contention exercise) — counts sessions currently
    # waiting on ANY lock against the loadtest Postgres instance. Used to
    # observe `exec_ddl_locked`'s (`crates/engine/attome-metadata/src/provision/ddl.rs`)
    # `lock_timeout`+55P03-retry behavior actually engaging under concurrent
    # conflicting ALTERs, the same docker-exec-psql pattern as
    # Get-PgLoadtestConnectionCount above (no native psql client assumed on
    # the host).
    docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -t -A -c `
        "SELECT count(*) FROM pg_stat_activity WHERE datname = 'attome_loadtest' AND wait_event_type = 'Lock'"
}

function Get-AuditIngestBacklog {
    # Pending (captured-but-not-yet-chained) audit_ingest rows across every
    # organization — the PowerShell equivalent of attome_audit::verify::lag's
    # count half (verify.rs), which cuts off at the newest chain batch's
    # last_ingest_id. A chainer-on run is only trustworthy if this stays flat:
    # a number that climbs across a 10-minute window means the chainer is not
    # keeping up with the write rate, and the latency figures are describing a
    # deployment on its way to the 503 mutation gate rather than a steady one.
    #
    # Read-only, against the throwaway loadtest database only, through the same
    # docker-exec'd psql the connection/lock-count helpers above already use
    # (no native psql client assumed on the host). Tables are schema-qualified
    # because this connection has no search_path set, unlike the app's.
    $sql = @"
SELECT COALESCE(SUM(pending), 0) FROM (
  SELECT (
    SELECT COUNT(*) FROM attome_loadtest.audit_ingest i
    WHERE i.organization_ref = o.organization_ref
      AND i.id > COALESCE((
        SELECT b.last_ingest_id FROM attome_loadtest.audit_chain_batch b
        WHERE b.organization_ref = o.organization_ref
        ORDER BY b.id DESC LIMIT 1
      ), '00000000-0000-0000-0000-000000000000'::uuid)
  ) AS pending
  FROM (SELECT DISTINCT organization_ref FROM attome_loadtest.audit_ingest) o
) s
"@
    docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -t -A -c $sql
}

function Stop-LoadtestNodes {
    # Unconditional, and before the early return below: the chainer outlives a
    # node set that was already torn down, and a leftover one draining into the
    # next run's Postgres is exactly the cross-run contamination this harness
    # is built to avoid.
    Stop-LoadtestChainer
    if (-not (Test-Path $script:PidFile)) { return }
    Get-Content $script:PidFile | ForEach-Object {
        $procId, $port = $_ -split "`t"
        try { Stop-Process -Id $procId -Force -ErrorAction Stop } catch { }
    }
    Remove-Item $script:PidFile -Force
}

function Get-LoadtestNodePorts {
    # @(...) is load-bearing: Get-Content on a one-line file returns a bare
    # string, not a 1-element array, which made (Get-LoadtestNodePorts)[0]
    # index into the STRING "7900" and silently return the char '7' whenever
    # exactly one node was running -- the root cause of a long chain of
    # "unable to connect" failures (baseUrl became "http://127.0.0.1:7").
    if (-not (Test-Path $script:PidFile)) { return @() }
    return @(Get-Content $script:PidFile | ForEach-Object { ($_ -split "`t")[1] })
}
