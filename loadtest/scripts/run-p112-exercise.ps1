# P1.8d step 5 — the P1.12 exercise: does fronting N=20+ app nodes with a
# transaction-pooling pgbouncer keep Postgres connection count down and hold
# P99 latency roughly flat, compared to every node connecting directly?
#
# Scope (deliberately narrower than the full 6-scenario matrix, to keep a
# 20-node pass on a single dev machine tractable — see the results doc for
# why): crud_read (read-heavy baseline), list_query (the class most likely
# to hold a connection longer per request), and mutating_write (the class
# already flagged, LOADTEST-2026-07-19.md Finding 2, as the one under
# per-organization lock contention). Requires seed.ps1 to have already run.
#
# -ChainerEnabled (added post-2026-07-21, never actually run): the P1.12
# exercise (step 5) and the P1.13 chainer re-run (step 6) have so far only
# ever been measured separately — step 5 always ran with
# audit.chainer_enabled=false (production's current default), and step 6's
# chainer comparison only ever ran at N=1/4/12 via run-matrix.ps1, never at
# this script's N=20+. The one combination that actually answers "what's the
# real ceiling" — chainer on, N=20+, through pgbouncer — was never exercised.
# This flag closes that gap in the harness itself; running it still needs a
# dedicated host (this environment has no Docker daemon/Postgres to execute
# against — see document_v2/docs/LOADTEST-2026-07-21.md's own host caveat, unchanged).
#
# Usage:
#   $env:LOADTEST_ACK = "yes"
#   docker compose -f docker-compose.loadtest.yml up -d   # if not already up
#   ./scripts/run-p112-exercise.ps1
#   ./scripts/run-p112-exercise.ps1 -ChainerEnabled   # combined P1.12+P1.13 pass
param(
    [int]$NodeCount = 20,
    [string[]]$Scenarios = @('crud_read', 'list_query', 'mutating_write'),
    [string]$Duration = "20s",
    [switch]$ChainerEnabled
)
. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) {
    throw "loadtest/.generated/seed-info.json not found — run seed.ps1 first."
}
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json

# Distinguishes a -ChainerEnabled pass's result files from the step-5 baseline
# (chainer off) so re-running combined never silently overwrites the original
# p112-exercise-{raw,comparison}.json this doc's LOADTEST-2026-07-21.md cites.
$chainerSuffix = if ($ChainerEnabled) { "-chainer" } else { "" }

function Invoke-TopologyPass {
    param([Parameter(Mandatory)][ValidateSet("direct", "pgbouncer")][string]$Topology)

    if ($Topology -eq "pgbouncer") {
        # pgbouncer 1.18 (the Debian bookworm package this overlay's
        # Dockerfile installs) can't carry search_path via its own
        # [databases] line or a passed-through client `options` startup
        # parameter (see pgbouncer/pgbouncer.ini's comments) -- set it at
        # the role level instead, once, idempotently, before pgbouncer-fronted
        # connections start arriving.
        docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -c `
            "ALTER ROLE postgres IN DATABASE attome_loadtest SET search_path = attome_loadtest;" | Out-Null

        Write-Host "Bringing up pgbouncer-loadtest overlay..."
        & docker compose -f (Join-Path $script:LoadtestDir "docker-compose.loadtest.yml") `
            -f (Join-Path $script:LoadtestDir "docker-compose.pgbouncer.yml") up -d --build pgbouncer-loadtest
        if ($LASTEXITCODE -ne 0) { throw "docker compose up pgbouncer-loadtest failed" }
        Start-Sleep -Seconds 3
    }

    Write-Host ""
    Write-Host "=== Topology: $Topology chainer_enabled=$($ChainerEnabled.IsPresent) — starting $NodeCount node(s) ==="
    $ports = Start-LoadtestNodes -Count $NodeCount -BootstrapAdminEmail $seed.admin_email -Topology $Topology -ChainerEnabled:$ChainerEnabled
    Start-Sleep -Seconds 2
    $idleConns = [int](Get-PgLoadtestConnectionCount)
    Write-Host "Postgres connections at idle (N=$NodeCount, $Topology): $idleConns"

    $baseUrlsDocker = ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','
    $scenarioResults = @()

    foreach ($scenario in $Scenarios) {
        Write-Host "--- $scenario ($Topology, N=$NodeCount, chainer=$($ChainerEnabled.IsPresent)) ---"
        $resultPath = Join-Path $script:ResultsDir "p112-$scenario-$Topology$chainerSuffix.json"
        if (Test-Path $resultPath) { Remove-Item $resultPath -Force }

        $k6Env = @(
            "-e", "BASE_URLS=$baseUrlsDocker",
            "-e", "TEST_EMAIL=$($seed.test_email)",
            "-e", "TEST_PASSWORD=$($seed.test_password)",
            "-e", "ADMIN_EMAIL=$($seed.admin_email)",
            "-e", "ADMIN_PASSWORD=$($seed.admin_password)",
            "-e", "WIDE_ENTITY=$($seed.wide_entity)",
            "-e", "BULK_ENTITY=$($seed.bulk_entity)",
            "-e", "BULK_QUERY_ID=$($seed.bulk_query_id)",
            "-e", "MUT_ENTITY=$($seed.mut_entity)",
            "-e", "BULK_ROW_COUNT=$($seed.bulk_row_count)",
            "-e", "DURATION=$Duration"
        )
        if ($scenario -eq 'mutating_write') {
            $mutIdsPath = Join-Path $script:GenDir "mut-record-ids.json"
            $mutIdsJson = ($seed.mut_record_ids | ConvertTo-Json -Compress)
            [System.IO.File]::WriteAllText($mutIdsPath, $mutIdsJson, (New-Object System.Text.UTF8Encoding($false)))
            $k6Env += @("-e", "MUT_RECORD_IDS_FILE=/work/.generated/mut-record-ids.json")
        }

        # Sample pg_stat_activity every 2s in the background while k6 runs,
        # so the "under load" connection count reflects concurrent peak, not
        # just a single snapshot that might land between requests.
        $connSamples = [System.Collections.Generic.List[int]]::new()
        $samplerJob = Start-Job -ScriptBlock {
            param($containerName)
            while ($true) {
                $n = docker exec $containerName psql -U postgres -d attome_loadtest -t -A -c `
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = 'attome_loadtest'"
                if ($n) { $n }
                Start-Sleep -Seconds 2
            }
        } -ArgumentList "loadtest-postgres-loadtest-1"

        & docker run --rm -v "$($script:LoadtestDir):/work" @k6Env grafana/k6 run `
            "/work/k6/$scenario.js" `
            --summary-trend-stats "avg,min,med,p(50),p(90),p(99),max" `
            --summary-export "/work/results/p112-$scenario-$Topology$chainerSuffix.json"

        Stop-Job -Job $samplerJob -ErrorAction SilentlyContinue | Out-Null
        $rawSamples = Receive-Job -Job $samplerJob -ErrorAction SilentlyContinue
        Remove-Job -Job $samplerJob -Force -ErrorAction SilentlyContinue
        foreach ($s in $rawSamples) { if ($s -match '^\d+$') { $connSamples.Add([int]$s) } }
        $peakConns = if ($connSamples.Count -gt 0) { ($connSamples | Measure-Object -Maximum).Maximum } else { -1 }

        if (Test-Path $resultPath) {
            $summary = Get-Content $resultPath -Raw | ConvertFrom-Json
            $trend = $summary.metrics.http_req_duration
            $scenarioResults += [PSCustomObject]@{
                topology         = $Topology
                chainer_enabled  = $ChainerEnabled.IsPresent
                scenario         = $scenario
                nodes            = $NodeCount
                idle_conns       = $idleConns
                peak_conns       = $peakConns
                p50_ms           = [Math]::Round($trend.'p(50)', 1)
                p90_ms           = [Math]::Round($trend.'p(90)', 1)
                p99_ms           = [Math]::Round($trend.'p(99)', 1)
                max_ms           = [Math]::Round($trend.max, 1)
                requests         = $summary.metrics.http_reqs.count
            }
        } else {
            Write-Warning "$scenario ($Topology) produced no summary-export — check docker/k6 output above."
        }
    }

    Stop-LoadtestNodes
    if ($Topology -eq "pgbouncer") {
        & docker compose -f (Join-Path $script:LoadtestDir "docker-compose.loadtest.yml") `
            -f (Join-Path $script:LoadtestDir "docker-compose.pgbouncer.yml") stop pgbouncer-loadtest | Out-Null
    }
    return $scenarioResults
}

# Direct topology hitting Postgres's max_connections wall before reaching
# -NodeCount is itself the P1.12 finding this exercise exists to surface
# (each node's database.connection_number=50 vs. Postgres's default
# max_connections=100 means direct topology cannot scale node count
# arbitrarily) -- not a harness bug, so this does not abort the exercise.
# Cleans up any partially-started nodes and records the failure instead of
# forcing an artificial success.
$directFailure = $null
try {
    $directResults = Invoke-TopologyPass -Topology "direct"
} catch {
    $directFailure = $_.Exception.Message
    Write-Warning "Direct topology at N=$NodeCount failed: $directFailure"
    Stop-LoadtestNodes
    $directResults = @()
}

$pgbouncerResults = Invoke-TopologyPass -Topology "pgbouncer"

$all = @($directResults) + @($pgbouncerResults)
$all | Format-Table -AutoSize

$comparison = foreach ($scenario in $Scenarios) {
    $d = $directResults | Where-Object { $_.scenario -eq $scenario }
    $p = $pgbouncerResults | Where-Object { $_.scenario -eq $scenario }
    if ($d -and $p -and $d.p99_ms -gt 0) {
        $degradePct = [Math]::Round((($p.p99_ms - $d.p99_ms) / $d.p99_ms) * 100, 1)
    } else {
        $degradePct = $null
    }
    [PSCustomObject]@{
        scenario              = $scenario
        direct_peak_conns     = $d.peak_conns
        pgbouncer_peak_conns  = $p.peak_conns
        direct_p99_ms         = $d.p99_ms
        pgbouncer_p99_ms      = $p.p99_ms
        p99_degradation_pct   = $degradePct
        within_20pct_budget   = if ($null -ne $degradePct) { $degradePct -le 20 } else { $null }
    }
}
$comparison | Format-Table -AutoSize

$output = [PSCustomObject]@{
    node_count      = $NodeCount
    chainer_enabled = $ChainerEnabled.IsPresent
    direct_failure  = $directFailure
    direct_results  = @($directResults)
    pgbouncer_results = @($pgbouncerResults)
}
$rawPath = Join-Path $script:ResultsDir "p112-exercise-raw$chainerSuffix.json"
$comparisonPath = Join-Path $script:ResultsDir "p112-exercise-comparison$chainerSuffix.json"
$output | ConvertTo-Json -Depth 5 | Set-Content -Path $rawPath -Encoding utf8
$comparison | ConvertTo-Json -Depth 5 | Set-Content -Path $comparisonPath -Encoding utf8
Write-Host ""
if ($directFailure) {
    Write-Host "Direct topology FAILED at N=${NodeCount}: $directFailure"
}
Write-Host "Written: loadtest/results/p112-exercise-raw$chainerSuffix.json, loadtest/results/p112-exercise-comparison$chainerSuffix.json"
