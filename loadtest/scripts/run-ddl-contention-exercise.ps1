# P1.8d step 10 — Load-test runtime DDL under representative concurrency.
#
# `exec_ddl_locked` (crates/engine/attome-metadata/src/provision/ddl.rs:~76) is the
# lock_timeout+bounded-55P03-retry executor every provisioning ALTER routes
# through (P-provisioning-hardening item (c), extended to
# evolve_attribute_schema by P-online-schema-change Step 1) — well-reasoned,
# never measured under real concurrency. This script runs
# k6/schema_change_ddl.js: an admin session repeatedly toggling
# is_required true/false on one attribute of a seeded table (racing another
# DDL VU toward the opposite value on the SAME attribute — genuine
# conflicting-lock contention, not a synthetic single-writer case) while
# ordinary non-admin traffic concurrently PATCHes other rows of that same
# table, then reports:
#   - ddl_toggle request latency (the exec_ddl_locked call's own P50/P99,
#     since at/under SCHEMA_CHANGE_INLINE_ROW_LIMIT rows this runs inline on
#     the request thread)
#   - concurrent_write latency split before/during/after the DDL window —
#     the actual blast-radius question P-online-schema-change.md's problem
#     statement describes ("one admin's routine schema click produces a
#     shared-nothing platform's worst kind of incident")
#   - peak concurrently-lock-blocked Postgres sessions during the run
#     (Get-PgLoadtestBlockedSessionCount, sampled like run-p112-exercise.ps1's
#     connection sampler)
#   - a count of exec_ddl_locked's own "hit lock_timeout, retrying"
#     tracing::warn! lines actually observed in the node logs — direct
#     evidence the retry path engaged, not an inference from latency alone.
#
# Requires seed.ps1 to have already run (it provisions loadtest_ddl -- see
# that script's own P1.8d step 10 addition). This environment has no Docker
# daemon/Postgres/built release binary to execute this against — see
# loadtest/README.md's "2026-08-04 addition" note; this script is
# code-only/unexecuted until run on a real host, same caveat as
# run-soak-test.ps1/run-p112-exercise.ps1 -ChainerEnabled.
#
# Usage:
#   $env:LOADTEST_ACK = "yes"
#   docker compose -f docker-compose.loadtest.yml up -d   # if not already up
#   ./scripts/seed.ps1
#   ./scripts/run-ddl-contention-exercise.ps1
param(
    [int]$NodeCount = 4,
    [string]$Duration = "30s",
    [string]$DdlStartOffset = "5s",
    [string]$DdlDuration = "20s",
    [int]$DdlVUs = 2,
    [int]$WriteVUs = 10,
    [switch]$ChainerEnabled
)
. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) {
    throw "loadtest/.generated/seed-info.json not found — run seed.ps1 first."
}
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json
if (-not $seed.ddl_entity_id -or -not $seed.ddl_field_id) {
    throw "seed-info.json has no ddl_entity_id/ddl_field_id — re-run seed.ps1 (this exercise needs " +
          "its P1.8d step 10 loadtest_ddl provisioning; an older seed-info.json predates that addition)."
}
if (-not $seed.ddl_record_ids -or @($seed.ddl_record_ids).Count -eq 0) {
    throw "seed-info.json's ddl_record_ids is empty — re-run seed.ps1."
}

Write-Host "=== Starting $NodeCount node(s) (direct topology, chainer_enabled=$($ChainerEnabled.IsPresent)) ==="
$ports = Start-LoadtestNodes -Count $NodeCount -BootstrapAdminEmail $seed.admin_email -ChainerEnabled:$ChainerEnabled
Start-Sleep -Seconds 2

$ddlIdsPath = Join-Path $script:GenDir "ddl-record-ids.json"
$ddlIdsJson = ($seed.ddl_record_ids | ConvertTo-Json -Compress)
[System.IO.File]::WriteAllText($ddlIdsPath, $ddlIdsJson, (New-Object System.Text.UTF8Encoding($false)))

$baseUrlsDocker = ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','
$resultPath = Join-Path $script:ResultsDir "ddl-contention-k6-summary.json"
if (Test-Path $resultPath) { Remove-Item $resultPath -Force }

# Sample lock-blocked session count every 1s while k6 runs (finer-grained
# than run-p112-exercise.ps1's 2s connection sampler -- exec_ddl_locked's
# ACCESS EXCLUSIVE window is expected to be short-lived, so a coarser sample
# interval risks missing the peak entirely).
$lockSamples = [System.Collections.Generic.List[int]]::new()
$samplerJob = Start-Job -ScriptBlock {
    param($containerName)
    while ($true) {
        $n = docker exec $containerName psql -U postgres -d attome_loadtest -t -A -c `
            "SELECT count(*) FROM pg_stat_activity WHERE datname = 'attome_loadtest' AND wait_event_type = 'Lock'"
        if ($n) { $n }
        Start-Sleep -Seconds 1
    }
} -ArgumentList "loadtest-postgres-loadtest-1"

Write-Host "=== Running schema_change_ddl.js (DDL_VUS=$DdlVUs, WRITE_VUS=$WriteVUs, DDL window: +$DdlStartOffset for $DdlDuration, total $Duration) ==="
& docker run --rm -v "$($script:LoadtestDir):/work" `
    -e "BASE_URLS=$baseUrlsDocker" `
    -e "ADMIN_EMAIL=$($seed.admin_email)" `
    -e "ADMIN_PASSWORD=$($seed.admin_password)" `
    -e "TEST_EMAIL=$($seed.test_email)" `
    -e "TEST_PASSWORD=$($seed.test_password)" `
    -e "DDL_ENTITY=$($seed.ddl_entity)" `
    -e "DDL_ENTITY_ID=$($seed.ddl_entity_id)" `
    -e "DDL_FIELD_ID=$($seed.ddl_field_id)" `
    -e "DDL_RECORD_IDS_FILE=/work/.generated/ddl-record-ids.json" `
    -e "DURATION=$Duration" `
    -e "DDL_START_OFFSET=$DdlStartOffset" `
    -e "DDL_DURATION=$DdlDuration" `
    -e "DDL_VUS=$DdlVUs" `
    -e "WRITE_VUS=$WriteVUs" `
    grafana/k6 run "/work/k6/schema_change_ddl.js" `
    --summary-trend-stats "avg,min,med,p(50),p(90),p(99),max" `
    --summary-export "/work/results/ddl-contention-k6-summary.json"
$k6ExitCode = $LASTEXITCODE

Stop-Job -Job $samplerJob -ErrorAction SilentlyContinue | Out-Null
$rawSamples = Receive-Job -Job $samplerJob -ErrorAction SilentlyContinue
Remove-Job -Job $samplerJob -Force -ErrorAction SilentlyContinue
foreach ($s in $rawSamples) { if ($s -match '^\d+$') { $lockSamples.Add([int]$s) } }
$peakBlockedSessions = if ($lockSamples.Count -gt 0) { ($lockSamples | Measure-Object -Maximum).Maximum } else { -1 }

Write-Host "=== Scanning node logs for exec_ddl_locked's 55P03 retry warning ==="
# `tracing::warn!(..., "provisioning DDL hit lock_timeout, retrying")` --
# ddl.rs's exact message text. tracing_subscriber's default writer is
# stdout (crates/server/src/observability.rs — no with_writer override), and
# Start-LoadtestNodes redirects each node's stdout to logs/node-<port>.out.log,
# so this is a direct read of the executor's own retry decision, not an
# inference from latency alone.
$retryLogHits = 0
foreach ($port in $ports) {
    $logPath = Join-Path $script:LogDir "node-$port.out.log"
    if (Test-Path $logPath) {
        $hits = (Select-String -Path $logPath -Pattern "provisioning DDL hit lock_timeout, retrying" -SimpleMatch -ErrorAction SilentlyContinue)
        $count = if ($hits) { @($hits).Count } else { 0 }
        Write-Host "  node-$port : $count retry-warning line(s)"
        $retryLogHits += $count
    }
}

Stop-LoadtestNodes

if (-not (Test-Path $resultPath)) {
    Write-Warning "k6 produced no summary-export (exit code $k6ExitCode) — check the docker run output above."
    exit 1
}
$summary = Get-Content $resultPath -Raw | ConvertFrom-Json
$m = $summary.metrics

function Get-TrendRow {
    # `.count` on a Trend metric's --summary-export entry is used the same
    # way run-p112-exercise.ps1 reads `.p(50)` off http_req_duration --
    # unconfirmed against a real k6 export for a *custom* Trend specifically
    # (only ever exercised here against the built-in http_req_duration
    # before now), same disclosed-guess caveat run-soak-test.ps1 already
    # carries for its own `http_req_failed` field read.
    param($Trend, [string]$Name)
    if (-not $Trend) {
        return [PSCustomObject]@{ metric = $Name; requests = 0; p50_ms = $null; p90_ms = $null; p99_ms = $null; max_ms = $null }
    }
    [PSCustomObject]@{
        metric   = $Name
        requests = $Trend.count
        p50_ms   = [Math]::Round($Trend.'p(50)', 1)
        p90_ms   = [Math]::Round($Trend.'p(90)', 1)
        p99_ms   = [Math]::Round($Trend.'p(99)', 1)
        max_ms   = [Math]::Round($Trend.max, 1)
    }
}

$rows = @(
    Get-TrendRow -Trend $m.ddl_toggle_duration -Name "ddl_toggle"
    Get-TrendRow -Trend $m.concurrent_write_duration -Name "concurrent_write (overall)"
    Get-TrendRow -Trend $m.concurrent_write_duration_outside_ddl -Name "concurrent_write (outside DDL window)"
    Get-TrendRow -Trend $m.concurrent_write_duration_during_ddl -Name "concurrent_write (DURING DDL window)"
)
$rows | Format-Table -AutoSize

$outsideP99 = $rows[2].p99_ms
$duringP99 = $rows[3].p99_ms
$writeDegradationPct = if ($outsideP99 -and $outsideP99 -gt 0 -and $duringP99) {
    [Math]::Round((($duringP99 - $outsideP99) / $outsideP99) * 100, 1)
} else { $null }

Write-Host ""
Write-Host "Peak lock-blocked Postgres sessions observed: $peakBlockedSessions"
Write-Host "exec_ddl_locked 55P03-retry warning lines observed across $NodeCount node log(s): $retryLogHits"
if ($null -ne $writeDegradationPct) {
    Write-Host "concurrent_write P99 change during the DDL window vs. outside it: $writeDegradationPct%"
}

$output = [PSCustomObject]@{
    node_count                  = $NodeCount
    ddl_vus                     = $DdlVUs
    write_vus                   = $WriteVUs
    duration                    = $Duration
    ddl_start_offset            = $DdlStartOffset
    ddl_duration                = $DdlDuration
    ddl_row_count                = $seed.ddl_row_count
    ddl_toggle_failures          = $m.ddl_toggle_failures.count
    concurrent_write_failures    = $m.concurrent_write_failures.count
    peak_blocked_sessions        = $peakBlockedSessions
    exec_ddl_locked_retry_log_hits = $retryLogHits
    concurrent_write_p99_change_during_ddl_pct = $writeDegradationPct
    trends                       = $rows
}
$outputPath = Join-Path $script:ResultsDir "ddl-contention-summary.json"
$output | ConvertTo-Json -Depth 5 | Set-Content -Path $outputPath -Encoding utf8
Write-Host ""
Write-Host "Written: loadtest/results/ddl-contention-summary.json, loadtest/results/ddl-contention-k6-summary.json"
