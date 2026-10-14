# P1.8d soak test (new — no prior step number; see P1.8d-load-testing.md's
# addendum for where this sits in the plan). Closes a gap none of steps 1-7
# covered: every prior pass (run-matrix.ps1, run-p112-exercise.ps1) is a
# short, fixed-duration snapshot (15-30s per scenario) — nothing today holds
# load for a sustained period and asks "does anything drift as time passes"
# (a Postgres connection leak, a growing error rate, a slowly climbing tail).
#
# Design: start N app nodes ONCE and leave them running for the whole soak
# (unlike run-matrix.ps1, which recycles nodes per N) — that persistence is
# the point, since a leak or drift that only shows up after sustained uptime
# would be invisible to a harness that restarts everything between measurements.
# Run the same scenario back-to-back in $Windows fixed-length windows against
# that one long-lived node set, sampling the Postgres connection count
# throughout (not just once), and compare the first window against the last to
# surface drift instead of requiring a human to eyeball a big raw dump.
#
# This does NOT replace run-matrix.ps1/run-p112-exercise.ps1's node-count
# matrix or the pgbouncer/chainer comparisons — it answers a different
# question (stability over time at one fixed topology) than they do (relative
# behavior across topology/node-count/chainer state at a fixed short duration).
#
# Usage:
#   $env:LOADTEST_ACK = "yes"
#   docker compose -f docker-compose.loadtest.yml up -d   # if not already up
#   ./scripts/seed.ps1   # if not already seeded
#   ./scripts/run-soak-test.ps1                                    # 6 x 5min = 30min, mutating_write, N=4, direct
#   ./scripts/run-soak-test.ps1 -Windows 24 -WindowMinutes 15       # 6h soak
#   ./scripts/run-soak-test.ps1 -Scenario crud_read -NodeCount 12
#   ./scripts/run-soak-test.ps1 -Topology pgbouncer -ChainerEnabled  # combined with P1.12/P1.13 state
param(
    [int]$NodeCount = 4,
    [string]$Scenario = 'mutating_write',
    [int]$WindowMinutes = 5,
    [int]$Windows = 6,
    [int]$SampleIntervalSecs = 15,
    [string]$Vus = "",
    [ValidateSet("direct", "pgbouncer")]
    [string]$Topology = "direct",
    [switch]$ChainerEnabled,
    [string]$RunTag = "soak"
)
. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) {
    throw "loadtest/.generated/seed-info.json not found — run seed.ps1 first."
}
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json

if ($Topology -eq "pgbouncer") {
    # Same one-time role-level search_path fix run-p112-exercise.ps1 needs —
    # see pgbouncer/pgbouncer.ini's own comments for why this can't be carried
    # via the [databases] line or a client options= parameter on pgbouncer 1.18.
    docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -c `
        "ALTER ROLE postgres IN DATABASE attome_loadtest SET search_path = attome_loadtest;" | Out-Null
    Write-Host "Bringing up pgbouncer-loadtest overlay..."
    & docker compose -f (Join-Path $script:LoadtestDir "docker-compose.loadtest.yml") `
        -f (Join-Path $script:LoadtestDir "docker-compose.pgbouncer.yml") up -d --build pgbouncer-loadtest
    if ($LASTEXITCODE -ne 0) { throw "docker compose up pgbouncer-loadtest failed" }
    Start-Sleep -Seconds 3
}

Write-Host ""
Write-Host "=== Soak test: scenario=$Scenario N=$NodeCount topology=$Topology chainer_enabled=$($ChainerEnabled.IsPresent) ==="
Write-Host "=== $Windows window(s) x ${WindowMinutes}min = $($Windows * $WindowMinutes)min total ==="
$ports = Start-LoadtestNodes -Count $NodeCount -BootstrapAdminEmail $seed.admin_email -Topology $Topology -ChainerEnabled:$ChainerEnabled

$baseUrls = if ($script:IsWindowsHost) {
    ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','
} else {
    ($ports | ForEach-Object { "http://localhost:$_" }) -join ','
}

# Background connection-count sampler, running for the whole soak (not just
# per-window) — records elapsed-seconds-since-start alongside each sample so
# the time series can be plotted/compared without relying on job-queue timing.
$samplerJob = Start-Job -ScriptBlock {
    param($containerName, $intervalSecs)
    $started = Get-Date
    while ($true) {
        $n = docker exec $containerName psql -U postgres -d attome_loadtest -t -A -c `
            "SELECT count(*) FROM pg_stat_activity WHERE datname = 'attome_loadtest'"
        if ($n -match '^\d+$') {
            $elapsed = [Math]::Round(((Get-Date) - $started).TotalSeconds, 0)
            [PSCustomObject]@{ elapsed_secs = $elapsed; conns = [int]$n }
        }
        Start-Sleep -Seconds $intervalSecs
    }
} -ArgumentList "loadtest-postgres-loadtest-1", $SampleIntervalSecs

$mutIdsPath = $null
if ($Scenario -eq 'mutating_write') {
    $mutIdsPath = Join-Path $script:GenDir "mut-record-ids.json"
    $mutIdsJson = ($seed.mut_record_ids | ConvertTo-Json -Compress)
    [System.IO.File]::WriteAllText($mutIdsPath, $mutIdsJson, (New-Object System.Text.UTF8Encoding($false)))
}

$windowResults = @()
try {
    for ($w = 1; $w -le $Windows; $w++) {
        Write-Host ""
        Write-Host "--- window $w/$Windows ($Scenario, elapsed so far: $(($w - 1) * $WindowMinutes)min) ---"
        $resultPath = Join-Path $script:ResultsDir "$RunTag-$Scenario-w$w.json"
        if (Test-Path $resultPath) { Remove-Item $resultPath -Force }

        $k6EnvVars = @{
            BASE_URLS      = $baseUrls
            TEST_EMAIL     = $seed.test_email
            TEST_PASSWORD  = $seed.test_password
            ADMIN_EMAIL    = $seed.admin_email
            ADMIN_PASSWORD = $seed.admin_password
            WIDE_ENTITY    = $seed.wide_entity
            BULK_ENTITY    = $seed.bulk_entity
            BULK_QUERY_ID  = $seed.bulk_query_id
            MUT_ENTITY     = $seed.mut_entity
            BULK_ROW_COUNT = $seed.bulk_row_count
            DURATION       = "${WindowMinutes}m"
        }
        if ($Vus) { $k6EnvVars.VUS = $Vus }
        if ($mutIdsPath) {
            $k6EnvVars.MUT_RECORD_IDS_FILE = if ($script:IsWindowsHost) { "/work/.generated/mut-record-ids.json" } else { $mutIdsPath }
        }

        if ($script:IsWindowsHost) {
            $k6Env = @()
            foreach ($kv in $k6EnvVars.GetEnumerator()) { $k6Env += @("-e", "$($kv.Key)=$($kv.Value)") }
            & docker run --rm -v "$($script:LoadtestDir):/work" @k6Env grafana/k6 run `
                "/work/k6/$Scenario.js" `
                --summary-trend-stats "avg,min,med,p(50),p(90),p(99),max" `
                --summary-export "/work/results/$RunTag-$Scenario-w$w.json"
        } else {
            $k6Args = @()
            foreach ($kv in $k6EnvVars.GetEnumerator()) { $k6Args += @("-e", "$($kv.Key)=$($kv.Value)") }
            & k6 run @k6Args (Join-Path $script:LoadtestDir "k6/$Scenario.js") `
                --summary-trend-stats "avg,min,med,p(50),p(90),p(99),max" `
                --summary-export $resultPath
        }

        if (Test-Path $resultPath) {
            $summary = Get-Content $resultPath -Raw | ConvertFrom-Json
            $trend = $summary.metrics.http_req_duration
            # NOT independently verified in this environment (no k6 binary/Docker
            # daemon to actually run and inspect a real --summary-export against):
            # http_req_failed is a k6 "rate" metric: assuming --summary-export's
            # known-flat shape (same as http_req_duration.'p(50)' above, per the
            # comment in run-matrix.ps1) puts the fraction failed at either
            # .value or .rate depending on k6 version. Try both, else null rather
            # than a wrong number silently reading as "0% failed".
            $failedMetric = $summary.metrics.http_req_failed
            $errorRate = if ($null -ne $failedMetric.value) { $failedMetric.value }
                         elseif ($null -ne $failedMetric.rate) { $failedMetric.rate }
                         else { $null }
            $windowResults += [PSCustomObject]@{
                window     = $w
                elapsed_min = ($w - 1) * $WindowMinutes
                p50_ms     = [Math]::Round($trend.'p(50)', 1)
                p90_ms     = [Math]::Round($trend.'p(90)', 1)
                p99_ms     = [Math]::Round($trend.'p(99)', 1)
                max_ms     = [Math]::Round($trend.max, 1)
                error_rate = $errorRate
                requests   = $summary.metrics.http_reqs.count
            }
        } else {
            Write-Warning "window $w produced no summary-export — check docker/k6 output above."
        }
    }
} finally {
    Stop-Job -Job $samplerJob -ErrorAction SilentlyContinue | Out-Null
    $connSamples = @(Receive-Job -Job $samplerJob -ErrorAction SilentlyContinue)
    Remove-Job -Job $samplerJob -Force -ErrorAction SilentlyContinue
    Stop-LoadtestNodes
    if ($Topology -eq "pgbouncer") {
        & docker compose -f (Join-Path $script:LoadtestDir "docker-compose.loadtest.yml") `
            -f (Join-Path $script:LoadtestDir "docker-compose.pgbouncer.yml") stop pgbouncer-loadtest | Out-Null
    }
}

$windowResults | Format-Table -AutoSize

# Drift verdict — compare the first quarter of windows/samples against the
# last quarter, rather than just first-vs-last, so one noisy window on either
# edge doesn't flip the verdict. Thresholds (20% conn growth, 20% P99 growth)
# match guidelines §14.5/P1.12's own "not just degraded but within 20%" bar,
# reused here for consistency, not independently derived for this exercise.
function Get-EdgeAverage {
    param([array]$Values, [string]$Edge)
    if ($Values.Count -eq 0) { return $null }
    $quarter = [Math]::Max(1, [Math]::Floor($Values.Count / 4))
    $slice = if ($Edge -eq 'first') { $Values[0..($quarter - 1)] } else { $Values[($Values.Count - $quarter)..($Values.Count - 1)] }
    return ($slice | Measure-Object -Average).Average
}

$connCounts = @($connSamples | ForEach-Object { $_.conns })
$connFirstAvg = Get-EdgeAverage -Values $connCounts -Edge 'first'
$connLastAvg = Get-EdgeAverage -Values $connCounts -Edge 'last'
$connGrowthPct = if ($connFirstAvg -and $connFirstAvg -gt 0) { [Math]::Round((($connLastAvg - $connFirstAvg) / $connFirstAvg) * 100, 1) } else { $null }

$p99s = @($windowResults | ForEach-Object { $_.p99_ms })
$p99FirstAvg = Get-EdgeAverage -Values $p99s -Edge 'first'
$p99LastAvg = Get-EdgeAverage -Values $p99s -Edge 'last'
$p99GrowthPct = if ($p99FirstAvg -and $p99FirstAvg -gt 0) { [Math]::Round((($p99LastAvg - $p99FirstAvg) / $p99FirstAvg) * 100, 1) } else { $null }

$errorRates = @($windowResults | Where-Object { $null -ne $_.error_rate } | ForEach-Object { $_.error_rate })
$errorRateRising = $errorRates.Count -ge 2 -and ($errorRates[-1] -gt $errorRates[0])

$verdict = [PSCustomObject]@{
    conn_growth_pct        = $connGrowthPct
    conn_leak_suspected     = if ($null -ne $connGrowthPct) { $connGrowthPct -gt 20 } else { $null }
    p99_growth_pct         = $p99GrowthPct
    latency_drift_suspected = if ($null -ne $p99GrowthPct) { $p99GrowthPct -gt 20 } else { $null }
    error_rate_rising       = $errorRateRising
}
Write-Host ""
Write-Host "=== Verdict ==="
$verdict | Format-List

$output = [PSCustomObject]@{
    scenario          = $Scenario
    node_count        = $NodeCount
    topology          = $Topology
    chainer_enabled   = $ChainerEnabled.IsPresent
    window_minutes    = $WindowMinutes
    windows           = $Windows
    window_results    = @($windowResults)
    conn_samples      = @($connSamples)
    verdict           = $verdict
}
$outPath = Join-Path $script:ResultsDir "$RunTag-$Scenario-summary.json"
$output | ConvertTo-Json -Depth 6 | Set-Content -Path $outPath -Encoding utf8
Write-Host ""
Write-Host "Written: loadtest/results/$RunTag-$Scenario-summary.json"
