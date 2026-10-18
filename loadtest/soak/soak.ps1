# AA14-T7: the soak. Runs the production-shaped mix (k6/production_mix.js,
# AA1-T3) at 30% of the profile's rated load for -DurationMinutes (default
# 24 h) against one long-lived node set, in 5-minute windows. After each
# window it records the nodes' resident memory, the Postgres connection count
# and p95 per operation class into loadtest/results/soak-<date>.csv.
#
# At the end it compares the first hour with the last (the first and last
# third of the windows when the run is shorter than two hours) and FAILS when
# memory grew more than 15% or any class's p95 grew more than 10%.
#
# Usage (after seed.ps1 -Profile <profile>, with the load-test stack up):
#   $env:LOADTEST_ACK = "yes"
#   pwsh -File loadtest/soak/soak.ps1 -Profile solo                      # 24 h
#   pwsh -File loadtest/soak/soak.ps1 -Profile solo -DurationMinutes 10  # a quick check
param(
    [ValidateSet("solo", "team", "ha", "scale")]
    [string]$Profile = "solo",
    [int]$DurationMinutes = 1440,
    [int]$WindowMinutes = 5,
    [double]$LoadFraction = 0.3,
    [int]$NodeCount = 1,
    [double]$MaxRssGrowth = 0.15,
    [double]$MaxP95Growth = 0.10
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "../scripts/common.ps1")
Assert-LoadtestSafety

$ops = @("read", "list", "query", "write", "search", "bulk")
$profiles = Get-Content (Join-Path $script:LoadtestDir "profiles.json") -Raw | ConvertFrom-Json
$spec = $profiles.$Profile
if (-not $spec.rated_rps) { throw "profiles.json has no rated_rps for '$Profile'" }
$rate = [Math]::Max(1, [int][Math]::Round([double]$spec.rated_rps * $LoadFraction))

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) { throw "loadtest/.generated/seed-info.json not found; run seed.ps1 first." }
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json
$seedSummary = Join-Path $script:ResultsDir "seed-$Profile.json"

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmm")
$csvPath = Join-Path $script:ResultsDir "soak-$stamp.csv"
$windows = [int][Math]::Ceiling($DurationMinutes / [double]$WindowMinutes)
Write-Host "=== Soak: profile=$Profile rate=$rate req/s ($([int]($LoadFraction * 100))% of $($spec.rated_rps)) for $DurationMinutes min, $windows window(s) ==="

$ports = Start-LoadtestNodes -Count $NodeCount -BootstrapAdminEmail $seed.admin_email
$baseUrls = if ($script:IsWindowsHost) {
    ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','
} else {
    ($ports | ForEach-Object { "http://localhost:$_" }) -join ','
}

function Get-NodeRssMb {
    $total = 0
    foreach ($line in Get-Content $script:PidFile) {
        $procId = ($line -split "`t")[0]
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if ($proc) { $total += $proc.WorkingSet64 }
    }
    [Math]::Round($total / 1MB, 1)
}

function Get-PgConnections {
    $n = docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -t -A -c `
        "SELECT count(*) FROM pg_stat_activity WHERE datname = 'attome_loadtest'"
    [int]($n | Select-Object -First 1)
}

$rows = @()
"window,elapsed_min,rss_mb,pg_connections," + (($ops | ForEach-Object { "p95_$_" }) -join ",") |
    Set-Content -Path $csvPath -Encoding utf8
$started = Get-Date
try {
    for ($w = 1; $w -le $windows; $w++) {
        $minutes = [Math]::Min($WindowMinutes, $DurationMinutes - ($w - 1) * $WindowMinutes)
        $summaryName = "soak-$stamp-w$w.json"
        $k6Env = @{
            BASE_URLS      = $baseUrls
            TEST_EMAIL     = $seed.test_email
            TEST_PASSWORD  = $seed.test_password
            BULK_ENTITY    = $seed.bulk_entity
            BULK_QUERY_ID  = $seed.bulk_query_id
            BULK_ROW_COUNT = $seed.bulk_row_count
            RATE           = $rate
            DURATION       = "${minutes}m"
            WARMUP         = "0s"
        }
        if (Test-Path $seedSummary) {
            $k6Env.SEED_FILE = if ($script:IsWindowsHost) { "/work/results/seed-$Profile.json" } else { $seedSummary }
        }
        $k6Args = @()
        foreach ($kv in $k6Env.GetEnumerator()) { $k6Args += @("-e", "$($kv.Key)=$($kv.Value)") }
        if ($script:IsWindowsHost) {
            & docker run --rm -v "$($script:LoadtestDir):/work" @k6Args grafana/k6 run --quiet `
                "/work/k6/production_mix.js" --summary-export "/work/results/$summaryName" | Out-Null
        } else {
            & k6 run --quiet @k6Args (Join-Path $script:LoadtestDir "k6/production_mix.js") `
                --summary-export (Join-Path $script:ResultsDir $summaryName) | Out-Null
        }
        $summaryPath = Join-Path $script:ResultsDir $summaryName
        if (-not (Test-Path $summaryPath)) { throw "window ${w}: k6 wrote no summary" }
        $metrics = (Get-Content $summaryPath -Raw | ConvertFrom-Json).metrics
        $p95 = @{}
        foreach ($op in $ops) {
            $trend = $metrics."http_req_duration{op:$op,phase:measure}"
            $p95[$op] = if ($trend) { [Math]::Round([double]$trend.'p(95)', 2) } else { $null }
        }
        $row = [pscustomobject]@{
            window         = $w
            elapsed_min    = [Math]::Round(((Get-Date) - $started).TotalMinutes, 1)
            rss_mb         = Get-NodeRssMb
            pg_connections = Get-PgConnections
            p95            = $p95
        }
        $rows += $row
        "$($row.window),$($row.elapsed_min),$($row.rss_mb),$($row.pg_connections)," +
            (($ops | ForEach-Object { $p95[$_] }) -join ",") | Add-Content -Path $csvPath -Encoding utf8
        Write-Host ("  window {0}/{1}: rss {2} MB, {3} connections, p95 read {4} ms" -f $w, $windows, $row.rss_mb, $row.pg_connections, $p95.read)
    }
} finally {
    Stop-LoadtestNodes
}

# The first hour against the last, or the first and last third of a shorter run.
$perHour = [int][Math]::Floor(60 / $WindowMinutes)
$span = if ($DurationMinutes -ge 120) { $perHour } else { [Math]::Max(1, [int][Math]::Floor($rows.Count / 3)) }
$first = $rows | Select-Object -First $span
$last = $rows | Select-Object -Last $span

function Get-Growth($before, $after) {
    if ($null -eq $before -or $before -le 0 -or $null -eq $after) { return $null }
    ($after - $before) / $before
}

$failures = @()
$rssGrowth = Get-Growth (($first | Measure-Object rss_mb -Average).Average) (($last | Measure-Object rss_mb -Average).Average)
Write-Host ("memory growth: {0:P1} (limit {1:P0})" -f $rssGrowth, $MaxRssGrowth)
if ($null -ne $rssGrowth -and $rssGrowth -gt $MaxRssGrowth) { $failures += "memory grew {0:P1}" -f $rssGrowth }
foreach ($op in $ops) {
    $before = ($first | ForEach-Object { $_.p95[$op] } | Where-Object { $null -ne $_ } | Measure-Object -Average).Average
    $after = ($last | ForEach-Object { $_.p95[$op] } | Where-Object { $null -ne $_ } | Measure-Object -Average).Average
    $growth = Get-Growth $before $after
    if ($null -eq $growth) { Write-Host "p95 $op`: no data"; continue }
    Write-Host ("p95 {0}: {1:N1} -> {2:N1} ms ({3:P1}, limit {4:P0})" -f $op, $before, $after, $growth, $MaxP95Growth)
    if ($growth -gt $MaxP95Growth) { $failures += "p95 $op grew {0:P1}" -f $growth }
}
Write-Host "results: $csvPath"
if ($failures.Count -gt 0) {
    Write-Host "FAIL: $($failures -join '; ')"
    exit 1
}
Write-Host "PASS"
