# Y13-T6: the footprint of one deployment profile. Starts the release build
# as that profile runs it (Solo: one node with cache.backend = "memory", no
# Redis; the others: the loadtest Dragonfly), and records:
#   - startup: seconds from process start to the first ready answer;
#   - idle RSS: the node's resident memory after -IdleSeconds (default 60)
#     with no traffic;
#   - peak RSS: the highest resident memory sampled while the production mix
#     (k6/production_mix.js, AA1-T3) runs at -LoadFraction (default 50%) of
#     the profile's rated load for -DurationMinutes (default 10).
# RSS is the app process alone, never Postgres. The numbers go into
# docs/perf-history/footprint.json under the profile, with the machine they
# were measured on. The run FAILS when Solo's idle RSS exceeds -MaxIdleRssMb
# (default 512).
#
# Usage (after seed.ps1 -Profile <profile>, with the load-test stack up):
#   $env:LOADTEST_ACK = "yes"
#   pwsh -File loadtest/footprint/footprint.ps1 -Profile solo
param(
    [ValidateSet("solo", "team", "ha", "scale")]
    [string]$Profile = "solo",
    [int]$IdleSeconds = 60,
    [int]$DurationMinutes = 10,
    [double]$LoadFraction = 0.5,
    [int]$SampleSeconds = 2,
    [int]$MaxIdleRssMb = 512
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "../scripts/common.ps1")
Assert-LoadtestSafety

$profiles = Get-Content (Join-Path $script:LoadtestDir "profiles.json") -Raw | ConvertFrom-Json
$spec = $profiles.$Profile
if (-not $spec.rated_rps) { throw "profiles.json has no rated_rps for '$Profile'" }
$rate = [Math]::Max(1, [int][Math]::Round([double]$spec.rated_rps * $LoadFraction))
$backend = if ($Profile -eq "solo") { "memory" } else { "redis" }

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) { throw "loadtest/.generated/seed-info.json not found; run seed.ps1 first." }
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json
$seedSummary = Join-Path $script:ResultsDir "seed-$Profile.json"

# Always the binary at HEAD: a stale target/release would measure old code.
Write-Host "Building the release binary..."
& cargo build --release -p attome
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

function Get-NodeRssMb {
    $total = 0
    foreach ($line in Get-Content $script:PidFile) {
        $procId = ($line -split "`t")[0]
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        if (-not $proc) { throw "node process $procId exited; see loadtest/logs" }
        $total += $proc.WorkingSet64
    }
    [Math]::Round($total / 1MB, 1)
}

function Get-Machine {
    if ($script:IsWindowsHost) {
        $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
        $os = Get-CimInstance Win32_OperatingSystem
        [ordered]@{
            cpu       = $cpu.Name.Trim()
            cores     = [int]$cpu.NumberOfLogicalProcessors
            memory_gb = [Math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
            os        = "$($os.Caption) $($os.Version)"
        }
    } else {
        $model = (Get-Content /proc/cpuinfo | Where-Object { $_ -like "model name*" } | Select-Object -First 1) -replace "^model name\s*:\s*", ""
        $memKb = [double](((Get-Content /proc/meminfo | Select-Object -First 1) -split "\s+")[1])
        [ordered]@{
            cpu       = $model.Trim()
            cores     = [int](& nproc)
            memory_gb = [Math]::Round($memKb / 1MB, 1)
            os        = (& uname -sr)
        }
    }
}

Write-Host "=== Footprint: profile=$Profile cache=$backend, idle ${IdleSeconds}s, then $rate req/s for $DurationMinutes min ==="
$ports = Start-LoadtestNodes -Count 1 -BootstrapAdminEmail $seed.admin_email -CacheBackend $backend
$port = $ports | Select-Object -First 1
$startup = $script:NodeStartupSeconds[$port]
$peak = 0.0
try {
    Start-Sleep -Seconds $IdleSeconds
    $idle = Get-NodeRssMb
    Write-Host "startup ${startup}s, idle RSS $idle MB"

    $baseUrl = if ($script:IsWindowsHost) { "http://host.docker.internal:$port" } else { "http://localhost:$port" }
    $summaryName = "footprint-$Profile.json"
    $k6Env = @{
        BASE_URLS      = $baseUrl
        TEST_EMAIL     = $seed.test_email
        TEST_PASSWORD  = $seed.test_password
        BULK_ENTITY    = $seed.bulk_entity
        BULK_QUERY_ID  = $seed.bulk_query_id
        BULK_ROW_COUNT = $seed.bulk_row_count
        RATE           = $rate
        DURATION       = "${DurationMinutes}m"
        WARMUP         = "0s"
    }
    if (Test-Path $seedSummary) {
        $k6Env.SEED_FILE = if ($script:IsWindowsHost) { "/work/results/seed-$Profile.json" } else { $seedSummary }
    }
    $k6Args = @()
    foreach ($kv in $k6Env.GetEnumerator()) { $k6Args += @("-e", "$($kv.Key)=$($kv.Value)") }
    # k6 runs in the background so the node's memory can be sampled while it
    # is under load.
    $k6 = if ($script:IsWindowsHost) {
        Start-Process -FilePath "docker" -PassThru -WindowStyle Hidden -ArgumentList (
            @("run", "--rm", "-v", "$($script:LoadtestDir):/work") + $k6Args +
            @("grafana/k6", "run", "--quiet", "/work/k6/production_mix.js", "--summary-export", "/work/results/$summaryName"))
    } else {
        Start-Process -FilePath "k6" -PassThru -ArgumentList (
            @("run", "--quiet") + $k6Args +
            @((Join-Path $script:LoadtestDir "k6/production_mix.js"), "--summary-export", (Join-Path $script:ResultsDir $summaryName)))
    }
    $peak = $idle
    while (-not $k6.HasExited) {
        Start-Sleep -Seconds $SampleSeconds
        $peak = [Math]::Max($peak, (Get-NodeRssMb))
    }
    if (-not (Test-Path (Join-Path $script:ResultsDir $summaryName))) { throw "k6 wrote no summary; the load did not run" }
    Write-Host "peak RSS under load $peak MB"
} finally {
    Stop-LoadtestNodes
}

$historyPath = Join-Path $script:RepoRoot "docs/perf-history/footprint.json"
$history = if (Test-Path $historyPath) {
    Get-Content $historyPath -Raw | ConvertFrom-Json
} else {
    [pscustomobject]@{ schema = "attome-footprint/v1"; profiles = [pscustomobject]@{} }
}
$commit = (& git -C $script:RepoRoot rev-parse --short HEAD).Trim()
$record = [ordered]@{
    measured_at     = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    commit          = $commit
    machine         = Get-Machine
    cache_backend   = $backend
    startup_seconds = $startup
    idle_rss_mb     = $idle
    idle_seconds    = $IdleSeconds
    peak_rss_mb     = $peak
    load            = [ordered]@{ rate_rps = $rate; fraction = $LoadFraction; duration_minutes = $DurationMinutes; mix = "k6/production_mix.js" }
    # The seeded size the load ran over (seed.ps1 -RowCount, or the profile's records_per_entity).
    bulk_rows       = $seed.bulk_row_count
}
$history.profiles | Add-Member -NotePropertyName $Profile -NotePropertyValue $record -Force
$json = $history | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($historyPath, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))

Write-Host ("startup {0}s, idle RSS {1} MB, peak RSS {2} MB -> {3}" -f $startup, $idle, $peak, $historyPath)
if ($Profile -eq "solo" -and $idle -gt $MaxIdleRssMb) {
    Write-Host "FAIL: Solo idle RSS $idle MB exceeds $MaxIdleRssMb MB"
    exit 1
}
Write-Host "PASS"
