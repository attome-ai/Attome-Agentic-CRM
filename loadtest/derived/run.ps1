# A26-T6 - stored derived entity membership under a busy change feed.
#
# Defines a stored derived entity over loadtest_bulk (`title == "hot"`),
# waits for its first full refresh (A26-T3), then changes -ChangesPerSecond
# records a second through the record API (PATCH with If-Match, so every
# change goes through the change feed): each record is set "hot" (it must
# enter) and later back to "cold" (it must leave). The lag of each change is
# the time from its PATCH answering to its row in derived_entity_history
# (A26-T2). Reports the lag p50/p95/max, changes that never arrived, the
# refresh time and the node's CPU, and records them in
# docs/perf-history/derived.json. Passes when the p95 lag is under
# -MaxP95Seconds (10) and nothing is missing.
#
# Requires seed.ps1 with a loadtest_bulk of the size to test (the plan's
# figure is 2,000,000: ./scripts/seed.ps1 -RowCount 2000000). Never point it
# at the shared dev server: it starts its own loadtest node.
#
# Usage:
#   pwsh -File loadtest/derived/run.ps1 -Plan     # print the phases, run nothing
#   $env:LOADTEST_ACK = "yes"
#   docker compose -f loadtest/docker-compose.loadtest.yml up -d
#   pwsh -File loadtest/scripts/seed.ps1 -RowCount 2000000
#   pwsh -File loadtest/derived/run.ps1
param(
    [int]$ChangesPerSecond = 10,
    [int]$DurationSeconds = 120,
    [int]$CatchUpSeconds = 60,
    [double]$MaxP95Seconds = 10,
    [int]$RefreshTimeoutSeconds = 3600,
    [switch]$Plan
)

$name = "loadtest_hot"
$changes = $ChangesPerSecond * $DurationSeconds
$records = [Math]::Ceiling($changes / 2)

if ($Plan) {
    Write-Host "Derived entity membership under load (A26-T6):"
    Write-Host "  1. PUT /api/v1/admin/derived-entities/$name (anchor loadtest_bulk, title == ""hot"", stored);"
    Write-Host "     wait for the first full refresh (membership count = hot rows), up to ${RefreshTimeoutSeconds}s."
    Write-Host "  2. $changes changes at $ChangesPerSecond/s over ${DurationSeconds}s on $records records:"
    Write-Host "     each set ""hot"" (enters), then later ""cold"" (leaves), through PATCH with If-Match."
    Write-Host "  3. Wait ${CatchUpSeconds}s, then read derived_entity_history for each change."
    Write-Host "  Report: lag p50/p95/max (PATCH answered -> history row), missing changes, refresh time, CPU."
    Write-Host "  Pass: p95 under ${MaxP95Seconds}s and nothing missing; recorded in docs/perf-history/derived.json."
    exit 0
}

. "$PSScriptRoot/../scripts/common.ps1"
Assert-LoadtestSafety

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) {
    throw "loadtest/.generated/seed-info.json not found - run seed.ps1 first."
}
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json

function Invoke-Psql {
    param([string]$Sql)
    docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -t -A -F "," -c $Sql
}

function Invoke-Api {
    # curl, as the other exercises use it; the Sec-Fetch-Site header is the
    # browser signal csrf_protect needs on a cookie-authenticated write.
    param($Method, $BaseUrl, $Path, $CookieJar, $Body = $null, $IfMatch = $null)
    $curlArgs = @("-s", "-X", $Method.ToUpper(), "$BaseUrl$Path",
        "-H", "Content-Type: application/json",
        "-H", "Sec-Fetch-Site: same-origin",
        "-b", $CookieJar, "-c", $CookieJar,
        "-w", "`n%{http_code}")
    if ($null -ne $IfMatch) { $curlArgs += @("-H", "If-Match: ""$IfMatch""") }
    $bodyFile = $null
    if ($null -ne $Body) {
        $bodyFile = Join-Path $script:GenDir "derived-body-$([guid]::NewGuid()).json"
        [System.IO.File]::WriteAllText($bodyFile, ($Body | ConvertTo-Json -Depth 10 -Compress),
            (New-Object System.Text.UTF8Encoding($false)))
        $curlArgs += @("--data-binary", "@$bodyFile")
    }
    try {
        $raw = & $script:CurlExe --connect-timeout 5 @curlArgs 2>$null
    } finally {
        if ($bodyFile) { Remove-Item $bodyFile -ErrorAction SilentlyContinue }
    }
    $lines = @($raw)
    $status = [int]$lines[-1]
    $text = ($lines[0..($lines.Length - 2)] -join "`n")
    if ($status -lt 200 -or $status -ge 300) {
        throw "API call failed: $Method $Path -> HTTP ${status}: $text"
    }
    if ($text) { return $text | ConvertFrom-Json }
    return $null
}

function Get-Quantile {
    param([double[]]$Values, [double]$Q)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $sorted = $Values | Sort-Object
    $index = [Math]::Max(0, [Math]::Ceiling($Q * $sorted.Count) - 1)
    return [Math]::Round($sorted[$index], 2)
}

function Get-NodeCpuSeconds {
    $total = 0.0
    foreach ($p in (Get-Process -Name "attome*" -ErrorAction SilentlyContinue)) {
        if ($p.TotalProcessorTime) { $total += $p.TotalProcessorTime.TotalSeconds }
    }
    return $total
}

Write-Host "=== Starting one node ==="
$ports = Start-LoadtestNodes -Count 1 -BootstrapAdminEmail $seed.admin_email
Start-Sleep -Seconds 2
$baseUrl = "http://127.0.0.1:$($ports[0])"
$jar = Join-Path $script:GenDir "derived-admin-cookies.txt"
Remove-Item $jar -ErrorAction SilentlyContinue

try {
    Invoke-Api -Method Post -BaseUrl $baseUrl -Path "/api/v1/auth/login" -CookieJar $jar `
        -Body @{ email = $seed.admin_email; password = $seed.admin_password } | Out-Null

    # The records to change: never "hot" now, chosen at random.
    $rows = @(Invoke-Psql "SELECT id, row_version FROM loadtest_bulk WHERE title IS DISTINCT FROM 'hot' AND (is_active IS NULL OR is_active) ORDER BY random() LIMIT $records")
    if ($rows.Count -lt $records) { throw "loadtest_bulk has only $($rows.Count) records to change; seed more" }
    $targets = $rows | ForEach-Object { $id, $version = $_ -split ","; [pscustomobject]@{ id = $id; version = [long]$version } }

    Write-Host "=== Phase 1: define $name (stored) and wait for its first refresh ==="
    $refreshStart = [DateTimeOffset]::UtcNow
    Invoke-Api -Method Put -BaseUrl $baseUrl -Path "/api/v1/admin/derived-entities/$name" -CookieJar $jar `
        -Body @{ anchor = "loadtest_bulk"; condition = 'title == "hot"'; mode = "stored" } | Out-Null
    $hot = [long](Invoke-Psql "SELECT count(*) FROM loadtest_bulk WHERE title = 'hot' AND (is_active IS NULL OR is_active)")
    do {
        Start-Sleep -Seconds 2
        $members = [long](Invoke-Psql "SELECT count(*) FROM xrm_dm_$name")
        $waited = ([DateTimeOffset]::UtcNow - $refreshStart).TotalSeconds
    } while ($members -ne $hot -and $waited -lt $RefreshTimeoutSeconds)
    $refreshSeconds = [Math]::Round($waited, 1)
    Write-Host "  refresh: $members of $hot members after ${refreshSeconds}s"

    Write-Host "=== Phase 2: $changes changes at $ChangesPerSecond/s ==="
    $cpuBefore = Get-NodeCpuSeconds
    $plan = [System.Collections.Generic.List[object]]::new()
    foreach ($t in $targets) { $plan.Add([pscustomobject]@{ target = $t; title = "hot"; change = "enter" }) }
    foreach ($t in $targets) { $plan.Add([pscustomobject]@{ target = $t; title = "cold"; change = "leave" }) }
    $sent = [System.Collections.Generic.List[object]]::new()
    $loadStart = [DateTimeOffset]::UtcNow
    for ($i = 0; $i -lt $plan.Count -and $i -lt $changes; $i++) {
        $due = $loadStart.AddSeconds($i / $ChangesPerSecond)
        $wait = ($due - [DateTimeOffset]::UtcNow).TotalMilliseconds
        if ($wait -gt 0) { Start-Sleep -Milliseconds ([int]$wait) }
        $step = $plan[$i]
        Invoke-Api -Method Patch -BaseUrl $baseUrl -Path "/api/v1/loadtest_bulk/$($step.target.id)" -CookieJar $jar `
            -Body @{ title = $step.title } -IfMatch $step.target.version | Out-Null
        $step.target.version += 1
        $sent.Add([pscustomobject]@{ id = $step.target.id; change = $step.change; at = [DateTimeOffset]::UtcNow })
    }
    $loadSeconds = ([DateTimeOffset]::UtcNow - $loadStart).TotalSeconds
    $cpuAfter = Get-NodeCpuSeconds
    Write-Host "  sent $($sent.Count) changes in $([Math]::Round($loadSeconds, 1))s"

    Write-Host "=== Phase 3: catch up ${CatchUpSeconds}s, then read the history ==="
    Start-Sleep -Seconds $CatchUpSeconds
    $history = @{}
    foreach ($line in @(Invoke-Psql "SELECT anchor_id, change, to_char(min(at) AT TIME ZONE 'UTC', 'YYYY-MM-DD""T""HH24:MI:SS.US""Z""') FROM derived_entity_history WHERE name = '$name' AND at >= '$($loadStart.ToString("o"))' GROUP BY 1, 2")) {
        if (-not $line) { continue }
        $id, $change, $at = $line -split ","
        $history["$id/$change"] = [DateTimeOffset]::Parse($at)
    }
    $lags = [System.Collections.Generic.List[double]]::new()
    $missing = 0
    foreach ($s in $sent) {
        $arrived = $history["$($s.id)/$($s.change)"]
        if ($null -eq $arrived) { $missing++; continue }
        $lags.Add([Math]::Max(0, ($arrived - $s.at).TotalSeconds))
    }
} finally {
    Stop-LoadtestNodes
}

$cores = [Environment]::ProcessorCount
$cpuPercent = if ($loadSeconds -gt 0) { [Math]::Round(100 * ($cpuAfter - $cpuBefore) / ($loadSeconds * $cores), 1) } else { $null }
$p50 = Get-Quantile $lags.ToArray() 0.5
$p95 = Get-Quantile $lags.ToArray() 0.95
$max = Get-Quantile $lags.ToArray() 1.0
Write-Host ("membership lag p50 {0}s, p95 {1}s, max {2}s; {3} missing of {4}; refresh {5}s; node CPU {6}% of {7} cores" -f `
    $p50, $p95, $max, $missing, $sent.Count, $refreshSeconds, $cpuPercent, $cores)

$historyPath = Join-Path $script:RepoRoot "docs/perf-history/derived.json"
$file = if (Test-Path $historyPath) {
    Get-Content $historyPath -Raw | ConvertFrom-Json
} else {
    [pscustomobject]@{ schema = "attome-derived-bench/v1"; runs = @() }
}
$commit = (& git -C $script:RepoRoot rev-parse --short HEAD).Trim()
$record = [ordered]@{
    measured_at         = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    commit              = $commit
    cores               = $cores
    anchor_rows         = $seed.bulk_row_count
    changes_per_second  = $ChangesPerSecond
    changes             = $sent.Count
    lag_p50_seconds     = $p50
    lag_p95_seconds     = $p95
    lag_max_seconds     = $max
    missing             = $missing
    refresh_seconds     = $refreshSeconds
    node_cpu_percent    = $cpuPercent
}
$file.runs = @($file.runs) + @([pscustomobject]$record)
[System.IO.File]::WriteAllText($historyPath, ($file | ConvertTo-Json -Depth 6) + "`n", (New-Object System.Text.UTF8Encoding($false)))

if ($missing -gt 0 -or $null -eq $p95 -or $p95 -ge $MaxP95Seconds) {
    Write-Host "FAIL: membership lag p95 must be under ${MaxP95Seconds}s with nothing missing"
    exit 1
}
Write-Host "PASS: membership lag p95 $p95 s"
